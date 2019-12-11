#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "devices/block.h"
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "filesys/cache.h"
#include "threads/malloc.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

/* The mutex for the inode_create. */
static struct lock inode_mutex;

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors (off_t size)
{
  return DIV_ROUND_UP (size, BLOCK_SECTOR_SIZE);
}

/* Returns the block device sector index that contains byte offset POS
   within INODE. */
static block_sector_t
byte_to_sector (const struct inode *inode, off_t pos) 
{
  ASSERT (inode != NULL);
  
  /* The sector index within the given inode. */
  return pos / BLOCK_SECTOR_SIZE;
}

/* Return the number of second indirect index table stored
   in the first indirect index table in inode. */
static block_sector_t
num_second_table (struct inode *inode)
{
  ASSERT (inode != NULL);
  
  /* Fetch the sector_disk and get the first_index. */
  struct sector_disk *info = cache_read (inode->sector, 0, 0, NULL, FETCH);
  
  return info->first_index + 1;
}

/* Return the number of data sectors stored
   in the second indirect index table in inode. */
static block_sector_t
num_data_sector (struct inode *inode)
{
  ASSERT (inode != NULL);
  
  /* Fetch the sector_disk and get the second_idx. */
  struct sector_disk *info = cache_read (inode->sector, 0, 0, NULL, FETCH);
  
  return info->second_index + 1;
}

/* Calculate the next indices of the given table indices. */
static void
next_indices (size_t first_old, size_t second_old, size_t *first_new, size_t *second_new)
{
  size_t first, second;
  
  /* There's no data yet. */
  if (first_old == -1)
  {
    *first_new = 0;
    *second_new = 0;
    return;
  }
  
  first = first_old;
  second = second_old + 1;
  
  if (second == 128)
  {
    first += 1;
    second = 0;
  }
  
  /* This should not happen.
     A file size exeeds 8MB. */
  if (first == 128)
  {
    *first_new = -1;
    *second_new = -1;
    return;
  }
  
  *first_new = first;
  *second_new = second;
}

/* Get the sector number for real data,
   with given first index and second index. */
static block_sector_t
get_data_sector (struct inode *inode, size_t first_index, size_t second_index)
{
  struct sector_disk *info;
  struct idx_table *first_table, *second_table;
  block_sector_t second_table_sector, data_sector;
  
  /* Check if given indices exceeds the boundary. */
  size_t first_bound = num_second_table (inode);
  size_t second_bound = num_data_sector (inode);
  
  if (first_bound == -1)
    return -1;
  
  if (first_index >= first_bound)
    return -1;
  
  if (first_index == first_bound - 1 && second_index >= second_bound)
    return -1;
  
  /* Fetch the sector_disk, and get the sector number for
     the first indirect index table. */
  info = cache_read (inode->sector, 0, 0, NULL, FETCH);
  block_sector_t table_sector = info->table_sector;
  
  /* Fetch the first indirect table,
     get the sector number for the first_index. */
  first_table = cache_read(table_sector, 0, 0, NULL, FETCH);
  second_table_sector = first_table->table[first_index];
  
  /* Fetch the second indirect table,
     get the sector number for the second_index. */
  second_table = cache_read(first_table->table[first_index], 0, 0, NULL, FETCH);
  data_sector = second_table->table[second_index];
  
  return data_sector;
}

/* Extend a file by allocate extra sectors for given inode.
   Calculate how many sectors are needed for given offset and
   size, considering number of sectors allocated currently.
   Update the inode's length information, and index tables,
   and then return the sector number for data which has given
   offset. */
static block_sector_t
extend_inode (struct inode *inode, block_sector_t num_sector_new)
{
  block_sector_t num_sector_old, num_sector;
  size_t first_index_old, second_index_old;
  size_t first_index_new, second_index_new;
  size_t first_index, second_index;
  off_t length_old;
  block_sector_t table;
  
  /* Get the current information of the given inode. */
  struct sector_disk *info = cache_read (inode->sector, 0, 0, NULL, FETCH);
  first_index_old = info->first_index;
  second_index_old = info->second_index;
  num_sector_old = info->num_sector;
  length_old = info->length;
  table = info->table_sector;
  
  /* Check the number of sectors needed. */
  num_sector = num_sector_new - num_sector_old;
  
  /* Mutex. */
  lock_acquire (&inode_mutex);
  
  /* Check if there's enough free sectors. */
  if (num_sector > free_map_count ())
  {
    lock_release (&inode_mutex);
    return -1;
  }
  
  /* Get the next index of the index tables. */
  next_indices (first_index_old, second_index_old, &first_index, &second_index);
  
  /* Get the final index of the index tables. */
  first_index_new = (num_sector_new - 1) / 128;
  second_index_new = (num_sector_new - 1) % 128;
  
  /* Now allocate, and save the sectors for tables, and data. */
  while (first_index <= first_index_new)
  {
    struct idx_table *first_table, *second_table;
    static char zeros[BLOCK_SECTOR_SIZE];
    
    first_table = cache_read (table, 0, 0, NULL, FETCH);
    
    /* If the first index not equals to old first index,
       allocate a second indirect index table,
       fetch the first indirect index table, and modify it. */
    if (first_index == first_index_old)
    {
      second_table = cache_read (first_table->table[first_index], 0, 0, NULL, FETCH);
    }
    else
    {
      free_map_allocate (1, &first_table->table[first_index]);
      cache_set_dirty (table);
      second_table = calloc (1, sizeof (struct idx_table));
      if (second_table == NULL)
      {
        lock_release (&inode_mutex);
        return -1;
      }
    }
    
    /* Now allocate the data sector,
       modify second indirect index table and save. */
    while (second_index < 128)
    {
      if (first_index == first_index_new && second_index > second_index_new)
        break;
      
      free_map_allocate (1, &second_table->table[second_index]);
      block_write (fs_device, second_table->table[second_index], zeros);
      
      /* Advance. */
      second_index++;
    }
    
    first_table = cache_read (table, 0, 0, NULL, FETCH);
    
    /* Save the second indirect index table. */
    if (first_index == first_index_old)
    {
      /* Set the dirty boolean of the entry for the second indirect index table. */
      cache_set_dirty (first_table->table[first_index]);
    }
    else
    {
      block_write (fs_device, first_table->table[first_index], second_table);
      free (second_table);
    }
    
    /* Advance. */
    if (second_index == 128)
      second_index = 0;
    first_index++;
  }
  
  /* Save the first indirect index table. */
  cache_set_dirty (table);
  
  /* Calculate the result length.
     Do not consider the length about the last sector,
     because it will be considered at inode_write_at. */
  off_t length_new;
  off_t length_ofs = length_old % BLOCK_SECTOR_SIZE;
  if (length_ofs == 0)
  {
    length_new = length_old + (num_sector - 1) * BLOCK_SECTOR_SIZE;
  }
  else
  {
    length_new = length_old - length_ofs + (num_sector * BLOCK_SECTOR_SIZE);
  }
  
  /* Update the sector disk. */
  info = cache_read (inode->sector, 0, 0, NULL, FETCH);
  info->length = length_new;
  info->first_index = first_index_new;
  info->second_index = second_index_new;
  info->num_sector = num_sector_new;
  cache_set_dirty (inode->sector);
  
  lock_release (&inode_mutex);
  
  /* Return the sector for the data. */
  return get_data_sector (inode, first_index_new, second_index_new);
}

/* Release free map for given sectors.
   This function can be called for releasing of
   sectors for a inode which is a removal. */
static void
free_map_release_inode (struct inode *inode)
{
  struct sector_disk *info;
  struct idx_table *first_table, *second_table;
  size_t first_idx = 0;
  
  /* Fetch the sector_disk and get table_sector. */
  info = cache_read (inode->sector, 0, 0, NULL, FETCH);
  block_sector_t table = info->table_sector;
  
  /* Get the index boundaries. */
  size_t first_bound = num_second_table (inode);
  size_t second_bound = num_data_sector (inode);
  
  /* Iterate the first indirect index table. */
  while (first_idx < first_bound)
  {
    /* Fetch the first indirect index table, and get the sector number
       for the second indirect index table. */
    first_table = cache_read (table, 0, 0, NULL, FETCH);
    block_sector_t table_sector = first_table->table[first_idx];
    
    /* Iterate the second indirect index table. */
    size_t second_idx = 0;
    while (second_idx < 128)
    {
      /* This is the end of the data sectors. */
      if (first_idx == first_bound - 1 && second_idx == second_bound - 1)
        break;
      
      /* Fetch the second indirect index table, and get the sector number
         for the data sector. */
      second_table = cache_read (table_sector, 0, 0, NULL, FETCH);
      block_sector_t data_sector = second_table->table[second_idx];
      
      /* If this sector is in buffer cache, evict and flush. */
      cache_inode_close (data_sector);
      
      /* Release the sector for the data. */
      free_map_release (data_sector, 1);
      
      /* Advance. */
      second_idx++;
    }
    
    /* If the sector is in buffer cache, evict and flush. */
    cache_inode_close (table_sector);
    
    /* Release the sector for the second indirect index table. */
    free_map_release (table_sector, 1);
    
    /* Advance. */
    first_idx++;
  }
  
  /* If the sector is in buffer cache, evict and flush. */
  cache_inode_close (table);
  
  /* Release the sector for the first indirect index table. */
  free_map_release (table, 1);
  
  /* If the sector is in buffer cache, evict and flush. */
  cache_inode_close (inode->sector);
  
  /* Finally, release the sector_disk. */
  free_map_release (inode->sector, 1);
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void
inode_init (void) 
{
  list_init (&open_inodes);
  lock_init (&inode_mutex);
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool
inode_create (block_sector_t sector, off_t length)
{
  lock_acquire (&inode_mutex);
  
  /* Calculate the number of sectors needed for the length. */
  size_t num_sector = bytes_to_sectors (length);

  /* Calculate the number of second indirect index table needed
     for the number of sectors. */
  size_t num_table = num_sector / 128 + 1;
  
  /* Check if there're enough free sectors for
     first/second indirect index table, and data. */
  if (num_sector + num_table + 1 > free_map_count ())
  {
    lock_release (&inode_mutex);
    return false;
  }
  struct sector_disk *info = NULL;
  struct idx_table *first_table = NULL;

  ASSERT (length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT (sizeof (struct idx_table) == BLOCK_SECTOR_SIZE);
  ASSERT (sizeof (struct sector_disk) == BLOCK_SECTOR_SIZE);
  
  /* Allocate the sector disk, and allocate sector for the
     first indirect index table. */
  info = calloc (1, sizeof (struct sector_disk));
  if (info == NULL)
  {
    lock_release (&inode_mutex);
    return false;
  }
  free_map_allocate (1, &info->table_sector);
  
  /* Allocate the first indirect index table. */
  first_table = calloc (1, sizeof (struct idx_table));
  if (first_table == NULL)
  {
    lock_release (&inode_mutex);
    return false;
  }
  
  /* Allocate the second indirect index tables,
     and save the sector numbers in the first indirect index table.
     And then, allocate the real data sectors, and save the sector
     number in the second indirect index table.
     At the end of the first and second indirect index table,
     save -1 to indicate the end. */
  block_sector_t table_idx = 0;
  
  while (table_idx < num_table)
  {
    /* If the length is 0, do not allocate the second indirect index table. */
    if (length == 0)
      break;
    
    /* First allocate the sector. */
    free_map_allocate (1, &first_table->table[table_idx]);
    
    /* Allocate the second indirect index table. */
    struct idx_table *second_table = calloc (1, sizeof (struct idx_table));
    
    if (second_table == NULL)
    {
      lock_release (&inode_mutex);
      return false;
    }
    
    /* Allocate the sectors for the real data,
       and save the sector numbers in the second indirect index table. */
    block_sector_t sector_idx = table_idx * 128;
    block_sector_t sector_next_idx = sector_idx + 128;
    static char zeros[BLOCK_SECTOR_SIZE];
    
    while (sector_idx < num_sector && sector_idx < sector_next_idx)
    {
      block_sector_t idx = sector_idx % 128;
      
      /* Allocate the sector for real data. */
      free_map_allocate (1, &second_table->table[idx]);
      
      /* Fill the data sector with zeros. */
      block_write (fs_device, second_table->table[idx], zeros);
      
      /* Advance. */
      sector_idx++;
    }
    
    /* Save one second indirect index table sector.
       And free the allocated memory for the second table. */
    block_write (fs_device, first_table->table[table_idx], second_table);
    free (second_table);
    
    /* Advance. */
    table_idx++;
  }
  
  /* Save the first indirect index table sector.
     And free the allocated memory for the first table. */
  block_write (fs_device, info->table_sector, first_table);
  free (first_table);
  
  /* Save the sector_disk sector.
     And free the allocated memory for the sector_disk. */
  info->length = length;
  info->num_sector = num_sector;
  if (num_sector == 0)
  {
    info->first_index = -1;
    info->second_index = -1;
  }
  else
  {
    info->first_index = (num_sector - 1) / 128;
    info->second_index = (num_sector - 1) % 128;
  }
  block_write (fs_device, sector, info);
  free (info);
  
  lock_release (&inode_mutex);
  
  return true;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (block_sector_t sector)
{
  struct list_elem *e;
  struct inode *inode;

  /* Check whether this inode is already open. */
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e)) 
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector) 
        {
          inode_reopen (inode);
          return inode; 
        }
    }

  /* Allocate memory. */
  inode = malloc (sizeof (struct inode));
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front (&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  
  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t
inode_get_inumber (const struct inode *inode)
{
  return inode->sector;
}

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode) 
{
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0)
  {
    /* Remove from inode list and release lock. */
    list_remove (&inode->elem);
     
    /* Deallocate blocks, evict and flush the cache entry if removed. */
    if (inode->removed) 
    {
      free_map_release_inode (inode); 
    }
    
    free (inode); 
  }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode) 
{
  ASSERT (inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset) 
{
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;
  uint8_t *bounce = NULL;
  
  while (size > 0) 
  {
    /* Calculate the index of sector within the inode. */
    block_sector_t sector_idx = byte_to_sector (inode, offset);
    
    /* Get the actual sector number for the given offset. */
    block_sector_t first_idx = sector_idx / 128;
    block_sector_t second_idx = sector_idx % 128;
    block_sector_t sector = get_data_sector (inode, first_idx, second_idx);
    
    if (sector == -1)
      break;
    
    int sector_ofs = offset % BLOCK_SECTOR_SIZE;
    
    /* Bytes left in inode, bytes left in sector, lesser of the two. */
    off_t inode_left = inode_length (inode) - offset;
    int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
    int min_left = inode_left < sector_left ? inode_left : sector_left;
    
    /* Number of bytes to actually copy out of this sector. */
    int chunk_size = size < min_left ? size : min_left;
    if (chunk_size <= 0)
      break;
    
    /* Fetch the sector in buffer cache if needed, and read the content
       from buffer cache to the buffer. */
    cache_read (sector, sector_ofs, chunk_size, buffer + bytes_read, READ);
    
    /* Advance. */
    size -= chunk_size;
    offset += chunk_size;
    bytes_read += chunk_size;
  }
  
  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset) 
{
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;
  uint8_t *bounce = NULL;

  if (inode->deny_write_cnt)
    return 0;

  while (size > 0) 
  {
    /* The boolean extend determines if update of file length is necessary. */
    bool extend = false;
    
    /* Calculate the index of sector within the inode. */
    block_sector_t sector_idx = byte_to_sector (inode, offset);
    
    /* The offset within the sector. */
    int sector_ofs = offset % BLOCK_SECTOR_SIZE;
    
    /* Bytes left in inode, bytes left in sector, lesser of the two. */
    int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
    
    /* Number of bytes to actually write into this sector. */
    int chunk_size = size < sector_left ? size : sector_left;
    if (chunk_size <= 0)
      break;
    
    /* Get the actual sector number for the given offset. */
    block_sector_t first_idx = sector_idx / 128;
    block_sector_t second_idx = sector_idx % 128;
    
    /* Get the sector number for the data. */
    block_sector_t sector = get_data_sector (inode, first_idx, second_idx);
    
    /* If file extension is needed, extend.
       Calculate the additional length.
       Note that the extend_inode updates the length if the distance between
       sector with given offset and current sector boundary is more than
       one block. */
    if (sector == -1)
    {
      sector = extend_inode (inode, sector_idx + 1);
      if (sector == -1)
        break;
      extend = true;
    }
    
    struct sector_disk *info = cache_read (inode->sector, 0, 0, NULL, FETCH);
    off_t length_old = info->length;
    off_t additional_len;
    
    /* EXTENSION.
       If given offset is larger than current length,
       the difference should be added to length. */
    if (offset > length_old)
    {
      additional_len = chunk_size;
      additional_len += offset - length_old;
      extend = true;
    }
    /* EXTENSION.
       If given offset is smaller than current length,
       and the end of extension is larger than or equals to current length,
       additional length is smaller than the chunk size. */
    else if (offset < length_old && offset + chunk_size - 1 >= length_old)
    {
      additional_len = chunk_size;
      additional_len -= length_old - offset;
      extend = true;
    }
    /* EXTENSION.
       If given offset equals to current length,
       additional length is the chunk size. */
    else if (offset == length_old)
    {
      additional_len = chunk_size;
      extend = true;
    }
    /* NO EXTENSION.
       If given offset is smaller than current length + 1,
       and the end of written chunk is smaller or equal than
       the current length, there's no additional length. */
    else
    {
      ;
    } 
    
    /* Fetch the sector into the buffer cache,
       and modify the content of the cache. */
    cache_modify (sector, sector_ofs, chunk_size, buffer + bytes_written, extend);
    
    /* Update the file length if it's extended. */
    if (extend)
    {
      struct sector_disk *info = cache_read (inode->sector, 0, 0, NULL, FETCH);
      info->length += additional_len;
      cache_set_dirty (inode->sector);
    }
    
    /* Advance. */
    size -= chunk_size;
    offset += chunk_size;
    bytes_written += chunk_size;
  }
  
  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode) 
{
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode) 
{
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode)
{
  struct sector_disk *info;
  info = cache_read (inode->sector, 0, 0, NULL, FETCH);
  
  return info->length;
}
