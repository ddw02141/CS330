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
   in the given first indirect index table.
   This function scans and find -1 in the first table. */
static block_sector_t
first_table_to_num_second_table (struct idx_table *first_table)
{
  for (size_t i = 0; i < 128; i++)
  {
    if (first_table->table[i] == -1)
      return i;
  }
  return 128;
}

/* Return the number of data sector table stored
   in the given second indirect index table.
   The given second indirect index table would be
   returned from first_table_to_num_second_table. */
static block_sector_t
second_table_to_num_sector (struct idx_table *second_table)
{
  for (size_t i = 0; i < 128; i++)
  {
    if (second_table->table[i] == -1)
      return i;
  }
  return 128;
}

/* Get the sector number for real data,
   with given first index and second index. */
static block_sector_t
get_data_sector (struct inode *inode, size_t first_index, size_t second_index)
{
  struct sector_disk *info;
  struct idx_table *first_table, *second_table;
  block_sector_t second_table_sector, data_sector;
  
  /* Fetch the sector_disk, and get the sector number for
     the first indirect index table. */
  info = cache_read (inode->sector, 0, 0, NULL, FETCH);
  block_sector_t table_sector = info->table_sector;
  
  /* Fetch the first indirect table,
     get the sector number for the first_index,
     and check if the first_index exceeds the boundary. */
  first_table = cache_read(table_sector, 0, 0, NULL, FETCH);
  second_table_sector = first_table->table[first_index];
  if (first_index >= first_table_to_num_second_table (first_table))
    return -1;
  
  /* Fetch the second indirect table,
     get the sector number for the second_index,
     and check if the second_index exceeds the boundary. */
  second_table = cache_read(first_table->table[first_index], 0, 0, NULL, FETCH);
  data_sector = second_table->table[second_index];
  if (second_index >= second_table_to_num_sector (second_table))
    return -1;
  
  return data_sector;
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
  
  /* Iterate the first indirect index table. */
  while (first_idx < 128)
  {
    first_table = cache_read (table, 0, 0, NULL, FETCH);
    block_sector_t table_sector = first_table->table[first_idx];
    
    if (table_sector == -1)
      break;
    
    /* Iterate the second indirect index table. */
    size_t second_idx = 0;
    while (second_idx < 128)
    {
      second_table = cache_read (table_sector, 0, 0, NULL, FETCH);
      block_sector_t data_sector = second_table->table[second_idx];
      
      if (data_sector == -1)
        break;
      
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
    
    /* If the number of sectors for real data is not a multiple of 128,
       save -1 to indicate the end. */
    if (sector_idx % 128 != 0)
    {
      second_table->table[sector_idx % 128] = -1;
    }
    
    /* Save one second indirect index table sector.
       And free the allocated memory for the second table. */
    block_write (fs_device, first_table->table[table_idx], second_table);
    free (second_table);
    
    /* Advance. */
    table_idx++;
  }
  
  /* If the number of sectors for second indirect index table is not
     a multiple of 128, save -1 to indicate the end. */
  if (table_idx != 128)
  {
    first_table->table[table_idx] = -1;
  }
  
  /* Save the first indirect index table sector.
     And free the allocated memory for the first table. */
  block_write (fs_device, info->table_sector, first_table);
  free (first_table);
  
  /* Save the sector_disk sector.
     And free the allocated memory for the first table. */
  info->length = length;
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
  
  /* Fetch and read the first indirect index table in the buffer cache,
     calculate the number of sectors in this inode. */
/*  struct sector_disk *info;
  struct idx_table *first_table, *second_table;
  info = cache_read (inode->sector, 0, 0, NULL, FETCH);
  first_table = cache_read (info->table_sector, 0, 0, NULL, FETCH);
  block_sector_t last_second_table = first_table_to_num_second_table (first_table);
  second_table = cache_read (last_second_table, 0, 0, NULL, FETCH);
  inode->num_sector = second_table_to_num_sector (second_table); */
  
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
    /* Calculate the index of sector within the inode. */
    block_sector_t sector_idx = byte_to_sector (inode, offset);
    
    /* Get the actual sector number for the given offset. */
    block_sector_t first_idx = sector_idx / 128;
    block_sector_t second_idx = sector_idx % 128;
    block_sector_t sector = get_data_sector (inode, first_idx, second_idx);
    
    if (sector == -1)
    {
      break;
    }
    
    int sector_ofs = offset % BLOCK_SECTOR_SIZE;
    
    /* Bytes left in inode, bytes left in sector, lesser of the two. */
    off_t inode_left = inode_length (inode) - offset;
    int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
    int min_left = inode_left < sector_left ? inode_left : sector_left;
    
    /* Number of bytes to actually write into this sector. */
    int chunk_size = size < min_left ? size : min_left;
    if (chunk_size <= 0)
      break;
    
    /* Fetch the sector into the buffer cache,
       and modify the content of the cache. */
    cache_modify (sector, sector_ofs, chunk_size, buffer + bytes_written);
    
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
