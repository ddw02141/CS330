#include <stdio.h>
#include "lib/kernel/bitmap.h"
#include "lib/kernel/hash.h"
#include "lib/string.h"
#include "devices/block.h"
#include "devices/timer.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "filesys/cache.h"
#include "filesys/file.h"
#include "filesys/inode.h"
#include "filesys/filesys.h"
#include "filesys/free-map.h"

//static void *disk_free_map;

/* A bitmap which tracks the uses of the cache entries. */
static struct bitmap *cache_bitmap;

/* Load free map in disk into the memory.
   Allocate pages for cache. */
void
cache_init (void)
{
  /* The buffer cache covers up to 64 disk sectors.
     This bitmap tracks the uses of the cache entries. */
  cache_bitmap = bitmap_create (64);
  size_t bitmap_idx = 0;
  
  /* Allocate the pages for cache.
     8 pages are needed for 64 disk sectors. */
  for (int i = 0; i < 8; i++)
  {
    void *page = palloc_get_page (0);
    if (page == NULL)
    {
      printf ("Fail: palloc in cache_init\n");
      return;
    }
    
    /* A single page is divided into 8 cache entries for 8 disk sectors. */
    for (int j = 0; j < 8; j++)
    {
      /* Allocate the cache table entry. */
      struct cache_table_entry *entry = malloc (sizeof (struct cache_table_entry));
      entry->idx = bitmap_idx;
      entry->sector = -1;
      entry->cache = page + 512 * j;
      entry->dirty = false;
      entry->accessed = false;
      lock_init (&entry->cache_entry_lock);
      entry->cnt = 0;
      lock_init (&entry->cnt_lock);
      sema_init (&entry->cache_evict_sema, 1);
      entry->call_read_aheader = false;
      
      /* Insert the entry into the cache table. */
      lock_acquire (&cache_table_lock);
      hash_insert (&cache_table, &entry->hash_elem);
      lock_release (&cache_table_lock);
      
      /* Advance. */
      bitmap_idx ++;
    }
  }
  
  /* Start the flusher thread. */
  thread_create ("flusher", PRI_DEFAULT, flusher_function, NULL);
}

/* Read content of a file into the buffer cache.
   First, check if given file sector is already fetched in buffer cache.
   If it is, read the content from buffer cache, not from disk,
   and it not, fetch the sector into the buffer cache. */
void
cache_read (block_sector_t sector, int sector_ofs, int chunk_size, uint8_t *buffer, enum cache_mode mode)
{
  /* Finding the entry should be wrapped by Mutex.
     If not, entry can be evicted after the lookup succeeds. */
  lock_acquire (&cache_mutex);
  
  /* Check if given file sector is already fetched in buffer cache. */
  struct cache_table_entry *entry = cache_table_entry_lookup (sector);
  
  /* If given file sector is not in buffer cache, get one entry. */
  if (entry == NULL)
  { 
    /* Get a cache entry. */
    entry = get_cache_entry ();
    
    if (mode != FETCH)
    {
      /* The entry should have cnt 0. */
      lock_acquire (&entry->cnt_lock);
    
      /* This semaphore prevents the eviction or close of this entry
         during read or modify procedure.
         This semaphore is downed by only the first reader or modifier. */ 
      sema_down (&entry->cache_evict_sema);
      
      entry->cnt++;
      lock_release (&entry->cnt_lock);
    }
    
    /* Update the cache table entry. */
    entry->sector = sector;
    entry->sector_ofs = sector_ofs;
    entry->chunk_size = chunk_size;
    entry->accessed = true;		// Prevent imediate eviction.
      
    /* Fetch the file sector into the buffer cache. */
    block_read (fs_device, sector, entry->cache);
  }
  else
  {
    /* If there's no reader/modifier or writer, down the semaphore. */
    lock_acquire (&entry->cnt_lock);
    if (entry->cnt <= 0)
      sema_down (&entry->cache_evict_sema);
    entry->cnt++;
    lock_release (&entry->cnt_lock);
    
    /* Update the entry. */
    entry->accessed = true;
  }
  
  lock_release (&cache_mutex);
  
  /* If this function is called by file_write (i.e. by cache_modify),
     or read aheader, because they want no read but just the fetching,
     do not read the content into the buffer and just return.
     They call this function just to make sure that the entry is in cache. */
  if (mode != READ)
    return;
  
  /* Read the full sector. */
  if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
  {
    memcpy (buffer, entry->cache, BLOCK_SECTOR_SIZE);
  }
  /* Read a part of sector, not the full sector. */
  else
  {
    memcpy (buffer, entry->cache + sector_ofs, chunk_size);
  }
  
  /* If this is the last reader/modifier, up the semaphore.
     Update the cnt. */
  lock_acquire (&entry->cnt_lock);
  if (entry->cnt == 1)
    sema_up (&entry->cache_evict_sema);
  entry->cnt--;
  lock_release (&entry->cnt_lock);
}

/* Write content of the cache into the file if the dirty boolean is set.
   This function should be called periodically. */
void
cache_write (struct cache_table_entry *entry)
{
  /* If the dirty boolean is set,
     write the contents of the cache back into the sector. */
  if (entry->dirty && sema_try_down (&entry->cache_evict_sema))
  {
    //sema_down (&entry->cache_evict_sema);
    block_write (fs_device, entry->sector, entry->cache);
    lock_acquire (&cache_table_lock);
    entry->dirty = false;
    lock_release (&cache_table_lock);
    sema_up (&entry->cache_evict_sema);
  }
}

/* Modify the content of the file.
   This function does not change the content of the disk directly,
   but change the content of the buffer cache entry.
   When cache_write is called, the content of the buffer cache is written to
   the disk. */
void
cache_modify (block_sector_t sector, int sector_ofs, int chunk_size, const uint8_t *buffer)
{
  /* If the file sector is not in the buffer cache, fetch it.
     In cache_read, if this is the first modifier, semaphore is downed.
     The cnt is also increased. */
  cache_read (sector, 0, 0, NULL, MODIFY);
  struct cache_table_entry *entry = cache_table_entry_lookup (sector);
  
  entry->accessed = true;
  entry->dirty = true;
  
  /* Write the full sector to the buffer cache entry. */
  if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
  {
    memcpy (entry->cache, buffer, BLOCK_SECTOR_SIZE);
  }
  /* Write a part of the sector, not the full sector. */
  else
  {
    memcpy (entry->cache + sector_ofs, buffer, chunk_size);
  }
  
  /* If this is the last reader/modifier, up the semaphore.
     Update the cnt. */
  lock_acquire (&entry->cnt_lock);
  if (entry->cnt == 1)
    sema_up (&entry->cache_evict_sema);
  entry->cnt--;
  lock_release (&entry->cnt_lock);
}

/* Write back all cache entries related to given inode to their sectors,
   and update the cache table entries and bitmap.
   
   ## This function should be synchronized with get_cache_entry,
      especially, with the eviction routine. */
void
cache_inode_close (block_sector_t start, block_sector_t end)
{
  lock_acquire (&cache_mutex);
  
  block_sector_t sector = start;
  while (sector <= end)
  {
    struct cache_table_entry *entry = cache_table_entry_lookup (sector);
    
    if (entry == NULL)
    {
      sector++;
      continue;
    }
    
    /* Write back. */
    cache_write (entry);
    
    /* Update the cache table entry. */
    lock_acquire (&cache_table_lock);
    entry->sector = -1;
    entry->dirty = false;
    entry->accessed = false;
    lock_release (&cache_table_lock);
    
    /* Update the cache bitmap. */
    lock_acquire (&cache_bitmap_lock);
    bitmap_flip (cache_bitmap, entry->idx);
    lock_release (&cache_bitmap_lock);
    
    /* Advance. */
    sector++;
  }
  
  lock_release (&cache_mutex);
}

/* Flush contetns of all dirty cache entries into the disk sectors.
   This funciton should be called
   when the Pintos is halted, thus when filesys_done is called,
   and periodically because the write behind makes file system more fragile. */
void
cache_flush (void)
{
  lock_acquire (&cache_mutex);
  
  struct hash_iterator i;
  
  hash_first (&i, &cache_table);
  while (hash_next (&i))
  {
    struct cache_table_entry *entry = hash_entry (hash_cur (&i), struct cache_table_entry, hash_elem);
    cache_write (entry);
  }
  
  lock_release (&cache_mutex);
}

/* Check if there's an empty entry in buffer cache.
   If there is, return a pointer to the cache table entry,
   and if not, evict one, and return a pointer to the cache table entry. */
struct cache_table_entry *
get_cache_entry (void)
{
  /* First, check if there's an empty entry in buffer cache. */
  lock_acquire (&cache_bitmap_lock);
  size_t bitmap_idx = bitmap_scan_and_flip (cache_bitmap, 0, 1, false);
  lock_release (&cache_bitmap_lock);
  
  /* There's an empty entry in buffer cache. */
  if (bitmap_idx != BITMAP_ERROR)
  {
    /* Get a cache table entry for the buffer cache entry. */
    struct hash_elem *e;
    struct cache_table_entry c;
    
    c.idx = bitmap_idx;
    
    lock_acquire (&cache_table_lock);
    e = hash_find (&cache_table, &c.hash_elem);
    lock_release (&cache_table_lock);
    
    if (e == NULL)
      printf ("Fatal: hash_find failed with bitmap idx.\n");
    
    struct cache_table_entry *entry = hash_entry (e, struct cache_table_entry, hash_elem);
    entry->accessed = true;
    return entry;
  }
  /* There's no empty entry in buffer cache. Need an eviction. */
  else
  {
    /* Find a victim block in buffer cache. */
    lock_acquire (&cache_table_lock);
    struct cache_table_entry *entry = cache_find_victim ();
    lock_release (&cache_table_lock);
    
    /* If the block in cache is dirty, write its content back to the disk. */
    cache_write (entry);
    
    /* Return the buffer cache entry. */
    return entry;
  }
}

/* Find a victim block in cache, using second chance algorithm
   which is an approximation of the LRU algorithm.
   The finding should succeed at least in the second iteration.
   
   ## Be careful: This function needs an outer lock. ##
*/
struct cache_table_entry *
cache_find_victim (void)
{
  struct hash_iterator i;
  
  /* The first iteration. */
  hash_first (&i, &cache_table);
  while (hash_next (&i))
  {
    struct cache_table_entry *entry = hash_entry (hash_cur (&i), struct cache_table_entry, hash_elem);
    if (entry->accessed == false && entry->cnt == 0)
    {
      entry->accessed = true;
      return entry;
    }
    else
      entry->accessed = false;
  }
  
  /* The second iteration.
     The finding should succeed in this iteration. */
  hash_first (&i, &cache_table);
  while (hash_next (&i))
  {
    struct cache_table_entry *entry = hash_entry (hash_cur (&i), struct cache_table_entry, hash_elem);
    if (entry->accessed == false && entry->cnt == 0)
    {
      entry->accessed = true;
      return entry;
    }
    else
      entry->accessed = false;
  }
  
  /* Control cannot reach here. */
  printf ("Fatal: cache_find_victim failed.\n");
  return NULL;
}

/* Check if given file is already fetched in buffer.
   If it is, return a pointer to the entry,
   and if not, return NULL. */
struct cache_table_entry *
cache_table_entry_lookup (block_sector_t sector)
{
  /* Iterate the cache table and find the entry with given inode and sector number. */
  struct hash_iterator i;
  
  lock_acquire (&cache_table_lock);
  hash_first (&i, &cache_table);
  while (hash_next (&i))
  {
    struct cache_table_entry *entry = hash_entry (hash_cur (&i), struct cache_table_entry, hash_elem);
    if (entry->sector == sector)
    {
      entry->accessed = true;
      lock_release (&cache_table_lock);
      return entry;
    }
  }
  lock_release (&cache_table_lock);
  return NULL;
}

/* The thread function of the flusher thread.
   The flusher thread periodically flushes out the cache,
   and sleeps.
   This function needs no argument. */
void
flusher_function (void *aux UNUSED)
{
  while (true)
  {
    timer_sleep (1000);
    cache_flush ();
  }
}

/* The thread function of the read aheader thread.
   The read aheader thread calls cache_read for the given disk sector.
   This function needs an argument which is a sector number. */
void
read_aheader_function (void *aux)
{
  block_sector_t sector = *(block_sector_t *) aux;
  cache_read (sector, 0, 0, NULL, FETCH);
  free (aux);
}

/* A hash function used for cache_table.
   The bitmap index of the cache is used as a key. */
unsigned
cache_hash_func (const struct hash_elem *elem, void *aux UNUSED)
{
  const struct cache_table_entry *entry = hash_entry (elem, struct cache_table_entry, hash_elem);
  return hash_int (entry->idx);
}

/* Return true if address of the cache of entry 'a' is larger than of 'b'. */
bool
cache_less_func (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
  const struct cache_table_entry *entry_a = hash_entry (a, struct cache_table_entry, hash_elem);
  const struct cache_table_entry *entry_b = hash_entry (b, struct cache_table_entry, hash_elem);
  return entry_a->idx < entry_b->idx;
}
