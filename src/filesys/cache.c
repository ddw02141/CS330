#include <stdio.h>
#include "lib/kernel/bitmap.h"
#include "lib/kernel/hash.h"
#include "threads/synch.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "filesys/cache.h"

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
      entry->cache = page + 512 * j;
      entry->dirty = false;
      entry->accessed = false;
      lock_init (&entry->cache_entry_lock);
      
      /* Insert the entry into the cache table. */
      lock_acquire (&cache_table_lock);
      hash_insert (&cache_table, &entry->hash_elem);
      lock_release (&cache_table_lock);
      
      /* Advance. */
      bitmap_idx ++;
    }
  }
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
    return entry;
  }
  /* There's no empty entry in buffer cache. Need an eviction. */
  else
  {
    /* Find a victim block in buffer cache.
       ## A Mutex is needed. ## */
    lock_acquire (&cache_table_lock);
    struct cache_table_entry *entry = cache_find_victim ();
    lock_release (&cache_table_lock);
    
    /* If the block in cache is dirty, write its content back to the disk. */
    //////////////////
    
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
    if (entry->accessed == false)
      return entry;
    else
      entry->accessed = false;
  }
  
  /* The second iteration.
     The finding should succeed in this iteration. */
  hash_first (&i, &cache_table);
  while (hash_next (&i))
  {
    struct cache_table_entry *entry = hash_entry (hash_cur (&i), struct cache_table_entry, hash_elem);
    if (entry->accessed == false)
      return entry;
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
cache_table_entry_lookup (struct file *file)
{
  /* The syscall handler checks if the file is opened. */
  struct hash_iterator i;
  
  lock_acquire (&cache_table_lock);
  hash_first (&i, &cache_table);
  while (hash_next (&i))
  {
    struct cache_table_entry *entry = hash_entry (hash_cur (&i), struct cache_table_entry, hash_elem);
    if (entry->file == file)
    {
      lock_release (&cache_table_lock);
      return entry;
    }
  }
  lock_release (&cache_table_lock);
  return NULL;
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
