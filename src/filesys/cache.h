#include "lib/kernel/bitmap.h"
#include "lib/kernel/hash.h"
#include "threads/synch.h"


/* A bitmap which tracks the uses of the cache entries. */
struct hash cache_table;

/* A lock used for the cache table. */
struct lock cache_table_lock;

/* A lock used for the cache map. */
struct lock cache_bitmap_lock;

/* The format of cache_table entry. */
struct cache_table_entry
{
  struct hash_elem hash_elem;
  
  /* This info does not change. */
  size_t idx;			/* cache_map index. */
  void *cache;			/* Address of the cache entry. */
  
  /* This info can change. */
  struct file *file;		/* File. */
  bool dirty;			/* True if the cache entry is dirty. */
  bool accessed;		/* True if the cache entry is accessed. */
  
  /* A process will acquire this lock only when it is about to extend a file. */
  struct lock cache_entry_lock;
};


/* Function prototypes. */
void cache_init (void);
struct cache_table_entry *get_cache_entry (void);
struct cache_table_entry *cache_find_victim (void);
struct cache_table_entry *cache_table_entry_lookup (struct file *file);
unsigned cache_hash_func (const struct hash_elem *elem, void *aux);
bool cache_less_func (const struct hash_elem *a, const struct hash_elem *b, void *aux);
