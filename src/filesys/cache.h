#include "lib/kernel/bitmap.h"
#include "lib/kernel/hash.h"
#include "threads/synch.h"
#include "filesys/inode.h"

/* A bitmap which tracks the uses of the cache entries. */
struct hash cache_table;

/* A lock used for the cache table. */
struct lock cache_table_lock;

/* A lock used for the cache map. */
struct lock cache_bitmap_lock;

/* A mutex used for the eviction. */
struct lock cache_mutex;

/* Enum that encodes the aim of cache_read. */
enum cache_mode
{
  READ = 1,
  MODIFY = 2,
  FETCH = 4
};

/* The format of cache_table entry. */
struct cache_table_entry
{
  struct hash_elem hash_elem;
  
  /* This info does not change. */
  size_t idx;			/* cache_map index. */
  uint8_t *cache;		/* Address of the cache entry. */
  
  /* This info can change. */
  block_sector_t sector;	/* Block sector number. */
  int sector_ofs;		/* The sector offset. */
  int chunk_size;		/* The chunk size. */
  bool dirty;			/* True if the cache entry is dirty. */
  bool accessed;		/* True if the cache entry is accessed. */
  
  /* A process will acquire this lock only when it is about to extend a file. */
  struct lock cache_entry_lock;
  
  /* This cnt prevent a eviction while some reads or modifyings take place. */
  size_t cnt;			/* 0 if no use,
				   more than if any use exists,
				   -1 if in eviction procedure. */
  struct lock cnt_lock;		/* A lock for cnt. */
  
  /* This semaphore is a mutex for read/modify and flush/evict. */
  struct semaphore cache_evict_sema;
  
  /* This boolean prevents multiple read aheader. */
  bool call_read_aheader;	/* True if already called. */
};


/* Function prototypes. */
void cache_init (void);
struct cache_table_entry *get_cache_entry (void);
void *cache_read (block_sector_t sector, int sector_ofs, int chunk_size, uint8_t *buffer, enum cache_mode);
void cache_write (struct cache_table_entry *entry);
void cache_modify (block_sector_t sector, int sector_ofs, int chunk_size, const uint8_t *buffer, bool extend);
void cache_set_dirty (block_sector_t sector);
void cache_inode_close (block_sector_t sector);
void cache_flush (void);
struct cache_table_entry *cache_find_victim (void);
struct cache_table_entry *cache_table_entry_lookup (block_sector_t sector);
void flusher_function (void *aux);
void read_aheader_function (void *aux);
unsigned cache_hash_func (const struct hash_elem *elem, void *aux);
bool cache_less_func (const struct hash_elem *a, const struct hash_elem *b, void *aux);
