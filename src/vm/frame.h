#include "lib/kernel/hash.h"
#include "threads/palloc.h"
#include "threads/synch.h"

/* A frame table containing currently being used frames by user pages. */
struct hash frame_table;

/* The format of a frame table entry. */
struct frame_entry
{
  struct hash_elem hash_elem;
  uint32_t *pd;		// The page directory.
  void *upage;		// The user page address.
  void *kpage;		// The kernel page address.
};

/* A lock used to synchronize accesses to the frame table. */
struct lock frame_table_lock;

/* A semaphore used as mutex of page eviction. */
struct semaphore page_evict_sema;

/* Function prototypes. */
bool frame_new_usage (uint32_t *pd, void *upage, void *kpage);
void frame_free (void *kpage);
struct frame_entry *frame_entry_lookup (void *kpage);
struct frame_entry *frame_find_victim (void);
unsigned frame_hash_func (const struct hash_elem *elem, void *aux);
bool frame_less_func (const struct hash_elem *a, const struct hash_elem *b, void *aux);
