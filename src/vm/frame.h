#include "lib/kernel/hash.h"
#include "threads/synch.h"

/* A frame table containing currently being used frames by user pages. */
struct hash frame_table;

/* The format of a frame table entry. */
struct frame_entry
{
  struct hash_elem hash_elem;
  void *frame_addr;	// The frame address.
  void *page_addr;	// The page address.
};

/* A lock used to synchronize accesses to the frame table. */
struct lock frame_table_lock;

/* Function prototypes. */
void frame_new_usage (void *upage, uint32_t pte);
unsigned frame_hash_func (const struct hash_elem *elem, void *aux);
bool frame_less_func (const struct hash_elem *a, const struct hash_elem *b, void *aux);
