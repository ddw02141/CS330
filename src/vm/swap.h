#include "lib/kernel/hash.h"
#include "lib/kernel/bitmap.h"
#include "threads/synch.h"
#include "devices/block.h"

/* A swap table which records the information about swap disk.
   A pair of user page address and swap_bitmap index will be recorded. */
struct hash swap_table;

/* A swap bitmap which records the uses of swap disk.
   The bitmap index represents the starting sector number of swap disk.
   One page need 8 sectors in swap disk. */
struct bitmap *swap_bitmap;

/* A swap disk. */
struct block *swap_disk;

/* The format of swap table entry. */
struct swap_table_entry
{
  struct hash_elem hash_elem;
  void *pd;
  void *upage;
  size_t bitmap_idx;
};

/* A lock used to synchronize accesses to the swap table. */
struct lock swap_table_lock;

/* A lock used to synchronize accesses to the swap bitmap. */
struct lock swap_bitmap_lock;

/* A lock used to synchronize accesses to the swap disk. */
struct lock swap_disk_lock;

/* Function prototypes. */
void swap_init (void);
bool swap_out (uint32_t *pd, void *upage, void *kpage);
bool swap_in (uint32_t *pd, void *upage, void *kpage);
void swap_free (uint32_t *pd, void *upage);
void swap_disk_read (size_t idx, void *kpage);
void swap_disk_write (size_t idx, void *kpage);
struct swap_table_entry *swap_table_entry_lookup (uint32_t *pd, void *upage);
unsigned swap_hash_func (const struct hash_elem *elem, void *aux);
bool swap_less_func (const struct hash_elem *a, const struct hash_elem *b, void *aux);
