#include "lib/kernel/hash.h"
#include "lib/kernel/list.h"
#include "threads/synch.h"

/* A supplemental page table which records mappings from user pages to frames. */
struct hash supp_page_table;

/* The format of a supplemental page table entry.
   Supplemental page table should have enough information
   to call functions in pagedir.c, because supplemental page table
   exploits pagedir functions.*/
struct supp_table_entry
{
  struct hash_elem hash_elem;
  uint32_t *pd;
  void *frame_addr;
  void *page_addr;
  bool valid;	// 1 if in memory, 0 if in swap disk.
};

/* The format of mapping list entry.
   A mapping list is used for tracking all the mapping information
   related with a thread.
   Especially, a mapping list is useful when the supplemental page
   and the frame table should be updated with respect to a
   pagedir_destroy. */
struct mapping_list_entry
{
  struct list_elem elem;
  void *page_addr;
  uint32_t *pte;
};

/* A lock used to synchronize acccess to the supplemental page table. */
struct lock supp_table_lock;

/* Function prototypes. */
bool supp_new_mapping (uint32_t *pd, void *upage, void *kpage, bool writable, struct thread *t);
void supp_free_all (uint32_t *pd, struct thread *t);
void supp_free_mapping (void *upage);
struct supp_table_entry *supp_table_entry_lookup (void *upage);
unsigned supp_hash_func (const struct hash_elem *elem, void *aux);
bool supp_less_func (const struct hash_elem *a, const struct hash_elem *b, void *aux);
