#include "lib/kernel/hash.h"
#include "lib/kernel/list.h"
#include "threads/palloc.h"
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
  void *upage;
  void *kpage;
  bool writable;
  struct thread *thread;
  enum palloc_flags flags;
  bool valid;	// 1 if in memory, 0 if in swap disk.
};

/* The format of a upage list entry.
   The upage list of a thread is useful when the thread terminates,
   which requires frees in supp_page_table, frame_table, or disk. */
struct upage_list_entry
{
  struct list_elem elem;
  void *upage;
};

/* A lock used to synchronize acccesses to the supplemental page table. */
struct lock supp_table_lock;

/* Function prototypes. */
void *frame_obtain (enum palloc_flags);
bool supp_new_mapping (uint32_t *pd, void *upage, void *kpage, bool writable, struct thread *t, enum palloc_flags);
void supp_free_all (uint32_t *pd, struct thread *t);
void supp_free_mapping (uint32_t *pd, void *upage);
bool restore_page (uint32_t *pd, void *uaddr);
struct supp_table_entry *supp_table_entry_lookup (uint32_t *pd, void *upage);
unsigned supp_hash_func (const struct hash_elem *elem, void *aux);
bool supp_less_func (const struct hash_elem *a, const struct hash_elem *b, void *aux);
