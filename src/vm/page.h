#include "lib/kernel/hash.h"
#include "lib/kernel/list.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "filesys/off_t.h"
#include "filesys/file.h"
#include <stdio.h>

typedef int mapid_t;

/* A supplemental page table which records mappings from user pages to frames. */
struct hash supp_page_table;

/* The mode of mapping. */
enum mapping_mode
{
  MODE_MEMORY = 1,
  MODE_LAZY = 2,
  MODE_MMAP = 4
};

/* The location of a page. */
enum mapping_position
{
  MEMORY = 1,
  SWAPDISK = 2,
  LAZY = 4,
  MMAP = 8
};

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
  
  /* Used for lazy loading or Mmap. */
  enum mapping_mode initial_mode;
  enum mapping_position position;
  bool zero;
  struct file *file;
  off_t ofs;
  off_t ofs_eof;	// offset from ofs, not from begining of file.
};

/* The format of a upage list entry.
   The upage list of a thread is useful when the thread terminates,
   which requires frees in supp_page_table, frame_table, or disk. */
struct upage_list_entry
{
  struct list_elem elem;
  void *upage;
  mapid_t mapid;
};

/* A lock used to synchronize acccesses to the supplemental page table. */
struct lock supp_table_lock;

/* Function prototypes. */
void *frame_obtain (enum palloc_flags);
bool supp_new_mapping (uint32_t *pd, void *upage, void *kpage, bool writable, struct thread *t, enum palloc_flags, enum mapping_mode, bool zero, struct file *file, off_t ofs, off_t ofs_eof, mapid_t mapid);
void supp_free_all (uint32_t *pd, struct thread *t);
void supp_free_mapping (uint32_t *pd, void *upage);
bool restore_page (uint32_t *pd, void *uaddr);
bool supp_new_mmap (uint32_t *pd, void *upage, struct thread *t, struct file *file, mapid_t mapid);
void supp_unmmap (uint32_t *pd, void *upage);
bool write_back (struct supp_table_entry *entry);
bool lazy_load_all_zero (uint32_t *pd, void *upage, void *kpage, bool writable, struct thread *t );
bool lazy_load_read (uint32_t *pd, void *upage, void *kpage, bool writable, struct thread *t, struct file *file, off_t ofs);
bool lazy_mmap (uint32_t *pd, void *upage, void *kpage, struct thread *t, struct file *file, off_t ofs, bool zero);
struct supp_table_entry *supp_table_entry_lookup (uint32_t *pd, void *upage);
unsigned supp_hash_func (const struct hash_elem *elem, void *aux);
bool supp_less_func (const struct hash_elem *a, const struct hash_elem *b, void *aux);
