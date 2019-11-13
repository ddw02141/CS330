#include "lib/kernel/hash.h"
#include "lib/kernel/list.h"
#include "vm/frame.h"
#include "vm/page.h"
#include "userprog/pagedir.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/pte.h"
#include "threads/thread.h"
#include <stdio.h>

/* Implementation of Supplemental page table and related functions. */

/* Add and record the mapping from a user page to frame, which would
   exploit the function pagdir_set_page () in "pagedir.h".
   If the addition of mapping is succeed, update supplemental page table,
   and the frame table. */
bool
supp_new_mapping (uint32_t *pd, void *upage, void *kpage, bool writable, struct thread *t)
{
  /* Add a mapping from upage which is a virtual address
     to frame which is a physical address of the corresponding frame.
     If the setting is succeed, update the supplemntal page table and
     the frame table. */
  if (!pagedir_set_page (pd, upage, kpage, writable))
  {
    printf ("Allocation failed: pagedir_set_page\n");
    return false;
  }
  
  /* Get a Pintos page table entry for this mapping. */
  uint32_t *pte = lookup_page (pd, upage, false);
    
  /* Construct a supplemental page table entry. */
  struct supp_table_entry *new_mapping = malloc (sizeof (struct supp_table_entry));
  if (new_mapping == NULL)
  {
    printf ("Allocation failed: Supplemental page table entry\n");
    return false;
  }
  new_mapping->pd = pd;
  new_mapping->frame_addr = *pte & PTE_ADDR;
  new_mapping->page_addr = upage;
  new_mapping->valid = true;
  
  /* Update the supplemental page table. */
  lock_acquire (&supp_table_lock);
  hash_insert (&supp_page_table, &new_mapping->hash_elem);
  lock_release (&supp_table_lock);
  
  /* Construct a mapping list entry. */
  struct mapping_list_entry *mapping = malloc (sizeof (struct mapping_list_entry));
  mapping->page_addr = upage;
  mapping->pte = pte;
  
  /* Update the thread's mapping list. */
  lock_acquire (&t->mapping_list_lock);
  list_push_back (&t->mapping_list, &mapping->elem);
  lock_release (&t->mapping_list_lock);
  
  /* Update the frame table. */
  if (!frame_new_usage (upage, pte))
    return false;
  return true;
}

/* Free all mappings in given page directory, after update
   the supplemental page table, and the frame table. */
void
supp_free_all (uint32_t *pd, struct thread *t)
{
  struct list_elem *e = list_begin (&t->mapping_list);
  
  /* Iterate the mapping list of the given thread,
     free corresponding entries in supplemental page table,
     and entries in frame table. */
  lock_acquire (&t->mapping_list_lock);
  while (e != list_end (&t->mapping_list))
  {
    struct mapping_list_entry *mapping = list_entry (e, struct mapping_list_entry, elem);
    /* Free an entry in supplemental page table. */
    supp_free_mapping (mapping->page_addr);
    
    /* If this mapping is in physical memory, free an entry in frame table. */
    if (mapping->pte != NULL)
      frame_free (mapping->pte);
    
    /* Remove this mapping list entry in mapping list. */
    e = list_remove (e);
    
    /* Free allocated memory for mapping_list_entry. */
    free (mapping);
  }
  lock_release (&t->mapping_list_lock);
  
  /* Call pagedir_destroy () to free allocated memory
     by palloc_get_page (). */
  pagedir_destroy (pd);
}

/* Free a mapping when a corresponding page is freed.
   Unlike frame_free, which can be called when a page is swapped into the swap disk,
   supp_free_mapping should be called when a page is exactly freed. */
void
supp_free_mapping (void *upage)
{
  /* Find the supplentary page table entry. */
  lock_acquire (&supp_table_lock);
  struct supp_table_entry *target_mapping = supp_table_entry_lookup (upage);
  lock_release (&supp_table_lock);
  
  if (target_mapping == NULL)
    return;
  
  /* Delete the mapping from the supplementary page table,
     and free the allocated memory for that entry. */
  lock_acquire (&supp_table_lock);
  hash_delete (&supp_page_table, &target_mapping->hash_elem);
  lock_release (&supp_table_lock);
  free (target_mapping);
}

/* Find a supplementary table entry corresponding to given user page address. */
struct supp_table_entry *
supp_table_entry_lookup (void *upage)
{
  struct supp_table_entry mapping;
  struct hash_elem *e;
  
  mapping.page_addr = upage;
  e = hash_find (&supp_page_table, &mapping.hash_elem);
  return e != NULL ? hash_entry (e, struct supp_table_entry, hash_elem) : NULL;
}

/* A hash function used for supp_page_table.
   A virtual address of user page is used as a key. */
unsigned
supp_hash_func (const struct hash_elem *elem, void *aux UNUSED)
{
  const struct supp_table_entry *mapping = hash_entry (elem, struct supp_table_entry, hash_elem);
  return hash_bytes (&mapping->page_addr, sizeof (mapping->page_addr));
}

/* Return true if virtual address of user page of mapping 'a' is larger than of 'b'. */
bool
supp_less_func (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
  const struct supp_table_entry *mapping_a = hash_entry (a, struct supp_table_entry, hash_elem);
  const struct supp_table_entry *mapping_b = hash_entry (b, struct supp_table_entry, hash_elem);
  return mapping_a->page_addr < mapping_b->page_addr;
}
