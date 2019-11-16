#include "lib/kernel/hash.h"
#include "lib/kernel/list.h"
#include "vm/frame.h"
#include "vm/page.h"
#include "vm/swap.h"
#include "userprog/pagedir.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/pte.h"
#include "threads/thread.h"
#include <stdio.h>
#include "devices/block.h"

/* Implementation of Supplemental page table and related functions. */

/* Obtain a free frame by calling palloc_get_page ()
   which should be gotten from user pool.
   Return address of allocated page if success at first try, or by do swapping,
   and return NULL if allocation failed.
   Do not call frame_new_usage yet, because the allocated page is not mapped to
   physical memory yet. */
void *
frame_obtain (enum palloc_flags flags)
{
  /* This function should be called with PAL_USER. */
  ASSERT (flags & PAL_USER);

  void *kpage = palloc_get_page (flags);
  
  /* If allocation fails, try swapping. */
  if (kpage == NULL)
  {
    /* Get a victim page which is mapped in frame. */
    struct frame_entry *victim = frame_find_victim ();
    
    /* Store the whole victim page into the swap disk. */
    if (!swap_out (victim->pd, victim->upage, victim->kpage))
    {
      printf ("Frame obtain: swap failed.\n");
      return NULL;
    }
    
    /* Update the supplemental page table. */
    struct supp_table_entry *entry = supp_table_entry_lookup (victim->pd, victim->upage);
    entry->kpage = NULL;
    entry->valid = false;
    
    /* Clear the victim page, update the frame table, and free the entry. */
    pagedir_clear_page (victim->pd, victim->upage);
    frame_free (victim->kpage);
    palloc_free_page (victim->kpage);
    
    /* Obtain frame once again. */
    void *kpage = palloc_get_page (flags);
    if (kpage == NULL)
    {
      printf ("Frame obtain: Failed.\n");
      return NULL;
    }
  }
  return kpage;
}

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
    printf ("Allocation failed: pagedir_set_page\n.");
    return false;
  }
  
  /* If this mapping is actually new mapping, it requires some more
     steps than a modifying of mapping does. */
  struct supp_table_entry *old_entry = supp_table_entry_lookup (pd, upage);
  if (old_entry == NULL)
  {
    /* Construct a supplemental page table entry. */
    struct supp_table_entry *new_entry = malloc (sizeof (struct supp_table_entry));
    if (new_entry == NULL)
    {
      printf ("Allocation failed: Supplemental page table entry\n.");
      return false;
    }
    new_entry->pd = pd;
    new_entry->upage = upage;
    new_entry->kpage = kpage;
    new_entry->writable = writable;
    new_entry->thread = t;
    new_entry->valid = true;
    
    /* Update the supplemental page table. */
    lock_acquire (&supp_table_lock);
    hash_insert (&supp_page_table, &new_entry->hash_elem);
    lock_release (&supp_table_lock);
    
    /* Construct a upage list entry. */
    struct upage_list_entry *new_upage = malloc (sizeof (struct upage_list_entry));
    new_upage->upage = upage;
    
    /* Update the upage list of the given thread. */
    lock_acquire (&t->upage_list_lock);
    list_push_back (&t->upage_list, &new_upage->elem);
    lock_release (&t->upage_list_lock);
  }
  /* If this mapping is just a modifying of mapping, just modify some entry.
     This steps is for restore_page. */
  else
  {
    old_entry->kpage = kpage;
    old_entry->valid = true;
  }
  
  /* Update the frame table, which is necessary for restore_page as well. */
  if (!frame_new_usage (pd, upage, kpage))
  {
    printf ("Fail: supp new mapping with frame new usage.\n");
    return false;
  }
  return true;
}

/* Free all mappings in given page directory, after update
   the supplemental page table, and the frame table. */
void
supp_free_all (uint32_t *pd, struct thread *t)
{
  struct list_elem *e = list_begin (&t->upage_list);
  
  /* Iterate the mapping list of the given thread,
     free corresponding entries in supplemental page table,
     and entries in frame table. */
  lock_acquire (&t->upage_list_lock);
  while (e != list_end (&t->upage_list))
  {
    struct upage_list_entry *upage_entry = list_entry (e, struct upage_list_entry, elem);
    /* Get the supplementary page table entry with given upage,
       to know where the given upage is mapped(either in frame, or swap disk). */
    struct supp_table_entry *entry = supp_table_entry_lookup (pd, upage_entry->upage);
    
    /* If this mapping is in physical memory, free an entry in frame table.
       If this mapping is in swap disk, free an entry in swap table and bitmap. */
    if (entry->valid)
    {
      frame_free (entry->kpage);
    }
    else
    {
      swap_free (entry->pd, entry->upage);
    }
    
    /* Free an entry in supplemental page table. */
    supp_free_mapping (pd, entry->upage);
    
    /* Remove this mapping list entry in upage list. */
    e = list_remove (e);
    
    /* Free allocated memory for upage_list_entry. */
    free (upage_entry);
  }
  lock_release (&t->upage_list_lock);
  
  /* Call pagedir_destroy () to free allocated memory
     by palloc_get_page (). */
  pagedir_destroy (pd);
}

/* Free a mapping when a corresponding page is freed.
   Unlike frame_free, which can be called when a page is swapped into the swap disk,
   supp_free_mapping should be called when a page is exactly freed. */
void
supp_free_mapping (uint32_t *pd, void *upage)
{
  /* Find the supplemental page table entry. */
  lock_acquire (&supp_table_lock);
  struct supp_table_entry *target_entry = supp_table_entry_lookup (pd, upage);
  
  /* If the target mapping does not exist in supplemental page table, return. */
  if (target_entry == NULL)
    return;
  
  /* Delete the mapping from the supplementary page table,
     and free the allocated memory for that entry. */
  hash_delete (&supp_page_table, &target_entry->hash_elem);
  lock_release (&supp_table_lock);
  free (target_entry);
}

bool
restore_page (uint32_t *pd, void *uaddr)
{
  /* Get a supplemental page table entry for the page which includes
     the given user address. */
  void *upage = pg_round_down (uaddr);
  struct supp_table_entry *target_entry = supp_table_entry_lookup (pd, upage);
  
  /* If given page is already in frame, it means that
     there's an implementation fault. */
  if (target_entry->valid)
  {
    printf ("Error: A page fault with a valid page.\n");
    return false;
  }
  /* Obtain a frame. */
  void *kpage = frame_obtain ();
  if (kpage == NULL)
  {
    printf ("Fail: Restore page with frame obtain.\n ");
    return false;
  }
  
  /* Restore the target page in swap disk into the obtained frame. */
  if (!swap_in (pd, upage, kpage))
  {
    printf ("Fail: Swap in.\n");
    return false;
  }
  
  /* Set real mapping, update the supplemental page table,
     and the frame table. */
  if (!supp_new_mapping (pd, upage, kpage, target_entry->writeable, target_entry->thread))
  {
    printf ("Fail: restore_page with supp_new_mapping.\n");
    return false;
  }
  return true;
}

/* Find a supplemental table entry corresponding to given user page address. */
struct supp_table_entry *
supp_table_entry_lookup (uint32_t *pd, void *upage)
{
  struct supp_table_entry entry;
  struct hash_elem *e;
  
  entry.pd = pd;
  entry.upage = upage;
  e = hash_find (&supp_page_table, &entry.hash_elem);
  return e != NULL ? hash_entry (e, struct supp_table_entry, hash_elem) : NULL;
}

/* A hash function used for supp_page_table.
   A virtual address of user page is used as a key. */
unsigned
supp_hash_func (const struct hash_elem *elem, void *aux UNUSED)
{
  const struct supp_table_entry *entry = hash_entry (elem, struct supp_table_entry, hash_elem);
  return hash_bytes (&entry->pd, sizeof (entry->pd) + sizeof (entry->upage));
}

/* Return true if virtual address of user page of mapping 'a' is larger than of 'b'. */
bool
supp_less_func (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
  const struct supp_table_entry *entry_a = hash_entry (a, struct supp_table_entry, hash_elem);
  const struct supp_table_entry *entry_b = hash_entry (b, struct supp_table_entry, hash_elem);
  unsigned key_a = hash_bytes (&entry_a->pd, sizeof (entry_a->pd) + sizeof (entry_a->upage));
  unsigned key_b = hash_bytes (&entry_b->pd, sizeof (entry_b->pd) + sizeof (entry_b->upage));
  return key_a < key_b;
}
