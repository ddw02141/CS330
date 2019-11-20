#include "vm/frame.h"
#include "vm/page.h"
#include "userprog/pagedir.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/pte.h"
#include <stdio.h>

/* Implementation of Frame table and relataed functions. */

/* Record the mapping from a user page to frame which is
   occured by pagedir_set_page.
   Argument: void *upage - a pointer to a new user page.
             uint32_t *pte - a pointer to the corresponding frame.*/
bool
frame_new_usage (uint32_t *pd, void *upage, void *kpage)
{
  /* Construct a frame table entry. */
  struct frame_entry *new_entry = malloc (sizeof (struct frame_entry));
  if (new_entry == NULL)
  {
    printf ("Allocation failed: Frame table entry\n");
    return false;
  }
  new_entry->pd = pd;
  new_entry->upage = upage;
  new_entry->kpage = kpage;
  
  /* Update the frame table. */
  lock_acquire (&frame_table_lock);
  hash_insert (&frame_table, &new_entry->hash_elem);
  lock_release (&frame_table_lock);
  
  return true;
}

/* Free a frame when a corresponding page is cleared.
   The flag PTE_P should be changed to 0. */
void
frame_free (void *kpage)
{
  /* Find the frame_entry with given kpage. */
  struct frame_entry *target_entry = frame_entry_lookup (kpage);
  
  /* If the target frame does not exist, return. */
  if (target_entry == NULL)
    return;
  
  /* Delete the frame_entry from the frame table,
     make the flag PTE_P of pte 0,
     and free the allocated memory for that entry. */
  lock_acquire (&frame_table_lock);
  hash_delete (&frame_table, &target_entry->hash_elem);
  lock_release (&frame_table_lock);
  free (target_entry);
}

/* Find a frame table entry corresponding to given frame_addr. */
struct frame_entry *
frame_entry_lookup (void *kpage)
{
  struct frame_entry entry;
  struct hash_elem *e;
  
  entry.kpage = kpage;
  lock_acquire (&frame_table_lock);
  e = hash_find (&frame_table, &entry.hash_elem);
  lock_release (&frame_table_lock);
  return e != NULL ? hash_entry (e, struct frame_entry, hash_elem) : NULL;
}

/* Find a victim page in frame.
   Use the second chance algorithm.
   If fails to find a victim in first iteration, try a interation again
   by which a selecting of victim page is guaranteed. */
struct frame_entry *
frame_find_victim (void)
{
  struct hash_iterator i;
  
  lock_acquire (&frame_table_lock);
  hash_first (&i, &frame_table);
  while (hash_next (&i))
  {
    struct frame_entry *entry = hash_entry (hash_cur (&i), struct frame_entry, hash_elem);
    
    if (pagedir_is_accessed (entry->pd, entry->upage) || pagedir_is_accessed (entry->pd, entry->kpage))
    {
      pagedir_set_accessed (entry->pd, entry->upage, false);
      pagedir_set_accessed (entry->pd, entry->kpage, false);
    }
    else
    {
      lock_release (&frame_table_lock);
      return entry;
    }
  }
  lock_release (&frame_table_lock);
  
  /*If finding a victim fails during one interation, iterate once again.
    In second interation, it is certain that there's a victim. */
  lock_acquire (&frame_table_lock);
  hash_first (&i, &frame_table);
  while (hash_next (&i))
  {
    struct frame_entry *entry = hash_entry (hash_cur (&i), struct frame_entry, hash_elem);
    
    if (pagedir_is_accessed (entry->pd, entry->upage) || pagedir_is_accessed (entry->pd, entry->kpage))
    {
      pagedir_set_accessed (entry->pd, entry->upage, false);
      pagedir_set_accessed (entry->pd, entry->kpage, false);
    }
    else
    {
      lock_release (&frame_table_lock);
      return entry;
    }
  }
  lock_release (&frame_table_lock);
  printf("Fatal: find victim - program cannot reach here");
  return NULL;
}

/* A hash function used for frame_table.
   A physical address which is address of a frame used by a user page
   is used as a key. */
unsigned
frame_hash_func (const struct hash_elem *elem, void *aux UNUSED)
{
  const struct frame_entry *entry = hash_entry (elem, struct frame_entry, hash_elem);
  return hash_bytes (&entry->kpage, sizeof (entry->kpage));
}

/* Return true if address of frame 'b' is larger than address of frame 'a'. */
bool
frame_less_func (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
  const struct frame_entry *entry_a = hash_entry (a, struct frame_entry, hash_elem);
  const struct frame_entry *entry_b = hash_entry (b, struct frame_entry, hash_elem);
  return entry_a->kpage < entry_b->kpage;
}
