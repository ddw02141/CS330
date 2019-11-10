#include "vm/frame.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/pte.h"

/* Implementation of Frame table and relataed functions. */

/* Record the mapping from a user page to frame which is
   occured by pagedir_set_page.
   Argument: void *upage - a pointer to a new user page.
             uint32_t *pte - a pointer to the corresponding frame.*/
void
frame_new_usage (void *upage, uint32_t *pte)
{
  /* Construct a frame table entry. */
  struct frame_entry *new_frame = malloc (sizeof (struct frame_entry));
  new_frame->frame_addr = pte_get_page (*pte);
  new_frame->page_addr = upage;
  
  /* Update the frame table. */
  lock_acquire (&frame_table_lock);
  hash_insert (&frame_table, &new_frame->hash_elem);
  lock_release (&frame_table_lock);
}

/* Free a frame when a corresponding page is cleared.
   The flag PTE_P should be changed to 0. */
void
frame_free (uint32_t *pte)
{
  /* Find the frame_entry with given pte. */
  void *frame_addr = pte_get_page (*pte);
  lock_acquire (&frame_table_lock);
  struct frame_entry *target_frame = frame_entry_lookup (frame_addr);
  lock_release (&frame_table_lock);
  
  /* Delete the frame_entry from the frame table,
     make the flag PTE_P of pte 0,
     and free the allocated memory for that entry. */
  lock_acquire (&frame_table_lock);
  hash_delete (&frame_table, &target_frame->hash_elem);
  lock_release (&frame_table_lock);
  *pte &= ~PTE_P;
  free (target_frame);
}

/* Find a frame table entry corresponding to given frame_addr. */
struct frame_entry *
frame_entry_lookup (void *frame_addr)
{
  struct frame_entry f;
  struct hash_elem *e;
  
  f.frame_addr = frame_addr;
  e = hash_find (&frame_table, &f.hash_elem);
  return e != NULL ? hash_entry (e, struct frame_entry, hash_elem) : NULL;
}

/* A hash function used for frame_table.
   A physical address which is address of a frame used by a user page
   is used as a key. */
unsigned
frame_hash_func (const struct hash_elem *elem, void *aux UNUSED)
{
  const struct frame_entry *frame = hash_entry (elem, struct frame_entry, hash_elem);
  return hash_bytes (&frame->frame_addr, sizeof (frame->frame_addr));
}

/* Return true if address of frame 'b' is larger than address of frame 'a'. */
bool
frame_less_func (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
  const struct frame_entry *frame_a = hash_entry (a, struct frame_entry, hash_elem);
  const struct frame_entry *frame_b = hash_entry (b, struct frame_entry, hash_elem);
  return frame_a->frame_addr < frame_b->frame_addr;
}
