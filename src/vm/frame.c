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
frame_new_usage(void *upage, uint32_t pte)
{
  /* Construct a frame table entry. */
  struct frame_entry *new_frame = malloc (sizeof (struct frame_entry));
  new_frame->frame_addr = pte_get_page (pte);
  new_frame->page_addr = upage;
  
  /* Update the frame table. */
  lock_acquire (&frame_table_lock);
  hash_insert (&frame_table, &new_frame->hash_elem);
  lock_release (&frame_table_lock);
}

/* A hash function used for frame_table.
   A physical address which is address of a frame used by a user page
   is used as a key. */
unsigned
frame_hash_func (const struct hash_elem *elem, void *aux)
{
  const struct frame_entry *frame = hash_entry (elem, struct frame_entry, hash_elem);
  return hash_bytes (&frame->frame_addr, sizeof (frame->frame_addr));
}

/* Return true if address of frame 'b' is larger than address of frame 'a'. */
bool
frame_less_func (const struct hash_elem *a, const struct hash_elem *b, void *aux)
{
  const struct frame_entry *frame_a = hash_entry (a, struct frame_entry, hash_elem);
  const struct frame_entry *frame_b = hash_entry (b, struct frame_entry, hash_elem);
  return frame_a->frame_addr < frame_b->frame_addr;
}
