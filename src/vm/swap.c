#include "lib/kernel/hash.h"
#include "lib/kernel/bitmap.h"
#include "devices/block.h"
#include "threads/malloc.h"
#include "vm/swap.h"
#include <stdio.h>

/* Implementation of swap table, and related functions. */

/* Initialize a pointer to the swap disk, and create a bitmap which tracks
   the use of sectors of the swap disk. */
void
swap_init (void)
{
  /* First get the swap_disk and its size. */
  swap_disk = block_get_role (BLOCK_SWAP);
  block_sector_t num_sectors = block_size (swap_disk);
  
  /* The swap bitmap will manage the sectors of swap disk. */
  swap_bitmap = bitmap_create (num_sectors);
}

/* Get 8 consecutive free sectors in swap disk, which are 4 KB totally,
   by scanning the swap bitmap.
   And then write a given page to the sectors and update the swap table.*/
bool
swap_out (uint32_t *pd, void *upage, void *kpage)
{
  /* Get 8 consecutive free sectors in swap disk. */
  lock_acquire (&swap_bitmap_lock);
  size_t idx = bitmap_scan_and_flip (&swap_bitmap, 0, 8, false);
  lock_release (&swap_bitmap_lock);
  
  if (idx == BITMAP_ERROR)
    return false;
  
  /* Write to the swap disk. */
  swap_disk_write (idx, kpage);
  
  /* Construct a swap table entry. */
  struct swap_table_entry *entry = malloc (sizeof (struct swap_table_entry));
  
  if (entry == NULL)
  {
    printf ("Allocation failed: Swap table entry.\n");
    return false;
  }
  entry->pd = pd;
  entry->upage = upage;
  entry->bitmap_idx = idx;
  
  /* Record a information of the new mapping in swap table. */
  lock_acquire (&swap_table_lock);
  hash_insert (&swap_table, &entry->hash_elem);
  lock_release (&swap_table_lock);
  return true;
}

/* Get 8 consecutive sectors corresponding to the given pagedir and user page,
   which is its swapped in contents, and read back into kpage.
   And then free the swap disk. */
bool
swap_in (uint32_t *pd, void *upage, void *kpage)
{
  /* Get the target swap table entry. */
  struct swap_table_entry *target_entry = swap_table_entry_lookup (pd, upage);
  if (target_entry == NULL)
  {
    printf ("Fail: Swap out with lookup.\n");
    return false;
  }
  
  /* Read the contents of the given upage into kpage. */
  swap_disk_read (target_entry->bitmap_idx, kpage);
  
  /* Update the swap disk related data structures. */
  swap_free (pd, upage);
  return true;
}

/* Free a memory allocated to given upage,
   and update the swap table and swap bitmap. */
void
swap_free (uint32_t *pd, void *upage)
{
  /* Get the target swap table entry. */
  lock_acquire (&swap_table_lock);
  struct swap_table_entry *target_entry = swap_table_entry_lookup (pd, upage);
  
  /* Update the swap bitmap.
     And do not initialize the actual swap disk. */
  lock_acquire (&swap_bitmap_lock);
  bitmap_set_multiple (&swap_bitmap, target_entry->idx, 8, false);
  lock_release (&swap_bitmap_lock);
  
  /* Remove the entry from the swap table,
     and free the entry. */
  hash_delete (&swap_table, &target_entry->hash_elem);
  lock_release (&swap_table_lock);
  free (target_entry);
}

/* Read the whole contents of the given page from the swap disk.
   This function reads from swap disk 8 times, because a read from
   the swap disk is sectorwise, and a page is composed of 4KB
   which is size of 8 sectors of the swap disk. */
void
swap_disk_read (size_t idx, void *kpage)
{
  for (int i = 0; i < 8; i++)
  {
    /* Because each sector in swap disk is composed of 512 bytes,
       and each page is composed of 4096 bytes, code below reads
       a whole page from the swap disk. */
    block_read (swap_disk, idx + i, kpage + (512 * i));
  }
}

/* Write the whole contents of the given page to the swap disk.
   This function writes to swap disk 8 times, because a write to
   the swap disk is sectorwise, and a page is composed of 4KB
   which is size of 8 sectors of the swap disk.
   This function can sure that the 8 consecutive sectors starting
   at index 'idx' are free, because 'idx' is returned by
   'bitmap_scan'. */
void
swap_disk_write (size_t idx, void *kpage)
{
  for (int i = 0; i < 8; i++)
  {
    /* Because each sector in swap disk is composed of 512 bytes,
       and each page is composed of 4096 bytes, code below writes
       a whole page in the swap disk. */
    block_write (swap_disk, idx + i, kpage + (512 * i));
  }
}

/* Find a swap table entry corresponding to
   given page directory and user address. */
struct swap_table_entry *
swap_table_entry_lookup (uint32_t *pd, void *upage)
{
  struct swap_table_entry entry;
  struct hash_elem *e;
  
  entry.pd = pd;
  entry.upage = upage;
  e = hash_find (&swap_page_table, &entry.hash_elem);
  return e != NULL ? hash_entry (e, struct swap_table_entry, hash_elem) : NULL;
}

/* A hash function used for swap_table.
   A virtual address of a user page is used as a key. */
unsigned
swap_hash_func (const struct hash_elem *elem, void *aux UNUSED)
{
  const struct swap_table_entry *entry = hash_entry (elem, struct swap_table_entry, hash_elem);
  return hash_bytes (&entry->pd, sizeof (entry->pd) + sizeof (entry->upage));
}

/* Return true if virtual address of user page of mapping 'a' is larger than of 'b'. */
bool
swap_less_func (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
  const struct swap_table_entry *entry_a = hash_entry (a, struct swap_table_entry, hash_elem);
  const struct swap_table_entry *entry_b = hash_entry (b, struct swap_table_entry, hash_elem);
  unsigned key_a = hash_bytes (&entry_a->pd, sizeof (entry_a->pd) + sizeof (entry_a->upage));
  unsigned key_b = hash_bytes (&entry_b->pd, sizeof (entry_b->pd) + sizeof (entry_b->upage));
  return key_a < key_b;
}
