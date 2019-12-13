#ifndef FILESYS_INODE_H
#define FILESYS_INODE_H

#include <stdbool.h>
#include "filesys/off_t.h"
#include "devices/block.h"
#include "lib/kernel/list.h"

struct bitmap;

/* On-disk inode information.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct sector_disk
{
  block_sector_t table_sector;		/* The sector of first indirect index table. */
  off_t length;				/* The length of the inode. */
  block_sector_t num_sector;		/* The number of the data sectors. */
  
  /* The index of the last second table in first table,
     And the index of the data sector in the second table. */
  size_t first_index;
  size_t second_index;
  block_sector_t unused[123];		/* Unused. */
};

/* On-disk index table.
   Must be exactly BLOCK_SECTOR_SIZE bytes long.
   If an instance of this struct is used as a first index table,
   a content is interpreted as a sector number of second index table.
   If an instance of this struct is used as a second index table,
   a content is interpreted as a sector number of the real file content.*/
struct idx_table
{
  block_sector_t table[128];		/* sector index table. */
};

/* In-memory inode. */
struct inode
{
  struct list_elem elem;		/* Element in inode list. */
  block_sector_t sector;		/* Sector number of sector_disk. */
  int open_cnt;				/* Number of openers. */
  bool removed;				/* True if deleted, false otherwise. */
  int deny_write_cnt;			/* 0: writes ok, >0: deny writes. */
};

void inode_init (void);
bool inode_create (block_sector_t, off_t);
struct inode *inode_open (block_sector_t);
struct inode *inode_reopen (struct inode *);
block_sector_t inode_get_inumber (const struct inode *);
void inode_close (struct inode *);
void inode_remove (struct inode *);
off_t inode_read_at (struct inode *, void *, off_t size, off_t offset);
off_t inode_write_at (struct inode *, const void *, off_t size, off_t offset);
void inode_deny_write (struct inode *);
void inode_allow_write (struct inode *);
off_t inode_length (const struct inode *);

#endif /* filesys/inode.h */
