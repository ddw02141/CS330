#ifndef FILESYS_FILESYS_H
#define FILESYS_FILESYS_H

#include <stdbool.h>
#include <stddef.h>
#include "filesys/off_t.h"

/* Sectors of system file inodes. */
#define FREE_MAP_SECTOR 0       /* Free map file inode sector. */
#define ROOT_DIR_SECTOR 1       /* Root directory file inode sector. */

/* Block device that contains the file system. */
struct block *fs_device;

void filesys_init (bool format);
void filesys_done (void);
bool filesys_create (const char *name, off_t initial_size, bool is_dir);
struct file *filesys_open (const char *name, bool *is_dir);
bool filesys_remove (const char *name);
size_t parse_file_name (char *name, char *name_copy, char **res_ptr);
struct dir *find_last_directory (char **tokens, size_t num_token, struct dir *dir_root);

#endif /* filesys/filesys.h */
