#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"

/* Partition that contains the file system. */
struct block *fs_device;

static void do_format (void);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void
filesys_init (bool format) 
{
  fs_device = block_get_role (BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC ("No file system device found, can't initialize file system.");

  inode_init ();
  free_map_init ();

  if (format) 
    do_format ();

  free_map_open ();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void
filesys_done (void) 
{
  cache_flush ();
  free_map_close ();
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails.
   
   The given name is a absolute path,
   and the given boolean is_dir is true if this call should
   create not a file but a directory. */
bool
filesys_create (const char *name, off_t initial_size, bool is_dir) 
{
  block_sector_t inode_sector = 0;
  struct dir *dir_root = dir_open_root ();
  struct inode *inode;
  bool dir;
  
  if (dir_root == NULL)
    return false;
  
  /* Parse the name. */
  char *tokens[10];
  size_t num_token = parse_file_name (name, tokens);
  
  /* The root already exists. */
  if (num_token == 0)
    return false;
  
  /* Look up the subdirectories. */
  struct dir *dir_last = find_last_directory (tokens, num_token, dir_root);
  if (dir_last == NULL)
    return false;
  
  /* Now check if there already exists a file with given name,
     and create a new file if there's no such file. */
  if (dir_lookup (dir_last, tokens[num_token - 1], &inode, &dir))
    return false;
  
  bool success = (free_map_allocate (1, &inode_sector)
                  && inode_create (inode_sector, initial_size)
                  && dir_add (dir_last, tokens[num_token - 1], inode_sector, is_dir));
  if (!success && inode_sector != 0)
    free_map_release (inode_sector, 1);
  dir_close (dir_last);

  return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails.
   
   The given name is a absolute path of the
   file or a directory.
   If the target file is a directory,
   set the boolean is_dir. */
struct file *
filesys_open (const char *name, bool *is_dir)
{
  struct dir *dir_root = dir_open_root ();
  struct inode *inode = NULL;
  struct file *file;
  
  if (dir_root == NULL)
    return NULL;
  
  /* Parse the name. */
  char *tokens[10];
  size_t num_token = parse_file_name (name, tokens);
  
  /* If the target file is the root directory itself, open. */
  if (num_token == 0)
  {
    struct file *file = file_open (dir_get_inode (dir_root));
    dir_close (dir_root);
    return file;
  }
  
  /* Look up the subdirectories. */
  struct dir *dir_last = find_last_directory (tokens, num_token, dir_root);
  if (dir_last == NULL)
    return NULL;
  
  /* Now look up for the file, or a directory with given name. */
  dir_lookup (dir_last, tokens[num_token - 1], &inode, &is_dir);
  dir_close (dir_last);

  return file_open (inode);
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails.
   
   The given name is an absolute path.
   dir_remove removes directories as well. */
bool
filesys_remove (const char *name) 
{
  struct dir *dir_root = dir_open_root ();
  
  if (dir_root == NULL)
    return false;
  
  /* Parse the name. */
  char *tokens[10];
  size_t num_token = parse_file_name (name, tokens);
  
  /* If the target file is the root directory itself, reject. */
  if (num_token == 0)
  {
    dir_close (dir_root);
    return false;
  }
  
  /* Look up the subdirectories. */
  struct dir *dir_last = find_last_directory (tokens, num_token, dir_root);
  if (dir_last == NULL)
    return false;
  
  /* Now reomve the file in current directory. */
  bool success = dir_remove (dir_last, tokens[num_token - 1]);
  dir_close (dir_last); 
  
  return success;
}

/* Formats the file system. */
static void
do_format (void)
{
  printf ("Formatting file system...");
  free_map_create ();
  if (!dir_create (ROOT_DIR_SECTOR, 16))
    PANIC ("root directory creation failed");
  free_map_close ();
  printf ("done.\n");
}

/* Parse the name.
   Store the tokens in res,
   and return the number of tokens. */
size_t
parse_file_name (char *name, char **res_ptr)
{
  char *token, *save_ptr;
  size_t num_token = 0;
  
  for (token = strtok_r (name, "/", &save_ptr); token != NULL;
       token = strtok_r (NULL, "/", &save_ptr))
  {
    *(res_ptr + num_token) = token;
    num_token++;
  }
  return num_token;
}

/* Look up the directory with given absolute path,
   return the last directory if found, and return
   NULL if not found.
   Note that the last directory does not include the
   end of the absolute path if it is directory. */
struct dir *
find_last_directory (char **tokens, size_t num_token, struct dir *dir_root)
{
  struct dir *dir_cur = dir_root;
  struct inode *inode_cur = NULL;
  size_t token_idx = 0;
  bool is_dir;
  
  /* Look up the subdirectories. */
  while (token_idx < num_token - 1)
  {
    /* Check if there's a directory we are finding.
       If not, return NULL. */
    if (!dir_lookup (dir_cur, *(tokens + token_idx), &inode_cur, &is_dir) || !is_dir)
    {
      dir_close (dir_cur);
      return NULL;
    }
    
    /* Close the current directory, and open deeper directory. */
    dir_close (dir_cur);
    dir_cur = dir_open (inode_cur);
    
    /* If there's no such directory, return NULL. */
    if (dir_cur == NULL)
      return NULL;
    
    /* Advance. */
    token_idx++;
  }
  
  /* Now return the dir_cur. */
  return dir_cur;
}
