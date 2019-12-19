#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "threads/vaddr.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "lib/string.h"
#include "vm/page.h"

// void free_tokens(char **tokens);

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
  // printf("filesys_create : %s\n", name);
  // char *name_copy = palloc_get_page(0);
  // strlcpy(name_copy, name, PGSIZE);
  char *name_copy = calloc(1, strlen(name) + 1);
  strlcpy(name_copy, name, strlen(name) + 1);

  block_sector_t inode_sector = 0;
  struct dir *dir_root = dir_open_root ();
  struct inode *inode;
  bool dir;
  
  if (dir_root == NULL){
    // palloc_free_page(name_copy);
    free(name_copy);
    return false;
  }
    
  
  /* Parse the name. */
  char * tokens[20];
  // char tokens[20][strlen(name)];
  size_t num_token = parse_file_name (name, name_copy, tokens);
  
  /* The root already exists. */
  if (num_token == 0){
    // palloc_free_page(name_copy);
    free(name_copy);
    return false;
  }
  
  /* Look up the subdirectories. */
  struct dir *dir_last = find_last_directory (tokens, num_token, dir_root);
  if (dir_last == NULL){
    // palloc_free_page(name_copy);
    free(name_copy);
    return false;
  }
  /* Now check if there already exists a file with given name,
     and create a new file if there's no such file. */
  if (dir_lookup (dir_last, tokens[num_token - 1], &inode, &dir)){
    // palloc_free_page(name_copy);
    free(name_copy);
    return false;
  }
    
  // printf("tokens[num_token - 1] : %s\n", tokens[num_token - 1]);
  bool success = (free_map_allocate (1, &inode_sector)
                  && inode_create (inode_sector, initial_size)
                  && dir_add (dir_last, tokens[num_token - 1], inode_sector, is_dir, initial_size));
  if (!success && inode_sector != 0)
    free_map_release (inode_sector, 1);
  dir_close (dir_last);

  // palloc_free_page(name_copy);
  free(name_copy);
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
  // printf("filesys_open : %s\n", name);

  // char *name_copy = palloc_get_page(0);
  // strlcpy(name_copy, name, PGSIZE);
  char *name_copy = calloc(1, strlen(name) + 1);
  strlcpy(name_copy, name, strlen(name) + 1);


  struct dir *dir_root = dir_open_root ();
  struct inode *inode = NULL;
  struct file *file;
  
  if (dir_root == NULL){
    // palloc_free_page(name_copy);
    free(name_copy);
    return NULL;
  }
    
  
  /* Parse the name. */
  if (strlen(name)==0) {
    // palloc_free_page(name_copy);
    free(name_copy);
    return NULL;
  }
  char *tokens[20];
  // char tokens[20][strlen(name)+1];
  size_t num_token = parse_file_name (name, name_copy, tokens);
  
  /* If the target file is the root directory itself, open. */
  if (num_token == 0)
  {
    *is_dir = true;
    // palloc_free_page(name_copy);
    free(name_copy);
    return dir_root;
  }
  
  /* Look up the subdirectories. */
  struct dir *dir_last = find_last_directory (tokens, num_token, dir_root);
  if (dir_last == NULL){
    // palloc_free_page(name_copy);
    free(name_copy);
    return NULL;
  }
    
  
  /* Now look up for the file, or a directory with given name. */
  if (!dir_lookup (dir_last, tokens[num_token - 1], &inode, is_dir))
  {
    // palloc_free_page(name_copy);
    free(name_copy);
    return NULL;
  }
  else
  {
    if (is_dir != NULL && *is_dir)
    {
      dir_close (dir_last);
      // palloc_free_page(name_copy);
      free(name_copy);
      return dir_open (inode);
    }
    else
    {
      dir_close (dir_last);
      // palloc_free_page(name_copy);
      free(name_copy);
      return file_open (inode);
    }
  }
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
  // char *name_copy = palloc_get_page(0);
  // strlcpy(name_copy, name, PGSIZE);
  char *name_copy = calloc(1, strlen(name) + 1);
  strlcpy(name_copy, name, strlen(name) + 1);

  struct dir *dir_root = dir_open_root ();
  
  if (dir_root == NULL){
    // palloc_free_page(name_copy);
    free(name_copy);
    return false;
  }
    
  
  /* Parse the name. */
  char *tokens[20];
  // char tokens[20][strlen(name)];
  size_t num_token = parse_file_name (name, name_copy, tokens);
  
  /* If the target file is the root directory itself, reject. */
  if (num_token == 0)
  {
    dir_close (dir_root);
    // palloc_free_page(name_copy);
    free(name_copy);
    return false;
  }
  
  /* Look up the subdirectories. */
  struct dir *dir_last = find_last_directory (tokens, num_token, dir_root);
  if (dir_last == NULL){
    // palloc_free_page(name_copy);
    free(name_copy);
    return false;
  }
  
  /* Now look up for the file, or a directory with given name.
     Check if it is a directory. */
  struct inode *inode = NULL;
  bool is_dir;
  if (dir_lookup (dir_last, tokens[num_token - 1], &inode, &is_dir) && is_dir)
  {
    /* If it is a directory, open. */
    struct dir *dir_target = dir_open (inode);
    
    /* If the directory is not empty, reject. */
    if (!dir_is_empty (dir_target))
    {
      dir_close (dir_last);
      dir_close (dir_target);
      // palloc_free_page(name_copy);
      free(name_copy);
      return false;
    }
    dir_close (dir_target);
  }
  
  /* Now reomve the file in current directory. */
  bool success = dir_remove (dir_last, tokens[num_token - 1]);
  dir_close (dir_last); 

  // palloc_free_page(name_copy);
  free(name_copy);
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
parse_file_name (char *name, char *name_copy, char **res_ptr)
{
  char *token, *save_ptr;
  size_t num_token = 0;
  // char *name_copy = (char *)malloc( (strlen(name) + 1) );
  // memcpy(name_copy, name, sizeof(char) * ((int)strlen(name) + 1));
  // memcpy(name_copy, name, strlen(name) + 1);
  // char *name_copy = palloc_get_page(0);
  // strlcpy(name_copy, name, strlen(name) + 1);
  
  for (token = strtok_r (name_copy, "/", &save_ptr); token != NULL;
       token = strtok_r (NULL, "/", &save_ptr))
  {
    *(res_ptr + num_token) = token;
    num_token++;
  }

  // free(name_copy);
  // palloc_free_page(name_copy);

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
    bool dir_lookup_suceess = dir_lookup (dir_cur, *(tokens + token_idx), &inode_cur, &is_dir) || !is_dir;
    dir_close (dir_cur);
    if (!dir_lookup_suceess) return NULL;
    // if (!dir_lookup (dir_cur, *(tokens + token_idx), &inode_cur, &is_dir) || !is_dir)
    // {
    //   dir_close (dir_cur);
    //   return NULL;
    // }
    
    /* Close the current directory, and open deeper directory. */
    // dir_close (dir_cur);
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

// void free_tokens(char **tokens){
  
//   void* addr = pg_round_down(*tokens);
//   // printf("addr : %x\n", addr); addr : c0119000
//   palloc_free_page(addr);
//   return;

// }