#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "filesys/inode.h"
#include "devices/shutdown.h"
#include "lib/string.h"
#include "lib/kernel/list.h"
#include "threads/synch.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "userprog/syscall.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "vm/page.h"
#include "filesys/filesys.h"
#include "filesys/directory.h"

/* Function prototypes. */
static void syscall_handler (struct intr_frame *);
static bool is_valid_esp (void *esp);
static bool is_valid_args (void *esp, int num_args);
static bool is_valid_str (char *str);
static bool is_valid_ptr (void *ptr);
static struct file *find_file_by_name (char *file_name);
static struct file *find_file_by_fd (int fd);
static struct dir *find_dir_by_name (char *dir_name);
static struct dir *find_dir_by_fd (int fd);
static bool find_exec_by_name (char *file_name);
static void append_exit_list (struct exited_thread *t, int exit_status);
static bool is_page_overlap (void *addr, off_t file_size);
static void remove_mapid_list (mapid_t mapid);
static void append_mapid_list (mapid_t mapid);
static bool is_relative (const char *path);
static const char *get_final_dir (const char *path);
static bool is_chdir_possible (char **tokens, size_t num_token);
static bool is_valid_chdir (void);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init (&filesys_lock);
}

static void
syscall_handler (struct intr_frame *f)
{
  /* Before to handle the system call, check if the syscall esp
     is valid because we need to dereference it to know the
     syscall number. */
  if (!is_valid_esp (f->esp))
  {
    error_exit ();
  }
  
  /* Get syscall number and pointer to arguments.
     The arguments may be not used. */
  int syscall_num = *((int *)(f->esp));
  void *arg1 = (void *)(f->esp + 4);
  void *arg2 = (void *)(f->esp + 8);
  void *arg3 = (void *)(f->esp + 12);
  
  /* Handle the syscall with given syscall number. */
  
  /**************************
   *       SYS_HALT         *
   *************************/
  if (syscall_num == SYS_HALT)
  {
    shutdown_power_off ();
  }
  
  /**************************
   *       SYS_EXIT         *
   *************************/
  else if (syscall_num == SYS_EXIT)
  {
    struct thread *current_thread = thread_current ();
    
    // Check if the argument lies in valid address.
    if (!is_valid_args (f->esp, 1))
    {
      error_exit ();
    }
    
    int exit_status = *((int *) arg1);
    printf ("%s: exit(%d)\n", current_thread->name, exit_status);
    current_thread->exit_status = exit_status;
    
    /* If exit_status is -1, do not append this thread info into
       the exit list.
       Because,
         1. it is hard to free, and
         2. if a thread info is not in exit list,
            its parent automatically take -1 as its exit status. */
    /* wait_sema has 2 functionality:
         1. Ensure that the parent thread waits.
         2. Synchronize exit_list and child_list. */
    if (exit_status != -1)
    {
      lock_acquire (&exit_list_lock);
      // If parent thread already exited, do not allocate exited_thread.
      if (!current_thread -> parent_exited)
      {
        struct exited_thread *t = malloc (sizeof (struct exited_thread));
        append_exit_list (t, exit_status);
      }
      lock_release (&exit_list_lock);
      sema_up (&current_thread->wait_sema);
      thread_exit ();
    }
    else
    {
      sema_up (&current_thread->wait_sema);
      thread_exit ();
    }
  }
  
  /**************************
   *       SYS_EXEC         *
   *************************/
  else if (syscall_num == SYS_EXEC)
  {
    // Check if the argument lies in valid address.
    if (!is_valid_args (f->esp, 1))
    {
      error_exit ();
    }
    
    char *file_name = *((char **) arg1);
    
    // Check if the file_name is valid.
    if (!is_valid_str (file_name))
    {
      error_exit ();
    }
    
    tid_t pid = process_execute(file_name);
    struct thread *current_thread = thread_current ();
    
    if (pid == TID_ERROR)
    {
      f->eax = -1;
    }
    else
    {
      // Wait for the child loads the program.
      sema_down (&(current_thread->exec_sema));
      
      // Check if the loading succeed or not.
      if (!current_thread->load_success)
      {
        f->eax = -1;
      }
      else
      {
        f->eax = pid;
      }
    }
  }
  
  /**************************
   *       SYS_WAIT         *
   *************************/
  else if (syscall_num == SYS_WAIT)
  {
    tid_t tid = *((tid_t *) arg1);
    f->eax = process_wait (tid);
  }
  
  /**************************
   *      SYS_CREATE        *
   *************************/
  else if (syscall_num == SYS_CREATE)
  {
    char *file_name = *((char **) arg1);
    unsigned size = *((unsigned *) arg2);
    
    /* Check if the file_name is valid. */
    if (!is_valid_ptr(file_name))
    {
      error_exit ();
    }
    else if (!is_valid_chdir ())
    {
      f->eax = false;
    }
    else
    {
      /* Get the absolute path for the file name. */
      char *file_name_abs = get_final_dir (file_name);
      f->eax = filesys_create (file_name_abs, size, false);
      
      /* Free the allocated memory for the absolute path. */
      palloc_free_page (file_name_abs);
    }
  }
  
  /**************************
   *      SYS_REMOVE        *
   *************************/
  else if (syscall_num == SYS_REMOVE)
  {
    char *file_name = *((char **) arg1);
    
    /* Get the absolute path for the file name. */
    char *file_name_abs = get_final_dir (file_name);
    f->eax = filesys_remove(file_name_abs);

    palloc_free_page (file_name_abs);
  }
  
  /**************************
   *       SYS_OPEN         *
   *************************/
  else if (syscall_num == SYS_OPEN)
  {
    char *file_name = *((char **) arg1);
    struct thread *current_thread = thread_current ();
    struct file *file, *new_file;
    struct dir *dir, *new_dir;
    
    /* Check if the file_name is valid. */
    if (!is_valid_ptr(file_name))
    {
      error_exit ();
    }
    else if (!is_valid_str(file_name))
    {
      f->eax = -1;
    }
    else if (!is_valid_chdir ())
    {
      f->eax = -1;
    }
    else
    {
      /* Get the absolute path of the file. */
      char *file_name_abs = get_final_dir (file_name);
      
      /* Find the file or directory with given name. */
      file = find_file_by_name (file_name_abs);
      dir = find_dir_by_name (file_name_abs);
      
      /* Check if the file or directory is already opened by this thread. */
      if (file == NULL && dir == NULL)
      {
        bool is_dir;
        void *new = filesys_open (file_name_abs, &is_dir);
        
        /* There's no such file. */
        if (new == NULL)
        {
          f->eax = -1;
        }
        /* This is the initial open. */
        else
        {
          /* First check if the target thing is a file or a directory. */
          if (is_dir)
          {
            new_dir = new;
            new_dir->fd = current_thread->max_fd;
            // printf("OPEN DIR: %s %d\n", file_name, new_dir->fd);
            // printf("DIR NAME : %s\n", file_name_abs);
            new_dir->dir_name = calloc(1, strlen(file_name_abs) + 1);
            strlcpy (new_dir->dir_name, file_name_abs, strlen(file_name_abs) + 1);

            lock_acquire (&current_thread->dir_list_lock);
            list_push_back (&current_thread->dir_list,
                            &new_dir->elem);
            current_thread->max_fd += 1;
            lock_release (&current_thread->dir_list_lock);
            f->eax = new_dir->fd;
          }
          else
          {
            new_file = new;
            new_file->fd = current_thread->max_fd;
            //printf("OPEN FILE: %s %d\n", file_name, new_file->fd);
            new_file->file_name = calloc(1, strlen(file_name_abs) + 1);
            strlcpy (new_file->file_name, file_name_abs, strlen(file_name_abs)+ 1);

            lock_acquire (&current_thread->file_list_lock);
            list_push_back (&current_thread->file_list,
                            &new_file->elem);
            current_thread->max_fd += 1;
            lock_release (&current_thread->file_list_lock);
            f->eax = new_file->fd;
          }
        }
      }
      /* This file(not a directory) is already opened by this thread. */
      else if (file != NULL)
      {
        /* Check if the file is about to be removed. */
        if (!file->inode->removed)
        {
          new_file = file_reopen (file);
          new_file->fd = current_thread->max_fd;
          new_file->file_name = calloc(1, strlen(file_name_abs) + 1);
          strlcpy (new_file->file_name, file_name_abs, strlen(file_name_abs)+ 1);

          lock_acquire (&current_thread->file_list_lock);
          list_push_back (&current_thread->file_list,
                          &new_file->elem);
          current_thread->max_fd += 1;
          lock_release (&current_thread->file_list_lock);
          f->eax = new_file->fd;
        }
        else
        {
          f->eax = -1;
        }
      }
      /* This directory is already opened by this thread. */
      else
      {
        /* Check if the directory is about to be removed. */
        if (!dir->inode->removed)
        {
          new_dir = dir_reopen (dir);
          new_file->fd = current_thread->max_fd;
          new_dir->dir_name = calloc(1, strlen(file_name_abs) + 1);
          strlcpy (new_dir->dir_name, file_name_abs, strlen(file_name_abs)+ 1);

          lock_acquire (&current_thread->dir_list_lock);
          list_push_back (&current_thread->dir_list,
                          &new_dir->elem);
          current_thread->max_fd += 1;
          lock_release (&current_thread->dir_list_lock);
          f->eax = new_dir->fd;
        }
        else
        {
          f->eax = -1;
        }
      }
      /* Free the allocated page for the absolute path. */
      palloc_free_page (file_name_abs);
    }
  }
  
  /**************************
   *     SYS_FILESIZE       *
   *************************/
  else if (syscall_num == SYS_FILESIZE)
  {
    int fd = *((int *) arg1);
    
    struct file *file = find_file_by_fd (fd);
    
    if (file == NULL)
    {
      f->eax = -1;
    }
    else
    {
      f->eax = file_length (file);
    }
  }
  
  /**************************
   *       SYS_READ         *
   *************************/
  else if (syscall_num == SYS_READ)
  {
    int fd = *((int *) arg1);
    void *buffer = *((void **) arg2);
    unsigned size = *((unsigned *) arg3);
    
    /* Check if the given buffer is valid. */
    if (!is_valid_ptr (buffer))
    {
      error_exit ();
    }
    
    if (fd == 0)
    {
      input_getc(buffer, size);
    }
    else{
      struct file *file = find_file_by_fd (fd);
      if (file == NULL)
      {
        f->eax = -1;
      }
      else
      {
        f->eax = file_read (file, buffer, size);
      }
    }
  }
  
  /**************************
   *       SYS_WRITE        *
   *************************/
  else if (syscall_num == SYS_WRITE)
  {
    int fd = *((int *) arg1);
    void *buffer = *((void **) arg2);
    unsigned size = *((unsigned *) arg3);
    
    /* Check if given buffer is valid. */
    if (!is_valid_ptr (buffer))
    {
      error_exit ();
    }
    
    if (fd == 1)
    {
      putbuf (buffer, size);
    }
    else
    {
      struct file *file = find_file_by_fd (fd);
      struct dir *dir = find_dir_by_fd (fd);
      
      if (file == NULL && dir == NULL)
      {
        f->eax = 0;
      }
      else if (file == NULL)
      {
        f->eax = -1;
      }
      else
      {
        f->eax = file_write (file, buffer, size);
      }
    }
  }
  
  /**************************
   *       SYS_SEEK         *
   *************************/
  else if (syscall_num == SYS_SEEK)
  {
    int fd = *((int *) arg1);
    unsigned pos = *((unsigned *) arg2);
    
    struct file *file = find_file_by_fd (fd);
    if (file != NULL)
      file_seek (file, pos);
  }
  
  /**************************
   *       SYS_TELL         *
   *************************/
  else if (syscall_num == SYS_TELL)
{
    int fd = *((int *) arg1);
    
    struct file *file = find_file_by_fd (fd);
    if (file != NULL)
      f->eax = file_tell (file);
    else
      f->eax = -1;
  }
  
  /**************************
   *       SYS_CLOSE        *
   *************************/
  else if (syscall_num == SYS_CLOSE)
  {
    int fd = *((int *) arg1);
    
    struct file *file = find_file_by_fd (fd);
    struct dir *dir = find_dir_by_fd (fd);
    struct thread *current_thread = thread_current ();
    
    if (file != NULL)
    {
      lock_acquire (&current_thread->file_list_lock);
      list_remove (&file->elem);
      lock_release (&current_thread->file_list_lock);
      
      file_close (file);
    }
    else if (dir != NULL)
    {
      lock_acquire (&current_thread->dir_list_lock);
      list_remove (&dir->elem);
      lock_release (&current_thread->dir_list_lock);
      
      dir_close (dir);
    }
    else
    {
      ;
    }
  }
  
  /**************************
   *       SYS_MMAP         *
   *************************/
  else if (syscall_num == SYS_MMAP)
  {
    int fd = *((int *) arg1);
    void *addr = *((void **) arg2);
    struct thread *current_thread = thread_current ();
    
    /* If fd is 0 or 1, which are not mappable file, fail. */
    if (fd == 0 || fd == 1)
    {
      f->eax = -1;
      return;
    }
    
    /* If addr is 0, fail. */
    if (addr == 0)
    {
      f->eax = -1;
      return;
    }
    
    /* If addr is not page-aligned, fail. */
    if (pg_ofs (addr) != 0)
    {
      f->eax = -1;
      return;
    }
    
    struct file *file = find_file_by_fd (fd);
    /* If there's no file with given fd, fail. */
    if (file == NULL)
    {
      f->eax = -1;
      return;
    }
    
    /* Reopen the file for an independent reference. */
    struct file *new_file = file_reopen (file);
    new_file->fd = current_thread->max_fd;
    new_file->file_name = calloc(1, strlen(file->file_name) + 1);
    strlcpy (new_file->file_name, file->file_name, strlen(file->file_name) + 1);
    lock_acquire (&current_thread->file_list_lock);
    list_push_back (&current_thread->file_list, &new_file->elem);
    current_thread->max_fd += 1;
    lock_release (&current_thread->file_list_lock);
    
    /* If target file has length 0, fail. */
    off_t file_size = file_length (new_file);
    if (file_size == 0)
    {
      f->eax = -1;
      return;
    }
    
    /* If the range of pages needed to map the file from addr overlaps
       any already mapped page, fail. */
    if (is_page_overlap (addr, file_size))
    {
      f->eax = -1;
      return;
    }
    
    /* Mmapped file should be loaded lazily, which is handled by
       supplemental page table. For here, in system call, just
       call supp_new_mapping. */
    if (!supp_new_mmap (current_thread->pagedir, addr, current_thread,
                        new_file, new_file->fd))
    {
      f->eax = -1;
      return;
    }
    
    append_mapid_list (new_file->fd);
    f->eax = new_file->fd;
  }
  
  /**************************
   *      SYS_MUNMAP        *
   *************************/
  else if (syscall_num == SYS_MUNMAP)
  {
    mapid_t mapid = *((mapid_t *) arg1);
    
    munmap_pages (mapid);
    remove_mapid_list (mapid);
  }
  /**************************
   *       SYS_CHDIR        *
   *************************/
  else if (syscall_num == SYS_CHDIR)
  {
    const char *dir = *((const char **) arg1);
    char *target_dir = get_final_dir (dir);

    char *target_dir_copy = calloc(1, strlen(target_dir) + 1);
    strlcpy(target_dir_copy, target_dir, strlen(target_dir) + 1);

    // char *target_dir_copy = palloc_get_page(0);
    // strlcpy(target_dir_copy, target_dir, PGSIZE);
    //char *target_dir_copy = palloc_get_page(0);

    //strlcpy(target_dir_copy, target_dir, PGSIZE);

    struct thread *current_thread = thread_current ();
    
    /* Parse the absolute path. */
    char *tokens[10];
    
    size_t num_token = parse_file_name (target_dir, target_dir_copy, tokens);
    
    /* If num_token is 0, it is the root directory. */
    if (num_token == 0)
    {
      strlcpy (current_thread->current_dir, "/", 2);
      f->eax = true;
    }
    else
    {
      if (!is_chdir_possible (tokens, num_token))
      {
        f->eax = false;
      }
      else
      {
        strlcpy (current_thread->current_dir, target_dir, strlen(target_dir) + 1);
        f->eax = true;
      }
      //palloc_free_page(target_dir_copy);
    }
    
    /* Free the page for the target dir. */
    // palloc_free_page (target_dir);
    // palloc_free_page(target_dir_copy);
    // free(target_dir);
    free(target_dir_copy);
  }
  /**************************
   *       SYS_MKDIR        *
   *************************/
  else if (syscall_num == SYS_MKDIR)
  {
    const char *dir = *((const char **) arg1);
    
    /* Get the absolute path. */
    char *target_dir = get_final_dir (dir);
    
    /* Try creating a directory with absolute path. */
    f->eax = filesys_create (target_dir, 0, true);
    
    /* Free the page for the target dir. */
    // palloc_free_page (target_dir);
  }
  /**************************
   *      SYS_READDIR       *
   *************************/
  else if (syscall_num == SYS_READDIR)
  {
    int fd = *((int *) arg1);
    char *name = *((char **) arg2);
    
    /* Get the file. */
    //printf("name : %s\n", name);
    struct dir *dir = find_dir_by_fd (fd);
    //printf("dir_name : %s\n", dir->dir_name);
    
    /* Get the directory. */
//    struct dir *target_dir = dir_open (dir->inode);
    
    /* Read directory. */
    // printf("current_dir : %s\n", thread_current()->current_dir);
    bool readdir_success = dir_readdir (dir, name);
    // printf("dir : %s\n", dir->dir_name);
    // printf("name[0] : %s\n", name[0]);
    // printf("name[1] : %s\n", name[1]);
    // printf("name[2] : %s\n", name[2]);
    // printf("readdir_success : %d\n", readdir_success);
    f->eax = readdir_success;
    //printf("name after readdir : %s\n", name);
    
    
    /* Close the directory. */
//    dir_close (target_dir);
  }
  /**************************
   *       SYS_ISDIR        *
   *************************/
  else if (syscall_num == SYS_ISDIR)
  {
    int fd = *((int *) arg1);
    
    struct file *file = find_file_by_fd (fd);
    struct dir *dir = find_dir_by_fd (fd);
    
    if (file == NULL && dir != NULL)
      f->eax = true;
    else
      f->eax = false;
  }
  /**************************
   *      SYS_INUMBER       *
   *************************/
  else if (syscall_num == SYS_INUMBER)
  {
    int fd = *((int *) arg1);
    
    /* Get the file. */
    struct file *file = find_file_by_fd (fd);
    struct dir *dir = find_dir_by_fd (fd);
    
    /* Return the number of inode. */
    if (file == NULL)
      f->eax = dir->inode->sector;
    else
      f->eax = file->inode->sector;
  }
  else
  {
    ;
  }
}

/* Check if the system call esp is valid. */
static bool
is_valid_esp (void *esp)
{
  for (int i = 0; i < 4; i++)
  {
    if (!is_valid_ptr (esp + i))
      return false;
  }
  return true;
}

/* Check if the system call arguments are valid.
   The num_arg should be larger than 0, which means
   that if a system call needs no argument,
   it has not to call this function. */
static bool
is_valid_args (void *esp, int num_args)
{
  ASSERT (num_args > 0);
  ASSERT (num_args <= 3);
  
  for (int i = 4; i < 4 * (num_args + 1); i++)
  {
    if (!is_valid_ptr (esp + i))
      return false;
  }
  return true;
}

/* Check if given string lies on valid address,
   considering the null character.
   If any character in given string lies on invalid
   address, return false, otherwise, return true. */
static bool
is_valid_str (char *str)
{ 
  // The str should not be a empty string.
  if (is_valid_ptr (str) && *str == '\0')
  {
    return false;
  }
  
  // Check if the string lies on valid address,
  // considering the null character.
  while (true)
  {
    if (!is_valid_ptr (str))
      return false;
    if (*str == '\0')
      return true;
    str++;
  }
}

/* Check if the given pointer is valid. */
static bool
is_valid_ptr (void *ptr)
{
  struct thread *current_thread = thread_current ();
  uint32_t *pd = current_thread -> pagedir;
  
  // Check if the given pointer is NULL.
  if (ptr == NULL)
  {
    return false;
  }
  // Check if the given pointer points to user stack.
  else if (!is_user_vaddr (ptr))
  {
    return false;
  }
  else
  {
    return true;
  }
}

/* Abnormal exit. */
void
error_exit (void)
{
  struct thread *current_thread = thread_current ();
  
  printf ("%s: exit(%d)\n", current_thread->name, -1);
  current_thread->exit_status = -1;
  sema_up(&current_thread->wait_sema);
  //sema_up (&current_thread->parent->exec_sema);

  thread_exit ();
}

/* Check if the file with given file_name is already opended
   by the current thread.
   If given file is already opened by the current thread,
   return a pointer to the file, and if not, return NULL. */
static struct file *
find_file_by_name (char *file_name)
{
  struct thread *current_thread = thread_current ();
  struct list *file_list = &(current_thread->file_list);
  struct list_elem *e;
  
  if (!list_empty (file_list))
  {
    for (e = list_begin (file_list);
         e != list_end  (file_list);
         e = list_next (e))
    {
      struct file *file_info =
        list_entry (e, struct file, elem);
      if (strcmp (file_info->file_name, file_name) == 0)
      {
        return file_info;
      }
    }
  }
  return NULL;
}

/* Check if the file with given fd is already opended
   by the current thread.
   If given file is already opened by the current thread,
   return a pointer to the file, and if not, return NULL. */
static struct file *
find_file_by_fd (int fd)
{
  struct thread *current_thread = thread_current ();
  struct list *file_list = &(current_thread->file_list);
  struct list_elem *e;

  if (!list_empty (file_list))
  {
    for (e = list_begin (file_list);
         e != list_end  (file_list);
         e = list_next (e))
    {
      struct file *file_info =
        list_entry (e, struct file, elem);
      if (file_info->fd == fd)
      {
        return file_info;
      }
    }
  }
  return NULL;
}

/* Check if the dir with given file_name is already opened
   by the current thread.
   If given dir is already opened by the current thread,
   return a pointer to the dir, and if not, return NULL. */
static struct dir *
find_dir_by_name (char *dir_name)
{
  struct thread *current_thread = thread_current ();
  struct list *dir_list = &(current_thread->dir_list);
  struct list_elem *e;

  if (!list_empty (dir_list))
  {
    for (e = list_begin (dir_list);
         e != list_end  (dir_list);
         e = list_next (e))
    {
      struct dir *dir_info =
        list_entry (e, struct dir, elem);
      if (strcmp (dir_info->dir_name, dir_name) == 0)
      {
        return dir_info;
      }
    }
  }
  return NULL;
}

/* Check if the dir with given fd is already opended
   by the current thread.
   If given dir is already opened by the current thread,
   return a pointer to the dir, and if not, return NULL. */
static struct dir *
find_dir_by_fd (int fd)
{
  //printf("find_dir_by_fd : %d\n", fd);
  struct thread *current_thread = thread_current ();
  struct list *dir_list = &(current_thread->dir_list);
  struct list_elem *e;

  if (!list_empty (dir_list))
  {
    for (e = list_begin (dir_list);
         e != list_end  (dir_list);
         e = list_next (e))
    {
      struct dir *dir_info =
        list_entry (e, struct dir, elem);
      
      if (dir_info->fd == fd)
      {
        //printf("%s\n", dir_info->dir_name);
        return dir_info;
      }
    }
  }
  return NULL;
}

static bool
find_exec_by_name (char *file_name)
{
  struct list_elem *e;
  
  if (list_empty (&exec_list))
    return false;
  
  for (e = list_begin (&exec_list);
       e != list_end (&exec_list);
       e = list_next (e))
  {
    struct thread *exec_thread =
      list_entry (e, struct thread, exec_elem);
    if (strcmp (exec_thread->name, file_name) == 0)
      return true;
  }
  return false;
}

static void
append_exit_list (struct exited_thread *t, int exit_status)
{
  struct thread *current_thread = thread_current ();
  t->tid = current_thread->tid;
  t->exit_status = exit_status;
  t->parent_tid = current_thread->parent->tid;
  list_push_back (&exit_list, &t->elem);
}

static bool
is_page_overlap (void *addr, off_t file_size)
{
  struct thread *current_thread = thread_current ();
  void *page_start = addr;
  void *page_end = pg_round_down (addr + file_size);
  
  void *page = page_start;
  while (page <= page_end)
  {
    if (supp_table_entry_lookup (current_thread->pagedir, page) != NULL)
      return true;
    page += PGSIZE;
  }
  return false;
}

static void
append_mapid_list (mapid_t mapid)
{
  struct thread *current_thread = thread_current ();
  
  struct mapid_list_entry *entry = malloc (sizeof (struct mapid_list_entry));
  entry->mapid = mapid;
  
  lock_acquire (&current_thread->mapid_list_lock);
  list_push_back (&current_thread->mapid_list, &entry->elem);
  lock_release (&current_thread->mapid_list_lock);
}

static void
remove_mapid_list (mapid_t mapid)
{
  struct thread *current_thread = thread_current ();
  struct list_elem *e;
  
  if (list_empty (&current_thread->mapid_list))
    return;
  
  lock_acquire (&current_thread->mapid_list_lock);
  e = list_begin (&current_thread->mapid_list);
  while (e != list_end (&current_thread->mapid_list))
  {
    struct mapid_list_entry *entry = list_entry (e, struct mapid_list_entry, elem);
    if (entry->mapid == mapid)
    {
      list_remove (&entry->elem);
      free (entry);
      lock_release (&current_thread->mapid_list_lock);
      return;
    }
    e = list_next (e);
  }
  
  /* Control cannot reach here. */
  lock_release (&current_thread->mapid_list_lock);
}

void
munmap_pages (mapid_t mapid)
{
  struct thread *current_thread = thread_current ();
  struct list_elem *e;
  
  lock_acquire (&current_thread->upage_list_lock);
  e = list_begin (&current_thread->upage_list);
  while (e != list_end (&current_thread->upage_list))
  {
    struct upage_list_entry *entry = list_entry (e, struct upage_list_entry, elem);
    if (entry->mapid == mapid)
    {
      supp_munmap (current_thread->pagedir, entry->upage);
      e = list_remove (e);
      free (entry);
    }
    else
    {
      e = list_next (e);
    }
  }
  lock_release (&current_thread->upage_list_lock);
}

void
munmap_all (struct thread *t)
{
  lock_acquire (&t->mapid_list_lock);
  struct list_elem *e = list_begin (&t->mapid_list);
  while (e != list_end (&t->mapid_list))
  {
    struct mapid_list_entry *entry = list_entry (e, struct mapid_list_entry, elem);
    munmap_pages (entry->mapid);
    e = list_remove (e);
    free (entry);
  }
  lock_release (&t->mapid_list_lock);
}

/* Check if the given path is relative path. */
static bool
is_relative (const char *path)
{
  if (*path == '/')
    return false;
  return true;
}

/* Get the absolute path considering
   current directory and the given path. */
static char *
parse(char *path, bool is_relative){
  
  struct thread *current_thread = thread_current ();
  char *current_dir = current_thread->current_dir;

  char *result_path = palloc_get_page (0);
  // char *path_copy = palloc_get_page (0); 
  char *path_copy = calloc(1, strlen(path) + 1);
  char *current_dir_copy = NULL; 
  char *result_path_token[10];
  char *token_path, *token_cur, *save_path, *save_cur;
  int idx = 0;

  if (is_relative){
    // current_dir_copy = palloc_get_page (0);
    current_dir_copy = calloc(1, strlen(current_dir) + 1 );
    
    strlcpy (path_copy, path, PGSIZE);
    strlcpy (current_dir_copy, current_dir, PGSIZE);
    
    /* First, tokenize the current directory and append it to result path token array. */
    for (token_cur = strtok_r (current_dir_copy, "/", &save_cur); token_cur != NULL;
        token_cur = strtok_r (NULL, "/", &save_cur))
    {
      result_path_token[idx] = token_cur;
      idx++;
    }
  }
  else{
    strlcpy (path_copy, path, PGSIZE);
  }
  
  /* And, then modify the result path token array using the given path. */
  for (token_path = strtok_r (path_copy, "/", &save_path); token_path != NULL;
       token_path = strtok_r (NULL, "/", &save_path))
  {
    if (!strcmp (token_path, "."))
    {
      continue;
    }
    else if (!strcmp (token_path, ".."))
    {
      idx--;
      result_path_token[idx] = NULL;
    }
    else
    {
      result_path_token[idx] = token_path;
      idx++;
    }
  }
  
  /* Concatenate the result path tokens. */
  int trav_idx = 0;
  strlcpy (result_path, "/", PGSIZE);
  while (trav_idx < idx)
  {
    char *token = result_path_token[trav_idx];
    strlcat (result_path, token, PGSIZE/*strlen (result_path) + strlen (token) + 1*/);
    strlcat (result_path, "/", PGSIZE/*strlen (result_path) + 2*/);
    trav_idx++;
  }
  
  /* Free the pages. */
  // palloc_free_page (path_copy);
  free(path_copy);
  if (current_dir_copy!=NULL)
    // palloc_free_page (current_dir_copy);
    free(current_dir_copy);
  
  return result_path;
}

static const char *
get_final_dir (const char *path)
{
  char *result_path;
  /* If the given path is already an absolute path, return. */
  if (!is_relative (path))
  {
    // char *result_path = palloc_get_page (0);
    result_path = parse(path, false);
    // strlcpy (result_path, path, PGSIZE);
    // return result_path;
  }
  else{
    result_path = parse(path, true);
  }
  // struct thread *current_thread = thread_current ();
  // char *current_dir = current_thread->current_dir;
  
  /* Parse the given relative path. */
  
  // char *path_copy = palloc_get_page (0);
  // char *current_dir_copy = palloc_get_page (0);
  // char *result_path_token[10];
  // char *result_path = palloc_get_page (0);
  // char *token_path, *token_cur, *save_path, *save_cur;
  // int idx = 0;
  
  // strlcpy (path_copy, path, PGSIZE);
  // strlcpy (current_dir_copy, current_dir, PGSIZE);
  
  // /* First, tokenize the current directory and append it to result path token array. */
  // for (token_cur = strtok_r (current_dir_copy, "/", &save_cur); token_cur != NULL;
  //      token_cur = strtok_r (NULL, "/", &save_cur))
  // {
  //   result_path_token[idx] = token_cur;
  //   idx++;
  // }
  
  // /* And, then modify the result path token array using the given path. */
  // for (token_path = strtok_r (path_copy, "/", &save_path); token_path != NULL;
  //      token_path = strtok_r (NULL, "/", &save_path))
  // {
  //   if (!strcmp (token_path, "."))
  //   {
  //     continue;
  //   }
  //   else if (!strcmp (token_path, ".."))
  //   {
  //     idx--;
  //     result_path_token[idx] = NULL;
  //   }
  //   else
  //   {
  //     result_path_token[idx] = token_path;
  //     idx++;
  //   }
  // }
  
  // /* Concatenate the result path tokens. */
  // int trav_idx = 0;
  // strlcpy (result_path, "/", PGSIZE);
  // while (trav_idx < idx)
  // {
  //   char *token = result_path_token[trav_idx];
  //   strlcat (result_path, token, PGSIZE/*strlen (result_path) + strlen (token) + 1*/);
  //   strlcat (result_path, "/", PGSIZE/*strlen (result_path) + 2*/);
  //   trav_idx++;
  // }
  
  // /* Free the pages. */
  // palloc_free_page (path_copy);
  // palloc_free_page (current_dir_copy);
  
  return result_path;
}

/* Check if chdir is possible. */
static bool
is_chdir_possible (char **tokens, size_t num_token)
{
  struct dir *dir_root = dir_open_root ();
  struct inode *inode_cur = NULL;
  bool is_dir;
  
  if (dir_root == NULL)
    return false;
  
  struct dir *dir_last = find_last_directory (tokens, num_token, dir_root);
  if (dir_last == NULL)
  {
    dir_close (dir_root);
    return false;
  }
  
  if (!dir_lookup (dir_last, *(tokens + num_token - 1), &inode_cur, &is_dir) || !is_dir)
  {
    dir_close (dir_last);
    return false;
  }
  
  return true;
}

/* Check if current directory of the current thread is valid.
   It may be removed. */
static bool
is_valid_chdir (void)
{
  struct thread *current_thread = thread_current ();
  char *chdir = get_final_dir (current_thread->current_dir);
  // char *chdir_copy = palloc_get_page(0);
  // strlcpy(chdir_copy, chdir, PGSIZE);
  char *chdir_copy = calloc(1, strlen(chdir) + 1);
  strlcpy(chdir_copy, chdir, strlen(chdir) + 1);
  char *tokens[10];
  size_t num_token = parse_file_name (chdir, chdir_copy, tokens);
  
  if (num_token == 0)
    return true;
  
  if (!is_chdir_possible (tokens, num_token)){
    // palloc_free_page(chdir_copy);
    free(chdir_copy);
    return false;
  }
    
  // palloc_free_page(chdir_copy);
  free(chdir_copy);
  return true;
}
