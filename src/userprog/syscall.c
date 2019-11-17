#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "filesys/inode.h"
#include "devices/shutdown.h"
#include "lib/kernel/list.h"
#include "threads/synch.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "threads/malloc.h"

/* Function prototypes. */
static void syscall_handler (struct intr_frame *);
static bool is_valid_esp (void *esp);
static bool is_valid_args (void *esp, int num_args);
static bool is_valid_str (char *str);
static bool is_valid_ptr (void *ptr);
static struct file *find_file_by_name (char *file_name);
static struct file *find_file_by_fd (int fd);
static bool find_exec_by_name (char *file_name);
static void append_exit_list (struct exited_thread *t, int exit_status);

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
  if (syscall_num == SYS_HALT)
  {
    shutdown_power_off ();
  }
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
  else if (syscall_num == SYS_WAIT)
  {
    tid_t tid = *((tid_t *) arg1);
    f->eax = process_wait (tid);
  }  
  else if (syscall_num == SYS_CREATE)
  {
    char *file_name = *((char **) arg1);
    unsigned size = *((unsigned *) arg2);
    
    // Check if the file_name is valid.
    if (!is_valid_ptr(file_name))
    {
      error_exit ();
    }
    else
    {
      lock_acquire (&filesys_lock);
      f->eax = filesys_create (file_name, size);
      lock_release (&filesys_lock);
    }
  }
  else if (syscall_num == SYS_REMOVE)
  {
    char *file_name = *((char **) arg1);
    
    lock_acquire (&filesys_lock);
    f->eax = filesys_remove(file_name);
    lock_release (&filesys_lock);
  }
  else if (syscall_num == SYS_OPEN)
  {
    char *file_name = *((char **) arg1);
    struct thread *current_thread = thread_current ();
    struct file* file, *new_file;
    
    // Check if the file_name is valid.
    if (!is_valid_ptr(file_name))
    {
      error_exit ();
    }
    else
    {
      lock_acquire (&filesys_lock);
      file = find_file_by_name (file_name);
      // Check if the file is already opened by this thread.
      if (file == NULL)
      {
        new_file = filesys_open (file_name);
        // There's no such file.
        if (new_file == NULL)
        {
          f->eax = -1;
        }
        // This is the initial open.
        else
        {
          new_file->fd = current_thread->max_fd;
          new_file->file_name = file_name;
          list_push_back (&current_thread->file_list,
                          &new_file->elem);
          current_thread->max_fd += 1;
          f->eax = new_file->fd;
        }
      }
      // This file is already opened by this thread.
      else
      {
        new_file = file_reopen (file);
        new_file->fd = current_thread->max_fd;
        new_file->file_name = file_name;
        list_push_back (&current_thread->file_list,
                        &new_file->elem);
        current_thread->max_fd += 1;
        f->eax = new_file->fd;
      }
      lock_release (&filesys_lock);
    }
  }
  else if (syscall_num == SYS_FILESIZE)
  {
    int fd = *((int *) arg1);
    
    lock_acquire (&filesys_lock);
    struct file *file = find_file_by_fd (fd);
    
    if (file == NULL)
    {
      f->eax = -1;
    }
    else
    {
      f->eax = file_length (file);
    }
    lock_release (&filesys_lock);
  }
  else if (syscall_num == SYS_READ)
  {
    int fd = *((int *) arg1);
    void *buffer = *((void **) arg2);
    unsigned size = *((unsigned *) arg3);
    
    // Check if the given buffer is valid.
    if (!is_valid_ptr (buffer))
    {
      error_exit ();
    }
    
    lock_acquire (&filesys_lock);
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
    lock_release (&filesys_lock);
  }
  else if (syscall_num == SYS_WRITE)
  {
    int fd = *((int *) arg1);
    void *buffer = *((void **) arg2);
    unsigned size = *((unsigned *) arg3);
    
    // Check if given buffer is valid.
    if (!is_valid_ptr (buffer))
    {
      error_exit ();
    }
    
    lock_acquire (&filesys_lock);
    if (fd == 1)
    {
      putbuf (buffer, size);
    }
    else
    {
      struct file *file = find_file_by_fd (fd);
      if (file == NULL)
      {
        f->eax = 0;
      }
      else
      {
        // Check if given file is running.
        if (find_exec_by_name (file->file_name))
        {
          f->eax = 0;
        }
        else
        {
          f->eax = file_write (file, buffer, size);
        }
      }
    }
    lock_release (&filesys_lock);
  }
  else if (syscall_num == SYS_SEEK)
  {
    int fd = *((int *) arg1);
    unsigned pos = *((unsigned *) arg2);
    
    struct file *file = find_file_by_fd (fd);
    if (file != NULL)
      file_seek (file, pos);
  }
  else if (syscall_num == SYS_TELL)
  {
    int fd = *((int *) arg1);
    
    struct file *file = find_file_by_fd (fd);
    if (file != NULL)
      f->eax = file_tell (file);
    else
      f->eax = -1;
  }
  else if (syscall_num == SYS_CLOSE)
  {
    int fd = *((int *) arg1);
    
    struct file *file = find_file_by_fd (fd);
    struct thread *current_thread = thread_current ();
    
    if (file != NULL)
    {
      lock_acquire (&current_thread->file_list_lock);
      list_remove (&file->elem);
      lock_release (&current_thread->file_list_lock);
      
      lock_acquire (&filesys_lock);
      file_close (file);
      lock_release (&filesys_lock);
    }
  }
  else{
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
  // Check if the given pointer points to mapped section.
  /*else if (pagedir_get_page(pd, ptr) == NULL)
  {
    return false;
  }*/
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
