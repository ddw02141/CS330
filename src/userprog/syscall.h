#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/synch.h"
#include "threads/thread.h"

/* Semaphore for parent thread to wait child's load. */
struct semaphore exec_sema;

/* Lock for synchronization of file system. */
struct lock filesys_lock;

/* Write-forbidden file list.
   Elements are threads because their name are the file name. */
struct list exec_list;

/* List of normally exited thread. */
struct list norm_exit_list;

/* Struct of element of norm_exit_list. */
struct exited_thread
{
  struct list_elem elem;
  tid_t tid;
  int exit_status;
};

void syscall_init (void);
void error_exit (void);

#endif /* userprog/syscall.h */
