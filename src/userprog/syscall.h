#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/synch.h"
#include "threads/thread.h"

typedef int mapid_t;

/* Lock for synchronization of file system. */
struct lock filesys_lock;

/* Write-forbidden file list.
   Elements are threads because their name are the file name. */
struct list exec_list;

/* List of normally exited thread. */
struct list exit_list;
struct lock exit_list_lock;

/* Struct of element of exit_list. */
struct exited_thread
{
  struct list_elem elem;
  tid_t tid;
  tid_t parent_tid;
  int exit_status;
};

struct mapid_list_entry
{
  struct list_elem elem;
  mapid_t mapid;
};

void syscall_init (void);
void error_exit (void);
void munmap_pages (mapid_t mapid);
void munmap_all (struct thread *t);
#endif /* userprog/syscall.h */
