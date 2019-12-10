#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "userprog/syscall.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "vm/frame.h"
#include "vm/page.h"

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);
static struct thread *find_thread (tid_t tid);
static int find_exited_thread (tid_t tid);
static void file_all_close (void);
static void free_child_info (void);

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
  char *fn_copy;
  tid_t tid;
  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);
  
  /* Parse the file_name with the space as a delimeter. */
  size_t len_file_name = strlen(fn_copy) + 1;
  char *fn_pointer;
  int count = 0;
  
  for (fn_pointer = fn_copy;
       count < len_file_name;
       fn_pointer++)
  {
    if (*fn_pointer == ' ')
    {
      *fn_pointer = '\0';
    }
    count++;
  }
  *fn_pointer = 3;		// End of text(file_name).
  
  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (fn_copy, PRI_DEFAULT, start_process, fn_copy);
  if (tid == TID_ERROR)
    palloc_free_page (fn_copy);
  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *file_name_)
{
  char *file_name = file_name_;
  struct intr_frame if_;
  bool success;
  struct thread *current_thread = thread_current ();
  struct thread *parent = current_thread->parent;
  
  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  
  /* The load accesses to file system which is critical section. */
  success = load (file_name, &if_.eip, &if_.esp);
  
  /* If load failed, inform to parent, and quit. */
  if (!success)
  {
    parent->load_success = false;
    palloc_free_page (file_name);
    error_exit ();
  }
  
  /* If load succeed, inform to parent. */
  parent->load_success = true;
  //sema_up (&parent->exec_sema);
  
  /* Push parsed arguments into the user stack. */
  void *esp = if_.esp;
  char *arg_string;
  char *arg_pointers[100];
  int argc;
  size_t arg_len_sum;			// For word alignment.
  
  arg_string = file_name;
  argc = 0;
  arg_len_sum = 0;
  
  while (*arg_string != 3)
  {
    // Check if arg_string is null_character,
    // because there could be more than 1 delimeters in file_name.
    if (*arg_string == '\0')
    {
      arg_string += 1;
    }
    else
    {
      // Consider the null character when calculate the string length.
      size_t arg_len = strlen(arg_string) + 1;
      esp -= arg_len;
      strlcpy((char *) esp, arg_string, arg_len);
      arg_pointers[argc] = esp;
      argc++;
      arg_string += arg_len;
      arg_len_sum += arg_len;
    }
  }
  arg_pointers[argc] = 0;
  
  /* Push a word alignment values into the user stack. */
  if (arg_len_sum % 4 != 0)
  {
    size_t remainder = arg_len_sum % 4;
    esp -= remainder; 
  }
  
  /* Push pointers to pre-pushed arguments into the user stack. */
  esp -= sizeof(char *);
  char **pos_arg_pointer;
  
  for (int i = argc; i >= 0; i--)
  {
    pos_arg_pointer = esp;
    char *arg_pointer = arg_pointers[i];
    *pos_arg_pointer = arg_pointer;
    esp -= sizeof(char *);
  }
  char ***argv_pointer = esp;
  *argv_pointer = pos_arg_pointer;
  
  /* Push the argc into the user stack. */
  esp -= sizeof(int);
  int *pos_argc = esp;
  *pos_argc = argc;
  
  /* Push a fake return address into the user stack. */
  esp -= sizeof(void *);
  void **pos_ret_addr = esp;
  *pos_ret_addr = 0;
  
  if_.esp = esp;
  
  palloc_free_page (file_name);
  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid) 
{
  struct thread *current_thread = thread_current ();
  int exit_status;
  
  lock_acquire (&current_thread->child_list_lock);
  struct thread *child_thread = find_thread (child_tid);
  lock_release (&current_thread->child_list_lock);
  
  /* There're five cases:
       1. child_tid is not a tid of child thread.
       2. Child thread already exited normally.
       3. Child thread already exited by kernel.
       4. child_tid is invalid.
       5. This thread(parent) already waited the child_thread.*/
  if (child_thread == NULL)
  {
    lock_acquire (&exit_list_lock);
    exit_status = find_exited_thread (child_tid);
    lock_release (&exit_list_lock);
    
    return exit_status;
  }
  /* There's only one case:
       1. Child thread not exited yet.
     But it can exit either normally or abnormally. */
  else
  {
    /* Wait for the wait_lock of the child thread:
         1. The wait_lock will be released if child terminates.
         2. We can ensure that the information of child thread
            is inserted into the exit_list. */
    sema_down(&child_thread->wait_sema);
    
    lock_acquire (&exit_list_lock);
    exit_status = find_exited_thread (child_tid);
    lock_release (&exit_list_lock);
    
    return exit_status;
  }
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  struct thread *parent = cur->parent;
  uint32_t *pd;
  
  /************************************************/
  /* This thread is a child thread of one thread. */
  /************************************************/
  
  /* Remove this thread from child_list. */
  lock_acquire (&cur->parent->child_list_lock);
  if (!cur->removed)
  {
    list_remove (&cur->celem);
  }
  lock_release (&cur->parent->child_list_lock);
  
  /************************************************/
  
  /* Munmap all before file_all_close. */
  munmap_all (cur);
  
  /* Close all the opened file by this thread.
     First check if the current thread is  already
     holding filesys lock. It is possible if this
     exit is due to page fault during file read. */
  //if (lock_held_by_current_thread (&filesys_lock))
  //  lock_release (&filesys_lock);
  file_all_close ();
  
  /************************************************/
  
  /*************************************************/
  /* This thread is a parent thread of one thread. */
  /*************************************************/
  
  /* Free the allocated 'exited_thread' struct. */
  lock_acquire (&cur->child_list_lock);
  lock_acquire (&exit_list_lock);
  free_child_info ();
  lock_release (&exit_list_lock);
  lock_release (&cur->child_list_lock);
  
  /************************************************/
  
  /************************************************/
  /* This thread is a child thread of one thread. */
  /************************************************/
  
  /* If a exec fails to load, wake up its parent. */
  sema_up (&parent->exec_sema);
  
  /************************************************/
  
  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      supp_free_all (pd, cur);
      //pagedir_destroy (pd);
    }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* Find a thread with given tid in current thread's
   child list. Return NULL if there's no such child.
   
   Caution: If a child thread of the current thread
            already exited normally, this function
            returns NULL.
            Thus a caller of this function should
            consider that.*/
static struct thread *
find_thread (tid_t tid)
{
  struct thread *current_thread = thread_current ();
  struct list *child_list = &current_thread->child_list;
  struct list_elem *e;
  
  if (list_empty (child_list))
    return NULL;
  
  for (e = list_begin (child_list);
       e != list_end (child_list);
       e = list_next (e))
  {
    struct thread *child =
      list_entry (e, struct thread, celem);
    if (child->tid == tid)
    {
      // Remove if the thread is found.
      list_remove (&child->celem);
      child->removed = true;	// Avoid double removing which is an undefined.
      return child;
    }
  }
  return NULL;
}

/* Find a exit_status information of exited thread
   with given tid.
   If there's no such thread, return -1. */
static int
find_exited_thread (tid_t tid)
{
  struct list_elem *e;
  
  if (list_empty (&exit_list))
    return -1;
  
  for (e = list_begin (&exit_list);
       e != list_end (&exit_list);
       e = list_next (e))
  {
    struct exited_thread *t =
      list_entry (e, struct exited_thread, elem);
    if (t->tid == tid)
    {
      // Remove if the exited thread is found.
      // -1 will be returned for later looking up.
      list_remove (&t->elem);
      int exit_status = t->exit_status;
      
      // Free the t which is allocated by malloc.
      free (t);
      return exit_status;
    }
  }
  return -1;
}

static void
file_all_close (void)
{
  struct thread *current_thread = thread_current ();
  struct list *file_list = &current_thread->file_list;
  struct list_elem *e;
  
  if (list_empty (file_list))
    return;
  
  e = list_begin (file_list);
  while (e != list_end (file_list))
  {
    struct file *file = list_entry (e, struct file, elem);
    e = list_remove (&file->elem);
    //lock_acquire (&filesys_lock);
    file_close (file);
    //lock_release (&filesys_lock);
  }
}

/* Free all the child info of the current thread.
   Set child->removed true to avoid double removing of
   elements of current_thread's child_list, and
   set child->parent_exited true to avoid malloc of
   children who are not exited yet. */
static void
free_child_info (void)
{
  struct thread *current_thread = thread_current ();
  struct list *child_list = &current_thread->child_list;
  struct list_elem *e1, *e2;
  
  if (list_empty (&exit_list) || list_empty (child_list))
  {
    return;
  }
  
  /* Set child->removed true to avoid double removing.
     Set child->parent_exited true to make children who
       are not exited yet do not allocate
       struct exited_thread. */
  e1 = list_begin (child_list);
  while (e1 != list_end (child_list))
  {
    struct thread *child =
      list_entry (e1, struct thread, celem);
    
    child->removed = true;
    child->parent_exited = true;
    e1 = list_next (e1);
  }
  
  /* Free all the struct exited_thread of  already exited children
     to avoid memory leak. */
  e2 = list_begin (&exit_list);
  while (e2 != list_end (&exit_list))
  {
    struct exited_thread *t =
      list_entry (e2, struct exited_thread, elem);
    if (t->parent_tid == current_thread->tid)
    {
      e2 = list_remove (&t->elem);
      free (t);
    }
    else
    {
      e2 = list_next (e2);
    }
  }
}


/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  /* Open executable file. */
  //lock_acquire (&filesys_lock);
  file = filesys_open (file_name);
  //lock_release (&filesys_lock);
  
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }
  
  /* If the file exists, append it to the threads's file list,
     and deny any write during execution. */
  file->file_name = file_name;
  lock_acquire (&t->file_list_lock);
  list_push_back (&t->file_list, &file->elem);
  lock_release (&t->file_list_lock);
  //lock_acquire (&filesys_lock);
  file_deny_write (file);
  //lock_release (&filesys_lock);
  
  /* Read and verify executable header. */
  //lock_acquire (&filesys_lock);
  off_t ehdr_read_size = file_read (file, &ehdr, sizeof ehdr);
  //lock_release (&filesys_lock);
  
  if (ehdr_read_size != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      
      //lock_acquire (&filesys_lock);
      file_seek (file, file_ofs);
      //lock_release (&filesys_lock);
      
      //lock_acquire (&filesys_lock);
      off_t phdr_read_size = file_read (file, &phdr, sizeof phdr);
      //lock_release (&filesys_lock);
      
      if (phdr_read_size != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable, enum palloc_flags);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);
  
  struct thread *current_thread = thread_current ();
  
  //lock_acquire (&filesys_lock);
  file_seek (file, ofs);
  //lock_release (&filesys_lock);
  
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;
      
      /* If neither page_read_bytes nor page_zero_bytes is 0,
         do not load lazily.
         Thus, load that page directly. */
      if (page_read_bytes != 0 && page_zero_bytes != 0)
      {
        /* Get a page of memory. */
        uint8_t *kpage = frame_obtain (PAL_USER);
        if (kpage == NULL)
          return false;
        
        /* Load this page. */
        //lock_acquire (&filesys_lock);
        off_t kpage_read_size = file_read (file, kpage, page_read_bytes);
        //lock_release (&filesys_lock);
        
        if (kpage_read_size != (int) page_read_bytes)
        {
          palloc_free_page (kpage);
          return false; 
        }
        memset (kpage + page_read_bytes, 0, page_zero_bytes);
        
        /* Add the page to the process's address space. */
        if (!install_page (upage, kpage, writable, PAL_USER)) 
          {
            palloc_free_page (kpage);
            return false; 
          }
      }
      /* If either page_read_bytes or page_zero_bytes is 0,
         load lazily, which means that no frame_obtain is required.
         The required informations to store differ for two
         cases. */
      else
      {
        if (page_read_bytes == 0)
        {
          /* Because this page will be all zero when
             loaded after by page fault handler, just
             store some minimal information. */
          supp_new_mapping (current_thread->pagedir,
                            upage, NULL, writable,
                            current_thread, PAL_USER,
                            MODE_LAZY, true, NULL, 0, 0, -1);
        }
        else
        {
          /* Because this page should be filled with
             read bytes from file, store the needed
             information to load later. */
          //lock_acquire (&filesys_lock);
          off_t ofs_now = file_tell (file);
          //lock_release (&filesys_lock);
          supp_new_mapping (current_thread->pagedir,
                            upage, NULL, writable,
                            current_thread, PAL_USER,
                            MODE_LAZY, false, file, ofs_now, 0, -1);
          /* Because there's no file read in this part,
             due to the lazy loading, we should update
             file's position by ourselves. */
          //lock_acquire (&filesys_lock);
          file_seek (file, ofs_now + PGSIZE);
          //lock_release (&filesys_lock);
        }
      }
      
      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp) 
{
  struct thread *current_thread = thread_current ();
  uint8_t *kpage;
  bool success = false;

  kpage = frame_obtain (PAL_USER | PAL_ZERO);
  if (kpage != NULL) 
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true, PAL_USER | PAL_ZERO);
      if (success)
      {
        *esp = PHYS_BASE;
        current_thread->stack_bound = PHYS_BASE - PGSIZE;
      }
      else
        palloc_free_page (kpage);
    }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable, enum palloc_flags flags)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && supp_new_mapping (t->pagedir, upage, kpage,
                               writable, t, flags,
                               MODE_MEMORY, false, NULL, 0, 0, -1));
}
