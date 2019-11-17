#ifndef USERPROG_EXCEPTION_H
#define USERPROG_EXCEPTION_H

#include <stdio.h>
#include "filesys/off_t.h"

/* Page fault error code bits that describe the cause of the exception.  */
#define PF_P 0x1    /* 0: not-present page. 1: access rights violation. */
#define PF_W 0x2    /* 0: read, 1: write. */
#define PF_U 0x4    /* 0: kernel, 1: user process. */

/* Limit of the stack growthi(8MB).
   A fault address due to the stack growth cannot be lower than
   this address. */
#define SG_LIMIT 0xbf800000

void exception_init (void);
void exception_print_stats (void);
bool lazy_load_all_zero (uint32_t *pd, void *upage, void *kpage, bool writable, struct thread *t);
bool lazy_load_read (uint32_t *pd, void *upage, void *kpage, bool writable, struct thread *t, struct file *file, off_t ofs);
#endif /* userprog/exception.h */
