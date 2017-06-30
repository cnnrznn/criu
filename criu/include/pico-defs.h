#ifndef _CR_PICO_DEFS_H
#define _CR_PICO_DEFS_H

#include "array.h"

#define PICO_PINNED_FD -3 /* the file descriptor was pinned on a different machine */

extern void pico_dump_cache_inet_sks(array*, int*, int,
                struct pstree_item *, struct cr_img *);

extern char comp_fds(void*, void*);
extern char comp_InetSkEntry(void*, void*);

extern struct file_desc_ops pico_inet_desc_ops;
extern struct fdtype_ops pico_inet_dump_ops;

struct pico_page_list {
    unsigned long addr;
    unsigned long size;
    struct pico_page_list *next;
};

#endif /* _CR_PICO_DEFS_H */
