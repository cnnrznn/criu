#ifndef _PF_INET_SK_H
#define _PF_INET_SK_H

#include "array.h"

#define PICO_PINNED_FD -3 /* the file descriptor was pinned on a different machine */

extern void pico_dump_cache_inet_sks(array*, int*, int,
                    struct pstree_item *, struct cr_img *);

extern char comp_fds(void*, void*);
extern char comp_InetSkEntry(void*, void*);

extern struct file_desc_ops pico_inet_desc_ops;
extern struct fdtype_ops pico_inet_dump_ops;

#endif /* _PF_INET_SK_H */
