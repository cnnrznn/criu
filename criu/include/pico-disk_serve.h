#ifndef _PJ_DISK_SERVE_H
#define _PJ_DISK_SERVE_H

#include "page-xfer.h"

#define DISK_SERVE_PSBUF_SIZE 1024  /* number of processes to create buffers for */

struct disk_pages {
    int pid;
    struct page_read pr;
};

extern int
disk_serve_get_pages(int sk, struct page_server_iov *pi);

extern int
disk_serve_prepare(void);

extern void
disk_serve_cleanup();

#endif /* _PJ_DISK_SERVE_H */
