#ifndef _PJ_RESTORE_H
#define _PJ_RESTORE_H

#include "pagemap.h"

typedef struct page_server_t {
    uint32_t addr;
    int sk;
} page_server;

extern void *pico_uffd_buf;

extern int
pico_get_remote_pages(struct page_read *, long unsigned, int, void *);

extern int
pico_disconn_page_servers(void);

#endif /* _PJ_RESTORE_H */
