#ifndef _PJ_RESTORE_H
#define _PJ_RESTORE_H

#include "pagemap.h"

typedef struct page_server_t {
    uint32_t addr;
    int sk;
} page_server;

extern int
pico_select_page_server(struct page_read *, long unsigned);

#endif /* _PJ_RESTORE_H */
