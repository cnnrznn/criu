#ifndef _PJ_PICO_MAN_H
#define _PJ_PICO_MAN_H

#include "pico-page_list.h"

#include "int.h"

void
pico_crash(void);

int
pico_remote_pages(uint32_t addr, struct pico_page_list *pl, int n);

void
pico_remote_pages_fin(int);

void
migrate_soft(const char ip[15]);

#endif /* _PJ_PICO_MAN_H */
