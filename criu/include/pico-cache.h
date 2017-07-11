#ifndef _PJ_CACHE_H
#define _PJ_CACHE_H

#include <stdbool.h>

#include "page-pipe.h"
#include "page-xfer.h"

extern int
pico_page_xfer_dump_pages(struct page_xfer *, struct page_pipe *,
				unsigned long off, bool dump_lazy);

extern void
pico_reset_page_read();

extern int
pico_dump_end_cached_pagemaps(struct page_xfer *);

#endif /* _PJ_CACHE_H */
