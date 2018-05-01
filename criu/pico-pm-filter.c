/*
 * Make the 'minimal checkpoint'.
 * Create new pagemap/pages files with lazy pages removed.
 *
 * @pid
 *      VPID of process
 *
 * @return
 *      0: success
 *      1: failure
 */

#include "pico-pm-filter.h"

#include "stdio.h"
#include "image.h"
#include "image-desc.h"
#include "page-xfer.h"
#include "pagemap.h"
#include "pico-man.h"
#include "stdlib.h"
#include "unistd.h"

#define BUFSIZE 1024 * PAGE_SIZE

unsigned long *
populate_wslist(int pid, int *wsn)
{
        unsigned long *ws_list;
        char fn[20] = { 0 };

        sprintf(fn, "/tmp/ws.%d", pid);

        FILE *f = fopen(fn, "r");

        // read number of elements, allocate mem
        size_t i;
        fscanf(f, "%d", wsn);
        ws_list = malloc(*wsn * sizeof(unsigned long));

        // read elements
        for (i=0; i<*wsn; i++) {
                fscanf(f, "%lu", &ws_list[i]);
        }

        fclose(f);

        return ws_list;
}

static void
free_wslist(unsigned long *ws_list)
{
    free(ws_list);
}

static char
next_ws_iov(struct iovec *iov, int *index, size_t n, unsigned long *ws_list, unsigned long limit)
{
        if (n <= 0) {
                iov->iov_len = (void*)limit - iov->iov_base;
                return 0;
        }

    // scan to first address in iov
    while (*index < n-1 &&
            (void*)ws_list[*index] < iov->iov_base)
        (*index)++;

    // working set page is not in bounds
    if ((void*)ws_list[*index] < iov->iov_base ||
            ws_list[*index] >= limit) {
        iov->iov_len = (void*)limit - iov->iov_base;
        return 0;
    }

    // next working set page is ahead in bounds
    if ((void*)ws_list[*index] > iov->iov_base) {
        iov->iov_len = (void*)ws_list[*index] - iov->iov_base;
        return 0;
    }

    // increment iov_len by 4096 for all consecutive pages
    iov->iov_len = 0;
    while (ws_list[*index] < limit &&
            (void*)ws_list[*index] == iov->iov_base + iov->iov_len) {
        iov->iov_len += PAGE_SIZE;
        (*index)++;
    }

    return 1;
}

int
pico_pm_filter(int pid)
{
        int ret;
        struct page_read pr;
        struct page_xfer xfer = { .parent = NULL };
        struct iovec iov;
        char *buf = malloc(BUFSIZE);
        int pe_flags = 0;
        int wsi = 0;
        int wsn;
        struct iovec wsiov;
        unsigned long *wslist = populate_wslist(pid, &wsn);
        char in_ws;

        // page reader object for 'full' pagemap/pages
        ret = open_page_read(pid, &pr, PR_TASK);
        if (ret <= 0)
                goto err;

        // page writer object for 'minimal' pagemap/pages
        ret = open_page_xfer(&xfer, CR_FD_META_PAGEMAP, pid, true);
        if (ret)
                goto err_xfer;

        // TODO
        // just make copy of pagemap/pages for testing
        pr.reset(&pr);
        while (pr.advance(&pr)) {
                iov.iov_base = (void*) pr.cvaddr;
                iov.iov_len  = pr.pe->nr_pages * PAGE_SIZE;

                // walk through next iov's
                wsiov.iov_base = iov.iov_base;

                while (wsiov.iov_base < iov.iov_base + iov.iov_len) {
                        in_ws = next_ws_iov(&wsiov, &wsi, wsn, wslist,
                                        (unsigned long)iov.iov_base + iov.iov_len);
                        //in_ws = 1;

                        if (pr.pe->flags == PE_PRESENT) {       // must dump
                                pe_flags = PE_PRESENT;
                                pr.read_pages(&pr, (unsigned long)wsiov.iov_base,
                                                wsiov.iov_len / PAGE_SIZE,
                                                buf, 0);
                                if (write(img_raw_fd(xfer.pi), buf, wsiov.iov_len) !=
                                                wsiov.iov_len) {
                                        pr_err("CONNOR: problem with writing pages\n");
                                        goto err_all;
                                }
                        }
                        else if (pr.pe->flags & PE_PRESENT) {   // dump if in_ws
                                if (in_ws) {
                                        pr.read_pages(&pr, (unsigned long)wsiov.iov_base,
                                                        wsiov.iov_len / PAGE_SIZE,
                                                        buf, 0);
                                        // send activeset to manager
                                        activeset_append(wsiov, buf);
                                }
                                else {
                                        pr.skip_pages(&pr, wsiov.iov_len);
                                }

                                pe_flags = PE_LAZY;
                        }
                        else if (pr.pe->flags == PE_LAZY) {     // just copy pagemap
                                pe_flags = PE_LAZY;
                                pr.skip_pages(&pr, wsiov.iov_len);
                        }
                        else {
                                // error
                                pr_debug("CONNOR: fatal\n");
                                goto err_all;
                        }

                        if (xfer.write_pagemap(&xfer, &wsiov, pe_flags, pr.pe->version,
                                                pr.pe->n_addrs, pr.pe->addrs, pr.pe->port))
                                goto err_all;

                        wsiov.iov_base += wsiov.iov_len;
                }
        }

        // cleanup
        free(buf);
        free_wslist(wslist);
        pr.close(&pr);
        xfer.close(&xfer);

        return 0;

err_all:
        xfer.close(&xfer);
err_xfer:
        pr.close(&pr);
err:
        free(buf);
        free_wslist(wslist);

        pr_debug("CONNOR: error in %s:%d\n", __FILE__, __LINE__);

        return 1;
}
