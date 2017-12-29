#include "pico-disk_serve.h"

#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#include "array.h"
#include "binsearch.h"
#include "criu-log.h"
#include "cr_options.h"
#include "image.h"
#include "images/pstree.pb-c.h"
#include "pagemap.h"
#include "page-xfer.h"
#include "protobuf.h"
#include "quicksort.h"

#include "pico-util.h"

#define MIN(a, b) a < b ? a : b;

static struct disk_pages **dpgs;
static int dpgs_index = 0;
static array dpgs_arr;

static inline int
send_psi(int sk, u32 cmd, u32 nr_pages, u64 vaddr, u64 dst_id)
{
	struct page_server_iov pi = {
		.cmd		= cmd,
		.nr_pages	= nr_pages,
		.vaddr		= vaddr,
		.dst_id		= dst_id,
	};

	if (write(sk, &pi, sizeof(pi)) != sizeof(pi)) {
		pr_perror("Can't write PSI %d to server", cmd);
		return -1;
	}

	return 0;
}

static char
comp_disk_pages(void *a, void *b)
{
    struct disk_pages *x = a;
    struct disk_pages *y = b;

    if (x->pid < y->pid)
        return 1;
    else if (x->pid > y->pid)
        return -1;
    else
        return 0;
}

int
disk_serve_prepare(void)
{
    int i;
    int ret = 0;
    struct cr_img *img;

    dpgs = malloc(DISK_SERVE_PSBUF_SIZE * sizeof(struct disk_pages *));

    if (opts.pico_cache) {
        int dfd = open(opts.pico_cache, O_RDONLY);
        img = open_image_at(dfd, CR_FD_PSTREE, O_RSTR);
        close(dfd);
    }
    else {
        img = open_image(CR_FD_PSTREE, O_RSTR);
    }
    if (!img)
        return -1;

    while (1) {
        PstreeEntry *e;

        ret = pb_read_one_eof(img, &e, PB_PSTREE);
        if (ret <= 0)
            break;

        //pr_debug("CONNOR: Found pid: %u\n", e->pid);

        dpgs[dpgs_index] = malloc(sizeof(struct disk_pages));
        dpgs[dpgs_index]->pid = e->pid;
        open_page_read(e->pid, &dpgs[dpgs_index]->pr, PR_TASK);

        dpgs_index++;

        pstree_entry__free_unpacked(e, NULL);
    }

    // sort array for O(ln) lookup of pid
    array_init(&dpgs_arr, dpgs_index, comp_disk_pages);
    for (i=0; i<dpgs_index; i++)
        dpgs_arr.elems[i] = dpgs[i];
    quicksort(0, dpgs_index-1, &dpgs_arr);

    close_image(img);

    return 0;
}

void
disk_serve_cleanup(void)
{
    int i;
    for (i=0; i<dpgs_index; i++) {
        dpgs[i]->pr.close(&dpgs[i]->pr);
        free(dpgs[i]);
    }
    free(dpgs);
    array_free(&dpgs_arr);
}

int
disk_serve_get_pages(int sk, struct page_server_iov *pi)
{
    int ret = 0;
    struct disk_pages other, *dps;
    other.pid = pi->dst_id;
    void *buf = malloc(pi->nr_pages * PAGE_SIZE);
    int nr_sent = 0;

    dps = binsearch(&dpgs_arr, &other, 0, dpgs_index-1);

    dps->pr.reset(&dps->pr);
    dps->pr.seek_pagemap(&dps->pr, pi->vaddr);
    dps->pr.skip_pages(&dps->pr, pi->vaddr > dps->pr.cvaddr ? pi->vaddr - dps->pr.cvaddr : 0);
    //dps->pr.skip_pages(&dps->pr, pi->vaddr - dps->pr.pe->vaddr);

    //pr_debug("CONNOR: seeked to pagemap 0x%lx\n", dps->pr.cvaddr);

    //dps->pr.read_pages(&dps->pr, pi->vaddr, pi->nr_pages, buf, 0);
    //pr_debug("CONNOR: read %d pages starting at %lx into buffer\n", pi->nr_pages, (long unsigned)pi->vaddr);

    pr_debug("CONNOR: time before page write\n");
    while (nr_sent < pi->nr_pages) {
        unsigned long start = dps->pr.cvaddr;
        unsigned long end = MIN(dps->pr.pe->vaddr + (dps->pr.pe->nr_pages * PAGE_SIZE),
                                    dps->pr.cvaddr + ((pi->nr_pages - nr_sent) * PAGE_SIZE));
        if (pagemap_contains_addr(dps->pr.pe->n_addrs, dps->pr.pe->addrs, opts.pico_addr.s_addr) &&
                dps->pr.pe->flags & PE_LAZY) {
            dps->pr.read_pages(&dps->pr, dps->pr.cvaddr, (end - dps->pr.cvaddr)/PAGE_SIZE, buf, 0);
            if (write(sk, buf, (end - start)) != (end - start)) {
                ret = -1;
                pr_err("CONNOR: failed to serve disk pages\n");
                goto out;
            }
            nr_sent += (end - start) / PAGE_SIZE;
        }
        else {
            dps->pr.skip_pages(&dps->pr, end - dps->pr.cvaddr);
        }
        dps->pr.advance(&dps->pr);
    }
    pr_debug("CONNOR: time after page write\n");

    // flush socket buffer
    tcp_nodelay(sk, true);

    /*pr_debug("CONNOR: disk-serve raw page data (%lu):\n", pi->nr_pages * PAGE_SIZE);
    pr_debug("====================\n");
    int logfd = log_get_fd();
    int foo = write(logfd, buf, pi->nr_pages * PAGE_SIZE);
    if (foo < pi->nr_pages * PAGE_SIZE)
        pr_debug("CONNOR: foo\n");
    pr_debug("\n====================\n");*/

    pr_debug("\n");

out:
    free(buf);

    return ret;
}
