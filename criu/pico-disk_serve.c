#include "pico-disk_serve.h"

#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#include "array.h"
#include "binsearch.h"
#include "cr_options.h"
#include "image.h"
#include "images/pstree.pb-c.h"
#include "pagemap.h"
#include "page-xfer.h"
#include "protobuf.h"
#include "quicksort.h"

static struct disk_pages **dpgs;
static int dpgs_index = 0;
static array dpgs_arr;

static inline int send_psi(int sk, u32 cmd, u32 nr_pages, u64 vaddr, u64 dst_id)
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

        //printf("Found pid: %d\n", e->pid);

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

    dps = binsearch(&dpgs_arr, &other, 0, dpgs_arr.size-1);
    pr_debug("CONNOR: binsearch success!\n");

    dps->pr.reset(&dps->pr);
    dps->pr.seek_pagemap(&dps->pr, pi->vaddr);

    dps->pr.read_pages(&dps->pr, pi->vaddr, pi->nr_pages, buf, 0);
    pr_debug("CONNOR: read %d pages starting at %lx into buffer\n", pi->nr_pages, (long unsigned)pi->vaddr);

    ret = send_psi(sk, PS_IOV_ADD, pi->nr_pages, dps->pr.pe->vaddr, pi->dst_id);
    if (ret)
        goto out;
    pr_debug("CONNOR: send_psi success!\n");

    if (write(sk, buf, pi->nr_pages * PAGE_SIZE) != pi->nr_pages*PAGE_SIZE) {
        ret = 1;
        goto out;
    }
    pr_debug("CONNOR: wrote %d pages to sk\n", pi->nr_pages);
    pr_debug("CONNOR: vaddr: %lx\n", (long unsigned)pi->vaddr);
    pr_debug("CONNOR: pid: %lu\n", pi->dst_id);
    pr_debug("\n");

out:
    free(buf);
    if (ret)
        return -1;
    return 0;
}
