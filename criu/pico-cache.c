#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "pico-cache.h"

#include "cr_options.h"
#include "page-xfer.h"
#include "vma.h"

#define MIN(a, b) a < b ? a : b;

static struct page_read pr = { 0 };
static struct iovec ciov;
static int page_read_set = 0;

static void
pico_reset_page_read()
{
    /*
     * In between full and lazy dump,
     * reset the page reader for the cache
     */

    pr.reset(&pr);
    pr.advance(&pr);
    ciov.iov_base = (void*)pr.pe->vaddr;
    ciov.iov_len = pr.pe->nr_pages * PAGE_SIZE;
}

int
pico_page_xfer_dump_pages(struct page_xfer *xfer, struct page_pipe *pp,
			 unsigned long off, bool dump_lazy)
{
    struct page_pipe_buf *ppb;
    unsigned int cur_hole = 0;
    int ret;

    struct iovec tmpiov, vmaiov;
    vmaiov.iov_base = NULL;
    struct vma_area *vma = NULL;
    int dfd = -1;
    long version = 0;
    const uint32_t maddr = opts.pico_addr.s_addr;
    uint32_t addr = maddr;
    const uint32_t mport = opts.pico_port;
    uint32_t port = mport;

    if (opts.pico_cache && !page_read_set) {
        page_read_set = 1;
        // 1. open pico-cache dirfd for open_page_read_at
        dfd = open(opts.pico_cache, O_RDONLY);
        // 2. open pagemap image for cached pagemap
        ret = open_page_read_at(dfd, xfer->pid, &pr, PR_TASK);
        if (ret <= 0)
            return -1;
        close(dfd);
        pico_reset_page_read();
    }
    if (opts.pico_cache) {
        vma = list_entry(xfer->vma_area_list->h.next, typeof(*vma), list);
        vmaiov.iov_base = (void*)vma->e->start;
    }

    pr_debug("Transferring pages:\n");

    list_for_each_entry(ppb, &pp->bufs, l) {
        unsigned int i;

        pr_debug("\tbuf %d/%d\n", ppb->pages_in, ppb->nr_segs);

        for (i = 0; i < ppb->nr_segs; i++) {
            struct iovec iov = ppb->iov[i];
            u32 flags = PE_PRESENT;

            ret = dump_holes(xfer, pp, &cur_hole, iov.iov_base, off);
            if (ret)
                return ret;

            BUG_ON(iov.iov_base < (void *)off);
            iov.iov_base -= off;
            pr_debug("\tp %p [%u]\n", iov.iov_base,
                    (unsigned int)(iov.iov_len / PAGE_SIZE));

            if (opts.pico_cache) {
                /*
                * 1. dump all complete cached pmes/pages (unless lazy) until next present region
                * 2. dump partial cached region before present region (if exists)
                * 3. alternate dumping new regions and overlapping regions
                When they overlap, use appropriate version# and addr. Increment page_read appropriately
                When new, verion#=0, addr and port are current interface
                */
                void *end;

                //pr_debug("CONNOR: dumping cached pagemaps\n");

                while ((void*)pr.cvaddr < iov.iov_base) {
                    // find the bounds of the unloaded pme
                    end = MIN(ciov.iov_base + ciov.iov_len, iov.iov_base);
                    tmpiov.iov_base = (void*)pr.cvaddr;
                    tmpiov.iov_len = end - tmpiov.iov_base;

                    // find the first vma <= bounds
                    while (vmaiov.iov_base < tmpiov.iov_base) {
                        if ((void*)vma->e->end <= tmpiov.iov_base) {
                            vma = list_entry(vma->list.next, typeof(*vma), list);
                            vmaiov.iov_base = (void*)vma->e->start;
                        }
                        else {
                            vmaiov.iov_base = tmpiov.iov_base;
                        }
                    }

                    // dump every section of pme that overlaps with vmas
                    while (vmaiov.iov_base < tmpiov.iov_base + tmpiov.iov_len) {
                        void *vmaend = MIN((void*)vma->e->end, tmpiov.iov_base + tmpiov.iov_len);
                        vmaiov.iov_len = vmaend - vmaiov.iov_base;

                        // dump pagemap entry
                        //pr_debug("CONNOR: writing pagemap 0x%lx - 0x%lx\n", (long unsigned)vmaiov.iov_base, (long unsigned)vmaiov.iov_base + vmaiov.iov_len);
                        xfer->write_pagemap(xfer, &vmaiov, pr.pe->flags, pr.pe->version, pr.pe->addr, pr.pe->port);

                        if ((void*)vma->e->end > tmpiov.iov_base + tmpiov.iov_len) {
                            vmaiov.iov_base = tmpiov.iov_base + tmpiov.iov_len;
                        }
                        else {
                            vma = list_entry(vma->list.next, typeof(*vma), list);
                            vmaiov.iov_base = (void*)vma->e->start;
                        }
                    }

                    if (ciov.iov_base + ciov.iov_len > iov.iov_base) {
                        pr.skip_pages(&pr, (long unsigned)iov.iov_base - pr.cvaddr);
                        //pr_debug("CONNOR: pr.cvaddr = 0x%lx\n", pr.cvaddr);
                    }
                    else {
                        pr.advance(&pr);
                        ciov.iov_base = (void*)pr.pe->vaddr;
                        ciov.iov_len = pr.pe->nr_pages * PAGE_SIZE;
                    }
                }

                //pr_debug("CONNOR: dumping current and overlapping pagemaps\n");

                unsigned long size_dumped = 0;
                tmpiov.iov_base = iov.iov_base;
                while (size_dumped < iov.iov_len) {
                    if (tmpiov.iov_base < (void*)pr.cvaddr) {   // only in new
                        end = MIN(iov.iov_base + iov.iov_len, (void*)pr.cvaddr);
                        version = 0;
                        addr = maddr;
                        port = mport;
                    }
                    else {                                      // overlap
                        end = MIN(iov.iov_base + iov.iov_len, ciov.iov_base + ciov.iov_len)
                        version = pr.pe->version;
                        if (ppb->flags & PPB_DIRTY) {
                            version++;
                            addr = maddr;
                            port = mport;
                        }
                        else {
                            addr = pr.pe->addr;
                            port = pr.pe->port;
                        }

                        if (ciov.iov_base + ciov.iov_len > iov.iov_base + iov.iov_len) {
                            pr.skip_pages(&pr, (long unsigned)(iov.iov_base) + iov.iov_len - pr.cvaddr);
                            //pr_debug("CONNOR: pr.cvaddr = 0x%lx\n", pr.cvaddr);
                        }
                        else {
                            pr.advance(&pr);
                            ciov.iov_base = (void*)pr.pe->vaddr;
                            ciov.iov_len = pr.pe->nr_pages * PAGE_SIZE;
                        }
                    }

                    tmpiov.iov_len = end - tmpiov.iov_base;

                    if (ppb->flags & PPB_LAZY && !dump_lazy) {
                        flags = PE_LAZY;
                        //pr_debug("CONNOR: writing pagemap 0x%lx - 0x%lx\n", (long unsigned)tmpiov.iov_base, (long unsigned)tmpiov.iov_base + tmpiov.iov_len);
                        if (xfer->write_pagemap(xfer, &tmpiov, flags, version, addr, port)) {
                            return -1;
                        }
                    }
                    else if (ppb->flags & PPB_LAZY && dump_lazy) {
                        flags |= PE_LAZY;
                    }
                    if (flags != PE_LAZY) {
                        //pr_debug("CONNOR: writing pagemap 0x%lx - 0x%lx\n", (long unsigned)tmpiov.iov_base, (long unsigned)tmpiov.iov_base + tmpiov.iov_len);
                        if (xfer->write_pagemap(xfer, &tmpiov, flags, version, addr, port)) {
                            return -1;
                        }
                        if (xfer->write_pages(xfer, ppb->p[0], tmpiov.iov_len))
                            return -1;
                    }

                    size_dumped += tmpiov.iov_len;
                    tmpiov.iov_base = tmpiov.iov_base + tmpiov.iov_len;
                }
            }
            else {
                if (ppb->flags & PPB_LAZY) {
                    if (!dump_lazy) {
                        if (xfer->write_pagemap(xfer, &iov, PE_LAZY, version, addr, port))
                            return -1;
                        continue;
                    } else {
                        flags |= PE_LAZY;
                    }
                }

                if (xfer->write_pagemap(xfer, &iov, flags, version, addr, port))
                    return -1;
                if (xfer->write_pages(xfer, ppb->p[0], iov.iov_len))
                    return -1;
            }
        }
    }

    return dump_holes(xfer, pp, &cur_hole, NULL, off);

}

int
pico_dump_end_cached_pagemaps(struct page_xfer *xfer)
{
    struct iovec vmaiov, ciov;
    struct vma_area *vma = NULL;

    // if all cached pme's have been dumped
    if (pr.curr_pme >= pr.nr_pmes)
        goto out;

    vma = list_entry(xfer->vma_area_list->h.next, typeof(*vma), list);
    vmaiov.iov_base = (void*)vma->e->start;

    do {
        ciov.iov_base = (void*) pr.pe->vaddr;
        ciov.iov_len  = pr.pe->nr_pages * PAGE_SIZE;

        // align vma
        while (vmaiov.iov_base < (void*)pr.cvaddr) {
            if ((void*)vma->e->end <= (void*)pr.cvaddr) {
                vma = list_entry(vma->list.next, typeof(*vma), list);
                vmaiov.iov_base = (void*)vma->e->start;
            }
            else {
                vmaiov.iov_base = (void*)pr.cvaddr;
            }
        }

        // dump all sections of pagemap within vmas
        while (vmaiov.iov_base < ciov.iov_base + ciov.iov_len) {
            void *vmaend = MIN((void*)vma->e->end, ciov.iov_base + ciov.iov_len);
            vmaiov.iov_len = vmaend - vmaiov.iov_base;

            // dump pagemap entry
            xfer->write_pagemap(xfer, &vmaiov, pr.pe->flags, pr.pe->version,
            pr.pe->addr, pr.pe->port);

            if ((void*)vma->e->end <= ciov.iov_base + ciov.iov_len) {
                vma = list_entry(vma->list.next, typeof(*vma), list);
                vmaiov.iov_base = (void*)vma->e->start;
            }
            else {
                vmaiov.iov_base = ciov.iov_base + ciov.iov_len;
            }
        }

    } while (pr.advance(&pr));

out:
    pico_reset_page_read();
    return 0;
}

void
pico_reset_pagemap_cache()
{
    // if multiple processes, will need to reopen a different pagemap cache
    page_read_set = 0;
    pr.close(&pr);
}
