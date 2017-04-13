#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/falloc.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <linux/mman.h>
#include <sys/un.h>

#include "cr_options.h"
#include "servicefd.h"
#include "image.h"
#include "page-xfer.h"
#include "page-pipe.h"
#include "util.h"
#include "protobuf.h"
#include "images/pagemap.pb-c.h"
#include "pstree.h"
#include "parasite-syscall.h"
#include "fcntl.h"
#include "lpi.h"
#include "rst_info.h"

#include "vma.h"
#include "images/pstree.pb-c.h"
#include "disk-serve.h"
#include "array.h"
#include "quicksort.h"
#include "binsearch.h"
#include "migrate.h"

#define MIN(a, b) a < b ? a : b;

static disk_pages **dpgs;
static int dpgs_index = 0;
static array dpgs_arr;

typedef struct page_server_t {
    uint32_t addr;
    int sk;
} page_server;

char comp_page_servers(void *a, void *b) {
    page_server *x = a;
    page_server *y = b;

    if (x->addr < y->addr)
        return 1;
    else if (x->addr > y->addr)
        return -1;
    else
        return 0;
}

page_server *page_servers = NULL;
int page_servers_size = 0;
int page_servers_ct = 0;
array page_servers_arr;

static int page_server_sk = -1;

struct page_server_iov {
	u32	cmd;
	u32	nr_pages;
	u64	vaddr;
	u64	dst_id;
};

static void psi2iovec(struct page_server_iov *ps, struct iovec *iov)
{
	iov->iov_base = decode_pointer(ps->vaddr);
	iov->iov_len = ps->nr_pages * PAGE_SIZE;
}

#define PS_IOV_ADD	1
#define PS_IOV_HOLE	2
#define PS_IOV_OPEN	3
#define PS_IOV_OPEN2	4
#define PS_IOV_PARENT	5
#define PS_IOV_ZERO	6
#define PS_IOV_LAZY	7
#define PS_IOV_GET	8

#define PS_IOV_FLUSH		0x1023
#define PS_IOV_FLUSH_N_CLOSE	0x1024

#define PS_CMD_BITS	16
#define PS_CMD_MASK	((1 << PS_CMD_BITS) - 1)

#define PS_TYPE_BITS	8
#define PS_TYPE_MASK	((1 << PS_TYPE_BITS) - 1)

static inline u64 encode_pm_id(int type, long id)
{
	return ((u64)id) << PS_TYPE_BITS | type;
}

static int decode_pm_type(u64 dst_id)
{
	return dst_id & PS_TYPE_MASK;
}

static long decode_pm_id(u64 dst_id)
{
	return (long)(dst_id >> PS_TYPE_BITS);
}

static inline u32 encode_ps_cmd(u32 cmd, u32 flags)
{
	return flags << PS_CMD_BITS | cmd;
}

static inline u32 decode_ps_cmd(u32 cmd)
{
	return cmd & PS_CMD_MASK;
}

static inline u32 decode_ps_flags(u32 cmd)
{
	return cmd >> PS_CMD_BITS;
}

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

/* page-server xfer */
static int write_pages_to_server(struct page_xfer *xfer,
		int p, unsigned long len)
{
	pr_debug("Splicing %lu bytes / %lu pages into socket\n", len, len / PAGE_SIZE);

	if (splice(p, NULL, xfer->sk, NULL, len, SPLICE_F_MOVE) != len) {
		pr_perror("Can't write pages to socket");
		return -1;
	}

	return 0;
}

static int write_pagemap_to_server(struct page_xfer *xfer, struct iovec *iov, u32 flags,
                    unsigned long version, unsigned int addr, unsigned int port)
{
	u32 cmd = 0;

	if (flags & PE_PRESENT)
		cmd = encode_ps_cmd(PS_IOV_ADD, flags);
	else if (flags & PE_PARENT)
		cmd = PS_IOV_HOLE;
	else if (flags & PE_LAZY)
		cmd = PS_IOV_LAZY;
	else if (flags & PE_ZERO)
		cmd = PS_IOV_ZERO;
	else
		BUG();

	return send_psi(xfer->sk, cmd,
			iov->iov_len / PAGE_SIZE, encode_pointer(iov->iov_base),
			xfer->dst_id);
}

static void close_server_xfer(struct page_xfer *xfer)
{
	xfer->sk = -1;
}

static int open_page_server_xfer(struct page_xfer *xfer, int fd_type, long id)
{
	char has_parent;

	xfer->sk = page_server_sk;
	xfer->write_pagemap = write_pagemap_to_server;
	xfer->write_pages = write_pages_to_server;
	xfer->close = close_server_xfer;
	xfer->dst_id = encode_pm_id(fd_type, id);
	xfer->parent = NULL;

	if (send_psi(xfer->sk, PS_IOV_OPEN2, 0, 0, xfer->dst_id)) {
		pr_perror("Can't write to page server");
		return -1;
	}

	/* Push the command NOW */
	tcp_nodelay(xfer->sk, true);

	if (read(xfer->sk, &has_parent, 1) != 1) {
		pr_perror("The page server doesn't answer");
		return -1;
	}

	if (has_parent)
		xfer->parent = (void *) 1; /* This is required for generate_iovs() */

	return 0;
}

/* local xfer */
static int write_pages_loc(struct page_xfer *xfer,
		int p, unsigned long len)
{
	ssize_t ret;

	ret = splice(p, NULL, img_raw_fd(xfer->pi), NULL, len, SPLICE_F_MOVE);
	if (ret == -1) {
		pr_perror("Unable to spice data");
		return -1;
	}
	if (ret != len) {
		pr_err("Only %zu of %lu bytes have been spliced\n", ret, len);
		return -1;
	}

	return 0;
}

static int check_pagehole_in_parent(struct page_read *p, struct iovec *iov)
{
	int ret;
	unsigned long off, end;

	/*
	 * Try to find pagemap entry in parent, from which
	 * the data will be read on restore.
	 *
	 * This is the optimized version of the page-by-page
	 * read_pagemap_page routine.
	 */

	pr_debug("Checking %p/%zu hole\n", iov->iov_base, iov->iov_len);
	off = (unsigned long)iov->iov_base;
	end = off + iov->iov_len;
	while (1) {
		struct iovec piov;
		unsigned long pend;

		ret = p->seek_page(p, off, true);
		if (ret <= 0 || !p->pe)
			return -1;

		pagemap2iovec(p->pe, &piov);
		pr_debug("\tFound %p/%zu\n", piov.iov_base, piov.iov_len);

		/*
		 * The pagemap entry in parent may heppen to be
		 * shorter, than the hole we write. In this case
		 * we should go ahead and check the remainder.
		 */

		pend = (unsigned long)piov.iov_base + piov.iov_len;
		if (end <= pend)
			return 0;

		pr_debug("\t\tcontinue on %lx\n", pend);
		off = pend;
	}
}

static int write_pagemap_loc(struct page_xfer *xfer, struct iovec *iov, u32 flags,
                    unsigned long version, unsigned int addr, unsigned int port)
{
	int ret;
	PagemapEntry pe = PAGEMAP_ENTRY__INIT;

	iovec2pagemap(iov, &pe);
	pe.has_flags = true;
	pe.flags = flags;
    pe.has_version = true;
    pe.version = version;
    pe.has_addr = true;
    pe.addr = addr;
    pe.has_port = true;
    pe.port = port;

	if (flags & PE_PRESENT) {
		if (opts.auto_dedup && xfer->parent != NULL) {
			ret = dedup_one_iovec(xfer->parent, iov);
			if (ret == -1) {
				pr_perror("Auto-deduplication failed");
				return ret;
			}
		}
	} else if (flags & PE_PARENT) {
		if (xfer->parent != NULL) {
			ret = check_pagehole_in_parent(xfer->parent, iov);
			if (ret) {
				pr_err("Hole %p/%zu not found in parent\n",
				       iov->iov_base, iov->iov_len);
				return -1;
			}
		}
	}

	if (pb_write_one(xfer->pmi, &pe, PB_PAGEMAP) < 0)
		return -1;

	return 0;
}

static void close_page_xfer(struct page_xfer *xfer)
{
	if (xfer->parent != NULL) {
		xfer->parent->close(xfer->parent);
		xfree(xfer->parent);
		xfer->parent = NULL;
	}
	close_image(xfer->pi);
	close_image(xfer->pmi);
}

static int open_page_local_xfer(struct page_xfer *xfer, int fd_type, long id,
                                bool meta)
{
	xfer->pmi = open_image(fd_type, O_DUMP, id);
	if (!xfer->pmi)
		return -1;

	xfer->pi = open_pages_image(O_DUMP, xfer->pmi, meta);
	if (!xfer->pi) {
		close_image(xfer->pmi);
		return -1;
	}

	/*
	 * Open page-read for parent images (if it exists). It will
	 * be used for two things:
	 * 1) when writing a page, those from parent will be dedup-ed
	 * 2) when writing a hole, the respective place would be checked
	 *    to exist in parent (either pagemap or hole)
	 */
	xfer->parent = NULL;
	if (fd_type == CR_FD_PAGEMAP || fd_type == CR_FD_SHMEM_PAGEMAP ||
            fd_type == CR_FD_META_PAGEMAP) {
		int ret;
		int pfd;
		int pr_flags = (fd_type == CR_FD_PAGEMAP ||
                        fd_type == CR_FD_META_PAGEMAP) ? PR_TASK : PR_SHMEM;

		pfd = openat(get_service_fd(IMG_FD_OFF), CR_PARENT_LINK, O_RDONLY);
		if (pfd < 0 && errno == ENOENT)
			goto out;

		xfer->parent = xmalloc(sizeof(*xfer->parent));
		if (!xfer->parent) {
			close(pfd);
			return -1;
		}

		ret = open_page_read_at(pfd, id, xfer->parent, pr_flags);
		if (ret <= 0) {
			pr_perror("No parent image found, though parent directory is set");
			xfree(xfer->parent);
			xfer->parent = NULL;
			close(pfd);
			goto out;
		}
		close(pfd);
	}

out:
	xfer->write_pagemap = write_pagemap_loc;
	xfer->write_pages = write_pages_loc;
	xfer->close = close_page_xfer;
	return 0;
}

int open_page_xfer(struct page_xfer *xfer, int fd_type, long id, bool meta)
{
	if (opts.use_page_server)
		return open_page_server_xfer(xfer, fd_type, id);
	else
		return open_page_local_xfer(xfer, fd_type, id, meta);
}

static int page_xfer_dump_hole(struct page_xfer *xfer,
			       struct iovec *hole, unsigned long off, u32 flags)
{
	BUG_ON(hole->iov_base < (void *)off);
	hole->iov_base -= off;
	pr_debug("\th %p [%u]\n", hole->iov_base,
			(unsigned int)(hole->iov_len / PAGE_SIZE));

	if (xfer->write_pagemap(xfer, hole, flags, 0, 0, 0))
		return -1;

	return 0;
}

static struct iovec get_iov(struct iovec *iovs, unsigned int n, bool compat)
{
	if (likely(!compat)) {
		return iovs[n];
	} else {
		struct iovec ret;
		struct iovec_compat *tmp = (struct iovec_compat*)(void *)iovs;

		tmp += n;
		ret.iov_base = (void *)(uintptr_t)tmp->iov_base;
		ret.iov_len = tmp->iov_len;
		return ret;
	}
}

static int get_hole_flags(struct page_pipe *pp, int n)
{
	unsigned int hole_flags = pp->hole_flags[n];

	if (hole_flags == PP_HOLE_PARENT)
		return PE_PARENT;
	if (hole_flags == PP_HOLE_ZERO)
		return PE_ZERO;
	else
		BUG();

	return -1;
}

static int dump_holes(struct page_xfer *xfer, struct page_pipe *pp,
		      unsigned int *cur_hole, void *limit, unsigned long off)
{
	int ret;

	for (; *cur_hole < pp->free_hole ; (*cur_hole)++) {
		struct iovec hole = get_iov(pp->holes, *cur_hole,
						pp->flags & PP_COMPAT);
		u32 hole_flags;

		if (limit && hole.iov_base >= limit)
			break;

		hole_flags = get_hole_flags(pp, *cur_hole);
		ret = page_xfer_dump_hole(xfer, &hole, off, hole_flags);
		if (ret)
			return ret;
	}

	return 0;
}

int shared_page_xfer_dump_pages(struct page_xfer *xfer, struct page_pipe *pp,
            unsigned long off, bool dump_lazy)
{
	struct page_pipe_buf *ppb;
	unsigned int cur_hole = 0;
	int ret;

	pr_debug("Transferring pages:\n");

	list_for_each_entry(ppb, &pp->bufs, l) {
		unsigned int i;

		pr_debug("\tbuf %d/%d\n", ppb->pages_in, ppb->nr_segs);

		for (i = 0; i < ppb->nr_segs; i++) {
			struct iovec iov = get_iov(ppb->iov, i, pp->flags & PP_COMPAT);
			u32 flags = PE_PRESENT;

			ret = dump_holes(xfer, pp, &cur_hole, iov.iov_base, off);
			if (ret)
				return ret;

			BUG_ON(iov.iov_base < (void *)off);
			iov.iov_base -= off;
			pr_debug("\tp %p [%u]\n", iov.iov_base,
					(unsigned int)(iov.iov_len / PAGE_SIZE));

            if (ppb->flags & PPB_LAZY) {
                if (!dump_lazy) {
                    if (xfer->write_pagemap(xfer, &iov, PE_LAZY, 0, 0, 0))
                        return -1;
                    continue;
                } else {
                    flags |= PE_LAZY;
                }
            }

            if (xfer->write_pagemap(xfer, &iov, flags, 0, 0, 0))
                return -1;
            if (xfer->write_pages(xfer, ppb->p[0], iov.iov_len))
                return -1;
        }
    }

	return dump_holes(xfer, pp, &cur_hole, NULL, off);
}

struct page_read pr;
char page_read_set = 0;
struct iovec ciov;

int page_xfer_dump_pages(struct page_xfer *xfer, struct page_pipe *pp,
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
    const uint32_t mport = 3333;
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
        pr.get_pagemap(&pr, &ciov);
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
			struct iovec iov = get_iov(ppb->iov, i, pp->flags & PP_COMPAT);
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
                        xfer->write_pagemap(xfer, &vmaiov, pr.pe->flags, pr.pe->version,
                                        pr.pe->addr, pr.pe->port);

                        if ((void*)vma->e->end > tmpiov.iov_base + tmpiov.iov_len) {
                            vmaiov.iov_base = tmpiov.iov_base + tmpiov.iov_len;
                        }
                        else {
                            vma = list_entry(vma->list.next, typeof(*vma), list);
                            vmaiov.iov_base = (void*)vma->e->start;
                        }
                    }

                    if (ciov.iov_base + ciov.iov_len <= iov.iov_base) {
                        pr.get_pagemap(&pr, &ciov);
                    }
                    else {
                        pr.seek_page(&pr, (unsigned long)iov.iov_base, 1);
                    }
                }

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

                        if (ciov.iov_base + ciov.iov_len > iov.iov_base + iov.iov_len)
                            pr.seek_page(&pr, (unsigned long)(iov.iov_base + iov.iov_len), 1);
                        else
                            pr.get_pagemap(&pr, &ciov);
                    }

                    tmpiov.iov_len = end - tmpiov.iov_base;

                    if (ppb->flags & PPB_LAZY && !dump_lazy) {
                        flags = PE_LAZY;
                        if (xfer->write_pagemap(xfer, &tmpiov, flags, version, addr, port))
                            return -1;
                    }
                    else if (ppb->flags & PPB_LAZY && dump_lazy) {
                        flags |= PE_LAZY;
                    }
                    if (flags != PE_LAZY) {
                        if (xfer->write_pagemap(xfer, &tmpiov, flags, version, addr, port))
                            return -1;
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

/*
 * Return:
 *	 1 - if a parent image exists
 *	 0 - if a parent image doesn't exist
 *	-1 - in error cases
 */
int check_parent_local_xfer(int fd_type, int id)
{
	char path[PATH_MAX];
	struct stat st;
	int ret, pfd;

	pfd = openat(get_service_fd(IMG_FD_OFF), CR_PARENT_LINK, O_RDONLY);
	if (pfd < 0 && errno == ENOENT)
		return 0;

	snprintf(path, sizeof(path), imgset_template[fd_type].fmt, id);
	ret = fstatat(pfd, path, &st, 0);
	if (ret == -1 && errno != ENOENT) {
		pr_perror("Unable to stat %s", path);
		close(pfd);
		return -1;
	}

	close(pfd);
	return (ret == 0);
}

/* page server */
static int page_server_check_parent(int sk, struct page_server_iov *pi)
{
	int type, ret;
	long id;

	type = decode_pm_type(pi->dst_id);
	id = decode_pm_id(pi->dst_id);

	ret = check_parent_local_xfer(type, id);
	if (ret < 0)
		return -1;

	if (write(sk, &ret, sizeof(ret)) != sizeof(ret)) {
		pr_perror("Unable to send response");
		return -1;
	}

	return 0;
}

static int check_parent_server_xfer(int fd_type, long id)
{
	struct page_server_iov pi = {};
	int has_parent;

	pi.cmd = PS_IOV_PARENT;
	pi.dst_id = encode_pm_id(fd_type, id);

	if (write(page_server_sk, &pi, sizeof(pi)) != sizeof(pi)) {
		pr_perror("Can't write to page server");
		return -1;
	}

	tcp_nodelay(page_server_sk, true);

	if (read(page_server_sk, &has_parent, sizeof(int)) != sizeof(int)) {
		pr_perror("The page server doesn't answer");
		return -1;
	}

	return has_parent;
}

int check_parent_page_xfer(int fd_type, long id)
{
	if (opts.use_page_server)
		return check_parent_server_xfer(fd_type, id);
	else
		return check_parent_local_xfer(fd_type, id);
}

struct page_xfer_job {
	u64	dst_id;
	int	p[2];
	unsigned pipe_size;
	struct page_xfer loc_xfer;
};

static struct page_xfer_job cxfer = {
	.dst_id = ~0,
};

static void page_server_close(void)
{
	if (cxfer.dst_id != ~0)
		cxfer.loc_xfer.close(&cxfer.loc_xfer);
}

static int page_server_open(int sk, struct page_server_iov *pi)
{
	int type;
	long id;

	type = decode_pm_type(pi->dst_id);
	id = decode_pm_id(pi->dst_id);
	pr_info("Opening %d/%ld\n", type, id);

	page_server_close();

	if (open_page_local_xfer(&cxfer.loc_xfer, type, id, false))
		return -1;

	cxfer.dst_id = pi->dst_id;

	if (sk >= 0) {
		char has_parent = !!cxfer.loc_xfer.parent;

		if (write(sk, &has_parent, 1) != 1) {
			pr_perror("Unable to send response");
			close_page_xfer(&cxfer.loc_xfer);
			return -1;
		}
	}

	return 0;
}

static int prep_loc_xfer(struct page_server_iov *pi)
{
	if (cxfer.dst_id != pi->dst_id) {
		pr_warn("Deprecated IO w/o open\n");
		return page_server_open(-1, pi);
	} else
		return 0;
}

static int page_server_add(int sk, struct page_server_iov *pi, u32 flags)
{
	size_t len;
	struct page_xfer *lxfer = &cxfer.loc_xfer;
	struct iovec iov;

	pr_debug("Adding %"PRIx64"/%u\n", pi->vaddr, pi->nr_pages);

	if (prep_loc_xfer(pi))
		return -1;

	psi2iovec(pi, &iov);
	if (lxfer->write_pagemap(lxfer, &iov, flags, 0, 0, 0))
		return -1;

	if (!(flags & PE_PRESENT))
		return 0;

	len = iov.iov_len;
	while (len > 0) {
		ssize_t chunk;

		chunk = len;
		if (chunk > cxfer.pipe_size)
			chunk = cxfer.pipe_size;

		chunk = splice(sk, NULL, cxfer.p[1], NULL, chunk, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
		if (chunk < 0) {
			pr_perror("Can't read from socket");
			return -1;
		}

		if (lxfer->write_pages(lxfer, cxfer.p[0], chunk))
			return -1;

		len -= chunk;
	}

	return 0;
}

static int page_server_get_pages(int sk, struct page_server_iov *pi)
{
	struct pstree_item *item;
	struct page_pipe *pp;
	struct page_pipe_buf *ppb;
	struct iovec *iov;
	int ret;

	item = pstree_item_by_virt(pi->dst_id);
	pp = dmpi(item)->mem_pp;

	ret = page_pipe_split(pp, pi->vaddr, &pi->nr_pages);
	if (ret)
		return ret;

	if (pi->nr_pages == 0) {
		/* no iovs found means we've hit a zero page */
		pr_debug("no iovs found, zero pages\n");
		return send_psi(sk, PS_IOV_ZERO, 0, 0, 0);
	}

	ppb = list_first_entry(&pp->bufs, struct page_pipe_buf, l);
	iov = &ppb->iov[0];

	BUG_ON(!(ppb->flags & PPB_LAZY));
	BUG_ON(iov->iov_len != pi->nr_pages * PAGE_SIZE);
	BUG_ON(pi->vaddr != encode_pointer(iov->iov_base));

	if (send_psi(sk, PS_IOV_ADD, pi->nr_pages, pi->vaddr, pi->dst_id))
		return -1;

	ret = splice(ppb->p[0], NULL, sk, NULL, iov->iov_len, SPLICE_F_MOVE);
	if (ret != iov->iov_len)
		return -1;

	tcp_nodelay(sk, true);

	page_pipe_destroy_ppb(ppb);

	return 0;
}

static char comp_disk_pages(void *a, void *b)
{
    disk_pages *x = a;
    disk_pages *y = b;

    if (x->pid < y->pid)
        return 1;
    else if (x->pid > y->pid)
        return -1;
    else
        return 0;
}

static int disk_serve_get_pages(int sk, struct page_server_iov *pi)
{
    int ret = 0;
    disk_pages other, *dps;
    other.pid = pi->dst_id;
    void *buf = malloc(pi->nr_pages * PAGE_SIZE);

    dps = binsearch(&dpgs_arr, &other, 0, dpgs_arr.size-1);
    pr_debug("CONNOR: binsearch success!\n");

    dps->pr.reset(&dps->pr);
    dps->pr.seek_page(&dps->pr, pi->vaddr, 1);

    dps->pr.read_pages(&dps->pr, pi->vaddr, pi->nr_pages, buf);
    pr_debug("CONNOR: read %d pages starting at %lu into buffer\n", pi->nr_pages, pi->vaddr);

	ret = send_psi(sk, PS_IOV_ADD, pi->nr_pages, dps->pr.pe->vaddr, pi->dst_id);
    if (ret)
        goto out;
    pr_debug("CONNOR: send_psi success!\n");

    if (write(sk, buf, pi->nr_pages * PAGE_SIZE) != pi->nr_pages*PAGE_SIZE) {
        ret = 1;
        goto out;
    }
    pr_debug("CONNOR: wrote %d pages to sk\n", pi->nr_pages);
    pr_debug("CONNOR: vaddr: %lu\n", pi->vaddr);
    pr_debug("CONNOR: pid: %lu\n", pi->dst_id);
    pr_debug("\n");

out:
    free(buf);
    if (ret)
        return -1;
    return 0;
}

static int disk_serve_prepare(void)
{
    int i;
    int ret = 0;
    struct cr_img *img;

    dpgs = malloc(DISK_SERVE_PSBUF_SIZE * sizeof(disk_pages*));

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

        dpgs[dpgs_index] = malloc(sizeof(disk_pages));
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

static void disk_serve_cleanup(void)
{
    int i;
    for (i=0; i<dpgs_index; i++) {
        dpgs[i]->pr.close(&dpgs[i]->pr);
        free(dpgs[i]);
    }
    free(dpgs);
    array_free(&dpgs_arr);
}

static int page_server_serve(int sk)
{
	int ret = -1;
	bool flushed = false;

	if (!opts.lazy_pages) {
		/*
		 * This socket only accepts data except one thing -- it
		 * writes back the has_parent bit from time to time, so
		 * make it NODELAY all the time.
		 */
		tcp_nodelay(sk, true);

		if (pipe(cxfer.p)) {
			pr_perror("Can't make pipe for xfer");
			close(sk);
			return -1;
		}

		cxfer.pipe_size = fcntl(cxfer.p[0], F_GETPIPE_SZ, 0);
		pr_debug("Created xfer pipe size %u\n", cxfer.pipe_size);
	} else {
		tcp_cork(sk, true);
	}

	while (1) {
		struct page_server_iov pi;
		u32 cmd;

		ret = recv(sk, &pi, sizeof(pi), MSG_WAITALL);
		if (!ret)
			break;

		if (ret != sizeof(pi)) {
			pr_perror("Can't read pagemap from socket");
			ret = -1;
			break;
		}

		flushed = false;
		cmd = decode_ps_cmd(pi.cmd);

		switch (cmd) {
		case PS_IOV_OPEN:
			ret = page_server_open(-1, &pi);
			break;
		case PS_IOV_OPEN2:
			ret = page_server_open(sk, &pi);
			break;
		case PS_IOV_PARENT:
			ret = page_server_check_parent(sk, &pi);
			break;
		case PS_IOV_ADD:
			ret = page_server_add(sk, &pi, PE_PRESENT | decode_ps_flags(pi.cmd));
			break;
		case PS_IOV_HOLE:
			ret = page_server_add(sk, &pi, PE_PARENT);
			break;
		case PS_IOV_ZERO:
			ret = page_server_add(sk, &pi, PE_ZERO);
			break;
		case PS_IOV_LAZY:
			ret = page_server_add(sk, &pi, PE_LAZY);
			break;
		case PS_IOV_FLUSH:
		case PS_IOV_FLUSH_N_CLOSE:
		{
			int32_t status = 0;

			ret = 0;

			/*
			 * An answer must be sent back to inform another side,
			 * that all data were received
			 */
			if (write(sk, &status, sizeof(status)) != sizeof(status)) {
				pr_perror("Can't send the final package");
				ret = -1;
			}

			flushed = true;
			break;
		}
		case PS_IOV_GET:
			flushed = true;
            if (opts.disk_serve)
                ret = disk_serve_get_pages(sk, &pi);
            else
                ret = page_server_get_pages(sk, &pi);
			break;
		default:
			pr_err("Unknown command %u\n", pi.cmd);
			ret = -1;
			break;
		}

		if (ret || (pi.cmd == PS_IOV_FLUSH_N_CLOSE))
			break;
	}

	if (!ret && !flushed) {
		pr_err("The data were not flushed\n");
		ret = -1;
	}

	if (ret == 0 && opts.ps_socket == -1) {
		char c;

		/*
		 * Wait when a remote side closes the connection
		 * to avoid TIME_WAIT bucket
		 */

		if (read(sk, &c, sizeof(c)) != 0) {
			pr_perror("Unexpected data");
			ret = -1;
		}
	}

	page_server_close();
	pr_info("Session over\n");

	close(sk);
	return ret;
}

int cr_page_server(bool daemon_mode, int cfd)
{
	int ask = -1;
	int sk = -1;
	int ret;

    if (opts.disk_serve) {
        ret = disk_serve_prepare();
        if (ret) {
            disk_serve_cleanup();
            close(sk);
            return -1;
        }
    }

	if (!opts.lazy_pages)
		up_page_ids_base();

	if (opts.ps_socket != -1) {
		ret = 0;
		ask = opts.ps_socket;
		pr_info("Re-using ps socket %d\n", ask);
		goto no_server;
	}

	sk = setup_tcp_server("page");
	if (sk == -1)
		return -1;
no_server:
	ret = run_tcp_server(daemon_mode, &ask, cfd, sk);
	if (ret != 0)
		return ret;

	if (ask >= 0)
		ret = page_server_serve(ask);

    if (opts.disk_serve)
        disk_serve_cleanup();

	if (daemon_mode)
		exit(ret);

	return ret;
}

int pico_conn_server(int addr, int port)
{
    /*
     * connect to a page server specified by addr and port
     * return the fd of the socket
     * wrapper function for pico_setup_tcp_client(...)
     */
	struct sockaddr_in saddr;
	int sk;

	pr_info("Connecting to server %d:%u\n", addr, port);

	saddr.sin_family = AF_INET;
	saddr.sin_addr.s_addr = addr;
	saddr.sin_port = htons(port);

	sk = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sk < 0) {
		pr_perror("Can't create socket");
		return -1;
	}

	if (connect(sk, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
		pr_perror("Can't connect to server");
		close(sk);
		return -1;
	}

	tcp_cork(sk, true);

	return sk;
}

int pico_disc_server(int sk)
{
    close(sk);

    return 0;
}

int connect_to_page_server(void)
{
	if (!opts.use_page_server)
		return 0;

	if (opts.ps_socket != -1) {
		page_server_sk = opts.ps_socket;
		pr_info("Re-using ps socket %d\n", page_server_sk);
		goto out;
	}

	page_server_sk = setup_tcp_client(opts.addr);
	if (page_server_sk == -1)
		return -1;
out:
	/*
	 * CORK the socket at the very beginning. As per ANK
	 * the corked by default socket with sporadic NODELAY-s
	 * on urgent data is the smartest mode ever.
	 */
	tcp_cork(page_server_sk, true);
	return 0;
}

int disconnect_from_page_server(void)
{
	struct page_server_iov pi = { };
	int32_t status = -1;
	int ret = -1;

	if (!opts.use_page_server)
		return 0;

	if (page_server_sk == -1)
		return 0;

	pr_info("Disconnect from the page server %s:%u\n",
			opts.addr, (int)ntohs(opts.port));

	if (opts.ps_socket != -1)
		/*
		 * The socket might not get closed (held by
		 * the parent process) so we must order the
		 * page-server to terminate itself.
		 */
		pi.cmd = PS_IOV_FLUSH_N_CLOSE;
	else
		pi.cmd = PS_IOV_FLUSH;

	if (write(page_server_sk, &pi, sizeof(pi)) != sizeof(pi)) {
		pr_perror("Can't write the fini command to server");
		goto out;
	}

	if (read(page_server_sk, &status, sizeof(status)) != sizeof(status)) {
		pr_perror("The page server doesn't answer");
		goto out;
	}

	ret = 0;
out:
	close_safe(&page_server_sk);
	return ret ? : status;
}

int get_remote_pages(int pid, unsigned long addr, int nr_pages, void *dest)
{
	int ret;

	struct page_server_iov pi;

	if (send_psi(page_server_sk, PS_IOV_GET, nr_pages, addr, pid))
		return -1;

	tcp_nodelay(page_server_sk, true);

	ret = recv(page_server_sk, &pi, sizeof(pi), MSG_WAITALL);
	if (ret != sizeof(pi))
		return -1;

	/* zero page */
	if (pi.cmd == PS_IOV_ZERO)
		return 0;

	if (pi.nr_pages > nr_pages)
		return -1;

	ret = recv(page_server_sk, dest, PAGE_SIZE, MSG_WAITALL);
	if (ret != PAGE_SIZE)
		return -1;

	return 1;
}

int pico_get_remote_page(struct lazy_pages_info *lpi, unsigned long addr, void *dest)
{
    /*
     * 0. if pinned, checkpoint and restore on page owner's machine
     * 1. get address and port from lpi->pr pagemap entry
     * 2. binsearch to determine if the socket to that server exists
     * 3. if not, establish tcp socket to that server
     * 4. request page as in get_remote_pages()
     */

    // get vmas (from pstree item)
    // if page is pinned (must be pinned on different machine), checkpoint and restore on target machine (IPC with criu-chamber?)
    // write to stdout (addr) (criu-chamber will have set this up as pipe
    int ret;
	struct vma_area *vma;
	struct vm_area_list *vmas;
	struct pstree_item *item = pstree_item_by_virt(lpi->pid);
	vmas = &rsti(item)->vmas;

    list_for_each_entry(vma, &vmas->h, list) {
        if (vma->e->start <= addr && vma->e->end > addr) {
            if (vma->e->flags & MAP_PIN) {
                // call migration library
                struct in_addr inaddr;
                inaddr.s_addr = vma->e->pico_addr;

                migrate_ip(inet_ntoa(inaddr));
                goto jail; // do not pass go, do not collect $200
            }
            else {
                break;
            }
        }
    }

    if (page_servers == NULL) {
        page_servers_size = 16;
        page_servers = malloc(16 * sizeof(page_server));
        array_init(&page_servers_arr, 16, comp_page_servers);
    }

    pr_debug("CONNOR: trying to find page with page read\n");
    lpi->pr.reset(&lpi->pr);
    ret = lpi->pr.seek_page(&lpi->pr, addr, 1);

    if (!ret)
        return 0;

    if (page_servers_ct == 0) { // fist entry
        page_servers[0].addr = lpi->pr.pe->addr;
        page_servers[0].sk = pico_conn_server(lpi->pr.pe->addr, lpi->pr.pe->port);
        page_servers_arr.elems[0] = (void*) &page_servers[0];
        page_servers_ct++;
    }

    page_server tmp = { .sk = 0, .addr = lpi->pr.pe->addr };
    page_server *server = binsearch(&page_servers_arr, &tmp, 0, page_servers_ct-1);

    if (server == NULL) {   // not found; connect
        if (page_servers_ct == page_servers_size) { // realloc
            page_servers_size *= 2;
            page_servers = realloc(page_servers, 
                                    page_servers_size * sizeof(page_server));
            page_servers_arr.size = page_servers_size;
            page_servers_arr.elems = realloc(page_servers_arr.elems,
                                                page_servers_size * sizeof(void*));
        }

        page_servers[page_servers_ct].addr = lpi->pr.pe->addr;
        page_servers[page_servers_ct].sk = pico_conn_server(lpi->pr.pe->addr, lpi->pr.pe->port);
        page_servers_arr.elems[page_servers_ct] = (void*) &page_servers[page_servers_ct];
        server = &page_servers[page_servers_ct];
        page_servers_ct++;

        quicksort(0, page_servers_ct-1, &page_servers_arr);
    }

    // copy get_remote_pages()
	struct page_server_iov pi;

	if (send_psi(server->sk, PS_IOV_GET, 1, addr, lpi->pid))
		return -1;

	tcp_nodelay(server->sk, true);

	ret = recv(server->sk, &pi, sizeof(pi), MSG_WAITALL);
	if (ret != sizeof(pi))
		return -1;

	/* zero page */
	if (pi.cmd == PS_IOV_ZERO)
		return 0;

	if (pi.nr_pages > 1)
		return -1;

	ret = recv(server->sk, dest, PAGE_SIZE, MSG_WAITALL);
	if (ret != PAGE_SIZE)
		return -1;

jail:
	return 1;
}
