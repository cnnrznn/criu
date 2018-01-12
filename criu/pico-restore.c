#include <arpa/inet.h>
#include <linux/mman.h>
#include <netinet/in.h>

#include "pico-restore.h"
#include "pico-pin.h"
#include "pico-soft_mig.h"
#include "pico-util.h"
#include "pico-man.h"
#include "pico-page_list.h"

#include "array.h"
#include "binsearch.h"
#include "criu-log.h"
#include "page-xfer.h"
#include "pstree.h"
#include "quicksort.h"
#include "rst_info.h"
#include "util.h"
#include "vma.h"
#include "cr_options.h"

#define MIN(a, b) a < b ? a : b;

void *pico_uffd_buf = NULL;

static page_server *page_servers = NULL;
static int page_servers_size = 0;
static int page_servers_ct = 0;
static array page_servers_arr;

static inline int
recv_psi(int sk, struct page_server_iov *pi)
{
    if (recv(sk, pi, sizeof(*pi), 0) != sizeof(*pi)) {
        pr_perror("Can't recv PSI from server");
        return -1;
    }

    return 0;
}

static int
pico_conn_server(int addr, int port)
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

    // output is buffered
    tcp_cork(sk, true);

    return sk;
}

/*
int
pico_disconn_page_servers(void)
{
	struct page_server_iov pi = { };
	int32_t status = -1;
	int ret = -1;

	pr_info("PicoJump disconnect from the page servers\n");

	pi.cmd = PS_IOV_FLUSH_N_CLOSE;

    page_server *ps = page_servers;
    int i = 0;
    while (i < page_servers_ct) {
        if (write(ps->sk, &pi, sizeof(pi)) != sizeof(pi)) {
            pr_perror("Can't write the fini command to server");
            goto out;
        }

        if (read(ps->sk, &status, sizeof(status)) != sizeof(status)) {
            pr_perror("The page server doesn't answer");
            goto out;
        }
        i++;
        ps++;
    }

	ret = 0;
out:
	return ret ? : status;
}
*/

static char
comp_page_servers(void *a, void *b)
{
    page_server *x = a;
    page_server *y = b;

    if (x->addr < y->addr)
        return 1;
    else if (x->addr > y->addr)
        return -1;
    else
        return 0;
}

int
pico_get_remote_pages(struct page_read *pr, long unsigned addr, int nr, void *buf)
{
    /*
    * 0. if pinned, checkpoint and restore on page owner's machine
    * 1. get address and port from pr pagemap entry
    * 2. binsearch to determine if the socket to that server exists
    * 3. if not, establish tcp socket to that server
    * 4. request page as in get_remote_pages()
    */

    // get vmas (from pstree item)
    // if page is pinned (must be pinned on different machine), checkpoint and restore on target machine (IPC with criu-chamber?)
    // write to stdout (addr) (criu-chamber will have set this up as pipe
    int ret;
    //struct vma_area *vma;
    //struct vm_area_list *vmas;
    //struct pstree_item *item = pstree_item_by_virt(pr->pid);
    //vmas = &rsti(item)->vmas;

    //list_for_each_entry(vma, &vmas->h, list) {
    //    if (vma->e->start <= addr && vma->e->end > addr) {
    //        if (vma->e->flags & MAP_PIN) {
    //            // call migration library
    //            struct in_addr inaddr;
    //            inaddr.s_addr = vma->e->pico_addr;

    //            migrate_ip(inet_ntoa(inaddr));
    //            goto jail; // do not pass go, do not collect $200
    //        }
    //        else {
    //            break;
    //        }
    //    }
    //}

    int i;

    if (page_servers == NULL) {
        page_servers_size = 16;
        page_servers = malloc(16 * sizeof(page_server));
        array_init(&page_servers_arr, 16, comp_page_servers);
    }

    pr->reset(pr);
    ret = pr->seek_pagemap(pr, addr);
    if (!ret)
        return -1;

    // pick closest server
    unsigned long pico_addr = 0;

    for (i=0; i < opts.pico_npeers; i++) {
        if (pagemap_contains_addr(pr->pe->n_addrs, pr->pe->addrs, opts.pico_dist[i])) {
            pico_addr = opts.pico_dist[i];
            break;
        }
    }
    pr_debug("CONNOR: closest server is %lu\n", pico_addr);

    if (page_servers_ct == 0) { // fist entry
        page_servers[0].addr = pico_addr;
        page_servers[0].sk = pico_conn_server(pico_addr, pr->pe->port);
        page_servers_arr.elems[0] = (void*) &page_servers[0];
        page_servers_ct++;
    }

    page_server tmp = { .sk = 0, .addr = pico_addr };
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

        page_servers[page_servers_ct].addr = pico_addr;
        page_servers[page_servers_ct].sk = pico_conn_server(pico_addr, pr->pe->port);
        page_servers_arr.elems[page_servers_ct] = (void*) &page_servers[page_servers_ct];
        server = &page_servers[page_servers_ct];
        page_servers_ct++;

        quicksort(0, page_servers_ct-1, &page_servers_arr);
    }

    // request pages from page server

    struct pico_page_list *plhead = NULL;
    int plist_count = 0;

    // compute start of boundary
#define BLOCK_SIZE 64
    const unsigned long block = addr - (addr % (BLOCK_SIZE * PAGE_SIZE));
    const unsigned long blockend = block + (BLOCK_SIZE * PAGE_SIZE);
    unsigned long start = 0;
    int nr_pages = 0;

    // find first pagemap entry at start of boundary
    pr->reset(pr);
    pr->seek_pagemap(pr, block);

    // skip to first page
    pr->skip_pages(pr, block > pr->cvaddr ? block - pr->cvaddr : 0);

    // compute number of pages
    while (pr->pe->vaddr < blockend) {
        if (pagemap_contains_addr(pr->pe->n_addrs, pr->pe->addrs, pico_addr) &&
                pr->pe->flags & PE_LAZY) {
            if (!start)
                start = pr->cvaddr;
            unsigned long end = MIN(pr->pe->vaddr + (pr->pe->nr_pages * PAGE_SIZE), blockend);
            nr_pages += (end - pr->cvaddr) / PAGE_SIZE;

            struct pico_page_list *pl = malloc(sizeof(struct pico_page_list));
            pl->next = plhead;
            pl->addr = pr->cvaddr;
            pl->size = end - pr->cvaddr;
            plhead = pl;
            plist_count++;
        }
        if (!pr->advance(pr))
            break;
    }

    pico_remote_pages(server->addr, plhead, plist_count);

	struct page_server_iov pi = {
		.cmd		= PS_IOV_GET,
		.nr_pages	= nr_pages,
		.vaddr		= start,
		.dst_id		= pr->pid,
	};

    //if (pico_soft_migrate(pico_addr, nr_pages))
    //    goto jail;

	/* We cannot use send_psi here because we have to use MSG_DONTWAIT */
	if (send(server->sk, &pi, sizeof(pi), MSG_DONTWAIT) != sizeof(pi)) {
		pr_perror("Can't write PSI to server");
		return -1;
	}

    // flush socket buffer
	tcp_nodelay(server->sk, true);

    // recv page data
    int total_recv = 0;
    pr->reset(pr);
    pr->seek_pagemap(pr, start);
    pr->skip_pages(pr, start > pr->cvaddr ? start - pr->cvaddr : 0);

    pr_debug("CONNOR: time before page read\n");
    while (pr->pe->vaddr < blockend) {
        if (pagemap_contains_addr(pr->pe->n_addrs, pr->pe->addrs, pico_addr) &&
                pr->pe->flags & PE_LAZY) {
            unsigned long end = MIN(pr->pe->vaddr + (pr->pe->nr_pages * PAGE_SIZE), blockend);
            total_recv = 0;
            while (total_recv < (end - pr->cvaddr)) {
                int tmp = read(server->sk, pico_uffd_buf + total_recv, (end - pr->cvaddr) - total_recv);
                total_recv += tmp;
            }
            // copy pe into uffdio_copy
            if (read_page_complete(pr->pid, pr->cvaddr, (end - pr->cvaddr)/PAGE_SIZE, pr))
                return -1;
        }
        if (!pr->advance(pr))
            break;
    }
    pr_debug("CONNOR: time after page read\n\n");

    /*pr_debug("CONNOR: pico-restore raw page data (%lu):\n", nr * PAGE_SIZE);
    pr_debug("====================\n");
    int logfd = log_get_fd();
    int foo = write(logfd, buf, nr * PAGE_SIZE);
    if (foo < nr * PAGE_SIZE)
        pr_debug("CONNOR: foo\n");
    pr_debug("\n====================\n\n");*/

//jail:
    return 0;
}
