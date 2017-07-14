#include <arpa/inet.h>
#include <linux/mman.h>
#include <netinet/in.h>

#include "pico-restore.h"

#include "array.h"
#include "binsearch.h"
#include "migrate.h"
#include "pstree.h"
#include "quicksort.h"
#include "rst_info.h"
#include "util.h"
#include "vma.h"

static page_server *page_servers = NULL;
static int page_servers_size = 0;
static int page_servers_ct = 0;
static array page_servers_arr;

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

    tcp_cork(sk, true);

    return sk;
}

static char
comp_page_servers(void *a, void *b) {
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
pico_select_page_server(struct page_read *pr, long unsigned addr)
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
    struct vma_area *vma;
    struct vm_area_list *vmas;
    struct pstree_item *item = pstree_item_by_virt(pr->pid);
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

    //pr_debug("CONNOR: trying to find page with page read\n");
    pr->reset(pr);
    ret = pr->seek_pagemap(pr, addr);

    if (!ret)
        return -1;

    if (page_servers_ct == 0) { // fist entry
        page_servers[0].addr = pr->pe->addr;
        page_servers[0].sk = pico_conn_server(pr->pe->addr, pr->pe->port);
        page_servers_arr.elems[0] = (void*) &page_servers[0];
        page_servers_ct++;
    }

    page_server tmp = { .sk = 0, .addr = pr->pe->addr };
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

        page_servers[page_servers_ct].addr = pr->pe->addr;
        page_servers[page_servers_ct].sk = pico_conn_server(pr->pe->addr, pr->pe->port);
        page_servers_arr.elems[page_servers_ct] = (void*) &page_servers[page_servers_ct];
        server = &page_servers[page_servers_ct];
        page_servers_ct++;

        quicksort(0, page_servers_ct-1, &page_servers_arr);
    }

    return server->sk;

jail:
    return 1;
}
