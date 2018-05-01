#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "log.h"
#include "pico-man.h"
#include "pico-page_list.h"

#define PICOMAN_ADDR "/tmp/pico"
#define PICOMAN_ALT "/tmp/picoa"

#define CRASH           "\x0A"
#define REMOTE_PAGES    "\x0E"
#define ACTIVESET       "\xA0"
#define MIGRATE_SOFT    "\xFF"
#define REMOTE_PAGES_FIN "\xA1"

static int
open_comm_sock()
{
    struct sockaddr_un addr;
    unsigned int addr_len;

    int sk;

    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, PICOMAN_ADDR);
    addr_len = sizeof(struct sockaddr_un);

    sk = socket(AF_UNIX, SOCK_STREAM, 0);
    if (connect(sk, (struct sockaddr *)&addr, addr_len) == -1) {
        fprintf(stderr, "(%s:%d) failed to connect to manager\n", __FILE__, __LINE__);
        perror("migrate.c: connect");
        exit(1);
    }

    return sk;
}

static
int
open_alt_sock()
{
    struct sockaddr_un addr;
    unsigned int addr_len;

    int sk;

    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, PICOMAN_ALT);
    addr_len = sizeof(struct sockaddr_un);

    sk = socket(AF_UNIX, SOCK_STREAM, 0);
    if (connect(sk, (struct sockaddr *)&addr, addr_len) == -1) {
        fprintf(stderr, "(%s:%d) failed to connect to manager alt\n", __FILE__, __LINE__);
        perror("migrate.c: connect");
        exit(1);
    }

    return sk;
}

void
pico_crash(void)
{
    int sk;

    sk = open_comm_sock();

    if (write(sk, CRASH, 1) != 1)
        exit(1);

    close(sk);
}

void
pico_remote_pages(uint32_t addr, struct pico_page_list *pl, int n)
{
    int sk = open_comm_sock();
    struct pico_page_list *p;
    char dummy;

    if (write(sk, REMOTE_PAGES, 1) != 1)
        exit(1);

    if (write(sk, &addr, 4) != 4)
        exit(1);

    if (write(sk, &n, 4) != 4)
        exit(1);

    for (p=pl; p; p=p->next) {
        if (write(sk, &p->addr, 8) != 8)
            exit(1);
        if (write(sk, &p->size, 8) != 8)
            exit(1);
        if (read(sk, &p->ws, 1) != 1)
                exit(1);
    }

    read(sk, &dummy, 1); //block in case of migration

    close(sk);
}

void
pico_remote_pages_fin()
{
    int sk;

    sk = open_comm_sock();
    write(sk, REMOTE_PAGES_FIN, 1);
    close(sk);
}

void
migrate_soft(const char ip[15])
{
    int sk;
    char ret;

    sk = open_comm_sock();

    if (write(sk, MIGRATE_SOFT, 1) != 1)
        exit(1);
    if (write(sk, ip, 15) != 15)
        exit(1);
    if (read(sk, &ret, 1) != 1)
        exit(1);

    close(sk);

    if (ret == 's')
        sleep(3600);
}

void
activeset_append(struct iovec iov, void *buf)
{
        int sk;

        sk = open_alt_sock(); // happens during dump, main socket occupied

        write(sk, &iov.iov_base, 8);
        write(sk, &iov.iov_len, 8);
        write(sk, buf, iov.iov_len);

        close(sk);
}

void
activeset_get(unsigned long addr, unsigned long size, void *buf)
{
        int sk;
        int total = 0;
        int tmp;

        sk = open_comm_sock();

        write (sk, ACTIVESET, 1);

        write(sk, &addr, 8);
        write(sk, &size, 8);
        while (total < size) {
                tmp = read(sk, buf + total, size - total);
                total += tmp;
        }

        close(sk);
}
