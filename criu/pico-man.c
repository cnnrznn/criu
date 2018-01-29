#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "pico-man.h"
#include "pico-page_list.h"

#define PICOMAN_ADDR "/tmp/pico"

#define CRASH           "\x0A"
#define REMOTE_PAGES    "\x0E"
#define MIGRATE_SOFT    "\xFF"

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

void
pico_crash(void)
{
    int sk;

    sk = open_comm_sock();

    if (write(sk, CRASH, 1) != 1)
        exit(1);

    close(sk);
}

int
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
    }

    read(sk, &dummy, 1); //block in case of migration

    return sk;
}

void
pico_remote_pages_fin(int sk)
{
    char dummy;
    write(sk, &dummy, 1);
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
