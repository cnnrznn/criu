#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "pico-man.h"

#define CRASH           "\x0A"
#define MIGRATE_SOFT    "\x0C"
#define PICOMAN_ADDR "/tmp/pico"

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
