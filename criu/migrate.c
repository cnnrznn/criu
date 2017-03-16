#include <stdlib.h>
#include <unistd.h>
#include <dlfcn.h>
#include <stdio.h>
#include <sys/un.h>
#include <sys/socket.h>

#include "migrate.h"

static unsigned int psock;
static struct sockaddr_un paddr;
static unsigned int paddr_len;
static char ret;
static char init = 0;

static int      (*real_socket) (int sk_family, int sk_type, int prot);
static int      (*real_close) (int fd);
static ssize_t  (*real_write) (int fd, const void *buf, size_t count);
static ssize_t  (*real_read) (int fd, void *buf, size_t count);
static int      (*real_connect) (int fd, const struct sockaddr *addr, socklen_t len);

static void
libc_init()
{
    if (init)
        return;
    init = 1;

    void *libc = dlopen("libc.so.6", RTLD_LAZY);
    if (!libc) goto crash;

    real_socket     = dlsym(libc, "socket");
    if (!real_socket) goto crash;
    real_close      = dlsym(libc, "close");
    if (!real_close) goto crash;
    real_write      = dlsym(libc, "write");
    if (!real_write) goto crash;
    real_read       = dlsym(libc, "read");
    if (!real_read) goto crash;
    real_connect    = dlsym(libc, "connect");
    if (!real_connect) goto crash;

    return;

crash:
    printf("%s\n", dlerror());
    exit(1);
}

static void
open_comm_sock()
{
    paddr.sun_family = AF_UNIX;
    strcpy(paddr.sun_path, PICOMAN_ADDR);
    paddr_len = sizeof(struct sockaddr_un);

    psock = real_socket(AF_UNIX, SOCK_STREAM, 0);
    if (real_connect(psock, (struct sockaddr *)&paddr, paddr_len) == -1) {
        perror("connect");
        exit(1);
    }
}

void
migrate_ip(const char ip[15])
{ libc_init();

    open_comm_sock();

    real_write(psock, MIGRATE_IP, 1);
    real_write(psock, ip, 15);
    real_read(psock, &ret, 1);
    real_close(psock);

    if (ret == 's')
        sleep(3600);
}

void
migrate_fd(int fd)
{ libc_init();

    open_comm_sock();

    real_write(psock, MIGRATE_FD, 1);
    char buf[15] = { 0 };
    sprintf(buf, "%d", fd);
    real_write(psock, buf, 15);
    real_read(psock, &ret, 1);
    real_close(psock);

    if (ret == 's')
        sleep(3600);
}

int
check_fd(int fd)
{ libc_init();

    open_comm_sock();

    real_write(psock, CHECK_FD, 1);
    char buf[15] = { 0 };
    sprintf(buf, "%d", fd);
    real_write(psock, buf, 15);
    memset(buf, 0, 15);
    real_read(psock, buf, 15);
    real_close(psock);

    return atoi(buf);
}

void
close_fd(int fd)
{ libc_init();

    open_comm_sock();

    real_write(psock, CLOSE_FD, 1);
    char buf[15] = { 0 };
    sprintf(buf, "%d", fd);
    real_write(psock, buf, 15);
    real_close(psock);
}
