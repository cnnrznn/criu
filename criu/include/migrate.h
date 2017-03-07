#ifndef _CR_PICO_MIGRATE_H
#define _CR_PICO_MIGRATE_H

#define CHECK_FD        "\x00"
#define MIGRATE_IP      "\x01"
#define MIGRATE_FD      "\x02"
#define CLOSE_FD        "\x03"

#define PICOMAN_ADDR "/tmp/pico"

void
migrate_ip(const char ip[15]);

void
migrate_fd(int fd);

int
check_fd(int fd);

void
close_fd(int fd);

#endif /* _CR_PICO_MIGRATE_H */
