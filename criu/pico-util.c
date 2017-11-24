#include "pico-util.h"

#include <arpa/inet.h>

#include "cr_options.h"
#include "log.h"

uint32_t *
parse_pico_dist(char *s)
{
    int i,j;
    int pos = -1;
    uint32_t *list = malloc(opts.pico_npeers * sizeof(uint32_t));

    for (i=0; i < opts.pico_npeers; i++) {
        char ip[16] = { 0 };
        j = -1;

        do {
            j++;
            pos++;
            ip[j] = s[pos];
        } while (ip[j] != ',');
        ip[j] = '\0';

        struct in_addr tmp;

        inet_aton(ip, &tmp);
        list[i] = tmp.s_addr;

        pr_debug("CONNOR: dist - %d\n", list[i]);
    }

    return list;
}

char
pagemap_contains_addr(int naddrs, uint32_t *addrs, uint32_t target)
{
    int i;

    for (i=0; i < naddrs; i++) {
        if (addrs[i] == target)
            return 1;
    }

    return 0;
}
