#ifndef _PJ_UTIL_H
#define _PJ_UTIL_H

#include <stdint.h>

uint32_t *
parse_pico_dist(char *s);

char
pagemap_contains_addr(int, uint32_t *, uint32_t);

#endif /* _PJ_UTIL_H */
