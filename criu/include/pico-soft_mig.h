#ifndef _PJ_SOFT_MIG_H
#define _PJ_SOFT_MIG_H

#define SM_NODE_LIMIT 20000
#define SM_ADDR_LIMIT 1024

#define SM_COUNT_THRESH 2000
#define SM_TIME_THRESH 4

struct sm_node_t {
    unsigned int addr;
    int np;
    struct timeval time;
    struct sm_node_t *next;
};

extern int
pico_soft_migrate(unsigned int, int);

#endif /* _PJ_SOFT_MIG_H */
