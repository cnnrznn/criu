#ifndef _PJ_SOFT_MIG_H
#define _PJ_SOFT_MIG_H

#define SM_NODE_LIMIT 1024
#define SM_ADDR_LIMIT 1024

#define SM_COUNT_THRESH 1000
#define SM_TIME_THRESH 1

struct sm_node_t {
    unsigned int addr;
    struct timeval time;
    struct sm_node_t *next;
};

extern int
pico_soft_migrate(unsigned int);

#endif /* _PJ_SOFT_MIG_H */
