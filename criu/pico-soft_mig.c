#include <arpa/inet.h>
#include <netinet/in.h>

#include "log.h"
#include "migrate.h"
#include "pico-soft_mig.h"

static long unsigned addrs[SM_ADDR_LIMIT] = { 0 };
static int counts[SM_ADDR_LIMIT] = { 0 };

static int addrs_size = 0;

static struct sm_node_t *head = NULL;
static int num_nodes = 0;

int
pico_soft_migrate(unsigned int addr)
{
    int i;

    // initialize data structure
    if (head == NULL) {
        head = malloc(sizeof(struct sm_node_t));
        head->addr = -1;
        head->next = NULL;
        num_nodes++;
    }

    // replace the fault record at head

    // decrement the count for the address stored at head
    // increment the count for the new address, creating new index not in array (and increment size)
    char found_addr = 0;
    int addr_index = -1;
    for (i=0; i < addrs_size; i++) {
        if (addrs[i] == head->addr) {
            counts[i]--;
        }
        if (addrs[i] == addr) {
            found_addr = 1;
            addr_index = i;
            counts[i]++;
        }
    }
    if (!found_addr) {
        addrs[addrs_size] = addr;
        counts[addrs_size] = 1;
        addr_index = addrs_size;
        addrs_size++;
    }

    // replace the data at head with current time, addr
    head->addr = addr;
    gettimeofday(&head->time, NULL);

    // if count is above threshold, check time diff of head and head->next;
    if (counts[addr_index] > SM_COUNT_THRESH) {
        // if diff is below threshold, migrate_ip and return 1 for safety
        struct timeval tmp = head->time;
        timediff(&head->next->time, &tmp);
        if (tmp.tv_sec < SM_TIME_THRESH) {
            struct in_addr inaddr;
            inaddr.s_addr = addr;

            migrate_ip(inet_ntoa(inaddr));
            return 1;
        }
    }

    // increment head, create new node if needed
    if (head->next == NULL) {
        head->next = malloc(sizeof(struct sm_node_t));
        head->next->next = head;
        head->next->addr = -1;
        num_nodes++;
    }
    else if (num_nodes < SM_NODE_LIMIT) {
        struct sm_node_t *u = malloc(sizeof(struct sm_node_t));
        u->addr = -1;
        u->next = head->next;
        head->next = u;
        num_nodes++;
    }
    head = head->next;

    // return 0 (indicate no migration)
    return 0;
}
