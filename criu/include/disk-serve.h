#ifndef __CR_DISK_SERVE_H__
#define __CR_DISK_SERVE_H__

// number of processes to create buffers
#define DISK_SERVE_PSBUF_SIZE   1024

typedef struct disk_pages_t {
    int pid;
    struct page_read pr;
} disk_pages;

#endif /* __CR_DISK_SERVE_H__ */
