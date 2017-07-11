#ifndef _PJ_PAGE_LIST_H
#define _PJ_PAGE_LIST_H

struct pico_page_list {
    unsigned long addr;
    unsigned long size;
    struct pico_page_list *next;
};

#endif /* _PJ_PAGE_LIST_H */
