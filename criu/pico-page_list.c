#include <stdlib.h>

#include "pico-page_list.h"

void
pico_page_list_free(struct pico_page_list *pl)
{
    struct pico_page_list *tmp;

    while (pl) {
        tmp = pl;
        pl = pl->next;
        free(tmp);
    }
}
