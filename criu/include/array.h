#ifndef _CZARRAY
#define _CZARRAY

typedef struct array_t {
    int size;
    void **elems;
    char (*comp)(void*, void*);
} array;

void array_init(array*, int size, char (*)(void*,void*));
void array_free(array*);

#endif /* _CZARRAY */
