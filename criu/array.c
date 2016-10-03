#include <stdlib.h>

#include "array.h"

void array_init(array *arr, int size, char (*compare)(void*,void*))
{
    arr->size = size;
    arr->comp = compare;
    arr->elems = malloc(size * sizeof(void*));
}

void array_free(array *arr)
{
    free(arr->elems);
}
