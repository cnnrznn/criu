#include "binsearch.h"

void* binsearch(array *arr, void *other)
{
    char res;
    int index = arr->size / 2;
    int first = 0, last = arr->size-1;

    while (arr->comp(arr->elems[index], other) != 0) {
        res = arr->comp(arr->elems[index], other);
        if (res > 0)
            first = index + 1;
        else // res < 0
            last = index - 1;

        index = (first + last) / 2;
    }

    return arr->elems[index];
}
