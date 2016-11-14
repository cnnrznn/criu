#include "binsearch.h"

#include <stdlib.h>

void* binsearch(array *arr, void *other, int start, int end)
{
    char res;
    int first = start, last = end;
    int index = (first + last) / 2;

    while (arr->comp(arr->elems[index], other) != 0) {
        if (last <= first)
            return NULL;

        res = arr->comp(arr->elems[index], other);
        if (res > 0)
            first = index + 1;
        else // res < 0
            last = index - 1;

        index = (first + last) / 2;
    }

    return arr->elems[index];
}
