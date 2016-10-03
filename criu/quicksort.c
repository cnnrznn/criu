#include "quicksort.h"

/*
 * I had some fun with naming conventions in this file:
 *  lohi - the place where lo and hi meet
 */

static void swap(int a, int b, array *arr)
{
    void *tmp = arr->elems[a];
    arr->elems[a] = arr->elems[b];
    arr->elems[b] = tmp;
}

static int partition(int lo, int hi, array *arr)
{
    void *pivot = arr->elems[hi];
    int i, lohi=lo;

    for (i=lo; i<hi; i++) {
        if (arr->comp(arr->elems[i], pivot) > 0) {
            swap(i, lohi++, arr);
        }
    }
    swap(hi, lohi, arr);

    return lohi;
}

void quicksort(int lo, int hi, array *arr)
{
    if (hi < lo) {
        return;
    }

    int lohi = partition(lo, hi, arr);

    quicksort(lo, lohi-1, arr);
    quicksort(lohi+1, hi, arr);
}
