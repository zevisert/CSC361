#pragma once
#include <stdlib.h>

typedef struct {
	int *array;
	size_t used;
	size_t size;
} DynArray;

void initArray(DynArray *a, size_t initialSize) {
	a->array = (int *)malloc(initialSize * sizeof(int));
	a->used = 0;
	a->size = initialSize;
}

void insertArray(DynArray *a, int element) {
	if (a->used == a->size) {
		a->size *= 2;
		a->array = (int *)realloc(a->array, a->size * sizeof(int));
	}
	a->array[a->used++] = element;
}

void freeArray(DynArray *a) {
	free(a->array);
	a->array = NULL;
	a->used = a->size = 0;
}