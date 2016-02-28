#pragma once
#include <stdlib.h>
#include <sys/time.h>

struct array_t
{
	unsigned int data;
	struct timeval ts;
};

typedef struct {
	struct array_t* array;
	size_t used;
	size_t size;
} DynArray;

int initArray(DynArray *a, size_t initialSize) {
	a->array = (struct array_t*)malloc(initialSize * sizeof(struct array_t));
	a->used = 0;
	a->size = initialSize;
	return 0;
}

void insertArray(DynArray *a, struct array_t element) {
	if (a->used == a->size) {
		a->size *= 2;
		a->array = (struct array_t*)realloc(a->array, a->size * sizeof(struct array_t));
	}
	a->array[a->used++] = element;
}

void freeArray(DynArray *a) {
	free(a->array);
	a->array = NULL;
	a->used = a->size = 0;
}