#include <stdlib.h>

typedef struct {
    int *array;
    size_t used;
    size_t size;
} dynamic_array;

void init(dynamic_array *array, size_t size) {
    array->array = malloc(size * sizeof(int));
    array->used = 0;
    array->size = size;
}

void insert(dynamic_array *array, int element) {
  // a->used is the number of used entries, because a->array[a->used++] updates a->used only *after* the array has been accessed.
  // Therefore a->used can go up to a->size 
  if (array->used == array->size) {
    array->size *= 2;
    array->array = realloc(array->array, array->size * sizeof(int));
  }
  array->array[array->used++] = element;
}