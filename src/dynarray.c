#include <stdlib.h>

typedef struct {
    char *array;
    size_t used;
    size_t size;
} dynamic_array;

void dynarray_init(dynamic_array *dynarray, size_t size) {
    dynarray->array = malloc(size * sizeof(int));
    dynarray->used = 0;
    dynarray->size = size;
}

void dynarray_insert(dynamic_array *dynarray, char *ip_address) {
  // a->used is the number of used entries, because a->array[a->used++] updates a->used only *after* the array has been accessed.
  // Therefore a->used can go up to a->size 
  if (dynarray->used == dynarray->size) {
    dynarray->size *= 2;
    dynarray->array = realloc(dynarray->array, dynarray->size * sizeof(ip_address));
  }
  dynarray->array[dynarray->used++] = *ip_address;
}

/*int check_unique(dynamic_array *dynarray, char address) {

}
*/
int dynarray_size(dynamic_array *dynarray) {
  return dynarray->array[0];
}

void dynarray_close(dynamic_array *dynarray) {
  free(dynarray->array);
  dynarray->array = NULL;
  dynarray->used = 0;
  dynarray->size = 0;
}