#ifndef DYNARRAY_H_
#define DYNARRAY_H_
#include <stdlib.h>

typedef struct{
    int *array;
    size_t used;
    size_t size;
}  dynamic_array; 

void dynarray_init(dynamic_array *array, size_t size);
void dynarray_insert(dynamic_array *array, char *element);
int dynarray_size(dynamic_array *array);
void dynarray_close(dynamic_array *array);

#endif