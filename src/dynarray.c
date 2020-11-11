#include <stdlib.h>
#include <string.h>
#include <stdio.h>

typedef struct {
    size_t used;
    size_t size;
    char array[][15];
} dynamic_array;

void dynarray_init(dynamic_array *dynarray, size_t size) {
    dynarray->used = 0;
    dynarray->size = size;
}

int check_unique(dynamic_array *dynarray, char *address) {
  for (int i = 0; i < dynarray->used; i++) {
    char *ip = (char *) malloc(sizeof(address));
    ip = (char *) dynarray->array[i];
    //printf("ip set to %s\n used: %ld, index: %d\n", ((char *) dynarray->array[i]), dynarray->used, i);
    //printf("Comparing %s to %s\n", ip, address);
    if (strcmp(ip, address) == 0) {
      //printf("Duplicate IP found\n");
      return 0;
    }
    //printf("not a duplicate\n");
    //printf("%s compared to %s\n", ip, address);
  }
  return 1;
} 

void dynarray_insert(dynamic_array *dynarray, char *ip_address) {
  // a->used is the number of used entries, because a->array[a->used++] updates a->used only *after* the array has been accessed.
  // Therefore a->used can go up to a->size
  if (check_unique(dynarray, ip_address) == 0) 
    return;
  if (dynarray->used == dynarray->size) {
    //dynarray = realloc(dynarray, dynarray->size * sizeof(ip_address));
  }
  strcpy(dynarray->array[dynarray->used], ip_address);
  dynarray->used++;
}



int dynarray_size(dynamic_array *dynarray) {
  return dynarray->used;
}

void dynarray_close(dynamic_array *dynarray) {
  dynarray->used = 0;
  dynarray->size = 0;
}