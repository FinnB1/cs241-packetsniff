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
  //loop through array
  for (int i = 0; i < dynarray->used; i++) {
    char *ip = (char *) malloc(sizeof(address));
    ip = (char *) dynarray->array[i];
    // if ip already exists return 0
    if (strcmp(ip, address) == 0) {
      return 0;
    }
  }
  return 1;
} 

void dynarray_insert(dynamic_array *dynarray, char *ip_address) {
  // if address already in array exit
  if (check_unique(dynarray, ip_address) == 0) 
    return;
  //otherwise add it to array
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