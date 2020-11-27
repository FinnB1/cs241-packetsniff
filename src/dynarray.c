#include <stdlib.h>

#include <string.h>

#include <stdio.h>

typedef struct {
  size_t used;
  size_t size;
  char array[][15];
}
dynamic_array;

/**
* Initialise dynamic array
* @param dynarray array to be initialised
* @param size start size of array
*/
void dynarray_init(dynamic_array * dynarray, size_t size) {
  dynarray -> used = 0;
  dynarray -> size = size;
}

/**
* Checks if supplied IP address is already stored in the array.
* @param dynarray array to be checked
* @param address address to be checked
* @return flag 1 if unique otherwise 0
*/
int check_unique(dynamic_array * dynarray, char * address) {
  //loop through array
  for (int i = 0; i < dynarray -> used; i++) {
    // if ip already exists return 0
    if (strcmp((char * ) dynarray -> array[i], address) == 0) {
      return 0;
    }
  }
  return 1;
}

/**
* Inserts ip address into dynamic array
* @param dynarray array 
* @param ip_address address to be inserted
*/
void dynarray_insert(dynamic_array * dynarray, char * ip_address) {
  // if address already in array exit
  if (check_unique(dynarray, ip_address) == 0)
    return;
  //otherwise add it to array
  strcpy(dynarray -> array[dynarray -> used], ip_address);
  dynarray -> used++;
}

/**
* Check how many ip's are stored
* @param dynarray array
* @return number of ip's
*/
int dynarray_size(dynamic_array * dynarray) {
  return dynarray -> used;
}

/**
* Resets array
* @param dynarray array
*/
void dynarray_close(dynamic_array * dynarray) {
  dynarray -> used = 0;
  dynarray -> size = 0;
}