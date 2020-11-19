#include "dispatch.h"

#include <pcap.h>

#include <pthread.h>

#include <stdlib.h>

#include <string.h>

#include "analysis.h"
 // threads and locks
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
pthread_t threads[8];
// struct to store packet as linked list/queue node
struct packet_queue {
  int length;
  int number;
  const unsigned char * packet;
  struct packet_queue * next;
};
// set list to null
struct packet_queue * head = NULL;
struct packet_queue * tail = NULL;
// flags
int run = 0;
int packets = 0;
int v;

// Dequeue function
void * dequeue(void * arg) {
  // while threads are active
  while (run) {
    // lock
    pthread_mutex_lock( & lock);
    // while no packets in queue
    while (packets == 0) {
      // wait for signal
      pthread_cond_wait( & cond, & lock);
    }
    // ensure thread terminates correctly
    if (run) {
      // pointer to head for later
      struct packet_queue * tmp = head;
      // malloc to store packet
      struct packet_queue * packet2go = (struct packet_queue * ) malloc(sizeof(struct packet_queue));
      // prep head for analysis
      * packet2go = * head;
      // if last packet in queue
      if (head == tail) {
        // reset queue
        head = NULL;
        tail = NULL;
      }
      // otherwise move head to next
      else {
        head = head -> next;
      }
      // decrease size variable
      packets--;
      // free head
      free(tmp);
      //unlock
      pthread_mutex_unlock( & lock);
      // send packet for analysis
      analyse(packet2go -> length, packet2go -> packet, v);
      // free stored packet
      free(packet2go);
    } else {
      // unlock
      pthread_mutex_unlock( & lock);
    }

  }
  return NULL;
}

// enqueue function
void enqueue(int length,
  const unsigned char * packet) {
  // lock
  pthread_mutex_lock( & lock);
  // if queue empty make and set the head
  if (head == NULL) {
    head = (struct packet_queue * ) malloc(sizeof(struct packet_queue));
    head -> length = length;
    head -> packet = packet;
    head -> number = packets;
    head -> next = NULL;
  }
  //otherwise
  else {
    struct packet_queue * current = (struct packet_queue * ) head;
    // loop through list until you get to the end of the queue
    while (current -> next != NULL) {
      current = current -> next;
    }
    // add packet to the end of queue
    current -> next = (struct packet_queue * ) malloc(sizeof(struct packet_queue));
    current -> next -> length = length;
    current -> next -> packet = packet;
    current -> next -> number = packets;
    current -> next -> next = NULL;
  }
  // increase packet count
  packets++;
  // signal that queue is no longer empty/ has a new packet in
  pthread_cond_signal( & cond);
  // unlock
  pthread_mutex_unlock( & lock);
}
//function to join threads on exit
void close_threads() {
  //lock
  pthread_mutex_lock( & lock);
  // reset flags
  run = 0;
  packets = 1;
  // unblock all threads
  pthread_cond_broadcast( & cond);
  // unlock
  pthread_mutex_unlock( & lock);
  // destroy lock and condition
  pthread_mutex_destroy( & lock);
  pthread_cond_destroy( & cond);
  int i;
  // join all threads
  for (i = 0; i < 8; i++) {
    pthread_join(threads[i], NULL);
  }
}
// main dispatch function
void dispatch(struct pcap_pkthdr * header,
  const unsigned char * packet, int verbose) {
  int i;
  // if running for first time
  if (run != 1) {
    // set flag
    run = 1;
    // create threads
    for (i = 0; i < 8; i++) {
      pthread_create( & threads[i], NULL, & dequeue, (void * ) NULL);
    }
  }
  // copy packet into memory so it is not overwritten by new incoming packet
  unsigned char * payload = malloc(256);
  memcpy(payload, packet, 256);
  // flags
  v = verbose;
  int length = header -> len;
  // queue up packet 
  enqueue(length, payload);
}