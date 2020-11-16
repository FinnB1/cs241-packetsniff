#include "dispatch.h"

#include <pcap.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "analysis.h"

pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
pthread_t threads[4];

struct packet_queue {
  int length;
  int number;
  const unsigned char *packet;
  struct packet_queue *next;
};
struct packet_queue *head = NULL;
struct packet_queue *tail = NULL;

int run = 0;
int packets = 0;
int v;

void *dequeue(void *arg) {
  while (run) {
    pthread_mutex_lock(&lock);
    while (packets < 1) {
      pthread_cond_wait(&cond, &lock);
    }
    if (run) {
      struct packet_queue *tmp = head;
      struct packet_queue *packet2go = (struct packet_queue *) malloc(sizeof(struct packet_queue));
      *packet2go = *head;
      if (head == tail) {
       head = NULL;
       tail = NULL;
      }
      else {
       head = head->next;  
      }
      packets--;
      free(tmp);
      pthread_mutex_unlock(&lock);
      analyse(packet2go->length, packet2go->packet, v);
      free(packet2go);
    }
    else {
      pthread_mutex_unlock(&lock);
    }



  }
  return arg;
}

void enqueue(int length,
              const unsigned char *packet) {
  pthread_mutex_lock(&lock);
  if (head == NULL) {
    head = (struct packet_queue *) malloc(sizeof(struct packet_queue));
    head->length = length;
    head->packet = packet;
    head->number = packets;
    head->next = NULL;
  }
  else {
    //printf("head val %d\n", head->header->len);
    struct packet_queue *current = (struct packet_queue *) head;
    while (current->next != NULL) {
      //printf("going frm no %d to %d\n", current->number, current->next->number);
      current = current->next;
    }
    current->next = (struct packet_queue *) malloc(sizeof(struct packet_queue));
    current->next->length = length;
    current->next->packet = packet;
    current->next->number = packets;
    current->next->next = NULL;
  }


  packets++;
  pthread_cond_signal(&cond);
  pthread_mutex_unlock(&lock);
}

void close_threads() {
  pthread_mutex_lock(&lock);
  run = 0;
  packets = 1;
  pthread_cond_broadcast(&cond);
  pthread_mutex_unlock(&lock);
  pthread_mutex_destroy(&lock);
  pthread_cond_destroy(&cond);
  int i;
  for (i = 0; i < 4; i++) {
    pthread_join(threads[i], NULL);
  }
}

void printqueue() {
  struct packet_queue * current = head;
  int i = 50;
  while (i > 0 && current != NULL) {
    printf("Number %d with header length: %d\n", current->number, current->length);
    current = current->next;
    i--;
  }
}

void dispatch(struct pcap_pkthdr *header,
              const unsigned char *packet,
              int verbose) {
  // TODO: Your part 2 code here
  // This method should handle dispatching of work to threads. At present
  // it is a simple passthrough as this skeleton is single-threaded.
  int i;
  if (run != 1) {
    run = 1;
    for (i= 0; i < 4; i++) {
      pthread_create(&threads[i], NULL, &dequeue, (void *) NULL);
    }
  }
  unsigned char* payload = malloc(64);
  memcpy(payload, packet, 64);
  v = verbose;
  int length = header->len;

  enqueue(length, payload);
}
