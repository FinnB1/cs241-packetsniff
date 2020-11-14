#include "dispatch.h"

#include <pcap.h>
#include <pthread.h>
#include <stdlib.h>

#include "analysis.h"

pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
pthread_t threads[4];

struct packet_queue {
  struct pcap_pkthdr *header;
  unsigned char *packet;
  struct packet_queue *next;
};
struct packet_queue *head;
struct packet_queue *tail;

int run;
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
      analyse(packet2go->header, packet2go->packet, v);



      free(packet2go);
    }
    else {
      pthread_mutex_unlock(&lock);
    }



  }
  return arg;
}

void enqueue(struct packet_queue *pq) {
  pthread_mutex_lock(&lock);
  if (head == NULL) {
    head = pq;
    tail = pq;
  }
  else {
    tail->next = pq;
    tail = pq;
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


void dispatch(struct pcap_pkthdr *header,
              const unsigned char *packet,
              int verbose) {
  // TODO: Your part 2 code here
  // This method should handle dispatching of work to threads. At present
  // it is a simple passthrough as this skeleton is single-threaded.
  v = verbose;
  int i;
  if (run != 1) {
    run = 1;
    for (i= 0; i < 4; i++) {
      pthread_create(&threads[i], NULL, dequeue, (void *) NULL);
    }
  }

  struct packet_queue *next_packet = (struct packet_queue *) malloc(sizeof(struct packet_queue));
  next_packet->header = (struct pcap_pkthdr *) header;
  next_packet->packet = (unsigned char * ) packet;
  next_packet->next = NULL;
  enqueue(next_packet);
}
