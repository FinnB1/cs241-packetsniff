#include "dispatch.h"

#include <pcap.h>
#include <pthread.h>
#include <stdlib.h>

#include "analysis.h"

struct packet_node {
    int length;
    const unsigned char *packet;
};

int v;

void *process(void *args) {
    struct packet_node *dpack = (struct packet_node *) args;
    analyse(dpack->length, dpack->packet, v);
    return NULL;
}

void dispatch(struct pcap_pkthdr *header, const unsigned char *packet, int verbose) {
    pthread_t thread;
    v = verbose;
    struct packet_node *args = malloc(sizeof(struct packet_node));
    args->length = header->len;
    args->packet = packet;
    pthread_create(&thread, NULL, &process, (void *) args);
    pthread_detach(thread);
}