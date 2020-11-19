#include "analysis.h"

#include <pcap.h>

#include <pthread.h>

#include <string.h>

#include <netinet/if_ether.h>

#include <netinet/ip.h>

#include <netinet/tcp.h>

#include "sniff.h"

#include "dynarray.h"

pthread_mutex_t syn_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t blacklist_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t arp_lock = PTHREAD_MUTEX_INITIALIZER;

void arp(const unsigned char * packet, int verbose) {
  // ethernet arp structure
  packet += ETH_HLEN;
  int i;
  struct ether_arp * arp_header = (struct ether_arp * ) packet;
  // if ARP message is a response then increment count
  if (ntohs(arp_header -> arp_op) == ARPOP_REPLY) {
    pthread_mutex_lock( & arp_lock);
    arp_count++;
    pthread_mutex_unlock( & arp_lock);
  }
  // DEBUGGING PRINTS
  if (verbose == 1) {
    printf("----ARP MESSAGE RECEIVED----\n");
    printf("Sender HWA: ");
    for (i = 0; i < 6; ++i) {
      printf("%02x", arp_header -> arp_sha[i]);
      if (i < 5) {
        printf(":");
      }
    }
    printf("\n");
    printf("Sender PA: ");
    for (i = 0; i < 4; ++i) {
      printf("%02x", arp_header -> arp_spa[i]);
      if (i < 3) {
        printf(":");
      }
    }
    printf("\n");
    printf("Target HWA: ");
    for (i = 0; i < 6; ++i) {
      printf("%02x", arp_header -> arp_tha[i]);
      if (i < 5) {
        printf(":");
      }
    }
    printf("\n");
    printf("Target PA: ");
    for (i = 0; i < 4; ++i) {
      printf("%02x", arp_header -> arp_spa[i]);
      if (i < 3) {
        printf(":");
      }
    }
    printf("\n");
    printf("ARP Operation: %d\n", ntohs(arp_header -> arp_op));
    printf("\n");
  }
}

// URL blacklisting function
void blacklist(const unsigned char * packet, int length, int verbose) {
  //tcp header
  struct tcphdr * tcp = (struct tcphdr * ) packet;
  //move past tcp header to packet data
  packet += tcp -> doff * 4;
  length -= tcp -> doff * 4;

  // convert packet data to char * (bad code)
  char * payload = (char * ) packet;
  char needle[8] = "Host";
  char * ret;
  // point to line containing "Host: ", if not present then skip
  if ((ret = strstr(payload, needle)) != NULL) {
    // trim by end of line characters
    ret = strtok(ret, "\r\n");
    // if equal to blacklisted URL
    if (strcmp(ret, "Host: www.google.com") == 0) {
      // increase count
      pthread_mutex_lock( & blacklist_lock);
      blacklist_count++;
      pthread_mutex_unlock( & blacklist_lock);
      // DEBUGGING PRINTS
      if (verbose == 1) {
        printf("----BLACKLISTED URL FOUND----\n");
        printf("Outgoing packet to www.google.com found\n\n");
      }
    }
  }

}

//main analyse function
void analyse(int length,
  const unsigned char * packet, int verbose) {
  //headers
  struct ip * ip;
  struct tcphdr * tcp;
  struct ether_header * eth_header = (struct ether_header * ) packet;
  // if packet contains ARP message
  if (ntohs(eth_header -> ether_type) == ETHERTYPE_ARP) {
    //process
    arp(packet, verbose);
  }

  //move past ethernet header
  packet += sizeof(struct ether_header);
  length -= sizeof(struct ether_header);

  ip = (struct ip * ) packet;
  // calculate ip header length
  unsigned int iphl = ip -> ip_hl * 4;
  // if protocol is not TCP return
  if (ip -> ip_p != 6) {
    return;
  }

  //skip IP header
  packet += iphl;
  length -= iphl;

  // tcp header
  tcp = (struct tcphdr * ) packet;

  // check if ip is src (aka packet is outgoing) and port is 80 (http)
  if (strcmp(inet_ntoa(ip -> ip_src), "10.0.2.15") == 0 && ntohs(tcp -> dest) == 80) {
    //process
    blacklist(packet, length, verbose);
    return;
  }

  // if syn bit is set to 1
  if (tcp -> syn == 1) {

    //check if packet is incoming from external ip
    if (strcmp(inet_ntoa(ip -> ip_src), "10.0.2.15") != 0) {
      //insert IP address to dynamic array

      // DEBUGGING PRINTS
      if (verbose == 1) {
        printf("----SYN PACKET RECEIVED----\n");
        printf("Source IP address: %s\n", inet_ntoa(ip -> ip_src));
        printf("Destination IP address: %s\n", inet_ntoa(ip -> ip_dst));
        printf("Source Port: %d\n", ntohs(tcp -> source));
        printf("Destination Port: %d\n", ntohs(tcp -> dest));
        printf("SYN: %d\n", tcp -> syn);
        printf("ACK: %d\n", tcp -> ack);
        printf("\n");

      }
      //lock
      pthread_mutex_lock( & syn_lock);
      dynarray_insert( & syn_adds, inet_ntoa(ip -> ip_src));
      //increment count
      syn_count++;
      pthread_mutex_unlock( & syn_lock);
    }

  }

}