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

void arp(const unsigned char *packet, int verbose) {
    // ethernet arp structure
    packet += ETH_HLEN;
    int i;
    struct ether_arp *arp_header = (struct ether_arp *) packet;
    // if ARP message is a response then increment count
    if (ntohs(arp_header->arp_op) == ARPOP_REPLY) {
      pthread_mutex_lock(&arp_lock);
      arp_count++;
      pthread_mutex_unlock(&arp_lock);
    }

    if (verbose == 1) {
      printf("----ARP MESSAGE RECEIVED----\n");
      printf("Sender HWA: ");
      for (i = 0; i < 6; ++i) {
        printf("%02x", arp_header->arp_sha[i]);
        if (i<5) {
          printf(":");
        }
      }
      printf("\n");
      printf("Sender PA: ");
      for (i = 0; i < 4; ++i) {
        printf("%02x", arp_header->arp_spa[i]);
        if (i<3) {
          printf(":");
        }
      }
      printf("\n");
      printf("Target HWA: ");
      for (i = 0; i < 6; ++i) {
        printf("%02x", arp_header->arp_tha[i]);
        if (i<5) {
          printf(":");
        }
      }
      printf("\n");
      printf("Target PA: ");
      for (i = 0; i < 4; ++i) {
        printf("%02x", arp_header->arp_spa[i]);
        if (i<3) {
          printf(":");
        }
      }
      printf("\n");
      printf("ARP Operation: %d\n", ntohs(arp_header->arp_op));
      printf("\n");
    }
}

void blacklist(const unsigned char *packet, int length, int verbose) {
  // strings for comparison
  char * get = "GET";
  char * post = "POST";
  char * host = "Host:";
  //tcp header
  struct tcphdr *tcp = (struct tcphdr *) packet;
  //move past tcp header to packet data
  packet+= tcp->doff * 4;
  length-= tcp->doff * 4;

  char *payload = (char *) packet;
  // filter out packets that do not contain header
  if (strncmp(payload, get, strlen(get)) != 0 && strncmp(payload, post, strlen(post)) != 0) {
    return;
  }
  char *token;
  // split string into tokens by line
  token = strtok(payload, "\r\n");
  // check if line starts with "Host:"
  while (strncmp(token, host, strlen(host)) != 0) {
    token = strtok(NULL, "\r\n");
  }
  // split string by whitespace
  token = strtok(token, " ");
  token = strtok(NULL, " ");
  // if it matches the blacklisted URL then increment count
  if (strcmp(token, "www.google.com") == 0) {
    pthread_mutex_lock(&blacklist_lock);
    blacklist_count++;
    pthread_mutex_unlock(&blacklist_lock);
    if (verbose == 1) {
    printf("----BLACKLISTED URL----\n");
    printf("Outgoing packet to www.google.com found\n\n");
  }
  }
  
}

void analyse(struct pcap_pkthdr *header,
             const unsigned char *packet,
             int verbose) {
  //headers
  struct ip *ip;
  struct tcphdr *tcp;
  struct ether_header *eth_header = (struct ether_header *) packet;
  // if packet contains ARP message
  int length = header->len;
  int i;
  if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP) {
    //process
    arp(packet, verbose);
  }
    
  //move past ethernet header
  packet += sizeof(struct ether_header);
  length -= sizeof(struct ether_header);

  ip = (struct ip*) packet;
  // calculate ip header length
  unsigned int iphl = ip->ip_hl * 4;
  // if protocol is not TCP return
  if (ip->ip_p != 6) {
    return;
  }

  //skip IP header
  packet += iphl;
  length -= iphl;

  // tcp header
  tcp = (struct tcphdr*) packet;

  // check if ip is src (aka packet is outgoing) and port is 80 (http)
  if (strcmp(inet_ntoa(ip->ip_src), "10.0.2.15") == 0 && ntohs(tcp->dest) == 80) {
    //process
    blacklist(packet, length, verbose);
  }

  // if syn bit is set to 1
  if (tcp->syn == 1) {
      
      //check if packet is incoming from external ip
      if (strcmp(inet_ntoa(ip->ip_src), "10.0.2.15") != 0){
        //insert IP address to dynamic array

        if (verbose == 1) {
          printf("----PACKET RECEIVED----\n");
          printf("Source IP address: %s\n", inet_ntoa(ip->ip_src));
          printf("Source Port: %d\n", ntohs(tcp->source));
          printf("Destination Port: %d\n", ntohs(tcp->dest));
          printf("SYN: %d\n", tcp->syn);
          printf("ACK: %d\n", tcp->ack);
          printf("\n");

        }
        pthread_mutex_lock(&syn_lock);
        dynarray_insert(&syn_adds, inet_ntoa(ip->ip_src));
        //increment count
        syn_count++;
        pthread_mutex_unlock(&syn_lock);
      }
      
        
  }
  
}


