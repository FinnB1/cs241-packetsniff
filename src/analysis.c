#include "analysis.h"

#include <pcap.h>
#include <string.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include "sniff.h"
#include "dynarray.h"

void arp(const unsigned char *packet) {
  // add verbose stuff
    struct ether_arp *arp_header = (struct ether_arp *) packet;
    if (ntohs(arp_header->arp_op) == ARPOP_REPLY) {
      arp_count++;
    }
}

void blacklist(const unsigned char *packet, int length) {
  char * get = "GET";
  char * post = "POST";
  char * host = "Host:";
  struct tcphdr *tcp = (struct tcphdr *) packet;
  packet+= tcp->doff * 4;
  length-= tcp->doff * 4;

  char *payload = (char *) packet;
  // filter out packets that do not contain header
  if (strncmp(payload, get, strlen(get)) != 0 && strncmp(payload, post, strlen(post)) != 0) {
    return;
  }
  char *token;
  token = strtok(payload, "\r\n");
  while (strncmp(token, host, strlen(host)) != 0) {
    token = strtok(NULL, "\r\n");
  }
  token = strtok(token, " ");
  token = strtok(NULL, " ");
  if (strcmp(token, "www.google.com") == 0) {
    blacklist_count++;
  }
}

void analyse(struct pcap_pkthdr *header,
             const unsigned char *packet,
             int verbose) {
  // TODO your part 2 code here
  struct ip *ip;
  struct tcphdr *tcp;
  struct ether_header *eth_header = (struct ether_header *) packet;
  int length = header->len;
  if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP) {
    packet += ETH_HLEN;
    arp(packet);
  }
    
  
  packet += sizeof(struct ether_header);
  length -= sizeof(struct ether_header);

  ip = (struct ip*) packet;
  unsigned int IP_header_length = ip->ip_hl * 4;
  if (ip->ip_p != 6) {
    return;
  }

  packet += IP_header_length;
  length -= IP_header_length;

  tcp = (struct tcphdr*) packet;

  // check if ip is src (aka packet is outgoing) and port is 80 (http)
  if (strcmp(inet_ntoa(ip->ip_src), "10.0.2.15") == 0 && ntohs(tcp->dest) == 80) {
    blacklist(packet, length);
  }

  
  if (tcp->syn == 1) {
      
      //check if packet is incoming from external ip ?
      if (strcmp(inet_ntoa(ip->ip_src), "10.0.2.15") != 0){
        dynarray_insert(&syn_adds, inet_ntoa(ip->ip_src));
        //printf("%d\n", dynarray_size(&syn_adds));
        syn_count++;
      }
        
  }

  if (verbose == 1) {
    printf("TCP src_port = %d dst_port = %d\nsyn = %d ack = %d\n",
          ntohs(tcp->source),
          ntohs(tcp->dest),
          ntohs(tcp->syn),
          ntohs(tcp->ack));
  }
  
}


