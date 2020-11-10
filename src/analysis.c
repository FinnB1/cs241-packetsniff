#include "analysis.h"

#include <pcap.h>
#include <string.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include "sniff.h"
#include "dynarray.h"

void analyse(struct pcap_pkthdr *header,
             const unsigned char *packet,
             int verbose) {
  // TODO your part 2 code here
  struct ip *ip;
  struct tcphdr *tcp;

  int length = header->len;

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

  if (tcp->syn == 1) {
      syn_count++;
      //check if internal ?
      if (strcmp(inet_ntoa(ip->ip_src), "10.0.2.15") != 0){
        dynarray_insert(&syn_adds, inet_ntoa(ip->ip_src));
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
