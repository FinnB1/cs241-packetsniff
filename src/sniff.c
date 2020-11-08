#ifndef __USE_BSD
#define __USE_BSD
#endif

#include "sniff.h"

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/in.h>


#include "dispatch.h"


struct UDP_hdr {
  u_short uh_sport;
  u_short uh_dport;
  u_short uh_ulen;
  u_short uh_sum;
};

void sig_handler(int signo) {
  if (signo == SIGINT) {
    printf("\nExiting\n");
    exit(0);
  }
}

// Application main sniffing loop
void sniff(char *interface, int verbose) {
  // Open network interface for packet capture
  signal(SIGINT, sig_handler);
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *pcap_handle = pcap_open_live(interface, 4096, 1, 0, errbuf);
  if (pcap_handle == NULL) {
    fprintf(stderr, "Unable to open interface %s\n", errbuf);
    exit(EXIT_FAILURE);
  } else {
    printf("SUCCESS! Opened %s for capture\n", interface);
  }
  // Capture packets (very ugly code)
  struct pcap_pkthdr header;
  const unsigned char *packet;
  while (1) {
    // Capture a  packet
    packet = pcap_next(pcap_handle, &header);
    if (packet == NULL) {
      // pcap_next can return null if no packet is seen within a timeout
      if (verbose) {
        printf("No packet received. %s\n", pcap_geterr(pcap_handle));
      }
    } else {
      // Optional: dump raw data to terminal
      if (verbose) {
        // tcp_dump(packet, header.len);
      }
      // Dispatch packet for processing
      dispatch(&header, packet, verbose);
    }
  }
}

void tcp_dump(const unsigned char *data, int length) {
  struct ip *ip;
  struct tcphdr *tcp;

  data += sizeof(struct ether_header);
  length -= sizeof(struct ether_header);

  ip = (struct ip*) data;
  unsigned int IP_header_length = ip->ip_hl * 4;

  if (ip->ip_p != 6) {
    return;
  }

  data += IP_header_length;
  length -= IP_header_length;

  tcp = (struct tcphdr*) data;

  printf("TCP src_port = %d dst_port = %d\nsyn = %d ack = %d\n",
          ntohs(tcp->th_sport),
          ntohs(tcp->th_dport),
          ntohs(tcp->syn),
          ntohs(tcp->th_ack));
}

void udp_dump(const unsigned char *data, int length) {
  struct ip *ip;
  struct UDP_hdr *udp;
  unsigned int IP_header_length;

  data += sizeof(struct ether_header);
  length -= sizeof(struct ether_header);

  ip = (struct ip*) data;
  IP_header_length = ip->ip_hl * 4;

  data += IP_header_length;
  length -= IP_header_length;

  udp = (struct UDP_hdr*) data;

  printf("UDP src_port = %d dst_port = %d length = %d\n",
          ntohs(udp->uh_sport),
          ntohs(udp->uh_dport),
          ntohs(udp->uh_ulen));
}

void ip_dump(const unsigned char *data, int length) {
  struct ip *ip;

  data += sizeof(struct ether_header);
  length -= sizeof(struct ether_header);

  ip = (struct ip*) data;

  printf("IP version = %d tos = %d length = %d id = %d ttl = %d proto = %d\nsrc = %s dst = %s\n",
          ip->ip_v,
          ip->ip_tos,
          ntohs(ip->ip_len),
          ntohs(ip->ip_id),
          ip->ip_ttl,
          ip->ip_p,
          inet_ntoa(ip->ip_src),
          inet_ntoa(ip->ip_dst));
}

// Utility/Debugging method for dumping raw packet data
void dump(const unsigned char *data, int length) {
  unsigned int i;
  static unsigned long pcount = 0;
  // Decode Packet Header
  struct ether_header *eth_header = (struct ether_header *) data;
  printf("\n\n === PACKET %ld HEADER ===", pcount);
  printf("\nSource MAC: ");
  for (i = 0; i < 6; ++i) {
    printf("%02x", eth_header->ether_shost[i]);
    if (i < 5) {
      printf(":");
    }
  }
  printf("\nDestination MAC: ");
  for (i = 0; i < 6; ++i) {
    printf("%02x", eth_header->ether_dhost[i]);
    if (i < 5) {
      printf(":");
    }
  }
  printf("\nType: %hu\n", eth_header->ether_type);
  printf(" === PACKET %ld DATA == \n", pcount);
  // Decode Packet Data (Skipping over the header)
  int data_bytes = length - ETH_HLEN;
  const unsigned char *payload = data + ETH_HLEN;
  const static int output_sz = 20; // Output this many bytes at a time
  while (data_bytes > 0) {
    int output_bytes = data_bytes < output_sz ? data_bytes : output_sz;
    // Print data in raw hexadecimal form
    for (i = 0; i < output_sz; ++i) {
      if (i < output_bytes) {
        printf("%02x ", payload[i]);
      } else {
        printf ("   "); // Maintain padding for partial lines
      }
    }
    printf ("| ");
    // Print data in ascii form
    for (i = 0; i < output_bytes; ++i) {
      char byte = payload[i];
      if (byte > 31 && byte < 127) {
        // Byte is in printable ascii range
        printf("%c", byte);
      } else {
        printf(".");
      }
    }
    printf("\n");
    payload += output_bytes;
    data_bytes -= output_bytes;
  }
  pcount++;
}
