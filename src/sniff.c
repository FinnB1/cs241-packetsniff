#ifndef __USE_BSD
#define __USE_BSD
#endif

#include "sniff.h"

#include <stdio.h>

#include <stdlib.h>

#include <signal.h>

#include <pcap.h>

#include <arpa/inet.h>

#include <netinet/if_ether.h>

#include <netinet/ip.h>

#include <netinet/tcp.h>

#include <netinet/in.h>


#include "dispatch.h"

#include "dynarray.h"

dynamic_array syn_adds;
pcap_t * pcap_handle;
int syn_count = 0;
int arp_count = 0;
int blacklist_count = 0;
int v;


/**
* Handles exiting of program by breaking packet capture loop
* @param signo signal value
*/
void sig_handler(int signo) {
  // If Ctrl C Signal received
  if (signo == SIGINT) {
    // break pcap loop
    pcap_breakloop(pcap_handle);
  }
}

/**
* Function called by packet capture loop when packet arrives, sending packet off to dispatch
* @param placeholder satisfy method signature
* @param header packet header
* @param packet data
*/
void pre_dispatch(u_char * placeholder,
  const struct pcap_pkthdr * header,
    const unsigned char * packet) {
  dispatch((struct pcap_pkthdr *) header, packet, v);
}

/**
* Sniff for packets, printing a report of findings upon breaking the loop and exiting.
* @param interface interface to sniff on
* @param verbose debugging flag
*/
void sniff(char * interface, int verbose) {
  v = verbose;
  // Open network interface for packet capture
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_handle = pcap_open_live(interface, 4096, 1, 0, errbuf);
  // set up signal handler
  signal(SIGINT, sig_handler);
  if (pcap_handle == NULL) {
    fprintf(stderr, "Unable to open interface %s\n", errbuf);
    exit(EXIT_FAILURE);
  } else {
    printf("SUCCESS! Opened %s for capture\n", interface);
  }

  //initialise dynamic array
  dynarray_init( & syn_adds, 5);
  // start pcap loop with pre dispatch as function
  pcap_loop(pcap_handle, 0, pre_dispatch, NULL);
  // Report printing on loop break.
  printf("\nExiting\n");
  printf("----SYN DETECTION----\n");
  printf("Total number of syn packets: %d\n", syn_count);
  printf("Total number of Unique IP Addresses found: %d\n", dynarray_size( & syn_adds));
  printf("----ARP POISONING----\n");
  printf("Total number of ARP responses: %d\n", arp_count);
  printf("----URL BLACKLIST----\n");
  printf("Total number of requests to blacklisted URLs: %d\n", blacklist_count);
  // close dynamic array
  dynarray_close( & syn_adds);
  // close all threads and exit
  close_threads();
  exit(0);
}