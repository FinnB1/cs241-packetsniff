#ifndef CS241_SNIFF_H
#define CS241_SNIFF_H

#include "dynarray.h"

extern dynamic_array syn_adds;
extern int syn_count;

void sig_handler(int signo);
void sniff(char *interface, int verbose);
void tcp_dump(const unsigned char *data, int length);
void udp_dump(const unsigned char *data, int length);
void ip_dump(const unsigned char *data, int length);
void dump(const unsigned char *data, int length);

#endif
