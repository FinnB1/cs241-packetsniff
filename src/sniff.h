#ifndef CS241_SNIFF_H
#define CS241_SNIFF_H

void sig_handler(int signo);
void sniff(char *interface, int verbose);
void tcp_dump(const unsigned char *data, int length);
void udp_dump(const unsigned char *data, int length);
void ip_dump(const unsigned char *data, int length);
void dump(const unsigned char *data, int length);

#endif
