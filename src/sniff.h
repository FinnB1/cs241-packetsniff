#ifndef CS241_SNIFF_H
#define CS241_SNIFF_H

void sniff(char *interface, int verbose);
void udp_dump(const unsigned char *data, int length);
void ip_dump(const unsigned char *data, int length);
void dump(const unsigned char *data, int length);

#endif
