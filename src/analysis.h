#ifndef CS241_ANALYSIS_H
#define CS241_ANALYSIS_H

#include <pcap.h>

void analyse(int length,
              const unsigned char *packet,
              int verbose);

#endif
