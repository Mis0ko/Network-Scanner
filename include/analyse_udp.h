#ifndef UDP_H
#define UDP_H
#include <stdio.h>
#include <pcap.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include "analyse_port.h"

void udp_info(const struct udphdr* udp_hd);
void udp_packet(const u_char *packet, int byte_left);
#endif