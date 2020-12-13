#ifndef IPV4_H
#define IPV4_H
#include <stdio.h>
#include <pcap.h>
#include <netinet/ip.h>


void ipv4_info(const struct ip *ip_hd);
void ipv4_packet(const u_char *packet);
#endif