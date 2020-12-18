#ifndef IPV6_H
#define IPV6_H
#include <netinet/ip6.h>
#include <stdio.h>
#include <pcap.h>
#include "fct_utilitaires.h"
#include "analyse_udp.h"
#include "analyse_tcp.h"

void ipv6_packet(const u_char *packet, int byte_left);
void ipv6_info(struct ip6_hdr *hd);

#endif