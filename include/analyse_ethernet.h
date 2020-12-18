#ifndef ETHER_H
#define ETHER_H
#include <net/ethernet.h> 
#include <stdio.h>
#include "fct_utilitaires.h"
#include "analyse_IPV4.h"
#include "analyse_ipv6.h"
#include "analyse_arp.h"


void eth_info(const struct ether_header *eth_hd);
void eth_packet(const u_char *packet, int byte_left);

#endif