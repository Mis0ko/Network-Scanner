#ifndef ARP_H
#define ARP_H
#include "net/if_arp.h"
#include "fct_utilitaires.h"

void arp_packet(const u_char *packet, const uint8_t src[6], const uint8_t dst[6]);
void arp_info(struct arphdr *arp_hd, const uint8_t src[6], const uint8_t dst[6]);
void print_hrd_ident(unsigned short int format);
void print_procol(unsigned short int format);
void request(const u_char *packet);
void reply(const u_char *packet);

/*
doc for MACRO of ARP
https://sites.uclouvain.be/SystInfo/usr/include/linux/if_arp.h.html
*/

#endif