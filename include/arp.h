#ifndef ARP_H
#define ARP_H
#include "net/if_arp.h"
#include "fct_utilitaires.h"

void arp_packet(char *, uint8_t [6], uint8_t [6]);
void arp_info(struct arphdr *, uint8_t src [6], uint8_t dst [6]);
void print_hrd(unsigned short int format);
void print_pro(unsigned short int format);
void request(char * packet);
void reply(char * packet);


#endif