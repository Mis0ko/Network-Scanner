#ifndef ETHER_H
#define ETHER_H
#include <net/ethernet.h> //dans /usr/include

void eth_info(struct ether_header* eth_hd);
void eth_packet(const u_char *packet);

#endif