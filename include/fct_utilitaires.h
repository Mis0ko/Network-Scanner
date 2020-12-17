#ifndef MAIN_H
#define MAIN_H
#include <net/ethernet.h> //dans /usr/include
#include <stdio.h>
#include <pcap.h>
#include <netinet/ip.h>
void print_mac_addr(uint8_t * addr);
// void print_ipv4_addr(struct in_addr addr);
void print_ipv6_addr(struct in6_addr *addr);
void print_ipv4_addr(int32_t addr);
extern int verbosity;
#endif