#ifndef MAIN_H
#define MAIN_H
#include <net/ethernet.h> 
#include <stdio.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <ctype.h>
#include <string.h>

void print_mac_addr(uint8_t * addr);
void print_ipv6_addr(struct in6_addr *addr);
void print_ipv4_addr(int32_t addr);
void print_ascii(const u_char *str,u_char* end);
void print_ascii_until(const u_char* line, const char* until);

extern int verbosity;
#endif