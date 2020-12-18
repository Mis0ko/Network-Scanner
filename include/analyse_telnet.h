#ifndef TELNET_H
#define TELNET_H
#include <stdio.h>
#include <pcap.h>
#include <netinet/tcp.h>

void tcp_flags(uint8_t flag);
void tcp_packet(const u_char *packet);
void tcp_info(struct tcphdr* tcp_hd);
#endif