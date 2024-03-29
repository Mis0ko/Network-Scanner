#ifndef TCP_H
#define TCP_H
#include <stdio.h>
#include <pcap.h>
#include <netinet/tcp.h>
#include "analyse_port.h"

void tcp_flags(uint8_t flag);
void tcp_packet(const u_char *packet, int byte_left);
void tcp_info(struct tcphdr* tcp_hd);
#endif