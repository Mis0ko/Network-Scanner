#ifndef BOOTP_H
#define BOOTP_H
#include <netinet/tcp.h>
#include <stdio.h>
#include <string.h>
#include "fct_utilitaires.h"
#include "bootp_library.h"
int test_magic_cookie(const u_char* packet);
void DHCP_MSG(uint8_t MSG_DHCP);
void print_bootp_opcode(uint8_t opcode);
void bootp_option(const u_char* packet);
void bootp_packet(const u_char *packet);

/* DHCP OPCODE */
#define     BOOTP_REQ 1
#define     BOOTP_REPLY 2
#endif

/*
documentation pour the bootp struct
http://www.ethernut.de/api/structbootp.html
*/