#ifndef DNS_H
#define DNS_H

#include <netinet/tcp.h>
#include <stdio.h>
#include <endian.h>
#include <stdint.h>
#include <strings.h>
#include <arpa/inet.h>
#include "fct_utilitaires.h"

/**
 *  The code below describe the DNS header and options codes
 *  It has been taken from internet
 *  Source: https://0x00sec.org/t/dns-header-for-c/618
 */

/*
    DNS Header for packet forging
    Copyright (C) 2016 unh0lys0da
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#define DNS_OPCODE_QUERY	0
#define DNS_OPCODE_IQUERY	1
#define DNS_OPCODE_STATUS	2
#define DNS_OPCODE_NOTIFY	4   // RFC 1996
#define DNS_OPCODE_UPDATE	5   // RFC 2136



struct  dnshdr{
	uint16_t id;
#if BYTE_ORDER == BIG_ENDIAN
	uint16_t qr:1;
	uint16_t opcode:4;
	uint16_t aa:1;
	uint16_t tc:1;
	uint16_t rd:1;
	uint16_t ra:1;
	uint16_t zero:3;
	uint16_t rcode:4;
#endif
#if BYTE_ORDER == LITTLE_ENDIAN
	uint16_t rd:1;
	uint16_t tc:1;
	uint16_t aa:1;
	uint16_t opcode:4;
	uint16_t qr:1;
	uint16_t rcode:4;
	uint16_t zero:3;
	uint16_t ra:1;
#endif
	uint16_t qcount;	/* question count */
	uint16_t ancount;	/* Answer record count */
	uint16_t nscount;	/* Name Server (Autority Record) Count */ 
	uint16_t adcount;	/* Additional Record Count */
};



/*
    fonctionnalité  du DNS-over-TCP implémenté mais pas encore utilisée.
    seulement 2 modes d'affichage : full et short
*/
void print_operation_type(uint16_t opcode);
void print_dns_short(const u_char *packet, int overTCP);
void print_dns_full(const u_char *packet, int overTCP);
void dns_packet(const u_char * packet);
#endif