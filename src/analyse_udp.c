#include <stdio.h>
#include <pcap.h>
#include "../include/analyse_udp.h"

//#include "ana_bootp.h"

void udp_packet(const u_char *packet) {
	//recup partie udp du paquet à analyser
	const struct udphdr *udp_hd;
	udp_hd = (const struct udphdr*)(packet);

    udp_info(udp_hd);

	u_int sport = ntohs(udp_hd->uh_sport);
	u_int dport = ntohs(udp_hd->uh_dport);

	process_port(sport, dport, packet + sizeof(struct udphdr));
}


void udp_info(const struct udphdr* udp_hd)
{
	u_int sport = ntohs(udp_hd->uh_sport);
	u_int dport = ntohs(udp_hd->uh_dport);
	
	printf("\n");
	printf("ANALYSE UDP\n");
	printf("\tSource port : %u\n", sport);
	printf("\tDestination port : %u\n", dport);
	printf("\tUDP length : %u bytes\n", ntohs(udp_hd->uh_ulen));
	printf("\tUDP checksum : 0x%.2x\n", ntohs(udp_hd->uh_sum));
}


