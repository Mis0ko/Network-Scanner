#include <stdio.h>
#include <pcap.h>

#include <net/ethernet.h> //dans /usr/include
#include "../include/analyse_IPV4.h"

void eth_info(const struct ether_header* eth_hd)
{
	printf("\n");
	printf("ANALYSE ETHERNET : \n\n");
	printf("\tDestination host address : ");
	for (int i = 0; i < 5; i++) {
		printf("%.2x", eth_hd->ether_dhost[i]);
		printf(":");
	}
	printf("%.2x\n", eth_hd->ether_dhost[5]);
	printf("\tSource host address : ");
	for (int i = 0; i < 5; i++) {
		printf("%.2x", eth_hd->ether_shost[i]);
		printf(":");
	}
	printf("%.2x\n", eth_hd->ether_shost[5]);
	printf("\ttype : %.2x\n", ntohs(eth_hd->ether_type));
}

//ANALYSE ETHERNET
/*
ether_header :
    u_char 	ether_dhost [6] Dst MAC address.
    u_char 	ether_shost [6] Source MAC address.
    u_short ether_type Protocol type.


*/

void eth_packet(const u_char *packet) {
	//recup partie ethernet du paquet à analyser
	const struct ether_header *eth_hd;
	eth_hd = (struct ether_header*)(packet);

    eth_info(eth_hd);
    /*network byte order = big eldian, we convert it to 
    host byte order 
    */
	switch(ntohs(eth_hd->ether_type)){
		case ETHERTYPE_IP :
			ipv4_packet(packet+sizeof(struct ether_header));
			break;
		case ETHERTYPE_IPV6 :
			break;
		default :
			printf("Type pas encore étudié\n");
			break;
	}	
	printf("\n");
	printf("----------------------------------------------------------");
	printf("\n");
}

