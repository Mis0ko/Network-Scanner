#include "../include/analyse_ethernet.h"

/*
les types de protocoles sont dans netinet
*/

void eth_info(const struct ether_header *eth_hd)
{
	if (verbosity == 3 || verbosity == 2)
	{
		printf("\n");
		printf("ANALYSE ETHERNET : \n\n");
		printf("\tDestination host address : ");
		print_mac_addr((uint8_t *)eth_hd->ether_dhost);
		printf("\tSource host address : ");
		print_mac_addr((uint8_t *)eth_hd->ether_shost);
	}
	else if (verbosity == 1)
	{
		printf("\n\nETHERNET");
	}
}


/*
ether_header :
    u_char 	ether_dhost [6] Dst MAC address.
    u_char 	ether_shost [6] Source MAC address.
    u_short ether_type Protocol type.
*/

void eth_packet(const u_char *packet, int byte_left)
{
	const struct ether_header *eth_hd;
	eth_hd = (struct ether_header *)(packet);

	eth_info(eth_hd);
	/* network byte order = big eldian, we convert it to host byte order */
	switch (ntohs(eth_hd->ether_type))
	{
	case ETHERTYPE_IP:
		ipv4_packet(packet + sizeof(struct ether_header), byte_left - sizeof(struct ether_header));
		break;
	case ETHERTYPE_IPV6:
		ipv6_packet(packet + sizeof(struct ether_header), byte_left - sizeof(struct ether_header));
		break;
	case ETHERTYPE_ARP:
		arp_packet(packet + sizeof(struct ether_header),
				   eth_hd->ether_shost, eth_hd->ether_dhost);
		break;
	default:
		printf(":type_protocol_not_processed\n");
		break;
	}
	printf("\n");
	printf("----------------------------------------------------------");
	printf("\n");
}
