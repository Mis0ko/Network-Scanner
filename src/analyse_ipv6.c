#include "../include/analyse_ipv6.h"

void ipv6_info(struct ip6_hdr *hd)
{
    
    if (verbosity == 3)
    {
        printf("\nANALYSE IPV6 : \n");
        printf("\tVersion : %u\n", hd->ip6_vfc);
        printf("\tNext header : %#2x\n", hd->ip6_nxt);
        printf("\tPayload length : %u\n", ntohs(hd->ip6_plen));
        printf("\tHop limit : %u\n", hd->ip6_hlim);
        printf("\tFlow ID : %u\n", htonl(hd->ip6_flow));
        printf("\tDestination adress : ");
        print_ipv6_addr(&hd->ip6_dst);
        printf("\n");
        printf("\tSource adress : ");
        print_ipv6_addr(&hd->ip6_src);
        printf("\n");
    }
    else if (verbosity == 2)
    {
        printf("\nANALYSE IPV6 : \n");
        printf("\tDestination adress : ");
        print_ipv6_addr(&hd->ip6_dst);
        printf("\n");
        printf("\tSource adress : ");
        print_ipv6_addr(&hd->ip6_src);
        printf("\n");
    }
    else if (verbosity == 1)
        printf(":IPV6");
}

void ipv6_packet(const u_char *packet, int byte_left)
{

    struct ip6_hdr *hd = (struct ip6_hdr *)packet;
    ipv6_info(hd);

    switch (hd->ip6_nxt)
    {
    case 0x06: //TCP
        tcp_packet(packet + sizeof(struct ip6_hdr), byte_left - sizeof(struct ip6_hdr));
        break;

    case 0x11: //UDP
        udp_packet(packet + sizeof(struct ip6_hdr), byte_left - sizeof(struct ip6_hdr));
        break;

    default:
        printf(":protocol unknown\n\n");
        break;
    }
}