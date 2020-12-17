#include "../include/analyse_ipv6.h"
#include "analyse_udp.h"
#include "analyse_tcp.h"

void ipv6_info(struct ip6_hdr *hd)
{
    printf("\nANALYSE ipv6\n");
    printf("\tVersion : %u\n", hd->ip6_vfc);
    printf("\tNext header : %#2x\n", hd->ip6_nxt);
    printf("\tPayload length : %u\n", ntohs(hd->ip6_plen));
    printf("\tHop limit : %u\n", hd->ip6_hlim);
    printf("\tFlow ID : %u\n", htonl(hd->ip6_flow));
    // char addr_dst[INET6_ADDRSTRLEN];
    // inet_ntop(AF_INET6, &hd->ip6_dst, addr_dst, INET6_ADDRSTRLEN);
    // char addr_src[INET6_ADDRSTRLEN];
    // inet_ntop(AF_INET6, &hd->ip6_src, addr_src, INET6_ADDRSTRLEN);
    printf("\tDestination adress : ");
    print_ipv6_addr(&hd->ip6_dst);
    printf("\n");
    printf("\tSource adress : ");
    print_ipv6_addr(&hd->ip6_src);
    printf("\n");

}

void ipv6_packet(const u_char *packet)
{

    struct ip6_hdr *hd = (struct ip6_hdr *)packet;
    ipv6_info(hd);

    switch (hd->ip6_nxt)
    {
    case 0x06: //TCP
        tcp_packet(packet + sizeof(struct ip6_hdr));
        break;

    case 0x11: //UDP
        udp_packet(packet + sizeof(struct ip6_hdr));
        break;

    // case 0x84: //SCTP
    //     sctp_packet(packet + sizeof(struct ip6_hdr));
    //     break;

    default:
        printf("protocol unknown\n\n");
        break;
    }
}