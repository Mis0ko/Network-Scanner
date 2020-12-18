#include "../include/analyse_arp.h"

void arp_info(struct arphdr *arp_hd, const uint8_t src[6], const uint8_t dst[6])
{
    switch (verbosity)
    {
    case 1:
        printf(":ARP");
        break;
    case 2:
        printf("ANALYSE ARP :\n");
        printf("from  ");
        print_mac_addr((uint8_t *)src);
        printf("to  ");
        print_mac_addr((uint8_t *)dst);
        break;
    case 3:
        printf("ANALYSE ARP :\n");
        printf("\tFrom  ");
        print_mac_addr((uint8_t *)src);
        printf("\tTo  ");
        print_mac_addr((uint8_t *)dst);
        printf("\tFormat of hardware address %u\n", arp_hd->ar_hrd);
        printf("\tFormat of protocol address %u\n\t", arp_hd->ar_pro);
        print_hrd_ident(ntohs(arp_hd->ar_hrd));
        printf("\tLength of hardware protocol address: %u\n", arp_hd->ar_hln);
        printf("\tLength of protocol address: %u\n", arp_hd->ar_pln);
        printf("\tOpCode: %u\n", arp_hd->ar_op);
        break;
    }
}

void arp_packet(const u_char *packet, const uint8_t src[6], const uint8_t dst[6])
{
    struct arphdr *arp_hd = (struct arphdr *)packet;

    arp_info(arp_hd, src, dst);

    switch (ntohs(arp_hd->ar_op))
    {
    case ARPOP_REQUEST: /* request to resolve address */
        if (verbosity == 3)
        {
            printf("\t\trequest:1\n");
            if (ntohs(arp_hd->ar_hrd) == ARPHRD_ETHER &&
                ntohs(arp_hd->ar_pro) == 0x0800)
                request(packet + sizeof(struct arphdr));
        }
        break;

    case ARPOP_REPLY: /* response to previous request */
        if (verbosity == 3)
        {
            printf("\t\treply:2\n");
            if (ntohs(arp_hd->ar_hrd) == ARPHRD_ETHER &&
                ntohs(arp_hd->ar_pro) == 0x0800)
                reply(packet + sizeof(struct arphdr));
        }
        break;

    case ARPOP_RREQUEST:
        printf("\t\t RARP request:3\n");
        break;

    case ARPOP_RREPLY:
        printf("\t\t RARP reply:4\n");
        break;
    case ARPOP_InREQUEST: /* request to identify peer */
        printf("\t\trequest:8\n");
        break;

    case ARPOP_InREPLY: /* response identifying peer */
        printf("\t\treply:9\n");
        break;

    case ARPOP_NAK:
        printf("\t\tNAK:10\n");
        break;

    default:
        printf("\t\tunknown request\n");
        break;
    }
}

void request(const u_char *packet)
{
    printf("\t\t\tWho has ");
    print_ipv4_addr(*(uint32_t *)(packet + 6 * 2 + 4)); //target ip
    printf("\t\t\tTell ");
    print_ipv4_addr(*(uint32_t *)(packet + 6)); //sender ip address
    printf("\n");
}

void reply(const u_char *packet)
{
    print_ipv4_addr(*(uint32_t *)packet); //sender ip address
    printf("is at ");
    print_mac_addr((uint8_t *)packet); //sender mac address
}

void print_hrd_ident(unsigned short int format)
{
    printf("hardware type : %u ", format);
    switch (format)
    {
    case ARPHRD_NETROM:
        printf(" from KA9Q: NET/ROM pseudo");
        break;
    case ARPHRD_ETHER:
        printf(" Ethernel 10Mbps");
        break;
    case ARPHRD_DLCI:
        printf(" Frame Relay DLCI");
        break;
    case ARPHRD_ATM:
        printf(" ATM");
        break;
    case ARPHRD_METRICOM:
        printf(" Metricom STRIP (new IANA id)");
        break;
    case ARPHRD_IEEE1394:
        printf(" IEEE 1394 IPv4 - RFC 2734");
        break;
    case ARPHRD_EUI64:
        printf(" EUI-64\n");
        break;
    case ARPHRD_INFINIBAND:
        printf(" InfiniBand");
        break;
    }
    printf("\n");
}