#include "arp.h"

void arp_info(struct arphdr *arp_hd, uint8_t src[6], uint8_t dst[6])
{
    printf("ARP :\n");
    switch (verbosity)
    {
    case 1:
        printf("from");
        print_mac_addr(src);
        printf(" to");
        print_mac_addr(dst);
        break;
    case 3:
        print_mac_addr(src);
        print_mac_addr(dst);
        printf("\tFormat of hardware address %u\n", arp_hd->ar_hrd);
        printf("\tFormat of protocol address %u\n", arp_hd->ar_pro);
        // print_hrd(ntohs(hd->ar_hrd));
        // print_pro(ntohs(hd->ar_pro));
        printf("\tLength of hardware protocol address: %u\n", arp_hd->ar_hln);
        printf("\tLength of protocol address: %u\n", arp_hd->ar_pln);
        printf("\tOpCode: %u\n", arp_hd->ar_op);
        break;
    }
}

void arp_packet(char *packet, uint8_t src[6], uint8_t dst[6])
{
    struct arphdr *arp_hd = (struct arphdr *)packet;

    arp_info(arp_hd, src, dst);

    switch (ntohs(arp_hd->ar_op))
    {
    case ARPOP_REQUEST: /* request to resolve address */
        if (verbosity == 3)
            printf("request 1:(\n");
        if (ntohs(arp_hd->ar_hrd) == ARPHRD_ETHER &&
            ntohs(arp_hd->ar_pro) == 0x0800)
            request(packet + sizeof(struct arphdr));
        break;

    case ARPOP_REPLY: /* response to previous request */
        if (verbosity == 3)
            printf("reply (2)\n");
        if (ntohs(arp_hd->ar_hrd) == ARPHRD_ETHER &&
            ntohs(arp_hd->ar_pro) == 0x0800)
            reply(packet + sizeof(struct arphdr));
        break;

    case ARPOP_InREQUEST: /* request to identify peer */
        printf("request (8)\n");
        break;

    case ARPOP_InREPLY: /* response identifying peer */
        printf("reply (9)\n");
        break;

    case ARPOP_NAK:
        printf("NAK (10)\n");
        break;

    default:
        printf("unknown\n");
        break;
    }
}

void request(char *packet)
{
    printf("Who has ");
    //print_ipv4("Who has ", (uint32_t)(packet + 6 * 2 + 4)); //target ip address
    print_ipv4_addr((uint32_t)(packet + 6*2+4));     //target ip
    printf("? Tell");
    print_ipv4_addr((uint32_t)(packet + 6));        //sender ip address
    printf("\n");
}

void reply(char *packet)
{
    print_ipv4_addr((uint32_t) packet);    //sender ip address
    printf("is at ");
    print_mac_addr((uint8_t *)packet); //sender mac address
}
