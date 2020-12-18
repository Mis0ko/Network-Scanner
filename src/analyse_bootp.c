#include "../include/analyse_bootp.h"

int test_magic_cookie(const u_char *packet)
{
    if (packet == NULL || /* test du magic cookie */
        *(char*)packet != (char)99 ||
        *(char*)(packet + 1) != (char)130 ||
        *(char*)(packet + 2) != (char)83 ||
        *(char*)(packet + 3) != (char)99)
    {
        return 1;
    }
    return 0;
}

void DHCP_MSG(uint8_t MSG_DHCP)
{
    switch (MSG_DHCP)
    {
    case DHCPDISCOVER:
        printf("DHCP Discover");
        break;
    case DHCPOFFER:
        printf("DHCP Offer");
        break;
    case DHCPREQUEST:
        printf("DHCP Request");
        break;
    case DHCPDECLINE:
        printf("DHCP Decline");
        break;
    case DHCPACK:
        printf("DHCP Ack");
        break;
    case DHCPNAK:
        printf("DHCP NAck");
        break;
    case DHCPRELEASE:
        printf("DHCP Release");
        break;
    case DHCPINFORM:
        printf("DHCP Inform");
        break;
    default:
        printf("error");
        break;
    }
}

void print_bootp_opcode(uint8_t opcode)
{
    printf("\tBOOTP OPCODE %u : ", opcode);
    switch (opcode)
    {
    case BOOTP_REQ:
        printf("REQUEST");
        break;
    case BOOTP_REPLY:
        printf("BOOT REPLY");
        break;
    }
    printf("\n");
}

void bootp_option(const u_char *packet)
{
    int offset;
    /* we keep the vendor without the 4 first octets
    that enable us to see if the cookie is present*/
    if (test_magic_cookie(packet))
    {
        packet = packet + sizeof(struct bootp) - 60;
        while (packet[0] != TAG_END)
        {
            offset = 2; // octet code + longueur (pour avancer à la fin)
            printf("\n\tOption: (%d)\n", packet[0]);
            // switch le code de l'option
            switch (packet[0])
            {
            // padding
            case TAG_PAD:
                offset = 1;
                break;

            // subnet mask
            case TAG_SUBNET_MASK:
                printf("\tsubnet mask: %d.%d.%d.%d", packet[2], packet[3], packet[4], packet[5]);
                break;

            // Router option
            case TAG_GATEWAY:
                printf("\tRouter option\n");
                printf("\tIP address: %d.%d.%d.%d", packet[2], packet[3], packet[4], packet[5]);
                break;

            // DNS
            case TAG_DOMAIN_SERVER:
                printf("\tDomain Name Server");
                // on boucle pour le nombre de serveurs mentionné (addr taille 4)
                for (int i = 2; i < packet[1]; i = i + 4)
                {
                    printf("\n\tIP address: %d.%d.%d.%d", packet[i], packet[i + 1], packet[i + 2], packet[i + 3]);
                }
                break;
            /* DHCP OPTIONS */
            // IP requested
            case TAG_REQUESTED_IP:
                printf("\tRequested IP Address\n");
                printf("\tIP address: %d.%d.%d.%d", packet[2], packet[3], packet[4], packet[5]);
                break;

            // option DHCP message type
            case TAG_DHCP_MESSAGE:
                // type message
                printf("\t");
                DHCP_MSG(packet[2]);
                break;

            // paramètres req
            case TAG_PARM_REQUEST:
                printf("\tParameter Request List\n");
                for (int i = 1; i <= packet[1]; i++)
                    printf("\tParameter Request List Item: (%d)\n", packet[1 + i]);
                break;

            default:
                printf("\tnot supported");
                break;
            }
            printf("\n\tlength: %u", packet[1]);
            // avancer selon la longueur + code et lg
            if (packet[0] == 0)
                packet += offset;
            else
                packet += packet[1] + offset;
        }
    }
}

void bootp_packet(const u_char *packet)
{
    struct bootp *bootp_hd = (struct bootp *)packet;
    if (verbosity == 3)
    { /* on affiche tout le header */
        printf("\nANALYSE BOOTP\n");
        print_bootp_opcode(bootp_hd->bp_op);
        printf("\thardware addr type: %.2x\n", bootp_hd->bp_htype);
        printf("\thardware addr length: %u\n", bootp_hd->bp_hlen);
        printf("\tgateway hops: %u\n", bootp_hd->bp_hops);
        printf("\ttransaction ID: %.2x\n", ntohs(bootp_hd->bp_xid));
        printf("\tseconds since boot began %u\n", ntohs(bootp_hd->bp_secs));
        printf("\tflags: %.2x", bootp_hd->bp_flags);
        if (bootp_hd->bp_flags & 0x80000)
            printf(" ==> broadcast\n");
        else
            printf("\n");
        printf("\tclient IP address ");
        print_ipv4_addr(*(uint32_t *)(&bootp_hd->bp_ciaddr));
        printf("\t'your' IP address ");
        print_ipv4_addr(*(uint32_t *)(&bootp_hd->bp_yiaddr));
        printf("\tserver IP address ");
        print_ipv4_addr(*(uint32_t *)(&bootp_hd->bp_siaddr));
        printf("\tgateway IP address ");
        print_ipv4_addr(*(uint32_t *)(&bootp_hd->bp_giaddr));

        printf("\tclient hardware address ");
        print_mac_addr(bootp_hd->bp_chaddr);
        // the 2 below cause error I didnt have time to check
        // printf("\tServer Host Name: ");
        // if (bootp_hd->bp_sname == NULL)
        //     printf(" not given\n");
        // else
        //     printf(" %s\n", bootp_hd->bp_sname);
        // printf("\tBoot file: ");
        // if (strlen((char *)bootp_hd->bp_file) == 0)
        //     printf(" not given\n");
        // else
        //     printf(" %s\n", bootp_hd->bp_file);
    }
    if (verbosity > 1)
    {
        if (verbosity == 2)
            printf("\nANALYSE BOOTP\n");
        bootp_option(packet);
    }
    if (verbosity == 1)
        printf(":BOOTP");
}
