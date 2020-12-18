#include "../include/analyse_port.h"
/*
The ntohs() function converts the unsigned short 
integer netshort from network byte order to host byte order.
*/

void process_port(int src, int dst, const u_char *packet, int byte_left)
{
    printf("voici le port %i %i\n", src, ntohs(src));
    if (ntohs(src) == PROT_HTTP || ntohs(dst) == PROT_HTTP)
        http_packet(packet, byte_left);
    else if (ntohs(src) == PROT_ECHO || ntohs(dst) == PROT_ECHO)
        printf(":ECHO");
    else if (ntohs(src) == PROT_FTP || ntohs(dst) == PROT_FTP)
        ftp_packet(packet, byte_left);
    else if (ntohs(src) == PROT_SSH || ntohs(dst) == PROT_SSH)
        printf(":SSH");
    else if (ntohs(src) == PROT_TELNET || ntohs(dst) == PROT_TELNET)
        printf(":TELNET");
    else if ((ntohs(src) == PROT_SMTP1 || ntohs(dst) == PROT_SMTP1) ||
             (ntohs(src) == PROT_SMTP2 || ntohs(dst) == PROT_SMTP2) ||
             (ntohs(src) == PROT_SMTP3 || ntohs(dst) == PROT_SMTP3))
        {smtp_packet(packet, byte_left);}
    else if (src == PROT_DNS || dst == PROT_DNS)
        dns_packet(packet);
    else if (src == PROT_BOOTP1 || src== PROT_BOOTP2 || dst == PROT_BOOTP2 || dst == PROT_BOOTP1)
        bootp_packet(packet);
    else if (ntohs(src) == PROT_POP || ntohs(dst) == PROT_POP)
        pop_packet(packet, byte_left);
    else if (ntohs(src) == PROT_IMAP || ntohs(dst) == PROT_IMAP)
        imap(packet, byte_left);
    else if (ntohs(src) == PROT_HTTPS || ntohs(dst) == PROT_HTTPS)
        printf(":HTTPS");
    else
        printf(":app_unknown_protocol:port_src: %i:port_dst: %i ", ntohs(src), ntohs(dst));
}