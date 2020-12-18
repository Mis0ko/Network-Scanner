#include "../include/analyse_port.h"
/*
The ntohs() function converts the unsigned short 
integer netshort from network byte order to host byte order.
*/

void process_port(int src, int dst, const u_char *packet)
{
    packet = packet;
    if (src == PROT_HTTP || dst == PROT_HTTP)
        printf("on a du http ici");
    else if (src == PROT_ECHO || dst == PROT_ECHO)
        printf("on a du echo ici");
    else if (src == PROT_FTP || dst == PROT_FTP)
        printf("on a du ftp ici");
    else if (src == PROT_SSH || dst == PROT_SSH)
        printf("on a du ssh ici");
    else if (src == PROT_TELNET || dst == PROT_TELNET)
        printf("on a du telnet ici");
    else if (src == PROT_SMTP || dst == PROT_SMTP)
        printf("on a du smtp ici");

    else if (src == PROT_DNS || dst == PROT_DNS)
        printf("on a du echo ici");
    else if (src == PROT_BOOTP1 || src == PROT_BOOTP2
            || dst == PROT_BOOTP2 || dst==PROT_BOOTP1)
        bootp_packet(packet);
    else if (src == PROT_POP || dst == PROT_POP)
        printf("on a du POP ici");
    else if (src == PROT_IMAP || dst == PROT_IMAP)
        printf("on a du IMAP ici");
    else if (src == PROT_HTTPS || dst == PROT_HTTPS)
        printf("on a du HTTPS ici");
    else 
        printf("protocole applicatif non pris en compte");
}