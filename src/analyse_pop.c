#include "../include/analyse_pop.h"

void pop_packet(const u_char *packet, int byte_left)
{
    switch (verbosity)
    {
    case 1:
        printf(":POP3");
        break;
    case 2:
        printf("\nANALYSE POP\n\n");
        pop_command((const u_char *)packet);
        break;

    case 3:
        printf("\nANALYSE POP\n\n");
        if (byte_left > 0)
            print_ascii((const u_char *)packet, (u_char *)(packet + byte_left));
        else
            printf("\tNo POP data\n");
        break;
    }
}

void pop_command(const u_char *packet)
{
    char *p;

    if (((p = strstr((const char *)packet, "USER")) != NULL) ||
        ((p = strstr((const char *)packet, "PASS")) != NULL) ||
        ((p = strstr((const char *)packet, "STAT")) != NULL) ||
        ((p = strstr((const char *)packet, "LIST")) != NULL) ||
        ((p = strstr((const char *)packet, "UIDL")) != NULL) ||
        ((p = strstr((const char *)packet, "RETR")) != NULL) ||
        ((p = strstr((const char *)packet, "DELE")) != NULL) ||
        ((p = strstr((const char *)packet, "TOP")) != NULL) ||
        ((p = strstr((const char *)packet, "LAST")) != NULL) ||
        ((p = strstr((const char *)packet, "RSET")) != NULL) ||
        ((p = strstr((const char *)packet, "NOOP")) != NULL) ||
        ((p = strstr((const char *)packet, "STLS")) != NULL) ||
        ((p = strstr((const char *)packet, "QUIT")) != NULL))
    {
        print_ascii_until((const u_char *)p, POP_ENDLINE);
    }
    else
        printf("\tCommand not recognize\n");
    if (((p = strstr((const char *)packet, "+OK")) != NULL) ||
        ((p = strstr((const char *)packet, "-ERR")) != NULL))
    {
        print_ascii_until((const u_char *)p, POP_ENDLINE);
    }
}