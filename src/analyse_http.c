#include "../include/analyse_http.h"

void http_packet(const u_char *packet)
{
    http_info(packet);
}

void http_info(const u_char *packet)
{
    printf("\nANALYSE HTTP \n\t");
    switch (verbosity)
    {
    case 1:
        http_medium(packet); 
        break;
    case 2:
        http_medium(packet);
        break;
    case 3:
        print_ascii((char*)packet); /* on affiche l'intégralité du packet */
        break;
    }
}

void http_medium(const u_char *packet)
{
    if (strstr((const char *)packet, "GET") != NULL)
        printf(" GET");
    else if (strstr((const char *)packet, "PUT") != NULL)
        printf(" PUT");
    else if (strstr((const char *)packet, "POST") != NULL)
        printf(" POST");
    else if (strstr((const char *)packet, "DELETE") != NULL)
        printf(" DELETE");
    else if (strstr((const char *)packet, "HEAD") != NULL)
        printf(" HEAD");
    else
        printf(" Aucune requête");
    printf("\n");
}