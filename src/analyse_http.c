#include "../include/analyse_http.h"

void http_packet(const u_char *packet, int byte_left)
{
    http_info(packet, (u_char *)(packet + byte_left), byte_left);
}

void http_info(const u_char *packet, u_char *end, int byte_left)
{
    switch (verbosity)
    {
    case 1:
        printf(":HTTP");
        break;
    case 2:
        printf("\nANALYSE HTTP \n\t");
        http_medium(packet);
        break;
    case 3:
        printf("\nANALYSE HTTP \n\t");
        if (byte_left != 0)
            print_ascii((u_char *)packet, end); /* display the whole packet */
        else
            http_medium(packet);
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