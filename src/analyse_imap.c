#include "../include/analyse_imap.h"

void imap(const u_char *packet, int byte_left)
{
 
    if (verbosity == 2)
    {
        printf("ANALYSE IMAP\n");
        if (strstr((const char *)packet, "OK CLOSE") != NULL)
            printf("OK CLOSE\n");
        else if (strstr((const char *)packet, "OK LOGOUT") != NULL)
            printf("OK LOGOUT\n");
        else if (strstr((const char *)packet, "NO") != NULL)
            printf("NO\n");
        else if (strstr((const char *)packet, "BAD") != NULL)
            printf("BAD\n");
        else if (strstr((const char *)packet, "LOGIN") != NULL)
            printf("LOGIN\n");
        else if (strstr((const char *)packet, "SELECT") != NULL)
            printf("SELECT\n");
        else if (strstr((const char *)packet, "NOOP") != NULL)
            printf("NOOP\n");
        else if (strstr((const char *)packet, "LIST") != NULL)
            printf("LIST\n");
        else if (strstr((const char *)packet, "CREATE") != NULL)
            printf("CREATE\n");
        else if (strstr((const char *)packet, "DELETE") != NULL)
            printf("DELETE\n");
        else if (strstr((const char *)packet, "RENAME") != NULL)
            printf("RENAME\n");
        else if (strstr((const char *)packet, "APPEND") != NULL)
            printf("APPEND\n");
        else if (strstr((const char *)packet, "FLAGS") != NULL)
            printf("FLAGS\n");
        else if (strstr((const char *)packet, "SEARCH") != NULL)
            printf("SEARCH\n");
        else if (strstr((const char *)packet, "EXISTS") != NULL)
            printf("EXISTS\n");
        else if (strstr((const char *)packet, "RECENT") != NULL)
            printf("RECENT\n");
        else if (strstr((const char *)packet, "Completed") != NULL)
            printf("Completed\n");
        else if (strstr((const char *)packet, "FETCH") != NULL)
            printf("FETCH\n");
        else if (strstr((const char *)packet, "COPY") != NULL)
            printf("COPY\n");
        else if (strstr((const char *)packet, "STORE") != NULL)
            printf("STORE\n");
        else if (strstr((const char *)packet, "EXPUNGE") != NULL)
            printf("EXPUNGE\n");
        else if (strstr((const char *)packet, "BYE") != NULL)
            printf("BYE\n");
        else if (strstr((const char *)packet, "AUTHENTICATE") != NULL)
            printf("AUTHENTICATE\n");
        else if (strstr((const char *)packet, "EXAMINE") != NULL)
            printf("EXAMINE\n");
        else if (strstr((const char *)packet, "INBOX") != NULL)
            printf("INBOX\n");
        else if (strstr((const char *)packet, "UID") != NULL)
            printf("UID\n");
        else if (strstr((const char *)packet, "OK") != NULL)
            printf("OK connection without authentification\n");
    }
    else if (verbosity == 3)
    {
        printf("ANALYSE IMAP\n");
        if (byte_left != 0)
            print_ascii(packet, (u_char *)(packet + byte_left));
        else
            printf("no data from IMAP");
    }
    else if (verbosity == 1)
        printf(":IMAP");
}