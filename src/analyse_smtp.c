#include "../include/analyse_smtp.h"

void smtp_packet(const u_char *packet, int byte_left)
{
    char *p;
    if (verbosity == 3)
    {
        printf("\nANALYSE SMTP\n\n\t");
        if (byte_left == 0)
        {
            printf("No data SMTP\n");
            return;
        }
        print_ascii(packet, (u_char *)(packet + byte_left));
    }
    else if (verbosity == 2)
    {
        printf("\nANALYSE SMTP\n\n\t");
        p = smtp_command(packet);
        if (p == NULL)
            smtp_code((char *)packet);
        else
        {
            print_ascii_until((const u_char *)p, SMTP_ENDLINE);
        }
    }
    else if (verbosity == 1)
        printf(":SMTP");
}

/* codage MIME : 3 octets*/
void smtp_code(char *packet)
{
    char code[3];
    code[0] = *packet;
    code[1] = *(packet + 1);
    code[2] = *(packet + 2);
    int c = atoi(code);
    if (c < 600 && c > 0)
        print_ascii_until((const u_char *)packet, SMTP_ENDLINE);
}

char *smtp_command(const u_char *packet)
{
    char *p;

    if (((p = strstr((const char *)packet, "MAIL")) != NULL) ||
        ((p = strstr((const char *)packet, "RCPT")) != NULL) ||
        ((p = strstr((const char *)packet, "DATA")) != NULL) ||
        ((p = strstr((const char *)packet, "HELO")) != NULL) ||
        ((p = strstr((const char *)packet, "EHLO")) != NULL) ||
        ((p = strstr((const char *)packet, "AUTH")) != NULL) ||
        ((p = strstr((const char *)packet, "STARTTLS")) != NULL) ||
        ((p = strstr((const char *)packet, "QUIT")) != NULL) ||
        ((p = strstr((const char *)packet, "HELP")) != NULL))
    {
        return p;
    }

    return NULL;
}