#include "../include/analyse_ftp.h"

void ftp_packet(const u_char *packet, int byte_left)
{
    printf("\nANALYSE FTP\n");
    /*To avoid  segfault  in the next functions*/
    if (byte_left < 4)
    {
        printf("\tNo data from FTP\n");
        return;
    }

    switch (verbosity)
    {
    case 1:
        printf(":FTP");
        break;

    case 2:
        ftp_command(packet);
        break;

    case 3:
        print_ascii(packet, (u_char *)(packet + byte_left));
        break;
    }
}

void ftp_command(const u_char *packet)
{
    char *p;
    char *command;
    char char_code[3];
    int code = 0;

    /* FTP basics command */
    if (((p = strstr((const char *)packet, "USER")) != NULL) ||
        ((p = strstr((const char *)packet, "PASS")) != NULL) ||
        ((p = strstr((const char *)packet, "SYST")) != NULL) ||
        ((p = strstr((const char *)packet, "SITE")) != NULL) ||
        ((p = strstr((const char *)packet, "LIST")) != NULL) ||
        ((p = strstr((const char *)packet, "PWD")) != NULL) ||
        ((p = strstr((const char *)packet, "PASV")) != NULL) ||
        ((p = strstr((const char *)packet, "PORT")) != NULL) ||
        ((p = strstr((const char *)packet, "RETR")) != NULL) ||
        ((p = strstr((const char *)packet, "QUIT")) != NULL))
    {
        command = p;
    }

    /*
        Whether that is a request or an Answer we print it.
        Answer begin with a 4 characteres opcode.
        opcode is between 100 and 633 in decimal
        Either way the line finish with "\r\n" with is FTP_ENDLINE

    */
    if (command != NULL && (const u_char *)(command) == packet)
    {
        printf("Request: ");
        print_ascii_until(packet, FTP_ENDLINE);
    }
    else
    {
        char_code[0] = *packet;
        char_code[1] = *(packet + 1);
        char_code[2] = *(packet + 2);

        code = atoi(char_code);
        if (code >= 110 && code <= 633)
        {
            printf("Answer: ");
            print_ascii_until(packet, FTP_ENDLINE);
        }
        else
            printf("\tSome Data not translated\n");
    }
}
