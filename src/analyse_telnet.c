#include <stdio.h>
#include <pcap.h>

#include <string.h>
#include <arpa/telnet.h>

//gestion des options négociées
void telnet_opt(const u_char opt)
{
    switch (opt)
    {
    case TELOPT_ECHO:
        printf("Echo\n");
        break;
    case TELOPT_SGA:
        printf("Suppress go ahead\n");
        break;
    case TELOPT_TTYPE:
        printf("Terminal type\n");
        break;
    case TELOPT_NAWS:
        printf("Window size\n");
        break;
    case TELOPT_TSPEED:
        printf("Terminal speed\n");
        break;
    case TELOPT_LINEMODE:
        printf("Linemode option\n");
        break;
    case TELOPT_OLD_ENVIRON:
        printf("Old environment variables\n");
        break;
    case TELOPT_NEW_ENVIRON:
        printf("New environment variables\n");
        break;
    default:
        printf("Unknown option\n");
        break;
    }
}

//appelée dans ana_tcp
void telnet_func(const u_char *packet)
{
    printf("\nANALYSE TELNET\n");
    int len = strlen(packet);
    printf("Telnet header length : %i bytes\n", len);
    int i = 0;
    //IAC : interpret as command
    while ((packet[i] == IAC) && (i < len))
    {
        i++; //pour considérer octet suivant
        switch (packet[i])
        {
        case NOP:
            printf(" - No operation\n");
            break;
        case DM:
            printf(" - Data mark\n");
            break;
        case IP:
            printf(" - Interrupt process\n");
            break;
        case AO:
            printf(" - Abort output\n");
            break;
        case AYT:
            printf(" - Are you there\n");
            break;
        case EC:
            printf(" - Erase character\n");
            break;
        case EL:
            printf(" - Erase line\n");
            break;
        case SB:
            printf(" - Subnegotiation : ");
            i++;
            telnet_opt(packet[i]);
            printf("   Option data : ");
            while (packet[i + 1] != IAC)
            {
                printf("%.2x ", packet[i + 1]);
                i++;
            }
            break;
        case SE:
            printf("\n   End of subnegotiation\n");
            break;
        case WILL:
            printf(" - WILL : ");
            i++;
            telnet_opt(packet[i]);
            break;
        case WONT:
            printf(" - WON'T : ");
            i++;
            telnet_opt(packet[i]);
            break;
        case DO:
            printf(" - DO : ");
            i++;
            telnet_opt(packet[i]);
            break;
        case DONT:
            printf(" - DON'T : ");
            i++;
            telnet_opt(packet[i]);
            break;
        }
        i++;
    }
    //Affichage en ASCII
    if (i < len)
    {
        printf("Data : ");
        for (int j = i; j < len; j++)
            printf("%c", packet[j]);
        printf("\n");
    }
}



