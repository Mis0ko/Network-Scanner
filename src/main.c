#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include "../include/analyse_ethernet.h"
#include <getopt.h>
#include <string.h>
int verbosity = 3;
//compteur de trames
int trame_cpt;

struct opt_struct
{
    int live; //analyse offline ou non
    char *interface;
    char *file;  //nom de fichier
    u_char verb; //verbosité
};

//Gestion des options
void opt_func(int opt, struct opt_struct *os)
{
    printf("in opt_func\n");
    switch (opt)
    {
    case 'i':
        printf("Interface for live analysis: ");
        os->interface = optarg;
        printf("%s\n", os->interface);
        os->live = 1;
        break;
    case 'o':
        printf("Entry file : ");
        os->file = optarg;
        printf("%s\n", os->file);
        //priorité de la lecture fichier si -i et -o demandés
        os->live = 0;
        break;
    case 'f':
        printf("BPF filter\n");
        break;
    case 'v':
        printf("Verbosity level : ");
        os->verb = *optarg;
        printf("%c\n", os->verb);
        break;
    default:
        printf("Invalid option\n");
        break;
    }
}

/*
pcap_pkthdr
    timestamp
    caplen
    len (packet)

args = state of the current session

*/
//pcap_pkthrdr dans pcap.h, pour les entetes des paquets
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    //affichage paquets puis analyse
    printf("\n");
    printf("TRAME %i\n", trame_cpt);
    for (uint i = 0; i < header->caplen; i++)
    {
        printf("%.2x ", *(packet + i));
    }
    printf("\n");
    trame_cpt++;
    eth_packet(packet);
    args = args; // à enlever
}

/*
ouvre un pacap_t à partir d'un file sur la struct

*/

int file_func(struct opt_struct *os)
{
    pcap_t *f;
    char errbuf[PCAP_ERRBUF_SIZE];
    if ((f = pcap_open_offline(os->file, errbuf)) == NULL)
    {
        printf("Error while opening file : %s\n", errbuf);
        return (2);
    }
    if (pcap_loop(f, 0, got_packet, &(os->verb)) < 0)
    {
        printf("Error with pcap_loop: %s\n", errbuf);
        return (2);
    }
    return (0);
}

/*
open an interface intro a pcap_t file and collect a group of packet
(5packet) with pcap_loop.
*/
int interf_func(struct opt_struct *os)
{
    char error[PCAP_ERRBUF_SIZE];
    pcap_if_t *interfaces;//, *temp;
    //int i = 0;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&interfaces, error) == -1)
    {
        printf("\nerror in pcap findall devs");
        return -1;
    }
    printf("\n the interfaces present on the system are:");
    os->interface = malloc(sizeof(strlen(interfaces->name)));
    strcpy(os->interface, interfaces->name);
    printf("voici ce qu'on stock %s\n", os->interface);
    if (os->interface == NULL)
    {
        printf("Couldn't find default device: %s\n", errbuf);
        return (2);
    }

    printf("Device: %s\n", os->interface);

    pcap_t *handle;

    handle = pcap_open_live(os->interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL)
    {
        printf("Couldn't open device %s : %s\n", os->interface, errbuf);
        return (2);
    }
    printf("Device is open\n");
    printf("\n");

    if (pcap_loop(handle, 20, got_packet, NULL) == -1)
    {
        printf("An error happened\n");
        return (2);
    }
    return (0);
}

int main(int argc, char **argv)
{
    const char *optstring = "i:o:f:v:";
    struct opt_struct os;
    int opt;
    trame_cpt = 1;

    while ((opt = getopt(argc, argv, optstring)) != -1)
    {
        opt_func(opt, &os);
    }
    if (os.live == 0)
        file_func(&os);
    else
        interf_func(&os);

    return (0);
}