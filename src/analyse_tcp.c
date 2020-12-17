#include <stdio.h>
#include <pcap.h>
#include <netinet/tcp.h>
#include "../include/analyse_tcp.h"
//#include "ana_telnet.h"

void tcp_flags(uint8_t flag){
	if (flag & TH_FIN)
		printf("\t\tFIN: fin de transmission\n");
	if (flag & TH_SYN)
		printf("\t\tSYN: synchronisation num seq\n");
	if (flag & TH_RST)
		printf("\t\tRST: reset connection \n");
	if (flag & TH_PUSH)
		printf("\t\tPUSH: receiver must push data to app and doesnt wait the tampon filling\n");
	if (flag & TH_ACK)
		printf("\t\tACK: ACK num seq\n");
	if (flag & TH_FIN)
		printf("\t\tURG: Urgent data pointer field is used\n");
}

void tcp_packet(const u_char *packet) {
	//recup partie tcp du paquet à analyser
	struct tcphdr *tcp_hd;
	tcp_hd = (struct tcphdr*)(packet);

    tcp_info(tcp_hd);

	if (ntohs(tcp_hd->source) == 23 || ntohs(tcp_hd->dest) == 23){
        //telnet_func(packet + tcp_hd->th_off*4);
        printf("telnet fonction à finir\n");
	}
}

void tcp_info(struct tcphdr* tcp_hd)
{
    printf("\nANALYSE TCP\n\n");
	printf("\tSource port : %u\n", ntohs(tcp_hd->th_sport));
	printf("\tDestination port : %u\n", ntohs(tcp_hd->th_dport));
	printf("\tSequence number : 0x%.2x\n", ntohl(tcp_hd->th_seq));
	printf("\tAcknowledgement number : 0x%.2x\n", ntohl(tcp_hd->th_ack));
	printf("\tData offset : %u\n\t => total size : %u bytes\n", tcp_hd->th_off, tcp_hd->th_off*4);
	printf("\tFlags : 0x%.2x\n",tcp_hd->th_flags);
	tcp_flags(tcp_hd->th_flags);
	printf("\tWindow : %u\n", ntohs(tcp_hd->th_win));
	printf("\tChecksum : 0x%.2x\n", ntohs(tcp_hd->th_sum));
	printf("\tUrgent pointer : %u\n", tcp_hd->th_urp);
}