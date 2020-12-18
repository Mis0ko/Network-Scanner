#ifndef MAIN_H
#define MAIN_H
#include <net/ethernet.h> //dans /usr/include
#include <stdio.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <ctype.h>


void print_mac_addr(uint8_t * addr);
// void print_ipv4_addr(struct in_addr addr);
void print_ipv6_addr(struct in6_addr *addr);
void print_ipv4_addr(int32_t addr);
void print_ascii(char *str);


extern int verbosity;

#define DEFAULT   "\033[0m"
#define HIGHLIGHT  "\033[1m"
#define UNDERLINE  "\033[4m"
#define BLINK      "\033[5m"
#define BLACK      "\033[30m"
#define RED  	   "\033[31m"
#define GREEN      "\033[32m"
#define YELLOW     "\033[33m"
#define BLUE       "\033[34m"
#define PURPLE     "\033[35m"
#define CYAN      "\033[36m"
#define WHITE     "\033[37m"
#endif