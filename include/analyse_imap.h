#ifndef IMAP_H
#define IMAP_H
#include <stdio.h>
#include <pcap.h>
#include <netinet/tcp.h>
#include "fct_utilitaires.h"

void imap(const u_char *packet, int byte_left);
#endif