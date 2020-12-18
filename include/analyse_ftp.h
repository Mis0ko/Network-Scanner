#ifndef FTP_H
#define FTP_H
#include <netinet/tcp.h>
#include <stdio.h>
#include <string.h>
#include "fct_utilitaires.h"
#include <stdlib.h>
#define FTP_ENDLINE "\r\n"

void ftp_packet(const u_char * packet, int byte_left);
void ftp_command(const u_char * packet);

#endif