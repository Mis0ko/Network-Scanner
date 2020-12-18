#ifndef SMTP_H
#define SMTP_H
#include <netinet/tcp.h>
#include <stdio.h>
#include <string.h>
#include "fct_utilitaires.h"
#include <stdlib.h>
#define SMTP_ENDLINE "\r\n"

void smtp_packet(const u_char *packet, int byte_left);
void smtp_code(char *packet);
char* smtp_command(const u_char *packet);
#endif