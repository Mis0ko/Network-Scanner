#ifndef POP_H
#define POP_H
#include <netinet/tcp.h>
#include <stdio.h>
#include <string.h>
#include "fct_utilitaires.h"
#include <stdlib.h>
#define POP_ENDLINE "\r\n"

void pop_packet(const u_char * packet, int byte_left);
void pop_command(const u_char * packet);
#endif