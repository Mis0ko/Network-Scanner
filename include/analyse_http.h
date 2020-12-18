#ifndef HTTP_H
#define HTTP_H
#include "fct_utilitaires.h"
#include <string.h>

#define HTTP_DELIM "\r\n"

void http_packet(const u_char* packet);
void http_info(const u_char* packet);
void http_medium(const u_char* packet);
#endif