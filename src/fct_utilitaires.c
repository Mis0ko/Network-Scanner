#include "../include/fct_utilitaires.h"

void print_mac_addr(uint8_t *addr)
{
    for (int i = 0; i < 5; i++)
    {
        printf("%.2x", addr[i]);
        printf(":");
    }
    printf("%.2x\n", addr[5]);
}

void print_ipv4_addr(int32_t addr)
{
    printf("%u.", addr & 0xff);
    printf("%u.", (addr >> 8) & 0xff);
    printf("%u.", (addr >> 16) & 0xff);
    printf("%u\n", (addr >> 24) & 0xff);
}

void print_ipv6_addr(struct in6_addr *addr)
{
    char addr_dst[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, addr, addr_dst, INET6_ADDRSTRLEN);
    printf("%s\n", addr_dst);
}

/* affiche en ascii */
void print_ascii(const u_char *str, u_char *end)
{
    u_char *p = (u_char *)str;
    for (; p != (end - 1); p++)
    {
        if (isprint(*p))
            printf("%c", *p);
        else
            printf(".");
    }
    printf("\n");
}

/*
    print in ASCII until the char* until that is inside the 
    line
*/
void print_ascii_until(const u_char *line, const char *until)
{
    char *end = strstr((const char *)line, until);
    if (end == NULL)
        return;

    print_ascii(line, (u_char *)end);
    printf("\n");
}