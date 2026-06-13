#ifndef ICMP_H
#define ICMP_H

#include <stddef.h>
#include <stdint.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#define MAX_DATA_BUFFER 1500

enum {
    ICMP_UNKNOWN_TYPE = -1,
    ICMP_ERROR_BUILD = -2,
    ICMP_ERROR_SEND = -3,
};

struct icmp_echo {
    struct iphdr iph;
    struct icmphdr icmph;

    uint8_t *data;
    size_t data_len;
};

void deinit_icmp_echo(struct icmp_echo *rp);
struct icmp_echo *read_icmp_echo(int s);
int send_echo_packet(int s, uint8_t type, uint32_t dst, uint8_t *data, size_t len);

#endif
