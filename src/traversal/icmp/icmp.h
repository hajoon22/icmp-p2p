#ifndef ICMP_H
#define ICMP_H

#include <stddef.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#define MAX_DATA_BUFFER 1500

struct icmp_unreach {
    struct iphdr iph;
    struct icmphdr icmph;

    uint8_t *data;
    size_t data_len;
};

void deinit_icmp_unreach(struct icmp_unreach *rp);
struct icmp_unreach *read_icmp_unreach(int s);
int send_icmp_unreach(int s, uint32_t saddr, uint16_t sport, uint32_t daddr, uint16_t dport, uint8_t *data, size_t len);

#endif
