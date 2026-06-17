#include <stdint.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <unistd.h>
#include <string.h>

#include "icmp.h"
#include "checksum/checksum.h"

void deinit_icmp_unreach(struct icmp_unreach *rp) {
    if (!rp) return;
    free(rp->data);
    free(rp);
}

static ssize_t build_icmp_unreach(uint8_t **buf, struct iphdr *iph, struct udphdr *udph, uint8_t *data, size_t len) {
    *buf = malloc(8+iph->ihl*4+sizeof(struct udphdr)+len);
    if (!*buf) return -1;

    struct icmphdr *icmph = (struct icmphdr *)*buf;
    memset(icmph, 0, sizeof(*icmph));
    icmph->type = ICMP_DEST_UNREACH;
    icmph->code = ICMP_NET_UNREACH;
    memcpy(*buf+8, iph, iph->ihl*4); // ip header
    memcpy(*buf+8+iph->ihl*4, udph, sizeof(struct udphdr));
    memcpy(*buf+8+iph->ihl*4+sizeof(struct udphdr), data, len);

    ((struct icmphdr *)(*buf))->checksum = htons(checksum(*buf, 8+iph->ihl*4+sizeof(struct udphdr)+len));

    return 8+iph->ihl*4+sizeof(struct udphdr)+len;
}

int send_icmp_unreach(int s, uint32_t saddr, uint16_t sport, uint32_t daddr, uint16_t dport, uint8_t *data, size_t len) {
    struct iphdr iph;
    struct udphdr udph;

    memset(&iph, 0, sizeof(iph));
    memset(&udph, 0, sizeof(udph));

    iph.version = 4; // ipv4
    iph.ihl = 5;
    iph.tos = 0;
    iph.tot_len = htons(sizeof(struct iphdr)+sizeof(struct udphdr)+len);
    iph.id = 0;
    iph.frag_off = 0;
    iph.ttl = 64;
    iph.protocol = 17; // udp
    iph.check = 0;
    iph.saddr = htonl(saddr);
    iph.daddr = htonl(daddr);
    iph.check = htons(checksum((uint8_t *)&iph, sizeof(iph)));

    udph.source = htons(sport);
    udph.dest   = htons(dport);
    udph.len    = htons(sizeof(struct udphdr)+len);
    udph.check  = htons(checksum((uint8_t *)&udph, sizeof(udph)));

    uint8_t *buf = NULL;
    ssize_t size = build_icmp_unreach(&buf, &iph, &udph, data, len);
    if (size < 0) return size;

    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(saddr);

    int n = sendto(s, buf, size, 0, (struct sockaddr *)&sin, sizeof(sin));
    free(buf);
    if (n != size) return -1;

    return 0;
}

struct icmp_unreach *read_icmp_unreach(int s) {
    struct icmp_unreach *rp = calloc(1, sizeof(struct icmp_unreach));
    if (!rp) return NULL;

    char buf[MAX_DATA_BUFFER];
    int n = read(s, buf, MAX_DATA_BUFFER);
    if (n < 0) {
        free(rp);
        return NULL;
    }

    struct iphdr *iph = (struct iphdr *)buf;
    if (n < sizeof(struct iphdr) || ntohs(iph->tot_len) != n) {
        free(rp);
        return NULL;
    }

    if (iph->ihl < 5 || iph->ihl*4+sizeof(struct icmphdr) > n) {
        free(rp);
        return NULL;
    }

    struct icmphdr *icmph = (struct icmphdr*)(buf+(iph->ihl*4));
    if (icmph->type == ICMP_DEST_UNREACH) {
        uint8_t *payload = (uint8_t *)icmph+sizeof(struct icmphdr)+28;
        int len = ntohs(iph->tot_len)-(sizeof(struct icmphdr)+iph->ihl*4+28);
        if (len <= 0) {
            free(rp);
            return NULL;
        }

        if (len > MAX_DATA_BUFFER) {
            len = MAX_DATA_BUFFER;
        }

        // allocate heap buffer for payload
        uint8_t *data = calloc(1, len);
        if (!data) {
            free(rp);
            return NULL;
        }

        // copy stack to heap
        memcpy(data, payload, len);

        // set results
        rp->iph = *iph;
        rp->icmph = *icmph;

        rp->data = data;
        rp->data_len = len;

        return rp;
    }

    free(rp);
    return NULL;
}
