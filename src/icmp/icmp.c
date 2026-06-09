#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#include "icmp.h"
#include "../utils/utils.h"
#include "checksum/checksum.h"

void deinit_icmp_echo(struct icmp_echo *rp) {
    if (!rp) return;
    free(rp->data);
    free(rp);
}

struct icmp_echo *read_icmp_echo(int s) {
    struct icmp_echo *rp = calloc(1, sizeof(struct icmp_echo));
    if (!rp) return NULL;

    char buf[1500];
    while (1) {
        int n = read(s, buf, 1500);
        if (n < 0) {
            free(rp);
            return NULL;
        }

        struct iphdr *iph = (struct iphdr *)buf;
        struct icmphdr *icmph = (struct icmphdr*)(buf+(iph->ihl*4));
        
        // 0 or 8 (echo reply or request)
        if (icmph->type == 0 || icmph->type == 8) {
            char *payload = (char *)(icmph+1);
            int len = ntohs(iph->tot_len)-(sizeof(struct icmphdr)+iph->ihl*4);
            if (len <= 0) {
                continue;
            }

            if (len > MAX_DATA_BUFFER) {
                len = MAX_DATA_BUFFER;
            }

            // allocate heap buffer for payload
            char *data = calloc(1, len);
            if (!data) {
                continue;
            }

            // copy stack to heap
            memcpy(data, payload, len);

            // set results
            rp->iph = *iph;
            rp->icmph = *icmph;

            rp->data = data;
            rp->data_len = len;

            break;
        }
    }

    return rp;
}

static char *build_echo_packet(uint8_t type, char *data, size_t len) {
    char *buf = calloc(1, len+sizeof(struct icmphdr));
    if (!buf) return NULL;

    struct icmphdr *icmph = (struct icmphdr *)buf;
    icmph->type = type; // echo type (0 = reply, 8 = request)
    icmph->un.echo.id = random_int(65535);
    icmph->un.echo.sequence = htons(1);
    
    memcpy(buf+sizeof(struct icmphdr), data, len);
    icmph->checksum = checksum(buf, len+sizeof(struct icmphdr));

    return buf;
}


int send_echo_packet(int s, uint8_t type, uint32_t dst, char *data, size_t len) {
    if (type != 0 && type != 8) {
        return ICMP_UNKNOWN_TYPE;
    }
    
    char *buf = build_echo_packet(type, data, len);
    if (!buf) return ICMP_ERROR_BUILD;

    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(dst);
    
    int n = sendto(s, buf, len+sizeof(struct icmphdr), 0, (struct sockaddr *)&sin, sizeof(sin));
    free(buf);
    if (n != (len+sizeof(struct icmphdr))) {
        return ICMP_ERROR_SEND;
    }

    return n;
}
