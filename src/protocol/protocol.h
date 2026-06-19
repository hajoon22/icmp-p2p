#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>
#include "../icmp/icmp.h"

enum {
    LOOKUP_REQ = 0,
    LOOKUP_RES = 1,
    MESSAGE = 2,
};

void parse_lookup_request(int s, uint8_t *pub, uint8_t *priv, struct icmp_unreach *rp);
void parse_lookup_response(int s, uint8_t *pub, uint8_t *priv, struct icmp_unreach *rp);

uint16_t send_lookup_request(int s, uint8_t *pub, uint8_t *priv, uint32_t daddr, uint16_t dport, uint16_t sport, uint8_t f);

#endif
