#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>

#include "../traversal/traversal.h"
#include "../traversal/icmp/icmp.h"

enum {
    LOOKUP_REQ = 0,
    LOOKUP_RES = 1,
    MESSAGE = 2,
};

void parse_lookup_request(struct traversal_session *ts, uint8_t *pub, uint8_t *priv, struct icmp_unreach *rp);
void parse_lookup_response(uint8_t *pub, uint8_t *priv, struct icmp_unreach *rp);

uint16_t send_lookup_request(struct traversal_session *ts, uint8_t *pub, uint8_t *priv, uint32_t daddr, uint16_t dport, uint8_t f);

#endif
