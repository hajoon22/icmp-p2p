#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>
#include "../icmp/icmp.h"

enum {
    LOOKUP = 0,
    MESSAGE = 1,
};

void parse_lookup_request(int s, char *pub, char *priv, struct icmp_echo *rp);
int send_lookup_request(int s, char *pub, char *priv, uint32_t addr, uint8_t f);

void parse_lookup_response(int s, char *pub, char *priv, struct icmp_echo *rp);
int send_lookup_response(int s, char *pub, char *priv, uint32_t addr, uint8_t want, uint8_t f);

#endif
