#ifndef PEER_H
#define PEER_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#include "../traversal/traversal.h"

enum state {
    checked, // checked peer
    checking, // sent the lookup request and wating response
    unchecked, // not checked yet
};

struct peer {
    enum state state;
    bool is_bootstrap;

    uint8_t pub_key[32]; // public key
    uint32_t address; // ip address
    uint16_t mapped_port; // mapped port (udp)
    uint8_t free_slots; // free connection slots

    uint16_t nonce; // now nonce
    
    time_t last_sent;
    time_t last_seen;

    int trust; // trust score
    uint32_t source; // source of this peer (ipv4)

    int tried; // lookup request tried
};

uint8_t free_slots(void);
int peer_trust(uint32_t addr);
uint8_t unchecked_slots(void);
uint8_t *get_peers(uint32_t dst, uint8_t count, uint8_t *len);
void handle_peers(struct traversal_session *ts, uint8_t *pub, uint8_t *priv);
void broadcast_peers(struct traversal_session *ts, uint8_t fanout, uint8_t *data, size_t len);
int new_peer(uint8_t *pub, uint32_t addr, uint16_t port, uint8_t fs, uint32_t source, uint16_t save_nonce, uint16_t check_nonce, bool bootstrap);

#endif
