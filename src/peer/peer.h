#ifndef PEER_H
#define PEER_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

enum state {
    checked,
    checking,
    unchecked,
};

struct peer {
    enum state state;
    bool is_bootstrap;

    char pub_key[32]; // public key
    uint32_t address; // ip address
    uint8_t free_slots; // free connection slots

    
    time_t last_sent;
    time_t last_seen;

    int trust; // trust score
    uint32_t source; // source of this peer (ipv4)
};

void handle_peers(int s, char *pub, char *priv);
uint8_t free_slots(void);
uint32_t *get_peers(uint32_t dst, uint8_t count, uint8_t *len);
int new_peer(char *pub, uint32_t addr, uint8_t free_slots, uint32_t source, bool bootstrap);
void broadcast_peers(int s, uint8_t fanout, char *data, size_t len);
int peer_trust(uint32_t addr);
uint8_t unchecked_slots(void);

#endif
