#ifndef PEER_H
#define PEER_H

#include <stdint.h>
#include <time.h>

enum state {
    checked,
    checking,
    unchecked,
};

struct peer {
    enum state state;

    char pub_key[32]; // public key

    uint32_t address; // ip address

    time_t last_sent;
    time_t last_seen;
    uint8_t free_slots; // free connection slots
};

void handle_peers(int s, char *pub, char *priv);
uint8_t free_slots(void);
uint32_t *get_peers(uint32_t dst, uint8_t count, uint8_t *len);
int new_peer(char *pub, uint32_t addr, uint8_t free_slots);
void broadcast_peers(int s, char *data, size_t len);

#endif
