#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>

#include "peer.h"
#include "../../config.h"
#include "../protocol/protocol.h"

static int next_index = 0;
static struct peer peers[MAX_PEERS];

static void add_trust_score(uint32_t addr, int n) {
    if (addr == 0) return;
    for (int i = 0; i < next_index; i++) {
        struct peer *p = &peers[i];
        if (p->address == addr) {
            if (p->trust+n > MAX_TRUST) {
                p->trust = MAX_TRUST;
                return;
            } else if (p->trust+n < BAN_TRUST) {
                p->trust = BAN_TRUST;
                return;
            }

            p->trust += n;

            return;
        }
    }
}

static void update_peer(struct peer *p, char *pub, uint8_t fs) {
    p->state = checked;
    p->free_slots = fs;
    p->last_seen = time(NULL);
    memcpy(p->pub_key, pub, 32);

    add_trust_score(p->address, GOOD_PEER_TRUST);
    add_trust_score(p->source, GOOD_SOURCE_TRUST);

    struct in_addr a = {
        .s_addr = htonl(p->address)
    };
    printf("updated peer: addr=%s, free=%d, last_seen=%ld, trust=%d\n", inet_ntoa(a), fs, p->last_seen, p->trust);
}

static int add_peer(char *pub, uint32_t addr, uint8_t fs, uint32_t source) {
    if (next_index >= MAX_PEERS) {
        return -1; // max
    } else if (pub && fs < 1) {
        return 0;
    }
    
    peers[next_index] = (struct peer) {
        .state = unchecked,
        .address = addr,
        .last_sent = 0,
        .last_seen = 0,
        .free_slots = fs,
        .pub_key = {0},
        .source = source,
        .trust = DEFAULT_TRUST,
    };

    if (pub) {
        memcpy(peers[next_index].pub_key, pub, 32);
        peers[next_index].state = checked;
        peers[next_index].last_seen = time(NULL);
    }
    next_index++;

    struct in_addr a = {
        .s_addr = htonl(addr)
    };
    printf("added peer: addr=%s, free=%d\n", inet_ntoa(a), fs);

    return 0;
}

int new_peer(char *pub, uint32_t addr, uint8_t fs, uint32_t source) {
    for (int i = 0; i < next_index; i++) {
        struct peer *p = &peers[i];
        if (p->address == addr) {
            if (!pub) return 0;
            if (p->state == checked) {
                if (memcmp(p->pub_key, pub, 32) == 0) {
                    update_peer(p, p->pub_key, fs);
                    return 0;    
                }

                return -1; // invalid public key
            }

            if (p->state != checked) {
                update_peer(p, pub, fs);
                return 0;
            }
        }
    }

    return add_peer(pub, addr, fs, source);
}

uint8_t free_slots(void) {
    uint8_t free = 0;
    free = MAX_PEERS-next_index;

    return free;
}

uint32_t *get_peers(uint32_t dst, uint8_t count, uint8_t *len) {
    uint32_t *results = malloc(sizeof(uint32_t)*count);
    if (!results) return NULL;

    for (int i = 0; i < next_index && *len < count; i++) {
        if (peers[i].free_slots == 0 || peers[i].state != checked || peers[i].address == dst) {
            continue;
        }

        if (peers[i].trust <= MIN_TRUST) continue;

        results[*len] = htonl(peers[i].address);
        (*len)++;
    }
    
    if (*len == 0) {
        free(results);
        return NULL;
    }

    return results;
}

void broadcast_peers(int s, char *data, size_t len) {
    for (int i = 0; i < next_index; i++) {
        struct peer *p = &peers[i];
        if (p->state == checked) {
            send_echo_packet(s, 8, p->address, data, len);
        }
    }
}

void handle_peers(int s, char *pub, char *priv) {
    time_t now = time(NULL);
    for (int i = 0; i < next_index; i++) {
        struct peer *p = &peers[i];
        if (p->trust == BAN_TRUST) {
            memmove(p, p+1, sizeof(struct peer)*(next_index-i-1));
            next_index--;
            i--;

            continue;    
        }
        
        
        if (p->state == unchecked && p->last_seen == 0) {
            p->state = checking;
            p->last_sent = time(NULL);
            p->last_seen = time(NULL);
            send_lookup_request(s, pub, priv, p->address, MAX_PEERS-next_index);

            continue;
        }

        // check the timeout and removing the peer (10 min)
        if (now-p->last_seen >= 600) {
            if (p->state == checking) {
                add_trust_score(p->source, BAD_SOURCE_TRUST);
            }
            
            memmove(p, p+1, sizeof(struct peer)*(next_index-i-1));
            next_index--;
            i--;

            continue;
        }

        // check the last seen
        if (now-p->last_seen >= 60 && now-p->last_sent >= 60) {
            p->last_sent = time(NULL);
            send_lookup_request(s, pub, priv, p->address, MAX_PEERS-next_index);
        }
    }
}
