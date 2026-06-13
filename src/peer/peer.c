#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <stdbool.h>

#include "peer.h"
#include "../../config.h"
#include "../protocol/protocol.h"
#include "../utils/utils.h"

static int next_index = 0;
static size_t unchecked_peers = 0;
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

int peer_trust(uint32_t addr) {
    for (int i = 0; i < next_index; i++) {
        struct peer *p = &peers[i];
        if (p->address == addr) {
            return p->trust;
        }
    }

    return DEFAULT_TRUST;
}

static void update_peer(struct peer *p, char *pub, uint8_t fs) {
    if (p->state != checked) {
        unchecked_peers--;
    }

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

static int add_peer(char *pub, uint32_t addr, uint8_t fs, uint32_t source, bool bootstrap) {
    struct in_addr a = {
        .s_addr = htonl(addr)
    };

    if (next_index >= MAX_PEERS) {
        printf("table full: addr=%s free=%u source=%u next_index=%d\n", inet_ntoa(a), fs, source, next_index);
        return 0;
    } else if (pub && fs < 1) {
        printf("no free slots: addr=%s free=%u next_index=%d\n", inet_ntoa(a), fs, next_index);
        return 0;
    }

    peers[next_index] = (struct peer) {
        .state = unchecked,
        .is_bootstrap = bootstrap,
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

    if (!pub) unchecked_peers++;

    printf("added peer: addr=%s, free=%d\n", inet_ntoa(a), fs);

    return 0;
}

int new_peer(char *pub, uint32_t addr, uint8_t fs, uint32_t source, bool bootstrap) {
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

    // unchecked slots are full
    if (!pub && unchecked_peers+1 > MAX_UNCHECKED_PEERS) {
        return 0;
    }

    return add_peer(pub, addr, fs, source, bootstrap);
}

uint8_t free_slots(void) {
    uint8_t free = 0;
    free = MAX_PEERS-next_index;
    return free;
}

uint8_t unchecked_slots(void) {
    if (unchecked_peers >= MAX_UNCHECKED_PEERS) {
        return 0;
    }

    return MAX_UNCHECKED_PEERS-unchecked_peers;
}

uint32_t *get_peers(uint32_t dst, uint8_t count, uint8_t *len) {
    if (count == 0) return NULL;

    uint32_t *results = malloc(sizeof(uint32_t)*count);
    if (!results) return NULL;

    for (int i = 0; i < next_index && *len < count; i++) {
        if (peers[i].is_bootstrap) continue;
        if (peers[i].free_slots == 0) continue;
        if (peers[i].state != checked) continue;
        if (peers[i].address == dst) continue;
        if (peers[i].trust <= MIN_TRUST) continue;

        results[*len] = htonl(peers[i].address);
        (*len)++;
    }

    if (*len < count) {
        for (int i = 0; i < next_index && *len < count; i++) {
            if (peers[i].is_bootstrap) continue;
            if (peers[i].free_slots != 0) continue;
            if (peers[i].state != checked) continue;
            if (peers[i].address == dst) continue;
            if (peers[i].trust <= MIN_TRUST) continue;

            results[*len] = htonl(peers[i].address);
            (*len)++;
        }
    }
    
    if (*len == 0) {
        free(results);
        return NULL;
    }

    return results;
}

static void shuffle_peers(void) {
    if (next_index == 0) return;

    for (int i = 0; i < next_index; i++) {
        int n = random_int(next_index-1);
        struct peer tmp = peers[n];
        peers[n] = peers[i];
        peers[i] = tmp;
    }
}

void broadcast_peers(int s, uint8_t fanout, char *data, size_t len) {
    int index[MAX_PEERS], next = 0;
    for (int i = 0; i < next_index; i++) {
        if (peers[i].state == checked) {
            index[next++] = i;
        }
    }
    if (next == 0) return;

    // all broadcast
    if (fanout == 0 || next <= fanout) {
        for (int i = 0; i < next; i++) {
            send_echo_packet(s, 8, peers[index[i]].address, data, len);
        }

        return;
    }

    // broadcast random peers using fanout
    for (int i = 0; i < fanout; i++) {
        int n = random_int(next-1);
        send_echo_packet(s, 8, peers[index[n]].address, data, len);

        index[n] = index[--next];
    } 
}

void handle_peers(int s, char *pub, char *priv) {
    shuffle_peers();

    time_t now = time(NULL);
    for (int i = 0; i < next_index; i++) {
        struct peer *p = &peers[i];
        if (p->trust == BAN_TRUST) {
            peers[i] = peers[--next_index];
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
        if (now-p->last_seen >= PEER_TIMEOUT) {
            if (p->state == checking) {
                unchecked_peers--;
                add_trust_score(p->source, BAD_SOURCE_TRUST);
            }
            
            peers[i] = peers[--next_index];
            i--;

            continue;
        }

        // check the last seen
        if (now-p->last_seen >= PEER_REQUEST_INTERVAL && now-p->last_sent >= PEER_REQUEST_INTERVAL) {
            p->last_sent = time(NULL);
            send_lookup_request(s, pub, priv, p->address, MAX_PEERS-next_index);
        }
    }
}
