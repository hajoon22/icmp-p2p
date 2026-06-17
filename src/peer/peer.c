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

static void update_peer(struct peer *p, uint8_t *pub, uint8_t fs) {
    if (p->state != checked) {
        unchecked_peers--;
    }

    p->state = checked;
    p->free_slots = fs;
    p->last_sent = time(NULL);
    p->last_seen = time(NULL);

    if (pub) memcpy(p->pub_key, pub, 32);

    add_trust_score(p->address, GOOD_PEER_TRUST);
    add_trust_score(p->source, GOOD_SOURCE_TRUST);

    struct in_addr a = {
        .s_addr = htonl(p->address)
    };
    printf("updated peer: addr=%s, free=%d, last_seen=%ld, trust=%d\n", inet_ntoa(a), fs, p->last_seen, p->trust);
}

static int add_peer(uint8_t *pub, uint32_t addr, uint16_t port, uint8_t fs, uint32_t source, bool bootstrap) {
    struct in_addr a = {
        .s_addr = htonl(addr)
    };

    if (next_index >= MAX_PEERS) {
        printf("table full: addr=%s free=%u source=%u next_index=%d\n", inet_ntoa(a), fs, source, next_index);
        return 0;
    }

    peers[next_index] = (struct peer) {
        .state = unchecked,
        .is_bootstrap = bootstrap,
        .address = addr,
        .mapped_port = port,
        .last_sent = 0,
        .last_seen = 0,
        .free_slots = fs,
        .pub_key = {0},
        .source = source,
        .trust = DEFAULT_TRUST,
        .tried = 0,
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

int new_peer(uint8_t *pub, uint32_t addr, uint16_t port, uint8_t fs, uint32_t source, bool bootstrap) {
    for (int i = 0; i < next_index; i++) {
        struct peer *p = &peers[i];
        if (p->address == addr) {
            if (!pub) return 0;
            if (p->state == checked) {
                if (memcmp(p->pub_key, pub, 32) == 0) {
                    update_peer(p, NULL, fs);
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

    return add_peer(pub, addr, port, fs, source, bootstrap);
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

// [ipv4:4][port:2]
uint8_t *get_peers(uint32_t dst, uint8_t count, uint8_t *len) {
    if (count == 0) return NULL;

    uint8_t *buf = malloc(6*count);
    if (!buf) return NULL;

    for (int i = 0; i < next_index && *len < count; i++) {
        if (peers[i].is_bootstrap) continue;
        if (peers[i].free_slots == 0) continue;
        if (peers[i].state != checked) continue;
        if (peers[i].address == dst) continue;
        if (peers[i].trust <= MIN_TRUST) continue;

        uint32_t ip = htonl(peers[i].address);
        uint16_t port = htons(peers[i].mapped_port);
        memcpy(buf+((*len)*6), &ip, 4);
        memcpy(buf+((*len)*6+4), &port, 2);
        (*len)++;
    }

    if (*len < count) {
        for (int i = 0; i < next_index && *len < count; i++) {
            if (peers[i].is_bootstrap) continue;
            if (peers[i].free_slots != 0) continue;
            if (peers[i].state != checked) continue;
            if (peers[i].address == dst) continue;
            if (peers[i].trust <= MIN_TRUST) continue;

            uint32_t ip = htonl(peers[i].address);
            uint16_t port = htons(peers[i].mapped_port);
            memcpy(buf+((*len)*6), &ip, 4);
            memcpy(buf+((*len)*6+4), &port, 2);
            (*len)++;
        }
    }

    if (*len == 0) {
        free(buf);
        return NULL;
    }

    return buf;
}

static void shuffle_peers(void) {
    if (next_index == 0) return;

    for (int i = 0; i < next_index; i++) {
        int n = random_int(next_index-1);
        if (n < 0) continue;

        struct peer tmp = peers[n];
        peers[n] = peers[i];
        peers[i] = tmp;
    }
}

void broadcast_peers(int s, uint8_t fanout, uint8_t *data, size_t len) {
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
            for (int j = 0; j < MAX_RETRY; j++) {
                struct peer *p = &peers[index[i]];
                if (send_icmp_unreach(s, p->address, p->mapped_port, ntohl(inet_addr(STUN_ADDR)), STUN_PORT, data, len) < 0) {
                    continue;
                }    

                break;
            }
        }

        return;
    }

    // broadcast random peers using fanout
    for (int i = 0; i < fanout; i++) {
        int n = random_int(next-1);
        if (n < 0) {
            i--;
            continue;
        }

        for (int j = 0; j < MAX_RETRY; j++) {
            struct peer *p = &peers[index[j]];
            if (send_icmp_unreach(s, p->address, p->mapped_port, ntohl(inet_addr(STUN_ADDR)), STUN_PORT, data, len) < 0) {
                continue;
            }  

            break;
        }
        
        index[n] = index[--next];
    } 
}

void handle_peers(int s, uint16_t port, uint8_t *pub, uint8_t *priv) {
    shuffle_peers();

    time_t now = time(NULL);
    for (int i = 0; i < next_index; i++) {
        struct peer *p = &peers[i];
        if (p->trust == BAN_TRUST) {
            peers[i--] = peers[--next_index];
            continue;
        }

       if (now-p->last_seen >= PEER_REQUEST_INTERVAL && now-p->last_sent >= PEER_REQUEST_INTERVAL) {
            if (p->state == unchecked) {
                p->state = checking;
                p->last_sent = time(NULL);
                send_lookup_request(s, pub, priv, p->address, p->mapped_port, port, MAX_PEERS-next_index);

                continue;
            }

            if (p->state == checking) {
                if (now-p->last_sent >= PEER_REQUEST_INTERVAL) {
                    if (p->tried+1 < MAX_RETRY) {
                        p->tried++;
                        p->last_sent = time(NULL);
                        send_lookup_request(s, pub, priv, p->address, p->mapped_port, port, MAX_PEERS-next_index);

                        continue; 
                    }  
                }
                
                if (now-p->last_sent >= PEER_TIMEOUT) {
                    unchecked_peers--;
                    add_trust_score(p->source, BAD_SOURCE_TRUST);
                    peers[i--] = peers[--next_index];
                
                    continue;
                }
            }
            
            if (p->state == checked) {
                if (now-p->last_seen >= PEER_TIMEOUT) {
                    add_trust_score(p->source, BAD_SOURCE_TRUST);
                    peers[i--] = peers[--next_index];
            
                    continue;      
                }

                p->last_sent = time(NULL);
                send_lookup_request(s, pub, priv, p->address, p->mapped_port, port, MAX_PEERS-next_index);
            }
       }
    }
}
