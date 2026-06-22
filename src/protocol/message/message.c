#include <stdio.h>
#include <time.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>

#include "../protocol.h"
#include "../../../config.h"
#include "../../peer/peer.h"
#include "../../monocypher/monocypher.h"
#include "../../traversal/traversal.h"

static int next_index = 0;
static uint64_t last_ids[MAX_MESSAGE_HISTORY];

//[type:1][message:n][fanout:1][expiry:8][siagnature:64]
void parse_message(struct traversal_session *ts, struct icmp_unreach *rp) {    
    if (rp->data_len < 74) return;
    if (rp->data[0] != MESSAGE) return;

    char *message = rp->data+1;
    size_t message_len = rp->data_len-74;

    uint64_t expiry;
    memcpy(&expiry, message+message_len+1, 8);
    expiry = be64toh(expiry);
    
    uint8_t *signature = message+message_len+9;

    // check the signature
    if (crypto_eddsa_check(signature, admin_pub, rp->data, message_len+10) != 0) {
		return;
	}

    // check expiry
    if (expiry < time(NULL)) {
        return;
    }

    uint64_t id;
    memcpy(&id, signature, sizeof(id));
    for (int i = 0; i < MAX_MESSAGE_HISTORY; i++) {
        if (last_ids[i] == id) return;
    }

    last_ids[next_index] = id;
    next_index = (next_index+1)%MAX_MESSAGE_HISTORY;

    printf("%.*s\n", (int)message_len, message);

    uint8_t fanout = *(uint8_t *)(message+message_len);
    broadcast_peers(ts, fanout, rp->data, rp->data_len);
}
