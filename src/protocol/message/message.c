#include <stdio.h>
#include <time.h>
#include <stdint.h>
#include <string.h>

#include "../../../config.h"
#include "../../icmp/icmp.h"
#include "../../peer/peer.h"
#include "../../monocypher/monocypher.h"

static int next_index = 0;
static uint8_t last_ids[10];

//[type:1][id:1][message:n][expiry:8][siagnature:64]
void parse_message(int s, struct icmp_echo *rp) {
    uint8_t id = *(rp->data+1);

    char *message = rp->data+2;
    size_t message_len = rp->data_len-74;

    uint64_t expiry;
    memcpy(&expiry, message+message_len, 8);
    expiry = be64toh(expiry);
    
    char *signature = message+message_len+8;

    // check the signature
    if (crypto_eddsa_check(signature, admin_pub, rp->data, message_len+10) != 0) {
		return;
	}

    // check expiry
    if (expiry < time(NULL)) {
        return;
    }
    
    for (int i = 0; i < 10; i++) {
        if (last_ids[i] == id) return;
    }

    last_ids[next_index] = id;
    next_index = (next_index+1)%10;

    printf("%.*s\n", (int)message_len, message);
    broadcast_peers(s, rp->data, rp->data_len);
}
