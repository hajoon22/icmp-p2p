//#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "protocol.h"
#include "../icmp/icmp.h"
#include "../peer/peer.h"
#include "../monocypher/monocypher.h"
#include "../../config.h"

// [type:1][want:1][free slots:1][public key:32][signature:64]
static size_t build_lookup_request(uint8_t **buf, uint8_t *pub, uint8_t *priv, uint8_t want, uint8_t f) {
	*buf = malloc(99);
	if (!*buf) return 0;

	(*buf)[0] = LOOKUP; // lookup type
	(*buf)[1] = want; // want peers
	(*buf)[2] = f; // free slots
	memcpy(*buf+3, pub, 32);
	crypto_eddsa_sign(*buf+35, priv, *buf, 35);

	return 99;
}

int send_lookup_request(int s, uint8_t *pub, uint8_t *priv, uint32_t addr, uint8_t f) {
	// build lookup request packet
	uint8_t *buf = NULL;

	uint8_t want = free_slots()*peer_trust(addr)/MAX_TRUST;
	uint8_t unchecked = unchecked_slots();
	if (want > unchecked) {
	    want = unchecked;
	}

	size_t n = build_lookup_request(&buf, pub, priv, want, f);
	if (n < 1) return -1;

	// lookup request to bootstrap
	for (int i = 0; i < MAX_RETRY; i++) {
		if (send_echo_packet(s, 8, addr, buf, n) < 0) {
			continue;
		}

		break;
	}
	
	free(buf);

	return 0;
}

void parse_lookup_request(int s, uint8_t *pub, uint8_t *priv, struct icmp_echo *rp) {
	if (rp->icmph.type != 8) return;
	if (rp->data_len != 99) return;
	if (rp->data[0] != LOOKUP) return;

	uint8_t want = rp->data[1]; // want peers
	uint8_t f = rp->data[2]; // free slots
	uint8_t *pk = rp->data+3;
	uint8_t *sig = rp->data+35;
	
	if (crypto_eddsa_check(sig, pk, rp->data, 35) != 0) {
		return;
	}

	if (new_peer(pk, ntohl(rp->iph.saddr), f, 0, false) < 0) {
		return; // invalid public key
	}
	
	// send lookup response
	send_lookup_response(s, pub, priv, ntohl(rp->iph.saddr), want, free_slots());
}

// [type:1][free_slots:1][peers:n][public key:32][signature:64]
// peer entry: [ip:4]
static size_t build_lookup_response(uint32_t dst, uint8_t **buf, uint8_t *pub, uint8_t *priv, uint8_t want, uint8_t f) {
	uint8_t len = 0;
	uint32_t *lists = get_peers(dst, want, &len);

	*buf = malloc(98+len*4);
	if (!*buf) {
		free(lists);
		return 0;
	}

	(*buf)[0] = LOOKUP;
	(*buf)[1] = f;
	if (0 < len) {
		memcpy(*buf+2, lists, 4*len);
		free(lists);
	}

	memcpy(*buf+2+len*4, pub, 32);
	crypto_eddsa_sign(*buf+34+len*4, priv, *buf, 34+len*4);

	return 98+len*4;
}

int send_lookup_response(int s, uint8_t *pub, uint8_t *priv, uint32_t addr, uint8_t want, uint8_t f) {
	uint8_t *buf = NULL;
	size_t n = build_lookup_response(addr, &buf, pub, priv, want, f);
	if (n < 1) return -1;

	for (int i = 0; i < MAX_RETRY; i++) {
		if (send_echo_packet(s, 0, addr, buf, n) < 0) {
			continue;
		}

		break;
	}

	free(buf);

	return 0;
}

void parse_lookup_response(int s, uint8_t *pub, uint8_t *priv, struct icmp_echo *rp) {
	if (rp->icmph.type != 0) return;
	if (rp->data_len < 98) return;
	if (rp->data[0] != LOOKUP) return;

	uint8_t f = rp->data[1];

	if ((rp->data_len-98)%4 != 0) return;
	size_t peers_len = (rp->data_len-98)/4;
	if (MAX_PEERS < peers_len) return;

	uint8_t *pk = rp->data+2+4*peers_len;
	uint8_t *sig = rp->data+34+4*peers_len;

	if (crypto_eddsa_check(sig, pk, rp->data, 34+4*peers_len) != 0) {
		return;
	}

	if (new_peer(pk, ntohl(rp->iph.saddr), f, 0, false) < 0) {
		return; // failed check the public key
	}

	for (int i = 0; i < peers_len; i++) {
		uint32_t ip = 0;
		memcpy(&ip, rp->data+2+4*i, 4);
		new_peer(NULL, ntohl(ip), 0, ntohl(rp->iph.saddr), false);
	}
}
