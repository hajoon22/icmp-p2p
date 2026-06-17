//#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "protocol.h"
#include "../icmp/icmp.h"
#include "../peer/peer.h"
#include "../monocypher/monocypher.h"
#include "../../config.h"

// [type:1][port:2][want:1][free slots:1][public key:32][signature:64]
static size_t build_lookup_request(uint8_t **buf, uint8_t *pub, uint8_t *priv, uint16_t port, uint8_t want, uint8_t f) {
	*buf = malloc(101);
	if (!*buf) return 0;

	(*buf)[0] = LOOKUP_REQ; // lookup type

	// udp mapped port
	port = htons(port);
	memcpy(*buf+1, &port, 2);

	(*buf)[3] = want; // want peers
	(*buf)[4] = f; // free slots
	memcpy(*buf+5, pub, 32);
	crypto_eddsa_sign(*buf+37, priv, *buf, 37);

	return 101;
}

void send_lookup_request(int s, uint8_t *pub, uint8_t *priv, uint32_t daddr, uint16_t dport, uint16_t sport, uint8_t f) {
	// build lookup request packet
	uint8_t *buf = NULL;

	uint8_t want = free_slots()*peer_trust(daddr)/MAX_TRUST;
	uint8_t unchecked = unchecked_slots();
	if (want > unchecked) {
	    want = unchecked;
	}

	size_t n = build_lookup_request(&buf, pub, priv, sport, want, f);
	if (n < 1) return;

	// lookup request to bootstrap
	for (int i = 0; i < MAX_RETRY; i++) {
		if (send_icmp_unreach(s, daddr, dport, ntohl(inet_addr(STUN_ADDR)), STUN_PORT, buf, n) < 0) {
			continue;
		}

		break;
	}
	
	free(buf);
}

void parse_lookup_request(int s, uint8_t *pub, uint8_t *priv, struct icmp_unreach *rp) {
	if (rp->data_len != 101) return;
	if (rp->data[0] != LOOKUP_REQ) return;

	uint16_t port = 0;
	memcpy(&port, rp->data+1, 2);
	port = ntohs(port);

	uint8_t want = rp->data[3]; // want peers
	uint8_t f = rp->data[4]; // free slots
	uint8_t *pk = rp->data+5;
	uint8_t *sig = rp->data+37;
	
	if (crypto_eddsa_check(sig, pk, rp->data, 37) != 0) {
		return;
	}

	if (new_peer(pk, ntohl(rp->iph.saddr), port, f, 0, false) < 0) {
		return; // invalid public key
	}
	
	// send lookup response
	send_lookup_response(s, pub, priv, ntohl(rp->iph.saddr), port, want, free_slots());
}

// [type:1][free_slots:1][peers:n][public key:32][signature:64]
// peer entry: [ip:4][mapped_port:2]
static size_t build_lookup_response(uint32_t dst, uint8_t **buf, uint8_t *pub, uint8_t *priv, uint8_t want, uint8_t f) {
	uint8_t len = 0;
	uint8_t *lists = get_peers(dst, want, &len);

	*buf = malloc(98+len*6);
	if (!*buf) {
		free(lists);
		return 0;
	}

	(*buf)[0] = LOOKUP_RES;
	(*buf)[1] = f;
	if (0 < len) {
		memcpy(*buf+2, lists, len*6);
		free(lists);
	}

	memcpy(*buf+2+len*6, pub, 32);
	crypto_eddsa_sign(*buf+34+len*6, priv, *buf, 34+len*6);

	return 98+len*6;
}

void send_lookup_response(int s, uint8_t *pub, uint8_t *priv, uint32_t addr, uint16_t port, uint8_t want, uint8_t f) {
	uint8_t *buf = NULL;
	size_t n = build_lookup_response(addr, &buf, pub, priv, want, f);
	if (n < 1) return;

	for (int i = 0; i < MAX_RETRY; i++) {
		if (send_icmp_unreach(s, addr, port, ntohl(inet_addr(STUN_ADDR)), STUN_PORT, buf, n) < 0) {
			continue;
		}

		break;
	}

	free(buf);
}

void parse_lookup_response(int s, uint8_t *pub, uint8_t *priv, struct icmp_unreach *rp) {
	if (rp->data_len < 98) return;
	if (rp->data[0] != LOOKUP_RES) return;

	uint8_t f = rp->data[1];

	if ((rp->data_len-98)%6 != 0) return;
	size_t peers_len = (rp->data_len-98)/6;
	if (MAX_PEERS < peers_len) return;

	uint8_t *pk = rp->data+2+6*peers_len;
	uint8_t *sig = rp->data+34+6*peers_len;

	if (crypto_eddsa_check(sig, pk, rp->data, 34+6*peers_len) != 0) {
		return;
	}

	if (new_peer(pk, ntohl(rp->iph.saddr), 0, f, 0, false) < 0) {
		return; // failed check the public key
	}

	for (int i = 0; i < peers_len; i++) {
		uint32_t addr = 0;
		uint16_t port = 0;
		memcpy(&addr, rp->data+2+i*6, 4);
		memcpy(&port, rp->data+2+i*6+4, 2);
		addr = ntohl(addr);
		port = ntohs(port);

		new_peer(NULL, addr, port, 0, ntohl(rp->iph.saddr), false);
	}
}
