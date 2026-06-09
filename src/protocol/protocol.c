#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "protocol.h"
#include "../icmp/icmp.h"
#include "../peer/peer.h"
#include "../monocypher/monocypher.h"

// [type:1][free slots:1][public key:32][signature:64]
static size_t build_lookup_request(char **buf, char *pub, char *priv, uint8_t f) {
	*buf = malloc(98);
	if (!*buf) return 0;

	(*buf)[0] = LOOKUP; // lookup type
	(*buf)[1] = f;
	memcpy(*buf+2, pub, 32);
	crypto_eddsa_sign(*buf+34, priv, *buf, 34);

	return 98;
}

int send_lookup_request(int s, char *pub, char *priv, uint32_t addr, uint8_t f) {
	// build lookup request packet
	char *buf = NULL;
	size_t n = build_lookup_request(&buf, pub, priv, f);
	if (n < 1) return -1;

	// lookup request to bootstrap
	send_echo_packet(s, 8, addr, buf, n);
	free(buf);

	return 0;
}

void parse_lookup_request(int s, char *pub, char *priv, struct icmp_echo *rp) {
	uint8_t f = rp->data[1]; // free slots
	char *pk = rp->data+2;
	char *sig = rp->data+34;
	
	if (crypto_eddsa_check(sig, pk, rp->data, 34) != 0) {
		return;
	}

	new_peer(pk, ntohl(rp->iph.saddr), f, 0);
	
	// send lookup response
	send_lookup_response(s, pub, priv, ntohl(rp->iph.saddr), f, free_slots());
}

// [type:1][free_slots:1][peers:n][public key:32][signature:64]
// peer entry: [ip:4]
static size_t build_lookup_response(uint32_t dst, char **buf, char *pub, char *priv, uint8_t want, uint8_t f) {
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

int send_lookup_response(int s, char *pub, char *priv, uint32_t addr, uint8_t want, uint8_t f) {
	char *buf = NULL;
	size_t n = build_lookup_response(addr, &buf, pub, priv, want, f);
	if (n < 1) return -1;

	send_echo_packet(s, 0, addr, buf, n);
	free(buf);

	return 0;
}

void parse_lookup_response(int s, char *pub, char *priv, struct icmp_echo *rp) {
	uint8_t f = rp->data[1];
	uint8_t peers_len = (rp->data_len-98)/4;

	char *pk = rp->data+2+4*peers_len;
	char *sig = rp->data+34+4*peers_len;

	if (crypto_eddsa_check(sig, pk, rp->data, 34+4*peers_len) != 0) {
		return;
	}

	new_peer(pk, ntohl(rp->iph.saddr), f, 0);

	for (int i = 0; i < peers_len; i++) {
		uint32_t ip = 0;
		memcpy(&ip, rp->data+2+4*i, 4);
		new_peer(NULL, ntohl(ip), 0, ntohl(rp->iph.saddr));
	}
}
