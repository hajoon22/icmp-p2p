#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip_icmp.h>
#include <poll.h>
#include <stdbool.h>

#include "config.h"
#include "src/peer/peer.h"
#include "src/utils/utils.h"
#include "src/protocol/protocol.h"
#include "src/monocypher/monocypher.h"
#include "src/protocol/message/message.h"
#include "src/traversal/traversal.h"
#include "src/traversal/icmp/icmp.h"

int main(int argc, char *argv[]) {
	// generate random seed and public/private key
	uint8_t seed[32], pub[32], priv[64];
	if (random_bytes(seed, 32) < 0) return -1;

	crypto_eddsa_key_pair(priv, pub, seed);

    struct traversal_session ts;
	uint32_t stun_address = ntohl(inet_addr(STUN_ADDR));
    if (new_traversal_session(&ts, stun_address, STUN_PORT) < 0) {
        return -1;
    }
    
    struct in_addr a;
    a.s_addr = htonl(ts.public_address);
    printf("udp mapped: public addr=%s, public sport=%d\n", inet_ntoa(a), ts.mapped_port);

	// send lookup request packet to bootstraps
	for (int i = 1; i < argc; i++) {
		uint32_t addr;
		uint16_t port;
		if (parse_ipv4_port(argv[i], &addr, &port) < 0) {
			continue;
		}

		struct in_addr a;
    	a.s_addr = htonl(addr);
		printf("bootstrap: addr=%s, mapped port=%d\n", inet_ntoa(a), port);

		uint16_t nonce = send_lookup_request(&ts, pub, priv, addr, port, free_slots());
		new_peer(NULL, addr, port, 0, 0, nonce, 0, true);
	}

	while (1) {
		handle_peers(&ts, pub, priv);
		struct icmp_unreach *rp = traversal_read(&ts, 100);
		if (!rp) continue;

		parse_message(&ts, rp);
		parse_lookup_request(&ts, pub, priv, rp);
		parse_lookup_response(pub, priv, rp); 		

		deinit_icmp_unreach(rp);
	}

	deinit_traversal_session(&ts);
	return 0;
}
