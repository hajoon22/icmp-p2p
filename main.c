#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip_icmp.h>
#include <poll.h>
#include <stdbool.h>

#include "src/icmp/icmp.h"
#include "src/peer/peer.h"
#include "src/utils/utils.h"
#include "src/protocol/protocol.h"
#include "src/monocypher/monocypher.h"
#include "src/protocol/message/message.h"

int main(int argc, char *argv[]) {
	// generate random seed and public/private key
	uint8_t seed[32], pub[32], priv[64];
	if (random_bytes(seed, 32) < 0) return -1;

	crypto_eddsa_key_pair(priv, pub, seed);

	// make icmp raw socket
	int s = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (s < 0) return s;

	// send lookup request packet to bootstraps
	for (int i = 1; i < argc; i++) {
		new_peer(NULL, ntohl(inet_addr(argv[i])), 0, 0, true);
		send_lookup_request(s, pub, priv, ntohl(inet_addr(argv[i])), free_slots());
	}

	struct pollfd pfd = {
		.fd = s,
		.events = POLLIN
	};

	while (1) {
		handle_peers(s, pub, priv);
		
		int n = poll(&pfd, 1, 100);
		if (n < 0) break;
		
		if (n > 0) {
			struct icmp_echo *rp = read_icmp_echo(s);
			if (!rp) continue;

			parse_message(s, rp);
			parse_lookup_request(s, pub, priv, rp);
			parse_lookup_response(s, pub, priv, rp); 

			deinit_icmp_echo(rp);
		}
	}
}
