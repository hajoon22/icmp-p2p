#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip_icmp.h>
#include <poll.h>

#include "src/icmp/icmp.h"
#include "src/peer/peer.h"
#include "src/utils/utils.h"
#include "src/protocol/protocol.h"
#include "src/monocypher/monocypher.h"
#include "src/protocol/message/message.h"

int main(int argc, char *argv[]) {
	// generate random seed and public/private key
	char seed[32], pub[32], priv[64];
	int n = random_bytes(seed, 32);
	if (n < 0) return n;

	crypto_eddsa_key_pair(priv, pub, seed);

	// make icmp raw socket
	int s = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (s < 0) return s;

	// send lookup request packet to bootstraps
	for (int i = 1; i < argc; i++) {
		send_lookup_request(s, pub, priv, ntohl(inet_addr(argv[i])), free_slots());
	}

	struct pollfd pfd = {
		.fd = s,
		.events = POLLIN
	};

	while (1) {
		int n = poll(&pfd, 1, 100);
		if (n < 0) break;
		
		if (n > 0) {
			struct icmp_echo *rp = read_icmp_echo(s);
			if (!rp) continue;

			if (rp->icmph.type == 0) {
				if (rp->data_len >= 98 && rp->data[0] == LOOKUP) {
					parse_lookup_response(s, pub, priv, rp);
				}
			} 

			if (rp->icmph.type == 8) {
				if (rp->data_len == 99 && rp->data[0] == LOOKUP) {
					parse_lookup_request(s, pub, priv, rp);
				}

				if (rp->data_len >= 76 && rp->data[0] == MESSAGE) {
					parse_message(s, rp);
				}
			}

			deinit_icmp_echo(rp);
		}

		handle_peers(s, pub, priv);
	}
}
