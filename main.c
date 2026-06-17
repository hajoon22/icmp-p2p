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
#include "src/stun/stun.h"
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

	// get public address and make mapping port
	uint32_t pub_addr;
	uint16_t mapped_port;
	int udp_s = get_stun(ntohl(inet_addr(STUN_ADDR)), STUN_PORT, &pub_addr, &mapped_port); 
	if (udp_s < 0) {
		return -1;
	}

	struct in_addr a;
    a.s_addr = htonl(pub_addr);
	printf("udp mapped: public addr=%s, port=%d\n", inet_ntoa(a), mapped_port);

	// make icmp raw socket
	int icmp_s = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (icmp_s < 0) return icmp_s;

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

		new_peer(NULL, addr, port, 0, 0, true);
		send_lookup_request(icmp_s, pub, priv, addr, port, mapped_port, free_slots());
	}

	struct pollfd pfd = {
		.fd = icmp_s,
		.events = POLLIN
	};

	int c = 0;
	while (1) {
		c++;
		if (c == 10) { // 10 sec
			c = 0;
			send(udp_s, "aaaaa", 5, 0); // keepalive udp mapping
		}

		handle_peers(icmp_s, mapped_port, pub, priv);

		int n = poll(&pfd, 1, 100);
		if (n < 0) break;
		
		if (n > 0) {
			struct icmp_unreach *rp = read_icmp_unreach(icmp_s);
			if (!rp) continue;

			parse_message(icmp_s, rp);
			parse_lookup_request(icmp_s, pub, priv, rp);
			parse_lookup_response(icmp_s, pub, priv, rp); 

			deinit_icmp_unreach(rp);
		}
	}
}
