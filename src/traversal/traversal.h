#ifndef TRAVERSAL_H
#define TRAVERSAL_H

#include <stdint.h>
#include <poll.h>
#include <stddef.h>

struct traversal_session {
    int udp_socket;
    int keepalive_pid;

    int icmp_socket;
    struct pollfd pfd;

    uint32_t stun_address;
    uint16_t stun_port;

    uint32_t public_address;
    uint16_t mapped_port;
};

void deinit_traversal_session(struct traversal_session *ts);
int new_traversal_session(struct traversal_session *ts, uint32_t stun_addr, uint16_t stun_port);
struct icmp_unreach *traversal_read(struct traversal_session *ts, int timeout);
int traversal_send(struct traversal_session *ts, uint32_t dst, uint16_t dst_port, uint8_t *data, size_t len);

#endif
