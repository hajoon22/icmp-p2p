#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <poll.h>

#include "traversal.h"
#include "stun/stun.h"
#include "icmp/icmp.h"

static int udp_keepalive(int s) {
    int pid = fork();
    if (pid == 0) {
        while (1) {
            send(s, "hello", 5, 0); // keepalive
            sleep(10);
        }
    }

    return pid;
}

void deinit_traversal_session(struct traversal_session *ts) {
    kill(ts->keepalive_pid, SIGTERM);
    waitpid(ts->keepalive_pid, NULL, 0);
    
    close(ts->udp_socket);
    close(ts->icmp_socket);
}

int new_traversal_session(struct traversal_session *ts, uint32_t stun_addr, uint16_t stun_port) {
    ts->stun_address = stun_addr;
    ts->stun_port = stun_port;

    ts->udp_socket = get_stun(ts->stun_address, ts->stun_port, &ts->public_address, &ts->mapped_port);
    if (ts->udp_socket < 0) return ts->udp_socket;

    // start udp keepalive
    ts->keepalive_pid = udp_keepalive(ts->udp_socket);
    if (ts->keepalive_pid < 0) {
        close(ts->udp_socket);
        return ts->keepalive_pid;
    }

    ts->icmp_socket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (ts->icmp_socket < 0) {
        kill(ts->keepalive_pid, SIGTERM);
        waitpid(ts->keepalive_pid, NULL, 0);

        close(ts->udp_socket);
        return ts->icmp_socket;
    }

    ts->pfd = (struct pollfd){
        .fd = ts->icmp_socket,
        .events = POLLIN
    };

    return 0;
}

struct icmp_unreach *traversal_read(struct traversal_session *ts, int timeout) {
    int n = poll(&ts->pfd, 1, timeout);
    if (n > 0) {
        struct icmp_unreach *rp = read_icmp_unreach(ts->icmp_socket);
        return rp;
    }

    return NULL;
}

int traversal_send(struct traversal_session *ts, uint32_t dst, uint16_t dst_port, uint8_t *data, size_t len) {
    return send_icmp_unreach(ts->icmp_socket, dst, dst_port, ts->stun_address, ts->stun_port, data, len);
}
