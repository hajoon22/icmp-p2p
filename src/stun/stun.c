#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <string.h> 

static ssize_t build_binding_request(uint8_t **buf) {
    *buf = malloc(20);
    if (!*buf) return -1; 
    
    uint16_t type = htons(0x0001);
    uint32_t magic = htonl(0x2112A442); 

    memcpy(*buf, &type, 2); // message type
    memset(*buf+2, 0, 2); // message length
    memcpy(*buf+4, &magic, 4); // magic cookie
    memset(*buf+8, 0, 12); // transaction id (0)

    return 20;
}

static int parse_binding_reply(uint8_t *buf, size_t len, uint32_t *addr, uint16_t *port) {
    if (len < 32) return -1; // invalid buffer length
    
    // x-port
    memcpy(port, buf+26, 2);
    *port ^= htons(0x2112);
    *port = ntohs(*port);

    // x-address
    memcpy(addr, buf+28, 4);
    *addr ^= htonl(0x2112A442);
    *addr = ntohl(*addr);

    return 0;
}

int get_stun(uint32_t stun, uint16_t stun_port, uint32_t *addr, uint16_t *port) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return s;

    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(stun_port);
    sin.sin_addr.s_addr = htonl(stun);

    if (connect(s, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        goto error;
    }

    uint8_t *buf = NULL;
    ssize_t n = build_binding_request(&buf);
    if (n < 0) goto error;

    if (send(s, buf, n, 0) < 0) {
        free(buf);
        goto error;   
    }
    free(buf);

    buf = malloc(32);
    if (!buf) goto error;

    n = recv(s, buf, 32, 0);
    if (n < 0) {
        free(buf);
        goto error;
    }

    if (parse_binding_reply(buf, n, addr, port) < 0) {
        free(buf);
        goto error;
    }
    free(buf);

    return s;

    error:
    close(s);
    return -1;
}
