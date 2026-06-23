#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <string.h> 
#include <poll.h>

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
    if (len < 20) return -1; // invalid header length
    
    uint16_t message_type;
    memcpy(&message_type, buf, 2);
    message_type = ntohs(message_type);
    if (message_type != 0x0101) return -1; // is not binding success reply

    uint16_t message_length;
    memcpy(&message_length, buf+2, 2);
    message_length = ntohs(message_length);
    if (message_length < 12) return -1;
    if (message_length+20 > len) return -1;

    int offset = 20;
    while (offset < message_length+20) {
        if (offset+4 > message_length+20) return -1; // invalid attribute length

        uint16_t attribute_type, attribute_length;
        memcpy(&attribute_type, buf+offset, 2);
        memcpy(&attribute_length, buf+offset+2, 2);
        attribute_type = ntohs(attribute_type);
        attribute_length = ntohs(attribute_length);

        int padding_length = (4-(attribute_length%4))%4;
        if (offset+4+attribute_length+padding_length > message_length+20) return -1;

        // X-MAPPED-ADDRESS
        if (attribute_type == 0x0020) {
            if (attribute_length == 8 && buf[offset+5] == 0x01) {
                 // x-port
                memcpy(port, buf+offset+6, 2);
                *port ^= htons(0x2112);
                *port = ntohs(*port);

                // x-address
                memcpy(addr, buf+offset+8, 4);
                *addr ^= htonl(0x2112A442);
                *addr = ntohl(*addr);

                return 0;
            }

            return -1; // invalid X-MAPPED-ADDRESS
        }

        offset = offset+4+attribute_length+padding_length;
    }

    return -1;
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

    struct pollfd pfd = {
        .fd = s,
        .events = POLLIN
    };

    // timeout: 10 sec
    int r = poll(&pfd, 1, 10000);
    if (r > 0) {
        buf = malloc(1500);
        if (!buf) goto error;

        n = recv(s, buf, 1500, 0);
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
    }

    goto error; // timeout
    error:
    close(s);
    return -1;
}
