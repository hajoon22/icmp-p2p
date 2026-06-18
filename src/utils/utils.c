#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <arpa/inet.h>

#include "utils.h"

int random_bytes(uint8_t *buf, ssize_t len) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;

    ssize_t n = read(fd, buf, len);
    close(fd);

    return (n == len) ? 0 : -1;
}

int random_int(int end) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;

    unsigned int num;
    ssize_t n = read(fd, &num, sizeof(num));
    close(fd);
    if (n < 0) return -1;


    return num%(end+1);
}

int parse_ipv4_port(char *arg, uint32_t *ip, uint16_t *port) {
    char *c = strchr(arg, ':');
    if (!c) return -1;

    // parse ipv4
    size_t ip_len = c-arg;
    if (ip_len >= 16 || ip_len == 0) return -1; // invalid ip address length

    char ip_str[16];
    memcpy(&ip_str, arg, ip_len);
    ip_str[ip_len] = '\0';

    *ip = ntohl(inet_addr(ip_str));
    if (*ip == 0xFFFFFFFF) return -1; // invalid ip address

    // parse port
    char *end;
    unsigned long port_long = strtoul(c+1, &end, 10);
    if (*end != '\0' || port_long > 65535 || port_long < 1) {
        return -1; // invalid port
    }
    *port = (uint16_t)port_long;

    return 0;
}
