#ifndef UTILS_H
#define UTILS_H

#include <unistd.h>
#include <stdint.h>

int random_int(int end);
int random_bytes(uint8_t *buf, ssize_t len);
int parse_ipv4_port(char *arg, uint32_t *ip, uint16_t *port);

#endif
