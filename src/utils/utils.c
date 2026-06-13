#include <unistd.h>
#include <fcntl.h>

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
