#include <unistd.h>
#include <fcntl.h>

#include "utils.h"

int random_bytes(char *buf, size_t len) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;

    size_t n = read(fd, buf, len);
    close(fd);

    return (n == (ssize_t)len) ? 0 : -1;
}

int random_int(int end) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;

    unsigned int num;
    read(fd, &num, sizeof(num));

    close(fd);

    return num%(end+1);
}
