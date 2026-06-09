#ifndef CONFIG_H
#define CONFIG_H

#define PEER_TIMEOUT 600 // second
#define PEER_REQUEST_INTERVAL 60 // second

#define MAX_PEERS 50
#define MAX_MESSAGE_HISTORY 10

#define DEFAULT_TRUST 50

#define MAX_TRUST 100
#define BAN_TRUST 0

#define MIN_TRUST 20

#define GOOD_PEER_TRUST 1
#define GOOD_SOURCE_TRUST 2
#define BAD_SOURCE_TRUST -5

// admin's public key
static const uint8_t admin_pub[32] = {
    0xd2,  0x46,  0xda,  0x63,
    0x92,  0x15,  0x3f,  0x01,
    0xd6,  0x1f,  0xd1,  0xe0,
    0xba,  0x0f,  0xf3,  0x4d,
    0x32,  0xda,  0xb8,  0x5c,
    0xe5,  0x83,  0xc0,  0x51,
    0x4e,  0xd3,  0xf4,  0x03,
    0xfa,  0xc0,  0xc9,  0x45
};

#endif
