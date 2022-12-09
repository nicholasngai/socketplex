#ifndef SOCKETPLEX_COMMON_H
#define SOCKETPLEX_COMMON_H

#include <stdint.h>

#ifdef __GNUC__
#define PACKED __attribute__((packed))
#else
#define PACKED
#endif

#define CLIENTFDS_SIZE 1024
#define BUF_SIZE 65536

#define SOCKETPLEX_MSG_OPEN 1u
#define SOCKETPLEX_MSG_CLOSE 2u
#define SOCKETPLEX_MSG_DATA 3u

struct socketplex_msg {
    uint32_t type;
    union {
        struct {
            uint32_t id;
            uint32_t port;
        } PACKED open;
        struct {
            uint32_t id;
        } PACKED close;
        struct {
            uint32_t id;
            uint32_t length;
        } PACKED data;
    } PACKED msg;
    unsigned char data[];
} PACKED;

#endif
