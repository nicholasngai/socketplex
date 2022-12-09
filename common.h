#ifndef SOCKETPLEX_COMMON_H
#define SOCKETPLEX_COMMON_H

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

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

static int do_read(int fd, void *buf, size_t len) {
    int ret = 0;

    while (len) {
        int bytes_read = read(fd, buf, len);
        if (bytes_read == -1) {
            perror("write");
            ret = errno;
            goto exit;
        }
        if (bytes_read == 0) {
            goto exit;
        }
        ret += bytes_read;
        buf = (unsigned char *) buf + bytes_read;
        len -= bytes_read;
    }

exit:
     return ret;
}

static int do_write(int fd, const void *buf, size_t len) {
    int ret = 0;

    while (len) {
        int bytes_written = write(fd, buf, len);
        if (bytes_written == -1) {
            perror("write");
            ret = errno;
            goto exit;
        }
        if (bytes_written == 0) {
            goto exit;
        }
        ret += bytes_written;
        buf = (unsigned char *) buf + bytes_written;
        len -= bytes_written;
    }

exit:
     return ret;
}

#endif
