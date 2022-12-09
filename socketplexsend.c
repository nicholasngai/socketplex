#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include "common.h"

static uint32_t next_id;

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

static int handle_incoming_connection(uint32_t id, int plexfd, int serverfd,
        int *clientfd) {
    int ret;

    /* Accept socket. */
    // TODO Handle blocking state.
    int cfd = accept(serverfd, NULL, 0);
    if (cfd == -1) {
        ret = errno;
        goto exit;
    }

    /* Send open message. */
    struct socketplex_msg open_msg = {
        .type = htonl(SOCKETPLEX_MSG_OPEN),
        .msg = {
            .open = {
                .id = htonl(id),
            },
        },
    };
    if (do_write(plexfd, &open_msg, sizeof(open_msg)) != sizeof(open_msg)) {
        fprintf(stderr, "Truncated write to plex socket\n");
        ret = -1;
        goto exit;
    }

    *clientfd = cfd;
    ret = 0;

exit:
    return ret;
}

static int handle_closed_connection(uint32_t id, int plexfd, int *clientfd) {
    int ret;

    /* Close socket. */
    close(*clientfd);
    *clientfd = -1;

    /* Send close message. */
    struct socketplex_msg close_msg = {
        .type = htonl(SOCKETPLEX_MSG_CLOSE),
        .msg = {
            .close = {
                .id = htonl(id),
            },
        },
    };
    if (do_write(plexfd, &close_msg, sizeof(close_msg)) != sizeof(close_msg)) {
        fprintf(stderr, "Truncated write to plex socket\n");
        ret = -1;
        goto exit;
    }

    ret = 0;

exit:
    return ret;
}

static int handle_incoming_plex_data(int plexfd, int *clientfds,
        size_t clientfds_len, struct socketplex_msg *msg) {
    int ret;

    /* Read the header of the message. */
    int bytes_read = do_read(plexfd, msg, sizeof(*msg));
    if (bytes_read != sizeof(*msg)) {
        fprintf(stderr, "Truncated read from plex socket\n");
        ret = -1;
        goto exit;
    }

    switch (ntohl(msg->type)) {
    case SOCKETPLEX_MSG_DATA: {
        uint32_t id = ntohl(msg->msg.data.id);
        uint32_t length = ntohl(msg->msg.data.length);

        if (id >= clientfds_len || clientfds[id] == -1) {
            fprintf(stderr, "Invalid incoming message ID: %u\n", id);
            ret = -1;
            goto exit;
        }

        if (length > BUF_SIZE) {
            fprintf(stderr, "Invalid incoming message length: %u\n", length);
            ret = -1;
            goto exit;
        }

        bytes_read = do_read(plexfd, msg->data, length);
        if (bytes_read != (int) length) {
            fprintf(stderr, "Truncated read from plex socket\n");
            ret = -1;
            goto exit;
        }

        if (do_write(clientfds[id], msg->data, length) != (int) length) {
            fprintf(stderr, "Truncated write to client socket\n");
            ret = -1;
            goto exit;
        }

        break;
    }

    default:
        fprintf(stderr, "Invalid message type coming into server\n");
        ret = -1;
        goto exit;
    }

    ret = 0;

exit:
    return ret;
}

static int handle_incoming_client_data(uint32_t id, int plexfd, int *clientfd,
        struct socketplex_msg *msg) {
    int ret;

    /* Read data. */
    int bytes_read = read(*clientfd, msg->data, BUF_SIZE);
    if (bytes_read < 0) {
        perror("read");
        ret = errno;
        goto exit;
    }
    if (bytes_read == 0) {
        ret = handle_closed_connection(id, plexfd, clientfd);
        goto exit;
    }

    /* Send data. */
    msg->type = htonl(SOCKETPLEX_MSG_DATA);
    msg->msg.data.id = htonl(id);
    msg->msg.data.length = htonl(bytes_read);
    if (do_write(plexfd, msg, sizeof(*msg) + bytes_read)
            != (int) (sizeof(*msg) + bytes_read)) {
        ret = -1;
        goto exit;
    }

    ret = 0;

exit:
    return ret;
}

int main(int argc, char **argv) {
    int ret = 0;

    long port = 5000;
    int opt;
    while ((opt = getopt(argc, argv, "p:")) != -1) {
        switch (opt) {
        case 'p':
            port = strtol(optarg, NULL, 10);
            if (port <= 0 || port > 65535) {
                fprintf(stderr, "Invalid port: %s\n", optarg);
                return 1;
            }
            break;
        }
    }

    if (argc - optind != 1) {
        printf("usage: %s [-p PORT] SOCKET\n", argv[0]);
        return 1;
    }

    /* Parse plex FD. */
    int plexfd;
    {
        long plexfdl = strtol(argv[optind], NULL, 10);
        if (plexfdl == LONG_MIN) {
            fprintf(stderr, "Invalid fd: %s\n", argv[optind]);
            ret = errno;
            goto exit;
        }
        plexfd = plexfdl;
    }

    /* Open server FD. */
    struct sockaddr_in addr;
    memset(&addr, '\0', sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    int serverfd = socket(AF_INET, SOCK_STREAM, 0);
    if (serverfd == -1) {
        perror("socket");
        ret = errno;
        goto exit;
    }
    int one = 1;
    if (setsockopt(serverfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one))) {
        perror("setsockopt");
        ret = errno;
        goto exit_close_serverfd;
    }
    if (bind(serverfd, (struct sockaddr *) &addr, sizeof(addr))) {
        perror("bind");
        ret = errno;
        goto exit_close_serverfd;
    }
    if (listen(serverfd, 0)) {
        perror("listen");
        ret = errno;
        goto exit_close_serverfd;
    }

    /* Allocate client FD buffer. */
    int *clientfds = calloc(CLIENTFDS_SIZE, sizeof(*clientfds));
    if (!clientfds) {
        perror("malloc clientfds");
        ret = errno;
        goto exit_close_serverfd;
    }
    for (size_t i = 0; i < CLIENTFDS_SIZE; i++) {
        clientfds[i] = -1;
    }
    size_t clientfds_len = 0;

    /* Allocate data message that's also used as the buffer. */
    struct socketplex_msg *msg = malloc(sizeof(*msg) + BUF_SIZE);
    if (!msg) {
        goto exit_close_clientfds;
    }

    for (;;) {
        fd_set read_fds;

        FD_ZERO(&read_fds);

        /* Add all sockets to select. */
        FD_SET(plexfd, &read_fds);
        FD_SET(serverfd, &read_fds);
        for (size_t i = 0; i < clientfds_len; i++) {
            if (clientfds[i] != -1) {
                FD_SET(clientfds[i], &read_fds);
            }
        }

        /* Select. */
        if (select(FD_SETSIZE, &read_fds, NULL, NULL, NULL) < 0) {
            goto exit_close_clientfds;
        }

        /* Handle plex socket. */
        if (FD_ISSET(plexfd, &read_fds)) {
            ret =
                handle_incoming_plex_data(plexfd, clientfds, clientfds_len,
                        msg);
            if (ret) {
                goto exit_close_clientfds;
            }
        }

        /* Handle server socket. */
        if (FD_ISSET(serverfd, &read_fds)) {
            uint32_t id = next_id++;
            clientfds_len++;
            ret =
                handle_incoming_connection(id, plexfd, serverfd,
                        &clientfds[clientfds_len - 1]);
            if (ret) {
                goto exit_close_clientfds;
            }
        }

        /* Handle client sockets. */
        for (size_t i = 0; i < clientfds_len; i++) {
            if (FD_ISSET(clientfds[i], &read_fds)) {
                ret =
                    handle_incoming_client_data(i, plexfd, &clientfds[i],
                            msg);
                if (ret) {
                    goto exit_close_clientfds;
                }
            }
        }
    }

exit_close_clientfds:
    for (size_t i = 0; i < clientfds_len; i++) {
        if (clientfds[i] != -1) {
            close(clientfds[i]);
        }
    }
    free(clientfds);
exit_close_serverfd:
    close(serverfd);
exit:
    return ret;
}
