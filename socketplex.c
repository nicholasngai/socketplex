#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <poll.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include "common.h"

static uint32_t next_id;

static int handle_incoming_connection(uint32_t id, int plexfd, int serverfd,
        struct pollfd *clientfd) {
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

    clientfd->fd = cfd;
    clientfd->events = POLLIN | POLLHUP;
    ret = 0;

exit:
    return ret;
}

static int handle_closed_connection(uint32_t id, int plexfd,
        struct pollfd *clientfd) {
    int ret;

    /* Close socket. */
    close(clientfd->fd);
    clientfd->fd = -1;

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


static int handle_open_msg(struct pollfd *clientfds, size_t *clientfds_len,
        int out_port) {
    int ret;

    /* Open a new socket to the target. */
    int cfd = socket(AF_INET, SOCK_STREAM, 0);
    if (cfd == -1) {
        perror("socket");
        ret = errno;
        goto exit;
    }
    struct sockaddr_in addr;
    memset(&addr, '\0', sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port = htons(out_port);
    if (connect(cfd, (struct sockaddr *) &addr, sizeof(addr))) {
        perror("connect");
        ret = errno;
        goto exit_close_cfd;
    }

    (*clientfds_len)++;
    clientfds[*clientfds_len - 1].fd = cfd;
    clientfds[*clientfds_len - 1].events = POLLIN | POLLHUP;

    return 0;

exit_close_cfd:
    close(cfd);
exit:
    return ret;
}

static int handle_close_msg(struct pollfd *clientfds, size_t *clientfds_len,
        uint32_t id) {
    int ret;

    if (id >= *clientfds_len || clientfds[id].fd == -1) {
        fprintf(stderr, "Invalid incoming message ID: %u\n", id);
        ret = -1;
        goto exit;
    }

    /* Close the socket. */
    close(clientfds[id].fd);
    clientfds[id].fd = -1;

    ret = 0;

exit:
    return ret;
}

static int handle_data_msg(int plexfd, struct pollfd *clientfds,
        size_t *clientfds_len, struct socketplex_msg *msg, uint32_t id,
        uint32_t length) {
    int ret;

    if (id >= *clientfds_len || clientfds[id].fd == -1) {
        fprintf(stderr, "Invalid incoming message ID: %u\n", id);
        ret = -1;
        goto exit;
    }

    if (length > BUF_SIZE) {
        fprintf(stderr, "Invalid incoming message length: %u\n", length);
        ret = -1;
        goto exit;
    }

    int bytes_read = do_read(plexfd, msg->data, length);
    if (bytes_read != (int) length) {
        fprintf(stderr, "Truncated read from plex socket\n");
        ret = -1;
        goto exit;
    }

    if (do_write(clientfds[id].fd, msg->data, length) != (int) length) {
        fprintf(stderr, "Truncated write to client socket\n");
        ret = -1;
        goto exit;
    }

    ret = 0;

exit:
    return ret;
}

static int handle_incoming_plex_data(int plexfd, struct pollfd *clientfds,
        size_t *clientfds_len, struct socketplex_msg *msg, int out_port) {
    int ret;

    /* Read the header of the message. */
    int bytes_read = do_read(plexfd, msg, sizeof(*msg));
    if (bytes_read != sizeof(*msg)) {
        fprintf(stderr, "Truncated read from plex socket\n");
        ret = -1;
        goto exit;
    }

    switch (ntohl(msg->type)) {
    case SOCKETPLEX_MSG_OPEN: {
        ret = handle_open_msg(clientfds, clientfds_len, out_port);
        if (ret) {
            goto exit;
        }
        break;
    }

    case SOCKETPLEX_MSG_CLOSE: {
        ret =
            handle_close_msg(clientfds, clientfds_len,
                    ntohl(msg->msg.close.id));
        if (ret) {
            goto exit;
        }
        break;
    }

    case SOCKETPLEX_MSG_DATA: {
        uint32_t id = ntohl(msg->msg.data.id);
        uint32_t length = ntohl(msg->msg.data.length);
        ret =
            handle_data_msg(plexfd, clientfds, clientfds_len, msg, id, length);
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

static int handle_incoming_client_data(uint32_t id, int plexfd,
        struct pollfd *clientfd, struct socketplex_msg *msg) {
    int ret;

    /* Read data. */
    int bytes_read = read(clientfd->fd, msg->data, BUF_SIZE);
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

    long in_port = -1;
    long out_port = -1;
    int opt;
    while ((opt = getopt(argc, argv, "i:o:")) != -1) {
        switch (opt) {
        case 'i':
            in_port = strtol(optarg, NULL, 10);
            if (in_port <= 0 || in_port > 65535) {
                fprintf(stderr, "Invalid port: %s\n", optarg);
                return 1;
            }
            break;
        case 'o':
            out_port = strtol(optarg, NULL, 10);
            if (out_port <= 0 || out_port > 65535) {
                fprintf(stderr, "Invalid port: %s\n", optarg);
                return 1;
            }
            break;
        }
    }

    if ((in_port == -1 && out_port == -1) || argc - optind != 1) {
        printf("usage: %s [-i IN_PORT] [-o OUT_PORT] SOCKET\n", argv[0]);
        return 1;
    }

    /* Allocate poll FD buffer. */
    struct pollfd *pollfds = calloc(CLIENTFDS_SIZE + 2, sizeof(*pollfds));
    if (!pollfds) {
        perror("malloc clientfds");
        ret = errno;
        goto exit;
    }
    struct pollfd *plexfd = &pollfds[0];
    struct pollfd *serverfd = &pollfds[1];
    struct pollfd *clientfds = pollfds + 2;
    for (size_t i = 0; i < CLIENTFDS_SIZE; i++) {
        clientfds[i].fd = -1;
    }
    size_t clientfds_len = 0;

    /* Parse plex FD. */
    long plexfdl = strtol(argv[optind], NULL, 10);
    if (plexfdl == LONG_MIN) {
        fprintf(stderr, "Invalid fd: %s\n", argv[optind]);
        ret = errno;
        goto exit_free_pollfds;
    }
    plexfd->fd = plexfdl;
    plexfd->events = POLLIN | POLLHUP;

    /* Open server FD. */
    struct sockaddr_in addr;
    memset(&addr, '\0', sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(in_port);
    serverfd->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (serverfd->fd == -1) {
        perror("socket");
        ret = errno;
        goto exit_free_pollfds;
    }
    serverfd->events = POLLIN;
    int one = 1;
    if (setsockopt(serverfd->fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one))) {
        perror("setsockopt");
        ret = errno;
        goto exit_close_serverfd;
    }
    if (bind(serverfd->fd, (struct sockaddr *) &addr, sizeof(addr))) {
        perror("bind");
        ret = errno;
        goto exit_close_serverfd;
    }
    if (listen(serverfd->fd, 0)) {
        perror("listen");
        ret = errno;
        goto exit_close_serverfd;
    }

    /* Allocate data message that's also used as the buffer. */
    struct socketplex_msg *msg = malloc(sizeof(*msg) + BUF_SIZE);
    if (!msg) {
        goto exit_close_clientfds;
    }

    for (;;) {
        /* Poll. */
        if (poll(pollfds, 2 + clientfds_len, -1) < 0) {
            perror("poll");
            ret = errno;
            goto exit_close_clientfds;
        }

        /* Handle plex socket. */
        if (plexfd->revents) {
            ret =
                handle_incoming_plex_data(plexfd->fd, clientfds, &clientfds_len,
                        msg, out_port);
            if (ret) {
                goto exit_close_clientfds;
            }
        }

        /* Handle server socket. */
        if (serverfd->revents) {
            uint32_t id = next_id++;
            clientfds_len++;
            ret =
                handle_incoming_connection(id, plexfd->fd, serverfd->fd,
                        &clientfds[clientfds_len - 1]);
            if (ret) {
                goto exit_close_clientfds;
            }
        }

        /* Handle client sockets. */
        for (size_t i = 0; i < clientfds_len; i++) {
            if (clientfds[i].revents) {
                ret =
                    handle_incoming_client_data(i, plexfd->fd, &clientfds[i],
                            msg);
                if (ret) {
                    goto exit_close_clientfds;
                }
            }
        }
    }

exit_close_clientfds:
    for (size_t i = 0; i < clientfds_len; i++) {
        if (clientfds[i].fd != -1) {
            close(clientfds[i].fd);
        }
    }
exit_close_serverfd:
    close(serverfd->fd);
exit_free_pollfds:
    free(pollfds);
exit:
    return ret;
}
