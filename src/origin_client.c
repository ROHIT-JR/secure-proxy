/* origin_client.c: Implements DNS resolution, the outbound TCP connection to the origin, and streaming of the HTTP response back to the client. */

/* Strict -std=c11 hides POSIX-only declarations (getaddrinfo, AI_NUMERICSERV,
 * struct addrinfo, ...) in glibc's headers unless a feature-test macro asks
 * for them explicitly. Must be defined before any system header is included. */
#define _POSIX_C_SOURCE 200809L

#include "origin_client.h"
#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define ORIGIN_CONNECT_TIMEOUT_SECONDS 5
#define ORIGIN_READ_TIMEOUT_SECONDS 10
#define RELAY_CHUNK_SIZE 8192

const char *fetch_status_to_string(FetchStatus status) {
    switch (status) {
        case FETCH_OK: return "OK";
        case FETCH_ERR_DNS: return "DNS resolution failed";
        case FETCH_ERR_CONNECT: return "Could not connect to origin (refused or timed out)";
        case FETCH_ERR_SEND: return "Failed to send request or relay response to output";
        case FETCH_ERR_RECV: return "Failed to read response from origin";
        default: return "Unknown fetch error";
    }
}

/* Connects fd to addr, but gives up after timeout_sec instead of blocking
 * forever -- a plain connect() has no built-in timeout, so this switches
 * the socket to non-blocking mode, starts the connection attempt, and
 * uses poll() to wait for it to finish (or time out). */
static int connect_with_timeout(int fd, const struct sockaddr *addr, socklen_t addrlen,
                                 int timeout_sec) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        return -1;
    }

    int rc = connect(fd, addr, addrlen);
    if (rc == 0) {
        fcntl(fd, F_SETFL, flags); /* restore blocking mode for the rest of this connection's life */
        return 0;
    }
    if (errno != EINPROGRESS) {
        return -1;
    }

    struct pollfd pfd;
    pfd.fd = fd;
    pfd.events = POLLOUT;

    int poll_rc = poll(&pfd, 1, timeout_sec * 1000);
    if (poll_rc <= 0) {
        return -1; /* 0 = timed out, <0 = poll() error */
    }

    int so_error = 0;
    socklen_t so_error_len = sizeof(so_error);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_error, &so_error_len) < 0 || so_error != 0) {
        return -1;
    }

    fcntl(fd, F_SETFL, flags);
    return 0;
}

FetchStatus fetch_and_relay(const ParsedUrl *url, int out_fd) {
    char port_str[6];
    snprintf(port_str, sizeof(port_str), "%u", (unsigned)url->port);

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC; /* accept either IPv4 or IPv6, whichever DNS returns */
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_NUMERICSERV; /* port_str is always numeric, skip service-name lookup */

    struct addrinfo *res = NULL;
    if (getaddrinfo(url->host, port_str, &hints, &res) != 0 || res == NULL) {
        return FETCH_ERR_DNS;
    }

    int origin_fd = -1;
    for (struct addrinfo *rp = res; rp != NULL; rp = rp->ai_next) {
        origin_fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (origin_fd < 0) {
            continue;
        }
        if (connect_with_timeout(origin_fd, rp->ai_addr, rp->ai_addrlen,
                                  ORIGIN_CONNECT_TIMEOUT_SECONDS) == 0) {
            break; /* connected successfully */
        }
        close(origin_fd);
        origin_fd = -1;
    }

    freeaddrinfo(res); /* no longer needed once we've picked (or failed to pick) an address */

    if (origin_fd < 0) {
        return FETCH_ERR_CONNECT;
    }

    struct timeval read_timeout;
    read_timeout.tv_sec = ORIGIN_READ_TIMEOUT_SECONDS;
    read_timeout.tv_usec = 0;
    setsockopt(origin_fd, SOL_SOCKET, SO_RCVTIMEO, &read_timeout, sizeof(read_timeout));

    char request[MAX_HOST_LEN + MAX_PATH_LEN + 64];
    int req_len = snprintf(request, sizeof(request),
                            "GET %s HTTP/1.0\r\n"
                            "Host: %s\r\n"
                            "Connection: close\r\n"
                            "\r\n",
                            url->path, url->host);

    if (req_len < 0 || send_all(origin_fd, request, (size_t)req_len) < 0) {
        close(origin_fd);
        return FETCH_ERR_SEND;
    }

    /* Stream the response in fixed-size chunks rather than buffering the
     * whole thing -- an origin response can be arbitrarily large, and we
     * must not let it exhaust memory or overflow a stack buffer. */
    char chunk[RELAY_CHUNK_SIZE];
    ssize_t n;
    FetchStatus result = FETCH_OK;

    while ((n = recv(origin_fd, chunk, sizeof(chunk), 0)) > 0) {
        if (send_all(out_fd, chunk, (size_t)n) < 0) {
            result = FETCH_ERR_SEND;
            break;
        }
    }

    if (n < 0 && result == FETCH_OK) {
        result = FETCH_ERR_RECV;
    }

    close(origin_fd);
    return result;
}
