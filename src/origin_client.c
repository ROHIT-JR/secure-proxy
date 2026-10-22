/* origin_client.c: Implements DNS resolution, the outbound TCP connection to the origin, and streaming of the HTTP response back to the client. */

/* Strict -std=c11 hides POSIX-only declarations (getaddrinfo, AI_NUMERICSERV,
 * struct addrinfo, ...) in glibc's headers unless a feature-test macro asks
 * for them explicitly. Must be defined before any system header is included. */
#define _POSIX_C_SOURCE 200809L

#include "origin_client.h"
#include "policy.h"
#include "util.h"

#include <ctype.h>
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
        case FETCH_ERR_UNSAFE_ADDRESS: return "Destination address is not permitted";
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

static int g_allow_private = 0; /* set once at startup, before any thread exists */

void origin_client_set_allow_private(int allow) {
    g_allow_private = allow;
}

/* Returns 1 if every address in the list is safe to contact (or the testing override is on). */
static int all_addresses_safe(const struct addrinfo *list) {
    if (g_allow_private) {
        return 1;
    }
    for (const struct addrinfo *rp = list; rp != NULL; rp = rp->ai_next) {
        if (address_is_unsafe(rp->ai_addr)) {
            return 0;
        }
    }
    return 1;
}

FetchStatus origin_connect(const char *host, unsigned port, int *out_fd) {
    *out_fd = -1;

    if (!g_allow_private && hostname_is_local_name(host)) {
        return FETCH_ERR_UNSAFE_ADDRESS; /* refused before any DNS lookup */
    }

    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", port);

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC; /* accept either IPv4 or IPv6, whichever DNS returns */
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_NUMERICSERV; /* port_str is always numeric, skip service-name lookup */

    struct addrinfo *res = NULL;

    /* Step 1: is the host a numeric address in ANY accepted spelling (dotted, decimal
     * "2130706433", hex "0x7f.1", ...)? AI_NUMERICHOST guarantees no DNS query is made. */
    hints.ai_flags |= AI_NUMERICHOST;
    int rc = getaddrinfo(host, port_str, &hints, &res);
    if (rc != 0) {
        /* Step 2: not numeric -- a real DNS lookup, done exactly once. */
        hints.ai_flags &= ~AI_NUMERICHOST;
        res = NULL;
        rc = getaddrinfo(host, port_str, &hints, &res);
    }
    if (rc != 0 || res == NULL) {
        return FETCH_ERR_DNS;
    }

    /* Refuse the whole destination if ANY returned address is unsafe. */
    if (!all_addresses_safe(res)) {
        freeaddrinfo(res);
        return FETCH_ERR_UNSAFE_ADDRESS;
    }

    int fd = -1;
    FetchStatus result = FETCH_ERR_CONNECT;
    for (struct addrinfo *rp = res; rp != NULL; rp = rp->ai_next) {
        /* Re-check at connection time, immediately before connect(). */
        if (!g_allow_private && address_is_unsafe(rp->ai_addr)) {
            result = FETCH_ERR_UNSAFE_ADDRESS;
            break;
        }
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) {
            continue;
        }
        if (connect_with_timeout(fd, rp->ai_addr, rp->ai_addrlen, ORIGIN_CONNECT_TIMEOUT_SECONDS) == 0) {
            /* Verify the peer we actually reached, not just the one we meant to reach. */
            struct sockaddr_storage peer;
            socklen_t peer_len = sizeof(peer);
            if (!g_allow_private &&
                (getpeername(fd, (struct sockaddr *)&peer, &peer_len) != 0 ||
                 address_is_unsafe((struct sockaddr *)&peer))) {
                close(fd);
                fd = -1;
                result = FETCH_ERR_UNSAFE_ADDRESS;
                break;
            }
            result = FETCH_OK;
            break;
        }
        close(fd);
        fd = -1;
    }

    freeaddrinfo(res); /* no longer needed once we've picked (or failed to pick) an address */

    if (result == FETCH_OK) {
        *out_fd = fd;
    }
    return result;
}

/* Extracts the 3-digit status code from an "HTTP/x.y NNN ..." status line, or 0 if absent. */
static int parse_origin_status(const char *buf, size_t len) {
    if (len < 12 || memcmp(buf, "HTTP/", 5) != 0 || buf[8] != ' ') {
        return 0;
    }
    if (!isdigit((unsigned char)buf[9]) || !isdigit((unsigned char)buf[10]) ||
        !isdigit((unsigned char)buf[11])) {
        return 0;
    }
    return (buf[9] - '0') * 100 + (buf[10] - '0') * 10 + (buf[11] - '0');
}

FetchStatus fetch_and_relay(const ParsedUrl *url, int out_fd, FetchStats *stats) {
    if (stats != NULL) {
        stats->bytes_relayed = 0;
        stats->origin_status = 0;
    }

    int origin_fd = -1;
    FetchStatus conn = origin_connect(url->host, url->port, &origin_fd);
    if (conn != FETCH_OK) {
        return conn;
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

    int first_chunk = 1;
    while ((n = recv(origin_fd, chunk, sizeof(chunk), 0)) > 0) {
        if (first_chunk) {
            first_chunk = 0;
            if (stats != NULL) {
                stats->origin_status = parse_origin_status(chunk, (size_t)n);
            }
        }
        if (send_all(out_fd, chunk, (size_t)n) < 0) {
            result = FETCH_ERR_SEND;
            break;
        }
        if (stats != NULL) {
            stats->bytes_relayed += (unsigned long long)n;
        }
    }

    if (n < 0 && result == FETCH_OK) {
        result = FETCH_ERR_RECV;
    }

    close(origin_fd);
    return result;
}
