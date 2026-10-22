#pragma once
/* origin_client.h: Declares functions that resolve a hostname and fetch bytes from the origin web server on behalf of a client. */

#include "request_parser.h"

typedef enum {
    FETCH_OK = 0,
    FETCH_ERR_DNS,
    FETCH_ERR_CONNECT,
    FETCH_ERR_SEND,
    FETCH_ERR_RECV,
    FETCH_ERR_UNSAFE_ADDRESS /* destination is (or resolves to) a loopback/private/link-local/... address */
} FetchStatus;

/* Optional facts about a fetch, filled in by fetch_and_relay() for logging. */
typedef struct {
    unsigned long long bytes_relayed; /* origin bytes successfully written to out_fd */
    int origin_status;                /* HTTP status code from the origin's status line, 0 if unknown */
} FetchStats;

/*
 * Resolves url->host, opens an outbound TCP connection to the origin (with
 * a connect timeout), sends an HTTP/1.0 GET request for url->path, and
 * streams the raw response bytes to out_fd as they arrive -- never
 * buffering the whole response in memory.
 *
 * out_fd may be a client socket or a plain file; send_all() only relies on
 * write(), which both support.
 *
 * If this returns anything other than FETCH_OK, the caller may only write
 * its own error response to out_fd when the failure happened before any
 * origin bytes were relayed (FETCH_ERR_DNS or FETCH_ERR_CONNECT). Once
 * relaying has started, out_fd has already received a partial raw
 * response and must not receive a second, different one on top of it.
 *
 * `stats` may be NULL. When provided it is always initialised, so callers
 * can read it on every return path.
 */
FetchStatus fetch_and_relay(const ParsedUrl *url, int out_fd, FetchStats *stats);

/* Returns a human-readable description of a FetchStatus code. */
const char *fetch_status_to_string(FetchStatus status);

/*
 * Resolves `host` and opens a TCP connection to it, enforcing network safety:
 *   - "localhost" and ".localhost"/".local" names are refused with no lookup;
 *   - numeric forms (127.0.0.1, 2130706433, 0x7f.1, ...) are parsed WITHOUT any
 *     DNS query, then checked;
 *   - after DNS, EVERY returned address must be safe, otherwise the whole
 *     destination is refused (a mix of public and private answers is a classic
 *     DNS-rebinding trick);
 *   - each address is checked again immediately before connect(), and the
 *     address actually connected to is checked once more.
 * The name is resolved exactly once and the checked address is the one used,
 * so there is no second lookup an attacker could answer differently.
 *
 * On FETCH_OK, *out_fd is a connected, blocking socket owned by the caller.
 * Possible failures: FETCH_ERR_DNS, FETCH_ERR_UNSAFE_ADDRESS, FETCH_ERR_CONNECT.
 */
FetchStatus origin_connect(const char *host, unsigned port, int *out_fd);

/*
 * TESTING ONLY. When set to 1, loopback/private destinations are allowed so the
 * automated tests can use a local origin server. Must be called (if at all)
 * before any worker thread starts. The proxy only enables it when the operator
 * sets PROXY_UNSAFE_ALLOW_PRIVATE_NETWORKS=1, and then prints a loud warning.
 */
void origin_client_set_allow_private(int allow);
