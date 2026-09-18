#pragma once
/* origin_client.h: Declares functions that resolve a hostname and fetch bytes from the origin web server on behalf of a client. */

#include "request_parser.h"

typedef enum {
    FETCH_OK = 0,
    FETCH_ERR_DNS,
    FETCH_ERR_CONNECT,
    FETCH_ERR_SEND,
    FETCH_ERR_RECV
} FetchStatus;

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
 */
FetchStatus fetch_and_relay(const ParsedUrl *url, int out_fd);

/* Returns a human-readable description of a FetchStatus code. */
const char *fetch_status_to_string(FetchStatus status);
