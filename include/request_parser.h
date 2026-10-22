/* request_parser.h: Typed data structures and contracts for URL parsing. */
#ifndef REQUEST_PARSER_H
#define REQUEST_PARSER_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#define MAX_URL_LEN   2048
#define MAX_HOST_LEN  256
#define MAX_PATH_LEN  2048

typedef enum {
    PARSE_OK = 0,
    PARSE_ERR_OVERLONG,
    PARSE_ERR_HOST_TOO_LONG,
    PARSE_ERR_INVALID_SCHEME,
    PARSE_ERR_CREDENTIALS,
    PARSE_ERR_EMPTY_HOST,
    PARSE_ERR_INVALID_HOST,
    PARSE_ERR_INVALID_PORT,
    PARSE_ERR_CONTROL_CHAR,
    PARSE_ERR_FRAGMENT,
    PARSE_ERR_MALFORMED
} ParseStatus;

typedef struct {
    char host[MAX_HOST_LEN];
    uint16_t port;
    char path[MAX_PATH_LEN];
} ParsedUrl;

/**
 * Parses, validates, and normalises an HTTP URL (http://host[:port][/path]).
 * Lowercases the host and ensures memory bounds are strictly respected.
 */
ParseStatus parse_http_url(const char *raw_url, ParsedUrl *out);

/**
 * Returns a human-readable description of a ParseStatus code.
 */
const char *parse_status_to_string(ParseStatus status);

typedef struct {
    char host[MAX_HOST_LEN]; /* lowercased */
    uint16_t port;
} ParsedConnect;

/* Returns true if the line starts with "CONNECT " (the method is case-sensitive). */
bool request_is_connect(const char *line);

/**
 * Parses "CONNECT host:port [HTTP/1.0|HTTP/1.1]" safely. The line must already have
 * its trailing CR/LF removed. Rejects: a missing or non-numeric port, port 0 or above
 * 65535, an empty or overlong host, credentials ('@'), paths, IPv6 brackets, control
 * characters or spaces inside the target, extra tokens, and any version other than
 * HTTP/1.0 or HTTP/1.1.
 *
 * @return PARSE_OK, or PARSE_ERR_MALFORMED / PARSE_ERR_EMPTY_HOST / PARSE_ERR_INVALID_HOST /
 *         PARSE_ERR_INVALID_PORT / PARSE_ERR_CONTROL_CHAR / PARSE_ERR_OVERLONG /
 *         PARSE_ERR_CREDENTIALS.
 */
ParseStatus parse_connect_request(const char *line, ParsedConnect *out);

#endif /* REQUEST_PARSER_H */