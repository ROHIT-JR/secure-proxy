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
 *
 * @param raw_url The input URL string to parse.
 * @param out     Pointer to ParsedUrl struct to receive parsed fields.
 * @return PARSE_OK on success, or an appropriate ParseStatus error code.
 */
ParseStatus parse_http_url(const char *raw_url, ParsedUrl *out);

/**
 * Returns a human-readable description of a ParseStatus code.
 */
const char *parse_status_to_string(ParseStatus status);

#endif /* REQUEST_PARSER_H */