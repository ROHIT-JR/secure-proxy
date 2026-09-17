#include "request_parser.h"
#include <string.h>
#include <ctype.h>
#include <stdlib.h>

const char *parse_status_to_string(ParseStatus status) {
    switch (status) {
        case PARSE_OK: return "OK";
        case PARSE_ERR_OVERLONG: return "URL exceeds maximum length (2048 bytes)";
        case PARSE_ERR_INVALID_SCHEME: return "Unsupported or missing URL scheme (only http:// supported)";
        case PARSE_ERR_CREDENTIALS: return "Embedded credentials are not allowed";
        case PARSE_ERR_EMPTY_HOST: return "Host component is empty";
        case PARSE_ERR_INVALID_HOST: return "Host contains invalid characters";
        case PARSE_ERR_INVALID_PORT: return "Port is malformed, zero, or out of range (1-65535)";
        case PARSE_ERR_CONTROL_CHAR: return "URL contains forbidden control characters or whitespace";
        case PARSE_ERR_FRAGMENT: return "URL fragments (#) are not permitted";
        case PARSE_ERR_MALFORMED: return "Malformed URL";
        default: return "Unknown parse error";
    }
}

ParseStatus parse_http_url(const char *raw_url, ParsedUrl *out) {
    if (!raw_url || !out) {
        return PARSE_ERR_MALFORMED;
    }

    size_t len = strlen(raw_url);
    if (len == 0) {
        return PARSE_ERR_MALFORMED;
    }
    if (len > MAX_URL_LEN) {
        return PARSE_ERR_OVERLONG;
    }

    /* Reject control characters (ASCII 0..31, 127) and unencoded spaces (ASCII 32) */
    for (size_t i = 0; i < len; i++) {
        unsigned char uc = (unsigned char)raw_url[i];
        if (uc <= 32 || uc == 127) {
            return PARSE_ERR_CONTROL_CHAR;
        }
    }

    /* Reject URL fragments (#) */
    if (strchr(raw_url, '#') != NULL) {
        return PARSE_ERR_FRAGMENT;
    }

    /* Validate scheme: strictly http:// (case-insensitive) */
    const char scheme[] = "http://";
    size_t scheme_len = strlen(scheme);
    if (len < scheme_len) {
        return PARSE_ERR_INVALID_SCHEME;
    }
    for (size_t i = 0; i < scheme_len; i++) {
        if (tolower((unsigned char)raw_url[i]) != scheme[i]) {
            return PARSE_ERR_INVALID_SCHEME;
        }
    }

    const char *p = raw_url + scheme_len;

    /* Locate boundary of authority: first '/' or '?' or string end */
    const char *auth_end = p;
    while (*auth_end && *auth_end != '/' && *auth_end != '?') {
        auth_end++;
    }

    size_t auth_len = auth_end - p;
    if (auth_len == 0) {
        return PARSE_ERR_EMPTY_HOST;
    }

    /* Reject embedded credentials (@ anywhere in authority) */
    for (const char *c = p; c < auth_end; c++) {
        if (*c == '@') {
            return PARSE_ERR_CREDENTIALS;
        }
    }

    /* Locate optional port delimiter ':' */
    const char *colon = NULL;
    if (*p == '[') {
        /* Handle bracketed IPv6 literal [::1]:port */
        const char *bracket_close = memchr(p, ']', auth_len);
        if (!bracket_close) {
            return PARSE_ERR_INVALID_HOST;
        }
        if (bracket_close + 1 < auth_end && *(bracket_close + 1) == ':') {
            colon = bracket_close + 1;
        }
    } else {
        for (const char *c = p; c < auth_end; c++) {
            if (*c == ':') {
                if (colon != NULL) {
                    return PARSE_ERR_MALFORMED;
                }
                colon = c;
            }
        }
    }

    const char *host_start = p;
    size_t host_len = colon ? (size_t)(colon - host_start) : auth_len;

    if (host_len == 0) {
        return PARSE_ERR_EMPTY_HOST;
    }
    if (host_len >= sizeof(out->host)) {
        return PARSE_ERR_OVERLONG;
    }

    /* Validate host characters and normalise to lowercase */
    for (size_t i = 0; i < host_len; i++) {
        char ch = host_start[i];
        if (!isalnum((unsigned char)ch) && ch != '.' && ch != '-' && ch != '_' && ch != '[' && ch != ']') {
            return PARSE_ERR_INVALID_HOST;
        }
        out->host[i] = (char)tolower((unsigned char)ch);
    }
    out->host[host_len] = '\0';

    /* Parse port */
    if (colon) {
        const char *port_str = colon + 1;
        size_t port_len = auth_end - port_str;
        if (port_len == 0) {
            return PARSE_ERR_INVALID_PORT;
        }

        unsigned long port_val = 0;
        for (size_t i = 0; i < port_len; i++) {
            if (!isdigit((unsigned char)port_str[i])) {
                return PARSE_ERR_INVALID_PORT;
            }
            port_val = port_val * 10 + (port_str[i] - '0');
            if (port_val > 65535) {
                return PARSE_ERR_INVALID_PORT;
            }
        }
        if (port_val == 0 || port_val > 65535) {
            return PARSE_ERR_INVALID_PORT;
        }
        out->port = (uint16_t)port_val;
    } else {
        out->port = 80;
    }

    /* Extract path, defaulting to "/" if absent */
    if (*auth_end == '\0') {
        out->path[0] = '/';
        out->path[1] = '\0';
    } else if (*auth_end == '?') {
        size_t query_len = strlen(auth_end);
        if (query_len + 2 > sizeof(out->path)) {
            return PARSE_ERR_OVERLONG;
        }
        out->path[0] = '/';
        memcpy(out->path + 1, auth_end, query_len + 1);
    } else {
        size_t path_len = strlen(auth_end);
        if (path_len >= sizeof(out->path)) {
            return PARSE_ERR_OVERLONG;
        }
        memcpy(out->path, auth_end, path_len + 1);
    }

    return PARSE_OK;
}