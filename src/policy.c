/* policy.c: Implements loading of config/allowlist.txt and config/blocklist.txt and the SSRF-safe address checks used to accept or reject a destination. */

#define _POSIX_C_SOURCE 200809L

#include "policy.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define POLICY_LINE_MAX 1024
#define POLICY_HOST_MAX 253 /* longest valid DNS name */

/* Lowercases `in` into `out` and strips a port and trailing dots, so
 * "Example.COM.", "example.com:8080" and "example.com" all compare equal. */
static void normalize_host(const char *in, char *out, size_t out_len) {
    size_t o = 0;
    for (size_t i = 0; in != NULL && in[i] != '\0' && o + 1 < out_len; i++) {
        if (in[i] == ':') {
            break;
        }
        out[o++] = (char)tolower((unsigned char)in[i]);
    }
    while (o > 0 && out[o - 1] == '.') {
        o--;
    }
    out[o] = '\0';
}

/* Parses one rule line. Returns 1 = valid rule stored in *rule, 0 = blank/comment, -1 = malformed. */
static int parse_rule_line(const char *line, PolicyRule *rule) {
    char buf[POLICY_LINE_MAX];
    size_t n = strcspn(line, "#\r\n"); /* cut an inline or whole-line comment */
    if (n >= sizeof(buf)) {
        return -1;
    }
    memcpy(buf, line, n);
    buf[n] = '\0';

    char *start = buf;
    while (*start != '\0' && isspace((unsigned char)*start)) {
        start++;
    }
    size_t len = strlen(start);
    while (len > 0 && isspace((unsigned char)start[len - 1])) {
        start[--len] = '\0';
    }
    if (len == 0) {
        return 0;
    }

    int subdomains = 0;
    if (start[0] == '.') {
        subdomains = 1;
        start++;
        len--;
    }
    while (len > 0 && start[len - 1] == '.') { /* tolerate "example.com." */
        start[--len] = '\0';
    }
    if (len == 0 || len > POLICY_HOST_MAX) {
        return -1;
    }

    /* Only plain hostname characters; no '*', '/', ':', spaces, or empty labels. */
    char prev = '.';
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)start[i];
        if (!(isalnum(c) || c == '-' || c == '_' || c == '.')) {
            return -1;
        }
        if (c == '.' && prev == '.') {
            return -1;
        }
        prev = (char)c;
    }

    for (size_t i = 0; i < len; i++) {
        rule->host[i] = (char)tolower((unsigned char)start[i]);
    }
    rule->host[len] = '\0';
    rule->include_subdomains = subdomains;
    return 1;
}

static int append_rule(PolicyRule **rules, size_t *count, const PolicyRule *rule) {
    PolicyRule *grown = realloc(*rules, (*count + 1) * sizeof(PolicyRule));
    if (grown == NULL) {
        return -1;
    }
    grown[*count] = *rule;
    *rules = grown;
    (*count)++;
    return 0;
}

/* Loads one file. *missing is set if it cannot be opened. *saw_text is set if
 * the file had any non-blank, non-comment line (used for fail-closed allowlists). */
static int load_file(const char *path, PolicyRule **rules, size_t *count, size_t *loaded,
                     size_t *malformed, int *missing, int *saw_text) {
    *missing = 0;
    *saw_text = 0;
    if (path == NULL) {
        *missing = 1;
        return 0;
    }
    FILE *f = fopen(path, "r");
    if (f == NULL) {
        *missing = 1;
        return 0;
    }

    char line[POLICY_LINE_MAX];
    while (fgets(line, sizeof(line), f) != NULL) {
        /* A line longer than the buffer is malformed; discard the rest of it. */
        size_t got = strlen(line);
        int too_long = (got == sizeof(line) - 1 && line[got - 1] != '\n');
        if (too_long) {
            int c;
            while ((c = fgetc(f)) != EOF && c != '\n') {
            }
            (*malformed)++;
            *saw_text = 1;
            continue;
        }

        PolicyRule rule;
        int r = parse_rule_line(line, &rule);
        if (r == 0) {
            continue;
        }
        *saw_text = 1;
        if (r < 0) {
            (*malformed)++;
            continue;
        }
        if (append_rule(rules, count, &rule) != 0) {
            fclose(f);
            return -1;
        }
        (*loaded)++;
    }
    fclose(f);
    return 0;
}

int policy_load(Policy *p, const char *allowlist_path, const char *blocklist_path,
                PolicyLoadReport *report) {
    PolicyLoadReport local;
    if (report == NULL) {
        report = &local;
    }
    memset(report, 0, sizeof(*report));
    memset(p, 0, sizeof(*p));

    int saw_block_text = 0, saw_allow_text = 0;
    if (load_file(blocklist_path, &p->block_rules, &p->block_count, &report->block_loaded,
                  &report->block_malformed, &report->block_file_missing, &saw_block_text) != 0 ||
        load_file(allowlist_path, &p->allow_rules, &p->allow_count, &report->allow_loaded,
                  &report->allow_malformed, &report->allow_file_missing, &saw_allow_text) != 0) {
        policy_free(p);
        return -1;
    }
    p->allowlist_active = saw_allow_text; /* fail closed: any rule text turns the mode on */
    return 0;
}

static int rule_matches(const PolicyRule *rule, const char *host) {
    if (strcmp(host, rule->host) == 0) {
        return 1;
    }
    if (rule->include_subdomains) {
        size_t hl = strlen(host), rl = strlen(rule->host);
        /* Require the dot boundary so ".example.com" never matches "notexample.com". */
        if (hl > rl + 1 && host[hl - rl - 1] == '.' && strcmp(host + (hl - rl), rule->host) == 0) {
            return 1;
        }
    }
    return 0;
}

PolicyDecision policy_check_host(const Policy *p, const char *host) {
    char norm[POLICY_HOST_MAX + 2];
    normalize_host(host, norm, sizeof(norm));

    for (size_t i = 0; i < p->block_count; i++) {
        if (rule_matches(&p->block_rules[i], norm)) {
            return POLICY_DENY_BLOCKLIST;
        }
    }
    if (p->allowlist_active) {
        for (size_t i = 0; i < p->allow_count; i++) {
            if (rule_matches(&p->allow_rules[i], norm)) {
                return POLICY_ALLOW;
            }
        }
        return POLICY_DENY_NOT_ALLOWLISTED;
    }
    return POLICY_ALLOW;
}

void policy_free(Policy *p) {
    free(p->block_rules);
    free(p->allow_rules);
    memset(p, 0, sizeof(*p));
}

/* ---------- Network safety: SSRF protection ---------- */

#include <arpa/inet.h>
#include <netdb.h>
#include <stdint.h>

/* `ip` is in host byte order. */
static int ipv4_is_unsafe(uint32_t ip) {
    static const struct {
        uint32_t net;
        uint32_t mask;
    } blocked[] = {
        {0x00000000u, 0xFF000000u}, /* 0.0.0.0/8        "this" network / unspecified */
        {0x0A000000u, 0xFF000000u}, /* 10.0.0.0/8       private (RFC 1918) */
        {0x64400000u, 0xFFC00000u}, /* 100.64.0.0/10    carrier-grade NAT */
        {0x7F000000u, 0xFF000000u}, /* 127.0.0.0/8      loopback */
        {0xA9FE0000u, 0xFFFF0000u}, /* 169.254.0.0/16   link-local, cloud metadata */
        {0xAC100000u, 0xFFF00000u}, /* 172.16.0.0/12    private (RFC 1918) */
        {0xC0000000u, 0xFFFFFF00u}, /* 192.0.0.0/24     IETF protocol assignments */
        {0xC0000200u, 0xFFFFFF00u}, /* 192.0.2.0/24     documentation */
        {0xC0A80000u, 0xFFFF0000u}, /* 192.168.0.0/16   private (RFC 1918) */
        {0xC6120000u, 0xFFFE0000u}, /* 198.18.0.0/15    benchmarking */
        {0xC6336400u, 0xFFFFFF00u}, /* 198.51.100.0/24  documentation */
        {0xCB007100u, 0xFFFFFF00u}, /* 203.0.113.0/24   documentation */
        {0xE0000000u, 0xF0000000u}, /* 224.0.0.0/4      multicast */
        {0xF0000000u, 0xF0000000u}, /* 240.0.0.0/4      reserved + 255.255.255.255 broadcast */
    };
    for (size_t i = 0; i < sizeof(blocked) / sizeof(blocked[0]); i++) {
        if ((ip & blocked[i].mask) == blocked[i].net) {
            return 1;
        }
    }
    return 0;
}

static uint32_t v4_from_bytes(const unsigned char *b) {
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) | ((uint32_t)b[2] << 8) | (uint32_t)b[3];
}

static int ipv6_is_unsafe(const unsigned char *a) {
    int all_zero_to_12 = 1, first_10_zero = 1;
    for (int i = 0; i < 12; i++) {
        if (a[i] != 0) {
            all_zero_to_12 = 0;
        }
    }
    for (int i = 0; i < 10; i++) {
        if (a[i] != 0) {
            first_10_zero = 0;
        }
    }

    /* ::/96 covers "::" (unspecified), "::1" (loopback) and IPv4-compatible ::a.b.c.d */
    if (all_zero_to_12) {
        return 1;
    }
    /* ::ffff:a.b.c.d  IPv4-mapped: judge by the embedded IPv4 address */
    if (first_10_zero && a[10] == 0xFF && a[11] == 0xFF) {
        return ipv4_is_unsafe(v4_from_bytes(a + 12));
    }
    /* 64:ff9b::/96  NAT64: judge by the embedded IPv4 address */
    static const unsigned char nat64[12] = {0x00, 0x64, 0xFF, 0x9B, 0, 0, 0, 0, 0, 0, 0, 0};
    if (memcmp(a, nat64, 12) == 0) {
        return ipv4_is_unsafe(v4_from_bytes(a + 12));
    }
    /* 64:ff9b:1::/48  local-use NAT64 */
    if (a[0] == 0x00 && a[1] == 0x64 && a[2] == 0xFF && a[3] == 0x9B && a[4] == 0x00 && a[5] == 0x01) {
        return 1;
    }
    /* 2002::/16  6to4: IPv4 address is in bytes 2..5 */
    if (a[0] == 0x20 && a[1] == 0x02) {
        return ipv4_is_unsafe(v4_from_bytes(a + 2));
    }
    /* 2001::/32  Teredo (embeds an obfuscated IPv4 and relays through it): refuse */
    if (a[0] == 0x20 && a[1] == 0x01 && a[2] == 0x00 && a[3] == 0x00) {
        return 1;
    }
    /* 2001:db8::/32  documentation */
    if (a[0] == 0x20 && a[1] == 0x01 && a[2] == 0x0D && a[3] == 0xB8) {
        return 1;
    }
    /* 100::/64  discard-only */
    if (a[0] == 0x01 && a[1] == 0x00 && a[2] == 0 && a[3] == 0 && a[4] == 0 && a[5] == 0 && a[6] == 0 && a[7] == 0) {
        return 1;
    }
    /* fc00::/7  unique local (private) */
    if ((a[0] & 0xFE) == 0xFC) {
        return 1;
    }
    /* fe80::/10 link-local, fec0::/10 deprecated site-local */
    if (a[0] == 0xFE && ((a[1] & 0xC0) == 0x80 || (a[1] & 0xC0) == 0xC0)) {
        return 1;
    }
    /* ff00::/8  multicast */
    if (a[0] == 0xFF) {
        return 1;
    }
    return 0;
}

int address_is_unsafe(const struct sockaddr *addr) {
    if (addr == NULL) {
        return 1;
    }
    if (addr->sa_family == AF_INET) {
        const struct sockaddr_in *sin = (const struct sockaddr_in *)addr;
        return ipv4_is_unsafe(ntohl(sin->sin_addr.s_addr));
    }
    if (addr->sa_family == AF_INET6) {
        const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)addr;
        return ipv6_is_unsafe(sin6->sin6_addr.s6_addr);
    }
    return 1; /* unknown family: never connect */
}

int hostname_is_local_name(const char *host) {
    char norm[POLICY_HOST_MAX + 2];
    normalize_host(host, norm, sizeof(norm));
    if (strcmp(norm, "localhost") == 0) {
        return 1;
    }
    size_t n = strlen(norm);
    static const char *suffixes[] = {".localhost", ".local"};
    for (size_t i = 0; i < sizeof(suffixes) / sizeof(suffixes[0]); i++) {
        size_t sl = strlen(suffixes[i]);
        if (n > sl && strcmp(norm + (n - sl), suffixes[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

int host_is_numeric_address(const char *host) {
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV; /* guarantees no DNS query */
    int rc = getaddrinfo(host, "80", &hints, &res);
    if (rc == 0) {
        freeaddrinfo(res);
        return 1;
    }
    return 0;
}
