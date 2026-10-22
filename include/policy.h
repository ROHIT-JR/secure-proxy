#pragma once
/* policy.h: Declares the allowlist/blocklist and network-safety policy checks applied before any origin connection is made. */

#include <netinet/in.h>
#include <stddef.h>
#include <sys/socket.h>

/* ---------- Host allowlist / blocklist (Issue: policy engine) ---------- */

typedef enum {
    POLICY_ALLOW = 0,
    POLICY_DENY_BLOCKLIST,        /* host (or a parent domain) is on the blocklist */
    POLICY_DENY_NOT_ALLOWLISTED   /* allowlist mode is on and the host is not listed */
} PolicyDecision;

typedef struct {
    char host[256]; /* lowercase, no leading dot, no trailing dot */
    int include_subdomains;
} PolicyRule;

typedef struct {
    PolicyRule *block_rules;
    size_t block_count;
    PolicyRule *allow_rules;
    size_t allow_count;
    int allowlist_active; /* 1 if the allowlist file contained any rule text (valid or not) */
} Policy;

/* What loading found, so the caller can report it without the policy module printing. */
typedef struct {
    size_t block_loaded, block_malformed;
    size_t allow_loaded, allow_malformed;
    int block_file_missing, allow_file_missing;
} PolicyLoadReport;

/*
 * Loads newline-delimited rules. A missing file is reported (not fatal here);
 * the caller decides whether that is acceptable. Malformed lines are skipped
 * and counted, never silently accepted.
 *
 * Fail-closed rule: if the allowlist file contains ANY rule text, allowlist
 * mode is on even when every rule was malformed (then nothing is allowed).
 * Returns 0 on success, -1 on out-of-memory.
 */
int policy_load(Policy *p, const char *allowlist_path, const char *blocklist_path,
                PolicyLoadReport *report);

/* Checks a (validated) hostname. Case, a trailing dot, and port are normalised away.
 * The blocklist is checked first, then the allowlist. */
PolicyDecision policy_check_host(const Policy *p, const char *host);

/* Releases everything policy_load() allocated. Safe on a zeroed or already-freed Policy. */
void policy_free(Policy *p);

/* ---------- Network safety: SSRF (Server-Side Request Forgery) protection ---------- */

/* Returns 1 if the proxy must never connect to this address: loopback, private,
 * link-local (including the 169.254.169.254 cloud metadata address), multicast,
 * unspecified, carrier-grade NAT, documentation/benchmark/reserved ranges, and
 * any IPv6 form that embeds an unsafe IPv4 address (IPv4-mapped, NAT64, 6to4,
 * IPv4-compatible). Unknown or malformed addresses are treated as unsafe. */
int address_is_unsafe(const struct sockaddr *addr);

/* Returns 1 if `host` is an IP address in ANY spelling the system resolver accepts
 * (dotted, decimal, hex, octal, short forms). Never performs a DNS query. */
int host_is_numeric_address(const char *host);

/* Returns 1 for names that must be refused without any DNS lookup:
 * "localhost" and anything under ".localhost" or ".local". Case and a
 * trailing dot are ignored. */
int hostname_is_local_name(const char *host);
