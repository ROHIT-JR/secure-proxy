/* test_policy.c: Unit tests for the allowlist/blocklist policy engine (exact, subdomain, comment, malformed, bypass attempts). */

#define _POSIX_C_SOURCE 200809L

#include "policy.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int total_tests = 0;
static int passed_tests = 0;

#define CHECK(cond, ...)                          \
    do {                                          \
        total_tests++;                            \
        if (cond) {                               \
            passed_tests++;                       \
        } else {                                  \
            printf("FAIL (line %d): ", __LINE__); \
            printf(__VA_ARGS__);                  \
            printf("\n");                         \
        }                                         \
    } while (0)

/* Writes `text` to a fresh temp file and returns its path (caller unlinks). */
static char *write_temp(const char *text) {
    static char paths[8][64];
    static int next = 0;
    char *path = paths[next++ % 8];
    snprintf(path, 64, "/tmp/test_policy_XXXXXX");
    int fd = mkstemp(path);
    if (fd >= 0) {
        if (write(fd, text, strlen(text)) < 0) {
            /* test helper: a short write just makes the following checks fail */
        }
        close(fd);
    }
    return path;
}

static const char *name_of(PolicyDecision d) {
    return d == POLICY_ALLOW ? "ALLOW" : d == POLICY_DENY_BLOCKLIST ? "DENY_BLOCKLIST" : "DENY_NOT_ALLOWLISTED";
}

static void expect(const Policy *p, const char *host, PolicyDecision want) {
    PolicyDecision got = policy_check_host(p, host);
    CHECK(got == want, "host \"%s\": expected %s, got %s", host, name_of(want), name_of(got));
}

static void test_exact_and_subdomain_blocking(void) {
    char *bl = write_temp("blocked.test\n.evil.test\n");
    Policy p;
    PolicyLoadReport r;
    CHECK(policy_load(&p, NULL, bl, &r) == 0, "load should succeed");
    CHECK(r.block_loaded == 2 && r.block_malformed == 0, "2 rules loaded, got %zu/%zu", r.block_loaded,
          r.block_malformed);

    expect(&p, "blocked.test", POLICY_DENY_BLOCKLIST);
    expect(&p, "www.blocked.test", POLICY_ALLOW);    /* exact rule: subdomains are NOT covered */
    expect(&p, "evil.test", POLICY_DENY_BLOCKLIST);  /* ".evil.test" covers the apex ... */
    expect(&p, "a.evil.test", POLICY_DENY_BLOCKLIST);
    expect(&p, "a.b.c.evil.test", POLICY_DENY_BLOCKLIST); /* ... and any depth below it */
    expect(&p, "notevil.test", POLICY_ALLOW);        /* the dot boundary matters */
    expect(&p, "evil.test.example.com", POLICY_ALLOW);
    expect(&p, "example.com", POLICY_ALLOW);
    policy_free(&p);
    unlink(bl);
}

static void test_case_cannot_bypass(void) {
    char *bl = write_temp("Blocked.TEST\n.EVIL.test\n");
    Policy p;
    policy_load(&p, NULL, bl, NULL);
    expect(&p, "blocked.test", POLICY_DENY_BLOCKLIST);
    expect(&p, "BLOCKED.TEST", POLICY_DENY_BLOCKLIST);
    expect(&p, "BlOcKeD.tEsT", POLICY_DENY_BLOCKLIST);
    expect(&p, "WWW.Evil.Test", POLICY_DENY_BLOCKLIST);
    policy_free(&p);
    unlink(bl);
}

static void test_other_normalisation_bypasses(void) {
    char *bl = write_temp("blocked.test\n");
    Policy p;
    policy_load(&p, NULL, bl, NULL);
    expect(&p, "blocked.test.", POLICY_DENY_BLOCKLIST);   /* fully-qualified trailing dot */
    expect(&p, "blocked.test..", POLICY_DENY_BLOCKLIST);
    expect(&p, "blocked.test:8080", POLICY_DENY_BLOCKLIST); /* port is not part of the host */
    expect(&p, "Blocked.Test.:80", POLICY_DENY_BLOCKLIST);
    policy_free(&p);
    unlink(bl);
}

static void test_comments_blank_lines_whitespace(void) {
    char *bl = write_temp(
        "# a whole-line comment\n"
        "\n"
        "   \t  \n"
        "  spaced.test   \n"
        "inline.test # trailing comment\n"
        "#commented.test\n"
        "crlf.test\r\n");
    Policy p;
    PolicyLoadReport r;
    policy_load(&p, NULL, bl, &r);
    CHECK(r.block_loaded == 3, "3 valid rules expected, got %zu", r.block_loaded);
    CHECK(r.block_malformed == 0, "no malformed expected, got %zu", r.block_malformed);
    expect(&p, "spaced.test", POLICY_DENY_BLOCKLIST);
    expect(&p, "inline.test", POLICY_DENY_BLOCKLIST);
    expect(&p, "crlf.test", POLICY_DENY_BLOCKLIST);
    expect(&p, "commented.test", POLICY_ALLOW); /* a commented-out rule must NOT apply */
    expect(&p, "comment", POLICY_ALLOW);
    policy_free(&p);
    unlink(bl);
}

static void test_malformed_rules_are_rejected_and_counted(void) {
    char *bl = write_temp(
        "good.test\n"
        "*.wild.test\n"          /* wildcards are not supported: use ".wild.test" */
        "has space.test\n"
        "http://url.test/\n"
        "bad/path.test\n"
        "double..dot.test\n"
        "host:8080\n"
        ".\n"
        "..\n"
        "semi;colon.test\n"
        "another-good.test\n");
    Policy p;
    PolicyLoadReport r;
    policy_load(&p, NULL, bl, &r);
    CHECK(r.block_loaded == 2, "only the 2 valid rules load, got %zu", r.block_loaded);
    CHECK(r.block_malformed == 9, "9 malformed rules counted, got %zu", r.block_malformed);
    expect(&p, "good.test", POLICY_DENY_BLOCKLIST);
    expect(&p, "another-good.test", POLICY_DENY_BLOCKLIST);
    expect(&p, "anything.wild.test", POLICY_ALLOW); /* the malformed wildcard did not become a rule */
    expect(&p, "wild.test", POLICY_ALLOW);
    policy_free(&p);
    unlink(bl);

    /* An overlong rule line is malformed and must not swallow the next line. */
    char big[3000];
    memset(big, 'a', sizeof(big));
    memcpy(big + 2000, ".test\nafter.test\n", 18);
    big[2000 + 18] = '\0';
    bl = write_temp(big);
    policy_load(&p, NULL, bl, &r);
    CHECK(r.block_malformed == 1, "overlong line counted malformed, got %zu", r.block_malformed);
    expect(&p, "after.test", POLICY_DENY_BLOCKLIST);
    policy_free(&p);
    unlink(bl);
}

static void test_allowlist_mode(void) {
    char *al = write_temp("allowed.test\n.corp.test\n");
    char *bl = write_temp("bad.corp.test\n");
    Policy p;
    PolicyLoadReport r;
    policy_load(&p, al, bl, &r);
    CHECK(p.allowlist_active == 1, "allowlist mode should be on");
    expect(&p, "allowed.test", POLICY_ALLOW);
    expect(&p, "www.corp.test", POLICY_ALLOW);
    expect(&p, "ALLOWED.test", POLICY_ALLOW);
    expect(&p, "other.test", POLICY_DENY_NOT_ALLOWLISTED);
    expect(&p, "www.allowed.test", POLICY_DENY_NOT_ALLOWLISTED);
    expect(&p, "notcorp.test", POLICY_DENY_NOT_ALLOWLISTED);
    /* The blocklist wins even over an allowlisted parent domain. */
    expect(&p, "bad.corp.test", POLICY_DENY_BLOCKLIST);
    policy_free(&p);
    unlink(al);
    unlink(bl);
}

static void test_allowlist_off_when_only_comments(void) {
    char *al = write_temp("# nothing but comments\n\n# example.com\n");
    Policy p;
    policy_load(&p, al, NULL, NULL);
    CHECK(p.allowlist_active == 0, "comment-only allowlist must leave allowlist mode off");
    expect(&p, "anything.test", POLICY_ALLOW);
    policy_free(&p);
    unlink(al);
}

static void test_allowlist_fails_closed(void) {
    /* A typo'd allowlist must NOT silently turn the allowlist off. */
    char *al = write_temp("*.example.com\nhttp://example.com\n");
    Policy p;
    PolicyLoadReport r;
    policy_load(&p, al, NULL, &r);
    CHECK(r.allow_loaded == 0 && r.allow_malformed == 2, "both rules malformed, got %zu/%zu",
          r.allow_loaded, r.allow_malformed);
    CHECK(p.allowlist_active == 1, "allowlist mode must stay ON when the file had rule text");
    expect(&p, "example.com", POLICY_DENY_NOT_ALLOWLISTED);
    expect(&p, "anything.test", POLICY_DENY_NOT_ALLOWLISTED);
    policy_free(&p);
    unlink(al);
}

static void test_missing_and_empty_files(void) {
    Policy p;
    PolicyLoadReport r;
    CHECK(policy_load(&p, "/nonexistent/allow.txt", "/nonexistent/block.txt", &r) == 0,
          "missing files are reported, not fatal");
    CHECK(r.block_file_missing == 1 && r.allow_file_missing == 1, "both flagged missing");
    CHECK(p.allowlist_active == 0, "a missing allowlist does not enable allowlist mode");
    expect(&p, "example.com", POLICY_ALLOW);
    policy_free(&p);

    char *empty = write_temp("");
    CHECK(policy_load(&p, empty, empty, &r) == 0, "empty files load");
    CHECK(r.block_loaded == 0 && p.allowlist_active == 0, "empty files mean no rules");
    expect(&p, "example.com", POLICY_ALLOW);
    policy_free(&p);
    unlink(empty);

    /* Freeing twice / a never-loaded policy must be safe. */
    policy_free(&p);
    Policy zero;
    memset(&zero, 0, sizeof(zero));
    policy_free(&zero);
    CHECK(1, "double free of an empty Policy did not crash");
}

static void test_shipped_config_is_valid(void) {
    Policy p;
    PolicyLoadReport r;
    if (access("config/blocklist.txt", R_OK) != 0) {
        return; /* run from somewhere other than the repo root */
    }
    CHECK(policy_load(&p, "config/allowlist.txt", "config/blocklist.txt", &r) == 0, "load shipped config");
    CHECK(r.block_malformed == 0 && r.allow_malformed == 0, "shipped config has no malformed rules");
    CHECK(p.allowlist_active == 0, "shipped allowlist must be inactive by default (examples are comments)");
    expect(&p, "blocked-example.test", POLICY_DENY_BLOCKLIST);
    expect(&p, "x.malicious-example.test", POLICY_DENY_BLOCKLIST);
    expect(&p, "example.com", POLICY_ALLOW);
    policy_free(&p);
}


/* ---------- SSRF: address classification ---------- */

static int unsafe_text(const char *text) {
    struct sockaddr_storage ss;
    memset(&ss, 0, sizeof(ss));
    struct sockaddr_in *v4 = (struct sockaddr_in *)&ss;
    struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)&ss;
    if (inet_pton(AF_INET, text, &v4->sin_addr) == 1) {
        v4->sin_family = AF_INET;
    } else if (inet_pton(AF_INET6, text, &v6->sin6_addr) == 1) {
        v6->sin6_family = AF_INET6;
    } else {
        printf("FAIL (line %d): test bug, cannot parse \"%s\"\n", __LINE__, text);
        total_tests++;
        return -1;
    }
    return address_is_unsafe((struct sockaddr *)&ss);
}

static void expect_unsafe(const char *text, int want) {
    int got = unsafe_text(text);
    CHECK(got == want, "address %s: expected %s, got %s", text, want ? "UNSAFE" : "safe", got ? "UNSAFE" : "safe");
}

static void test_ipv4_ranges(void) {
    /* every blocked range: first, a middle, and last address; and the neighbours just outside */
    const char *unsafe[] = {"0.0.0.0", "0.255.255.255", "10.0.0.0", "10.1.2.3", "10.255.255.255",
                            "100.64.0.0", "100.127.255.255", "127.0.0.1", "127.255.255.254",
                            "169.254.0.1", "169.254.169.254", "169.254.255.255", "172.16.0.0",
                            "172.20.1.1", "172.31.255.255", "192.0.0.1", "192.0.2.55", "192.168.0.1",
                            "192.168.255.255", "198.18.0.1", "198.19.255.255", "198.51.100.7",
                            "203.0.113.9", "224.0.0.1", "239.255.255.250", "240.0.0.1",
                            "255.255.255.255"};
    for (size_t i = 0; i < sizeof(unsafe) / sizeof(unsafe[0]); i++) {
        expect_unsafe(unsafe[i], 1);
    }
    /* boundaries just outside the blocked ranges must stay reachable */
    const char *safe[] = {"1.1.1.1", "8.8.8.8", "9.255.255.255", "11.0.0.0", "100.63.255.255",
                          "100.128.0.0", "126.255.255.255", "128.0.0.1", "169.253.255.255",
                          "169.255.0.0", "172.15.255.255", "172.32.0.0", "192.0.1.1", "192.167.255.255",
                          "192.169.0.0", "198.17.255.255", "198.20.0.0", "203.0.114.1", "223.255.255.255",
                          "93.184.216.34"};
    for (size_t i = 0; i < sizeof(safe) / sizeof(safe[0]); i++) {
        expect_unsafe(safe[i], 0);
    }
}

static void test_ipv6_ranges(void) {
    const char *unsafe[] = {"::", "::1", "fe80::1", "febf::1", "fec0::1", "fc00::1", "fd12:3456::1",
                            "ff02::1", "ff00::", "2001:db8::1", "2001:0:4136:e378:8000:63bf:3fff:fdd2",
                            "::ffff:127.0.0.1", "::ffff:10.1.2.3", "::ffff:169.254.169.254",
                            "::ffff:192.168.0.1", "::ffff:0.0.0.0", "64:ff9b::7f00:1",
                            "64:ff9b::a9fe:a9fe", "64:ff9b:1::1", "2002:7f00:1::1", "2002:0a00:1::",
                            "2002:a9fe:a9fe::1", "::127.0.0.1", "100::1"};
    for (size_t i = 0; i < sizeof(unsafe) / sizeof(unsafe[0]); i++) {
        expect_unsafe(unsafe[i], 1);
    }
    const char *safe[] = {"2606:4700:4700::1111", "2001:4860:4860::8888", "::ffff:8.8.8.8",
                          "::ffff:93.184.216.34", "64:ff9b::808:808", "2002:0808:0808::1",
                          "2a00:1450:4001::1"};
    for (size_t i = 0; i < sizeof(safe) / sizeof(safe[0]); i++) {
        expect_unsafe(safe[i], 0);
    }
}

static void test_malformed_address_is_unsafe(void) {
    CHECK(address_is_unsafe(NULL) == 1, "NULL address must be unsafe");
    struct sockaddr_un_like {
        unsigned short family;
        char data[14];
    } weird = {AF_UNIX, {0}};
    CHECK(address_is_unsafe((struct sockaddr *)&weird) == 1, "unknown address family must be unsafe");
}

static void test_local_names(void) {
    const char *local[] = {"localhost", "LOCALHOST", "Localhost.", "foo.localhost", "a.b.LOCALHOST.",
                           "printer.local", "x.local."};
    for (size_t i = 0; i < sizeof(local) / sizeof(local[0]); i++) {
        CHECK(hostname_is_local_name(local[i]) == 1, "\"%s\" is a local name", local[i]);
    }
    const char *normal[] = {"example.com", "notlocalhost", "localhost.example.com", "mylocal",
                            "local.example.com", "localhostx"};
    for (size_t i = 0; i < sizeof(normal) / sizeof(normal[0]); i++) {
        CHECK(hostname_is_local_name(normal[i]) == 0, "\"%s\" is not a local name", normal[i]);
    }
}

/* The URL parser accepts any alphanumeric/dotted "host", so a client can spell
 * 127.0.0.1 as 2130706433, 0x7f.1, 017700000001 or 127.1. The resolver turns all of
 * them into the same loopback address WITHOUT a DNS query; make sure we then reject it. */
static void test_numeric_spellings_resolve_to_unsafe(void) {
    const char *spellings[] = {"127.0.0.1", "2130706433", "0x7f.1", "0x7f000001", "017700000001",
                               "127.1", "127.0.1", "0177.0.0.1", "169.254.169.254", "2852039166",
                               "10.1", "167772161", "192.168.1.1", "0xc0a80101", "3232235777"};
    for (size_t i = 0; i < sizeof(spellings) / sizeof(spellings[0]); i++) {
        struct addrinfo hints, *res = NULL;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
        int rc = getaddrinfo(spellings[i], "80", &hints, &res);
        CHECK(rc == 0 && res != NULL, "resolver should accept numeric spelling \"%s\"", spellings[i]);
        if (rc == 0 && res != NULL) {
            int any_unsafe = 0;
            for (struct addrinfo *rp = res; rp; rp = rp->ai_next) {
                any_unsafe |= address_is_unsafe(rp->ai_addr);
            }
            CHECK(any_unsafe == 1, "numeric spelling \"%s\" must resolve to an unsafe address", spellings[i]);
            freeaddrinfo(res);
        }
    }
}

static void test_numeric_address_detection(void) {
    const char *numeric[] = {"127.0.0.1", "2130706433", "0x7f.1", "017700000001", "127.1", "8.8.8.8",
                             "10.1", "0xc0a80101"};
    for (size_t i = 0; i < sizeof(numeric) / sizeof(numeric[0]); i++) {
        CHECK(host_is_numeric_address(numeric[i]) == 1, "\"%s\" is a numeric address", numeric[i]);
    }
    const char *names[] = {"example.com", "localhost", "a.b.test", "1.2.3.4.5", "999.1.1.1", "abc", "", "bad-host.test"};
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        CHECK(host_is_numeric_address(names[i]) == 0, "\"%s\" is not a numeric address", names[i]);
    }
}

int main(void) {
    printf("=== Running Policy Unit Tests ===\n");
    test_exact_and_subdomain_blocking();
    test_case_cannot_bypass();
    test_other_normalisation_bypasses();
    test_comments_blank_lines_whitespace();
    test_malformed_rules_are_rejected_and_counted();
    test_allowlist_mode();
    test_allowlist_off_when_only_comments();
    test_allowlist_fails_closed();
    test_missing_and_empty_files();
    test_shipped_config_is_valid();
    test_ipv4_ranges();
    test_ipv6_ranges();
    test_malformed_address_is_unsafe();
    test_local_names();
    test_numeric_spellings_resolve_to_unsafe();
    test_numeric_address_detection();
    printf("Result: %d / %d tests passed successfully.\n", passed_tests, total_tests);
    return passed_tests == total_tests ? 0 : 1;
}
