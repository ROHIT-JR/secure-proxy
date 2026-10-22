/* test_policy.c: Unit tests for the allowlist/blocklist policy engine (exact, subdomain, comment, malformed, bypass attempts). */

#define _POSIX_C_SOURCE 200809L

#include "policy.h"

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
    printf("Result: %d / %d tests passed successfully.\n", passed_tests, total_tests);
    return passed_tests == total_tests ? 0 : 1;
}
