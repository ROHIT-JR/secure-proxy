/* test_decision.c: Unit tests for the explainable risk scoring and the safe HTML block page. */

#include "decision.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

static Decision eval(int policy, int network, int port, int rep_checked, ReputationVerdict rep) {
    DecisionInputs in;
    memset(&in, 0, sizeof(in));
    in.policy_denied = policy;
    in.network_unsafe = network;
    in.port_denied = port;
    in.reputation_checked = rep_checked;
    in.reputation = rep;
    return decision_evaluate(&in);
}

static void expect(const char *label, Decision d, DecisionAction action, DecisionReason reason, int score) {
    CHECK(d.action == action && d.reason == reason && d.risk_score == score,
          "%s: expected action=%d reason=%s score=%d, got action=%d reason=%s score=%d", label, action,
          decision_reason_name(reason), score, d.action, decision_reason_name(d.reason), d.risk_score);
}

static void test_scores(void) {
    CHECK(decision_score_reputation(REP_SAFE) == 0, "safe scores 0");
    CHECK(decision_score_reputation(REP_UNAVAILABLE) == 10, "unavailable scores 10");
    CHECK(decision_score_reputation(REP_SUSPICIOUS) == 50, "suspicious scores 50");
    CHECK(decision_score_reputation(REP_MALICIOUS) == 90, "malicious scores 90");
    CHECK(decision_score_reputation((ReputationVerdict)77) == RISK_REPUTATION_UNAVAILABLE, "unknown verdict is treated like unavailable");
    CHECK(RISK_REPUTATION_SUSPICIOUS < DECISION_BLOCK_THRESHOLD && RISK_REPUTATION_UNAVAILABLE < DECISION_BLOCK_THRESHOLD,
          "suspicious and unavailable must stay below the block threshold");
    CHECK(RISK_REPUTATION_MALICIOUS >= DECISION_BLOCK_THRESHOLD && RISK_BLOCKED_BY_RULE >= DECISION_BLOCK_THRESHOLD,
          "malicious and rule-based blocks must reach the block threshold");
}

static void test_single_signals(void) {
    expect("nothing known", eval(0, 0, 0, 0, REP_SAFE), DECISION_ALLOW, REASON_NONE, 0);
    expect("safe", eval(0, 0, 0, 1, REP_SAFE), DECISION_ALLOW, REASON_NONE, 0);
    expect("unavailable is NOT a block", eval(0, 0, 0, 1, REP_UNAVAILABLE), DECISION_ALLOW, REASON_NONE, 10);
    expect("suspicious is allowed but scored", eval(0, 0, 0, 1, REP_SUSPICIOUS), DECISION_ALLOW, REASON_NONE, 50);
    expect("malicious blocks", eval(0, 0, 0, 1, REP_MALICIOUS), DECISION_BLOCK, REASON_REPUTATION, 90);
    expect("policy blocks", eval(1, 0, 0, 0, REP_SAFE), DECISION_BLOCK, REASON_POLICY, 100);
    expect("network blocks", eval(0, 1, 0, 0, REP_SAFE), DECISION_BLOCK, REASON_NETWORK, 100);
    expect("port blocks", eval(0, 0, 1, 0, REP_SAFE), DECISION_BLOCK, REASON_PORT, 100);
}

static void test_combination(void) {
    /* the highest signal wins; a reassuring signal can never lower the risk of a dangerous one */
    expect("policy + safe reputation", eval(1, 0, 0, 1, REP_SAFE), DECISION_BLOCK, REASON_POLICY, 100);
    expect("network + safe reputation", eval(0, 1, 0, 1, REP_SAFE), DECISION_BLOCK, REASON_NETWORK, 100);
    expect("malicious + safe-looking nothing else", eval(0, 0, 0, 1, REP_MALICIOUS), DECISION_BLOCK, REASON_REPUTATION, 90);
    /* a rule (100) outranks a malicious verdict (90) */
    expect("network outranks malicious", eval(0, 1, 0, 1, REP_MALICIOUS), DECISION_BLOCK, REASON_NETWORK, 100);
    expect("policy outranks malicious", eval(1, 0, 0, 1, REP_MALICIOUS), DECISION_BLOCK, REASON_POLICY, 100);
    /* ties between rules follow the documented order: port, policy, network, reputation */
    expect("port beats policy on a tie", eval(1, 0, 1, 0, REP_SAFE), DECISION_BLOCK, REASON_PORT, 100);
    expect("policy beats network on a tie", eval(1, 1, 0, 0, REP_SAFE), DECISION_BLOCK, REASON_POLICY, 100);
    expect("port beats everything", eval(1, 1, 1, 1, REP_MALICIOUS), DECISION_BLOCK, REASON_PORT, 100);
    /* an unchecked reputation must contribute nothing, whatever stale verdict value is lying around */
    expect("unchecked reputation is ignored", eval(0, 0, 0, 0, REP_MALICIOUS), DECISION_ALLOW, REASON_NONE, 0);

    /* exhaustive check: for every combination, blocked <=> score >= threshold, and the reason is set exactly when blocked */
    int violations = 0;
    for (int mask = 0; mask < 64; mask++) {
        for (int v = 0; v < 4; v++) {
            Decision d = eval(mask & 1, (mask >> 1) & 1, (mask >> 2) & 1, (mask >> 3) & 1, (ReputationVerdict)v);
            int should_block = d.risk_score >= DECISION_BLOCK_THRESHOLD;
            if ((d.action == DECISION_BLOCK) != should_block || (d.action == DECISION_BLOCK) != (d.reason != REASON_NONE) ||
                d.risk_score < 0 || d.risk_score > 100) {
                violations++;
            }
        }
    }
    CHECK(violations == 0, "%d inconsistent decisions across all 256 signal combinations", violations);
}

/* ---------- the block page ---------- */

static char page[2048];

static size_t build(unsigned long id, DecisionReason r) {
    memset(page, 'X', sizeof(page));
    return decision_build_block_response(page, sizeof(page), id, r);
}

static const char *body_of(void) {
    const char *b = strstr(page, "\r\n\r\n");
    return b ? b + 4 : "";
}

static void test_page_structure(void) {
    size_t n = build(4711, REASON_POLICY);
    CHECK(n > 0 && n < sizeof(page), "page builds (%zu bytes)", n);
    CHECK(strlen(page) == n, "the response is NUL-terminated at its reported length");
    CHECK(strncmp(page, "HTTP/1.1 403 Forbidden\r\n", 24) == 0, "status line is 403 Forbidden");
    CHECK(strstr(page, "Content-Type: text/html; charset=utf-8\r\n") != NULL, "HTML content type");
    CHECK(strstr(page, "X-Request-Id: 4711\r\n") != NULL, "request id is also a header");
    CHECK(strstr(page, "Cache-Control: no-store\r\n") != NULL, "block pages must not be cached");
    CHECK(strstr(page, "X-Content-Type-Options: nosniff\r\n") != NULL, "nosniff");
    CHECK(strstr(page, "Connection: close\r\n") != NULL, "connection close");

    const char *cl = strstr(page, "Content-Length: ");
    int declared = cl ? atoi(cl + 16) : -1;
    CHECK(declared == (int)strlen(body_of()), "Content-Length (%d) matches the body (%zu)", declared, strlen(body_of()));
    CHECK(strstr(body_of(), "<code id=\"request-id\">4711</code>") != NULL, "the page shows the request id");
    CHECK(strstr(body_of(), "<!DOCTYPE html>") == body_of(), "starts with a doctype");
}

static void test_reasons_are_distinguishable(void) {
    const DecisionReason reasons[] = {REASON_POLICY, REASON_NETWORK, REASON_REPUTATION, REASON_PORT};
    char bodies[4][2048];
    for (int i = 0; i < 4; i++) {
        build(1, reasons[i]);
        snprintf(bodies[i], sizeof(bodies[i]), "%s", body_of());
        char marker[64];
        snprintf(marker, sizeof(marker), "data-reason=\"%s\"", decision_reason_name(reasons[i]));
        CHECK(strstr(bodies[i], marker) != NULL, "page carries its category marker %s", marker);
    }
    for (int i = 0; i < 4; i++) {
        for (int j = i + 1; j < 4; j++) {
            CHECK(strcmp(bodies[i], bodies[j]) != 0, "pages for %s and %s must differ", decision_reason_name(reasons[i]),
                  decision_reason_name(reasons[j]));
        }
    }
}

/* The page must reveal nothing about configuration, providers, rules or addresses. */
static void test_page_leaks_nothing(void) {
    const char *forbidden[] = {"127.", "10.", "192.168", "169.254", "localhost", "malicious", "suspicious",
                               "fixture", ".txt", "/etc", "/tmp", "blocklist", "allowlist", "config", "provider",
                               "rule", "score", "risk", "PROXY_", "token", "password", "secret", "dns",
                               "resolved", "cloud metadata", "offline"};
    const DecisionReason reasons[] = {REASON_NONE, REASON_POLICY, REASON_NETWORK, REASON_REPUTATION, REASON_PORT};
    int leaks = 0;
    for (size_t r = 0; r < sizeof(reasons) / sizeof(reasons[0]); r++) {
        build(123, reasons[r]);
        char lower[2048];
        const char *b = body_of();
        size_t k = 0;
        for (; b[k] && k + 1 < sizeof(lower); k++) {
            lower[k] = (char)((b[k] >= 'A' && b[k] <= 'Z') ? b[k] + 32 : b[k]);
        }
        lower[k] = '\0';
        for (size_t f = 0; f < sizeof(forbidden) / sizeof(forbidden[0]); f++) {
            char needle[64];
            size_t m = 0;
            for (; forbidden[f][m]; m++) {
                char c = forbidden[f][m];
                needle[m] = (char)((c >= 'A' && c <= 'Z') ? c + 32 : c);
            }
            needle[m] = '\0';
            if (strstr(lower, needle) != NULL) {
                printf("  page for reason %s contains \"%s\"\n", decision_reason_name(reasons[r]), forbidden[f]);
                leaks++;
            }
        }
    }
    CHECK(leaks == 0, "%d forbidden word(s) appeared in a block page", leaks);
}

static void test_bounds_and_extremes(void) {
    /* the largest possible request id must still fit and be printed in full */
    char big[32];
    snprintf(big, sizeof(big), "%lu", ULONG_MAX);
    size_t n = build(ULONG_MAX, REASON_REPUTATION);
    CHECK(n > 0 && strstr(body_of(), big) != NULL, "ULONG_MAX request id is shown in full");

    /* too-small output buffers must be refused, never overrun */
    char tiny[64];
    memset(tiny, 'Z', sizeof(tiny));
    CHECK(decision_build_block_response(tiny, sizeof(tiny), 1, REASON_POLICY) == 0, "a 64-byte buffer is refused");
    CHECK(decision_build_block_response(tiny, 0, 1, REASON_POLICY) == 0, "a zero-length buffer is refused");
    char exact[2048];
    size_t need = decision_build_block_response(exact, sizeof(exact), 1, REASON_POLICY);
    char edge[2048];
    memset(edge, 'E', sizeof(edge));
    CHECK(decision_build_block_response(edge, need, 1, REASON_POLICY) == 0, "one byte too small (no room for NUL) is refused");
    CHECK(edge[need] == 'E', "nothing was written past the buffer");
    CHECK(decision_build_block_response(edge, need + 1, 1, REASON_POLICY) == need, "the exact size works");

    /* the page itself must be small enough that 2048 is always sufficient */
    CHECK(need < 1500, "page is comfortably under the 2048-byte buffer (%zu)", need);
    CHECK(strcmp(decision_reason_name(REASON_NONE), "none") == 0 && strcmp(decision_reason_name((DecisionReason)99), "none") == 0,
          "reason names are stable and total");
}

int main(void) {
    printf("=== Running Decision Unit Tests ===\n");
    test_scores();
    test_single_signals();
    test_combination();
    test_page_structure();
    test_reasons_are_distinguishable();
    test_page_leaks_nothing();
    test_bounds_and_extremes();
    printf("Result: %d / %d tests passed successfully.\n", passed_tests, total_tests);
    return passed_tests == total_tests ? 0 : 1;
}
