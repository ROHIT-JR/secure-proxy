/* decision.c: Implements the explainable risk scoring that combines policy, network-safety, and reputation outcomes into one documented decision and a safe block page. */

#include "decision.h"

#include <stdio.h>
#include <string.h>

int decision_score_reputation(ReputationVerdict v) {
    switch (v) {
        case REP_SAFE: return RISK_REPUTATION_SAFE;
        case REP_SUSPICIOUS: return RISK_REPUTATION_SUSPICIOUS;
        case REP_MALICIOUS: return RISK_REPUTATION_MALICIOUS;
        case REP_UNAVAILABLE: return RISK_REPUTATION_UNAVAILABLE;
    }
    return RISK_REPUTATION_UNAVAILABLE; /* an unknown verdict is treated like "could not tell" */
}

const char *decision_reason_name(DecisionReason r) {
    switch (r) {
        case REASON_NONE: return "none";
        case REASON_POLICY: return "policy";
        case REASON_NETWORK: return "network";
        case REASON_REPUTATION: return "reputation";
        case REASON_PORT: return "port";
    }
    return "none";
}

Decision decision_evaluate(const DecisionInputs *in) {
    /* Candidates in tie-break order: port, policy, network, reputation. */
    struct {
        int active;
        int score;
        DecisionReason reason;
    } c[4];
    c[0].active = in->port_denied;
    c[0].score = RISK_BLOCKED_BY_RULE;
    c[0].reason = REASON_PORT;
    c[1].active = in->policy_denied;
    c[1].score = RISK_BLOCKED_BY_RULE;
    c[1].reason = REASON_POLICY;
    c[2].active = in->network_unsafe;
    c[2].score = RISK_BLOCKED_BY_RULE;
    c[2].reason = REASON_NETWORK;
    c[3].active = in->reputation_checked;
    c[3].score = in->reputation_checked ? decision_score_reputation(in->reputation) : 0;
    c[3].reason = REASON_REPUTATION;

    Decision d = {DECISION_ALLOW, REASON_NONE, 0};
    DecisionReason top_reason = REASON_NONE;
    for (int i = 0; i < 4; i++) {
        if (c[i].active && c[i].score > d.risk_score) { /* strict '>' keeps the earlier one on a tie */
            d.risk_score = c[i].score;
            top_reason = c[i].reason;
        }
    }
    if (d.risk_score >= DECISION_BLOCK_THRESHOLD) {
        d.action = DECISION_BLOCK;
        d.reason = top_reason;
    }
    return d;
}

static const char *reason_headline(DecisionReason r) {
    switch (r) {
        case REASON_POLICY: return "Blocked by access policy";
        case REASON_NETWORK: return "Destination not permitted";
        case REASON_REPUTATION: return "Flagged as unsafe";
        case REASON_PORT: return "Port not permitted";
        case REASON_NONE: break;
    }
    return "Request blocked";
}

static const char *reason_explanation(DecisionReason r) {
    switch (r) {
        case REASON_POLICY:
            return "This destination is not allowed by the access policy that applies to this proxy.";
        case REASON_NETWORK:
            return "This destination is on a private, local or otherwise restricted network, "
                   "which this proxy never connects to.";
        case REASON_REPUTATION:
            return "A threat-reputation check flagged this destination as unsafe.";
        case REASON_PORT:
            return "Secure tunnels are only permitted to the standard HTTPS port.";
        case REASON_NONE: break;
    }
    return "This request was blocked.";
}

size_t decision_build_block_response(char *out, size_t out_len, unsigned long request_id, DecisionReason reason) {
    /* Fixed text plus a number: nothing here is attacker-controlled, so no escaping is needed. */
    char body[1024];
    int blen = snprintf(body, sizeof(body),
                        "<!DOCTYPE html>\n"
                        "<html lang=\"en\">\n"
                        "<head><meta charset=\"utf-8\"><title>Request blocked</title></head>\n"
                        "<body>\n"
                        "<h1>Request blocked</h1>\n"
                        "<p><strong>Reason:</strong> <span id=\"reason\" data-reason=\"%s\">%s</span></p>\n"
                        "<p>%s</p>\n"
                        "<p>Request ID: <code id=\"request-id\">%lu</code></p>\n"
                        "<p>If you think this is a mistake, give the request ID to your administrator.</p>\n"
                        "</body>\n"
                        "</html>\n",
                        decision_reason_name(reason), reason_headline(reason), reason_explanation(reason), request_id);
    if (blen < 0 || (size_t)blen >= sizeof(body)) {
        return 0;
    }
    int hlen = snprintf(out, out_len,
                        "HTTP/1.1 403 Forbidden\r\n"
                        "Content-Type: text/html; charset=utf-8\r\n"
                        "Content-Length: %d\r\n"
                        "X-Request-Id: %lu\r\n"
                        "Cache-Control: no-store\r\n"
                        "X-Content-Type-Options: nosniff\r\n"
                        "Connection: close\r\n"
                        "\r\n",
                        blen, request_id);
    if (hlen < 0 || (size_t)hlen + (size_t)blen + 1 > out_len) {
        return 0;
    }
    memcpy(out + hlen, body, (size_t)blen + 1);
    return (size_t)hlen + (size_t)blen;
}
