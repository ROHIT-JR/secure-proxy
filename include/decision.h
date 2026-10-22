#pragma once
/* decision.h: Declares the explainable risk scoring that combines policy, network-safety, and reputation outcomes into one documented decision and a safe, human-readable block page. */

#include "reputation.h"

#include <stddef.h>

/*
 * Why a request is blocked, as a SAFE category. These are the only reasons a
 * client is ever told; the technical detail (which rule, which address, what the
 * provider said) stays in the server log.
 */
typedef enum {
    REASON_NONE = 0,    /* not blocked */
    REASON_POLICY,      /* the access policy (blocklist / allowlist) refused the destination */
    REASON_NETWORK,     /* the destination is on a private, local or otherwise restricted network */
    REASON_REPUTATION,  /* a threat-reputation check flagged the destination as unsafe */
    REASON_PORT         /* a tunnel was requested to a port other than the HTTPS port */
} DecisionReason;

typedef enum { DECISION_ALLOW = 0, DECISION_BLOCK } DecisionAction;

/* Everything that was learned about a request so far. Unknown signals stay at their defaults. */
typedef struct {
    int policy_denied;          /* 1 = blocklist, or not on the allowlist */
    int network_unsafe;         /* 1 = private / loopback / link-local / metadata / local name */
    int port_denied;            /* 1 = CONNECT to a port that is not allowed */
    int reputation_checked;     /* 1 if `reputation` holds a real answer */
    ReputationVerdict reputation;
} DecisionInputs;

typedef struct {
    DecisionAction action;
    DecisionReason reason;      /* REASON_NONE when allowed */
    int risk_score;             /* 0..100, higher is riskier */
} Decision;

/* Risk scores (documented in docs/risk-scoring.md). */
#define RISK_BLOCKED_BY_RULE 100   /* policy, network safety and port rules are absolute */
#define RISK_REPUTATION_MALICIOUS 90
#define RISK_REPUTATION_SUSPICIOUS 50
#define RISK_REPUTATION_UNAVAILABLE 10
#define RISK_REPUTATION_SAFE 0
#define DECISION_BLOCK_THRESHOLD 80 /* a score at or above this blocks the request */

/*
 * Combines the signals into one decision:
 *   risk score = the HIGHEST score of any signal (so adding a "safe" signal can never
 *                lower the risk of something already dangerous);
 *   blocked    = score >= DECISION_BLOCK_THRESHOLD;
 *   reason     = the signal that produced the highest score; when two signals tie, the
 *                order is port, policy, network, reputation.
 * Pure function: no I/O, no global state.
 */
Decision decision_evaluate(const DecisionInputs *in);

/* The risk score contributed by a reputation verdict alone. */
int decision_score_reputation(ReputationVerdict v);

/* Short stable word for logs, e.g. "policy". */
const char *decision_reason_name(DecisionReason r);

/*
 * Writes a complete HTTP response ("403 Forbidden", text/html, with the request ID and the
 * safe reason category, and nothing else) into `out`. The page contains only fixed text and
 * the numeric request ID, so there is nothing a client can inject into it and nothing about
 * the proxy's configuration, rules, providers or internal addresses to read from it.
 * Returns the number of bytes written, or 0 if `out` is too small (2048 bytes is always enough).
 */
size_t decision_build_block_response(char *out, size_t out_len, unsigned long request_id, DecisionReason reason);
