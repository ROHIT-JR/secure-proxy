#pragma once
/* reputation.h: Declares the ReputationProvider interface used to classify a host as safe, suspicious, malicious, or unavailable. */

#include <stddef.h>
#include <time.h>

typedef enum {
    REP_SAFE = 0,
    REP_SUSPICIOUS,
    REP_MALICIOUS,
    REP_UNAVAILABLE /* the provider could not answer: an observable EVENT, never an assumption of "malicious" */
} ReputationVerdict;

/*
 * A reputation source. Implementations receive ONLY a validated, lowercase
 * hostname -- never a URL, path, query string, credentials, request body or
 * user identifier. The framework enforces that before calling lookup().
 *
 * lookup() may be slow or fail; the framework applies a timeout, so an
 * implementation does not need its own. It must be safe to call from several
 * threads at once and must tolerate being called after the proxy gave up
 * waiting for an earlier call.
 */
typedef struct {
    const char *name;
    ReputationVerdict (*lookup)(void *ctx, const char *host);
    void *ctx;
} ReputationProvider;

/* Why a result is what it is -- logged and counted so outages are visible. */
typedef enum {
    REP_REASON_OK = 0,      /* the provider answered */
    REP_REASON_CACHE,       /* answered from the result cache */
    REP_REASON_TIMEOUT,     /* the provider took too long */
    REP_REASON_ERROR,       /* the provider failed, returned nonsense, or a thread could not start */
    REP_REASON_SATURATED,   /* too many lookups already outstanding; this one was not attempted */
    REP_REASON_BAD_INPUT    /* the host is not a plain hostname; it was NOT sent to the provider */
} ReputationReason;

typedef struct {
    ReputationVerdict verdict;
    ReputationReason reason;
} ReputationResult;

typedef struct {
    unsigned long lookups;      /* reputation_check() calls */
    unsigned long provider_calls;
    unsigned long cache_hits;
    unsigned long timeouts;
    unsigned long errors;
    unsigned long saturated;
    unsigned long rejected_input;
    unsigned long safe, suspicious, malicious, unavailable;
} ReputationStats;

#define REPUTATION_MAX_INFLIGHT 16     /* provider calls allowed to be outstanding at once */
#define REPUTATION_CACHE_ENTRIES 256
#define REPUTATION_NEGATIVE_TTL_SECONDS 5  /* how long a timeout/error is remembered */

/*
 * Enables reputation checking with `provider` (copied). Results are cached for
 * cache_ttl_seconds. Returns 0 on success. Call before worker threads start.
 */
int reputation_init(const ReputationProvider *provider, unsigned timeout_ms, unsigned cache_ttl_seconds);
void reputation_shutdown(void);
int reputation_is_enabled(void);

/*
 * Classifies `host`. Never blocks longer than the configured timeout (plus a
 * little scheduling slack), never crashes on a failing provider, and returns
 * REP_UNAVAILABLE -- with a reason -- instead of guessing when it cannot answer.
 * Thread-safe.
 */
ReputationResult reputation_check(const char *host);

void reputation_get_stats(ReputationStats *out);
const char *reputation_verdict_name(ReputationVerdict v);
const char *reputation_reason_name(ReputationReason r);

/* TESTING ONLY: make the result cache believe it is `now` (0 restores the real clock). */
void reputation_test_set_time(time_t now);

/* ---------- Offline fixture provider (deterministic; the default test mode) ---------- */

/*
 * Reads rules "host verdict" (one per line, '#' comments). verdict is one of:
 *   safe | suspicious | malicious | unavailable | timeout
 * `timeout` makes the provider answer only after FIXTURE_SLOW_SECONDS, to
 * exercise the timeout path. A host beginning with '.' also covers its
 * subdomains. Hosts not listed are "safe". Returns 0 on success.
 * If query_log_path is not NULL, every host the provider is asked about is
 * appended to that file (so tests can prove nothing but a hostname is sent).
 */
#define FIXTURE_SLOW_SECONDS 3
int reputation_fixture_load(const char *path, const char *query_log_path, ReputationProvider *out,
                            size_t *malformed_lines);
void reputation_fixture_free(ReputationProvider *provider);
