/* reputation.c: Implements an offline fixture-based reputation provider so tests remain deterministic without a live threat-intelligence feed. */

#define _POSIX_C_SOURCE 200809L

#include "reputation.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define HOST_MAX 253

/* ---------- result cache ---------- */

typedef struct {
    char host[HOST_MAX + 2];
    ReputationVerdict verdict;
    time_t expires;
    uint64_t last_used;
    int used;
} CacheEntry;

static pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;
static int g_enabled = 0;
static ReputationProvider g_provider;
static unsigned g_timeout_ms = 1500;
static unsigned g_ttl_seconds = 300;
static CacheEntry g_cache[REPUTATION_CACHE_ENTRIES];
static uint64_t g_tick = 0;
static unsigned g_inflight = 0;
static ReputationStats g_stats;
static time_t g_fake_now = 0;

static time_t now_locked(void) {
    return g_fake_now != 0 ? g_fake_now : time(NULL);
}

void reputation_test_set_time(time_t now) {
    pthread_mutex_lock(&g_mutex);
    g_fake_now = now;
    pthread_mutex_unlock(&g_mutex);
}

const char *reputation_verdict_name(ReputationVerdict v) {
    switch (v) {
        case REP_SAFE: return "safe";
        case REP_SUSPICIOUS: return "suspicious";
        case REP_MALICIOUS: return "malicious";
        case REP_UNAVAILABLE: return "unavailable";
    }
    return "unavailable";
}

const char *reputation_reason_name(ReputationReason r) {
    switch (r) {
        case REP_REASON_OK: return "ok";
        case REP_REASON_CACHE: return "cache";
        case REP_REASON_TIMEOUT: return "timeout";
        case REP_REASON_ERROR: return "error";
        case REP_REASON_SATURATED: return "saturated";
        case REP_REASON_BAD_INPUT: return "bad_input";
    }
    return "error";
}

int reputation_init(const ReputationProvider *provider, unsigned timeout_ms, unsigned cache_ttl_seconds) {
    if (provider == NULL || provider->lookup == NULL || timeout_ms == 0) {
        return -1;
    }
    pthread_mutex_lock(&g_mutex);
    g_provider = *provider;
    g_timeout_ms = timeout_ms;
    g_ttl_seconds = cache_ttl_seconds;
    memset(g_cache, 0, sizeof(g_cache));
    memset(&g_stats, 0, sizeof(g_stats));
    g_tick = 0;
    g_enabled = 1;
    pthread_mutex_unlock(&g_mutex);
    return 0;
}

void reputation_shutdown(void) {
    pthread_mutex_lock(&g_mutex);
    g_enabled = 0;
    memset(&g_provider, 0, sizeof(g_provider));
    pthread_mutex_unlock(&g_mutex);
}

int reputation_is_enabled(void) {
    pthread_mutex_lock(&g_mutex);
    int e = g_enabled;
    pthread_mutex_unlock(&g_mutex);
    return e;
}

void reputation_get_stats(ReputationStats *out) {
    pthread_mutex_lock(&g_mutex);
    *out = g_stats;
    pthread_mutex_unlock(&g_mutex);
}

/* Lowercases, strips ONE trailing dot, and accepts only plain hostname characters.
 * This is the privacy gate: anything that is not a bare hostname (a URL, a path, a
 * query, "user:pass@host", a port, whitespace...) is refused and never leaves. */
static int normalise_host(const char *in, char *out, size_t out_len) {
    if (in == NULL) {
        return -1;
    }
    size_t n = strlen(in);
    if (n > 0 && in[n - 1] == '.') {
        n--;
    }
    if (n == 0 || n > HOST_MAX || n + 1 > out_len) {
        return -1;
    }
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)in[i];
        if (!(isalnum(c) || c == '.' || c == '-' || c == '_')) {
            return -1;
        }
        out[i] = (char)tolower(c);
    }
    out[n] = '\0';
    if (out[0] == '.' || strstr(out, "..") != NULL) {
        return -1;
    }
    return 0;
}

/* ---------- cache helpers (caller holds g_mutex) ---------- */

static CacheEntry *cache_find(const char *host) {
    for (size_t i = 0; i < REPUTATION_CACHE_ENTRIES; i++) {
        if (g_cache[i].used && strcmp(g_cache[i].host, host) == 0) {
            return &g_cache[i];
        }
    }
    return NULL;
}

static void cache_put(const char *host, ReputationVerdict v, unsigned ttl) {
    if (ttl == 0) {
        return;
    }
    CacheEntry *slot = cache_find(host);
    if (slot == NULL) {
        for (size_t i = 0; i < REPUTATION_CACHE_ENTRIES; i++) {
            if (!g_cache[i].used) {
                slot = &g_cache[i];
                break;
            }
            if (slot == NULL || g_cache[i].last_used < slot->last_used) {
                slot = &g_cache[i]; /* least recently used */
            }
        }
    }
    snprintf(slot->host, sizeof(slot->host), "%s", host);
    slot->verdict = v;
    slot->expires = now_locked() + (time_t)ttl;
    slot->last_used = ++g_tick;
    slot->used = 1;
}

/* ---------- timed provider call ---------- */

/* One lookup, shared by the waiting caller and the helper thread. Whoever drops the
 * last reference frees it, so a caller that gave up on a slow provider leaves no leak
 * and no dangling pointer behind. */
typedef struct {
    pthread_mutex_t m;
    pthread_cond_t c;
    int done;
    int refs;
    ReputationVerdict verdict;
    ReputationProvider provider;
    char host[HOST_MAX + 2];
} Job;

static void job_release(Job *j) {
    pthread_mutex_lock(&j->m);
    int left = --j->refs;
    pthread_mutex_unlock(&j->m);
    if (left == 0) {
        pthread_mutex_destroy(&j->m);
        pthread_cond_destroy(&j->c);
        free(j);
    }
}

static void *job_thread(void *arg) {
    Job *j = (Job *)arg;
    ReputationVerdict v = j->provider.lookup(j->provider.ctx, j->host);

    pthread_mutex_lock(&j->m);
    j->verdict = v;
    j->done = 1;
    pthread_cond_signal(&j->c);
    pthread_mutex_unlock(&j->m);

    pthread_mutex_lock(&g_mutex);
    g_inflight--; /* the provider call has REALLY finished, so the thread bound is honest */
    pthread_mutex_unlock(&g_mutex);

    job_release(j);
    return NULL;
}

ReputationResult reputation_check(const char *host) {
    ReputationResult res = {REP_UNAVAILABLE, REP_REASON_ERROR};
    char norm[HOST_MAX + 2];

    pthread_mutex_lock(&g_mutex);
    g_stats.lookups++;
    if (!g_enabled) {
        g_stats.errors++;
        g_stats.unavailable++;
        pthread_mutex_unlock(&g_mutex);
        return res;
    }
    if (normalise_host(host, norm, sizeof(norm)) != 0) {
        g_stats.rejected_input++;
        g_stats.unavailable++;
        pthread_mutex_unlock(&g_mutex);
        res.reason = REP_REASON_BAD_INPUT; /* NOT sent to the provider */
        return res;
    }

    CacheEntry *hit = cache_find(norm);
    if (hit != NULL && hit->expires > now_locked()) {
        hit->last_used = ++g_tick;
        res.verdict = hit->verdict;
        res.reason = REP_REASON_CACHE;
        g_stats.cache_hits++;
        if (res.verdict == REP_UNAVAILABLE) {
            g_stats.unavailable++;
        }
        pthread_mutex_unlock(&g_mutex);
        return res;
    }

    if (g_inflight >= REPUTATION_MAX_INFLIGHT) {
        g_stats.saturated++;
        g_stats.unavailable++;
        pthread_mutex_unlock(&g_mutex);
        res.reason = REP_REASON_SATURATED;
        return res;
    }
    g_inflight++;
    ReputationProvider provider = g_provider;
    unsigned timeout_ms = g_timeout_ms;
    unsigned ttl = g_ttl_seconds;
    g_stats.provider_calls++;
    pthread_mutex_unlock(&g_mutex);

    Job *j = calloc(1, sizeof(Job));
    int started = 0;
    if (j != NULL) {
        pthread_condattr_t attr;
        pthread_condattr_init(&attr);
        pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
        pthread_mutex_init(&j->m, NULL);
        pthread_cond_init(&j->c, &attr);
        pthread_condattr_destroy(&attr);
        j->refs = 2; /* the caller and the helper thread */
        j->provider = provider;
        snprintf(j->host, sizeof(j->host), "%s", norm);

        pthread_t tid;
        pthread_attr_t tattr;
        pthread_attr_init(&tattr);
        pthread_attr_setdetachstate(&tattr, PTHREAD_CREATE_DETACHED);
        started = (pthread_create(&tid, &tattr, job_thread, j) == 0);
        pthread_attr_destroy(&tattr);
    }
    if (!started) {
        if (j != NULL) {
            j->refs = 1;
            job_release(j);
        }
        pthread_mutex_lock(&g_mutex);
        g_inflight--;
        g_stats.errors++;
        g_stats.unavailable++;
        pthread_mutex_unlock(&g_mutex);
        return res; /* UNAVAILABLE / ERROR */
    }

    struct timespec deadline;
    clock_gettime(CLOCK_MONOTONIC, &deadline);
    deadline.tv_sec += timeout_ms / 1000;
    deadline.tv_nsec += (long)(timeout_ms % 1000) * 1000000L;
    if (deadline.tv_nsec >= 1000000000L) {
        deadline.tv_sec++;
        deadline.tv_nsec -= 1000000000L;
    }

    pthread_mutex_lock(&j->m);
    int rc = 0;
    while (!j->done && rc != ETIMEDOUT) {
        rc = pthread_cond_timedwait(&j->c, &j->m, &deadline);
    }
    int finished = j->done;
    ReputationVerdict v = j->verdict;
    pthread_mutex_unlock(&j->m);
    job_release(j); /* if we timed out, the helper thread frees it when the provider finally returns */

    unsigned cache_ttl = 0;
    if (!finished) {
        res.verdict = REP_UNAVAILABLE;
        res.reason = REP_REASON_TIMEOUT;
        cache_ttl = REPUTATION_NEGATIVE_TTL_SECONDS;
    } else if ((int)v < REP_SAFE || (int)v > REP_UNAVAILABLE) {
        res.verdict = REP_UNAVAILABLE; /* a provider returning nonsense is a failure, not a verdict */
        res.reason = REP_REASON_ERROR;
        cache_ttl = REPUTATION_NEGATIVE_TTL_SECONDS;
    } else if (v == REP_UNAVAILABLE) {
        res.verdict = REP_UNAVAILABLE;
        res.reason = REP_REASON_ERROR;
        cache_ttl = REPUTATION_NEGATIVE_TTL_SECONDS;
    } else {
        res.verdict = v;
        res.reason = REP_REASON_OK;
        cache_ttl = ttl;
    }

    pthread_mutex_lock(&g_mutex);
    if (g_enabled) {
        cache_put(norm, res.verdict, cache_ttl);
    }
    switch (res.verdict) {
        case REP_SAFE: g_stats.safe++; break;
        case REP_SUSPICIOUS: g_stats.suspicious++; break;
        case REP_MALICIOUS: g_stats.malicious++; break;
        case REP_UNAVAILABLE: g_stats.unavailable++; break;
    }
    if (res.reason == REP_REASON_TIMEOUT) {
        g_stats.timeouts++;
    } else if (res.reason == REP_REASON_ERROR) {
        g_stats.errors++;
    }
    pthread_mutex_unlock(&g_mutex);
    return res;
}

/* ---------- offline fixture provider ---------- */

typedef enum { FX_SAFE, FX_SUSPICIOUS, FX_MALICIOUS, FX_UNAVAILABLE, FX_TIMEOUT } FixtureVerdict;

typedef struct {
    char host[HOST_MAX + 2];
    int include_subdomains;
    FixtureVerdict verdict;
} FixtureRule;

typedef struct {
    FixtureRule *rules;
    size_t count;
    char query_log[512];
} FixtureData;

static int fixture_verdict_from_text(const char *t, FixtureVerdict *out) {
    static const struct {
        const char *name;
        FixtureVerdict v;
    } map[] = {{"safe", FX_SAFE},       {"suspicious", FX_SUSPICIOUS}, {"malicious", FX_MALICIOUS},
               {"unavailable", FX_UNAVAILABLE}, {"timeout", FX_TIMEOUT}};
    for (size_t i = 0; i < sizeof(map) / sizeof(map[0]); i++) {
        if (strcmp(t, map[i].name) == 0) {
            *out = map[i].v;
            return 0;
        }
    }
    return -1;
}

static void fixture_log_query(const FixtureData *d, const char *host) {
    if (d->query_log[0] == '\0') {
        return;
    }
    int fd = open(d->query_log, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (fd >= 0) {
        char line[HOST_MAX + 4];
        int n = snprintf(line, sizeof(line), "%s\n", host);
        if (n > 0 && write(fd, line, (size_t)n) < 0) {
            /* test hook only: ignore a failed write */
        }
        close(fd);
    }
}

static ReputationVerdict fixture_lookup(void *ctx, const char *host) {
    const FixtureData *d = (const FixtureData *)ctx;
    fixture_log_query(d, host);

    FixtureVerdict found = FX_SAFE; /* unlisted hosts are safe */
    for (size_t i = 0; i < d->count; i++) {
        const FixtureRule *r = &d->rules[i];
        size_t hl = strlen(host), rl = strlen(r->host);
        int match = (strcmp(host, r->host) == 0) ||
                    (r->include_subdomains && hl > rl + 1 && host[hl - rl - 1] == '.' &&
                     strcmp(host + (hl - rl), r->host) == 0);
        if (match) {
            found = r->verdict;
            break;
        }
    }
    switch (found) {
        case FX_SAFE: return REP_SAFE;
        case FX_SUSPICIOUS: return REP_SUSPICIOUS;
        case FX_MALICIOUS: return REP_MALICIOUS;
        case FX_UNAVAILABLE: return REP_UNAVAILABLE;
        case FX_TIMEOUT:
            sleep(FIXTURE_SLOW_SECONDS); /* a provider that answers far too late */
            return REP_SAFE;
    }
    return REP_UNAVAILABLE;
}

int reputation_fixture_load(const char *path, const char *query_log_path, ReputationProvider *out,
                            size_t *malformed_lines) {
    size_t bad = 0;
    FILE *f = fopen(path, "r");
    if (f == NULL) {
        return -1;
    }
    FixtureData *d = calloc(1, sizeof(FixtureData));
    if (d == NULL) {
        fclose(f);
        return -1;
    }
    if (query_log_path != NULL) {
        snprintf(d->query_log, sizeof(d->query_log), "%s", query_log_path);
    }

    char line[1024];
    while (fgets(line, sizeof(line), f) != NULL) {
        char *hash = strchr(line, '#');
        if (hash != NULL) {
            *hash = '\0';
        }
        char host[HOST_MAX + 2], verdict[32], extra[8];
        int n = sscanf(line, "%254s %31s %7s", host, verdict, extra);
        if (n <= 0) {
            continue; /* blank or comment-only */
        }
        FixtureRule rule;
        memset(&rule, 0, sizeof(rule));
        char *h = host;
        if (h[0] == '.') {
            rule.include_subdomains = 1;
            h++;
        }
        char norm[HOST_MAX + 2];
        if (n != 2 || normalise_host(h, norm, sizeof(norm)) != 0 ||
            fixture_verdict_from_text(verdict, &rule.verdict) != 0) {
            bad++;
            continue;
        }
        snprintf(rule.host, sizeof(rule.host), "%s", norm);
        FixtureRule *grown = realloc(d->rules, (d->count + 1) * sizeof(FixtureRule));
        if (grown == NULL) {
            free(d->rules);
            free(d);
            fclose(f);
            return -1;
        }
        d->rules = grown;
        d->rules[d->count++] = rule;
    }
    fclose(f);

    out->name = "offline-fixture";
    out->lookup = fixture_lookup;
    out->ctx = d;
    if (malformed_lines != NULL) {
        *malformed_lines = bad;
    }
    return 0;
}

void reputation_fixture_free(ReputationProvider *provider) {
    if (provider != NULL && provider->ctx != NULL) {
        FixtureData *d = (FixtureData *)provider->ctx;
        free(d->rules);
        free(d);
        provider->ctx = NULL;
    }
}
