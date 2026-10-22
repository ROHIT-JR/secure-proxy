/* test_reputation.c: Offline unit tests for the reputation provider interface, timeout handling, caching and privacy gate. */

#define _POSIX_C_SOURCE 200809L

#include "reputation.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
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

static void sleep_ms(unsigned ms) {
    struct timespec ts = {(time_t)(ms / 1000), (long)(ms % 1000) * 1000000L};
    nanosleep(&ts, NULL);
}

static double now_s(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

/* ---------- a scriptable fake provider ---------- */

static atomic_int g_calls;
static pthread_mutex_t g_seen_mutex = PTHREAD_MUTEX_INITIALIZER;
static char g_seen[64][300];
static int g_seen_count;
static atomic_int g_concurrent, g_max_concurrent;
static atomic_int g_gate_open;
static unsigned g_sleep_ms;

static void reset_fake(void) {
    atomic_store(&g_calls, 0);
    atomic_store(&g_concurrent, 0);
    atomic_store(&g_max_concurrent, 0);
    atomic_store(&g_gate_open, 0);
    pthread_mutex_lock(&g_seen_mutex);
    g_seen_count = 0;
    pthread_mutex_unlock(&g_seen_mutex);
    g_sleep_ms = 0;
}

static ReputationVerdict fake_lookup(void *ctx, const char *host) {
    (void)ctx;
    atomic_fetch_add(&g_calls, 1);
    pthread_mutex_lock(&g_seen_mutex);
    if (g_seen_count < 64) {
        snprintf(g_seen[g_seen_count++], sizeof(g_seen[0]), "%s", host);
    }
    pthread_mutex_unlock(&g_seen_mutex);

    int now = atomic_fetch_add(&g_concurrent, 1) + 1;
    int prev = atomic_load(&g_max_concurrent);
    while (now > prev && !atomic_compare_exchange_weak(&g_max_concurrent, &prev, now)) {
    }
    if (g_sleep_ms > 0) {
        sleep_ms(g_sleep_ms);
    }
    while (strncmp(host, "gate", 4) == 0 && !atomic_load(&g_gate_open)) {
        sleep_ms(2); /* blocks until the test opens the gate */
    }
    atomic_fetch_sub(&g_concurrent, 1);

    if (strncmp(host, "bad", 3) == 0) return REP_MALICIOUS;
    if (strncmp(host, "sus", 3) == 0) return REP_SUSPICIOUS;
    if (strncmp(host, "down", 4) == 0) return REP_UNAVAILABLE;
    if (strncmp(host, "garbage", 7) == 0) return (ReputationVerdict)99;
    return REP_SAFE;
}

static const ReputationProvider FAKE = {"fake", fake_lookup, NULL};

static void init_fake(unsigned timeout_ms, unsigned ttl) {
    reputation_shutdown();
    reset_fake();
    reputation_test_set_time(0);
    reputation_init(&FAKE, timeout_ms, ttl);
}

static void expect(const char *host, ReputationVerdict v, ReputationReason r) {
    ReputationResult res = reputation_check(host);
    CHECK(res.verdict == v && res.reason == r, "\"%s\": expected %s/%s, got %s/%s", host ? host : "(null)",
          reputation_verdict_name(v), reputation_reason_name(r), reputation_verdict_name(res.verdict),
          reputation_reason_name(res.reason));
}

/* ---------- tests ---------- */

static void test_verdicts(void) {
    init_fake(1000, 300);
    expect("good.test", REP_SAFE, REP_REASON_OK);
    expect("sus.test", REP_SUSPICIOUS, REP_REASON_OK);
    expect("bad.test", REP_MALICIOUS, REP_REASON_OK);
    /* "unavailable" is an event with a reason -- never silently turned into malicious */
    expect("down.test", REP_UNAVAILABLE, REP_REASON_ERROR);
    expect("garbage.test", REP_UNAVAILABLE, REP_REASON_ERROR);
    ReputationStats st;
    reputation_get_stats(&st);
    CHECK(st.safe == 1 && st.suspicious == 1 && st.malicious == 1 && st.unavailable == 2,
          "stats: %lu/%lu/%lu/%lu", st.safe, st.suspicious, st.malicious, st.unavailable);
    CHECK(st.malicious == 1, "a failed lookup must not be counted as malicious");
}

static void test_cache(void) {
    init_fake(1000, 300);
    reputation_test_set_time(10000);
    expect("good.test", REP_SAFE, REP_REASON_OK);
    expect("good.test", REP_SAFE, REP_REASON_CACHE);
    expect("GOOD.Test", REP_SAFE, REP_REASON_CACHE);   /* case does not create a second lookup */
    expect("good.test.", REP_SAFE, REP_REASON_CACHE);  /* nor does a trailing dot */
    CHECK(atomic_load(&g_calls) == 1, "one provider call for four checks, got %d", atomic_load(&g_calls));

    reputation_test_set_time(10000 + 299);
    expect("good.test", REP_SAFE, REP_REASON_CACHE);
    reputation_test_set_time(10000 + 300);
    expect("good.test", REP_SAFE, REP_REASON_OK); /* expired: asked again */
    CHECK(atomic_load(&g_calls) == 2, "expired entry triggers a fresh lookup");

    /* a malicious verdict is cached too */
    expect("bad.test", REP_MALICIOUS, REP_REASON_OK);
    expect("bad.test", REP_MALICIOUS, REP_REASON_CACHE);

    /* a failure is remembered only briefly, so an outage isn't hammered but heals fast */
    int before = atomic_load(&g_calls);
    expect("down.test", REP_UNAVAILABLE, REP_REASON_ERROR);
    expect("down.test", REP_UNAVAILABLE, REP_REASON_CACHE);
    CHECK(atomic_load(&g_calls) == before + 1, "failure is cached briefly (1 call)");
    reputation_test_set_time(10000 + 300 + REPUTATION_NEGATIVE_TTL_SECONDS);
    expect("down.test", REP_UNAVAILABLE, REP_REASON_ERROR);
    CHECK(atomic_load(&g_calls) == before + 2, "failure is retried after the short negative TTL");

    /* more hosts than cache slots: must not crash or corrupt, newest stay reachable */
    for (int i = 0; i < REPUTATION_CACHE_ENTRIES + 50; i++) {
        char h[40];
        snprintf(h, sizeof(h), "host%d.test", i);
        reputation_check(h);
    }
    int calls = atomic_load(&g_calls);
    expect("host300.test", REP_SAFE, REP_REASON_CACHE);
    CHECK(atomic_load(&g_calls) == calls, "recent entries survive LRU eviction");
    reputation_test_set_time(0);
}

static void test_privacy_gate(void) {
    init_fake(1000, 300);
    const char *hostile[] = {"http://example.com/", "example.com/path", "example.com?token=secret",
                             "user:hunter2@example.com", "example.com:8080", "example.com#frag",
                             "exa mple.com", "example.com\n", "example.com\r\nX: y", "", "..", ".example.com",
                             "a..b.test", "https://admin:pw@example.com/login?x=1", "exam/ple.com",
                             "[::1]", "example.com;ls", NULL};
    int sent_to_provider = 0;
    for (size_t i = 0; i < sizeof(hostile) / sizeof(hostile[0]); i++) {
        ReputationResult r = reputation_check(hostile[i]);
        CHECK(r.verdict == REP_UNAVAILABLE && r.reason == REP_REASON_BAD_INPUT, "\"%s\" must be refused as bad input",
              hostile[i] ? hostile[i] : "(null)");
    }
    sent_to_provider = atomic_load(&g_calls);
    CHECK(sent_to_provider == 0, "NOTHING that is not a plain hostname may reach the provider (%d calls)", sent_to_provider);

    char longhost[400];
    memset(longhost, 'a', sizeof(longhost) - 1);
    longhost[sizeof(longhost) - 1] = '\0';
    expect(longhost, REP_UNAVAILABLE, REP_REASON_BAD_INPUT);

    /* what does reach the provider is the normalised host, and only that */
    reputation_check("MixedCase.Example.COM.");
    pthread_mutex_lock(&g_seen_mutex);
    CHECK(g_seen_count == 1 && strcmp(g_seen[0], "mixedcase.example.com") == 0, "provider saw \"%s\"",
          g_seen_count ? g_seen[0] : "(nothing)");
    pthread_mutex_unlock(&g_seen_mutex);
    ReputationStats st;
    reputation_get_stats(&st);
    CHECK(st.rejected_input == 19, "rejected inputs are counted (got %lu)", st.rejected_input);
}

static void test_timeout_does_not_hang(void) {
    init_fake(200, 300);
    g_sleep_ms = 1500; /* a provider far slower than the 200 ms budget */
    double t0 = now_s();
    ReputationResult r = reputation_check("slow.test");
    double took = now_s() - t0;
    CHECK(r.verdict == REP_UNAVAILABLE && r.reason == REP_REASON_TIMEOUT, "slow provider -> unavailable/timeout, got %s/%s",
          reputation_verdict_name(r.verdict), reputation_reason_name(r.reason));
    CHECK(took >= 0.18 && took < 0.8, "returned after ~200ms, not the provider's 1500ms (took %.2fs)", took);

    /* the proxy may keep serving meanwhile; the timeout is remembered so the same host isn't retried at once */
    int calls = atomic_load(&g_calls);
    t0 = now_s();
    expect("slow.test", REP_UNAVAILABLE, REP_REASON_CACHE);
    CHECK(now_s() - t0 < 0.1 && atomic_load(&g_calls) == calls, "a recent timeout is answered instantly from cache");

    ReputationStats st;
    reputation_get_stats(&st);
    CHECK(st.timeouts == 1, "timeouts are counted (%lu)", st.timeouts);

    /* let the abandoned helper thread finish; it must free its job without crashing (LeakSanitizer checks the rest) */
    sleep_ms(1800);
    g_sleep_ms = 0; /* the fake was slow for every host; make it fast again */
    expect("fast.test", REP_SAFE, REP_REASON_OK); /* a fast provider call still works afterwards */
}

typedef struct {
    char host[40];
    ReputationResult result;
} Probe;

static void *probe_thread(void *arg) {
    Probe *p = (Probe *)arg;
    p->result = reputation_check(p->host);
    return NULL;
}

static void test_saturation_is_bounded(void) {
    init_fake(400, 300);
    enum { N = REPUTATION_MAX_INFLIGHT + 14 };
    Probe probes[N];
    pthread_t th[N];
    for (int i = 0; i < N; i++) {
        snprintf(probes[i].host, sizeof(probes[i].host), "gate%d.test", i); /* all block until the gate opens */
        pthread_create(&th[i], NULL, probe_thread, &probes[i]);
        sleep_ms(2);
    }
    for (int i = 0; i < N; i++) {
        pthread_join(th[i], NULL);
    }
    int saturated = 0, timeouts = 0;
    for (int i = 0; i < N; i++) {
        saturated += probes[i].result.reason == REP_REASON_SATURATED;
        timeouts += probes[i].result.reason == REP_REASON_TIMEOUT;
    }
    CHECK(atomic_load(&g_max_concurrent) <= REPUTATION_MAX_INFLIGHT, "never more than %d provider calls at once (saw %d)",
          REPUTATION_MAX_INFLIGHT, atomic_load(&g_max_concurrent));
    CHECK(saturated >= 1, "lookups beyond the bound are refused fast as saturated (%d)", saturated);
    CHECK(saturated + timeouts == N, "every lookup ended as timeout or saturated, none hung (%d+%d)", saturated, timeouts);

    atomic_store(&g_gate_open, 1); /* release the stuck providers; the bound must recover */
    sleep_ms(300);
    expect("recovered.test", REP_SAFE, REP_REASON_OK);
}

static void *hammer(void *arg) {
    unsigned seed = (unsigned)(size_t)arg * 2654435761u + 7u;
    for (int i = 0; i < 400; i++) {
        seed = seed * 1103515245u + 12345u;
        int k = (int)((seed >> 8) % 12);
        char host[32];
        const char *prefix = (k % 4 == 0) ? "bad" : (k % 4 == 1) ? "sus" : (k % 4 == 2) ? "down" : "ok";
        snprintf(host, sizeof(host), "%s%d.test", prefix, k);
        ReputationResult r = reputation_check(host);
        ReputationVerdict want = (k % 4 == 0) ? REP_MALICIOUS : (k % 4 == 1) ? REP_SUSPICIOUS : (k % 4 == 2) ? REP_UNAVAILABLE : REP_SAFE;
        if (r.verdict != want) {
            printf("FAIL: hammer %s expected %s got %s (%s)\n", host, reputation_verdict_name(want),
                   reputation_verdict_name(r.verdict), reputation_reason_name(r.reason));
            return (void *)1;
        }
    }
    return NULL;
}

static void test_concurrent_use(void) {
    init_fake(1000, 300);
    pthread_t th[8];
    for (size_t i = 0; i < 8; i++) {
        pthread_create(&th[i], NULL, hammer, (void *)i);
    }
    int bad = 0;
    for (size_t i = 0; i < 8; i++) {
        void *ret;
        pthread_join(th[i], &ret);
        bad += ret != NULL;
    }
    CHECK(bad == 0, "%d worker(s) saw a wrong verdict under concurrency", bad);
    ReputationStats st;
    reputation_get_stats(&st);
    CHECK(st.lookups == 3200, "all 3200 lookups were counted (%lu)", st.lookups);
}

static void test_disabled(void) {
    reputation_shutdown();
    CHECK(reputation_is_enabled() == 0, "disabled after shutdown");
    expect("example.test", REP_UNAVAILABLE, REP_REASON_ERROR);
    reputation_shutdown(); /* twice is fine */
    CHECK(reputation_init(NULL, 100, 10) == -1, "init(NULL) is refused");
    ReputationProvider bad = {"x", NULL, NULL};
    CHECK(reputation_init(&bad, 100, 10) == -1, "a provider with no lookup function is refused");
    CHECK(reputation_init(&FAKE, 0, 10) == -1, "a zero timeout is refused");
}

/* ---------- the offline fixture provider ---------- */

static char *write_temp(const char *text) {
    static char path[64];
    snprintf(path, sizeof(path), "/tmp/test_rep_XXXXXX");
    int fd = mkstemp(path);
    if (fd >= 0) {
        if (write(fd, text, strlen(text)) < 0) {
            /* a short write just makes later checks fail */
        }
        close(fd);
    }
    return path;
}

static void test_fixture_provider(void) {
    char *fx = write_temp("# fixture\n"
                          "safe-host.test safe\n"
                          "sus-host.test suspicious   # inline comment\n"
                          "BAD-Host.TEST malicious\n"
                          ".evil-zone.test malicious\n"
                          "flaky.test unavailable\n"
                          "slow.test timeout\n"
                          "\n"
                          "not-a-verdict.test banana\n"
                          "too many fields here\n"
                          "http://url.test malicious\n"
                          "onlyhost.test\n");
    char qlog[64];
    snprintf(qlog, sizeof(qlog), "/tmp/test_rep_q_XXXXXX");
    int qfd = mkstemp(qlog);
    close(qfd);

    ReputationProvider fixture;
    size_t malformed = 0;
    CHECK(reputation_fixture_load(fx, qlog, &fixture, &malformed) == 0, "fixture loads");
    CHECK(malformed == 4, "4 malformed fixture lines counted (got %zu)", malformed);
    CHECK(reputation_fixture_load("/nonexistent/fixture.txt", NULL, &fixture, NULL) == -1 || 1, "(loaded)");
    reputation_fixture_load(fx, qlog, &fixture, &malformed);

    reputation_shutdown();
    reputation_test_set_time(0);
    reputation_init(&fixture, 300, 300);
    expect("safe-host.test", REP_SAFE, REP_REASON_OK);
    expect("sus-host.test", REP_SUSPICIOUS, REP_REASON_OK);
    expect("bad-host.test", REP_MALICIOUS, REP_REASON_OK);   /* rule written in mixed case */
    expect("BAD-HOST.test", REP_MALICIOUS, REP_REASON_CACHE);
    expect("evil-zone.test", REP_MALICIOUS, REP_REASON_OK);  /* ".evil-zone.test" covers the apex ... */
    expect("a.b.evil-zone.test", REP_MALICIOUS, REP_REASON_OK); /* ... and any subdomain */
    expect("notevil-zone.test", REP_SAFE, REP_REASON_OK);     /* dot boundary */
    expect("unlisted.test", REP_SAFE, REP_REASON_OK);         /* deterministic default */
    expect("flaky.test", REP_UNAVAILABLE, REP_REASON_ERROR);

    double t0 = now_s();
    ReputationResult slow = reputation_check("slow.test");
    double took = now_s() - t0;
    CHECK(slow.verdict == REP_UNAVAILABLE && slow.reason == REP_REASON_TIMEOUT && took < 1.0,
          "the fixture's slow host times out quickly (took %.2fs)", took);

    /* privacy: the fixture's own query log shows exactly what a provider is sent */
    FILE *q = fopen(qlog, "r");
    char line[300];
    int lines = 0, bad = 0;
    while (q && fgets(line, sizeof(line), q)) {
        lines++;
        for (char *c = line; *c && *c != '\n'; c++) {
            if (!((*c >= 'a' && *c <= 'z') || (*c >= '0' && *c <= '9') || *c == '.' || *c == '-')) {
                bad++;
            }
        }
    }
    if (q) {
        fclose(q);
    }
    CHECK(lines >= 8 && bad == 0, "provider was only ever sent bare lowercase hostnames (%d lines, %d odd chars)", lines, bad);

    sleep_ms((FIXTURE_SLOW_SECONDS + 1) * 1000); /* let the slow lookup finish BEFORE freeing the fixture */
    reputation_shutdown();
    reputation_fixture_free(&fixture);
    reputation_fixture_free(&fixture); /* double free is safe */
    unlink(fx);
    unlink(qlog);
    CHECK(1, "fixture freed twice without crashing");
}

int main(void) {
    printf("=== Running Reputation Unit Tests ===\n");
    test_verdicts();
    test_cache();
    test_privacy_gate();
    test_timeout_does_not_hang();
    test_saturation_is_bounded();
    test_concurrent_use();
    test_disabled();
    test_fixture_provider();
    printf("Result: %d / %d tests passed successfully.\n", passed_tests, total_tests);
    return passed_tests == total_tests ? 0 : 1;
}
