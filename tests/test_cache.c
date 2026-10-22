/* test_cache.c: Unit tests for the bounded response cache (LRU eviction, expiry, eligibility rules, thread safety). */

#define _POSIX_C_SOURCE 200809L

#include "cache.h"

#include <pthread.h>
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

static int has(const char *key) {
    size_t n;
    unsigned char *p = cache_lookup(key, &n);
    free(p);
    return p != NULL;
}

static void put(const char *key, size_t len) {
    unsigned char *buf = malloc(len > 0 ? len : 1);
    memset(buf, key[0], len);
    cache_store(key, buf, len, 60);
    free(buf);
}

static void test_basic_roundtrip_and_miss(void) {
    cache_init(8, 1024, 512);
    const unsigned char data[] = "HTTP/1.0 200 OK\r\n\r\nhello";
    CHECK(cache_store("k1", data, sizeof(data) - 1, 60) == 0, "store should succeed");
    size_t n = 0;
    unsigned char *got = cache_lookup("k1", &n);
    CHECK(got != NULL && n == sizeof(data) - 1 && memcmp(got, data, n) == 0, "lookup returns identical bytes");
    free(got);
    CHECK(cache_lookup("nope", &n) == NULL && n == 0, "unknown key is a miss");

    /* the returned buffer is a private copy: mutating it must not change the cache */
    got = cache_lookup("k1", &n);
    got[0] = 'X';
    free(got);
    got = cache_lookup("k1", &n);
    CHECK(got != NULL && got[0] == 'H', "cache content is isolated from returned copies");
    free(got);

    CacheStats st;
    cache_get_stats(&st);
    CHECK(st.hits == 3 && st.misses == 1 && st.stores == 1 && st.entries == 1,
          "stats: hits=%lu misses=%lu stores=%lu entries=%zu", st.hits, st.misses, st.stores, st.entries);
    cache_destroy();
}

static void test_disabled_cache_is_safe(void) {
    cache_destroy(); /* make sure it is off */
    size_t n;
    CHECK(cache_is_enabled() == 0, "not enabled before init");
    CHECK(cache_lookup("k", &n) == NULL, "lookup on a disabled cache is a miss");
    CHECK(cache_store("k", (const unsigned char *)"x", 1, 60) == -1, "store on a disabled cache is rejected");
    cache_destroy(); /* double destroy */
    CHECK(1, "double cache_destroy did not crash");
}

static void test_lru_eviction_by_entry_count(void) {
    cache_init(3, 100000, 1000);
    put("a", 10);
    put("b", 10);
    put("c", 10);
    CHECK(has("a"), "a present"); /* touching a makes it the MOST recently used; b is now the oldest */
    put("d", 10);                 /* must evict the least recently used: b (FIFO would wrongly drop a) */
    CHECK(has("a") && !has("b") && has("c") && has("d"), "LRU evicts b, not the recently used a");
    CacheStats st;
    cache_get_stats(&st);
    CHECK(st.evictions == 1 && st.entries == 3, "1 eviction, 3 entries (got %lu, %zu)", st.evictions, st.entries);
    cache_destroy();
}

static void test_eviction_by_total_bytes(void) {
    cache_init(100, 100, 100); /* only 100 bytes in total */
    put("a", 40);
    put("b", 40);
    CacheStats st;
    cache_get_stats(&st);
    CHECK(st.bytes == 80, "80 bytes stored, got %zu", st.bytes);
    put("c", 40); /* 120 > 100: oldest (a) must go */
    cache_get_stats(&st);
    CHECK(!has("a") && has("b") && has("c") && st.bytes == 80, "a evicted to stay under the byte bound (bytes=%zu)", st.bytes);
    put("d", 90); /* needs nearly everything: evicts until it fits */
    cache_get_stats(&st);
    CHECK(st.bytes <= 100 && has("d"), "never exceeds the total bound (bytes=%zu)", st.bytes);
    cache_destroy();
}

static void test_entry_size_limit_and_replace(void) {
    cache_init(8, 1000, 50);
    unsigned char big[51];
    memset(big, 'z', sizeof(big));
    CHECK(cache_store("big", big, 51, 60) == -1, "an entry over the per-entry limit is rejected");
    CHECK(!has("big"), "rejected entry is not stored");
    CHECK(cache_store("ok", big, 50, 60) == 0, "an entry exactly at the limit is accepted");

    put("r", 10);
    put("r", 20); /* same key again: replaces, does not duplicate */
    CacheStats st;
    cache_get_stats(&st);
    size_t n = 0;
    unsigned char *got = cache_lookup("r", &n);
    CHECK(n == 20, "replacement keeps the newest value (len %zu)", n);
    free(got);
    CHECK(st.entries == 2 && st.bytes == 70, "no duplicate entry / byte leak (entries=%zu bytes=%zu)", st.entries, st.bytes);
    CHECK(cache_store("zero", (const unsigned char *)"", 0, 60) == 0 && has("zero"), "zero-length body is storable");
    CHECK(cache_store("ttl0", big, 5, 0) == -1, "a zero lifetime is rejected");
    cache_destroy();
}

static void test_expiry(void) {
    cache_init(8, 1000, 100);
    cache_test_set_time(1000);
    cache_store("e", (const unsigned char *)"data", 4, 10);
    cache_test_set_time(1009);
    CHECK(has("e"), "still fresh 9s into a 10s lifetime");
    cache_test_set_time(1010);
    CHECK(!has("e"), "expired exactly at its lifetime");
    CacheStats st;
    cache_get_stats(&st);
    CHECK(st.entries == 0 && st.bytes == 0, "expired entry released its memory");

    cache_store("long", (const unsigned char *)"x", 1, 999999); /* capped at CACHE_MAX_TTL_SECONDS */
    cache_test_set_time(1010 + CACHE_MAX_TTL_SECONDS - 1);
    CHECK(has("long"), "within the capped lifetime");
    cache_test_set_time(1010 + CACHE_MAX_TTL_SECONDS);
    CHECK(!has("long"), "an excessive max-age is capped");
    cache_test_set_time(0);
    cache_destroy();
}

static void test_keys(void) {
    char a[CACHE_KEY_MAX], b[CACHE_KEY_MAX], c[CACHE_KEY_MAX], d[CACHE_KEY_MAX];
    CHECK(cache_make_key(a, sizeof(a), "Example.COM", 80, "/x") == 0, "key builds");
    cache_make_key(b, sizeof(b), "example.com", 80, "/x");
    cache_make_key(c, sizeof(c), "example.com", 8080, "/x");
    cache_make_key(d, sizeof(d), "example.com", 80, "/X");
    CHECK(strcmp(a, b) == 0, "host case does not create a second entry");
    CHECK(strcmp(b, c) != 0, "different port -> different key");
    CHECK(strcmp(b, d) != 0, "paths are case-sensitive");
    char tiny[8];
    CHECK(cache_make_key(tiny, sizeof(tiny), "example.com", 80, "/long/path") == -1, "key that does not fit is refused");
}

/* ---------- eligibility ---------- */

static CacheVerdict eval(const char *text) {
    return cache_evaluate_response((const unsigned char *)text, strlen(text));
}

static void expect_cacheable(const char *label, const char *text, unsigned ttl) {
    CacheVerdict v = eval(text);
    CHECK(v.cacheable && v.ttl_seconds == ttl, "%s: expected cacheable ttl=%u, got cacheable=%d ttl=%u (%s)",
          label, ttl, v.cacheable, v.ttl_seconds, v.reason);
}

static void expect_not_cacheable(const char *label, const char *text) {
    CacheVerdict v = eval(text);
    CHECK(!v.cacheable, "%s: must NOT be cacheable", label);
}

static void test_eligibility(void) {
    expect_cacheable("plain 200", "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\nhi", CACHE_DEFAULT_TTL_SECONDS);
    expect_cacheable("HTTP/1.1 200", "HTTP/1.1 200 OK\r\n\r\nhi", CACHE_DEFAULT_TTL_SECONDS);
    expect_cacheable("public max-age", "HTTP/1.1 200 OK\r\nCache-Control: public, max-age=120\r\n\r\nhi", 120);
    expect_cacheable("header names are case-insensitive", "HTTP/1.1 200 OK\r\ncache-control: PUBLIC, Max-Age=30\r\n\r\nhi", 30);
    expect_cacheable("s-maxage wins for a shared cache", "HTTP/1.1 200 OK\r\nCache-Control: max-age=10, s-maxage=90\r\n\r\nhi", 90);
    expect_cacheable("huge max-age is capped", "HTTP/1.1 200 OK\r\nCache-Control: max-age=99999999\r\n\r\nhi", CACHE_MAX_TTL_SECONDS);
    expect_cacheable("matching Content-Length", "HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nhi", CACHE_DEFAULT_TTL_SECONDS);
    expect_cacheable("bare-LF line endings", "HTTP/1.0 200 OK\nContent-Type: x\n\nhi", CACHE_DEFAULT_TTL_SECONDS);
    expect_cacheable("benign Vary", "HTTP/1.1 200 OK\r\nVary: Accept-Encoding\r\n\r\nhi", CACHE_DEFAULT_TTL_SECONDS);

    /* the three the issue names explicitly */
    expect_not_cacheable("Set-Cookie", "HTTP/1.1 200 OK\r\nSet-Cookie: id=1\r\n\r\nhi");
    expect_not_cacheable("set-cookie (lowercase)", "HTTP/1.1 200 OK\r\nset-cookie: id=1; HttpOnly\r\n\r\nhi");
    expect_not_cacheable("Set-Cookie after other headers", "HTTP/1.1 200 OK\r\nA: b\r\nC: d\r\nSet-Cookie: x=y\r\n\r\nhi");
    expect_not_cacheable("Authorization", "HTTP/1.1 200 OK\r\nAuthorization: Bearer abc\r\n\r\nhi");
    expect_not_cacheable("WWW-Authenticate", "HTTP/1.1 200 OK\r\nWWW-Authenticate: Basic\r\n\r\nhi");
    expect_not_cacheable("Cache-Control: private", "HTTP/1.1 200 OK\r\nCache-Control: private\r\n\r\nhi");
    expect_not_cacheable("Cache-Control: no-store", "HTTP/1.1 200 OK\r\nCache-Control: no-store\r\n\r\nhi");
    expect_not_cacheable("Cache-Control: no-cache", "HTTP/1.1 200 OK\r\nCache-Control: no-cache\r\n\r\nhi");
    expect_not_cacheable("unapproved directive mixed with an approved one", "HTTP/1.1 200 OK\r\nCache-Control: public, max-age=60, must-revalidate\r\n\r\nhi");
    expect_not_cacheable("unknown directive", "HTTP/1.1 200 OK\r\nCache-Control: x-surprise\r\n\r\nhi");
    expect_not_cacheable("max-age=0", "HTTP/1.1 200 OK\r\nCache-Control: max-age=0\r\n\r\nhi");
    expect_not_cacheable("malformed max-age", "HTTP/1.1 200 OK\r\nCache-Control: max-age=abc\r\n\r\nhi");
    expect_not_cacheable("Pragma: no-cache", "HTTP/1.0 200 OK\r\nPragma: no-cache\r\n\r\nhi");
    expect_not_cacheable("Vary: *", "HTTP/1.1 200 OK\r\nVary: *\r\n\r\nhi");
    expect_not_cacheable("Vary: Cookie", "HTTP/1.1 200 OK\r\nVary: Accept, Cookie\r\n\r\nhi");

    expect_not_cacheable("404", "HTTP/1.0 404 Not Found\r\n\r\nno");
    expect_not_cacheable("301", "HTTP/1.1 301 Moved\r\nLocation: /x\r\n\r\n");
    expect_not_cacheable("500", "HTTP/1.1 500 Oops\r\n\r\n");
    expect_not_cacheable("2000 is not 200", "HTTP/1.1 2000 OK\r\n\r\nhi");
    expect_not_cacheable("not HTTP at all", "garbage bytes");
    expect_not_cacheable("truncated status line", "HTTP/1.1 20");
    expect_not_cacheable("headers never finished", "HTTP/1.1 200 OK\r\nContent-Type: x\r\n");
    expect_not_cacheable("Content-Length larger than the body (partial)", "HTTP/1.0 200 OK\r\nContent-Length: 100\r\n\r\nhi");
    expect_not_cacheable("Content-Length smaller than the body", "HTTP/1.0 200 OK\r\nContent-Length: 1\r\n\r\nhi");
    expect_not_cacheable("garbage Content-Length", "HTTP/1.0 200 OK\r\nContent-Length: ten\r\n\r\nhi");
    expect_not_cacheable("empty buffer", "");

    /* binary junk / NULs in the body must not confuse the header scanner */
    unsigned char bin[] = "HTTP/1.0 200 OK\r\n\r\n\x00\x01\x02\xff";
    CacheVerdict v = cache_evaluate_response(bin, sizeof(bin) - 1);
    CHECK(v.cacheable, "binary body is fine");
}

/* ---------- concurrency ---------- */

#define THREADS 8
#define OPS 4000
#define KEYS 24

static int g_torn = 0;
static pthread_mutex_t g_torn_mutex = PTHREAD_MUTEX_INITIALIZER;

static void *hammer(void *arg) {
    unsigned seed = (unsigned)(size_t)arg * 7919u + 1u;
    for (int i = 0; i < OPS; i++) {
        seed = seed * 1103515245u + 12345u;
        int k = (int)((seed >> 8) % KEYS);
        char key[32];
        snprintf(key, sizeof(key), "key-%d", k);
        size_t want_len = 100 + (size_t)k * 37; /* every key has its own length and fill byte */
        unsigned char fill = (unsigned char)('A' + k);

        if ((seed >> 4) % 3 == 0) {
            unsigned char *buf = malloc(want_len);
            memset(buf, fill, want_len);
            cache_store(key, buf, want_len, 60);
            free(buf);
        } else {
            size_t n = 0;
            unsigned char *got = cache_lookup(key, &n);
            if (got != NULL) {
                int ok = (n == want_len);
                for (size_t j = 0; ok && j < n; j++) {
                    ok = (got[j] == fill);
                }
                if (!ok) {
                    pthread_mutex_lock(&g_torn_mutex);
                    g_torn++;
                    pthread_mutex_unlock(&g_torn_mutex);
                }
                free(got);
            }
        }
    }
    return NULL;
}

static void test_concurrent_access(void) {
    cache_init(10, 6000, 4000); /* far smaller than the key set: forces constant eviction */
    pthread_t t[THREADS];
    for (size_t i = 0; i < THREADS; i++) {
        pthread_create(&t[i], NULL, hammer, (void *)i);
    }
    for (size_t i = 0; i < THREADS; i++) {
        pthread_join(t[i], NULL);
    }
    CacheStats st;
    cache_get_stats(&st);
    CHECK(g_torn == 0, "%d torn/corrupt reads under concurrent access", g_torn);
    CHECK(st.entries <= 10 && st.bytes <= 6000, "bounds respected under load (entries=%zu bytes=%zu)", st.entries, st.bytes);
    CHECK(st.hits + st.misses > 0 && st.stores > 0 && st.evictions > 0,
          "the test really exercised hits/stores/evictions (%lu/%lu/%lu)", st.hits, st.stores, st.evictions);
    cache_destroy();
}

int main(void) {
    printf("=== Running Cache Unit Tests ===\n");
    test_basic_roundtrip_and_miss();
    test_disabled_cache_is_safe();
    test_lru_eviction_by_entry_count();
    test_eviction_by_total_bytes();
    test_entry_size_limit_and_replace();
    test_expiry();
    test_keys();
    test_eligibility();
    test_concurrent_access();
    printf("Result: %d / %d tests passed successfully.\n", passed_tests, total_tests);
    return passed_tests == total_tests ? 0 : 1;
}
