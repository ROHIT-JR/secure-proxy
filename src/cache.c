/* cache.c: Implements a mutex-protected, bounded-size cache with a documented eviction policy for eligible HTTP responses. */

#define _POSIX_C_SOURCE 200809L

#include "cache.h"

#include <ctype.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char key[CACHE_KEY_MAX];
    unsigned char *data; /* NULL means the slot is free */
    size_t len;
    time_t expires;
    uint64_t last_used; /* logical clock: larger = more recently used */
} CacheEntry;

static pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;
static CacheEntry *g_entries = NULL;
static size_t g_max_entries = 0, g_max_total = 0, g_max_entry = 0;
static size_t g_used_entries = 0, g_used_bytes = 0;
static uint64_t g_tick = 0;
static CacheStats g_stats;
static time_t g_fake_now = 0;

static time_t now_locked(void) {
    return g_fake_now != 0 ? g_fake_now : time(NULL);
}

void cache_test_set_time(time_t now) {
    pthread_mutex_lock(&g_mutex);
    g_fake_now = now;
    pthread_mutex_unlock(&g_mutex);
}

int cache_init(size_t max_entries, size_t max_total_bytes, size_t max_entry_bytes) {
    if (max_entries == 0 || max_total_bytes == 0 || max_entry_bytes == 0) {
        return -1;
    }
    CacheEntry *fresh = calloc(max_entries, sizeof(CacheEntry));
    if (fresh == NULL) {
        return -1;
    }
    pthread_mutex_lock(&g_mutex);
    if (g_entries != NULL) { /* re-init: release the old contents first */
        for (size_t i = 0; i < g_max_entries; i++) {
            free(g_entries[i].data);
        }
        free(g_entries);
    }
    g_entries = fresh;
    g_max_entries = max_entries;
    g_max_total = max_total_bytes;
    g_max_entry = max_entry_bytes;
    g_used_entries = g_used_bytes = 0;
    g_tick = 0;
    memset(&g_stats, 0, sizeof(g_stats));
    pthread_mutex_unlock(&g_mutex);
    return 0;
}

void cache_destroy(void) {
    pthread_mutex_lock(&g_mutex);
    if (g_entries != NULL) {
        for (size_t i = 0; i < g_max_entries; i++) {
            free(g_entries[i].data);
        }
        free(g_entries);
        g_entries = NULL;
    }
    g_max_entries = g_max_total = g_max_entry = 0;
    g_used_entries = g_used_bytes = 0;
    pthread_mutex_unlock(&g_mutex);
}

int cache_is_enabled(void) {
    pthread_mutex_lock(&g_mutex);
    int on = (g_entries != NULL);
    pthread_mutex_unlock(&g_mutex);
    return on;
}

int cache_make_key(char *out, size_t out_len, const char *host, unsigned port, const char *path) {
    char lowered[300];
    size_t i = 0;
    for (; host[i] != '\0' && i + 1 < sizeof(lowered); i++) {
        lowered[i] = (char)tolower((unsigned char)host[i]);
    }
    lowered[i] = '\0';
    int n = snprintf(out, out_len, "%s:%u %s", lowered, port, path);
    return (n < 0 || (size_t)n >= out_len) ? -1 : 0;
}

/* Frees one entry. Caller holds the mutex. */
static void remove_entry_locked(CacheEntry *e) {
    g_used_bytes -= e->len;
    g_used_entries--;
    free(e->data);
    e->data = NULL;
    e->len = 0;
    e->key[0] = '\0';
}

/* Evicts the least recently used live entry. Caller holds the mutex. Returns 0 if none left. */
static int evict_lru_locked(void) {
    CacheEntry *victim = NULL;
    for (size_t i = 0; i < g_max_entries; i++) {
        if (g_entries[i].data != NULL && (victim == NULL || g_entries[i].last_used < victim->last_used)) {
            victim = &g_entries[i];
        }
    }
    if (victim == NULL) {
        return 0;
    }
    remove_entry_locked(victim);
    g_stats.evictions++;
    return 1;
}

static CacheEntry *find_locked(const char *key) {
    for (size_t i = 0; i < g_max_entries; i++) {
        if (g_entries[i].data != NULL && strcmp(g_entries[i].key, key) == 0) {
            return &g_entries[i];
        }
    }
    return NULL;
}

unsigned char *cache_lookup(const char *key, size_t *len_out) {
    unsigned char *copy = NULL;
    *len_out = 0;

    pthread_mutex_lock(&g_mutex);
    if (g_entries != NULL) {
        CacheEntry *e = find_locked(key);
        if (e != NULL && e->expires <= now_locked()) {
            remove_entry_locked(e); /* expired: behaves as a miss */
            e = NULL;
        }
        if (e != NULL) {
            copy = malloc(e->len > 0 ? e->len : 1);
            if (copy != NULL) {
                memcpy(copy, e->data, e->len);
                *len_out = e->len;
                e->last_used = ++g_tick; /* LRU: this is now the most recently used */
                g_stats.hits++;
            }
        }
        if (copy == NULL) {
            g_stats.misses++;
        }
    }
    pthread_mutex_unlock(&g_mutex);
    return copy;
}

int cache_store(const char *key, const unsigned char *data, size_t len, unsigned ttl_seconds) {
    if (strlen(key) >= CACHE_KEY_MAX || ttl_seconds == 0) {
        return -1;
    }
    if (ttl_seconds > CACHE_MAX_TTL_SECONDS) {
        ttl_seconds = CACHE_MAX_TTL_SECONDS;
    }

    /* Copy outside the lock so a big memcpy never blocks other workers. */
    unsigned char *copy = malloc(len > 0 ? len : 1);
    if (copy == NULL) {
        return -1;
    }
    memcpy(copy, data, len);

    int rc = -1;
    pthread_mutex_lock(&g_mutex);
    if (g_entries == NULL || len > g_max_entry || len > g_max_total) {
        g_stats.rejected++;
    } else {
        CacheEntry *e = find_locked(key);
        if (e != NULL) {
            remove_entry_locked(e); /* replace an existing entry for the same key */
        }
        while (g_used_entries >= g_max_entries || g_used_bytes + len > g_max_total) {
            if (!evict_lru_locked()) {
                break;
            }
        }
        CacheEntry *slot = NULL;
        for (size_t i = 0; i < g_max_entries; i++) {
            if (g_entries[i].data == NULL) {
                slot = &g_entries[i];
                break;
            }
        }
        if (slot != NULL) {
            snprintf(slot->key, sizeof(slot->key), "%s", key);
            slot->data = copy;
            slot->len = len;
            slot->expires = now_locked() + (time_t)ttl_seconds;
            slot->last_used = ++g_tick;
            g_used_entries++;
            g_used_bytes += len;
            g_stats.stores++;
            copy = NULL; /* ownership moved into the cache */
            rc = 0;
        } else {
            g_stats.rejected++;
        }
    }
    pthread_mutex_unlock(&g_mutex);

    free(copy); /* NULL when stored; otherwise the unused copy */
    return rc;
}

void cache_get_stats(CacheStats *out) {
    pthread_mutex_lock(&g_mutex);
    *out = g_stats;
    out->entries = g_used_entries;
    out->bytes = g_used_bytes;
    pthread_mutex_unlock(&g_mutex);
}

/* ---------- response eligibility ---------- */

static int ci_prefix(const char *s, size_t n, const char *prefix) {
    size_t pl = strlen(prefix);
    if (n < pl) {
        return 0;
    }
    for (size_t i = 0; i < pl; i++) {
        if (tolower((unsigned char)s[i]) != tolower((unsigned char)prefix[i])) {
            return 0;
        }
    }
    return 1;
}

static int ci_contains(const char *s, size_t n, const char *needle) {
    size_t nl = strlen(needle);
    for (size_t i = 0; i + nl <= n; i++) {
        if (ci_prefix(s + i, n - i, needle)) {
            return 1;
        }
    }
    return 0;
}

/* Parses one Cache-Control value ("public, max-age=60"). Returns 1 if every directive is approved. */
static int parse_cache_control(const char *v, size_t n, long *max_age, long *s_maxage) {
    size_t i = 0;
    while (i < n) {
        while (i < n && (v[i] == ' ' || v[i] == '\t' || v[i] == ',')) {
            i++;
        }
        size_t start = i;
        while (i < n && v[i] != ',') {
            i++;
        }
        size_t end = i;
        while (end > start && (v[end - 1] == ' ' || v[end - 1] == '\t')) {
            end--;
        }
        if (end == start) {
            continue;
        }
        const char *d = v + start;
        size_t dl = end - start;
        if (dl == 6 && ci_prefix(d, dl, "public")) {
            continue;
        }
        int is_max = ci_prefix(d, dl, "max-age=");
        int is_smax = ci_prefix(d, dl, "s-maxage=");
        if (is_max || is_smax) {
            const char *num = d + (is_max ? 8 : 9);
            size_t nl = dl - (is_max ? 8 : 9);
            if (nl == 0 || nl > 9) {
                return 0;
            }
            long val = 0;
            for (size_t k = 0; k < nl; k++) {
                if (!isdigit((unsigned char)num[k])) {
                    return 0;
                }
                val = val * 10 + (num[k] - '0');
            }
            if (is_max) {
                *max_age = val;
            } else {
                *s_maxage = val;
            }
            continue;
        }
        return 0; /* private, no-store, no-cache, must-revalidate, ... : not approved */
    }
    return 1;
}

CacheVerdict cache_evaluate_response(const unsigned char *response, size_t len) {
    CacheVerdict no = {0, 0, ""};
    const char *r = (const char *)response;

    if (len < 12 || memcmp(r, "HTTP/1.", 7) != 0 || r[8] != ' ' || memcmp(r + 9, "200", 3) != 0 ||
        (len > 12 && r[12] != ' ' && r[12] != '\r' && r[12] != '\n')) {
        no.reason = "status is not 200";
        return no;
    }

    /* find the end of the header block */
    size_t header_end = 0;
    for (size_t i = 0; i + 1 < len; i++) {
        if (r[i] == '\n' && (r[i + 1] == '\n' || (r[i + 1] == '\r' && i + 2 < len && r[i + 2] == '\n'))) {
            header_end = i + (r[i + 1] == '\n' ? 2 : 3);
            break;
        }
    }
    if (header_end == 0) {
        no.reason = "incomplete header block";
        return no;
    }

    long max_age = -1, s_maxage = -1, content_length = -1;
    int saw_cache_control = 0;

    size_t pos = 0;
    while (pos < header_end) { /* walk header lines (the first is the status line) */
        size_t eol = pos;
        while (eol < header_end && r[eol] != '\n') {
            eol++;
        }
        size_t line_len = eol - pos;
        if (line_len > 0 && r[pos + line_len - 1] == '\r') {
            line_len--;
        }
        const char *line = r + pos;
        if (pos != 0 && line_len > 0) {
            if (ci_prefix(line, line_len, "set-cookie:")) {
                no.reason = "Set-Cookie present";
                return no;
            }
            if (ci_prefix(line, line_len, "authorization:") || ci_prefix(line, line_len, "www-authenticate:")) {
                no.reason = "Authorization present";
                return no;
            }
            if (ci_prefix(line, line_len, "pragma:") && ci_contains(line, line_len, "no-cache")) {
                no.reason = "Pragma: no-cache";
                return no;
            }
            if (ci_prefix(line, line_len, "vary:")) {
                if (ci_contains(line, line_len, "*") || ci_contains(line, line_len, "cookie") ||
                    ci_contains(line, line_len, "authorization")) {
                    no.reason = "Vary makes it personalised";
                    return no;
                }
            }
            if (ci_prefix(line, line_len, "cache-control:")) {
                saw_cache_control = 1;
                if (!parse_cache_control(line + 14, line_len - 14, &max_age, &s_maxage)) {
                    no.reason = "unapproved Cache-Control directive";
                    return no;
                }
            }
            if (ci_prefix(line, line_len, "content-length:")) {
                long v = 0;
                size_t k = 15;
                while (k < line_len && (line[k] == ' ' || line[k] == '\t')) {
                    k++;
                }
                if (k >= line_len) {
                    no.reason = "bad Content-Length";
                    return no;
                }
                for (; k < line_len; k++) {
                    if (!isdigit((unsigned char)line[k]) || v > 1000000000L) {
                        no.reason = "bad Content-Length";
                        return no;
                    }
                    v = v * 10 + (line[k] - '0');
                }
                content_length = v;
            }
        }
        pos = eol + 1;
    }

    if (content_length >= 0 && (size_t)content_length != len - header_end) {
        no.reason = "body does not match Content-Length (partial response)";
        return no;
    }

    long ttl = CACHE_DEFAULT_TTL_SECONDS;
    if (saw_cache_control) {
        if (s_maxage >= 0) {
            ttl = s_maxage; /* we are a shared cache: s-maxage wins */
        } else if (max_age >= 0) {
            ttl = max_age;
        }
    }
    if (ttl <= 0) {
        no.reason = "lifetime is zero";
        return no;
    }
    if (ttl > (long)CACHE_MAX_TTL_SECONDS) {
        ttl = CACHE_MAX_TTL_SECONDS;
    }

    CacheVerdict yes = {1, (unsigned)ttl, "eligible"};
    return yes;
}
