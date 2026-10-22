#pragma once
/* cache.h: Declares the thread-safe bounded response cache used to avoid re-fetching identical safe GET requests. */

#include <stddef.h>
#include <time.h>

/* Default limits (override with cache_init). */
#define CACHE_DEFAULT_MAX_ENTRIES 128
#define CACHE_DEFAULT_MAX_TOTAL_BYTES (8u * 1024u * 1024u) /* all entries together */
#define CACHE_DEFAULT_MAX_ENTRY_BYTES (256u * 1024u)       /* one response */
#define CACHE_DEFAULT_TTL_SECONDS 60u    /* used when the origin gives no max-age */
#define CACHE_MAX_TTL_SECONDS 3600u      /* never keep anything longer than this */
#define CACHE_KEY_MAX 2400

typedef struct {
    unsigned long hits, misses, stores, evictions, rejected;
    size_t entries, bytes;
} CacheStats;

/*
 * Eviction policy: LRU (least recently used). Every hit marks an entry as the
 * most recently used; when the entry-count or total-byte bound would be
 * exceeded, the least recently used entries are removed first.
 *
 * Thread safety: one mutex protects all state. cache_lookup() hands back a
 * private COPY of the response, so a concurrent eviction can never free memory
 * a worker is still sending.
 */
int cache_init(size_t max_entries, size_t max_total_bytes, size_t max_entry_bytes);
void cache_destroy(void);
int cache_is_enabled(void);

/* Builds the key "host:port path" (host lowercased). Returns 0 on success, -1 if it does not fit. */
int cache_make_key(char *out, size_t out_len, const char *host, unsigned port, const char *path);

/* Returns a malloc()'d copy of the cached response (caller must free) and sets *len_out,
 * or NULL on a miss/expired entry. */
unsigned char *cache_lookup(const char *key, size_t *len_out);

/* Stores a copy. Returns 0 if stored, -1 if rejected (too large, disabled, out of memory). */
int cache_store(const char *key, const unsigned char *data, size_t len, unsigned ttl_seconds);

void cache_get_stats(CacheStats *out);

/* TESTING ONLY: make the cache believe it is `now` (0 restores the real clock). */
void cache_test_set_time(time_t now);

typedef struct {
    int cacheable;
    unsigned ttl_seconds;   /* valid when cacheable */
    const char *reason;     /* short static string explaining the decision */
} CacheVerdict;

/*
 * Decides whether a COMPLETE origin response may be cached. A response is only
 * cacheable if ALL of these hold:
 *   - status line is HTTP/1.x 200,
 *   - the header block is complete and any Content-Length matches the body we hold,
 *   - no Set-Cookie, Authorization, WWW-Authenticate or Pragma: no-cache header,
 *   - no Vary: * and no Vary naming a cookie or credential header,
 *   - Cache-Control, if present, only uses approved directives: public, max-age=N,
 *     s-maxage=N (anything else, e.g. private / no-store / no-cache /
 *     must-revalidate, makes it uncacheable) and the resulting lifetime is > 0.
 */
CacheVerdict cache_evaluate_response(const unsigned char *response, size_t len);
