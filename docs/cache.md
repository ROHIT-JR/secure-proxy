# Response Cache

Caching makes repeated, safe HTTP (Hypertext Transfer Protocol) requests faster, and it is also a good lesson in sharing state between threads correctly. SecureBrowse keeps a small in-memory cache that is **bounded**, **thread-safe**, and deliberately **conservative**: when in doubt, it does not cache. Every acronym is spelled out on first use.

## What gets cached

A response is cached only if **all** of these are true:

| Rule | Why |
| --- | --- |
| The request URL has **no query string** | A `?` part often carries a token or a per-user value. |
| The status is exactly **200** | Errors and redirects are not worth sharing. |
| The header block is complete and any `Content-Length` matches the body held | Never cache a partial or truncated response. |
| No `Set-Cookie` header | The response is tied to one user's session. |
| No `Authorization` or `WWW-Authenticate` header | The response involves credentials. |
| No `Pragma: no-cache`, and no `Vary: *` or `Vary` naming a cookie/credential header | The origin says it differs per user. |
| `Cache-Control`, if present, uses **only approved directives**: `public`, `max-age=N`, `s-maxage=N` | Anything else (`private`, `no-store`, `no-cache`, `must-revalidate`, unknown directives) is unapproved, so it is not cached. |
| The resulting lifetime is greater than zero | `max-age=0` means "do not reuse". |
| The response is at most **256 KiB** | One large file must not push everything else out. |

Lifetime: `s-maxage` (we are a shared cache), else `max-age`, else **60 seconds**. Never longer than **1 hour**.

Only requests to destinations that already passed the policy and network-safety checks ever reach the cache, because those checks run *before* the cache is consulted. A cached response is served without contacting the origin.

## Bounds and eviction

| Limit | Value |
| --- | --- |
| Entries | 128 |
| Total bytes | 8 MiB |
| One response | 256 KiB |

**Eviction policy: LRU (least recently used).** Each hit marks the entry as the most recently used. When a new entry would break the entry or byte bound, the least recently used entries are removed first. (A plain first-in-first-out policy would wrongly evict a popular old entry; a unit test checks LRU behaviour specifically.)

## Thread safety

- One mutex protects all cache state.
- `cache_lookup()` returns a **private copy** of the response. If another thread evicts the entry a moment later, nothing a worker is still sending is freed under it.
- Copies are made outside the lock where possible, so a large copy does not block other workers.
- The fetcher keeps a bounded copy of the response while streaming it to the client. If the response grows past the cache limit the copy is simply dropped. **Streaming to the client is never delayed or truncated by caching.**

## Logging

Each request that goes through the cache adds one field to its [log line](logging.md), with no URL and no query string:

| Field | Meaning |
| --- | --- |
| `cache=hit` | Served from memory; the origin was not contacted. |
| `cache=stored` | A miss: fetched from the origin, judged eligible, and stored. |
| `cache=miss` | A miss: fetched from the origin, not stored (ineligible response). |
| `cache=bypass` | The URL has a query string, so the cache was not used. |
| *(no field)* | The cache is turned off. |

```text
2026-10-22T10:00:00Z req=11 host=example.com decision=allowed status=200 bytes=1256 duration_ms=48 cache=stored
2026-10-22T10:00:02Z req=12 host=example.com decision=allowed status=200 bytes=1256 duration_ms=0 cache=hit
```

## Configuration

| Setting | Effect |
| --- | --- |
| `PROXY_CACHE=0` | Turn the cache off completely. |

The size bounds are compile-time constants in `include/cache.h`.

## What the tests prove

- `tests/test_cache.c` (71 checks): round trip and isolation of returned copies, LRU order, entry-count and byte bounds, per-entry limit, replacement of an existing key, expiry (with a fake clock), key building, **38 eligibility cases** (every rule above, header-name case, bare-LF line endings, binary bodies), and 8 threads performing 32,000 mixed operations against a cache far smaller than the key set, verifying that no read is ever corrupt.
- `tests/integration/run_integration_tests.py`: against the real proxy and a test origin that counts requests, a repeated eligible request hits the cache, `Set-Cookie` / `Authorization` / `private` / `no-store` / 404 responses are fetched from the origin every time, query-string URLs bypass the cache and never appear in the log, an oversized response is delivered in full but not cached, entries expire, and 30 simultaneous requests for one URL all get the correct bytes.
- Removing the mutex from `cache_lookup()` makes AddressSanitizer report a heap-use-after-free, so the concurrency test genuinely detects races.

## Limits

- The cache is in memory only and starts empty on every restart.
- It does not revalidate with the origin (`ETag` / `If-None-Match`); it just waits for the lifetime to end.
- Only the exact URL is cached; there is no cache-key normalisation of equivalent paths.
