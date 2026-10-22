# Testing

Security features are only credible if the proxy stays stable under bad input and concurrent load. This page explains the layers of testing, how to run each one, what each one proves, and what is **not** covered. Every acronym is spelled out on first use.

## At a glance

| Command | What it runs | Time |
| --- | --- | --- |
| `make test` | Unit tests, then the end-to-end integration suite against the real proxy | about 40 s |
| `make sanitize` | The same, rebuilt with AddressSanitizer and UndefinedBehaviorSanitizer | about 1 min |
| `make load-test` | A seeded concurrent load test (32 clients, 4800 requests) | about 20 s |
| `make load-test-sanitize` | The same load against the sanitizer build, with a leak report at shutdown | about 10 s |
| `make valgrind` | Unit tests plus a short load test under Valgrind (skips itself if Valgrind is not installed) | a few minutes |

Reproduce a load-test failure with the same seed: `make load-test SEED=7`.

## The layers

1. **Unit tests** (`tests/test_*.c`) check one module in isolation with no network: the URL and CONNECT parsers, the logger, the policy engine and address classifier, the cache, the reputation framework, and the risk-scoring/block page. They include hostile inputs and, for the shared-state modules, multi-threaded stress.
2. **Integration tests** (`tests/integration/run_integration_tests.py`) start the real `bin/proxy` with local test servers and talk to it over real sockets. They check behaviour end to end, including what is written to the log.
3. **Load test** (`tests/load/run_load_test.py`) runs many clients at once against the real proxy with a seeded random mix of normal and hostile traffic.
4. **Sanitizers** rebuild everything with AddressSanitizer (memory errors and leaks) and UndefinedBehaviorSanitizer, so the layers above also hunt memory bugs.
5. **Valgrind** is a second, independent memory checker, used where it is installed.

Everything uses only local servers and reserved `.invalid` names. No real or harmful site is ever contacted.

## What the issue's list maps to

| Scenario | Where it is tested |
| --- | --- |
| Malformed requests | Parser unit tests (71); integration battery of 294 hostile requests (random bytes, truncated URLs, bad ports, credentials, control characters, NUL bytes, garbage `CONNECT` lines); load test |
| Oversized input | Integration (request line, `CONNECT` headers); battery; load test |
| Blocked hosts | Policy unit tests (200); integration (policy, reputation, `CONNECT`); load test |
| Private addresses | Address-classifier unit tests; integration: 17 destinations plus `CONNECT`, with a connection-counting listener proving no connection was made |
| DNS failures | Integration (HTTP and `CONNECT`); load test |
| **Origin timeouts** | Integration with an origin that accepts then goes silent (`504`), sends nothing (`502`), truncates cleanly, resets, stalls mid-body, or sends non-HTTP bytes |
| Cache races | Cache unit test (8 threads, 32,000 mixed operations on a cache far smaller than the key set); integration (30 simultaneous identical requests); load test (hot set plus long tail forces eviction) |
| `CONNECT` disconnects | Integration: client vanishes, origin hangs up, idle timeout, early data; load test (40% of tunnels reset abruptly) |

## Failure behaviour that is now guaranteed

- **A silent origin** gets the client a `504 Gateway Timeout` at the read timeout (`PROXY_ORIGIN_READ_TIMEOUT_SECONDS`, default 10).
- **An origin that hangs up without sending anything** gets a `502`, not an empty "success".
- **A response that breaks partway** is relayed exactly as far as it got and then the connection ends. The proxy never glues an error page onto a partial response, and truncated responses are never cached.
- **A NUL byte anywhere in the request line** is rejected with `400` at once. This was a real bug found by this testing: the NUL ended the C string early, so the validator never saw what followed it, and `http://example.com/\0x` was quietly processed as `http://example.com/`.
- **`SIGTERM` / `SIGINT`** shut the proxy down cleanly (exit code 0): it stops accepting, gives running requests up to 3 seconds, frees its state, and exits. This also lets LeakSanitizer and Valgrind produce a final leak report for the proxy itself, which was impossible while it could only be killed.

## What the load test checks

Every client repeats a seeded random mix of: content-verified page fetches (a hot set to produce cache hits, a long tail to force evictions), a 300 KB response, a cookie-setting response, malformed / NUL / oversized / blocked requests, DNS failures, `CONNECT` tunnels carrying random binary data (some closed with a TCP reset mid-tunnel), and clients that hang up mid-request.

It then asserts that:

- every response is correct (page bodies are compared byte for byte, so responses cannot be mixed up between clients);
- the proxy never crashed;
- **file descriptors return to their starting count**;
- memory growth stays within a limit (the bounded cache plus working memory);
- the cache actually reduced origin traffic;
- the proxy still serves correctly afterwards;
- `SIGTERM` shuts it down with exit code 0 within 60 s;
- its stderr contains **no AddressSanitizer, LeakSanitizer, UndefinedBehaviorSanitizer or Valgrind report**.

It prints a table of counts and 50th/95th/99th percentile latency per action, so a performance regression is visible too.

## Proof that the tests can fail

These checks were each broken on purpose and confirmed to fail, then restored:

- Planting a leak in the proxy (dropping the `free()` of the captured response) made the sanitizer load test fail with **LeakSanitizer: 8.9 MB leaked in 546 allocations** and exit code 1.
- Removing the mutex from the cache made AddressSanitizer report a heap-use-after-free in the cache unit test.
- Leaking a reputation-lookup job made LeakSanitizer report it.
- Disabling the SSRF checks let 5 real TCP connections reach a local listener.

## Known limits (read before trusting a green run)

- **Valgrind has not been run by the author.** The `make valgrind` target and its non-blocking CI job were written without a machine that has Valgrind, so their first run is also a test of the job itself.
- **No outbound internet** was available when this was written, so DNS-failure tests use `.invalid` names and "success" paths use local origin servers. DNS failure latency in the load test reflects the local resolver.
- **The connect timeout** (`PROXY_ORIGIN_CONNECT_TIMEOUT_SECONDS`) is implemented but not exercised end to end: a reliably unreachable address that still passes the safety checks is hard to arrange without a network.
- **Races** are detected by AddressSanitizer and by assertions on content integrity, not by ThreadSanitizer, which is not part of the build.
- **The load is moderate** (tens of concurrent clients, thousands of requests). It finds leaks, crashes and cross-talk; it is not a capacity benchmark.
- **A truncated response to a client that already received part of it** cannot be reported with a status code; the connection simply ends. This is inherent to relaying a response and is documented behaviour.
