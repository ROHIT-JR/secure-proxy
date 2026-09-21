# Phase 1 Demo — Working Concurrent Proxy

This is the demo script required by Issue #9: exact commands and expected results for everything Phase 1 (issues #1–#9) built. Anyone should be able to follow this from a clean checkout and get the same result every time. Every acronym is spelled out on first use.

Run everything from the repository root.

## 1. Build

```sh
make clean && make
```

**Expected result:** the build finishes with no compiler warnings. The project compiles with `-Wall -Wextra -Werror -pthread`, so any warning would already be a build failure.

## 2. Start the proxy

```sh
./bin/proxy
```

**Expected result:**

```text
proxy: listening on port 8080
```

The proxy keeps running in the foreground. Open a second terminal for the remaining steps, or background it with `./bin/proxy &`.

## 3. Fetch an allowed HTTP page

```sh
./bin/client http://example.com/
```

**Expected result:**

```text
Saved response to example.com.html (approx. 1-2 KB, varies with the live page)
```

`example.com.html` now contains the real, complete HTTP response (headers and body) exactly as the origin server sent it. Open it and confirm it looks like a normal web page response.

> If your machine has no internet access (for example, in an isolated CI or sandbox environment), you can demonstrate the same flow against a local origin instead:
> ```sh
> cd tests/fixtures/webroot && python3 -m http.server 9195 &
> cd - && ./bin/client http://127.0.0.1:9195/index.html
> ```
> This is exactly what `make test`'s integration suite does automatically (see Step 8).

## 4. Show simultaneous clients

```sh
./bin/client http://example.com/ &
./bin/client http://example.com/ &
./bin/client http://example.com/ &
wait
```

**Expected result:** all three `client` processes print `Saved response to example.com.html (...)` and exit successfully. Because they share the same output filename here, the point of this step is to show the proxy handling three truly concurrent connections without hanging, crashing, or mixing up which response goes to which socket — not to inspect the (overwritten) file afterward. To see per-connection correctness explicitly, use distinct URLs/paths per client, or run `make test`'s integration suite (Step 8), which verifies eight simultaneous clients each receive their own distinct, correct content.

## 5. Show a malformed request is rejected safely

```sh
printf 'not-a-url\n' | nc localhost 8080
```

**Expected result:**

```text
HTTP/1.1 400 Bad Request
Content-Type: text/plain
Content-Length: ...
Connection: close

400 Bad Request: Unsupported or missing URL scheme (only http:// supported)
```

The proxy stays running afterward — try Step 3 again immediately and it still works.

## 6. Show a non-existent domain fails safely

```sh
printf 'http://this-domain-absolutely-does-not-exist-xyz123.invalid/\n' | nc localhost 8080
```

**Expected result:**

```text
HTTP/1.1 502 Bad Gateway
Content-Type: text/plain
Content-Length: ...
Connection: close

502 Bad Gateway: DNS resolution failed
```

Again, the proxy is still alive and accepting new connections afterward.

## 7. Show an oversized request is rejected safely

```sh
python3 -c "print('http://example.com/' + 'a' * 3000)" | nc localhost 8080
```

**Expected result:**

```text
HTTP/1.1 413 Payload Too Large
Content-Type: text/plain
Content-Length: ...
Connection: close

413 Payload Too Large: Request URL exceeds 2048B.
```

## 8. Run the full automated test suite

```sh
make test
```

**Expected result:** every check passes, in this order:

```text
hello_proxy: build system initialized successfully.
=== Running URL Parser Unit Tests ===
Result: 31 / 31 tests passed successfully.
[PASS] success: fetch a real local page
[PASS] malformed URL -> 400 Bad Request
[PASS] DNS failure -> 502 Bad Gateway
[PASS] oversized request line -> 413 Payload Too Large
[PASS] 8 simultaneous clients each get their own correct response
[PASS] no leaked file descriptors after repeated success/failure requests

All Phase 1 integration tests passed.
```

The integration suite (`tests/integration/run_integration_tests.py`) automatically starts a local test origin server and the proxy, exercises every scenario above against them (using only local-origin fixtures and RFC-2606-reserved `.invalid` domains, never real external sites), and shuts both down afterward.

Run `make test` twice in a row — both runs must produce the identical pass/fail result. Run `make sanitize` for the same suite rebuilt under AddressSanitizer + UndefinedBehaviorSanitizer.

## Resource checklist: every allocation freed, every socket closed

This is checked two ways, not just claimed:

1. **Automated, every `make test` run**: the integration suite's last check compares the proxy process's open file descriptor count (via `/proc/<pid>/fd`) before and after running every request scenario above. If any code path leaked a client or origin socket, this check fails.
2. **Sanitizer build**: `make sanitize` rebuilds everything with AddressSanitizer, which detects heap corruption, use-after-free, and (via its allocator hooks) memory that was `malloc`'d but never `free`'d during the traced execution.

Manually, tracing the code confirms the same thing:

- Every accepted `client_fd` is closed exactly once, via `drain_and_close()` at the single `cleanup:` label in `handle_client()` — every early-exit path (`goto cleanup`) and the normal completion path both funnel through it.
- Every `ClientArgs` heap allocation in `main()`'s accept loop is freed exactly once: either immediately in `main()` if `pthread_create()` fails, or inside `handle_client()` right after `client_fd` is extracted from it.
- Every outbound origin socket opened by `fetch_and_relay()` (`src/origin_client.c`) is closed on every return path (success, DNS failure before it's even opened, connect failure, send failure, and receive failure).
- `getaddrinfo()`'s result is always released with `freeaddrinfo()`, including on the failure path.

## Explaining the heap-owned worker arguments

If asked to demonstrate understanding of the concurrency model (Issue #8): the main thread's `accept()` loop allocates a fresh `ClientArgs` struct on the heap for every connection, copies that connection's `client_fd` into it, and only then calls `pthread_create()`, passing a pointer to that heap allocation. The new worker thread reads `client_fd` out of `ClientArgs` and frees it immediately — before doing anything else. This avoids the classic **loop-variable bug**: if the code instead passed a pointer to a stack variable that gets reused every loop iteration, a slower-to-start thread could end up reading a `client_fd` that has already been overwritten by a later connection, causing one client to receive another client's response. See `docs/architecture.md`'s "Concurrency model" section for the full explanation.
