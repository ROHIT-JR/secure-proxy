# Architecture

This document explains how a request flows through SecureBrowse, how the source tree is organized, who owns each socket, and how concurrency works. It assumes no prior knowledge of proxies — every acronym is spelled out on first use.

## Data flow: client -> proxy -> origin

```text
+--------+        +---------------------------------------------------+        +--------+
| Client | -----> | SecureBrowse proxy                                | -----> | Origin |
+--------+        |                                                   |        +--------+
                  |  1. accept()            (src/proxy.c)             |
                  |  2. parse request       (src/request_parser.c)    |
                  |  3. policy check        (src/policy.c)            |
                  |  4. DNS + safety check  (src/policy.c, origin_client.c)|
                  |  5. reputation check    (src/reputation.c)        |
                  |  6. cache lookup        (src/cache.c)             |
                  |  7. fetch/tunnel        (src/origin_client.c)     |
                  |  8. log decision        (src/logger.c)            |
                  +---------------------------------------------------+
```

The proxy is both a **TCP (Transmission Control Protocol) server** (it accepts connections from clients) and a **TCP client** (it opens outbound connections to origin web servers). This dual role is why the code is split into a client-facing side (`src/proxy.c`, `src/request_parser.c`) and an origin-facing side (`src/origin_client.c`).

## Module boundaries

| Module | Responsibility |
| --- | --- |
| `src/proxy.c` | Program entry point: creates the listening socket and dispatches accepted connections to worker threads. |
| `src/request_parser.c/.h` | Parses and validates the client's request line into a typed URL structure. Trusts nothing from the network. |
| `src/policy.c/.h` | Allowlist/blocklist checks and network-safety (SSRF, Server-Side Request Forgery) checks, applied before any DNS lookup or outbound connection. |
| `src/origin_client.c/.h` | DNS (Domain Name System) resolution and the outbound TCP connection to the origin server; streams the response back. |
| `src/cache.c/.h` | Thread-safe, bounded response cache for eligible GET requests. |
| `src/logger.c/.h` | Mutex-protected, privacy-aware structured logging. |
| `src/reputation.c/.h` | Pluggable `ReputationProvider` interface (offline fixture provider by default). |
| `src/util.c/.h` | Small shared helpers: bounded string copies, `send_all()`. |
| `src/client.c` | Command-line test client used for manual and integration testing. |

## Trust boundaries

- **Client -> proxy**: the client is untrusted. Every byte read from a client socket is treated as attacker-controlled until `request_parser.c` validates it.
- **Proxy -> origin**: the origin server is semi-trusted. Its response is streamed to the client but its address is validated first by `policy.c` (see `docs/threat-model.md` for SSRF protections).
- **Proxy -> reputation provider**: only the normalised hostname is sent, never credentials, full URLs, or request bodies (see Issue 14 in the project plan).

## Socket ownership rules

- Each accepted client socket is owned by exactly one worker thread, from `accept()` until that thread calls `close()` on it — on every code path, including error paths.
- Each outbound origin socket is owned by the worker thread that opened it and is closed by that same thread before the worker exits.
- No socket file descriptor is ever shared between two threads at the same time.

## Concurrency model

SecureBrowse uses a **thread-per-connection** model built on POSIX (Portable Operating System Interface) threads (`pthread`):

1. The main thread calls `accept()` in a loop.
2. For each accepted connection, the main thread allocates a heap-owned `ClientArgs` structure containing (at minimum) the client socket file descriptor.
3. The main thread calls `pthread_create()`, passing a pointer to the heap-owned `ClientArgs`.
4. The worker thread casts the argument back to `ClientArgs*`, extracts the socket, and is responsible for freeing the `ClientArgs` structure exactly once.
5. Worker threads are detached (or joined under a documented strategy) so that finished threads do not accumulate as zombies.
6. A bounded concurrency limit prevents unlimited thread creation from exhausting system resources.

The heap allocation in step 2 exists specifically to avoid the classic **loop-variable bug**: passing a pointer to a stack variable (or a loop counter) into `pthread_create()` is unsafe because the variable may change or go out of scope before the new thread reads it. Giving each connection its own heap allocation removes that race entirely.

---

## Phase 1 protocol contract: client -> proxy

To keep initial parsing, validation, and memory boundaries deterministic before implementing full RFC 7230 request line parsing, Phase 1 defines an explicit framing contract:

- **Request Framing:** Exactly one newline-terminated URL per TCP connection:
```text
[http://example.com/index.html](http://example.com/index.html)\n
```
Both Unix line endings (`\n` / LF) and Windows/network line endings (`\r\n` / CRLF) are accepted as valid terminators. The newline character is stripped before parsing.
- **Connection Lifecycle:** Non-persistent (one request per connection in Phase 1). The client initiates the TCP handshake, sends the single URL line, receives the streamed HTTP response from the proxy, and the proxy closes the client socket immediately upon completion.
- **Trust Assumption:** The client is completely untrusted. Any data arriving before the newline terminator is treated as untrusted input and must not be parsed until line framing is complete.

---

## Why recv() must run in a loop

TCP is a **stream-oriented protocol**, not a message- or datagram-oriented protocol (unlike UDP):

1. **No Inherent Message Boundaries:** TCP treats network data as an unstructured stream of bytes. The underlying operating system, network MTU (Maximum Transmission Unit), and intermediate routers may fragment or combine TCP segments unpredictably.
2. **Partial Reads:** A single call to `recv(client_fd, buf, sizeof(buf), 0)` is only guaranteed to return *at least 1 byte* (if unblocked), up to the buffer size requested. It does **not** guarantee that an entire line or URL will arrive in a single system call.
   - For example, if the client sends `http://example.com/index.html\n`, the proxy's first `recv()` might return only `http://examp`, the second `le.com/`, and the third `index.html\n`.
3. **Framing Invariant:** A server must maintain an accumulation buffer and execute `recv()` in a loop, inspecting incoming chunks for the `\n` delimiter. The loop terminates only when:
   - A `\n` delimiter is encountered (successful frame).
   - The accumulated bytes exceed the maximum URL length limit (framing error / payload too large).
   - `recv()` returns `0` (client closed connection prematurely).
   - `recv()` returns `-1` (network error or timeout).

---

## Protocol limits & safety bounds

To prevent Denial of Service (DoS), slowloris socket exhaustion, and buffer overflows, the proxy enforces the following bounds:

| Parameter | Limit | Rationale | Enforcement Behavior |
| :--- | :--- | :--- | :--- |
| **Max URL Size** | `2048 bytes` (2 KB) | Accommodates standard browser URLs while preventing heap bloat. | Abort read loop immediately; return `413 Payload Too Large`. |
| **Max Header Size** | `8192 bytes` (8 KB) | Bounds origin response headers in memory. | Rejects malformed or oversized upstream headers; return `502 Bad Gateway`. |
| **Max Response Size** | `10 MB` (buffered) | Restricts non-streaming response caching. | Streaming responses pipe directly without limits; buffered caching paths abort on excess. |
| **Client Read Timeout** | `5 seconds` | Protects against slowloris attacks where a client connects but drips bytes slowly. | Close client socket; return `408 Request Timeout`. |
| **Origin Connect Timeout** | `5 seconds` | Prevents worker threads from blocking indefinitely on unresponsive origin servers. | Abort upstream connection attempt; return `502 Bad Gateway`. |
| **Origin Read Timeout** | `10 seconds` | Mitigates hanging upstream HTTP transactions. | Abort origin read; return `504 Gateway Timeout`. |

---

## Proxy failure responses

When request parsing, policy validation, DNS safety checks, or origin communication fails, the proxy responds with standard HTTP/1.1 status lines, a `text/plain` body, and immediately closes the client connection:

### 400 Bad Request
Triggered when request framing is violated, the URL scheme is unsupported (non-HTTP), the URL is malformed, or the hostname is missing:
```http
HTTP/1.1 400 Bad Request
Content-Type: text/plain
Content-Length: 57
Connection: close

400 Bad Request: Malformed URL or missing host component.
```

### 403 Forbidden
Triggered when the requested hostname violates an allowlist/blocklist policy or resolves to a private, loopback, or link-local address (SSRF mitigation):
```http
HTTP/1.1 403 Forbidden
Content-Type: text/plain
Content-Length: 48
Connection: close

403 Forbidden: Destination host blocked by policy.
```

### 413 Payload Too Large
Triggered when the incoming request stream exceeds 2048 bytes before a newline delimiter (`\n`) is encountered:
```http
HTTP/1.1 413 Payload Too Large
Content-Type: text/plain
Content-Length: 50
Connection: close

413 Payload Too Large: Request URL exceeds 2048B.
```

### 502 Bad Gateway
Triggered when upstream DNS resolution fails, connection to the origin port is refused, or the origin server resets the connection:
```http
HTTP/1.1 502 Bad Gateway
Content-Type: text/plain
Content-Length: 68
Connection: close

502 Bad Gateway: Failed to establish upstream connection to origin.
```