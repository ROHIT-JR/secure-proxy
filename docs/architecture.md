# Architecture

This document explains how a request flows through SecureBrowse, how the source tree is organized, who owns each socket, and how concurrency works. It assumes no prior knowledge of proxies — every acronym is spelled out on first use.

## Data flow: client -> proxy -> origin

```text
+--------+        +---------------------------------------------------+        +--------+
| Client | -----> | SecureBrowse proxy                                 | -----> | Origin |
+--------+        |                                                     |        +--------+
                  |  1. accept()            (src/proxy.c)               |
                  |  2. parse request       (src/request_parser.c)      |
                  |  3. policy check        (src/policy.c)              |
                  |  4. DNS + safety check  (src/policy.c, origin_client.c)|
                  |  5. reputation check    (src/reputation.c)          |
                  |  6. cache lookup        (src/cache.c)               |
                  |  7. fetch/tunnel        (src/origin_client.c)       |
                  |  8. log decision        (src/logger.c)              |
                  +-----------------------------------------------------+
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
