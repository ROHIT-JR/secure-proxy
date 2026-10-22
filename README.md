# SecureBrowse — Security-Aware Concurrent Forward Proxy

> **Read [`docs/workflow.md`](docs/workflow.md) before you pick up any issue.** It is required reading for every teammate and every AI agent working on this repository — it explains what an issue actually is and the exact steps from "assigned to me" to a merged pull request. Reading an issue and clicking "Close" on it is never correct; skipping this file is the most common way to get your work reverted or your issue reopened.

SecureBrowse is a Linux/C forward proxy built as a university Operating Systems project and released as a real open-source project from day one. It accepts a web request from a local client, checks whether the request is safe, fetches or tunnels it, and returns the result — the same broad pattern used by commercial secure web gateways, built here with POSIX sockets and `pthread` (POSIX threads).

## New to this project? Start here

If you are new to this repository (student teammate or outside contributor), read these in order:

1. [`docs/workflow.md`](docs/workflow.md) — **required**: how to actually take an issue from assignment to a merged, issue-closing pull request.
2. [`docs/architecture.md`](docs/architecture.md) — how a request flows through the proxy and how the code is organized.
3. The Phase 1 issues in the [issue tracker](../../issues) (labelled `P0`) — these build the working concurrent proxy step by step, in dependency order.

You do not need prior open-source experience to contribute. [`CONTRIBUTING.md`](CONTRIBUTING.md) walks through setup, branch naming, and how to open your first pull request.

## Purpose

Build a forward proxy that:

```text
Client
  -> request parser
  -> URL/domain policy
  -> DNS (Domain Name System) and private-network protection
  -> optional reputation check
  -> cache
  -> web origin
  -> response back to client
```

The project is split into two milestones:

- **Phase 1 — Working proxy:** a complete, demonstrable proxy that fetches ordinary HTTP (Hypertext Transfer Protocol) pages and serves several clients concurrently.
- **Phase 2 — Security-aware proxy:** adds safe policy enforcement, logging, caching, HTTPS (Hypertext Transfer Protocol Secure) tunnelling via `CONNECT`, and optional threat-intelligence checks.

## Feature list

### Phase 1 — Working Concurrent Proxy
- TCP (Transmission Control Protocol) listening socket with explicit error handling.
- Safe HTTP URL parsing and hostname normalisation.
- Outbound DNS resolution and HTTP origin fetching with `502 Bad Gateway` on failure.
- Thread-per-connection concurrency model with heap-owned, safely freed per-client arguments.
- Integration tests and a repeatable Phase 1 demo.

### Phase 2 — Security-Aware and More Valuable
- Privacy-aware structured request logging (no credentials, query strings, fragments, or paths logged) — **implemented**, see [`docs/logging.md`](docs/logging.md).
- Allowlist/blocklist policy engine, checked before any DNS lookup — **implemented**, see [`docs/policy.md`](docs/policy.md).
- SSRF (Server-Side Request Forgery) protection: rejects loopback, private, link-local, and other unsafe addresses, re-checked at connect time — **implemented**, see the "Allowed-network policy" in [`docs/threat-model.md`](docs/threat-model.md).
- Thread-safe bounded response cache (LRU eviction) that never caches cookies, credentials, or query-string URLs — **implemented**, see [`docs/cache.md`](docs/cache.md).
- HTTPS `CONNECT` tunnelling with byte relay only — no interception, no decryption — **implemented**, see [`docs/https-tunnelling.md`](docs/https-tunnelling.md).
- Pluggable `ReputationProvider` interface with an offline fixture provider for deterministic tests (**implemented**, see [`docs/reputation.md`](docs/reputation.md)), and an optional live threat-feed adapter (not yet built).
- Explainable risk scoring with a safe, non-sensitive decision page — **implemented**, see [`docs/risk-scoring.md`](docs/risk-scoring.md).

## Quick start

### Build

```sh
make
```

### Run

```sh
./bin/proxy        # starts the proxy on port 8080
./bin/client http://example.com/   # fetches a URL through the proxy
```

### Test

```sh
make test               # unit tests + end-to-end integration tests
make load-test          # seeded concurrent load test
make load-test-sanitize # the same load under AddressSanitizer + leak check at shutdown
```

See [`docs/testing.md`](docs/testing.md) for what each layer proves and its known limits.

### Sanitizer build (AddressSanitizer + UndefinedBehaviorSanitizer)

```sh
make sanitize
```

### Example terminal session

```text
$ make
$ ./bin/proxy &
$ ./bin/client http://example.com/
Saved response to example.com.html (1256 bytes)
```

## Configuration

All settings are environment variables; with none set the proxy is in its secure default state.

| Variable | Default | Meaning |
| --- | --- | --- |
| `PROXY_PORT` | 8080 | Listening port (also read by `bin/client`). |
| `PROXY_CONNECT_PORT` | 443 | The only port `CONNECT` tunnels may reach. |
| `PROXY_TUNNEL_IDLE_SECONDS` | 60 | Idle timeout for tunnels. |
| `PROXY_ORIGIN_CONNECT_TIMEOUT_SECONDS` | 10 | Origin connect timeout. |
| `PROXY_ORIGIN_READ_TIMEOUT_SECONDS` | 15 | Origin silence timeout (`504`). |
| `PROXY_ALLOWLIST` / `PROXY_BLOCKLIST` | unset | Policy files (see `docs/policy.md`). |
| `PROXY_LOG_FILE` | unset | Privacy-aware request log (mode 600). |
| `PROXY_CACHE` | on | Set to `0` to disable the cache. |
| `PROXY_REPUTATION_FIXTURE` | unset | Offline reputation fixture file. |
| `PROXY_REPUTATION_TIMEOUT_MS` / `PROXY_REPUTATION_TTL_SECONDS` | see docs | Reputation timeout and cache lifetime. |
| `PROXY_REPUTATION_QUERY_LOG` | unset | Records what was sent to the provider (tests). |
| `PROXY_UNSAFE_ALLOW_PRIVATE_NETWORKS` | unset | **Testing only**: disables the SSRF guard; the proxy warns loudly. |

## Known limits

- Thread-per-connection with a 64-client cap; not built for production scale.
- The reputation check fails open if the provider is unavailable.
- The live threat-feed adapter (Issue 16) is not built; only the interface and offline fixture exist.
- Valgrind has a CI job but was not run locally; sanitizers were.
- HTTPS is tunnelled, never inspected.

## Demo and viva

- Five-minute demo with exact commands: [`docs/demo.md`](docs/demo.md) (`make demo-check` verifies it).
- Viva preparation: [`docs/viva.md`](docs/viva.md).
- All docs: [`architecture`](docs/architecture.md), [`threat-model`](docs/threat-model.md), [`testing`](docs/testing.md), [`policy`](docs/policy.md), [`logging`](docs/logging.md), [`cache`](docs/cache.md), [`https-tunnelling`](docs/https-tunnelling.md), [`reputation`](docs/reputation.md), [`risk-scoring`](docs/risk-scoring.md).

## Safe-use limits

This project follows strict rules to stay safe and testable:

- C on Linux, POSIX sockets, `pthread`. Compiled with `-Wall -Wextra -Werror -pthread`.
- All network input is treated as untrusted; lengths are validated before copying.
- Every `malloc` has one clear `free`; every socket has one clear `close`.
- No real usernames, API (Application Programming Interface) keys, private URLs (Uniform Resource Locators), or sensitive request bodies are ever sent to a threat-intelligence provider or committed to this repository.
- Tests use only safe sites (`example.com`), local test servers, and fake threat-provider fixtures — never real harmful URLs.
- No transparent HTTPS interception, no TLS (Transport Layer Security) certificate bypassing, no content decryption. HTTPS is handled via `CONNECT` tunnelling only: a raw byte relay, with no inspection.

This is an educational proxy, not a replacement for a commercial or enterprise secure web gateway.

## Contributing and security

- Want to contribute? See [`CONTRIBUTING.md`](CONTRIBUTING.md).
- Found a security issue? See [`SECURITY.md`](SECURITY.md) — please do not open a public issue first.
- Need help using the project? See [`SUPPORT.md`](SUPPORT.md).

## License

MIT — see [`LICENSE`](LICENSE).
