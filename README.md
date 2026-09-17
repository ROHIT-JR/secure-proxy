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
- Privacy-aware structured request logging (no credentials, query strings, or fragments logged).
- Allowlist/blocklist policy engine, checked before any DNS lookup.
- SSRF (Server-Side Request Forgery) protection: rejects loopback, private, link-local, and other unsafe addresses, re-checked at connect time.
- Thread-safe bounded response cache with a documented eviction policy.
- HTTPS `CONNECT` tunnelling with byte relay only — no interception, no decryption.
- Pluggable `ReputationProvider` interface with an offline fixture provider for deterministic tests, and an optional live threat-feed adapter.
- Explainable risk scoring with a safe, non-sensitive decision page.

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
make test
```

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
