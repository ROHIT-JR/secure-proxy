# SecureBrowse — Security-Aware Concurrent Forward Proxy

## Purpose

Build a Linux/C forward proxy that accepts a web request from a local client, checks whether it is safe, fetches or tunnels the request, and returns the result. The project demonstrates sockets, TCP, HTTP, threads, mutexes, shared memory, security policy, testing, and practical observability.

The project is deliberately split into two milestones:

- **Phase 1 — Working proxy:** a complete, demonstrable university assignment that fetches ordinary HTTP pages and serves several clients concurrently.
- **Phase 2 — Security-aware proxy:** adds safe policy enforcement, logging, caching, HTTPS tunnelling, and optional threat-intelligence checks without pretending to be a commercial security product.

## Real-world value

Companies use forward proxies to control and monitor outbound web access. This project follows the same broad pattern as secure web gateways:

```text
Client
  -> request parser
  -> URL/domain policy
  -> DNS and private-network protection
  -> optional reputation check
  -> cache
  -> web origin
  -> response back to client
```

For HTTPS, the proxy will use **CONNECT tunnelling**. It will not decrypt traffic, generate certificates, capture passwords, or inspect private page contents.

## Project rules

- Build with C on Linux using POSIX sockets and `pthread`.
- Compile with `-Wall -Wextra -Werror -pthread`.
- Treat all network input as untrusted; validate lengths before copying.
- Every `malloc` has one clear `free`; every socket has one clear `close`.
- Do not submit real usernames, API keys, private URLs, or sensitive request bodies to a threat-intelligence provider.
- Tests must use safe sites such as `example.com`, local test servers, and fake threat-provider responses.
- No transparent HTTPS interception or TLS certificate bypassing.

## Open-source publication checklist

This project should be public only after the **required before first public release** files are present. GitHub’s community profile recognises `README`, `LICENSE`, `CONTRIBUTING`, and `CODE_OF_CONDUCT`, while GitHub also supports `SECURITY`, `SUPPORT`, issue forms, and pull-request templates. Do not add a file only for a badge: every file must describe what this project actually does.

### Required before the first public release

| File | What it must contain | Why it matters |
| --- | --- | --- |
| `README.md` | Purpose, architecture, feature list, quick start, build/run/test commands, safe-use limits, demo screenshot or terminal example, and links to contribution/security docs. | Lets a new user understand and run the project. |
| `LICENSE` | The complete text of the licence selected by the maintainers. Suggested choices: MIT for simple permissive reuse, or Apache-2.0 when its explicit patent grant is preferred. | Clearly states how others may use and contribute to the code. |
| `CONTRIBUTING.md` | Setup, branch naming, coding style, test commands, how to open an issue/PR, review expectations, and the rule not to submit secrets or real harmful URLs. | Makes first contributions predictable. |
| `CODE_OF_CONDUCT.md` | A recognised code of conduct, a contact route for reports, and a commitment to respectful collaboration. | Sets expected behaviour for contributors. |
| `SECURITY.md` | Supported versions, in-scope issues, private reporting route, expected acknowledgement target, disclosure process, and a clear instruction not to post vulnerabilities publicly first. | Gives researchers a safe way to report flaws. |
| `SUPPORT.md` | Where to ask usage questions, where to report bugs, what information to include, and what support is not offered. | Keeps support questions separate from security reports. |
| `.gitignore` | Binaries, object files, coverage output, local configuration, log files, temporary captures, API-key files, and IDE artifacts. | Prevents accidental publishing of build output and secrets. |
| `.editorconfig` and `.clang-format` | One agreed whitespace/style policy for C and Markdown. | Stops formatting-only pull requests. |
| `.github/ISSUE_TEMPLATE/bug_report.yml` | Reproduction steps, expected/actual result, OS/compiler version, logs with secrets removed, and security-report warning. | Produces actionable bug reports. |
| `.github/ISSUE_TEMPLATE/feature_request.yml` | Problem, proposed value, alternatives, security/privacy impact, and willingness to contribute. | Keeps feature requests useful. |
| `.github/ISSUE_TEMPLATE/config.yml` | Links to support and `SECURITY.md`; disables blank issues only if the team can still be contacted easily. | Directs people to the correct channel. |
| `.github/pull_request_template.md` | Summary, linked issue, tests run, security/privacy impact, docs updated, and a checklist that secrets are absent. | Makes reviews safer and consistent. |
| `.github/workflows/ci.yml` | Build with warnings enabled, run unit/integration tests, and run sanitizers on pull requests and the default branch. | Ensures the published branch stays buildable. |
| `docs/architecture.md` | Data flow, module boundaries, trust boundaries, socket ownership, and concurrency model. | Explains the design to reviewers and contributors. |
| `docs/threat-model.md` | Assets, attackers, abuse cases, safety controls, non-goals, and residual risks. | Especially important because this is a network-security project. |
| `docs/demo.md` | Exact demonstration steps and expected output. | Lets someone else reproduce the demo. |

### Strongly recommended after the basic project works

| File or setting | What it adds | When to add it |
| --- | --- | --- |
| `.github/workflows/codeql.yml` | C/C++ code scanning for common security flaws. | When CI is stable. |
| `.github/dependabot.yml` | Keeps GitHub Actions references current. | As soon as workflows use third-party actions. |
| `.github/CODEOWNERS` | States who reviews networking/security-sensitive paths. | When the team has clear maintainers. |
| `CHANGELOG.md` | Human-readable changes by release. Use the Keep a Changelog style if the team wants formal releases. | Before the first tagged release. |
| `docs/release-process.md` | Versioning, release checklist, tag process, binaries, checksum generation, and rollback. | Before distributing binaries. |
| `SECURITY-INSIGHTS.yml` | Machine-readable description of project security practices. | After `SECURITY.md` and CI are real and maintained. |
| `sbom.cdx.json` or release SBOM artifact | A generated inventory of dependencies and build components. Do not hand-edit it. | When shipping binaries or using third-party libraries. |
| `.github/workflows/release.yml` | Reproducible tagged builds, checksums, and SBOM attachment. | Only after release process is agreed. |
| `.github/workflows/scorecard.yml` | Optional OpenSSF Scorecard monitoring. | After CI permissions and action pinning are understood. |

### Optional — add only when it is true for the project

| File | Use it when |
| --- | --- |
| `GOVERNANCE.md` | The project has several maintainers and needs a written decision-making process. |
| `MAINTAINERS.md` | Ownership or succession needs to be explicit. |
| `FUNDING.yml` | The project is genuinely accepting sponsorship. |
| `CITATION.cff` | The project is part of academic research and should be cited. |
| `AUTHORS.md` or `NOTICE` | Attribution is not already clear through Git history or licence notices. |

### GitHub repository settings to enable

- Enable branch protection for `main`: pull request required, at least one review, required CI checks, and no direct force-pushes.
- Enable secret scanning and push protection where the repository/account supports them.
- Enable private vulnerability reporting for a public repository.
- Enable Dependabot security updates if dependencies or Actions are used.
- Use least-privilege permissions in every GitHub Actions workflow; do not give workflows write permission unless a specific job needs it.

### Licence note

Choosing a licence is a maintainer decision, not a coding task. Do not copy a licence name into the README without adding the complete matching `LICENSE` file. If the project has employer, university, or client ownership rules, get approval before publishing.

## Suggested repository layout

```text
secure-proxy/
├── src/
│   ├── proxy.c
│   ├── client.c
│   ├── request_parser.c/.h
│   ├── origin_client.c/.h
│   ├── policy.c/.h
│   ├── cache.c/.h
│   ├── logger.c/.h
│   ├── reputation.c/.h
│   └── util.c/.h
├── tests/
│   ├── unit/
│   ├── integration/
│   └── fixtures/
├── config/
│   ├── allowlist.txt
│   └── blocklist.txt
├── docs/
│   ├── architecture.md
│   ├── threat-model.md
│   └── demo.md
├── Makefile
└── README.md
```

## Standard issue format

Create each GitHub issue with these sections:

```md
## Why this exists
## What to build
## Learning goals
## Acceptance criteria
## Verification
## Security and privacy boundaries
## Depends on
## Out of scope
```

Use labels: `P0`, `P1`, `area:core`, `area:networking`, `area:security`, `area:testing`, `area:docs`, and `good-first-task` where suitable.

---

# Phase 1 — Working Concurrent Proxy

## Issue 0 — Open-source foundation and community health files

**Labels:** `P0`, `area:docs`, `area:security`

### Why this exists

An open-source security project needs clear rules for use, contribution, support, and vulnerability reporting before strangers begin using or contributing to it.

### What to build

- Add every file listed in **Required before the first public release** above.
- Decide and add the complete licence text only after the maintainers agree on the licence.
- Create GitHub issue forms and a pull-request template.
- Add initial CI that builds with strict warnings and runs the test suite.
- Enable the listed repository security settings and record which ones were enabled in `docs/release-process.md`.

### Acceptance criteria

- GitHub’s community profile marks README, licence, contributing guidelines, and code of conduct as present.
- The Security tab shows `SECURITY.md` and private vulnerability reporting is enabled where available.
- A test pull request runs CI automatically.
- The repository contains no keys, compiled binaries, captured browsing data, or personal data.

### Verification

- Review the GitHub community profile checklist.
- Open a sample bug issue and a sample pull request to confirm the templates appear.
- Run a secret scan and inspect `.gitignore` against generated files.

### Depends on

Nothing. This can be started alongside Issue 1.

### Out of scope

Funding, governance, release signing, and SBOM publication are deferred until the project has a working baseline.

## Issue 1 — Repository foundation and reproducible build

**Labels:** `P0`, `area:core`, `good-first-task`

### Why this exists

The team needs one repeatable way to compile and run the same program on every laptop.

### What to build

- Create the directory structure, `.gitignore`, `README.md`, and a strict `Makefile`.
- Add `make`, `make test`, `make clean`, and `make sanitize` targets.
- Add a tiny `hello_proxy` program to prove the compiler works.

### Learning goals

Compiler warnings, Makefile targets, Linux file permissions, and the write → compile → run cycle.

### Acceptance criteria

- A clean clone builds with `make` and produces no compiler warnings.
- `make clean && make` works.
- `make sanitize` enables AddressSanitizer and UndefinedBehaviorSanitizer.

### Verification

Run `make clean`, `make`, `make test`, and `make sanitize` from a fresh checkout.

### Depends on

Nothing.

---

## Issue 2 — Protocol contract and architecture notes

**Labels:** `P0`, `area:docs`

### Why this exists

The client and proxy need one agreed request format before networking code is written.

### What to build

- Write `docs/architecture.md` showing client → proxy → origin.
- Define the Phase 1 client protocol: one newline-terminated `http://` URL per connection.
- Define expected proxy errors: `400 Bad Request`, `403 Forbidden`, `413 Payload Too Large`, and `502 Bad Gateway`.
- Document limits: maximum URL size, headers, response size, and connection timeout.

### Learning goals

TCP streams, HTTP request/response structure, DNS, ports, and why `recv()` must run in a loop.

### Acceptance criteria

- A new contributor can draw the request flow and explain why the proxy is both a server and a client.
- Request framing and failure responses are documented before implementation.

### Depends on

Issue 1.

---

## Issue 3 — Safe URL parser and domain normalisation

**Labels:** `P0`, `area:core`, `area:security`

### Why this exists

Every later security decision depends on correctly understanding the requested host and path.

### What to build

- Implement `parse_http_url()` for `http://host[:port]/path`.
- Reject unsupported schemes, embedded credentials, empty hosts, control characters, malformed ports, fragments, and overlong values.
- Lowercase and normalise the hostname for comparisons while preserving the request path separately.
- Return a typed parse result rather than scattering string logic through the proxy.

### Learning goals

Pointers, structs, bounded copying, null termination, `strstr`, `snprintf`, and ownership of allocated memory.

### Acceptance criteria

- Valid URLs with and without a path parse correctly.
- Malformed URLs are rejected without crashing or reading outside a buffer.
- Tests include at least 20 valid and invalid cases.

### Verification

`make test` and the sanitizer build pass.

### Depends on

Issue 2.

---

## Issue 4 — TCP server skeleton and explicit error handling

**Labels:** `P0`, `area:networking`

### Why this exists

The proxy needs a reliable listening socket before it can proxy anything.

### What to build

- Implement `socket`, `setsockopt(SO_REUSEADDR)`, `bind`, `listen`, and `accept` on configurable port `8080`.
- Implement complete request reads with a maximum request size and timeout.
- Return a useful HTTP error page for malformed input instead of exiting the server.

### Learning goals

File descriptors, network byte order, blocking calls, and socket lifecycle.

### Acceptance criteria

- `nc localhost 8080` can send a sample request and receive a valid error or acknowledgement.
- Restarting the server does not normally fail with “Address already in use”.
- The listening socket stays alive after a bad client request.

### Depends on

Issue 3.

---

## Issue 5 — Outbound DNS and HTTP origin fetcher

**Labels:** `P0`, `area:networking`, `area:core`

### Why this exists

The proxy must be able to resolve a hostname, contact a web origin, and forward the exact bytes it receives.

### What to build

- Implement `getaddrinfo`, outbound TCP connection with a timeout, and `freeaddrinfo`.
- Build an HTTP/1.0 `GET` request using `Host` and `Connection: close`.
- Stream origin bytes to a supplied output socket using `send_all()`.
- Map DNS/connect/read failures to a safe `502 Bad Gateway` response.

### Learning goals

DNS resolution, TCP client sockets, partial sends, raw byte handling, and `fwrite` versus `printf`.

### Acceptance criteria

- A command-line fetch test retrieves `http://example.com/`.
- A non-existent domain returns 502 without killing the proxy.
- Large responses are streamed rather than stored entirely in a fixed stack buffer.

### Depends on

Issue 4.

---

## Issue 6 — Single-threaded forward proxy

**Labels:** `P0`, `area:core`, `area:networking`

### Why this exists

Before concurrency is added, the complete request path must work in the simplest possible form.

### What to build

- Combine the listener, parser, and origin fetcher.
- Accept one client, fetch one allowed HTTP URL, forward the response, and close both client and origin sockets.
- Add a small command-line client that saves output to a binary `.html` file.

### Acceptance criteria

- Sending `http://example.com/` to the proxy produces a saved HTML response.
- The proxy handles one request at a time correctly.
- All sockets close on success and failure paths.

### Depends on

Issues 3–5.

---

## Issue 7 — Concurrent worker model with safe argument ownership

**Labels:** `P0`, `area:core`, `area:networking`

### Why this exists

The main real-world requirement is serving several clients without one slow origin blocking everybody else.

### What to build

- Move per-client work into `handle_client(void *)`.
- Allocate a separate heap-owned `ClientArgs` object for every accepted connection.
- Copy the client socket into that object, pass it to `pthread_create`, extract it inside the worker, then free the object exactly once.
- Detach worker threads, or use a documented join strategy.
- Add a bounded concurrency limit to avoid unlimited thread creation.

### Learning goals

`pthread_create`, detached threads, race conditions, stack versus heap lifetime, and the loop-variable bug.

### Acceptance criteria

- Three or more simultaneous clients receive the correct response.
- No worker uses the wrong client socket.
- Thread creation failure closes the client socket and frees its arguments.

### Verification

Run parallel client tests and `make sanitize`.

### Depends on

Issue 6.

---

## Issue 8 — Phase 1 integration tests and baseline demo

**Labels:** `P0`, `area:testing`, `area:docs`

### Why this exists

The base assignment should be demonstrably complete before security features make debugging harder.

### What to build

- Add local-origin integration tests for success, malformed URL, DNS failure, oversized input, and multiple concurrent clients.
- Add `docs/demo-phase-1.md` with exact commands and expected results.
- Add a resource checklist: all allocations freed and all sockets closed.

### Acceptance criteria

- `make test` proves all Phase 1 flows.
- Two clean demo runs produce the same result.
- The team can demonstrate concurrent requests and explain the heap-owned worker arguments.

### Depends on

Issue 7.

---

# Phase 2 — Security-Aware and More Valuable

## Issue 9 — Privacy-aware structured request logging

**Labels:** `P1`, `area:security`, `area:core`

### Why this exists

Logs make a proxy operationally useful, but careless logging can leak private data.

### What to build

- Add a mutex-protected append-only log writer.
- Log timestamp, request ID, normalised host, decision, response status, bytes forwarded, and duration.
- Remove URL credentials, query strings, fragments, and request bodies from logs.
- Add log rotation guidance; do not build a complex log platform.

### Acceptance criteria

- Concurrent requests produce complete, non-interleaved log lines.
- A URL containing `?token=secret` never records `secret`.
- Logging errors do not terminate the proxy.

### Depends on

Issue 7.

---

## Issue 10 — Allowlist and blocklist policy engine

**Labels:** `P1`, `area:security`

### Why this exists

An organisation needs a simple, explainable way to permit or deny destinations.

### What to build

- Load newline-delimited rules from `config/allowlist.txt` and `config/blocklist.txt` at startup.
- Support exact hosts and explicitly documented subdomain rules.
- Apply the policy before DNS lookup or origin connection.
- Return a clean `403 Forbidden` page with a non-sensitive reason.

### Acceptance criteria

- A blocked host never triggers DNS resolution or an outbound connection.
- Case variations cannot bypass a block rule.
- Tests cover exact matches, subdomains, comments, blank lines, and malformed rules.

### Depends on

Issues 3 and 7.

---

## Issue 11 — DNS safety and SSRF protection

**Labels:** `P0`, `area:security`, `area:networking`

### Why this exists

A proxy must not become a route into localhost, private networks, cloud metadata services, or other internal systems.

### What to build

- Reject literal loopback, private, link-local, multicast, and unspecified IPv4/IPv6 addresses.
- After DNS resolution, reject every unsafe returned address before connecting.
- Re-check addresses at connection time to reduce DNS-rebinding risk.
- Document the allowed-network policy in `docs/threat-model.md`.

### Acceptance criteria

- Requests for `127.0.0.1`, `localhost`, RFC1918 ranges, and link-local ranges are rejected.
- A hostname resolving to a private address is rejected.
- No unsafe address is connected to in tests.

### Depends on

Issues 3, 5, and 10.

---

## Issue 12 — Thread-safe bounded response cache

**Labels:** `P1`, `area:core`, `area:performance`

### Why this exists

Caching makes repeated safe HTTP requests faster and demonstrates correct shared-state synchronisation.

### What to build

- Cache only successful, bounded-size, non-personalised HTTP GET responses.
- Use a cache mutex and a simple documented eviction policy such as LRU or FIFO.
- Never cache responses with `Set-Cookie`, `Authorization`, or an unapproved cache-control directive.
- Clearly log cache hit/miss without recording full URLs with queries.

### Acceptance criteria

- Repeating an eligible request produces a cache hit.
- Concurrent cache access does not corrupt data under sanitizers.
- Responses with cookies or credentials are never cached.

### Depends on

Issues 7, 9, and 11.

---

## Issue 13 — HTTPS CONNECT tunnelling without inspection

**Labels:** `P1`, `area:security`, `area:networking`

### Why this exists

Most practical browsing uses HTTPS. CONNECT adds useful real-world capability without breaking encryption.

### What to build

- Parse `CONNECT host:443` safely.
- Apply the same allow/block, DNS safety, rate, and reputation policy before connection.
- Connect to the permitted destination, send `200 Connection Established`, and relay bytes both directions.
- Use `poll`/`select` or a carefully tested relay loop with timeouts.

### Security boundaries

- Do not decrypt, inspect, modify, store, or log HTTPS content.
- Do not accept arbitrary private-network ports; start with port 443 only.

### Acceptance criteria

- A permitted HTTPS site can be tunnelled by a compatible client.
- A blocked or private destination is rejected before tunnel creation.
- Both tunnel sockets close correctly when either side disconnects.

### Depends on

Issues 7, 10, and 11.

---

## Issue 14 — Threat-intelligence provider interface and offline tests

**Labels:** `P1`, `area:security`, `area:core`

### Why this exists

Reputation data can improve a security decision, but a project must remain testable and useful without an external API.

### What to build

- Define a `ReputationProvider` interface returning `safe`, `suspicious`, `malicious`, or `unavailable`.
- Implement an offline fixture provider for deterministic tests.
- Add result caching and a timeout so a slow provider cannot block the proxy.
- Use “unavailable” as an observable event, not an automatic assumption that a host is malicious.

### Security and privacy boundaries

- Never send credentials, request bodies, full private URLs, or user identifiers to a third-party provider.
- The initial provider input is the normalised host only, unless explicit consent and a privacy review approve more.

### Acceptance criteria

- Offline tests prove safe, suspicious, malicious, timeout, and unavailable decisions.
- A provider failure does not crash or hang the proxy.

### Depends on

Issues 9–11.

---

## Issue 15 — Optional live threat-feed adapter

**Labels:** `P2`, `area:security`, `external-dependency`

### Why this exists

Live reputation data makes the demo more realistic, but must not become a hard dependency or leak data.

### What to build

- Integrate one approved provider after reviewing its terms, cost, privacy policy, and rate limits.
- Load its API key only from an environment variable; never commit it.
- Add rate limiting, error handling, and a visible “feed unavailable” state.
- Keep the offline provider as the default test mode.

### Acceptance criteria

- No secret appears in source, logs, test fixtures, or screenshots.
- Disabling the API key returns to offline mode cleanly.
- A known test fixture can demonstrate a blocked reputation decision without querying a harmful real URL.

### Depends on

Issue 14 and explicit approval to use the selected provider.

---

## Issue 16 — Explainable risk scoring and decision page

**Labels:** `P1`, `area:security`

### Why this exists

“Blocked” should have a reason a user or examiner can understand.

### What to build

- Combine policy, network safety, and reputation outcomes into documented decision reasons.
- Return a simple HTML error page containing a request ID and safe reason category.
- Keep full technical detail only in server logs.

### Acceptance criteria

- A private-address block, blocklist block, and malicious-reputation block produce distinguishable safe messages.
- The client never receives secret configuration, provider responses, or internal IP details.

### Depends on

Issues 10, 11, and 14.

---

## Issue 17 — Load, failure, and leak testing

**Labels:** `P0`, `area:testing`

### Why this exists

Security features are only credible if the server remains stable under bad input and concurrent load.

### What to build

- Add automated tests for malformed requests, oversized input, blocked hosts, private addresses, DNS failures, origin timeouts, cache races, and CONNECT disconnects.
- Add a repeatable concurrent-load script.
- Run AddressSanitizer, UndefinedBehaviorSanitizer, and Valgrind where available.

### Acceptance criteria

- No crashes, hangs, double-frees, or sanitizer reports in the supported test suite.
- The proxy remains usable after malformed or blocked requests.
- Concurrent requests produce correct, non-mixed responses.

### Depends on

Issues 9–16.

---

## Issue 18 — Documentation, demo script, and viva preparation

**Labels:** `P0`, `area:docs`

### Why this exists

The project should be understandable and demonstrable by somebody who did not build it.

### What to build

- Complete README: purpose, architecture, build, run, configuration, limits, and safe-use policy.
- Create `docs/demo.md` with a five-minute script:
  1. Start proxy and client.
  2. Fetch an allowed HTTP page.
  3. Show simultaneous clients.
  4. Show blocklist rejection.
  5. Show private-network rejection.
  6. Show cache hit.
  7. Show safe logs.
  8. Optionally show HTTPS CONNECT and offline reputation result.
- Add a viva question sheet covering sockets, DNS, threads, mutexes, the loop-variable bug, SSRF, caching, and privacy.

### Acceptance criteria

- A teammate can follow the demo twice from a clean build without asking for missing steps.
- Every feature shown in the demo is implemented and tested.
- Documentation clearly states that this is an educational proxy, not a replacement for an enterprise secure web gateway.

### Depends on

Issue 17.

---

## Issue 19 — Release hygiene and open-source security automation

**Labels:** `P1`, `area:security`, `area:docs`, `area:testing`

### Why this exists

Once the project is usable, releases need to be traceable, reproducible, and easier for downstream users to assess.

### What to build

- Add `CHANGELOG.md` and `docs/release-process.md`.
- Enable or add CodeQL scanning for C/C++ and Dependabot updates for GitHub Actions.
- Add `CODEOWNERS` for security-sensitive paths when team ownership is agreed.
- Generate an SBOM as a release artifact if the project distributes a binary or adds external dependencies.
- Add `SECURITY-INSIGHTS.yml` only after its declared practices are implemented.

### Acceptance criteria

- A tagged release can be built from a clean checkout using documented commands.
- Release notes link to the exact tag, checksum, and changelog section.
- Security automation has no unnecessary write permissions and does not require secrets for pull-request builds.
- The project does not claim an SBOM, CodeQL coverage, or a security policy that is not actually maintained.

### Verification

- Perform one dry-run release from a clean clone.
- Confirm CodeQL and CI complete on a pull request.
- Review the generated SBOM rather than committing an unverified manually written inventory.

### Depends on

Issues 0, 17, and 18.

---

# Dependency map

```text
0 -> 1 -> 2 -> 3 -> 4 -> 5 -> 6 -> 7 -> 8
0 -> community health files and CI
8 -> 9 -> 10 -> 11 -> 12 -> 17 -> 18 -> 19
                         -> 13 ------^
                         -> 14 -> 15
                         -> 16 ------^
```

# Recommended implementation order

1. Complete Issue 0 and finish Issues 1–8 as one team. This is the minimum complete assignment with a responsible public repository.
2. Split Phase 2 work only after Issue 8 passes:
   - Member A: Issues 9 and 12 (logs and cache).
   - Member B: Issues 10 and 11 (policy and SSRF protection).
   - Member C: Issue 13 (HTTPS CONNECT tunnel).
   - Member D: Issues 14 and 16 (offline reputation and decision messages).
3. Work on Issue 15 only after the team has approval for an external provider and a safe demo key.
4. Everyone owns Issues 17–19.

# Definition of project completion

The project is complete when:

- It builds cleanly from a fresh checkout.
- It serves multiple clients correctly.
- It handles expected failures safely rather than crashing.
- It blocks disallowed and unsafe destinations before outbound connection.
- HTTPS is tunnelled without content interception.
- Shared logs and cache are safe under concurrent requests.
- Optional reputation data fails safely and does not expose private request data.
- The demo, tests, and documentation are reproducible.
- A public release includes its licence, contributor guidance, security reporting route, and maintained automation.
