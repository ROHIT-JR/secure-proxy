# Viva Preparation

Short, honest answers a teammate can give. Each ends with where to look in the code.

## Core concepts
- **Socket**: an OS handle for one end of a network connection. The proxy makes a listening socket (`socket`, `bind`, `listen`) and one per client from `accept()` (`src/proxy.c`).
- **DNS (Domain Name System)**: turns a name into addresses. We call `getaddrinfo` once, then check *every* returned address (`src/origin_client.c`).
- **Threads**: thread-per-connection with `pthread_create`, detached, limit 64 active (a 65th gets `503`). Per-client data is heap-allocated so each thread owns its own copy.
- **Mutex**: guards shared state: the active-client counter, the cache, the logger, the reputation cache.
- **The loop-variable bug**: passing `&client_fd` of a loop variable to a thread means the next `accept()` overwrites it before the thread reads it. We pass a `malloc`'d `ClientArgs` the thread frees.

## Security
- **SSRF**: tricking the proxy into reaching internal systems (e.g. cloud metadata at 169.254.169.254). We block loopback, private, link-local, IPv6 mapped/NAT64/6to4/Teredo; refuse numeric spellings like `2130706433`; refuse if *any* resolved address is unsafe; re-check at connect time (`src/policy.c`).
- **Blocklist/allowlist**: checked before DNS; blocklist wins; leading-dot rules match subdomains at a dot boundary only.
- **HTTPS**: `CONNECT` tunnel, port 443 only, byte relay with `poll()`. No decryption, no certificate tricks.
- **Reputation**: only a bare hostname leaves the program; "provider unavailable" is logged as an event, not a verdict, and the proxy fails open (documented trade-off).
- **Risk score**: rules 100, malicious 90, suspicious 50, unavailable 10; block at 80 (`src/decision.c`, `docs/risk-scoring.md`).
- **Caching**: only `200`, no cookies/credentials/query strings; LRU bounded by entries, bytes and per-entry size; lookups return copies.
- **Privacy**: logs hold host, decision, status, size, duration — never paths, queries, cookies or bodies; file mode 600.

## Testing
- Unit tests per module, an end-to-end Python suite, a seeded concurrent load test, AddressSanitizer/UBSan/LeakSanitizer runs, and mutation checks (break the code on purpose to prove the tests fail). See `docs/testing.md`.

## Tricky questions — be honest
- *Does it scale?* No: thread-per-connection with a 64 cap suits a course project, not a production gateway. An event loop (`epoll`) would scale better.
- *Why fail open on reputation?* A dead threat feed must not take browsing down; policy and SSRF checks still apply. Configurable fail-closed is future work.
- *Is the live threat feed built?* No (Issue #16 needs an approved provider and key). The interface and offline fixture are tested.
- *Was Valgrind run?* Not locally (not installed); the CI job is non-blocking. Sanitizers were run.
- *Is HTTPS inspected?* No, deliberately.
- *DNS rebinding?* We resolve once and connect to the checked address, then re-check the connected peer.
