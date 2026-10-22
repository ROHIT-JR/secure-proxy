# Changelog

All notable changes to this project are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

Nothing yet.

## [0.2.0] - Phase 2: security-aware proxy

### Added
- Privacy-aware request logging (no paths, queries, credentials; file mode 600).
- Allowlist/blocklist policy engine, checked before any DNS lookup.
- SSRF (Server-Side Request Forgery) protection for IPv4 and IPv6, re-checked at connect time.
- Thread-safe, bounded LRU response cache with strict eligibility rules.
- HTTPS `CONNECT` tunnelling (byte relay only; no interception).
- `ReputationProvider` interface with an offline fixture provider.
- Explainable risk scoring and a safe block page with a request ID.
- Load, failure and leak testing (sanitizers, optional Valgrind), a repeatable five-minute demo (`make demo-check`), and viva preparation.

### Fixed
- NUL bytes in request lines are rejected.
- A silent origin now yields `504`; an origin that sends nothing yields `502`.
- Graceful shutdown on SIGTERM/SIGINT so leak checkers can report.

### Known limits
- Live threat-feed adapter not built (Issue 16).
- Reputation checks fail open when the provider is unavailable.
- Valgrind CI job exists but was not run locally.

## [0.1.0] - Phase 1: working concurrent proxy

### Added
- TCP listener, safe HTTP URL parsing, DNS resolution and origin fetching with `502` on failure.
- Thread-per-connection concurrency with heap-owned per-client arguments.
- Integration tests and a repeatable Phase 1 demo.

[Unreleased]: https://github.com/ROHIT-JR/secure-proxy/compare/v0.2.0...HEAD
