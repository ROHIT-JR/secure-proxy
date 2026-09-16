# Threat Model

This document describes what SecureBrowse protects, who it protects against, how it fails safely, and what it deliberately does not attempt. Every acronym is spelled out on first use.

## Assets

- **The proxy host itself**: its CPU, memory, file descriptors, and network access.
- **Internal network reachability**: anything on `localhost`, private IP (Internet Protocol) ranges, or link-local addresses that the proxy host can reach but an external client should not be able to reach through the proxy.
- **Request metadata in logs and cache**: hostnames, decisions, and timings that must not leak credentials or full private URLs (Uniform Resource Locators).
- **Any reputation-provider API (Application Programming Interface) key**, if the optional live threat-feed adapter (Issue 15 in the project plan) is enabled.

## Attackers considered

- **A malicious or careless proxy client**, sending malformed, oversized, or adversarial requests to crash the proxy or exhaust its resources.
- **An attacker who controls DNS (Domain Name System) responses for a domain they own**, attempting to use the proxy as a stepping stone into the proxy host's private network (SSRF, Server-Side Request Forgery).
- **An attacker performing DNS rebinding**: a domain that resolves to a safe address during the policy check, then to a private/internal address at connection time.
- **A passive log reader** (for example, another process on the same host, or a misconfigured log-shipping pipeline) who should not be able to recover credentials or full private URLs from logs.

## Abuse cases

1. **SSRF via a directly requested private address.** A client requests `http://127.0.0.1:9000/` or `http://169.254.169.254/` (a common cloud metadata address). The proxy must reject this before connecting.
2. **SSRF via DNS rebinding.** A client requests `http://attacker-domain.example/`, which resolves to a public IP address during policy evaluation but is re-pointed to `127.0.0.1` or a private range before (or during) the actual connection attempt. See Issue 11 in the project plan: SecureBrowse re-checks the resolved address immediately before connecting, not only once at the start.
3. **Blocklist bypass via case or subdomain tricks.** A client requests `HTTP://Example.COM/` or a subdomain of a blocked domain, hoping string comparison misses it. Hostnames are normalised (lowercased) before every policy comparison.
4. **Resource exhaustion via unbounded threads or unbounded reads.** A client opens many connections or sends an extremely large request, hoping to exhaust memory or threads. SecureBrowse enforces a maximum request size and a bounded concurrency limit.
5. **Credential leakage through logs or cache.** A URL like `http://example.com/?token=secret` must never appear with `secret` intact in a log line or cache key.

## Safety controls in place

- Allowlist/blocklist policy checks happen **before** DNS resolution or any outbound connection (Issue 10).
- Resolved addresses are checked against loopback, private (RFC 1918), link-local, multicast, and unspecified ranges for both IPv4 and IPv6, and re-checked at connection time to reduce DNS-rebinding risk (Issue 11).
- Logs strip credentials, query strings, and fragments before writing (Issue 9).
- The cache never stores responses containing `Set-Cookie`, `Authorization`, or unapproved cache-control directives (Issue 12).
- The reputation provider only ever receives the normalised hostname, never full URLs, credentials, or request bodies (Issue 14).
- Every request has a maximum size and a connection timeout, so a slow or oversized client cannot tie up a worker thread indefinitely.

## Explicit non-goals

- **No transparent HTTPS (Hypertext Transfer Protocol Secure) interception.** SecureBrowse does not generate TLS (Transport Layer Security) certificates, does not perform a "man-in-the-middle" on HTTPS traffic, and does not decrypt or inspect HTTPS content. HTTPS is handled purely via `CONNECT` tunnelling: the proxy relays encrypted bytes between client and origin without reading them.
- **Not a replacement for a commercial secure web gateway.** SecureBrowse does not claim enterprise-grade threat coverage, does not do deep packet inspection, and is not hardened against a determined, well-resourced attacker.
- **No content filtering beyond hostname-level policy.** SecureBrowse decides based on hostname and address, not on page content.

## Residual risks

- A reputation provider marked "unavailable" is treated as an observable event, not an automatic block — an operator who wants fail-closed behavior on provider outage must configure that explicitly; the default is fail-open with logging.
- Because HTTPS content is never inspected, SecureBrowse cannot detect malicious content carried over an otherwise-permitted HTTPS destination.
- DNS-rebinding protection reduces but does not eliminate the race between "check" and "use"; a sufficiently fast rebind between the final check and `connect()` remains a theoretical (TOCTOU, Time-Of-Check-To-Time-Of-Use) risk, which is why the check is performed as close to connection time as practical.
