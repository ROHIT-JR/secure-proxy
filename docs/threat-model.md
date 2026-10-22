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

- Allowlist/blocklist policy checks happen **before** DNS resolution or any outbound connection (Issue 10; see `docs/policy.md`). Allowlists fail closed, and a policy file the operator explicitly configured but that cannot be read stops the proxy from starting.
- Every destination address is checked against the allowed-network policy below, both when a name is resolved and again immediately before (and just after) connecting. Names are resolved exactly once and the checked address is the one used, which defeats DNS rebinding by construction (Issue 11; see "Allowed-network policy").
- Logs record only the validated hostname — never credentials, query strings, fragments, paths, or the raw request line — are written with owner-only permissions, and cannot be interleaved or forged by hostile input (Issue 9; see `docs/logging.md`).
- The cache never stores responses containing `Set-Cookie`, `Authorization`, unapproved cache-control directives, partial bodies, non-200 statuses, or responses to URLs with a query string; it is bounded (entries, bytes, per-entry size, lifetime) and consulted only after the policy and network-safety checks (Issue 12; see `docs/cache.md`).
- `CONNECT` tunnels are limited to the HTTPS port, go through the same policy and network-safety checks as plain requests *before* the tunnel exists, are bounded by the worker limit and an idle timeout, and are relayed blindly: the bytes are never examined, stored or logged (Issue 13; see `docs/https-tunnelling.md`).
- Blocked requests get a page that names only a safe reason category and the request ID; rules, addresses, provider answers and scores stay in the server log, and nothing the client sent is echoed back (Issue 16; see `docs/risk-scoring.md`).
- A slow, failing or hung reputation provider cannot stall the proxy: lookups have a timeout, a bound on outstanding calls, and a short failure cache, and "unavailable" is logged as an event instead of being treated as a verdict (Issue 14; see `docs/reputation.md`).
- The reputation provider only ever receives the normalised hostname, never full URLs, credentials, or request bodies (Issue 14).
- A NUL byte in a request line is rejected outright, so a client cannot hide bytes from the validator by ending the C string early (found by the hostile-input battery; see `docs/testing.md`).
- Every request has a maximum size and a connection timeout, so a slow or oversized client cannot tie up a worker thread indefinitely.

## Allowed-network policy

The proxy connects **only to public, globally routable addresses**. The check runs on the *address*, not the name, so it cannot be dodged by choosing a clever hostname.

| Refused | Examples | Why |
| --- | --- | --- |
| Loopback | `127.0.0.0/8`, `::1` | Would let a client reach services bound to the proxy host itself. |
| Private (RFC 1918) and unique-local | `10/8`, `172.16/12`, `192.168/16`, `fc00::/7` | Internal networks behind the proxy. |
| Link-local | `169.254/16` (**includes the cloud metadata address `169.254.169.254`**), `fe80::/10` | Cloud instance metadata can hand out credentials. |
| Unspecified / "this network" | `0.0.0.0/8`, `::` | Many systems treat these as "this machine". |
| Carrier-grade NAT, benchmarking, documentation, reserved, broadcast | `100.64/10`, `198.18/15`, `192.0.2/24`, `240/4` | Not valid public destinations. |
| Multicast | `224/4`, `ff00::/8` | Not a unicast destination. |
| IPv6 forms that *contain* an IPv4 address | `::ffff:127.0.0.1` (mapped), `64:ff9b::7f00:1` (NAT64), `2002:7f00:1::` (6to4), `::127.0.0.1`, Teredo | The embedded IPv4 address is judged by the same rules. |
| Local names (refused with **no DNS lookup**) | `localhost`, `*.localhost`, `*.local` | Never meant to leave the machine. |
| Any unknown or malformed address | | Fail closed. |

### How the checks are layered

1. **Names:** `localhost`-style names are refused before any lookup.
2. **Numeric spellings:** the host is first parsed with `AI_NUMERICHOST`, which *never* queries DNS. This catches every spelling the system resolver accepts for the same address: `127.0.0.1`, `2130706433` (decimal), `0x7f.1` (hex), `017700000001` (octal) and `127.1` all resolve to loopback and are refused. These are classic SSRF filter bypasses, and the unit tests resolve each one through the real resolver to prove it.
3. **After DNS:** if the name is not numeric it is resolved once, and **every** returned address must be safe. If even one is not, the whole destination is refused. A mix of public and private answers is a known rebinding trick.
4. **At connection time:** each address is checked again immediately before `connect()`, and the peer actually reached is checked again afterwards.

Because step 3 resolves once and step 4 connects to *that same checked address*, there is no second lookup that an attacker's DNS server could answer differently ("DNS rebinding").

The client only ever sees a `403 Forbidden` page whose safe reason category is "Destination not permitted" (see [`risk-scoring.md`](risk-scoring.md)). It never learns which address a name resolved to. Refusals are logged as `decision=blocked_private`.

### Operator notes and limits

- **Testing override:** `PROXY_UNSAFE_ALLOW_PRIVATE_NETWORKS=1` turns all of the above off so the automated tests can use a loopback origin server. It is off by default and prints a loud warning when enabled. Never set it on a real deployment.
- **Not simulated end to end:** the tests prove the address rules, the numeric-spelling bypasses and that no TCP connection is made to forbidden addresses. They do not stand up a malicious DNS server to flip answers between lookups; the rebinding defence is structural (single resolution, checked address reused) rather than demonstrated against a live attacker.
- **IPv6 literals in URLs** (`http://[::1]/`) are already rejected by the URL parser as invalid hosts; the IPv6 rules apply to AAAA records returned by DNS.

## Explicit non-goals

- **No transparent HTTPS (Hypertext Transfer Protocol Secure) interception.** SecureBrowse does not generate TLS (Transport Layer Security) certificates, does not perform a "man-in-the-middle" on HTTPS traffic, and does not decrypt or inspect HTTPS content. HTTPS is handled purely via `CONNECT` tunnelling: the proxy relays encrypted bytes between client and origin without reading them. This is implemented and tested with a real TLS handshake through the tunnel: the client sees the origin's own certificate and the proxy's log never contains the decrypted request (see `docs/https-tunnelling.md`).
- **Not a replacement for a commercial secure web gateway.** SecureBrowse does not claim enterprise-grade threat coverage, does not do deep packet inspection, and is not hardened against a determined, well-resourced attacker.
- **No content filtering beyond hostname-level policy.** SecureBrowse decides based on hostname and address, not on page content.

## Residual risks

- A reputation provider marked "unavailable" is treated as an observable event, not an automatic block — there is currently **no fail-closed option**: when the provider is unavailable the request proceeds (fail-open) and the outage is logged as `rep=unavailable` with a reason. A configurable fail-closed mode is a possible future improvement.
- Because HTTPS content is never inspected, SecureBrowse cannot detect malicious content carried over an otherwise-permitted HTTPS destination.
- DNS-rebinding protection reduces but does not eliminate the race between "check" and "use"; a sufficiently fast rebind between the final check and `connect()` remains a theoretical (TOCTOU, Time-Of-Check-To-Time-Of-Use) risk, which is why the check is performed as close to connection time as practical.
