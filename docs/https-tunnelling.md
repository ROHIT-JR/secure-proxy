# HTTPS Tunnelling (CONNECT)

Most browsing today uses HTTPS (Hypertext Transfer Protocol Secure). SecureBrowse supports it with the standard `CONNECT` method, **without ever breaking the encryption**. Every acronym is spelled out on first use.

## What it does, in one picture

```text
Client ──"CONNECT example.com:443"──► SecureBrowse ──TCP connect──► example.com:443
Client ◄──"200 Connection Established"── SecureBrowse
Client ◄════ encrypted TLS bytes, relayed blindly in both directions ════► Origin
```

1. The client asks for a tunnel to `host:443`.
2. SecureBrowse runs the **same checks as for plain HTTP**: allowlist/blocklist, network-safety (SSRF, Server-Side Request Forgery) and the concurrency limit. If any check fails, the client gets a `403` and **no tunnel is created**.
3. SecureBrowse connects to the destination and answers `HTTP/1.1 200 Connection Established`.
4. From then on it only copies bytes between the two sockets, in both directions, until either side finishes.

## What it never does

- It **does not decrypt** TLS (Transport Layer Security) traffic.
- It **does not generate or present any certificate**. The client's TLS handshake happens directly with the real origin, so the client sees the origin's own certificate.
- It **does not inspect, modify, store or log** the bytes that pass through. The relay loop copies a buffer from one socket to the other and counts it; nothing else touches it.
- It **does not bypass certificate checks**: the client verifies the certificate itself, exactly as it would without a proxy.

This is a deliberate safety boundary of the project, not a missing feature.

## Rules

| Rule | Detail |
| --- | --- |
| **Port** | Only port **443**. Any other port gets `403` (decision `blocked_port`) before anything is contacted. Operators and tests can change the single allowed port with `PROXY_CONNECT_PORT`. |
| **Request format** | `CONNECT host:port` with an optional `HTTP/1.0` or `HTTP/1.1`. The port is mandatory. Credentials (`user@`), paths, IPv6 brackets, extra tokens, control characters and unknown versions are rejected with `400`. |
| **Headers** | The header lines after the `CONNECT` line are read up to a blank line, at most 8 KiB. The relay starts *exactly* at the blank line, so bytes a client sends early (a TLS "ClientHello") are relayed, not swallowed. |
| **Policy** | Blocklist, then allowlist mode, exactly as for HTTP ([`policy.md`](policy.md)). |
| **Network safety** | Loopback, private, link-local (cloud metadata), multicast and other unsafe addresses are refused, including tricky numeric spellings ([`threat-model.md`](threat-model.md)). |
| **Capacity** | A tunnel occupies one worker thread, so the 64-client limit also acts as the rate limit for tunnels. |
| **Idle time** | A tunnel with no traffic is closed after 120 seconds (`PROXY_TUNNEL_IDLE_SECONDS`, 1 to 3600). |
| **Write stalls** | A peer that stops reading is dropped after 30 seconds. |

## When a side disconnects

When one side finishes (clean close or error), SecureBrowse tells the other side with a write-shutdown so it sees the end of the stream **straight away**, keeps relaying the other direction until it also ends or stays idle for 5 seconds, then closes both sockets. A client that vanishes therefore ends the origin connection, and an origin that hangs up ends the client connection, both within moments rather than waiting for the idle timer. The origin socket has a single `close()` on every path.

## Logging

Tunnels are logged like every other request, with **metadata only**:

```text
2026-10-22T10:00:00Z req=21 host=example.com decision=allowed status=200 bytes=48213 duration_ms=1530 method=connect
2026-10-22T10:00:02Z req=22 host=127.0.0.1 decision=blocked_private status=403 bytes=0 duration_ms=0 method=connect
```

`bytes` is the total relayed in both directions. The port and the content are never logged. See [`logging.md`](logging.md).

## Reputation checks

The planned reputation check (a later issue) will be added at the shared destination-check step that both plain HTTP and CONNECT already use, so tunnels will get it without further changes.

## What the tests prove

- `tests/test_parser.c` (40 new checks): valid forms, and every malformed form listed under "Rules".
- `tests/integration/run_integration_tests.py`, against the real proxy:
  - 1 MiB of random binary data crosses the tunnel unchanged in both directions; bytes sent right behind the headers are relayed.
  - **A real TLS handshake** with a self-signed server succeeds through the tunnel, the client's verification (trusting *only* the origin's certificate) passes, the certificate it sees is byte-for-byte the origin's, the encrypted request/response completes end to end, and the proxy's log contains none of the decrypted request.
  - A client disconnect closes the origin side, and an origin disconnect closes the client side, **promptly** (well inside the idle timeout, so the idle timer is not what did it). An idle tunnel is closed by the idle timeout. File-descriptor count returns to baseline.
  - Wrong-port, blocklisted, private/loopback/metadata and unresolvable targets are refused **before** any tunnel; a connection-counting listener recorded zero connections.
  - Malformed requests and oversized headers get `400`; normal requests still work afterwards.

## Limits

- Only the HTTPS port is allowed by default; there is no per-destination port list.
- Because content is invisible by design, SecureBrowse cannot detect malicious content carried inside an HTTPS tunnel to a permitted destination.
- IPv6 literal targets (`CONNECT [::1]:443`) are rejected by the parser.
