# Request Logging

SecureBrowse writes one line per request to an append-only log file. Logs make a proxy useful to operate, but careless logging leaks private data, so this log is designed to be **safe by construction**. This page explains the format, the privacy guarantees, how to configure it, and how to rotate it. Every acronym is spelled out on first use.

## Where the log goes

| Setting | Value |
| --- | --- |
| Default file | `proxy.log` in the directory the proxy was started from |
| Override | set the `PROXY_LOG_FILE` environment variable to any path |
| File permissions | `0600` (readable and writable only by the user running the proxy) |
| Ignored by Git | yes — `*.log` and `logs/` are in `.gitignore` |

```sh
PROXY_LOG_FILE=/var/log/securebrowse/proxy.log ./bin/proxy
```

If the file cannot be opened, the proxy prints one warning to the terminal and keeps serving traffic with logging disabled. **A logging problem can never stop the proxy.**

## Line format

Each request produces exactly one line of space-separated `key=value` fields (easy to read, and easy to search with `grep` or `awk`):

```text
2026-10-17T09:21:05Z req=1 host=127.0.0.1 decision=allowed status=200 bytes=256 duration_ms=2
2026-10-17T09:21:05Z req=2 host=- decision=bad_request status=400 bytes=0 duration_ms=0
2026-10-17T09:21:05Z req=4 host=nope-xyz.invalid decision=bad_gateway status=502 bytes=0 duration_ms=44
2026-10-17T09:21:05Z req=5 host=- decision=too_large status=413 bytes=0 duration_ms=9
```

| Field | Meaning |
| --- | --- |
| timestamp | Time the request finished, in UTC (ISO 8601 format). |
| `req` | Request ID. Unique and increasing within one proxy run. |
| `host` | The validated, lowercased hostname. `-` when the request was rejected before a host could be trusted. |
| `decision` | What the proxy did (see below). |
| `status` | The HTTP (Hypertext Transfer Protocol) status code: the origin's status when a page was forwarded, or the proxy's own error code. `0` means "no response was sent". |
| `bytes` | Bytes of origin response forwarded to the client. Always `0` for errors the proxy generates itself. |
| `duration_ms` | Time spent handling the request, in milliseconds. |
| *extras* (optional) | Extra `key=value` fields after `duration_ms`. Today `cache=hit\|stored\|miss\|bypass` (see [`cache.md`](cache.md)) `method=connect` (see [`https-tunnelling.md`](https-tunnelling.md)) and `rep=safe|suspicious|malicious|unavailable`, plus `rep_reason=...` when unavailable (see [`reputation.md`](reputation.md)), and `risk=0..100`, the combined risk score (see [`risk-scoring.md`](risk-scoring.md)). Extras are always fixed tokens chosen by the proxy, never client data. |

### Decision values

| `decision` | Meaning |
| --- | --- |
| `allowed` | The page was fetched and forwarded. |
| `bad_request` | The request line was not a valid `http://` URL, or contained a NUL byte (400). |
| `too_large` | The request line exceeded 2048 bytes (413). |
| `timeout` | The client did not finish sending its request line in time (408). |
| `bad_gateway` | DNS (Domain Name System) lookup or connection to the origin failed, or the origin hung up without sending anything (502). |
| `gateway_timeout` | The origin accepted the connection but did not respond in time (504). |
| `relay_error` | The origin or client connection broke after forwarding had started. |
| `overloaded` | The 64-client concurrency limit was reached (503). |
| `client_closed` | The client connected and disconnected without sending a request (for example a port scan or health check). |
| `internal_error` | The proxy could not allocate memory or start a worker thread. |
| `blocked_policy` | The host is on the blocklist, or not on the allowlist ([`policy.md`](policy.md)) (403). |
| `blocked_private` | The destination is, or resolves to, a loopback/private/link-local/other unsafe address (403). |
| `blocked_reputation` | The reputation provider classified the host as malicious (403, see [`reputation.md`](reputation.md)). |
| `blocked_port` | A `CONNECT` asked for a port other than the HTTPS port (403). |

> Later Phase 2 issues add more decisions (for example `blocked_policy` and `blocked_private_address`). The format does not change.

## Privacy guarantees

The log never contains any of the following, and automated tests prove it:

- **URL credentials** (`user:password@host`)
- **Query strings** (`?token=secret`)
- **Fragments** (`#section`)
- **Paths** (`/account/orders/12345`)
- **The raw request line** — even for malformed requests
- **Request bodies** — the proxy never reads them

How this is enforced, in two layers:

1. **Only the validated host is ever handed to the logger.** The URL parser has already rejected credentials and fragments, and the path and query are simply never passed on.
2. **The logger sanitises anyway** (`logger_sanitize_host()` in `src/logger.c`). If a future caller ever passes a full URL by mistake, the logger drops the scheme, path, query, fragment and `user:password@` part, lowercases the rest, and replaces any character that is not a normal hostname character with `_`. That also stops *log injection*: a hostile value containing a newline cannot forge a second, fake log line.

## Concurrency: lines are never interleaved

Many worker threads log at the same time. Each line is built completely in a private buffer, then written with a **single `write()` call while holding a mutex** to a file opened with `O_APPEND`. Two requests can therefore never produce a half-line from one and a half-line from the other. A unit test with 8 threads writing 2000 lines, and an integration test with 40 simultaneous requests, both check this.

## Log rotation guidance

The proxy does not rotate its own log — that would mean building a log platform, which is out of scope. Use the standard Linux tool `logrotate`. Because the file is opened with `O_APPEND`, the `copytruncate` method is safe: the proxy keeps writing to the same file and never needs a restart or a signal.

Example `/etc/logrotate.d/securebrowse`:

```text
/var/log/securebrowse/proxy.log {
    weekly
    rotate 8
    compress
    missingok
    notifempty
    copytruncate
    create 0600 securebrowse securebrowse
}
```

This was checked by hand: after a `copytruncate`-style truncation, the running proxy kept logging at the start of the fresh file with no gap of `NUL` bytes and without being restarted.

Retention is also a privacy decision. Even this log (timestamps plus hostnames) shows what users browsed. Keep it only as long as you need it, and keep the file permissions at `0600`.

## What a logging failure does

| Situation | Behaviour |
| --- | --- |
| Log path cannot be opened at startup | One warning on the terminal; logging disabled; proxy keeps serving. |
| A write fails later (disk full, volume removed) | The failure is counted internally and the line is dropped; the request itself is unaffected. |

Both cases are covered by automated tests (including a real failing write using `/dev/full`).
