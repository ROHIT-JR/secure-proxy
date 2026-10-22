# Risk Scoring and the Block Page

"Blocked" should come with a reason a user, or an examiner, can understand. SecureBrowse combines everything it knows about a destination into **one documented decision**, tells the user only a **safe reason category**, and keeps every technical detail in the **server log**. Every acronym is spelled out on first use.

## The signals

| Signal | Where it comes from | Meaning |
| --- | --- | --- |
| **Policy** | The blocklist / allowlist ([`policy.md`](policy.md)) | The access policy refuses this host. |
| **Network** | The SSRF (Server-Side Request Forgery) checks ([`threat-model.md`](threat-model.md)) | The destination is, or resolves to, a private, loopback, link-local or otherwise restricted address. |
| **Port** | The `CONNECT` rules ([`https-tunnelling.md`](https-tunnelling.md)) | A tunnel was requested to a port other than the HTTPS port. |
| **Reputation** | The reputation provider ([`reputation.md`](reputation.md)) | `safe`, `suspicious`, `malicious` or `unavailable`. |

## The scores

Each signal contributes a **risk score from 0 to 100**. The request's risk score is the **highest** score of any signal, so a reassuring signal can never lower the risk of something already dangerous.

| Signal | Score |
| --- | --- |
| Policy refuses the host | **100** |
| Destination on a restricted network | **100** |
| Tunnel to a disallowed port | **100** |
| Reputation `malicious` | **90** |
| Reputation `suspicious` | 50 |
| Reputation `unavailable` (could not tell) | 10 |
| Reputation `safe`, or not checked | 0 |

**A request is blocked when its risk score is 80 or more** (`DECISION_BLOCK_THRESHOLD`). So:

- Rules (100) and a malicious verdict (90) block.
- `suspicious` (50) is **allowed but scored**, so it is visible in the log.
- `unavailable` (10) is **allowed**: not being able to find out is an event to watch, not a reason to assume the worst.

When two signals tie for the highest score, the reason reported is chosen in this fixed order: **port, policy, network, reputation**. The whole decision is a pure function (`decision_evaluate()` in `src/decision.c`) and is tested over every combination of signals.

## What the user sees

A blocked request gets an HTML page with `403 Forbidden`, the **request ID**, and one of four **safe reason categories**, each with different wording and a `data-reason` marker:

| Category | Headline | Shown when |
| --- | --- | --- |
| `policy` | Blocked by access policy | The blocklist / allowlist refused the destination. |
| `network` | Destination not permitted | The destination is on a private, local or restricted network. |
| `reputation` | Flagged as unsafe | A reputation check flagged the destination. |
| `port` | Port not permitted | A tunnel to a port other than the HTTPS port was requested. |

The page contains **only fixed text and the numeric request ID**. It also sends `X-Request-Id`, `Cache-Control: no-store` and `X-Content-Type-Options: nosniff`.

The client **never** receives: which rule matched, the policy or fixture file names or paths, the resolved or internal IP address, what a reputation provider said (not even the word "malicious"), the risk score, the host it asked for, or any part of its own URL. Because nothing the client sent is echoed, there is nothing to inject into the page.

Other errors (400 bad request, 413 too large, 502 bad gateway, 503 busy) are unchanged plain-text responses, because they are not decisions about the destination.

## What the log keeps

Everything else is in the [request log](logging.md), keyed by the same request ID that is on the page:

```text
2026-10-22T10:00:00Z req=34 host=blocked-page.invalid decision=blocked_policy status=403 bytes=0 duration_ms=0 risk=100
2026-10-22T10:00:01Z req=35 host=malicious-page.invalid decision=blocked_reputation status=403 bytes=0 duration_ms=0 rep=malicious risk=90
2026-10-22T10:00:02Z req=36 host=10.20.30.40 decision=blocked_private status=403 bytes=0 duration_ms=0 risk=100
2026-10-22T10:00:03Z req=37 host=suspicious-page.invalid decision=bad_gateway status=502 bytes=0 duration_ms=40 rep=suspicious risk=50
```

An administrator holding a request ID from a user can find that exact line and see the decision, the verdict and the score.

## What the tests prove

- `tests/test_decision.c` (55 checks): the score table, the threshold, every single signal, combinations and tie-breaks, an exhaustive check over all 256 signal combinations (blocked exactly when the score is at least 80, and a reason is set exactly when blocked), the page structure (headers, `Content-Length` matches the body, request ID), four pages that differ from each other, a list of 26 forbidden words that must never appear in any page, the largest possible request ID, and buffers that are too small being refused without writing past the end.
- `tests/integration/run_integration_tests.py`, against the real proxy with SSRF protection on, a blocklist and a reputation fixture: seven kinds of block (HTTP and `CONNECT`, every category) each return the right category, the four categories give four distinguishable pages, **the request ID on every page matches that request's log line and decision**, nothing sensitive reaches the client, and the log carries the decision, verdict and score (rules 100, malicious 90, suspicious 50, unavailable 10, safe 0).

## Limits

- The scores are fixed, documented constants, not a learned model. "Explainable" here means a person can read the table above and predict any decision.
- Only reputation contributes a graded score today; all other signals are absolute (100).
- The request ID restarts from 1 whenever the proxy restarts, so match it against the log of the same run.
