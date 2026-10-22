# Threat-Reputation Checks

Reputation data ("is this host known to be bad?") can improve a security decision, but a project must stay **testable and useful without an external service**, and must never leak what its users browse. SecureBrowse therefore defines a small provider interface, ships an **offline fixture provider** as the default test mode, and treats "I could not find out" as an observable event, never as a verdict. Every acronym is spelled out on first use.

## The interface

A provider answers one question about one hostname with one of four verdicts (`include/reputation.h`):

| Verdict | Meaning | What the proxy does |
| --- | --- | --- |
| `safe` | No known problem. | Allows the request. |
| `suspicious` | Some warning signs. | **Allows** it and logs `rep=suspicious`. |
| `malicious` | Known bad. | **Refuses** it with `403` (`decision=blocked_reputation`) before any DNS lookup or connection. |
| `unavailable` | The provider could not answer. | **Allows** it and logs `rep=unavailable` plus a reason. It is **not** assumed to be malicious. |

```c
typedef struct {
    const char *name;
    ReputationVerdict (*lookup)(void *ctx, const char *host);
    void *ctx;
} ReputationProvider;
```

A future live provider is just another `lookup` function. Nothing else in the proxy changes.

## Privacy: only a bare hostname is ever sent

The provider receives **only the normalised hostname** (lowercase, no trailing dot). The framework enforces this before calling any provider, so a provider cannot be handed anything else even by mistake:

- A URL, path, query string, fragment, port, `user:password@` credentials, whitespace, control characters, brackets, empty or malformed names, or anything longer than 253 characters is **refused as `bad_input` and never sent**.
- **IP addresses (in any spelling) and local names such as `localhost` are never sent** either. There is nothing useful to learn about them, and they are handled by the network-safety checks.
- Request bodies and user identifiers never reach this code at all.

Sending more than the host would need an explicit consent and privacy review first, as the project rules state.

## A slow or broken provider cannot hurt the proxy

| Protection | Behaviour |
| --- | --- |
| **Timeout** | Each lookup runs on a helper thread and the proxy waits at most `PROXY_REPUTATION_TIMEOUT_MS` (default 1500 ms). After that the result is `unavailable` / `timeout` and the request continues. |
| **No leaks, no dangling pointers** | A caller that gives up leaves the job to the helper thread, and whichever side finishes last frees it (reference-counted). A test deliberately breaks this and LeakSanitizer reports the leak. |
| **Bounded threads** | At most 16 provider calls are outstanding at once. A hung provider therefore cannot pile up threads; extra lookups return `unavailable` / `saturated` immediately. |
| **Failures are not verdicts** | A provider that reports `unavailable`, returns an invalid value, or cannot be started gives `unavailable` / `error`. |
| **Caching** | Real answers are cached for `PROXY_REPUTATION_TTL_SECONDS` (default 300 s). Failures are remembered for only 5 s, so an outage is not hammered but heals quickly. 256 entries, least-recently-used eviction. |

## Using the offline fixture provider

Reputation is **off unless you configure it**:

```sh
PROXY_REPUTATION_FIXTURE=config/reputation-fixture.txt ./bin/proxy
```

The file lists `host verdict` pairs (verdicts: `safe`, `suspicious`, `malicious`, `unavailable`, `timeout`). A leading dot covers subdomains. Unlisted hosts are `safe`. The `timeout` verdict makes the provider answer 3 seconds late, to exercise the timeout path. See `config/reputation-fixture.txt` (all names use the reserved `.invalid` TLD, so they can never be real sites).

| Setting | Meaning |
| --- | --- |
| `PROXY_REPUTATION_FIXTURE` | Path of the fixture file. Unset means reputation is off. A configured but unreadable file **stops startup** rather than running unchecked. |
| `PROXY_REPUTATION_TIMEOUT_MS` | Per-lookup budget, 50 to 30000 (default 1500). |
| `PROXY_REPUTATION_TTL_SECONDS` | Cache lifetime, 1 to 86400 (default 300). |
| `PROXY_REPUTATION_QUERY_LOG` | Test hook: append every host the provider is asked about to this file. |

## Logging

The log line gets fixed tokens (see [`logging.md`](logging.md)):

```text
... decision=blocked_reputation status=403 bytes=0 duration_ms=0 rep=malicious
... decision=bad_gateway status=502 bytes=0 duration_ms=41 rep=suspicious
... decision=bad_gateway status=502 bytes=0 duration_ms=312 rep=unavailable rep_reason=timeout
```

`rep_reason` is one of `error`, `timeout`, `saturated`, `bad_input` and appears only when the verdict is `unavailable`, so outages are visible in the log.

## What the tests prove

- `tests/test_reputation.c` (78 checks, fully offline): verdict mapping, cache hit/expiry/negative cache/LRU, **18 hostile inputs that must never reach the provider**, a provider that is 7x too slow returns at the timeout (not after 1.5 s), a recent timeout is answered instantly from cache, a bound of 16 outstanding calls with recovery, 8 threads x 400 lookups, disabled/invalid configuration, and the fixture provider (mixed-case rules, subdomain rule and dot boundary, malformed lines, its slow host, and its own query log showing only bare hostnames). The test exits normally, so LeakSanitizer inspects the abandoned-helper path.
- `tests/integration/run_integration_tests.py`: against the real proxy, a malicious host is refused before DNS (also for `CONNECT`, with zero connections made), suspicious/safe/unavailable hosts proceed, a slow provider is cut off at the timeout while other requests stay fast, the provider is only ever sent bare lowercase hostnames (never a path, query, port, credential, IP address or `localhost`), repeats come from the cache, reputation is off by default, and an unreadable fixture stops startup.

## Limits

- Only the offline fixture provider exists. A live feed is a separate, approval-gated issue.
- "Unavailable" fails **open** (the request proceeds, visibly). There is no fail-closed switch yet.
- The fixture provider's data must not be freed while a slow lookup is still running; the proxy never frees it before exit.
