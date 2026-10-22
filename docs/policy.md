# Allowlist and Blocklist Policy

An organisation needs a simple, explainable way to permit or deny destinations. SecureBrowse reads two plain-text files at startup and applies them **before any DNS (Domain Name System) lookup or outbound connection**, so a blocked destination is never even resolved. Every acronym is spelled out on first use.

## Files

| File | Purpose | Default state |
| --- | --- | --- |
| `config/blocklist.txt` | Hosts the proxy must never contact. | Two harmless example rules for reserved `.test` names. |
| `config/allowlist.txt` | Optional "only these hosts" mode. | **Off** — every example is a comment. |

Override the paths with environment variables (relative paths are resolved from where you start the proxy, normally the repository root):

```sh
PROXY_BLOCKLIST=/etc/securebrowse/block.txt PROXY_ALLOWLIST=/etc/securebrowse/allow.txt ./bin/proxy
```

## Rule format

One rule per line. `#` starts a comment (a whole line, or after a rule). Blank lines are ignored. Rules are case-insensitive.

| Rule | Matches | Does not match |
| --- | --- | --- |
| `example.com` | `example.com` only | `www.example.com` |
| `.example.com` (leading dot) | `example.com` **and** every subdomain at any depth (`a.b.example.com`) | `notexample.com` |

The leading-dot form is the only subdomain rule. Wildcards such as `*.example.com` are **not** supported and are reported as malformed (a typo must never be mistaken for a working rule).

A rule must be a plain hostname: letters, digits, `-`, `_` and `.` only, no empty labels, at most 253 characters. Anything else (spaces, `/`, `:`, `http://`, `;`) is malformed: it is skipped, counted, and the proxy prints how many were ignored at startup.

## How a request is decided

1. **Blocklist first.** A match means `403 Forbidden`, even if the host is also on the allowlist.
2. **Allowlist mode** (only if the allowlist file contains at least one rule line): the host must match an allowlist rule, otherwise `403 Forbidden`.
3. Otherwise the request continues to the next checks.

Before matching, the host is normalised: lowercased, a trailing dot removed (`example.com.`), and any port removed. This closes the classic bypasses `EXAMPLE.com`, `example.com.` and `example.com:80`.

## Fail-closed behaviour

| Situation | What the proxy does |
| --- | --- |
| Allowlist file has rule text, but every rule is malformed (a typo) | Allowlist mode stays **ON** and everything is denied, rather than silently turning the allowlist off. |
| Allowlist file contains only comments or blank lines | Allowlist mode is off. |
| A file you set with `PROXY_ALLOWLIST` / `PROXY_BLOCKLIST` cannot be read | The proxy **refuses to start** instead of running with fewer rules than you asked for. |
| A *default* file is missing (fresh checkout with no `config/`) | Warning only, so the proxy still starts. |

## What the client sees, and what is logged

The client receives `403 Forbidden: Destination blocked by policy.` — it does not say which rule matched or where the files are. The request log records `decision=blocked_policy status=403` with the (validated) host. See [`logging.md`](logging.md).

## What the tests prove

- `tests/test_policy.c` (61 checks): exact and subdomain rules, the dot boundary, case, trailing dot and port variants, comments, blank lines, whitespace, CRLF line endings, 9 kinds of malformed rule, an overlong line, allowlist mode, fail-closed allowlists, missing and empty files, and the shipped config files.
- `tests/integration/run_integration_tests.py`: against the real proxy, a blocked host never reaches a local origin server (its request counter does not move), a blocked non-existent name returns `403` not `502` (proving policy runs before DNS), and the fail-closed startup cases above.

## Limits

- Policy matches **hostnames**, not IP addresses a hostname might resolve to. Private and loopback addresses are the job of the separate network-safety checks (the SSRF issue).
- Rules are read once at startup. Restart the proxy to apply changes.
