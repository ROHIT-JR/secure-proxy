# Security Policy

SecureBrowse is an educational, security-aware forward proxy. It is not a production secure web gateway, but we still take vulnerability reports seriously.

## Supported versions

This project has not yet made a tagged release. Until a `v1.0.0` tag exists, only the `main` branch is supported for security fixes.

| Version | Supported |
| --- | --- |
| `main` (latest commit) | Yes |
| Any tagged pre-1.0 release | Best effort |

## In scope

- Memory safety issues (buffer overflows, use-after-free, double free) in `src/`.
- Ways to bypass the allowlist/blocklist policy engine.
- SSRF (Server-Side Request Forgery): reaching loopback, private, or link-local addresses through the proxy.
- Ways to make the proxy hang, crash, or leak file descriptors from untrusted network input.
- Log or cache entries that leak sensitive request data (credentials, query strings, cookies).

## Out of scope

- Missing HTTPS interception or TLS (Transport Layer Security) inspection — this is an intentional design decision, not a bug. See `docs/threat-model.md`.
- Denial-of-service reports that rely on unrealistic resource assumptions (for example, running the demo on a machine with no memory limits).
- Vulnerabilities in third-party dependencies that have no available fix.

## How to report a vulnerability

**Please do not open a public GitHub issue for a suspected vulnerability.**

Use GitHub's private vulnerability reporting feature instead:

1. Go to the repository's **Security** tab.
2. Select **Report a vulnerability**.
3. Describe the issue, the affected file(s), and steps to reproduce it. Use only safe test data (`example.com`, local test servers) in your report — never real harmful URLs.

If private vulnerability reporting is not available to you, contact the maintainers at:

`[TEAM: replace with your maintainer contact email before making the repo public]`

## What to expect

- We aim to acknowledge new reports within **5 business days**.
- We will work with you to confirm the issue, assess severity, and agree on a disclosure timeline.
- Once a fix is available, we will credit reporters who wish to be credited in the release notes, unless you ask us not to.

## Disclosure process

1. Report received privately.
2. Maintainers confirm and reproduce the issue.
3. A fix is developed and tested, generally on a private branch.
4. The fix is released, and a public advisory is published describing the issue at a level of detail appropriate for an educational project.
5. The reporter is credited unless anonymity was requested.

Thank you for helping keep SecureBrowse and its users safe.
