# Demo Script

This file will be completed by Issue 18 ("Documentation, demo script, and viva preparation") once Phase 2 is finished.

The Phase 1 demo is complete and lives in [`docs/demo-phase-1.md`](demo-phase-1.md) — it covers build, start, a successful fetch, concurrent clients, all three safe-failure paths (malformed URL, DNS failure, oversized input), the full `make test` integration suite, and the resource-cleanup checklist for Issue #9.

Every acronym is spelled out on first use.

## Phase 2 demo (security-aware proxy)

The following sections will be completed once the corresponding issue is implemented. Placeholders are listed so the full five-minute demo script (Issue 18) has a fixed shape to fill in:

- Blocklist rejection (Issue 10) — *pending*
- Private-network rejection / SSRF (Server-Side Request Forgery) protection (Issue 11) — *pending*
- Cache hit (Issue 12) — *pending*
- Safe logs with no leaked secrets (Issue 9) — *pending*
- Optional: HTTPS (Hypertext Transfer Protocol Secure) `CONNECT` tunnelling (Issue 13) — *pending*
- Optional: offline reputation result (Issue 14) — *pending*

See `ISSUE_PLAN.md` for the full Issue 18 specification that will replace the placeholders above with exact commands and expected output.
