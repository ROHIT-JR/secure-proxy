# Demo Script

This file will be completed by Issue 18 ("Documentation, demo script, and viva preparation") once Phase 2 is finished. Until then, it contains the Phase 1 demo skeleton so the project has a reproducible baseline demo from the start.

Every acronym is spelled out on first use.

## Phase 1 demo (working concurrent proxy)

Run these steps from a clean checkout.

### 1. Build

```sh
make clean && make
```

Expected result: the build finishes with no compiler warnings (the project builds with `-Wall -Wextra -Werror -pthread`).

### 2. Start the proxy

```sh
./bin/proxy
```

Expected result: *[to be filled in by Issue 4/6 once the listener is implemented — expected startup message and port]*

### 3. Fetch an allowed HTTP (Hypertext Transfer Protocol) page

```sh
./bin/client http://example.com/
```

Expected result: *[to be filled in by Issue 6 — expected saved file name and approximate size]*

### 4. Show simultaneous clients

```sh
./bin/client http://example.com/ &
./bin/client http://example.com/ &
./bin/client http://example.com/ &
wait
```

Expected result: *[to be filled in by Issue 7/8 — all three clients receive correct, non-mixed responses]*

## Phase 2 demo (security-aware proxy)

The following sections will be completed once the corresponding issue is implemented. Placeholders are listed so the full five-minute demo script (Issue 18) has a fixed shape to fill in:

- Blocklist rejection (Issue 10) — *pending*
- Private-network rejection / SSRF (Server-Side Request Forgery) protection (Issue 11) — *pending*
- Cache hit (Issue 12) — *pending*
- Safe logs with no leaked secrets (Issue 9) — *pending*
- Optional: HTTPS (Hypertext Transfer Protocol Secure) `CONNECT` tunnelling (Issue 13) — *pending*
- Optional: offline reputation result (Issue 14) — *pending*

See `ISSUE_PLAN.md` for the full Issue 18 specification that will replace the placeholders above with exact commands and expected output.
