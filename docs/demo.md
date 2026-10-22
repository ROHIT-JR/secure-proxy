# Five-Minute Demo Script

This script shows every Phase 1 and Phase 2 feature using only local servers and reserved fake names. It needs no internet. Every step's output below was captured from a real run, and `make demo-check` runs the same steps automatically and fails if the document and the code drift apart.

## 0. Set up (one terminal each)

```sh
make                                   # build everything
python3 scripts/demo_servers.py        # terminal 1: local web server (127.0.0.1:9100) + local HTTPS server (127.0.0.1:9443)
```

Terminal 2 — the **demo-mode proxy** (port 8080). Local servers live on 127.0.0.1, which the proxy normally refuses, so this one turns the SSRF (Server-Side Request Forgery) guard off and says so loudly on start-up:

```sh
mkdir -p demo-out
PROXY_UNSAFE_ALLOW_PRIVATE_NETWORKS=1 PROXY_CONNECT_PORT=9443 \
PROXY_BLOCKLIST=config/blocklist.txt PROXY_REPUTATION_FIXTURE=config/reputation-fixture.txt \
PROXY_LOG_FILE=demo-out/demo.log ./bin/proxy
```

Terminal 3 — the **secure default proxy** (port 8081), with no override:

```sh
PROXY_PORT=8081 PROXY_LOG_FILE=demo-out/secure.log ./bin/proxy
```

## 1. Fetch an allowed page

```sh
./bin/client http://127.0.0.1:9100/index.html demo-out/index.html
```
Expected: `Saved response to demo-out/index.html (...)`; the file starts with `HTTP/1.0 200 OK`.

## 2. Five simultaneous clients, each gets its own page

```sh
for i in 1 2 3 4 5; do ./bin/client http://127.0.0.1:9100/page$i.html demo-out/page$i.html & done; wait
grep -l "fixture-page-.-unique-content" demo-out/page*.html | sort
```
Expected: each `pageN.html` contains `fixture-page-N-unique-content` (no mixing).

## 3. Blocklist rejection

```sh
./bin/client http://blocked-example.test/ demo-out/blocked.html; head -c 300 demo-out/blocked.html
```
Expected: instant `HTTP/1.1 403` "Blocked by access policy" page with a Request ID. No DNS lookup happened.

## 4. Private-network rejection (secure proxy, port 8081)

```sh
PROXY_PORT=8081 ./bin/client http://127.0.0.1:9100/index.html demo-out/private.html
PROXY_PORT=8081 ./bin/client http://169.254.169.254/latest/meta-data/ demo-out/metadata.html
```
Expected: both get a 403 page with reason `network`; the page never shows the address, and the local server prints nothing for the first request.

## 5. Cache hit

```sh
./bin/client http://127.0.0.1:9100/page1.html demo-out/page1-again.html
grep cache= demo-out/demo.log
```
Expected: the local server's terminal shows `/page1.html` only once; the log shows `cache=stored` then `cache=hit`.

## 6. Safe logs

```sh
./bin/client "http://127.0.0.1:9100/index.html?token=very-secret-value" demo-out/query.html
grep -c "very-secret-value" demo-out/demo.log     # prints 0
stat -c '%a' demo-out/demo.log                    # prints 600
```

## 7. Reputation (offline fixture)

```sh
./bin/client http://malicious-fixture.invalid/ demo-out/rep.html
grep "rep=malicious" demo-out/demo.log
```
Expected: 403 page with reason `reputation`; log shows `rep=malicious risk=90`. The user-facing page never says "malicious".

## 8. HTTPS through a CONNECT tunnel (no interception)

```sh
curl --proxy http://127.0.0.1:8080 --proxytunnel --cacert demo-out/demo-cert.pem https://localhost:9443/secret-demo-path
```
Expected: `tls-demo-response`. The TLS server's terminal prints the decrypted path; the proxy log has `method=connect` but never `secret-demo-path`, because the proxy only relays encrypted bytes.

## Automatic check

```sh
make demo-check
```
Runs steps 1–8 against fresh servers and proxies and prints `Demo check passed`.

## If you have internet (optional, not verified in CI)

`./bin/proxy` with no environment variables, then `./bin/client http://example.com/` — the secure default fetches a real page. Only safe sites such as `example.com` should be used.

## Cleanup

Press Ctrl+C in each terminal (the proxies shut down gracefully), then `rm -rf demo-out`.
