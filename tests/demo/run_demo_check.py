#!/usr/bin/env python3
"""Runs the five-minute demo from docs/demo.md exactly as written and checks every result.

If the demo document and the code ever drift apart, this fails. It is safe to run any number of
times (the demo is meant to be repeatable): it starts its own local servers and proxies, uses
only 127.0.0.1 and reserved ".invalid"/".test" names, and cleans up after itself.

    make demo-check
"""

import os
import re
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
OUT = REPO / "demo-out"
failures = []
procs = []


def report(name, ok, detail=""):
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not ok else ""))
    if not ok:
        failures.append(name)


def run(cmd, env_extra=None, shell=False):
    env = dict(os.environ, **(env_extra or {}))
    return subprocess.run(cmd, cwd=REPO, env=env, capture_output=True, text=True, shell=shell, timeout=60)


def client(url, out_name, port=None):
    env = {"PROXY_PORT": str(port)} if port else {}
    r = run([str(REPO / "bin" / "client"), url, str(OUT / out_name)], env)
    return r, (OUT / out_name).read_text(errors="replace") if (OUT / out_name).exists() else ""


def start(cmd, env_extra, out_file):
    env = dict(os.environ, **env_extra)
    f = open(OUT / out_file, "w")
    p = subprocess.Popen(cmd, cwd=REPO, env=env, stdout=f, stderr=subprocess.STDOUT)
    procs.append((p, f))
    return p


def wait_for(path, text, timeout=15):
    end = time.time() + timeout
    while time.time() < end:
        if path.exists() and text in path.read_text(errors="replace"):
            return True
        time.sleep(0.1)
    return False


def origin_hits(path):
    return (OUT / "servers.txt").read_text().count(f"GET {path} ")


def main():
    if not (REPO / "bin" / "proxy").exists():
        print("error: bin/proxy not found -- run `make` first", file=sys.stderr)
        return 2
    shutil.rmtree(OUT, ignore_errors=True)
    OUT.mkdir()

    try:
        # ---------------- setup: local servers and the two proxies (docs/demo.md "Set up") ----------------
        start([sys.executable, "scripts/demo_servers.py"], {}, "servers.txt")
        report("demo servers start", wait_for(OUT / "servers.txt", "waiting for requests"))
        tls_available = "tls-origin ready" in (OUT / "servers.txt").read_text()

        demo_env = {"PROXY_UNSAFE_ALLOW_PRIVATE_NETWORKS": "1", "PROXY_CONNECT_PORT": "9443",
                    "PROXY_BLOCKLIST": "config/blocklist.txt",
                    "PROXY_REPUTATION_FIXTURE": "config/reputation-fixture.txt",
                    "PROXY_LOG_FILE": "demo-out/demo.log"}
        proxy_a = start([str(REPO / "bin" / "proxy")], demo_env, "proxyA.txt")
        proxy_b = start([str(REPO / "bin" / "proxy")], {"PROXY_PORT": "8081", "PROXY_LOG_FILE": "demo-out/secure.log"},
                        "proxyB.txt")
        a_ok = wait_for(OUT / "proxyA.txt", "listening on port 8080")
        b_ok = wait_for(OUT / "proxyB.txt", "listening on port 8081")
        report("demo-mode proxy (port 8080) and secure default proxy (port 8081) start", a_ok and b_ok)
        a_text = (OUT / "proxyA.txt").read_text()
        report("the demo-mode proxy warns loudly that SSRF protection is off",
               "SSRF protection is DISABLED" in a_text)
        report("the secure default proxy has no such warning",
               "DISABLED" not in (OUT / "proxyB.txt").read_text())

        # ---------------- step 2: fetch an allowed HTTP page ----------------
        r, text = client("http://127.0.0.1:9100/index.html", "index.html")
        report("step 2: an allowed page is fetched and saved",
               r.returncode == 0 and "Saved response to" in r.stdout and "HTTP/1.0 200 OK" in text
               and "index page" in text, r.stdout + r.stderr)

        # ---------------- step 3: simultaneous clients ----------------
        ps = [subprocess.Popen([str(REPO / "bin" / "client"), f"http://127.0.0.1:9100/page{i}.html",
                                str(OUT / f"page{i}.html")], cwd=REPO, stdout=subprocess.DEVNULL) for i in range(1, 6)]
        for p in ps:
            p.wait(timeout=30)
        contents = {i: (OUT / f"page{i}.html").read_text(errors="replace") for i in range(1, 6)}
        report("step 3: five simultaneous clients each get their OWN page",
               all(f"fixture-page-{i}-unique-content" in contents[i] for i in range(1, 6)),
               {i: c[-60:] for i, c in contents.items()})

        # ---------------- step 4: blocklist rejection ----------------
        t0 = time.time()
        r, text = client("http://blocked-example.test/", "blocked.html")
        took = time.time() - t0
        report("step 4: a blocklisted host gets a 403 'Blocked by access policy' page with a request ID, instantly",
               text.startswith("HTTP/1.1 403") and 'data-reason="policy"' in text and "Request ID" in text and took < 2,
               text[:80])

        # ---------------- step 5: private-network rejection (secure proxy, port 8081) ----------------
        before = origin_hits("/index.html")
        _, t1 = client("http://127.0.0.1:9100/index.html", "private.html", port=8081)
        _, t2 = client("http://169.254.169.254/latest/meta-data/", "metadata.html", port=8081)
        report("step 5: the secure proxy refuses loopback and the cloud-metadata address with the 'network' reason",
               t1.startswith("HTTP/1.1 403") and 'data-reason="network"' in t1 and 'data-reason="network"' in t2)
        report("step 5: the refused loopback request never reached the origin",
               origin_hits("/index.html") == before)
        report("step 5: the refusal page does not reveal the address",
               "127.0.0.1" not in t1.split("\r\n\r\n", 1)[-1] and "169.254" not in t2.split("\r\n\r\n", 1)[-1])

        # ---------------- step 6: cache hit ----------------
        hits_before = origin_hits("/page1.html")
        client("http://127.0.0.1:9100/page1.html", "page1-again.html")
        report("step 6: a repeat request is a cache hit (the origin is NOT contacted again)",
               hits_before == 1 and origin_hits("/page1.html") == 1, f"origin saw {origin_hits('/page1.html')}")
        log = (OUT / "demo.log").read_text()
        report("step 6: the log line says cache=hit", "cache=hit" in log and "cache=stored" in log)

        # ---------------- step 7: safe logs ----------------
        client("http://127.0.0.1:9100/index.html?token=very-secret-value", "query.html")
        log = (OUT / "demo.log").read_text()
        report("step 7: a ?token=... URL works but the secret never reaches the log",
               "very-secret-value" not in log and "token" not in log and "cache=bypass" in log)
        mode = oct((OUT / "demo.log").stat().st_mode & 0o777)
        report("step 7: the log file is private (mode 600)", mode == "0o600", mode)
        report("step 7: every log line has the documented fields",
               all(re.match(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ req=\d+ host=\S+ decision=\S+ status=\d+ bytes=\d+ "
                            r"duration_ms=-?\d+( \S+=\S+)*$", l) for l in log.splitlines() if l))

        # ---------------- step 8: reputation and HTTPS CONNECT ----------------
        _, text = client("http://malicious-fixture.invalid/", "rep.html")
        client("http://suspicious-fixture.invalid/", "sus.html")
        log = (OUT / "demo.log").read_text()
        report("step 8a: a host the offline reputation fixture calls malicious is blocked with the 'reputation' reason",
               text.startswith("HTTP/1.1 403") and 'data-reason="reputation"' in text)
        report("step 8a: the log shows the verdict and risk score, the user page does not",
               "rep=malicious risk=90" in log and "malicious" not in text.split("\r\n\r\n", 1)[-1].lower())

        if tls_available and shutil.which("curl"):
            r = run(["curl", "--silent", "--show-error", "--proxy", "http://127.0.0.1:8080", "--proxytunnel",
                     "--cacert", "demo-out/demo-cert.pem", "https://localhost:9443/secret-demo-path"])
            report("step 8b: real curl completes a VERIFIED HTTPS request through the CONNECT tunnel",
                   r.returncode == 0 and "tls-demo-response" in r.stdout, r.stdout + r.stderr)
            time.sleep(0.3)
            report("step 8b: only the TLS server saw the decrypted request path",
                   "GET /secret-demo-path" in (OUT / "servers.txt").read_text())
            log = (OUT / "demo.log").read_text()
            report("step 8b: the proxy's log has the tunnel's metadata but never the path",
                   "method=connect" in log and "secret-demo-path" not in log)
        else:
            print("[SKIP] step 8b (needs the 'curl' and 'openssl' commands)")

        # ---------------- clean shutdown of both proxies ----------------
        for p, name in ((proxy_a, "proxyA.txt"), (proxy_b, "proxyB.txt")):
            p.send_signal(signal.SIGTERM)
            try:
                rc = p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()
                rc = None
            report(f"shutdown: {name[:-4]} exits cleanly on SIGTERM (code 0)",
                   rc == 0 and "shut down" in (OUT / name).read_text(), f"rc={rc}")
    finally:
        for p, f in procs:
            if p.poll() is None:
                p.kill()
            f.close()

    print()
    if failures:
        print(f"{len(failures)} demo check(s) FAILED: {', '.join(failures)}")
        return 1
    print("Demo check passed: every step in docs/demo.md behaves exactly as documented.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
