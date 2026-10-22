#!/usr/bin/env python3
"""Repeatable concurrent-load test for the SecureBrowse proxy.

Starts a local origin server, a local TCP echo server (for CONNECT tunnels) and the
real bin/proxy, then runs many clients at once, each following a seeded random mix of:

  * content-verified page fetches (cache hits, misses and evictions),
  * a large response, and a response with a cookie (never cached),
  * malformed, oversized and blocked requests, and DNS failures,
  * CONNECT tunnels carrying random binary data, closed cleanly and abruptly,
  * clients that hang up in the middle of a request.

It checks that every response is correct and never mixed up between clients, that
the proxy never crashes, that file descriptors and memory return to normal, that a
SIGTERM shuts it down cleanly, and that its stderr contains no sanitizer or Valgrind
report. Only local servers and reserved ".invalid" names are used, never a real site.

The workload is deterministic for a given --seed and --requests-per-client, so a failure
can be reproduced:   python3 tests/load/run_load_test.py --seed 7

Run it against a sanitizer build (make sanitize) or under Valgrind
(PROXY_WRAPPER="valgrind --error-exitcode=99 --leak-check=full") to hunt memory bugs
under load.
"""

import argparse
import hashlib
import http.server
import os
import random
import re
import shlex
import signal
import socket
import statistics
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
PROXY_PORT = 8080
PAGES = 200
BIG_BODY = (b"0123456789abcdef" * 20000)[:300000]  # larger than the proxy's per-entry cache limit

SANITIZER_PATTERNS = re.compile(
    r"(AddressSanitizer|LeakSanitizer|ThreadSanitizer|UndefinedBehaviorSanitizer|runtime error:|"
    r"Invalid read|Invalid write|Invalid free|definitely lost|Conditional jump or move depends|"
    r"Use of uninitialised|Mismatched free)"
)


def page_body(n):
    return (f"page-{n}-".encode() * (50 + n % 400))[: 200 + (n * 37) % 5800]


# ---------------------------------------------------------------- local servers

class Origin:
    def __init__(self):
        self.hits = {"page": 0, "big": 0, "cookie": 0}
        self.lock = threading.Lock()
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                kind, _, arg = self.path.strip("/").partition("/")
                with outer.lock:
                    outer.hits[kind if kind in outer.hits else "page"] += 1
                if kind == "page":
                    body, headers = page_body(int(arg)), {}
                elif kind == "cookie":
                    body, headers = page_body(int(arg)) + b"-cookie", {"Set-Cookie": "sid=%s" % arg}
                elif kind == "big":
                    body, headers = BIG_BODY, {}
                else:
                    self.send_error(404)
                    return
                self.send_response(200)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.httpd.daemon_threads = True
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()


class Echo:
    def __init__(self):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(128)
        self.port = self.sock.getsockname()[1]
        self.stop = False
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        self.sock.settimeout(0.2)
        while not self.stop:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                continue
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    @staticmethod
    def _serve(conn):
        try:
            while True:
                data = conn.recv(65536)
                if not data:
                    break
                conn.sendall(data)
        except OSError:
            pass
        finally:
            conn.close()

    def close(self):
        self.stop = True
        self.sock.close()


# ---------------------------------------------------------------- client actions

def read_to_eof(sock, timeout=20):
    sock.settimeout(timeout)
    data = b""
    while True:
        chunk = sock.recv(65536)
        if not chunk:
            return data
        data += chunk


def request(line, timeout=20):
    with socket.create_connection(("127.0.0.1", PROXY_PORT), timeout=timeout) as s:
        s.sendall(line if isinstance(line, bytes) else line.encode())
        return read_to_eof(s, timeout)


def split(raw):
    head, _, body = raw.partition(b"\r\n\r\n")
    return head, body


class Ctx:
    def __init__(self, origin_port, echo_port):
        self.o = origin_port
        self.e = echo_port


def act_page(rng, ctx):
    # skewed choice: a hot set gets many hits, the long tail forces cache evictions
    n = int(rng.expovariate(1 / 40.0)) % PAGES
    head, body = split(request(f"http://127.0.0.1:{ctx.o}/page/{n}\n"))
    return head.startswith(b"HTTP/1.0 200") and body == page_body(n), f"page {n}: {head[:30]!r} len={len(body)}"


def act_cookie(rng, ctx):
    n = rng.randrange(PAGES)
    head, body = split(request(f"http://127.0.0.1:{ctx.o}/cookie/{n}\n"))
    return head.startswith(b"HTTP/1.0 200") and body == page_body(n) + b"-cookie", f"cookie {n}"


def act_big(rng, ctx):
    head, body = split(request(f"http://127.0.0.1:{ctx.o}/big/1\n"))
    return head.startswith(b"HTTP/1.0 200") and hashlib.sha256(body).digest() == hashlib.sha256(BIG_BODY).digest(), \
        f"big len={len(body)}"


def act_malformed(rng, ctx):
    line = rng.choice(["not a url", "ftp://x/", "http://", "http://a:99999/", "http://u:p@h/", "http://h/#f",
                       "GET / HTTP/1.1", "CONNECT", "http://exa mple/"])
    raw = request(line + "\n")
    return raw.startswith(b"HTTP/1.1 400"), f"malformed {line!r}: {raw[:30]!r}"


def act_nul(rng, ctx):
    raw = request(b"http://127.0.0.1/\x00" + bytes(rng.randrange(1, 256) for _ in range(5)) + b"\n")
    return raw.startswith(b"HTTP/1.1 400"), f"nul: {raw[:30]!r}"


def act_oversized(rng, ctx):
    raw = request("http://127.0.0.1/" + "a" * rng.randrange(2100, 4000) + "\n")
    return raw.startswith(b"HTTP/1.1 413"), f"oversized: {raw[:30]!r}"


def act_blocked(rng, ctx):
    raw = request("http://blocked-load.invalid/x\n")
    head, body = split(raw)
    return head.startswith(b"HTTP/1.1 403") and b'data-reason="policy"' in body, f"blocked: {raw[:30]!r}"


def act_dns(rng, ctx):
    raw = request(f"http://no-such-host-{rng.randrange(1000)}.invalid/\n")
    return raw.startswith(b"HTTP/1.1 502"), f"dns: {raw[:30]!r}"


def act_tunnel(rng, ctx):
    abrupt = rng.random() < 0.4
    size = rng.randrange(1, 65536)
    payload = bytes(rng.randrange(256) for _ in range(min(size, 4096))) * (size // 4096 + 1)
    payload = payload[:size]
    s = socket.create_connection(("127.0.0.1", PROXY_PORT), timeout=20)
    try:
        s.sendall(f"CONNECT 127.0.0.1:{ctx.e} HTTP/1.1\r\nHost: x\r\n\r\n".encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = s.recv(4096)
            if not chunk:
                return False, "tunnel: closed before 200"
            buf += chunk
        if not buf.startswith(b"HTTP/1.1 200"):
            return False, f"tunnel: {buf[:40]!r}"
        s.sendall(payload)
        if abrupt:  # vanish mid-tunnel with a TCP reset, without reading the echo
            s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            return True, "tunnel abrupt"
        got = b""
        s.settimeout(20)
        while len(got) < len(payload):
            chunk = s.recv(65536)
            if not chunk:
                break
            got += chunk
        return got == payload, f"tunnel echo {len(got)}/{len(payload)}"
    finally:
        s.close()


def act_hangup(rng, ctx):
    s = socket.create_connection(("127.0.0.1", PROXY_PORT), timeout=10)
    if rng.random() < 0.7:
        s.sendall(b"http://127.0.0.1/pa")  # half a request line, then leave
    s.close()
    return True, "hangup"


ACTIONS = [  # (name, weight, function)
    ("page", 52, act_page), ("cookie", 6, act_cookie), ("big", 3, act_big), ("malformed", 5, act_malformed),
    ("nul", 2, act_nul), ("oversized", 3, act_oversized), ("blocked", 4, act_blocked), ("dns", 4, act_dns),
    ("tunnel", 15, act_tunnel), ("hangup", 6, act_hangup),
]


def worker(wid, args, ctx, results, stop_at):
    rng = random.Random(args.seed * 1000 + wid)
    names = [a[0] for a in ACTIONS]
    weights = [a[1] for a in ACTIONS]
    funcs = {a[0]: a[2] for a in ACTIONS}
    done = 0
    while done < args.requests_per_client and (stop_at is None or time.time() < stop_at):
        name = rng.choices(names, weights)[0]
        t0 = time.time()
        try:
            ok, detail = funcs[name](rng, ctx)
            kind = "ok" if ok else "wrong"
        except (OSError, socket.timeout) as e:
            ok, detail, kind = False, f"{name}: {type(e).__name__}: {e}", "error"
        results.append((name, kind, time.time() - t0, "" if ok else detail))
        done += 1


# ---------------------------------------------------------------- process helpers

def proc_fds(pid):
    return len(os.listdir(f"/proc/{pid}/fd"))


def proc_rss_mb(pid):
    for line in Path(f"/proc/{pid}/status").read_text().splitlines():
        if line.startswith("VmRSS:"):
            return int(line.split()[1]) / 1024.0
    return 0.0


def wait_listening(timeout):
    end = time.time() + timeout
    while time.time() < end:
        try:
            socket.create_connection(("127.0.0.1", PROXY_PORT), timeout=0.5).close()
            return True
        except OSError:
            time.sleep(0.2)
    return False


def pct(sorted_vals, p):
    return sorted_vals[min(len(sorted_vals) - 1, int(len(sorted_vals) * p))] if sorted_vals else 0.0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--clients", type=int, default=32, help="concurrent clients (default 32; the proxy caps at 64)")
    ap.add_argument("--requests-per-client", type=int, default=150)
    ap.add_argument("--duration", type=float, default=None, help="optional wall-clock limit in seconds")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--proxy-bin", default=str(REPO_ROOT / "bin" / "proxy"))
    ap.add_argument("--max-rss-growth-mb", type=float, default=96.0,
                    help="allowed memory growth of the proxy; raise it for sanitizer/valgrind builds")
    ap.add_argument("--startup-timeout", type=float, default=60.0)
    args = ap.parse_args()

    if not Path(args.proxy_bin).exists():
        print(f"error: {args.proxy_bin} does not exist -- run `make` first", file=sys.stderr)
        return 2
    if args.clients > 60:
        print("note: more than ~60 clients will legitimately see 503 'busy' responses", file=sys.stderr)

    tmp = Path(tempfile.mkdtemp(prefix="secure-proxy-load-"))
    origin, echo = Origin(), Echo()
    (tmp / "allow.txt").write_text("# off\n")
    (tmp / "block.txt").write_text("blocked-load.invalid\n")
    stderr_path = tmp / "proxy.stderr"
    env = dict(os.environ, PROXY_LOG_FILE=str(tmp / "proxy.log"), PROXY_ALLOWLIST=str(tmp / "allow.txt"),
               PROXY_BLOCKLIST=str(tmp / "block.txt"), PROXY_CONNECT_PORT=str(echo.port),
               PROXY_UNSAFE_ALLOW_PRIVATE_NETWORKS="1",  # TEST ONLY: the fixtures live on 127.0.0.1
               PROXY_TUNNEL_IDLE_SECONDS="30")
    wrapper = shlex.split(os.environ.get("PROXY_WRAPPER", ""))
    with open(stderr_path, "wb") as err:
        proc = subprocess.Popen(wrapper + [args.proxy_bin], env=env, stdout=subprocess.DEVNULL, stderr=err)

    problems = []
    try:
        if not wait_listening(args.startup_timeout):
            print("FAIL: the proxy did not start listening", file=sys.stderr)
            return 1
        time.sleep(0.5)
        fds_before, rss_before = proc_fds(proc.pid), proc_rss_mb(proc.pid)

        ctx = Ctx(origin.port, echo.port)
        results = []
        stop_at = time.time() + args.duration if args.duration else None
        t_start = time.time()
        threads = [threading.Thread(target=worker, args=(i, args, ctx, results, stop_at)) for i in range(args.clients)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        elapsed = time.time() - t_start

        # let in-flight work, drains and idle tunnels settle before measuring
        settle_deadline = time.time() + 15
        while time.time() < settle_deadline and proc_fds(proc.pid) > fds_before:
            time.sleep(0.5)
        fds_after, rss_after = proc_fds(proc.pid), proc_rss_mb(proc.pid)

        # ------------------------------------------------ report
        total = len(results)
        bad = [r for r in results if r[1] != "ok"]
        print(f"\nLoad test: {args.clients} clients x up to {args.requests_per_client} requests, seed {args.seed}")
        print(f"{total} requests in {elapsed:.1f}s ({total / elapsed:.0f} req/s)\n")
        print(f"{'action':<10} {'count':>6} {'ok':>6} {'bad':>5} {'p50 ms':>8} {'p95 ms':>8} {'p99 ms':>8}")
        for name, _, _ in ACTIONS:
            rows = [r for r in results if r[0] == name]
            if not rows:
                continue
            lat = sorted(r[2] * 1000 for r in rows)
            print(f"{name:<10} {len(rows):>6} {sum(r[1] == 'ok' for r in rows):>6} {sum(r[1] != 'ok' for r in rows):>5} "
                  f"{statistics.median(lat):>8.1f} {pct(lat, 0.95):>8.1f} {pct(lat, 0.99):>8.1f}")
        print(f"\nproxy file descriptors: {fds_before} before, {fds_after} after")
        print(f"proxy memory (RSS):     {rss_before:.1f} MB before, {rss_after:.1f} MB after "
              f"(+{rss_after - rss_before:.1f} MB)")
        pages = sum(1 for r in results if r[0] == "page")
        print(f"origin saw {origin.hits['page']} page requests for {pages} page fetches by clients "
              f"({100 * (1 - origin.hits['page'] / max(1, pages)):.0f}% served from the proxy cache)")

        if bad:
            problems.append(f"{len(bad)} wrong or failed responses; first: " + "; ".join(f"{b[1]}:{b[3]}" for b in bad[:5]))
        if proc.poll() is not None:
            problems.append(f"the proxy exited during the load test (code {proc.returncode})")
        if fds_after > fds_before:
            problems.append(f"file descriptors leaked: {fds_before} -> {fds_after}")
        if rss_after - rss_before > args.max_rss_growth_mb:
            problems.append(f"memory grew by {rss_after - rss_before:.1f} MB (limit {args.max_rss_growth_mb} MB)")
        if pages >= 200 and origin.hits["page"] >= pages * 0.8:
            problems.append("the response cache did not reduce origin traffic")

        # the proxy must still be fully usable
        head, body = split(request(f"http://127.0.0.1:{origin.port}/page/3\n"))
        if body != page_body(3):
            problems.append("the proxy no longer serves correct content after the load")

        # graceful shutdown (also lets LeakSanitizer / Valgrind produce their final report)
        proc.send_signal(signal.SIGTERM)
        try:
            rc = proc.wait(timeout=60)
        except subprocess.TimeoutExpired:
            proc.kill()
            rc = None
            problems.append("the proxy did not shut down within 60 s of SIGTERM")
        if rc not in (0, None):
            problems.append(f"the proxy exited with code {rc} on shutdown")
        err_text = stderr_path.read_text(errors="replace")
        hits = [l for l in err_text.splitlines() if SANITIZER_PATTERNS.search(l)]
        if hits:
            problems.append("sanitizer/valgrind output in the proxy's stderr: " + " | ".join(hits[:3]))
    finally:
        if proc.poll() is None:
            proc.kill()
        origin.close()
        echo.close()

    print()
    if problems:
        for p in problems:
            print(f"FAIL: {p}")
        print(f"(logs kept in {tmp})")
        return 1
    print("PASS: every response correct, no leaks, clean shutdown, no sanitizer reports.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
