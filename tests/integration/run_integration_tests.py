#!/usr/bin/env python3
"""Phase 1 integration tests: exercises the built bin/proxy end to end
against a local-origin test server, covering success, malformed URL, DNS
failure, oversized input, and multiple concurrent clients. Also checks
that the proxy's open file descriptor count returns to its baseline after
every scenario, as evidence that every socket it opens is also closed, and
that the privacy-aware request log is well formed, leak-free and never
interleaved under concurrent load.

Deliberately uses only local-origin servers -- no real external site is
ever contacted, per the project's safe-testing rules.
"""

import http.server
import os
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
PROXY_BIN = REPO_ROOT / "bin" / "proxy"
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures" / "webroot"

PROXY_PORT = 8080
ORIGIN_PORT = 9195

# One structured line per request, e.g.:
#   2026-10-17T10:00:00Z req=7 host=example.com decision=allowed status=200 bytes=1256 duration_ms=12
LOG_LINE_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z req=\d+ host=\S+ decision=[a-z0-9_-]+ "
    r"status=\d+ bytes=\d+ duration_ms=-?\d+$"
)

failures = []


def report(name, ok, detail=""):
    status = "PASS" if ok else "FAIL"
    print(f"[{status}] {name}" + (f" -- {detail}" if detail and not ok else ""))
    if not ok:
        failures.append(name)


def send_request(line, timeout=6):
    """Opens a fresh raw TCP connection to the proxy, sends one request
    line, and returns the full raw response bytes."""
    with socket.create_connection(("127.0.0.1", PROXY_PORT), timeout=timeout) as s:
        s.sendall(line.encode() if isinstance(line, str) else line)
        s.settimeout(timeout)
        data = b""
        try:
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
        except socket.timeout:
            pass
        return data


def status_line_of(response_bytes):
    return response_bytes.split(b"\r\n", 1)[0].decode(errors="replace")


def proxy_fd_count(pid):
    return len(os.listdir(f"/proc/{pid}/fd"))


origin_hits = {"count": 0}  # how many requests the local origin has actually received


def start_origin_server():
    handler = http.server.SimpleHTTPRequestHandler

    class QuietHandler(handler):
        def log_message(self, *args):
            pass  # keep test output focused on our own PASS/FAIL lines

        def do_GET(self):
            origin_hits["count"] += 1
            super().do_GET()

    os.chdir(FIXTURES_DIR)
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", ORIGIN_PORT), QuietHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd


def write_rules(tmp_dir, name, text):
    path = Path(tmp_dir) / name
    path.write_text(text)
    return path


def start_proxy(log_path, extra_env=None, tmp_dir=None, private_ok=True):
    # Always pin both policy files so a test never depends on the working directory.
    env = dict(os.environ, PROXY_LOG_FILE=str(log_path))
    if tmp_dir is not None:
        env.setdefault("PROXY_ALLOWLIST", str(write_rules(tmp_dir, "empty_allow.txt", "# off\n")))
        env.setdefault("PROXY_BLOCKLIST", str(write_rules(tmp_dir, "empty_block.txt", "# none\n")))
    env.pop("PROXY_UNSAFE_ALLOW_PRIVATE_NETWORKS", None)
    if private_ok:
        # TEST-ONLY override so the fixtures can live on 127.0.0.1. SSRF tests turn it off.
        env["PROXY_UNSAFE_ALLOW_PRIVATE_NETWORKS"] = "1"
    env.update(extra_env or {})
    proc = subprocess.Popen(
        [str(PROXY_BIN)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=env,
    )
    # Wait for the listening socket to actually be ready instead of a fixed sleep guess.
    for _ in range(50):
        try:
            with socket.create_connection(("127.0.0.1", PROXY_PORT), timeout=0.2):
                return proc
        except OSError:
            time.sleep(0.1)
    raise RuntimeError("proxy did not start listening in time")


def test_success():
    resp = send_request(f"http://127.0.0.1:{ORIGIN_PORT}/index.html\n")
    ok = b"200 OK" in resp.split(b"\r\n", 1)[0] and b"fixture: index page" in resp
    report("success: fetch a real local page", ok, status_line_of(resp))


def test_malformed_url():
    resp = send_request("this-is-not-a-url\n")
    line = status_line_of(resp)
    report("malformed URL -> 400 Bad Request", line.startswith("HTTP/1.1 400"), line)


def test_dns_failure():
    # .invalid is reserved by RFC 2606 to never resolve, in any environment.
    resp = send_request("http://this-host-does-not-exist.invalid/\n")
    line = status_line_of(resp)
    report("DNS failure -> 502 Bad Gateway", line.startswith("HTTP/1.1 502"), line)


def test_oversized_input():
    oversized_url = "http://example.com/" + ("a" * 3000) + "\n"
    resp = send_request(oversized_url)
    line = status_line_of(resp)
    report("oversized request line -> 413 Payload Too Large", line.startswith("HTTP/1.1 413"), line)


def test_concurrent_clients(n=8):
    results = {}
    errors = {}

    def fetch(i):
        page = (i % 5) + 1
        try:
            resp = send_request(f"http://127.0.0.1:{ORIGIN_PORT}/page{page}.html\n")
            results[i] = (page, resp)
        except Exception as e:  # noqa: BLE001 -- test harness, want to record any failure
            errors[i] = str(e)

    threads = [threading.Thread(target=fetch, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    all_ok = True
    for i in range(n):
        if i in errors:
            report(f"concurrent client {i}", False, errors[i])
            all_ok = False
            continue
        page, resp = results[i]
        expected = f"fixture-page-{page}-unique-content".encode()
        ok = expected in resp
        if not ok:
            report(f"concurrent client {i} (page{page})", False, resp[-100:])
            all_ok = False

    report(f"{n} simultaneous clients each get their own correct response", all_ok)


def test_no_fd_leak(pid):
    baseline = proxy_fd_count(pid)

    # Run every scenario type again to make sure none of them leaks a
    # client or origin socket over repeated use.
    send_request(f"http://127.0.0.1:{ORIGIN_PORT}/index.html\n")
    send_request("not-a-url\n")
    send_request("http://this-host-does-not-exist.invalid/\n")
    send_request("http://example.com/" + ("a" * 3000) + "\n")
    time.sleep(0.3)  # give detached worker threads a moment to finish closing up

    after = proxy_fd_count(pid)
    report(
        "no leaked file descriptors after repeated success/failure requests",
        after <= baseline,
        f"baseline={baseline}, after={after}",
    )


def stop_proxy(proc):
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


def read_log(log_path):
    return Path(log_path).read_text().splitlines()


def test_log_line_format(log_path):
    send_request(f"http://127.0.0.1:{ORIGIN_PORT}/index.html\n")
    time.sleep(0.2)
    last = [l for l in read_log(log_path) if "host=127.0.0.1" in l]
    ok = bool(last) and LOG_LINE_RE.match(last[-1]) is not None
    ok = ok and "decision=allowed status=200" in last[-1]
    report("log line has timestamp, request id, host, decision, status, bytes, duration", ok,
           last[-1] if last else "no log line for 127.0.0.1")
    bytes_logged = int(re.search(r"bytes=(\d+)", last[-1]).group(1)) if last else -1
    expected = len(send_request(f"http://127.0.0.1:{ORIGIN_PORT}/index.html\n"))
    report("logged bytes equals the bytes actually forwarded", bytes_logged == expected,
           f"logged={bytes_logged}, actual={expected}")


def test_log_privacy(log_path):
    secret_requests = [
        f"http://127.0.0.1:{ORIGIN_PORT}/index.html?token=secret\n",   # forwarded
        "http://admin:hunter2@127.0.0.1:%d/index.html?token=secret\n" % ORIGIN_PORT,  # rejected
        f"http://127.0.0.1:{ORIGIN_PORT}/index.html#frag-secret\n",      # rejected
        "this is a garbage line with token=secret and hunter2\n",         # rejected
    ]
    for r in secret_requests:
        send_request(r)
    time.sleep(0.3)
    text = Path(log_path).read_text()
    leaked = [w for w in ("secret", "hunter2", "token", "admin", "frag", "garbage") if w in text]
    report("?token=secret, credentials, fragments and raw request text never reach the log",
           not leaked, f"leaked: {leaked}")


def test_log_concurrent_lines(log_path, n=40):
    before = len(read_log(log_path))
    threads = [threading.Thread(target=send_request,
                                args=(f"http://127.0.0.1:{ORIGIN_PORT}/page{(i % 5) + 1}.html\n",))
               for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    time.sleep(0.3)
    lines = read_log(log_path)
    bad = [l for l in lines if not LOG_LINE_RE.match(l)]
    ids = [int(re.search(r"req=(\d+)", l).group(1)) for l in lines if LOG_LINE_RE.match(l)]
    report(f"{n} concurrent requests -> {n} complete, non-interleaved log lines",
           len(lines) - before == n and not bad, f"new={len(lines) - before}, malformed={bad[:2]}")
    report("every request id in the log is unique", len(ids) == len(set(ids)))


def test_logging_failures_do_not_stop_proxy(tmp_dir):
    """A log path that cannot be opened, and one whose writes always fail
    (/dev/full), must both leave the proxy serving requests normally."""
    scenarios = [("unopenable log path", str(Path(tmp_dir) / "no-such-dir" / "x.log"))]
    if os.access("/dev/full", os.W_OK):
        scenarios.append(("log writes failing (/dev/full)", "/dev/full"))
    for label, path in scenarios:
        proc = start_proxy(path, tmp_dir=tmp_dir)
        try:
            resp = send_request(f"http://127.0.0.1:{ORIGIN_PORT}/index.html\n")
            bad = send_request("not-a-url\n")
            ok = (b"fixture: index page" in resp and status_line_of(bad).startswith("HTTP/1.1 400")
                  and proc.poll() is None)
            report(f"proxy keeps serving with {label}", ok, status_line_of(resp))
        finally:
            stop_proxy(proc)


def test_policy_blocklist(tmp_dir):
    """A blocked host is refused with 403 BEFORE any DNS lookup or connection."""
    block = write_rules(tmp_dir, "block.txt",
                        "127.0.0.1\nblocked-example.test\n.malicious-example.test\n")
    proc = start_proxy(Path(tmp_dir) / "policy.log",
                       {"PROXY_BLOCKLIST": str(block)}, tmp_dir)
    try:
        before = origin_hits["count"]
        resp = send_request(f"http://127.0.0.1:{ORIGIN_PORT}/index.html\n")
        line = status_line_of(resp)
        report("blocked host -> 403 Forbidden", line.startswith("HTTP/1.1 403"), line)
        report("blocked host never reached the origin (no outbound connection)",
               origin_hits["count"] == before, f"origin saw {origin_hits['count'] - before} request(s)")

        # A name that cannot resolve: if the proxy did DNS first this would be 502, not 403.
        resp = send_request("http://blocked-example.test/\n")
        line = status_line_of(resp)
        report("blocked host is refused before DNS (403, not a 502 DNS failure)",
               line.startswith("HTTP/1.1 403"), line)
        resp = send_request("http://deep.sub.malicious-example.test/\n")
        report("subdomain rule blocks any depth below the domain",
               status_line_of(resp).startswith("HTTP/1.1 403"), status_line_of(resp))

        variants = ["BLOCKED-EXAMPLE.TEST", "Blocked-Example.Test", "blocked-example.test.",
                    "bLoCkEd-ExAmPlE.tEsT:80"]
        bad = [v for v in variants
               if not status_line_of(send_request(f"http://{v}/\n")).startswith("HTTP/1.1 403")]
        report("case / trailing-dot / port variants cannot bypass a block rule", not bad, f"bypassed: {bad}")

        resp = send_request("http://notblocked-example.test/\n")
        report("a similar-looking host is not blocked (suffix boundary)",
               status_line_of(resp).startswith("HTTP/1.1 502"), status_line_of(resp))

        body = resp_body = send_request("http://blocked-example.test/\n").decode(errors="replace")
        report("403 reason is non-sensitive (no rule text, file paths or config)",
               "blocked-example" not in body.split("\r\n\r\n", 1)[1] and "block.txt" not in body, body[-120:])
        time.sleep(0.2)
        log = Path(tmp_dir, "policy.log").read_text()
        report("blocked requests are logged as decision=blocked_policy status=403",
               "decision=blocked_policy status=403" in log)
    finally:
        stop_proxy(proc)


def test_policy_allowlist(tmp_dir):
    allow = write_rules(tmp_dir, "allow.txt", "# only the local origin\n127.0.0.1\n")
    proc = start_proxy(Path(tmp_dir) / "allowmode.log", {"PROXY_ALLOWLIST": str(allow)}, tmp_dir)
    try:
        ok = send_request(f"http://127.0.0.1:{ORIGIN_PORT}/index.html\n")
        report("allowlist mode: a listed host is served", b"fixture: index page" in ok, status_line_of(ok))
        before = origin_hits["count"]
        other = send_request("http://this-host-does-not-exist.invalid/\n")
        report("allowlist mode: an unlisted host is refused before DNS (403, not 502)",
               status_line_of(other).startswith("HTTP/1.1 403"), status_line_of(other))
        report("allowlist mode: refusal made no outbound connection", origin_hits["count"] == before)
    finally:
        stop_proxy(proc)

    typo = write_rules(tmp_dir, "typo_allow.txt", "*.example.com\n")
    proc = start_proxy(Path(tmp_dir) / "typomode.log", {"PROXY_ALLOWLIST": str(typo)}, tmp_dir)
    try:
        resp = send_request(f"http://127.0.0.1:{ORIGIN_PORT}/index.html\n")
        report("a malformed allowlist fails closed (denies everything, not allow-all)",
               status_line_of(resp).startswith("HTTP/1.1 403"), status_line_of(resp))
    finally:
        stop_proxy(proc)


class ConnectionCounter:
    """A bare TCP listener on 127.0.0.1 that only counts accepted connections. If the proxy
    ever connects to a forbidden address, this count goes up -- far stronger evidence than
    'the HTTP response said 403'."""

    def __init__(self):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self.count = 0
        self._stop = False
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self):
        self.sock.settimeout(0.2)
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
                self.count += 1
                conn.close()
            except OSError:
                pass

    def close(self):
        self._stop = True
        self.sock.close()


def test_ssrf_protection(tmp_dir):
    counter = ConnectionCounter()
    log_path = Path(tmp_dir) / "ssrf.log"
    proc = start_proxy(log_path, tmp_dir=tmp_dir, private_ok=False)  # NO test override
    try:
        before_hits = origin_hits["count"]
        p = counter.port
        forbidden = {
            "loopback literal": f"127.0.0.1:{p}",
            "localhost name": f"localhost:{p}",
            "LOCALHOST. (case, trailing dot)": f"LOCALHOST.:{p}",
            "subdomain of .localhost": f"anything.localhost:{p}",
            "decimal-integer loopback (2130706433)": f"2130706433:{p}",
            "hex loopback (0x7f.1)": f"0x7f.1:{p}",
            "octal loopback (017700000001)": f"017700000001:{p}",
            "short loopback (127.1)": f"127.1:{p}",
            "private 10.0.0.0/8": "10.255.255.254:80",
            "private 172.16.0.0/12": "172.16.0.1:80",
            "private 192.168.0.0/16": "192.168.1.1:80",
            "link-local 169.254.0.0/16": "169.254.10.10:80",
            "cloud metadata 169.254.169.254": "169.254.169.254:80",
            "metadata as decimal (2852039166)": "2852039166:80",
            "unspecified 0.0.0.0": "0.0.0.0:80",
            "carrier-grade NAT 100.64.0.0/10": "100.64.0.1:80",
            "multicast 224.0.0.1": "224.0.0.1:80",
        }
        bad = []
        slow = []
        for label, target in forbidden.items():
            t0 = time.time()
            resp = send_request(f"http://{target}/\n")
            took = time.time() - t0
            line = status_line_of(resp)
            if not line.startswith("HTTP/1.1 403"):
                bad.append(f"{label} -> {line}")
            if took > 2.0:
                slow.append(f"{label} took {took:.1f}s (looks like a connection attempt)")
        report(f"{len(forbidden)} loopback/private/link-local/metadata destinations are all refused with 403",
               not bad, "; ".join(bad))
        report("refusals are immediate (no connect attempt / timeout)", not slow, "; ".join(slow))
        time.sleep(0.3)
        report("NO TCP connection was made to the forbidden local listener", counter.count == 0,
               f"{counter.count} connection(s) reached 127.0.0.1:{p}")
        report("the local origin server received no request", origin_hits["count"] == before_hits)

        body = send_request(f"http://127.0.0.1:{p}/\n").decode(errors="replace")
        report("403 body reveals no address details", "127." not in body.split("\r\n\r\n", 1)[1]
               and str(p) not in body, body[-100:])
        log = log_path.read_text()
        report("refusals are logged as decision=blocked_private status=403",
               "decision=blocked_private status=403" in log)
        report("the logged host is only the validated host (no path/port/query)",
               "host=127.0.0.1 decision=blocked_private" in log and "?" not in log)
    finally:
        stop_proxy(proc)
        counter.close()


def test_ssrf_override_is_loud(tmp_dir):
    env = dict(os.environ, PROXY_LOG_FILE=str(Path(tmp_dir) / "o.log"),
               PROXY_ALLOWLIST=str(write_rules(tmp_dir, "oa.txt", "# off\n")),
               PROXY_BLOCKLIST=str(write_rules(tmp_dir, "ob.txt", "# none\n")),
               PROXY_UNSAFE_ALLOW_PRIVATE_NETWORKS="1")
    proc = subprocess.Popen([str(PROXY_BIN)], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    time.sleep(0.6)
    stop_proxy(proc)
    err = proc.stderr.read().decode(errors="replace")
    proc.stderr.close()
    report("the testing-only SSRF override prints a loud warning at startup",
           "SSRF protection is DISABLED" in err, err[-120:])


def test_policy_startup_errors(tmp_dir):
    env = dict(os.environ, PROXY_LOG_FILE=str(Path(tmp_dir) / "x.log"),
               PROXY_BLOCKLIST=str(Path(tmp_dir) / "does-not-exist.txt"))
    proc = subprocess.run([str(PROXY_BIN)], env=env, capture_output=True, timeout=10)
    report("an explicitly configured but unreadable policy file stops startup (fail closed)",
           proc.returncode != 0 and b"refusing to start" in proc.stderr, f"rc={proc.returncode}")


def main():
    if not PROXY_BIN.exists():
        print(f"error: {PROXY_BIN} does not exist -- run `make` first", file=sys.stderr)
        sys.exit(2)

    httpd = start_origin_server()
    tmp_dir = tempfile.mkdtemp(prefix="secure-proxy-it-")
    log_path = Path(tmp_dir) / "proxy.log"
    proxy_proc = start_proxy(log_path, tmp_dir=tmp_dir)

    try:
        test_success()
        test_malformed_url()
        test_dns_failure()
        test_oversized_input()
        test_concurrent_clients()
        test_no_fd_leak(proxy_proc.pid)
        test_log_line_format(log_path)
        test_log_privacy(log_path)
        test_log_concurrent_lines(log_path)
        stop_proxy(proxy_proc)
        test_logging_failures_do_not_stop_proxy(tmp_dir)
        test_policy_blocklist(tmp_dir)
        test_policy_allowlist(tmp_dir)
        test_policy_startup_errors(tmp_dir)
        test_ssrf_protection(tmp_dir)
        test_ssrf_override_is_loud(tmp_dir)
    finally:
        stop_proxy(proxy_proc)  # no-op if already stopped
        httpd.shutdown()

    print()
    if failures:
        print(f"{len(failures)} integration test(s) FAILED: {', '.join(failures)}")
        sys.exit(1)
    print("All Phase 1 integration tests passed.")


if __name__ == "__main__":
    main()
