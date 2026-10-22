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


def start_origin_server():
    handler = http.server.SimpleHTTPRequestHandler

    class QuietHandler(handler):
        def log_message(self, *args):
            pass  # keep test output focused on our own PASS/FAIL lines

    os.chdir(FIXTURES_DIR)
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", ORIGIN_PORT), QuietHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd


def start_proxy(log_path):
    env = dict(os.environ, PROXY_LOG_FILE=str(log_path))
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
        proc = start_proxy(path)
        try:
            resp = send_request(f"http://127.0.0.1:{ORIGIN_PORT}/index.html\n")
            bad = send_request("not-a-url\n")
            ok = (b"fixture: index page" in resp and status_line_of(bad).startswith("HTTP/1.1 400")
                  and proc.poll() is None)
            report(f"proxy keeps serving with {label}", ok, status_line_of(resp))
        finally:
            stop_proxy(proc)


def main():
    if not PROXY_BIN.exists():
        print(f"error: {PROXY_BIN} does not exist -- run `make` first", file=sys.stderr)
        sys.exit(2)

    httpd = start_origin_server()
    tmp_dir = tempfile.mkdtemp(prefix="secure-proxy-it-")
    log_path = Path(tmp_dir) / "proxy.log"
    proxy_proc = start_proxy(log_path)

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
