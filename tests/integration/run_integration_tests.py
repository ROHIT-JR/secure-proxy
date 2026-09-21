#!/usr/bin/env python3
"""Phase 1 integration tests: exercises the built bin/proxy end to end
against a local-origin test server, covering success, malformed URL, DNS
failure, oversized input, and multiple concurrent clients. Also checks
that the proxy's open file descriptor count returns to its baseline after
every scenario, as evidence that every socket it opens is also closed.

Deliberately uses only local-origin servers -- no real external site is
ever contacted, per the project's safe-testing rules.
"""

import http.server
import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
PROXY_BIN = REPO_ROOT / "bin" / "proxy"
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures" / "webroot"

PROXY_PORT = 8080
ORIGIN_PORT = 9195

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


def start_proxy():
    proc = subprocess.Popen(
        [str(PROXY_BIN)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
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


def main():
    if not PROXY_BIN.exists():
        print(f"error: {PROXY_BIN} does not exist -- run `make` first", file=sys.stderr)
        sys.exit(2)

    httpd = start_origin_server()
    proxy_proc = start_proxy()

    try:
        test_success()
        test_malformed_url()
        test_dns_failure()
        test_oversized_input()
        test_concurrent_clients()
        test_no_fd_leak(proxy_proc.pid)
    finally:
        proxy_proc.terminate()
        try:
            proxy_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proxy_proc.kill()
        httpd.shutdown()

    print()
    if failures:
        print(f"{len(failures)} integration test(s) FAILED: {', '.join(failures)}")
        sys.exit(1)
    print("All Phase 1 integration tests passed.")


if __name__ == "__main__":
    main()
