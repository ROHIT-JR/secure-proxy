#!/usr/bin/env python3
"""demo_servers.py: local servers for the SecureBrowse demo (docs/demo.md).

Starts, on this machine only:
  * a plain HTTP origin on 127.0.0.1:9100 that serves the pages in tests/fixtures/webroot and
    PRINTS every request it receives, so you can see whether the proxy contacted it or answered
    from its cache;
  * a TLS (HTTPS) origin on 127.0.0.1:9443 with a throw-away self-signed certificate, which prints
    the request it decrypted, to show that only the real server can read a tunnelled request.

Nothing leaves your computer, no internet is needed, and the certificate and its key are created
fresh in demo-out/ and are never committed. Stop with Ctrl+C.
"""

import argparse
import http.server
import socket
import ssl
import subprocess
import sys
import threading
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
WEBROOT = REPO_ROOT / "tests" / "fixtures" / "webroot"


def say(msg):
    print(msg, flush=True)


class OriginHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(WEBROOT), **kwargs)

    def log_message(self, fmt, *args):
        pass  # replaced by the explicit line printed in do_GET

    def do_GET(self):
        # Show only the path: the demo never prints query strings, and neither does the proxy's log.
        say(f"origin: GET {self.path.split('?', 1)[0]}   <- the proxy contacted this server")
        if self.path.split("?", 1)[0] == "/cookie.html":
            body = b"<html><body>a page that sets a cookie (so the proxy must NOT cache it)</body></html>\n"
            self.send_response(200)
            self.send_header("Set-Cookie", "session=demo-not-a-real-session")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        super().do_GET()


def make_certificate(out_dir):
    out_dir.mkdir(parents=True, exist_ok=True)
    key, cert = out_dir / "demo-key.pem", out_dir / "demo-cert.pem"
    result = subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(cert),
         "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
        capture_output=True,
    )
    return (key, cert) if result.returncode == 0 else None


def tls_server(port, key, cert):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(cert), str(key))
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(16)
    while True:
        conn, _ = srv.accept()
        try:
            tls = ctx.wrap_socket(conn, server_side=True)
            request = tls.recv(8192)
            first_line = request.split(b"\r\n", 1)[0].decode(errors="replace")
            say(f"tls-origin: decrypted request: {first_line}   <- only THIS server can read it")
            body = b"tls-demo-response: this text travelled encrypted all the way from the origin\n"
            tls.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: %d\r\n\r\n" % len(body) + body)
            tls.close()
        except (ssl.SSLError, OSError):
            conn.close()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--origin-port", type=int, default=9100)
    ap.add_argument("--tls-port", type=int, default=9443)
    ap.add_argument("--out-dir", default=str(REPO_ROOT / "demo-out"))
    args = ap.parse_args()

    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", args.origin_port), OriginHandler)
    httpd.daemon_threads = True
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    say(f"origin ready:     http://127.0.0.1:{args.origin_port}/   (pages from tests/fixtures/webroot)")

    pair = None
    try:
        pair = make_certificate(Path(args.out_dir))
    except OSError:
        pass
    if pair is None:
        say("tls-origin skipped: the 'openssl' command was not found (the HTTPS CONNECT step needs it)")
    else:
        key, cert = pair
        threading.Thread(target=tls_server, args=(args.tls_port, key, cert), daemon=True).start()
        say(f"tls-origin ready: https://localhost:{args.tls_port}/   (certificate: {cert})")

    say("waiting for requests... (Ctrl+C to stop)")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        say("\nstopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
