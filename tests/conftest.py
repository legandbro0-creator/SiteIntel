"""Shared fixtures: a local HTTP server exercising redirects, cookies,
security headers, big bodies, JS navigation — no internet needed."""
from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

HTML = b"""<!doctype html><html lang="en"><head>
<title>Fixture Page</title>
<meta name="description" content="A test page">
<meta name="generator" content="WordPress 6.5">
<link rel="canonical" href="http://localhost/canonical">
<script src="/static/app.js"></script><img src="http://insecure.example/x.png">
</head><body><a href="/a">x</a></body></html>"""

JSNAV = b"""<!doctype html><html><head>
<meta http-equiv="refresh" content="0; url=/secure"></head><body>go</body></html>"""

BIG_BODY = b"x" * (600 * 1024)

ROBOTS = b"User-agent: *\nDisallow: /admin\nDisallow: /tmp\n"
SITEMAP = b"<?xml version='1.0'?><urlset><url><loc>http://localhost/a</loc></url></urlset>"


class FixtureHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def _send(self, status, body=b"", headers=()):
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        for name, value in headers:
            self.send_header(name, value)
        self.end_headers()
        if body and self.command != "HEAD":
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass  # client truncated the download on purpose (size-limit test)

    def do_GET(self):
        if self.path == "/secure":
            self._send(200, HTML, [
                ("Content-Type", "text/html; charset=utf-8"),
                ("X-Content-Type-Options", "nosniff"),
                ("Content-Security-Policy", "default-src 'self'"),
                ("Referrer-Policy", "strict-origin-when-cross-origin"),
                ("Set-Cookie", "session=abc; Secure; HttpOnly; SameSite=Lax"),
            ])
        elif self.path == "/weak":
            self._send(200, HTML, [
                ("Content-Type", "text/html"),
                ("X-Powered-By", "PHP/8.3.1"),
                ("Set-Cookie", "tracking=42"),
            ])
        elif self.path == "/jsnav":
            self._send(200, JSNAV, [("Content-Type", "text/html")])
        elif self.path in ("/redirect", "/chain"):
            self._send(302, b"", [("Location", "/redirect" if self.path == "/chain" else "/secure")])
        elif self.path == "/rel-redir":
            self._send(302, b"", [("Location", "../secure")])
        elif self.path == "/loop1":
            self._send(302, b"", [("Location", "/loop2")])
        elif self.path == "/loop2":
            self._send(302, b"", [("Location", "/loop1")])
        elif self.path == "/big":
            self._send(200, BIG_BODY, [("Content-Type", "text/html")])
        elif self.path == "/robots.txt":
            self._send(200, ROBOTS, [("Content-Type", "text/plain")])
        elif self.path == "/sitemap.xml":
            self._send(200, SITEMAP, [("Content-Type", "application/xml")])
        elif self.path == "/favicon.ico":
            self._send(200, b"FAKEICONBYTES123456", [("Content-Type", "image/x-icon")])
        else:
            self._send(404, b"nope")

    do_HEAD = do_GET


@pytest.fixture(scope="session")
def fixture_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    thread.join(timeout=2)
