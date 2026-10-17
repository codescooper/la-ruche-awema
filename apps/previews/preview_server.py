#!/usr/bin/env python3
"""Read-only, isolated static host for reviewed AWEMA website deliverables."""
from __future__ import annotations

import os
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(os.environ.get('AWEMA_PREVIEW_ROOT', '/srv/awema-previews')).resolve()
HOST_RE = re.compile(r'^m-[a-f0-9]{24}\.preview\.awema\.cloud$')
PAGE_CSP = (
    "sandbox allow-scripts; default-src 'none'; script-src 'unsafe-inline'; "
    "style-src 'unsafe-inline'; img-src data:; media-src data:; font-src data:; "
    "connect-src 'none'; frame-src 'none'; object-src 'none'; form-action 'none'; "
    "base-uri 'none'; frame-ancestors 'none'"
)


class Handler(BaseHTTPRequestHandler):
    server_version = 'AwemaPreview/1'
    sys_version = ''

    def do_HEAD(self):
        self._serve(body=False)

    def do_GET(self):
        self._serve(body=True)

    def do_POST(self):
        self._send(405, b'', 'text/plain; charset=utf-8')

    def _serve(self, body=True):
        host = self.headers.get('Host', '').lower().split(':', 1)[0].rstrip('.')
        path = urlsplit(self.path).path
        if not HOST_RE.fullmatch(host) or path not in ('/', '/index.html'):
            self._send(404, b'Not found\n', 'text/plain; charset=utf-8', body)
            return
        slug = host.split('.', 1)[0]
        folder = ROOT / slug
        page = folder / 'index.html'
        try:
            if folder.is_symlink() or page.is_symlink() or not page.is_file():
                raise FileNotFoundError
            if page.stat().st_size > 1024 * 1024:
                raise OSError
            content = page.read_bytes()
        except (OSError, ValueError):
            self._send(404, b'Preview unavailable\n', 'text/plain; charset=utf-8', body)
            return
        self._send(200, content, 'text/html; charset=utf-8', body, PAGE_CSP)

    def _send(self, status, data, mime, body=True, csp="default-src 'none'"):
        self.send_response(status)
        self.send_header('Content-Type', mime)
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store, max-age=0')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Robots-Tag', 'noindex, nofollow, noarchive')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Content-Security-Policy', csp)
        self.end_headers()
        if body:
            self.wfile.write(data)

    def log_message(self, fmt, *args):
        # Keep access logs free of query strings and page content.
        super().log_message('%s %s', self.command, self.path.split('?', 1)[0])


def main():
    ThreadingHTTPServer(('0.0.0.0', int(os.environ.get('AWEMA_PREVIEW_PORT', '8080'))), Handler).serve_forever()


if __name__ == '__main__':
    main()
