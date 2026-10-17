"""Separate owner-only read surface. No subprocess, model, raw database or guest code.

OWNER_PASSWORD_HASH=sha256:<hex> hashes a randomly generated >=32-byte token,
NOT a human password. Operator retains the token outside code/logs/public assets.
Socket directory is provisioned by the operator, owned by service UID/GID10001.
"""
import collections
import errno
import hashlib
import hmac
import json
import os
import re
import secrets
import signal
import socket
import socketserver
import stat
import threading
import time
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlsplit

from owner_schema import load
from trace_schema import load as load_traces

COOKIE = '__Host-awema_owner'
SOCKET = '/run/owner/owner.sock'
DATA = Path('/owner-data/activity.json')
STATIC = Path(__file__).parent / 'private'
TTL = 3600


def prepare_socket(path):
    """Remove only our refused stale socket in an operator-controlled directory."""
    try:
        before = path.lstat()
    except FileNotFoundError:
        return
    if not stat.S_ISSOCK(before.st_mode) or before.st_uid != os.geteuid():
        raise RuntimeError('owner_socket_unsafe')
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
        probe.settimeout(1)
        try:
            probe.connect(str(path))
        except OSError as error:
            if error.errno != errno.ECONNREFUSED:
                raise RuntimeError('owner_socket_not_confirmed_stale') from None
        else:
            raise RuntimeError('owner_socket_active')
    after = path.lstat()
    if (not stat.S_ISSOCK(after.st_mode) or
            (after.st_dev, after.st_ino, after.st_uid) !=
            (before.st_dev, before.st_ino, before.st_uid)):
        raise RuntimeError('owner_socket_changed')
    path.unlink()


class State:
    def __init__(self, password_hash, origin, clock=time.time):
        if not re.fullmatch(r'sha256:[a-f0-9]{64}', password_hash or ''):
            raise ValueError('owner_password_hash_required')
        parsed = urlsplit(origin)
        if (parsed.scheme != 'https' or not parsed.hostname or parsed.username or
                parsed.password or parsed.path or parsed.query or parsed.fragment or
                origin != 'https://' + parsed.netloc):
            raise ValueError('owner_https_origin_required')
        self.password_hash, self.origin, self.clock = password_hash[7:], origin, clock
        self.sessions = {}
        self.requests, self.logins = collections.deque(), collections.deque()
        self.lock = threading.RLock()

    def admitted(self, login=False):
        with self.lock:
            now = self.clock()
            bucket, maximum = (self.logins, 5) if login else (self.requests, 240)
            while bucket and bucket[0] <= now - 60:
                bucket.popleft()
            if len(bucket) >= maximum:
                return False
            bucket.append(now)
            return True

    def session(self, token):
        with self.lock:
            now = self.clock()
            self.sessions = {k: v for k, v in self.sessions.items() if v['expires'] > now}
            return self.sessions.get(token)

    def login(self, password, previous):
        if type(password) is not str or not 43 <= len(password) <= 128:
            return None
        digest = hashlib.sha256(password.encode()).hexdigest()
        if not hmac.compare_digest(digest, self.password_hash):
            return None
        with self.lock:
            self.session('')
            self.sessions.pop(previous, None)
            if len(self.sessions) >= 128:
                return None
            token = secrets.token_urlsafe(32)
            self.sessions[token] = {'csrf': secrets.token_urlsafe(32),
                                    'expires': int(self.clock()) + TTL}
            return token


class Handler(BaseHTTPRequestHandler):
    server_version = 'AwemaOwner'
    sys_version = ''

    def log_message(self, *_args):
        pass

    def token(self):
        try:
            raw = self.headers.get('Cookie', '')
            if len(raw) > 4096 or raw.count(COOKIE + '=') != 1:
                return ''
            cookies = SimpleCookie(raw)
            value = cookies[COOKIE].value
            return value if re.fullmatch(r'[A-Za-z0-9_-]{43}', value) else ''
        except (KeyError, ValueError, CookieError):
            return ''

    def respond(self, status, body, content='application/json; charset=utf-8', cookie=None):
        if not isinstance(body, bytes):
            body = json.dumps(body, separators=(',', ':')).encode()
        self.send_response(status)
        self.send_header('Content-Type', content)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'private, no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Content-Security-Policy', "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        self.send_header('Cross-Origin-Resource-Policy', 'same-origin')
        if cookie:
            self.send_header('Set-Cookie', cookie)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        state = self.server.state
        if not state.admitted():
            return self.respond(429, {'error': 'rate_limited'})
        files = {'/private': ('index.html', 'text/html; charset=utf-8'),
                 '/private/': ('index.html', 'text/html; charset=utf-8'),
                 '/private/app.js': ('app.js', 'text/javascript; charset=utf-8'),
                 '/private/style.css': ('style.css', 'text/css; charset=utf-8')}
        if self.path in files:
            name, mime = files[self.path]
            return self.respond(200, (STATIC / name).read_bytes(), mime)
        if self.path not in ('/private/api/session', '/private/api/activity', '/private/api/traces'):
            return self.respond(404, {'error': 'not_found'})
        session = state.session(self.token())
        if not session:
            return self.respond(401, {'error': 'unauthorized'})
        if self.path.endswith('/session'):
            return self.respond(200, {'authenticated': True, **session})
        if self.path.endswith('/traces'):
            return self.respond(200, load_traces(Path('/owner-data/traces.json'), private=True))
        return self.respond(200, load(self.server.data_path, state.clock()))

    def do_POST(self):
        state = self.server.state
        if not state.admitted():
            return self.respond(429, {'error': 'rate_limited'})
        if self.path not in ('/private/api/login', '/private/api/logout'):
            return self.respond(404, {'error': 'not_found'})
        if (self.headers.get_all('Origin') != [state.origin] or
                self.headers.get('Sec-Fetch-Site') not in (None, 'same-origin')):
            return self.respond(403, {'error': 'origin_rejected'})
        if self.headers.get_all('Content-Type') != ['application/json']:
            return self.respond(415, {'error': 'json_required'})
        try:
            lengths = self.headers.get_all('Content-Length') or []
            if len(lengths) != 1 or self.headers.get('Transfer-Encoding'):
                raise ValueError()
            length = int(lengths[0])
            if not 2 <= length <= 1024:
                raise ValueError()
            body = json.loads(self.rfile.read(length))
            if type(body) is not dict:
                raise ValueError()
        except (ValueError, UnicodeError):
            return self.respond(400, {'error': 'invalid_request'})
        if self.path.endswith('/login'):
            if not state.admitted(login=True):
                return self.respond(429, {'error': 'rate_limited'})
            if set(body) != {'password'}:
                return self.respond(400, {'error': 'invalid_request'})
            token = state.login(body['password'], self.token())
            if not token:
                return self.respond(401, {'error': 'unauthorized'})
            return self.respond(200, {'authenticated': True}, cookie=
                                f'{COOKIE}={token}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age={TTL}')
        token = self.token()
        session = state.session(token)
        if not session:
            return self.respond(401, {'error': 'unauthorized'})
        csrf = self.headers.get('X-CSRF-Token', '')
        if body or not hmac.compare_digest(csrf.encode(), session['csrf'].encode()):
            return self.respond(403, {'error': 'csrf_rejected'})
        with state.lock:
            state.sessions.pop(token, None)
        return self.respond(200, {'authenticated': False}, cookie=
                            f'{COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0')


def serve():
    state = State(os.environ.get('OWNER_PASSWORD_HASH', ''), os.environ.get('OWNER_ORIGIN', ''))
    path = Path(SOCKET)
    if not stat.S_ISDIR(path.parent.stat().st_mode):
        raise RuntimeError('owner_socket_directory_required')
    prepare_socket(path)
    class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
        daemon_threads = True
        slots = threading.BoundedSemaphore(24)
        def process_request(self, request, address):
            if not self.slots.acquire(blocking=False):
                self.shutdown_request(request)
                return
            try:
                super().process_request(request, address)
            except BaseException:
                self.slots.release()
                raise
        def process_request_thread(self, request, address):
            try:
                super().process_request_thread(request, address)
            finally:
                self.slots.release()
        def handle_error(self, request, address):
            # Generic failures never log headers, request bodies or sessions.
            pass
        def get_request(self):
            request, address = super().get_request()
            request.settimeout(5)
            return request, address
    with Server(SOCKET, Handler) as server:
        os.chmod(SOCKET, 0o660)
        server.state, server.data_path = state, DATA
        def stop(_signal, _frame):
            threading.Thread(target=server.shutdown, daemon=True).start()
        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
        try:
            server.serve_forever()
        finally:
            path.unlink(missing_ok=True)


if __name__ == '__main__':
    serve()
