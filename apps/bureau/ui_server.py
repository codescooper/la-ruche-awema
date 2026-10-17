"""Static-only AWEMA UI. No credentials, database, action, or outbound network."""
from http.server import BaseHTTPRequestHandler
from socketserver import ThreadingMixIn, UnixStreamServer
from pathlib import Path
import os, stat
ROOT = Path('/app/ruche-ui')
FILES = {
    '/': 'index.html', '/index.html': 'index.html',
    '/ruche': 'index.html', '/ruche/': 'index.html',
    '/ruche/app.js': 'app.js', '/ruche/style.css': 'style.css',
    '/ruche/world.json': 'world.json',
    '/ruche/worker_ui.js': 'worker_ui.js', '/ruche/awema-logo.png': 'awema-logo.png',
    '/worker_ui.js': 'worker_ui.js', '/awema-logo.png': 'awema-logo.png',
    '/office.svg': 'office.svg',
}
MIME = {'html':'text/html', 'js':'application/javascript', 'css':'text/css', 'json':'application/json', 'svg':'image/svg+xml', 'png':'image/png'}
class Handler(BaseHTTPRequestHandler):
    server_version = ''; sys_version = ''
    def log_message(self, *args): pass
    def address_string(self): return 'local'
    def do_GET(self):
        name = FILES.get(self.path.split('?', 1)[0])
        if not name:
            self.send_error(404); return
        data = (ROOT / name).read_bytes()
        self.send_response(200)
        self.send_header('Content-Type', MIME[name.rsplit('.', 1)[1]] + '; charset=utf-8')
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'same-origin')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'self'")
        self.end_headers(); self.wfile.write(data)
    def do_POST(self): self.send_error(405)
class Server(ThreadingMixIn, UnixStreamServer):
    daemon_threads = True; block_on_close = False
socket = Path('/run/ui/ruche.sock')
if socket.exists():
    info = socket.lstat()
    assert stat.S_ISSOCK(info.st_mode) and info.st_uid == os.getuid()
    socket.unlink()
os.umask(0o007)
server = Server(str(socket), Handler); os.chmod(socket, 0o660); server.serve_forever()
