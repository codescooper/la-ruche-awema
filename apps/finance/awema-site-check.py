#!/usr/bin/env python3
"""Read-only, offline checks for the AWEMA static-site mission profile."""
import argparse
import html.parser
import json
import mimetypes
import os
import re
import shutil
import subprocess
import sys
import threading
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import web_project

REQUIRED = ('index.html', 'styles.css', 'app.js', 'README.md')
MAX_BYTES = 1024 * 1024


class PageParser(html.parser.HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.ids = set()
        self.duplicate_ids = 0
        self.links = []
        self.resources = []
        self.labels = set()
        self.controls = []
        self.images_without_alt = 0
        self.buttons = []
        self._button = None
        self.title = False
        self._in_title = False
        self._title_text = ''
        self.lang = False
        self.viewport = False

    def handle_starttag(self, tag, raw_attrs):
        attrs = {key.lower(): value or '' for key, value in raw_attrs}
        if attrs.get('id'):
            if attrs['id'] in self.ids:
                self.duplicate_ids += 1
            self.ids.add(attrs['id'])
        if tag == 'html':
            self.lang = bool(attrs.get('lang'))
        if tag == 'title':
            self._in_title = True
        if tag == 'meta' and attrs.get('name', '').lower() == 'viewport':
            self.viewport = 'width=device-width' in attrs.get('content', '').lower()
        if tag == 'label' and attrs.get('for'):
            self.labels.add(attrs['for'])
        if tag == 'img' and 'alt' not in attrs:
            self.images_without_alt += 1
        if tag in ('input', 'select', 'textarea') and attrs.get('type', '').lower() != 'hidden':
            self.controls.append((attrs.get('id', ''), bool(attrs.get('aria-label') or attrs.get('aria-labelledby'))))
        if tag == 'button':
            self._button = {'text': '', 'named': bool(attrs.get('aria-label') or attrs.get('aria-labelledby'))}
        if tag == 'a' and attrs.get('href'):
            self.links.append(attrs['href'])
        for key in ('src', 'poster'):
            if attrs.get(key):
                self.resources.append((tag, attrs[key]))
        if tag == 'link' and attrs.get('href') and 'stylesheet' in attrs.get('rel', '').lower():
            self.resources.append((tag, attrs['href']))

    def handle_endtag(self, tag):
        if tag == 'title':
            self._in_title = False
            self.title = bool(self._title_text.strip())
        if tag == 'button' and self._button is not None:
            self.buttons.append(bool(self._button['named'] or self._button['text'].strip()))
            self._button = None

    def handle_data(self, data):
        if self._in_title:
            self._title_text += data
        if self._button is not None:
            self._button['text'] += data


def safe_text(root, name):
    path = root / name
    if path.is_symlink() or not path.is_file() or path.resolve().parent != root.resolve():
        raise ValueError('required or referenced file is missing or unsafe')
    raw = path.read_bytes()
    if len(raw) > MAX_BYTES or b'\x00' in raw:
        raise ValueError('file exceeds the text boundary')
    return raw.decode('utf-8')


def local_target(value, source):
    parsed = urllib.parse.urlsplit(value.strip())
    if parsed.scheme or parsed.netloc:
        return None
    path = urllib.parse.unquote(parsed.path)
    if not path:
        return ('fragment', parsed.fragment) if parsed.fragment else None
    if path.startswith('/'):
        path = path.lstrip('/')
    name = Path(path)
    if name.is_absolute() or '\\' in path or any(part in ('.', '..') for part in name.parts):
        raise ValueError('unsafe local path')
    if not name.parts:
        return None
    return name.as_posix()


def check_web_project(root):
    project=web_project.read_project(root/web_project.ARTIFACT_NAME)
    rendered=web_project.render_project(project)
    parser=PageParser();parser.feed(project.dist['index.html'].text);parser.close()
    if not parser.lang or not parser.title or not parser.viewport:raise ValueError('HTML must declare language, title and a mobile viewport')
    if parser.duplicate_ids or parser.images_without_alt or not all(parser.buttons):raise ValueError('HTML accessibility basics failed')
    if any(not (named or field_id in parser.labels) for field_id,named in parser.controls):raise ValueError('HTML control without accessible label')
    for value in parser.links:
        if value.startswith('#') and value[1:] and value[1:] not in parser.ids:raise ValueError('HTML anchor points to a missing id')
    css='\n'.join(item.text for path,item in project.dist.items() if path.endswith('.css'))
    if not re.search(r'@media[^{}]*\b(?:max|min)-width\s*:',css,re.I):raise ValueError('CSS has no width-based responsive breakpoint')
    node=shutil.which('node')
    if not node:raise ValueError('Node.js unavailable for syntax checking')
    js_files=[item for path,item in project.dist.items() if path.endswith('.js')]
    if not js_files:raise ValueError('Compiled JavaScript missing')
    for item in js_files:
        parsed=subprocess.run([node,'--check','--input-type=commonjs'],input=item.text,capture_output=True,text=True,timeout=15,check=False)
        if parsed.returncode:raise ValueError('Compiled JavaScript syntax check failed')
    return {'status':'pass','checks':{'web_project_envelope':True,'actual_dist_rendered':True,'html_mobile_and_accessibility_basics':True,'local_links_and_assets':True,'responsive_css_breakpoint':True,'javascript_syntax':True,'external_resources_fetched':False,'browser_visual_interaction':'native_browser_required'},'web_project':web_project.project_metadata(project,rendered),'limitations':['Static parsing and syntax only; independent native browser receipt is required.','Build metadata in the envelope is a claim until bound to the native builder receipt.']}


def check_site(root):
    if root.is_symlink() or not root.is_dir():
        raise ValueError('site root must be a regular directory')
    root = root.resolve()
    if (root/web_project.ARTIFACT_NAME).exists():return check_web_project(root)
    for name in REQUIRED:
        safe_text(root, name)
    page = safe_text(root, 'index.html')
    css = safe_text(root, 'styles.css')
    js = safe_text(root, 'app.js')
    parser = PageParser()
    parser.feed(page)
    parser.close()

    if not parser.lang or not parser.title or not parser.viewport:
        raise ValueError('HTML must declare language, title and a mobile viewport')
    if parser.duplicate_ids:
        raise ValueError('HTML contains duplicate ids')
    if parser.images_without_alt:
        raise ValueError('HTML contains images without alt text')
    if not all(parser.buttons):
        raise ValueError('HTML contains a button without an accessible name')
    if any(not (named or field_id in parser.labels) for field_id, named in parser.controls):
        raise ValueError('HTML contains a form control without an accessible label')
    if not re.search(r'@media[^{}]*\b(?:max|min)-width\s*:', css, re.I):
        raise ValueError('CSS has no width-based responsive breakpoint')

    local_files = set()
    external_links = 0
    for value in parser.links:
        target = local_target(value, 'index.html')
        if target is None:
            parsed = urllib.parse.urlsplit(value)
            if parsed.scheme in ('http', 'https', 'mailto', 'tel'):
                external_links += 1
            continue
        if isinstance(target, tuple):
            if target[1] and target[1] not in parser.ids:
                raise ValueError('HTML anchor points to a missing id')
            continue
        safe_text(root, target)
        local_files.add(target)

    for tag, value in parser.resources:
        parsed = urllib.parse.urlsplit(value.strip())
        if parsed.scheme or parsed.netloc:
            raise ValueError('external resource loading is not allowed')
        target = local_target(value, 'index.html')
        if target:
            if isinstance(target, tuple):
                continue
            safe_text(root, target)
            local_files.add(target)

    css_refs = re.findall(r'url\(\s*[\"\']?([^\"\')]+)', css, re.I)
    css_refs += re.findall(r'@import\s+[\"\']([^\"\']+)', css, re.I)
    for value in css_refs:
        value = value.strip()
        if value.startswith('#') or value.startswith('data:image/'):
            continue
        target = local_target(value, 'styles.css')
        if target is None:
            raise ValueError('external CSS resource loading is not allowed')
        if isinstance(target, tuple):
            continue
        safe_text(root, target)
        local_files.add(target)

    node = shutil.which('node')
    if not node:
        raise ValueError('Node.js is unavailable for JavaScript syntax checking')
    parsed_js = subprocess.run([node, '--check', str(root / 'app.js')], capture_output=True,
                               text=True, timeout=15, check=False)
    if parsed_js.returncode:
        raise ValueError('JavaScript syntax check failed')

    # Exercise only static GET delivery on loopback. This never executes app.js
    # and never connects to an external host.
    served = {}
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            name = {'/': 'index.html', '/index.html': 'index.html',
                    '/styles.css': 'styles.css', '/app.js': 'app.js'}.get(self.path)
            if not name:
                self.send_error(404)
                return
            body = safe_text(root, name).encode('utf-8')
            self.send_response(200)
            self.send_header('Content-Type', mimetypes.guess_type(name)[0] or 'text/plain')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        def log_message(self, *_args):
            return

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        base = 'http://127.0.0.1:'+str(server.server_port)
        for path in ('/', '/styles.css', '/app.js'):
            with urllib.request.urlopen(base+path, timeout=3) as response:
                served[path] = response.status == 200 and response.read()
        if not all(served.values()):
            raise ValueError('loopback HTTP check failed')
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)

    return {'status': 'pass', 'checks': {
        'required_files': True, 'html_mobile_and_accessibility_basics': True,
        'local_links_and_assets': True, 'responsive_css_breakpoint': True,
        'javascript_syntax': True, 'loopback_http': True,
        'external_resources_fetched': False, 'browser_visual_interaction': 'not_available'
    }, 'local_references': len(local_files), 'external_navigation_links_not_fetched': external_links,
       'limitations': ['Aucun navigateur headless dans le worker : aucun rendu visuel ni clic simulé.']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('site_root', help='directory containing the four approved site files')
    args = parser.parse_args()
    try:
        result = check_site(Path(args.site_root))
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return 0
    except Exception as exc:
        print(json.dumps({'status': 'fail', 'reason': str(exc)}, ensure_ascii=False, sort_keys=True))
        return 1


if __name__ == '__main__':
    sys.exit(main())
