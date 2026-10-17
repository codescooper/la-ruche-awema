"""Authenticated, sandboxed previews for validated Ruche mission artifacts."""
from __future__ import annotations

import base64
import hashlib
import json
import re
from html import escape
from html.parser import HTMLParser
from pathlib import PurePosixPath
import web_project

MEDIA_PREFIX = 'AWEMA_MEDIA_V1\n'
MEDIA_TYPES = {
    '.png': ('image/png', b'\x89PNG\r\n\x1a\n'),
    '.jpg': ('image/jpeg', b'\xff\xd8\xff'),
    '.jpeg': ('image/jpeg', b'\xff\xd8\xff'),
    '.webp': ('image/webp', b'RIFF'),
    '.gif': ('image/gif', (b'GIF87a', b'GIF89a')),
    '.pdf': ('application/pdf', b'%PDF-'),
    '.mp4': ('video/mp4', b'ftyp'),
    '.webm': ('video/webm', b'\x1a\x45\xdf\xa3'),
    '.mp3': ('audio/mpeg', (b'ID3',)),
    '.wav': ('audio/wav', b'RIFF'),
}
SITE_TYPES = {
    '.html': 'text/html; charset=utf-8', '.htm': 'text/html; charset=utf-8',
    '.css': 'text/plain; charset=utf-8', '.js': 'text/plain; charset=utf-8',
    '.mjs': 'text/plain; charset=utf-8', '.jsx': 'text/plain; charset=utf-8',
    '.py': 'text/plain; charset=utf-8', '.ts': 'text/plain; charset=utf-8',
    '.tsx': 'text/plain; charset=utf-8', '.svg': 'text/plain; charset=utf-8',
    '.json': 'application/json; charset=utf-8',
    '.md': 'text/plain; charset=utf-8', '.txt': 'text/plain; charset=utf-8',
}
INLINE_SCRIPT_CSP = (
    "sandbox allow-scripts; default-src 'none'; script-src 'unsafe-inline'; "
    "style-src 'unsafe-inline'; img-src data:; media-src data:; font-src data:; "
    "connect-src 'none'; frame-src 'none'; object-src 'none'; form-action 'none'; "
    "base-uri 'none'; frame-ancestors 'self' https://web.telegram.org"
)
STATIC_CSP = (
    "sandbox; default-src 'none'; img-src 'self' data:; media-src 'self' data:; "
    "frame-ancestors 'self' https://web.telegram.org"
)
_SAFE_BASENAME = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$')


def _media(content: str, name: str, digest: str):
    if not isinstance(content, str) or not content.startswith(MEDIA_PREFIX):
        return None
    try:
        envelope = json.loads(content[len(MEDIA_PREFIX):])
        raw = base64.b64decode(envelope['base64'], validate=True)
    except (ValueError, TypeError, KeyError):
        return None
    ext = PurePosixPath(name).suffix.lower()
    definition = MEDIA_TYPES.get(ext)
    if not definition or len(raw) < 1 or len(raw) > 1024 * 1024:
        return None
    mime, signature = definition
    valid = raw.startswith(signature) if isinstance(signature, bytes) else raw.startswith(signature)
    if ext == '.webp':
        valid = len(raw) >= 12 and raw.startswith(b'RIFF') and raw[8:12] == b'WEBP'
    elif ext == '.mp4':
        valid = len(raw) >= 12 and raw[4:8] == b'ftyp'
    elif ext == '.wav':
        valid = len(raw) >= 12 and raw[:4] == b'RIFF' and raw[8:12] == b'WAVE'
    elif ext == '.mp3':
        valid = raw.startswith(b'ID3') or (len(raw) >= 2 and raw[0] == 0xff and raw[1] & 0xe0 == 0xe0)
    if (not valid or envelope.get('mime') != mime or envelope.get('size') != len(raw)
            or hashlib.sha256(raw).hexdigest() != digest):
        return None
    return mime, raw


def _data_uri(content: str, name: str, digest: str):
    media = _media(content, name, digest)
    if not media or media[0] == 'application/pdf':
        return None
    mime, raw = media
    if mime == 'image/svg+xml':
        return None
    return 'data:' + mime + ';base64,' + base64.b64encode(raw).decode('ascii')


def _bundle_name(value):
    """Resolve flat, bundle-local references without admitting paths or hosts."""
    value = value.split('#', 1)[0].split('?', 1)[0]
    if value.startswith('./'):
        value = value[2:]
    return value if _SAFE_BASENAME.fullmatch(value) else None


class _SiteDocument(HTMLParser):
    """Inline only bundle-local CSS, JS, and signature-checked raster assets."""
    VOID = {'area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta', 'param', 'source', 'track', 'wbr'}

    def __init__(self, files):
        super().__init__(convert_charrefs=False)
        self.files = files
        self.parts = []
        self.skip_script = False
        self.skip_frame = 0
        self.deferred_scripts = []

    def _inline(self, name, tag, attrs=None):
        name = _bundle_name(name)
        if not name:
            return None
        entry = self.files.get(name)
        if not entry:
            return None
        content = entry['content']
        if content.startswith(MEDIA_PREFIX):
            return None
        if tag == 'style' and name.lower().endswith('.css'):
            def css_asset(match):
                asset = match.group(2).strip().strip('"\'')
                if asset.startswith('#') and re.fullmatch(r'#[A-Za-z0-9_.:-]{1,128}', asset):
                    return 'url("' + asset + '")'
                asset = _bundle_name(asset)
                item = self.files.get(asset)
                uri = _data_uri(item['content'], asset, item['sha256']) if item else None
                return 'url("' + uri + '")' if uri else 'url("about:blank")'
            content = re.sub(r'url\(\s*(["\']?)([^)]+?)\1\s*\)', css_asset, content, flags=re.I)
            return '<style>' + re.sub(r'</style', r'<\\/style', content, flags=re.I) + '</style>'
        if tag == 'script' and name.lower().endswith(('.js', '.mjs')):
            attrs = attrs or {}
            kind = ' type="' + escape(attrs['type'], quote=True) + '"' if attrs.get('type') else ''
            if 'nomodule' in attrs:
                kind += ' nomodule'
            return '<script' + kind + '>' + re.sub(r'</script', r'<\\/script', content, flags=re.I) + '</script>'
        return None

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        values = {k.lower(): (v or '') for k, v in attrs}
        if self.skip_frame:
            if tag == 'iframe': self.skip_frame += 1
            return
        if tag in ('iframe', 'object', 'embed'):
            self.skip_frame = 1 if tag == 'iframe' else 0
            self.parts.append('<div class="awema-preview-note">Contenu intégré bloqué dans l’aperçu isolé.</div>')
            return
        if tag == 'script' and values.get('src'):
            replacement = self._inline(values['src'], 'script', values)
            if replacement and ('defer' in values or values.get('type', '').lower() == 'module'):
                self.deferred_scripts.append(replacement)
            else:
                self.parts.append(replacement or '')
            self.skip_script = True
            return
        if tag == 'link' and 'stylesheet' in values.get('rel', '').lower().split():
            replacement = self._inline(values.get('href', ''), 'style')
            self.parts.append(replacement or '')
            return
        if tag == 'base':
            return
        clean = []
        for key, value in attrs:
            key_lower = key.lower()
            value = value or ''
            if key_lower.startswith('on') or key_lower in ('srcdoc', 'formaction'):
                continue
            if key_lower in ('src', 'poster'):
                asset = _bundle_name(value)
                item = self.files.get(asset)
                uri = _data_uri(item['content'], asset, item['sha256']) if item else None
                if uri:
                    value = uri
                else:
                    continue
            elif key_lower == 'href':
                # Keep in-page anchors only; links cannot escape the preview.
                if not value.startswith('#'):
                    continue
            clean.append(' ' + key + '="' + escape(value, quote=True) + '"')
        self.parts.append('<' + tag + ''.join(clean) + '>')

    def handle_endtag(self, tag):
        tag = tag.lower()
        if self.skip_frame:
            if tag == 'iframe':
                self.skip_frame -= 1
            return
        if tag == 'script' and self.skip_script:
            self.skip_script = False
            return
        if tag == 'body' and self.deferred_scripts:
            self.parts.extend(self.deferred_scripts)
            self.deferred_scripts.clear()
        if tag not in self.VOID:
            self.parts.append('</' + tag + '>')

    def handle_data(self, data):
        if not self.skip_frame and not self.skip_script:
            self.parts.append(data)

    def handle_entityref(self, name):
        if not self.skip_frame and not self.skip_script:
            self.parts.append('&' + name + ';')

    def handle_charref(self, name):
        if not self.skip_frame and not self.skip_script:
            self.parts.append('&#' + name + ';')

    def handle_comment(self, data):
        if not self.skip_frame:
            self.parts.append('<!--' + data.replace('--', '—') + '-->')


def _build_legacy_site_preview(files: dict[str, dict]) -> bytes:
    index = files.get('index.html') or files.get('index.htm')
    if not index or index['content'].startswith(MEDIA_PREFIX):
        raise ValueError('site_index_missing')
    parser = _SiteDocument(files)
    parser.feed(index['content'])
    parser.close()
    # Fragments without an explicit body still execute deferred scripts last.
    parser.parts.extend(parser.deferred_scripts)
    rendered = ''.join(parser.parts)
    meta = ('<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            '<meta http-equiv="Content-Security-Policy" content="default-src &#39;none&#39;; script-src &#39;unsafe-inline&#39;; style-src &#39;unsafe-inline&#39;; img-src data:; media-src data:; connect-src &#39;none&#39;; frame-src &#39;none&#39;; object-src &#39;none&#39;; form-action &#39;none&#39;; base-uri &#39;none&#39;">')
    head = re.search(r'<head(?:\s[^>]*)?>', rendered, flags=re.I)
    if head:
        rendered = rendered[:head.end()] + meta + rendered[head.end():]
    else:
        rendered = '<head>' + meta + '</head>' + rendered
    return ('<!doctype html>' + rendered).encode('utf-8')


def build_site_preview(files: dict[str, dict]) -> bytes:
    return web_project.build_site_preview(files, _build_legacy_site_preview)


def artifact_preview(c, user, data, require):
    """Return only a caller-owned artifact, never a public or reusable URL."""
    # Store.authenticate returns sqlite3.Row; normalize at this API boundary.
    user = dict(user)
    mission = data.get('mission')
    ordinal = data.get('ordinal')
    name = data.get('name')
    if name == 'site':
        name = '__site__'
    require(isinstance(mission, str) and re.fullmatch(r'f_[a-f0-9]{24}', mission), 404, 'preview_missing')
    require(type(ordinal) is int and 0 <= ordinal < 64, 404, 'preview_missing')
    require(user.get('role') in ('owner', 'director'), 403, 'preview_role_denied')
    require(name == '__site__' or (isinstance(name, str) and _SAFE_BASENAME.fullmatch(name)), 404, 'preview_missing')
    row = c.execute('select user,generation from mission_flows where id=?', (mission,)).fetchone()
    require(row and (row['user'] == user['id'] and row['generation'] == user['generation']
                     or user.get('role') == 'owner'), 404, 'preview_missing')
    records = c.execute('select name,sha256,content from mission_artifacts where mission=? and ordinal=?',
                        (mission, ordinal)).fetchall()
    files = {r['name']: {'sha256': r['sha256'], 'content': r['content']} for r in records}
    if name == '__site__':
        return 'text/html; charset=utf-8', INLINE_SCRIPT_CSP, build_site_preview(files)
    artifact = files.get(name)
    require(artifact is not None, 404, 'preview_missing')
    media = _media(artifact['content'], name, artifact['sha256'])
    if media:
        mime, raw = media
        return mime, STATIC_CSP, raw
    ext = PurePosixPath(name).suffix.lower()
    mime = SITE_TYPES.get(ext)
    require(mime is not None, 415, 'preview_type_unsupported')
    raw = artifact['content'].encode('utf-8')
    if ext in ('.html', '.htm'):
        return 'text/html; charset=utf-8', INLINE_SCRIPT_CSP, build_site_preview(files)
    return mime, STATIC_CSP, raw
