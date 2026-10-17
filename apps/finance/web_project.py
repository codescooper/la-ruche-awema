"""Versioned offline web-project envelope. Pure validation/rendering; never executes a build.

Only this envelope may contain nested paths. Native RESULT artifacts stay flat.
A valid build claim is NOT an operator attestation; callers must bind native build/browser receipts.
"""
from __future__ import annotations
import base64
import hashlib
import json
import os
import re
import stat
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from html import escape
from html.parser import HTMLParser
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from urllib.parse import urlsplit

SCHEMA = 'awema-web-project-v1'
ARTIFACT_NAME = 'WEB_PROJECT.json'
TOOLCHAIN_ID = 'awema-web-tools-v1'
MAX_BUNDLE_BYTES = 16 * 1024 * 1024
MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_ASSET_BYTES = 8 * 1024 * 1024
MAX_TREE_FILES = 128
MAX_RENDER_BYTES = 24 * 1024 * 1024
CSP = ("sandbox allow-scripts; default-src 'none'; script-src 'unsafe-inline'; "
       "style-src 'unsafe-inline'; img-src data:; media-src data:; font-src data:; "
       "connect-src 'none'; frame-src 'none'; object-src 'none'; form-action 'none'; "
       "base-uri 'none'; frame-ancestors 'self' https://web.telegram.org")
MIME = {
    '.html': 'text/html', '.htm': 'text/html', '.css': 'text/css',
    '.js': 'text/javascript', '.mjs': 'text/javascript', '.jsx': 'text/jsx',
    '.ts': 'text/typescript', '.tsx': 'text/tsx', '.json': 'application/json',
    '.md': 'text/markdown', '.txt': 'text/plain', '.svg': 'image/svg+xml',
    '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg',
    '.webp': 'image/webp', '.gif': 'image/gif', '.ico': 'image/x-icon',
    '.woff': 'font/woff', '.woff2': 'font/woff2', '.ttf': 'font/ttf', '.otf': 'font/otf',
    '.mp4': 'video/mp4', '.webm': 'video/webm', '.mp3': 'audio/mpeg', '.wav': 'audio/wav',
    '.gltf': 'model/gltf+json', '.glb': 'model/gltf-binary',
}
TEXT_EXTENSIONS = {'.html', '.htm', '.css', '.js', '.mjs', '.jsx', '.ts', '.tsx', '.json', '.md', '.txt', '.svg', '.gltf'}
DIST_EXTENSIONS = set(MIME) - {'.jsx', '.ts', '.tsx', '.mjs'}
RESERVED = {'con', 'prn', 'aux', 'nul'} | {f'{prefix}{n}' for prefix in ('com', 'lpt') for n in range(1, 10)}
SECRET_NAMES = {'auth.json', 'credentials.json', 'token.json', 'tokens.json'}
SHA = re.compile(r'[a-f0-9]{64}\Z')
SEGMENT = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z')

class WebProjectError(ValueError):
    """Stable, non-secret error code for a refused envelope or resource."""

def fail(code):
    raise WebProjectError(code)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def canonical_path(path):
    if not isinstance(path, str) or not 1 <= len(path) <= 240 or not path.isascii():
        fail('web_path_denied')
    parts = path.split('/')
    if len(parts) > 12:
        fail('web_path_denied')
    for part in parts:
        if (not SEGMENT.fullmatch(part) or part in ('.', '..') or part.endswith(('.', ' '))
                or part.split('.')[0].casefold() in RESERVED or part.casefold() in SECRET_NAMES
                or part.casefold() in ('node_modules', '.git')):
            fail('web_path_denied')
    return path

def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            fail('web_duplicate_json_key')
        result[key] = value
    return result

def _json(raw):
    try:
        return json.loads(raw, object_pairs_hook=_unique_pairs,
                          parse_constant=lambda value: fail('web_json_constant_denied'))
    except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        if isinstance(exc, WebProjectError):
            raise
        fail('web_json_invalid')

@dataclass(frozen=True)
class FileEntry:
    path: str
    mime: str
    raw: bytes
    sha256: str
    encoding: str

    @property
    def text(self):
        if self.encoding != 'utf-8':
            fail('web_text_required')
        return self.raw.decode('utf-8')

@dataclass(frozen=True)
class Project:
    source: object
    dist: object
    source_sha256: str
    dist_sha256: str
    toolchain_id: str
    entrypoint: str = 'dist/index.html'


def _valid_svg(raw):
    if b'<!' in raw.upper():
        return False
    try:
        element = ET.fromstring(raw)
    except ET.ParseError:
        return False
    if element.tag.split('}')[-1].lower() != 'svg':
        return False
    for node in element.iter():
        if node.tag.split('}')[-1].lower() in ('script', 'foreignobject', 'iframe', 'object', 'embed'):
            return False
        for key, value in node.attrib.items():
            key = key.split('}')[-1].lower()
            if key.startswith('on') or (key in ('href', 'src') and not value.startswith('#')):
                return False
            if 'url(' in value.lower() and not re.fullmatch(r'url\(#[A-Za-z0-9_.:-]+\)', value):
                return False
    return True


def _valid_asset(ext, raw):
    if ext == '.png': return raw.startswith(b'\x89PNG\r\n\x1a\n')
    if ext in ('.jpg', '.jpeg'): return raw.startswith(b'\xff\xd8\xff')
    if ext == '.webp': return len(raw) >= 12 and raw[:4] == b'RIFF' and raw[8:12] == b'WEBP'
    if ext == '.gif': return raw.startswith((b'GIF87a', b'GIF89a'))
    if ext == '.ico': return raw.startswith(b'\x00\x00\x01\x00')
    if ext == '.woff': return raw.startswith(b'wOFF')
    if ext == '.woff2': return raw.startswith(b'wOF2')
    if ext == '.ttf': return raw.startswith((b'\x00\x01\x00\x00', b'true'))
    if ext == '.otf': return raw.startswith(b'OTTO')
    if ext == '.mp4': return len(raw) >= 12 and raw[4:8] == b'ftyp'
    if ext == '.webm': return raw.startswith(b'\x1a\x45\xdf\xa3')
    if ext == '.mp3': return raw.startswith(b'ID3') or (len(raw) >= 2 and raw[0] == 255 and raw[1] & 224 == 224)
    if ext == '.wav': return len(raw) >= 12 and raw[:4] == b'RIFF' and raw[8:12] == b'WAVE'
    if ext == '.glb': return len(raw) >= 12 and raw[:4] == b'glTF' and int.from_bytes(raw[4:8], 'little') == 2 and int.from_bytes(raw[8:12], 'little') == len(raw)
    return False


def tree_sha256(files):
    rows = [{'path': path, 'mime': item.mime, 'size': len(item.raw), 'sha256': item.sha256}
            for path, item in sorted(files.items())]
    return sha(json.dumps(rows, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii'))


def _tree(rows, section):
    if not isinstance(rows, list) or not 1 <= len(rows) <= MAX_TREE_FILES:
        fail('web_tree_count_denied')
    files, folded, asset_bytes, raw_bytes = {}, set(), 0, 0
    for row in rows:
        if not isinstance(row, dict) or set(row) != {'path', 'mime', 'encoding', 'content', 'sha256'}:
            fail('web_file_schema_denied')
        path = canonical_path(row['path'])
        if path.casefold() in folded:
            fail('web_duplicate_path')
        folded.add(path.casefold())
        ext = PurePosixPath(path).suffix.lower()
        if ext not in MIME or (section == 'dist' and ext not in DIST_EXTENSIONS):
            fail('web_file_type_denied')
        if row['mime'] != MIME[ext] or not isinstance(row['sha256'], str) or not SHA.fullmatch(row['sha256']):
            fail('web_mime_or_sha_denied')
        content = row['content']
        if not isinstance(content, str) or len(content) > MAX_BUNDLE_BYTES:
            fail('web_file_content_denied')
        if ext in TEXT_EXTENSIONS:
            if row['encoding'] != 'utf-8' or '\x00' in content:
                fail('web_text_encoding_denied')
            try: raw = content.encode('utf-8')
            except UnicodeError: fail('web_text_encoding_denied')
        else:
            if row['encoding'] != 'base64':
                fail('web_asset_encoding_denied')
            try: raw = base64.b64decode(content, validate=True)
            except (ValueError, TypeError): fail('web_asset_encoding_denied')
            if base64.b64encode(raw).decode('ascii') != content or not _valid_asset(ext, raw):
                fail('web_asset_signature_denied')
        if row['mime'].startswith(('image/', 'font/', 'audio/', 'video/', 'model/')):
            asset_bytes += len(raw)
        if ext == '.svg' and not _valid_svg(raw):
            fail('web_svg_denied')
        if not 1 <= len(raw) <= MAX_FILE_BYTES:
            fail('web_file_size_denied')
        if sha(raw) != row['sha256']:
            fail('web_file_sha_mismatch')
        raw_bytes += len(raw)
        files[path] = FileEntry(path, row['mime'], raw, row['sha256'], row['encoding'])
    for path in files:
        parts = path.split('/')
        if any('/'.join(parts[:index]).casefold() in folded for index in range(1, len(parts))):
            fail('web_path_prefix_collision')
    return MappingProxyType(files), asset_bytes, raw_bytes


def validate_project(payload):
    """dict -> immutable Project; raises WebProjectError. Does not certify a build."""
    if not isinstance(payload, dict) or set(payload) != {'schema', 'entrypoint', 'source', 'dist', 'build'}:
        fail('web_project_schema_denied')
    if payload['schema'] != SCHEMA or payload['entrypoint'] != 'dist/index.html':
        fail('web_entrypoint_denied')
    try:
        if len(json.dumps(payload, ensure_ascii=False, separators=(',', ':')).encode('utf-8')) > MAX_BUNDLE_BYTES:
            fail('web_bundle_size_denied')
    except (UnicodeError, TypeError, RecursionError):
        fail('web_json_invalid')
    source, source_assets, source_bytes = _tree(payload['source'], 'source')
    dist, dist_assets, dist_bytes = _tree(payload['dist'], 'dist')
    if source_assets + dist_assets > MAX_ASSET_BYTES or source_bytes + dist_bytes > MAX_BUNDLE_BYTES:
        fail('web_assets_size_denied')
    if 'index.html' not in dist:
        fail('web_dist_index_missing')
    build = payload['build']
    if (not isinstance(build, dict) or set(build) != {'toolchain_id', 'format', 'source_sha256', 'dist_sha256'}
            or build['toolchain_id'] != TOOLCHAIN_ID or build['format'] != 'iife'):
        fail('web_build_schema_denied')
    source_digest, dist_digest = tree_sha256(source), tree_sha256(dist)
    if build['source_sha256'] != source_digest or build['dist_sha256'] != dist_digest:
        fail('web_tree_sha_mismatch')
    return Project(source, dist, source_digest, dist_digest, build['toolchain_id'])


def load_project(raw, expected_sha256=None):
    """UTF-8 str/bytes -> immutable Project, bounded before JSON decoding."""
    if isinstance(raw, str):
        try: raw = raw.encode('utf-8')
        except UnicodeError: fail('web_json_invalid')
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= MAX_BUNDLE_BYTES:
        fail('web_bundle_size_denied')
    if expected_sha256 is not None and (not isinstance(expected_sha256, str) or not SHA.fullmatch(expected_sha256) or sha(raw) != expected_sha256):
        fail('web_bundle_sha_mismatch')
    return validate_project(_json(raw))


def _parents_regular(path):
    for parent in path.absolute().parents:
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or parent.is_symlink() or getattr(info, 'st_file_attributes', 0) & 1024:
            fail('web_parent_link_denied')


def read_project(path, expected_sha256=None):
    """Bounded regular-file reader; refuses symlinks and replacement while reading."""
    path = Path(path)
    _parents_regular(path)
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or path.is_symlink() or getattr(before, 'st_file_attributes', 0) & 1024 or not 1 <= before.st_size <= MAX_BUNDLE_BYTES:
        fail('web_regular_file_required')
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0)
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino, opened.st_size) != (before.st_dev, before.st_ino, before.st_size):
            fail('web_file_changed')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(MAX_BUNDLE_BYTES + 1)
        after = os.fstat(fd)
    finally:
        os.close(fd)
    current = path.lstat()
    _parents_regular(path)
    identity = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns)
    if identity(before) != identity(after) or identity(before) != identity(current) or path.is_symlink() or getattr(current, 'st_file_attributes', 0) & 1024:
        fail('web_file_changed')
    return load_project(raw, expected_sha256)


def build_project(source, dist, toolchain_id=TOOLCHAIN_ID):
    """Construct validated canonical bytes from path->bytes maps; never compiles.

    The operator's fixed offline builder supplies its actual source and dist bytes.
    Its separate receipt must pin the toolchain binaries/packages and exact envelope.
    """
    def rows(tree):
        if not isinstance(tree, dict) or not all(isinstance(key, str) for key in tree):
            fail('web_builder_mapping_required')
        result = []
        for path, raw in sorted(tree.items()):
            canonical_path(path)
            if not isinstance(raw, bytes): fail('web_builder_bytes_required')
            ext = PurePosixPath(path).suffix.lower()
            if ext not in MIME: fail('web_file_type_denied')
            encoding = 'utf-8' if ext in TEXT_EXTENSIONS else 'base64'
            try: content = raw.decode('utf-8') if encoding == 'utf-8' else base64.b64encode(raw).decode('ascii')
            except UnicodeError: fail('web_text_encoding_denied')
            result.append({'path': path, 'mime': MIME[ext], 'encoding': encoding, 'content': content, 'sha256': sha(raw)})
        return result
    src, dst = rows(source), rows(dist)
    src_tree, _, _ = _tree(src, 'source'); dst_tree, _, _ = _tree(dst, 'dist')
    payload = {'schema': SCHEMA, 'entrypoint': 'dist/index.html', 'source': src, 'dist': dst,
               'build': {'toolchain_id': toolchain_id, 'format': 'iife',
                         'source_sha256': tree_sha256(src_tree), 'dist_sha256': tree_sha256(dst_tree)}}
    validate_project(payload)
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode('utf-8')
    if len(raw) > MAX_BUNDLE_BYTES: fail('web_bundle_size_denied')
    return raw


def pack_project(source, dist, toolchain_id=TOOLCHAIN_ID):
    """dict[path, bytes] maps -> validated JSON-compatible envelope dictionary."""
    return _json(build_project(source, dist, toolchain_id))


def _resolve(reference, base):
    if (not isinstance(reference, str) or not reference or len(reference) > 2048
            or any(ord(ch) < 33 or ord(ch) > 126 for ch in reference) or '\\' in reference or '%' in reference):
        fail('web_resource_reference_denied')
    try: parsed = urlsplit(reference)
    except ValueError: fail('web_resource_reference_denied')
    if parsed.scheme or parsed.netloc or not parsed.path or reference.startswith('//'):
        fail('web_external_resource_denied')
    parts = [] if parsed.path.startswith('/') else base.split('/')[:-1]
    for part in parsed.path.split('/'):
        if part in ('', '.'):
            continue
        if part == '..':
            if not parts: fail('web_resource_escape_denied')
            parts.pop()
        else:
            parts.append(part)
    return canonical_path('/'.join(parts))


def _resource(files, reference, base, suffixes=None):
    path = _resolve(reference, base)
    if path not in files: fail('web_resource_missing')
    item = files[path]
    if suffixes and PurePosixPath(path).suffix.lower() not in suffixes:
        fail('web_resource_type_denied')
    return item


def _data_uri(item):
    if not item.mime.startswith(('image/', 'font/', 'audio/', 'video/')):
        fail('web_resource_type_denied')
    return 'data:' + item.mime + ';base64,' + base64.b64encode(item.raw).decode('ascii')



def _inline_data_uri(value):
    match = re.fullmatch(r'data:([A-Za-z0-9.+/-]+);base64,([A-Za-z0-9+/]*={0,2})', value)
    if not match or len(value) > MAX_FILE_BYTES * 2:
        fail('web_data_uri_denied')
    mime, content = match.groups()
    extensions = [ext for ext, definition in MIME.items() if definition == mime]
    if not extensions or not mime.startswith(('image/', 'font/', 'audio/', 'video/')):
        fail('web_data_uri_denied')
    try: raw = base64.b64decode(content, validate=True)
    except ValueError: fail('web_data_uri_denied')
    if not 1 <= len(raw) <= MAX_FILE_BYTES or base64.b64encode(raw).decode('ascii') != content:
        fail('web_data_uri_denied')
    valid = _valid_svg(raw) if '.svg' in extensions else any(_valid_asset(ext, raw) for ext in extensions)
    if not valid: fail('web_data_uri_denied')
    return 'data:' + mime + ';base64,' + content


def _css(files, text, base, seen=()):
    if len(seen) > 12 or base in seen: fail('web_css_import_cycle')
    # A fixed builder must flatten imports. This avoids incomplete CSS parsers.
    if re.search(r'@import\b|@charset\b', re.sub(r'/\*.*?\*/', '', text, flags=re.S), re.I):
        fail('web_css_import_not_bundled')
    expanded_bytes = len(text.encode('utf-8'))
    def replace(match):
        nonlocal expanded_bytes
        value = match.group(2).strip()
        if value.startswith('#') and re.fullmatch(r'#[A-Za-z0-9_.:-]{1,128}', value):
            return 'url("' + value + '")'
        uri = _inline_data_uri(value) if value.startswith('data:') else _data_uri(_resource(files, value, base))
        replacement = 'url("' + uri + '")'
        expanded_bytes += len(replacement.encode('utf-8')) - len(match.group(0).encode('utf-8'))
        if expanded_bytes > MAX_RENDER_BYTES: fail('web_render_size_denied')
        return replacement
    result = re.sub(r'url\(\s*([\'"]?)([^)]+?)\1\s*\)', replace, text, flags=re.I)
    # Escaped CSS URLs/imports are outside this deliberately narrow compiled format.
    if '\\' in re.sub(r'/\*.*?\*/', '', result, flags=re.S):
        fail('web_css_escape_not_bundled')
    return re.sub(r'</style', r'<\\/style', result, flags=re.I)


class _Parts(list):
    def __init__(self):
        super().__init__(); self.size = 0

    def append(self, value):
        self.size += len(value.encode('utf-8'))
        if self.size > MAX_RENDER_BYTES: fail('web_render_size_denied')
        super().append(value)

    def extend(self, values):
        for value in values: self.append(value)


class _Document(HTMLParser):
    VOID = {'area', 'br', 'col', 'hr', 'img', 'input', 'link', 'meta', 'param', 'source', 'track', 'wbr'}
    def __init__(self, files):
        super().__init__(convert_charrefs=False)
        self.files, self.parts, self.deferred = files, _Parts(), _Parts()
        self.skip_script, self.raw_tag = False, None
        self.raw_parts = []

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        values = {key.lower(): value or '' for key, value in attrs}
        if len(values) != len(attrs): fail('web_duplicate_html_attribute')
        if tag in ('iframe', 'object', 'embed', 'base'):
            fail('web_embedded_context_denied')
        if tag == 'meta' and 'http-equiv' in values:
            fail('web_meta_http_equiv_denied')
        if tag == 'script':
            kind = values.get('type', '').lower()
            if kind not in ('', 'text/javascript', 'application/javascript', 'application/json', 'application/ld+json'):
                fail('web_script_not_bundled')
            if values.get('src'):
                if kind in ('application/json', 'application/ld+json'):
                    fail('web_script_not_bundled')
                if any(key.startswith('on') for key in values):
                    fail('web_active_attribute_denied')
                item = _resource(self.files, values['src'], 'index.html', {'.js'})
                content = re.sub(r'</script', r'<\\/script', item.text, flags=re.I)
                replacement = '<script>' + content + '</script>'
                if 'defer' in values: self.deferred.append(replacement)
                else: self.parts.append(replacement)
                self.skip_script = True
                return
            self.raw_tag, self.raw_parts = 'script', []
        elif tag == 'style':
            self.raw_tag, self.raw_parts = 'style', []
        if tag == 'link':
            rel = values.get('rel', '').lower().split()
            if 'stylesheet' in rel:
                item = _resource(self.files, values.get('href', ''), 'index.html', {'.css'})
                self.parts.append('<style>' + _css(self.files, item.text, item.path) + '</style>')
                return
            if rel != ['icon']: fail('web_link_not_bundled')
        clean = []
        for key, value in attrs:
            key = key.lower(); value = value or ''
            if key.startswith('on') or key in ('srcdoc', 'formaction', 'action', 'ping', 'background', 'manifest', 'codebase'):
                fail('web_active_attribute_denied')
            if key in ('src', 'poster') or (tag == 'link' and key == 'href'):
                value = _inline_data_uri(value) if value.startswith('data:') else _data_uri(_resource(self.files, value, 'index.html'))
            elif key == 'srcset':
                fail('web_srcset_not_bundled')
            elif key in ('href', 'xlink:href'):
                if not value.startswith('#') or not re.fullmatch(r'#[A-Za-z0-9_.:-]{0,128}', value):
                    fail('web_external_link_denied')
            elif key == 'style':
                value = _css(self.files, value, 'index.html')
            elif key in ('integrity', 'crossorigin'):
                continue
            clean.append(' ' + key + '="' + escape(value, quote=True) + '"')
        self.parts.append('<' + tag + ''.join(clean) + '>')

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag.lower() not in self.VOID:
            self.handle_endtag(tag)

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag == 'script' and self.skip_script:
            self.skip_script = False
            return
        if tag == self.raw_tag:
            text = ''.join(self.raw_parts)
            self.parts.append(_css(self.files, text, 'index.html') if tag == 'style' else re.sub(r'</script', r'<\\/script', text, flags=re.I))
            self.raw_tag, self.raw_parts = None, []
        if tag == 'body' and self.deferred:
            self.parts.extend(self.deferred); self.deferred.clear()
        if tag not in self.VOID: self.parts.append('</' + tag + '>')

    def handle_data(self, data):
        if self.skip_script: return
        if self.raw_tag: self.raw_parts.append(data)
        else: self.parts.append(data)

    def handle_entityref(self, name):
        self.handle_data('&' + name + ';')

    def handle_charref(self, name):
        self.handle_data('&#' + name + ';')

    def handle_comment(self, data):
        if not self.skip_script and not self.raw_tag:
            self.parts.append('<!--' + data.replace('--', '—') + '-->')


def render_project(project):
    """Render only actual dist/index.html and dist resources into an opaque document.

    The exact dist tree is retained; render SHA differs because resources are inlined.
    No source file, remote URL, npm config, package script, or server-side code is executed.
    """
    if not isinstance(project, Project): fail('web_validated_project_required')
    parser = _Document(project.dist)
    parser.feed(project.dist['index.html'].text); parser.close()
    if parser.skip_script or parser.raw_tag: fail('web_html_unclosed_raw_tag')
    parser.parts.extend(parser.deferred)
    rendered = ''.join(parser.parts)
    meta = ('<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            '<meta http-equiv="Content-Security-Policy" content="' + escape(CSP.replace('sandbox allow-scripts; ', '').split('; frame-ancestors', 1)[0], quote=True) + '">')
    head = re.search(r'<head(?:\s[^>]*)?>', rendered, flags=re.I)
    rendered = rendered[:head.end()] + meta + rendered[head.end():] if head else '<head>' + meta + '</head>' + rendered
    raw = ('<!doctype html>' + rendered).encode('utf-8')
    if len(raw) > MAX_RENDER_BYTES: fail('web_render_size_denied')
    return raw


def project_metadata(project, rendered=None):
    result = {'schema': SCHEMA, 'entrypoint': project.entrypoint, 'toolchain_id': project.toolchain_id,
              'source_tree_sha256': project.source_sha256, 'dist_tree_sha256': project.dist_sha256,
              'source_files': len(project.source), 'dist_files': len(project.dist),
              'claims_are_operator_attestation': False}
    if rendered is not None: result['preview_sha256'] = sha(rendered)
    return result


def build_site_preview(files, legacy_renderer):
    """Additive dispatch: envelope if present, otherwise exact existing flat renderer."""
    item = files.get(ARTIFACT_NAME)
    if item is None:
        return legacy_renderer(files)
    if not isinstance(item, dict) or not {'content', 'sha256'} <= set(item):
        fail('web_artifact_schema_denied')
    if not isinstance(item['sha256'], str) or not SHA.fullmatch(item['sha256']):
        fail('web_bundle_sha_mismatch')
    project = load_project(item['content'], item['sha256'])
    return render_project(project)


def renderer_identity(legacy_path):
    """Both imported implementation files must be pinned by operator browser receipts."""
    return {'mission_preview.py': sha(Path(legacy_path).read_bytes()),
            'web_project.py': sha(Path(__file__).read_bytes())}
