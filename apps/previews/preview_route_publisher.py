"""Create atomic, exact-host Traefik routes for internal previews only."""
from __future__ import annotations

import os
import re
import tempfile
from pathlib import Path

SLUG_RE = re.compile(r'^m-([a-f0-9]{24})$')
ROUTE_RE = re.compile(r'^awema-preview-(m-[a-f0-9]{24})\.yml$')
MAX_PAGE_BYTES = 1024 * 1024


def _atomic_write(path: Path, content: bytes) -> bool:
    if path.is_symlink():
        raise RuntimeError('preview_route_symlink')
    if path.is_file() and path.read_bytes() == content:
        return False
    fd, temporary = tempfile.mkstemp(prefix='.awema-preview-route-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
        return True
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def publish_routes(*, site_root=None, dynamic_root=None, resolver=None) -> int:
    sites = Path(site_root or os.environ.get('AWEMA_PREVIEW_ROOT', '/opt/awema-jury/finance/data/previews'))
    dynamic = Path(dynamic_root or os.environ.get('AWEMA_TRAEFIK_DYNAMIC_DIR', '/data/coolify/proxy/dynamic'))
    resolver_name = resolver
    if resolver_name is None:
        resolver_file = Path('/etc/awema-preview/letsencrypt-resolver')
        resolver_name = resolver_file.read_text(encoding='ascii').strip()
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,48}', resolver_name or ''):
        raise RuntimeError('preview_tls_resolver_unconfigured')
    if not sites.is_dir() or sites.is_symlink() or not dynamic.is_dir() or dynamic.is_symlink():
        raise RuntimeError('preview_destination_unavailable')

    changed = 0
    live_slugs: set[str] = set()
    for folder in sites.iterdir():
        match = SLUG_RE.fullmatch(folder.name)
        if not match or folder.is_symlink() or not folder.is_dir():
            continue
        page = folder / 'index.html'
        if page.is_symlink() or not page.is_file() or page.stat().st_size > MAX_PAGE_BYTES:
            continue
        slug = folder.name
        live_slugs.add(slug)
        host = f'{slug}.preview.awema.cloud'
        service = f'awema-preview-{slug}'
        content = (
            'http:\n'
            '  routers:\n'
            f'    {service}:\n'
            f"      rule: 'Host(`{host}`)'\n"
            '      entryPoints:\n'
            '        - https\n'
            f'      service: {service}\n'
            '      tls:\n'
            f'        certResolver: {resolver_name}\n'
            '  services:\n'
            f'    {service}:\n'
            '      loadBalancer:\n'
            '        servers:\n'
            '          - url: http://awema-preview-sites:8080\n'
        ).encode('ascii')
        route = dynamic / f'{service}.yml'
        if _atomic_write(route, content):
            changed += 1

    # Remove only files in the private, reserved namespace created by this worker.
    for route in dynamic.iterdir():
        route_match = ROUTE_RE.fullmatch(route.name)
        if route_match and route_match.group(1) not in live_slugs:
            if route.is_symlink():
                raise RuntimeError('preview_route_symlink')
            route.unlink()
            changed += 1
    return changed


if __name__ == '__main__':
    changed = publish_routes()
    if changed:
        print(f'preview_routes_changed={changed}')
