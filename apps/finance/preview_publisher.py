"""Publish reviewed internal websites into the dedicated read-only preview volume."""
from __future__ import annotations

import os
import re
import tempfile
from pathlib import Path

import mission_preview

MISSION_RE = re.compile(r'^f_([a-f0-9]{24})$')
HOST_TEMPLATE = 'm-{hex}.preview.awema.cloud'
SITE_FILES = {'index.html', 'styles.css', 'app.js', 'README.md'}
MAX_PAGE_BYTES = 1024 * 1024


def _atomic_write(path: Path, content: bytes, mode: int) -> None:
    if path.parent.is_symlink():
        raise RuntimeError('preview_path_symlink')
    fd, temporary = tempfile.mkstemp(prefix='.awema-preview-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def publish(c, mission_id: str, scope: str, *, site_root=None) -> str | None:
    """Publish only reviewed internal sandbox site artifacts; never touches Traefik."""
    if scope != 'awema-internal-sandbox':
        return None
    match = MISSION_RE.fullmatch(mission_id or '')
    if not match:
        return None

    root = Path(site_root or os.environ.get('AWEMA_PREVIEW_ROOT', '/data/previews'))
    if not root.is_dir() or root.is_symlink():
        raise RuntimeError('preview_destination_unavailable')

    records = c.execute(
        'select name,sha256,content from mission_artifacts where mission=? and ordinal=1',
        (mission_id,),
    ).fetchall()
    files = {row['name']: {'sha256': row['sha256'], 'content': row['content']} for row in records}
    if not SITE_FILES.issubset(files):
        return None

    page = mission_preview.build_site_preview(files)
    if len(page) > MAX_PAGE_BYTES:
        raise RuntimeError('preview_page_too_large')

    hex_id = match.group(1)
    slug = 'm-' + hex_id
    target = root / slug
    if target.is_symlink():
        raise RuntimeError('preview_path_symlink')
    target.mkdir(mode=0o700, exist_ok=True)
    if target.is_symlink() or target.resolve().parent != root.resolve():
        raise RuntimeError('preview_path_escape')
    _atomic_write(target / 'index.html', page, 0o644)
    return 'https://' + HOST_TEMPLATE.format(hex=hex_id) + '/'
