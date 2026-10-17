import base64
import hashlib
import json
import sqlite3
import unittest

import mission_preview as preview
import mission_flow


def envelope(name, raw):
    mime = preview.MEDIA_TYPES[name[name.rfind('.'):].lower()][0]
    return preview.MEDIA_PREFIX + json.dumps({
        'mime': mime, 'size': len(raw), 'base64': base64.b64encode(raw).decode('ascii')
    })


def require(value, code=400, reason='invalid_request'):
    if not value:
        raise PermissionError(reason)


class MissionPreviewTests(unittest.TestCase):
    def test_site_preview_inlines_bundle_and_blocks_escape_routes(self):
        files = {
            'index.html': {'content': '<!doctype html><html><head><link rel="stylesheet" href="styles.css"><script src="app.js"></script></head><body><img src="MEDIA-1.png" onclick="alert(1)"><a href="https://outside.example">out</a><iframe src="https://outside.example"></iframe></body></html>', 'sha256': ''},
            'styles.css': {'content': 'body{color:#111} .hero{background:url(MEDIA-1.png)} .icon{fill:url(#local-gradient)}', 'sha256': ''},
            'app.js': {'content': 'document.body.dataset.ready="yes"; fetch("https://outside.example")', 'sha256': ''},
            'MEDIA-1.png': {'content': envelope('MEDIA-1.png', b'\x89PNG\r\n\x1a\nfixture'), 'sha256': hashlib.sha256(b'\x89PNG\r\n\x1a\nfixture').hexdigest()},
        }
        raw = preview.build_site_preview(files).decode()
        self.assertIn('<style>body{color:#111}', raw)
        self.assertIn('document.body.dataset.ready=', raw)
        self.assertIn('data:image/png;base64,', raw)
        self.assertNotIn('onclick=', raw)
        self.assertNotIn('href="https://outside.example"', raw)
        self.assertNotIn('src="https://outside.example"', raw)
        self.assertIn('fetch("https://outside.example")', raw)  # script is sandboxed; CSP blocks its network access
        self.assertIn("connect-src &#39;none&#39;", raw)
        self.assertIn('url("#local-gradient")', raw)

    def test_media_signature_hash_and_owner_scope_are_required(self):
        c = sqlite3.connect(':memory:')
        c.row_factory = sqlite3.Row
        c.executescript(mission_flow.SCHEMA)
        c.execute('insert into mission_flows values(?,?,?,?,?,?,?,?,?,?,?)', ('f_'+'a'*24, 'owner', 2, 'Site', '', 'd', 'review', 1, 1, 1, ''))
        raw = b'\x89PNG\r\n\x1a\nimage bytes'
        digest = hashlib.sha256(raw).hexdigest()
        c.execute('insert into mission_artifacts values(?,?,?,?,?)', ('f_'+'a'*24, 1, 'MEDIA-1.png', digest, envelope('MEDIA-1.png', raw)))
        c.commit()
        mime, csp, content = preview.artifact_preview(c, {'id':'owner','generation':2,'role':'owner'}, {'mission':'f_'+'a'*24,'ordinal':1,'name':'MEDIA-1.png'}, require)
        self.assertEqual((mime, content), ('image/png', raw))
        self.assertIn('sandbox;', csp)
        with self.assertRaises(PermissionError):
            preview.artifact_preview(c, {'id':'other','generation':2,'role':'director'}, {'mission':'f_'+'a'*24,'ordinal':1,'name':'MEDIA-1.png'}, require)
        with self.assertRaises(PermissionError):
            preview.artifact_preview(c, {'id':'owner','generation':2,'role':'owner'}, {'mission':'f_'+'a'*24,'ordinal':1,'name':'../secret.png'}, require)
        c.close()

    def test_active_svg_and_unknown_types_are_never_rendered_as_media(self):
        content = preview.MEDIA_PREFIX + json.dumps({'mime':'image/svg+xml','size':8,'base64':base64.b64encode(b'<svg/>xx').decode()})
        self.assertIsNone(preview._media(content, 'MEDIA-1.svg', hashlib.sha256(b'<svg/>xx').hexdigest()))

    def test_svg_source_is_served_as_text_not_executed(self):
        c = sqlite3.connect(':memory:')
        c.row_factory = sqlite3.Row
        c.executescript(mission_flow.SCHEMA)
        mission = 'f_' + 'b' * 24
        c.execute('insert into mission_flows values(?,?,?,?,?,?,?,?,?,?,?)', (mission, 'owner', 1, 'Site', '', 'd', 'review', 1, 1, 1, ''))
        source = '<svg><script>alert(1)</script></svg>'
        c.execute('insert into mission_artifacts values(?,?,?,?,?)', (mission, 1, 'logo.svg', hashlib.sha256(source.encode()).hexdigest(), source))
        c.commit()
        mime, csp, content = preview.artifact_preview(c, {'id':'owner','generation':1,'role':'owner'}, {'mission':mission,'ordinal':1,'name':'logo.svg'}, require)
        self.assertEqual(mime, 'text/plain; charset=utf-8')
        self.assertEqual(content, source.encode())
        self.assertNotIn('allow-scripts', csp)
        c.close()


if __name__ == '__main__':
    unittest.main()
