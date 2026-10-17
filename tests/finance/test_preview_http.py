"""Exercise the real HTTP handler and Store authentication with an isolated database."""
import hashlib
import http.client
import json
import secrets
import tempfile
import threading
import time
import unittest
from http.server import HTTPServer
from pathlib import Path
from urllib.parse import urlencode

import portal

MISSION = 'f_' + 'a' * 24


class PreviewHTTPTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = portal.Store(Path(self.tmp.name) / 'fixture.sqlite', mfa_required=False)
        self.token = secrets.token_urlsafe(32)
        with self.store.connect() as c:
            c.execute('insert into users values(?,?,?,?,?,?,?,?,?,?)',
                      ('fixture-owner', 'Fixture', 'owner', 1, 1, 'disabled', None, 0, 'cto', '{}'))
            c.execute('insert into sessions values(?,?,?,?,?)',
                      (hashlib.sha256(self.token.encode()).hexdigest(), 'fixture-owner', 1, 'fixture', time.time() + 60))
            c.execute('insert into mission_flows values(?,?,?,?,?,?,?,?,?,?,?)',
                      (MISSION, 'fixture-owner', 1, 'Test site', '', 'fixture', 'review', 1, 1, 1, ''))
            for name, content in {
                'index.html': '<html lang="fr"><head><link rel="stylesheet" href="styles.css"><script src="app.js" defer></script></head><body><h1>Site de test</h1></body></html>',
                'styles.css': 'body{color:#fff;background:#111}',
                'app.js': 'document.documentElement.dataset.ready="yes";'
            }.items():
                c.execute('insert into mission_artifacts values(?,?,?,?,?)',
                          (MISSION, 1, name, hashlib.sha256(content.encode()).hexdigest(), content))
        self.server = HTTPServer(('127.0.0.1', 0), portal.Handler)
        self.server.store = self.store
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={'poll_interval': .01}, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.tmp.cleanup()

    def get(self, name='__site__', headers=None, auth=True, query=None):
        h = {'Sec-Fetch-Site': 'same-origin', 'Sec-Fetch-Mode': 'navigate', 'Sec-Fetch-Dest': 'document'}
        if auth:
            h['Cookie'] = portal.COOKIE + '=' + self.token
        h.update(headers or {})
        target = '/finance/mission-preview?' + (query if query is not None else urlencode({'mission': MISSION, 'ordinal': 1, 'name': name}))
        conn = http.client.HTTPConnection(*self.server.server_address, timeout=5)
        try:
            conn.request('GET', target, headers=h)
            r = conn.getresponse()
            return r.status, dict(r.getheaders()), r.read()
        finally:
            conn.close()

    def test_authenticated_http_renders_real_sqlite_user_row(self):
        with self.store.connect() as c:
            self.assertEqual(type(self.store.authenticate(c, self.token)).__name__, 'Row')
        status, headers, body = self.get()
        self.assertEqual(status, 200, body)
        self.assertEqual(headers['Content-Type'], 'text/html; charset=utf-8')
        self.assertEqual(int(headers['Content-Length']), len(body))
        self.assertIn(b'<h1>Site de test</h1>', body)
        self.assertIn(b'dataset.ready=', body)
        self.assertIn("connect-src 'none'", headers['Content-Security-Policy'])
        self.assertIn('sandbox allow-scripts', headers['Content-Security-Policy'])
        self.assertEqual(headers['Cache-Control'], 'private, no-store')
        self.assertEqual(headers['Cross-Origin-Resource-Policy'], 'same-origin')

    def test_readable_site_alias_matches_existing_link(self):
        first = self.get('__site__')
        second = self.get('site')
        self.assertEqual((first[0], second[0]), (200, 200))
        self.assertEqual(first[2], second[2])

    def test_address_bar_navigation_is_allowed(self):
        status, _, body = self.get('site', headers={'Sec-Fetch-Site': 'none'})
        self.assertEqual(status, 200, body)

    def test_cross_site_frame_and_subresource_are_denied(self):
        for site, mode, dest in [('cross-site', 'navigate', 'iframe'), ('cross-site', 'cors', 'empty'), ('none', 'no-cors', 'image')]:
            with self.subTest(site=site, mode=mode, dest=dest):
                status, _, body = self.get(headers={'Sec-Fetch-Site': site, 'Sec-Fetch-Mode': mode, 'Sec-Fetch-Dest': dest})
                self.assertEqual(status, 403, body)

    def test_anonymous_preview_is_not_public(self):
        status, _, body = self.get(auth=False)
        self.assertEqual((status, json.loads(body)['error']), (401, 'authentication_required'))

    def test_expired_session_cannot_preview(self):
        with self.store.connect() as c:
            c.execute('update sessions set expires=0')
        self.assertEqual(self.get()[0], 401)

    def test_revoked_generation_cannot_preview(self):
        with self.store.connect() as c:
            c.execute('update users set generation=2')
        self.assertEqual(self.get()[0], 401)

    def test_reader_cannot_preview(self):
        with self.store.connect() as c:
            c.execute("update users set role='reader'")
        self.assertEqual(self.get()[0], 403)

    def test_director_cannot_preview_another_users_mission(self):
        with self.store.connect() as c:
            c.execute("update users set role='director'")
            c.execute("update mission_flows set user='another-user'")
        self.assertEqual(self.get()[0], 404)

    def test_owner_can_preview_other_users_mission(self):
        with self.store.connect() as c:
            c.execute("update mission_flows set user='another-user'")
        self.assertEqual(self.get()[0], 200)

    def test_invalid_queries_are_client_errors(self):
        for query in [f'mission={MISSION}&ordinal=1&name=site&name=site', f'mission={MISSION}&ordinal=9&name=site', 'broken', f'mission={MISSION}&ordinal=1']:
            with self.subTest(query=query):
                self.assertEqual(self.get(query=query)[0], 400)
        for name in ['', '../secret', 'unknown.html']:
            with self.subTest(name=name):
                self.assertEqual(self.get(name)[0], 404)

    def test_preview_does_not_modify_mission_or_artifacts(self):
        with self.store.connect() as c:
            before = list(c.iterdump())
        self.assertEqual(self.get()[0], 200)
        with self.store.connect() as c:
            self.assertEqual(list(c.iterdump()), before)


if __name__ == '__main__':
    unittest.main()
