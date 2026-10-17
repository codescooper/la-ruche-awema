"""Per-request factory and two-session concurrent real Catalog fixtures, offline only."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import socketserver
import sqlite3
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from voice_http import AuthenticatedVoiceSession, BASE, HTTPError, VoiceHTTP
from test_voice_http import Handler, Coordinator, ORIGIN

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "narration"))
sys.path.insert(0, str(ROOT / "baseline" / "source"))
with patch.object(socketserver, "UnixStreamServer", getattr(socketserver, "UnixStreamServer", socketserver.TCPServer), create=True):
    from viewer_v2 import Catalog
from catalog_resolver import CatalogResolver, SessionIdentity
from voice_coordinator import Policy, VoiceCoordinator
from test_voice_coordinator import audio_fixture

MISSION_A = "f_" + "a" * 24
MISSION_B = "f_" + "b" * 24
VOICE = "synthetic_voice_0123456789"


class FactoryContractTests(unittest.TestCase):
    def test_constructor_accepts_one_explicit_strategy(self):
        for arguments in [{}, {"coordinator": Coordinator(), "coordinator_factory": lambda **k: None}, {"coordinator_factory": 42}]:
            with self.assertRaisesRegex(ValueError, "one_coordinator_or_factory_required"):
                VoiceHTTP(**arguments)
        self.assertIsNotNone(VoiceHTTP(Coordinator()))

    def test_factory_receives_only_server_identity_and_reauth_callback(self):
        seen = []
        auth = {"user": "owner-1", "role": "owner", "ignored_private_field": "never-export"}
        def factory(**kwargs):
            seen.append(kwargs)
            current = kwargs["reauthenticate"]()
            self.assertIs(type(current), AuthenticatedVoiceSession)
            self.assertEqual(current.user, kwargs["caller"])
            self.assertEqual(current.role, "owner")
            self.assertEqual(current.generation, kwargs["generation_binding"])
            with self.assertRaises(FrozenInstanceError):
                current.role = "director"
            return Coordinator()
        api = VoiceHTTP(coordinator_factory=factory, authenticate=lambda cookie: dict(auth), csrf_key=b"s" * 32)
        h = Handler(BASE + "/status", cookie="session=factory")
        api.handle(h)
        self.assertEqual(h.response[0], 200)
        self.assertEqual(set(seen[0]), {"caller", "reauthenticate", "generation_binding"})
        self.assertRegex(seen[0]["generation_binding"], "^[a-f0-9]{64}$")
        self.assertNotIn("session=factory", repr(seen[0]))
        self.assertNotIn("never-export", json.dumps(h.response))
        self.assertIsNone(api.coordinator)

    def test_reauth_callback_cannot_be_rebound_by_a_later_request(self):
        callbacks = {}
        def auth(cookie):
            return {"user": "a" if cookie == "session=a" else "b", "role": "owner" if cookie == "session=a" else "director"}
        def factory(**kwargs):
            callbacks[kwargs["caller"]] = kwargs["reauthenticate"]
            return Coordinator()
        api = VoiceHTTP(coordinator_factory=factory, authenticate=auth)
        api.handle(Handler(BASE + "/status", cookie="session=a"))
        api.handle(Handler(BASE + "/status", cookie="session=b"))
        self.assertEqual(callbacks["a"]().user, "a")
        self.assertEqual(callbacks["a"]().role, "owner")
        self.assertEqual(callbacks["b"]().user, "b")
        self.assertEqual(callbacks["b"]().role, "director")
        self.assertNotEqual(callbacks["a"]().generation, callbacks["b"]().generation)

    def test_callback_refuses_same_user_role_change_and_revocation(self):
        current = {"user": "a", "role": "owner"}
        saved = []
        def factory(**kwargs):
            saved.append(kwargs["reauthenticate"])
            return Coordinator()
        api = VoiceHTTP(coordinator_factory=factory, authenticate=lambda cookie: dict(current))
        api.handle(Handler(BASE + "/status"))
        current["role"] = "director"
        with self.assertRaises(HTTPError):
            saved[0]()
        current["role"] = "reader"
        with self.assertRaises(HTTPError):
            saved[0]()

    def test_factory_errors_and_incomplete_objects_fail_without_leaking_details(self):
        def fail(**kwargs):
            raise RuntimeError("SECRET factory configuration")
        for factory in [fail, lambda **kwargs: object()]:
            api = VoiceHTTP(coordinator_factory=factory, authenticate=lambda cookie: {"user": "a", "role": "owner"})
            h = Handler(BASE + "/status"); api.handle(h)
            self.assertEqual(h.response[0], 503)
            self.assertNotIn("SECRET", json.dumps(h.response))


class ConcurrentCatalogFactoryTests(unittest.TestCase):
    def setUp(self):
        if os.name == "posix" and os.geteuid() != 0:
            self.skipTest("The real Catalog POSIX fixture requires operator-owned permissions")
        self.tmp = tempfile.TemporaryDirectory(prefix="awema-voice-factory-")
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "projection.sqlite"
        self.store = Path(self.tmp.name) / "private-voice"
        self.now = time.time()
        self.sessions = {
            "session=owner": {"user": "owner-01", "role": "owner"},
            "session=director": {"user": "director-02", "role": "director"},
        }
        self.lock = threading.Lock()
        self.factory_objects, self.factory_identities, self.provider_calls = [], [], []
        self.barrier = None
        with closing(sqlite3.connect(self.path)) as conn, conn:
            conn.executescript("""
                CREATE TABLE meta(id INTEGER PRIMARY KEY,schema TEXT,observed_at REAL);
                CREATE TABLE missions(id TEXT PRIMARY KEY,owner_id TEXT,objective_sanitized TEXT,state TEXT,created REAL,updated REAL,event_count INTEGER,artifact_count INTEGER);
                CREATE TABLE events(mission_id TEXT,id INTEGER,agent TEXT,kind TEXT,summary TEXT,created REAL,source_event_sha256 TEXT,PRIMARY KEY(mission_id,id));
            """)
            conn.execute("INSERT INTO meta VALUES(1,?,?)", ("awema-agent-standup-catalog-v2", self.now))
            for mid, owner, event, role, kind in [(MISSION_A, "director-01", 7, "qa", "qa_completed"),
                                                  (MISSION_B, "director-02", 8, "dev", "dev_completed")]:
                conn.execute("INSERT INTO missions VALUES(?,?,?,?,?,?,?,?)", (mid, owner, "Mission", "review", self.now - 30, self.now - 2, 1, 0))
                conn.execute("INSERT INTO events VALUES(?,?,?,?,?,?,?)", (mid, event, role, kind, "UNTRUSTED SUMMARY", self.now - 2,
                                                                            hashlib.sha256(kind.encode()).hexdigest()))
        if os.name == "posix":
            os.chown(self.path, 0, 10001); os.chmod(self.path, 0o640)
        self.policy = Policy(enabled=True, commercial_license_confirmed=True, expires_at=self.now + 3600,
                             monthly_character_budget=10000, role_voices=(("system", VOICE),))
        self.api = VoiceHTTP(coordinator_factory=self.factory, authenticate=self.authenticate,
                             clock=lambda: self.now, csrf_key=b"f" * 32)

    def authenticate(self, cookie):
        with self.lock:
            value = self.sessions.get(cookie)
            if value is None:
                class Revoked(Exception):
                    code = 401
                raise Revoked("private auth failure")
            return dict(value)

    def factory(self, *, caller, reauthenticate, generation_binding):
        fresh = reauthenticate()
        self.assertEqual(fresh.user, caller)
        self.assertEqual(fresh.generation, generation_binding)
        session = SessionIdentity(fresh.user, fresh.role, generation_binding)
        def current():
            checked = reauthenticate()
            return SessionIdentity(checked.user, checked.role, checked.generation)
        resolver = CatalogResolver(session, reauthenticate=current,
                                   catalog_factory=lambda user: Catalog(user, path=self.path), clock=lambda: self.now)
        parent = self
        class Provider:
            hard_deadline = True
            def generate(inner, **kwargs):
                with parent.lock:
                    parent.provider_calls.append((caller, session.role, kwargs))
                if parent.barrier is not None:
                    parent.barrier.wait(timeout=5)
                class Result:
                    audio = audio_fixture()
                    mime = "audio/mpeg"
                return Result()
        coordinator = VoiceCoordinator(policy=self.policy, resolver=resolver, store_root=self.store,
                                       provider=Provider(), clock=lambda: datetime.fromtimestamp(self.now, timezone.utc))
        with self.lock:
            self.factory_objects.append(coordinator)
            self.factory_identities.append(session)
        return coordinator

    def request(self, path, *, cookie, method="GET", body=b"", headers=None):
        h = Handler(path, method, cookie=cookie, body=body, headers=headers)
        self.api.handle(h)
        return h.response

    def token(self, cookie):
        result = self.request(BASE + "/status", cookie=cookie)
        self.assertEqual(result[0], 200, result)
        return result[1]["csrf_token"]

    def generate(self, cookie, mission, event, token):
        body = json.dumps({"mission_id": mission, "event_id": event}).encode()
        return self.request(BASE + "/generate", cookie=cookie, method="POST", body=body,
                            headers={"Origin": ORIGIN, "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": token,
                                     "X-AWEMA-Voice-Consent": "true", "Content-Type": "application/json", "Content-Length": str(len(body))})

    def test_two_concurrent_real_catalog_sessions_never_cross_roles_missions_or_handles(self):
        owner_cookie, director_cookie = "session=owner", "session=director"
        tokens = {cookie: self.token(cookie) for cookie in (owner_cookie, director_cookie)}
        self.barrier = threading.Barrier(2)
        with ThreadPoolExecutor(max_workers=2) as pool:
            owner_future = pool.submit(self.generate, owner_cookie, MISSION_A, 7, tokens[owner_cookie])
            director_future = pool.submit(self.generate, director_cookie, MISSION_B, 8, tokens[director_cookie])
            owner, director = owner_future.result(timeout=8), director_future.result(timeout=8)
        self.barrier = None
        self.assertEqual(owner[0], 200, owner); self.assertEqual(director[0], 200, director)
        self.assertEqual(owner[1]["mission_id"], MISSION_A); self.assertEqual(director[1]["mission_id"], MISSION_B)
        self.assertNotEqual(owner[1]["narration_sha256"], director[1]["narration_sha256"])
        self.assertEqual({(caller, role) for caller, role, _ in self.provider_calls}, {("owner-01", "owner"), ("director-02", "director")})
        self.assertEqual(len({item[2]["operation_id"] for item in self.provider_calls}), 2)
        self.assertIsNone(self.api.coordinator)
        self.assertEqual(len({id(c) for c in self.factory_objects}), len(self.factory_objects))
        owner_url, director_url = owner[1]["audio"]["url"], director[1]["audio"]["url"]
        self.assertEqual(self.request(owner_url, cookie=owner_cookie)[0], 200)
        self.assertEqual(self.request(director_url, cookie=director_cookie)[0], 200)
        self.assertEqual(self.request(owner_url, cookie=director_cookie)[0], 404)
        self.assertEqual(self.request(director_url, cookie=owner_cookie)[0], 404)
        self.assertEqual(self.generate(director_cookie, MISSION_A, 7, tokens[director_cookie])[0], 403)
        self.assertEqual(len(self.provider_calls), 2)
        # A newly constructed resolver/coordinator still reuses the same durable operation/cache.
        replay = self.generate(director_cookie, MISSION_B, 8, tokens[director_cookie])
        self.assertEqual(replay[0], 200, replay); self.assertTrue(replay[1]["cached"])
        self.assertEqual(replay[1]["audio"], director[1]["audio"])
        self.assertEqual(len(self.provider_calls), 2)

    def test_audio_get_new_factory_rechecks_real_catalog_acl_replacement(self):
        cookie = "session=director"
        result = self.generate(cookie, MISSION_B, 8, self.token(cookie))
        self.assertEqual(result[0], 200, result)
        with closing(sqlite3.connect(self.path)) as conn, conn:
            conn.execute("UPDATE missions SET owner_id='other-director' WHERE id=?", (MISSION_B,))
        if os.name == "posix":
            os.chown(self.path, 0, 10001); os.chmod(self.path, 0o640)
        self.assertEqual(self.request(result[1]["audio"]["url"], cookie=cookie)[0], 403)
        self.assertEqual(len(self.provider_calls), 1)

    def test_audio_handle_cannot_survive_session_revocation_or_role_change(self):
        cookie = "session=director"
        result = self.generate(cookie, MISSION_B, 8, self.token(cookie))
        self.assertEqual(result[0], 200, result)
        with self.lock:
            self.sessions[cookie]["role"] = "reader"
        self.assertEqual(self.request(result[1]["audio"]["url"], cookie=cookie)[0], 403)
        with self.lock:
            del self.sessions[cookie]
        self.assertEqual(self.request(result[1]["audio"]["url"], cookie=cookie)[0], 401)


if __name__ == "__main__":
    unittest.main()
