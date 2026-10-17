"""Offline host-app composition and policy tests. Synthetic credential fixtures only.

No provider request, real credential file, production socket or deployment.
"""
from contextlib import closing
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from email.message import Message
import hashlib
import http.client
import importlib
import io
import json
import os
from pathlib import Path
import socketserver
import sqlite3
import stat
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
for folder in ("service", "provider", "narration", "baseline/source"):
    sys.path.insert(0, str(ROOT / folder))
with patch.object(socketserver, "UnixStreamServer", getattr(socketserver, "UnixStreamServer", socketserver.TCPServer), create=True):
    import viewer
    import viewer_v2
import catalog_resolver
import voice_coordinator
import voice_http
import voice_store
import voice_profiles
import voice_app as app

MID = "f_" + "a" * 24
OTHER = "f_" + "b" * 24
VOICE = "synthetic_voice_0123456789"
COMPONENTS = {"voice_http": voice_http, "voice_coordinator": voice_coordinator,
    "voice_profiles": voice_profiles,
    "catalog_resolver": catalog_resolver, "viewer": viewer}

def metadata(*, uid=0, gid=10001, mode=stat.S_IFREG | 0o440, size=10, nlink=1):
    return SimpleNamespace(st_uid=uid, st_gid=gid, st_mode=mode, st_size=size, st_nlink=nlink)

class FakeProvider:
    hard_deadline = True
    def generate(self, **arguments):
        raise AssertionError("These composition tests must not generate audio")

class FakeHandler:
    def __init__(self, cookie="owner-cookie", path=None):
        self.command, self.close_connection = "GET", False
        self.path = path or voice_http.BASE + "/status"
        self.headers = Message()
        self.headers["Cookie"] = cookie
        self.headers["Sec-Fetch-Site"] = "same-origin"
        self.rfile = io.BytesIO()
        self.response = None
    def send(self, status, value, mime=None):
        self.response = (status, value, mime)

class AppTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.now = datetime.now(timezone.utc)
        self.data = {"schema": "awema-danse-voice-app-v1", "enabled": True,
            "commercial_license_confirmed": True, "issued_at": self.now.timestamp() - 10,
            "expires_at": self.now.timestamp() + 3600, "monthly_character_budget": 1000,
            "model_id": "eleven_multilingual_v2", "role_voices": {"system": VOICE, "qa": VOICE},
            "source_pins": {key: "a" * 64 for key in app.SOURCE_NAMES}}
        self.config = self.parse()
        self.db = Path(self.tmp.name) / "projection.sqlite"
        with closing(sqlite3.connect(self.db)) as connection, connection:
            connection.executescript("""
                CREATE TABLE meta(id INTEGER PRIMARY KEY,schema TEXT,observed_at REAL);
                CREATE TABLE missions(id TEXT PRIMARY KEY,owner_id TEXT,objective_sanitized TEXT,state TEXT,created REAL,updated REAL,event_count INTEGER,artifact_count INTEGER);
                CREATE TABLE events(mission_id TEXT,id INTEGER,agent TEXT,kind TEXT,summary TEXT,created REAL,source_event_sha256 TEXT,PRIMARY KEY(mission_id,id));
            """)
            connection.execute("INSERT INTO meta VALUES(1,?,?)", ("awema-agent-standup-catalog-v2", self.now.timestamp()))
            for mission, owner in ((MID, "director-a"), (OTHER, "director-b")):
                connection.execute("INSERT INTO missions VALUES(?,?,?,?,?,?,?,?)", (mission, owner, "Mission synthétique", "review", self.now.timestamp()-50, self.now.timestamp()-1, 1, 0))
                connection.execute("INSERT INTO events VALUES(?,?,?,?,?,?,?)", (mission, 52, "qa", "qa_completed", "UNTRUSTED SUMMARY", self.now.timestamp()-1, hashlib.sha256(b"qa_completed").hexdigest()))
        if os.name == "posix":
            if os.geteuid() != 0:
                # Actual Catalog requires root-owned fixture; other tests remain meaningful.
                self.catalog_supported = False
            else:
                os.chown(self.db, 0, 10001)
                os.chmod(self.db, 0o640)
                self.catalog_supported = True
        else:
            self.catalog_supported = True
    def tearDown(self):
        self.tmp.cleanup()
    def parse(self, **changes):
        return app.parse_config(json.dumps({**self.data, **changes}).encode(), now=self.now.timestamp())
    def factory(self, user):
        return viewer_v2.Catalog(user, path=self.db)
    def build(self, config=None, *, providers=None):
        def provider_builder():
            value = FakeProvider()
            if providers is not None:
                providers.append(value)
            return value
        return app.build_voice_http(config or self.config, components=COMPONENTS,
            key_loader=lambda: (_ for _ in ()).throw(AssertionError("no real credential read")),
            provider_builder=provider_builder, catalog_factory=self.factory, clock=lambda: self.now)
    def test_strict_config_and_static_budget_model(self):
        for changes in ({"monthly_character_budget": 0}, {"monthly_character_budget": 2500},
                        {"monthly_character_budget": 1001}, {"monthly_character_budget": True},
                        {"model_id": "unapproved-model"}, {"extra": "field"}, {"enabled": 1},
                        {"role_voices": {"invented-role": VOICE}}, {"role_voices": {"system": "../voice"}}):
            with self.subTest(changes=changes), self.assertRaisesRegex(app.AppError, "^invalid_voice_configuration$"):
                self.parse(**changes)
    def test_approved_budget_allowlist_is_preserved_to_coordinator(self):
        session = voice_http.AuthenticatedVoiceSession("owner", "owner", "a"*64)
        for budget in (1000, 10000):
            with self.subTest(budget=budget):
                config = self.parse(monthly_character_budget=budget)
                self.assertEqual(config.monthly_character_budget, budget)
                api = self.build(config)
                coordinator = api.coordinator_factory(caller="owner", reauthenticate=lambda: session, generation_binding="a"*64)
                self.assertEqual(coordinator.policy.monthly_character_budget, budget)
    def test_exact_seven_day_absolute_pilot_no_restart_extension(self):
        beginning = self.now.timestamp() - 100
        config = self.parse(issued_at=beginning, expires_at=beginning+7*86400)
        self.assertEqual(config.expires_at, beginning+7*86400)
        for expiry in (beginning+7*86400+1, beginning, float("inf"), float("nan")):
            with self.subTest(expiry=expiry), self.assertRaises(app.AppError):
                self.parse(issued_at=beginning, expires_at=expiry)
    def test_duplicate_config_and_missing_source_pin_denied(self):
        raw = json.dumps(self.data).encode()
        duplicate = raw[:-1] + b',"enabled":false}'
        with self.assertRaises(app.AppError):
            app.parse_config(duplicate, now=self.now.timestamp())
        pins = dict(self.data["source_pins"])
        pins.pop("service/voice_app.py")
        with self.assertRaises(app.AppError):
            self.parse(source_pins=pins)
    def test_config_root_owner_group_and_mode_enforced(self):
        app._check_metadata(metadata(), owner_uid=0, group_gid=10001, mode=0o440)
        bad = (metadata(uid=31551), metadata(gid=0), metadata(mode=stat.S_IFREG|0o640),
               metadata(mode=stat.S_IFLNK|0o440), metadata(nlink=2), metadata(size=999999))
        for info in bad:
            with self.subTest(info=info), self.assertRaises(app.AppError):
                app._check_metadata(info, owner_uid=0, group_gid=10001, mode=0o440)
    def test_load_config_only_reads_required_protected_path(self):
        with patch("voice_app._read_protected", return_value=json.dumps(self.data).encode()) as reader:
            result = app.load_config(Path("/operator/config.json"))
        self.assertEqual(result.monthly_character_budget, 1000)
        reader.assert_called_once_with(Path("/operator/config.json"), owner_uid=0, group_gid=10001, mode=0o440, maximum=16384)
    def test_immutable_source_mismatch_before_any_import_or_key(self):
        with patch("voice_app._read_protected", return_value=b"wrong source"), patch("voice_app.importlib.import_module") as importer:
            with self.assertRaisesRegex(app.AppError, "^voice_source_integrity_failed$"):
                app.load_components(self.config)
        importer.assert_not_called()
    def test_no_credentials_when_disabled_unlicensed_or_expired(self):
        for config in (replace(self.config, enabled=False), replace(self.config, commercial_license_confirmed=False),
                       replace(self.config, expires_at=self.now.timestamp()-1)):
            with self.subTest(config=config):
                key = lambda: (_ for _ in ()).throw(AssertionError("credential read forbidden"))
                api = app.build_voice_http(config, components=COMPONENTS, key_loader=key, catalog_factory=self.factory, clock=lambda: self.now)
                self.assertIsNotNone(api.coordinator_factory)
    def test_factory_distinct_request_contexts_no_session_bleed(self):
        if not self.catalog_supported:
            self.skipTest("Catalog requires root-owned POSIX fixtures")
        api = self.build()
        owner = voice_http.AuthenticatedVoiceSession("owner", "owner", "a"*64)
        director = voice_http.AuthenticatedVoiceSession("director-a", "director", "b"*64)
        one = api.coordinator_factory(caller=owner.user, reauthenticate=lambda: owner, generation_binding=owner.generation)
        two = api.coordinator_factory(caller=director.user, reauthenticate=lambda: director, generation_binding=director.generation)
        self.assertIsNot(one, two)
        self.assertIsNot(one.resolver, two.resolver)
        self.assertEqual(one.narration(caller="owner", mission_id=OTHER, event_id=52)["voice_role"], "system")
        self.assertEqual(two.narration(caller="director-a", mission_id=MID, event_id=52)["voice_role"], "system")
        with self.assertRaises(Exception):
            two.narration(caller="director-a", mission_id=OTHER, event_id=52)
        self.assertEqual(one.narration(caller="owner", mission_id=OTHER, event_id=52)["voice_role"], "system")
    def test_request_session_revoked_after_factory_is_denied(self):
        if not self.catalog_supported:
            self.skipTest("Catalog requires root-owned POSIX fixtures")
        api = self.build()
        current = [voice_http.AuthenticatedVoiceSession("owner", "owner", "a"*64)]
        value = api.coordinator_factory(caller="owner", reauthenticate=lambda: current[0], generation_binding="a"*64)
        self.assertTrue(value.profile_identity(caller="owner", role="qa")["available"])
        self.assertFalse(value.profile_identity(caller="another", role="qa")["available"])
        current[0] = replace(current[0], generation="b"*64)
        self.assertFalse(value.profile_identity(caller="owner", role="qa")["available"])
        with self.assertRaises(Exception):
            value.narration(caller="owner", mission_id=MID, event_id=52)
    def test_factory_requires_matching_authoritative_session(self):
        api = self.build()
        session = voice_http.AuthenticatedVoiceSession("owner", "owner", "a"*64)
        for caller, generation in (("another", "a"*64), ("owner", "b"*64)):
            with self.assertRaisesRegex(app.AppError, "^voice_session_changed$"):
                api.coordinator_factory(caller=caller, reauthenticate=lambda: session, generation_binding=generation)
    def test_per_request_new_provider_transient_budget(self):
        providers = []
        api = self.build(providers=providers)
        session = voice_http.AuthenticatedVoiceSession("owner", "owner", "a"*64)
        for _ in range(2):
            api.coordinator_factory(caller="owner", reauthenticate=lambda: session, generation_binding="a"*64)
        self.assertEqual(len(providers), 2)
        self.assertIsNot(providers[0], providers[1])
    def test_profile_identity_does_not_read_or_mutate_missions(self):
        api = self.build()
        session = voice_http.AuthenticatedVoiceSession("owner", "owner", "a"*64)
        value = api.coordinator_factory(caller="owner", reauthenticate=lambda: session, generation_binding="a"*64)
        before = self.db.read_bytes()
        with patch.object(value.resolver, "_catalog_factory", side_effect=AssertionError("No mission lookup for profile identity")):
            result = value.profile_identity(caller="owner", role="qa")
        self.assertTrue(result["available"], result)
        self.assertEqual(result["purpose"], "voice_profile_test")
        self.assertEqual(self.db.read_bytes(), before)
    def test_http_factory_wired_and_auth_per_request(self):
        api = self.build()
        users = {"owner-cookie": {"user": "owner", "role": "owner"}, "director-cookie": {"user": "director-a", "role": "director"}}
        with patch.object(api, "authenticate", side_effect=lambda cookie: users[cookie]):
            for cookie in users:
                handler = FakeHandler(cookie)
                api.handle(handler)
                self.assertEqual(handler.response[0], 200)
                self.assertTrue(handler.response[1]["available"])
                self.assertIn("csrf_token", handler.response[1])
    def test_runtime_requires_fixed_nonroot_uid_gid(self):
        with patch("voice_app.os.name", "posix"), patch.object(app.os, "geteuid", return_value=0, create=True), patch.object(app.os, "getegid", return_value=10001, create=True):
            with self.assertRaisesRegex(app.AppError, "^dedicated_nonroot_voice_identity_required$"):
                app.validate_runtime()
    def test_credential_loaded_only_from_systemd_memory_copy(self):
        # Metadata and read are synthetic; no real credential is created/read.
        directory = Path(self.tmp.name) / "credentials"
        def fake_stat(path):
            if path == directory:
                return metadata(uid=31551, mode=stat.S_IFDIR | 0o700)
            return metadata(uid=31551, mode=stat.S_IFREG | 0o400, size=30)
        synthetic = b"synthetic_key_TEST_ONLY_0123456789"
        with patch.dict(os.environ, {"CREDENTIALS_DIRECTORY": str(directory)}, clear=True), \
             patch.object(app.os, "geteuid", return_value=31551, create=True), \
             patch.object(Path, "lstat", fake_stat), \
             patch("voice_app._read_protected", return_value=synthetic) as reader:
            self.assertEqual(app.load_credential(), synthetic.decode())
        reader.assert_called_once_with(directory / "elevenlabs.key", owner_uid=31551, mode=0o400, maximum=512, ancestors=False)
    def test_credential_errors_never_echo_secret(self):
        directory = Path(self.tmp.name) / "credentials"
        def fake_stat(path):
            if path == directory:
                return metadata(uid=31551, mode=stat.S_IFDIR | 0o700)
            return metadata(uid=31551, mode=stat.S_IFREG | 0o400, size=30)
        with patch.dict(os.environ, {"CREDENTIALS_DIRECTORY": str(directory)}, clear=True), \
             patch.object(app.os, "geteuid", return_value=31551, create=True), \
             patch.object(Path, "lstat", fake_stat), \
             patch("voice_app._read_protected", side_effect=RuntimeError("synthetic secret never expose")):
            with self.assertRaisesRegex(app.AppError, "^voice_credential_unavailable$"):
                app.load_credential()
    def test_fixed_paths_have_no_client_or_policy_override(self):
        self.assertEqual(app.RUN_UID, 31551)
        self.assertEqual(app.RUN_GID, 10001)
        self.assertEqual(str(app.AUTH_SOCKET_PATH), "/opt/awema-danse-voice-inputs/auth/finance.sock")
        self.assertEqual(str(app.PROJECTION_PATH).replace("\\", "/"), "/opt/awema-danse-voice-inputs/projection/projection.sqlite")
        self.assertEqual(str(app.SOCKET_PATH).replace("\\", "/"), "/run/awema-danse-voice/endpoint/voice.sock")
        with self.assertRaises(app.AppError):
            self.parse(auth_socket="/tmp/injected.sock")
    def test_handler_private_headers_and_voice_routes_only(self):
        api = SimpleNamespace(matches=lambda path: path.startswith(voice_http.BASE), handle=lambda handler: handler.send(200, {"available": False}))
        Handler = app.make_handler(api)
        class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
            daemon_threads = True
            allow_reuse_address = True
        with Server(("127.0.0.1", 0), Handler) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                for path, status in ((voice_http.BASE+"/status", 200), ("/finance/api/session", 404)):
                    connection = http.client.HTTPConnection(*server.server_address, timeout=3)
                    connection.request("GET", path)
                    response = connection.getresponse()
                    response.read()
                    self.assertEqual(response.status, status)
                    self.assertEqual(response.getheader("Cache-Control"), "private, no-store")
                    self.assertEqual(response.getheader("Vary"), "Cookie")
                    self.assertEqual(response.getheader("X-Content-Type-Options"), "nosniff")
                    self.assertIn("default-src 'none'", response.getheader("Content-Security-Policy"))
                    connection.close()
            finally:
                server.shutdown()
                thread.join(timeout=3)

if __name__ == "__main__":
    unittest.main()
