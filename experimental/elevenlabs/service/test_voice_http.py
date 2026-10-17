"""In-memory HTTP-handler tests. No listener, provider request, account or production IO."""
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from email.message import Message
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

from voice_http import BASE, EphemeralAudio, VoiceHTTP, VoiceHTTPMixin

MISSION = "f_" + "a" * 24
OTHER = "f_" + "b" * 24
ORIGIN = "https://laruche.awema.cloud"
AUDIO = b"fixture-private-audio"
SHA = hashlib.sha256(AUDIO).hexdigest()


class Coordinator:
    def __init__(self):
        self.enabled, self.allowed, self.fail, self.changed = True, True, False, False
        self.calls, self.provider_calls, self.narration_calls = [], 0, []
        self._cached = False
        self.after = None

    def status(self):
        # Deliberately include private fields: status handler must allowlist its output.
        return {"available": self.enabled, "provider": "elevenlabs", "provider_key": "never-export",
                "voice_ids": ["private-voice"], "reason": "raw-private-detail"}

    def narration(self, *, caller, mission_id, event_id):
        self.narration_calls.append((caller, mission_id, event_id))
        if not self.allowed or mission_id != MISSION or event_id != 7:
            raise ValueError("sensitive exception detail")
        text = "Le dossier a été créé."
        return {"available": True, "mission_id": mission_id, "event_id": event_id, "text": text,
                "text_sha256": hashlib.sha256(text.encode()).hexdigest(),
                "narration_sha256": ("d" if self.changed else "c") * 64,
                "voice_role": "system", "authorization_scope": "private-owner-v1",
                "provenance": {"kind": "system_milestone", "attested": False, "role": "system",
                               "source_event_sha256": "e" * 64}}

    def generate(self, **kwargs):
        self.calls.append(kwargs)
        if self.fail:
            return {"available": False, "reason": "provider body never exported"}
        reused = self._cached
        if not reused:
            self.provider_calls += 1
            self._cached = True
        if self.after:
            self.after()
        return {"available": True, "mission_id": kwargs["mission_id"], "event_id": kwargs["event_id"],
                "narration_sha256": "c" * 64, "voice_role": "system", "audio": AUDIO, "mime": "audio/mpeg",
                "audio_sha256": SHA, "cache_reused": reused}


class Handler:
    def __init__(self, path, method="GET", *, cookie="session=owner", headers=None, body=b""):
        self.path, self.command, self.close_connection = path, method, False
        self.headers = Message()
        if cookie is not None:
            self.headers["Cookie"] = cookie
        for key, value in (headers or {}).items():
            self.headers[key] = value
        self.rfile = io.BytesIO(body)
        self.response = None

    def send(self, code, body, mime="application/json; charset=utf-8"):
        # Real viewer's send supplies private/no-store, Vary:Cookie, CSP and no-microphone headers.
        self.response = (code, body, mime)


class HTTPTests(unittest.TestCase):
    def setUp(self):
        self.now = 1792212000.0
        self.c = Coordinator()
        self.auth_calls = []
        self.role = "owner"
        self.auth_revoked = False
        self.api = VoiceHTTP(self.c, authenticate=self.authenticate, clock=lambda: self.now, csrf_key=b"x" * 32)

    def authenticate(self, cookie):
        self.auth_calls.append(cookie)
        if cookie == "session=expired" or self.auth_revoked:
            class Expired(Exception):
                code = 401
            raise Expired("private auth error")
        return {"user": "owner" if cookie != "session=other-user" else "director-2", "role": self.role}

    def req(self, path, method="GET", **kwargs):
        h = Handler(path, method, **kwargs)
        self.api.handle(h)
        return h

    def csrf(self, cookie="session=owner"):
        h = self.req(BASE + "/status", cookie=cookie)
        self.assertEqual(h.response[0], 200, h.response)
        return h.response[1]["csrf_token"]

    def post(self, *, payload=None, raw=None, cookie="session=owner", headers=None, token=None):
        body = raw if raw is not None else json.dumps(payload or {"mission_id": MISSION, "event_id": 7}).encode()
        base = {"Origin": ORIGIN, "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": token or self.csrf(cookie),
                "X-AWEMA-Voice-Consent": "true", "Content-Type": "application/json", "Content-Length": str(len(body))}
        base.update(headers or {})
        return self.req(BASE + "/generate", "POST", cookie=cookie, headers=base, body=body)

    def generated(self):
        h = self.post()
        self.assertEqual(h.response[0], 200, h.response)
        return h.response[1]

    def test_disabled_status_has_no_csrf_no_private_fields(self):
        self.c.enabled = False
        h = self.req(BASE + "/status")
        self.assertFalse(h.response[1]["available"])
        self.assertNotIn("csrf_token", h.response[1])
        self.assertNotIn("never-export", json.dumps(h.response))
        self.assertEqual(self.c.provider_calls, 0)

    def test_explicit_coordinator_default_status_is_disabled(self):
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "narration"))
        from voice_coordinator import VoiceCoordinator
        c = VoiceCoordinator(resolver=object(), store_root="unused-no-IO")
        api = VoiceHTTP(c, authenticate=self.authenticate, clock=lambda: self.now)
        h = Handler(BASE + "/status"); api.handle(h)
        self.assertEqual(h.response[0], 200); self.assertFalse(h.response[1]["available"])

    def test_status_uses_existing_session_role_and_allowlisted_fields(self):
        h = self.req(BASE + "/status")
        self.assertEqual(self.auth_calls, ["session=owner"])
        self.assertEqual(set(h.response[1]), {"available", "provider", "automatic_retry", "automatic_purchase", "csrf_token"})
        self.assertEqual(self.c.provider_calls, 0)

    def test_missing_session_and_expired_session_are_denied(self):
        self.assertEqual(self.req(BASE + "/status", cookie=None).response[0], 401)
        self.assertEqual(self.req(BASE + "/status", cookie="session=expired").response[0], 401)
        self.role = "reader"
        self.assertEqual(self.req(BASE + "/status").response[0], 403)

    def test_same_origin_narration_is_readonly_and_available_when_provider_disabled(self):
        self.c.enabled = False
        h = self.req(BASE + "/narration?mission_id=" + MISSION + "&event_id=7")
        self.assertEqual(h.response[0], 200); self.assertTrue(h.response[1]["available"])
        self.assertEqual(self.c.provider_calls, 0)

    def test_narration_rejects_unassigned_project(self):
        h = self.req(BASE + "/narration?mission_id=" + OTHER + "&event_id=7")
        self.assertEqual(h.response[0], 403)
        self.assertNotIn("sensitive", json.dumps(h.response))

    def test_narration_rejects_duplicate_extra_and_invalid_parameters(self):
        for query in ["mission_id=" + MISSION + "&event_id=7&text=free", "mission_id=" + MISSION + "&event_id=7&event_id=7",
                      "mission_id=" + MISSION + "&event_id=true", "mission_id=" + MISSION + "&event_id=0", "mission_id=bad&event_id=7"]:
            self.assertEqual(self.req(BASE + "/narration?" + query).response[0], 400)

    def test_cross_site_get_cannot_read_status_or_narration(self):
        for headers in [{"Sec-Fetch-Site": "cross-site"}, {"Sec-Fetch-Site": "same-site"}, {"Origin": "https://evil.invalid"}]:
            self.assertEqual(self.req(BASE + "/status", headers=headers).response[0], 403)
        self.assertEqual(self.auth_calls, [])

    def test_post_requires_exact_origin_and_fetch_site(self):
        token = self.csrf()
        for headers in [{"Origin": "null"}, {"Origin": "https://evil.invalid"}, {"Origin": ORIGIN + ".evil.invalid"},
                        {"Origin": ""}, {"Sec-Fetch-Site": "same-site"}, {"Sec-Fetch-Site": "none"}, {"Sec-Fetch-Site": ""}]:
            h = self.post(headers=headers, token=token)
            self.assertEqual(h.response[0], 403); self.assertTrue(h.close_connection)
        self.assertEqual(self.c.provider_calls, 0)

    def test_post_requires_explicit_consent_header(self):
        for consent in ["", "false", "1", "TRUE"]:
            self.assertEqual(self.post(headers={"X-AWEMA-Voice-Consent": consent}).response[0], 403)
        self.assertEqual(self.c.provider_calls, 0)

    def test_missing_csrf_or_consent_is_a_closed_connection_without_generation(self):
        token = self.csrf()
        body = json.dumps({"mission_id": MISSION, "event_id": 7}).encode()
        headers = {"Origin": ORIGIN, "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": token,
                   "X-AWEMA-Voice-Consent": "true", "Content-Type": "application/json", "Content-Length": str(len(body))}
        for missing in ["X-CSRF-Token", "X-AWEMA-Voice-Consent"]:
            supplied = {k: v for k, v in headers.items() if k != missing}
            h = self.req(BASE + "/generate", "POST", headers=supplied, body=body)
            self.assertEqual(h.response[0], 403); self.assertTrue(h.close_connection)
        self.assertEqual(self.c.provider_calls, 0)

    def test_csrf_bound_to_exact_cookie_even_for_same_owner(self):
        token = self.csrf("session=owner")
        h = self.post(cookie="session=rotated-owner", token=token)
        self.assertEqual(h.response[0], 403); self.assertEqual(self.c.provider_calls, 0)

    def test_csrf_tamper_expiry_and_second_session_cannot_generate(self):
        token = self.csrf()
        self.assertEqual(self.post(token=token[:-1] + ("a" if token[-1] != "a" else "b")).response[0], 403)
        self.assertEqual(self.post(cookie="session=other-user", token=token).response[0], 403)
        self.now += 300
        self.assertEqual(self.post(token=token).response[0], 403); self.assertEqual(self.c.provider_calls, 0)

    def test_generate_accepts_only_two_ids_and_does_not_expose_bytes(self):
        result = self.generated()
        self.assertTrue(result["available"]); self.assertFalse(result["cached"])
        self.assertEqual(self.c.calls, [{"caller": "owner", "mission_id": MISSION, "event_id": 7, "consent": True}])
        self.assertEqual(set(result["audio"]), {"url", "expires_at", "mime_type", "sha256"})
        self.assertEqual(result["audio"]["expires_at"], self.now + 300)
        self.assertNotIn(AUDIO.decode(), json.dumps(result)); self.assertNotIn("never-export", json.dumps(result))

    def test_freeform_role_voice_budget_scope_and_bool_id_rejected(self):
        for extra in ["text", "voice_id", "voice_role", "authorization_scope", "budget", "consent"]:
            p = {"mission_id": MISSION, "event_id": 7, extra: "not-allowed"}
            self.assertEqual(self.post(payload=p).response[0], 400)
        self.assertEqual(self.post(payload={"mission_id": MISSION, "event_id": True}).response[0], 400)
        self.assertEqual(self.c.provider_calls, 0)

    def test_duplicate_json_keys_non_utf8_nan_and_large_body_rejected(self):
        bodies = [b'{"mission_id":"' + MISSION.encode() + b'","event_id":7,"event_id":7}', b'\xff\xfe', b'{"event_id":NaN}']
        for body in bodies:
            self.assertEqual(self.post(raw=body).response[0], 400)
        self.assertEqual(self.post(raw=b" " * 4097).response[0], 413)
        self.assertEqual(self.c.provider_calls, 0)

    def test_transfer_encoding_duplicate_length_and_wrong_content_type_rejected(self):
        self.assertEqual(self.post(headers={"Transfer-Encoding": "chunked"}).response[0], 400)
        self.assertEqual(self.post(headers={"Content-Type": "text/plain"}).response[0], 415)
        self.assertEqual(self.post(headers={"Content-Length": "0"}).response[0], 413)
        token = self.csrf(); body = json.dumps({"mission_id": MISSION, "event_id": 7}).encode()
        h = Handler(BASE + "/generate", "POST", headers={"Origin": ORIGIN, "Sec-Fetch-Site": "same-origin",
            "X-CSRF-Token": token, "X-AWEMA-Voice-Consent": "true", "Content-Type": "application/json", "Content-Length": str(len(body))}, body=body)
        h.headers["Content-Length"] = str(len(body)); self.api.handle(h)
        self.assertEqual(h.response[0], 400); self.assertTrue(h.close_connection)
        self.assertEqual(self.c.provider_calls, 0)

    def test_unauthorized_project_does_not_reach_generation(self):
        h = self.post(payload={"mission_id": OTHER, "event_id": 7})
        self.assertEqual(h.response[0], 403); self.assertEqual(self.c.calls, [])

    def test_private_audio_rechecks_acl_and_exact_session_each_get(self):
        url = self.generated()["audio"]["url"]
        before = len(self.c.narration_calls)
        h = self.req(url); self.assertEqual(h.response, (200, AUDIO, "audio/mpeg"))
        self.assertGreater(len(self.c.narration_calls), before)
        self.assertEqual(self.req(url, cookie="session=rotated-owner").response[0], 404)
        self.c.allowed = False
        self.assertEqual(self.req(url).response[0], 403)

    def test_audio_expiration_and_revoked_session(self):
        url = self.generated()["audio"]["url"]
        self.assertEqual(self.req(url, cookie="session=expired").response[0], 401)
        self.now += 300
        self.assertEqual(self.req(url).response[0], 404)

    def test_audio_link_rechecks_pilot_disable(self):
        url = self.generated()["audio"]["url"]; self.c.enabled = False
        self.assertEqual(self.req(url).response[0], 503)

    def test_audio_narration_change_revokes_opaque_handle(self):
        url = self.generated()["audio"]["url"]; self.c.changed = True
        self.assertEqual(self.req(url).response[0], 410)
        self.c.changed = False
        self.assertEqual(self.req(url).response[0], 404)

    def test_slow_acl_resolution_cannot_outlive_audio_expiry(self):
        url = self.generated()["audio"]["url"]
        original = self.c.narration
        def delayed(**kwargs):
            value = original(**kwargs); self.now += 301; return value
        self.c.narration = delayed
        self.assertEqual(self.req(url).response[0], 404)

    def test_replay_post_reuses_audio_and_does_not_extend_handle_expiry(self):
        first = self.generated(); self.now += 20
        second = self.generated()
        self.assertTrue(second["cached"]); self.assertEqual(first["audio"], second["audio"])
        self.assertEqual(self.c.provider_calls, 1)

    def test_provider_uncertainty_returns_fixed_text_with_no_second_attempt(self):
        self.c.fail = True
        h = self.post(); self.assertEqual(h.response[0], 503)
        self.assertEqual(len(self.c.calls), 1); self.assertNotIn("provider body", json.dumps(h.response))

    def test_disabled_provider_cannot_be_reached_even_with_valid_csrf(self):
        token = self.csrf(); self.c.enabled = False
        self.assertEqual(self.post(token=token).response[0], 503)
        self.assertEqual(self.c.calls, [])

    def test_session_revoked_during_generation_cannot_publish_handle(self):
        self.c.after = lambda: setattr(self, "auth_revoked", True)
        self.assertEqual(self.post().response[0], 401)
        self.assertEqual(self.api.cache._entries, {})

    def test_acl_revoked_during_generation_cannot_publish_handle(self):
        self.c.after = lambda: setattr(self.c, "allowed", False)
        h = self.post(); self.assertEqual(h.response[0], 403)
        self.assertEqual(self.api.cache._entries, {})

    def test_generation_different_narration_is_not_published(self):
        self.c.after = lambda: setattr(self.c, "changed", True)
        self.assertEqual(self.post().response[0], 409)
        self.assertEqual(self.api.cache._entries, {})

    def test_audio_hash_from_coordinator_is_rechecked(self):
        original = self.c.generate
        def corrupt(**kwargs):
            value = original(**kwargs); value["audio"] = b"corrupt"; return value
        self.c.generate = corrupt
        self.assertEqual(self.post().response[0], 503); self.assertEqual(self.api.cache._entries, {})

    def test_capacity_guard_does_not_start_a_third_generation(self):
        self.api._generation_slots.acquire(); self.api._generation_slots.acquire()
        try:
            self.assertEqual(self.post().response[0], 429); self.assertEqual(self.c.calls, [])
        finally:
            self.api._generation_slots.release(); self.api._generation_slots.release()

    def test_request_routes_methods_and_query_constraints(self):
        for path, method, code in [(BASE + "/generate", "GET", 405), (BASE + "/status?extra=1", "GET", 405),
                                   (BASE + "/audio/bad", "GET", 404), (BASE + "/unknown", "GET", 404),
                                   (BASE + "/status", "PUT", 405), ("https://evil.invalid" + BASE + "/status", "GET", 400)]:
            self.assertEqual(self.req(path, method).response[0], code)

    def test_cache_is_bounded_and_eviction_does_not_leave_public_or_disk_handles(self):
        cache = EphemeralAudio(clock=lambda: self.now, ttl=10, max_entries=2, max_bytes=10, max_audio_bytes=5)
        def put(event):
            audio = b"12345"
            return cache.put(session_binding="s", caller="owner", mission_id=MISSION, event_id=event,
                             narration_sha256="c" * 64, voice_role="system", audio=audio, mime="audio/mpeg",
                             sha256=hashlib.sha256(audio).hexdigest())
        a, b = put(1), put(2); self.now += 1; c = put(3)
        self.assertLessEqual(len(cache._entries), 2)
        self.assertLessEqual(sum(len(e.audio) for e in cache._entries.values()), 10)
        self.assertIsNone(cache.get(a.opaque_id)); self.assertIsNotNone(cache.get(c.opaque_id))
        self.now += 11; self.assertIsNone(cache.get(c.opaque_id)); self.assertEqual(cache._entries, {})

    def test_mixin_preserves_all_legacy_nonvoice_routes(self):
        class Parent(Handler):
            def do_GET(self): self.response = "parent-get"
            def do_HEAD(self): self.response = "parent-head"
            def do_POST(self): self.response = "parent-readonly"
        class Mixed(VoiceHTTPMixin, Parent):
            pass
        for method, response in [("GET", "parent-get"), ("HEAD", "parent-head"), ("POST", "parent-readonly")]:
            h = Mixed("/finance/standup/api/session", method); getattr(h, "do_" + method)(); self.assertEqual(h.response, response)
        h = Mixed(BASE + "/status"); h.do_GET(); self.assertFalse(h.response[1]["available"])
        h.voice_http = self.api; h.do_GET(); self.assertTrue(h.response[1]["available"])

    def test_full_http_flow_uses_real_coordinator_durable_replay_cache(self):
        # Real narration/store/coordinator with synthetic provider bytes. No HTTP listener or network.
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "narration"))
        from test_voice_coordinator import MemoryResolver, FakeProvider, MISSION as REAL_MISSION, EVENT_ID, VOICE
        from voice_coordinator import Policy, VoiceCoordinator
        resolver, provider = MemoryResolver(), FakeProvider()
        now = datetime(2026, 10, 17, 12, tzinfo=timezone.utc)
        policy = Policy(enabled=True, commercial_license_confirmed=True, expires_at=(now + timedelta(hours=1)).timestamp(),
                        monthly_character_budget=10000, role_voices=(("qa", VOICE),))
        with tempfile.TemporaryDirectory() as tmp:
            coordinator = VoiceCoordinator(policy=policy, resolver=resolver, store_root=Path(tmp) / "private",
                                           provider=provider, clock=lambda: now)
            api = VoiceHTTP(coordinator, authenticate=self.authenticate, clock=lambda: now.timestamp(), csrf_key=b"y" * 32)
            h = Handler(BASE + "/status"); api.handle(h); token = h.response[1]["csrf_token"]
            body = json.dumps({"mission_id": REAL_MISSION, "event_id": EVENT_ID}).encode()
            def post():
                request = Handler(BASE + "/generate", "POST", headers={"Origin": ORIGIN, "Sec-Fetch-Site": "same-origin",
                    "X-CSRF-Token": token, "X-AWEMA-Voice-Consent": "true", "Content-Type": "application/json", "Content-Length": str(len(body))}, body=body)
                api.handle(request); self.assertEqual(request.response[0], 200, request.response); return request.response[1]
            first, second = post(), post()
            self.assertFalse(first["cached"]); self.assertTrue(second["cached"]); self.assertEqual(first["audio"], second["audio"])
            self.assertEqual(len(provider.calls), 1)
            request = Handler(first["audio"]["url"]); api.handle(request); self.assertEqual(request.response[0], 200)
            resolver.auth = replace(resolver.auth, allowed=False)
            request = Handler(first["audio"]["url"]); api.handle(request); self.assertEqual(request.response[0], 403)


if __name__ == "__main__":
    unittest.main()
