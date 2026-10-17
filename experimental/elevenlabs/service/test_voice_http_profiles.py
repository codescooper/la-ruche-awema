"""Audition HTTP flow: real SQLite ledger + fixed profile coordinator, fake provider only."""
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "narration"))
from voice_profiles import PROFILE_NAMES, ProfileVoiceCoordinator
from voice_coordinator import Policy
from voice_http import BASE, VoiceHTTP
from test_voice_http import Handler, ORIGIN
from test_voice_coordinator import FakeProvider

VOICE = "synthetic_voice_0123456789"


class ProfileHTTPTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="awema-profile-http-")
        self.addCleanup(self.tmp.cleanup)
        self.now = datetime(2026, 10, 17, 12, tzinfo=timezone.utc)
        self.provider = FakeProvider()
        self.current = {"session=owner": {"user": "owner", "role": "owner"},
                        "session=director": {"user": "director", "role": "director"}}
        self.policy = Policy(enabled=True, commercial_license_confirmed=True, expires_at=self.now.timestamp() + 3600,
                            monthly_character_budget=1000, role_voices=tuple((r, VOICE) for r in PROFILE_NAMES))
        self.created = []
        self.api = VoiceHTTP(coordinator_factory=self.factory, authenticate=self.authenticate,
                             clock=lambda: self.now.timestamp(), csrf_key=b"t" * 32)

    def authenticate(self, cookie):
        if cookie not in self.current:
            class Missing(Exception):
                code = 401
            raise Missing("private auth failure")
        return dict(self.current[cookie])

    def factory(self, *, caller, reauthenticate, generation_binding):
        def check(candidate):
            return candidate == caller and reauthenticate().user == caller
        coordinator = ProfileVoiceCoordinator(policy=self.policy, resolver=object(), store_root=Path(self.tmp.name) / "private",
            provider=self.provider, clock=lambda: self.now, profile_session_check=check)
        self.created.append(coordinator)
        return coordinator

    def request(self, path, method="GET", *, cookie="session=owner", body=b"", headers=None):
        h = Handler(path, method, cookie=cookie, body=body, headers=headers)
        self.api.handle(h)
        return h.response

    def token(self, cookie="session=owner"):
        response = self.request(BASE + "/status", cookie=cookie)
        self.assertEqual(response[0], 200, response)
        return response[1]["csrf_token"]

    def audition(self, role="dev", *, cookie="session=owner", token=None, payload=None, headers=None, raw=None):
        body = raw if raw is not None else json.dumps(payload if payload is not None else {"role": role}).encode()
        supplied = {"Origin": ORIGIN, "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": token or self.token(cookie),
                    "X-AWEMA-Voice-Consent": "true", "Content-Type": "application/json", "Content-Length": str(len(body))}
        supplied.update(headers or {})
        return self.request(BASE + "/test", "POST", cookie=cookie, body=body, headers=supplied)

    def test_response_matches_ui_fixed_test_contract_without_mission_fields(self):
        response = self.audition(); self.assertEqual(response[0], 200, response)
        data = response[1]
        self.assertEqual(data["purpose"], "voice_profile_test"); self.assertEqual(data["role"], "dev")
        self.assertEqual(data["text"], "Bonjour, je suis Développeur. Ceci est un test de ma voix dans la Danse.")
        self.assertEqual(data["voice_role"], "dev"); self.assertNotIn("mission_id", data); self.assertNotIn("event_id", data)
        self.assertEqual(set(data["audio"]), {"url", "expires_at", "mime_type", "sha256"})
        self.assertNotIn("synthetic_voice_", json.dumps(data))
        entry = self.api.cache.get(data["audio"]["url"].rsplit("/", 1)[1])
        self.assertEqual(entry.purpose, "voice_profile_test"); self.assertEqual(entry.profile_role, "dev")
        self.assertIsNone(entry.mission_id); self.assertIsNone(entry.event_id)

    def test_get_audio_revalidates_identity_without_generation_or_provider_call(self):
        response = self.audition(); self.assertEqual(response[0], 200, response)
        url = response[1]["audio"]["url"]
        self.assertEqual(len(self.provider.calls), 1)
        for _ in range(3):
            self.assertEqual(self.request(url)[0], 200)
        self.assertEqual(len(self.provider.calls), 1)
        self.assertTrue(all(c.resolver.__class__ is object for c in self.created))

    def test_no_mission_access_is_required_for_fixed_profile_audition(self):
        # resolver=object() has no authorization/event API; the profile path must never call it.
        response = self.audition(cookie="session=director")
        self.assertEqual(response[0], 200, response)
        self.assertEqual(len(self.provider.calls), 1)

    def test_replay_cached_across_new_request_coordinator_and_opaque_handle(self):
        first = self.audition(); second = self.audition()
        self.assertEqual(first[0], 200, first); self.assertEqual(second[0], 200, second)
        self.assertFalse(first[1]["cached"]); self.assertTrue(second[1]["cached"])
        self.assertEqual(first[1]["audio"], second[1]["audio"]); self.assertEqual(len(self.provider.calls), 1)

    def test_tests_cannot_accept_client_text_voice_scope_or_mission(self):
        for key in ["text", "voice_id", "scope", "budget", "mission_id", "event_id", "purpose"]:
            self.assertEqual(self.audition(payload={"role": "dev", key: "client-controlled"})[0], 400)
        for role in ["system", "unknown", 7, {"role": "dev"}]:
            self.assertEqual(self.audition(payload={"role": role})[0], 400)
        self.assertEqual(len(self.provider.calls), 0)

    def test_duplicate_json_role_and_large_body_rejected(self):
        self.assertEqual(self.audition(raw=b'{"role":"dev","role":"qa"}')[0], 400)
        self.assertEqual(self.audition(raw=b" " * 4097)[0], 413)
        self.assertEqual(len(self.provider.calls), 0)

    def test_get_or_query_or_cross_origin_cannot_generate_audition(self):
        self.assertEqual(self.request(BASE + "/test")[0], 405)
        self.assertEqual(self.audition(headers={"Origin": "https://evil.invalid"})[0], 403)
        self.assertEqual(self.audition(headers={"Sec-Fetch-Site": "same-site"})[0], 403)
        self.assertEqual(self.audition(headers={"X-AWEMA-Voice-Consent": "false"})[0], 403)
        self.assertEqual(self.audition(headers={"X-CSRF-Token": "tampered"})[0], 403)
        self.assertEqual(len(self.provider.calls), 0)

    def test_transfer_encoding_is_rejected(self):
        self.assertEqual(self.audition(headers={"Transfer-Encoding": "chunked"})[0], 400)
        self.assertEqual(len(self.provider.calls), 0)

    def test_session_and_policy_revocation_block_existing_profile_audio(self):
        response = self.audition(); self.assertEqual(response[0], 200, response)
        url = response[1]["audio"]["url"]
        self.assertEqual(self.request(url, cookie="session=director")[0], 404)
        self.current["session=owner"]["role"] = "reader"
        self.assertEqual(self.request(url)[0], 403)
        del self.current["session=owner"]
        self.assertEqual(self.request(url)[0], 401)
        self.assertEqual(len(self.provider.calls), 1)

    def test_voice_mapping_change_invalidates_handle_without_regeneration(self):
        from dataclasses import replace
        response = self.audition(); self.assertEqual(response[0], 200, response)
        self.policy = replace(self.policy, role_voices=(("dev", "synthetic_other_voice_123456"),))
        self.assertEqual(self.request(response[1]["audio"]["url"])[0], 410)
        self.assertEqual(len(self.provider.calls), 1)

    def test_profile_audio_expiry_is_not_a_provider_replay(self):
        response = self.audition(); self.assertEqual(response[0], 200, response)
        self.now += timedelta(minutes=5)
        self.assertEqual(self.request(response[1]["audio"]["url"])[0], 404)
        self.assertEqual(len(self.provider.calls), 1)

    def test_ledger_failure_or_uncertainty_never_retries_automatically(self):
        self.provider.action = lambda: (_ for _ in ()).throw(RuntimeError("private provider error"))
        first = self.audition(); second = self.audition()
        self.assertEqual(first[0], 503); self.assertEqual(second[0], 503)
        self.assertEqual(len(self.provider.calls), 1)
        self.assertNotIn("private provider", json.dumps(first))

    def test_session_revoked_during_provider_publishes_no_profile_handle(self):
        self.provider.action = lambda: self.current.pop("session=owner")
        response = self.audition()
        self.assertEqual(response[0], 503, response)
        self.assertEqual(self.api.cache._entries, {})
        self.assertEqual(len(self.provider.calls), 1)


if __name__ == "__main__":
    unittest.main()
