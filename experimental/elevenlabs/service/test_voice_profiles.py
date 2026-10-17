"""Fixed audition + real durable SQLite/cache tests, with synthetic MP3 provider only."""
from dataclasses import replace
from contextlib import closing
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "narration"))
from voice_profiles import PROFILE_NAMES, ProfileVoiceCoordinator
from voice_coordinator import Policy, VoiceCoordinator
from test_voice_coordinator import FakeProvider, MemoryResolver, MISSION, EVENT_ID, audio_fixture

VOICE = "synthetic_voice_0123456789"


class ProfileTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="awema-voice-profiles-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "private"
        self.now = datetime(2026, 10, 17, 12, tzinfo=timezone.utc)
        self.current = True
        self.checks = []
        self.provider = FakeProvider()
        self.policy = Policy(enabled=True, commercial_license_confirmed=True,
            expires_at=(self.now + timedelta(hours=1)).timestamp(), monthly_character_budget=1000,
            role_voices=tuple((role, VOICE) for role in PROFILE_NAMES))
        self.c = self.make()

    def check(self, caller):
        self.checks.append(caller)
        return self.current and caller in ("owner", "director")

    def make(self, **changes):
        return ProfileVoiceCoordinator(policy=changes.get("policy", self.policy), resolver=object(),
            store_root=self.root, provider=changes.get("provider", self.provider), clock=lambda: self.now,
            profile_session_check=changes.get("check", self.check))

    def run_profile(self, role="dev", caller="owner", **kwargs):
        return self.c.test_voice(caller=caller, role=role, consent=kwargs.get("consent", True))

    def test_requires_live_session_callback(self):
        with self.assertRaisesRegex(ValueError, "profile_session_check_required"):
            self.make(check=None)

    def test_fixed_phrase_has_no_mission_ids_or_fake_activity(self):
        result = self.run_profile()
        self.assertTrue(result["available"], result)
        self.assertEqual(result["purpose"], "voice_profile_test")
        self.assertEqual(result["text"], "Bonjour, je suis Développeur. Ceci est un test de ma voix dans la Danse.")
        self.assertEqual(result["text_sha256"], hashlib.sha256(result["text"].encode()).hexdigest())
        self.assertNotIn("mission_id", result); self.assertNotIn("event_id", result)
        self.assertEqual(result["voice_role"], "dev"); self.assertEqual(result["role"], "dev")
        self.assertEqual(self.provider.calls[0]["text"], result["text"])
        self.assertEqual(result["audio"], audio_fixture())

    def test_all_nine_roles_are_explicit_fixed_tests_under_global_1000_budget(self):
        self.assertEqual(len(PROFILE_NAMES), 9)
        for role, name in PROFILE_NAMES.items():
            result = self.run_profile(role)
            self.assertTrue(result["available"], result)
            self.assertEqual(result["text"], "Bonjour, je suis " + name + ". Ceci est un test de ma voix dans la Danse.")
            self.assertEqual(result["voice_role"], role)
        self.assertEqual(len(self.provider.calls), 9)
        with closing(sqlite3.connect(self.root / "voice.sqlite3")) as conn:
            total = conn.execute("SELECT sum(characters) FROM generations").fetchone()[0]
            self.assertLessEqual(total, 1000)

    def test_consent_disabled_expired_and_unlicensed_are_noops(self):
        self.assertFalse(self.run_profile(consent=False)["available"])
        for policy in [replace(self.policy, enabled=False), replace(self.policy, commercial_license_confirmed=False),
                       replace(self.policy, expires_at=self.now.timestamp())]:
            c = self.make(policy=policy)
            self.assertFalse(c.test_voice(caller="owner", role="dev", consent=True)["available"])
        self.assertEqual(self.provider.calls, []); self.assertFalse(self.root.exists())

    def test_invalid_roles_or_expired_session_do_not_touch_ledger(self):
        for role in ["system", "unknown", "voice-id", {"text": "free text"}, 1]:
            self.assertFalse(self.run_profile(role)["available"])
        self.current = False
        self.assertFalse(self.run_profile()["available"])
        self.assertFalse(self.root.exists()); self.assertEqual(self.provider.calls, [])

    def test_profile_identity_is_pure_and_revalidates_session(self):
        first = self.c.profile_identity(caller="owner", role="dev")
        self.assertTrue(first["available"]); self.assertFalse(self.root.exists()); self.assertEqual(self.provider.calls, [])
        self.current = False
        self.assertFalse(self.c.profile_identity(caller="owner", role="dev")["available"])

    def test_session_rechecked_before_after_store_provider_and_cache(self):
        self.assertTrue(self.run_profile()["available"])
        self.assertGreaterEqual(len(self.checks), 14)
        before = len(self.checks); self.assertTrue(self.run_profile()["available"])
        self.assertGreater(len(self.checks), before + 10); self.assertEqual(len(self.provider.calls), 1)

    def test_replay_and_new_coordinator_reuse_cache_without_new_provider_call(self):
        first = self.run_profile(); second = self.run_profile()
        self.assertFalse(first["cache_reused"]); self.assertTrue(second["cache_reused"])
        c = self.make(provider=FakeProvider())
        third = c.test_voice(caller="owner", role="dev", consent=True)
        self.assertTrue(third["cache_reused"]); self.assertEqual(first["narration_sha256"], third["narration_sha256"])
        self.assertEqual(len(self.provider.calls), 1); self.assertEqual(c.provider.calls, [])

    def test_users_and_voice_versions_do_not_cross_identity(self):
        owner = self.run_profile(); director = self.run_profile(caller="director")
        self.assertNotEqual(owner["narration_sha256"], director["narration_sha256"])
        other = self.make(policy=replace(self.policy, role_voices=(("dev", "synthetic_voice_other_12345"),)))
        changed = other.test_voice(caller="owner", role="dev", consent=True)
        self.assertTrue(changed["available"], changed)
        self.assertNotEqual(changed["narration_sha256"], owner["narration_sha256"])

    def test_global_budget_is_shared_across_users_profiles_and_restarts(self):
        self.c = self.make(policy=replace(self.policy, monthly_character_budget=100))
        self.assertTrue(self.run_profile()["available"])
        self.assertFalse(self.run_profile(role="qa", caller="director")["available"])
        restarted = self.make(policy=replace(self.policy, monthly_character_budget=100), provider=FakeProvider())
        self.assertFalse(restarted.test_voice(caller="director", role="qa", consent=True)["available"])
        self.assertEqual(len(self.provider.calls), 1); self.assertEqual(restarted.provider.calls, [])

    def test_mission_and_profile_use_one_global_budget_in_the_same_store(self):
        resolver = MemoryResolver()
        base = VoiceCoordinator(policy=self.policy, resolver=resolver, store_root=self.root,
                                provider=self.provider, clock=lambda: self.now)
        mission_text = base.narration(caller="owner", mission_id=MISSION, event_id=EVENT_ID)["text"]
        profile_text = self.c.profile_identity(caller="owner", role="dev")["text"]
        policy = replace(self.policy, monthly_character_budget=len(mission_text) + len(profile_text) - 1)
        base = VoiceCoordinator(policy=policy, resolver=resolver, store_root=self.root,
                                provider=self.provider, clock=lambda: self.now)
        self.assertTrue(base.generate(caller="owner", mission_id=MISSION, event_id=EVENT_ID, consent=True)["available"])
        self.c = self.make(policy=policy)
        self.assertFalse(self.run_profile()["available"])
        self.assertEqual(len(self.provider.calls), 1)

    def test_provider_uncertainty_is_not_retried_after_restart(self):
        def fail():
            raise RuntimeError("provider private body")
        self.provider.action = fail
        self.assertFalse(self.run_profile()["available"])
        self.provider.action = None
        self.assertFalse(self.run_profile()["available"])
        restarted = self.make(provider=FakeProvider())
        self.assertFalse(restarted.test_voice(caller="owner", role="dev", consent=True)["available"])
        self.assertEqual(len(self.provider.calls), 1); self.assertEqual(restarted.provider.calls, [])

    def test_session_revoked_during_provider_preserves_uncertainty_and_returns_no_audio(self):
        self.provider.action = lambda: setattr(self, "current", False)
        result = self.run_profile(); self.assertFalse(result["available"]); self.assertNotIn("audio", result)
        self.current = True; self.provider.action = None
        self.assertFalse(self.run_profile()["available"]); self.assertEqual(len(self.provider.calls), 1)

    def test_policy_expired_during_provider_preserves_uncertainty(self):
        self.provider.action = lambda: setattr(self, "now", self.now + timedelta(hours=2))
        self.assertFalse(self.run_profile()["available"]); self.assertEqual(len(self.provider.calls), 1)

    def test_invalid_provider_audio_never_becomes_a_cached_test(self):
        class Invalid:
            hard_deadline = True
            def generate(self, **kwargs):
                class Result:
                    audio = b"not valid mp3"; mime = "audio/mpeg"
                return Result()
        self.c = self.make(provider=Invalid())
        self.assertFalse(self.run_profile()["available"])
        restarted = self.make(provider=FakeProvider())
        self.assertFalse(restarted.test_voice(caller="owner", role="dev", consent=True)["available"])
        self.assertEqual(restarted.provider.calls, [])


if __name__ == "__main__":
    unittest.main()
