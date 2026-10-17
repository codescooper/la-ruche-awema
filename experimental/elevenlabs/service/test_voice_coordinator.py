"""Offline composition tests: real narration + real SQLite + synthetic provider.

No credentials, browser, network, server routes or production calls. Add sibling
narration directory to imports only; no source or state is copied from a server.
"""
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "narration"))
import narration as n
from voice_coordinator import Policy, VoiceCoordinator
from voice_store import VoiceStore

MISSION = "f_" + "a" * 24
VOICE = "synthetic_voice_0123456789"
EVENT_ID = 52

def audio_fixture():
    # Structural MP3 fixture, never an assertion of real voice audibility/quality.
    return (b"\xff\xfb\x90\x00" + b"\x00" * 413) * 3

class MemoryResolver:
    def __init__(self):
        self.auth = n.Authorization("owner", "private-owner-v1", MISSION, True)
        binding = n.Binding(MISSION, EVENT_ID, "qa", 3, 2, 154, "browser-01")
        kind = "worker_progress_reported"
        self.event = n.EventRecord(binding, kind, 100.0, hashlib.sha256(kind.encode()).hexdigest(), "progress-01")
        self.report = n.WorkerReport(binding, "progress-01", 99.0, "verified", "Contrôler le menu sur mobile",
            "Le menu dépasse à 320 pixels", "receipt:browser-01", "Transmettre ce défaut au développeur", "")
        self.update_report()
        self.proof = n.EvidenceProof(binding, "receipt:browser-01", "c" * 64, "verified", "verified")
        self.calls = []
    def authorize(self, caller, mission):
        self.calls.append("authorize")
        return self.auth
    def resolve_event(self, auth, mission, event):
        self.calls.append("event")
        return self.event
    def resolve_report(self, auth, event, report):
        self.calls.append("report")
        return self.report
    def resolve_evidence(self, auth, binding, reference):
        self.calls.append("proof")
        return self.proof
    def update_report(self, **changes):
        self.report = replace(self.report, **changes)
        self.report = replace(self.report, report_sha256=n.report_digest(self.report))

class FakeProvider:
    hard_deadline = True
    def __init__(self, action=None):
        self.calls, self.action = [], action
    def generate(self, **arguments):
        self.calls.append(arguments)
        if self.action:
            self.action()
        return SimpleNamespace(audio=audio_fixture(), mime="audio/mpeg")

class CoordinatorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "private"
        self.now = datetime(2026, 10, 17, 12, tzinfo=timezone.utc)
        self.resolver = MemoryResolver()
        self.provider = FakeProvider()
        self.policy = Policy(enabled=True, commercial_license_confirmed=True,
            expires_at=(self.now + timedelta(hours=1)).timestamp(), monthly_character_budget=10000,
            role_voices=(("qa", VOICE),))
        self.coordinator = self.make()
    def tearDown(self):
        self.tmp.cleanup()
    def make(self, *, provider=None, policy=None):
        return VoiceCoordinator(policy=policy or self.policy, resolver=self.resolver,
            store_root=self.root, provider=self.provider if provider is None else provider,
            clock=lambda: self.now)
    def generate(self, coordinator=None, **changes):
        values = dict(caller="owner", mission_id=MISSION, event_id=EVENT_ID, consent=True)
        values.update(changes)
        return (coordinator or self.coordinator).generate(**values)
    def assertUnavailable(self, result, reason=None):
        self.assertFalse(result["available"])
        self.assertNotIn("audio", result)
        if reason is not None:
            self.assertEqual(result["reason"], reason)
    def stored_operation(self):
        projected = self.coordinator.narration(caller="owner", mission_id=MISSION, event_id=EVENT_ID)
        identifier = self.coordinator._identity(projected, VOICE, self.policy.model_id)
        store = VoiceStore(self.root, monthly_character_budget=self.policy.monthly_character_budget,
            authorize=lambda scope, action: True, clock=lambda: self.now)
        return store.operation(scope=self.resolver.auth.scope_id, operation_id=identifier)
    def test_exact_factual_narration_passed_to_provider(self):
        narration = self.coordinator.narration(caller="owner", mission_id=MISSION, event_id=EVENT_ID)
        result = self.generate()
        self.assertTrue(result["available"], result)
        self.assertEqual(self.provider.calls[0]["text"], narration["text"])
        self.assertEqual(result["narration_sha256"], narration["narration_sha256"])
        self.assertEqual(result["voice_role"], "qa")
        self.assertEqual(result["audio"], audio_fixture())
        self.assertFalse(result["cache_reused"])
    def test_replay_cache_one_provider_call(self):
        first = self.generate()
        second = self.generate()
        self.assertTrue(second["available"], second)
        self.assertTrue(second["cache_reused"])
        self.assertEqual(first["audio_sha256"], second["audio_sha256"])
        self.assertEqual(len(self.provider.calls), 1)
    def test_restart_preserves_cache_and_quota(self):
        self.assertTrue(self.generate()["available"])
        replacement_provider = FakeProvider()
        result = self.generate(self.make(provider=replacement_provider))
        self.assertTrue(result["available"], result)
        self.assertTrue(result["cache_reused"])
        self.assertEqual(replacement_provider.calls, [])
        self.assertEqual(self.stored_operation().status, "complete")
    def test_quota_blocks_before_provider(self):
        other = self.make(policy=replace(self.policy, monthly_character_budget=1))
        self.assertUnavailable(self.generate(other), "voice_evidence_or_access_unavailable")
        self.assertEqual(self.provider.calls, [])
    def test_quota_stays_spent_after_restart(self):
        length = len(self.coordinator.narration(caller="owner", mission_id=MISSION, event_id=EVENT_ID)["text"])
        policy = replace(self.policy, monthly_character_budget=length)
        first = self.make(policy=policy)
        self.assertTrue(self.generate(first)["available"])
        self.resolver.update_report(observed_result="Le menu dépasse encore à 360 pixels")
        second = self.make(policy=policy)
        self.assertUnavailable(self.generate(second), "voice_evidence_or_access_unavailable")
        self.assertEqual(len(self.provider.calls), 1)
    def test_unauthorized_denied_before_provider_and_store(self):
        self.resolver.auth = replace(self.resolver.auth, allowed=False)
        self.assertUnavailable(self.generate(), "voice_evidence_or_access_unavailable")
        self.assertEqual(self.provider.calls, [])
        self.assertFalse(self.root.exists())
        self.assertEqual(self.resolver.calls, ["authorize"])
    def test_different_caller_cannot_reuse_owner_cache(self):
        self.assertTrue(self.generate()["available"])
        self.assertUnavailable(self.generate(caller="another"), "voice_evidence_or_access_unavailable")
        self.assertEqual(len(self.provider.calls), 1)
    def test_revoked_during_provider_call_no_audio_no_retry(self):
        def revoke():
            self.resolver.auth = replace(self.resolver.auth, allowed=False)
        self.provider.action = revoke
        self.assertUnavailable(self.generate(), "voice_evidence_or_access_unavailable")
        self.assertEqual(len(self.provider.calls), 1)
        self.resolver.auth = replace(self.resolver.auth, allowed=True)
        self.provider.action = None
        self.assertEqual(self.stored_operation().status, "uncertain")
        self.assertUnavailable(self.generate(), "generation_uncertain_no_automatic_retry")
        self.assertEqual(len(self.provider.calls), 1)
    def test_cached_audio_revocation_blocks_replay(self):
        self.assertTrue(self.generate()["available"])
        self.resolver.auth = replace(self.resolver.auth, allowed=False)
        self.assertUnavailable(self.generate(), "voice_evidence_or_access_unavailable")
        self.assertEqual(len(self.provider.calls), 1)
    def test_source_changes_during_provider_no_stale_audio(self):
        self.provider.action = lambda: self.resolver.update_report(observed_result="Le menu a été corrigé à 320 pixels")
        self.assertUnavailable(self.generate(), "narration_changed")
        self.assertEqual(len(self.provider.calls), 1)
    def test_evidence_changes_during_provider_no_stale_audio(self):
        self.provider.action = lambda: setattr(self.resolver, "proof", replace(self.resolver.proof, sha256="d" * 64))
        self.assertUnavailable(self.generate(), "narration_changed")
    def test_expired_before_call(self):
        self.now += timedelta(hours=2)
        self.assertUnavailable(self.generate(), "pilot_expired")
        self.assertEqual(self.provider.calls, [])
        self.assertFalse(self.root.exists())
    def test_expired_during_call_no_audio(self):
        def expire():
            self.now += timedelta(hours=2)
        self.provider.action = expire
        self.assertUnavailable(self.generate(), "pilot_expired_or_disabled")
        self.assertEqual(len(self.provider.calls), 1)
    def test_disabled_provider_and_missing_commercial_license(self):
        for changes, reason in (({"enabled": False}, "provider_disabled"),
                                ({"commercial_license_confirmed": False}, "commercial_license_required")):
            with self.subTest(reason=reason):
                self.assertUnavailable(self.generate(self.make(policy=replace(self.policy, **changes))), reason)
        self.assertEqual(self.provider.calls, [])
        self.assertFalse(self.root.exists())
    def test_explicit_consent_is_strict(self):
        for consent in (False, None, 1, "yes"):
            with self.subTest(consent=consent):
                self.assertUnavailable(self.generate(consent=consent), "explicit_voice_consent_required")
        self.assertEqual(self.provider.calls, [])
    def test_hard_deadline_provider_required(self):
        self.provider.hard_deadline = False
        self.assertUnavailable(self.generate(), "hard_deadline_required")
        self.assertEqual(self.provider.calls, [])
    def test_provider_error_keeps_uncertainty_and_hides_exception(self):
        def fail():
            raise RuntimeError("synthetic secret body do not echo")
        self.provider.action = fail
        first = self.generate()
        self.assertUnavailable(first, "voice_unavailable_text_continues")
        self.assertNotIn("synthetic secret", str(first))
        self.assertEqual(self.stored_operation().status, "uncertain")
        second = self.generate(self.make(provider=FakeProvider()))
        self.assertUnavailable(second, "generation_uncertain_no_automatic_retry")
        self.assertEqual(len(self.provider.calls), 1)
    def test_invalid_audio_keeps_uncertainty(self):
        class InvalidProvider(FakeProvider):
            def generate(self, **arguments):
                self.calls.append(arguments)
                return SimpleNamespace(audio=b"ID3fake", mime="audio/mpeg")
        bad = InvalidProvider()
        self.assertUnavailable(self.generate(self.make(provider=bad)), "voice_evidence_or_access_unavailable")
        self.assertEqual(self.stored_operation().status, "uncertain")
        self.assertUnavailable(self.generate(), "generation_uncertain_no_automatic_retry")
        self.assertEqual(self.provider.calls, [])
    def test_no_agent_voice_for_system_journal_without_system_assignment(self):
        kind = "qa_completed"
        self.resolver.event = replace(self.resolver.event, kind=kind,
            source_event_sha256=hashlib.sha256(kind.encode()).hexdigest(), worker_report_id=None)
        self.resolver.proof = replace(self.resolver.proof, reference="event:52", level="recorded",
            action_state="completed", sha256=self.resolver.event.source_event_sha256)
        self.assertUnavailable(self.generate(), "role_voice_not_configured")
        self.assertEqual(self.provider.calls, [])
    def test_non_finite_expiry_is_rejected(self):
        for expiry in (float("nan"), float("inf"), -float("inf")):
            with self.subTest(expiry=expiry):
                with self.assertRaises(ValueError):
                    self.make(policy=replace(self.policy, expires_at=expiry))
    def test_invalid_role_or_voice_mapping_rejected_before_io(self):
        mappings = ((("qa", VOICE), ("qa", VOICE)), (("not_a_role", VOICE),),
                    (("qa", "../unsafe"),), (("qa", 123),), ((123, VOICE),),
                    (("qa", VOICE, "extra"),), (["qa", VOICE],))
        for mapping in mappings:
            with self.subTest(mapping=mapping):
                with self.assertRaises(ValueError):
                    self.make(policy=replace(self.policy, role_voices=mapping))
        self.assertFalse(self.root.exists())
        self.assertEqual(self.provider.calls, [])
    def test_budget_and_voice_configuration_required(self):
        for policy, reason in ((replace(self.policy, monthly_character_budget=0), "budget_not_configured"),
                               (replace(self.policy, role_voices=()), "voices_not_configured")):
            self.assertUnavailable(self.generate(self.make(policy=policy)), reason)
        self.assertFalse(self.root.exists())
        self.assertEqual(self.provider.calls, [])
    def test_wrong_mission_and_event_never_reach_provider(self):
        self.assertUnavailable(self.generate(mission_id="f_" + "b" * 24), "voice_evidence_or_access_unavailable")
        self.assertUnavailable(self.generate(event_id=53), "voice_evidence_or_access_unavailable")
        self.assertEqual(self.provider.calls, [])
    def test_invalid_proof_during_call_never_returns_audio(self):
        self.provider.action = lambda: setattr(self.resolver, "proof", replace(self.resolver.proof, level="recorded"))
        self.assertUnavailable(self.generate(), "voice_evidence_or_access_unavailable")
        self.assertEqual(len(self.provider.calls), 1)

if __name__ == "__main__":
    unittest.main()
