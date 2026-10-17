"""Offline tests, real SQLite/filesystem, no provider/key/network."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import multiprocessing
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch
from voice_store import VoiceStore, StoreError, valid_mp3

VOICE = "synthetic_voice_0123456789"
TEXT = "Je vérifie le menu mobile puis je remets le résultat au CTO."
def op(value="first"):
    return hashlib.sha256(value.encode()).hexdigest()
def mp3():
    return (b"\xff\xfb\x90\x00" + b"\x00" * 413) * 3
def child_reserve(root, index, queue):
    store = VoiceStore(root, monthly_character_budget=1000, authorize=lambda scope, action: True)
    r = store.reserve(scope="test", operation_id=op(str(index)), text="same narration", voice_id=VOICE)
    queue.put(r.should_generate)
def child_crash(root):
    store = VoiceStore(root, monthly_character_budget=1000, authorize=lambda scope, action: True)
    store.reserve(scope="mission_test", operation_id=op(), text=TEXT, voice_id=VOICE)
    os._exit(42)

class StoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "private"
        self.allowed, self.calls = True, []
        self.now = datetime(2026, 10, 17, tzinfo=timezone.utc)
        self.store = self.make()
    def tearDown(self):
        self.tmp.cleanup()
    def authorize(self, scope, action):
        self.calls.append((scope, action))
        return self.allowed
    def make(self, budget=1000, **changes):
        args = dict(monthly_character_budget=budget, authorize=self.authorize, clock=lambda: self.now)
        args.update(changes)
        return VoiceStore(self.root, **args)
    def reserve(self, store=None, **changes):
        args = dict(scope="mission_test", operation_id=op(), text=TEXT, voice_id=VOICE)
        args.update(changes)
        return (store or self.store).reserve(**args)
    def complete(self):
        r = self.reserve()
        self.store.complete(r, audio=mp3())
        return r
    def assertCode(self, code, call):
        with self.assertRaises(StoreError) as caught:
            call()
        self.assertEqual(caught.exception.code, code)
    def test_uncertain_before_any_provider_call(self):
        r = self.reserve()
        self.assertTrue(r.should_generate)
        self.assertEqual(r.status, "uncertain")
        self.assertIsNone(self.store.get_cached(scope=r.scope, operation_id=r.operation_id))
    def test_restart_no_resend_even_new_operation_id(self):
        r = self.reserve()
        for identifier in (op(), op("new invocation")):
            again = self.reserve(self.make(), operation_id=identifier)
            self.assertFalse(again.should_generate)
            self.assertIsNone(again.claim)
            self.assertEqual(again.status, "uncertain")
        self.assertEqual(self.store.usage(scope=r.scope)["scope_characters_reserved"], len(TEXT))
    def test_actual_process_crash_keeps_reservation(self):
        ctx = multiprocessing.get_context("spawn")
        child = ctx.Process(target=child_crash, args=(str(self.root),))
        child.start()
        child.join(timeout=30)
        self.assertEqual(child.exitcode, 42)
        again = self.reserve(self.make())
        self.assertFalse(again.should_generate)
        self.assertEqual(again.status, "uncertain")
    def test_crash_after_file_replace_before_database_commit(self):
        r = self.reserve()
        real_replace = os.replace
        def replace_then_crash(source, target):
            real_replace(source, target)
            raise OSError("synthetic crash")
        with patch("voice_store.os.replace", side_effect=replace_then_crash):
            with self.assertRaises(OSError):
                self.store.complete(r, audio=mp3())
        other = self.make()
        self.assertIsNone(other.get_cached(scope=r.scope, operation_id=r.operation_id))
        self.assertFalse(self.reserve(other, operation_id=op("another invocation")).should_generate)
        self.assertEqual(other.operation(scope=r.scope, operation_id=r.operation_id).status, "uncertain")
    def test_complete_and_repeat_completion(self):
        r = self.complete()
        self.assertEqual(self.store.complete(r, audio=mp3()).status, "complete")
        self.assertEqual(self.store.get_cached(scope=r.scope, operation_id=r.operation_id).audio, mp3())
        self.assertFalse(self.reserve().should_generate)
    def test_cache_reuse_no_second_charge(self):
        first = self.complete()
        second = self.reserve(operation_id=op("second"))
        self.assertEqual(first.cache_key, second.cache_key)
        self.assertFalse(second.should_generate)
        self.assertEqual(second.status, "complete")
        self.assertEqual(self.store.usage(scope=first.scope)["scope_characters_reserved"], len(TEXT))
    def test_cross_scope_isolation(self):
        one = self.complete()
        self.assertIsNone(self.store.get_cached(scope="another_scope", operation_id=op()))
        two = self.reserve(scope="another_scope")
        self.assertNotEqual(one.cache_key, two.cache_key)
        self.assertTrue(two.should_generate)
    def test_each_read_rechecks_authorization(self):
        r = self.complete()
        self.store.get_cached(scope=r.scope, operation_id=r.operation_id)
        self.assertEqual(self.calls.count((r.scope, "read")), 2)
        self.allowed = False
        self.assertCode("scope_not_authorized", lambda: self.store.get_cached(scope=r.scope, operation_id=r.operation_id))
    def test_revocation_during_read(self):
        r, reads = self.complete(), []
        def once(scope, action):
            if action == "read":
                reads.append(True)
                return len(reads) == 1
            return True
        other = self.make(authorize=once)
        self.assertCode("scope_not_authorized", lambda: other.get_cached(scope=r.scope, operation_id=r.operation_id))
    def test_authorizer_error_fail_closed(self):
        def fail(scope, action):
            raise RuntimeError("do not echo upstream data")
        self.assertCode("scope_not_authorized", lambda: self.reserve(self.make(authorize=fail)))
    def test_persistent_global_month_budget(self):
        self.reserve(text="x" * 600)
        self.assertCode("monthly_character_budget_exceeded", lambda: self.reserve(self.make(), text="y" * 401, scope="another", operation_id=op("two")))
        self.assertEqual(self.store.usage(scope="another")["scope_characters_reserved"], 0)
    def test_month_rollover_preserves_old_uncertainty(self):
        self.reserve(text="x" * 1000)
        self.now = datetime(2026, 11, 1, tzinfo=timezone.utc)
        self.assertTrue(self.reserve(text="y" * 1000, operation_id=op("new month")).should_generate)
        old = self.reserve(text="x" * 1000)
        self.assertFalse(old.should_generate)
        self.assertEqual(old.period, "2026-10")
    def test_mismatched_policy_denied(self):
        self.assertCode("budget_or_schema_policy_mismatch", lambda: self.make(budget=2000))
    def test_operation_changed_payload_denied(self):
        self.reserve()
        self.assertCode("idempotency_conflict", lambda: self.reserve(text="Different text"))
    def test_cache_key_covers_all_fields(self):
        original = self.reserve()
        changes = [{"voice_id": "different_voice_0123456789"}, {"model_id": "other_model"}, {"settings": {"stability": .4}}, {"text": TEXT + "!"}]
        for index, change in enumerate(changes):
            r = self.reserve(operation_id=op(str(index)), **change)
            self.assertNotEqual(r.cache_key, original.cache_key)
    def test_settings_canonical_order(self):
        one = self.reserve(settings={"style": .2, "stability": .5})
        two = self.reserve(operation_id=op("second"), settings={"stability": .5, "style": .2})
        self.assertEqual(one.cache_key, two.cache_key)
        self.assertFalse(two.should_generate)
    def test_no_arbitrary_settings_or_secret(self):
        for settings in ({"api_key": "synthetic secret"}, {"speed": float("nan")}, {"style": "bad"}, {"seed": True}, {"use_speaker_boost": 1}):
            self.assertCode("invalid_settings", lambda: self.reserve(settings=settings))
    def test_database_does_not_store_raw_text_or_claim(self):
        r = self.reserve()
        raw = self.store.database.read_bytes()
        self.assertNotIn(TEXT.encode(), raw)
        self.assertNotIn(r.claim.encode(), raw)
        self.assertNotIn(r.claim, repr(r))
    def test_invalid_audio_preserves_uncertainty(self):
        r = self.reserve()
        for data in (b"ID3fake", b"<html>not audio</html>", mp3()[:-1], b"\xff\xe0" + b"X" * 400):
            self.assertCode("invalid_audio_uncertain", lambda: self.store.complete(r, audio=data))
        self.assertEqual(self.store.operation(scope=r.scope, operation_id=r.operation_id).status, "uncertain")
        self.assertFalse(self.reserve().should_generate)
    def test_content_type_and_claim(self):
        r = self.reserve()
        self.assertCode("invalid_audio_uncertain", lambda: self.store.complete(r, audio=mp3(), content_type="text/html"))
        self.assertCode("generation_claim_required", lambda: self.store.complete(replace(r, claim=None), audio=mp3()))
        self.assertCode("generation_claim_invalid", lambda: self.store.complete(replace(r, claim="0" * 64), audio=mp3()))
    def test_tampered_audio_no_return_no_regeneration(self):
        r = self.complete()
        (self.store.cache / (r.cache_key + ".mp3")).write_bytes(mp3() + b"bad")
        self.assertCode("cached_audio_corrupt", lambda: self.store.get_cached(scope=r.scope, operation_id=r.operation_id))
        self.assertFalse(self.reserve().should_generate)
    def test_scope_traversal_denied(self):
        for scope in ("../secret", "/root", "", "x" * 129):
            self.assertCode("invalid_scope", lambda: self.reserve(scope=scope))
    def test_thread_duplicate_single_ticket(self):
        def call(i):
            return self.reserve(self.make(), operation_id=op(str(i))).should_generate
        with ThreadPoolExecutor(max_workers=8) as workers:
            results = list(workers.map(call, range(24)))
        self.assertEqual(sum(results), 1)
        self.assertEqual(self.store.usage(scope="mission_test")["scope_characters_reserved"], len(TEXT))
    def test_thread_budget_race(self):
        def call(i):
            try:
                return self.reserve(self.make(), operation_id=op(str(i)), text=str(i) + "x" * 299).should_generate
            except StoreError as exc:
                self.assertEqual(exc.code, "monthly_character_budget_exceeded")
                return False
        with ThreadPoolExecutor(max_workers=8) as workers:
            results = list(workers.map(call, range(8)))
        self.assertEqual(sum(results), 3)
        self.assertEqual(self.store.usage(scope="mission_test")["scope_characters_reserved"], 900)
    def test_process_duplicate_single_ticket(self):
        ctx = multiprocessing.get_context("spawn")
        queue = ctx.Queue()
        processes = [ctx.Process(target=child_reserve, args=(str(self.root), i, queue)) for i in range(4)]
        for p in processes:
            p.start()
        results = [queue.get(timeout=30) for p in processes]
        for p in processes:
            p.join(timeout=30)
            self.assertEqual(p.exitcode, 0)
        self.assertEqual(sum(results), 1)
    @unittest.skipUnless(os.name == "posix", "Linux deployment permissions")
    def test_linux_modes(self):
        r = self.complete()
        for path in (self.store.root, self.store.cache):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700)
        for path in (self.store.database, self.store.cache / (r.cache_key + ".mp3")):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
    @unittest.skipUnless(os.name == "posix", "Linux symlink protection")
    def test_cache_symlink_denied(self):
        r = self.complete()
        path = self.store.cache / (r.cache_key + ".mp3")
        path.unlink()
        path.symlink_to(self.store.database)
        self.assertCode("unsafe_storage_path", lambda: self.store.get_cached(scope=r.scope, operation_id=r.operation_id))
    def test_mp3_validation_frames_tags_truncation_payload(self):
        self.assertTrue(valid_mp3(mp3()))
        self.assertTrue(valid_mp3(b"ID3\x04\x00\x00\x00\x00\x00\x00" + mp3()))
        self.assertFalse(valid_mp3(b"ID3" + b"X" * 900))
        self.assertFalse(valid_mp3(mp3() + b"<script>"))
        self.assertFalse(valid_mp3(mp3(), maximum_bytes=100))

if __name__ == "__main__":
    unittest.main()
