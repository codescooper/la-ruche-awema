"""Fake transport only. No provider account, key, network or audio audition."""
import hashlib
import io
import json
import threading
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from elevenlabs_client import (API_BASE, OUTPUT_FORMAT, ElevenLabsClient,
    VoiceConfig, VoiceError, VoiceRequest, VoiceResponse, UrllibNoRedirectTransport, _NoRedirect)

VOICE = "test_voice_0123456789"
KEY = "synthetic_key_DO_NOT_TRANSMIT"
TEXT = "J’ai compilé les trois fichiers et remis le site à Vérification."
OP = hashlib.sha256(b"test-operation").hexdigest()


class FakeTransport:
    def __init__(self, action=None): self.calls, self.action = [], action
    def send(self, request, **options):
        self.calls.append((request, options))
        if self.action: return self.action(request, options)
        return VoiceResponse(200, request.url, "audio/mpeg", b"ID3synthetic")


class ClientTests(unittest.TestCase):
    def make(self, transport=None, **changes):
        values = dict(enabled=True, allowed_voice_ids=frozenset({VOICE}), max_total_characters=1000)
        values.update(changes)
        self.transport = transport or FakeTransport()
        return ElevenLabsClient(VoiceConfig(**values), api_key=KEY, transport=self.transport)
    def call(self, client, **changes):
        args = dict(operation_id=OP, voice_id=VOICE, text=TEXT)
        args.update(changes)
        return client.generate(**args)
    def error(self, code, client, **changes):
        with self.assertRaises(VoiceError) as caught: self.call(client, **changes)
        self.assertEqual(caught.exception.code, code)
        return caught.exception
    def test_disabled_by_default_no_request(self):
        c = ElevenLabsClient(transport=FakeTransport())
        self.error("provider_disabled", c)
        self.assertEqual(c.characters_reserved, 0)
    def test_explicit_transport_required(self):
        self.error("transport_not_configured", ElevenLabsClient(VoiceConfig(enabled=True), api_key=KEY))
    def test_key_required_never_echoed(self):
        c = ElevenLabsClient(VoiceConfig(enabled=True), transport=FakeTransport())
        self.assertNotIn(KEY, str(self.error("provider_key_missing_or_invalid", c)))
    def test_header_injection_key_denied(self):
        c = self.make(); c._api_key = KEY + "\r\nmalicious: value"
        self.error("provider_key_missing_or_invalid", c)
        self.assertEqual(self.transport.calls, [])
    def test_url_body_and_bound_options(self):
        result = self.call(self.make()); req, opt = self.transport.calls[0]
        self.assertEqual(req.url, API_BASE + VOICE + "?output_format=" + OUTPUT_FORMAT)
        self.assertEqual(req.headers["xi-api-key"], KEY)
        self.assertEqual(json.loads(req.body), {"text": TEXT, "model_id": "eleven_multilingual_v2"})
        self.assertIs(opt["follow_redirects"], False)
        self.assertEqual(opt["timeout_seconds"], 15.0)
        self.assertEqual(result.characters_reserved, len(TEXT))
        self.assertEqual(result.text_sha256, hashlib.sha256(TEXT.encode()).hexdigest())
    def test_repr_no_key_text_or_audio(self):
        c = self.make(); result = self.call(c); req, _ = self.transport.calls[0]
        for value in (c, result, req):
            self.assertNotIn(KEY, repr(value)); self.assertNotIn(TEXT, repr(value))
            self.assertNotIn("ID3synthetic", repr(value))
    def test_voice_allowlist(self):
        self.error("voice_not_allowed", self.make(), voice_id="other_voice_0123456789")
        self.assertFalse(self.transport.calls)
    def test_voice_path_injection(self):
        for v in (VOICE + "/../", "https://attacker.invalid/a", VOICE + "?x=y"):
            self.error("voice_not_allowed", self.make(), voice_id=v)
    def test_model_allowlist(self):
        self.error("model_not_allowed", self.make(), model_id="arbitrary_model")
    def test_operation_requires_sha(self):
        self.error("invalid_operation_id", self.make(), operation_id="../../secret")
    def test_empty_control_surrogate_and_nonstring_text_denied(self):
        for text in ("  ", "a\0b", "a\ud800b", {"text": "x"}):
            self.error("narration_invalid_or_too_large", self.make(), text=text)
    def test_request_text_limit(self):
        self.error("narration_invalid_or_too_large", self.make(max_request_characters=5))
    def test_zero_budget_blocks_without_network(self):
        self.error("character_budget_exceeded", self.make(max_total_characters=0))
        self.assertFalse(self.transport.calls)
    def test_budget_enforced_for_following_operation(self):
        c = self.make(max_total_characters=len(TEXT)); self.call(c)
        self.error("character_budget_exceeded", c, operation_id="f" * 64)
        self.assertEqual(len(self.transport.calls), 1)
    def test_duplicate_not_sent(self):
        c = self.make(); self.call(c); self.error("operation_already_attempted", c)
        self.assertEqual(len(self.transport.calls), 1)
    def test_timeout_uncertain_not_retried_and_reservation_retained(self):
        def timeout(*_): raise TimeoutError(KEY + TEXT)
        c = self.make(FakeTransport(timeout)); e = self.error("provider_outcome_uncertain", c)
        self.assertTrue(e.outcome_uncertain); self.assertIsNone(e.__context__); self.assertIsNone(e.__cause__)
        self.error("operation_already_attempted", c)
        self.assertEqual(c.characters_reserved, len(TEXT)); self.assertEqual(len(self.transport.calls), 1)
    def test_arbitrary_transport_error_is_sanitized(self):
        def fail(*_): raise RuntimeError(KEY + TEXT)
        e = self.error("provider_outcome_uncertain", self.make(FakeTransport(fail)))
        self.assertNotIn(KEY, str(e)); self.assertNotIn(TEXT, str(e)); self.assertIsNone(e.__context__)
    def test_elapsed_deadline_rejects_late_audio(self):
        c = self.make(); c._clock = iter((0, 16)).__next__
        self.error("provider_deadline_exceeded", c)
    def test_changed_final_url_denied(self):
        f = FakeTransport(lambda r, _: VoiceResponse(200, "https://other.invalid/", "audio/mpeg", b"ID3x"))
        self.error("provider_redirect_forbidden", self.make(f))
    def test_http_errors_and_redirects_never_retried(self):
        for status in (301, 302, 307, 400, 401, 403, 429, 500, 503):
            f = FakeTransport(lambda r, _, s=status: VoiceResponse(s, r.url, "", b""))
            self.error("provider_response_rejected", self.make(f)); self.assertEqual(len(f.calls), 1)
    def test_invalid_audio_type_length_and_signature_denied(self):
        for ct, audio in (("text/html", b"ID3x"), ("audio/mpeg", b""),
                ("audio/mpeg", b'{"error":"x"}'), ("audio/mpeg", b"ID3" + b"x" * 1024)):
            f = FakeTransport(lambda r, _, c=ct, a=audio: VoiceResponse(200, r.url, c, a))
            self.error("provider_audio_invalid", self.make(f, max_audio_bytes=1024))
    def test_mp3_frame_header_accepted(self):
        f = FakeTransport(lambda r, _: VoiceResponse(200, r.url, "audio/mpeg; q=1", b"\xff\xfb\x90\x00"))
        self.assertEqual(self.call(self.make(f)).mime, "audio/mpeg")
    def test_invalid_configuration_values(self):
        cases = (dict(enabled="yes"), dict(allowed_voice_ids=frozenset({"bad/path"})),
            dict(allowed_model_ids=frozenset({"arbitrary"})), dict(timeout_seconds=float("nan")),
            dict(timeout_seconds=31), dict(max_total_characters=-1),
            dict(max_request_characters=2001), dict(max_audio_bytes=1))
        for values in cases:
            with self.subTest(values=values), self.assertRaises(VoiceError): VoiceConfig(**values)
    def test_concurrent_same_operation_sent_once(self):
        c = self.make(); outcomes = []
        def run():
            try: self.call(c); outcomes.append("ok")
            except VoiceError as e: outcomes.append(e.code)
        threads = [threading.Thread(target=run) for _ in range(10)]
        for t in threads: t.start()
        for t in threads: t.join()
        self.assertEqual(outcomes.count("ok"), 1)
        self.assertEqual(outcomes.count("operation_already_attempted"), 9)
        self.assertEqual(len(self.transport.calls), 1)
    def test_redirect_handler_never_constructs_redirect_request(self):
        self.assertIsNone(_NoRedirect().redirect_request(None, None, 302, "", {}, "https://other.invalid/"))
    def test_real_transport_not_used_by_fake_tests(self):
        with patch.object(UrllibNoRedirectTransport, "send", side_effect=AssertionError("no real calls")):
            self.call(self.make())


class TransportTests(unittest.TestCase):
    def request(self):
        return VoiceRequest(API_BASE + VOICE + "?output_format=" + OUTPUT_FORMAT,
                            {"xi-api-key": KEY}, b'{"text":"synthetic"}')
    def send(self, request=None):
        return UrllibNoRedirectTransport().send(request or self.request(),
            timeout_seconds=2, max_response_bytes=1024, follow_redirects=False)
    def test_fixed_url_no_arbitrary_path_or_query(self):
        with patch("elevenlabs_client.build_opener") as factory:
            for url in ("https://other.invalid/", API_BASE + VOICE + "/extra",
                        API_BASE + VOICE + "?output_format=wav"):
                with self.assertRaises(VoiceError) as caught:
                    self.send(VoiceRequest(url, {}, b""))
                self.assertEqual(caught.exception.code, "invalid_endpoint")
            factory.assert_not_called()
    def test_mocked_opener_post_no_proxy_and_bounded_read(self):
        url = self.request().url
        class Response(io.BytesIO):
            status, headers = 200, {"Content-Type": "audio/mpeg"}
            def geturl(self): return url
        response = Response(b"ID3mocked")
        class Opener:
            def open(this, req, timeout):
                self.assertEqual(req.method, "POST")
                self.assertEqual(req.full_url, url)
                self.assertEqual(timeout, 2)
                return response
        with patch("elevenlabs_client.build_opener", return_value=Opener()) as factory:
            result = self.send()
        self.assertEqual(result.audio, b"ID3mocked")
        handlers = factory.call_args.args
        self.assertEqual(handlers[0].proxies, {})
        self.assertIsInstance(handlers[2], _NoRedirect)
        self.assertTrue(response.closed)
    def test_http_error_body_not_read_or_returned(self):
        class ForbiddenBody(io.BytesIO):
            def read(self, *args): raise AssertionError("error body must not be read")
        exc = HTTPError(self.request().url, 429, KEY + TEXT, {}, ForbiddenBody())
        with patch("elevenlabs_client.build_opener") as factory:
            factory.return_value.open.side_effect = exc
            result = self.send()
        self.assertEqual(result.status, 429)
        self.assertEqual(result.audio, b"")
        self.assertNotIn(KEY, repr(result))
    def test_mocked_opener_error_is_sanitized_without_context(self):
        with patch("elevenlabs_client.build_opener") as factory:
            factory.return_value.open.side_effect = TimeoutError(KEY + TEXT)
            with self.assertRaises(VoiceError) as caught: self.send()
        self.assertNotIn(KEY, str(caught.exception))
        self.assertNotIn(TEXT, str(caught.exception))
        self.assertIsNone(caught.exception.__context__)
    def test_mocked_redirect_final_url_rejected_before_read(self):
        class Response:
            def geturl(self): return "https://other.invalid/"
            def read(self, *_): raise AssertionError("must not read changed origin")
            def close(self): pass
        with patch("elevenlabs_client.build_opener") as factory:
            factory.return_value.open.return_value = Response()
            with self.assertRaises(VoiceError) as caught: self.send()
        self.assertEqual(caught.exception.code, "unexpected_response_origin")


if __name__ == "__main__": unittest.main()
