"""Offline real-child process tests. Stub children never perform network IO."""
from concurrent.futures import ThreadPoolExecutor
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "provider"))
from elevenlabs_client import VoiceError, VoiceRequest
import hard_deadline_transport as h

KEY = "synthetic_key_NEVER_TRANSMIT_012345"
VOICE = "synthetic_voice_0123456789"
URL = "https://api.elevenlabs.io/v1/text-to-speech/" + VOICE + "?output_format=mp3_44100_128"
STUB = r'''
import sys,json,base64,time
mode=MODE
if mode=='no_read':
    time.sleep(30)
p=json.loads(sys.stdin.buffer.read())
if mode=='hang':
    time.sleep(30)
elif mode=='slow':
    time.sleep(.25)
    sys.stdout.write(json.dumps({'status':200,'final_url':p['url'],'content_type':'audio/mpeg','audio_b64':base64.b64encode(b'ID3synthetic').decode()}))
elif mode=='malformed':
    sys.stdout.write(p['headers']['xi-api-key']+' NOT JSON')
elif mode=='oversize':
    sys.stdout.buffer.write(b'x'*30000)
elif mode=='bad_audio':
    sys.stdout.write(json.dumps({'status':200,'final_url':p['url'],'content_type':'audio/mpeg','audio_b64':base64.b64encode(b'x'*3000).decode()}))
elif mode=='wrong_origin':
    sys.stdout.write(json.dumps({'status':200,'final_url':'https://invalid.example/','content_type':'audio/mpeg','audio_b64':''}))
elif mode=='stderr':
    sys.stderr.write(p['headers']['xi-api-key'])
    sys.exit(5)
elif mode=='no_read':
    time.sleep(30)
else:
    sys.stdout.write(json.dumps({'status':200,'final_url':p['url'],'content_type':'audio/mpeg','audio_b64':base64.b64encode(b'ID3synthetic').decode()}))
'''

class TransportTests(unittest.TestCase):
    def setUp(self):
        self.script_sha = hashlib.sha256(h._SCRIPT.read_bytes()).hexdigest()
        self.provider_sha = hashlib.sha256(h._PROVIDER.read_bytes()).hexdigest()
        self.transport = h.HardDeadlineProcessTransport(expected_script_sha256=self.script_sha, expected_provider_sha256=self.provider_sha)
        self.request = VoiceRequest(URL, {"xi-api-key": KEY, "Content-Type": "application/json", "Accept": "audio/mpeg"},
            json.dumps({"text": "Je vérifie le menu.", "model_id": "eleven_multilingual_v2"}).encode())
        self.real_popen, self.children, self.launches = subprocess.Popen, [], []
    def spawn(self, mode):
        def launch(args, **kwargs):
            self.launches.append((args, kwargs))
            child = self.real_popen([sys.executable, "-I", "-B", "-c", STUB.replace("MODE", repr(mode))], **kwargs)
            self.children.append(child)
            return child
        return patch("hard_deadline_transport.subprocess.Popen", side_effect=launch)
    def send(self, **changes):
        options = dict(timeout_seconds=2, max_response_bytes=1024, follow_redirects=False)
        options.update(changes)
        return self.transport.send(self.request, **options)
    def assertFailure(self, code, **options):
        with self.assertRaises(VoiceError) as caught:
            self.send(**options)
        self.assertEqual(caught.exception.code, code)
        self.assertTrue(caught.exception.outcome_uncertain)
        self.assertNotIn(KEY, str(caught.exception))
        self.assertNotIn(KEY, repr(caught.exception))
        return caught.exception
    def test_success_real_child_fixed_options_secret_not_argv_or_env(self):
        with self.spawn("success"):
            result = self.send()
        self.assertEqual(result.audio, b"ID3synthetic")
        self.assertEqual(result.final_url, URL)
        argv, options = self.launches[0]
        self.assertEqual(argv[1:], ["-I", "-B", str(h._SCRIPT), "--worker"])
        self.assertIs(options["shell"], False)
        self.assertIs(options["close_fds"], True)
        self.assertEqual(options["stderr"], subprocess.DEVNULL)
        self.assertNotIn(KEY, repr(argv))
        self.assertNotIn(KEY, repr(options))
        self.assertNotIn("PYTHONPATH", options["env"])
        self.assertNotIn("PATH", options["env"])
        self.assertNotIn(KEY, repr(result))
    def test_parent_kills_hung_child_with_global_deadline(self):
        start = time.monotonic()
        with self.spawn("hang"):
            self.assertFailure("process_deadline_exceeded", timeout_seconds=.3)
        elapsed = time.monotonic() - start
        self.assertLess(elapsed, 2.5)
        self.assertIsNotNone(self.children[0].poll())
        self.assertEqual(len(self.children), 1)
    def test_slow_response_inside_global_deadline(self):
        with self.spawn("slow"):
            self.assertEqual(self.send(timeout_seconds=2).status, 200)
    def test_startup_time_is_inside_same_global_deadline(self):
        def delayed_spawn(args, **kwargs):
            time.sleep(.25)
            child = self.real_popen([sys.executable, "-I", "-B", "-c", STUB.replace("MODE", repr("hang"))], **kwargs)
            self.children.append(child)
            return child
        started = time.monotonic()
        with patch("hard_deadline_transport.subprocess.Popen", side_effect=delayed_spawn):
            self.assertFailure("process_deadline_exceeded", timeout_seconds=.3)
        self.assertLess(time.monotonic() - started, .9)
        self.assertEqual(len(self.children), 1)
        self.assertIsNotNone(self.children[0].poll())
    def test_child_not_reading_stdin_cannot_hold_parent(self):
        self.request = VoiceRequest(URL, self.request.headers,
            json.dumps({"text": "é" * 2000, "model_id": "eleven_multilingual_v2"}).encode())
        started = time.monotonic()
        with self.spawn("no_read"):
            self.assertFailure("process_deadline_exceeded", timeout_seconds=.3)
        self.assertLess(time.monotonic() - started, 2.5)
        self.assertIsNotNone(self.children[0].poll())
    def test_no_secret_from_malformed_stdout(self):
        with self.spawn("malformed"):
            self.assertFailure("process_response_invalid")
    def test_stderr_never_returned(self):
        with self.spawn("stderr"):
            self.assertFailure("process_transport_failed")
    def test_stdout_is_bounded_and_child_killed(self):
        with self.spawn("oversize"):
            self.assertFailure("process_response_size_exceeded")
        self.assertIsNotNone(self.children[0].poll())
    def test_decoded_audio_bound_is_enforced(self):
        with self.spawn("bad_audio"):
            self.assertFailure("process_response_invalid")
    def test_redirect_origin_rejected(self):
        with self.spawn("wrong_origin"):
            self.assertFailure("process_response_invalid")
    def test_constructor_requires_both_pins(self):
        for first, second in (("0" * 64, self.provider_sha), (self.script_sha, "0" * 64)):
            with self.assertRaisesRegex(ValueError, "^transport_source_integrity_failed$"):
                h.HardDeadlineProcessTransport(expected_script_sha256=first, expected_provider_sha256=second)
    def test_sources_rechecked_before_every_child(self):
        with patch("hard_deadline_transport._source_ok", return_value=False), patch("hard_deadline_transport.subprocess.Popen") as popen:
            with self.assertRaises(VoiceError) as caught:
                self.send()
        self.assertEqual(caught.exception.code, "transport_source_integrity_failed")
        popen.assert_not_called()
    def test_invalid_endpoint_and_headers_never_spawn(self):
        for request in (VoiceRequest("https://attacker.invalid/", self.request.headers, self.request.body),
                        VoiceRequest(URL, {**self.request.headers, "X-Extra": "bad"}, self.request.body)):
            with patch("hard_deadline_transport.subprocess.Popen") as popen:
                with self.assertRaises(VoiceError) as caught:
                    self.transport.send(request, timeout_seconds=1, max_response_bytes=1024)
                self.assertEqual(caught.exception.code, "invalid_process_transport_request")
                popen.assert_not_called()
    def test_invalid_options_never_spawn(self):
        for changes in ({"timeout_seconds": float("nan")}, {"timeout_seconds": 31}, {"max_response_bytes": 8 * 1024 * 1024 + 1}, {"follow_redirects": True}):
            with patch("hard_deadline_transport.subprocess.Popen") as popen:
                with self.assertRaises(VoiceError):
                    self.send(**changes)
                popen.assert_not_called()
    def test_concurrent_exact_children_not_global_kill(self):
        with self.spawn("hang"):
            def run(index):
                try:
                    self.send(timeout_seconds=.4)
                except VoiceError as exc:
                    return exc.code
            with ThreadPoolExecutor(max_workers=4) as workers:
                results = list(workers.map(run, range(4)))
        self.assertEqual(results, ["process_deadline_exceeded"] * 4)
        self.assertEqual(len(self.children), 4)
        self.assertTrue(all(child.poll() is not None for child in self.children))
        self.assertEqual(len(set(child.pid for child in self.children)), 4)
    def test_timeout_does_not_kill_unrelated_process(self):
        unrelated = self.real_popen([sys.executable, "-I", "-B", "-c", "import time; time.sleep(30)"],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            with self.spawn("hang"):
                self.assertFailure("process_deadline_exceeded", timeout_seconds=.3)
            self.assertIsNone(unrelated.poll())
        finally:
            unrelated.kill()
            unrelated.wait(timeout=3)
    def test_real_worker_bad_endpoint_emits_fixed_error_without_secret(self):
        packet = {"version": 1, "script_sha256": self.script_sha, "provider_sha256": self.provider_sha,
            "url": "https://attacker.invalid/", "headers": self.request.headers,
            "body_b64": base64.b64encode(self.request.body).decode(), "timeout_seconds": 1, "max_response_bytes": 1024}
        child = self.real_popen([sys.executable, "-I", "-B", str(h._SCRIPT), "--worker"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=h._minimal_env())
        out, err = child.communicate(json.dumps(packet).encode(), timeout=3)
        self.assertEqual(child.returncode, 2)
        self.assertEqual(json.loads(out), {"error": "worker_failed"})
        self.assertNotIn(KEY.encode(), out)
        self.assertEqual(err, b"")

if __name__ == "__main__":
    unittest.main()
