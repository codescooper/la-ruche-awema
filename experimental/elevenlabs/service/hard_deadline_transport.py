"""ElevenLabs transport with a parent-enforced, process-wide deadline.

No IO/network on import. Deployment supplies SHA256 pins for this exact file and
the sibling provider/elevenlabs_client.py. Both must be immutable to the runtime
user (root-owned read-only deployment); hashes alone do not defeat a hostile
same-user filesystem race. Worker/interpreter paths cannot be caller-selected.

The fixed child runs the existing no-redirect/no-proxy transport. Request headers
(including API key) enter ONLY over a private stdin pipe, never argv/env/file/log.
Worker stderr is DEVNULL. Parent stdout capture is bounded; stderr and malformed
payloads are never returned. Deadline covers startup, DNS, TLS and body transfer.
On timeout/overflow/bad response only the exact Popen child is killed, with no
retry. OS process scheduling/termination still applies; cleanup wait <= 1 second.
The worker does not spawn other processes. The provider can bill an interrupted
request: all post-spawn failures are outcome_uncertain=True.
"""
from __future__ import annotations
import base64
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import threading
import time

_SCRIPT = Path(__file__).resolve()
_PROVIDER = _SCRIPT.parent.parent / "provider" / "elevenlabs_client.py"
_PYTHON = str(Path(sys.executable).resolve())
_MAX_AUDIO = 8 * 1024 * 1024
_MAX_INPUT = 64 * 1024
_MAX_BODY = 16 * 1024
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_URL = re.compile(r"https://api\.elevenlabs\.io/v1/text-to-speech/[A-Za-z0-9_-]{16,64}\?output_format=mp3_44100_128\Z")


def _source_ok(path, expected):
    if type(expected) is not str or not _SHA.fullmatch(expected):
        return False
    try:
        st = path.lstat()
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_size > 256 * 1024:
            return False
        if os.name == "posix" and st.st_mode & 0o022:
            return False
        return hashlib.sha256(path.read_bytes()).hexdigest() == expected
    except Exception:
        return False


def _load_provider():
    # Trusted path only, never import from PYTHONPATH/current directory.
    spec = importlib.util.spec_from_file_location("_awema_elevenlabs_pinned", _PROVIDER)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _valid_request(url, headers, body):
    if type(url) is not str or not _URL.fullmatch(url):
        return False
    if type(headers) is not dict or set(headers) != {"xi-api-key", "Content-Type", "Accept"}:
        return False
    key = headers.get("xi-api-key")
    if (type(key) is not str or not 16 <= len(key) <= 512
            or any(ord(c) < 33 or ord(c) > 126 for c in key)
            or headers.get("Content-Type") != "application/json" or headers.get("Accept") != "audio/mpeg"):
        return False
    if type(body) is not bytes or not 1 <= len(body) <= _MAX_BODY:
        return False
    try:
        data = json.loads(body)
        return (type(data) is dict and set(data) == {"text", "model_id"}
                and data["model_id"] == "eleven_multilingual_v2"
                and type(data["text"]) is str and 1 <= len(data["text"]) <= 2000
                and data["text"].strip()
                and not any((ord(c) < 32 and c not in "\n\t") or 0xD800 <= ord(c) <= 0xDFFF for c in data["text"]))
    except Exception:
        return False


def _minimal_env():
    environment = {"LANG": "C.UTF-8"}
    if os.name == "nt":
        # CPython/Windows need the OS directory; never inherit PATH, HOME,
        # PYTHONPATH, proxy/cert overrides or provider credentials.
        value = os.environ.get("SystemRoot") or os.environ.get("SYSTEMROOT")
        if value:
            environment["SystemRoot"] = value
    return environment


def _stop_exact_child(process):
    try:
        if process.poll() is None:
            process.kill()
    except Exception:
        pass
    try:
        process.wait(timeout=1.0)
    except Exception:
        pass


class HardDeadlineProcessTransport:
    hard_deadline = True

    def __init__(self, *, expected_script_sha256, expected_provider_sha256):
        if not _source_ok(_SCRIPT, expected_script_sha256) or not _source_ok(_PROVIDER, expected_provider_sha256):
            raise ValueError("transport_source_integrity_failed")
        self._script_sha = expected_script_sha256
        self._provider_sha = expected_provider_sha256

    def __repr__(self):
        return "HardDeadlineProcessTransport(pinned_sources=True, secrets=redacted)"

    def send(self, request, *, timeout_seconds, max_response_bytes, follow_redirects=False):
        # Import the public response/error types for compatibility with the client.
        from elevenlabs_client import VoiceError, VoiceResponse
        if (type(timeout_seconds) not in (int, float) or not math.isfinite(timeout_seconds)
                or not .1 <= timeout_seconds <= 30 or type(max_response_bytes) is not int
                or not 1 <= max_response_bytes <= _MAX_AUDIO or follow_redirects is not False):
            raise VoiceError("invalid_process_transport_options")
        if (not _source_ok(_SCRIPT, self._script_sha) or not _source_ok(_PROVIDER, self._provider_sha)):
            raise VoiceError("transport_source_integrity_failed")
        if not _valid_request(getattr(request, "url", None), getattr(request, "headers", None), getattr(request, "body", None)):
            raise VoiceError("invalid_process_transport_request")
        packet = json.dumps({"version": 1, "script_sha256": self._script_sha, "provider_sha256": self._provider_sha,
            "url": request.url, "headers": request.headers, "body_b64": base64.b64encode(request.body).decode("ascii"),
            "timeout_seconds": timeout_seconds, "max_response_bytes": max_response_bytes},
            ensure_ascii=True, separators=(",", ":")).encode("utf-8")
        if len(packet) > _MAX_INPUT:
            raise VoiceError("process_request_size_exceeded")
        # Base64 max size + bounded metadata. Capture never grows past this bound.
        output_limit = 4 * ((max_response_bytes + 2) // 3) + 8192
        deadline = time.monotonic() + timeout_seconds
        process, threads = None, []
        result = {"chunks": [], "size": 0, "overflow": False, "read_error": False, "write_error": False}
        finished = threading.Event()
        try:
            try:
                process = subprocess.Popen([_PYTHON, "-I", "-B", str(_SCRIPT), "--worker"],
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                    shell=False, close_fds=True, env=_minimal_env(), cwd=str(_SCRIPT.parent),
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0)
            except Exception:
                raise VoiceError("process_start_failed", outcome_uncertain=True) from None

            def write_request():
                try:
                    process.stdin.write(packet)
                    process.stdin.close()
                except Exception:
                    result["write_error"] = True

            def read_response():
                try:
                    while True:
                        block = process.stdout.read(min(65536, output_limit + 1 - result["size"]))
                        if not block:
                            break
                        result["size"] += len(block)
                        if result["size"] > output_limit:
                            result["overflow"] = True
                            break
                        result["chunks"].append(block)
                except Exception:
                    result["read_error"] = True
                finally:
                    finished.set()

            threads = [threading.Thread(target=read_response, daemon=True), threading.Thread(target=write_request, daemon=True)]
            for thread in threads:
                thread.start()
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not finished.wait(remaining):
                raise VoiceError("process_deadline_exceeded", outcome_uncertain=True)
            if result["overflow"]:
                raise VoiceError("process_response_size_exceeded", outcome_uncertain=True)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise VoiceError("process_deadline_exceeded", outcome_uncertain=True)
            try:
                return_code = process.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                raise VoiceError("process_deadline_exceeded", outcome_uncertain=True) from None
            if return_code != 0 or result["read_error"] or result["write_error"]:
                raise VoiceError("process_transport_failed", outcome_uncertain=True)
            # Never echo raw stdout, including malformed JSON/upstream bodies.
            try:
                payload = json.loads(b"".join(result["chunks"]))
                if type(payload) is not dict or set(payload) != {"status", "final_url", "content_type", "audio_b64"}:
                    raise ValueError()
                if (type(payload["status"]) is not int or not 100 <= payload["status"] <= 599
                        or payload["final_url"] != request.url or type(payload["content_type"]) is not str
                        or len(payload["content_type"]) > 128 or type(payload["audio_b64"]) is not str):
                    raise ValueError()
                audio = base64.b64decode(payload["audio_b64"], validate=True)
                if len(audio) > max_response_bytes:
                    raise ValueError()
            except Exception:
                raise VoiceError("process_response_invalid", outcome_uncertain=True) from None
            if time.monotonic() > deadline:
                raise VoiceError("process_deadline_exceeded", outcome_uncertain=True)
            return VoiceResponse(payload["status"], payload["final_url"], payload["content_type"], audio)
        finally:
            if process is not None:
                _stop_exact_child(process)
                for thread in threads:
                    thread.join(timeout=.2)
                # Child has exited, so pipe close cannot wait on a live writer.
                for pipe in (process.stdin, process.stdout):
                    try:
                        pipe.close()
                    except Exception:
                        pass


def _worker():
    """Fixed isolated child entrypoint; emits one bounded JSON response only."""
    try:
        raw = sys.stdin.buffer.read(_MAX_INPUT + 1)
        if len(raw) > _MAX_INPUT:
            raise ValueError()
        packet = json.loads(raw)
        fields = {"version", "script_sha256", "provider_sha256", "url", "headers", "body_b64", "timeout_seconds", "max_response_bytes"}
        if type(packet) is not dict or set(packet) != fields or packet["version"] != 1:
            raise ValueError()
        if not _source_ok(_SCRIPT, packet["script_sha256"]) or not _source_ok(_PROVIDER, packet["provider_sha256"]):
            raise ValueError()
        body = base64.b64decode(packet["body_b64"], validate=True)
        timeout, maximum = packet["timeout_seconds"], packet["max_response_bytes"]
        if (type(timeout) not in (int, float) or not math.isfinite(timeout) or not .1 <= timeout <= 30
                or type(maximum) is not int or not 1 <= maximum <= _MAX_AUDIO
                or not _valid_request(packet["url"], packet["headers"], body)):
            raise ValueError()
        provider = _load_provider()
        response = provider.UrllibNoRedirectTransport().send(provider.VoiceRequest(packet["url"], packet["headers"], body),
            timeout_seconds=timeout, max_response_bytes=maximum, follow_redirects=False)
        if (type(response.audio) is not bytes or len(response.audio) > maximum or response.final_url != packet["url"]
                or type(response.status) is not int or not 100 <= response.status <= 599
                or type(response.content_type) is not str or len(response.content_type) > 128):
            raise ValueError()
        payload = {"status": response.status, "final_url": response.final_url,
                   "content_type": response.content_type, "audio_b64": base64.b64encode(response.audio).decode("ascii")}
        encoded = json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
        if len(encoded) > 4 * ((maximum + 2) // 3) + 8192:
            raise ValueError()
        sys.stdout.buffer.write(encoded)
        sys.stdout.buffer.flush()
        return 0
    except BaseException:
        # Neither exception repr, request, headers, input, text nor stderr escape.
        try:
            sys.stdout.buffer.write(b'{"error":"worker_failed"}')
            sys.stdout.buffer.flush()
        except BaseException:
            pass
        return 2


if __name__ == "__main__":
    if sys.argv[1:] == ["--worker"]:
        raise SystemExit(_worker())
    raise SystemExit(2)
