"""Inactive server-side TTS prototype: no logging, env lookup or automatic retry.

The caller owns authorization, approved narration, durable quotas/idempotency,
private caching and deployment. This per-instance budget is not distributed.
No network call happens on import or construction. Real transport is optional.
"""
from __future__ import annotations
from dataclasses import dataclass, field
import hashlib
import json
import math
import re
import threading
import time
from typing import Protocol
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener

API_BASE = "https://api.elevenlabs.io/v1/text-to-speech/"
OUTPUT_FORMAT = "mp3_44100_128"
SUPPORTED_MODELS = frozenset({"eleven_multilingual_v2"})
VOICE_ID = re.compile(r"[A-Za-z0-9_-]{16,64}\Z")
OPERATION_ID = re.compile(r"[a-f0-9]{64}\Z")


class VoiceError(RuntimeError):
    """Fixed codes only, without narration, secret or upstream body."""
    def __init__(self, code, *, outcome_uncertain=False):
        self.code = code
        self.outcome_uncertain = outcome_uncertain
        super().__init__(code)


@dataclass(frozen=True)
class VoiceConfig:
    enabled: bool = False
    allowed_voice_ids: frozenset[str] = frozenset()
    allowed_model_ids: frozenset[str] = SUPPORTED_MODELS
    max_request_characters: int = 600
    max_total_characters: int = 0
    timeout_seconds: float = 15.0
    max_audio_bytes: int = 4 * 1024 * 1024

    def __post_init__(self):
        valid = (type(self.enabled) is bool
            and type(self.allowed_voice_ids) is frozenset
            and all(type(x) is str and VOICE_ID.fullmatch(x) for x in self.allowed_voice_ids)
            and type(self.allowed_model_ids) is frozenset and bool(self.allowed_model_ids)
            and self.allowed_model_ids <= SUPPORTED_MODELS
            and type(self.max_request_characters) is int and 1 <= self.max_request_characters <= 2000
            and type(self.max_total_characters) is int and 0 <= self.max_total_characters <= 1_000_000
            and type(self.timeout_seconds) in (int, float) and math.isfinite(self.timeout_seconds)
            and .1 <= self.timeout_seconds <= 30
            and type(self.max_audio_bytes) is int and 1024 <= self.max_audio_bytes <= 8 * 1024 * 1024)
        if not valid:
            raise VoiceError("invalid_configuration")


@dataclass(frozen=True)
class VoiceRequest:
    url: str
    headers: dict[str, str] = field(repr=False)
    body: bytes = field(repr=False)


@dataclass(frozen=True)
class VoiceResponse:
    status: int
    final_url: str
    content_type: str
    audio: bytes = field(repr=False)


@dataclass(frozen=True)
class VoiceResult:
    operation_id: str
    text_sha256: str
    voice_id: str
    model_id: str
    characters_reserved: int
    audio_sha256: str
    audio: bytes = field(repr=False)
    mime: str = "audio/mpeg"


class VoiceTransport(Protocol):
    def send(self, request: VoiceRequest, *, timeout_seconds: float,
             max_response_bytes: int, follow_redirects: bool) -> VoiceResponse: ...


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class UrllibNoRedirectTransport:
    """Explicit optional real transport, never installed automatically.

    No redirects/environment proxy/retry. Socket timeout plus elapsed read
    deadline; DNS resolution is still subject to OS DNS timeouts. Production
    must additionally impose a process-level total deadline.
    """
    def send(self, request, *, timeout_seconds, max_response_bytes, follow_redirects=False):
        if follow_redirects is not False:
            raise VoiceError("redirects_forbidden")
        if (type(request.url) is not str or not re.fullmatch(re.escape(API_BASE)
                + r"[A-Za-z0-9_-]{16,64}\?output_format=" + re.escape(OUTPUT_FORMAT), request.url)):
            raise VoiceError("invalid_endpoint")
        deadline = time.monotonic() + timeout_seconds
        opener = build_opener(ProxyHandler({}), HTTPSHandler(), _NoRedirect())
        req = Request(request.url, data=request.body, headers=request.headers, method="POST")
        error_code = None
        try:
            response = opener.open(req, timeout=timeout_seconds)
        except HTTPError as exc:
            status = exc.code
            try: exc.close()
            except Exception: pass
            return VoiceResponse(status, request.url, "", b"")
        except Exception:
            error_code = "transport_interrupted"
        if error_code:
            raise VoiceError(error_code, outcome_uncertain=True)
        try:
            if response.geturl() != request.url:
                error_code = "unexpected_response_origin"
            else:
                parts, size = [], 0
                while True:
                    if time.monotonic() > deadline:
                        error_code = "transport_deadline_exceeded"
                        break
                    part = response.read(min(65536, max_response_bytes + 1 - size))
                    if not part: break
                    size += len(part)
                    if size > max_response_bytes:
                        error_code = "audio_size_exceeded"
                        break
                    parts.append(part)
                if not error_code:
                    result = VoiceResponse(response.status, request.url,
                        response.headers.get("Content-Type", ""), b"".join(parts))
        except Exception:
            error_code = "transport_interrupted"
        finally:
            try: response.close()
            except Exception: error_code = "transport_interrupted"
        if error_code:
            raise VoiceError(error_code, outcome_uncertain=True)
        return result


class ElevenLabsClient:
    def __init__(self, config: VoiceConfig = VoiceConfig(), *, api_key=None,
                 transport: VoiceTransport | None = None, clock=time.monotonic):
        if type(config) is not VoiceConfig:
            raise VoiceError("invalid_configuration")
        self.config, self._api_key, self._transport = config, api_key, transport
        self._clock, self._lock = clock, threading.Lock()
        self._reserved, self._attempted = 0, set()

    def __repr__(self):
        return "ElevenLabsClient(secrets=redacted, inactive_by_default=True)"

    @property
    def characters_reserved(self):
        with self._lock: return self._reserved

    @property
    def hard_deadline(self):
        # Derived only from the trusted, reviewed transport chosen by operator.
        # A truthy flag is an interface contract, not independent qualification.
        return getattr(self._transport, "hard_deadline", False) is True

    def generate(self, *, operation_id, voice_id, text, model_id="eleven_multilingual_v2"):
        cfg = self.config
        if not cfg.enabled: raise VoiceError("provider_disabled")
        if (type(self._api_key) is not str or not 16 <= len(self._api_key) <= 512
                or any(ord(c) < 33 or ord(c) > 126 for c in self._api_key)):
            raise VoiceError("provider_key_missing_or_invalid")
        if self._transport is None: raise VoiceError("transport_not_configured")
        if type(operation_id) is not str or not OPERATION_ID.fullmatch(operation_id):
            raise VoiceError("invalid_operation_id")
        if (type(voice_id) is not str or not VOICE_ID.fullmatch(voice_id)
                or voice_id not in cfg.allowed_voice_ids):
            raise VoiceError("voice_not_allowed")
        if type(model_id) is not str or model_id not in cfg.allowed_model_ids:
            raise VoiceError("model_not_allowed")
        if (type(text) is not str or not text.strip() or len(text) > cfg.max_request_characters
                or any((ord(c) < 32 and c not in "\n\t") or 0xD800 <= ord(c) <= 0xDFFF for c in text)):
            raise VoiceError("narration_invalid_or_too_large")
        # Keep reservation after failure: provider billing/generation is uncertain.
        with self._lock:
            if operation_id in self._attempted: raise VoiceError("operation_already_attempted")
            if self._reserved + len(text) > cfg.max_total_characters:
                raise VoiceError("character_budget_exceeded")
            self._reserved += len(text)
            self._attempted.add(operation_id)
        url = API_BASE + voice_id + "?output_format=" + OUTPUT_FORMAT
        request = VoiceRequest(url,
            {"xi-api-key": self._api_key, "Content-Type": "application/json", "Accept": "audio/mpeg"},
            json.dumps({"text": text, "model_id": model_id}, ensure_ascii=False,
                       separators=(",", ":")).encode("utf-8"))
        started, error_code = self._clock(), None
        try:
            response = self._transport.send(request, timeout_seconds=cfg.timeout_seconds,
                max_response_bytes=cfg.max_audio_bytes, follow_redirects=False)
        except Exception:
            error_code = "provider_outcome_uncertain"
        # Outside except: no secret-bearing upstream exception context.
        if error_code: raise VoiceError(error_code, outcome_uncertain=True)
        if self._clock() - started > cfg.timeout_seconds:
            raise VoiceError("provider_deadline_exceeded", outcome_uncertain=True)
        if type(response) is not VoiceResponse:
            raise VoiceError("provider_response_invalid", outcome_uncertain=True)
        if response.final_url != url:
            raise VoiceError("provider_redirect_forbidden", outcome_uncertain=True)
        if type(response.status) is not int or response.status != 200:
            raise VoiceError("provider_response_rejected", outcome_uncertain=True)
        if (type(response.content_type) is not str
                or response.content_type.split(";", 1)[0].strip().lower() not in ("audio/mpeg", "audio/mp3")
                or type(response.audio) is not bytes or not 4 <= len(response.audio) <= cfg.max_audio_bytes
                or not (response.audio.startswith(b"ID3")
                    or response.audio[0] == 0xFF and response.audio[1] & 0xE0 == 0xE0)):
            raise VoiceError("provider_audio_invalid", outcome_uncertain=True)
        return VoiceResult(operation_id, hashlib.sha256(text.encode()).hexdigest(), voice_id,
            model_id, len(text), hashlib.sha256(response.audio).hexdigest(), response.audio)
