"""Opt-in HTTP adapter candidate, with no listener, provider, key lookup or IO on import.

Compose explicitly: class Handler(VoiceHTTPMixin, viewer_v2.Handler), then assign
one VoiceHTTP instance to Handler.voice_http. Non-voice routes go to super().
The default authenticator calls viewer_v2.legacy.authenticate(cookie); tests or
an embedding service may inject the same trusted session-authentication contract.
Nothing here edits the canonical viewer or starts a service.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
import re
import secrets
import threading
import time
from urllib.parse import parse_qs, urlsplit

BASE = "/finance/standup/api/voice"
MID = re.compile(r"f_[a-f0-9]{24}\Z")
SHA = re.compile(r"[a-f0-9]{64}\Z")
OPAQUE = re.compile(r"[A-Za-z0-9_-]{43}\Z")
ROLES = frozenset(("system", "cto", "pm", "designer", "dev", "qa", "security", "ops", "assa", "cl-producer"))
MIME = frozenset(("audio/mpeg", "audio/ogg", "audio/wav"))


class HTTPError(ValueError):
    def __init__(self, code, reason):
        self.code, self.reason = code, reason


def need(condition, code=400, reason="invalid_voice_request"):
    if not condition:
        raise HTTPError(code, reason)


def legacy_authenticate(cookie):
    # Import lazily only after an explicitly installed adapter receives a request.
    import viewer_v2
    return viewer_v2.legacy.authenticate(cookie)


@dataclass(frozen=True)
class AudioEntry:
    opaque_id: str
    session_binding: str
    caller: str
    mission_id: str | None
    event_id: int | None
    narration_sha256: str
    voice_role: str
    audio: bytes
    mime: str
    sha256: str
    expires_at: float
    purpose: str = "mission_narration"
    profile_role: str | None = None


@dataclass(frozen=True)
class AuthenticatedVoiceSession:
    """Server-only immutable identity, never populated from a request JSON body."""
    user: str
    role: str
    generation: str


class EphemeralAudio:
    """Bounded private memory cache; no disk, public URL or lifetime extension."""
    def __init__(self, *, clock=time.time, ttl=300, max_entries=128, max_bytes=16 * 1024 * 1024,
                 max_audio_bytes=8 * 1024 * 1024):
        if (type(ttl) is not int or not 1 <= ttl <= 300 or type(max_entries) is not int or not 1 <= max_entries <= 1024
                or type(max_bytes) is not int or not 1 <= max_bytes <= 64 * 1024 * 1024
                or type(max_audio_bytes) is not int or not 1 <= max_audio_bytes <= min(max_bytes, 8 * 1024 * 1024)):
            raise ValueError("invalid_audio_cache_limits")
        self.clock, self.ttl, self.max_entries = clock, ttl, max_entries
        self.max_bytes, self.max_audio_bytes = max_bytes, max_audio_bytes
        self._entries, self._lock = {}, threading.RLock()

    def _prune(self):
        now = self.clock()
        self._entries = {key: entry for key, entry in self._entries.items() if now < entry.expires_at}

    def get(self, opaque_id):
        with self._lock:
            self._prune()
            return self._entries.get(opaque_id)

    def discard(self, opaque_id):
        with self._lock:
            self._entries.pop(opaque_id, None)

    def put(self, *, session_binding, caller, mission_id=None, event_id=None, narration_sha256,
            voice_role, audio, mime, sha256, purpose="mission_narration", profile_role=None):
        need(type(audio) is bytes and 0 < len(audio) <= self.max_audio_bytes, 503, "voice_audio_invalid")
        need(mime in MIME and SHA.fullmatch(sha256 or "") and hashlib.sha256(audio).hexdigest() == sha256,
             503, "voice_audio_invalid")
        need(purpose in ("mission_narration", "voice_profile_test"), 503, "voice_audio_invalid")
        if purpose == "voice_profile_test":
            need(profile_role in ROLES - {"system"} and voice_role == profile_role and mission_id is None and event_id is None,
                 503, "voice_audio_invalid")
        else:
            need(type(mission_id) is str and MID.fullmatch(mission_id) and type(event_id) is int and event_id > 0
                 and profile_role is None, 503, "voice_audio_invalid")
        with self._lock:
            self._prune()
            identity = (session_binding, caller, mission_id, event_id, narration_sha256, voice_role, sha256, purpose, profile_role)
            for entry in self._entries.values():
                candidate = (entry.session_binding, entry.caller, entry.mission_id, entry.event_id,
                             entry.narration_sha256, entry.voice_role, entry.sha256, entry.purpose, entry.profile_role)
                if candidate == identity:
                    return entry
            # Evict the earliest expiration first. Bounds cover all sessions together.
            while self._entries and (len(self._entries) >= self.max_entries or
                                      sum(len(e.audio) for e in self._entries.values()) + len(audio) > self.max_bytes):
                del self._entries[min(self._entries, key=lambda key: self._entries[key].expires_at)]
            identifier = secrets.token_urlsafe(32)
            while identifier in self._entries:
                identifier = secrets.token_urlsafe(32)
            entry = AudioEntry(identifier, session_binding, caller, mission_id, event_id, narration_sha256,
                               voice_role, audio, mime, sha256, self.clock() + self.ttl, purpose, profile_role)
            self._entries[identifier] = entry
            return entry


class VoiceHTTP:
    def __init__(self, coordinator=None, *, coordinator_factory=None, authenticate=legacy_authenticate,
                 origin="https://laruche.awema.cloud", clock=time.time, csrf_key=None, cache=None):
        parsed = urlsplit(origin)
        if (parsed.scheme != "https" or not parsed.netloc or parsed.path not in ("", "/") or parsed.query or
                parsed.fragment or parsed.username or parsed.password or origin.endswith("/")):
            raise ValueError("invalid_voice_origin")
        if csrf_key is not None and (type(csrf_key) is not bytes or len(csrf_key) < 32):
            raise ValueError("invalid_csrf_key")
        if ((coordinator is None) == (coordinator_factory is None)
                or coordinator_factory is not None and not callable(coordinator_factory)):
            raise ValueError("one_coordinator_or_factory_required")
        self.coordinator, self.authenticate, self.origin, self.clock = coordinator, authenticate, origin, clock
        self.coordinator_factory = coordinator_factory
        self._key = csrf_key if csrf_key is not None else secrets.token_bytes(32)
        self.cache = cache if cache is not None else EphemeralAudio(clock=clock)
        self._generation_slots = threading.BoundedSemaphore(2)

    @staticmethod
    def matches(path):
        try:
            pathname = urlsplit(path).path
        except ValueError:
            return False
        return pathname == BASE or pathname.startswith(BASE + "/")

    @staticmethod
    def _one(headers, field, required=False):
        values = headers.get_all(field) or []
        need(len(values) <= 1 and (not required or len(values) == 1))
        return values[0] if values else None

    def _authenticate(self, handler):
        cookie = self._one(handler.headers, "Cookie")
        return self._authenticate_cookie(cookie)

    def _authenticate_cookie(self, cookie):
        need(type(cookie) is str and 0 < len(cookie) <= 8192 and "\r" not in cookie and "\n" not in cookie,
             401, "authentication_required")
        try:
            session = self.authenticate(cookie)
        except Exception as exc:
            code = getattr(exc, "code", 503)
            raise HTTPError(code if code in (401, 403) else 503,
                            "authentication_required" if code == 401 else "voice_access_unavailable") from None
        need(type(session) is dict and session.get("role") in ("owner", "director") and
             type(session.get("user")) is str and 0 < len(session["user"]) <= 128, 403, "voice_access_denied")
        caller = session["user"]
        binding = hmac.new(self._key, ("session\0" + caller + "\0" + cookie).encode("utf-8"), hashlib.sha256).hexdigest()
        return AuthenticatedVoiceSession(caller, session["role"], binding)

    def _coordinator_for_request(self, handler, session):
        if self.coordinator_factory is None:
            # Backward compatibility for a deliberately session-independent coordinator.
            # A CatalogResolver must use the factory path, since it binds one session.
            return self.coordinator
        cookie = self._one(handler.headers, "Cookie")

        def reauthenticate():
            # Capture this request's cookie, never a mutable global handler/session.
            current = self._authenticate_cookie(cookie)
            need(current == session, 401, "authentication_required")
            return current

        try:
            coordinator = self.coordinator_factory(caller=session.user, reauthenticate=reauthenticate,
                                                   generation_binding=session.generation)
        except HTTPError:
            raise
        except Exception:
            raise HTTPError(503, "voice_request_context_unavailable") from None
        need(coordinator is not None and all(callable(getattr(coordinator, method, None))
                                            for method in ("status", "narration", "generate")),
             503, "voice_request_context_unavailable")
        return coordinator

    def _csrf(self, binding):
        payload = "v1." + str(int(self.clock()) + 300) + "." + secrets.token_urlsafe(16)
        mac = hmac.new(self._key, ("csrf\0" + binding + "\0" + payload).encode(), hashlib.sha256).hexdigest()
        return payload + "." + mac

    def _check_csrf(self, token, binding):
        need(type(token) is str and len(token) <= 256, 403, "voice_csrf_required")
        parts = token.split(".")
        need(len(parts) == 4 and parts[0] == "v1" and re.fullmatch(r"[0-9]{1,16}", parts[1]) and
             re.fullmatch(r"[A-Za-z0-9_-]{22}", parts[2]) and SHA.fullmatch(parts[3]), 403, "voice_csrf_invalid")
        expiry = int(parts[1])
        need(self.clock() < expiry <= self.clock() + 300, 403, "voice_csrf_expired")
        payload = ".".join(parts[:3])
        expected = hmac.new(self._key, ("csrf\0" + binding + "\0" + payload).encode(), hashlib.sha256).hexdigest()
        need(hmac.compare_digest(expected, parts[3]), 403, "voice_csrf_invalid")

    def _origin(self, handler, post=False):
        origin = self._one(handler.headers, "Origin")
        site = self._one(handler.headers, "Sec-Fetch-Site")
        need(origin is None or origin == self.origin, 403, "voice_origin_denied")
        need(site is None or site in ("same-origin", "none"), 403, "voice_origin_denied")
        if post:
            need(origin == self.origin and site == "same-origin", 403, "voice_origin_denied")

    @staticmethod
    def _ids(mission, event):
        need(type(mission) is str and MID.fullmatch(mission) and type(event) is int and 0 < event < 2**63)
        return mission, event

    @staticmethod
    def _query(query):
        try:
            values = parse_qs(query, keep_blank_values=True, strict_parsing=True, max_num_fields=2)
        except ValueError:
            raise HTTPError(400, "invalid_voice_request") from None
        need(set(values) == {"mission_id", "event_id"} and all(len(value) == 1 for value in values.values()))
        raw = values["event_id"][0]
        need(bool(re.fullmatch(r"[1-9][0-9]{0,18}", raw)))
        return VoiceHTTP._ids(values["mission_id"][0], int(raw))

    @staticmethod
    def _post_json(handler):
        # Close after every POST, including rejection, so unread bytes cannot become a pipelined request.
        handler.close_connection = True
        need(not handler.headers.get_all("Transfer-Encoding"), 400, "voice_transfer_encoding_denied")
        length = VoiceHTTP._one(handler.headers, "Content-Length", True)
        need(bool(re.fullmatch(r"[0-9]{1,4}", length or "")) and 0 < int(length) <= 4096,
             413, "voice_body_limit")
        content_type = VoiceHTTP._one(handler.headers, "Content-Type", True)
        need(bool(re.fullmatch(r"application/json(?:;\s*charset=utf-8)?", content_type or "", re.I)),
             415, "voice_json_required")
        raw = handler.rfile.read(int(length))
        need(len(raw) == int(length))
        def pairs(items):
            result = {}
            for key, value in items:
                need(key not in result)
                result[key] = value
            return result
        def constant(_value):
            raise HTTPError(400, "invalid_voice_request")
        try:
            body = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
        except (UnicodeError, json.JSONDecodeError):
            raise HTTPError(400, "invalid_voice_request") from None
        need(type(body) is dict)
        return body

    @staticmethod
    def _post_ids(handler):
        body = VoiceHTTP._post_json(handler)
        need(set(body) == {"mission_id", "event_id"})
        return VoiceHTTP._ids(body["mission_id"], body["event_id"])

    @staticmethod
    def _post_role(handler):
        body = VoiceHTTP._post_json(handler)
        need(set(body) == {"role"} and type(body["role"]) is str and body["role"] in ROLES - {"system"})
        return body["role"]

    def _narration(self, coordinator, caller, mission, event):
        try:
            value = coordinator.narration(caller=caller, mission_id=mission, event_id=event)
        except Exception:
            raise HTTPError(403, "voice_evidence_or_access_unavailable") from None
        need(type(value) is dict and value.get("available") is True and value.get("mission_id") == mission and
             value.get("event_id") == event and SHA.fullmatch(value.get("narration_sha256", "")) and
             value.get("voice_role") in ROLES, 503, "voice_narration_invalid")
        return value

    def _profile_identity(self, coordinator, caller, role):
        method = getattr(coordinator, "profile_identity", None)
        need(callable(method), 503, "voice_profile_unavailable")
        try:
            value = method(caller=caller, role=role)
        except Exception:
            raise HTTPError(403, "voice_profile_access_unavailable") from None
        # Imported only for an audition request; legacy mission routes stay independent.
        from voice_profiles import PROFILE_NAMES
        expected = "Bonjour, je suis " + PROFILE_NAMES[role] + ". Ceci est un test de ma voix dans la Danse."
        need(type(value) is dict and value.get("available") is True, 403, "voice_profile_access_unavailable")
        need(value.get("purpose") == "voice_profile_test" and value.get("role") == value.get("voice_role") == role and
             value.get("text") == expected and value.get("text_sha256") == hashlib.sha256(expected.encode()).hexdigest() and
             SHA.fullmatch(value.get("narration_sha256", "")) and "mission_id" not in value and "event_id" not in value,
             503, "voice_profile_invalid")
        return value

    def handle(self, handler):
        """Write one response via the existing handler.send (private,no-store)."""
        try:
            need(type(handler.path) is str and len(handler.path) <= 8192)
            parsed = urlsplit(handler.path)
            need(not parsed.scheme and not parsed.netloc and not parsed.fragment)
            path = parsed.path
            method = handler.command
            if method == "POST":
                handler.close_connection = True
            need(method in ("GET", "HEAD", "POST"), 405, "voice_method_denied")
            self._origin(handler, post=method == "POST")
            session = self._authenticate(handler)
            caller, binding = session.user, session.generation
            coordinator = self._coordinator_for_request(handler, session)
            if path == BASE + "/status":
                need(method in ("GET", "HEAD") and not parsed.query, 405, "voice_method_denied")
                status = coordinator.status()
                # Do not return policy internals, role voice IDs, provider headers or a provider key.
                response = {"available": status.get("available") is True, "provider": "elevenlabs",
                            "automatic_retry": False, "automatic_purchase": False}
                if response["available"]:
                    response["csrf_token"] = self._csrf(binding)
                else:
                    response["reason"] = "voice_not_configured_or_disabled"
                return handler.send(200, response)
            if path == BASE + "/narration":
                need(method in ("GET", "HEAD"), 405, "voice_method_denied")
                mission, event = self._query(parsed.query)
                return handler.send(200, self._narration(coordinator, caller, mission, event))
            if path == BASE + "/test":
                need(method == "POST" and not parsed.query, 405, "voice_method_denied")
                need(self._one(handler.headers, "X-AWEMA-Voice-Consent") == "true", 403, "explicit_voice_consent_required")
                self._check_csrf(self._one(handler.headers, "X-CSRF-Token"), binding)
                role = self._post_role(handler)
                need(coordinator.status().get("available") is True, 503, "voice_not_configured_or_disabled")
                before = self._profile_identity(coordinator, caller, role)
                method = getattr(coordinator, "test_voice", None)
                need(callable(method), 503, "voice_profile_unavailable")
                need(self._generation_slots.acquire(blocking=False), 429, "voice_capacity_busy")
                try:
                    result = method(caller=caller, role=role, consent=True)
                finally:
                    self._generation_slots.release()
                if type(result) is not dict or result.get("available") is not True:
                    return handler.send(503, {"available": False, "reason": "voice_profile_unavailable_text_continues"})
                need(self._authenticate(handler) == session, 401, "authentication_required")
                after = self._profile_identity(coordinator, caller, role)
                need(result.get("purpose") == "voice_profile_test" and result.get("role") == result.get("voice_role") == role and
                     result.get("narration_sha256") == before["narration_sha256"] == after["narration_sha256"] and
                     result.get("text") == after["text"] and result.get("text_sha256") == after["text_sha256"] and
                     "mission_id" not in result and "event_id" not in result, 409, "voice_profile_changed")
                entry = self.cache.put(session_binding=binding, caller=caller, purpose="voice_profile_test", profile_role=role,
                    narration_sha256=after["narration_sha256"], voice_role=role, audio=result.get("audio"),
                    mime=result.get("mime"), sha256=result.get("audio_sha256"))
                return handler.send(200, {**after, "cached": result.get("cache_reused") is True,
                    "audio": {"url": BASE + "/audio/" + entry.opaque_id, "expires_at": entry.expires_at,
                              "mime_type": entry.mime, "sha256": entry.sha256}})
            if path == BASE + "/generate":
                need(method == "POST" and not parsed.query, 405, "voice_method_denied")
                need(self._one(handler.headers, "X-AWEMA-Voice-Consent") == "true", 403, "explicit_voice_consent_required")
                self._check_csrf(self._one(handler.headers, "X-CSRF-Token"), binding)
                mission, event = self._post_ids(handler)
                need(coordinator.status().get("available") is True, 503, "voice_not_configured_or_disabled")
                # ACL/provenance are checked before generation, after it, and at every audio GET.
                before = self._narration(coordinator, caller, mission, event)
                need(self._generation_slots.acquire(blocking=False), 429, "voice_capacity_busy")
                try:
                    result = coordinator.generate(caller=caller, mission_id=mission, event_id=event, consent=True)
                finally:
                    self._generation_slots.release()
                if type(result) is not dict or result.get("available") is not True:
                    return handler.send(503, {"available": False, "reason": "voice_unavailable_text_continues"})
                need(self._authenticate(handler) == session, 401, "authentication_required")
                need(coordinator.status().get("available") is True, 503, "voice_not_configured_or_disabled")
                after = self._narration(coordinator, caller, mission, event)
                need(result.get("mission_id") == mission and result.get("event_id") == event and
                     result.get("narration_sha256") == before["narration_sha256"] == after["narration_sha256"] and
                     result.get("voice_role") == before["voice_role"] == after["voice_role"], 409, "voice_narration_changed")
                entry = self.cache.put(session_binding=binding, caller=caller, mission_id=mission, event_id=event,
                                       narration_sha256=after["narration_sha256"], voice_role=after["voice_role"],
                                       audio=result.get("audio"), mime=result.get("mime"), sha256=result.get("audio_sha256"))
                return handler.send(200, {"available": True, "mission_id": mission, "event_id": event,
                    "narration_sha256": entry.narration_sha256, "voice_role": entry.voice_role,
                    "cached": result.get("cache_reused") is True,
                    "audio": {"url": BASE + "/audio/" + entry.opaque_id, "expires_at": entry.expires_at,
                              "mime_type": entry.mime, "sha256": entry.sha256}})
            if path.startswith(BASE + "/audio/"):
                need(method in ("GET", "HEAD") and not parsed.query, 405, "voice_method_denied")
                opaque = path[len(BASE + "/audio/"):]
                need(bool(OPAQUE.fullmatch(opaque)), 404, "voice_audio_missing")
                entry = self.cache.get(opaque)
                need(entry is not None and hmac.compare_digest(entry.session_binding, binding) and entry.caller == caller,
                     404, "voice_audio_missing")
                need(coordinator.status().get("available") is True, 503, "voice_not_configured_or_disabled")
                fresh = (self._profile_identity(coordinator, caller, entry.profile_role) if entry.purpose == "voice_profile_test"
                         else self._narration(coordinator, caller, entry.mission_id, entry.event_id))
                if fresh["narration_sha256"] != entry.narration_sha256 or fresh["voice_role"] != entry.voice_role:
                    self.cache.discard(opaque)
                    raise HTTPError(410, "voice_audio_changed")
                need(self._authenticate(handler) == session, 401, "authentication_required")
                # Re-read after potentially slow ACL resolver, so expiry is not bypassed while it runs.
                need(self.cache.get(opaque) is entry, 404, "voice_audio_missing")
                return handler.send(200, entry.audio, entry.mime)
            raise HTTPError(404, "voice_route_missing")
        except HTTPError as exc:
            return handler.send(exc.code, {"error": exc.reason})
        except Exception:
            # Fixed text only. No stack, source row, cookie, key, provider body or prompt escapes.
            return handler.send(503, {"error": "voice_temporarily_unavailable"})


class VoiceHTTPMixin:
    """Install before viewer_v2.Handler in MRO; voice_http=None preserves legacy routes."""
    voice_http = None

    def _voice_route(self):
        if not VoiceHTTP.matches(self.path):
            return False
        if self.command == "POST":
            self.close_connection = True
        if self.voice_http is None:
            self.send(503, {"available": False, "reason": "voice_disabled"})
        else:
            self.voice_http.handle(self)
        return True

    def do_GET(self):
        if not self._voice_route():
            return super().do_GET()

    def do_HEAD(self):
        if not self._voice_route():
            return super().do_HEAD()

    def do_POST(self):
        if not self._voice_route():
            return super().do_POST()
