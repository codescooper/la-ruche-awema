"""Explicit voice-profile auditions, distinct from mission activity; no IO on import.

Fixed server phrases only. The live session callback must recheck the HTTP-bound
user/role/generation; it must never be derived from body JSON or profile role.
The existing durable ledger/cache and policy budget are shared with mission TTS.
"""
from __future__ import annotations
import hashlib
import json

from voice_coordinator import VoiceCoordinator
from voice_store import StoreError, VoiceStore

PROFILE_NAMES = {
    "cto": "CTO", "pm": "Chef de projet", "designer": "Designer", "dev": "Développeur",
    "qa": "Vérification", "security": "Sécurité", "ops": "Opérations", "assa": "Direction AWEMA",
    "cl-producer": "CL Producer",
}
VERSION = "awema-danse-profile-narration-v1"


class ProfileError(ValueError):
    pass


def _hash(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True,
                                     separators=(",", ":"), allow_nan=False).encode("utf-8")).hexdigest()


class ProfileVoiceCoordinator(VoiceCoordinator):
    def __init__(self, *args, profile_session_check, **kwargs):
        if not callable(profile_session_check):
            raise ValueError("profile_session_check_required")
        super().__init__(*args, **kwargs)
        self._profile_session_check = profile_session_check

    def _session(self, caller):
        if (type(caller) is not str or not 0 < len(caller) <= 128 or
                any(ord(ch) < 32 or 0xD800 <= ord(ch) <= 0xDFFF for ch in caller)):
            raise ProfileError("profile_session_unavailable")
        try:
            okay = self._profile_session_check(caller) is True
        except Exception:
            okay = False
        if not okay:
            raise ProfileError("profile_session_unavailable")
        if self.status().get("available") is not True:
            raise ProfileError("profile_disabled_or_expired")

    def _checked(self, caller, action):
        self._session(caller)
        value = action()
        self._session(caller)
        return value

    def _profile(self, caller, role):
        self._session(caller)
        if type(role) is not str or role not in PROFILE_NAMES:
            raise ProfileError("invalid_voice_profile")
        voice = dict(self.policy.role_voices).get(role)
        if voice is None:
            raise ProfileError("role_voice_not_configured")
        text = "Bonjour, je suis " + PROFILE_NAMES[role] + ". Ceci est un test de ma voix dans la Danse."
        # Generation is intentionally excluded: re-login cannot reset billing/cache.
        scope = _hash(["awema-danse-profile-scope-v1", caller])
        narration_sha = _hash([VERSION, caller, role, text, voice, self.policy.model_id])
        metadata = {"available": True, "purpose": "voice_profile_test", "role": role, "voice_role": role,
                    "text": text, "text_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
                    "narration_sha256": narration_sha}
        operation = _hash(["awema-danse-profile-operation-v1", scope, role, narration_sha])
        self._session(caller)
        return metadata, scope, operation, voice

    def profile_identity(self, *, caller, role):
        """Revalidate fixed test identity, without a ledger read or provider call."""
        try:
            return self._profile(caller, role)[0]
        except ProfileError as exc:
            return {"available": False, "reason": str(exc)}
        except Exception:
            return {"available": False, "reason": "voice_profile_unavailable"}

    def test_voice(self, *, caller, role, consent=False):
        if consent is not True:
            return {"available": False, "reason": "explicit_voice_consent_required"}
        # Disabled policy is a noop: no directory, ledger, cache or provider work.
        status = self.status()
        if status.get("available") is not True:
            return status
        try:
            metadata, scope, operation, voice = self._profile(caller, role)
            def authorize(candidate, action):
                try:
                    self._session(caller)
                    return candidate == scope and action in ("reserve", "complete", "read", "inspect")
                except ProfileError:
                    return False
            store = self._checked(caller, lambda: VoiceStore(self.store_root,
                monthly_character_budget=self.policy.monthly_character_budget, authorize=authorize,
                clock=self.clock, max_request_characters=600))
            ticket = self._checked(caller, lambda: store.reserve(scope=scope, operation_id=operation,
                text=metadata["text"], voice_id=voice, model_id=self.policy.model_id))
            if ticket.should_generate:
                # A durable uncertain reservation exists before the single provider call.
                result = self._checked(caller, lambda: self.provider.generate(operation_id=operation,
                    voice_id=voice, text=metadata["text"], model_id=self.policy.model_id))
                self._checked(caller, lambda: store.complete(ticket, audio=result.audio, content_type=result.mime))
            cached = self._checked(caller, lambda: store.get_cached(scope=scope, operation_id=operation))
            if cached is None:
                return {"available": False, "reason": "generation_uncertain_no_automatic_retry"}
            fresh = self._profile(caller, role)[0]
            if fresh != metadata:
                return {"available": False, "reason": "voice_profile_changed"}
            return {**metadata, "audio": cached.audio, "mime": cached.content_type,
                    "audio_sha256": cached.audio_sha256, "cache_reused": not ticket.should_generate}
        except (ProfileError, StoreError):
            return {"available": False, "reason": "voice_profile_evidence_or_access_unavailable"}
        except Exception:
            return {"available": False, "reason": "voice_profile_unavailable_text_continues"}
