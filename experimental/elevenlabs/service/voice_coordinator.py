"""Inactive integration candidate. No HTTP route, environment/key lookup or IO on import.

The embedding HTTP adapter MUST authenticate the real session, enforce CSRF and
same-origin POST, and pass only caller/mission/event IDs. It must never accept
client speech text, role, voice, budget, evidence, or a client authorization scope.
The trusted resolver is responsible for journal/report/receipt integrity and ACL.
Production requires a hard-deadline provider transport and a reviewed deployment.
"""
from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import math
import re
from narration import project_event, NarrationError
from voice_store import VoiceStore, StoreError


@dataclass(frozen=True)
class Policy:
    enabled: bool = False
    commercial_license_confirmed: bool = False
    expires_at: float = 0
    monthly_character_budget: int = 0
    role_voices: tuple[tuple[str, str], ...] = ()
    model_id: str = "eleven_multilingual_v2"


class VoiceCoordinator:
    """Compose factual narration + durable ledger + injected provider.

    Failures return a fixed code to the presentation layer, never a mission-state
    mutation. Audio is private bytes for an ACL-protected HTTP response, not a
    public URL. There is deliberately no retry/reset-budget/operator-bypass API.
    """
    def __init__(self, *, policy=Policy(), resolver, store_root, provider=None, clock=None):
        if type(policy) is not Policy:
            raise ValueError("invalid_policy")
        if (type(policy.enabled) is not bool or type(policy.commercial_license_confirmed) is not bool
                or type(policy.monthly_character_budget) is not int
                or not 0 <= policy.monthly_character_budget <= 1_000_000
                or type(policy.expires_at) not in (int, float)
                or not math.isfinite(policy.expires_at) or policy.expires_at < 0
                or policy.model_id != "eleven_multilingual_v2"
                or type(policy.role_voices) is not tuple
                or any(type(p) is not tuple or len(p) != 2
                       or type(p[0]) is not str or p[0] not in {"system", "cto", "pm", "designer", "dev", "qa", "security", "ops", "assa", "cl-producer"}
                       or type(p[1]) is not str or not re.fullmatch(r"[A-Za-z0-9_-]{16,64}", p[1])
                       for p in policy.role_voices)
                or len(dict(policy.role_voices)) != len(policy.role_voices)):
            raise ValueError("invalid_policy")
        self.policy, self.resolver, self.store_root = policy, resolver, store_root
        self.provider = provider
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def status(self):
        p = self.policy
        if not p.enabled: code = "provider_disabled"
        elif not p.commercial_license_confirmed: code = "commercial_license_required"
        elif self.clock().timestamp() >= p.expires_at: code = "pilot_expired"
        elif p.monthly_character_budget <= 0: code = "budget_not_configured"
        elif not p.role_voices: code = "voices_not_configured"
        elif self.provider is None: code = "provider_not_configured"
        elif getattr(self.provider, "hard_deadline", False) is not True: code = "hard_deadline_required"
        else: code = None
        return {"available": code is None, "provider": "elevenlabs", "reason": code,
                "automatic_purchase": False, "automatic_retry": False}

    def narration(self, *, caller, mission_id, event_id):
        return project_event(caller, mission_id, event_id, self.resolver)

    def _store(self, caller, mission_id, scope):
        def authorize(candidate, action):
            auth = self.resolver.authorize(caller, mission_id)
            return (auth.allowed is True and auth.subject == caller and auth.mission_id == mission_id
                    and auth.scope_id == scope == candidate)
        return VoiceStore(self.store_root, monthly_character_budget=self.policy.monthly_character_budget,
                          authorize=authorize, clock=self.clock, max_request_characters=600)

    @staticmethod
    def _identity(n, voice, model):
        # Server-only identity; binds changing narration/provenance and voice.
        raw = json.dumps([1, n["authorization_scope"], n["mission_id"], n["event_id"],
                          n["narration_sha256"], voice, model], separators=(",", ":")).encode()
        return hashlib.sha256(raw).hexdigest()

    def generate(self, *, caller, mission_id, event_id, consent=False):
        if consent is not True:
            return {"available": False, "reason": "explicit_voice_consent_required"}
        status = self.status()
        if not status["available"]:
            return status
        try:
            n = self.narration(caller=caller, mission_id=mission_id, event_id=event_id)
            voice = dict(self.policy.role_voices).get(n["voice_role"])
            if voice is None:
                return {"available": False, "reason": "role_voice_not_configured"}
            operation = self._identity(n, voice, self.policy.model_id)
            store = self._store(caller, mission_id, n["authorization_scope"])
            ticket = store.reserve(scope=n["authorization_scope"], operation_id=operation,
                                   text=n["text"], voice_id=voice, model_id=self.policy.model_id)
            if ticket.should_generate:
                # Reserve durably first. Any exception/timeout retains uncertainty.
                result = self.provider.generate(operation_id=operation, voice_id=voice,
                                                text=n["text"], model_id=self.policy.model_id)
                store.complete(ticket, audio=result.audio, content_type=result.mime)
            cached = store.get_cached(scope=n["authorization_scope"], operation_id=operation)
            if cached is None:
                return {"available": False, "reason": "generation_uncertain_no_automatic_retry"}
            # Recheck source, scope, revocation AND narration after slow generation.
            fresh = self.narration(caller=caller, mission_id=mission_id, event_id=event_id)
            if fresh["narration_sha256"] != n["narration_sha256"]:
                return {"available": False, "reason": "narration_changed"}
            if not self.status()["available"]:
                return {"available": False, "reason": "pilot_expired_or_disabled"}
            return {"available": True, "mission_id": mission_id, "event_id": event_id,
                    "narration_sha256": n["narration_sha256"], "voice_role": n["voice_role"],
                    "audio": cached.audio, "mime": cached.content_type,
                    "audio_sha256": cached.audio_sha256, "cache_reused": not ticket.should_generate}
        except (NarrationError, StoreError):
            return {"available": False, "reason": "voice_evidence_or_access_unavailable"}
        except Exception:
            # Never include provider exception bodies, prompts, headers or keys.
            return {"available": False, "reason": "voice_unavailable_text_continues"}
