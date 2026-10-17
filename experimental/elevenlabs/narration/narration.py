"""Fact-bound speech/caption projection. Pure stdlib; no IO or model call.

The resolver is a trusted server adapter, never client JSON. It must authorize
every read against current ACL/revocation and resolve immutable journal rows,
stored reports and operator-owned execution proofs. Dataclasses are data, not
proof of trust. A model report is a declaration; evidence must independently
support its action state. No raw output or private reasoning enters this API.
"""
from __future__ import annotations
from dataclasses import asdict, dataclass
import hashlib
import json
import math
import re
import unicodedata
from typing import Protocol

SCHEMA = "awema-danse-narration-v1"
MAX_TEXT, MAX_FIELD, MAX_FULL_TEXT = 600, 4096, 2400
ROLES = frozenset(("cto", "pm", "designer", "dev", "qa", "security", "ops", "assa", "cl-producer"))
ROLE_NAMES = {"cto": "CTO", "pm": "Chef de projet", "designer": "Designer", "dev": "Développeur", "qa": "Vérification", "security": "Sécurité", "ops": "Opérations", "assa": "Direction AWEMA", "cl-producer": "CL Producer"}
STATES = frozenset(("planned", "started", "completed", "verified", "blocked"))
MID = re.compile(r"f_[a-f0-9]{24}\Z")
SHA = re.compile(r"[a-f0-9]{64}\Z")
CODE = re.compile(r"[a-z][a-z0-9_-]{0,95}\Z")
IDENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
SENSITIVE = re.compile(r"(?i)(?:^|[/:._-])(?:auth|credentials|tokens|secret|password|id_rsa|id_ed25519)(?:$|[/:._-])|\.env(?:$|[.])|\.dpapi$")
RAW = re.compile(r"(?i)```|<[^>]+>|<\||\|>|-----BEGIN|Traceback \(most recent|\b(?:system|developer|assistant)\s*:|\b(?:ignore|disregard)\b.{0,40}\b(?:previous|instructions)\b|\b(?:system prompt|chain.of.thought|raisonnement interne|prompt système)\b")
OUTCOME = re.compile(r"(?i)\b(?:j.ai (?:terminé|validé|livré|corrigé)|test[s]? (?:réussi[s]?|passé[s]?)|c.est (?:terminé|validé)|déjà (?:terminé|validé)|successfully (?:completed|verified)|all tests passed)\b")

# Journal descriptions, never words attributed to an agent. A completion record
# is not a quality PASS; a dispatch is not a confirmed worker start.
SYSTEM_EVENTS = {
    "plan_created": ("completed", "Le dossier de mission a été créé dans le registre."),
    "objective_execution_requested": ("planned", "L’exécution de cet objectif a été demandée."),
    "human_plan_approved": ("completed", "L’opérateur a approuvé le plan."),
    "human_cancel_requested": ("planned", "L’opérateur a demandé un arrêt ; son exécution reste à confirmer."),
    "human_retry_requested": ("planned", "L’opérateur a demandé une relance."),
    "human_continue_requested": ("planned", "L’opérateur a demandé une reprise avec précision."),
    "human_retry_applied": ("completed", "La relance opérateur a été enregistrée."),
    "human_continue_applied": ("completed", "La reprise opérateur a été enregistrée."),
    "automatic_retry_scheduled": ("planned", "Une nouvelle tentative automatique a été planifiée."),
    "automatic_checkpoint_resume_scheduled": ("planned", "Une reprise depuis un point confirmé a été planifiée."),
    "automatic_contract_repair_scheduled": ("planned", "Une correction du contrat de sortie a été planifiée."),
    "automatic_correction_scheduled": ("planned", "Une correction a été transmise aux étapes concernées."),
    "human_correction_scheduled": ("planned", "Une correction demandée par l’opérateur a été transmise."),
    "operator_explanation_required": ("blocked", "Une explication du blocage a été enregistrée."),
    "operator_technical_fix_verified": ("completed", "Une vérification technique de reprise a été enregistrée ; consulter sa preuve."),
    "waiting_capacity": ("planned", "La mission attend une capacité d’exécution disponible."),
    "capacity_available": ("completed", "Une capacité d’exécution a été signalée comme disponible."),
    "kanban_retry_scheduled": ("planned", "Une vérification du Kanban a été planifiée."),
    "recovery_waiting_for_worker": ("planned", "La reprise attend la confirmation de l’arrêt du worker."),
    "recovery_refused_uncertain": ("blocked", "La reprise est refusée car un effet reste incertain."),
    "recovery_limit_reached": ("blocked", "La limite de reprise enregistrée a été atteinte."),
    "worker_timeout_cancel_requested": ("planned", "Un arrêt du worker a été demandé après expiration du délai."),
    "worker_state_missing_waiting": ("planned", "La mission attend un état worker confirmé."),
    "blocked": ("blocked", "Un blocage de mission a été enregistré ; consulter le dossier."),
    "review": ("completed", "La mission a été transmise pour relecture ; elle attend une validation."),
    "delivered": ("completed", "Une livraison a été enregistrée ; son contenu reste à consulter."),
    "cancelled": ("completed", "L’arrêt de la mission a été enregistré."),
    "running": ("started", "L’exécution de la mission a été enregistrée ; ce jalon ne prouve pas une activité continue."),
    "queued": ("planned", "La mission a été placée en attente."),
    "human_accepted": ("completed", "L’opérateur a accepté la livraison."),
    "human_correction_requested": ("planned", "L’opérateur a demandé une correction."),
}

class NarrationError(ValueError):
    """Only fixed codes; never echo source content or an identity."""

def _need(condition, code):
    if not condition:
        raise NarrationError(code)

def _resolved(method, *args):
    # Resolver exceptions can contain database rows, secrets or raw log text.
    # Expose one fixed diagnostic and suppress their chained exception text.
    try:
        return method(*args)
    except Exception:
        raise NarrationError("resolver_unavailable") from None

def canonical_bytes(value):
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError):
        raise NarrationError("canonical_data_invalid") from None

def digest(value):
    return hashlib.sha256(canonical_bytes(value)).hexdigest()

@dataclass(frozen=True)
class Binding:
    mission_id: str
    event_id: int
    role: str | None = None
    ordinal: int | None = None
    attempt: int | None = None
    run_id: int | None = None
    checkpoint_id: str | None = None

@dataclass(frozen=True)
class Authorization:
    subject: str
    scope_id: str
    mission_id: str
    allowed: bool

@dataclass(frozen=True)
class EventRecord:
    binding: Binding
    kind: str
    observed_at: float
    source_event_sha256: str
    worker_report_id: str | None = None

@dataclass(frozen=True)
class WorkerReport:
    binding: Binding
    report_id: str
    recorded_at: float
    action_state: str
    action_summary: str
    observed_result: str
    evidence_reference: str
    next_step: str
    report_sha256: str

@dataclass(frozen=True)
class EvidenceProof:
    binding: Binding
    reference: str
    sha256: str
    action_state: str
    level: str  # recorded (journal), executed (worker), verified (operator proof)

class Resolver(Protocol):
    def authorize(self, caller: str, mission_id: str) -> Authorization: ...
    def resolve_event(self, authorization: Authorization, mission_id: str, event_id: int) -> EventRecord: ...
    def resolve_report(self, authorization: Authorization, event: EventRecord, report_id: str) -> WorkerReport: ...
    def resolve_evidence(self, authorization: Authorization, binding: Binding, reference: str) -> EvidenceProof: ...

def _binding(binding, worker=False):
    _need(type(binding) is Binding, "binding_invalid")
    _need(isinstance(binding.mission_id, str) and bool(MID.fullmatch(binding.mission_id)), "mission_id_invalid")
    _need(type(binding.event_id) is int and 0 < binding.event_id < 2**63, "event_id_invalid")
    _need(binding.role is None or isinstance(binding.role, str) and binding.role in ROLES, "role_invalid")
    for val, low, high, code in ((binding.ordinal, 0, 63, "ordinal_invalid"), (binding.attempt, 1, 1000, "attempt_invalid"), (binding.run_id, 1, 2**63-1, "run_id_invalid")):
        _need(val is None or type(val) is int and low <= val <= high, code)
    _need(binding.checkpoint_id is None or isinstance(binding.checkpoint_id, str) and bool(IDENT.fullmatch(binding.checkpoint_id)), "checkpoint_invalid")
    if worker:
        _need(all(value is not None for value in (binding.role, binding.ordinal, binding.attempt, binding.run_id, binding.checkpoint_id)), "worker_binding_incomplete")

def _timestamp(value):
    return type(value) in (int, float) and math.isfinite(value) and value >= 0

def _reference(value):
    _need(isinstance(value, str) and 0 < len(value) <= 128, "evidence_reference_invalid")
    _need(bool(re.fullmatch(r"(?:event|report|receipt|artifact|checkpoint):[A-Za-z0-9][A-Za-z0-9._:-]{0,110}", value)), "evidence_reference_invalid")
    _need(".." not in value and not SENSITIVE.search(value), "evidence_reference_sensitive")

def _redact(value):
    _need(isinstance(value, str) and len(value) <= MAX_FIELD, "report_text_invalid")
    value = unicodedata.normalize("NFC", value)
    _need(not RAW.search(value), "unsafe_report_text")
    value = "".join(ch for ch in value if not unicodedata.category(ch).startswith("C") or ch in "\n\t")
    value = " ".join(value.split())
    _need(not RAW.search(value), "unsafe_report_text")
    before = value
    value = re.sub(r"(?i)\b(?:password|mot de passe|secret|token|api[_ -]?key|authorization|bearer|cookie|csrf)\s*(?:[:=]\s*|\s+)(?:\"[^\"]*\"|'[^']*'|\S+)", "[donnée masquée]", value)
    value = re.sub(r"\b(?:sk_[A-Za-z0-9_-]{12,}|sk-[A-Za-z0-9_-]{12,}|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\b", "[donnée masquée]", value)
    value = re.sub(r"https?://\S+", "[lien disponible dans le dossier]", value)
    value = re.sub(r"[A-Za-z0-9.!#$%&'*+/=?^_{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+", "[adresse masquée]", value)
    value = re.sub(r"(?<!\w)\+?\d(?:[ .()-]*\d){7,}(?!\w)", "[numéro masqué]", value)
    return value, value != before

def report_digest(report):
    """Hash expected in immutable report registry, before text redaction."""
    data = asdict(report)
    data.pop("report_sha256")
    return digest(data)

def _proof(resolver, auth, binding, reference, state, level):
    _reference(reference)
    proof = _resolved(resolver.resolve_evidence, auth, binding, reference)
    _need(type(proof) is EvidenceProof and proof.binding == binding and proof.reference == reference, "evidence_binding_mismatch")
    _need(isinstance(proof.sha256, str) and bool(SHA.fullmatch(proof.sha256)), "evidence_digest_invalid")
    _need(proof.action_state == state and proof.level in level, "evidence_state_not_supported")
    return proof

def _lifecycle(event):
    if event.kind in SYSTEM_EVENTS:
        return SYSTEM_EVENTS[event.kind]
    role = event.binding.role
    for candidate in ROLES:
        name = ROLE_NAMES[candidate]
        known = {
            candidate + "_dispatching": ("planned", f"{name} : affectation enregistrée ; le démarrage reste à confirmer."),
            candidate + "_handoff_received": ("completed", f"La réception du travail par {name} a été enregistrée ; aucun échange oral n’est prouvé."),
            candidate + "_completed": ("completed", f"L’étape {name} est enregistrée terminée ; son résultat reste à relire."),
            "blocker_" + candidate + "_explained": ("blocked", f"Une explication de blocage a été enregistrée pour {name}."),
        }
        if event.kind in known:
            _need(role == candidate, "event_role_mismatch")
            return known[event.kind]
    return "completed", "Un événement réel non interprété a été enregistré ; consulter le dossier de mission."

def _short(value, limit):
    if len(value) <= limit:
        return value
    cut = value[:limit-1]
    if " " in cut[max(0, len(cut)-35):]:
        cut = cut.rsplit(" ", 1)[0]
    return cut.rstrip(" .,:;") + "…"

def _worker_text(state, action, result, evidence, next_step, short):
    if short:
        action, result, next_step = _short(action, 160), _short(result, 125), _short(next_step, 75)
    prefixes = {"planned": "Je prévois : ", "started": "Je commence : ", "completed": "J’ai terminé : ", "verified": "Contrôle enregistré : ", "blocked": "Je suis bloqué sur : "}
    text = prefixes[state] + action.rstrip(".") + "."
    if result:
        text += (" Résultat observé : " if state == "verified" else " Constat : " if state == "blocked" else " Résultat déclaré : ") + result.rstrip(".") + "."
    text += " Preuve : " + evidence + "."
    if next_step:
        text += " Suite : " + next_step.rstrip(".") + "."
    return text

def project_event(caller, mission_id, event_id, resolver: Resolver):
    """Authorize, then project ONE persisted event. Accepts no client text.

    Serialize JSON, render via textContent and use ``text`` unchanged for bubble,
    subtitle, TTS and replay. ``full_text`` is an optional expanded inspector.
    Provider must separately enforce voice consent, current ACL and usage caps.
    """
    _need(isinstance(caller, str) and bool(caller) and len(caller) <= 128, "caller_invalid")
    _binding(Binding(mission_id, event_id))
    _need(resolver is not None and all(callable(getattr(resolver, method, None)) for method in ("authorize", "resolve_event", "resolve_report", "resolve_evidence")), "resolver_required")
    auth = _resolved(resolver.authorize, caller, mission_id)
    _need(type(auth) is Authorization and auth.allowed is True and auth.subject == caller and auth.mission_id == mission_id, "access_denied")
    _need(isinstance(auth.scope_id, str) and bool(IDENT.fullmatch(auth.scope_id)), "authorization_scope_invalid")
    event = _resolved(resolver.resolve_event, auth, mission_id, event_id)
    _need(type(event) is EventRecord, "event_record_invalid")
    _binding(event.binding)
    _need((event.binding.mission_id, event.binding.event_id) == (mission_id, event_id), "event_binding_mismatch")
    _need(isinstance(event.kind, str) and bool(CODE.fullmatch(event.kind)) and _timestamp(event.observed_at), "event_record_invalid")
    _need(event.source_event_sha256 == hashlib.sha256(event.kind.encode()).hexdigest(), "event_digest_mismatch")
    redacted, full = False, None
    if event.worker_report_id is None:
        state, text = _lifecycle(event)
        proof = _proof(resolver, auth, event.binding, "event:" + str(event_id), state, {"recorded"})
        _need(proof.sha256 == event.source_event_sha256, "event_proof_digest_mismatch")
        speaker, source = "system", "system_journal"
        reference, report_sha = proof.reference, None
        action, result, next_step = text, "Jalon du registre ; ne certifie pas la qualité ni une action intermédiaire.", "Consulter le dossier pour les preuves et les livrables."
    else:
        _binding(event.binding, worker=True)
        _need(event.kind in {"worker_report_recorded", "worker_progress_reported"}, "worker_report_event_required")
        _need(isinstance(event.worker_report_id, str) and bool(IDENT.fullmatch(event.worker_report_id)), "report_id_invalid")
        report = _resolved(resolver.resolve_report, auth, event, event.worker_report_id)
        _need(type(report) is WorkerReport and report.binding == event.binding and report.report_id == event.worker_report_id, "report_binding_mismatch")
        _need(_timestamp(report.recorded_at) and report.recorded_at <= event.observed_at, "report_timestamp_invalid")
        _need(isinstance(report.action_state, str) and report.action_state in STATES, "action_state_invalid")
        _need(isinstance(report.report_sha256, str) and bool(SHA.fullmatch(report.report_sha256)) and report.report_sha256 == report_digest(report), "report_digest_mismatch")
        state = report.action_state
        cleaned = [_redact(getattr(report, key)) for key in ("action_summary", "observed_result", "next_step")]
        action, result, next_step = (x[0] for x in cleaned)
        redacted = any(x[1] for x in cleaned)
        _need(bool(action), "action_summary_required")
        if state in {"planned", "started"}:
            _need(not result and not OUTCOME.search(action), "intent_execution_conflict")
        else:
            _need(bool(result), "observed_result_required")
        if state == "blocked":
            _need(bool(next_step), "blocked_next_step_required")
        levels = {"verified"} if state == "verified" else {"executed", "verified"} if state in {"completed", "blocked"} else {"recorded", "executed"}
        proof = _proof(resolver, auth, event.binding, report.evidence_reference, state, levels)
        reference, report_sha = proof.reference, report.report_sha256
        expanded = _worker_text(state, action, result, reference, next_step, False)
        _need(len(expanded) <= MAX_FULL_TEXT, "expanded_report_too_long")
        text = _worker_text(state, action, result, reference, next_step, True)
        _need(len(text) <= MAX_TEXT, "narration_too_long")
        if expanded != text:
            full = expanded
        speaker, source = event.binding.role, "recorded_worker_report"
    output = {
        "schema": SCHEMA, "available": True, **asdict(event.binding), "role": speaker,
        "voice_role": speaker,
        "step_role": event.binding.role, "observed_at": event.observed_at,
        "action_state": state, "action_summary": _short(action, 220),
        "observed_result": _short(result, 220), "evidence_reference": reference,
        "next_step": _short(next_step, 160), "text": text,
        "text_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "bubble": text, "subtitle": text, "audio_text": text, "replay_text": text,
        "speaker_source": source, "lifecycle_only": source == "system_journal",
        "quality_verdict": "not_evaluated_by_narration", "redacted": redacted,
        "authorization_scope": auth.scope_id,
        "provenance": {"kind": "system_milestone" if source == "system_journal" else "attested_worker_report", "attested": source == "recorded_worker_report", "role": event.binding.role, "source_event_sha256": event.source_event_sha256, "source_event_digest_scope": "event_code_only", "report_sha256": report_sha, "evidence_sha256": proof.sha256, "evidence_level": proof.level},
    }
    if full:
        output["full_text"] = full
    output["narration_sha256"] = digest(output)
    return output
