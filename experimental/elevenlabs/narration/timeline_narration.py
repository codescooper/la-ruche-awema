"""Candidate canonical journal timeline. No DB/network/provider operation.

Patch recipe (not applied here) for viewer_v2.Catalog.timeline:

    def timeline(self, row, after=0, limit=500, *, caller, narration_resolver):
        # Existing SELECT/read-only timeline construction produces `packet`.
        ...
        return project_timeline(caller, packet, narration_resolver)

The HTTP adapter must pass caller from its authenticated session and construct a
CatalogResolver from trusted live session revalidation, never request JSON. Route
and narration GET must use that same resolver policy. Do not return the legacy
packet as a silent fallback if canonical projection fails; report a fixed
unavailable error and leave mission execution independent from the observer.

Today Catalog contains lifecycle milestones only. Every spoken timeline event is
therefore journal/say, never an agent dialogue or report. `awema_role` preserves
the actual affected role for observation-state status; it is NOT the speaker.
The upstream kind=report prefix and order labels are removed to avoid changing
the canonical spoken text. True worker reports need a separate future adapter
and persistent evidence registry; they are explicitly refused by this candidate.
"""
from __future__ import annotations

import copy
import hashlib
import re
from narration import Authorization, NarrationError, ROLES, digest, project_event

SCHEMA = "awema-danse-canonical-timeline-v1"
MID = re.compile(r"f_[a-f0-9]{24}\Z")
SHA = re.compile(r"[a-f0-9]{64}\Z")
CODE = re.compile(r"[a-z][a-z0-9_-]{0,95}\Z")
MAX_EVENTS = 1000
MAX_SQLITE_ID = 2**63-1
EVENT_FIELDS = frozenset(("k", "source_event_id", "ts", "t", "agent", "kind",
                          "text", "fr", "awema_kind", "awema_role", "to", "title",
                          "awema_narration"))


def _need(condition, code):
    if not condition:
        raise NarrationError(code)


def _role_id(role):
    return "main" if role == "cto" else role if role in ROLES else "journal"


def project_timeline(caller, timeline, resolver):
    """Return a new timeline with canonical system narration on every milestone.

    Source must already be ACL-filtered, but each event is independently resolved
    by project_event against the trusted current policy. IDs, code hashes and
    timestamps bind the displayed event to that exact persisted source. Only the
    event code is covered by source_event_sha256; the resolver/RO registry remains
    responsible for the source row, timestamp and mission binding.

    Text equality here is byte-for-byte. Client bubble/subtitle/replay must use
    event.text unchanged (no `Terminé`, paraphrase, translation or truncation);
    the voice response should match both narration_sha256 and text_sha256.
    """
    _need(type(timeline) is dict, "timeline_invalid")
    mid = timeline.get("id")
    _need(isinstance(mid, str) and bool(MID.fullmatch(mid)), "mission_id_invalid")
    _need(type(timeline.get("mission")) is dict
          and timeline["mission"].get("id") == mid, "timeline_mission_mismatch")
    _need(timeline.get("proj") == "awema"
          and timeline.get("ep") == "awema-"+mid, "timeline_identity_invalid")
    # Empty pages still contain private mission metadata. Never use an empty
    # event list to bypass current authorization or mix policy revisions.
    _need(callable(getattr(resolver,"authorize",None)),"resolver_required")
    try:
        authorization = resolver.authorize(caller,mid)
    except Exception:
        raise NarrationError("timeline_access_unavailable") from None
    _need(type(authorization) is Authorization and authorization.allowed is True
          and authorization.subject == caller and authorization.mission_id == mid,
          "access_denied")
    events = timeline.get("events")
    _need(type(events) is list and len(events) <= MAX_EVENTS, "timeline_event_window_invalid")
    agents = timeline.get("agents")
    _need(type(agents) is list and len(agents) <= 51, "timeline_agents_invalid")
    seen = set()
    for agent in agents:
        _need(type(agent) is dict and isinstance(agent.get("id"), str)
              and agent["id"] in {"main", "journal"} | (set(ROLES)-{"cto"})
              and agent["id"] not in seen, "timeline_agents_invalid")
        seen.add(agent["id"])
    seq = timeline.get("seq")
    _need(type(seq) is int and 0 <= seq <= MAX_SQLITE_ID, "timeline_sequence_invalid")
    result = copy.deepcopy(timeline)
    projected = []
    previous = 0
    for source in events:
        _need(type(source) is dict and set(source) <= EVENT_FIELDS,
              "timeline_event_fields_invalid")
        eid = source.get("source_event_id")
        _need(type(eid) is int and previous < eid <= MAX_SQLITE_ID
              and source.get("k") == "awema:"+str(eid), "timeline_event_identity_invalid")
        _need(eid <= seq, "timeline_sequence_invalid")
        previous = eid
        kind = source.get("awema_kind")
        _need(isinstance(kind, str) and bool(CODE.fullmatch(kind)), "timeline_event_code_invalid")
        narration = project_event(caller, mid, eid, resolver)
        _need(narration.get("mission_id") == mid and narration.get("event_id") == eid,
              "timeline_narration_binding_mismatch")
        _need(narration.get("authorization_scope") == authorization.scope_id,
              "timeline_authorization_scope_changed")
        p = narration.get("provenance", {})
        _need(narration.get("available") is True and narration.get("lifecycle_only") is True
              and narration.get("voice_role") == "system" and narration.get("role") == "system"
              and p.get("kind") == "system_milestone" and p.get("attested") is False,
              "worker_narration_not_supported_by_catalog")
        _need(p.get("source_event_digest_scope") == "event_code_only"
              and p.get("source_event_sha256") == hashlib.sha256(kind.encode("utf-8")).hexdigest(),
              "timeline_event_code_mismatch")
        ts = source.get("ts")
        _need(type(ts) is int and ts == int(narration["observed_at"]*1000),
              "timeline_event_timestamp_mismatch")
        _need(type(source.get("t")) is int and source["t"] >= 0, "timeline_relative_time_invalid")
        text = narration.get("text")
        _need(isinstance(text, str) and 0 < len(text) <= 600
              and all(narration.get(key) == text for key in ("bubble", "subtitle", "audio_text", "replay_text"))
              and narration.get("text_sha256") == hashlib.sha256(text.encode("utf-8")).hexdigest()
              and isinstance(narration.get("narration_sha256"), str)
              and bool(SHA.fullmatch(narration["narration_sha256"])), "timeline_canonical_text_invalid")
        clean = {k: copy.deepcopy(v) for k, v in source.items()
                 if k not in {"to", "title", "awema_narration"}}
        clean.update(agent="journal", kind="say", text=text, fr=text,
                     awema_role=_role_id(narration.get("step_role")),
                     awema_narration=narration)
        projected.append(clean)
    result["events"] = projected
    # A system journal profile is not a newly invented worker.
    journal = {"id": "journal", "name": "Journal système",
               "role": "Jalons automatiques — pas un agent IA",
               "roleFr": "Jalons automatiques — pas un agent IA", "type": "system"}
    result["agents"] = [a for a in result["agents"] if a["id"] != "journal"] + [journal]
    _need(type(result.get("provenance")) is dict, "timeline_provenance_invalid")
    result["provenance"]["narration_projection"] = {
        "schema": SCHEMA, "event_count": len(projected),
        "events_sha256": digest(projected),
        "speaker_policy": "system_journal_only",
        "worker_reports_available": False,
        "source_event_digest_scope": "event_code_only",
    }
    return result
