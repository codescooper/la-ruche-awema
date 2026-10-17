"""Read-only lifecycle resolver for the existing private Catalog projection.

No network call, filesystem write, cookie/key lookup or service operation. The
server supplies an already-authenticated identity, a live reauthentication
callback and (optionally) an injected Catalog factory. Only fixed journal text
can be projected: today's Catalog has no attested worker progress registry.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import math
import re
import time
from typing import Callable
from narration import (Authorization, Binding, EventRecord, EvidenceProof,
                       NarrationError, ROLES, SYSTEM_EVENTS, _lifecycle,
                       canonical_bytes)

_MID = re.compile(r"f_[a-f0-9]{24}\Z")
_HEX = re.compile(r"[a-f0-9]{64}\Z")
_CODE = re.compile(r"[a-z][a-z0-9_-]{0,95}\Z")
_ROLE_SUFFIXES = ("_dispatching", "_handoff_received", "_completed")


def _need(condition, code):
    if not condition:
        raise NarrationError(code)


@dataclass(frozen=True)
class SessionIdentity:
    """Trusted server identity; generation is an opaque persistent 64-hex tag.

    Legacy viewer.authenticate currently returns user+role only. Its HTTP wrapper
    must provide a stable server-generated session-generation tag and revalidate
    the real session each time. Never take generation/caller from request JSON.
    """
    user: str
    role: str
    generation: str
    active: bool = True
    acl_policy_version: str = "owner-director-ownmission-v1"


def _identity(identity):
    _need(type(identity) is SessionIdentity, "session_identity_incomplete")
    _need(isinstance(identity.user, str) and 0 < len(identity.user) <= 128
          and not any(ord(ch) < 32 for ch in identity.user), "session_identity_incomplete")
    _need(identity.role in ("owner", "director") and identity.active is True,
          "session_not_authorized")
    _need(isinstance(identity.generation, str) and bool(_HEX.fullmatch(identity.generation)),
          "session_identity_incomplete")
    _need(isinstance(identity.acl_policy_version, str)
          and bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,95}",identity.acl_policy_version)),
          "acl_policy_version_invalid")
    return identity


def _default_catalog(user):
    # Lazy import only: importing this module does not open a DB or authenticate.
    from viewer_v2 import Catalog
    return Catalog(user)


class CatalogResolver:
    """Resolver accepted directly by narration.project_event().

    Caller is bound to the constructor's authenticated user. Each operation
    revalidates that identity and mission ACL before and after the read; the
    latter uses a *fresh* Catalog snapshot to see replacement/revocation. The
    Catalog itself enforces immutable projection ownership, RO SQLite, query_only
    transaction and the ten-second freshness limit. We check those invariants
    again before reading. No source text/summary participates in narration.
    """
    def __init__(self, session: SessionIdentity, *,
                 reauthenticate: Callable[[], SessionIdentity],
                 catalog_factory=None, clock=None):
        self._session = _identity(session)
        _need(callable(reauthenticate), "session_revalidation_required")
        _need(catalog_factory is None or callable(catalog_factory), "catalog_factory_invalid")
        _need(clock is None or callable(clock), "clock_invalid")
        self._reauthenticate = reauthenticate
        self._catalog_factory = catalog_factory or _default_catalog
        self._clock = clock or time.time

    def _current(self):
        try:
            current = _identity(self._reauthenticate())
        except Exception:
            raise NarrationError("session_not_authorized") from None
        _need(current == self._session, "session_changed")
        return current

    def _scope(self, mission_id):
        # Stable across re-login/restart: session generation is a live identity
        # check, NEVER a new billing/cache partition. Role/mission/ACL version
        # segregate access policies. If project grants are later introduced,
        # the server must include their revision in acl_policy_version.
        return hashlib.sha256(canonical_bytes([
            "catalog-narration-v1", self._session.user,
            self._session.role, mission_id, self._session.acl_policy_version,
        ])).hexdigest()

    @staticmethod
    def _ids(mission_id, event_id=None):
        _need(isinstance(mission_id, str) and bool(_MID.fullmatch(mission_id)), "mission_id_invalid")
        _need(event_id is None or type(event_id) is int and 0 < event_id < 2**63, "event_id_invalid")

    def _catalog_guard(self, catalog):
        observed, now = catalog.observed, self._clock()
        _need(type(observed) in (int, float) and math.isfinite(observed)
              and type(now) in (int, float) and math.isfinite(now)
              and -3 <= now-observed <= 10, "projection_stale")
        _need(catalog.conn is not None and catalog.conn.in_transaction,
              "read_transaction_required")
        _need(catalog.conn.execute("PRAGMA query_only").fetchone()[0] == 1,
              "query_only_required")

    @contextmanager
    def _catalog(self, mission_id):
        identity = self._current()
        user = {"user": identity.user, "role": identity.role}
        try:
            with self._catalog_factory(user) as catalog:
                self._catalog_guard(catalog)
                _need(catalog.mission(mission_id)["id"] == mission_id, "mission_not_authorized")
                yield catalog
                self._catalog_guard(catalog)
                _need(catalog.mission(mission_id)["id"] == mission_id, "mission_not_authorized")
            self._current()
            # A fresh projection, never a post-check against the old snapshot.
            with self._catalog_factory(user) as current:
                self._catalog_guard(current)
                _need(current.mission(mission_id)["id"] == mission_id, "mission_not_authorized")
            self._current()
        except NarrationError:
            raise
        except Exception:
            raise NarrationError("catalog_unavailable") from None

    def authorize(self, caller, mission_id):
        self._ids(mission_id)
        if caller != self._session.user:
            # Do not open a mission to answer an unrelated caller.
            return Authorization(str(caller), self._scope(mission_id), mission_id, False)
        with self._catalog(mission_id):
            pass
        return Authorization(self._session.user, self._scope(mission_id), mission_id, True)

    def _authorized(self, authorization, mission_id):
        self._ids(mission_id)
        _need(type(authorization) is Authorization and authorization.allowed is True
              and authorization.subject == self._session.user
              and authorization.mission_id == mission_id
              and authorization.scope_id == self._scope(mission_id), "access_denied")

    @staticmethod
    def _event_role(kind, agent):
        for role in ROLES:
            if kind in {role+suffix for suffix in _ROLE_SUFFIXES} | {"blocker_"+role+"_explained"}:
                _need(agent == role, "event_role_mismatch")
                return role
        # System lifecycle events, and future code-only journal events, cannot
        # acquire an agent voice from a freeform summary or spoofed agent field.
        _need(agent == "system", "event_role_mismatch")
        return None

    def resolve_event(self, authorization, mission_id, event_id):
        self._ids(mission_id, event_id)
        self._authorized(authorization, mission_id)
        with self._catalog(mission_id) as catalog:
            row = catalog.conn.execute(
                "SELECT id,agent,kind,created,source_event_sha256 FROM events "
                "WHERE mission_id=? AND id=?", (mission_id, event_id)).fetchone()
            _need(row is not None, "event_missing")
            kind, source_sha = row["kind"], row["source_event_sha256"]
            _need(type(row["id"]) is int and row["id"] == event_id,
                  "event_binding_mismatch")
            _need(isinstance(kind, str) and bool(_CODE.fullmatch(kind))
                  and kind != "unmapped", "event_code_not_attestable")
            _need(source_sha == hashlib.sha256(kind.encode("utf-8")).hexdigest(),
                  "event_digest_mismatch")
            created = row["created"]
            _need(type(created) in (int, float) and math.isfinite(created)
                  and created >= 0, "event_timestamp_invalid")
            role = self._event_role(kind, row["agent"])
            # Current projection has no ordinal/attempt/run/checkpoint binding.
            # Even a terminal event stays a system milestone with those unknown.
            result = EventRecord(Binding(mission_id, event_id, role), kind,
                                 created, source_sha, worker_report_id=None)
        return result

    def resolve_report(self, authorization, event, report_id):
        _need(type(event) is EventRecord, "event_record_invalid")
        self._authorized(authorization, event.binding.mission_id)
        with self._catalog(event.binding.mission_id):
            pass
        raise NarrationError("worker_reports_unavailable")

    def resolve_evidence(self, authorization, binding, reference):
        _need(type(binding) is Binding, "binding_invalid")
        _need(reference == "event:"+str(binding.event_id), "journal_reference_required")
        event = self.resolve_event(authorization, binding.mission_id, binding.event_id)
        _need(event.binding == binding, "evidence_binding_mismatch")
        state, _ = _lifecycle(event)
        # This digest attests only the projected code, not the whole source row.
        return EvidenceProof(binding, reference, event.source_event_sha256,
                             state, "recorded")
