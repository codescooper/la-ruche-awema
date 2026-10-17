"""Offline private TTS ledger/cache. No network, provider credentials, or logs.

Reserve BEFORE generation. Only a fresh should_generate=True ticket permits ONE
provider call. The durable row is already uncertain: crashes, invalid responses,
and even new operation IDs never allow automatic rebilling. No quota release or
retry API is provided. Operator reconciliation must be designed separately.

Monthly limits count Unicode code points, globally across scopes in this store,
not provider invoice credits. UTC month rollover does not clear old uncertainty.
authorize(scope, action) must check the current caller, not trust a supplied scope.
Actions: reserve, complete, read, inspect. Every cache read rechecks authorization.
Linux: dedicated user, directories0700/files0600, local filesystem. Windows chmod
does not replace ACLs. SQLite FULL sync/DELETE journal/BEGIN IMMEDIATE coordinate
threads/processes. Backup the DB and cache together, under an operator snapshot.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import secrets
import sqlite3
import stat

_SCOPE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_:.-]{0,127}\Z")
_OP = re.compile(r"[0-9a-f]{64}\Z")
_VOICE = re.compile(r"[A-Za-z0-9_-]{16,64}\Z")
_MODEL = re.compile(r"[A-Za-z0-9_-]{3,96}\Z")
_SETTINGS = frozenset({"stability", "similarity_boost", "style", "use_speaker_boost", "speed", "seed"})

class StoreError(RuntimeError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)

@dataclass(frozen=True)
class Reservation:
    scope: str
    operation_id: str
    cache_key: str
    status: str
    should_generate: bool
    characters_reserved: int
    period: str
    claim: str | None = field(default=None, repr=False, compare=False)

@dataclass(frozen=True)
class CachedAudio:
    cache_key: str
    audio_sha256: str
    audio: bytes = field(repr=False)
    content_type: str = "audio/mpeg"

def _sha(value):
    return hashlib.sha256(value).hexdigest()

def _identity(scope, text, voice_id, model_id, settings, maximum):
    if type(scope) is not str or not _SCOPE.fullmatch(scope):
        raise StoreError("invalid_scope")
    if (type(text) is not str or not text.strip() or len(text) > maximum
            or any((ord(c) < 32 and c not in "\n\t") or 0xD800 <= ord(c) <= 0xDFFF for c in text)):
        raise StoreError("invalid_narration")
    if type(voice_id) is not str or not _VOICE.fullmatch(voice_id):
        raise StoreError("invalid_voice")
    if type(model_id) is not str or not _MODEL.fullmatch(model_id):
        raise StoreError("invalid_model")
    settings = {} if settings is None else settings
    if type(settings) is not dict or not set(settings) <= _SETTINGS:
        raise StoreError("invalid_settings")
    for name, value in settings.items():
        if name == "use_speaker_boost":
            valid = type(value) is bool
        elif name == "seed":
            valid = type(value) is int and 0 <= value <= 4294967295
        else:
            valid = type(value) in (int, float) and math.isfinite(value)
            valid = valid and (.7 <= value <= 1.2 if name == "speed" else 0 <= value <= 1)
        if not valid:
            raise StoreError("invalid_settings")
    canon = json.dumps(settings, sort_keys=True, separators=(",", ":"), allow_nan=False)
    data = json.dumps([1, scope, text, voice_id, model_id, "mp3_44100_128", canon],
                      ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return _sha(data), _sha(text.encode("utf-8")), _sha(canon.encode())

def valid_mp3(audio, *, maximum_bytes=4 * 1024 * 1024):
    """Structural Layer III validation; NOT a speech/quality/codec decode test."""
    if type(audio) is not bytes or not 48 <= len(audio) <= maximum_bytes:
        return False
    pos, frames = 0, 0
    if audio.startswith(b"ID3"):
        if len(audio) < 10 or audio[3] not in (2, 3, 4) or audio[4] == 255:
            return False
        tag = audio[6:10]
        if any(x & 128 for x in tag):
            return False
        size = (tag[0] << 21) | (tag[1] << 14) | (tag[2] << 7) | tag[3]
        if size > 1024 * 1024:
            return False
        pos = 10 + size + (10 if audio[3] == 4 and audio[5] & 16 else 0)
    end = len(audio) - (128 if len(audio) >= 128 and audio[-128:-125] == b"TAG" else 0)
    while pos < end:
        if pos + 4 > end:
            return False
        a, b, c, _ = audio[pos:pos + 4]
        version, layer, rate, sample = (b >> 3) & 3, (b >> 1) & 3, c >> 4, (c >> 2) & 3
        if a != 255 or b & 224 != 224 or version == 1 or layer != 1 or rate in (0, 15) or sample == 3:
            return False
        kbps = ([0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320]
                if version == 3 else [0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160])[rate]
        hz = [44100, 48000, 32000][sample] // (1 if version == 3 else 2 if version == 2 else 4)
        size = (144000 if version == 3 else 72000) * kbps // hz + ((c >> 1) & 1)
        if size < 24 or pos + size > end:
            return False
        frames += 1
        pos += size
    return frames >= 2 and pos == end

class VoiceStore:
    def __init__(self, root, *, monthly_character_budget, authorize, clock=None,
                 max_request_characters=2000, max_audio_bytes=4 * 1024 * 1024):
        if (type(monthly_character_budget) is not int or not 0 <= monthly_character_budget <= 1_000_000
                or not callable(authorize) or clock is not None and not callable(clock)
                or type(max_request_characters) is not int or not 1 <= max_request_characters <= 2000
                or type(max_audio_bytes) is not int or not 1024 <= max_audio_bytes <= 8 * 1024 * 1024):
            raise StoreError("invalid_configuration")
        self.root = Path(root).absolute()
        self.cache, self.database = self.root / "cache", self.root / "voice.sqlite3"
        self.budget, self.authorize = monthly_character_budget, authorize
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.max_request_characters, self.max_audio_bytes = max_request_characters, max_audio_bytes
        for directory in (self.root, self.cache):
            try:
                directory.mkdir(mode=0o700, exist_ok=True)
                self._private(directory, directory=True)
            except StoreError:
                raise
            except Exception:
                raise StoreError("private_directory_unavailable") from None
        try:
            fd = os.open(self.database, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except FileExistsError:
            pass
        except Exception:
            raise StoreError("private_database_unavailable") from None
        else:
            os.close(fd)
        self._private(self.database)
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("CREATE TABLE IF NOT EXISTS policy (id INTEGER PRIMARY KEY CHECK(id=1), version INTEGER NOT NULL, monthly_budget INTEGER NOT NULL)")
            db.execute("INSERT OR IGNORE INTO policy VALUES (1,1,?)", (self.budget,))
            if tuple(db.execute("SELECT version,monthly_budget FROM policy WHERE id=1").fetchone()) != (1, self.budget):
                raise StoreError("budget_or_schema_policy_mismatch")
            db.execute("""CREATE TABLE IF NOT EXISTS generations (
                scope TEXT NOT NULL, cache_key TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('uncertain','complete')),
                period TEXT NOT NULL, characters INTEGER NOT NULL CHECK(characters>0), text_sha TEXT NOT NULL,
                voice_id TEXT NOT NULL, model_id TEXT NOT NULL, settings_sha TEXT NOT NULL, claim_sha TEXT NOT NULL,
                audio_sha TEXT, audio_size INTEGER, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
                PRIMARY KEY(scope,cache_key))""")
            db.execute("""CREATE TABLE IF NOT EXISTS operations (
                scope TEXT NOT NULL, operation_id TEXT NOT NULL, cache_key TEXT NOT NULL, created_at TEXT NOT NULL,
                PRIMARY KEY(scope,operation_id), FOREIGN KEY(scope,cache_key) REFERENCES generations(scope,cache_key))""")
            db.execute("CREATE INDEX IF NOT EXISTS generations_period ON generations(period)")
            db.commit()

    def __repr__(self):
        return "VoiceStore(private=True, durable_budget=True, no_provider_credentials=True)"

    @staticmethod
    def _private(path, *, directory=False):
        try:
            st = path.lstat()
            valid = stat.S_ISDIR(st.st_mode) if directory else stat.S_ISREG(st.st_mode) and st.st_nlink == 1
            if not valid or os.name == "posix" and st.st_uid != os.geteuid():
                raise StoreError("unsafe_storage_path")
            if os.name == "posix":
                os.chmod(path, 0o700 if directory else 0o600, follow_symlinks=False)
            else:
                # Windows has no POSIX privacy mode; caller must supply its ACL.
                os.chmod(path, 0o700 if directory else 0o600)
        except StoreError:
            raise
        except Exception:
            raise StoreError("unsafe_storage_path") from None

    @contextmanager
    def _connect(self):
        self._private(self.root, directory=True)
        self._private(self.database)
        try:
            db = sqlite3.connect(self.database, timeout=15, isolation_level=None)
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA journal_mode=DELETE")
            db.execute("PRAGMA synchronous=FULL")
            db.execute("PRAGMA foreign_keys=ON")
        except Exception:
            raise StoreError("storage_unavailable") from None
        try:
            with db:
                yield db
        finally:
            db.close()

    def _auth(self, scope, action):
        if type(scope) is not str or not _SCOPE.fullmatch(scope):
            raise StoreError("invalid_scope")
        allowed = False
        try:
            allowed = self.authorize(scope, action) is True
        except Exception:
            pass
        if not allowed:
            raise StoreError("scope_not_authorized")

    def _now(self):
        try:
            value = self.clock()
            if not isinstance(value, datetime) or value.tzinfo is None:
                raise ValueError()
            value = value.astimezone(timezone.utc)
            return value.strftime("%Y-%m"), value.isoformat()
        except Exception:
            raise StoreError("invalid_clock") from None

    @staticmethod
    def _ticket(row, operation_id, claim=None):
        return Reservation(row["scope"], operation_id, row["cache_key"], row["status"],
                           claim is not None, row["characters"], row["period"], claim)

    def reserve(self, *, scope, operation_id, text, voice_id, model_id="eleven_multilingual_v2", settings=None):
        self._auth(scope, "reserve")
        if type(operation_id) is not str or not _OP.fullmatch(operation_id):
            raise StoreError("invalid_operation_id")
        key, text_sha, settings_sha = _identity(scope, text, voice_id, model_id, settings, self.max_request_characters)
        period, now = self._now()
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            existing = db.execute("SELECT cache_key FROM operations WHERE scope=? AND operation_id=?", (scope, operation_id)).fetchone()
            if existing is not None and existing[0] != key:
                raise StoreError("idempotency_conflict")
            row = db.execute("SELECT * FROM generations WHERE scope=? AND cache_key=?", (scope, key)).fetchone()
            claim = None
            if row is None:
                spent = db.execute("SELECT COALESCE(SUM(characters),0) FROM generations WHERE period=?", (period,)).fetchone()[0]
                if spent + len(text) > self.budget:
                    raise StoreError("monthly_character_budget_exceeded")
                claim = secrets.token_hex(32)
                db.execute("INSERT INTO generations VALUES (?,?, 'uncertain', ?,?,?,?,?,?,?, NULL,NULL,?,?)",
                           (scope, key, period, len(text), text_sha, voice_id, model_id, settings_sha, _sha(claim.encode()), now, now))
                row = db.execute("SELECT * FROM generations WHERE scope=? AND cache_key=?", (scope, key)).fetchone()
            db.execute("INSERT OR IGNORE INTO operations VALUES (?,?,?,?)", (scope, operation_id, key, now))
            db.commit()
        return self._ticket(row, operation_id, claim)

    def operation(self, *, scope, operation_id):
        self._auth(scope, "inspect")
        if type(operation_id) is not str or not _OP.fullmatch(operation_id):
            raise StoreError("invalid_operation_id")
        with self._connect() as db:
            row = db.execute("SELECT g.* FROM generations g JOIN operations o USING(scope,cache_key) WHERE o.scope=? AND o.operation_id=?", (scope, operation_id)).fetchone()
        return None if row is None else self._ticket(row, operation_id)

    def usage(self, *, scope):
        """Scope-only totals; global enforcement does not expose other scopes."""
        self._auth(scope, "inspect")
        period, _ = self._now()
        with self._connect() as db:
            rows = db.execute("SELECT status,SUM(characters) AS characters FROM generations WHERE scope=? AND period=? GROUP BY status", (scope, period)).fetchall()
        return {"period": period, "scope_characters_reserved": sum(r["characters"] for r in rows),
                "scope_uncertain_characters": sum(r["characters"] for r in rows if r["status"] == "uncertain")}

    def complete(self, reservation, *, audio, content_type="audio/mpeg"):
        if type(reservation) is not Reservation:
            raise StoreError("invalid_reservation")
        self._auth(reservation.scope, "complete")
        if (type(content_type) is not str or content_type.split(";", 1)[0].strip().lower() not in ("audio/mpeg", "audio/mp3")
                or not valid_mp3(audio, maximum_bytes=self.max_audio_bytes)):
            raise StoreError("invalid_audio_uncertain")
        if not reservation.claim or not _OP.fullmatch(reservation.claim):
            raise StoreError("generation_claim_required")
        digest, temporary = _sha(audio), None
        _, now = self._now()
        try:
            with self._connect() as db:
                db.execute("BEGIN IMMEDIATE")
                row = db.execute("SELECT g.* FROM generations g JOIN operations o USING(scope,cache_key) WHERE o.scope=? AND o.operation_id=? AND o.cache_key=?", (reservation.scope, reservation.operation_id, reservation.cache_key)).fetchone()
                if row is None or not secrets.compare_digest(row["claim_sha"], _sha(reservation.claim.encode())):
                    raise StoreError("generation_claim_invalid")
                if row["status"] == "complete":
                    if row["audio_sha"] != digest:
                        raise StoreError("completed_audio_conflict")
                    return self._ticket(row, reservation.operation_id)
                self._private(self.cache, directory=True)
                target = self.cache / (reservation.cache_key + ".mp3")
                if target.exists() or target.is_symlink():
                    self._private(target)
                temporary = self.cache / ("." + secrets.token_hex(16) + ".tmp")
                fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
                with os.fdopen(fd, "wb") as output:
                    output.write(audio)
                    output.flush()
                    os.fsync(output.fileno())
                os.replace(temporary, target)
                temporary = None
                self._private(target)
                if os.name == "posix":
                    fd = os.open(self.cache, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
                    try:
                        os.fsync(fd)
                    finally:
                        os.close(fd)
                db.execute("UPDATE generations SET status='complete',audio_sha=?,audio_size=?,updated_at=? WHERE scope=? AND cache_key=?",
                           (digest, len(audio), now, reservation.scope, reservation.cache_key))
                db.commit()
                row = db.execute("SELECT * FROM generations WHERE scope=? AND cache_key=?", (reservation.scope, reservation.cache_key)).fetchone()
                return self._ticket(row, reservation.operation_id)
        finally:
            if temporary is not None:
                try:
                    temporary.unlink()
                except OSError:
                    pass

    def get_cached(self, *, scope, operation_id):
        self._auth(scope, "read")
        if type(operation_id) is not str or not _OP.fullmatch(operation_id):
            raise StoreError("invalid_operation_id")
        with self._connect() as db:
            row = db.execute("SELECT g.* FROM generations g JOIN operations o USING(scope,cache_key) WHERE o.scope=? AND o.operation_id=?", (scope, operation_id)).fetchone()
        if row is None or row["status"] != "complete":
            return None
        self._private(self.cache, directory=True)
        path = self.cache / (row["cache_key"] + ".mp3")
        self._private(path)
        try:
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            with os.fdopen(fd, "rb") as source:
                st = os.fstat(source.fileno())
                if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
                    raise StoreError("unsafe_storage_path")
                data = source.read(self.max_audio_bytes + 1)
        except StoreError:
            raise
        except Exception:
            raise StoreError("cached_audio_unavailable") from None
        if len(data) != row["audio_size"] or _sha(data) != row["audio_sha"] or not valid_mp3(data, maximum_bytes=self.max_audio_bytes):
            raise StoreError("cached_audio_corrupt")
        self._auth(scope, "read")
        return CachedAudio(row["cache_key"], row["audio_sha"], data)
