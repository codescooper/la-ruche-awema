"""Isolated host UDS application. No credential/network/filesystem IO on import.

Operator entry: python3 -I -B /release/service/voice_app.py --config /release/config.json
Config and all source files must be root-owned, immutable to UID31551. Only the
systemd credential copy is read, in memory; no key appears in argv/env/output.
This application serves voice routes only and never writes mission databases.
"""
from __future__ import annotations
import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import http.server
import importlib
import json
import math
import os
from pathlib import Path
import re
import signal
import socket
import socketserver
import stat
import sys
import threading
import time

RUN_UID, RUN_GID = 31551, 10001
SOCKET_PATH = Path("/run/awema-danse-voice/endpoint/voice.sock")
STATE_ROOT = Path("/var/lib/awema-danse-voice")
PROJECTION_PATH = Path("/opt/awema-danse-voice-inputs/projection/projection.sqlite")
AUTH_SOCKET_PATH = "/opt/awema-danse-voice-inputs/auth/finance.sock"
ORIGIN = "https://laruche.awema.cloud"
RELEASE_ROOT = Path(__file__).resolve().parent.parent
SOURCE_NAMES = (
    "service/voice_app.py", "service/voice_http.py", "service/voice_coordinator.py",
    "service/voice_profiles.py",
    "service/voice_store.py", "service/hard_deadline_transport.py", "provider/elevenlabs_client.py",
    "narration/narration.py", "narration/catalog_resolver.py",
    "baseline/source/viewer.py", "baseline/source/viewer_v2.py")
ROLE_NAMES = frozenset(("system", "cto", "pm", "designer", "dev", "qa", "security", "ops", "assa", "cl-producer"))
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_VOICE = re.compile(r"[A-Za-z0-9_-]{16,64}\Z")

class AppError(RuntimeError):
    """Fixed safe codes; never include a key, cookie, source row or upstream body."""

@dataclass(frozen=True)
class AppConfig:
    enabled: bool
    commercial_license_confirmed: bool
    issued_at: float
    expires_at: float
    monthly_character_budget: int
    role_voices: tuple
    model_id: str
    source_pins: tuple


def _check_metadata(info, *, owner_uid, group_gid=None, mode=None, directory=False, maximum=256 * 1024):
    valid = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode) and info.st_nlink == 1
    if (not valid or info.st_uid != owner_uid or group_gid is not None and info.st_gid != group_gid
            or info.st_mode & 0o022 or mode is not None and stat.S_IMODE(info.st_mode) != mode
            or not directory and not 0 < info.st_size <= maximum):
        raise AppError("protected_file_metadata_invalid")


def _check_ancestors(path):
    for parent in path.parents:
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise AppError("protected_ancestor_required")


def _read_protected(path, *, owner_uid=0, group_gid=None, mode=None, maximum=256 * 1024, ancestors=True):
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts:
        raise AppError("absolute_protected_path_required")
    try:
        if ancestors:
            _check_ancestors(path)
        before = path.lstat()
        _check_metadata(before, owner_uid=owner_uid, group_gid=group_gid, mode=mode, maximum=maximum)
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as source:
            after = os.fstat(source.fileno())
            _check_metadata(after, owner_uid=owner_uid, group_gid=group_gid, mode=mode, maximum=maximum)
            if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                raise AppError("protected_file_replaced")
            raw = source.read(maximum + 1)
        if not 0 < len(raw) <= maximum:
            raise AppError("protected_file_size_invalid")
        return raw
    except AppError:
        raise
    except Exception:
        raise AppError("protected_file_unavailable") from None


def parse_config(raw, *, now=None):
    """Strict nonsecret operator configuration; no paths/models/budgets from HTTP."""
    if type(raw) is not bytes or not 0 < len(raw) <= 16384:
        raise AppError("invalid_voice_configuration")
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise AppError("invalid_voice_configuration")
            value[key] = item
        return value
    try:
        data = json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: None)
        expected = {"schema", "enabled", "commercial_license_confirmed", "issued_at", "expires_at",
                    "monthly_character_budget", "role_voices", "model_id", "source_pins"}
        current = time.time() if now is None else now
        if (type(data) is not dict or set(data) != expected or data["schema"] != "awema-danse-voice-app-v1"
                or type(data["enabled"]) is not bool or type(data["commercial_license_confirmed"]) is not bool
                or any(type(data[k]) not in (int, float) or not math.isfinite(data[k]) for k in ("issued_at", "expires_at"))
                or not 0 < data["issued_at"] <= current + 5
                or not data["issued_at"] < data["expires_at"] <= data["issued_at"] + 7 * 86400
                or type(data["monthly_character_budget"]) is not int or data["monthly_character_budget"] not in (1000, 10000)
                or data["model_id"] != "eleven_multilingual_v2"
                or type(data["role_voices"]) is not dict or not data["role_voices"]
                or not set(data["role_voices"]) <= ROLE_NAMES
                or any(type(v) is not str or not _VOICE.fullmatch(v) for v in data["role_voices"].values())
                or type(data["source_pins"]) is not dict or set(data["source_pins"]) != set(SOURCE_NAMES)
                or any(type(v) is not str or not _SHA.fullmatch(v) for v in data["source_pins"].values())):
            raise AppError("invalid_voice_configuration")
        return AppConfig(data["enabled"], data["commercial_license_confirmed"], float(data["issued_at"]),
            float(data["expires_at"]), data["monthly_character_budget"], tuple(sorted(data["role_voices"].items())), data["model_id"],
            tuple(sorted(data["source_pins"].items())))
    except AppError:
        raise
    except Exception:
        raise AppError("invalid_voice_configuration") from None


def load_config(path):
    return parse_config(_read_protected(path, owner_uid=0, group_gid=RUN_GID, mode=0o440, maximum=16384))


def load_credential():
    """Read only the systemd credential copy, never the operator /etc key file."""
    value = None
    try:
        directory = Path(os.environ.get("CREDENTIALS_DIRECTORY", ""))
        if not directory.is_absolute() or ".." in directory.parts:
            raise AppError("voice_credential_unavailable")
        info = directory.lstat()
        uid = os.geteuid()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, uid) or info.st_mode & 0o022:
            raise AppError("voice_credential_unavailable")
        target = directory / "elevenlabs.key"
        info = target.lstat()
        if info.st_uid not in (0, uid) or stat.S_IMODE(info.st_mode) not in (0o400, 0o600):
            raise AppError("voice_credential_unavailable")
        raw = _read_protected(target, owner_uid=info.st_uid, mode=stat.S_IMODE(info.st_mode), maximum=512, ancestors=False)
        value = raw.decode("ascii")
        if not re.fullmatch(r"[A-Za-z0-9_-]{16,512}", value):
            raise AppError("voice_credential_unavailable")
        return value
    except Exception:
        value = None
        raise AppError("voice_credential_unavailable") from None


def load_components(config):
    """Verify all source bytes before imports and reject preloaded wrong modules."""
    for name, digest in config.source_pins:
        if hashlib.sha256(_read_protected(RELEASE_ROOT / name)).hexdigest() != digest:
            raise AppError("voice_source_integrity_failed")
    paths = [RELEASE_ROOT / x for x in ("service", "provider", "narration", "baseline/source")]
    for path in paths:
        value = str(path)
        if value not in sys.path:
            sys.path.insert(0, value)
    names = {"voice_http": "service/voice_http.py", "voice_coordinator": "service/voice_coordinator.py",
        "voice_profiles": "service/voice_profiles.py",
        "voice_store": "service/voice_store.py", "hard_deadline_transport": "service/hard_deadline_transport.py",
        "elevenlabs_client": "provider/elevenlabs_client.py", "narration": "narration/narration.py",
        "catalog_resolver": "narration/catalog_resolver.py", "viewer": "baseline/source/viewer.py",
        "viewer_v2": "baseline/source/viewer_v2.py"}
    modules = {}
    for name, path in names.items():
        module = importlib.import_module(name)
        if Path(module.__file__).resolve() != (RELEASE_ROOT / path).resolve():
            raise AppError("voice_module_origin_invalid")
        modules[name] = module
    # Constant host paths: neither policy JSON nor client JSON can redirect these.
    modules["viewer_v2"].CACHE = PROJECTION_PATH
    modules["viewer"].AUTH_SOCKET = AUTH_SOCKET_PATH
    return modules


def build_voice_http(config, *, components=None, key_loader=None, provider_builder=None,
                     catalog_factory=None, clock=None):
    """Trusted composition function; injections are for offline qualification only."""
    modules = load_components(config) if components is None else components
    clock = clock or (lambda: datetime.now(timezone.utc))
    hc, cc, cr = modules["voice_http"], modules["voice_coordinator"], modules["catalog_resolver"]
    policy = cc.Policy(enabled=config.enabled, commercial_license_confirmed=config.commercial_license_confirmed,
        expires_at=config.expires_at, monthly_character_budget=config.monthly_character_budget, role_voices=config.role_voices,
        model_id=config.model_id)
    active = config.enabled and config.commercial_license_confirmed and clock().timestamp() < config.expires_at
    api_key = (key_loader or load_credential)() if active and provider_builder is None else None
    if active and provider_builder is None:
        pins = dict(config.source_pins)
        transport = modules["hard_deadline_transport"].HardDeadlineProcessTransport(
            expected_script_sha256=pins["service/hard_deadline_transport.py"],
            expected_provider_sha256=pins["provider/elevenlabs_client.py"])
        def provider_builder():
            provider = modules["elevenlabs_client"]
            # Per-request transient guard; the persistent monthly ledger is global.
            return provider.ElevenLabsClient(provider.VoiceConfig(enabled=True,
                allowed_voice_ids=frozenset(v for _, v in config.role_voices),
                max_request_characters=600, max_total_characters=600, timeout_seconds=15.0,
                max_audio_bytes=4 * 1024 * 1024), api_key=api_key, transport=transport)
    def coordinator_factory(*, caller, reauthenticate, generation_binding):
        session = reauthenticate()
        if session.user != caller or session.generation != generation_binding:
            raise AppError("voice_session_changed")
        original = cr.SessionIdentity(session.user, session.role, session.generation)
        def current():
            refreshed = reauthenticate()
            return cr.SessionIdentity(refreshed.user, refreshed.role, refreshed.generation)
        resolver = cr.CatalogResolver(original, reauthenticate=current, catalog_factory=catalog_factory,
                                      clock=lambda: clock().timestamp())
        provider = provider_builder() if active and provider_builder is not None else None
        def profile_session_check(candidate):
            try:
                return candidate == caller and current() == original
            except Exception:
                return False
        return modules["voice_profiles"].ProfileVoiceCoordinator(policy=policy, resolver=resolver, store_root=STATE_ROOT,
            provider=provider, clock=clock, profile_session_check=profile_session_check)
    return hc.VoiceHTTP(coordinator_factory=coordinator_factory,
        authenticate=modules["viewer"].authenticate, origin=ORIGIN, clock=lambda: clock().timestamp())


def make_handler(api):
    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "AWEMA-Voice"
        sys_version = ""
        def setup(self):
            super().setup()
            self.connection.settimeout(10)
        def log_message(self, *_):
            pass
        def send(self, status, value, mime="application/json; charset=utf-8"):
            raw = value if type(value) is bytes else json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            self.close_connection = True
            self.send_response(status)
            for key, item in {"Content-Type": mime, "Content-Length": str(len(raw)), "Connection": "close",
                "Cache-Control": "private, no-store", "Vary": "Cookie", "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "no-referrer", "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
                "Permissions-Policy": "camera=(), microphone=(), geolocation=()"}.items():
                self.send_header(key, item)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(raw)
        def send_error(self, code, message=None, explain=None):
            self.send(code, {"error": "voice_http_request_rejected"})
        def _route(self):
            if not api.matches(self.path):
                return self.send(404, {"error": "voice_route_missing"})
            return api.handle(self)
        do_GET = do_HEAD = do_POST = _route
        def _denied(self):
            self.send(405, {"error": "voice_method_denied"})
        do_PUT = do_PATCH = do_DELETE = do_OPTIONS = do_CONNECT = do_TRACE = _denied
    return Handler


def validate_runtime():
    if os.name != "posix" or os.geteuid() != RUN_UID or os.getegid() != RUN_GID:
        raise AppError("dedicated_nonroot_voice_identity_required")
    for path, mode in ((STATE_ROOT, 0o700), (SOCKET_PATH.parent, 0o750)):
        try:
            _check_metadata(path.lstat(), owner_uid=RUN_UID, group_gid=RUN_GID, mode=mode, directory=True)
        except Exception:
            raise AppError("private_voice_runtime_directory_invalid") from None


def prepare_socket(path=SOCKET_PATH):
    """Remove only an inactive, exactly owned Unix socket; never a generic file."""
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != RUN_UID or info.st_gid != RUN_GID or stat.S_IMODE(info.st_mode) != 0o660:
        raise AppError("unsafe_voice_socket")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
        probe.settimeout(.3)
        try:
            probe.connect(str(path))
        except ConnectionRefusedError:
            pass
        except Exception:
            raise AppError("voice_socket_probe_uncertain") from None
        else:
            raise AppError("voice_socket_already_active")
    after = path.lstat()
    if (info.st_dev, info.st_ino) != (after.st_dev, after.st_ino):
        raise AppError("unsafe_voice_socket")
    path.unlink()


def serve(api):
    validate_runtime()
    os.umask(0o077)
    prepare_socket()
    base = getattr(socketserver, "UnixStreamServer", None)
    if base is None:
        raise AppError("unix_voice_service_required")
    class Server(socketserver.ThreadingMixIn, base):
        daemon_threads = True
        block_on_close = False
        request_queue_size = 8
        def __init__(self, *args, **kwargs):
            self._slots = threading.BoundedSemaphore(8)
            super().__init__(*args, **kwargs)
        def process_request(self, request, address):
            if not self._slots.acquire(blocking=False):
                request.close()
                return
            try:
                super().process_request(request, address)
            except Exception:
                self._slots.release()
                raise
        def process_request_thread(self, request, address):
            try:
                super().process_request_thread(request, address)
            finally:
                self._slots.release()
        def handle_error(self, request, address):
            pass
    with Server(str(SOCKET_PATH), make_handler(api)) as server:
        os.chmod(SOCKET_PATH, 0o660, follow_symlinks=False)
        identity = SOCKET_PATH.lstat()
        try:
            server.serve_forever(poll_interval=.2)
        finally:
            try:
                current = SOCKET_PATH.lstat()
                if stat.S_ISSOCK(current.st_mode) and (current.st_dev, current.st_ino) == (identity.st_dev, identity.st_ino):
                    SOCKET_PATH.unlink()
            except FileNotFoundError:
                pass


def main():
    parser = argparse.ArgumentParser(description="AWEMA private voice UDS service")
    parser.add_argument("--config", required=True)
    args = parser.parse_args()
    validate_runtime()
    config = load_config(Path(args.config))
    api = build_voice_http(config)
    def stop(_signal, _frame):
        raise KeyboardInterrupt()
    signal.signal(signal.SIGTERM, stop)
    serve(api)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
    except Exception:
        raise SystemExit("voice_service_start_or_runtime_failed") from None
