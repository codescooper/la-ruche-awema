#!/usr/bin/env python3
"""Bibliotheque d'approbation executoire — Control Plane AWEMA (contrat HOSTAPR v2).

Principes (corrections P0-1 / C-01, C-02, C-04) :
  * refus par defaut : tout ce qui n'est pas explicitement valide ET signe est refuse ;
  * liaison stricte action + tache + projet verifiee a la DECISION et a la CONSOMMATION
    (meme semantique que les tests Broker v2 : liaison approval/action, liaison tache,
    liaison projet, expiration, consommation controlee, anti-rejeu) ;
  * decideur distinct du demandeur, decideur habilite et authentifie par jeton
    (le jeton n'est jamais ecrit dans le magasin d'approbations) ;
  * usage unique + expiration + anti-rejeu (nonce, consommation atomique, verrou) ;
  * re-verification de la politique a la decision ET a la consommation ;
  * journal ecrit AVANT toute mutation ; si l'ecriture du journal echoue, l'action
    est refusee (fail-closed).

Ce module ne connait que AWEMA_CORE_ROOT (la copie isolee). Aucune ecriture ailleurs.
La cle de signature et les jetons d'approbateur vivent HORS du magasin, dans des
fichiers dont on refuse tout mode accessible au groupe ou aux autres (0600/0400).
"""
from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import os
import re
import secrets
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

SCHEMA = "awema-apr/2"
HOSTAPR_CONTRACT = "HOSTAPR v2"
CONTRACT_SCHEMA = "awema-approval-contract/2"
APPROVERS_SCHEMA = "awema-approvers/1"

STATES = ("pending", "approved", "rejected", "consumed", "expired")
TERMINAL_NEVER_DECIDABLE = ("approved", "rejected", "consumed", "expired")

APR_ID_RE = re.compile(r"^APR-\d{14,20}$")
ACTION_RE = re.compile(r"^[a-z][a-z0-9_]{2,63}$")
TASK_RE = re.compile(r"^TASK-[A-Za-z0-9][A-Za-z0-9\-]{1,63}$")
PROJECT_RE = re.compile(r"^[a-z0-9][a-z0-9\-]{1,63}$")
NONCE_RE = re.compile(r"^[0-9a-f]{32}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")

APR_FIELDS = (
    "schema", "hostapr_contract", "id", "action", "task", "project",
    "requester", "requester_kind", "reason", "status", "created_at",
    "expires_at", "nonce", "policy_digest", "task_digest", "approver", "decided_at",
    "decision_token_id", "consumed_at", "consumed_by", "sig",
)

DEFAULT_CONTRACT = {
    "schema": CONTRACT_SCHEMA,
    "hostapr_contract": HOSTAPR_CONTRACT,
    "ttl_seconds": 3600,
    "min_ttl_seconds": 1,
    "max_ttl_seconds": 86400,
    "require_distinct_approver": True,
    "single_use": True,
    "deny_unknown_actions": True,
    "key_file": "/etc/awema/approval.key",
    "approvers_file": "/etc/awema/approvers.secrets.json",
    "max_clock_skew_seconds": 300,
}


class Refus(Exception):
    """Erreur de refus : message affiche en « REFUS: ... », code de sortie 64."""


# --------------------------------------------------------------------------- #
# temps
# --------------------------------------------------------------------------- #
def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_ts(value, champ):
    if not isinstance(value, str):
        raise Refus(f"horodatage invalide ({champ}) : {value!r}")
    try:
        d = datetime.fromisoformat(value)
    except ValueError:
        raise Refus(f"horodatage illisible ({champ}) : {value!r}")
    if d.tzinfo is None:
        raise Refus(f"horodatage sans fuseau ({champ}) : {value!r}")
    return d


def _now_dt():
    return datetime.now(timezone.utc)


# --------------------------------------------------------------------------- #
# chargement strict de configuration
# --------------------------------------------------------------------------- #
def _read_json(path, quoi):
    p = Path(path)
    if not p.exists():
        raise Refus(f"{quoi} introuvable : {p}")
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise Refus(f"{quoi} illisible ({p}) : {exc}")


def contract(root) -> dict:
    root = Path(root)
    p = root / "config/approval-contract.json"
    if not p.exists():
        raise Refus(f"contrat d'approbation introuvable : {p}")
    c = _read_json(p, "contrat d'approbation")
    if not isinstance(c, dict) or c.get("schema") != CONTRACT_SCHEMA:
        raise Refus(f"contrat d'approbation non conforme ({CONTRACT_SCHEMA} attendu)")
    if c.get("hostapr_contract") != HOSTAPR_CONTRACT:
        raise Refus(f"contrat hote non conforme ({HOSTAPR_CONTRACT} attendu)")
    for k, v in DEFAULT_CONTRACT.items():
        c.setdefault(k, v)
    for k in ("ttl_seconds", "min_ttl_seconds", "max_ttl_seconds", "max_clock_skew_seconds"):
        if not isinstance(c[k], int) or c[k] < 0:
            raise Refus(f"contrat : valeur invalide pour {k}")
    if c["ttl_seconds"] < c["min_ttl_seconds"]:
        raise Refus("contrat : ttl_seconds < min_ttl_seconds")
    if c["ttl_seconds"] > c["max_ttl_seconds"]:
        raise Refus("contrat : ttl_seconds > max_ttl_seconds")
    return c


def approveurs(root) -> dict:
    root = Path(root)
    p = root / "config/approvers.json"
    d = _read_json(p, "registre des approbateurs")
    if not isinstance(d, dict) or d.get("schema") != APPROVERS_SCHEMA:
        raise Refus(f"registre des approbateurs non conforme ({APPROVERS_SCHEMA} attendu)")
    a = d.get("approvers")
    if not isinstance(a, dict) or not a:
        raise Refus("registre des approbateurs vide ou malforme")
    for name, spec in a.items():
        if not isinstance(name, str) or not name or len(name) > 64:
            raise Refus("nom d'approbateur invalide")
        if not isinstance(spec, dict):
            raise Refus(f"spec d'approbateur invalide : {name}")
        allowed = spec.get("may_approve")
        if not isinstance(allowed, list):
            raise Refus(f"may_approve absent ou invalide : {name}")
        for act in allowed:
            if act != "*" and not ACTION_RE.match(str(act)):
                raise Refus(f"action invalide dans may_approve ({name}) : {act!r}")
    return d


def secrets_approbateurs(path=None):
    env = os.environ.get("AWEMA_APPROVERS_SECRETS_FILE")
    path = Path(env if env else (path or "/etc/awema/approvers.secrets.json"))
    if not path.exists():
        raise Refus(f"jetons d'approbateur introuvables : {path}")
    _require_private(path, "jetons d'approbateur")
    d = _read_json(path, "jetons d'approbateur")
    if not isinstance(d, dict):
        raise Refus("jetons d'approbateur malformes")
    for name, h in d.items():
        if not isinstance(h, str) or not HEX64_RE.match(h):
            raise Refus(f"empreinte de jeton invalide pour {name}")
    return d


def _require_private(p: Path, quoi: str):
    st = p.stat()
    if st.st_mode & 0o077:
        raise Refus(f"{quoi} accessible au groupe/aux autres ({oct(st.st_mode & 0o777)}) : {p}")


# --------------------------------------------------------------------------- #
# politique d'approbation (source unique : config/approval-policy.yaml)
# --------------------------------------------------------------------------- #
def politique_path(root):
    return Path(root) / "config/approval-policy.yaml"


def politique_digest(root) -> str:
    p = politique_path(root)
    if not p.exists():
        raise Refus(f"politique introuvable : {p}")
    return hashlib.sha256(p.read_bytes()).hexdigest()


def actions_sous_approbation(root) -> frozenset:
    p = politique_path(root)
    if not p.exists():
        raise Refus(f"politique introuvable : {p}")
    out, active = set(), False
    for line in p.read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if s == "approval_required:":
            active = True
            continue
        if active and s.startswith("- "):
            act = s[2:].strip()
            if not ACTION_RE.match(act):
                raise Refus(f"action invalide dans la politique : {act!r}")
            out.add(act)
        elif active and s and not line.startswith(" "):
            break
    if not out:
        raise Refus("politique sans liste approval_required")
    return frozenset(out)


def exige_approbation(root, action) -> bool:
    if not isinstance(action, str) or not ACTION_RE.match(action):
        raise Refus(f"action malformee : {action!r}")
    act = actions_sous_approbation(root)
    c = contract(root)
    if action in act:
        return True
    if c["deny_unknown_actions"]:
        raise Refus(f"action hors politique : {action}")
    return False


# --------------------------------------------------------------------------- #
# cle de signature
# --------------------------------------------------------------------------- #
def chemin_cle(c=None) -> Path:
    env = os.environ.get("AWEMA_APPROVAL_KEY_FILE")
    if env:
        return Path(env)
    return Path((c or {}).get("key_file", DEFAULT_CONTRACT["key_file"]))


def cle(c=None) -> bytes:
    p = chemin_cle(c)
    if not p.exists():
        raise Refus(f"cle de signature absente : {p} (refus par defaut)")
    _require_private(p, "cle de signature")
    data = p.read_bytes().strip()
    if len(data) < 32:
        raise Refus(f"cle de signature trop courte ({len(data)} octets)")
    return data


def canonical(obj: dict) -> bytes:
    return json.dumps({k: v for k, v in obj.items() if k != "sig"},
                      sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sceller(obj: dict, key: bytes) -> dict:
    obj = dict(obj)
    obj.pop("sig", None)
    obj["sig"] = hmac.new(key, canonical(obj), hashlib.sha256).hexdigest()
    return obj


def signature_valide(obj: dict, key: bytes) -> bool:
    sig = obj.get("sig")
    if not isinstance(sig, str) or not HEX64_RE.match(sig):
        return False
    attendu = hmac.new(key, canonical(obj), hashlib.sha256).hexdigest()
    return hmac.compare_digest(sig, attendu)


# --------------------------------------------------------------------------- #
# journal (ecrit AVANT la mutation ; echec => refus)
# --------------------------------------------------------------------------- #
def journal_path(root):
    return Path(root) / "data/audit/events.jsonl"


def journal(root, event, **kw):
    p = journal_path(root)
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        ligne = json.dumps({"ts": now(), "event": event, **kw}, ensure_ascii=False) + "\n"
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(fd, ligne.encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError as exc:
        raise Refus(f"journal inscriptible impossible ({exc.strerror or exc}) — action refusee")
    return ligne


def lire_journal(root):
    p = journal_path(root)
    if not p.exists():
        return []
    out = []
    for line in p.read_text(encoding="utf-8").splitlines():
        if line.strip():
            out.append(json.loads(line))
    return out


# --------------------------------------------------------------------------- #
# verrou (consommation atomique)
# --------------------------------------------------------------------------- #
@contextlib.contextmanager
def verrou(root, nom, stale_after=30.0, attente=5.0):
    d = Path(root) / "data/locks"
    try:
        d.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise Refus(f"verrou indisponible ({exc})")
    p = d / (nom + ".lock")
    limite = time.time() + attente
    while True:
        try:
            fd = os.open(p, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.write(fd, f"{os.getpid()} {now()}".encode())
            os.close(fd)
            break
        except FileExistsError:
            try:
                if time.time() - p.stat().st_mtime > stale_after:
                    p.unlink()
                    continue
            except FileNotFoundError:
                continue
            if time.time() > limite:
                raise Refus(f"verrou occupe : {nom}")
            time.sleep(0.05)
    try:
        yield p
    finally:
        try:
            p.unlink()
        except FileNotFoundError:
            pass


# --------------------------------------------------------------------------- #
# magasin
# --------------------------------------------------------------------------- #
def magasin(root) -> Path:
    return Path(root) / "data/approvals"


def chemin_apr(root, apr_id) -> Path:
    if not isinstance(apr_id, str) or not APR_ID_RE.match(apr_id):
        raise Refus(f"identifiant d'approbation malforme : {apr_id!r}")
    return magasin(root) / (apr_id + ".json")


def _ecrire_atomique(p: Path, data: str):
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(p.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, p)
    try:
        dfd = os.open(p.parent, os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    except OSError:
        pass


def ecrire_apr(root, obj, key):
    obj = sceller(obj, key)
    p = chemin_apr(root, obj["id"])
    _ecrire_atomique(p, json.dumps(obj, ensure_ascii=False, indent=2) + "\n")
    return p


def valider_apr(obj) -> None:
    """Validation stricte du payload : champs obligatoires, types, formats, coherence."""
    if not isinstance(obj, dict):
        raise Refus("approbation : objet JSON attendu")
    manquants = [k for k in APR_FIELDS if k not in obj]
    if manquants:
        raise Refus("approbation : champs obligatoires absents : " + ",".join(manquants))
    inconnus = [k for k in obj if k not in APR_FIELDS]
    if inconnus:
        raise Refus("approbation : champs inconnus refuses : " + ",".join(sorted(inconnus)))
    if obj["schema"] != SCHEMA:
        raise Refus(f"approbation : schema non conforme ({SCHEMA} attendu)")
    if obj["hostapr_contract"] != HOSTAPR_CONTRACT:
        raise Refus(f"approbation : contrat hote non conforme ({HOSTAPR_CONTRACT} attendu)")
    if not APR_ID_RE.match(str(obj["id"])):
        raise Refus(f"approbation : identifiant malforme {obj['id']!r}")
    if not ACTION_RE.match(str(obj["action"])):
        raise Refus(f"approbation : action malformee {obj['action']!r}")
    if not TASK_RE.match(str(obj["task"])):
        raise Refus(f"approbation : tache malformee {obj['task']!r}")
    if not PROJECT_RE.match(str(obj["project"])):
        raise Refus(f"approbation : projet malforme {obj['project']!r}")
    if not NONCE_RE.match(str(obj["nonce"])):
        raise Refus("approbation : nonce invalide")
    if not HEX64_RE.match(str(obj["policy_digest"])):
        raise Refus("approbation : empreinte de politique invalide")
    if not HEX64_RE.match(str(obj["task_digest"])):
        raise Refus("empreinte de cible invalide")
    if obj["status"] not in STATES:
        raise Refus(f"approbation : statut inconnu {obj['status']!r}")
    for champ in ("requester", "reason", "requester_kind"):
        if not isinstance(obj[champ], str) or not obj[champ]:
            raise Refus(f"approbation : champ {champ} vide ou malforme")
    if obj["requester_kind"] not in ("agent", "human"):
        raise Refus("approbation : requester_kind doit valoir agent ou human")
    if len(obj["reason"]) > 500:
        raise Refus("approbation : motif trop long")
    created = parse_ts(obj["created_at"], "created_at")
    expires = parse_ts(obj["expires_at"], "expires_at")
    if expires <= created:
        raise Refus("approbation : expires_at <= created_at")
    if obj["approver"] is not None and not isinstance(obj["approver"], str):
        raise Refus("approbation : approver malforme")
    for champ in ("decided_at", "consumed_at"):
        if obj[champ] is not None:
            parse_ts(obj[champ], champ)
    if obj["consumed_by"] is not None and not isinstance(obj["consumed_by"], str):
        raise Refus("approbation : consumed_by malforme")
    if obj["decision_token_id"] is not None and not isinstance(obj["decision_token_id"], str):
        raise Refus("approbation : decision_token_id malforme")
    # coherence statut <-> champs de decision
    if obj["status"] == "pending":
        if obj["approver"] or obj["decided_at"] or obj["consumed_at"]:
            raise Refus("approbation : statut pending incoherent avec des champs de decision")
    if obj["status"] in ("approved", "rejected", "consumed"):
        if not obj["approver"] or not obj["decided_at"]:
            raise Refus(f"approbation : statut {obj['status']} sans decideur horodate")
    if obj["status"] in ("rejected", "expired") and obj["consumed_at"]:
        raise Refus(f"approbation : statut {obj['status']} ne peut pas etre consomme")
    if obj["status"] == "consumed" and (not obj["consumed_at"] or not obj["consumed_by"]):
        raise Refus("approbation : statut consumed sans trace de consommation")


def quarantaine(root, p: Path, motif: str):
    q = Path(root) / "data/approvals/quarantine"
    q.mkdir(parents=True, exist_ok=True)
    cible = q / (p.name + ".quarantine")
    try:
        os.replace(p, cible)
    except OSError as exc:
        raise Refus(f"approbation non conforme et mise en quarantaine impossible ({exc})")
    journal(root, "approval_quarantined", fichier=p.name, motif=motif)
    return cible


def charger_apr(root, apr_id, c=None, mettre_en_quarantaine=True):
    """Charge une approbation : validation stricte + signature. Toute anomalie => refus."""
    c = c or contract(root)
    key = cle(c)
    p = chemin_apr(root, apr_id)
    if not p.exists():
        raise Refus(f"approbation introuvable : {apr_id}")
    try:
        obj = json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        if mettre_en_quarantaine:
            quarantaine(root, p, f"json illisible: {exc}")
        raise Refus(f"approbation illisible : {apr_id}")
    try:
        valider_apr(obj)
    except Refus as exc:
        if mettre_en_quarantaine:
            quarantaine(root, p, str(exc))
        raise
    if not signature_valide(obj, key):
        if mettre_en_quarantaine:
            quarantaine(root, p, "signature invalide")
        raise Refus(f"approbation non signee ou falsifiee : {apr_id}")
    return obj


# --------------------------------------------------------------------------- #
# cycle de vie
# --------------------------------------------------------------------------- #
def empreinte_tache(tache):
    champs = ("id", "project", "assignee", "objective", "secret", "target", "version", "artifact_digest", "completion_criteria")
    payload = {k: tache.get(k) for k in champs}
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()

def verifier_empreinte_tache(root, obj):
    p = Path(root) / "data/tasks" / (obj["task"] + ".json")
    if not p.exists():raise Refus("tache absente pour verification de cible")
    tache = json.loads(p.read_text(encoding="utf-8"))
    if not hmac.compare_digest(obj["task_digest"], empreinte_tache(tache)):
        raise Refus("cible ou version de tache modifiee depuis la demande")

def nouveau_id():
    return "APR-" + _now_dt().strftime("%Y%m%d%H%M%S%f")


def demander(root, task_id, action, reason, requester, requester_kind="agent", ttl_seconds=None):
    c = contract(root)
    if not isinstance(task_id, str) or not TASK_RE.match(task_id):
        raise Refus(f"tache malformee : {task_id!r}")
    if not isinstance(reason, str) or not reason.strip():
        raise Refus("motif obligatoire")
    if requester_kind not in ("agent", "human"):
        raise Refus("requester_kind invalide")
    if not isinstance(requester, str) or not requester.strip():
        raise Refus("demandeur obligatoire")
    if not exige_approbation(root, action):
        raise Refus(f"action sans approbation requise : {action}")
    taches = Path(root) / "data/tasks"
    tf = taches / (task_id + ".json")
    if not tf.exists():
        raise Refus(f"tache inexistante : {task_id}")
    try:
        tache = json.loads(tf.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        raise Refus(f"tache illisible : {task_id}")
    if tache.get("id") != task_id:
        raise Refus("tache incoherente : identifiant different du nom de fichier")
    project = str(tache.get("project") or "")
    if not PROJECT_RE.match(project):
        raise Refus(f"projet de la tache malforme : {project!r}")
    ttl = c["ttl_seconds"] if ttl_seconds is None else int(ttl_seconds)
    if ttl < c["min_ttl_seconds"] or ttl > c["max_ttl_seconds"]:
        raise Refus(f"ttl hors bornes ({c['min_ttl_seconds']}..{c['max_ttl_seconds']}) : {ttl}")
    created = _now_dt()
    obj = {
        "schema": SCHEMA,
        "hostapr_contract": HOSTAPR_CONTRACT,
        "id": nouveau_id(),
        "action": action,
        "task": task_id,
        "project": project,
        "requester": requester.strip(),
        "requester_kind": requester_kind,
        "reason": reason.strip()[:500],
        "status": "pending",
        "created_at": created.isoformat(),
        "expires_at": (created + timedelta(seconds=ttl)).isoformat(),
        "nonce": secrets.token_hex(16),
        "policy_digest": politique_digest(root),
        "task_digest": empreinte_tache(tache),
        "approver": None,
        "decided_at": None,
        "decision_token_id": None,
        "consumed_at": None,
        "consumed_by": None,
    }
    key = cle(c)
    journal(root, "approval_requested", approval=obj["id"], task=obj["task"],
            project=obj["project"], action=obj["action"], requester=obj["requester"],
            requester_kind=obj["requester_kind"], expires_at=obj["expires_at"],
            policy_digest=obj["policy_digest"])
    ecrire_apr(root, obj, key)
    return obj


def _autorise(registre, approver, action):
    spec = registre["approvers"].get(approver)
    if spec is None:
        raise Refus(f"approbateur non habilite : {approver}")
    allowed = spec.get("may_approve") or []
    if "*" in allowed:
        return True
    if action not in allowed:
        raise Refus(f"approbateur {approver} non habilite pour {action}")
    return True


def decider(root, apr_id, decision, approver, token, c=None):
    if decision not in ("approved", "rejected"):
        raise Refus(f"decision invalide : {decision!r}")
    c = c or contract(root)
    obj = charger_apr(root, apr_id, c)
    registre = approveurs(root)
    _autorise(registre, approver, obj["action"])
    secrets_ = secrets_approbateurs(c.get("approvers_file"))
    attendu = secrets_.get(approver)
    if not attendu:
        raise Refus(f"aucun jeton enregistre pour l'approbateur {approver}")
    if not isinstance(token, str) or not token:
        raise Refus("jeton d'approbateur obligatoire (--token ou AWEMA_APPROVER_TOKEN)")
    if not hmac.compare_digest(hashlib.sha256(token.encode()).hexdigest(), attendu):
        raise Refus("jeton d'approbateur invalide")
    if obj["status"] != "pending":
        raise Refus(f"approbation deja decidee ou close ({obj['status']}) : {apr_id}")
    if c["require_distinct_approver"] and approver == obj["requester"]:
        raise Refus("auto-approbation interdite : le decideur doit differer du demandeur")
    maintenant = _now_dt()
    if maintenant >= parse_ts(obj["expires_at"], "expires_at"):
        obj["status"] = "expired"
        journal(root, "approval_expired", approval=apr_id, at=now())
        ecrire_apr(root, obj, cle(c))
        raise Refus(f"approbation expiree : {apr_id}")
    if parse_ts(obj["created_at"], "created_at") > maintenant + timedelta(
            seconds=c["max_clock_skew_seconds"]):
        raise Refus("approbation datee dans le futur (horloge non fiable)")
    # re-verification de la politique a la decision
    if not exige_approbation(root, obj["action"]):
        raise Refus(f"action retiree de la politique : {obj['action']}")
    if obj["policy_digest"] != politique_digest(root):
        raise Refus("politique modifiee depuis la demande : decision refusee")
    # liaison action/tache/projet verifiee a la decision
    tache = json.loads((Path(root) / "data/tasks" / (obj["task"] + ".json")).read_text(encoding="utf-8"))
    verifier_empreinte_tache(root, obj)
    if tache.get("project") != obj["project"]:
        raise Refus("liaison projet incoherente entre l'approbation et la tache")
    obj["status"] = decision
    obj["approver"] = approver
    obj["decided_at"] = maintenant.isoformat()
    obj["decision_token_id"] = hashlib.sha256(token.encode()).hexdigest()[:12]
    journal(root, "approval_decided", approval=apr_id, task=obj["task"], project=obj["project"],
            action=obj["action"], decision=decision, approver=approver,
            decision_token_id=obj["decision_token_id"])
    ecrire_apr(root, obj, cle(c))
    return obj


def consommer(root, apr_id, task, project, action, acteur, c=None):
    """Consommation a usage unique avec liaison stricte action + tache + projet."""
    c = c or contract(root)
    if not c["single_use"]:
        raise Refus("contrat non conforme : usage unique obligatoire")
    with verrou(root, "apr-" + apr_id):
        obj = charger_apr(root, apr_id, c)
        if obj["task"] != task:
            raise Refus(f"liaison tache invalide : approbation={obj['task']} demande={task}")
        if obj["project"] != project:
            raise Refus(f"liaison projet invalide : approbation={obj['project']} demande={project}")
        if obj["action"] != action:
            raise Refus(f"liaison action invalide : approbation={obj['action']} demande={action}")
        if obj["status"] == "consumed":
            raise Refus(f"anti-rejeu : approbation deja consommee le {obj['consumed_at']}")
        if obj["status"] != "approved":
            raise Refus(f"approbation non approuvee ({obj['status']}) : {apr_id}")
        maintenant = _now_dt()
        if maintenant >= parse_ts(obj["expires_at"], "expires_at"):
            raise Refus(f"approbation expiree : {apr_id}")
        if not exige_approbation(root, action):
            raise Refus(f"action retiree de la politique : {action}")
        if obj["policy_digest"] != politique_digest(root):
            raise Refus("politique modifiee depuis la decision : consommation refusee")
        verifier_empreinte_tache(root, obj)
        if not acteur:
            raise Refus("acteur de consommation obligatoire")
        obj["status"] = "consumed"
        obj["consumed_at"] = maintenant.isoformat()
        obj["consumed_by"] = acteur
        journal(root, "approval_consumed", approval=apr_id, task=task, project=project,
                action=action, approver=obj["approver"], actor=acteur,
                decision_token_id=obj["decision_token_id"])
        ecrire_apr(root, obj, cle(c))
        return obj


def _fichiers_magasin(root):
    """Fichiers du magasin (hors sous-dossier de quarantaine)."""
    d = magasin(root)
    if not d.exists():
        return []
    return sorted(p for p in d.iterdir() if p.is_file())


def lister(root, c=None):
    """Liste + mise en quarantaine des fichiers non conformes (C-04 : lettre morte)."""
    c = c or contract(root)
    out = []
    for p in _fichiers_magasin(root):
        if p.name.endswith(".json") and p.stem.startswith("APR-"):
            try:
                out.append(charger_apr(root, p.stem, c))
            except Refus:
                continue
        else:
            quarantaine(root, p, "nom de fichier non conforme au schema")
    return out


def verifier_magasin(root, c=None):
    """Controle d'integrite : chaque fichier du magasin doit etre conforme et signe."""
    c = c or contract(root)
    rapport = {"conformes": [], "ecartes": [], "orphelins_journal": [], "date_utc": now()}
    journal_events = [e for e in lire_journal(root) if str(e.get("event", "")).startswith("approval_")]
    ids_journal = {e.get("approval") for e in journal_events if e.get("approval")}
    for p in _fichiers_magasin(root):
        if p.name.endswith(".json") and p.stem.startswith("APR-"):
            try:
                obj = charger_apr(root, p.stem, c)
                rapport["conformes"].append(obj["id"])
            except Refus as exc:
                rapport["ecartes"].append({"fichier": p.name, "motif": str(exc)})
        else:
            try:
                quarantaine(root, p, "nom de fichier non conforme au schema")
            except Refus as exc:
                rapport["ecartes"].append({"fichier": p.name, "motif": str(exc)})
    rapport["orphelins_journal"] = sorted(ids_journal - set(rapport["conformes"]))
    statuts = {}
    for o in lister(root, c):
        statuts.setdefault(o["status"], []).append(o["id"])
    rapport["par_statut"] = statuts
    # indicateur operationnel : une approbation approuvee qui n'a pas encore produit d'effet
    rapport["approuvees_non_consommees"] = statuts.get("approved", [])
    rapport["en_attente"] = statuts.get("pending", [])
    return rapport
