#!/usr/bin/env python3
"""Bibliotheque du journal d'audit opposable et fail-closed — Control Plane AWEMA.

Correction P0-3 (ecarts consolides C-05, C-06, C-14 ; partiellement C-07, C-08).

Mecanismes
----------
1. Magasin scelle : le journal n'est ouvert en ecriture que par le service
   awema-auditd, qui garde le descripteur puis pose fichier 0400 / repertoire
   0500. Tout autre processus — y compris le meme UID — recoit EACCES.
   Mesure dans les preuves (tentative d'append direct refusee).
2. Chaine de hachage : hash = SHA256(prev_hash || canonique(entree)), seq
   contigu, ts non decroissant. Suppression, reecriture, duplication et
   insertion sont detectees par le verificateur.
3. Signature : sig = HMAC-SHA256(hash) avec une cle 0600 lue HORS du repertoire
   du journal (mode trop ouvert => refus). Sans la cle, une entree fabriquee ne
   verifie pas.
4. Identite et horodatage non declaratifs : l'acteur est authentifie par jeton
   contre config/actors.json, l'UID/PID reels du client sont lus par le noyau
   (SO_PEERCRED) et la commande reelle est relue dans /proc/<pid>/cmdline ;
   l'horodatage est produit par le service. Un champ ts/seq/hash/sig fourni par
   le client est refuse (tentative de detournement).
5. Fail-closed : emettre() leve AuditIndisponible si l'ecriture n'est pas
   confirmee ; les executants refusent alors l'action AVANT tout effet.

Limites assumees (INVENTAIRE-ACTIONS-AUDITEES.md) : la separation reelle des UID
(journal hors du perimetre de l'UID agent au sens noyau) exige une frontiere hote
(P0-4) ; chainage + signature + verificateur sont le controle compensatoire en
conteneur. Rotation / retention / export continu restent P1 (C-10).
"""
from __future__ import annotations

import ast
import fnmatch
import hashlib
import hmac
import json
import os
import re
import secrets
import socket
import struct
import time
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = "awema-audit/1"
ACTEURS_SCHEMA = "awema-actors/1"
GENESIS = "0" * 64
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
EVENT_RE = re.compile(r"^[a-z][a-z0-9_]{2,63}$")
ACTOR_RE = re.compile(r"^[a-z0-9][a-z0-9\-\.]{1,63}$")
TASK_RE = re.compile(r"^TASK-[A-Za-z0-9][A-Za-z0-9\-]{1,63}$")
PROJECT_RE = re.compile(r"^[a-z0-9][a-z0-9\-]{1,63}$")
ACTION_RE = re.compile(r"^[a-z][a-z0-9_]{2,63}$")
ID_RE = re.compile(r"^EVT-[0-9a-f]{16}$")
TOOL_RE = re.compile(r"^[a-z][a-z0-9\-]{2,63}$")

# Champs obligatoires d'une entree exploitable par un auditeur.
CHAMPS = ("schema", "seq", "id", "ts", "event", "actor", "actor_kind", "actor_uid",
          "actor_pid", "actor_tool", "actor_declare", "action", "target", "task",
          "project", "correlation_id", "detail", "anchor", "prev_hash", "hash", "sig")
# Champs que le client n'a pas le droit de fournir (anti-detournement).
CHAMPS_INTERDITS = ("seq", "id", "ts", "anchor", "prev_hash", "hash", "sig",
                    "actor_uid", "actor_pid", "actor_kind")
# Evenements qui doivent exister pour couvrir un parcours critique complet.
EVENEMENTS_CRITIQUES = ("task_created", "task_move_starting", "task_moved",
                        "agent_claimed", "agent_submitted", "approval_requested",
                        "approval_decided", "approval_consumed", "action_starting",
                        "action_executed")
MAX_DETAIL = 4096
MAX_LIGNE = 8192


class AuditRefus(Exception):
    """Refus du magasin d'audit : entree non conforme, identite non authentifiee."""


class AuditIdentityMismatch(AuditRefus):
    """Identite authentifiee valide mais differente de l'identite declaree."""

    def __init__(self, message, actor, kind):
        super().__init__(message)
        self.actor = actor
        self.kind = kind


class AuditIndisponible(Exception):
    """Ecriture d'audit non confirmee : service absent, journal scelle ou corrompu."""


# --------------------------------------------------------------------------- #
# chemins
# --------------------------------------------------------------------------- #
def racine(root=None) -> Path:
    return Path(root or os.environ.get("AWEMA_CORE_ROOT", "/awema-core"))


def journal_path(root) -> Path:
    return Path(root) / "data/audit/events.jsonl"


def socket_path(root) -> Path:
    env = os.environ.get("AWEMA_AUDIT_SOCKET")
    return Path(env) if env else Path(root) / "data/audit/audit.sock"


def cle_path(root=None) -> Path:
    env = os.environ.get("AWEMA_AUDIT_KEY_FILE")
    if env:
        return Path(env)
    return Path(root or racine()) / "secrets/audit.key"


def acteurs_path(root) -> Path:
    return Path(root) / "config/actors.json"


def quarantaine_dir(root) -> Path:
    return Path(root) / "data/audit/quarantine"


def pid_path(root) -> Path:
    return Path(root) / "data/locks/auditd.pid"


# --------------------------------------------------------------------------- #
# temps
# --------------------------------------------------------------------------- #
def maintenant() -> str:
    return datetime.now(timezone.utc).isoformat()


def lire_ts(valeur, champ="ts"):
    if not isinstance(valeur, str):
        raise AuditRefus(f"horodatage invalide ({champ})")
    try:
        d = datetime.fromisoformat(valeur)
    except ValueError:
        raise AuditRefus(f"horodatage illisible ({champ})")
    if d.tzinfo is None:
        raise AuditRefus(f"horodatage sans fuseau ({champ})")
    return d


# --------------------------------------------------------------------------- #
# cle de signature (hors perimetre du journal)
# --------------------------------------------------------------------------- #
def cle(root=None) -> bytes:
    p = cle_path(root)
    if not p.exists():
        raise AuditIndisponible(f"cle d'audit absente : {p}")
    st = p.stat()
    if st.st_mode & 0o077:
        raise AuditIndisponible(
            f"cle d'audit accessible au groupe/aux autres ({oct(st.st_mode & 0o777)}) : {p}")
    data = p.read_bytes().strip()
    if len(data) < 32:
        raise AuditIndisponible(f"cle d'audit trop courte ({len(data)} octets)")
    return data


# --------------------------------------------------------------------------- #
# canonique / hash / signature (le hash couvre toutes les autres donnees)
# --------------------------------------------------------------------------- #
def canonique(entree: dict) -> bytes:
    return json.dumps({k: v for k, v in entree.items() if k not in ("hash", "sig")},
                      sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def calcul_hash(entree: dict, prev_hash: str) -> str:
    return hashlib.sha256(prev_hash.encode() + canonique(entree)).hexdigest()


def signer(hash_hex: str, key: bytes) -> str:
    return hmac.new(key, hash_hex.encode(), hashlib.sha256).hexdigest()


# --------------------------------------------------------------------------- #
# validation d'une entree (utilisee a l'ecriture ET par le verificateur)
# --------------------------------------------------------------------------- #
def valider_entree(e) -> str | None:
    """Retourne None si l'entree est exploitable, sinon le motif d'ecart."""
    if not isinstance(e, dict):
        return "entree non objet"
    manquants = [k for k in CHAMPS if k not in e]
    if manquants:
        return "champs obligatoires absents : " + ",".join(manquants)
    inconnus = [k for k in e if k not in CHAMPS]
    if inconnus:
        return "champs inconnus refuses : " + ",".join(sorted(inconnus))
    if e["schema"] != SCHEMA:
        return f"schema non conforme ({SCHEMA} attendu)"
    if not isinstance(e["seq"], int) or isinstance(e["seq"], bool) or e["seq"] < 1:
        return "seq invalide"
    if not isinstance(e["id"], str) or not ID_RE.match(e["id"]):
        return "identifiant d'evenement malforme"
    lire_ts(e["ts"])
    if not isinstance(e["event"], str) or not EVENT_RE.match(e["event"]):
        return "nom d'evenement malforme"
    for champ, motif in (("actor", ACTOR_RE), ("actor_tool", TOOL_RE)):
        if not isinstance(e[champ], str) or not motif.match(e[champ]):
            return f"{champ} malforme"
    if e["actor_declare"] is not None:
        if not isinstance(e["actor_declare"], str) or not ACTOR_RE.match(e["actor_declare"]):
            return "actor_declare malforme"
    if e["actor_kind"] not in ("agent", "human"):
        return "actor_kind doit valoir agent ou human"
    for champ in ("actor_uid", "actor_pid"):
        if not isinstance(e[champ], int) or isinstance(e[champ], bool) or e[champ] < (0 if champ == "actor_uid" else 1):
            return f"{champ} invalide"
    if e["action"] is not None and (not isinstance(e["action"], str)
                                    or not ACTION_RE.match(e["action"])):
        return "action malformee"
    if not isinstance(e["target"], str) or not e["target"] or len(e["target"]) > 200:
        return "cible (target) absente ou malformee"
    for champ, motif in (("task", TASK_RE), ("project", PROJECT_RE)):
        if e[champ] is not None and (not isinstance(e[champ], str) or not motif.match(e[champ])):
            return f"{champ} malforme"
    if not isinstance(e["correlation_id"], str) or not e["correlation_id"].strip():
        return "correlation_id absente"
    if not isinstance(e["detail"], dict):
        return "detail doit etre un objet"
    if len(json.dumps(e["detail"], ensure_ascii=False)) > MAX_DETAIL:
        return "detail trop volumineux"
    a = e["anchor"]
    if not isinstance(a, dict) or set(a) != {"id", "mono_ns"}:
        return "ancre (anchor) malformee"
    if not isinstance(a["id"], str) or not a["id"] or len(a["id"]) > 64:
        return "ancre : identifiant de service invalide"
    if not isinstance(a["mono_ns"], int) or isinstance(a["mono_ns"], bool) or a["mono_ns"] <= 0:
        return "ancre : compteur monotone invalide"
    for champ in ("prev_hash", "hash", "sig"):
        if not isinstance(e[champ], str) or not HEX64_RE.match(e[champ]):
            return f"{champ} invalide"
    return None


# --------------------------------------------------------------------------- #
# identites (jeton d'acteur, jamais ecrit dans le journal)
# --------------------------------------------------------------------------- #
def _lire_json(p: Path, quoi: str):
    if not p.exists():
        raise AuditIndisponible(f"{quoi} introuvable : {p}")
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise AuditIndisponible(f"{quoi} illisible ({p}) : {exc}")


def acteurs(root) -> dict:
    d = _lire_json(acteurs_path(root), "registre d'acteurs")
    if not isinstance(d, dict) or d.get("schema") != ACTEURS_SCHEMA:
        raise AuditIndisponible(f"registre d'acteurs non conforme ({ACTEURS_SCHEMA} attendu)")
    a = d.get("actors")
    if not isinstance(a, dict) or not a:
        raise AuditIndisponible("registre d'acteurs vide")
    for nom, spec in a.items():
        if not isinstance(nom, str) or not ACTOR_RE.match(nom):
            raise AuditIndisponible(f"nom d'acteur invalide : {nom!r}")
        if not isinstance(spec, dict) or spec.get("kind") not in ("agent", "human"):
            raise AuditIndisponible(f"acteur sans nature valide : {nom}")
        if not isinstance(spec.get("token_sha256"), str) or not HEX64_RE.match(spec["token_sha256"]):
            raise AuditIndisponible(f"empreinte de jeton invalide : {nom}")
        if spec["kind"] == "human" and not spec.get("credential_file"):
            raise AuditIndisponible(
                f"acteur humain sans fichier d'accreditation : {nom} (le jeton d'environnement ne suffit pas)")
    if not d.get("human_credential_dir"):
        raise AuditIndisponible("registre d'acteurs : human_credential_dir absent")
    return d


def authentifier(root, token: str | None, declare: str | None = None, credential: str | None = None):
    """Authentifie un acteur par jeton. Retourne (actor, kind).

    Un acteur humain ne peut PAS s'authentifier par variable d'environnement : son
    accreditation doit venir du fichier dedie (0400) presente par le client, sinon
    l'humain et l'agent sont indistinguables (C-08).
    """
    if not isinstance(token, str) or not token:
        raise AuditRefus("identite absente : jeton d'acteur obligatoire")
    reg = acteurs(root)
    h = hashlib.sha256(token.encode()).hexdigest()
    correspondances = [n for n, s in reg["actors"].items() if hmac.compare_digest(s["token_sha256"], h)]
    if not correspondances:
        raise AuditRefus("jeton d'acteur inconnu")
    if len(correspondances) > 1:
        raise AuditRefus("jeton d'acteur ambigu")
    actor = correspondances[0]
    kind = reg["actors"][actor]["kind"]
    if declare is not None and declare != actor:
        raise AuditIdentityMismatch(
            f"action detournee : acteur declare {declare!r} different de l'acteur authentifie {actor!r}",
            actor,
            kind,
        )
    if kind == "human":
        if not credential:
            raise AuditRefus(
                f"acteur humain {actor} : accreditation absente (variable d'environnement insuffisante)")
        cdir = (Path(root) / reg["human_credential_dir"]).resolve()
        p = Path(credential)
        try:
            if p.resolve().parent != cdir:
                raise AuditRefus("accreditation hors du repertoire dedie (refus)")
        except OSError:
            raise AuditRefus("accreditation illisible (refus)")
        mode = p.stat().st_mode & 0o777
        if mode != 0o400:
            raise AuditRefus(
                f"accreditation doit etre en 0400 (observe {oct(mode)})"
            )
        if not hmac.compare_digest(
                hashlib.sha256(p.read_bytes().strip()).hexdigest(),
                reg["actors"][actor]["token_sha256"]):
            raise AuditRefus("accreditation non conforme au registre")
    return actor, kind


def jeton_client(root, declare=None):
    """(jeton, chemin d'accreditation) a presenter : fichier dedie pour un humain."""
    cred = os.environ.get("AWEMA_ACTOR_CREDENTIAL")
    env = os.environ.get("AWEMA_ACTOR_TOKEN")
    if cred:
        p = Path(cred)
        if not p.exists():
            raise AuditRefus(f"accreditation introuvable : {p}")
        mode = p.stat().st_mode & 0o777
        if mode != 0o400:
            raise AuditRefus(
                f"accreditation doit etre en 0400 (observe {oct(mode)})"
            )
        return p.read_text(encoding="utf-8").strip(), str(p)
    return env, None


# --------------------------------------------------------------------------- #
# client : emission d'une entree (voie unique = service d'audit)
# --------------------------------------------------------------------------- #
def _requete(root, charge, timeout=10.0):
    sp = socket_path(root)
    if not sp.exists():
        raise AuditIndisponible(f"service d'audit absent (socket {sp}) — ecriture d'audit non confirmee")
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(str(sp))
        s.sendall((json.dumps(charge, ensure_ascii=False) + "\n").encode("utf-8"))
        buf = b""
        while b"\n" not in buf:
            bloc = s.recv(65536)
            if not bloc:
                break
            buf += bloc
    except (OSError, socket.timeout) as exc:
        raise AuditIndisponible(f"service d'audit injoignable ({exc}) — action refusee")
    finally:
        s.close()
    if not buf.strip():
        raise AuditIndisponible("service d'audit sans reponse — action refusee")
    try:
        rep = json.loads(buf.decode("utf-8").splitlines()[0])
    except json.JSONDecodeError:
        raise AuditIndisponible("reponse d'audit illisible — action refusee")
    if not rep.get("ok"):
        raise AuditRefus("magasin d'audit : " + str(rep.get("error", "refus sans motif")))
    return rep


def emettre(root, event, *, tool, target, correlation_id, action=None, task=None,
            project=None, detail=None, acteur=None, token=None, credential=None):
    """Ecrit une entree d'audit AVANT l'effet de l'action. Leve si non confirme."""
    root = Path(root)
    if not isinstance(event, str) or not EVENT_RE.match(event):
        raise AuditRefus(f"evenement malforme : {event!r}")
    if not isinstance(target, str) or not target:
        raise AuditRefus("cible (target) obligatoire : une entree sans cible n'est pas exploitable")
    if not isinstance(correlation_id, str) or not correlation_id.strip():
        raise AuditRefus("correlation_id obligatoire")
    if tool is not None and (not isinstance(tool, str) or not TOOL_RE.match(tool)):
        raise AuditRefus(f"outil malforme : {tool!r}")
    declare = acteur
    tok, cred = (token, credential) if token is not None else jeton_client(root, declare)
    if tok is None:
        raise AuditRefus("identite absente : jeton d'acteur obligatoire")
    charge = {"op": "append", "schema": SCHEMA, "event": event,
              "tool": tool or Path(os.environ.get("AWEMA_AUDIT_TOOL", "awema-unknown")).name,
              "actor_declare": declare, "actor_token": tok, "actor_credential": cred,
              "action": action, "target": target, "task": task, "project": project,
              "correlation_id": correlation_id, "detail": detail or {}}
    rep = _requete(root, charge)
    return rep.get("entry")


def lire_journal(root):
    """Lecture tolerante (diagnostic). Le controle d'integrite est verifier_journal."""
    p = journal_path(root)
    if not p.exists():
        return []
    out = []
    for ligne in p.read_text(encoding="utf-8", errors="replace").splitlines():
        if not ligne.strip():
            continue
        try:
            out.append(json.loads(ligne))
        except json.JSONDecodeError:
            out.append({"_illisible": ligne[:200]})
    return out


def dernier(entrees):
    for e in reversed(entrees):
        if isinstance(e, dict) and "hash" in e:
            return e
    return None


# --------------------------------------------------------------------------- #
# verificateur (opposabilite : le controle est rejouable hors ligne)
# --------------------------------------------------------------------------- #
def verifier_journal(root, key=None, entrees=None) -> dict:
    root = Path(root)
    p = journal_path(root)
    rapport = {"schema": SCHEMA, "fichier": str(p), "existe": p.exists(),
               "sha256": None, "octets": None, "entrees": 0, "ecarts": [],
               "evenements": {}, "acteurs": {}, "dernier_seq": 0, "dernier_hash": None,
               "ts_min": None, "ts_max": None, "date_utc": maintenant(),
               "chaine_intacte": False, "signature_valide": False}
    if not p.exists():
        rapport["ecarts"].append({"ligne": 0, "motif": "journal absent"})
        return rapport
    rapport["sha256"] = hashlib.sha256(p.read_bytes()).hexdigest()
    rapport["octets"] = p.stat().st_size
    try:
        k = cle(root) if key is None else key
    except AuditIndisponible as exc:
        rapport["ecarts"].append({"ligne": 0, "motif": str(exc)})
        k = None
    if entrees is None:
        entrees = []
        for ligne in p.read_text(encoding="utf-8", errors="replace").splitlines():
            if not ligne.strip():
                continue
            try:
                entrees.append(json.loads(ligne))
            except json.JSONDecodeError:
                entrees.append(None)
    prev_hash = GENESIS
    prev_ts = None
    prev_mono = None
    sign_ok = True
    for i, e in enumerate(entrees, start=1):
        rapport["entrees"] = i
        if e is None:
            rapport["ecarts"].append({"ligne": i, "motif": "ligne illisible (json invalide)"})
            continue
        motif = valider_entree(e)
        if motif:
            rapport["ecarts"].append({"ligne": i, "motif": motif})
            continue
        if e["seq"] != i:
            rapport["ecarts"].append({"ligne": i, "seq": e["seq"],
                                      "motif": f"sequence discontinue (attendu {i})"})
        if e["prev_hash"] != prev_hash:
            rapport["ecarts"].append({"ligne": i, "motif": "chaine rompue : prev_hash != hash precedent"})
        attendu = calcul_hash(e, prev_hash)
        if e["hash"] != attendu:
            rapport["ecarts"].append({"ligne": i, "motif": "hash non conforme : entree reecrite ou inseree"})
        if k is not None and not hmac.compare_digest(signer(e["hash"], k), e["sig"]):
            rapport["ecarts"].append({"ligne": i, "motif": "signature HMAC invalide : entree non emise par le magasin"})
            sign_ok = False
        ts = lire_ts(e["ts"])
        if prev_ts is not None and ts < prev_ts:
            rapport["ecarts"].append({"ligne": i, "motif": "horodatage non monotone (antidatage)"})
        if (ts - datetime.now(timezone.utc)).total_seconds() > 300:
            rapport["ecarts"].append({"ligne": i, "motif": "horodatage dans le futur (> 300 s)"})
        if prev_mono is not None and e["anchor"]["id"] == prev_mono[0] and e["anchor"]["mono_ns"] <= prev_mono[1]:
            rapport["ecarts"].append({"ligne": i, "motif": "ancre monotone non croissante"})
        prev_hash = e["hash"]
        prev_ts = ts
        prev_mono = (e["anchor"]["id"], e["anchor"]["mono_ns"])
        rapport["evenements"][e["event"]] = rapport["evenements"].get(e["event"], 0) + 1
        cle_acteur = f'{e["actor"]}:{e["actor_kind"]}'
        rapport["acteurs"][cle_acteur] = rapport["acteurs"].get(cle_acteur, 0) + 1
        rapport["ts_min"] = rapport["ts_min"] or e["ts"]
        rapport["ts_max"] = e["ts"]
    rapport["dernier_seq"] = (
        entrees[-1].get("seq", 0)
        if entrees and isinstance(entrees[-1], dict)
        else 0
    )
    rapport["dernier_hash"] = entrees[-1].get("hash") if entrees and isinstance(entrees[-1], dict) else None
    rapport["chaine_intacte"] = not any("chaine" in x["motif"] or "hash" in x["motif"] or
                                        "sequence" in x["motif"] or "illisible" in x["motif"]
                                        for x in rapport["ecarts"])
    rapport["signature_valide"] = sign_ok and not any("signature" in x["motif"] for x in rapport["ecarts"])
    rapport["verdict"] = "conforme" if not rapport["ecarts"] else "ecart"
    return rapport


def detecter_ecritures_directes(root) -> list:
    """Heuristique C-07 : fichier de tache modifie apres la derniere entree d'audit."""
    root = Path(root)
    p = journal_path(root)
    if not p.exists():
        return []
    mtime_journal = p.stat().st_mtime
    ecarts = []
    for t in sorted((root / "data/tasks").glob("TASK-*.json")):
        try:
            m = t.stat().st_mtime
        except OSError:
            continue
        if m > mtime_journal + 0.5:
            ecarts.append({"fichier": t.name, "motif":
                           "mutation plus recente que la derniere entree d'audit (ecriture directe possible)",
                           "mtime": datetime.fromtimestamp(m, timezone.utc).isoformat(),
                           "derniere_entree": datetime.fromtimestamp(mtime_journal, timezone.utc).isoformat()})
    return ecarts


def quarantaine_journal(root, motif: str) -> Path:
    """Met le journal corrompu de cote (le magasin reste ferme jusqu'a decision humaine)."""
    root = Path(root)
    p = journal_path(root)
    d = quarantaine_dir(root)
    d.mkdir(parents=True, exist_ok=True)
    cible = d / (p.name + "." + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + ".quarantine")
    if p.exists():
        os.replace(p, cible)
    rapport = d / (cible.name + ".motif.json")
    rapport.write_text(json.dumps({"motif": motif, "date_utc": maintenant(),
                                   "quarantine": str(cible)}, ensure_ascii=False, indent=2) + "\n",
                       encoding="utf-8")
    os.chmod(rapport, 0o600)
    return cible


# --------------------------------------------------------------------------- #
# couverture statique : journal avant mutation, pas d'acces direct au journal
# --------------------------------------------------------------------------- #
EMETTEURS = {"journal", "emettre", "audit"}
MUTATIONS = {"save", "ecrire_apr", "ecrire_effet", "_ecrire_atomique", "save_task",
             "ecrire_tache"}
# primitives d'ecriture : ce sont leurs APPELEURS qui doivent journaliser avant
PRIMITIVES = {"save", "_ecrire_atomique", "ecrire_apr", "ecrire_effet"}
EXEMPTS = {"awema-auditd": "magasin d'audit (seul ecrivain du journal)",
           "awema-audit": "lecteur / verificateur / export du journal",
           "awema_audit_lib.py": "bibliotheque du journal",
           "awema_approval_lib_base.py": "bibliotheque CP-01 surchargee : sa fonction "
                                         "journal est remplacee par la surcharge P0-3"}


def _appels(noeud):
    """Positions (ligne, colonne) des emissions et mutations du bloc courant.

    Les definitions imbriquees sont analysees separement. La colonne permet
    notamment de distinguer save(...); audit(...) sur une meme ligne.
    """
    emit, mut = [], []

    class Visiteur(ast.NodeVisitor):
        def visit_Call(self, n):
            f = n.func
            nom = (
                f.attr if isinstance(f, ast.Attribute)
                else (f.id if isinstance(f, ast.Name) else None)
            )
            pos = (n.lineno, n.col_offset)

            if nom in EMETTEURS:
                emit.append(pos)
            elif nom in MUTATIONS:
                mut.append(pos)

            self.generic_visit(n)

        def visit_FunctionDef(self, n):
            if n is noeud:
                for stmt in n.body:
                    self.visit(stmt)

        def visit_AsyncFunctionDef(self, n):
            if n is noeud:
                for stmt in n.body:
                    self.visit(stmt)

        def visit_ClassDef(self, n):
            if n is noeud:
                for stmt in n.body:
                    self.visit(stmt)

    visiteur = Visiteur()

    if isinstance(noeud, ast.Module):
        for stmt in noeud.body:
            if not isinstance(
                stmt,
                (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
            ):
                visiteur.visit(stmt)
    else:
        visiteur.visit(noeud)

    return emit, mut


def couverture_statique(bin_dir, exemps=None) -> dict:
    """Controle statique des executants : journal AVANT mutation, pas d'acces direct."""
    exemps = EXEMPTS if exemps is None else exemps
    bin_dir = Path(bin_dir)
    rapport = {"date_utc": maintenant(), "repertoire": str(bin_dir), "fichiers": {},
               "violations": [], "acces_direct_journal": [],
               "regle": "pour chaque fonction qui mute (save/ecrire_apr/ecrire_effet/...), "
                        "une entree d'audit doit etre emise AVANT ; les primitives "
                        "d'ecriture sont exemptes en tant que definitions, pas en tant qu'appels"}
    for p in sorted(bin_dir.iterdir()):
        if not p.is_file() or p.suffix == ".pyc" or fnmatch.fnmatch(p.name, "*.before-*"):
            continue
        if p.name in exemps:
            rapport["fichiers"][p.name] = {"exempt": exemps[p.name]}
            continue
        try:
            src = p.read_text(encoding="utf-8")
            arbre = ast.parse(src)
        except (OSError, UnicodeDecodeError, SyntaxError) as exc:
            rapport["fichiers"][p.name] = {"erreur": f"illisible ({type(exc).__name__})"}
            continue
        fonctions = []
        emit_mod, mut_mod = _appels(arbre)
        if mut_mod and (not emit_mod or min(emit_mod) > min(mut_mod)):
            rapport["violations"].append({"fichier": p.name, "fonction": "<module>",
                                          "emit": emit_mod, "mutation": mut_mod,
                                          "motif": "mutation sans entree d'audit prealable"})
        for noeud in ast.walk(arbre):
            if not isinstance(noeud, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            emit, mut = _appels(noeud)
            if not mut:
                continue
            if noeud.name in PRIMITIVES:
                fonctions.append({"nom": noeud.name, "emit": sorted(emit), "mutation": sorted(mut),
                                  "journal_avant_mutation": True,
                                  "primitive": "ecriture de base : ses appelants doivent journaliser"})
                continue
            conforme = bool(emit) and min(emit) < min(mut)
            relance = bool(emit) and min(emit) > min(mut)
            fonctions.append({"nom": noeud.name, "emit": sorted(emit), "mutation": sorted(mut),
                              "journal_avant_mutation": conforme,
                              "relance_apres_mutation": relance})
            if not conforme:
                rapport["violations"].append({"fichier": p.name, "fonction": noeud.name,
                                              "emit": sorted(emit), "mutation": sorted(mut),
                                              "motif": "aucune entree d'audit avant la mutation"})
        conforme_fichier = all(f["journal_avant_mutation"] for f in fonctions)
        if mut_mod and (not emit_mod or min(emit_mod) > min(mut_mod)):
            conforme_fichier = False
        rapport["fichiers"][p.name] = {"fonctions": fonctions,
                                       "journal_avant_mutation": conforme_fichier}
    rapport["verdict"] = "conforme" if not rapport["violations"] and not rapport["acces_direct_journal"] else "ecart"
    return rapport


def nouveau_cle_audit(chemin) -> Path:
    p = Path(chemin)
    p.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, secrets.token_hex(32).encode())
        os.fsync(fd)
    finally:
        os.close(fd)
    os.chmod(p, 0o600)
    return p


def pid_et_uid_client(conn):
    """Identite noyau du client connecte (SO_PEERCRED) : non declarative."""
    brut = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    pid, uid, gid = struct.unpack("3i", brut)
    return {"pid": pid, "uid": uid, "gid": gid}


def commande_reelle(pid, tool) -> bool | None:
    """La commande noyau du client correspond-elle a l'outil declare ? (None = non verifiable)"""
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            argv = [x.decode("utf-8", "replace") for x in f.read().split(b"\0") if x]
    except OSError:
        return None
    noms = [os.path.basename(x) for x in argv]
    return tool in noms


def construire_entree(charge, meta_client, prev_hash, seq, anchor_id) -> dict:
    """Construit l'entree cote service : ts, seq, hash et signature ne viennent pas du client."""
    e = {
        "schema": SCHEMA,
        "seq": seq,
        "id": "EVT-" + secrets.token_hex(8),
        "ts": maintenant(),
        "event": charge["event"],
        "actor": charge["_actor"],
        "actor_kind": charge["_kind"],
        "actor_uid": meta_client["uid"],
        "actor_pid": meta_client["pid"],
        "actor_tool": charge["tool"],
        "actor_declare": charge.get("actor_declare"),
        "action": charge.get("action"),
        "target": charge["target"],
        "task": charge.get("task"),
        "project": charge.get("project"),
        "correlation_id": charge["correlation_id"],
        "detail": charge.get("detail") or {},
        "anchor": {"id": anchor_id, "mono_ns": time.monotonic_ns()},
        "prev_hash": prev_hash,
        "hash": "",
        "sig": "",
    }
    return e
