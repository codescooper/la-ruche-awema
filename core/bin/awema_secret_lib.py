#!/usr/bin/env python3
"""Coeur du coffre de secrets par profil — phase 3C.3, correction P0-4 (CP-03).

Principe
--------
Les secrets sont stockes dans un coffre par profil, un fichier par secret, en
0600 dans un repertoire 0700. Aucun client ne lit les fichiers directement :
seul le service `awema-vaultd` ouvre le coffre, apres :

  1. authentification de l'acteur par jeton (registre d'acteurs CP-02) ;
  2. controle de l'UID noyau du client (SO_PEERCRED) contre l'UID attendu du
     profil dans la politique (cloisonnement OS reel) ;
  3. controle du cloisonnement du magasin (mode, type, proprietaire, pas de
     lien symbolique, pas de traversee de chemin) ;
  4. decision d'autorisation (refus par defaut) : proprietaire, ou consommateur
     explicitement habilite pour une portee non privee, ou proprietaire humain
     avec approbation CP-01 a usage unique liee a la cible ;
  5. journalisation AVANT toute reponse (contrat CP-02, fail-closed).

Aucune valeur de secret n'est journalisee : seules des empreintes HMAC
(jeton de verification irreversible sans la cle du coffre) sont ecrites.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets as _secrets
import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path

SCHEMA_POLICY = "awema-secret-policy/1"
SCHEMA_INDEX = "awema-secret-index/1"
SCHEMA_GRANTS = "awema-secret-grants/1"

ID_RE = re.compile(r"^[a-z0-9][a-z0-9\-\.]{0,31}/[a-z0-9][a-z0-9\-\.]{0,47}$")
NOM_RE = re.compile(r"^[a-z0-9][a-z0-9\-\.]{1,63}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")

SCOPES = ("profil", "projet", "service", "partage")
SCOPES_PARTAGEABLES = ("projet", "service", "partage")
MODE_SECRET = 0o600
MODE_DIR = 0o700
MAX_VALEUR = 65536


class SecretRefus(Exception):
    """Refus legitime du coffre : identite, cloisonnement, autorisation."""


class SecretIndisponible(Exception):
    """Le coffre ou le journal ne peut pas rendre le service (fail-closed)."""


class SecretUsurpation(SecretRefus):
    """Identite authentifiee differente de l'identite declaree."""

    def __init__(self, message, acteur=None, kind=None):
        super().__init__(message)
        self.acteur = acteur
        self.kind = kind


# --------------------------------------------------------------------------- #
# racine, politique
# --------------------------------------------------------------------------- #
def maintenant() -> str:
    return datetime.now(timezone.utc).isoformat()


def _now_dt() -> datetime:
    return datetime.now(timezone.utc)


def racine(root=None) -> Path:
    if root:
        return Path(root)
    return Path(os.environ.get("AWEMA_SECRET_ROOT") or os.environ.get("AWEMA_CORE_ROOT") or "/awema-core")


def _charger_json(p: Path, quoi: str):
    if not p.exists():
        raise SecretIndisponible(f"{quoi} introuvable : {p}")
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError, OSError) as exc:
        raise SecretIndisponible(f"{quoi} illisible ({p}) : {exc}")


def chemin_politique(root) -> Path:
    p = Path(root) / "config/secret-policy.json"
    override = os.environ.get("AWEMA_SECRET_POLICY_FILE")
    return Path(override) if override else p


def politique(root=None) -> dict:
    root = racine(root)
    d = _charger_json(chemin_politique(root), "politique de secrets")
    if not isinstance(d, dict) or d.get("schema") != SCHEMA_POLICY:
        raise SecretIndisponible(f"politique non conforme ({SCHEMA_POLICY} attendu)")
    profils = d.get("profiles")
    if not isinstance(profils, dict) or not profils:
        raise SecretIndisponible("politique sans profils")
    for nom, spec in profils.items():
        if not isinstance(nom, str) or not NOM_RE.match(nom):
            raise SecretIndisponible(f"nom de profil invalide : {nom!r}")
        if not isinstance(spec, dict) or not isinstance(spec.get("uid"), int):
            raise SecretIndisponible(f"profil {nom} sans uid attendu (cloisonnement OS requis)")
    secrets_ = d.get("secrets")
    if not isinstance(secrets_, dict) or not secrets_:
        raise SecretIndisponible("politique sans secret declare")
    for sid, spec in secrets_.items():
        if not isinstance(sid, str) or not ID_RE.match(sid):
            raise SecretIndisponible(f"identifiant de secret invalide : {sid!r}")
        if not isinstance(spec, dict):
            raise SecretIndisponible(f"specification invalide pour {sid}")
        if spec.get("owner") not in profils:
            raise SecretIndisponible(f"proprietaire inconnu pour {sid} : {spec.get('owner')!r}")
        if spec.get("scope") not in SCOPES:
            raise SecretIndisponible(f"portee invalide pour {sid} : {spec.get('scope')!r}")
        for c in spec.get("consumers") or []:
            if c not in profils:
                raise SecretIndisponible(f"consommateur inconnu pour {sid} : {c!r}")
    regles = d.get("rules")
    if not isinstance(regles, dict):
        raise SecretIndisponible("politique sans bloc rules")
    return d


def uid_coffre(pol: dict) -> int:
    return int(pol["rules"].get("vault_uid", pol.get("vault_uid", os.getuid())))


def profil(pol: dict, nom: str) -> dict:
    spec = pol["profiles"].get(nom)
    if spec is None:
        raise SecretRefus(f"profil inconnu du coffre : {nom!r}")
    return spec


def spec_secret(pol: dict, secret_id: str) -> dict:
    spec = pol["secrets"].get(secret_id)
    if spec is None:
        raise SecretRefus(f"secret inconnu du coffre : {secret_id!r}")
    return spec


# --------------------------------------------------------------------------- #
# magasin
# --------------------------------------------------------------------------- #
def vault_root(root) -> Path:
    return Path(root) / str(politique(root)["vault_root"] if politique(root).get("vault_root") else "vault")


def index_dir(root) -> Path:
    return Path(root) / "vault/index"


def grants_path(root) -> Path:
    return Path(root) / "data/vault-grants.json"


def journal_grants_path(root) -> Path:
    return Path(root) / "data/vault-grants.jsonl"


def cle_empreinte(root=None) -> bytes:
    root = racine(root)
    override = os.environ.get("AWEMA_SECRET_FINGERPRINT_KEY_FILE")
    p = Path(override) if override else Path(root) / "secrets/vault.key"
    try:
        f = stat.S_ISREG(p.stat().st_mode)
    except OSError as exc:
        raise SecretIndisponible(f"cle d'empreinte du coffre illisible ({p}) : {exc}")
    if not f:
        raise SecretIndisponible(f"cle d'empreinte non reguliere ({p})")
    if p.stat().st_mode & 0o077:
        raise SecretIndisponible(
            f"cle d'empreinte trop ouverte ({oct(p.stat().st_mode & 0o777)}) : cloisonnement rompu")
    brut = p.read_bytes().strip()
    if len(brut) < 32:
        raise SecretIndisponible("cle d'empreinte du coffre trop courte")
    return brut


def empreinte(valeur: bytes, cle: bytes) -> str:
    """Empreinte HMAC : verifiable, non inversible sans la cle du coffre."""
    return "FP-" + hmac.new(cle, valeur, hashlib.sha256).hexdigest()[:32]


def nom_index(secret_id: str) -> str:
    return secret_id.replace("/", "__") + ".json"


def nom_fichier(secret_id: str, version: int) -> str:
    proprietaire, _ = secret_id.split("/", 1)
    return f"{secret_id.replace('/', '__')}.v{int(version)}.secret"


def chemin_valeur(root, secret_id: str, version: int) -> Path:
    return Path(root) / "vault" / secret_id.split("/", 1)[0] / nom_fichier(secret_id, version)


def _verifier_type_regulier(p: Path, quoi: str):
    try:
        st = os.lstat(p)
    except OSError as exc:
        raise SecretRefus(f"{quoi} inaccessible ({p}) : {exc}")
    if stat.S_ISLNK(st.st_mode):
        raise SecretRefus(f"{quoi} est un lien symbolique : refus (cloisonnement)")
    if not stat.S_ISREG(st.st_mode):
        raise SecretRefus(f"{quoi} n'est pas un fichier regulier : refus")
    return st


def verifier_cloisonnement_fichier(p: Path, uid_attendu: int, quoi: str):
    st = _verifier_type_regulier(p, quoi)
    mode = st.st_mode & 0o777
    if mode != MODE_SECRET:
        raise SecretRefus(f"{quoi} mode {oct(mode)} : {oct(MODE_SECRET)} requis (cloisonnement rompu)")
    if st.st_uid != uid_attendu:
        raise SecretRefus(
            f"{quoi} appartient a uid {st.st_uid} alors que le profil attend {uid_attendu} : refus")
    return st


def verifier_cloisonnement_repertoire(p: Path, uid_attendu: int, quoi: str):
    st = os.lstat(p)
    if stat.S_ISLNK(st.st_mode):
        raise SecretRefus(f"{quoi} est un lien symbolique : refus")
    if not stat.S_ISDIR(st.st_mode):
        raise SecretRefus(f"{quoi} n'est pas un repertoire : refus")
    mode = st.st_mode & 0o777
    if mode != MODE_DIR:
        raise SecretRefus(f"{quoi} mode {oct(mode)} : {oct(MODE_DIR)} requis (cloisonnement rompu)")
    if st.st_uid != uid_attendu:
        raise SecretRefus(f"{quoi} appartient a uid {st.st_uid} au lieu de {uid_attendu} : refus")
    return st


# --------------------------------------------------------------------------- #
# index
# --------------------------------------------------------------------------- #
def charger_index(root, secret_id: str) -> dict:
    pol = politique(root)
    spec = spec_secret(pol, secret_id)
    p = index_dir(root) / nom_index(secret_id)
    d = _charger_json(p, f"index du secret {secret_id}")
    if not isinstance(d, dict) or d.get("schema") != SCHEMA_INDEX:
        raise SecretIndisponible(f"index non conforme pour {secret_id}")
    if d.get("id") != secret_id:
        raise SecretIndisponible(f"index incoherent : identifiant different pour {secret_id}")
    if d.get("owner") != spec["owner"] or d.get("scope") != spec["scope"]:
        raise SecretRefus(
            f"index de {secret_id} divergent de la politique (proprietaire/portee) : refus")
    versions = d.get("versions")
    if not isinstance(versions, list) or not versions:
        raise SecretIndisponible(f"index de {secret_id} sans version")
    courante = None
    for v in versions:
        if v.get("n") == d.get("current") and not v.get("revoked"):
            courante = v
    if courante is None:
        raise SecretRefus(f"secret {secret_id} sans version courante valide")
    return d


def sauver_index(root, obj: dict):
    d = index_dir(root)
    d.mkdir(parents=True, exist_ok=True)
    os.chmod(d, 0o700)
    p = d / nom_index(obj["id"])
    tmp = p.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, p)
    os.chmod(p, 0o600)


def version_courante(idx: dict) -> dict:
    for v in idx["versions"]:
        if v["n"] == idx["current"] and not v.get("revoked"):
            return v
    raise SecretRefus(f"secret {idx['id']} sans version courante")


def version_demandee(idx: dict, version=None) -> dict:
    if version is None:
        return version_courante(idx)
    for v in idx["versions"]:
        if int(v["n"]) == int(version):
            if v.get("revoked"):
                raise SecretRefus(f"version {version} du secret {idx['id']} revoquee : refus")
            return v
    raise SecretRefus(f"version {version} inconnue pour {idx['id']}")


# --------------------------------------------------------------------------- #
# lecture / ecriture de la valeur (reservees au service awema-vaultd)
# --------------------------------------------------------------------------- #
def lire_valeur(root, secret_id: str, version=None, uid_attendu=None) -> tuple[bytes, dict]:
    pol = politique(root)
    idx = charger_index(root, secret_id)
    spec = spec_secret(pol, secret_id)
    v = version_demandee(idx, version)
    uid = spec["owner"] if uid_attendu is None else uid_attendu
    uid_reel = uid_coffre(pol)
    chemin_owner = Path(root) / "vault" / secret_id.split("/", 1)[0]
    verifier_cloisonnement_repertoire(chemin_owner, uid_reel, f"coffre du profil {spec['owner']}")
    p = chemin_valeur(root, secret_id, v["n"])
    verifier_cloisonnement_fichier(p, uid_reel, f"secret {secret_id} v{v['n']}")
    fd = os.open(p, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        brut = b""
        while True:
            bloc = os.read(fd, 65536)
            if not bloc:
                break
            brut += bloc
    finally:
        os.close(fd)
    if len(brut) > MAX_VALEUR:
        raise SecretRefus(f"secret {secret_id} trop volumineux")
    cle = cle_empreinte(root)
    if not hmac.compare_digest(empreinte(brut, cle), v["fingerprint"]):
        raise SecretRefus(
            f"empreinte divergente pour {secret_id} v{v['n']} : contenu modifie hors coffre, refus")
    return brut, idx


def ecrire_valeur(root, secret_id: str, valeur: bytes, version: int, revoquer_anterieures=False) -> str:
    pol = politique(root)
    spec = spec_secret(pol, secret_id)
    if not isinstance(valeur, (bytes, bytearray)) or not valeur:
        raise SecretRefus("valeur de secret vide")
    if len(valeur) > MAX_VALEUR:
        raise SecretRefus("valeur de secret trop volumineuse")
    uid = uid_coffre(pol)
    if os.getuid() != uid:
        raise SecretRefus("ecriture hors UID du coffre : refus")
    d = Path(root) / "vault" / secret_id.split("/", 1)[0]
    d.mkdir(parents=True, exist_ok=True)
    os.chmod(d, MODE_DIR)
    p = chemin_valeur(root, secret_id, version)
    if p.exists() or p.is_symlink():
        raise SecretRefus(f"la version {version} de {secret_id} existe deja")
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, MODE_SECRET)
    try:
        os.write(fd, bytes(valeur))
        os.fsync(fd)
    finally:
        os.close(fd)
    os.chmod(p, MODE_SECRET)
    cle = cle_empreinte(root)
    return empreinte(bytes(valeur), cle)


def provisionner(root, secret_id: str, valeur: bytes, acteur: str, kind: str,
                 rotation=False) -> dict:
    """Creation ou rotation d'un secret (le proprietaire ou le proprietaire humain)."""
    pol = politique(root)
    spec = spec_secret(pol, secret_id)
    if kind == "agent" and acteur != spec["owner"]:
        raise SecretRefus(
            f"un agent ne peut pas provisionner le secret d'un autre profil : {acteur} != {spec['owner']}")
    if kind == "human" and acteur not in (pol.get("humans") or {}):
        raise SecretRefus(f"acteur humain inconnu du coffre : {acteur!r}")
    idx_p = index_dir(root) / nom_index(secret_id)
    if idx_p.exists():
        idx = charger_index(root, secret_id)
        derniere = max(v["n"] for v in idx["versions"])
        if not rotation:
            raise SecretRefus(f"secret {secret_id} deja present : rotation explicite requise")
        version = derniere + 1
        fp = ecrire_valeur(root, secret_id, valeur, version)
        vc = version_courante(idx)
        vc["revoked"] = True
        vc["revoked_at"] = maintenant()
        idx["versions"].append({"n": version, "file": nom_fichier(secret_id, version),
                                "fingerprint": fp, "created_at": maintenant(),
                                "revoked": False, "revoked_at": None})
        idx["current"] = version
        idx["rotated_at"] = maintenant()
        idx["rotations"] = int(idx.get("rotations", 0)) + 1
        sauver_index(root, idx)
        return {"id": secret_id, "action": "rotate", "version": version,
                "fingerprint": fp, "version_precedente": vc["n"]}
    version = 1
    fp = ecrire_valeur(root, secret_id, valeur, version)
    idx = {"schema": SCHEMA_INDEX, "id": secret_id, "owner": spec["owner"],
           "scope": spec["scope"], "kind": spec.get("kind", "text"),
           "consumers": list(spec.get("consumers") or []),
           "rotation_days": spec.get("rotation_days"),
           "created_at": maintenant(), "rotated_at": None, "rotations": 0,
           "current": version,
           "versions": [{"n": version, "file": nom_fichier(secret_id, version),
                         "fingerprint": fp, "created_at": maintenant(),
                         "revoked": False, "revoked_at": None}]}
    sauver_index(root, idx)
    return {"id": secret_id, "action": "place", "version": version, "fingerprint": fp,
            "version_precedente": None}


def revoquer_version(root, secret_id: str, version: int, acteur: str, kind: str) -> dict:
    pol = politique(root)
    spec = spec_secret(pol, secret_id)
    if kind == "agent" and acteur != spec["owner"]:
        raise SecretRefus(f"revocation interdite : {acteur} n'est pas proprietaire de {secret_id}")
    idx = charger_index(root, secret_id)
    v = next((x for x in idx["versions"] if int(x["n"]) == int(version)), None)
    if v is None:
        raise SecretRefus(f"version {version} inconnue pour {secret_id}")
    if v.get("revoked"):
        raise SecretRefus(f"version {version} de {secret_id} deja revoquee")
    if idx["current"] == v["n"]:
        raise SecretRefus(
            "refus : la version courante ne peut pas etre revoquee sans rotation prealable")
    v["revoked"] = True
    v["revoked_at"] = maintenant()
    v["revoked_by"] = acteur
    sauver_index(root, idx)
    return {"id": secret_id, "version": version, "action": "revoke"}


# --------------------------------------------------------------------------- #
# habilitations (portee non privee uniquement)
# --------------------------------------------------------------------------- #
def grants_lire(root) -> dict:
    p = grants_path(root)
    if not p.exists():
        return {"schema": SCHEMA_GRANTS, "grants": []}
    d = _charger_json(p, "registre d'habilitations")
    if not isinstance(d, dict) or d.get("schema") != SCHEMA_GRANTS:
        raise SecretIndisponible("registre d'habilitations non conforme")
    return d


def grants_ecrire(root, d: dict):
    p = grants_path(root)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(d, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, p)
    os.chmod(p, 0o600)


def grant_creer(root, secret_id: str, vers: str, emetteur: str, kind: str, ttl_seconds: int) -> dict:
    pol = politique(root)
    spec = spec_secret(pol, secret_id)
    profil(pol, vers)
    if spec["scope"] not in SCOPES_PARTAGEABLES:
        raise SecretRefus(
            f"portee {spec['scope']!r} non partageable : aucune habilitation possible pour {secret_id}")
    if vers not in (spec.get("consumers") or []):
        raise SecretRefus(f"{vers} n'est pas un consommateur declare dans la politique pour {secret_id}")
    if kind == "agent" and emetteur != spec["owner"]:
        raise SecretRefus(f"seul le proprietaire {spec['owner']} peut habiliter {secret_id}")
    if kind == "human" and emetteur not in (pol.get("humans") or {}):
        raise SecretRefus(f"acteur humain inconnu : {emetteur!r}")
    ttl_max = int(pol["rules"].get("max_grant_ttl_seconds", 86400))
    if not (1 <= int(ttl_seconds) <= ttl_max):
        raise SecretRefus(f"duree d'habilitation hors bornes (1..{ttl_max})")
    d = grants_lire(root)
    deja = [g for g in d["grants"]
            if g["secret"] == secret_id and g["to"] == vers and not g.get("revoked_at")
            and not _grant_expire(g)]
    if deja:
        raise SecretRefus(f"habilitation deja active pour {vers} sur {secret_id}")
    g = {"id": "GRT-" + _secrets.token_hex(6), "secret": secret_id, "to": vers,
         "from": emetteur, "created_at": maintenant(),
         "expires_at": (_now_dt() + timedelta(seconds=int(ttl_seconds))).isoformat(),
         "revoked_at": None, "used": 0}
    d["grants"].append(g)
    grants_ecrire(root, d)
    with open(journal_grants_path(root), "a", encoding="utf-8") as f:
        f.write(json.dumps({"ts": maintenant(), "event": "grant_created", "grant": g["id"],
                            "secret": secret_id, "to": vers, "from": emetteur,
                            "expires_at": g["expires_at"]}, ensure_ascii=False) + "\n")
    return g


def _grant_expire(g: dict) -> bool:
    try:
        return _now_dt() >= datetime.fromisoformat(g["expires_at"])
    except (KeyError, ValueError):
        return True


def grant_revoquer(root, secret_id: str, vers: str, acteur: str, kind: str) -> dict:
    pol = politique(root)
    spec = spec_secret(pol, secret_id)
    if kind == "agent" and acteur != spec["owner"]:
        raise SecretRefus(f"seul le proprietaire {spec['owner']} peut revoquer une habilitation")
    d = grants_lire(root)
    n = 0
    for g in d["grants"]:
        if g["secret"] == secret_id and g["to"] == vers and not g.get("revoked_at"):
            g["revoked_at"] = maintenant()
            g["revoked_by"] = acteur
            n += 1
    if not n:
        raise SecretRefus(f"aucune habilitation active pour {vers} sur {secret_id}")
    grants_ecrire(root, d)
    with open(journal_grants_path(root), "a", encoding="utf-8") as f:
        f.write(json.dumps({"ts": maintenant(), "event": "grant_revoked", "secret": secret_id,
                            "to": vers, "by": acteur}, ensure_ascii=False) + "\n")
    return {"secret": secret_id, "to": vers, "revoquees": n}


def grant_valide(root, secret_id: str, vers: str) -> tuple[bool, str]:
    d = grants_lire(root)
    actifs = [g for g in d["grants"] if g["secret"] == secret_id and g["to"] == vers]
    if not actifs:
        return False, "aucune habilitation"
    if all(g.get("revoked_at") for g in actifs):
        return False, "habilitation revoquee"
    for g in actifs:
        if g.get("revoked_at"):
            continue
        if _grant_expire(g):
            return False, "habilitation expiree"
        return True, f"habilitation {g['id']} valide"
    return False, "aucune habilitation active"


# --------------------------------------------------------------------------- #
# decision d'autorisation (refus par defaut)
# --------------------------------------------------------------------------- #
def autoriser(root, secret_id: str, acteur: str, kind: str, action: str = "read",
              approval_id: str | None = None, tache_secret=None, token=None,
              credential=None) -> dict:
    """Decision pure : ne lit aucune valeur, ne journalise pas.

    Retourne {"autorise": bool, "motif": str, "base": str, "details": {...}}.
    """
    pol = politique(root)
    try:
        spec = spec_secret(pol, secret_id)
    except SecretRefus as exc:
        return {"autorise": False, "motif": str(exc), "base": "secret_inconnu", "details": {}}
    idx = charger_index(root, secret_id)
    motif_deny = None
    if action != "read":
        return {"autorise": False, "motif": f"action non supportee par le coffre : {action!r}",
                "base": "action_inconnue", "details": {}}

    if kind == "agent":
        if acteur == spec["owner"]:
            return {"autorise": True, "motif": "proprietaire du secret",
                    "base": "proprietaire", "details": {"version": idx["current"]}}
        # un agent ne lit jamais le secret d'un autre profil, meme avec un grant prive
        if acteur not in (spec.get("consumers") or []):
            return {"autorise": False,
                    "motif": f"agent {acteur} non habilite pour {secret_id} (refus par defaut)",
                    "base": "consommateur_absent", "details": {}}
        if spec["scope"] not in SCOPES_PARTAGEABLES:
            return {"autorise": False,
                    "motif": f"portee {spec['scope']!r} strictement privee : partage interdit",
                    "base": "portee_privee", "details": {}}
        ok, motif = grant_valide(root, secret_id, acteur)
        if not ok:
            return {"autorise": False,
                    "motif": f"consommateur declare mais sans habilitation valide : {motif}",
                    "base": "habilitation", "details": {}}
        return {"autorise": True, "motif": motif, "base": "consommateur_habilite",
                "details": {"version": idx["current"]}}

    if kind == "human":
        if acteur not in (pol.get("humans") or {}):
            return {"autorise": False, "motif": f"acteur humain inconnu : {acteur!r}",
                    "base": "humain_inconnu", "details": {}}
        if not (pol["rules"].get("break_glass_approval_required", True)):
            return {"autorise": True, "motif": "acces humain direct autorise par politique",
                    "base": "humain_direct", "details": {"version": idx["current"]}}
        if not approval_id:
            return {"autorise": False,
                    "motif": "acces humain a un secret de profil : approbation obligatoire (break-glass)",
                    "base": "approbation_absente", "details": {}}
        regle = _consommer_approbation(root, approval_id, secret_id, acteur, token,
                                       credential, tache_secret)
        if not regle["ok"]:
            return {"autorise": False, "motif": regle["motif"], "base": "approbation",
                    "details": {"approval": approval_id}}
        return {"autorise": True, "motif": regle["motif"], "base": "break_glass_approuve",
                "details": {"version": idx["current"], "approval": approval_id,
                            "task": regle.get("task"), "project": regle.get("project")}}

    return {"autorise": False, "motif": f"nature d'acteur non supportee : {kind!r}",
            "base": "nature_inconnue", "details": {}}


def _consommer_approbation(root, approval_id: str, secret_id: str, acteur: str,
                           token=None, credential=None, tache_secret=None) -> dict:
    """Consomme une approbation CP-01 a usage unique, liee action + tache + projet + cible.

    Le coffre agit pour le compte de l'acteur authentifie : son identite (jeton ou
    accreditation humaine) est propagee le temps de la consommation, puis retiree.
    """
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    try:
        import awema_approval_lib as AP  # noqa: PLC0415
    except ImportError as exc:  # pragma: no cover - dependance de socle
        return {"ok": False, "motif": f"bibliotheque d'approbation indisponible : {exc}"}
    try:
        c = AP.contract(root)
        obj = AP.charger_apr(root, approval_id, c)
    except Exception as exc:  # noqa: BLE001 - refus par defaut
        return {"ok": False, "motif": f"approbation non exploitable : {exc}"}
    if obj.get("action") != "secret_read":
        return {"ok": False, "motif": f"approbation d'une autre action : {obj.get('action')!r}"}
    tache = obj.get("task")
    chemin_tache = Path(root) / "data/tasks" / f"{tache}.json"
    if not chemin_tache.exists():
        return {"ok": False, "motif": f"tache d'approbation absente : {tache}"}
    try:
        d = json.loads(chemin_tache.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {"ok": False, "motif": f"tache d'approbation illisible : {tache}"}
    cible = d.get("secret")
    if not cible:
        return {"ok": False, "motif": "tache d'approbation sans cible de secret (liaison absente)"}
    if cible != secret_id:
        return {"ok": False,
                "motif": f"approbation liee a {cible!r} : elle ne couvre pas {secret_id!r}"}
    if tache_secret is not None and tache_secret != cible:
        return {"ok": False, "motif": "cible de tache divergente : refus"}
    sauve_tok = os.environ.get("AWEMA_ACTOR_TOKEN")
    sauve_cred = os.environ.get("AWEMA_ACTOR_CREDENTIAL")
    try:
        if credential:
            os.environ["AWEMA_ACTOR_CREDENTIAL"] = str(credential)
            os.environ.pop("AWEMA_ACTOR_TOKEN", None)
        elif token:
            os.environ["AWEMA_ACTOR_TOKEN"] = str(token)
            os.environ.pop("AWEMA_ACTOR_CREDENTIAL", None)
        AP.consommer(root, approval_id, tache, obj.get("project"), "secret_read", acteur=acteur)
    except Exception as exc:  # noqa: BLE001 - une consommation non confirmee vaut refus
        return {"ok": False, "motif": f"approbation non consommable : {exc}"}
    finally:
        for cle, valeur in (("AWEMA_ACTOR_TOKEN", sauve_tok),
                            ("AWEMA_ACTOR_CREDENTIAL", sauve_cred)):
            if valeur is None:
                os.environ.pop(cle, None)
            else:
                os.environ[cle] = valeur
    return {"ok": True, "motif": f"break-glass approuve ({approval_id})", "task": tache,
            "project": obj.get("project")}


# --------------------------------------------------------------------------- #
# inventaire masque et cloisonnement du coffre
# --------------------------------------------------------------------------- #
def inventaire(root, reveler_portee=True) -> dict:
    pol = politique(root)
    secrets_out = []
    for sid, spec in sorted(pol["secrets"].items()):
        entree = {"id": sid, "proprietaire": spec["owner"], "portee": spec["scope"],
                  "type": spec.get("kind", "text"),
                  "consommateurs_declares": list(spec.get("consumers") or []),
                  "rotation_jours": spec.get("rotation_days"),
                  "present_au_coffre": (index_dir(root) / nom_index(sid)).exists()}
        if entree["present_au_coffre"]:
            try:
                idx = charger_index(root, sid)
                vc = version_courante(idx)
                entree["version_courante"] = vc["n"]
                entree["empreinte_courante"] = vc["fingerprint"]
                entree["versions_revoquees"] = [v["n"] for v in idx["versions"] if v.get("revoked")]
                entree["derniere_rotation"] = idx.get("rotated_at") or idx["created_at"]
                entree["habilitations_actives"] = [
                    {"to": g["to"], "expires_at": g["expires_at"]}
                    for g in grants_lire(root)["grants"]
                    if g["secret"] == sid and not g.get("revoked_at") and not _grant_expire(g)]
            except (SecretRefus, SecretIndisponible) as exc:
                entree["etat"] = f"coffre non conforme : {exc}"
        secrets_out.append(entree)
    return {"schema": "awema-secret-inventaire/1", "ts": maintenant(),
            "racine": str(root), "nb_secrets": len(secrets_out), "secrets": secrets_out,
            "note": "Aucune valeur de secret n'est listee : identifiants, portee, proprietaire et empreintes seulement."}


def verifier_coffre(root) -> dict:
    """Controle d'integrite et de cloisonnement de tout le coffre."""
    pol = politique(root)
    ecarts = []
    absents = []
    vus = 0
    for sid, spec in sorted(pol["secrets"].items()):
        p = index_dir(root) / nom_index(sid)
        if not p.exists():
            absents.append({"secret": sid, "motif": "absent du coffre"})
            continue
        vus += 1
        idx = charger_index(root, sid)
        uid = uid_coffre(pol)
        dossier = Path(root) / "vault" / sid.split("/", 1)[0]
        try:
            verifier_cloisonnement_repertoire(dossier, uid, f"coffre {spec['owner']}")
        except (SecretRefus, OSError) as exc:
            ecarts.append({"secret": sid, "motif": str(exc)})
        cle = cle_empreinte(root)
        for v in idx["versions"]:
            fp = chemin_valeur(root, sid, v["n"])
            try:
                verifier_cloisonnement_fichier(fp, uid, f"{sid} v{v['n']}")
            except (SecretRefus, OSError) as exc:
                ecarts.append({"secret": sid, "version": v["n"], "motif": str(exc)})
                continue
            brut = fp.read_bytes()
            if not hmac.compare_digest(empreinte(brut, cle), v["fingerprint"]):
                ecarts.append({"secret": sid, "version": v["n"],
                               "motif": "empreinte divergente (contenu altere)"})
        cible = version_courante(idx)
        if idx["scope"] not in SCOPES_PARTAGEABLES and (spec.get("consumers") or []):
            ecarts.append({"secret": sid, "motif": "portee privee avec consommateurs declares"})
        if cible["n"] != max(v["n"] for v in idx["versions"]):
            ecarts.append({"secret": sid, "motif": "version courante anterieure a une version existante"})
    return {"schema": "awema-secret-verification/1", "ts": maintenant(),
            "secrets_vus": vus, "absents": absents, "ecarts": ecarts,
            "verdict": "conforme" if not ecarts else "ecart"}
