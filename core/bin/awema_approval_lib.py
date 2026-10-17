#!/usr/bin/env python3
"""Surcharge P0-3 de la bibliotheque d'approbation (contrat CP-01 conserve).

Le module d'approbation verifie (awema_approval_lib_base.py, copie empreinte de
la carte t_d151fb18) ecrivait le journal en direct dans data/audit/events.jsonl :
une ecriture non chainee, non signee, dans un perimetre inscriptible par l'UID
agent, et un echec d'ecriture ne bloquait rien de plus que l'appelant.

Cette surcharge remplace TROIS fonctions du module de base et propage la
surcharge aux appels internes (monkey-patch du module) :

  * journal()        -> passe par le service d'audit scelle (awema-auditd) ;
                        toute indisponibilite devient un Refus : l'action
                        critique est refusee AVANT tout effet (P0-3) ;
  * lire_journal()   -> lecture du journal chaine ;
  * quarantaine()    -> ecrit l'entree d'audit AVANT le deplacement du fichier.

Le reste du module (validation, signature, cycle de vie) est inchange.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import awema_audit_lib as AUD
import awema_approval_lib_base as _base

# re-export de toute l'API de base (Refus, contract, demander, decider, ...)
globals().update({k: v for k, v in vars(_base).items() if not k.startswith("__")})

Refus = _base.Refus

CHAMPS_ACTEUR = ("actor", "agent", "requester", "approver", "by", "consumed_by", "consumed_by")
CHAMPS_CIBLE = ("task", "approval", "execution", "file", "id")
CHAMPS_LIENS = ("task", "project", "action", "approval", "execution", "file")


def _txt(v):
    """Preserve les valeurs JSON exploitables dans le journal."""
    if isinstance(v, (str, int, float, bool)) or v is None:
        return v
    if isinstance(v, list):
        return [_txt(x) for x in v]
    if isinstance(v, dict):
        return {str(k): _txt(x) for k, x in v.items()}
    return str(v)


def _outil() -> str:
    nom = os.environ.get("AWEMA_AUDIT_TOOL") or (sys.argv[0] if sys.argv else "")
    nom = Path(nom).name
    return nom if nom else "awema-inconnu"


def _acteur(kw) -> str | None:
    for champ in CHAMPS_ACTEUR:
        v = kw.get(champ)
        if isinstance(v, str) and v.strip():
            return v.strip()
    v = os.environ.get("AWEMA_ACTOR_ID")
    return v.strip() if isinstance(v, str) and v.strip() else None


def journal(root, event, **kw):
    """Entree d'audit AVANT la mutation ; toute defaillance => Refus (fail-closed)."""
    root = Path(root)
    acteur = _acteur(kw)
    cible = next((kw[c] for c in CHAMPS_CIBLE if isinstance(kw.get(c), str) and kw.get(c)), None)
    if cible is None:
        cible = "audit-store"
    corr = None
    for champ in ("execution", "approval", "task", "correlation_id"):
        v = kw.get(champ)
        if isinstance(v, str) and v.strip():
            corr = v.strip()
            break
    if corr is None:
        corr = str(event)
    detail = {k: _txt(v) for k, v in kw.items() if k not in CHAMPS_ACTEUR and k not in CHAMPS_CIBLE}
    detail["liens"] = {k: _txt(kw.get(k)) for k in CHAMPS_LIENS if kw.get(k) is not None}
    detail["declaration_acteur"] = acteur
    try:
        entree = AUD.emettre(root, event, tool=_outil(), target=str(cible),
                             correlation_id=str(corr), action=kw.get("action"),
                             task=kw.get("task") if isinstance(kw.get("task"), str) else None,
                             project=kw.get("project") if isinstance(kw.get("project"), str) else None,
                             detail=detail, acteur=acteur)
    except (AUD.AuditIndisponible, AUD.AuditRefus) as exc:
        raise Refus(f"journal d'audit refuse ({exc}) — action refusee")
    return json.dumps(entree, ensure_ascii=False) + "\n"


def lire_journal(root):
    return AUD.lire_journal(root)


def quarantaine(root, p, motif: str):
    """Entree d'audit avant le deplacement (C-06 applique a la quarantaine)."""
    path = Path(p)
    journal(root, "approval_quarantine_starting", file=path.name, motif=motif)
    q = Path(root) / "data/approvals/quarantine"
    q.mkdir(parents=True, exist_ok=True)
    cible = q / (path.name + ".quarantine")
    try:
        os.replace(path, cible)
    except OSError as exc:
        raise Refus(f"approbation non conforme et mise en quarantaine impossible ({exc})")
    journal(root, "approval_quarantined", file=path.name, motif=motif)
    return cible


# propagation aux appels internes du module de base
_base.journal = journal
_base.lire_journal = lire_journal
_base.quarantaine = quarantaine
