"""Strictly read-only projection of one operator-allowlisted test mission."""
from __future__ import annotations
import hashlib
import json
import math
import re
import time
from urllib.parse import urlencode
SCHEMA = "awema-agent-standup-feed-v1"
MAX_EVENTS = 10000
MAX_ARTIFACTS = 200
MAX_SQLITE_ID = (1 << 63) - 1
MISSION_ID = re.compile(r"f_[a-f0-9]{24}\Z")
SHA256 = re.compile(r"[a-f0-9]{64}\Z")
BASENAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
CODE = re.compile(r"[a-z][a-z0-9_-]{0,95}\Z")
ROLE_NAMES = {"cto":"CTO","pm":"Chef de projet","dev":"Développeur","qa":"Vérification","security":"Sécurité","ops":"Opérations","designer":"Designer","assa":"Direction AWEMA","cl-producer":"CL Producer"}
STEP_STATES = {"waiting","pending","dispatching","running","done","blocked","cancelled"}
MISSION_STATES = {"plan","queued","running","cancel_requested","cancelled","blocked","review","delivered"}
SYSTEM_EVENTS = {
 "plan_created":"Le dossier de mission a été créé.",
 "objective_execution_requested":"L’exécution de cet objectif a été demandée.",
 "human_plan_approved":"L’opérateur a approuvé le plan.",
 "human_cancel_requested":"L’opérateur a demandé un arrêt.",
 "human_retry_requested":"L’opérateur a demandé une relance.",
 "human_continue_requested":"L’opérateur a demandé une reprise avec précision.",
 "human_retry_applied":"La relance opérateur a été enregistrée.",
 "human_continue_applied":"La reprise opérateur a été enregistrée.",
 "automatic_retry_scheduled":"Une nouvelle tentative automatique a été planifiée.",
 "automatic_checkpoint_resume_scheduled":"Une reprise depuis un point confirmé a été planifiée.",
 "automatic_contract_repair_scheduled":"Une correction du contrat de sortie a été planifiée.",
 "automatic_correction_scheduled":"Une correction a été transmise aux étapes concernées.",
 "human_correction_scheduled":"Une correction demandée par l’opérateur a été transmise.",
 "operator_explanation_required":"Une explication du blocage a été enregistrée.",
 "operator_technical_fix_verified":"Une vérification technique de reprise a été enregistrée.",
 "waiting_capacity":"La mission attend une capacité d’exécution disponible.",
 "capacity_available":"Une capacité d’exécution est disponible.",
 "kanban_retry_scheduled":"Une vérification du Kanban a été planifiée.",
 "recovery_waiting_for_worker":"La reprise attend la confirmation de l’arrêt du worker.",
 "recovery_refused_uncertain":"La reprise est refusée car un effet reste incertain.",
 "recovery_limit_reached":"La limite de reprise enregistrée a été atteinte.",
 "worker_timeout_cancel_requested":"Un arrêt du worker a été demandé après expiration du délai.",
 "worker_state_missing_waiting":"La mission attend un état worker confirmé.",
 "blocked":"Un blocage de mission a été enregistré.",
 "review":"La mission a été transmise pour relecture.",
 "delivered":"Une livraison a été enregistrée ; son contenu reste à consulter.",
 "cancelled":"L’arrêt de la mission a été enregistré.",
 "running":"L’exécution de la mission a été enregistrée.",
 "queued":"La mission a été placée en attente.",
 "human_accepted":"L’opérateur a accepté la livraison.",
 "human_correction_requested":"L’opérateur a demandé une correction."
}
STATE_SUMMARIES = {
 "waiting":"Attend son étape dans le déroulé enregistré.",
 "pending":"Une tentative est préparée dans le registre.",
 "dispatching":"Affectation enregistrée ; le démarrage reste à confirmer.",
 "running":"Étape enregistrée en cours ; ce statut ne prouve pas une activité continue.",
 "done":"Étape enregistrée terminée. Le résultat reste à relire.",
 "blocked":"Étape enregistrée bloquée. Consulter le dossier de mission.",
 "cancelled":"L’arrêt de son étape est enregistré.",
 "unknown":"État enregistré non reconnu. Consulter la Ruche."
}
class FeedError(ValueError):
 """Fixed diagnostic codes only, never source text."""
def canonical_bytes(value):
 return json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(",",":"),allow_nan=False).encode("utf-8")
def digest(value):
 return hashlib.sha256(canonical_bytes(value)).hexdigest()
def json_bytes(value):
 return canonical_bytes(value).replace(b"<",b"\\u003c").replace(b">",b"\\u003e").replace(b"&",b"\\u0026")+b"\n"
def validate_mission_id(value):
 if not isinstance(value,str) or not MISSION_ID.fullmatch(value):raise FeedError("mission_id_invalid")
 return value
def _number(value,code):
 if isinstance(value,bool) or not isinstance(value,(int,float)) or not math.isfinite(value) or value<0:raise FeedError(code)
 return value
def _objective(value):
 if not isinstance(value,str) or not value.strip() or len(value)>16000:raise FeedError("objective_invalid")
 # Secondary redaction does not replace operator review and exact objective pin.
 value="".join(ch for ch in value if ch in "\n\t" or (ord(ch)>=32 and ch not in "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"))
 value=re.sub(r"(?i)\b(?:password|mot de passe|secret|token|api[_ -]?key|authorization|bearer|cookie|csrf)\s*[:=]\s*\S+","[donnée masquée]",value)
 value=re.sub(r"[A-Za-z0-9.!#$%&'*+/=?^_{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+","[adresse masquée]",value)
 value=re.sub(r"(?<!\w)\+?\d(?:[ .()-]*\d){7,}(?!\w)","[numéro masqué]",value)
 return value[:1200]
def _event(row,present_roles):
 eid,code,created=row
 if type(eid) is not int or not 0<eid<=MAX_SQLITE_ID:raise FeedError("event_id_invalid")
 _number(created,"event_timestamp_invalid")
 if not isinstance(code,str) or len(code)>1000:raise FeedError("event_code_invalid")
 agent="system";summary=SYSTEM_EVENTS.get(code)
 if summary is None:
  for role in sorted(present_roles,key=len,reverse=True):
   if code==role+"_dispatching":agent,summary=role,ROLE_NAMES[role]+" : affectation de l’étape enregistrée."
   elif code==role+"_handoff_received":agent,summary=role,ROLE_NAMES[role]+" a reçu la suite du travail dans le registre."
   elif code==role+"_completed":agent,summary=role,ROLE_NAMES[role]+" a terminé son étape enregistrée. Le contenu reste à relire."
   elif code=="blocker_"+role+"_explained":agent,summary=role,"Une explication de blocage est disponible pour "+ROLE_NAMES[role]+"."
   if summary is not None:break
 kind=code if summary is not None and CODE.fullmatch(code) else "unmapped"
 return {"id":eid,"agent":agent,"kind":kind,"summary":summary or "Un événement réel non interprété a été enregistré.","created":created,"source_event_sha256":hashlib.sha256(code.encode("utf-8")).hexdigest()}
def _agent(role,states):
 states=[s if s in STEP_STATES else "unknown" for s in states]
 state="done" if all(s=="done" for s in states) else next(s for s in ("running","dispatching","blocked","unknown","pending","waiting","cancelled") if s in states)
 return {"id":role,"name":ROLE_NAMES[role],"state":state,"summary":STATE_SUMMARIES[state]}
def build_feed(conn,mission_id,after=0):
 """Only SELECTs; use one query_only read transaction, never portal Store.

 Recorded lifecycle completion is deliberately never a quality PASS.
 Persistent cursor IDs are SQLite mission_events IDs, never list positions.
 """
 validate_mission_id(mission_id)
 if type(after) is not int or not 0<=after<=MAX_SQLITE_ID:raise FeedError("cursor_invalid")
 if conn.execute("PRAGMA query_only").fetchone()[0]!=1:raise FeedError("query_only_required")
 row=conn.execute("SELECT id,objective,state FROM mission_flows WHERE id=?",(mission_id,)).fetchone()
 if row is None:raise FeedError("mission_not_found")
 mid,objective,mission_state=tuple(row)
 if mission_state not in MISSION_STATES:raise FeedError("mission_state_unknown")
 objective_public=_objective(objective)
 steps=[tuple(r) for r in conn.execute("SELECT ordinal,role,state FROM mission_steps WHERE mission=? ORDER BY ordinal",(mission_id,))]
 if len(steps)>64:raise FeedError("too_many_steps")
 roles={}
 for ordinal,role,state in steps:
  if type(ordinal) is not int or ordinal<0 or role not in ROLE_NAMES:raise FeedError("step_invalid")
  if not isinstance(state,str) or not CODE.fullmatch(state):raise FeedError("step_state_invalid")
  roles.setdefault(role,[]).append(state)
 raw_events=[tuple(r) for r in conn.execute("SELECT id,event,created FROM mission_events WHERE mission=? AND id>? ORDER BY id LIMIT ?",(mission_id,after,MAX_EVENTS+1))]
 if len(raw_events)>MAX_EVENTS:raise FeedError("event_window_too_large")
 events=[_event(r,roles) for r in raw_events]
 if any(events[i]["id"]>=events[i+1]["id"] for i in range(len(events)-1)):raise FeedError("event_order_invalid")
 raw_artifacts=[tuple(r) for r in conn.execute("SELECT name,ordinal,sha256 FROM mission_artifacts WHERE mission=? ORDER BY ordinal,name LIMIT ?",(mission_id,MAX_ARTIFACTS+1))]
 if len(raw_artifacts)>MAX_ARTIFACTS:raise FeedError("too_many_artifacts")
 artifacts=[];withheld=0
 for name,ordinal,sha in raw_artifacts:
  if not isinstance(name,str) or not BASENAME.fullmatch(name) or type(ordinal) is not int or not 0<=ordinal<=4 or not isinstance(sha,str) or not SHA256.fullmatch(sha):raise FeedError("artifact_metadata_invalid")
  if name.lower() in {"auth.json","tokens.json","credentials.json","id_rsa","id_ed25519"} or name.lower().endswith(".dpapi"):
   withheld+=1;continue
  url="/finance/mission-preview?"+urlencode({"mission":mid,"ordinal":ordinal,"name":name})
  artifacts.append({"name":name,"ordinal":ordinal,"sha256":sha,"url":url})
 total_events=conn.execute("SELECT count(*) FROM mission_events WHERE mission=?",(mission_id,)).fetchone()[0]
 source={"mission":list(row),"steps":steps,"events":raw_events,"artifacts":raw_artifacts}
 feed={"schema":SCHEMA,"mission":{"id":mid,"objective":objective_public,"state":mission_state},"agents":[_agent(role,states) for role,states in roles.items()],"events":events,"artifacts":artifacts,"observed_at":time.time(),"cursor":{"after":after,"next":events[-1]["id"] if events else after},"provenance":{"source":"finance.sqlite/read-only","mission_id":mid,"persistent_event_ids":True,"event_count":total_events,"returned_event_count":len(events),"source_snapshot_sha256":digest(source),"events_sha256":digest(events),"objective_sha256":hashlib.sha256(objective.encode("utf-8")).hexdigest(),"withheld_artifacts":withheld,"quality_verdict":"not_evaluated_by_projection","agent_attribution":"recorded_role_code_only","freeform_worker_text_included":False}}
 feed["provenance"]["projection_sha256"]=digest(feed)
 return feed

