"""Private multi-mission catalog. No listener, auth data, actions or source writes."""
from __future__ import annotations
import hashlib
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import stat
import tempfile
import time
from urllib.parse import urlencode
import export_projection as exporter
from standup_feed import (FeedError, SCHEMA as FEED_SCHEMA, SHA256, ROLE_NAMES,
 MISSION_STATES, CODE, BASENAME, _agent, _event, _number, canonical_bytes,
 digest, validate_mission_id)

SCHEMA = "awema-agent-standup-catalog-v2"
MAX_TEXT_BYTES = 128 * 1024
MAX_CATALOG_BYTES = 128 * 1024 * 1024
MAX_EXPORT_SECONDS = 10
TEXT_EXTENSIONS = {".txt",".md",".json",".html",".htm",".css",".js",".mjs",".cjs",
 ".ts",".tsx",".jsx",".py",".sql",".xml",".csv",".yaml",".yml",".toml",".ini",
 ".svg",".sh",".ps1",".log",".rst"}
SECRET_NAME = re.compile(r"(?i)(?:^\.env(?:\.|$)|(?:^|[._-])(?:auth|credentials?|secrets?|tokens?|passwords?|cookies?|sessions?|oauth|private[_-]?key)(?:[._-]|$)|^id_(?:rsa|ed25519|ecdsa|dsa)(?:\.|$)|\.(?:dpapi|pem|key|p12|pfx|kdbx)$)")
SQL = """
CREATE TABLE meta(id INTEGER PRIMARY KEY CHECK(id=1),schema TEXT NOT NULL,
 observed_at REAL NOT NULL,source_sha256 TEXT NOT NULL,generation TEXT NOT NULL);
CREATE TABLE missions(id TEXT PRIMARY KEY,owner_id TEXT NOT NULL,
 objective_sanitized TEXT NOT NULL,state TEXT NOT NULL,created REAL NOT NULL,
 updated REAL NOT NULL,event_count INTEGER NOT NULL,artifact_count INTEGER NOT NULL);
CREATE INDEX mission_owner_id ON missions(owner_id,id);
CREATE TABLE feeds(mission_id TEXT PRIMARY KEY,content TEXT NOT NULL,sha256 TEXT NOT NULL);
CREATE TABLE events(mission_id TEXT NOT NULL,id INTEGER NOT NULL,agent TEXT NOT NULL,
 kind TEXT NOT NULL,summary TEXT NOT NULL,created REAL NOT NULL,
 source_event_sha256 TEXT NOT NULL,PRIMARY KEY(mission_id,id));
CREATE TABLE artifactsources(mission_id TEXT NOT NULL,ordinal INTEGER NOT NULL,
 name TEXT NOT NULL,role TEXT NOT NULL,source_sha256 TEXT NOT NULL,
 display_sha256 TEXT NOT NULL,text TEXT NOT NULL,mime TEXT NOT NULL,
 truncated INTEGER NOT NULL,redacted INTEGER NOT NULL,unavailable INTEGER NOT NULL,
 reason TEXT NOT NULL,PRIMARY KEY(mission_id,ordinal,name));
"""

def sanitize_text(value):
 """Conservative obvious-secret redaction, not a claim of full PII detection."""
 if not isinstance(value,str):raise FeedError("text_invalid")
 value="".join(ch for ch in value if ch in "\n\t" or
   (ord(ch)>=32 and ch not in "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"))
 # Cover ordinary key=value, JSON key/value and authorization headers.
 value=re.sub(r"""(?ix)\b(?:password|mot[ ]de[ ]passe|secret|token|api[_ -]?key|authorization|bearer|cookie|csrf)\b["']?\s*[:=]\s*(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;<>]+)""",
              "[donnée masquée]",value)
 value=re.sub(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}","Bearer [donnée masquée]",value)
 value=re.sub(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----",
              "[clé privée masquée]",value)
 value=re.sub(r"[A-Za-z0-9.!#$%&'*+/=?^_{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+",
              "[adresse masquée]",value)
 value=re.sub(r"(?<!\w)\+?\d(?:[ .()-]*\d){7,}(?!\w)","[numéro masqué]",value)
 return value

def _deadline(start):
 if time.monotonic()-start>MAX_EXPORT_SECONDS:raise FeedError("catalog_time_budget_exceeded")

def _owner(value):
 if not isinstance(value,str) or not value or len(value)>128 or any(ord(ch)<32 for ch in value):
  raise FeedError("mission_owner_id_invalid")
 return value

def _timestamp(value):
 return _number(value,"mission_timestamp_invalid")

def _steps(conn,mid):
 rows=[tuple(r) for r in conn.execute("SELECT ordinal,role,state FROM mission_steps WHERE mission=? ORDER BY ordinal",(mid,))]
 if len(rows)>64:raise FeedError("too_many_steps")
 roles={};by_ordinal={}
 for ordinal,role,state in rows:
  if type(ordinal) is not int or not 0<=ordinal<=63 or role not in ROLE_NAMES:raise FeedError("step_invalid")
  if ordinal in by_ordinal:raise FeedError("step_ordinal_duplicate")
  if not isinstance(state,str) or not CODE.fullmatch(state):raise FeedError("step_state_invalid")
  by_ordinal[ordinal]=role
  roles.setdefault(role,[]).append(state)
 return rows,roles,by_ordinal

def _artifact_source(conn,mid,ordinal,name,sha,role,byte_size,value_type):
 result={"mission_id":mid,"ordinal":ordinal,"name":name,"role":role,
  "source_sha256":sha,"display_sha256":"","text":"","mime":"text/plain",
  "truncated":False,"redacted":False,"unavailable":True,"reason":""}
 if SECRET_NAME.search(name):
  result["reason"]="sensitive_filename";return result
 if type(byte_size) is not int or byte_size<0 or value_type!="text":
  result["reason"]="non_text_source";return result
 if byte_size>MAX_TEXT_BYTES:
  result.update(reason="source_text_too_large",truncated=True);return result
 if Path(name).suffix.lower() not in TEXT_EXTENSIONS:
  result["reason"]="unsupported_text_format";return result
 row=conn.execute("SELECT content FROM mission_artifacts WHERE mission=? AND ordinal=? AND name=?",(mid,ordinal,name)).fetchone()
 content=row[0] if row else None
 if not isinstance(content,str):
  result["reason"]="non_text_source";return result
 try:raw=content.encode("utf-8")
 except UnicodeError:
  result["reason"]="invalid_utf8";return result
 if len(raw)!=byte_size or len(raw)>MAX_TEXT_BYTES:
  raise FeedError("artifact_source_size_changed")
 if content.startswith("AWEMA_MEDIA_V1\n"):
  result["reason"]="binary_media_envelope";return result
 if hashlib.sha256(raw).hexdigest()!=sha:
  result["reason"]="source_sha256_mismatch";return result
 display=sanitize_text(content)
 if len(display.encode("utf-8"))>MAX_TEXT_BYTES:
  result.update(reason="display_text_too_large",truncated=True);return result
 if "\x00" in content:
  result["reason"]="binary_text_content";return result
 result.update(text=display,display_sha256=hashlib.sha256(display.encode("utf-8")).hexdigest(),
               redacted=display!=content,unavailable=False)
 return result

def _hash_items():
 h=hashlib.sha256();h.update(b"[")
 return h

def _append_hash(h,value,first):
 if not first:h.update(b",")
 h.update(canonical_bytes(value))

def _finish_hash(h):
 h.update(b"]");return h.hexdigest()

def build_catalog(conn,target,observed_at=None,start=None):
 """Project only mission metadata/lifecycle/verified text, never users or sessions.

 Both connections are caller-owned. Source must be query_only in ONE transaction.
 Caller commits and closes target before publication. Every recorded event is kept.
 """
 if conn.execute("PRAGMA query_only").fetchone()[0]!=1:raise FeedError("query_only_required")
 if not conn.in_transaction:raise FeedError("source_transaction_required")
 start=time.monotonic() if start is None else start
 observed_at=time.time() if observed_at is None else _timestamp(observed_at)
 target.executescript(SQL)
 missions=events_count=artifact_count=0;selected_hash=_hash_items()
 for row in conn.execute("SELECT id,user,objective,state,created,updated FROM mission_flows ORDER BY id"):
  _deadline(start)
  mid,owner,objective,state,created,updated=tuple(row)
  validate_mission_id(mid);_owner(owner)
  if not isinstance(objective,str) or not objective.strip() or len(objective)>16000:raise FeedError("objective_invalid")
  if state not in MISSION_STATES:raise FeedError("mission_state_unknown")
  _timestamp(created);_timestamp(updated)
  steps,roles,by_ordinal=_steps(conn,mid)
  eh=_hash_items();ec=0
  for erow in conn.execute("SELECT id,event,created FROM mission_events WHERE mission=? ORDER BY id",(mid,)):
   _deadline(start)
   event=_event(tuple(erow),roles)
   target.execute("INSERT INTO events VALUES(?,?,?,?,?,?,?)",(mid,event["id"],event["agent"],event["kind"],event["summary"],event["created"],event["source_event_sha256"]))
   _append_hash(eh,event,ec==0);ec+=1
  events_sha=_finish_hash(eh)
  ah=_hash_items();ac=0
  for arow in conn.execute("SELECT ordinal,name,sha256,length(CAST(content AS BLOB)),typeof(content) FROM mission_artifacts WHERE mission=? ORDER BY ordinal,name",(mid,)):
   _deadline(start)
   ordinal,name,sha,byte_size,value_type=tuple(arow)
   if type(ordinal) is not int or not 0<=ordinal<=63 or not isinstance(name,str) or not BASENAME.fullmatch(name) or not isinstance(sha,str) or not SHA256.fullmatch(sha):
    raise FeedError("artifact_metadata_invalid")
   role=by_ordinal.get(ordinal,"system")
   a=_artifact_source(conn,mid,ordinal,name,sha,role,byte_size,value_type)
   target.execute("INSERT INTO artifactsources VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
    (mid,ordinal,name,role,sha,a["display_sha256"],a["text"],a["mime"],
     int(a["truncated"]),int(a["redacted"]),int(a["unavailable"]),a["reason"]))
   _append_hash(ah,{"ordinal":ordinal,"name":name,"sha256":sha,"role":role,
                    "display_sha256":a["display_sha256"],"reason":a["reason"]},ac==0)
   ac+=1
  artifacts_sha=_finish_hash(ah)
  objective_public=sanitize_text(objective)
  mission={"id":mid,"objective":objective_public,"state":state}
  mission_digest=digest({"mission":mission,"steps":steps,"events_sha256":events_sha,"artifacts_sha256":artifacts_sha})
  feed={"schema":FEED_SCHEMA,"mission":mission,
   "agents":[_agent(role,states) for role,states in roles.items()],
   "events":[],"artifacts":[],"observed_at":observed_at,
   "cursor":{"after":0,"next":0,"has_more":ec>0,"total":ec},
   "artifact_cursor":{"after":0,"next":0,"has_more":ac>0,"total":ac},
   "provenance":{"source":"private-mission-catalog/read-only","mission_id":mid,
    "persistent_event_ids":True,"event_count":ec,"returned_event_count":0,
    "source_snapshot_sha256":mission_digest,"events_sha256":digest([]),
    "full_events_sha256":events_sha,"objective_sha256":hashlib.sha256(objective.encode("utf-8")).hexdigest(),
    "quality_verdict":"not_evaluated_by_projection","agent_attribution":"recorded_role_code_only",
    "freeform_worker_text_included":False,"objective_sanitizer":"obvious-secrets-only",
    "objective_redacted":objective_public!=objective,"withheld_artifacts":0}}
  feed["provenance"]["projection_sha256"]=digest(feed)
  content=canonical_bytes(feed).decode("utf-8")
  target.execute("INSERT INTO missions VALUES(?,?,?,?,?,?,?,?)",(mid,owner,objective_public,state,created,updated,ec,ac))
  target.execute("INSERT INTO feeds VALUES(?,?,?)",(mid,content,hashlib.sha256(content.encode("utf-8")).hexdigest()))
  _append_hash(selected_hash,{"id":mid,"owner_id":owner,"created":created,"updated":updated,"mission_sha256":mission_digest},missions==0)
  missions+=1;events_count+=ec;artifact_count+=ac
  pages=target.execute("PRAGMA page_count").fetchone()[0]
  page_size=target.execute("PRAGMA page_size").fetchone()[0]
  if pages*page_size>MAX_CATALOG_BYTES:raise FeedError("catalog_size_budget_exceeded")
 generation=_finish_hash(selected_hash)
 return {"mission_count":missions,"event_count":events_count,"artifact_count":artifact_count,
         "generation":generation,"observed_at":observed_at}

def export_catalog_once(database,destination,group_gid=None,require_root=True):
 if require_root and (os.name!="posix" or os.geteuid()!=0):raise FeedError("operator_root_required")
 destination=Path(destination)
 exporter._private_parent(destination.parent,require_root)
 if destination.exists() or destination.is_symlink():
  old=exporter._regular(destination)
  if require_root and (old.st_uid!=0 or stat.S_IMODE(old.st_mode)&0o027):
   raise FeedError("existing_projection_not_protected")
 if group_gid is not None and (type(group_gid) is not int or group_gid<0 or not hasattr(os,"fchown")):
  raise FeedError("projection_group_invalid")
 fd,temp=tempfile.mkstemp(prefix=".catalog-",suffix=".sqlite",dir=destination.parent)
 try:
  if hasattr(os,"fchmod"):os.fchmod(fd,0o600)
  if group_gid is not None:os.fchown(fd,-1,group_gid)
  os.close(fd);fd=None
  start=time.monotonic()
  out=sqlite3.connect(temp)
  try:
   out.execute("PRAGMA journal_mode=DELETE")
   out.execute("PRAGMA synchronous=FULL")
   out.execute("PRAGMA max_page_count="+str(MAX_CATALOG_BYTES//4096))
   out.set_progress_handler(lambda:int(time.monotonic()-start>MAX_EXPORT_SECONDS),1000)
   with exporter.stable_snapshot(database) as (snapshot,audit):
    source=exporter.open_readonly(snapshot)
    try:
     source.execute("BEGIN")
     result=build_catalog(source,out,start=start)
     source.rollback()
    finally:source.close()
   out.execute("INSERT INTO meta VALUES(1,?,?,?,?)",(SCHEMA,result["observed_at"],digest(audit["source_sha256"]),result["generation"]))
   out.commit()
  finally:out.close()
  _deadline(start)
  if any(Path(temp+suffix).exists() for suffix in ("-wal","-shm","-journal")):
   raise FeedError("projection_sidecar_unexpected")
  os.chmod(temp,0o640)
  info=exporter._regular(temp)
  if info.st_size>MAX_CATALOG_BYTES:raise FeedError("catalog_size_budget_exceeded")
  with open(temp,"r+b") as stream:
   os.fsync(stream.fileno())
  os.replace(temp,destination)
  if os.name=="posix":
   directory=os.open(destination.parent,os.O_RDONLY|os.O_DIRECTORY)
   try:os.fsync(directory)
   finally:os.close(directory)
  return {"schema":SCHEMA,**result,"bytes":info.st_size,
          "read_only_source":True,"auth_data_exported":False}
 except BaseException:
  if fd is not None:os.close(fd)
  for path in (temp,temp+"-journal",temp+"-wal",temp+"-shm"):
   try:os.unlink(path)
   except FileNotFoundError:pass
  raise
