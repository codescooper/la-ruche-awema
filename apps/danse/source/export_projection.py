"""Operator-only exporter. No HTTP listener, actions, migrations or auth secrets."""
from __future__ import annotations
import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import sys
import tempfile
import time
from standup_feed import FeedError, SHA256, build_feed, digest, json_bytes, validate_mission_id

DATABASE = Path("/opt/awema-jury/finance/data/finance.sqlite")
ALLOWLIST_SCHEMA = "awema-agent-standup-allowlist-v1"
PROJECTION_SCHEMA = "awema-agent-standup-projection-v1"
MAX_PROJECTION_BYTES = 4 * 1024 * 1024

def _strict_object(pairs):
 value = {}
 for key,item in pairs:
  if key in value:raise FeedError("config_duplicate_key")
  value[key] = item
 return value

def _regular(path):
 path=Path(path)
 info=path.lstat()
 if not stat.S_ISREG(info.st_mode) or path.is_symlink():raise FeedError("regular_file_required")
 return info

def _private_parent(path,require_root):
 parent=Path(path)
 if parent.is_symlink() or not parent.is_dir():raise FeedError("output_directory_invalid")
 if require_root:
  for item in (parent,*parent.parents):
   info=item.lstat()
   if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or stat.S_IMODE(info.st_mode)&0o022:
    raise FeedError("parent_not_protected")

def load_allowlist(path,require_root=True):
 _private_parent(Path(path).parent,require_root)
 info=_regular(path)
 if info.st_size>4096:raise FeedError("config_too_large")
 if require_root and (info.st_uid!=0 or stat.S_IMODE(info.st_mode)&0o027):raise FeedError("config_not_protected")
 raw=Path(path).read_bytes()
 try:config=json.loads(raw.decode("utf-8"),object_pairs_hook=_strict_object)
 except (ValueError,UnicodeError) as exc:raise FeedError("config_invalid") from exc
 fields={"schema","mission_id","objective_sha256","objective_reviewed_no_sensitive_data"}
 if not isinstance(config,dict) or set(config)!=fields:raise FeedError("config_fields_invalid")
 if config["schema"]!=ALLOWLIST_SCHEMA:raise FeedError("config_schema_invalid")
 validate_mission_id(config["mission_id"])
 if not isinstance(config["objective_sha256"],str) or not SHA256.fullmatch(config["objective_sha256"]):raise FeedError("config_objective_pin_invalid")
 if config["objective_reviewed_no_sensitive_data"] is not True:raise FeedError("objective_privacy_review_required")
 return config,hashlib.sha256(raw).hexdigest()

MAX_SNAPSHOT_BYTES = 128 * 1024 * 1024
MAX_SNAPSHOT_SECONDS = 5
MAX_SNAPSHOT_ATTEMPTS = 3
SNAPSHOT_CHUNK = 1024 * 1024

class _SourceChanged(Exception):
 pass

def _snapshot_deadline(deadline):
 if time.monotonic() > deadline:raise FeedError("snapshot_time_budget_exceeded")

def _file_identity(info):
 return {"dev":info.st_dev,"ino":info.st_ino,"size":info.st_size,
         "mtime_ns":info.st_mtime_ns,"ctime_ns":info.st_ctime_ns}

def _source_files(database):
 database=Path(database)
 result={"base":_file_identity(_regular(database))}
 wal=Path(str(database)+"-wal")
 try:result["wal"]=_file_identity(_regular(wal))
 except FileNotFoundError:pass
 if sum(value["size"] for value in result.values())>MAX_SNAPSHOT_BYTES:
  raise FeedError("snapshot_size_budget_exceeded")
 return result

def _descriptor_matches(fd,path,expected):
 # Windows Python3.12 exposes different ctime semantics through fstat/lstat.
 # Full path identity, including ctime, is always checked. FD identity pins
 # the same inode and its byte/mtime generation, without that platform mismatch.
 actual=_file_identity(os.fstat(fd))
 return (all(actual[key]==expected[key] for key in ("dev","ino","size","mtime_ns"))
         and _file_identity(_regular(path))==expected)

def _read_source(path,expected,deadline,destination=None):
 """Opaque O_RDONLY copy/hash; no SQLite and no shm access on source."""
 flags=os.O_RDONLY|getattr(os,"O_NOFOLLOW",0)|getattr(os,"O_CLOEXEC",0)
 fd=os.open(path,flags)
 with os.fdopen(fd,"rb") as source:
  if not _descriptor_matches(source.fileno(),path,expected):raise _SourceChanged()
  h=hashlib.sha256();size=0;target=None
  try:
   if destination is not None:
    outfd=os.open(destination,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0),0o600)
    if hasattr(os,"fchmod"):os.fchmod(outfd,0o600)
    target=os.fdopen(outfd,"wb")
   while True:
    _snapshot_deadline(deadline)
    chunk=source.read(SNAPSHOT_CHUNK)
    if not chunk:break
    size+=len(chunk)
    if size>expected["size"] or size>MAX_SNAPSHOT_BYTES:raise _SourceChanged()
    h.update(chunk)
    if target is not None:target.write(chunk)
   _snapshot_deadline(deadline)
   if size!=expected["size"] or not _descriptor_matches(source.fileno(),path,expected):raise _SourceChanged()
   return h.hexdigest()
  finally:
   if target is not None:target.close()

@contextmanager
def stable_snapshot(database):
 """Copy one stable opaque base+WAL generation; never open source SQLite."""
 database=Path(database)
 deadline=time.monotonic()+MAX_SNAPSHOT_SECONDS
 for attempt in range(1,MAX_SNAPSHOT_ATTEMPTS+1):
  _snapshot_deadline(deadline)
  with tempfile.TemporaryDirectory(prefix="awema-standup-snapshot-") as folder:
   os.chmod(folder,0o700)
   folder=Path(folder)
   try:
    before=_source_files(database)
    paths={"base":database,"wal":Path(str(database)+"-wal")}
    initial={key:_read_source(paths[key],info,deadline) for key,info in before.items()}
    if _source_files(database)!=before:raise _SourceChanged()
    private_base=folder/"finance.sqlite"
    copies={"base":private_base,"wal":Path(str(private_base)+"-wal")}
    copied={key:_read_source(paths[key],info,deadline,copies[key]) for key,info in before.items()}
    if _source_files(database)!=before:raise _SourceChanged()
    final={key:_read_source(paths[key],info,deadline) for key,info in before.items()}
    if _source_files(database)!=before or copied!=initial or final!=initial:raise _SourceChanged()
    _snapshot_deadline(deadline)
   except (_SourceChanged,FileNotFoundError):
    _snapshot_deadline(deadline)
    if attempt==MAX_SNAPSHOT_ATTEMPTS:raise FeedError("snapshot_source_unstable") from None
    continue
   audit={"method":"stable_opaque_base_wal_copy","attempt":attempt,"source_files":before,
          "source_sha256":final,"shm_source_read":False,"sqlite_source_opened":False}
   # Consumer exceptions must propagate, not be caught as acquisition retries.
   yield private_base,audit
   return
 raise FeedError("snapshot_source_unstable")

def open_readonly(database):
 database=Path(database)
 _regular(database)
 # Open only the private stable snapshot; SQLite may create its own private sidecars.
 conn=sqlite3.connect(database.absolute().as_uri()+"?mode=ro",uri=True,timeout=1)
 conn.execute("PRAGMA query_only=ON")
 conn.execute("PRAGMA busy_timeout=1000")
 started=time.monotonic()
 conn.set_progress_handler(lambda:int(time.monotonic()-started>5),1000)
 return conn

def atomic_write(path,raw,group_gid=None,require_root=True):
 path=Path(path)
 if len(raw)>MAX_PROJECTION_BYTES:raise FeedError("projection_too_large")
 _private_parent(path.parent,require_root)
 if path.exists() or path.is_symlink():
  old=_regular(path)
  if require_root and (old.st_uid!=0 or stat.S_IMODE(old.st_mode)&0o027):raise FeedError("existing_projection_not_protected")
 fd,temp=tempfile.mkstemp(prefix=".projection-",suffix=".tmp",dir=path.parent)
 try:
  if hasattr(os,"fchmod"):os.fchmod(fd,0o640)
  if group_gid is not None:
   if type(group_gid) is not int or group_gid<0 or not hasattr(os,"fchown"):raise FeedError("projection_group_invalid")
   os.fchown(fd,-1,group_gid)
  with os.fdopen(fd,"wb") as stream:
   fd=None
   stream.write(raw);stream.flush();os.fsync(stream.fileno())
  os.replace(temp,path)
  if os.name=="posix":
   directory=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
   try:os.fsync(directory)
   finally:os.close(directory)
 except BaseException:
  if fd is not None:os.close(fd)
  try:os.unlink(temp)
  except FileNotFoundError:pass
  raise

def export_once(database,config_path,destination,group_gid=None,require_root=True):
 """Write ONE private envelope, atomically, only after every validation succeeds."""
 if require_root and (os.name!="posix" or os.geteuid()!=0):raise FeedError("operator_root_required")
 config,config_sha=load_allowlist(config_path,require_root)
 with stable_snapshot(database) as (snapshot,snapshot_audit):
  conn=open_readonly(snapshot)
  try:
   conn.execute("BEGIN")
   feed=build_feed(conn,config["mission_id"])
   if feed["provenance"]["objective_sha256"]!=config["objective_sha256"]:raise FeedError("objective_changed_since_review")
   row=conn.execute("SELECT user FROM mission_flows WHERE id=?",(config["mission_id"],)).fetchone()
   owner=row[0] if row else None
   if not isinstance(owner,str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}",owner):raise FeedError("mission_owner_id_invalid")
   conn.rollback()
  finally:conn.close()

 envelope={"schema":PROJECTION_SCHEMA,"feed":feed,"authorization":{"mission_owner_id":owner},
  "audit":{"allowlist_sha256":config_sha,"feed_sha256":digest(feed),"exporter_source_sha256":hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),"adapter_source_sha256":hashlib.sha256(Path(__file__).with_name("standup_feed.py").read_bytes()).hexdigest(),"read_only":True,"source_snapshot":snapshot_audit,"freeform_worker_text_included":False,"objective_privacy_review_required":True}}
 raw=json_bytes(envelope)
 atomic_write(destination,raw,group_gid,require_root)
 return {"schema":PROJECTION_SCHEMA,"mission_id":config["mission_id"],"observed_at":feed["observed_at"],"event_count":len(feed["events"]),"projection_file_sha256":hashlib.sha256(raw).hexdigest(),"bytes":len(raw)}

def watch_loop(export,interval):
 """Exit on the first failure; never re-date or replace the last good snapshot."""
 if not isinstance(interval,(int,float)) or isinstance(interval,bool) or not 1<=interval<=60:raise FeedError("watch_interval_invalid")
 deadline=time.monotonic()
 while True:
  export()
  deadline+=interval
  now=time.monotonic()
  if now>deadline:deadline=now
  time.sleep(max(0,deadline-now))

def safe_diagnostic(error):
 result={"class":type(error).__name__}
 if isinstance(error,FeedError):
  value=str(error)
  result["code"]=value if re.fullmatch(r"[a-z][a-z0-9_]{0,79}",value) else "feed_error"
 elif isinstance(error,sqlite3.Error):
  code=getattr(error,"sqlite_errorcode",None);name=getattr(error,"sqlite_errorname",None)
  if type(code) is int:result["sqlite_errorcode"]=code
  if isinstance(name,str) and re.fullmatch(r"SQLITE_[A-Z0-9_]{1,80}",name):result["sqlite_errorname"]=name
 elif isinstance(error,OSError):
  if type(error.errno) is int:result["errno"]=error.errno
 return result



def main(argv=None):
 parser=argparse.ArgumentParser(description="Private read-only single-test projection")
 parser.add_argument("--config")
 parser.add_argument("--format",choices=("single-v1","catalog-v2"),default="single-v1")
 parser.add_argument("--output",required=True)
 parser.add_argument("--group-gid",type=int)
 parser.add_argument("--watch",type=float,default=0)
 args=parser.parse_args(argv)
 try:
  if args.format=="catalog-v2":
   if args.config is not None:raise FeedError("catalog_allowlist_not_supported")
   from catalog_projection import export_catalog_once
   def perform():return export_catalog_once(DATABASE,args.output,args.group_gid)
  else:
   if not args.config:raise FeedError("config_required")
   def perform():return export_once(DATABASE,args.config,args.output,args.group_gid)
  if args.watch:watch_loop(perform,args.watch)
  else:
   result=perform()
   print(json.dumps(result,sort_keys=True))
  return 0
 except (FeedError,sqlite3.Error,OSError,ValueError) as error:
  print(json.dumps({"error":"standup_export_failed","diagnostic":safe_diagnostic(error)},sort_keys=True),file=sys.stderr)
  return 2

if __name__=="__main__":raise SystemExit(main())

