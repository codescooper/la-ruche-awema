"""Operator-only retention for encrypted internal AWEMA snapshots. Dry-run by default."""
import argparse,datetime,hashlib,json,os,re,shutil,socket,sys,time
from pathlib import Path
PATTERN=re.compile(r'awema-ai-(\d{8}T\d{6}Z)\.tgz\.age\Z')
PINNED_ARCHIVES=frozenset({'awema-ai-20261002T160409Z.tgz.age'})  # Last qualified cold-restore point; unpin only after new DR qualification.
PROFILES={'source':{'recent':8,'days':3,'maximum':12},'kvm1':{'recent':8,'days':3,'maximum':12},'pc':{'recent':8,'days':7,'maximum':16}}
CANONICAL={'source':'/opt/awema-ops/ai-backups','kvm1':'/home/deploy/awema-offsite','pc':r'E:\AWEMA\backups\internal'}
MIN_FREE_BYTES=8*1024**3
class PolicyRefused(ValueError):pass

def expected_uid():return os.geteuid() if hasattr(os,'geteuid') else None

def require_owner(path):
 uid=expected_uid()
 if uid is not None and Path(path).stat().st_uid!=uid:raise PolicyRefused('foreign_archive_owner')

def sha256(path):
 h=hashlib.sha256()
 with Path(path).open('rb') as stream:
  for chunk in iter(lambda:stream.read(1024*1024),b''):h.update(chunk)
 return h.hexdigest()

def expected_checksum(folder,name):
 p=Path(folder)/(name+'.sha256')
 if p.is_symlink() or not p.is_file() or not 66<=p.stat().st_size<=512:raise PolicyRefused('checksum_missing_or_invalid')
 require_owner(p);parts=p.read_text(encoding='ascii').strip().split()
 if len(parts)!=2 or not re.fullmatch('[a-f0-9]{64}',parts[0]) or parts[1].lstrip('*')!=name:raise PolicyRefused('checksum_identity_mismatch')
 return parts[0]

def inventory(folder):
 folder=Path(folder)
 if not folder.is_dir() or any(p.is_symlink() for p in (folder,*folder.parents)):raise PolicyRefused('archive_directory_boundary')
 require_owner(folder)
 result=[]
 for p in folder.iterdir():
  match=PATTERN.fullmatch(p.name)
  if not match:continue
  if p.is_symlink() or not p.is_file() or p.resolve().parent!=folder.resolve():raise PolicyRefused('archive_boundary')
  require_owner(p)
  created=datetime.datetime.strptime(match[1],'%Y%m%dT%H%M%SZ').replace(tzinfo=datetime.timezone.utc).timestamp()
  size=p.stat().st_size
  if size<=0:continue
  result.append({'name':p.name,'created':created,'bytes':size})
 return sorted(result,key=lambda value:(value['created'],value['name']),reverse=True)

def selection(entries,profile):
 cfg=PROFILES[profile]
 if not entries:return {'keep':[],'remove':[]}
 keep={value['name'] for value in entries[:cfg['recent']]};keep.update(value['name'] for value in entries if value['name'] in PINNED_ARCHIVES);days=set()
 for value in entries:
  day=datetime.datetime.fromtimestamp(value['created'],datetime.timezone.utc).date().isoformat()
  if day not in days and len(days)<cfg['days']:days.add(day);keep.add(value['name'])
 if len(keep)>cfg['maximum']:raise PolicyRefused('retention_count_bound')
 return {'keep':[value['name'] for value in entries if value['name'] in keep],'remove':[value['name'] for value in entries if value['name'] not in keep]}

def verified_plan(folder,profile,receipt=None,now=None):
 folder=Path(folder);now=time.time() if now is None else now;entries=inventory(folder)
 if not entries:raise PolicyRefused('no_complete_archive')
 current=entries[0]
 if not -60<=now-current['created']<=4*3600:raise PolicyRefused('newest_archive_outside_rpo4h')
 expected=expected_checksum(folder,current['name']);actual=sha256(folder/current['name'])
 if actual!=expected:raise PolicyRefused('local_archive_checksum_mismatch')
 if profile in ('source','pc'):
  if not isinstance(receipt,dict) or receipt.get('archive')!=current['name'] or receipt.get('bytes')!=current['bytes'] or receipt.get('sha256')!=actual:raise PolicyRefused('replication_receipt_mismatch')
  replicas=receipt.get('replicas',{})
  required=('source','kvm1') if profile=='pc' else ('source',)
  if any(not isinstance(replicas.get(host),dict) or replicas[host].get('verified') is not True or replicas[host].get('sha256')!=actual or replicas[host].get('bytes')!=current['bytes'] for host in required):raise PolicyRefused('verified_copy_required')
  if profile=='source':
   transfer=receipt.get('replication',{})
   if receipt.get('source_decryption_verified_by_backup_job') is not True or transfer.get('method')!='rsync --checksum' or transfer.get('completed') is not True or transfer.get('returncode')!=0 or transfer.get('destination')!='kvm1':raise PolicyRefused('successful_checksum_transfer_required')
 # On KVM1, the checksum is transported with the archive by the authenticated
 # source job. Recomputing it locally proves the destination bytes; merely
 # trusting the transferred sidecar is deliberately insufficient.
 choices=selection(entries,profile);remove=set(choices['remove']);reclaimed=sum(value['bytes'] for value in entries if value['name'] in remove);free=shutil.disk_usage(folder).free
 return {'schema':'awema-internal-retention-v1','profile':profile,'archive':current['name'],'bytes':current['bytes'],'sha256':actual,'keep':choices['keep'],'remove':choices['remove'],'reclaim_bytes':reclaimed,'free_bytes':free,'projected_free_bytes':free+reclaimed,'space_margin_met':free+reclaimed>=MIN_FREE_BYTES,'copy_evidence':('source_sidecar_and_recomputed_destination_sha256' if profile=='kvm1' else 'source_decryption_and_successful_rsync_checksum_transfer' if profile=='source' else 'source_and_kvm1_recomputed_sha256'),'destination_sha256_verified':profile in ('kvm1','pc'),'applied':False}

def apply(folder,plan):
 folder=Path(folder);expected_root=Path(CANONICAL[plan['profile']])
 if any(p.is_symlink() for p in (folder,*folder.parents)) or folder.resolve()!=expected_root.resolve():raise PolicyRefused('apply_directory_not_canonical')
 require_owner(folder)
 current=folder/plan['archive']
 require_owner(current)
 if current.is_symlink() or not current.is_file() or current.stat().st_size!=plan['bytes'] or sha256(current)!=plan['sha256']:raise PolicyRefused('current_copy_changed_before_purge')
 if len(plan['keep'])<1 or plan['archive'] not in plan['keep'] or plan['archive'] in plan['remove']:raise PolicyRefused('newest_copy_must_remain')
 # Preflight every owned candidate before the first irreversible unlink.
 candidates=[]
 for name in plan['remove']:
  if not PATTERN.fullmatch(name) or name in plan['keep'] or name in PINNED_ARCHIVES:raise PolicyRefused('purge_scope_denied')
  p=folder/name;checksum=folder/(name+'.sha256')
  if p.is_symlink() or not p.is_file() or p.resolve().parent!=folder.resolve():raise PolicyRefused('purge_boundary')
  require_owner(p)
  if checksum.exists():
   if checksum.is_symlink() or not checksum.is_file():raise PolicyRefused('purge_checksum_boundary')
   require_owner(checksum)
  candidates.append((name,p,checksum))
 removed=[]
 for name,p,checksum in candidates:
  p.unlink()
  if checksum.is_file():checksum.unlink()
  removed.append(name)
 return dict(plan,applied=True,removed=removed)

def main():
 parser=argparse.ArgumentParser();parser.add_argument('--directory',required=True);parser.add_argument('--profile',required=True,choices=sorted(PROFILES));parser.add_argument('--receipt');parser.add_argument('--apply',action='store_true');args=parser.parse_args();receipt=json.loads(Path(args.receipt).read_text()) if args.receipt else None
 try:
  plan=verified_plan(args.directory,args.profile,receipt);result=apply(args.directory,plan) if args.apply else plan;print(json.dumps(result,sort_keys=True));return 0 if result['space_margin_met'] else 2
 except (PolicyRefused,OSError,ValueError) as error:print(json.dumps({'applied':False,'error':str(error) if isinstance(error,PolicyRefused) else type(error).__name__}));return 1
if __name__=='__main__':raise SystemExit(main())
