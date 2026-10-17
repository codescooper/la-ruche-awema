#!/usr/bin/python3
import pathlib,subprocess,datetime,json,os,tarfile,hashlib,sqlite3,fcntl,shutil
os.umask(0o077)
base=pathlib.Path('/opt/awema-ops');lock=(base/'backup.lock').open('w');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
out=base/'backups'/stamp;out.mkdir(parents=True,mode=0o700)
def run(args,**kw):return subprocess.run(args,check=True,**kw)
dbs=[('afrocodeurs-production','awema-production-afro-db-1','afrocodeurs','afrocodeurs'),('cinelight','awema-supabase-restore-db','postgres','migrationtest'),('afrocodeurs','awema-afro-stage-db','afrocodeurs','afrocodeurs'),('coolify','coolify-db','coolify','coolify')]
manifest={'timestamp':stamp,'databases':[]}
try:
 with (out/'cinelight-cloud.dump').open('wb') as f:
  run(['docker','run','--rm','--env-file',str(base/'keys/supabase-cloud.env'),'postgres:17-alpine','pg_dump','-Fc'],stdout=f,timeout=600)
 run(['docker','run','--rm','-i','postgres:17-alpine','pg_restore','--list'],input=(out/'cinelight-cloud.dump').read_bytes(),stdout=subprocess.DEVNULL)
 manifest['cloud_backup']='Supabase Cinelight production'
 for key,container,user,db in dbs:
  with (out/(key+'.dump')).open('wb') as f:run(['docker','exec',container,'pg_dump','-U',user,'-d',db,'-Fc'],stdout=f)
  with (out/(key+'-roles.sql')).open('wb') as f:run(['docker','exec',container,'pg_dumpall','-U',user,'--roles-only','--no-role-passwords'],stdout=f)
  run(['docker','exec','-i',container,'pg_restore','--list'],input=(out/(key+'.dump')).read_bytes(),stdout=subprocess.DEVNULL)
  manifest['databases'].append({'name':key,'container':container,'database':db,'bytes':(out/(key+'.dump')).stat().st_size})
 src=sqlite3.connect('file:/opt/awema-migration/staging/other-sites-https/matos-data/matospro.db?mode=ro',uri=True)
 dst=sqlite3.connect(str(out/'matospro.db'));src.backup(dst);assert dst.execute('pragma integrity_check').fetchone()[0]=='ok';dst.close();src.close()
 with (out/'kvm1-production.tgz').open('wb') as f:
  run(['ssh','-p','22222','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile=/opt/awema-ops/keys/known_hosts','-i','/opt/awema-ops/keys/source-read','deploy@203.0.113.10'],stdout=f,timeout=600)
 with tarfile.open(out/'kvm1-production.tgz') as t:
  assert 'databases/matospro.db' in t.getnames() and 'databases/afrocodeurs.dump' in t.getnames()
 manifest['production_backup']='KVM1 PostgreSQL, SQLite, uploads, sources and configuration'
 prodsrc=sqlite3.connect('file:/opt/awema-migration/production-ready/matos-data/matospro.db?mode=ro',uri=True)
 proddst=sqlite3.connect(str(out/'matospro-production.db'));prodsrc.backup(proddst);assert proddst.execute('pragma integrity_check').fetchone()[0]=='ok';proddst.close();prodsrc.close()
 names=subprocess.check_output(['docker','ps','-aq']).decode().split()
 (out/'containers.json').write_bytes(subprocess.check_output(['docker','inspect',*names]))
 (out/'networks.json').write_bytes(subprocess.check_output(['docker','network','inspect',*subprocess.check_output(['docker','network','ls','-q']).decode().split()]))
 def filter_member(m):
  if any(x in m.name.split('/') for x in ['node_modules','.git','backups','__pycache__']):return None
  if m.name.endswith('.log'):return None
  return m
 with tarfile.open(out/'files.tgz','w:gz') as t:
  for root in ['/opt/awema-cl-producer', '/opt/awema-migration/staging','/opt/awema-migration/production-ready','/data/coolify/source','/data/coolify/proxy','/data/coolify/ssh','/data/coolify/services','/etc/ssh/sshd_config.d','/etc/ufw']:
   if pathlib.Path(root).exists():t.add(root,arcname=root.lstrip('/'),filter=filter_member)
  for p in base.glob('*.py'):t.add(p,arcname='opt/awema-ops/'+p.name)
  t.add(base/'keys',arcname='opt/awema-ops/keys')
  t.add(base/'status-nginx.conf',arcname='opt/awema-ops/status-nginx.conf')
  for p in pathlib.Path('/etc/systemd/system').glob('awema-*'):t.add(p,arcname='etc/systemd/system/'+p.name)
 volume=pathlib.Path(subprocess.check_output(['docker','volume','inspect','awema-supabase-storage-test','--format','{{.Mountpoint}}']).decode().strip())
 assert volume.is_dir() and volume.resolve().is_relative_to('/var/lib/docker/volumes')
 with tarfile.open(out/'cinelight-private-storage.tgz','w:gz') as t:t.add(volume,arcname='storage')
 manifest['private_storage']={'volume':'awema-supabase-storage-test','scope':'preproduction','archive':'cinelight-private-storage.tgz'}
 (out/'manifest.json').write_text(json.dumps(manifest,indent=2))
 (out/'SHA256SUMS').write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.name+'\n' for p in out.iterdir() if p.is_file()))
 archive=base/'backups'/('awema-'+stamp+'.tgz')
 with tarfile.open(archive,'w:gz') as t:t.add(out,arcname=stamp)
 recipient=subprocess.check_output(['age-keygen','-y',str(base/'keys/backup.agekey')]).decode().strip()
 encrypted=pathlib.Path(str(archive)+'.age')
 run(['age','-r',recipient,'-o',str(encrypted),str(archive)])
 # Verify authenticated decryption before transferring or removing plaintext bundle.
 verification=subprocess.Popen(['age','-d','-i',str(base/'keys/backup.agekey'),str(encrypted)],stdout=subprocess.PIPE)
 digest=hashlib.sha256()
 for chunk in iter(lambda:verification.stdout.read(1024*1024),b''):digest.update(chunk)
 assert verification.wait()==0 and digest.hexdigest()==hashlib.sha256(archive.read_bytes()).hexdigest()
 checksum=pathlib.Path(str(encrypted)+'.sha256');checksum.write_text(hashlib.sha256(encrypted.read_bytes()).hexdigest()+'  '+encrypted.name+'\n')
 ssh='ssh -p 22222 -o BatchMode=yes -o ConnectTimeout=20 -o StrictHostKeyChecking=yes -o UserKnownHostsFile=/opt/awema-ops/keys/known_hosts -i /opt/awema-ops/keys/offsite'
 run(['rsync','-av','--checksum','-e',ssh,str(encrypted),str(checksum),'deploy@203.0.113.10:./'])
 archive.unlink()
 manifest.update({'status':'success','offsite':'KVM1','encrypted_archive':str(encrypted),'encrypted_bytes':encrypted.stat().st_size})
 (base/'last-backup.json').write_text(json.dumps(manifest,indent=2))
 # Keep seven completed local generations; never delete unrelated directories.
 generations=sorted(p for p in (base/'backups').iterdir() if p.is_dir() and len(p.name)==16 and (p/'manifest.json').exists())
 for old in generations[:-7]:
  assert old.resolve().parent==(base/'backups').resolve()
  shutil.rmtree(old)
  for suffix in ['.tgz.age','.tgz.age.sha256']:
   p=base/'backups'/('awema-'+old.name+suffix)
   if p.exists():p.unlink()
 print(json.dumps(manifest))
except Exception as e:
 (base/'last-backup-error.txt').write_text(stamp+' '+str(e)+'\n');raise
