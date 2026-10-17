#!/usr/bin/python3
"""Restore encrypted AI archive into a temporary directory; never start its gateway."""
import pathlib,subprocess,tempfile,tarfile,sqlite3,json,datetime,hashlib,os
os.umask(0o077)
base=pathlib.Path('/opt/awema-ops/ai-backups')
archive=max(base.glob('awema-ai-*.tgz.age'),key=lambda p:p.name)
expected=pathlib.Path(str(archive)+'.sha256').read_text().split()[0]
assert hashlib.sha256(archive.read_bytes()).hexdigest()==expected
results=[]
with tempfile.TemporaryDirectory(prefix='restore-ai-',dir=base) as temp:
 temp=pathlib.Path(temp);tgz=temp/'restore.tgz'
 subprocess.run(['age','-d','-i','/opt/awema-ops/keys/backup.agekey','-o',str(tgz),str(archive)],check=True)
 with tarfile.open(tgz) as tar:
  names=set(tar.getnames())
  for part in ['compose.json','data/profiles/cto/auth.json','data/profiles/cto/.env','workspace/AGENTS.md']:
   assert 'opt/awema-ai/'+part in names,part
   results.append({'check':part,'ok':True})
  config=json.load(tar.extractfile('opt/awema-ai/compose.json'))
  assert isinstance(config['services'],dict)
  for idx,member in enumerate(tar.getmembers()):
   if not member.isfile() or not member.name.endswith('.db'):continue
   target=temp/f'{idx}.sqlite';target.write_bytes(tar.extractfile(member).read())
   with sqlite3.connect(target) as db:assert db.execute('pragma integrity_check').fetchone()[0]=='ok'
   results.append({'check':member.name,'ok':True})
assert any(r['check'].endswith('kanban.db') for r in results)
report={'timestamp':datetime.datetime.now(datetime.timezone.utc).isoformat(),'archive':archive.name,'ok':True,'checks':results,'scope':'Offline restore and SQLite integrity; no OAuth login or gateway launched'}
(base/'restore-results.json').write_text(json.dumps(report,indent=2))
print(json.dumps(report))
