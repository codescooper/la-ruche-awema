#!/usr/bin/python3
import pathlib, sqlite3, tarfile, tempfile, subprocess, hashlib, datetime, os, fcntl
import sys
sys.path.insert(0,'/usr/local/lib/awema-backup-policy')
from backup_coverage import extra_paths,extra_database_roots,runtime_checkpoint,verify_checkpoint_members
os.umask(0o077)
base=pathlib.Path('/opt/awema-ai')
out=pathlib.Path('/opt/awema-ops/ai-backups');out.mkdir(mode=0o700,exist_ok=True)
lock=(out/'backup.lock').open('w');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
def file_sha256(path):
    digest=hashlib.sha256()
    with pathlib.Path(path).open('rb') as stream:
        for chunk in iter(lambda:stream.read(1024*1024),b''):digest.update(chunk)
    return digest.hexdigest()

def keep(member):
    parts=pathlib.PurePosixPath(member.name).parts
    if any(p in parts for p in ['node_modules','.git','.venv','venv','cache','.cache','logs','__pycache__','audio_cache','image_cache']):return None
    if member.issym() or member.islnk():return member
    if not member.isfile() and not member.isdir():return None
    if member.name.endswith(('.db','.db-wal','.db-shm','.sqlite','.sqlite-wal','.sqlite-shm','.lock','.pid')):return None
    return member
checkpoint=runtime_checkpoint()
with tempfile.TemporaryDirectory(prefix='ai-backup-',dir=out) as work:
    work=pathlib.Path(work);archive=work/'backup.tgz'
    with tarfile.open(archive,'w:gz') as tar:
        for part in ['core','registry','data','workspace','omh','compose.json','INSTALLATION.json','image.txt','backup-ai.py','restore-ai-check.py']:
            p=base/part
            if p.exists():tar.add(p,arcname='opt/awema-ai/'+part,filter=keep)
        for name in dict.fromkeys(['/usr/local/sbin/awema-ops-broker','/usr/local/sbin/awema-host-approve','/usr/local/lib/awema-broker','/etc/systemd/system/awema-ops-broker.service','/opt/awema-ops/broker','/opt/awema-ai/agentz-operator-backups','/usr/local/lib/awema-monitor','/etc/systemd/system/awema-ai-backup.timer','/etc/systemd/system/awema-ai-backup.service','/root/.ssh/authorized_keys','/etc/awema/v2','/etc/systemd/system/awema-audit-v2.service','/etc/systemd/system/awema-vault-v2.service','/usr/local/lib/awema-model-gateway','/usr/local/lib/awema-worker-launcher','/opt/awema-ops/model-gateway','/opt/awema-ops/worker-launcher','/opt/awema-ops/runtime-images/manifest.json','/etc/systemd/system/awema-model-gateway.service','/etc/systemd/system/awema-worker-launcher.service','/etc/systemd/system/awema-worker-network.service','/usr/local/sbin/awema-worker-authorize','/opt/awema-jury','/usr/local/lib/awema-activity-v2','/etc/systemd/system/awema-activity-v2.service','/opt/awema-ops/keys/offsite','/opt/awema-ops/keys/known_hosts','/etc/systemd/system/awema-worker-observer-v2.service','/usr/local/sbin/awema-worker-dispatch','/opt/awema-ops/readiness','/opt/awema-ops/status','/usr/local/lib/awema-backup-policy','/etc/systemd/system/awema-ai-backup.timer.d','/etc/systemd/system/awema-ai-backup.service.d']+extra_paths()):
            root_part=pathlib.Path(name)
            if root_part.exists():tar.add(root_part,arcname=name.lstrip('/'),filter=keep)
        for idx,db in enumerate([*(base/'data').rglob('*.db'),*(base/'core/data').rglob('*.db'),*pathlib.Path('/opt/awema-jury').rglob('*.db'),*pathlib.Path('/opt/awema-jury').rglob('*.sqlite'),*[p for folder in extra_database_roots() for pattern in ('*.db','*.sqlite') for p in pathlib.Path(folder).rglob(pattern)]]):
            if '.cache' in db.parts:continue
            target=work/f'{idx}.db'
            src=sqlite3.connect(f'file:{db}?mode=ro',uri=True);dst=sqlite3.connect(target)
            src.backup(dst)
            assert dst.execute('pragma integrity_check').fetchone()[0]=='ok'
            src.close();dst.close()
            original=db.stat()
            def preserve_db_owner(member):
                member.uid=original.st_uid;member.gid=original.st_gid;member.mode=original.st_mode&0o777;member.uname='';member.gname='';return member
            tar.add(target,arcname=str(db).lstrip('/'),filter=preserve_db_owner)
    verify_checkpoint_members(archive,checkpoint)
    if runtime_checkpoint()!=checkpoint:raise RuntimeError('backup_runtime_changed_during_snapshot')
    recipient=subprocess.check_output(['age-keygen','-y','/opt/awema-ops/keys/backup.agekey']).decode().strip()
    encrypted=out/f'awema-ai-{stamp}.tgz.age'
    subprocess.run(['age','-r',recipient,'-o',str(encrypted),str(archive)],check=True)
    proc=subprocess.Popen(['age','-d','-i','/opt/awema-ops/keys/backup.agekey',str(encrypted)],stdout=subprocess.PIPE)
    h=hashlib.sha256()
    for chunk in iter(lambda:proc.stdout.read(1024*1024),b''):h.update(chunk)
    assert proc.wait()==0 and h.hexdigest()==file_sha256(archive)
    checksum=pathlib.Path(str(encrypted)+'.sha256')
    checksum.write_text(file_sha256(encrypted)+'  '+encrypted.name+'\n')
    ssh='ssh -p 22222 -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=/opt/awema-ops/keys/known_hosts -i /opt/awema-ops/keys/offsite'
    subprocess.run(['rsync','-q','--checksum','-e',ssh,str(encrypted),str(checksum),'deploy@203.0.113.10:./'],check=True)
    (out/'last-success.txt').write_text(stamp+' encrypted, decryption verified, copied to KVM1\n')
    for old in []:
        old.unlink();pathlib.Path(str(old)+'.sha256').unlink(missing_ok=True)
    print('AI backup verified and copied to KVM1: '+stamp)
