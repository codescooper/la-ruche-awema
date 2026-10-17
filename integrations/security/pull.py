"""Root collector. Existing pinned host key; dedicated forced-export identity; no agent credentials."""
import os,json,time,subprocess,sqlite3,hashlib,secrets
from pathlib import Path
from telemetry_safe import safe_source
R=Path('/opt/awema-ops/security-telemetry');P=Path('/opt/awema-jury/finance/source/roles/security-telemetry.json')
def atomic(path,data):
 raw=json.dumps(data,separators=(',',':')).encode();assert len(raw)<=60000
 tmp=path.with_name(path.name+'.'+secrets.token_hex(8)+'.tmp');fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
 os.replace(tmp,path)
def history(c,data,now):
 c.executescript('CREATE TABLE IF NOT EXISTS snapshots(hash TEXT PRIMARY KEY,observed REAL);CREATE TABLE IF NOT EXISTS observations(hash TEXT,ip TEXT,first REAL,last REAL,observed REAL,PRIMARY KEY(hash,ip));')
 with c:
  c.execute('delete from snapshots where observed<?',(now-30*86400,));c.execute('delete from observations where observed<?',(now-30*86400,))
  if data is not None:
   stable={k:v for k,v in data.items() if k!='observed_at'};key=hashlib.sha256(json.dumps(stable,sort_keys=True).encode()).hexdigest()
   if c.execute('insert or ignore into snapshots values(?,?)',(key,now)).rowcount:
    for v in data['top_sources']:c.execute('insert into observations values(?,?,?,?,?)',(key,v['ip'],v['first'],v['last'],now))
 return [{'ip':r[0],'first':r[1],'last':r[2],'distinct_observation_windows':r[3]} for r in c.execute('select ip,min(first),max(last),count(*) from observations where observed>=? group by ip order by count(*) desc,max(last) desc limit 20',(now-30*86400,))]
def main():
 assert os.geteuid()==0;os.umask(0o077);now=time.time()
 sources={}
 try:
  p=subprocess.run(['ssh','-F','/dev/null','-p','22222','-o','BatchMode=yes','-o','IdentitiesOnly=yes','-o','IdentityAgent=none','-o','ConnectTimeout=10','-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile=/opt/awema-ops/keys/known_hosts','-i',str(R/'id_ed25519'),'deploy@203.0.113.10','snapshot'],capture_output=True,timeout=30)
  assert p.returncode==0 and len(p.stdout)<=262144
  raw=json.loads(p.stdout);assert raw['schema']==1
  for name in ('cowrie','fail2ban'):
   source=raw['sources'].get(name,{})
   sources[name]=safe_source(name,source['data'],now) if source.get('available') is True else {'available':False,'reason':'source_unavailable'}
 except Exception:sources={n:{'available':False,'reason':'transport_unavailable'} for n in ('cowrie','fail2ban')}
 sources['kvm4']={'available':False,'reason':'cowrie_and_fail2ban_not_installed'}
 c=sqlite3.connect(R/'history.sqlite');cowrie=sources['cowrie'];recurring=history(c,cowrie.get('data') if cowrie['available'] else None,now)
 c.close()
 result={'schema':1,'observed_at':now,'sources':sources,'history_30_days':recurring,'history_counts_are_overlapping_windows_not_attack_totals':True,'attribution':'IP sources only; human identity unknown','cowrie_login_success_means_honeypot_login_not_production_compromise':True,'read_only':True}
 atomic(P,result);atomic(R/'latest.json',result)
 print(json.dumps({'published':True,'cowrie_available':cowrie['available'],'fail2ban_available':sources['fail2ban']['available'],'source_ips':cowrie.get('data',{}).get('unique_source_ips',0),'retention_days':30}))
if __name__=='__main__':main()
