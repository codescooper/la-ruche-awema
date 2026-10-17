"""Rebuild, do not forward, telemetry from untrusted JSON. No free-text enters model."""
import time,re,ipaddress
from collections import Counter
EVENTS={'cowrie.session.connect','cowrie.session.closed','cowrie.login.success','cowrie.login.failed','cowrie.login.publickey','cowrie.client.version','cowrie.client.kex','cowrie.command.input','cowrie.command.failed','cowrie.session.file_download','cowrie.session.file_upload','cowrie.direct-tcpip.request','cowrie.direct-tcpip.data','cowrie.log.open','cowrie.log.closed','cowrie.session.params','cowrie.client.size','cowrie.session.channel_open','cowrie.session.channel_closed'}
PATTERNS={'download','execution','reconnaissance','persistence','other'}
def ip(value):
 assert type(value) is str and len(value)<=45 and '%' not in value
 return str(ipaddress.ip_address(value))
def number(x):
 assert type(x) in (int,float) and 0<=x<=10**12;return x
def counts(x,allowed):
 assert type(x) is dict and set(x)<=allowed and len(x)<=50
 return {k:number(v) for k,v in x.items()}
def safe_source(name,data,now=None):
 now=time.time() if now is None else now
 try:
  assert type(data) is dict and data.get('schema')==1
  stamp=number(data['observed_at'])
  if not now-3600<=stamp<=now+300:return {'available':False,'reason':'source_stale'}
  if name=='fail2ban':
   if data.get('available') is not True:return {'available':False,'reason':'source_unavailable'}
   assert set(data)<= {'schema','server','source','observed_at','available','events','source_ips','window_seconds','tail_truncated','reason'}
   return {'available':True,'data':{'schema':1,'server':'kvm1','source':'fail2ban','observed_at':stamp,'events':counts(data['events'],{'found','ban','unban'}),'source_ips':[ip(v) for v in data.get('source_ips',[])[:50]],'window_seconds':86400,'tail_truncated':data.get('tail_truncated') is True}}
  assert name=='cowrie' and data.get('server')=='kvm1' and data.get('source')=='cowrie'
  assert set(data)<= {'schema','server','source','observed_at','window_seconds','accepted_events','invalid_or_unsupported','events','patterns','unique_source_ips','top_sources','limits','fail2ban','tail_truncated','source_bytes'}
  rows=[];assert type(data['top_sources']) is list and len(data['top_sources'])<=50
  for v in data['top_sources']:
   assert set(v)=={'ip','first','last','events','events_by_type','ssh_clients','command_patterns','payload_sha256','session_count'}
   clients=v['ssh_clients'];payload=v['payload_sha256'];assert type(clients) is list and len(clients)<=10 and all(type(s) is str and re.fullmatch(r'(openssh|libssh|paramiko|putty|dropbear|other):[0-9a-f]{20}',s) for s in clients)
   assert type(payload) is list and len(payload)<=10 and all(type(s) is str and re.fullmatch(r'[a-f0-9]{64}',s) for s in payload)
   first=number(v['first']);last=number(v['last']);assert now-90000<=first<=last<=now+300
   rows.append({'ip':ip(v['ip']),'first':first,'last':last,'events':number(v['events']),'session_count':number(v['session_count']),'events_by_type':counts(v['events_by_type'],EVENTS),'ssh_clients':clients,'command_patterns':counts(v['command_patterns'],PATTERNS),'payload_sha256':payload})
  return {'available':True,'data':{'schema':1,'server':'kvm1','source':'cowrie','observed_at':stamp,'window_seconds':86400,'accepted_events':number(data['accepted_events']),'invalid_or_unsupported':number(data['invalid_or_unsupported']),'events':counts(data['events'],EVENTS),'patterns':counts(data['patterns'],PATTERNS),'unique_source_ips':number(data['unique_source_ips']),'top_sources':rows,'tail_truncated':data.get('tail_truncated') is True,'source_bytes':number(data.get('source_bytes',0))}}
 except Exception:return {'available':False,'reason':'schema_rejected'}
