"""Private, deterministic, read-only AWEMA viewer for an upstream Agent Standup UI."""
import argparse, base64, hashlib, http.client, http.server, json, math, os, re, socket, socketserver, stat, time
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
BASE='/finance/standup'
ROOT=Path('/app')
UI=Path('/ui')
PROJECTION=Path('/projection/projection.json')
AUTH_SOCKET='/auth/finance.sock'
TTL=10
PIN='d674b9a46b8c2c132f5f1927db06b2fd25663f15'

class Denied(Exception):
 def __init__(self,code,reason):self.code,self.reason=code,reason
def need(ok,code=503,reason='prototype_unavailable'):
 if not ok:raise Denied(code,reason)
class UnixHTTP(http.client.HTTPConnection):
 def connect(self):
  self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.sock.settimeout(5);self.sock.connect(AUTH_SOCKET)
def authenticate(cookie):
 need(isinstance(cookie,str) and 0<len(cookie)<=8192,401,'authentication_required')
 need('\r' not in cookie and '\n' not in cookie,400,'invalid_cookie')
 c=UnixHTTP('localhost',timeout=5)
 try:
  # One fixed read-only path; neither caller URL nor HTTP method is forwarded.
  c.request('GET','/finance/api/session',headers={'Cookie':cookie,'Host':'laruche.awema.cloud','Connection':'close'})
  r=c.getresponse();raw=r.read(32769)
  need(r.status==200,401 if r.status in (401,403) else 503,'authentication_required' if r.status in (401,403) else 'authentication_unavailable')
  need(len(raw)<=32768)
  data=json.loads(raw)
  need(data.get('role') in ('owner','director'),403,'director_required')
  need(isinstance(data.get('user'),str) and 0<len(data['user'])<=128,503,'authentication_invalid')
  # Discard csrf, name and every other response field.
  return {'user':data.get('user'),'role':data['role']}
 finally:c.close()
def read_projection(user):
 need(PROJECTION.is_file() and not PROJECTION.is_symlink())
 info=PROJECTION.stat()
 need(info.st_size<=8*1024*1024 and -3<=time.time()-info.st_mtime<=TTL,503,'projection_stale')
 p=json.loads(PROJECTION.read_bytes())
 need(p.get('schema')=='awema-agent-standup-projection-v1')
 f=p.get('feed',{});observed=f.get('observed_at')
 need(type(observed) in (int,float) and math.isfinite(observed) and -3<=time.time()-observed<=TTL,503,'projection_stale')
 owner=p.get('authorization',{}).get('mission_owner_id')
 need(isinstance(owner,str) and 0<len(owner)<=128,503,'projection_authorization_invalid')
 need(user['role']=='owner' or owner==user['user'],403,'mission_denied')
 need(f.get('schema')=='awema-agent-standup-feed-v1')
 return f
def roleid(role):return 'main' if role=='cto' else role
def timeline(feed):
 ev=[];roles=[a['id'] for a in feed['agents']]
 agents=[{'id':roleid(a['id']),'name':a['name'],'role':a['name'],'roleFr':a['name'],'type':'main' if a['id']=='cto' else 'general-purpose'} for a in feed['agents']]
 agents.append({'id':'journal','name':'Journal système','role':'Jalons automatiques — pas un agent IA','roleFr':'Jalons automatiques — pas un agent IA','type':'system'})
 for x in feed['events']:
  ts=int(x['created']*1000);agent=roleid(x['agent']) if x['agent'] in roles else 'journal';kind=x['kind']
  e={'k':'awema:'+str(x['id']),'source_event_id':x['id'],'ts':ts,'agent':agent,'kind':'say','text':x['summary'],'fr':x['summary']}
  if kind.endswith('_handoff_received') and x['agent'] in roles:
   e.update(agent='journal',to=agent,kind='order',title='Réception enregistrée — émetteur non journalisé')
  elif kind.endswith('_dispatching') and agent!='main':
   e.update(agent='journal',to=agent,kind='order',title='Affectation enregistrée par l’orchestrateur')
  elif kind.endswith('_completed'):
   e.update(kind='report',to='journal')
  elif kind=='plan_created':e.update(agent='journal',kind='say')
  ev.append(e)
 need(any(a['id']=='main' for a in agents),503,'coordinator_not_observed')
 first=ev[0]['ts'] if ev else int(feed['observed_at']*1000)
 for e in ev:e['t']=max(0,e['ts']-first)
 mid=feed['mission']['id'];seq=max([e['source_event_id'] for e in ev],default=0)
 return {'id':mid,'proj':'awema','agents':agents,'events':ev,'durationMs':max([e['t'] for e in ev],default=0),'ep':'awema-'+mid,'seq':seq,'marks':{},'provenance':feed.get('provenance',{})}
def inline_hashes(raw):
 text=raw.decode().replace('\r\n','\n').replace('\r','\n')
 return ' '.join("'sha256-"+base64.b64encode(hashlib.sha256(s.encode()).digest()).decode()+"'" for s in re.findall(r'<script(?:\s[^>]*)?>(.*?)</script>',text,re.S) if s.strip())
def board(feed):
 state=feed['mission']['state'];view='working' if state in ('queued','running') else 'blocked' if state=='blocked' else 'turn'
 return [{'proj':'awema','id':feed['mission']['id'],'title':feed['mission']['objective'],'mtime':int(feed['observed_at']*1000),'asked':int(feed['events'][0]['created']*1000) if feed['events'] else 0,'state':view,'tool':'','ageMs':0,'subActive':sum(a['state']=='dispatching' for a in feed['agents']),'subTotal':len(feed['agents'])}]

class Handler(http.server.BaseHTTPRequestHandler):
 def log_message(self,*args):pass
 def setup(self):super().setup();self.connection.settimeout(10)
 def send(self,status,raw,mime='application/json; charset=utf-8'):
  if not isinstance(raw,bytes):raw=json.dumps(raw,ensure_ascii=False).encode()
  self.send_response(status)
  csp="default-src 'none'; script-src 'self' "+(inline_hashes(raw) if mime.startswith('text/html') else '')+"; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data: blob:; media-src 'self' blob:; font-src 'self' data:; frame-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'self'"
  for k,v in {'Content-Type':mime,'Content-Length':str(len(raw)),'Cache-Control':'private, no-store','Vary':'Cookie','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer','Permissions-Policy':'camera=(), microphone=(), geolocation=()','Content-Security-Policy':csp}.items():self.send_header(k,v)
  self.end_headers()
  if self.command!='HEAD':self.wfile.write(raw)
 def do_GET(self):self.handle_get()
 def do_HEAD(self):self.handle_get()
 def readonly(self):self.send(405,{'error':'read_only_prototype'})
 do_POST=readonly;do_PUT=readonly;do_PATCH=readonly;do_DELETE=readonly;do_OPTIONS=readonly
 def handle_get(self):
  try:
   need(self.headers.get('Sec-Fetch-Site')!='cross-site',403,'origin_denied')
   user=authenticate(self.headers.get('Cookie',''));feed=read_projection(user)
   u=urlsplit(self.path);path=u.path
   need(path.startswith(BASE+'/'),404,'route_missing')
   route=path[len(BASE):]
   query=parse_qs(u.query,keep_blank_values=True)
   if route=='/api/feed':
    need(set(query)<= {'after'} and all(len(v)==1 for v in query.values()),400,'invalid_cursor')
    after=query.get('after',['0'])[0];need(re.fullmatch(r'0|[1-9][0-9]{0,17}',after),400,'invalid_cursor');after=int(after)
    f=dict(feed);f['events']=[e for e in feed['events'] if e['id']>after]
    f['cursor']={'after':after,'next':max((e['id'] for e in f['events']),default=after)}
    provenance=dict(feed.get('provenance',{}))
    provenance['full_projection_sha256']=provenance.pop('projection_sha256',None)
    provenance['full_events_sha256']=provenance.get('events_sha256')
    provenance['events_sha256']=hashlib.sha256(json.dumps(f['events'],sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()).hexdigest()
    provenance['returned_event_count']=len(f['events']);f['provenance']=provenance
    provenance['projection_sha256']=hashlib.sha256(json.dumps(f,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()).hexdigest()
    return self.send(200,f)
   if route=='/api/current':
    return self.send(200,{'proj':'awema','id':feed['mission']['id'],'mtime':int(feed['observed_at']*1000),'asked':int(feed['events'][0]['created']*1000) if feed['events'] else 0})
   if route=='/api/session':
    need(set(query)<={'proj','id','after','ep'} and all(len(v)==1 for v in query.values()),400,'invalid_request')
    need(query.get('proj',['awema'])==['awema'] and query.get('id',[feed['mission']['id']])==[feed['mission']['id']],404,'mission_missing')
    tl=timeline(feed);after=query.get('after',[None])[0];ep=query.get('ep',[None])[0]
    if after is None:return self.send(200,tl)
    need(re.fullmatch(r'0|[1-9][0-9]{0,17}',after),400,'invalid_cursor')
    if ep is not None and ep!=tl['ep']:return self.send(200,{'resync':True})
    events=[e for e in tl['events'] if e['source_event_id']>int(after)] if ep is not None else tl['events'][int(after):]
    return self.send(200,{**{k:tl[k] for k in ('id','agents','ep','seq','marks')},'events':events,'total':len(tl['events'])})
   if route=='/api/board':return self.send(200,board(feed))
   if route=='/api/sessions':return self.send(200,board(feed))
   if route=='/api/projects':return self.send(200,[])
   if route=='/api/characters':return self.send(200,{'chars':[],'dir':''})
   if route=='/api/packs':return self.send(200,[])
   if route=='/api/voices':return self.send(200,{'available':False,'voices':[]})
   if route=='/api/health':return self.send(200,{'claude':None,'apiKey':False,'trError':'disabled_read_only_prototype','prototype':True})
   if route=='/api/prefs.js':return self.send(200,b'window.SAVED_PREFS = {};','text/javascript; charset=utf-8')
   if route=='/api/kokoro':return self.send(200,{'installed':False,'ready':False})
   if route=='/api/audio-owner':return self.send(200,{'owner':None})
   files={'/':'index.html','/index.html':'index.html','/standup.css':'standup.css','/standup.js':'standup.js','/config.js':'config.js','/LICENSE':'LICENSE','/reunion/':'reunion.html','/reunion/index.html':'reunion.html'}
   need(route in files,404,'route_missing')
   file=UI/files[route];need(file.is_file() and not file.is_symlink(),404,'asset_missing')
   mime='text/html; charset=utf-8' if file.suffix=='.html' else 'text/css; charset=utf-8' if file.suffix=='.css' else 'text/javascript; charset=utf-8' if file.suffix=='.js' else 'text/plain; charset=utf-8'
   return self.send(200,file.read_bytes(),mime)
  except Denied as e:self.send(e.code,{'error':e.reason})
  except (ValueError,TypeError,KeyError):self.send(503,{'error':'projection_invalid'})
  except Exception:self.send(503,{'error':'prototype_temporarily_unavailable'})

class Server(socketserver.ThreadingMixIn,socketserver.UnixStreamServer):
 daemon_threads=True;allow_reuse_address=False
def main():
 os.umask(0o007);path=Path('/socket/standup.sock')
 if path.exists():
  s=path.lstat();need(stat.S_ISSOCK(s.st_mode) and s.st_uid==os.geteuid(),503,'unsafe_socket')
  with socket.socket(socket.AF_UNIX) as probe:
   try:probe.connect(str(path))
   except ConnectionRefusedError:path.unlink()
   else:raise RuntimeError('socket_already_active')
 with Server(str(path),Handler) as server:
  path.chmod(0o660);server.serve_forever()
if __name__=='__main__':main()
