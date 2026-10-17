"""Authenticated read-only catalog adapter for the pinned Agent Standup UI.

The private cache has no auth material. ACL is applied in SQL before counting,
paging, titles and artifacts; no source database is mounted in this process.
"""
import contextlib, hashlib, json, math, os, re, socket, sqlite3, stat, time
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit
import viewer as legacy
BASE=legacy.BASE
UI=legacy.UI
CACHE=Path('/projection/projection.sqlite')
SCHEMA='awema-agent-standup-catalog-v2'
TTL=10
MID=re.compile(r'f_[a-f0-9]{24}\Z')
NAME=re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z')
need=legacy.need
Denied=legacy.Denied

def digest(value):
 return hashlib.sha256(json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()

def number(q,key,default,maximum):
 s=q.get(key,[str(default)])[0]
 need(bool(re.fullmatch(r'0|[1-9][0-9]{0,18}',s)),400,'invalid_cursor')
 n=int(s);need(n<=maximum,400,'invalid_cursor');return n

def params(q,allowed):
 need(set(q)<=set(allowed) and all(len(v)==1 for v in q.values()),400,'invalid_request')

def selected(q):
 mid=q.get('mission',q.get('id',[None]))[0]
 if mid is not None:need(bool(MID.fullmatch(mid)),400,'invalid_mission')
 if 'id' in q and 'mission' in q:need(q['id']==q['mission'],400,'mission_conflict')
 need(q.get('proj',['awema'])==['awema'],400,'invalid_project')
 return mid

class Catalog:
 def __init__(self,user,path=None):self.user=user;self.path=Path(path or CACHE);self.conn=None
 def __enter__(self):
  info=self.path.lstat();need(stat.S_ISREG(info.st_mode) and not self.path.is_symlink())
  need(0<info.st_size<=128*1024*1024 and -3<=time.time()-info.st_mtime<=TTL,503,'projection_stale')
  if os.name=='posix':need(info.st_uid==0 and info.st_gid==10001 and stat.S_IMODE(info.st_mode)==0o640,503,'projection_permissions_invalid')
  self.conn=sqlite3.connect(self.path.resolve().as_uri()+'?mode=ro',uri=True,timeout=.25)
  try:
   self.conn.row_factory=sqlite3.Row
   self.conn.execute('PRAGMA query_only=ON');self.conn.execute('PRAGMA trusted_schema=OFF')
   start=time.monotonic();self.conn.set_progress_handler(lambda:int(time.monotonic()-start>3),1000)
   self.conn.execute('BEGIN')
   meta=self.conn.execute('SELECT schema,observed_at FROM meta WHERE id=1').fetchone()
   need(meta and meta['schema']==SCHEMA)
   self.observed=meta['observed_at'];need(type(self.observed) in (int,float) and math.isfinite(self.observed) and -3<=time.time()-self.observed<=TTL,503,'projection_stale')
   need(self.user.get('role') in ('owner','director'),403,'director_required')
   self.acl='1' if self.user['role']=='owner' else 'owner_id=?'
   self.args=() if self.user['role']=='owner' else (self.user['user'],)
   return self
  except BaseException:self.conn.close();self.conn=None;raise
 def __exit__(self,*args):
  if self.conn:self.conn.rollback();self.conn.close()
 def mission(self,mid=None):
  clause=' AND id=?' if mid else ''
  args=self.args+((mid,) if mid else ())
  row=self.conn.execute('SELECT id,objective_sanitized,state,created,updated,event_count,artifact_count FROM missions WHERE '+self.acl+clause+' ORDER BY (state IN (\'queued\',\'running\')) DESC,updated DESC,id LIMIT 1',args).fetchone()
  need(row is not None,404,'mission_missing');return row
 def counts(self,mid):
  visible=self.conn.execute("SELECT count(*) FROM artifactsources WHERE mission_id=? AND reason!='sensitive_filename'",(mid,)).fetchone()[0]
  withheld=self.conn.execute("SELECT count(*) FROM artifactsources WHERE mission_id=? AND reason='sensitive_filename'",(mid,)).fetchone()[0]
  return visible,withheld
 def catalog(self,after,limit):
  # This is a lexicographic ID cursor, independent of changing mission states.
  where=self.acl+(' AND id>?' if after else '')
  args=self.args+((after,) if after else ())
  rows=self.conn.execute('SELECT id,objective_sanitized,state,updated,event_count FROM missions WHERE '+where+' ORDER BY id LIMIT ?',args+(limit+1,)).fetchall()
  total=self.conn.execute('SELECT count(*) FROM missions WHERE '+self.acl,self.args).fetchone()[0]
  more=len(rows)>limit;items=[]
  for row in rows[:limit]:
   item=dict(row);item['title']=item.pop('objective_sanitized');item['artifact_count'],item['withheld_artifacts']=self.counts(row['id']);items.append(item)
  return {'missions':items,'next':items[-1]['id'] if more and items else None,'has_more':more,'total_authorized':total}
 def artifacts(self,row,after=0,limit=200):
  mid=row['id'];total,withheld=self.counts(mid)
  rows=self.conn.execute("SELECT ordinal,name,role,source_sha256 FROM artifactsources WHERE mission_id=? AND reason!='sensitive_filename' ORDER BY ordinal,name LIMIT ? OFFSET ?",(mid,limit,after)).fetchall()
  items=[{'ordinal':r['ordinal'],'name':r['name'],'role':r['role'],'sha256':r['source_sha256'],'url':'/finance/mission-preview?'+urlencode({'mission':mid,'ordinal':r['ordinal'],'name':r['name']})} for r in rows]
  nxt=after+len(items);return {'mission_id':mid,'artifacts':items,'after':after,'next':nxt,'has_more':nxt<total,'total':total,'withheld_artifacts':withheld}
 def feed(self,row,after=0,limit=500):
  raw=self.conn.execute('SELECT content,sha256 FROM feeds WHERE mission_id=?',(row['id'],)).fetchone();need(raw is not None)
  need(hashlib.sha256(raw['content'].encode()).hexdigest()==raw['sha256'])
  feed=json.loads(raw['content']);need(feed.get('mission',{}).get('id')==row['id'] and feed.get('schema')=='awema-agent-standup-feed-v1')
  events=[dict(r) for r in self.conn.execute('SELECT id,agent,kind,summary,created,source_event_sha256 FROM events WHERE mission_id=? AND id>? ORDER BY id LIMIT ?',(row['id'],after,limit+1))]
  more=len(events)>limit;events=events[:limit];ap=self.artifacts(row)
  feed.update(events=events,artifacts=ap['artifacts'],observed_at=self.observed,cursor={'after':after,'next':events[-1]['id'] if events else after,'has_more':more,'total':row['event_count']},artifact_cursor={k:ap[k] for k in ('after','next','has_more','total')})
  p=feed['provenance'];p.pop('projection_sha256',None);p['withheld_artifacts']=ap['withheld_artifacts'];p['events_sha256']=digest(events);p['returned_event_count']=len(events)
  p['projection_sha256']=digest(feed)
  return feed
 def timeline(self,row,after=0,limit=500):
  feed=self.feed(row,after,limit);roles={a['id'] for a in feed['agents']}
  agents=[{'id':legacy.roleid(a['id']),'name':a['name'],'role':a['name'],'roleFr':a['name'],'type':'main' if a['id']=='cto' else 'general-purpose','awema_state':a.get('state','unknown')} for a in feed['agents']]
  agents.append({'id':'journal','name':'Journal système','role':'Jalons automatiques — pas un agent IA','roleFr':'Jalons automatiques — pas un agent IA','type':'system'})
  times=self.conn.execute('SELECT min(created),max(created),max(id) FROM events WHERE mission_id=?',(row['id'],)).fetchone()
  first=int((times[0] if times[0] is not None else row['created'])*1000);last=int((times[1] if times[1] is not None else row['created'])*1000)
  events=[]
  for x in feed['events']:
   agent=legacy.roleid(x['agent']) if x['agent'] in roles else 'journal';kind=x['kind'];ts=int(x['created']*1000)
   e={'k':'awema:'+str(x['id']),'source_event_id':x['id'],'ts':ts,'t':max(0,ts-first),'agent':agent,'kind':'say','text':x['summary'],'fr':x['summary'],'awema_kind':kind,'awema_role':agent}
   if kind.endswith('_handoff_received') and x['agent'] in roles:e.update(agent='journal',to=agent,kind='order',title='Réception enregistrée — émetteur non journalisé')
   elif kind.endswith('_dispatching') and agent!='main':e.update(agent='journal',to=agent,kind='order',title='Affectation enregistrée par l’orchestrateur')
   elif kind.endswith('_completed'):e.update(kind='report',to='journal')
   elif kind=='plan_created':e.update(agent='journal')
   events.append(e)
  return {'id':row['id'],'proj':'awema','agents':agents,'events':events,'durationMs':max(0,last-first),'ep':'awema-'+row['id'],'seq':times[2] or 0,'marks':{} if row['state'] in ('review','delivered') else None,'provenance':feed['provenance'],'total':row['event_count'],'has_more':feed['cursor']['has_more'],'mission':feed['mission'],'artifacts':feed['artifacts'],'artifacts_cursor':feed['artifact_cursor']}
 def source(self,row,ordinal,name):
  r=self.conn.execute("SELECT mission_id,ordinal,name,source_sha256,display_sha256,text,mime,truncated,redacted,unavailable,reason FROM artifactsources WHERE mission_id=? AND ordinal=? AND name=? AND reason!='sensitive_filename'",(row['id'],ordinal,name)).fetchone()
  need(r is not None,404,'artifact_missing');d=dict(r);d['available']=not bool(d.pop('unavailable'));d['truncated']=bool(d['truncated']);d['redacted']=bool(d['redacted'])
  need(len(d['text'].encode())<=128*1024)
  if d['available']:need(hashlib.sha256(d['text'].encode()).hexdigest()==d['display_sha256'])
  else:d['text']=''
  return d

def board(row,observed):
 return [{'proj':'awema','id':row['id'],'title':row['objective_sanitized'],'mtime':int(observed*1000),'asked':int(row['created']*1000),'state':'working' if row['state'] in ('queued','running') else 'blocked' if row['state']=='blocked' else 'turn','tool':'','ageMs':0,'subActive':0,'subTotal':0}]

class Handler(legacy.Handler):
 def handle_get(self):
  try:
   need(self.headers.get('Sec-Fetch-Site')!='cross-site',403,'origin_denied')
   user=legacy.authenticate(self.headers.get('Cookie',''))
   u=urlsplit(self.path);need(u.path.startswith(BASE+'/'),404,'route_missing');route=u.path[len(BASE):]
   try:q=parse_qs(u.query,keep_blank_values=True,max_num_fields=12)
   except ValueError:raise Denied(400,'invalid_request')
   files={'/':'reunion.html','/reunion/':'reunion.html','/reunion/index.html':'reunion.html','/index.html':'reunion.html','/details/':'index.html','/details/index.html':'index.html','/standup.css':'standup.css','/standup.js':'standup.js','/config.js':'config.js','/LICENSE':'LICENSE','/awema-upstream-controls.js':'awema-upstream-controls.js','/awema-upstream-controls.css':'awema-upstream-controls.css'}
   if route in files:
    f=UI/files[route];need(f.is_file() and not f.is_symlink(),404,'asset_missing')
    mime='text/html; charset=utf-8' if f.suffix=='.html' else 'text/css; charset=utf-8' if f.suffix=='.css' else 'text/javascript; charset=utf-8' if f.suffix=='.js' else 'text/plain; charset=utf-8'
    return self.send(200,f.read_bytes(),mime)
   disabled={'/api/projects':[],'/api/characters':{'chars':[],'dir':''},'/api/packs':[],'/api/voices':{'available':False,'voices':[]},'/api/health':{'claude':None,'apiKey':False,'trError':'disabled_read_only','prototype':True},'/api/kokoro':{'installed':False,'ready':False},'/api/audio-owner':{'owner':None}}
   if route in disabled:return self.send(200,disabled[route])
   if route=='/api/prefs.js':return self.send(200,b'window.SAVED_PREFS = {};','text/javascript; charset=utf-8')
   need(route in ('/api/catalog','/api/current','/api/feed','/api/session','/api/artifacts','/api/artifact','/api/board','/api/sessions'),404,'route_missing')
   with Catalog(user) as cat:
    if route=='/api/catalog':
     params(q,('after','limit'));after=q.get('after',['0'])[0]
     need(after=='0' or bool(MID.fullmatch(after)),400,'invalid_cursor')
     limit=number(q,'limit',50,200);need(limit>0,400,'invalid_cursor')
     return self.send(200,cat.catalog(None if after=='0' else after,limit))
    allowed=('mission','id','proj','after','limit','ep') if route=='/api/session' else ('mission','after','limit') if route in ('/api/feed','/api/artifacts') else ('mission','ordinal','name') if route=='/api/artifact' else ('mission','id','proj')
    params(q,allowed);mid=selected(q)
    try:row=cat.mission(mid)
    except Denied as e:
     if e.code!=404 or mid or route not in ('/api/current','/api/board','/api/sessions'):raise
     return self.send(200,{} if route=='/api/current' else [])
    if route=='/api/current':return self.send(200,{'proj':'awema','id':row['id'],'mtime':int(cat.observed*1000),'asked':int(row['created']*1000),'pick':bool(mid)})
    if route in ('/api/board','/api/sessions'):return self.send(200,board(row,cat.observed))
    if route=='/api/artifact':
     need('name' in q and bool(NAME.fullmatch(q['name'][0])),400,'invalid_artifact');ordinal=number(q,'ordinal',0,63)
     return self.send(200,cat.source(row,ordinal,q['name'][0]))
    after=number(q,'after',0,9223372036854775807);limit=number(q,'limit',200 if route=='/api/artifacts' else 500,200 if route=='/api/artifacts' else 1000);need(limit>0,400,'invalid_cursor')
    if route=='/api/artifacts':return self.send(200,cat.artifacts(row,after,limit))
    if route=='/api/feed':return self.send(200,cat.feed(row,after,limit))
    ep='awema-'+row['id']
    if 'ep' in q and q['ep']!=[ep]:return self.send(200,{'resync':True})
    return self.send(200,cat.timeline(row,after,limit))
  except Denied as e:self.send(e.code,{'error':e.reason})
  except (ValueError,TypeError,KeyError):self.send(503,{'error':'projection_invalid'})
  except Exception:self.send(503,{'error':'observer_temporarily_unavailable'})

def main():
 os.umask(0o007);path=Path('/socket/standup.sock')
 if path.exists():
  s=path.lstat();need(stat.S_ISSOCK(s.st_mode) and s.st_uid==os.geteuid(),503,'unsafe_socket')
  with socket.socket(socket.AF_UNIX) as probe:
   try:probe.connect(str(path))
   except ConnectionRefusedError:path.unlink()
   else:raise RuntimeError('socket_already_active')
 with legacy.Server(str(path),Handler) as server:
  path.chmod(0o660);server.serve_forever()
if __name__=='__main__':main()
