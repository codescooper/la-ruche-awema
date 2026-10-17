"""Private invitation demo. Only synthetic data; no outbound networking or subprocesses."""
import hashlib, hmac, json, os, re, secrets, socket, sqlite3, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from http.cookies import SimpleCookie
from pathlib import Path
from urllib.parse import urlsplit
from catalog import ROLES, ROLE_IDS
from engine import execute_plan
from activity_schema import load as load_activity
import classroom_view

ORIGIN=os.environ.get('PUBLIC_ORIGIN','https://laruche.awema.cloud')
INVITE_HASH=os.environ.get('INVITE_HASH','')
INTERNAL_TOKEN=os.environ.get('INTERNAL_TOKEN','')
CLASSROOM_HASH=os.environ.get('CLASSROOM_VIEW_HASH','')
DATA=Path(os.environ.get('DATA_DIR','/data'))
ACTIVITY=Path('/activity/activity.json')
from replay_schema import load as load_replays
from trace_schema import load as load_traces
TRACES=Path('/activity/traces.json')
COOKIE='__Host-awema_jury'
TTL=24*3600
LOCK=threading.RLock()
DB=None
PUBLIC=Path(__file__).parent/'public'

def digest(v):return hashlib.sha256(v.encode()).hexdigest()
def now():return int(time.time())
def init_db():
    global DB
    DATA.mkdir(parents=True,exist_ok=True)
    DB=sqlite3.connect(DATA/'demo.sqlite',check_same_thread=False,isolation_level=None)
    DB.row_factory=sqlite3.Row
    DB.executescript('''PRAGMA journal_mode=WAL; PRAGMA secure_delete=ON;
    CREATE TABLE IF NOT EXISTS sessions(id TEXT PRIMARY KEY, csrf TEXT, created INT, used INT DEFAULT 0);
    CREATE TABLE IF NOT EXISTS runs(id TEXT PRIMARY KEY, sid TEXT, idem TEXT, fingerprint TEXT, status TEXT, role TEXT, message TEXT, created INT, started INT, claim TEXT, result TEXT, UNIQUE(sid,idem));
    CREATE TABLE IF NOT EXISTS budgets(day TEXT PRIMARY KEY, used INT DEFAULT 0, logins INT DEFAULT 0);
    CREATE TABLE IF NOT EXISTS attempts(bucket TEXT PRIMARY KEY, count INT);
    ''')
    DB.execute("UPDATE runs SET status='failed', result=? WHERE status='running'",(json.dumps({'reply':'Mission interrompue par un redémarrage. Aucun résultat annoncé.','steps':[],'artifact':None}),))

def cleanup():
    t=now()
    DB.execute('DELETE FROM runs WHERE sid IN (SELECT id FROM sessions WHERE created<?)',(t-TTL,))
    DB.execute('DELETE FROM sessions WHERE created<?',(t-TTL,))
    DB.execute('DELETE FROM attempts WHERE CAST(substr(bucket,1,instr(bucket,\':\')-1) AS INTEGER)<?',(t//60-5,))
    DB.execute("UPDATE runs SET status='failed',result=? WHERE status IN ('queued','running') AND created<?",(json.dumps({'reply':'Délai de démonstration dépassé. Aucune reprise automatique.','steps':[],'artifact':None}),t-180))
    DB.execute("DELETE FROM budgets WHERE day < date('now','-8 days')")

def rate(key,limit):
    bucket=f'{now()//60}:{key}'
    DB.execute('INSERT INTO attempts VALUES (?,1) ON CONFLICT(bucket) DO UPDATE SET count=count+1',(bucket,))
    return DB.execute('SELECT count FROM attempts WHERE bucket=?',(bucket,)).fetchone()[0]<=limit

def public_run(row):
    out={'runId':row['id'],'status':row['status'],'role':row['role'],'created':row['created'],'reply':'','steps':[],'artifact':None}
    if row['result']:
        out.update(json.loads(row['result']))
        out['status']=row['status']
    return out

class Server(ThreadingHTTPServer):
    daemon_threads=True
    request_queue_size=32
    slots=threading.BoundedSemaphore(24)
    def process_request(self,request,address):
        if not self.slots.acquire(blocking=False):request.close();return
        super().process_request(request,address)
    def process_request_thread(self,request,address):
        try:super().process_request_thread(request,address)
        finally:self.slots.release()

class UnixServer(Server):
    address_family=socket.AF_UNIX
    def server_bind(self):
        socket.socket.bind(self.socket,self.server_address)
        self.server_name='localhost';self.server_port=0

class Handler(BaseHTTPRequestHandler):
    server_version='AwemaOffice'
    sys_version=''
    protocol_version='HTTP/1.0'
    def setup(self):
        super().setup(); self.connection.settimeout(8)
    def log_message(self,*args):pass  # No prompts, cookies or invitation in access logs.
    def send(self,status,obj,cookie=None):
        if isinstance(obj,bytes):body=obj
        else:body=json.dumps(obj,ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header('Content-Type',getattr(self,'mime','application/json; charset=utf-8'))
        self.send_header('Content-Length',str(len(body)))
        self.send_header('Cache-Control','no-store')
        self.send_header('X-Content-Type-Options','nosniff')
        self.send_header('X-Frame-Options','DENY')
        self.send_header('Referrer-Policy','no-referrer')
        self.send_header('Permissions-Policy','camera=(), microphone=(), geolocation=(), payment=()')
        self.send_header('Content-Security-Policy',"default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'")
        self.send_header('Strict-Transport-Security','max-age=31536000')
        if cookie:self.send_header('Set-Cookie',cookie)
        self.end_headers();self.wfile.write(body)
    def error(self,status,code):self.send(status,{'error':code})
    def session(self):
        try:
            c=SimpleCookie();c.load(self.headers.get('Cookie','')[:4096]);token=c[COOKIE].value
            if not re.fullmatch('[A-Za-z0-9_-]{43}',token):return None
            return DB.execute('SELECT * FROM sessions WHERE id=? AND created>?',(digest(token),now()-TTL)).fetchone()
        except (KeyError,ValueError):return None
    def do_GET(self):
        try:
            path=urlsplit(self.path).path
            if path=='/health':return self.send(200,{'ok':True})
            if path=='/api/public/activity':return self.send(200,load_activity(ACTIVITY))
            if path=='/api/public/replays':return self.send(200,load_replays(Path('/activity/replays.json')))
            if path=='/api/public/traces':return self.send(200,load_traces(TRACES))
            if path=='/api/public/financial-qualification':return self.send(200,json.loads((Path(__file__).parent/'financial_qualification.json').read_text(encoding='utf-8')))
            if path=='/api/catalog':return self.send(200,{'roles':ROLES,'demo':True,'activities':'separate_authenticated_metadata'})
            if path in ('/','/index.html','/app.js','/styles.css','/style.css','/favicon.svg','/office.svg'):
                f=PUBLIC/('index.html' if path=='/' else path[1:])
                if not f.is_file():return self.error(404,'not_found')
                self.mime={'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.svg':'image/svg+xml'}[f.suffix]
                return self.send(200,f.read_bytes())
            with LOCK:
                cleanup();s=self.session()
                if not s:return self.error(401,'invitation_required')
                if not rate('read:'+s['id'],90):return self.error(429,'rate_limit')
                if path=='/api/session':return self.send(200,{'csrf':s['csrf'],'remaining':max(0,12-s['used']),'expires':s['created']+TTL,'demo':True})
                if path=='/api/classroom':return self.send(200,classroom_view.load(DATA/'classroom.json'))
                if path=='/api/activity':return self.send(200,load_activity(ACTIVITY))
                if path=='/api/runs':
                    rows=DB.execute('SELECT * FROM runs WHERE sid=? ORDER BY created DESC LIMIT 12',(s['id'],)).fetchall()
                    return self.send(200,{'runs':[public_run(r) for r in rows]})
                if re.fullmatch('/api/runs/[a-f0-9]{32}',path):
                    row=DB.execute('SELECT * FROM runs WHERE sid=? AND id=?',(s['id'],path.rsplit('/',1)[1])).fetchone()
                    return self.send(200,public_run(row)) if row else self.error(404,'not_found')
                return self.error(404,'not_found')
        except (BrokenPipeError,ConnectionResetError):pass
        except Exception:self.error(500,'request_failed')
    def do_POST(self):
        try:
            if self.headers.get('Transfer-Encoding'):return self.error(400,'invalid_encoding')
            n=int(self.headers.get('Content-Length','0'))
            if n<=0 or n>18000:return self.error(413,'body_size')
            if self.headers.get_content_type()!='application/json':return self.error(415,'json_required')
            d=json.loads(self.rfile.read(n))
            if not isinstance(d,dict):return self.error(400,'invalid_schema')
            path=urlsplit(self.path).path
            with LOCK:
                cleanup()
                if path=='/classroom-observation':
                    auth=self.headers.get('Authorization','')
                    if not CLASSROOM_HASH or len(auth)>120 or not auth.startswith('Bearer ') or not hmac.compare_digest(digest(auth[7:]),CLASSROOM_HASH):return self.error(401,'observation_token_required')
                    if not rate('classroom-write',20):return self.error(429,'rate_limit')
                    classroom_view.save(DATA/'classroom.json',d);return self.send(200,{'ok':True})
                if path=='/internal':return self.internal(d)
                if self.headers.get('Origin')!=ORIGIN:return self.error(403,'origin_rejected')
                if self.headers.get('Sec-Fetch-Site','same-origin') not in ('same-origin','none'):return self.error(403,'origin_rejected')
                if path=='/api/login':
                    if not rate('login-global',30):return self.error(429,'rate_limit')
                    if set(d)!={'invitation'} or not isinstance(d['invitation'],str) or len(d['invitation'])>100:return self.error(400,'invalid_schema')
                    if not INVITE_HASH or not hmac.compare_digest(digest(d['invitation']),INVITE_HASH):return self.error(403,'invitation_invalid')
                    day=time.strftime('%Y-%m-%d',time.gmtime())
                    DB.execute('INSERT OR IGNORE INTO budgets(day) VALUES (?)',(day,))
                    if DB.execute('SELECT logins FROM budgets WHERE day=?',(day,)).fetchone()[0]>=20:return self.error(429,'daily_session_limit')
                    token=secrets.token_urlsafe(32);csrf=secrets.token_urlsafe(32)
                    DB.execute('INSERT INTO sessions(id,csrf,created) VALUES (?,?,?)',(digest(token),csrf,now()))
                    DB.execute('UPDATE budgets SET logins=logins+1 WHERE day=?',(day,))
                    return self.send(200,{'ok':True,'csrf':csrf},f'{COOKIE}={token}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age={TTL}')
                s=self.session()
                if not s:return self.error(401,'invitation_required')
                if not isinstance(d.get('csrf'),str) or not hmac.compare_digest(d['csrf'],s['csrf']):return self.error(403,'csrf_rejected')
                if not rate('write:'+s['id'],12):return self.error(429,'rate_limit')
                if path=='/api/message':
                    if set(d)!={'csrf','message','role','idempotencyKey'}:return self.error(400,'invalid_schema')
                    msg=d['message'];role=d['role'];idem=d['idempotencyKey']
                    if not isinstance(msg,str) or not 1<=len(msg.strip())<=2400 or not isinstance(role,str) or role not in ROLE_IDS or role in ('community-manager','accounting','finance') or not isinstance(idem,str) or not re.fullmatch('[A-Za-z0-9_-]{16,64}',idem):return self.error(400,'invalid_schema')
                    fingerprint=digest(json.dumps([msg,role]))
                    existing=DB.execute('SELECT * FROM runs WHERE sid=? AND idem=?',(s['id'],idem)).fetchone()
                    if existing:
                        if existing['fingerprint']!=fingerprint:return self.error(409,'idempotency_conflict')
                        return self.send(200,public_run(existing))
                    if (DATA/'PAUSE').exists():return self.error(503,'demo_paused')
                    day=time.strftime('%Y-%m-%d',time.gmtime());DB.execute('INSERT OR IGNORE INTO budgets(day) VALUES (?)',(day,))
                    if s['used']>=12 or DB.execute('SELECT used FROM budgets WHERE day=?',(day,)).fetchone()[0]>=40:return self.error(429,'mission_limit')
                    if DB.execute("SELECT count(*) FROM runs WHERE sid=? AND status IN ('queued','running')",(s['id'],)).fetchone()[0]:return self.error(409,'mission_already_running')
                    if DB.execute("SELECT count(*) FROM runs WHERE status IN ('queued','running')").fetchone()[0]>=4:return self.error(429,'queue_full')
                    rid=secrets.token_hex(16)
                    DB.execute('INSERT INTO runs(id,sid,idem,fingerprint,status,role,message,created) VALUES (?,?,?,?,?,?,?,?)',(rid,s['id'],idem,fingerprint,'queued',role,msg,now()))
                    DB.execute('UPDATE sessions SET used=used+1 WHERE id=?',(s['id'],))
                    DB.execute('UPDATE budgets SET used=used+1 WHERE day=?',(day,))
                    return self.send(202,{'runId':rid,'status':'queued'})
                if path=='/api/cancel':
                    if set(d)!={'csrf','runId'} or not isinstance(d['runId'],str):return self.error(400,'invalid_schema')
                    row=DB.execute('SELECT * FROM runs WHERE id=? AND sid=?',(d['runId'],s['id'])).fetchone()
                    if not row:return self.error(404,'not_found')
                    DB.execute("UPDATE runs SET status='cancelled',message='',claim=NULL,result=NULL WHERE id=? AND status IN ('queued','running')",(row['id'],))
                    return self.send(200,{'ok':True})
                if path=='/api/reset':
                    if set(d)!={'csrf'}:return self.error(400,'invalid_schema')
                    DB.execute('DELETE FROM runs WHERE sid=?',(s['id'],))
                    csrf=secrets.token_urlsafe(32);DB.execute('UPDATE sessions SET csrf=? WHERE id=?',(csrf,s['id']))
                    return self.send(200,{'ok':True,'csrf':csrf,'remaining':max(0,12-s['used'])})
                return self.error(404,'not_found')
        except (ValueError,TypeError,json.JSONDecodeError):self.error(400,'invalid_request')
        except (BrokenPipeError,ConnectionResetError):pass
        except Exception:self.error(500,'request_failed')
    def internal(self,d):
        auth=self.headers.get('Authorization','')
        if not INTERNAL_TOKEN or not hmac.compare_digest(auth,'Bearer '+INTERNAL_TOKEN):return self.error(404,'not_found')
        action=d.get('action')
        if action=='claim' and set(d)=={'action'}:
            if (DATA/'PAUSE').exists():return self.send(200,{'job':None})
            if DB.execute("SELECT count(*) FROM runs WHERE status='running'").fetchone()[0]:return self.send(200,{'job':None})
            row=DB.execute("SELECT * FROM runs WHERE status='queued' ORDER BY created LIMIT 1").fetchone()
            if not row:return self.send(200,{'job':None})
            claim=secrets.token_urlsafe(24)
            DB.execute("UPDATE runs SET status='running',started=?,claim=? WHERE id=? AND status='queued'",(now(),claim,row['id']))
            old=DB.execute("SELECT message,result FROM runs WHERE sid=? AND status IN ('completed','needs_input','refused') ORDER BY created DESC LIMIT 4",(row['sid'],)).fetchall()
            history=[{'message':r['message'][:1000],'reply':json.loads(r['result']).get('reply','')[:1000]} for r in reversed(old[:2])]
            return self.send(200,{'job':{'id':row['id'],'claim':claim,'message':row['message'],'role':row['role'],'history':history}})
        if action in ('check','finish'):
            allowed={'action','id','claim'}|({'plan','failed'} if action=='finish' else set())
            if set(d)-allowed or not isinstance(d.get('id'),str) or not isinstance(d.get('claim'),str):return self.error(400,'invalid_schema')
            row=DB.execute('SELECT * FROM runs WHERE id=?',(d['id'],)).fetchone()
            if not row or row['status']!='running' or not hmac.compare_digest(row['claim'] or '',d['claim']):return self.error(409,'stale_or_cancelled')
            if action=='check':return self.send(200,{'active':True})
            if d.get('failed'):
                result={'status':'failed','reply':'Le modèle est indisponible ou le délai a été dépassé. Aucun résultat fictif n’a été substitué. Réessayez plus tard.','steps':[],'artifact':None}
            else:
                try:result=execute_plan(d.get('plan'))
                except (ValueError,TypeError,AssertionError):result={'status':'failed','reply':'La proposition du modèle ne respecte pas le format autorisé. Aucune action exécutée.','steps':[],'artifact':None}
            DB.execute('UPDATE runs SET status=?,result=?,claim=NULL WHERE id=? AND status=?',(result['status'],json.dumps(result,ensure_ascii=False),row['id'],'running'))
            return self.send(200,{'ok':True})
        return self.error(400,'invalid_schema')

if __name__=='__main__':
    if len(INVITE_HASH)!=64 or len(INTERNAL_TOKEN)<32:raise SystemExit('Missing private configuration')
    init_db()
    path=os.environ.get('SOCKET_PATH')
    if path:
        if os.path.exists(path):os.unlink(path)
        http=UnixServer(path,Handler);os.chmod(path,0o660)
    else:http=Server(('0.0.0.0',8080),Handler)
    http.serve_forever()
