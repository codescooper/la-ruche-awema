import urllib.request,urllib.error,json,base64,pathlib,sys,re,datetime
base=sys.argv[1] if len(sys.argv)>1 else 'http://127.0.0.1:14182'
enc=lambda x:base64.urlsafe_b64encode(json.dumps(x).encode()).decode().rstrip('=')
token=enc({'alg':'HS256','typ':'JWT'})+'.'+enc({'exp':1,'sub':'00000000-0000-4000-8000-000000000001','aud':'authenticated'})+'.invalid'
session=enc({'access_token':token,'refresh_token':'invalid-regression-fixture','expires_at':1,'expires_in':1,'token_type':'bearer','user':{'id':'00000000-0000-4000-8000-000000000001'}})
checks=[]
def check(name,ok):
 checks.append({'name':name,'ok':bool(ok)});print(name,'PASS' if ok else 'FAIL',flush=True)
 if not ok:raise RuntimeError(name)
def get(path,cookie=None):
 req=urllib.request.Request(base+path,headers={'Cookie':cookie} if cookie else {})
 try:
  with urllib.request.urlopen(req,timeout=30) as r:return r.status,r.read().decode(),r.headers
 except urllib.error.HTTPError as e:return e.code,e.read().decode(),e.headers
try:
 for path in ['/','/fr','/en']:
  status,body,headers=get(path)
  check('Anonymous landing '+path,status==200 and 'Moins de dispersion.' in body and 'CL Producer' in body)
 status,body,headers=get('/','sb-txojmavlsxeqvybxivjx-auth-token=base64-'+session)
 check('Expired invalid session first request renders landing',status==200 and 'Moins de dispersion.' in body)
 check('Expired auth cookie removed',any('sb-txojmavlsxeqvybxivjx-auth-token=' in x and ('Max-Age=0' in x or 'max-age=0' in x.lower()) for x in headers.get_all('set-cookie',[])))
 status,body,headers=get('/login')
 check('Login reachable',status==200 and 'Application error' not in body)
 status,body,headers=get('/api/projects/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa/producer')
 check('Producer remains private',status==401)
 status,body,headers=get('/')
 assets=set(re.findall(r'(?:src|href)="([^"?]+\.(?:css|js))(?:\?[^"\s]*)?"',body))
 for path in assets:
  if path.startswith('/_next/'):
   status,_,_=get(path);check('Asset '+path.rsplit('/',1)[-1],status==200)
 report={'ok':True,'base':base,'time':datetime.datetime.now(datetime.timezone.utc).isoformat(),'checks':checks}
except Exception as e:report={'ok':False,'base':base,'error':str(e),'checks':checks}
pathlib.Path('/opt/awema-cl-producer/'+('LANDING-PRODUCTION.json' if base.startswith('https:') else 'LANDING-CANDIDATE.json')).write_text(json.dumps(report,indent=2))
raise SystemExit(0 if report['ok'] else 1)
