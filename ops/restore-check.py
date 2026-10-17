import pathlib,subprocess,json,time,re,datetime
b=pathlib.Path('/opt/awema-ops');state=json.loads((b/'last-backup.json').read_text());folder=b/'backups'/state['timestamp']
results=[]
def run(args,**kw):return subprocess.run(args,check=True,**kw)
def sql(n,q):return subprocess.check_output(['docker','exec',n,'psql','-U',dbuser,'-d','restoretest','-At','-c',q]).decode().strip()
for key,image in [('cinelight','supabase/postgres:203.0.113.10'),('cinelight-cloud','supabase/postgres:203.0.113.10'),('afrocodeurs','postgres:17-alpine'),('afrocodeurs-production','postgres:17-alpine'),('coolify','postgres:15-alpine')]:
 name='awema-restore-check-'+key
 dbuser='supabase_admin' if key.startswith('cinelight') else 'postgres'
 run(['docker','run','-d','--name',name,'--network','none','--memory','768m','--cpus','1','--tmpfs','/var/lib/postgresql/data:rw,size=512m','-e','POSTGRES_PASSWORD=temporary-isolated-restore',image],stdout=subprocess.DEVNULL)
 try:
  for i in range(40):
   r=subprocess.run(['docker','exec',name,'pg_isready','-h','127.0.0.1','-U','postgres'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
   if r.returncode==0:break
   time.sleep(1)
  else:raise RuntimeError('Database did not initialize')
  run(['docker','exec',name,'createdb','-U',dbuser,'-T','template0','restoretest'])
  roles=re.findall(r'^CREATE ROLE (.+);$',(folder/(('cinelight' if key.startswith('cinelight') else key)+'-roles.sql')).read_text(),re.M)
  for role in roles:
   # Identifiers originate from pg_dumpall; create only missing roles.
   exists=subprocess.check_output(['docker','exec',name,'psql','-U',dbuser,'-d','postgres','-At','-c',"SELECT rolname FROM pg_roles"]).decode().splitlines()
   raw=role.strip('"').replace('""','"')
   if raw not in exists:run(['docker','exec',name,'psql','-U',dbuser,'-d','postgres','-v','ON_ERROR_STOP=1','-c','CREATE ROLE '+role+' NOLOGIN;'],stdout=subprocess.DEVNULL)
  run(['docker','exec','-i',name,'pg_restore','-U',dbuser,'-d','restoretest','--exit-on-error','--single-transaction'],input=(folder/(key+'.dump')).read_bytes(),stdout=subprocess.DEVNULL)
  tables=int(sql(name,"SELECT count(*) FROM pg_tables WHERE schemaname='public'"))
  info={'database':key,'tables':tables,'status':'PASS'}
  if key.startswith('cinelight'):
   info['users']=int(sql(name,'SELECT count(*) FROM auth.users'));info['projects']=int(sql(name,'SELECT count(*) FROM public.projects'));info['rls_policies']=int(sql(name,"SELECT count(*) FROM pg_policies WHERE schemaname='public'"))
  results.append(info)
 finally:
  run(['docker','rm','-f','-v',name],stdout=subprocess.DEVNULL)
(b/'restore-results.json').write_text(json.dumps({'timestamp':datetime.datetime.now(datetime.timezone.utc).isoformat(),'source':state['timestamp'],'results':results},indent=2))
print(json.dumps(results))
