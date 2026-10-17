import re,html
from activity_collector import query,AI
from activity_schema import STATUSES
from live_catalog import LIVE_ROLES
from team_schema import validate
def clean_title(value,budget):
 text=html.unescape(str(value or ''))
 text=re.sub(r'<[^>]*>','',text).replace('<','').replace('>','')
 text=re.sub(r'(?i)\b(?:bearer\s+|(?:api[_ -]?key|token|password|secret|credential)\s*[:=]\s*)[^\s,;]+','[redacted]',text)
 text=re.sub(r'\bsk-[A-Za-z0-9_-]{8,}\b','[redacted]',text)
 text=re.sub(r'(?:/(?:opt|root|etc|home)/[^\s]*|[A-Za-z]:\\[^\s]*)','[private path]',text)
 text=''.join(c for c in text if ord(c)>=32)[:160]
 return text.encode('utf-8')[:budget].decode('utf-8',errors='ignore')
def collect_team(base=AI,clock=None):
 import time
 clock=int(time.time()) if clock is None else clock
 result={'version':1,'observed_at':clock,'available':False,'truncated':False,'tasks':[]}
 try:
  path=base/'kanban/boards/awema-agency/kanban.db'
  cards=query(path,"SELECT id,substr(title,1,160),assignee,status,created_at FROM tasks WHERE project_id IS NULL OR project_id='awema-ai-team' ORDER BY created_at DESC,id LIMIT 201")
  # Real native profile is read directly from task_runs, never inferred from assignee.
  runs=query(path,"SELECT r.task_id,r.id,r.profile,r.started_at,r.ended_at FROM task_runs r JOIN tasks t ON t.id=r.task_id WHERE t.project_id IS NULL OR t.project_id='awema-ai-team' ORDER BY r.started_at DESC,r.id DESC LIMIT 400")
  counts=dict(query(path,"SELECT r.task_id,count(*) FROM task_runs r JOIN tasks t ON t.id=r.task_id WHERE t.project_id IS NULL OR t.project_id='awema-ai-team' GROUP BY r.task_id"))
  result['truncated']=len(cards)>200 or len(runs)>=400 or any(n>2 for n in counts.values())
  title_budget=65536
  for tid,title,role,status,created in cards[:200]:
   if not isinstance(tid,str) or not re.fullmatch(r't_[a-f0-9]{8}',tid):continue
   created=created if type(created) is int and 0<=created<=clock+5 else 0
   events=[{'kind':'created','at':created,'profile':'unknown','run_id':0}]
   for task_id,rid,profile,started,ended in runs:
    if task_id!=tid or len(events)>=5:continue
    profile=profile if profile in LIVE_ROLES else 'unknown'
    if type(rid) is not int or not 0<rid<2147483648:continue
    for kind,at in [('run_started',started),('run_ended',ended)]:
     if type(at) is int and 0<at<=clock+5 and len(events)<5:events.append({'kind':kind,'at':at,'profile':profile,'run_id':rid})
   title=clean_title(title,title_budget);title_budget-=len(title.encode('utf-8'))
   result['tasks'].append({'id':tid,'title':title,'role':role if role in LIVE_ROLES else 'unknown','status':status if status in STATUSES else 'unknown','created_at':created,'run_count':min(9999,counts.get(tid,0)),'events':sorted(events,key=lambda e:e['at'])})
  result['available']=True
 except Exception:result['tasks']=[]
 return validate(result,clock)
