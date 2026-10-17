"""Operator-selected bounded role budgets, never accepted from mission text."""
VERSION='awema-role-budgets-v1'
_ROWS={
 'pm':(600,80,120,48,'1536m','1.5'),
 'designer':(900,100,180,64,'1536m','1.5'),
 'dev':(900,120,240,96,'2g','2'),
 'qa':(900,100,180,64,'1536m','1.5'),
 'security':(600,80,120,48,'1536m','1.5'),
 'ops':(600,80,120,48,'1536m','1.5'),
 'assa':(600,80,120,48,'1536m','1.5'),
 'cl-producer':(900,100,180,64,'1536m','1.5'),
 'cto':(600,80,120,48,'1536m','1.5'),
}
def role_budget(role):
 if role not in _ROWS:raise ValueError('role_budget_denied')
 seconds,turns,calls,mib,memory,cpus=_ROWS[role]
 return {'version':VERSION,'role':role,'seconds':seconds,'turns':turns,'max_calls':calls,'max_bytes':mib*1024*1024,'memory':memory,'cpus':cpus,'reasoning_effort':'low'}
def profile_config(role):
 b=role_budget(role)
 return ('model:\n  default: deepseek-flash\n  provider: deepseek\nagent:\n  reasoning_effort: '+b['reasoning_effort']+'\n  max_turns: '+str(b['turns'])+'\n  run_budget:\n    max_seconds: '+str(b['seconds'])+'\nterminal:\n  timeout: 60\napprovals:\n  mode: manual\n  single_query_mode: approve\n')
