import unittest,sqlite3,tempfile,json,time,hashlib,os,sys
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace
if os.name=='nt':sys.modules.setdefault('fcntl',SimpleNamespace())
import mission_runner as r
import mission_flow as f
class RunnerTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);(self.root/'states').mkdir();(self.root/'handoffs').mkdir();self.c=sqlite3.connect(':memory:');self.c.row_factory=sqlite3.Row
  self.c.executescript('create table users(id text,generation integer,active integer,role text);'+f.SCHEMA);self.c.execute("insert into users values('a',1,1,'owner')")
  self.mid='f_'+'a'*24;digest=hashlib.sha256(json.dumps(['objective','criteria',f.PLAN,'awema-internal-sandbox'],sort_keys=True).encode()).hexdigest();self.c.execute('insert into mission_flows values(?,?,?,?,?,?,?,?,?,?,?)',(self.mid,'a',1,'objective','criteria',digest,'running',time.time(),time.time(),time.time(),''))
  for i,role in enumerate(f.ROLES):self.c.execute('insert into mission_steps values(?,?,?,?,?,?,?)',(self.mid,i,role,None,'waiting','',None))
  self.c.commit();self.m=SimpleNamespace(audit=lambda *a:None,row=lambda t:{'status':'done'},save=lambda p,v:p.write_text(json.dumps(v)))
  self.patcher=patch.object(r,'WROOT',self.root);self.patcher.start();self.rootpatch=patch.object(r,'ROOT',self.root);self.rootpatch.start();self.aud=patch.object(r,'audit',lambda *a:None);self.aud.start()
 def tearDown(self):self.aud.stop();self.rootpatch.stop();self.patcher.stop();self.c.close();self.tmp.cleanup()
 def row(self):return self.c.execute('select * from mission_flows where id=?',(self.mid,)).fetchone()
 def test_security_scope_avoids_unbounded_environment_probes(self):
  self.assertIn('Aucun appel MCP, API distante',r.SECURITY_INSTRUCTION)
  self.assertIn('Au plus trois vérifications locales en lecture seule',r.SECURITY_INSTRUCTION)
  self.assertIn('SECURITY.md et REVIEW.json (seuls fichiers texte requis)',r.SECURITY_INSTRUCTION)
  self.assertIn('arrêter cette vérification',r.SECURITY_INSTRUCTION)
 def test_stage_rejects_unexpected_artifacts_with_actionable_reason(self):
  task='t_87654321';op='c'*24;handoff=self.root/'handoffs'/op;handoff.mkdir()
  files={'PLAN.md':'Plan','PROPOSITION-PM.md':'Proposal','REVIEW.json':'{}'};artifacts={}
  for name,content in files.items():
   (handoff/name).write_text(content);artifacts[name]=hashlib.sha256(content.encode()).hexdigest()
  (handoff/'RESULT.json').write_text(json.dumps({'summary':'PM stage complete'}))
  (self.root/'states'/(op+'.json')).write_text(json.dumps({'task':task,'operation':op,'status':'finished','outcome':'completed','handoff_dir':str(handoff),'artifact_sha256':artifacts}))
  self.c.execute("update mission_steps set task=?,state='dispatching' where mission=? and ordinal=0",(task,self.mid));self.c.commit()
  result=r.process(self.c,self.m)
  self.assertEqual(result['reason_code'],'artifact_contract');self.assertEqual(self.row()['state'],'blocked')
  self.assertIn('PLAN.md, PROPOSITION-PM.md',self.row()['blocker'])
 def test_media_artifact_requires_allowlisted_name_type_and_signature(self):
  pdf=b'%PDF-1.7\n%fixture'
  self.assertEqual(r.media_type('MEDIA-1.pdf',pdf),'application/pdf')
  self.assertIsNone(r.media_type('MEDIA-4.pdf',pdf))
  self.assertIsNone(r.media_type('MEDIA-1.pdf',b'<script>alert(1)</script>'))
  self.assertIsNone(r.media_type('MEDIA-1.svg',b'<svg/>'))
  self.assertIsNone(r.media_type('MEDIA-1.pdf',pdf+(b'x'*(1024*1024))))
 def test_checked_media_is_saved_as_versioned_envelope_and_visible_result(self):
  task='t_12345678';op='d'*24;handoff=self.root/'handoffs'/op;handoff.mkdir()
  files={'PLAN.md':b'Plan','PROPOSITION-PM.md':b'Proposal','MEDIA-1.pdf':b'%PDF-1.7\n%fixture'};artifacts={}
  for name,raw in files.items():(handoff/name).write_bytes(raw);artifacts[name]=hashlib.sha256(raw).hexdigest()
  (handoff/'RESULT.json').write_text(json.dumps({'summary':'Plan complete'}))
  (self.root/'states'/(op+'.json')).write_text(json.dumps({'task':task,'operation':op,'started':time.time(),'status':'finished','outcome':'completed','handoff_dir':str(handoff),'artifact_sha256':artifacts}))
  self.c.execute("update mission_steps set task=?,state='dispatching' where mission=? and ordinal=0",(task,self.mid));self.c.commit()
  result=r.process(self.c,self.m);self.assertEqual(result['completed_role'],'pm')
  stored=self.c.execute("select content,sha256 from mission_artifacts where mission=? and name='MEDIA-1.pdf'",(self.mid,)).fetchone()
  self.assertTrue(stored['content'].startswith(r.MEDIA_PREFIX));self.assertEqual(stored['sha256'],artifacts['MEDIA-1.pdf'])
  envelope=json.loads(stored['content'][len(r.MEDIA_PREFIX):]);self.assertEqual(envelope['mime'],'application/pdf');self.assertEqual(envelope['size'],len(files['MEDIA-1.pdf']))
  self.assertEqual(__import__('base64').b64decode(envelope['base64']),files['MEDIA-1.pdf'])
 def finish(self,i,verdict='pass',files_override=None):
  task='t_'+str(i).zfill(8);op='operation'+str(i);handoff=self.root/'handoffs'/op;handoff.mkdir();role=f.ROLES[i]
  files={
   'pm':{'PLAN.md':'Plan','PROPOSITION-PM.md':'Proposal'},
   'dev':{'total.py':'def total(values): return sum(values)','test_total.py':'test total','TESTS.md':'Tests passed'},
   'qa':{'QA.md':'QA passed','REVIEW.json':json.dumps({'verdict':verdict,'reason':'Executed checks'})},
   'security':{'SECURITY.md':'Security passed','REVIEW.json':json.dumps({'verdict':verdict,'reason':'Executed checks'})},
   'cto':{'LIVRAISON.md':'Delivery consolidated','REVIEW.json':json.dumps({'verdict':verdict,'reason':'Executed checks'})},
  }[role]
  if files_override is not None:files=files_override
  artifacts={}
  for name,text in files.items():(handoff/name).write_text(text);artifacts[name]=hashlib.sha256(text.encode()).hexdigest()
  (handoff/'RESULT.json').write_text(json.dumps({'summary':'Completed stage'}));(self.root/'states'/(op+'.json')).write_text(json.dumps({'task':task,'operation':op,'started':i,'status':'finished','outcome':'completed','handoff_dir':str(handoff),'artifact_sha256':artifacts}))
  self.c.execute("update mission_steps set task=?,state='dispatching' where mission=? and ordinal=?",(task,self.mid,i));self.c.commit()
 def test_five_steps_then_review(self):
  for i in range(5):
   if i:
    task='t_'+str(i).zfill(8);p=SimpleNamespace(returncode=0,stdout=json.dumps({'bridge_spawned':1}),stderr='')
    with patch.object(r,'native_create',return_value=task),patch.object(r,'promote'),patch.object(r,'dispatch_task'),patch.object(r.subprocess,'run',return_value=p):r.process(self.c,self.m)
   self.finish(i);r.process(self.c,self.m)
  self.assertEqual(self.row()['state'],'review');self.assertEqual(self.c.execute("select count(*) from mission_steps where state='done'").fetchone()[0],5)
  handoffs=[x[0] for x in self.c.execute("select event from mission_events where event like '%_handoff_received' order by id")]
  self.assertEqual(handoffs,['dev_handoff_received','qa_handoff_received','security_handoff_received','cto_handoff_received'])
 def test_review_correction_blocks_next(self):
  for i in range(3):self.finish(i,'correction' if i==2 else 'pass');r.process(self.c,self.m)
  self.assertEqual(self.row()['state'],'blocked');self.assertIsNone(self.c.execute('select task from mission_steps where ordinal=3').fetchone()[0])
  self.assertNotEqual(self.c.execute('select state from mission_steps where ordinal=2').fetchone()[0],'done')
 def test_review_pass_is_case_insensitive(self):
  for i in range(2):self.finish(i);r.process(self.c,self.m)
  self.finish(2,'PASS')
  result=r.process(self.c,self.m)
  self.assertEqual(result['completed_role'],'qa')
  self.assertEqual(self.row()['state'],'running')
  self.assertEqual(self.c.execute('select state from mission_steps where ordinal=2').fetchone()[0],'done')
 def test_revoked_cancel_is_terminal(self):
  self.c.execute('update users set active=0');self.c.commit();r.change(self.c,self.row(),'cancelled');self.assertEqual(self.row()['state'],'cancelled')
 def test_invalid_review_cannot_advance_after_restart(self):
  for i in range(2):self.finish(i);r.process(self.c,self.m)
  self.finish(2);p=self.root/'handoffs'/'operation2'/'REVIEW.json';p.write_text('{"verdict":"pass"}')
  r.process(self.c,self.m);self.assertEqual(self.row()['state'],'blocked');self.assertNotEqual(self.c.execute('select state from mission_steps where ordinal=2').fetchone()[0],'done');self.assertFalse(r.process(self.c,self.m)['processed'])
 def test_cto_copies_are_ignored_and_kept_out_of_owner_artifacts(self):
  for i in range(4):
   if i:
    task='t_'+str(i).zfill(8);p=SimpleNamespace(returncode=0,stdout=json.dumps({'bridge_spawned':1}),stderr='')
    with patch.object(r,'native_create',return_value=task),patch.object(r,'promote'),patch.object(r,'dispatch_task'),patch.object(r.subprocess,'run',return_value=p):r.process(self.c,self.m)
   self.finish(i);r.process(self.c,self.m)
  self.finish(4,files_override={'LIVRAISON.md':'Delivered','REVIEW.json':json.dumps({'verdict':'PASS','reason':'Reviewed'}),'total.py':'test copy','test_total.py':'test copy'})
  self.c.execute('insert into mission_artifacts values(?,?,?,?,?)',(self.mid,4,'OPERATOR-REPORT.md','stale','Previous blocker'));self.c.commit()
  result=r.process(self.c,self.m)
  self.assertEqual(result['state'],'review');self.assertEqual(self.row()['state'],'review')
  names={x[0] for x in self.c.execute('select name from mission_artifacts where mission=? and ordinal=4',(self.mid,))}
  self.assertEqual(names,{'LIVRAISON.md','REVIEW.json'})
  summary=self.c.execute('select summary from mission_steps where mission=? and ordinal=4',(self.mid,)).fetchone()[0]
  self.assertIn('2 fichier(s) auxiliaire(s)',summary)
 def test_change_preserves_cancel(self):
  row=self.row();self.c.execute("update mission_flows set state='cancel_requested'");self.c.commit();r.change(self.c,row,'review');self.assertEqual(self.row()['state'],'cancel_requested')
 def test_change_checks_revocation(self):
  row=self.row();self.c.execute('update users set generation=2');self.c.commit();r.change(self.c,row,'review');self.assertEqual(self.row()['state'],'cancel_requested')
 def test_cancel_during_native_create_never_authorizes(self):
  def create(*args):self.c.execute("update mission_flows set state='cancel_requested'");self.c.commit();return 't_12345678'
  with patch.object(r,'native_create',side_effect=create),patch.object(r.subprocess,'run',side_effect=AssertionError('Must never authorize')):r.process(self.c,self.m)
  self.assertEqual(self.row()['state'],'cancelled')
 def test_revoke_during_native_create_never_authorizes(self):
  def create(*args):self.c.execute('update users set active=0');self.c.commit();return 't_12345678'
  with patch.object(r,'native_create',side_effect=create),patch.object(r.subprocess,'run',side_effect=AssertionError('Must never authorize')):r.process(self.c,self.m)
  self.assertIn(self.row()['state'],('cancel_requested','cancelled'))
 def test_uncertain_dispatch_not_retried(self):
  self.c.execute("update mission_steps set task='t_12345678',state='dispatching' where ordinal=0");self.c.commit();self.m.row=lambda t:{'status':'ready'}
  with patch.object(r,'dispatch_task',side_effect=AssertionError('Must never redispatch')):r.process(self.c,self.m)
  self.assertEqual(self.row()['state'],'blocked')
 def test_pre_dispatch_registry_refusal_retries_once_and_records_activity(self):
  task='t_12345678';first=SimpleNamespace(returncode=1,stdout='',stderr='File "/usr/local/sbin/awema-worker-authorize", line 22\nAttributeError: module has no attribute REGISTRY')
  second=SimpleNamespace(returncode=0,stdout='{}',stderr='')
  with patch.object(r,'native_create',return_value=task),patch.object(r,'promote'),patch.object(r,'dispatch_task'),patch.object(r.subprocess,'run',side_effect=[first,second]) as run:
   result=r.process(self.c,self.m)
  self.assertEqual(result['state'],'running');self.assertEqual(run.call_count,2)
  self.assertEqual(self.c.execute("select count(*) from mission_events where event='authorization_retry'").fetchone()[0],1)
  diagnostic=json.loads((self.root/'mission-authorization-error.json').read_text())
  self.assertEqual(diagnostic['retry'],'succeeded');self.assertEqual(diagnostic['attempts'],2)
 def test_pre_dispatch_retry_is_refused_if_grant_already_exists(self):
  task='t_12345678';(self.root/'tasks').mkdir();(self.root/'tasks'/(task+'.json')).write_text('{}')
  diagnostic={'category':'registry','classes':['AttributeError']}
  self.assertFalse(r.safe_authorizer_retry(task,diagnostic))
 def test_pre_dispatch_retry_is_refused_if_worker_state_is_uncertain(self):
  task='t_12345678';(self.root/'states'/'operation.json').write_text(json.dumps({'task':task,'status':'starting'}))
  diagnostic={'category':'registry','classes':['AttributeError']}
  self.assertFalse(r.safe_authorizer_retry(task,diagnostic))
 def test_pre_dispatch_retry_uses_only_allowlisted_failure_categories(self):
  diagnostic={'category':'unclassified','classes':['RuntimeError']}
  self.assertFalse(r.safe_authorizer_retry('t_12345678',diagnostic))
 def test_owner_blocker_explains_exhausted_pre_dispatch_retry(self):
  (self.root/'mission-authorization-error.json').write_text(json.dumps({'task':'t_12345678','category':'registry','classes':['AttributeError'],'retry':'failed','attempts':2,'returncode':1}))
  reason=r.safe_authorizer_blocker('t_12345678')
  self.assertIn('registre de rôles',reason);self.assertIn('AttributeError',reason);self.assertIn('reprise unique a échoué',reason)
  self.assertIsNone(r.safe_authorizer_blocker('t_87654321'))
 def test_owner_blocker_ignores_unclassified_diagnostics(self):
  (self.root/'mission-authorization-error.json').write_text(json.dumps({'task':'t_12345678','category':'unclassified','classes':['RuntimeError']}))
  self.assertIsNone(r.safe_authorizer_blocker('t_12345678'))
 def test_failed_worker_persists_operator_explanation_from_safe_metadata(self):
  ordinal=3;task='t_87654321';op='a'*24;folder=self.root/'runs'/op/'output';folder.mkdir(parents=True)
  names=['SECURITY.md','REVIEW.json']+[f'probe-{i}.txt' for i in range(11)]
  (folder/'RESULT.json').write_text(json.dumps({'status':'completed','summary':'untrusted summary omitted','artifacts':names}))
  (folder/'REVIEW.json').write_text(json.dumps({'verdict':'pass','reason':'x','scope':'x','artifacts':[],'checks':[],'limitations':[]}))
  (folder.parent/'worker.log').write_text('HTTP 403 HTTP 429 request timeout')
  (self.root/'states'/(op+'.json')).write_text(json.dumps({'task':task,'operation':op,'started':time.time(),'status':'failed','outcome':'blocked','error':'RuntimeError','exit_code':1}))
  self.c.execute("update mission_steps set state='done' where mission=? and ordinal<?",(self.mid,ordinal))
  self.c.execute("update mission_steps set task=?,state='dispatching' where mission=? and ordinal=?",(task,self.mid,ordinal));self.c.commit()
  result=r.process(self.c,self.m)
  self.assertTrue(result['operator_action_required']);self.assertEqual(self.row()['state'],'blocked')
  reason=self.row()['blocker'];self.assertIn('code de sortie 1',reason);self.assertIn('13 livrables',reason)
  self.assertIn('format REVIEW.json invalide',reason);self.assertIn('HTTP 403, 429',reason);self.assertIn('délai d’attente',reason)
  artifact=self.c.execute("select content from mission_artifacts where mission=? and name='OPERATOR-REPORT.md'",(self.mid,)).fetchone()
  self.assertIsNotNone(artifact);self.assertNotIn('untrusted summary',artifact[0])
  self.assertFalse(r.process(self.c,self.m)['processed'])
 def test_missing_result_names_exact_handoff_failure_without_raw_output(self):
  ordinal=1;task='t_87654321';op='b'*24;folder=self.root/'runs'/op/'output';folder.mkdir(parents=True)
  (folder/'partial.txt').write_text('private raw output must not appear')
  (self.root/'states'/(op+'.json')).write_text(json.dumps({'task':task,'operation':op,'started':time.time(),'status':'failed','outcome':'blocked','error':'RuntimeError','exit_code':1}))
  self.c.execute("update mission_steps set state='done' where mission=? and ordinal<?",(self.mid,ordinal))
  self.c.execute("update mission_steps set task=?,state='dispatching' where mission=? and ordinal=?",(task,self.mid,ordinal));self.c.commit()
  result=r.process(self.c,self.m);reason=self.row()['blocker']
  self.assertEqual(result['reason_code'],'worker_failed');self.assertIn('code de sortie 1',reason)
  self.assertIn('RESULT.json absent',reason);self.assertIn('1 fichier(s) partiel(s)',reason)
  self.assertIn('total.py',reason);self.assertNotIn('private raw output',reason)
 def test_runner_blocks_at_exact_ten_mission_capacity(self):
  now=time.time()
  for i in range(9):
   mid='f_'+format(i,'024x');digest=hashlib.sha256(json.dumps(['objective','criteria',f.PLAN,'awema-internal-sandbox'],sort_keys=True).encode()).hexdigest()
   self.c.execute('insert into mission_flows values(?,?,?,?,?,?,?,?,?,?,?)',(mid,'a',1,'objective','criteria',digest,'delivered',now,now,now,''))
  self.c.commit();result=r.process(self.c,self.m)
  self.assertEqual(result['state'],'blocked');self.assertIn('10 missions sur 24 h',self.row()['blocker'])
  self.assertFalse(any(p.name.endswith('.json') for p in (self.root/'states').iterdir()))
 def test_worker_over_deadline_is_visible_and_not_retried(self):
  task='t_12345678';op='stale-operation';started=time.time()-r.WORKER_STALE_SECONDS-1
  state={'task':task,'operation':op,'started':started,'status':'running','cancel':False}
  (self.root/'states'/(op+'.json')).write_text(json.dumps(state))
  self.c.execute("update mission_steps set task=?,state='dispatching' where ordinal=0",(task,));self.c.commit()
  self.m.row=lambda t:{'status':'running'}
  result=r.process(self.c,self.m)
  self.assertEqual(result['state'],'blocked');self.assertEqual(result['reason'],'worker_timeout')
  self.assertIn('7 minutes',self.row()['blocker']);self.assertEqual(self.row()['state'],'blocked')
  self.assertTrue(json.loads((self.root/'states'/(op+'.json')).read_text())['cancel'])
  self.assertFalse(r.process(self.c,self.m)['processed'])
 def test_worker_stuck_in_starting_is_visible(self):
  task='t_12345678';op='stale-starting';path=self.root/'states'/(op+'.json')
  path.write_text(json.dumps({'task':task,'operation':op,'status':'starting','cancel':False}))
  old=time.time()-r.WORKER_STALE_SECONDS-1;os.utime(path,(old,old))
  self.c.execute("update mission_steps set task=?,state='dispatching' where mission=? and ordinal=0",(task,self.mid));self.c.commit()
  result=r.process(self.c,self.m)
  self.assertEqual(result['reason'],'worker_timeout');self.assertEqual(self.row()['state'],'blocked')
  self.assertTrue(json.loads(path.read_text())['cancel'])
 def test_missing_worker_state_with_native_running_blocks_after_deadline(self):
  task='t_12345678';old=time.time()-r.WORKER_STALE_SECONDS-1
  self.c.execute("update mission_flows set updated=? where id=?",(old,self.mid))
  self.c.execute("update mission_steps set task=?,state='dispatching' where mission=? and ordinal=0",(task,self.mid));self.c.commit()
  self.m.row=lambda t:{'status':'in_progress'}
  result=r.process(self.c,self.m)
  self.assertEqual(result['state'],'blocked');self.assertEqual(result['reason'],'worker_state_missing')
  self.assertIn('aucune opération du worker',self.row()['blocker'])
  self.assertFalse(list((self.root/'states').glob('*.json')))
  self.assertFalse(r.process(self.c,self.m)['processed'])
 def test_missing_worker_state_recent_native_running_stays_active(self):
  task='t_12345678';self.c.execute("update mission_steps set task=?,state='dispatching' where mission=? and ordinal=0",(task,self.mid));self.c.commit()
  self.m.row=lambda t:{'status':'running'}
  self.assertEqual(r.process(self.c,self.m)['state'],'running')
  self.assertEqual(self.row()['state'],'running')
 def test_capacity_wait_has_visible_reason_and_transition_events(self):
  (self.root/'states'/'other.json').write_text(json.dumps({'status':'running'}))
  self.assertEqual(r.process(self.c,self.m)['state'],'waiting_capacity')
  self.assertEqual(self.row()['blocker'],r.CAPACITY_WAIT_REASON)
  self.assertEqual(self.c.execute('select count(*) from mission_events where event=?',('waiting_capacity',)).fetchone()[0],1)
  r.process(self.c,self.m)
  self.assertEqual(self.c.execute('select count(*) from mission_events where event=?',('waiting_capacity',)).fetchone()[0],1)
  r.capacity_wait(self.c,self.row(),False)
  self.assertEqual(self.row()['blocker'],'')
  self.assertEqual(self.c.execute('select count(*) from mission_events where event=?',('capacity_available',)).fetchone()[0],1)
 def test_projection_failure_does_not_prevent_cancel(self):
  self.c.execute("update mission_flows set state='cancel_requested'");self.c.execute("update mission_steps set task='t_12345678',state='dispatching' where ordinal=0");self.c.commit()
  (self.root/'states/operation.json').write_text(json.dumps({'operation':'operation','task':'t_12345678','started':1,'status':'running'}))
  self.m.row=lambda t:(_ for _ in ()).throw(RuntimeError('Native DB unavailable'))
  with patch.object(r,'export_board',side_effect=RuntimeError('Projection failed')):r.refresh_board(self.c,self.m)
  self.assertEqual(r.process(self.c,self.m)['state'],'cancel_requested')
  self.assertTrue(json.loads((self.root/'states/operation.json').read_text())['cancel'])
if __name__=='__main__':unittest.main()
