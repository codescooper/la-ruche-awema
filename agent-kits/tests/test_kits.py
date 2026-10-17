import ast,copy,importlib.util,json,sqlite3,sys,types,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
import kit_loader as K
import design_tokens as D
RAW=(ROOT/'bundle/catalog.json').read_bytes();PIN=K.sha(RAW);CAT=json.loads(RAW)
def payload(role):return {n:(ROOT/'bundle'/n).read_bytes() for n in (*K.COMMON,*(f'roles/{role}/{f}' for f in K.ROLE_FILES))}
def loaded(role='dev',mode='native'):return K.validate_bundle_bytes(RAW,PIN,role,payload(role),mode=mode)
def enc(v):return (json.dumps(v,ensure_ascii=False)+'\n').encode()
def inspected(kit,prompt):
 uid={'cto':10000,'pm':25001,'dev':25002,'qa':25003,'security':25004,'ops':25005,'designer':25006,'assa':25007,'cl-producer':25008}[kit.role]
 snap={'source':'/root/fixture/run/kit','destination':'/kit','readonly':True,'files_sha256':{'catalog.json':PIN,**kit.file_hashes}}
 info={'Image':'sha256:'+'a'*64,'Config':{'User':f'{uid}:{uid}','Entrypoint':['/opt/hermes/.venv/bin/hermes'],'Cmd':['--cli','--toolsets','terminal,file','chat','-q',prompt]},'Mounts':[{'Type':'bind','Source':snap['source'],'Destination':'/kit','RW':False}]}
 ctx={'task':'t_1234abcd','run':7,'operation':'a'*24,'uid':uid,'image':info['Image']}
 return snap,info,ctx
class KitTests(unittest.TestCase):
 def test_twelve_real_mode_profiles_and_each_actual_file(self):
  self.assertEqual(len(K.NATIVE_ROLES),9);self.assertEqual(len(K.CONVERSATION_ROLES),3)
  for role in sorted(K.NATIVE_ROLES|K.CONVERSATION_ROLES):
   kit=loaded(role,'native' if role in K.NATIVE_ROLES else 'conversation-only');self.assertEqual(len(kit.files),5)
   self.assertTrue(all(K.sha(raw)==kit.file_hashes[name] for name,raw in kit.files))
 def test_catalog_pins_actual_loader(self):self.assertEqual(CAT['loader_sha256'],K.sha((ROOT/'kit_loader.py').read_bytes()))
 def test_wrong_pin_refused(self):
  with self.assertRaisesRegex(K.KitError,'catalog_pin'):K.validate_bundle_bytes(RAW,'0'*64,'dev',payload('dev'))
 def test_duplicate_json_key_refused(self):
  raw=b'{"schema":1,"schema":2}'
  with self.assertRaisesRegex(K.KitError,'duplicate_json_key'):K.validate_bundle_bytes(raw,K.sha(raw),'dev',{})
 def test_modes_cannot_be_promoted(self):
  for role,mode in [('finance','native'),('assistant','native'),('dev','conversation-only'),('../dev','native')]:
   with self.assertRaisesRegex(K.KitError,'role_mode_denied'):K.validate_bundle_bytes(RAW,PIN,role,{},mode=mode)
 def test_missing_extra_changed_or_empty_file_refused(self):
  for change in ['missing','extra','changed','empty']:
   p=payload('dev');name=next(iter(p))
   if change=='missing':p.pop(name)
   elif change=='extra':p['.env']=b'SYNTHETIC-NOT-A-CREDENTIAL'
   else:p[name]=b'changed' if change=='changed' else b''
   with self.assertRaises(K.KitError):K.validate_bundle_bytes(RAW,PIN,'dev',p)
 def test_manifest_traversal_and_registry_change_refused(self):
  for mutate in [lambda c:c['kits']['dev']['files'].update({'../../outside.md':'0'*64}),lambda c:c['native_roles'].append('admin')]:
   c=copy.deepcopy(CAT);mutate(c);raw=enc(c)
   with self.assertRaises(K.KitError):K.validate_bundle_bytes(raw,K.sha(raw),'dev',payload('dev'))
 def test_conversation_tool_invention_refused_even_with_new_hash(self):
  p=payload('finance');name='roles/finance/TOOLS.json';tools=json.loads(p[name]);tools['available']=['terminal'];p[name]=enc(tools);c=copy.deepcopy(CAT);c['kits']['finance']['files'][name]=K.sha(p[name]);raw=enc(c)
  with self.assertRaisesRegex(K.KitError,'toolset_changed'):K.validate_bundle_bytes(raw,K.sha(raw),'finance',p,mode='conversation-only')
 def test_runtime_prompt_includes_real_selected_bytes_only(self):
  kit=loaded();prompt=K.kit_prompt('Operator baseline',kit)
  for name,raw in kit.files:self.assertIn(raw.decode(),prompt);self.assertIn(K.sha(raw),prompt)
  self.assertNotIn('roles/finance/METHOD.md',prompt);self.assertIn('Methods are not permissions',prompt)
 def test_prompt_size_bounded(self):
  with self.assertRaisesRegex(K.KitError,'prompt_size'):K.kit_prompt('x'*K.MAX_KIT,loaded())
 def test_actual_config_binding_receipt_is_bounded_and_honest(self):
  kit=loaded();prompt=K.kit_prompt('Operator baseline',kit);snap,info,ctx=inspected(kit,prompt);r=K.worker_binding_receipt(kit,snap,prompt,info,ctx)
  self.assertEqual(r['prompt_sha256'],K.sha(prompt.encode()));self.assertTrue(r['readonly_mount_confirmed']);self.assertFalse(r['model_comprehension_verified']);self.assertFalse(r['business_quality_verified']);self.assertNotIn('content',r)
 def test_missing_kit_cannot_pass_as_configured_prompt(self):
  kit=loaded();snap,info,ctx=inspected(kit,'No kit present')
  with self.assertRaisesRegex(K.KitError,'kit_prompt_missing'):K.worker_binding_receipt(kit,snap,'No kit present',info,ctx)
 def test_wrong_image_uid_prompt_entrypoint_toolset_mount_refused(self):
  kit=loaded();prompt=K.kit_prompt('Base',kit)
  mutations=[lambda i:i.update(Image='sha256:'+'b'*64),lambda i:i['Config'].update(User='0:0'),lambda i:i['Config']['Cmd'].__setitem__(-1,'wrong'),lambda i:i['Config'].update(Entrypoint=['sh']),lambda i:i['Config']['Cmd'].__setitem__(2,'terminal,file,network'),lambda i:i['Mounts'][0].update(RW=True),lambda i:i['Mounts'][0].update(Source='/other'),lambda i:i['Mounts'].append(dict(i['Mounts'][0]))]
  for mutate in mutations:
   snap,info,ctx=inspected(kit,prompt);mutate(info)
   with self.assertRaises(K.KitError):K.worker_binding_receipt(kit,snap,prompt,info,ctx)
 def test_invalid_native_identity_refused(self):
  kit=loaded();prompt=K.kit_prompt('Base',kit)
  for key,value in [('task','../id'),('run',True),('uid',0),('operation','bad'),('image','latest')]:
   snap,info,ctx=inspected(kit,prompt);ctx[key]=value
   with self.assertRaises(K.KitError):K.worker_binding_receipt(kit,snap,prompt,info,ctx)
 def test_conversation_injects_actual_system_bytes_preserves_history_and_no_tools(self):
  kit=loaded('accounting','conversation-only');request={'messages':[{'role':'system','content':'private-context-fixture'},{'role':'user','content':'question'}],'max_tokens':1200};before=copy.deepcopy(request);actual,receipt=K.inject_conversation_kit(request,kit)
  self.assertEqual(request,before);self.assertEqual(actual['messages'][1:],before['messages'][1:]);self.assertTrue(actual['messages'][0]['content'].endswith('private-context-fixture'))
  for _,raw in kit.files:self.assertIn(raw.decode(),actual['messages'][0]['content'])
  self.assertNotIn('private-context-fixture',json.dumps(receipt));self.assertFalse(receipt['tools_supplied'])
 def test_native_kit_or_tool_request_cannot_be_used_for_no_tool_conversation(self):
  for kit,request in [(loaded(),{'messages':[{'role':'system','content':'test'}]}),(loaded('finance','conversation-only'),{'messages':[{'role':'system','content':'test'}],'tools':[]})]:
   with self.assertRaises(K.KitError):K.inject_conversation_kit(request,kit)
 def test_finance_method_records_the_known_double_counting_failure(self):
  text=dict(loaded('assa').files)['roles/assa/METHOD.md'].decode();self.assertIn('Budget ≠ financement',text);self.assertIn('double comptage',text);self.assertIn('valeurs ET relire la narration',text);self.assertIn('revue humaine',text)
 def test_designer_does_not_claim_unavailable_research_or_visual_tools(self):
  text=dict(loaded('designer').files)['roles/designer/METHOD.md'].decode();self.assertIn('Sans outil de recherche',text);self.assertIn('ne jamais inventer',text);self.assertIn('capacité visuelle réellement disponible',text)

def tokens():return {'schema':'awema-design-tokens-v1','colors':{'background':'#171815','surface':'#20221c','text':'#f5f5ed','muted':'#d1d4c5','accent':'#ffff00','accent_text':'#171815'},'typography':{'heading':'system-ui, sans-serif','body':'system-ui, sans-serif'},'spacing':[4,8,16,24,48,64],'radius':{'control':8,'card':16},'breakpoints':{'mobile':390,'desktop':1440},'motion':{'reduced_motion':'respect-prefers-reduced-motion','duration_ms':{'short':100,'standard':200,'long':400}}}
class DesignTests(unittest.TestCase):
 def test_valid_tokens_measure_not_certify(self):self.assertFalse(D.validate_design_tokens(tokens())['rendered_visual_quality_verified'])
 def test_bad_contrast_and_syntax_refused(self):
  for mutate in [lambda v:v['colors'].update(text='#171815'),lambda v:v.update(schema='other'),lambda v:v['typography'].update(body='url(https://example.invalid)'),lambda v:v.update(spacing=[4,4,8,16]),lambda v:v['breakpoints'].update(mobile=True),lambda v:v['radius'].update(card=float('nan')),lambda v:v['motion'].update(reduced_motion='ignore')]:
   v=tokens();mutate(v)
   with self.assertRaises(D.TokenError):D.validate_design_tokens(v)

class ConversationPathTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  source=(ROOT/'candidate-v4/model_worker.py').read_text(encoding='utf-8');node=next(n for n in ast.parse(source).body if isinstance(n,ast.FunctionDef) and n.name=='process');cls.function=compile(ast.Module(body=[node],type_ignores=[]),'<local-candidate-process>','exec')
 def fixture(self,role):
  c=sqlite3.connect(':memory:');c.row_factory=sqlite3.Row;c.execute('create table jobs(id text,agent text,context text,prompt text,state text,response text,created int)');c.execute('insert into jobs values(?,?,?,?,?,?,?)',('j_fixture',role,json.dumps({'history':[{'role':'user','content':'previous fixture'}]}),'question','queued',None,1));c.commit();requests=[]
  fake=types.SimpleNamespace(**{n:getattr(K,n) for n in ['CONVERSATION_ROLES','NATIVE_ROLES','KitError','inject_conversation_kit','inject_advisory_kit']},load_role_kit=lambda root,pin,role,mode='native':loaded(role,mode))
  scope={'json':json,'allowed':lambda c,r:True,'KIT':fake,'CAPABILITY_KITS':'unused-fixture','CAPABILITY_CATALOG_SHA256':PIN};exec(self.function,scope)
  return c,requests,scope,fake
 def test_three_actual_profile_requests_receive_kit_and_return_metadata(self):
  for role in sorted(K.CONVERSATION_ROLES):
   c,requests,scope,_=self.fixture(role)
   def provider(request):requests.append(request);return 'Réponse fictive'
   result=scope['process'](c,provider,lambda r:'Existing role\nMANDAT COURANT ET PROJET AUTORISE :\n'+r['context']);self.assertEqual(result['state'],'done');self.assertEqual(result['capability_kit']['role'],role);self.assertEqual(len(requests),1)
   self.assertIn(dict(loaded(role,'conversation-only').files)[f'roles/{role}/METHOD.md'].decode(),requests[0]['messages'][0]['content']);self.assertEqual(requests[0]['messages'][1],{'role':'user','content':'previous fixture'});self.assertNotIn('tools',requests[0]);c.close()
 def test_pin_failure_calls_no_provider_and_explains_code(self):
  c,requests,scope,fake=self.fixture('finance');fake.load_role_kit=lambda *a,**k:(_ for _ in ()).throw(K.KitError('catalog_pin'));result=scope['process'](c,lambda r:requests.append(r));self.assertEqual(requests,[]);self.assertEqual(result['state'],'failed');self.assertEqual(result['error_code'],'capability_kit_catalog_pin');c.close()
 def test_all_nine_native_roles_receive_advisory_methods_in_real_process(self):
  for role in sorted(K.NATIVE_ROLES):
   c,requests,scope,_=self.fixture(role);result=scope['process'](c,lambda r:(requests.append(r) or 'Conseil fictif'));receipt=result['capability_kit'];self.assertEqual(receipt['schema'],'awema-advisory-kit-loading-v1');self.assertFalse(receipt['execution_authorized']);self.assertFalse(receipt['tools_supplied']);text=requests[0]['messages'][0]['content'];self.assertIn('MODE PRIORITAIRE : CONSEIL',text);self.assertNotIn('BEGIN KIT FILE roles/'+role+'/TOOLS.json',text);self.assertEqual(len(receipt['files_sha256']),4)
   for name,raw in loaded(role).files:
    if not name.endswith('/TOOLS.json'):self.assertIn(raw.decode(),text);self.assertEqual(receipt['files_sha256'][name],K.sha(raw))
   c.close()
 def test_revoked_after_provider_cannot_store_answer(self):
  c,requests,scope,_=self.fixture('assistant');calls=[];scope['allowed']=lambda c,r:(calls.append(1) or len(calls)==1);result=scope['process'](c,lambda r:'fixture response');self.assertEqual(result['state'],'cancelled');self.assertIsNone(c.execute('select response from jobs').fetchone()[0]);c.close()

class SourceBoundaryTests(unittest.TestCase):
 def functions(self,path):return {n.name:ast.dump(n,include_attributes=False) for n in ast.parse(path.read_text(encoding='utf-8')).body if isinstance(n,ast.FunctionDef)}
 def test_native_claim_authorization_and_completion_guards_preserved(self):
  old=self.functions(ROOT.parent/'baseline/worker_launcher.py');new=self.functions(ROOT/'candidate-v4/worker_launcher.py')
  for name in ['check_claim','digest','native','expire','validate_result','worker_profile_config','worker_prompt']:self.assertEqual(old[name],new[name],name)
 def test_conversation_authorization_and_provider_not_changed(self):
  old=self.functions(ROOT.parent/'baseline/model_worker.py');new=self.functions(ROOT/'candidate-v4/model_worker.py')
  for name in ['allowed','provider','role_context','main']:self.assertEqual(old[name],new[name],name)

if __name__=='__main__':unittest.main(verbosity=2)
