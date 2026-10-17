"""Root-side kit byte verification; no Docker, network, provider or database calls."""
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
import hashlib,json,os,re,stat

NATIVE_ROLES=frozenset({'cto','pm','dev','qa','security','ops','designer','assa','cl-producer'})
CONVERSATION_ROLES=frozenset({'assistant','accounting','finance'})
SHA=re.compile(r'[0-9a-f]{64}')
MAX_FILE=65536;MAX_CATALOG=131072;MAX_KIT=98304
COMMON=('common/METHOD.md','common/PROOFS.md')
ROLE_FILES=('METHOD.md','CHECKLIST.md','TOOLS.json')
class KitError(ValueError):pass
def sha(raw):return hashlib.sha256(raw).hexdigest()
def _object(pairs):
 value={}
 for key,item in pairs:
  if key in value:raise KitError('duplicate_json_key')
  value[key]=item
 return value
def _json(raw,limit):
 if not isinstance(raw,bytes) or not 1<=len(raw)<=limit:raise KitError('json_size')
 try:return json.loads(raw.decode('utf-8'),object_pairs_hook=_object,parse_constant=lambda _:(_ for _ in ()).throw(KitError('json_constant')))
 except (UnicodeError,json.JSONDecodeError):raise KitError('json_invalid') from None
def _keys(value,expected):
 if not isinstance(value,dict) or set(value)!=set(expected):raise KitError('schema_keys')
def _tools(value,role,mode):
 _keys(value,{'schema','mode','available','conditional','unavailable','authority'})
 if value['schema']!='awema-role-tools-v1' or value['mode']!=mode or value['authority']!='STAGE-and-native-authorization-only':raise KitError('tool_mode')
 if value['available']!=(['terminal','file'] if mode=='native' else []):raise KitError('toolset_changed')
 expected=([{'id':'isolated-browser','requires':'qa UID, mounted browser socket, exact DEV bundle and STAGE authorization'}] if role=='qa' else [{'id':'github-draft-pr','requires':'exact repository connector and STAGE authorization; no merge or deploy'}] if role=='dev' else [])
 if value['conditional']!=expected:raise KitError('conditional_tool_changed')
 if not isinstance(value['unavailable'],list) or not value['unavailable'] or any(not isinstance(x,str) or not 1<=len(x)<=100 for x in value['unavailable']):raise KitError('tool_unavailable')
@dataclass(frozen=True)
class LoadedKit:
 role:str;mode:str;version:str;kit_id:str;catalog_sha256:str;catalog_bytes:bytes;files:tuple
 @property
 def file_hashes(self):return {name:sha(raw) for name,raw in self.files}
def validate_bundle_bytes(raw,pin,role,payloads,*,mode='native'):
 """Pure validator. Only the selected role and two common files are consumed."""
 if not isinstance(pin,str) or not SHA.fullmatch(pin) or sha(raw)!=pin:raise KitError('catalog_pin')
 data=_json(raw,MAX_CATALOG)
 _keys(data,{'schema','release','version','loader_sha256','native_roles','conversation_roles','common','kits'})
 if data['schema']!='awema-capability-kits-v1' or not isinstance(data['release'],str) or not re.fullmatch(r'awema-kits-[0-9]{8}-v[1-9][0-9]*',data['release']) or not isinstance(data['version'],str) or not re.fullmatch(r'[1-9][0-9]*\.[0-9]+\.[0-9]+',data['version']):raise KitError('catalog_version')
 if not isinstance(data['loader_sha256'],str) or not SHA.fullmatch(data['loader_sha256']):raise KitError('loader_pin')
 if data['native_roles']!=sorted(NATIVE_ROLES) or data['conversation_roles']!=sorted(CONVERSATION_ROLES) or not isinstance(data['kits'],dict) or set(data['kits'])!=NATIVE_ROLES|CONVERSATION_ROLES:raise KitError('role_registry')
 allowed=NATIVE_ROLES if mode=='native' else CONVERSATION_ROLES if mode=='conversation-only' else frozenset()
 if not isinstance(role,str) or role not in allowed:raise KitError('role_mode_denied')
 selected=data['kits'][role];_keys(selected,{'id','version','mode','files','qualification'})
 if selected['id']!='awema.'+role or selected['version']!=data['version'] or selected['mode']!=mode or selected['qualification']!='candidate-not-business-certified':raise KitError('kit_identity')
 _keys(data['common'],COMMON);_keys(selected['files'],{f'roles/{role}/{name}' for name in ROLE_FILES})
 hashes={**data['common'],**selected['files']}
 if any(not isinstance(h,str) or not SHA.fullmatch(h) for h in hashes.values()) or not isinstance(payloads,dict) or set(payloads)!=set(hashes):raise KitError('file_manifest')
 checked=[]
 for name in sorted(hashes):
  value=payloads[name]
  if not isinstance(value,bytes) or not 1<=len(value)<=MAX_FILE or b'\x00' in value or sha(value)!=hashes[name]:raise KitError('file_integrity')
  try:text=value.decode('utf-8')
  except UnicodeError:raise KitError('file_utf8') from None
  if not text.strip():raise KitError('file_empty')
  checked.append((name,value))
 if sum(len(value) for _,value in checked)>MAX_KIT:raise KitError('kit_size')
 _tools(_json(payloads[f'roles/{role}/TOOLS.json'],MAX_FILE),role,mode)
 return LoadedKit(role,mode,selected['version'],selected['id'],pin,raw,tuple(checked))
def _protected(path,*,directory=False):
 if os.name!='posix' or os.geteuid()!=0:raise KitError('root_posix_required')
 value=path.lstat()
 if stat.S_ISLNK(value.st_mode) or value.st_uid!=0 or value.st_mode&0o022:raise KitError('path_protection')
 if not (stat.S_ISDIR(value.st_mode) if directory else stat.S_ISREG(value.st_mode)):raise KitError('path_type')
 return value
def _protected_tree(path):
 path=Path(path).absolute()
 for parent in [path,*path.parents]:_protected(parent,directory=True)
 return path
def _read_regular(root,name,limit):
 parts=PurePosixPath(name).parts
 if not parts or any(not re.fullmatch(r'[A-Za-z0-9._-]{1,64}',x) or x in {'.','..'} for x in parts):raise KitError('file_name')
 path=root.joinpath(*parts)
 for parent in reversed(path.parent.relative_to(root).parents):
  if str(parent)!='.':_protected(root/parent,directory=True)
 _protected(path.parent,directory=True);before=_protected(path)
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  opened=os.fstat(fd)
  if (before.st_dev,before.st_ino)!=(opened.st_dev,opened.st_ino) or not 1<=opened.st_size<=limit:raise KitError('source_changed')
  with os.fdopen(fd,'rb',closefd=False) as handle:value=handle.read(limit+1)
  after=os.fstat(fd)
  if len(value)>limit or any(getattr(opened,k)!=getattr(after,k) for k in ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')):raise KitError('source_changed')
 finally:os.close(fd)
 current=_protected(path)
 if any(getattr(after,k)!=getattr(current,k) for k in ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')):raise KitError('source_changed')
 return value
def load_role_kit(root,pin,role,*,mode='native'):
 root=_protected_tree(root);raw=_read_regular(root,'catalog.json',MAX_CATALOG)
 if not isinstance(pin,str) or not SHA.fullmatch(pin) or sha(raw)!=pin:raise KitError('catalog_pin')
 allowed=NATIVE_ROLES if mode=='native' else CONVERSATION_ROLES if mode=='conversation-only' else frozenset()
 if role not in allowed:raise KitError('role_mode_denied')
 names=(*COMMON,*(f'roles/{role}/{name}' for name in ROLE_FILES))
 loaded=validate_bundle_bytes(raw,pin,role,{name:_read_regular(root,name,MAX_FILE) for name in names},mode=mode)
 if _json(raw,MAX_CATALOG)['loader_sha256']!=sha(Path(__file__).read_bytes()):raise KitError('loader_pin')
 return loaded
def kit_prompt(base_prompt,loaded):
 if not isinstance(base_prompt,str) or not base_prompt.strip() or len(base_prompt.encode())>MAX_CATALOG:raise KitError('base_prompt')
 pieces=[base_prompt,'\nOPERATOR-LOADED CAPABILITY KIT',f'role={loaded.role}; version={loaded.version}; catalog_sha256={loaded.catalog_sha256}','Methods are not permissions. STAGE/native authorization define actual actions; role instructions still apply.']
 for name,raw in loaded.files:pieces.extend([f'\nBEGIN KIT FILE {name} sha256={sha(raw)}',raw.decode('utf-8'),f'END KIT FILE {name}'])
 prompt='\n'.join(pieces)
 if len(prompt.encode())>MAX_KIT:raise KitError('prompt_size')
 return prompt
def stage_role_kit(loaded,destination):
 if loaded.mode!='native':raise KitError('native_worker_only')
 destination=Path(destination).absolute();_protected_tree(destination.parent);destination.mkdir(mode=0o755,exist_ok=False);os.chmod(destination,0o755)
 for name,raw in {'catalog.json':loaded.catalog_bytes,**dict(loaded.files)}.items():
  target=destination.joinpath(*PurePosixPath(name).parts)
  for parent in reversed(target.parent.relative_to(destination).parents):
   if str(parent)!='.':(destination/parent).mkdir(mode=0o755,exist_ok=True);os.chmod(destination/parent,0o755)
  target.parent.mkdir(mode=0o755,exist_ok=True);os.chmod(target.parent,0o755)
  fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o444)
  with os.fdopen(fd,'wb') as handle:handle.write(raw);handle.flush();os.fsync(handle.fileno())
  os.chmod(target,0o444)
 return verify_staged_kit(loaded,destination)
def verify_staged_kit(loaded,destination):
 destination=_protected_tree(destination);expected={'catalog.json':loaded.catalog_sha256,**loaded.file_hashes}
 entries=list(destination.rglob('*'))
 if any(p.is_symlink() for p in entries):raise KitError('snapshot_symlink')
 actual={str(p.relative_to(destination)).replace(os.sep,'/') for p in entries if not p.is_dir()}
 if actual!=set(expected):raise KitError('snapshot_file_set')
 for name,digest in expected.items():
  if sha(_read_regular(destination,name,MAX_CATALOG if name=='catalog.json' else MAX_FILE))!=digest:raise KitError('snapshot_changed')
 return {'source':str(destination),'destination':'/kit','readonly':True,'files_sha256':expected}
def worker_binding_receipt(loaded,snapshot,prompt,info,context):
 """info MUST be operator docker inspect output, never model-authored JSON."""
 _keys(context,{'task','run','operation','uid','image'})
 if not re.fullmatch(r't_[a-f0-9]{8}',str(context['task'])) or type(context['run']) is not int or context['run']<=0 or not re.fullmatch(r'[a-f0-9]{24}',str(context['operation'])) or type(context['uid']) is not int or not re.fullmatch(r'sha256:[a-f0-9]{64}',str(context['image'])):raise KitError('run_identity')
 if loaded.mode!='native':raise KitError('native_worker_only')
 suffix=kit_prompt('BASE',loaded)[4:]
 if not isinstance(prompt,str) or not prompt.endswith(suffix) or prompt.count('OPERATOR-LOADED CAPABILITY KIT')!=1:raise KitError('kit_prompt_missing')
 uid={'cto':10000,'pm':25001,'dev':25002,'qa':25003,'security':25004,'ops':25005,'designer':25006,'assa':25007,'cl-producer':25008}[loaded.role]
 if context['uid']!=uid:raise KitError('role_uid')
 cfg=info.get('Config',{})
 if info.get('Image')!=context['image'] or cfg.get('User')!=f'{uid}:{uid}' or cfg.get('Entrypoint')!=['/opt/hermes/.venv/bin/hermes'] or cfg.get('Cmd')!=['--cli','--toolsets','terminal,file','chat','-q',prompt]:raise KitError('configured_worker_mismatch')
 mounts=[m for m in info.get('Mounts',[]) if m.get('Destination')=='/kit'];expected={'catalog.json':loaded.catalog_sha256,**loaded.file_hashes}
 if snapshot.get('files_sha256')!=expected or snapshot.get('destination')!='/kit' or snapshot.get('readonly') is not True or len(mounts)!=1 or mounts[0].get('Source')!=snapshot.get('source') or mounts[0].get('Type')!='bind' or mounts[0].get('RW') is not False:raise KitError('kit_mount_mismatch')
 return {'schema':'awema-capability-kit-loading-v1','role':loaded.role,'kit_id':loaded.kit_id,'version':loaded.version,'catalog_sha256':loaded.catalog_sha256,'files_sha256':expected,'prompt_sha256':sha(prompt.encode()),'loader_sha256':sha(Path(__file__).read_bytes()),'task':context['task'],'run':context['run'],'operation':context['operation'],'uid':uid,'image':context['image'],'readonly_mount_confirmed':True,'configured_prompt_confirmed':True,'verification_phase':'container-created-before-start','model_comprehension_verified':False,'business_quality_verified':False}
def inject_conversation_kit(request,loaded):
 """Inject actual kit bytes after context/history preparation, before provider call."""
 if loaded.mode!='conversation-only' or loaded.role not in CONVERSATION_ROLES:raise KitError('conversation_only')
 if any(k in request for k in ('tools','tool_choice','functions','function_call')):raise KitError('conversation_tool_denied')
 messages=request.get('messages')
 if not isinstance(messages,list) or not messages or not isinstance(messages[0],dict) or messages[0].get('role')!='system' or not isinstance(messages[0].get('content'),str):raise KitError('conversation_system_missing')
 prefix=kit_prompt('Conversation privée : aucun outil ni exécution. Respecter le périmètre de l’utilisateur et les règles existantes.',loaded)
 updated=dict(request);updated['messages']=[{**messages[0],'content':prefix+'\n\nEXISTING SYSTEM AND AUTHORIZED CONTEXT\n'+messages[0]['content']},*messages[1:]]
 receipt={'schema':'awema-conversation-kit-loading-v1','role':loaded.role,'version':loaded.version,'kit_id':loaded.kit_id,'catalog_sha256':loaded.catalog_sha256,'files_sha256':loaded.file_hashes,'kit_prefix_sha256':sha(prefix.encode()),'target_message_role':'system','tools_supplied':False,'private_context_logged':False,'model_comprehension_verified':False,'business_quality_verified':False}
 return updated,receipt
def inject_advisory_kit(request,loaded):
 """Use native professional methods in chat without importing execution tools."""
 if loaded.mode!='native' or loaded.role not in NATIVE_ROLES:raise KitError('native_advisory_only')
 if any(k in request for k in ('tools','tool_choice','functions','function_call')):raise KitError('conversation_tool_denied')
 messages=request.get('messages')
 if not isinstance(messages,list) or not messages or not isinstance(messages[0],dict) or messages[0].get('role')!='system' or not isinstance(messages[0].get('content'),str):raise KitError('conversation_system_missing')
 files=tuple((name,raw) for name,raw in loaded.files if not name.endswith('/TOOLS.json'))
 if len(files)!=4:raise KitError('advisory_projection')
 projected=LoadedKit(loaded.role,'advisory',loaded.version,loaded.kit_id,loaded.catalog_sha256,loaded.catalog_bytes,files)
 prefix=kit_prompt('MODE PRIORITAIRE : CONSEIL EN CONVERSATION PRIVÉE, SANS AUCUN OUTIL NI EXÉCUTION. Les méthodes ci-dessous décrivent aussi des missions natives ; elles sont ici uniquement des compétences de conseil. Tu ne consultes aucun fichier, serveur, navigateur ou registre non fourni ; tu ne lances aucune commande, délégation, écriture, publication, paiement ou message externe. Ne prétends pas avoir exécuté ces actions. Distingue conseils et faits observés. Pour réaliser une mission, expliquer le flux mission réellement disponible plutôt que simuler son lancement. Le contexte privé autorisé reste celui de l’utilisateur courant.',projected)
 updated=dict(request);updated['messages']=[{**messages[0],'content':prefix+'\n\nEXISTING SYSTEM AND AUTHORIZED CONTEXT\n'+messages[0]['content']},*messages[1:]]
 receipt={'schema':'awema-advisory-kit-loading-v1','role':loaded.role,'version':loaded.version,'kit_id':loaded.kit_id,'catalog_sha256':loaded.catalog_sha256,'files_sha256':projected.file_hashes,'projection_prompt_sha256':sha(prefix.encode()),'excluded_files':[f'roles/{loaded.role}/TOOLS.json'],'target_message_role':'system','tools_supplied':False,'execution_authorized':False,'private_context_logged':False,'model_comprehension_verified':False,'business_quality_verified':False}
 return updated,receipt
