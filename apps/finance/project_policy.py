"""Narrow policy and payload validation for private non-production project tasks."""
import hashlib,json,re

PROJECT_REPOSITORIES={'awema-test/awema-dev-workbench'}
MAX_PROJECT_FILES=20
MAX_PROJECT_BYTES=200_000
MAX_PROJECT_FILE_BYTES=100_000
PATH_RE=re.compile(r'^[A-Za-z0-9_./-]{1,180}$')
SHA_RE=re.compile(r'^[a-f0-9]{40}$')
SECRET_RE=re.compile(r'-----BEGIN .*PRIVATE KEY-----|\b(?:ghp_|github_pat_|sk-|xox[baprs]-)[A-Za-z0-9_]{15,}|\bAKIA[0-9A-Z]{16}\b|\b[0-9]{8,12}:[A-Za-z0-9_-]{25,}\b|\beyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|(?:api[_-]?key|client[_-]?secret|access[_-]?token|refresh[_-]?token|password|passwd|service[_-]?role[_-]?key)\s*[:=]\s*[\"\']?[A-Za-z0-9_./+=-]{16,}',re.I)
FORBIDDEN_PARTS={'.git','.github','.env','auth.json','token.json','tokens.json','credentials.json','secrets','credentials','node_modules','vendor'}

def safe_path(path):
 if not isinstance(path,str) or not PATH_RE.fullmatch(path) or path.startswith('/') or '\\' in path:return False
 parts=path.lower().split('/')
 if any(p in ('','.','..') or p in FORBIDDEN_PARTS or p.startswith('.env.') or p.endswith(('.pem','.key','.dpapi')) for p in parts):return False
 suffix='.'+parts[-1].rsplit('.',1)[1] if '.' in parts[-1] else ''
 return suffix in {'.css','.html','.js','.json','.jsx','.md','.mjs','.py','.svg','.toml','.ts','.tsx','.txt','.yml','.yaml'}

def git_blob_sha(content):
 raw=content.encode('utf-8')
 return hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()

def validate_source_manifest(raw,expected_repo):
 try:data=json.loads(raw)
 except (ValueError,TypeError,UnicodeError):return 'snapshot projet illisible'
 if type(data) is not dict or set(data)!={'repository','commit','files'} or data.get('repository')!=expected_repo or not SHA_RE.fullmatch(str(data.get('commit',''))):return 'snapshot projet hors périmètre'
 files=data.get('files');
 if type(files) is not list or not 1<=len(files)<=MAX_PROJECT_FILES:return 'nombre de fichiers source invalide'
 seen=set();total=0
 for f in files:
  if type(f) is not dict or set(f)!={'path','sha','content'} or not safe_path(f.get('path')) or not SHA_RE.fullmatch(str(f.get('sha',''))) or not isinstance(f.get('content'),str):return 'fichier source invalide ou interdit'
  if f['path'] in seen:return 'chemin source dupliqué'
  size=len(f['content'].encode('utf-8'))
  if size>MAX_PROJECT_FILE_BYTES or git_blob_sha(f['content'])!=f['sha']:return 'empreinte ou taille source incohérente'
  if SECRET_RE.search(f['content']):return 'contenu potentiellement secret refusé'
  seen.add(f['path']);total+=size
 if total>MAX_PROJECT_BYTES:return 'snapshot projet trop volumineux'
 return None

def validate_changes(raw,expected_repo):
 try:data=json.loads(raw)
 except (ValueError,TypeError,UnicodeError):return 'proposition de changements illisible'
 if type(data) is not dict or set(data)!={'repository','base_commit','files'} or data.get('repository')!=expected_repo or not SHA_RE.fullmatch(str(data.get('base_commit',''))):return 'proposition hors dépôt ou commit source invalide'
 files=data.get('files')
 if type(files) is not list or not 1<=len(files)<=MAX_PROJECT_FILES:return 'nombre de changements invalide'
 seen=set();total=0
 for f in files:
  if type(f) is not dict or set(f)!={'path','content'} or not safe_path(f.get('path')) or not isinstance(f.get('content'),str):return 'chemin ou contenu de changement interdit'
  if f['path'] in seen:return 'chemin de changement dupliqué'
  body=f['content'];size=len(body.encode('utf-8'))
  if size>MAX_PROJECT_FILE_BYTES or SECRET_RE.search(body):return 'contenu secret ou fichier trop volumineux refusé'
  seen.add(f['path']);total+=size
 if total>MAX_PROJECT_BYTES:return 'proposition trop volumineuse'
 return None
