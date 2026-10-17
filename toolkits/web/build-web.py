#!/usr/bin/env python3
"""Fixed offline builder. Reads source bytes, compiles once and packs exact dist."""
import hashlib,json,os,shutil,subprocess,sys,tempfile
from pathlib import Path
TOOLKIT=Path(__file__).resolve().parent
sys.path.insert(0,str(TOOLKIT));import web_project
def regular_tree(root):
 if root.is_symlink() or not root.is_dir():raise ValueError('source_directory_required')
 result={};total=0
 for p in sorted(root.rglob('*')):
  if p.is_symlink():raise ValueError('symlink_denied')
  if p.is_dir():continue
  name=p.relative_to(root).as_posix()
  if any(x.startswith('.') or x.lower()in ('auth.json','token.json','tokens.json','credentials.json','node_modules') for x in p.relative_to(root).parts):raise ValueError('sensitive_source_denied')
  if not p.is_file() or not 0<p.stat().st_size<=4*1024*1024:raise ValueError('file_boundary')
  b=p.read_bytes();total+=len(b);result[name]=b
  if len(result)>128 or total>12*1024*1024:raise ValueError('source_bounds')
 return result
def build(source,destination):
 source=Path(source).resolve();destination=Path(destination).resolve()
 if source==destination or source in destination.parents or destination in source.parents:raise ValueError('separate_output_required')
 files=regular_tree(source)
 # Work from the captured bytes, never allow a symlink swap after validation.
 with tempfile.TemporaryDirectory(prefix='awema-web-build-') as scratch:
  scratch=Path(scratch);stage=scratch/'source';dist=scratch/'dist';stage.mkdir()
  for name,b in files.items():
   p=stage/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b)
  subprocess.run(['node',str(TOOLKIT/'build-web.cjs'),str(stage),str(dist)],check=True,timeout=60,capture_output=True)
  outputs=regular_tree(dist);bundle=web_project.build_project(files,outputs,'awema-web-tools-v1')
  if len(bundle)>16*1024*1024:raise ValueError('project_package_too_large')
  if destination.exists():
   if destination.is_symlink() or not destination.is_dir():raise ValueError('output_directory_denied')
   # Rebuild removes only known generated regular files in the chosen workspace.
   old=regular_tree(destination)
   for name in old:(destination/name).unlink()
  destination.mkdir(parents=True,exist_ok=True)
  for name,b in outputs.items():
   p=destination/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b)
  package=destination.parent/'WEB_PROJECT.json'
  if package.is_symlink():raise ValueError('package_symlink_denied')
  package.write_bytes(bundle)
  project=web_project.load_project(bundle)
  return {'schema':'awema-web-build-local-v1','artifact_sha256':hashlib.sha256(bundle).hexdigest(),'bytes':len(bundle),'source_files':len(files),'dist_files':len(outputs),'build':json.loads(bundle)['build'],'qualification':'Local worker build; native receipt pending'}
if __name__=='__main__':
 if len(sys.argv)>1 and sys.argv[1]in ('--extract','--inspect'):
  project=web_project.read_project(Path(sys.argv[2]))
  if sys.argv[1]=='--inspect':print(json.dumps(web_project.project_metadata(project)));raise SystemExit(0)
  target=Path(sys.argv[3]);target.mkdir(parents=True,exist_ok=False)
  for name,entry in project.source.items():
   p=target/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(entry.raw)
  print(json.dumps({'source_sha256':project.source_sha256,'files':len(project.source),'extracted_to':str(target)}));raise SystemExit(0)
 if len(sys.argv)>1 and sys.argv[1]=='--help':print('python3 /web-toolkit/build-web.py [source-dir output-dir]\nDefault: /workspace/web /workspace/dist. Entry index.html + src/main.js|ts|jsx|tsx; import ./styles.css from main. Only pinned three, gsap and esbuild available.');raise SystemExit(0)
 args=sys.argv[1:] or ['/workspace/web','/workspace/dist']
 if len(args)!=2:raise SystemExit('source and output required')
 print(json.dumps(build(*args),ensure_ascii=False))
