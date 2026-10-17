"""Operator rebuild from captured source bytes, without running project scripts."""
import hashlib,json,os,secrets,subprocess
from pathlib import Path
import web_project
RELEASE=Path('/opt/awema-ops/capabilities/releases/awema-runtime-20261017-v1')
TOOLKIT=RELEASE/'web-toolkit'
class WebBuildError(ValueError):pass
def sha(b):return hashlib.sha256(b).hexdigest()
def verify_build(folder,artifact,identity,image):
 project=web_project.read_project(artifact)
 if project.toolchain_id!='awema-web-tools-v1':raise WebBuildError('web_toolchain_denied')
 build=folder/'native-build'
 build.mkdir(mode=0o700);source=build/'source';output=build/'output';source.mkdir(mode=0o755);source.chmod(0o755);output.mkdir(mode=0o700);os.chown(output,25002,25002)
 for name,entry in project.source.items():
  dest=source/name;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(entry.raw);dest.chmod(0o444)
 for directory in source.rglob('*'):
  if directory.is_dir():directory.chmod(0o755)
 # Parent folder remains root-only; bind mounts grant only the exact child trees.
 command=['docker','run','--rm','--name','awema-build-'+identity['operation'],'--network','none','--read-only','--user','25002:25002','--cap-drop','ALL','--security-opt','no-new-privileges','--memory','1536m','--cpus','2','--pids-limit','128','--tmpfs','/tmp:rw,nosuid,nodev,size=384m','--mount','type=bind,src='+str(TOOLKIT)+',dst=/web-toolkit,readonly','--mount','type=bind,src='+str(source)+',dst=/build-source,readonly','--mount','type=bind,src='+str(output)+',dst=/build-output','--entrypoint','python3',image,'-B','/web-toolkit/build-web.py','/build-source','/build-output/dist']
 try:p=subprocess.run(command,capture_output=True,timeout=90)
 except subprocess.TimeoutExpired:
  subprocess.run(['docker','stop','--time','2','awema-build-'+identity['operation']],capture_output=True,timeout=10)
  raise WebBuildError('native_web_build_timeout')from None
 if p.returncode:
  # Operator-only diagnostic, never included in model prompts or public projections.
  diagnostic=build/'compiler-diagnostic.txt';diagnostic.write_bytes(p.stderr[-32768:]);diagnostic.chmod(0o400)
  raise WebBuildError('native_web_compilation_failed')
 rebuilt=web_project.read_project(output/'WEB_PROJECT.json')
 if (rebuilt.source_sha256,rebuilt.dist_sha256,rebuilt.toolchain_id)!=(project.source_sha256,project.dist_sha256,project.toolchain_id):raise WebBuildError('native_web_dist_mismatch')
 proof={'schema':'awema-web-build-receipt-v1',**identity,'artifact_sha256':sha(artifact.read_bytes()),'source_sha256':project.source_sha256,'dist_sha256':project.dist_sha256,'toolchain_id':project.toolchain_id,'toolchain_sha256':sha((TOOLKIT/'TOOLCHAIN.json').read_bytes()),'builder_sha256':sha((TOOLKIT/'build-web.py').read_bytes()),'image':image,'matched':True,'receipt_id':secrets.token_hex(16)}
 target=build/'receipt.json';target.write_text(json.dumps(proof,sort_keys=True)+'\n');target.chmod(0o400)
 return proof
