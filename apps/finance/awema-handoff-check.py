"""Read-only local contract check before an AWEMA worker hands off its files."""
import argparse,json,os
from pathlib import Path
import web_project
REQUIRED={'pm':{'PLAN.md'},'dev':set(),'qa':{'QA.md','REVIEW.json'},'security':{'SECURITY.md','REVIEW.json'},'cto':{'LIVRAISON.md','REVIEW.json'},'ops':set(),'designer':set(),'assa':set(),'cl-producer':set()}
FORBIDDEN={'auth.json','token.json','tokens.json','credentials.json'}
def check(folder,role):
 issues=[];root=Path(folder).resolve();report=root/'RESULT.json'
 if not report.is_file() or report.is_symlink() or report.stat().st_size>65536:return ['RESULT.json absent, invalide ou trop grand']
 try:data=json.loads(report.read_text(encoding='utf-8'))
 except (OSError,ValueError,UnicodeError):return ['RESULT.json doit être un JSON UTF-8 valide']
 if not isinstance(data,dict):return ['RESULT.json doit être un objet']
 if set(data)-{'status','summary','artifacts','checks','limitations'}:issues.append('RESULT.json : champs supplémentaires interdits')
 if data.get('status') not in ('completed','blocked'):issues.append('RESULT.json : status doit être completed ou blocked')
 if not isinstance(data.get('summary'),str) or (not data.get('summary','').strip() or not 1<=len(data.get('summary',''))<=4000):issues.append('RESULT.json : summary doit avoir de 1 à 4000 caractères')
 artifacts=data.get('artifacts')
 if not isinstance(artifacts,list) or len(artifacts)>12 or (data.get('status')=='completed' and not artifacts):issues.append('RESULT.json : artifacts doit déclarer 1 à 12 fichiers existants pour completed');artifacts=[]
 if len(set(str(n) for n in artifacts))!=len(artifacts):issues.append('RESULT.json : fichiers déclarés en double')
 for name in artifacts:
  if name=='RESULT.json':issues.append('RESULT.json est le compte rendu ; ne pas le déclarer comme livrable');continue
  if not isinstance(name,str) or Path(name).name!=name or name.startswith('.') or name.lower() in FORBIDDEN or Path(name).suffix.lower() in ('.key','.pem','.dpapi'):
   issues.append('RESULT.json : nom de fichier interdit');continue
  path=root/name
  limit=web_project.MAX_BUNDLE_BYTES if name==web_project.ARTIFACT_NAME else 1024*1024
  if not path.is_file() or path.is_symlink() or path.resolve().parent!=root or not 1<=path.stat().st_size<=limit:
   issues.append('Livrable absent, vide, trop grand ou hors périmètre : '+name);continue
  if name==web_project.ARTIFACT_NAME:
   try:web_project.render_project(web_project.read_project(path))
   except (OSError,ValueError,UnicodeError) as exc:issues.append('WEB_PROJECT.json refusé : '+str(exc))
 if data.get('status')=='completed':
  missing=REQUIRED[role]-set(n for n in artifacts if isinstance(n,str))
  if missing:issues.append('Livrables obligatoires absents : '+', '.join(sorted(missing)))
 if role in ('qa','security','cto') and data.get('status')=='completed':
  path=root/'REVIEW.json'
  if path.is_file() and not path.is_symlink() and path.stat().st_size<=65536:
   try:review=json.loads(path.read_text(encoding='utf-8'))
   except (OSError,ValueError,UnicodeError):review={}
   if not isinstance(review,dict) or set(review)!={'verdict','reason'}:issues.append('REVIEW.json : exactement verdict et reason sont requis')
   if not isinstance(review,dict) or not isinstance(review.get('verdict'),str) or review['verdict'].strip().casefold() not in ('pass','correction'):issues.append('REVIEW.json : verdict doit être pass ou correction ; conserver toute réserve réelle')
   reason=review.get('reason') if isinstance(review,dict) else None
   if not isinstance(reason,str) or (not reason.strip() or not 1<=len(reason)<=4000):issues.append('REVIEW.json : reason doit avoir de 1 à 4000 caractères ; viser 500 à 1500 et garder les détails dans le rapport Markdown')
 return issues
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('folder');p.add_argument('--role',required=True,choices=sorted(REQUIRED));a=p.parse_args();issues=check(a.folder,a.role);print(json.dumps({'status':'fail' if issues else 'pass','issues':issues},ensure_ascii=False));raise SystemExit(1 if issues else 0)
