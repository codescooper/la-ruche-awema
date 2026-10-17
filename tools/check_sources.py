"""Offline syntax and publication exclusions check. Never executes app code."""
from pathlib import Path
import ast,json,sys
root=Path(__file__).resolve().parents[1]
errors=[];checked=0
for p in root.rglob('*'):
 if not p.is_file()or'.git'in p.parts:continue
 if p.suffix in('.key','.pem','.dpapi','.sqlite','.db')or p.name in('.env','auth.json','tokens.json'):errors.append(str(p.relative_to(root))+':forbidden_file')
 if p.suffix=='.py':
  try:ast.parse(p.read_text(encoding='utf-8-sig'),filename=str(p.relative_to(root)));checked+=1
  except(SyntaxError,UnicodeError)as e:errors.append(str(p.relative_to(root))+':'+type(e).__name__)
print(json.dumps({'python_sources_checked':checked,'errors':errors,'offline_only':True}))
sys.exit(bool(errors))
