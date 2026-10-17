import supervisor as s,subprocess
rows,_=s.snapshot();_,h=s.decide(rows,0,{},'x')
p=subprocess.run(s.command(rows,h),capture_output=True,text=True)
print('EXIT',p.returncode);print('STDERR',p.stderr[:1500]);print('STDOUT',p.stdout[:150] if p.returncode else 'idempotent queue confirmed')
