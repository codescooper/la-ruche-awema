import subprocess
rules=[['INPUT','-i','br-awema-v2','-j','DROP'],['INPUT','-i','br-awema-v2','-d','172.30.90.1','-p','tcp','--dport','18090','-j','ACCEPT'],['DOCKER-USER','-i','br-awema-v2','-j','DROP']]
for rule in rules:
 if subprocess.run(['iptables','-C',*rule],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode:
  subprocess.run(['iptables','-I',rule[0],'1',*rule[1:]],check=True)
