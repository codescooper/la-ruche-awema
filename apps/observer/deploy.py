"""Operator deployment, new isolated service only. No production restart."""
import datetime, hashlib, json, os, secrets, subprocess, time, urllib.request
from pathlib import Path
from unix_http import request as local_request
BASE=Path('/opt/awema-jury');SOURCE=BASE/'source'
os.umask(0o077)
def run(args):return subprocess.run(args,check=True,capture_output=True,text=True).stdout
BASE.mkdir(exist_ok=True,mode=0o700)
private=BASE/'private.json'
if not private.exists():
    private.write_text(json.dumps({'invitation':secrets.token_urlsafe(32),'internal_token':secrets.token_urlsafe(40)}))
cfg=json.loads(private.read_text())
data=BASE/'data';data.mkdir(exist_ok=True);os.chown(data,10001,10001);os.chmod(data,0o700)
sock=BASE/'run';sock.mkdir(exist_ok=True);os.chown(sock,10001,10001);os.chmod(sock,0o700)
env=BASE/'app.env';env.write_text('SOCKET_PATH=/run/office/demo.sock\nPUBLIC_ORIGIN=https://laruche.awema.cloud\nINVITE_HASH='+hashlib.sha256(cfg['invitation'].encode()).hexdigest()+'\nINTERNAL_TOKEN='+cfg['internal_token']+'\n')
network='awema-jury-isolated'
networks=json.loads(run(['docker','network','ls','--format','json']).splitlines()[0]) if False else run(['docker','network','ls','--format','{{.Name}}']).splitlines()
if network not in networks:run(['docker','network','create','--internal',network])
proxy=json.loads(run(['docker','inspect','coolify-proxy']))[0]
if network not in proxy['NetworkSettings']['Networks']:run(['docker','network','connect',network,'coolify-proxy'])
image='awema-jury-office:20260922'
run(['docker','build','-t',image,str(SOURCE)])
hard={'read_only':True,'tmpfs':['/tmp:rw,noexec,nosuid,size=8m'],'cap_drop':['ALL'],'security_opt':['no-new-privileges:true'],'pids_limit':64,'mem_limit':'192m','cpus':0.5,'logging':{'driver':'json-file','options':{'max-size':'2m','max-file':'2'}}}
compose={'services':{'office':{**hard,'image':image,'container_name':'awema-jury-office','restart':'unless-stopped','env_file':[str(env)],'network_mode':'none','volumes':[str(data)+':/data:rw',str(sock)+':/run/office:rw']},'front':{**hard,'image':'nginx:1.28-alpine','container_name':'awema-jury-front','restart':'unless-stopped','user':'10001:10001','entrypoint':['nginx','-g','daemon off;'],'networks':[network],'volumes':[str(sock)+':/run/office:ro',str(SOURCE/'nginx.conf')+':/etc/nginx/nginx.conf:ro']}},'networks':{network:{'external':True}}}
cp=BASE/'compose.json';cp.write_text(json.dumps(compose,indent=2))
run(['docker','compose','-f',str(cp),'up','-d'])
for _ in range(25):
    try:
        assert local_request('/health')[0]==200;break
    except Exception:time.sleep(1)
else:raise RuntimeError('health_failed')
# Script is owned by root in sticky /tmp, so the non-root team cannot unlink/replace it.
run(['docker','cp',str(SOURCE/'model_entry.py'),'awema-ai-team:/tmp/awema-jury-model-entry.py'])
run(['docker','exec','-u','root','awema-ai-team','chown','root:root','/tmp/awema-jury-model-entry.py'])
run(['docker','exec','-u','root','awema-ai-team','chmod','0444','/tmp/awema-jury-model-entry.py'])
run(['docker','exec','awema-ai-team','which','pkill'])
unit='''[Unit]
Description=Awema jury bounded model bridge
After=docker.service
Requires=docker.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/awema-jury/source/broker.py
Restart=on-failure
RestartSec=10
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/awema-jury
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryMax=192M
CPUQuota=20%
TasksMax=32

[Install]
WantedBy=multi-user.target
'''
Path('/etc/systemd/system/awema-jury-broker.service').write_text(unit)
run(['systemctl','daemon-reload']);run(['systemctl','enable','--now','awema-jury-broker.service'])
info=json.loads(run(['docker','inspect','awema-jury-office']))[0]
proof={'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'image':info['Image'],'user':info['Config']['User'],'readonly':info['HostConfig']['ReadonlyRootfs'],'cap_drop':info['HostConfig']['CapDrop'],'security_opt':info['HostConfig']['SecurityOpt'],'mounts':[{'source':m['Source'],'destination':m['Destination'],'rw':m['RW']} for m in info['Mounts']],'network_mode':info['HostConfig']['NetworkMode'],'gateway_internal':json.loads(run(['docker','network','inspect',network]))[0]['Internal'],'published':info['NetworkSettings']['Ports'],'public_route_installed':False}
(BASE/'deployment.json').write_text(json.dumps(proof,indent=2));print(json.dumps(proof))
