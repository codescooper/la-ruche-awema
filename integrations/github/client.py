#!/usr/bin/env python3
"""Dev-only GitHub operations through a credential-free UNIX transport."""
import json,socket,sys
def request(payload):
 raw=json.dumps(payload).encode();assert len(raw)<=262144
 with socket.socket(socket.AF_UNIX) as c:
  c.settimeout(90);c.connect('/instructions/github.sock');c.sendall(len(raw).to_bytes(4,'big')+raw)
  head=b''
  while len(head)<4:
   part=c.recv(4-len(head));assert part;head+=part
  size=int.from_bytes(head,'big');assert size<=524288
  data=b''
  while len(data)<size:
   part=c.recv(min(65536,size-len(data)));assert part;data+=part
  result=json.loads(data)
  if not result.get('ok'):raise RuntimeError(result.get('error','github_operation_refused'))
  return result['result']
if __name__=='__main__':
 print(json.dumps(request(json.load(sys.stdin)),ensure_ascii=False))
