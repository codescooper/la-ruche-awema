"""Authenticated gateway envelope to Root-only personal endpoint."""
import hashlib,hmac,http.client,json,socket,time
from portal import require
def forward(envelope,key,native_ids):
 data=envelope.get('payload');signature=envelope.get('signature');require(type(data) is dict and type(signature) is str,403,'invalid_transport')
 raw=json.dumps(data,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode();require(hmac.compare_digest(hmac.new(key.encode(),raw,hashlib.sha256).hexdigest(),signature),403,'invalid_transport')
 require(set(data)=={'schema','bot','update_id','message_id','chat_id','user_id','date','user','generation','text'},400,'invalid_transport')
 require(data['schema']==1 and data['bot']==8690224851 and data['user']=='owner' and len(native_ids)==1 and '*' not in native_ids,403,'owner_denied')
 for field in ('update_id','message_id','chat_id','user_id','generation','date'):require(type(data[field]) is int and 0<data[field]<2**52,400,'invalid_transport')
 require(data['chat_id']==data['user_id'] and str(data['chat_id']) in native_ids and -30<=time.time()-data['date']<=300,403,'owner_denied')
 require(type(data['text']) is str and 0<len(data['text'])<=4000,400,'personal_prefix_required')
 class UnixHTTP(http.client.HTTPConnection):
  def connect(self):self.sock=socket.socket(socket.AF_UNIX);self.sock.settimeout(2);self.sock.connect('/opt/awema-jury/run/personal/personal.sock')
 c=UnixHTTP('localhost',timeout=2)
 try:
  c.request('POST','/internal/telegram',body=json.dumps({'user':'owner','generation':data['generation'],'chat':str(data['chat_id']),'update':data['update_id'],'text':data['text']}).encode(),headers={'Content-Type':'application/json'});r=c.getresponse();answer=json.loads(r.read(4096));require(r.status==200,503,'personal_unavailable');return answer
 finally:c.close()
