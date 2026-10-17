"""Gateway-only transport. No chat text persisted in the CTO container."""
import asyncio,hashlib,hmac,json,socket,time
from pathlib import Path
_known_ids=set();_owner_ids=set()

def send(payload,key):
 canonical=json.dumps(payload,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()
 envelope={'payload':payload,'signature':hmac.new(key.encode(),canonical,hashlib.sha256).hexdigest()}
 raw=json.dumps(envelope,ensure_ascii=False).encode();assert len(raw)<=32768
 with socket.socket(socket.AF_UNIX) as client:
  client.settimeout(3);client.connect('/awema-telegram/bridge.sock');client.sendall(len(raw).to_bytes(4,'big')+raw)
  reply=client.recv(4096);return json.loads(reply)

async def route(adapter,update):
 msg=adapter._effective_update_message(update)
 if not msg or not msg.text or msg.chat.type!='private' or not msg.from_user or msg.from_user.is_bot:return False
 if msg.chat.id!=msg.from_user.id:return False
 try:mirror=json.loads(Path('/awema-telegram/links.json').read_text())
 except Exception:return True
 personal=msg.text=='/perso' or msg.text.startswith('/perso ')
 _owner_ids.update(v['telegram_id'] for v in mirror.get('personal_owners',[]))
 owners=[v for v in mirror.get('personal_owners',[]) if v.get('telegram_id')==str(msg.from_user.id)]
 if owners:
  if not -30<=time.time()-mirror.get('observed_at',0)<=60:return True
  link=owners[0]
  payload={'schema':1,'bot':8690224851,'update_id':update.update_id,'message_id':msg.message_id,'chat_id':msg.chat.id,'user_id':msg.from_user.id,'date':int(msg.date.timestamp()),'user':link['user'],'generation':link['generation'],'text':msg.text}
  try:
   result=await asyncio.to_thread(send,payload,adapter._bot.token)
   if result.get('handled') is False and result.get('route')=='cto':return False
  except Exception:
   try:await msg.reply_text('Le suivi personnel est momentanément indisponible. Aucun renvoi au CTO.')
   except Exception:pass
  return True
 if personal or str(msg.from_user.id) in _owner_ids:return True
 if '*' in mirror.get('native_ids',[]) or str(msg.from_user.id) in mirror.get('native_ids',[]):return bool(mirror.get('personal_router'))
 _known_ids.update(v['telegram_id'] for v in mirror.get('links',[]));_known_ids.update(mirror.get('protected_ids',[]))
 matches=[v for v in mirror.get('links',[]) if v.get('telegram_id')==str(msg.from_user.id)]
 if not matches:return str(msg.from_user.id) in _known_ids
 # A recognized linked identity never falls through to native CTO handling.
 if not -30<=time.time()-mirror.get('observed_at',0)<=60:return True
 link=matches[0]
 payload={'schema':1,'bot':8690224851,'update_id':update.update_id,'message_id':msg.message_id,'chat_id':msg.chat.id,'user_id':msg.from_user.id,'date':int(msg.date.timestamp()),'user':link['user'],'generation':link['generation'],'text':msg.text}
 try:await asyncio.to_thread(send,payload,adapter._bot.token)
 except Exception:
  try:await msg.reply_text('Le chat privé AWEMA est momentanément indisponible. Ouvrez Espace AWEMA ; évitez de renvoyer plusieurs fois la même demande.')
  except Exception:pass
 return True
