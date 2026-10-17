"""Validate Telegram Mini App identity using Telegram's public Ed25519 key.

No bot credential, network call, external script or Telegram role grants.
Official contract: https://core.telegram.org/bots/webapps#validating-data-for-third-party-use
"""
import base64,json,re,time
from urllib.parse import parse_qsl
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

BOT_ID=8690224851
PUBLIC_KEY=bytes.fromhex('e7bf03a2fa4602af4580703d88dda5bb59f32ed8b02a56c187fe7d34caed242d')

def verify_init_data(raw,*,public_key=PUBLIC_KEY,bot_id=BOT_ID,now=None):
 try:
  if not isinstance(raw,str) or not 1<=len(raw)<=8000:raise ValueError()
  pairs=parse_qsl(raw,keep_blank_values=True,strict_parsing=True,max_num_fields=32)
  values=dict(pairs)
  if len(values)!=len(pairs) or any(not re.fullmatch('[a-z_]{1,64}',k) for k in values):raise ValueError()
  signature=values.get('signature','')
  if not re.fullmatch('[A-Za-z0-9_-]{86}(?:==)?',signature):raise ValueError()
  stamp=int(values['auth_date']);clock=time.time() if now is None else now
  if not -30<=clock-stamp<=600:raise ValueError()
  checked=str(bot_id)+':WebAppData\n'+'\n'.join(k+'='+values[k] for k in sorted(values) if k not in ('hash','signature'))
  signature_bytes=base64.urlsafe_b64decode(signature+'='*((-len(signature))%4))
  Ed25519PublicKey.from_public_bytes(public_key).verify(signature_bytes,checked.encode())
  user=json.loads(values['user'])
  if not isinstance(user,dict) or type(user.get('id')) is not int or not 0<user['id']<2**52 or user.get('is_bot'):raise ValueError()
  if values.get('chat_type','private') not in ('private','sender'):raise ValueError()
  if 'chat' in values and json.loads(values['chat']).get('type') not in ('private','sender'):raise ValueError()
  return {'id':str(user['id']),'auth_date':stamp,'proof':__import__('hashlib').sha256(checked.encode()+b'\n'+signature_bytes).hexdigest()}
 except Exception:raise ValueError('invalid_telegram_identity') from None
