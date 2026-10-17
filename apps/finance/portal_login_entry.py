"""Navigation-only login continuation around the unchanged qualified portal.

No authentication, session duration, permission or API behavior is changed.
"""
import hashlib
import html
import re
from pathlib import Path
from urllib.parse import parse_qsl, quote, urlencode, urlsplit

PORTAL_SHA256='50892dcbccaee60539b599c6c7db08e11d4fdd3fe370844980c455d5de296168'
MISSION=re.compile(r'f_[a-f0-9]{24}\Z')
NAME=re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z')

def preview_target(raw):
 if not isinstance(raw,str) or not 0<len(raw)<=1024 or any(ord(c)<32 or ord(c)==127 for c in raw) or '\\' in raw or '#' in raw:return None
 try:
  u=urlsplit(raw)
  if u.scheme or u.netloc or u.path!='/finance/mission-preview' or u.fragment:return None
  pairs=parse_qsl(u.query,keep_blank_values=True,strict_parsing=True,max_num_fields=3)
  if len(pairs)!=3 or len({k for k,v in pairs})!=3 or {k for k,v in pairs}!={'mission','ordinal','name'}:return None
  q=dict(pairs)
  if not MISSION.fullmatch(q['mission']) or re.fullmatch(r'(?:0|[1-9]|[1-5][0-9]|6[0-3])',q['ordinal']) is None or not (q['name']=='__site__' or NAME.fullmatch(q['name'])):return None
  return '/finance/mission-preview?'+urlencode([(k,q[k])for k in ('mission','ordinal','name')])
 except (ValueError,UnicodeError):return None

def document_navigation(headers):
 dest=headers.get('Sec-Fetch-Dest');mode=headers.get('Sec-Fetch-Mode')
 return (mode=='navigate' and dest=='document') or (not mode and not dest and 'text/html' in headers.get('Accept','').lower())

def install(portal):
 if getattr(portal.Handler,'_awema_login_continuation',False):return
 original=portal.Handler.reply
 def reply(self,code,value,cookie=None,mime='application/json'):
  target=preview_target(self.path) if self.command=='GET' else None
  if code==401 and isinstance(value,dict) and value.get('error')=='authentication_required' and target and document_navigation(self.headers):
   location='/finance/?return_to='+quote(target,safe='')
   body=('<!doctype html><html lang="fr"><meta charset="utf-8"><title>Connexion AWEMA</title><h1>Connexion nécessaire</h1><p>Connectez-vous pour ouvrir le site ou le livrable demandé.</p><a href="'+html.escape(location,quote=True)+'">Se connecter et continuer</a></html>').encode('utf-8')
   self.send_response(303)
   headers={'Location':location,'Content-Type':'text/html; charset=utf-8','Content-Length':str(len(body)),'Cache-Control':'private, no-store','Referrer-Policy':'no-referrer','X-Content-Type-Options':'nosniff','Content-Security-Policy':"default-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'self' https://web.telegram.org"}
   for k,v in headers.items():self.send_header(k,v)
   self.end_headers();self.wfile.write(body);return
  return original(self,code,value,cookie,mime)
 portal.Handler.reply=reply
 portal.Handler._awema_login_continuation=True

def main():
 import portal
 p=Path(portal.__file__)
 if str(p)!='/finance-app/portal.py' or p.is_symlink() or hashlib.sha256(p.read_bytes()).hexdigest()!=PORTAL_SHA256:raise RuntimeError('Qualified portal preimage changed')
 install(portal)
 portal.main()

if __name__=='__main__':main()
