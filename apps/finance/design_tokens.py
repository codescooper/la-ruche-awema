"""Pure design-token contract; arithmetic gate, never a rendered-pixel verdict."""
import math,re
class TokenError(ValueError):pass
def _keys(v,keys):
 if not isinstance(v,dict) or set(v)!=set(keys):raise TokenError('design_tokens_keys')
def _num(v,lo,hi,integer=False):
 if type(v) not in ((int,) if integer else (int,float)) or not math.isfinite(v) or not lo<=v<=hi:raise TokenError('design_tokens_value')
def _luminance(color):
 rgb=[int(color[i:i+2],16)/255 for i in (1,3,5)];values=[v/12.92 if v<=0.04045 else ((v+0.055)/1.055)**2.4 for v in rgb]
 return sum(v*w for v,w in zip(values,(0.2126,0.7152,0.0722)))
def validate_design_tokens(v):
 _keys(v,{'schema','colors','typography','spacing','radius','breakpoints','motion'})
 if v['schema']!='awema-design-tokens-v1':raise TokenError('design_tokens_schema')
 _keys(v['colors'],{'background','surface','text','muted','accent','accent_text'})
 if any(not isinstance(c,str) or not re.fullmatch(r'#[a-fA-F0-9]{6}',c) for c in v['colors'].values()):raise TokenError('design_tokens_color')
 _keys(v['typography'],{'heading','body'})
 if any(not isinstance(t,str) or not 1<=len(t)<=160 or any(x in t.lower() for x in ('url(', 'javascript:', '\n','\r','<','>')) for t in v['typography'].values()):raise TokenError('design_tokens_typography')
 spacing=v['spacing']
 if not isinstance(spacing,list) or not 4<=len(spacing)<=16:raise TokenError('design_tokens_spacing')
 for n in spacing:_num(n,1,128,True)
 if spacing!=sorted(set(spacing)):raise TokenError('design_tokens_spacing')
 _keys(v['radius'],{'control','card'})
 for n in v['radius'].values():_num(n,0,64)
 _keys(v['breakpoints'],{'mobile','desktop'});_num(v['breakpoints']['mobile'],320,767,True);_num(v['breakpoints']['desktop'],768,2560,True)
 _keys(v['motion'],{'reduced_motion','duration_ms'})
 if v['motion']['reduced_motion']!='respect-prefers-reduced-motion':raise TokenError('design_tokens_motion')
 durations=v['motion']['duration_ms'];_keys(durations,{'short','standard','long'})
 for n in durations.values():_num(n,0,2000,True)
 if not durations['short']<=durations['standard']<=durations['long']:raise TokenError('design_tokens_motion')
 contrast={}
 for foreground,background in [('text','background'),('text','surface'),('muted','background'),('accent_text','accent')]:
  a,b=sorted((_luminance(v['colors'][foreground]),_luminance(v['colors'][background])));ratio=(b+0.05)/(a+0.05);contrast[foreground+'/'+background]=round(ratio,6)
  if ratio<4.5:raise TokenError('design_tokens_contrast')
 return {'schema':'awema-design-token-validation-v1','pass':True,'contrast_ratio':contrast,'rendered_visual_quality_verified':False}
