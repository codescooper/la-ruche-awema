import urllib.request,json,time
p={"model":"qwen3-4b-8k-test","messages":[{"role":"user","content":"Utilise l’outil local_echo avec le texte OK."}],"stream":False,"max_tokens":32,"reasoning_effort":"none","tools":[{"type":"function","function":{"name":"local_echo","description":"Retourner le texte demandé","parameters":{"type":"object","properties":{"text":{"type":"string"}},"required":["text"],"additionalProperties":False}}}],"tool_choice":{"type":"function","function":{"name":"local_echo"}}}
t=time.monotonic();r=urllib.request.Request("http://10.0.8.3:11434/v1/chat/completions",data=json.dumps(p).encode(),headers={"Content-Type":"application/json"})
try:
 x=json.load(urllib.request.urlopen(r,timeout=45));m=x.get("choices",[{}])[0].get("message",{});print("tool_test",round(time.monotonic()-t,2),"choice",len(x.get("choices",[])),"tool_calls",len(m.get("tool_calls",[])),"finish",x.get("choices",[{}])[0].get("finish_reason"))
except Exception as e:print("tool_test_error",type(e).__name__)
