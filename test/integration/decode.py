import sys,json,base64
r=json.load(sys.stdin); p=r["payload"]; d=json.loads(base64.urlsafe_b64decode(p+"="*(-len(p)%4)))
res=d.get("result"); 
if isinstance(res,list): res=[{k:x.get(k) for k in ("names","service","action","state","op","ok","exitCode") if k in x} if isinstance(x,dict) else x for x in res][:5]
print("ok" if d["ok"] else "ERR", json.dumps(res if d["ok"] else d["error"])[:400])
