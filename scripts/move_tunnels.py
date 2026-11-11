#!/usr/bin/env python3
"""Move every tunnel from one server to another (same transport and ports), enable it and reconnect it.

  python3 move_tunnels.py PANEL_URL TOKEN                 # list servers (ids and names)
  python3 move_tunnels.py PANEL_URL TOKEN OLD_ID NEW_ID   # show what would change
  python3 move_tunnels.py PANEL_URL TOKEN OLD_ID NEW_ID go  # do it
"""
import json, ssl, sys, urllib.request

def call(method, path, body=None):
    req = urllib.request.Request(URL + path, method=method,
                                 data=None if body is None else json.dumps(body).encode(),
                                 headers={"Authorization": "Bearer " + TOK, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30, context=ssl.create_default_context()) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")

URL, TOK = sys.argv[1].rstrip("/"), sys.argv[2]
_, d = call("GET", "/api/tunnels")
for s in d["servers"]:
    print(f"server  {s['id']:<14} {s['name']:<24} {'online' if s.get('online') else 'OFFLINE'}")
if len(sys.argv) < 5:
    sys.exit(0)
old, new, go = sys.argv[3], sys.argv[4], len(sys.argv) > 5 and sys.argv[5] == "go"
print()
for t in d["tunnels"]:
    body = {"id": t["id"]}
    if t["entry"] == old:
        body["entry"] = new
    if t["exit"] == old:
        body["exit"] = new
    if len(body) == 1:
        continue
    print(f"tunnel  {t['name']:<28} {t.get('kind') or t['transport']:<10} port {t['port']}  {t['entry']} -> {t['exit']}  =>  {body.get('entry', t['entry'])} -> {body.get('exit', t['exit'])}")
    if go:
        print("   save   ", *call("POST", "/api/tunnels", body))
        print("   enable ", *call("POST", f"/api/tunnels/{t['id']}/enable"))
        print("   restart", *call("POST", f"/api/tunnels/{t['id']}/restart"))
if not go:
    print("\n(nothing changed; add `go` at the end to do it)")
