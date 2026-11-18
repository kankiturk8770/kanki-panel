#!/usr/bin/env python3
"""Where an account's data came from, from the panel's own database (read only).

    python3 who_used.py <username> [/var/lib/kanki/kanki.db]

Prints the account, then every counter the panel keeps per source:
- WireGuard / AmneziaWG: bytes per server (the `peers` table, the server's own counter)
- Xray, Kanki DNS, KPING: the last running total per server (settings `xray_prev_*`, `dns_prev_*`, `kping_prev_*`)
- after 3.52: data that came after the account had ended, by server and protocol (`after_limit`)
Hysteria2, KANKI MIX and microtun are added per round and not kept per source: what the list above
does not explain came through those three.
"""
import json, sqlite3, sys, datetime

def gb(b):
    return "%.3f GB" % (b / 1024 ** 3)

def t(ts):
    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC") if ts else "-"

name = sys.argv[1] if len(sys.argv) > 1 else ""
path = sys.argv[2] if len(sys.argv) > 2 else "/var/lib/kanki/kanki.db"
c = sqlite3.connect("file:%s?mode=ro" % path, uri=True)
u = c.execute("SELECT id,username,limit_gb,used_bytes,created_at,expires_at,enabled,protocols,nodes,notes,last_seen FROM users WHERE username=?", (name,)).fetchone()
if not u:
    sys.exit("no user named %r" % name)
uid = u[0]
print("user %s (id %d): limit %s GB, used %s, made %s, ends %s, enabled %s" % (u[1], uid, u[2], gb(u[3]), t(u[4]), t(u[5]), u[6]))
print("  protocols: %s   servers: %s   note: %s   last seen: %s" % (u[7], u[8] or "all", u[9], t(u[10])))
names = dict(c.execute("SELECT id,name FROM nodes").fetchall())
known = 0
print("\nWireGuard / AmneziaWG (the server's counter of this user's key):")
for node, proto, rx, tx in c.execute("SELECT node_id,proto,rx,tx FROM peers WHERE user_id=?", (uid,)):
    known += rx + tx
    print("  %-20s %-4s %s" % (names.get(node, node), proto, gb(rx + tx)))
print("\nXray / DNS / KPING (running total of the server's counter):")
for k, v in c.execute("SELECT k,v FROM settings WHERE k LIKE 'xray_prev_%' OR k LIKE 'dns_prev_%' OR k LIKE 'kping_prev_%'"):
    try:
        b = int((json.loads(v).get("users") or {}).get(str(uid), 0))
    except Exception:
        continue
    if b:
        known += b
        print("  %-30s %s" % (k, gb(b)))
print("\nexplained above: %s of %s; the rest came through Hysteria2, KANKI MIX or microtun" % (gb(known), gb(u[3])))
al = c.execute("SELECT v FROM settings WHERE k='after_limit'").fetchone()
if al:
    e = (json.loads(al[0]) or {}).get(str(uid))
    if e:
        print("\nafter the account had ended:")
        for s, b in (e.get("src") or {}).items():
            print("  %-30s %s" % (s, gb(b)))
print("\nservers:")
for nid, nm, on, last in c.execute("SELECT id,name,online,last_sync FROM nodes"):
    print("  %-20s %-8s last answer %s" % (nm, "online" if on else "OFFLINE", t(last)))
