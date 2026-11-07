"""Tunnel lab: old/new binaries at both ends, a lossy UDP path between, a fake game + a download.

Usage: OLD=<old kanki-panel> NEW=<new kanki-panel> [LOSS=0.03] python3 scripts/tunnel_lab.py <game|kcp|hq|quic> \
       <old-old|new-new|new-entry-old-exit|old-entry-new-exit> <free base port> [noload]
Prints the fake game's loss, p50/p95/p99/max round trip, jitter and packets over 150 ms, while a TCP
download fills the same tunnel. The path drops LOSS each way and adds 40 +- 10 ms. faketcp needs raw
sockets and is not covered (its lane is in the Rust tests).
"""
import asyncio, json, os, random, socket, statistics, subprocess, sys, time

OLD = os.environ.get("OLD", "/tmp/old/kanki-panel")
NEW = os.environ.get("NEW", "target/release/kanki-panel")
LOSS, DELAY, JIT = float(os.environ.get("LOSS", "0.03")), 0.040, 0.010

class Lossy(asyncio.DatagramProtocol):
    """client side <-> server port, each direction: drop LOSS, delay DELAY +- JIT (reordering possible)"""
    def __init__(self, server): self.server, self.ups = server, {}
    def connection_made(self, t): self.t = t
    def datagram_received(self, d, addr):
        if addr not in self.ups:
            loop = asyncio.get_running_loop()
            up = Up(self, addr); self.ups[addr] = up
            loop.create_task(loop.create_datagram_endpoint(lambda: up, remote_addr=self.server))
        self.ups[addr].send(d)
def later(f):
    if random.random() < LOSS: return
    asyncio.get_running_loop().call_later(max(0, DELAY + random.uniform(-JIT, JIT)), f)
class Up(asyncio.DatagramProtocol):
    def __init__(self, front, client): self.front, self.client, self.q, self.t = front, client, [], None
    def connection_made(self, t):
        self.t = t
        for d in self.q: self.send(d)
    def send(self, d):
        if not self.t: self.q.append(d); return
        later(lambda: self.t.sendto(d))
    def datagram_received(self, d, addr): later(lambda: self.front.t.sendto(d, self.client))

def spec(role, tr, base):
    s = {"id": "lab", "name": "lab", "role": role, "mode": "direct", "transport": tr, "port": base,
         "token": "lab-token-0123456789-0123456789-abcd", "conns": 4,
         "tcp": [f"{base+1}:{base+2}"], "udp": [f"{base+3}:{base+4}"], "target": "127.0.0.1"}
    if role == "entry": s["remote"] = f"127.0.0.1:{base+10}"
    return s

async def echo_udp(port):
    loop = asyncio.get_running_loop()
    class E(asyncio.DatagramProtocol):
        def connection_made(self, t): self.t = t
        def datagram_received(self, d, a): self.t.sendto(d, a)
    await loop.create_datagram_endpoint(E, local_addr=("127.0.0.1", port))

async def bulk_tcp(port):
    async def h(r, w):
        blob = os.urandom(65536)
        try:
            while True:
                w.write(blob); await w.drain()
        except Exception: pass
    return await asyncio.start_server(h, "127.0.0.1", port)

async def downloader(port, stop):
    got = 0
    while not stop.is_set():
        try:
            r, w = await asyncio.open_connection("127.0.0.1", port)
            while not stop.is_set():
                b = await asyncio.wait_for(r.read(65536), 5)
                if not b: break
                got += len(b)
            w.close()
        except Exception:
            await asyncio.sleep(0.2)
    return got

async def game(port, secs):
    """50 packets a second of 80 bytes, like a shooter; RTT of each, -1 = lost (no answer in 1 s)"""
    loop = asyncio.get_running_loop()
    sent, rtt = {}, {}
    class G(asyncio.DatagramProtocol):
        def datagram_received(self, d, a):
            i = int.from_bytes(d[:4], "big")
            if i in sent and i not in rtt: rtt[i] = (time.perf_counter() - sent[i]) * 1000
    t, _ = await loop.create_datagram_endpoint(G, remote_addr=("127.0.0.1", port))
    n = int(secs * 50)
    for i in range(n):
        sent[i] = time.perf_counter(); t.sendto(i.to_bytes(4, "big") + bytes(76)); await asyncio.sleep(0.02)
    await asyncio.sleep(1.2)
    t.close()
    v = [rtt.get(i, -1) for i in range(n)]
    ok = sorted(x for x in v if x >= 0 and x < 1000)
    if not ok: return {"loss%": 100}
    q = lambda p: round(ok[min(len(ok)-1, int(len(ok)*p))], 1)
    seq = [x for x in v if 0 <= x < 1000]
    jit = statistics.mean(abs(a-b) for a, b in zip(seq, seq[1:])) if len(seq) > 1 else 0
    return {"loss%": round(100*(n-len(ok))/n, 2), "p50": q(.5), "p95": q(.95), "p99": q(.99), "max": round(ok[-1], 1), "jit": round(jit, 1),
            "over150ms": sum(1 for x in ok if x > 150)}

async def run(tr, eb, xb, base, secs=20, load=True):
    d = f"/tmp/tunnel-lab/{tr}-{base}"; os.makedirs(d, exist_ok=True)
    procs = []
    for role, binp in (("exit", xb), ("entry", eb)):
        f = f"{d}/{role}.json"; json.dump(spec(role, tr, base), open(f, "w"))
        procs.append(subprocess.Popen([binp, "tunnel-run", f], stdout=subprocess.DEVNULL, stderr=open(f"{d}/{role}.log", "w")))
    loop = asyncio.get_running_loop()
    await loop.create_datagram_endpoint(lambda: Lossy(("127.0.0.1", base)), local_addr=("127.0.0.1", base+10))
    await echo_udp(base+4); srv = await bulk_tcp(base+2)
    await asyncio.sleep(4)
    stop = asyncio.Event()
    dl = loop.create_task(downloader(base+1, stop)) if load else None
    await asyncio.sleep(1)
    g = await game(base+3, secs)
    stop.set(); got = await dl if dl else 0
    for p in procs: p.terminate()
    srv.close()
    g["download_MB"] = round(got/1e6, 1)
    return g

async def main():
    tr = sys.argv[1]; which = sys.argv[2]; base = int(sys.argv[3]); load = sys.argv[4] != "noload" if len(sys.argv) > 4 else True
    e, x = {"old-old": (OLD, OLD), "new-new": (NEW, NEW), "new-entry-old-exit": (NEW, OLD), "old-entry-new-exit": (OLD, NEW)}[which]
    r = await run(tr, e, x, base, load=load)
    print(json.dumps({"transport": tr, "pair": which, "load": load, **r}))
asyncio.run(main())
