"""Lossy UDP path: listen -> target, each direction drops LOSS and delays DELAY +- JIT ms."""
import asyncio, random, sys
import os, time
lport, tport, LOSS, DELAY, JIT = int(sys.argv[1]), int(sys.argv[2]), float(sys.argv[3]), float(sys.argv[4])/1000, float(sys.argv[5])/1000
# Iran-like extras (env): MTU = biggest UDP payload that passes (bigger is dropped, like a small path MTU),
# CAP = UDP Mbit/s per direction (over it is dropped, like a throttle), SPIKE = "every_s,len_ms,loss,extra_ms"
MTU = int(os.environ.get("MTU") or 0); CAP = float(os.environ.get("CAP") or 0)
SP = [float(x) for x in os.environ.get("SPIKE", "").split(",")] if os.environ.get("SPIKE") else None
T0 = time.time()
class Bucket:
    def __init__(s): s.tok, s.t = 0.0, time.time()
    def ok(s, n):
        if CAP <= 0: return True
        now = time.time(); s.tok = min(CAP*1e6/8*0.05, s.tok + (now-s.t)*CAP*1e6/8); s.t = now
        if s.tok >= n: s.tok -= n; return True
        return False
UP, DOWN = Bucket(), Bucket()
def later(f, d=b"", b=None):
    if MTU and len(d) > MTU: return
    if b is not None and not b.ok(len(d)): return
    loss, extra = LOSS, 0.0
    if SP and (time.time()-T0) % SP[0] < SP[1]/1000: loss, extra = SP[2], SP[3]/1000
    if random.random() < loss: return
    asyncio.get_running_loop().call_later(max(0, DELAY + extra + random.uniform(-JIT, JIT)), f)
class Up(asyncio.DatagramProtocol):
    def __init__(s, front, client): s.front, s.client, s.q, s.t = front, client, [], None
    def connection_made(s, t):
        s.t = t
        for d in s.q: s.send(d)
    def send(s, d):
        if not s.t: s.q.append(d); return
        later(lambda: s.t.sendto(d), d, UP)
    def datagram_received(s, d, a): later(lambda: s.front.t.sendto(d, s.client), d, DOWN)
class Front(asyncio.DatagramProtocol):
    def __init__(s): s.ups = {}
    def connection_made(s, t): s.t = t
    def datagram_received(s, d, a):
        if a not in s.ups:
            u = Up(s, a); s.ups[a] = u
            asyncio.get_running_loop().create_task(asyncio.get_running_loop().create_datagram_endpoint(lambda: u, remote_addr=("127.0.0.1", tport)))
        s.ups[a].send(d)
async def main():
    await asyncio.get_running_loop().create_datagram_endpoint(Front, local_addr=("127.0.0.1", lport))
    await asyncio.Event().wait()
asyncio.run(main())
