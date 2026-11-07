"""Another user's download through the same tunnel: 1300-byte UDP packets at RATE Mbit/s to an echo, both ways."""
import socket, sys, time, threading
eport, tport, rate, secs = int(sys.argv[1]), int(sys.argv[2]), float(sys.argv[3]), float(sys.argv[4])
e = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); e.bind(("127.0.0.1", eport))
def echo():
    while True:
        d, a = e.recvfrom(4096); e.sendto(d, a)
threading.Thread(target=echo, daemon=True).start()
time.sleep(float(sys.argv[5]) if len(sys.argv) > 5 else 6)
c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); c.connect(("127.0.0.1", tport)); c.setblocking(False)
gap = 1300*8/(rate*1e6); end = time.time()+secs; n = 0; t = time.time()
while time.time() < end:
    try: c.send(b"x"*1300); n += 1
    except BlockingIOError: pass
    try:
        while True: c.recv(4096)
    except BlockingIOError: pass
    t += gap; d = t-time.time()
    if d > 0: time.sleep(d)
print("bulk sent", n, "packets", file=sys.stderr)
