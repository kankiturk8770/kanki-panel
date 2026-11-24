#!/bin/bash
# Direct tunnel (kfwd) for real, in network namespaces: user → entry (Iran) → exit (abroad), with the panel's
# own code applying the rules. The exit runs a UDP echo and a TCP server; the user reaches them on the entry.
#   sudo scripts/kfwd_lab.sh <test binary> [nat|gre]
# The test binary: cargo test --release --no-run (target/release/deps/kanki_panel-*). Needs ip, iptables, python3.
set -u
BIN=$1
MODE=${2:-nat}
STOP=/tmp/kfwd_lab.stop
rm -f "$STOP"
cleanup() { for n in u ir de; do ip netns del kf_$n 2>/dev/null; done; rm -f "$STOP"; }
trap cleanup EXIT
cleanup
for n in u ir de; do ip netns add kf_$n; ip -n kf_$n link set lo up; done
# user ↔ entry (the user's network), entry ↔ exit (the internet between the servers)
ip link add kfu type veth peer name kfi1
ip link set kfu netns kf_u; ip link set kfi1 netns kf_ir
ip link add kfi2 type veth peer name kfd
ip link set kfi2 netns kf_ir; ip link set kfd netns kf_de
ip -n kf_u addr add 10.70.1.2/24 dev kfu; ip -n kf_u link set kfu up; ip -n kf_u route add default via 10.70.1.1
ip -n kf_ir addr add 10.70.1.1/24 dev kfi1; ip -n kf_ir link set kfi1 up
ip -n kf_ir addr add 198.51.100.10/24 dev kfi2; ip -n kf_ir link set kfi2 up
ip -n kf_de addr add 198.51.100.20/24 dev kfd; ip -n kf_de link set kfd up
# the exit's own services: UDP echo on 4000, TCP on 443
ip netns exec kf_de python3 -c '
import socket,threading
u=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);u.bind(("0.0.0.0",4000))
def echo():
    while True:
        d,a=u.recvfrom(2000);u.sendto(b"de:"+d,a)
threading.Thread(target=echo,daemon=True).start()
t=socket.socket();t.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);t.bind(("0.0.0.0",443));t.listen(8)
while True:
    c,_=t.accept();d=c.recv(100);c.sendall(b"de-tcp:"+d);c.close()
' &
SRV=$!
spec() { echo "{\"tid\":\"lab\",\"role\":\"$1\",\"mode\":\"$MODE\",\"peer\":\"$2\",\"n\":7,\"tcp\":[\"8443:443\"],\"udp\":[\"4000\"]}"; }
KFWD_LAB=$(spec exit 198.51.100.10) KFWD_STOP=$STOP ip netns exec kf_de "$BIN" --ignored --exact tunnel::kfwd::lab::kfwd_lab --nocapture > /tmp/kfwd_de.log 2>&1 &
DE=$!
KFWD_LAB=$(spec entry 198.51.100.20) KFWD_STOP=$STOP ip netns exec kf_ir "$BIN" --ignored --exact tunnel::kfwd::lab::kfwd_lab --nocapture > /tmp/kfwd_ir.log 2>&1 &
IR=$!
sleep 4
# the user: 200 UDP packets and 5 TCP connections to the entry
ip netns exec kf_u python3 -c '
import socket,time
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(0.5);ok=0;rtt=[]
for i in range(200):
    t=time.time();s.sendto(b"p%d"%i,("10.70.1.1",4000))
    try:
        d,_=s.recvfrom(2000)
        if d==b"de:p%d"%i: ok+=1;rtt.append((time.time()-t)*1000)
    except Exception: pass
tc=0
for i in range(5):
    c=socket.create_connection(("10.70.1.1",8443),timeout=2);c.sendall(b"hi%d"%i)
    if c.recv(100)==b"de-tcp:hi%d"%i: tc+=1
    c.close()
print("UDP %d/200 answered, median %.2f ms; TCP %d/5" % (ok, sorted(rtt)[len(rtt)//2] if rtt else -1, tc))
'
echo "== what the entry holds"
ip netns exec kf_ir iptables-save | grep KFWD | head -20
ip -n kf_ir -o link show | grep kfg
touch "$STOP"
wait $IR $DE
kill $SRV 2>/dev/null
echo "== entry"; tail -3 /tmp/kfwd_ir.log
echo "== exit"; tail -3 /tmp/kfwd_de.log
