#!/bin/bash
# KANKI-UP lab: the official udp2raw with the exact options files the agents write, between two network
# namespaces (entry 10.77.0.1, exit 10.77.0.2, a 1500-byte link), a UDP echo on the exit's 127.0.0.1:51820.
# Checks: packets go and come back, the largest UDP payload that passes, and that nothing is left after.
#   sudo KUP_MODE=faketcp scripts/kup_lab.sh        (modes: faketcp easy-faketcp udp icmp)
set -u
cd "$(dirname "$0")/.." || exit 1
MODE=${KUP_MODE:-faketcp}
D=$(mktemp -d)
BIN=$D/udp2raw
zcat assets/bin/udp2raw_amd64.gz > "$BIN" && chmod 755 "$BIN"
KUP_LAB=$D KUP_MODE=$MODE cargo test -q kup_lab_files -- --ignored >/dev/null 2>&1 || { echo "conf files: failed"; exit 1; }
ip netns del kupA 2>/dev/null; ip netns del kupB 2>/dev/null
ip netns add kupA && ip netns add kupB
ip link add kupa type veth peer name kupb
ip link set kupa netns kupA && ip link set kupb netns kupB
ip -n kupA addr add 10.77.0.1/24 dev kupa && ip -n kupA link set kupa up mtu 1500 && ip -n kupA link set lo up
ip -n kupB addr add 10.77.0.2/24 dev kupb && ip -n kupB link set kupb up mtu 1500 && ip -n kupB link set lo up
ip netns exec kupB python3 -c '
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(("127.0.0.1",51820))
while True:
    d,a=s.recvfrom(65535); s.sendto(d,a)' &
ECHO=$!
ip netns exec kupB "$BIN" --conf-file "$D/exit.conf" > "$D/exit.log" 2>&1 &
SRV=$!
sleep 1
ip netns exec kupA "$BIN" --conf-file "$D/entry.conf" > "$D/entry.log" 2>&1 &
CLI=$!
for _ in $(seq 1 40); do grep -q "client_ready" "$D/entry.log" && break; sleep 0.25; done
if grep -q "client_ready" "$D/entry.log"; then echo "$MODE: connected"; else echo "$MODE: NOT connected"; tail -n 5 "$D/entry.log" "$D/exit.log"; fi
ip netns exec kupA python3 -c '
import socket,time
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(0.5)
ok=0; rtt=[]
for i in range(300):
    m=b"g"*60+str(i).encode(); t=time.time(); s.sendto(m,("127.0.0.1",51820))
    try:
        d,_=s.recvfrom(65535)
        if d==m: ok+=1; rtt.append((time.time()-t)*1000)
    except Exception: pass
    time.sleep(0.01)
print("game packets back: %d/300, rtt avg %.2f ms" % (ok, sum(rtt)/max(len(rtt),1)))
best=0
for n in range(1200,1501,4):
    m=b"x"*n; s.sendto(m,("127.0.0.1",51820))
    try:
        d,_=s.recvfrom(65535)
        if d==m: best=n
    except Exception: pass
print("largest UDP payload through the 1500 link:", best)'
grep -c "huge packet\|mtu" "$D/entry.log" "$D/exit.log" | sed 's/^/warnings /'
ip netns exec kupB iptables-save | grep -c udp2rawDwrW | sed 's/^/exit rules while running: /'
kill $CLI $SRV; sleep 1
echo "exit rules after stop: $(ip netns exec kupB iptables-save | grep -c udp2rawDwrW)  entry: $(ip netns exec kupA iptables-save | grep -c udp2rawDwrW)"
kill $ECHO 2>/dev/null
ip netns del kupA; ip netns del kupB; rm -rf "$D"
