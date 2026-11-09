#!/bin/bash
# The firewall guard for real: a network namespace with ufw, listeners on 22 (SSH), 8443 (a tunnel) and
# 9999 (something else), and checks from outside which of them answer. Needs root, ufw and iproute2.
#   cargo test --no-run && sudo scripts/fw_guard_live.sh
set -u
BIN=$(ls -t target/debug/deps/kanki_panel-* | grep -v '\.d$' | head -1)
ip netns del fwt 2>/dev/null; ip link del fwh 2>/dev/null
ip netns add fwt
ip link add fwh type veth peer name fwn
ip link set fwn netns fwt
ip addr add 10.200.0.1/24 dev fwh; ip link set fwh up
ip netns exec fwt ip addr add 10.200.0.2/24 dev fwn
ip netns exec fwt ip link set fwn up; ip netns exec fwt ip link set lo up
declare -A PID
for p in 22 8443 9443 9999; do ip netns exec fwt python3 -c "
import socket,sys
s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('0.0.0.0',$p));s.listen(9)
while True:
    c,_=s.accept();c.send(b'ok');c.close()" & PID[$p]=$!; done
sleep 1
can() { timeout 2 bash -c "exec 3<>/dev/tcp/10.200.0.2/$1" 2>/dev/null && echo open || echo closed; }
echo "before: 22 $(can 22) 8443 $(can 8443) 9999 $(can 9999)"
FW_HOLD=4 ip netns exec fwt "$BIN" fw::guard_live --ignored --nocapture > /tmp/fw_guard_live.log 2>&1 &
T=$!
for i in $(seq 1 60); do grep -q "GUARD ON" /tmp/fw_guard_live.log && break; sleep 0.5; done
echo "guard on: 22 $(can 22) 8443 $(can 8443) 9443 $(can 9443) 9999 $(can 9999)"
# the deleted tunnel stops listening first (as Kanki does), so its port may close
kill ${PID[8443]}
for i in $(seq 1 60); do grep -q "TUNNEL PORTS MOVED" /tmp/fw_guard_live.log && break; sleep 0.5; done
echo "tunnel moved: 22 $(can 22) 8443 $(can 8443) 9443 $(can 9443) 9999 $(can 9999)"
wait $T; R=$?
echo "after (ufw off again): 22 $(can 22) 9443 $(can 9443) 9999 $(can 9999)"
grep -E "GUARD LIVE OK|panicked|test result" /tmp/fw_guard_live.log
kill $(jobs -p) 2>/dev/null
ip netns exec fwt ufw --force disable >/dev/null 2>&1
ip netns del fwt; ip link del fwh 2>/dev/null
exit $R
