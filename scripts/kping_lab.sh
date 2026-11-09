#!/bin/bash
# KPING lab: a phone with two paths (Wi-Fi and mobile data, each with its own loss and delay), the Iran
# relay, a real reverse Game-FEC tunnel, the exit and a "game server", all on this machine (root).
# The same game-like stream (60 packets a second) goes through microtun (one path, as the app does it now)
# and KPING (one path, then two), under each loss profile.
#   sudo scripts/kping_lab.sh [seconds per run]
set -u
SRV=; ECHO=
SECS=${1:-30}
DIR=$(mktemp -d)
LAB=${LAB_BIN:-$DIR/kplab}
cd "$(dirname "$0")/.."
(cd scripts/kping-lab && go build -o "$LAB" .) || exit 1
cleanup() {
  kill $SRV $ECHO 2>/dev/null
  ip netns del kphone 2>/dev/null; ip netns del kgame 2>/dev/null
  ip link del wifi-h 2>/dev/null; ip link del cell-h 2>/dev/null; ip link del game-h 2>/dev/null
}
trap cleanup EXIT
cleanup
ip netns add kphone; ip netns add kgame
for p in wifi:1 cell:2; do n=${p%:*}; i=${p#*:}
  ip link add $n-h type veth peer name $n-p
  ip link set $n-p netns kphone
  ip addr add 10.200.$i.1/24 dev $n-h; ip link set $n-h up
  ip -n kphone addr add 10.200.$i.2/24 dev $n-p; ip -n kphone link set $n-p up
done
ip -n kphone link set lo up
ip link add game-h type veth peer name game-p
ip link set game-p netns kgame
ip addr add 10.200.9.1/24 dev game-h; ip link set game-h up
ip -n kgame addr add 10.200.9.2/24 dev game-p; ip -n kgame link set game-p up; ip -n kgame link set lo up
ip netns exec kgame "$LAB" echo 10.200.9.2:7777 & ECHO=$!
LAB_DIR=$DIR LAB_SECS=100000 cargo test --quiet kping_lab -- --ignored --nocapture > "$DIR/srv.log" 2>&1 & SRV=$!
for _ in $(seq 1 600); do grep -q READY "$DIR/srv.log" && break; sleep 1; done
grep -q READY "$DIR/srv.log" || { cat "$DIR/srv.log"; exit 1; }

# netem on both ends of a path: <dev> <args>
shape() { tc qdisc replace dev $1-h root netem $2; ip netns exec kphone tc qdisc replace dev $1-p root netem $2; }
run() {
  echo "== $1"
  ip netns exec kphone "$LAB" mtun "$DIR/mtun.link" $SECS 10.200.9.2:7777 | grep RESULT
  ip netns exec kphone "$LAB" kping "$DIR/kping.link" $SECS 10.200.1.2 10.200.1.1 10.200.9.2:7777 | grep -E "RESULT|KPING"
  ip netns exec kphone "$LAB" kping "$DIR/kping.link" $SECS 10.200.1.2,10.200.2.2 10.200.1.1,10.200.2.1 10.200.9.2:7777 | grep -E "RESULT|KPING"
}
shape wifi "delay 15ms 5ms loss 2%"; shape cell "delay 30ms 10ms loss 2%"
run "ordinary: Wi-Fi 15±5 ms 2% loss, data 30±10 ms 2% loss"
shape wifi "delay 20ms 10ms loss 6% 25%"; shape cell "delay 35ms 12ms loss 6% 25%"
run "bad: Wi-Fi 20±10 ms 6% loss in bursts, data 35±12 ms 6% loss in bursts"
shape wifi "delay 20ms 5ms loss 15% 50%"; shape cell "delay 35ms 8ms loss 3%"
run "Wi-Fi breaking up: Wi-Fi 15% loss in long bursts, data 35±8 ms 3% loss"
