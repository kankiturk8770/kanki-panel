#!/bin/bash
# KPING lab: a phone with two paths (Wi-Fi and mobile data, each with its own bursty loss and delay, made by
# `kplab lossy` since a kernel without netem is common), the Iran relay, a real reverse Game-FEC tunnel, the
# exit and a "game server" in its own network namespace, all on this machine (root).
# The same game-like stream (60 packets a second) goes through microtun (one path, as the app does it now)
# and KPING (one path, then two), under each profile.
#   sudo scripts/kping_lab.sh [seconds per run]
set -u
SRV=; ECHO=; PX=
SECS=${1:-30}
DIR=$(mktemp -d)
LAB=$DIR/kplab
cd "$(dirname "$0")/.."
(cd scripts/kping-lab && go build -o "$LAB" .) || exit 1
cleanup() {
  kill $SRV $ECHO $PX 2>/dev/null
  ip netns del kgame 2>/dev/null; ip link del game-h 2>/dev/null
}
trap cleanup EXIT
cleanup
ip netns add kgame
ip link add game-h type veth peer name game-p
ip link set game-p netns kgame
ip addr add 10.200.9.1/24 dev game-h; ip link set game-h up
ip -n kgame addr add 10.200.9.2/24 dev game-p; ip -n kgame link set game-p up; ip -n kgame link set lo up
ip netns exec kgame "$LAB" echo 10.200.9.2:7777 & ECHO=$!
LAB_DIR=$DIR LAB_SECS=100000 MT_DIAL=127.0.0.1:25400 cargo test --quiet kping_lab -- --ignored --nocapture > "$DIR/srv.log" 2>&1 & SRV=$!
for _ in $(seq 1 600); do grep -q READY "$DIR/srv.log" && break; sleep 1; done
grep -q READY "$DIR/srv.log" || { cat "$DIR/srv.log"; exit 1; }

# the paths: Wi-Fi to KPING (25300) and to microtun (25400), mobile data to KPING (25301)
# profile: <wifi: delay jitter loss% burst> <data: delay jitter loss% burst>
profile() {
  kill $PX 2>/dev/null; sleep 0.3; PX=
  "$LAB" lossy 127.0.0.1:25300 127.0.0.1:24300 $1 $2 $3 $4 & PX="$PX $!"
  "$LAB" lossy 127.0.0.1:25400 127.0.0.1:24400 $1 $2 $3 $4 & PX="$PX $!"
  "$LAB" lossy 127.0.0.1:25301 127.0.0.1:24300 $5 $6 $7 $8 & PX="$PX $!"
  sleep 0.5
}
run() {
  echo "== $1"
  "$LAB" mtun "$DIR/mtun.link" $SECS 10.200.9.2:7777 | grep RESULT
  "$LAB" kping "$DIR/kping.link" $SECS 127.0.0.1 127.0.0.1:25300 10.200.9.2:7777 | grep -E "RESULT|KPING"
  "$LAB" kping "$DIR/kping.link" $SECS 127.0.0.1,127.0.0.1 127.0.0.1:25300,127.0.0.1:25301 10.200.9.2:7777 | grep -E "RESULT|KPING"
}
profile 15 10 0 1   30 20 0 1
run "clean: Wi-Fi 15-25 ms, data 30-50 ms, no loss"
profile 15 10 2 1.5   30 20 2 1.5
run "ordinary: Wi-Fi 15-25 ms 2% loss, data 30-50 ms 2% loss"
profile 20 20 6 3   35 25 6 3
run "bad: Wi-Fi 20-40 ms 6% loss in bursts of ~3, data 35-60 ms 6% loss in bursts of ~3"
profile 20 10 15 8   35 15 3 2
run "Wi-Fi breaking up: Wi-Fi 20-30 ms 15% loss in bursts of ~8, data 35-50 ms 3% loss"
