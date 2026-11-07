#!/bin/bash
# End-to-end game lab: the phone's real KANKI MIX core -> lossy mobile path -> Iran entry (a real panel tunnel)
# -> lossy international path -> exit -> the real KANKI MIX server -> a fake game server (echo). Another user's
# UDP download shares the tunnel. Prints loss and round trips of a 50 pps game.
# Needs: KMIXSRV (built from src/vpn/kmix-server), KMIXCORE (a copy of kanki-app/kmix-core with kmix_e2e_test.go
# copied into its mobile/), HOSTIP (a non-loopback IP of this machine).
# Iran-like path (env): MMTU/MDEL/MJIT (mobile), IMTU/ICAP/ISPIKE/IDEL/IJIT (international), e.g.
#   MMTU=1372 MDEL=25 MJIT=15 IMTU=1372 ICAP=10 ISPIKE="8,500,0.30,150" IDEL=40 IJIT=12 ./run.sh <panel> game 43000 8 1 0.02 0.03
# run.sh <panel-binary> <transport> <base port> <bulk Mbit/s> <DUP 0/1> [mobile loss] [intl loss]
BIN=$1; TR=$2; B=$3; HERE=$(cd "$(dirname "$0")" && pwd); HOSTIP=${HOSTIP:-$(hostname -I | cut -d" " -f1)}; RATE=$4; DUP=$5; ML=${6:-0.01}; IL=${7:-0.02}
D=/tmp/kanki-e2e/run-$B; rm -rf $D; mkdir -p $D
K=$((B+1)); T=$((B+2)); P2=$((B+3)); E1=$((B+4)); E2=$((B+5)); BK=$((B+6)); P1=$((B+7))
TOK="lab-token-0123456789-0123456789-abcd"
cat > $D/exit.json <<J
{"id":"g","name":"g","role":"exit","mode":"direct","transport":"$TR","port":$T,"token":"$TOK","conns":4,"target":"127.0.0.1","udp":["$E1:$K","$E2:$BK"]}
J
cat > $D/entry.json <<J
{"id":"g","name":"g","role":"entry","mode":"direct","transport":"$TR","port":$T,"remote":"127.0.0.1:$P2","token":"$TOK","conns":4,"target":"127.0.0.1","udp":["$E1:$K","$E2:$BK"]}
J
pids=()
${KMIXSRV:-/tmp/kmix-server} -listen 127.0.0.1:$K -key 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff 2>$D/kmix.log & pids+=($!)
$BIN tunnel-run $D/exit.json 2>$D/exit.log >/dev/null & pids+=($!)
$BIN tunnel-run $D/entry.json 2>$D/entry.log >/dev/null & pids+=($!)
MTU=$IMTU CAP=$ICAP SPIKE=$ISPIKE python3 $HERE/proxy.py $P2 $T $IL ${IDEL:-35} ${IJIT:-8} & pids+=($!)      # Iran -> abroad
MTU=$MMTU python3 $HERE/proxy.py $P1 $E1 $ML ${MDEL:-15} ${MJIT:-5} & pids+=($!)     # phone -> Iran (mobile)
if [ "$RATE" != "0" ]; then python3 $HERE/bulk.py $BK $E2 $RATE 40 5 2>$D/bulk.log & pids+=($!); fi
sleep 4
cd ${KMIXCORE:?copy of kanki-app/kmix-core with kmix_e2e_test.go in mobile/} && SERVER=127.0.0.1:$P1 HOSTIP=$HOSTIP SECS=25 DUP=$DUP go test ./mobile/ -run TestE2EGame -count=1 -v 2>&1 | grep -E "RESULT|connected|FAIL|panic" 
kill ${pids[@]} 2>/dev/null; wait 2>/dev/null
