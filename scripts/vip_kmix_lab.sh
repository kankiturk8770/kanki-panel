#!/bin/sh
# The VIP tunnel with the real KANKI MIX server and a KANKI MIX client (game + download), on bad lines.
# Usage: scripts/vip_kmix_lab.sh   (needs Go; the game server listens on this machine's first address)
set -e
cd "$(dirname "$0")/.."
out=$(mktemp -d)
(cd src/vpn/kmix-server && go build -o "$out/kanki-server" ./cmd/kanki-server && go build -o "$out/kmix-lab" ./cmd/kmix-lab)
host=$(hostname -I | awk '{print $1}')
KMIX_LAB_SERVER="$out/kanki-server" KMIX_LAB_CLIENT="$out/kmix-lab" KMIX_LAB_HOST="$host" \
  cargo test --release vip_kmix_lab -- --ignored --nocapture
rm -rf "$out"
