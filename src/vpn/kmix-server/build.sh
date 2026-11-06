#!/bin/sh
# Builds the KANKI MIX server (Go) into the panel: assets/bin/kanki-mix-server, which the panel
# carries inside itself and every agent writes to its own server (src/vpn/kmix.rs). CI runs this
# before building the panel, so a release always holds the server built from this source.
set -e
cd "$(dirname "$0")"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false -ldflags "-s -w" \
  -o ../../../assets/bin/kanki-mix-server ./cmd/kanki-server
echo "assets/bin/kanki-mix-server: $(wc -c < ../../../assets/bin/kanki-mix-server) bytes"
