#!/usr/bin/env bash
# =====================================================================
#  Kanki standalone tunnel: installs ONE tunnel description as a systemd service.
#  No panel and no database are needed. Run it on both servers (Node A and Node B), each with
#  its own JSON file (examples: docs/examples/, guide: docs/STANDALONE-FA.md).
#
#    sudo bash install-standalone.sh /root/tunnel.json      install or update
#    sudo bash install-standalone.sh --uninstall            remove the service (keeps the config)
#    sudo bash install-standalone.sh --purge                remove everything, config and user too
#
#  Environment:
#    KANKI_BIN=/path/to/kanki-panel   use this binary instead of downloading one (a server that cannot
#                                     reach GitHub: copy the file with scp first)
#    KANKI_REPO=owner/repo            where releases are downloaded from (default below)
#
#  What it sets up:
#    /usr/local/bin/kanki-tunnel-run               the program (the same binary as the panel)
#    /etc/kanki-tunnel-run/tunnel.json             your tunnel (holds the secret: group-readable only)
#    /etc/systemd/system/kanki-tunnel-run.service  starts at boot, restarts by itself, never gives up
#    /etc/sysctl.d/91-kanki-tunnel-run.conf        bigger socket buffers for QUIC, BBR when available
#    ufw rules for the ports the file needs (only when ufw is active)
# =====================================================================
set -euo pipefail

NAME=kanki-tunnel-run
BIN=/usr/local/bin/$NAME
CONF_DIR=/etc/$NAME
CONF=$CONF_DIR/tunnel.json
UNIT=/etc/systemd/system/$NAME.service
SYSCTL=/etc/sysctl.d/91-$NAME.conf
REPO=${KANKI_REPO:-kankiturk8770/kanki-panel}
# `tunnel-run --check` exists from 2.9.1; 2.9.2 stops the needless AmneziaWG installation at start
MIN_VERSION=2.9.2

Y='\033[1;33m'; R='\033[1;31m'; N='\033[0m'; G='\033[1;32m'
say(){ echo -e "${Y}>> $*${N}"; }
ok(){ echo -e "${G}[ok] $*${N}"; }
warn(){ echo -e "${R}[!] $*${N}"; }
die(){ echo -e "${R}[x] $*${N}" >&2; exit 1; }

[ "$(id -u)" = "0" ] || die "Please run as root (sudo -i)"
command -v systemctl >/dev/null || die "systemd is required"

usage(){
  sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'
  exit 1
}

# ---------------------------------------------------------------- remove
remove_service(){
  systemctl disable --now "$NAME" >/dev/null 2>&1 || true
  rm -f "$UNIT" "$SYSCTL" "$BIN"
  systemctl daemon-reload
  sysctl -q --system >/dev/null 2>&1 || true
}

if [ "${1:-}" = "--uninstall" ]; then
  remove_service
  ok "Removed the service and the program. Your config is still in $CONF_DIR (use --purge to delete it)."
  exit 0
fi
if [ "${1:-}" = "--purge" ]; then
  remove_service
  rm -rf "$CONF_DIR"
  id -u "$NAME" >/dev/null 2>&1 && userdel "$NAME" >/dev/null 2>&1 || true
  ok "Removed everything. Ports opened in ufw earlier stay open: remove them with 'ufw delete allow <port/proto>'."
  exit 0
fi

# ---------------------------------------------------------------- install
FILE=${1:-}
{ [ -n "$FILE" ] && [ -f "$FILE" ]; } || usage

# version a >= b ?
ver_ge(){ [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1)" = "$2" ]; }

# 1. the program: a given file, or the latest release (its checksum is mandatory)
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
if [ -n "${KANKI_BIN:-}" ]; then
  [ -f "$KANKI_BIN" ] || die "KANKI_BIN=$KANKI_BIN does not exist"
  cp "$KANKI_BIN" "$TMP/kanki-panel"
else
  command -v curl >/dev/null || { apt-get update -qq && apt-get install -y -qq curl ca-certificates >/dev/null; } || die "curl is required"
  base="https://github.com/$REPO/releases/download/latest"
  say "Downloading the program from $base"
  curl -fL --retry 3 -o "$TMP/kanki-panel" "$base/kanki-panel" \
    || die "Download failed. If this server cannot reach GitHub, copy the binary here (scp) and run: KANKI_BIN=/path/to/kanki-panel bash $0 $FILE"
  # no checksum file = no installation: a missing file must not silently skip the check
  curl -fsL --retry 3 -o "$TMP/kanki-panel.sha256" "$base/kanki-panel.sha256" || die "Could not download kanki-panel.sha256, aborting (the binary was not verified)"
  (cd "$TMP" && sha256sum -c kanki-panel.sha256 >/dev/null) || die "Checksum mismatch, aborting"
fi
chmod 755 "$TMP/kanki-panel"
have=$("$TMP/kanki-panel" version 2>/dev/null | awk '{print $2}') || true
[ -n "$have" ] || die "This file does not run on this server (wrong CPU type?)"
ver_ge "$have" "$MIN_VERSION" || die "The program is v$have; v$MIN_VERSION or newer is needed (older ones cannot check the file first)"
ok "Program v$have"

# 2. the description is checked BEFORE anything on the system changes; the check prints the ports to open
say "Checking $FILE"
PORTS=$("$TMP/kanki-panel" tunnel-run "$FILE" --check) || die "The tunnel file is not usable (reason above)"

# 3. user, files
id -u "$NAME" >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin "$NAME"
install -d -m 750 -o root -g "$NAME" "$CONF_DIR"
# the file holds the shared secret: root writes it, the service user only reads it
install -m 640 -o root -g "$NAME" "$FILE" "$CONF"
install -m 755 "$TMP/kanki-panel" "$BIN"

# 4. kernel settings: QUIC wants large UDP buffers; BBR keeps long TCP paths fast
{
  echo "net.core.rmem_max=16777216"
  echo "net.core.wmem_max=16777216"
  if modprobe tcp_bbr 2>/dev/null || grep -qw bbr /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null; then
    echo "net.core.default_qdisc=fq"
    echo "net.ipv4.tcp_congestion_control=bbr"
  fi
} > "$SYSCTL"
sysctl -q --system >/dev/null 2>&1 || true

# 5. the service
cat > "$UNIT" <<'EOF'
[Unit]
Description=Kanki tunnel (standalone)
Documentation=https://github.com/kankiturk8770/kanki-panel/blob/main/docs/STANDALONE-FA.md
After=network-online.target
Wants=network-online.target
# never stop trying: a tunnel that cannot start now (network not up yet) starts when it can
StartLimitIntervalSec=0

[Service]
User=kanki-tunnel-run
Group=kanki-tunnel-run
ExecStart=/usr/local/bin/kanki-tunnel-run tunnel-run /etc/kanki-tunnel-run/tunnel.json
# the program also reconnects every link by itself (back-off 1..10 s) and keeps QUIC/TCP alive with
# pings; this line only covers the process itself dying
Restart=always
RestartSec=2
LimitNOFILE=65535
# lets a non-root user listen on 443 and other ports below 1024
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable -q "$NAME"
systemctl restart "$NAME"

# 6. firewall (only when ufw is active); the cloud provider's own firewall is up to you
if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "^Status: active"; then
  for p in $PORTS; do ufw allow "$p" >/dev/null || true; done
  ok "ufw: opened $(echo $PORTS)"
fi

# 7. did it start?
sleep 4
if systemctl is-active --quiet "$NAME"; then
  ok "The tunnel service is running and starts at every boot."
  echo "   Ports to open in the firewall of this server (also in your cloud panel): $(echo $PORTS)"
  echo "   Watch it:   journalctl -u $NAME -f"
  echo "   Change it:  edit $CONF, then: systemctl restart $NAME"
  echo "   Stop it:    systemctl stop $NAME     Remove it: bash $0 --uninstall"
else
  journalctl -u "$NAME" -n 20 --no-pager || true
  die "The service did not start (see above)."
fi
