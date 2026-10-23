#!/usr/bin/env bash
set -Eeuo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "Run as root: sudo bash install.sh" >&2
  exit 1
fi
if [[ ! -f go.mod || ! -d cmd/server || ! -d cmd/panel ]]; then
  echo "Run this script from the KLINK project root." >&2
  exit 1
fi

PROJECT_DIR="$(pwd -P)"
PROXY_PORT="${PROXY_PORT:-443}"
PANEL_PORT="${PANEL_PORT:-8080}"
SSH_PORT="${SSH_PORT:-22}"
ADMIN_USERNAME="${ADMIN_USERNAME:-admin}"
PUBLIC_HOST="${PUBLIC_HOST:-}"
PUBLIC_URL="${PUBLIC_URL:-}"
GO_VERSION="${GO_VERSION:-}"

for value in "$PROXY_PORT" "$PANEL_PORT" "$SSH_PORT"; do
  [[ "$value" =~ ^[0-9]+$ ]] && (( value >= 1 && value <= 65535 )) || { echo "Invalid port: $value" >&2; exit 1; }
done
[[ "$ADMIN_USERNAME" =~ ^[a-zA-Z0-9_.-]{3,32}$ ]] || { echo "Invalid ADMIN_USERNAME" >&2; exit 1; }

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y ca-certificates curl tar gzip ufw openssl iproute2

# Install the current stable Go toolchain unless GO_VERSION (for example
# GO_VERSION=go1.26.0) was explicitly supplied.
if [[ -z "$GO_VERSION" ]]; then
  GO_VERSION="$(curl -fsSL https://go.dev/VERSION?m=text | head -n 1)"
fi
[[ "$GO_VERSION" =~ ^go[0-9]+\.[0-9]+([.][0-9]+)?$ ]] || { echo "Could not determine Go version" >&2; exit 1; }
case "$(dpkg --print-architecture)" in
  amd64) GO_ARCH=amd64 ;;
  arm64) GO_ARCH=arm64 ;;
  armhf) GO_ARCH=armv6l ;;
  *) echo "Unsupported CPU architecture" >&2; exit 1 ;;
esac
GO_ARCHIVE="/tmp/${GO_VERSION}.linux-${GO_ARCH}.tar.gz"
curl -fL --retry 3 -o "$GO_ARCHIVE" "https://go.dev/dl/${GO_VERSION}.linux-${GO_ARCH}.tar.gz"
rm -rf /usr/local/go
tar -C /usr/local -xzf "$GO_ARCHIVE"
rm -f "$GO_ARCHIVE"
export PATH="/usr/local/go/bin:$PATH"

go version
go mod download
go test ./...
install -d -m 0755 /usr/local/bin /usr/share/klink/web /etc/klink
CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /usr/local/bin/klink-server ./cmd/server
CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /usr/local/bin/klink-panel ./cmd/panel
cp -a web/. /usr/share/klink/web/

if ! id klink >/dev/null 2>&1; then
  useradd --system --home /var/lib/klink --shell /usr/sbin/nologin klink
fi
install -d -o klink -g klink -m 0750 /var/lib/klink

CREDENTIALS_FILE=""
if [[ ! -f /etc/klink/server.json ]]; then
  if [[ -z "$PUBLIC_HOST" ]]; then
    PUBLIC_HOST="$(ip -4 route get 1.1.1.1 | sed -n 's/.*src \([0-9.]*\).*/\1/p' | head -n1)"
  fi
  [[ "$PUBLIC_HOST" =~ ^[a-zA-Z0-9.-]+$ ]] || { echo "Set PUBLIC_HOST to the server domain or public IPv4 address." >&2; exit 1; }
  [[ -n "$PUBLIC_HOST" ]] || { echo "Set PUBLIC_HOST to the server domain or public IPv4 address." >&2; exit 1; }
  if [[ -z "$PUBLIC_URL" ]]; then PUBLIC_URL="http://${PUBLIC_HOST}:${PANEL_PORT}"; fi
  [[ "$PUBLIC_URL" != *'"'* && "$PUBLIC_URL" != *'\'* ]] || { echo "Invalid PUBLIC_URL" >&2; exit 1; }

  KEY_OUTPUT="$(/usr/local/bin/klink-server -genkey)"
  SERVER_PRIVATE="$(sed -n 's/^private_key=//p' <<<"$KEY_OUTPUT")"
  SERVER_PUBLIC="$(sed -n 's/^public_key=//p' <<<"$KEY_OUTPUT")"
  STATUS_TOKEN="$(openssl rand -hex 32)"
  ADMIN_PASSWORD="${ADMIN_PASSWORD:-$(openssl rand -base64 24 | tr -d '\n')}"
  if (( ${#ADMIN_PASSWORD} < 12 )); then echo "ADMIN_PASSWORD must have at least 12 characters" >&2; exit 1; fi
  ADMIN_HASH="$(KLINK_PASSWORD="$ADMIN_PASSWORD" /usr/local/bin/klink-panel -hash-password)"

  cat >/etc/klink/server.json <<EOF
{
  "listen_udp": ":${PROXY_PORT}",
  "listen_tcp": ":${PROXY_PORT}",
  "database": "/var/lib/klink/klink.db",
  "server_private_key": "${SERVER_PRIVATE}",
  "obfuscation": "random",
  "handshake_timeout": "30s",
  "idle_timeout": "10m",
  "rekey_interval": "15m",
  "rekey_packets": 1048576,
  "status_listen": "127.0.0.1:9091",
  "status_token": "${STATUS_TOKEN}",
  "log_level": "info"
}
EOF
  cat >/etc/klink/panel.json <<EOF
{
  "listen": ":${PANEL_PORT}",
  "database": "/var/lib/klink/klink.db",
  "web_root": "/usr/share/klink/web",
  "admin_username": "${ADMIN_USERNAME}",
  "admin_password_hash": "${ADMIN_HASH}",
  "public_url": "${PUBLIC_URL}",
  "core_status_url": "http://127.0.0.1:9091/v1/status",
  "core_status_token": "${STATUS_TOKEN}",
  "server_public_key": "${SERVER_PUBLIC}",
  "udp_endpoint": "${PUBLIC_HOST}:${PROXY_PORT}",
  "tcp_endpoint": "${PUBLIC_HOST}:${PROXY_PORT}",
  "obfuscation": "random",
  "tls_cert_file": "",
  "tls_key_file": "",
  "secure_cookies": false,
  "session_ttl_hours": 12
}
EOF
  chmod 0600 /etc/klink/server.json /etc/klink/panel.json
  chown root:klink /etc/klink/server.json /etc/klink/panel.json
  chmod 0640 /etc/klink/server.json /etc/klink/panel.json
  CREDENTIALS_FILE="/root/klink-credentials.txt"
  umask 077
  cat >"$CREDENTIALS_FILE" <<EOF
KLINK panel: ${PUBLIC_URL}
Username: ${ADMIN_USERNAME}
Password: ${ADMIN_PASSWORD}
Server public key: ${SERVER_PUBLIC}
EOF
  umask 022
else
  echo "Existing /etc/klink configuration preserved; no keys or passwords rotated."
fi

cat >/etc/systemd/system/klink-core.service <<'EOF'
[Unit]
Description=KLINK v1 encrypted proxy core
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=klink
Group=klink
ExecStart=/usr/local/bin/klink-server -config /etc/klink/server.json
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/var/lib/klink
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
UMask=0077

[Install]
WantedBy=multi-user.target
EOF
cat >/etc/systemd/system/klink-panel.service <<'EOF'
[Unit]
Description=KLINK v1 management panel
After=network-online.target klink-core.service
Wants=network-online.target
Requires=klink-core.service

[Service]
Type=simple
User=klink
Group=klink
ExecStart=/usr/local/bin/klink-panel -config /etc/klink/panel.json
Restart=on-failure
RestartSec=3
LimitNOFILE=65536
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/var/lib/klink
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
UMask=0077

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable klink-core.service klink-panel.service
systemctl restart klink-core.service klink-panel.service

ufw allow "${SSH_PORT}/tcp" comment 'SSH'
ufw allow "${PROXY_PORT}/udp" comment 'KLINK UDP'
ufw allow "${PROXY_PORT}/tcp" comment 'KLINK TCP'
ufw allow "${PANEL_PORT}/tcp" comment 'KLINK panel'
ufw --force enable

sleep 2
systemctl --no-pager --full status klink-core.service klink-panel.service || true
curl -fsS http://127.0.0.1:9091/healthz >/dev/null

echo
echo "KLINK installation completed."
if [[ -n "$CREDENTIALS_FILE" ]]; then
  cat "$CREDENTIALS_FILE"
  echo "Credentials also saved in ${CREDENTIALS_FILE} (root-only)."
fi
echo "For production, put the panel behind HTTPS or configure tls_cert_file/tls_key_file and secure_cookies=true."
