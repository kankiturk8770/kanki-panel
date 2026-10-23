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
# SSL settings:
#   DOMAIN       domain whose DNS A record points at this server; the panel gets a
#                Let's Encrypt certificate for it and renews it automatically.
#   ACME_EMAIL   optional e-mail for Let's Encrypt expiry notices.
#   SSL_MODE     auto (default) | acme | selfsigned | off
#                auto: Let's Encrypt when a domain points here, otherwise a
#                self-signed certificate (still encrypted, the browser shows a warning).
#   FORCE_ACME=1 request a certificate even if the DNS check fails.
DOMAIN="${DOMAIN:-}"
ACME_EMAIL="${ACME_EMAIL:-}"
SSL_MODE="${SSL_MODE:-auto}"
FORCE_ACME="${FORCE_ACME:-0}"

for value in "$PROXY_PORT" "$PANEL_PORT" "$SSH_PORT"; do
  [[ "$value" =~ ^[0-9]+$ ]] && (( value >= 1 && value <= 65535 )) || { echo "Invalid port: $value" >&2; exit 1; }
done
[[ "$ADMIN_USERNAME" =~ ^[a-zA-Z0-9_.-]{3,32}$ ]] || { echo "Invalid ADMIN_USERNAME" >&2; exit 1; }
[[ "$SSL_MODE" =~ ^(auto|acme|selfsigned|off)$ ]] || { echo "SSL_MODE must be auto, acme, selfsigned or off" >&2; exit 1; }
[[ -z "$ACME_EMAIL" || "$ACME_EMAIL" =~ ^[^@[:space:]\"\\]+@[^@[:space:]\"\\]+\.[^@[:space:]\"\\]+$ ]] || { echo "Invalid ACME_EMAIL" >&2; exit 1; }
(( PANEL_PORT != PROXY_PORT )) || { echo "PANEL_PORT must differ from PROXY_PORT" >&2; exit 1; }
(( PANEL_PORT != 80 )) || { echo "PANEL_PORT 80 is reserved for the Let's Encrypt challenge" >&2; exit 1; }

is_ipv4() { [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; }
is_domain() { [[ "$1" =~ ^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$ ]]; }

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y ca-certificates curl tar gzip ufw openssl iproute2 jq

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
GO_ARCHIVE="$(mktemp /tmp/go.XXXXXX.tar.gz)"
curl -fL --retry 3 -o "$GO_ARCHIVE" "https://go.dev/dl/${GO_VERSION}.linux-${GO_ARCH}.tar.gz"
rm -rf /usr/local/go
tar -C /usr/local -xzf "$GO_ARCHIVE"
rm -f "$GO_ARCHIVE"
export PATH="/usr/local/go/bin:$PATH"

go version
go mod download
go test ./...
install -d -m 0755 /usr/local/bin /usr/share/klink/web /etc/klink
CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /usr/local/bin/klink-server.new ./cmd/server
CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /usr/local/bin/klink-panel.new ./cmd/panel
mv -f /usr/local/bin/klink-server.new /usr/local/bin/klink-server
mv -f /usr/local/bin/klink-panel.new /usr/local/bin/klink-panel
cp -a web/. /usr/share/klink/web/

if ! id klink >/dev/null 2>&1; then
  useradd --system --home /var/lib/klink --shell /usr/sbin/nologin klink
fi
install -d -o klink -g klink -m 0750 /var/lib/klink

# ---------------------------------------------------------------- SSL planning
LOCAL_IPV4="$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.*src \([0-9.]*\).*/\1/p' | head -n1 || true)"
PUBLIC_IPV4="$(curl -4 -fsS --max-time 6 https://api.ipify.org 2>/dev/null || curl -4 -fsS --max-time 6 https://ifconfig.me 2>/dev/null || true)"
is_ipv4 "$PUBLIC_IPV4" || PUBLIC_IPV4="$LOCAL_IPV4"

if [[ -z "$DOMAIN" ]] && is_domain "$PUBLIC_HOST"; then DOMAIN="$PUBLIC_HOST"; fi
if [[ -z "$DOMAIN" && "$SSL_MODE" =~ ^(auto|acme)$ && ! -f /etc/klink/panel.json && -t 0 ]]; then
  read -r -p "Domain pointing to this server, for the panel SSL certificate (leave empty if none): " DOMAIN || true
fi
DOMAIN="${DOMAIN,,}"
DOMAIN="${DOMAIN%.}"
if [[ -n "$DOMAIN" ]] && ! is_domain "$DOMAIN"; then echo "Invalid DOMAIN: $DOMAIN" >&2; exit 1; fi

# A certificate is requested only when the domain really resolves to this
# server and port 80 is free for the HTTP-01 challenge; otherwise Let's Encrypt
# would fail and rate-limit the domain.
dns_points_here() {
  local resolved
  resolved="$(getent ahostsv4 "$1" 2>/dev/null | awk '{print $1}' | sort -u)"
  [[ -n "$resolved" ]] || return 1
  grep -qxF "$PUBLIC_IPV4" <<<"$resolved" && return 0
  [[ -n "$LOCAL_IPV4" ]] && grep -qxF "$LOCAL_IPV4" <<<"$resolved"
}
port80_busy_by_other() {
  local owner
  owner="$(ss -Hltnp 'sport = :80' 2>/dev/null || true)"
  [[ -n "$owner" ]] && ! grep -q '"klink-panel"' <<<"$owner"
}

EFFECTIVE_SSL="off"
case "$SSL_MODE" in
  off) EFFECTIVE_SSL="off" ;;
  selfsigned) EFFECTIVE_SSL="selfsigned" ;;
  acme|auto)
    if [[ -z "$DOMAIN" ]]; then
      [[ "$SSL_MODE" == "acme" ]] && { echo "SSL_MODE=acme requires DOMAIN" >&2; exit 1; }
      EFFECTIVE_SSL="selfsigned"
    elif port80_busy_by_other; then
      echo "WARNING: TCP port 80 is used by another program; Let's Encrypt HTTP-01 needs it." >&2
      [[ "$SSL_MODE" == "acme" ]] && exit 1
      EFFECTIVE_SSL="selfsigned"
    elif dns_points_here "$DOMAIN" || [[ "$FORCE_ACME" == "1" ]]; then
      EFFECTIVE_SSL="acme"
    else
      echo "WARNING: ${DOMAIN} does not resolve to this server (${PUBLIC_IPV4:-unknown})." >&2
      echo "         Point its DNS A record here (without a CDN proxy) and re-run, or set FORCE_ACME=1." >&2
      [[ "$SSL_MODE" == "acme" ]] && exit 1
      EFFECTIVE_SSL="selfsigned"
    fi ;;
esac
echo "Panel TLS mode: ${EFFECTIVE_SSL}${DOMAIN:+ (domain ${DOMAIN})}"

make_selfsigned() {
  local name="$1" san
  if is_ipv4 "$name"; then san="IP:${name}"; else san="DNS:${name}"; fi
  if [[ -n "$PUBLIC_IPV4" && "$name" != "$PUBLIC_IPV4" ]]; then san="${san},IP:${PUBLIC_IPV4}"; fi
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -sha256 -days 825 \
    -subj "/CN=${name}" -addext "subjectAltName=${san}" \
    -keyout /etc/klink/panel.key -out /etc/klink/panel.crt >/dev/null 2>&1
  chown root:klink /etc/klink/panel.key /etc/klink/panel.crt
  chmod 0640 /etc/klink/panel.key
  chmod 0644 /etc/klink/panel.crt
}

CREDENTIALS_FILE=""
SSL_APPLY=0
if [[ ! -f /etc/klink/server.json ]]; then
  if [[ -z "$PUBLIC_HOST" ]]; then
    PUBLIC_HOST="${DOMAIN:-${PUBLIC_IPV4:-$LOCAL_IPV4}}"
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

  # Secrets are written with a private umask so they are never world-readable,
  # not even for the moment between creation and chmod.
  umask 077
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
  "log_level": "info",
  "allow_private_destinations": false
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
  chown root:klink /etc/klink/server.json /etc/klink/panel.json
  chmod 0640 /etc/klink/server.json /etc/klink/panel.json
  CREDENTIALS_FILE="/root/klink-credentials.txt"
  cat >"$CREDENTIALS_FILE" <<EOF
KLINK panel: ${PUBLIC_URL}
Username: ${ADMIN_USERNAME}
Password: ${ADMIN_PASSWORD}
Server public key: ${SERVER_PUBLIC}
EOF
  umask 022
  SSL_APPLY=1
else
  echo "Existing /etc/klink configuration preserved; no keys or passwords rotated."
  # An existing installation is switched to HTTPS only when asked explicitly,
  # because the panel and subscription URLs change from http:// to https://.
  if [[ -n "$DOMAIN" || "$SSL_MODE" == "selfsigned" || "$SSL_MODE" == "acme" ]]; then SSL_APPLY=1; fi
  if [[ "$SSL_APPLY" == "1" && "$EFFECTIVE_SSL" != "acme" ]] && jq -e '(.acme_domain // "") != ""' /etc/klink/panel.json >/dev/null; then
    echo "Keeping the existing Let's Encrypt configuration (the new domain check did not pass)."
    SSL_APPLY=0
  fi
fi

# ---------------------------------------------------------------- apply SSL
panel_set() { # panel_set <jq filter> [jq args...]
  local filter="$1" tmp
  shift
  tmp="$(mktemp /etc/klink/.panel.json.XXXXXX)"
  jq "$@" "$filter" /etc/klink/panel.json >"$tmp"
  chown root:klink "$tmp"
  chmod 0640 "$tmp"
  mv -f "$tmp" /etc/klink/panel.json
}
if [[ "$SSL_APPLY" == "1" && "$EFFECTIVE_SSL" != "off" ]]; then
  url_host="$(jq -r '.public_url' /etc/klink/panel.json | sed -E 's#^[a-zA-Z]+://([^/:]+).*#\1#')"
  case "$EFFECTIVE_SSL" in
    acme)
      install -d -o klink -g klink -m 0700 /var/lib/klink/acme
      panel_set '.acme_domain=$d | .acme_email=$e | .acme_cache_dir="/var/lib/klink/acme" | .acme_http_listen=":80"
        | .tls_cert_file="" | .tls_key_file="" | .secure_cookies=true | .public_url=("https://"+$d+":"+$p)' \
        --arg d "$DOMAIN" --arg e "$ACME_EMAIL" --arg p "$PANEL_PORT"
      ;;
    selfsigned)
      cert_name="${DOMAIN:-$url_host}"
      [[ -n "$cert_name" ]] || cert_name="${PUBLIC_IPV4:-$LOCAL_IPV4}"
      make_selfsigned "$cert_name"
      panel_set 'del(.acme_domain, .acme_email, .acme_cache_dir, .acme_http_listen)
        | .tls_cert_file="/etc/klink/panel.crt" | .tls_key_file="/etc/klink/panel.key" | .secure_cookies=true
        | .public_url=("https://"+$h+":"+$p)' --arg h "$cert_name" --arg p "$PANEL_PORT"
      ;;
  esac
  PUBLIC_URL="$(jq -r '.public_url' /etc/klink/panel.json)"
  if [[ -n "$CREDENTIALS_FILE" && -f "$CREDENTIALS_FILE" ]]; then
    sed -i "1s#^KLINK panel: .*#KLINK panel: ${PUBLIC_URL}#" "$CREDENTIALS_FILE"
  fi
fi
ACME_ACTIVE="$(jq -r '.acme_domain // ""' /etc/klink/panel.json)"

# Shared systemd sandbox. Both services only need the network and /var/lib/klink.
HARDENING='NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/var/lib/klink
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
SystemCallArchitectures=native
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
UMask=0077'

cat >/etc/systemd/system/klink-core.service <<EOF
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
${HARDENING}

[Install]
WantedBy=multi-user.target
EOF
cat >/etc/systemd/system/klink-panel.service <<EOF
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
# Needed only for the Let's Encrypt HTTP-01 listener on port 80 (or a panel port below 1024).
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
${HARDENING}

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable klink-core.service klink-panel.service
systemctl restart klink-core.service klink-panel.service

# Never lock the administrator out: allow every port sshd really listens on,
# not only SSH_PORT (the default 22 is wrong on servers with a custom SSH port).
SSH_PORTS="$(ss -Hltnp 2>/dev/null | awk '/"sshd"/ {n=split($4,a,":"); print a[n]}' | sort -un | tr '\n' ' ' || true)"
for port in "$SSH_PORT" $SSH_PORTS; do
  ufw allow "${port}/tcp" comment 'SSH'
done
ufw allow "${PROXY_PORT}/udp" comment 'KLINK UDP'
ufw allow "${PROXY_PORT}/tcp" comment 'KLINK TCP'
ufw allow "${PANEL_PORT}/tcp" comment 'KLINK panel'
if [[ -n "$ACME_ACTIVE" ]]; then
  ufw allow 80/tcp comment "KLINK Let's Encrypt"
fi
ufw --force enable

sleep 2
systemctl --no-pager --full status klink-core.service klink-panel.service || true
curl -fsS --retry 5 --retry-delay 1 --retry-connrefused http://127.0.0.1:9091/healthz >/dev/null

# Trigger and verify the first certificate. The request goes to this machine
# with the real SNI, so it also works where the provider blocks hairpin NAT.
if [[ -n "$ACME_ACTIVE" ]]; then
  echo "Requesting the Let's Encrypt certificate for ${ACME_ACTIVE} ..."
  if curl -fsS -o /dev/null --max-time 180 --retry 2 --retry-delay 10 --retry-all-errors \
      --resolve "${ACME_ACTIVE}:${PANEL_PORT}:127.0.0.1" "https://${ACME_ACTIVE}:${PANEL_PORT}/"; then
    echo "SSL certificate is active; it is renewed automatically before it expires."
  else
    echo "WARNING: the certificate could not be obtained yet. Check that ${ACME_ACTIVE} points to this" >&2
    echo "         server and that TCP port 80 is reachable, then see: journalctl -u klink-panel -e" >&2
  fi
fi

echo
echo "KLINK installation completed."
if [[ -n "$CREDENTIALS_FILE" ]]; then
  cat "$CREDENTIALS_FILE"
  echo "Credentials also saved in ${CREDENTIALS_FILE} (root-only)."
fi
case "$(jq -r 'if (.acme_domain // "") != "" then "acme" elif (.tls_cert_file // "") != "" then "tls" else "http" end' /etc/klink/panel.json)" in
  acme) echo "Panel HTTPS: Let's Encrypt certificate for ${ACME_ACTIVE} (renewed automatically)." ;;
  tls)
    echo "Panel HTTPS: certificate /etc/klink/panel.crt. A self-signed certificate shows a browser warning;"
    echo "             re-run with DOMAIN=your.domain to get a trusted Let's Encrypt certificate." ;;
  *) echo "WARNING: the panel uses plain HTTP. Re-run with DOMAIN=your.domain (or SSL_MODE=selfsigned) to enable HTTPS." ;;
esac
