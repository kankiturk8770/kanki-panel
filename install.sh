#!/usr/bin/env bash
# =====================================================================
#  Kanki Panel installer
#  bash <(curl -fsSL https://raw.githubusercontent.com/kankiturk8770/kanki-panel/main/install.sh)
#  After install you can run:  kanki
# =====================================================================
set -e
Y='\033[1;33m'; R='\033[1;31m'; N='\033[0m'; G='\033[1;32m'; C='\033[1;36m'
say(){ echo -e "${Y}>> $*${N}"; }
ok(){ echo -e "${G}[ok] $*${N}"; }
warn(){ echo -e "${R}[!] $*${N}"; }
die(){ echo -e "${R}[x] $*${N}"; exit 1; }
# not root (e.g. the "ubuntu" user of a cloud server): run again with sudo, keeping the KANKI_* settings
if [ "$(id -u)" != "0" ]; then
  command -v sudo >/dev/null || die "Please run as root (this server has no sudo)"
  say "Not root: running again with sudo ..."
  keep=()
  for v in KANKI_REPO KANKI_JOIN KANKI_PANEL KANKI_TUNNEL KANKI_DOMAIN KANKI_EMAIL KANKI_SSL KANKI_MOVE KANKI_PORTS KANKI_LOCAL_BIN; do
    if [ -n "${!v:-}" ]; then keep+=("$v=${!v}"); fi
  done
  # started as a file (the "kanki" command): run that file. Started as `bash <(curl ...)` or
  # `curl ... | bash`: the script is a pipe sudo cannot reopen, so fetch it again into a file
  if [ -f "$0" ] && [ -r "$0" ]; then
    self="$0"
  else
    r="${KANKI_REPO:-}"; echo "$r" | grep -Eq '^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$' || r="kankiturk8770/kanki-panel"
    self=$(mktemp) || die "mktemp failed"
    curl -fsSL "https://raw.githubusercontent.com/$r/main/install.sh" -o "$self" \
      || die "Could not download the installer again; run it as root (sudo -i)"
  fi
  exec sudo env "${keep[@]}" bash "$self" "$@"
fi
command -v apt-get >/dev/null || die "Only Ubuntu / Debian are supported"
# the port checks use `ss` (iproute2); a minimal image without it would see every port as free
command -v ss >/dev/null || { apt-get update -qq && apt-get install -y -qq iproute2; } >/dev/null 2>&1 || true

ENV_DIR=/etc/kanki; ENV=$ENV_DIR/kanki.env; BIN=/usr/local/bin/kanki-panel; TLS=$ENV_DIR/tls
mkdir -p "$ENV_DIR"; chmod 711 "$ENV_DIR"

rand(){ tr -dc 'A-Za-z0-9' </dev/urandom | head -c "${1:-24}"; }
rnum(){ shuf -i "$1"-"$2" -n 1; }
pubip(){ # the public IPv4; an error page from the lookup service is never taken for an address
  local ip; ip=$(curl -fs4 --max-time 8 https://api.ipify.org 2>/dev/null | tr -d '[:space:]')
  echo "$ip" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}$' || ip=$(hostname -I | awk '{print $1}')
  echo "$ip"; }
port_busy(){ ss -Htuln | awk '{print $5}' | grep -Eq "[:.]$1\$"; }
ask(){ # $1=var $2=prompt $3=default
  local v; read -rp "$2${3:+ [$3]}: " v; printf -v "$1" '%s' "${v:-$3}"; }
ask_port(){ # $1=var $2=prompt $3=default $4=proto(tcp/udp)
  local p
  while true; do
    ask p "$2" "$3"
    [[ "$p" =~ ^[0-9]+$ ]] && [ "$p" -ge 1 ] && [ "$p" -le 65535 ] || { warn "Invalid port"; continue; }
    if port_busy "$p"; then
      warn "Port $p is already in use:"; ss -tulnp | grep -E "[:.]$p " || true
      yes_no "Use it anyway (only if it is a Kanki service being reinstalled)?" N || continue
    fi
    break
  done
  printf -v "$1" '%s' "$p"; }
yes_no(){ local a; read -rp "$1 [${2:-Y}/$( [ "${2:-Y}" = Y ] && echo n || echo y )]: " a; a=${a:-${2:-Y}}; [[ "$a" =~ ^[Yy]$ ]]; }

# ---------------- GitHub repo (binary releases)
DEFAULT_REPO="kankiturk8770/kanki-panel"
REPO="${KANKI_REPO:-$(cat $ENV_DIR/repo 2>/dev/null || true)}"
# a missing or invalid value (e.g. just "kanki") falls back to the built-in repo
echo "$REPO" | grep -Eq '^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$' || REPO="$DEFAULT_REPO"
# one-command node join: the panel (Nodes > Add node) prints a line that sets these two
KANKI_JOIN="${KANKI_JOIN:-}"; KANKI_PANEL="${KANKI_PANEL:-}"
# --cores=wg,awg,…: the cores chosen in the panel's «Add server» window (switched on when it joins)
for a in "$@"; do case "$a" in --cores=*) KANKI_CORES="${a#--cores=}" ;; esac; done
KANKI_CORES="${KANKI_CORES:-}"
# one-command tunnel server (Tunnels > + Server): KANKI_TUNNEL=ID:TOKEN
KANKI_TUNNEL="${KANKI_TUNNEL:-}"
envget(){ grep -m1 "^$1=" "$ENV" 2>/dev/null | cut -d= -f2-; }
free_port(){ # $1=var $2=preferred port: keep it when free, otherwise take a random free one (no questions)
  local p="$2"
  while port_busy "$p"; do p=$(rnum 20000 59999); done
  printf -v "$1" '%s' "$p"; }
need_repo(){
  [ -n "$REPO" ] || REPO="$DEFAULT_REPO"
  echo "$REPO" > $ENV_DIR/repo
}

# The program from the panel itself (a new server is given a token for it): works where GitHub is
# filtered, and the server runs exactly the panel's version. Fails quietly so GitHub is tried next.
download_from_panel(){
  local id="" t="" q base="${KANKI_PANEL%/}"
  [ -n "$base" ] || return 1
  if [ -n "$KANKI_TUNNEL" ]; then id="${KANKI_TUNNEL%%:*}"; t="${KANKI_TUNNEL#*:}"; else t="$KANKI_JOIN"; fi
  [ -n "$t" ] || return 1
  q="id=$id&t=$t&arch=$(uname -m)"
  say "Downloading Kanki from the panel ($base) ..."
  local d; d=$(mktemp -d) || return 1
  curl -fsL --retry 2 --max-time 300 -o "$d/kanki-panel" "$base/dl/kanki-panel?$q" 2>/dev/null || { rm -rf "$d"; return 1; }
  curl -fsL --max-time 30 -o "$d/kanki-panel.sha256" "$base/dl/kanki-panel.sha256?$q" 2>/dev/null || { rm -rf "$d"; return 1; }
  (cd "$d" && sha256sum -c kanki-panel.sha256 >/dev/null 2>&1) || { warn "The panel's copy did not check out; trying GitHub"; rm -rf "$d"; return 1; }
  install -m 755 "$d/kanki-panel" "$BIN"
  rm -rf "$d"
}

# the `kanki` menu command: this installer itself
install_menu(){
  local tmp; tmp=$(mktemp /usr/local/bin/.kanki.XXXXXX) || return 0
  # write to a temp file and rename: the running script keeps reading its old copy
  # (writing over it in place made bash read the new text mid-run: "syntax error near ')'")
  if { [ -n "${KANKI_PANEL:-}" ] && curl -fsSL "${KANKI_PANEL%/}/dl/install.sh" -o "$tmp" 2>/dev/null && bash -n "$tmp" 2>/dev/null; } \
     || { curl -fsSL "https://raw.githubusercontent.com/$REPO/main/install.sh" -o "$tmp" 2>/dev/null && bash -n "$tmp" 2>/dev/null; } \
     || { [ -f "$0" ] && [ -r "$0" ] && cp "$0" "$tmp" && bash -n "$tmp" 2>/dev/null; }; then
    chmod +x "$tmp" && mv -f "$tmp" /usr/local/bin/kanki
  else
    rm -f "$tmp"
  fi
}

download_bin(){
  # started by the server's own agent (Install VPN in the panel): the program is already here
  if [ "${KANKI_LOCAL_BIN:-}" = 1 ] && [ -x "$BIN" ]; then
    ok "Using the Kanki program already on this server ($($BIN version))"; install_menu; return 0
  fi
  if download_from_panel; then install_menu; ok "$($BIN version)"; return 0; fi
  say "Downloading Kanki Panel from $REPO ..."
  local base="https://github.com/$REPO/releases/download/latest"
  say "URL: $base/kanki-panel"
  # a private folder of our own (a fixed /tmp name could be a link someone else made)
  local d; d=$(mktemp -d) || die "mktemp failed"
  curl -fL --retry 3 --max-time 600 -o "$d/kanki-panel" "$base/kanki-panel" \
    || die "Download failed. The repo must be public and the GitHub Actions build must have succeeded."
  # no checksum file = no installation (a missing file must not silently skip the check)
  curl -fsL --retry 3 --max-time 60 "$base/kanki-panel.sha256" -o "$d/kanki-panel.sha256" \
    || die "Could not download kanki-panel.sha256, aborting (the binary was not verified)"
  (cd "$d" && sha256sum -c kanki-panel.sha256 >/dev/null) || die "Checksum mismatch, aborting"
  install -m 755 "$d/kanki-panel" "$BIN"
  rm -rf "$d"
  install_menu
  ok "$($BIN version)"
}

base_packages(){
  say "Installing base packages ..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq curl wget iptables wireguard-tools openssl ca-certificates gnupg software-properties-common tar \
    "linux-headers-$(uname -r)" >/dev/null 2>&1 || apt-get install -y -qq curl wget iptables wireguard-tools openssl ca-certificates gnupg software-properties-common tar >/dev/null
  cat > /etc/sysctl.d/99-kanki.conf <<EOF
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
net.core.rmem_max=16777216
net.core.wmem_max=16777216
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF
  sysctl -q --system || true
  getent group kankitls >/dev/null || groupadd kankitls
}

iface_rules(){ # $1=subnet
  local ETH; ETH=$(ip route show default | awk '{print $5; exit}')
  echo "PostUp = iptables -t nat -A POSTROUTING -s $1 -o $ETH -j MASQUERADE; iptables -A FORWARD -s $1 -j ACCEPT; iptables -A FORWARD -d $1 -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -s $1 -o $ETH -j MASQUERADE; iptables -D FORWARD -s $1 -j ACCEPT; iptables -D FORWARD -d $1 -j ACCEPT"
}

setup_wireguard(){
  say "Setting up WireGuard on UDP $WG_PORT ..."
  mkdir -p /etc/wireguard
  if [ ! -f /etc/wireguard/wg0.conf ]; then
    cat > /etc/wireguard/wg0.conf <<EOF
[Interface]
Address = 10.66.0.1/16
ListenPort = $WG_PORT
PrivateKey = $(wg genkey)
$(iface_rules 10.66.0.0/16)
EOF
    chmod 600 /etc/wireguard/wg0.conf
  else
    local cur; cur=$(conf_port /etc/wireguard/wg0.conf)
    if [ -n "$cur" ] && [ "$cur" != "$WG_PORT" ]; then
      warn "WireGuard keeps its port $cur (users' files use it); to move it run 'kanki', option 8"; WG_PORT=$cur
    fi
  fi
  systemctl enable -q --now wg-quick@wg0 && ok "WireGuard is running" || warn "WireGuard failed to start"
}

setup_amneziawg(){
  say "Installing AmneziaWG (kernel module from the official Amnezia PPA) ..."
  if ! command -v awg >/dev/null; then
    add-apt-repository -y ppa:amnezia/ppa >/dev/null 2>&1 || true
    apt-get update -qq
    apt-get install -y -qq amneziawg amneziawg-tools >/dev/null 2>&1 || apt-get install -y -qq amneziawg-dkms amneziawg-tools >/dev/null 2>&1 || true
  fi
  if ! command -v awg >/dev/null; then warn "AmneziaWG could not be installed; skipping it"; AWG_PORT=""; return; fi
  mkdir -p /etc/amnezia/amneziawg
  if [ ! -f /etc/amnezia/amneziawg/awg0.conf ]; then
    local H1 H2 H3 H4
    H1=$(rnum 100000 400000000); H2=$(rnum 400000001 800000000); H3=$(rnum 800000001 1200000000); H4=$(rnum 1200000001 2000000000)
    cat > /etc/amnezia/amneziawg/awg0.conf <<EOF
[Interface]
Address = 10.67.0.1/16
ListenPort = $AWG_PORT
PrivateKey = $(wg genkey)
Jc = $(rnum 3 6)
Jmin = 40
Jmax = 70
S1 = $(rnum 15 60)
S2 = $(rnum 61 120)
H1 = $H1
H2 = $H2
H3 = $H3
H4 = $H4
$(iface_rules 10.67.0.0/16)
EOF
    chmod 600 /etc/amnezia/amneziawg/awg0.conf
  else
    local cur; cur=$(conf_port /etc/amnezia/amneziawg/awg0.conf)
    if [ -n "$cur" ] && [ "$cur" != "$AWG_PORT" ]; then
      warn "AmneziaWG keeps its port $cur (users' files use it); to move it run 'kanki', option 8"; AWG_PORT=$cur
    fi
  fi
  systemctl enable -q --now awg-quick@awg0 && ok "AmneziaWG is running" || warn "AmneziaWG failed to start (the server may need a reboot)"
}

tls_perms(){
  chgrp kankitls "$TLS" $TLS/*.pem; chmod 750 "$TLS"; chmod 640 $TLS/*.pem
}

get_cert(){ # $1=domain $2=email; CERT_SOFT=1: a failure warns and returns 1 instead of stopping the install
  say "Getting an SSL certificate for $1 ..."
  apt-get install -y -qq certbot >/dev/null
  port_busy 80 && warn "Port 80 is busy; certbot needs it free for a moment" || true
  certbot certonly --standalone -n --agree-tos -m "$2" -d "$1" \
    --pre-hook "systemctl stop caddy 2>/dev/null || true" --post-hook "systemctl start caddy 2>/dev/null || true" \
    || { [ -n "${CERT_SOFT:-}" ] && { warn "SSL failed: a self-signed certificate is used. The domain must point DIRECTLY (no Cloudflare proxy) to this server and port 80 must be open; then press «Try SSL again» in the panel."; return 1; }
         die "SSL failed. The domain must point DIRECTLY (no Cloudflare proxy) to this server and port 80 must be open."; }
  mkdir -p /etc/letsencrypt/renewal-hooks/deploy "$TLS"
  cat > /etc/letsencrypt/renewal-hooks/deploy/kanki.sh <<EOF
#!/bin/sh
cp -L /etc/letsencrypt/live/$1/fullchain.pem $TLS/fullchain.pem
cp -L /etc/letsencrypt/live/$1/privkey.pem $TLS/privkey.pem
chgrp kankitls $TLS/*.pem; chmod 640 $TLS/*.pem
systemctl reload caddy 2>/dev/null || true
systemctl restart hysteria-server 2>/dev/null || true
EOF
  chmod +x /etc/letsencrypt/renewal-hooks/deploy/kanki.sh
  sh /etc/letsencrypt/renewal-hooks/deploy/kanki.sh
  tls_perms
  ok "SSL ready (auto renew enabled)"
}

self_signed(){
  mkdir -p "$TLS"
  openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=kanki-node" -keyout $TLS/privkey.pem -out $TLS/fullchain.pem >/dev/null 2>&1
  tls_perms
}

# The official installer (get.hy2.sh). It first asks api.hy2.io for the newest version and gives up
# when only that site is blocked: then the same GitHub file is downloaded and handed to the same
# installer (--local), so the result is identical.
hy2_install(){
  command -v hysteria >/dev/null && return 0
  bash <(curl -fsSL https://get.hy2.sh/ 2>/dev/null) >/dev/null 2>&1; command -v hysteria >/dev/null && return 0
  local a f=/tmp/kanki-hysteria.bin s=/tmp/kanki-hy2-install.sh u
  case "$(uname -m)" in x86_64|amd64) a=amd64;; aarch64|arm64) a=arm64;; armv7*|armv6*) a=arm;; i?86) a=386;; riscv64) a=riscv64;; s390x) a=s390x;; *) return 1;; esac
  curl -fsSL --max-time 60 -o $s https://get.hy2.sh/ 2>/dev/null || curl -fsSL --max-time 60 -o $s https://raw.githubusercontent.com/apernet/hysteria/master/scripts/install_server.sh 2>/dev/null || s=""
  for u in "https://github.com/apernet/hysteria/releases/latest/download/hysteria-linux-$a" "https://download.hysteria.network/app/latest/hysteria-linux-$a"; do
    if curl -fsSL --connect-timeout 10 --max-time 180 -o $f "$u" 2>/dev/null && [ "$(head -c4 $f | tail -c3)" = "ELF" ]; then
      if [ -n "$s" ]; then bash $s --local $f >/dev/null 2>&1; else install -Dm755 $f /usr/local/bin/hysteria && hy2_unit; fi
    fi
    rm -f $f; command -v hysteria >/dev/null && { rm -f $s; return 0; }
  done
  rm -f $s; return 1
}
# The service the official installer makes (user "hysteria", the same unit), for when only the
# program itself could be downloaded
hy2_unit(){
  id hysteria >/dev/null 2>&1 || useradd --system --home-dir /var/lib/hysteria --create-home --shell /usr/sbin/nologin hysteria
  cat > /etc/systemd/system/hysteria-server.service <<'EOF'
[Unit]
Description=Hysteria Server Service (config.yaml)
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/hysteria server --config /etc/hysteria/config.yaml
WorkingDirectory=~
User=hysteria
Group=hysteria
Environment=HYSTERIA_LOG_LEVEL=info
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
}
setup_hysteria(){ # $1=auth url
  say "Installing Hysteria2 on UDP $HY2_PORT ..."
  hy2_install || { warn "Hysteria2 could not be installed"; HY2_PORT=""; return; }
  # the program without its service would look installed but never run
  systemctl cat hysteria-server.service >/dev/null 2>&1 || hy2_unit
  systemctl cat hysteria-server.service >/dev/null 2>&1 || { warn "Hysteria2 has no service on this server; it is not used"; HY2_PORT=""; return; }
  id hysteria >/dev/null 2>&1 && usermod -aG kankitls hysteria
  mkdir -p /etc/hysteria
  cat > /etc/hysteria/config.yaml <<EOF
listen: :$HY2_PORT
tls:
  cert: $TLS/fullchain.pem
  key: $TLS/privkey.pem
obfs:
  type: salamander
  salamander:
    password: $HY2_OBFS
auth:
  type: http
  http:
    url: $1
trafficStats:
  listen: 127.0.0.1:$HY2_STATS_PORT
  secret: $HY2_SECRET
acl:
  inline:
    - reject(127.0.0.0/8)
    - reject(::1)
    - reject(localhost)
EOF
  systemctl enable -q hysteria-server.service 2>/dev/null || true
  systemctl restart hysteria-server.service && ok "Hysteria2 is running" || warn "Hysteria2 failed to start"
}

install_caddy(){
  if ! command -v caddy >/dev/null; then
    apt-get update -qq; apt-get install -y -qq caddy >/dev/null 2>&1 || true
  fi
  if ! command -v caddy >/dev/null; then
    local ca cf
    case "$(uname -m)" in x86_64|amd64) ca=amd64;; aarch64|arm64) ca=arm64;; *) die "Caddy could not be installed (no package and no download for $(uname -m))";; esac
    cf=$(mktemp) || die "mktemp failed"
    # the downloaded program must really run here before it takes the place of /usr/bin/caddy
    if curl -fsSL --max-time 300 "https://caddyserver.com/api/download?os=linux&arch=$ca" -o "$cf" && chmod 755 "$cf" && "$cf" version >/dev/null 2>&1; then
      mv -f "$cf" /usr/bin/caddy
    else
      rm -f "$cf"; die "Caddy could not be downloaded"
    fi
    id caddy >/dev/null 2>&1 || useradd --system --home /var/lib/caddy --create-home --shell /usr/sbin/nologin caddy
    mkdir -p /etc/caddy
    printf '[Unit]\nDescription=Caddy\nAfter=network-online.target\n[Service]\nUser=caddy\nGroup=caddy\nExecStart=/usr/bin/caddy run --environ --config /etc/caddy/Caddyfile\nExecReload=/usr/bin/caddy reload --config /etc/caddy/Caddyfile --force\nAmbientCapabilities=CAP_NET_BIND_SERVICE\nRestart=on-failure\n[Install]\nWantedBy=multi-user.target\n' > /etc/systemd/system/caddy.service
    systemctl daemon-reload
  fi
  command -v caddy >/dev/null || die "Caddy could not be installed"
  id caddy >/dev/null 2>&1 || useradd --system --shell /usr/sbin/nologin caddy
  usermod -aG kankitls caddy
}

setup_caddy(){ # $1=site address $2=upstream port
  say "Setting up the Caddy web server ($1) ..."
  install_caddy
  cat > /etc/caddy/Caddyfile <<EOF
{
  auto_https off
}
$1 {
  tls $TLS/fullchain.pem $TLS/privkey.pem
  @blocked path /hy2/*
  respond @blocked 404
  header {
    Strict-Transport-Security "max-age=31536000"
    X-Content-Type-Options nosniff
    Referrer-Policy no-referrer
    -Server
  }
  reverse_proxy 127.0.0.1:$2
}
EOF
  systemctl enable -q caddy
  systemctl restart caddy && ok "Caddy is running" || { journalctl -u caddy -n 15 --no-pager; warn "Caddy failed to start (is the port free?)"; }
}

open_ports(){
  if command -v ufw >/dev/null && ufw status | grep -q "^Status: active"; then
    for p in "$@"; do if [ -n "${p%%/*}" ]; then ufw allow "$p" >/dev/null || true; fi; done
  fi
}

service(){ # $1=name $2=args
  cat > /etc/systemd/system/$1.service <<EOF
[Unit]
Description=Kanki ($1)
After=network-online.target wg-quick@wg0.service

[Service]
ExecStart=$BIN $2
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable -q "$1"
  systemctl restart "$1"
}

# The six cores, by number; $1 = the default ("" = none: the main server runs only the panel and its
# agent). Sets CORES (wg,awg,…).
pick_cores(){
  local d="$1" v n
  echo
  echo "  Which VPN cores should this server run?"
  echo "    0) None: only the panel / the server agent (monitoring)"
  echo "    1) WireGuard     2) AmneziaWG     3) Hysteria2"
  echo "    4) KANKI MIX     5) microtun      6) KPING (inside the server agent, nothing extra)"
  read -rp "  Numbers, comma separated (like 1,2 or 1,2,6) [${d:-0}]: " v
  v="${v:-${d:-0}}"; CORES=""
  for n in $(echo "$v" | tr ', ' '  '); do
    case "$n" in
      1) CORES="$CORES,wg" ;; 2) CORES="$CORES,awg" ;; 3) CORES="$CORES,hy2" ;;
      4) CORES="$CORES,kmix" ;; 5) CORES="$CORES,mtun" ;; 6) CORES="$CORES,kping" ;;
      0) ;; *) warn "Unknown choice: $n (skipped)" ;;
    esac
  done
  CORES="${CORES#,}"
  echo "  Cores: ${CORES:-none}"
}
has_core(){ [[ ",$CORES," == *",$1,"* ]]; }

ask_protocols(){
  # a reinstall offers the ports this server already uses (users' files point at them)
  local dw da dh
  dw=$(conf_port /etc/wireguard/wg0.conf); da=$(conf_port /etc/amnezia/amneziawg/awg0.conf); dh=$(envget HY2_PORT)
  pick_cores "$1"
  WG_PORT=""; AWG_PORT=""; HY2_PORT=""
  if has_core wg; then ask_port WG_PORT "WireGuard UDP port" "${dw:-51820}"; fi
  if has_core awg; then ask_port AWG_PORT "AmneziaWG UDP port" "${da:-51821}"; fi
  if has_core hy2; then ask_port HY2_PORT "Hysteria2 UDP port" "${dh:-8443}"; fi
  return 0
}

conf_port(){ awk -F' *= *' '/^ListenPort/{gsub(/[^0-9]/,"",$2); print $2; exit}' "$1" 2>/dev/null || true; }

# A reinstall keeps the Hysteria2 password and secret and the node token: the users' Hysteria2 links
# and the panel's access to this node keep working. New ones only on a first install.
keep_secrets(){
  local v hy=/etc/hysteria/config.yaml
  v=$(envget HY2_OBFS); [ -n "$v" ] || v=$(awk '/salamander:/{f=1;next} f&&/password:/{print $2; exit}' $hy 2>/dev/null || true)
  [ -n "$v" ] && HY2_OBFS=$v
  v=$(envget HY2_SECRET); [ -n "$v" ] || v=$(awk '/trafficStats:/{f=1;next} f&&/secret:/{print $2; exit}' $hy 2>/dev/null || true)
  [ -n "$v" ] && HY2_SECRET=$v
  v=$(envget HY2_STATS_PORT); [[ "$v" =~ ^[0-9]+$ ]] && HY2_STATS_PORT=$v
  if [ "$(envget MODE)" = node ]; then v=$(envget NODE_TOKEN); [ -n "$v" ] && NODE_TOKEN=$v; fi
  return 0
}

# =====================================================================
install_panel(){
  echo; say "Main panel installation"
  need_repo
  ask DOMAIN "Panel domain (must point directly to this server's IP)"
  [ -n "$DOMAIN" ] || die "Domain is required"
  ask EMAIL "Email for SSL"
  ask_port HTTPS_PORT "Panel HTTPS port" 2053
  ask ADMIN_USER "Admin username" admin
  while true; do
    read -rsp "Admin password (min 8 chars): " ADMIN_PASS; echo
    [ ${#ADMIN_PASS} -ge 8 ] && break; warn "Too short"
  done
  ask ENDPOINT "Public host/IP users connect to (empty = same as panel domain)" "$DOMAIN"
  ask LOCAL_NAME "Name of this server shown to users (e.g. Germany)" Main
  ask_port PANEL_PORT "Internal panel port (local only, behind HTTPS)" "$(rnum 20000 29999)"
  ask_protocols ""
  read -rsp "Telegram sales bot token (empty = no bot): " BOT_TOKEN; echo
  BOT_ADMINS=""; [ -n "$BOT_TOKEN" ] && ask BOT_ADMINS "Bot admin numeric ID(s), comma separated"

  HY2_STATS_PORT=$(rnum 30000 39999); HY2_OBFS=$(rand 20); HY2_SECRET=$(rand 24); keep_secrets
  echo; say "Summary"
  echo "  Domain: $DOMAIN  HTTPS: $HTTPS_PORT  Endpoint: $ENDPOINT  Server: $LOCAL_NAME"
  echo "  Cores: ${CORES:-none}  WireGuard: ${WG_PORT:-off}  AmneziaWG: ${AWG_PORT:-off}  Hysteria2: ${HY2_PORT:-off}"
  echo "  Bot: $([ -n "$BOT_TOKEN" ] && echo yes || echo no)"
  yes_no "Start installation?" Y || exit 0
  base_packages; download_bin
  get_cert "$DOMAIN" "$EMAIL"
  if [ -n "$WG_PORT" ]; then setup_wireguard; fi
  if [ -n "$AWG_PORT" ]; then setup_amneziawg; fi
  [ -n "$HY2_PORT" ] && setup_hysteria "http://127.0.0.1:$PANEL_PORT/hy2/auth"
  umask 077
  cat > $ENV <<EOF
MODE=panel
DOMAIN=$DOMAIN
ENDPOINT=$ENDPOINT
HTTPS_PORT=$HTTPS_PORT
PANEL_BIND=127.0.0.1
PANEL_PORT=$PANEL_PORT
ADMIN_USER=$ADMIN_USER
ADMIN_PASS=$($BIN hash-password "$ADMIN_PASS")
LOCAL_NAME=$LOCAL_NAME
BOT_TOKEN=$BOT_TOKEN
BOT_ADMINS=$BOT_ADMINS
HY2_PORT=$HY2_PORT
HY2_OBFS=$HY2_OBFS
HY2_SECRET=$HY2_SECRET
HY2_STATS_PORT=$HY2_STATS_PORT
CORES=$CORES
DATA_DIR=/var/lib/kanki
EOF
  umask 022
  setup_caddy "https://$DOMAIN:$HTTPS_PORT" "$PANEL_PORT"
  service kanki-panel serve
  open_ports 80/tcp "$HTTPS_PORT/tcp" "${WG_PORT:+$WG_PORT/udp}" "${AWG_PORT:+$AWG_PORT/udp}" "${HY2_PORT:+$HY2_PORT/udp}"
  echo; ok "Installation complete!"
  echo -e "   Panel:  ${C}https://$DOMAIN:$HTTPS_PORT/admin${N}"
  echo -e "   Login:  ${C}$ADMIN_USER${N} / (the password you entered)"
  [ -n "$BOT_TOKEN" ] && echo "   Bot:    send /start to your bot in Telegram"
  echo "   Manage: run 'kanki' any time"
}

install_node(){
  echo; say "Node installation (extra server)"
  need_repo
  if [ -n "$KANKI_JOIN" ]; then
    # join mode: nothing is asked, every protocol is installed on its default port (a random free one if busy)
    DOMAIN="${KANKI_DOMAIN:-}"; EMAIL="${KANKI_EMAIL:-}"
    if [ -n "$DOMAIN" ] && [ -z "$EMAIL" ]; then EMAIL="admin@$DOMAIN"; fi
    # the panel picks ports no other server of it uses (a tunnel entry can then carry them all)
    local pw=51820 pa=51821 ph=8443
    if [[ "${KANKI_PORTS:-}" =~ ^[0-9]+,[0-9]+,[0-9]+,[0-9]+$ ]]; then IFS=, read -r pw pa ph _ <<< "$KANKI_PORTS"; fi
    free_port NODE_PUBLIC_PORT 2096; free_port NODE_PORT "$(rnum 20000 29999)"
    free_port WG_PORT "$pw"; free_port AWG_PORT "$pa"; free_port HY2_PORT "$ph"
    # every core is installed (any can be switched on later with one tap); the panel switches on the
    # ones chosen in its «Add server» window (--cores) and keeps the rest off
    CORES="${KANKI_CORES:-}"
    if [ -n "$CORES" ]; then say "Cores the panel switches on: $CORES (the others are installed and off)"; fi
  else
    ask DOMAIN "Node domain (recommended for TLS; empty = self-signed certificate)"
    EMAIL=""; [ -n "$DOMAIN" ] && ask EMAIL "Email for SSL"
    ask_port NODE_PUBLIC_PORT "Node API port (HTTPS)" 2096
    ask_port NODE_PORT "Internal agent port (local only)" "$(rnum 20000 29999)"
    ask_protocols "1,2"
  fi
  HY2_STATS_PORT=$(rnum 30000 39999); HY2_OBFS=$(rand 20); HY2_SECRET=$(rand 24); NODE_TOKEN=$(rand 48); INSECURE=""; keep_secrets
  base_packages; download_bin
  # KANKI_SSL=0 (the panel's «without SSL»): no certbot; a joining server never stops on a failed SSL
  if [ -n "$DOMAIN" ] && [ "${KANKI_SSL:-1}" != 0 ]; then
    if [ -n "$KANKI_JOIN" ]; then CERT_SOFT=1 get_cert "$DOMAIN" "$EMAIL" || { self_signed; INSECURE=1; }; else get_cert "$DOMAIN" "$EMAIL"; fi
  else self_signed; INSECURE=1; fi
  if [ -n "$WG_PORT" ]; then setup_wireguard; fi
  if [ -n "$AWG_PORT" ]; then setup_amneziawg; fi
  [ -n "$HY2_PORT" ] && setup_hysteria "http://127.0.0.1:$NODE_PORT/hy2/auth"
  umask 077
  cat > $ENV <<EOF
MODE=node
DOMAIN=$DOMAIN
NODE_BIND=127.0.0.1
NODE_PORT=$NODE_PORT
NODE_PUBLIC_PORT=$NODE_PUBLIC_PORT
NODE_TOKEN=$NODE_TOKEN
HY2_PORT=$HY2_PORT
HY2_OBFS=$HY2_OBFS
HY2_SECRET=$HY2_SECRET
HY2_STATS_PORT=$HY2_STATS_PORT
HY2_INSECURE=$INSECURE
CORES=$CORES
DATA_DIR=/var/lib/kanki
EOF
  umask 022
  setup_caddy "https://:$NODE_PUBLIC_PORT" "$NODE_PORT"
  service kanki-node node
  open_ports "$NODE_PUBLIC_PORT/tcp" "${WG_PORT:+$WG_PORT/udp}" "${AWG_PORT:+$AWG_PORT/udp}" "${HY2_PORT:+$HY2_PORT/udp}"
  if [ -n "$KANKI_JOIN" ]; then register_node || return 1; return 0; fi
  IP=$(pubip)
  echo; ok "Node installed! In the panel go to Nodes > Add node and enter:"
  echo -e "   API address:  ${C}https://${DOMAIN:-$IP}:$NODE_PUBLIC_PORT${N}"
  echo -e "   Endpoint:     ${C}${DOMAIN:-$IP}${N}"
  echo -e "   Node token:   ${C}$NODE_TOKEN${N}"
  [ -n "$INSECURE" ] && echo -e "   ${Y}No domain: tick 'Self-signed certificate' when adding the node.${N}"
  echo "   Tip: allow port $NODE_PUBLIC_PORT only from the main panel IP for extra safety."
}

register_node(){ # tells the panel about this node; needs DOMAIN NODE_PUBLIC_PORT NODE_TOKEN INSECURE KANKI_PANEL KANKI_JOIN
  local host name ins body res
  host="${DOMAIN:-$(pubip)}"
  name="$(hostname | tr -cd 'A-Za-z0-9._-')"; name="${name:-node}"
  ins=false; [ -n "$INSECURE" ] && ins=true
  body="{\"token\":\"$KANKI_JOIN\",\"name\":\"$name\",\"address\":\"https://$host:$NODE_PUBLIC_PORT\",\"endpoint\":\"$host\",\"node_token\":\"$NODE_TOKEN\",\"insecure\":$ins}"
  say "Telling the panel about this node ..."
  # the tokens go only over a checked certificate (or the plain http:// address the panel gave)
  res=$(curl -sS -m 90 -X POST -H 'Content-Type: application/json' -d "$body" "$KANKI_PANEL/join/register" 2>&1) || {
    # only to say why: the panel answers when its certificate is not checked (nothing is sent)
    if curl -sk -m 15 -o /dev/null "$KANKI_PANEL/" 2>/dev/null; then
      res="the panel's certificate cannot be checked from this server, so the tokens were not sent ($res)"
    fi; }
  if echo "$res" | grep -q '"ok":true'; then
    echo; ok "Done! This server is now a node of $KANKI_PANEL (open Nodes in the panel)."
  else
    echo; warn "The node is installed but the panel did not accept it: $res"
    echo "   1) Open TCP port $NODE_PUBLIC_PORT in this server's firewall (cloud panel too), then run the same command again."
    echo "   2) Or add it by hand in the panel: Nodes > Add node > manual, with these values:"
    echo -e "      API address:  ${C}https://$host:$NODE_PUBLIC_PORT${N}"
    echo -e "      Endpoint:     ${C}$host${N}"
    echo -e "      Node token:   ${C}$NODE_TOKEN${N}"
    [ -n "$INSECURE" ] && echo "      (tick 'Self-signed certificate')"
    return 1
  fi
}

join_node(){
  [ -n "$KANKI_PANEL" ] || die "KANKI_PANEL is missing. Copy the full command from the panel (Nodes > Add node)."
  KANKI_PANEL="${KANKI_PANEL%/}"
  echo; say "Joining the panel $KANKI_PANEL"
  if [ -x "$BIN" ] && [ "$(envget MODE)" = node ]; then
    say "This server already runs the Kanki node agent, so it is only registered again."
    DOMAIN=$(envget DOMAIN); NODE_PUBLIC_PORT=$(envget NODE_PUBLIC_PORT); NODE_TOKEN=$(envget NODE_TOKEN)
    INSECURE=""; if [ -n "$(envget HY2_INSECURE)" ]; then INSECURE=1; fi
    register_node
  else
    install_node
  fi
}

install_tunnel_agent(){
  [ -n "$KANKI_PANEL" ] || die "KANKI_PANEL is missing. Copy the full command from the panel (Tunnels > + Server)."
  KANKI_PANEL="${KANKI_PANEL%/}"
  local id="${KANKI_TUNNEL%%:*}" tok="${KANKI_TUNNEL#*:}" ins="" code
  { [ -n "$id" ] && [ -n "$tok" ] && [ "$id" != "$tok" ]; } || die "KANKI_TUNNEL must look like ID:TOKEN. Copy the full command from the panel."
  echo; say "Installing the Kanki server agent for $KANKI_PANEL"
  [ -n "$KANKI_JOIN" ] || say "Only the server agent (tunnels, Xray, Kanki DNS) is installed here: no VPN, no web panel."
  need_repo
  command -v curl >/dev/null || { apt-get update -qq; apt-get install -y -qq curl ca-certificates >/dev/null; }
  download_bin
  # any HTTP answer means the panel is reachable; only a TLS problem needs the insecure flag
  code=$(curl -s -m 15 -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' -d '{}' "$KANKI_PANEL/tunnel/agent" 2>/dev/null || true)
  if [ -z "$code" ] || [ "$code" = "000" ]; then
    code=$(curl -sk -m 15 -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' -d '{}' "$KANKI_PANEL/tunnel/agent" 2>/dev/null || true)
    if [ -n "$code" ] && [ "$code" != "000" ]; then ins=1; warn "The panel's certificate is not trusted from here; continuing without checking it."
    else warn "This server cannot reach $KANKI_PANEL right now. The agent keeps trying by itself."; fi
  fi
  mkdir -p "$ENV_DIR" /var/lib/kanki
  umask 077
  printf 'PANEL_URL=%s\nAGENT_ID=%s\nAGENT_TOKEN=%s\nINSECURE=%s\n' "$KANKI_PANEL" "$id" "$tok" "$ins" > "$ENV_DIR/tunnel.env"
  umask 022
  # long-distance TCP links keep their speed better with BBR
  if modprobe tcp_bbr 2>/dev/null || grep -qw bbr /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null; then
    printf 'net.core.default_qdisc=fq\nnet.ipv4.tcp_congestion_control=bbr\nnet.core.rmem_max=16777216\nnet.core.wmem_max=16777216\n' > /etc/sysctl.d/90-kanki-tunnel.conf
    sysctl -q --system >/dev/null 2>&1 || true
  fi
  service kanki-tunnel tunnel-agent
  sleep 4
  if systemctl is-active --quiet kanki-tunnel; then
    echo; ok "The server agent is connected to the panel (Servers shows it as Connected)."
    if [ -z "$KANKI_JOIN" ]; then
      echo "   Make a tunnel there; the agent opens the ports it needs (when ufw is active)."
      echo "   If your cloud provider has its own firewall, open the tunnel port there too."
    fi
  else
    journalctl -u kanki-tunnel -n 20 --no-pager || true
    die "The tunnel agent did not start (see above)."
  fi
}

# One command for a whole server (Servers > Add server in the panel): the server agent (tunnels, Xray,
# Kanki DNS) and the VPN part (WireGuard, AmneziaWG, Hysteria2, KANKI MIX). What it runs is switched on
# in the panel; nothing else is typed here. The agent goes first: when the VPN part cannot be finished
# (a package mirror filtered, a firewall), the server still shows in the panel and the VPN part can be
# installed again from there with one button.
install_server(){
  install_tunnel_agent
  echo; say "Installing the VPN part (WireGuard, AmneziaWG, Hysteria2, KANKI MIX) ..."
  local rc
  set +e
  ( set -e; KANKI_LOCAL_BIN=1; join_node )
  rc=$?
  set -e
  echo
  if [ "$rc" = 0 ]; then
    ok "Server ready. Everything is installed; switch on what it should run in the panel (Servers)."
  else
    warn "The VPN part was not finished (see above). Tunnels, Xray and Kanki DNS work on this server."
    echo "   Fix the cause, then press Install VPN on this server in the panel (Servers), or run the same command again."
  fi
}

update(){
  need_repo
  download_bin
  systemctl restart kanki-panel 2>/dev/null || true
  systemctl restart kanki-node 2>/dev/null || true
  systemctl restart kanki-tunnel 2>/dev/null || true
  ok "Updated to $($BIN version)"
  if grep -q '^MODE=node' $ENV 2>/dev/null && ! grep -q '^NODE_BIND=' $ENV; then
    warn "This node uses the old plain-HTTP API. Reinstall it (option 2) to get TLS."
  fi
}

set_bot(){
  [ -x "$BIN" ] || die "Panel is not installed"
  grep -q '^MODE=panel' $ENV 2>/dev/null || die "The bot runs on the main panel server only"
  echo "Plans, prices, payments and trials are managed inside the bot (Admin panel button)."
  read -rsp "Bot token from @BotFather (empty = remove bot): " T; echo
  A=""; [ -n "$T" ] && ask A "Admin numeric Telegram ID(s), comma separated"
  $BIN set-bot "$T" "$A"
  systemctl restart kanki-panel && ok "Done. Send /start to your bot."
}

reset_admin(){
  ask U "New admin username" admin
  while true; do read -rsp "New password (min 8 chars): " P; echo; [ ${#P} -ge 8 ] && break; warn "Too short"; done
  $BIN reset-admin "$U" "$P"
  systemctl restart kanki-panel && ok "Admin login reset (2FA disabled, all sessions logged out)"
}

valid_port(){ [[ "$1" =~ ^[0-9]{1,5}$ ]] && [ "$1" -ge 1 ] && [ "$1" -le 65535 ]; }

change_ports(){
  [ -f "$ENV" ] || die "Kanki is not installed on this server"
  local WGC=/etc/wireguard/wg0.conf AWGC=/etc/amnezia/amneziawg/awg0.conf HYC=/etc/hysteria/config.yaml
  local cw ca ch np
  cw=$(awk -F' *= *' '/^ListenPort/{print $2; exit}' $WGC 2>/dev/null || true)
  ca=$(awk -F' *= *' '/^ListenPort/{print $2; exit}' $AWGC 2>/dev/null || true)
  ch=$(grep -E '^HY2_PORT=' $ENV | cut -d= -f2 || true)
  echo "Current ports:  WireGuard ${cw:-off}   AmneziaWG ${ca:-off}   Hysteria2 ${ch:-off}   (all UDP)"
  echo "Leave a question empty to keep the port. Users' old WireGuard/AmneziaWG files stop working after a change; subscription links update by themselves."
  ask np "New WireGuard port" "$cw"
  if [ -n "$cw" ] && [ "$np" != "$cw" ]; then
    if ! valid_port "$np"; then warn "$np is not a port (1-65535), WireGuard left as it was"
    elif port_busy "$np"; then warn "Port $np is in use, WireGuard left as it was"; else
      sed -i "s/^ListenPort *=.*/ListenPort = $np/" $WGC && systemctl restart wg-quick@wg0 && ok "WireGuard -> $np"; open_ports "$np/udp"; fi
  fi
  ask np "New AmneziaWG port" "$ca"
  if [ -n "$ca" ] && [ "$np" != "$ca" ]; then
    if ! valid_port "$np"; then warn "$np is not a port (1-65535), AmneziaWG left as it was"
    elif port_busy "$np"; then warn "Port $np is in use, AmneziaWG left as it was"; else
      sed -i "s/^ListenPort *=.*/ListenPort = $np/" $AWGC && systemctl restart awg-quick@awg0 && ok "AmneziaWG -> $np"; open_ports "$np/udp"; fi
  fi
  ask np "New Hysteria2 port" "$ch"
  if [ -n "$ch" ] && [ "$np" != "$ch" ]; then
    if ! valid_port "$np"; then warn "$np is not a port (1-65535), Hysteria2 left as it was"
    elif port_busy "$np"; then warn "Port $np is in use, Hysteria2 left as it was"; else
      sed -i "s/^listen: .*/listen: :$np/" $HYC && sed -i "s/^HY2_PORT=.*/HY2_PORT=$np/" $ENV && systemctl restart hysteria-server && ok "Hysteria2 -> $np"; open_ports "$np/udp"; fi
  fi
  systemctl restart kanki-panel 2>/dev/null || true
  systemctl restart kanki-node 2>/dev/null || true
  ok "Done. The panel shows the new ports within a minute. If a cloud firewall is used, open the new UDP ports there too."
}

status(){
  for s in kanki-panel kanki-node kanki-tunnel kanki-mix kanki-xray kanki-dns caddy wg-quick@wg0 awg-quick@awg0 hysteria-server; do
    systemctl list-unit-files "$s.service" >/dev/null 2>&1 || continue
    st=$(systemctl is-active "$s" 2>/dev/null || true)
    [ "$st" = "inactive" ] && ! systemctl is-enabled "$s" >/dev/null 2>&1 && continue
    printf "  %-22s %s\n" "$s" "$st"
  done
  [ -x "$BIN" ] && echo "  version: $($BIN version)"
}

uninstall(){
  yes_no "Remove the panel, database and settings?" N || exit 0
  # every Kanki service (they restart by themselves, so a deleted program would keep failing)
  local k
  for k in kanki-panel kanki-node kanki-tunnel kanki-emergency kanki-dns kanki-mix kanki-xray; do
    systemctl disable --now "$k" 2>/dev/null || true
    rm -f "/etc/systemd/system/$k.service"
  done
  # Hysteria2 tunnels made by the agent: stop them so their ports are free
  for u in /etc/systemd/system/kanki-hy2-*.service; do [ -e "$u" ] || continue; n=$(basename "$u" .service)
    systemctl disable --now "$n" 2>/dev/null || true; [ -f "/etc/kanki/hy2tun/$n-down.sh" ] && sh "/etc/kanki/hy2tun/$n-down.sh" 2>/dev/null; rm -f "$u"; done
  rm -rf /etc/kanki/hy2tun; systemctl daemon-reload 2>/dev/null || true
  rm -f /etc/systemd/system/kanki-panel.service /etc/systemd/system/kanki-node.service /etc/systemd/system/kanki-tunnel.service /etc/sysctl.d/90-kanki-tunnel.conf "$ENV_DIR/tunnel.env" "$BIN" /usr/local/bin/kanki
  rm -rf /var/lib/kanki
  # the certificate stays: Caddy and Hysteria2 (left untouched) still read it, and certbot renews it there
  find "$ENV_DIR" -mindepth 1 -maxdepth 1 ! -name tls -exec rm -rf {} + 2>/dev/null || true
  systemctl daemon-reload
  ok "Removed (WireGuard / AmneziaWG / Hysteria2 / Caddy were left untouched; the certificate in $TLS was kept for them)"
}

# =====================================================================
# The server files and database of a backup unpacked in $1/x put in place on this server, and every
# service set up from them (keys, ports, certificate, Caddy in front of the panel's own port).
# $2 = the old server's IP when moving (empty for a backup file).
restore_bundle(){
  local W=$1 OLD=$2
  # everything of a panel installed here before stops first: the restored one takes its place
  systemctl stop kanki-panel 2>/dev/null || true
  systemctl stop wg-quick@wg0 awg-quick@awg0 hysteria-server 2>/dev/null || true
  ip link del wg0 2>/dev/null || true; ip link del awg0 2>/dev/null || true
  # the server files, exactly as they were (keys, configs, certificate)
  local f
  for f in $ENV $ENV_DIR/repo /etc/wireguard/wg0.conf /etc/amnezia/amneziawg/awg0.conf /etc/hysteria/config.yaml $TLS/fullchain.pem $TLS/privkey.pem; do
    if [ -f "$W/x/files$f" ] && [ ! -L "$W/x/files$f" ]; then
      mkdir -p "$(dirname "$f")"
      # Hysteria2 runs as its own user: its config and the certificate must stay readable for it
      # (the same modes a normal install and the renewal hook give them)
      case "$f" in
        /etc/hysteria/config.yaml) install -m 644 "$W/x/files$f" "$f";;
        $TLS/*.pem) getent group kankitls >/dev/null || groupadd kankitls; install -m 640 -g kankitls "$W/x/files$f" "$f";;
        *) install -m 600 "$W/x/files$f" "$f";;
      esac
    fi
  done
  need_repo
  # an address that named the old server becomes the domain
  if [ -n "$OLD" ] && [ "$(envget ENDPOINT)" = "$OLD" ]; then sed -i "s|^ENDPOINT=.*|ENDPOINT=$(envget DOMAIN)|" "$ENV"; fi
  sed -i '/^MOVED_FROM=/d; /^RESTORED_AT=/d' "$ENV"; if [ -n "$OLD" ]; then echo "MOVED_FROM=$OLD" >> "$ENV"; fi
  echo "RESTORED_AT=$(date +%s)" >> "$ENV"
  local DATA; DATA=$(envget DATA_DIR); DATA=${DATA:-/var/lib/kanki}
  mkdir -p "$DATA"; chmod 700 "$DATA"
  install -m 600 "$W/x/kanki.db" "$DATA/kanki.db"; rm -f "$DATA/kanki.db-wal" "$DATA/kanki.db-shm"
  if [ -d "$W/x/apps" ]; then rm -rf "$DATA/apps"; mkdir -p "$DATA/apps"; find "$W/x/apps" -maxdepth 1 -type f -exec cp {} "$DATA/apps/" \;; fi
  # the certificates of self-signed nodes as first seen (the panel keeps trusting exactly those)
  if [ -d "$W/x/nodepins" ]; then mkdir -p "$DATA/nodepins"; find "$W/x/nodepins" -maxdepth 1 -type f -name '*.pin' -exec cp {} "$DATA/nodepins/" \;; fi
  ok "Database, settings, keys and app files restored"
  DOMAIN=$(envget DOMAIN); HTTPS_PORT=$(envget HTTPS_PORT); PANEL_PORT=$(envget PANEL_PORT); HY2_PORT=$(envget HY2_PORT)
  WG_PORT=$(grep -m1 '^ListenPort' /etc/wireguard/wg0.conf 2>/dev/null | awk -F= '{gsub(/ /,"",$2);print $2}')
  AWG_PORT=$(grep -m1 '^ListenPort' /etc/amnezia/amneziawg/awg0.conf 2>/dev/null | awk -F= '{gsub(/ /,"",$2);print $2}')
  # the network rules of the configs name the old server's network card: use this one's
  local ETH c; ETH=$(ip route show default | awk '{print $5; exit}')
  for c in /etc/wireguard/wg0.conf /etc/amnezia/amneziawg/awg0.conf; do
    [ -f "$c" ] && [ -n "$ETH" ] && sed -i -E "s/ -o [A-Za-z0-9._@-]+ -j MASQUERADE/ -o $ETH -j MASQUERADE/g" "$c"
  done
  [ -f /etc/wireguard/wg0.conf ] && setup_wireguard
  [ -f /etc/amnezia/amneziawg/awg0.conf ] && setup_amneziawg
  if [ -n "$HY2_PORT" ] && [ -f /etc/hysteria/config.yaml ]; then
    say "Installing Hysteria2 on UDP $HY2_PORT ..."
    if hy2_install; then
      id hysteria >/dev/null 2>&1 && usermod -aG kankitls hysteria
      systemctl enable -q hysteria-server.service 2>/dev/null || true
    else
      warn "Hysteria2 could not be installed"
    fi
  else
    # Hysteria2 was off on the backed up server: one left by an install here would hold its port
    systemctl disable -q --now hysteria-server.service 2>/dev/null || true
  fi
  # a fresh certificate when the domain already points here; else the one from the old server
  apt-get install -y -qq certbot >/dev/null 2>&1 || true
  mkdir -p "$TLS"
  if certbot certonly --standalone -n --agree-tos --register-unsafely-without-email -d "$DOMAIN" >/dev/null 2>&1; then
    mkdir -p /etc/letsencrypt/renewal-hooks/deploy
    printf '#!/bin/sh\ncp -L /etc/letsencrypt/live/%s/fullchain.pem %s/fullchain.pem\ncp -L /etc/letsencrypt/live/%s/privkey.pem %s/privkey.pem\nchgrp kankitls %s/*.pem; chmod 640 %s/*.pem\nsystemctl reload caddy 2>/dev/null || true\nsystemctl restart hysteria-server 2>/dev/null || true\n' \
      "$DOMAIN" "$TLS" "$DOMAIN" "$TLS" "$TLS" "$TLS" > /etc/letsencrypt/renewal-hooks/deploy/kanki.sh
    chmod +x /etc/letsencrypt/renewal-hooks/deploy/kanki.sh
    sh /etc/letsencrypt/renewal-hooks/deploy/kanki.sh
    ok "New SSL certificate for $DOMAIN"
  else
    warn "No new certificate yet ($DOMAIN does not point here yet, or port 80 is closed): the old server's certificate is used for now"
  fi
  [ -f $TLS/fullchain.pem ] && tls_perms
  if [ -n "$HY2_PORT" ]; then systemctl restart hysteria-server.service 2>/dev/null || true; fi
  setup_caddy "https://$DOMAIN:$HTTPS_PORT" "$PANEL_PORT"
  service kanki-panel serve
  open_ports 80/tcp "$HTTPS_PORT/tcp" "${WG_PORT:+$WG_PORT/udp}" "${AWG_PORT:+$AWG_PORT/udp}" "${HY2_PORT:+$HY2_PORT/udp}"
  say "Checking the panel ..."
  local i up=0
  for i in $(seq 1 30); do curl -fs -o /dev/null "http://127.0.0.1:$PANEL_PORT/admin" && { up=1; break; }; sleep 1; done
  [ "$up" = 1 ] || die "The panel did not start here (journalctl -u kanki-panel -n 30)"
  ok "The panel runs on this server"
}

# Move the whole panel here from another server (the old panel's Backup › Move to a new server
# prints this command). KANKI_MOVE=domain|https port|old server IP|one-time token|passphrase
move_panel(){
  local D P OLD T PASS W=/root/kanki-move
  IFS='|' read -r D P OLD T PASS <<< "$KANKI_MOVE"
  [ -n "$D" ] && [ -n "$P" ] && [ -n "$OLD" ] && [ -n "$T" ] && [ -n "$PASS" ] || die "The move command is incomplete: copy it again from the old panel"
  echo; say "Moving the Kanki panel $D here from $OLD"
  if [ -f "$ENV" ] && grep -q '^MODE=panel' "$ENV"; then yes_no "A Kanki panel is already installed here. Replace it with the one being moved?" N || exit 0; fi
  need_repo; base_packages; download_bin
  rm -rf "$W"; mkdir -p "$W"; chmod 700 "$W"
  say "Downloading the full backup from the old server ..."
  # by the old server's IP: the domain may already point here
  local URL="https://$D:$P/move/bundle?t=$T"
  local K=""
  if ! curl -fsS --retry 3 --max-time 900 --resolve "$D:$P:$OLD" -o "$W/b.kbk" "$URL"; then
    # the token is sent without a checked certificate only when the admin says so here
    curl -sk --max-time 20 --resolve "$D:$P:$OLD" -o /dev/null "https://$D:$P/" 2>/dev/null \
      || die "Could not download the backup from $OLD:$P. Is the old panel still running? Is the command older than 3 hours (make a new one)?"
    warn "The old server answers, but its certificate for $D cannot be checked from here."
    yes_no "Download the backup anyway without checking the certificate?" N || die "Stopped: nothing was moved"
    K=k
    curl -fsSk --retry 2 --max-time 900 --resolve "$D:$P:$OLD" -o "$W/b.kbk" "$URL" \
      || die "Could not download the backup from $OLD:$P. Is the command older than 3 hours (make a new one)?"
  fi
  KANKI_BK_PASS="$PASS" openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -in "$W/b.kbk" -out "$W/b.tgz" -pass env:KANKI_BK_PASS \
    || die "The backup could not be opened (wrong or damaged): make a new command in the old panel"
  mkdir -p "$W/x"; tar -xzf "$W/b.tgz" -C "$W/x" || die "The backup is damaged"
  [ -f "$W/x/kanki.db" ] && [ -f "$W/x/files$ENV" ] || die "The backup has no database or settings"
  ok "Backup downloaded ($(du -h "$W/b.kbk" | cut -f1))"
  restore_bundle "$W" "$OLD"
  # the old panel stops (no two panels for the same nodes and bot)
  if curl -fsS -X POST --max-time 20 --resolve "$D:$P:$OLD" "https://$D:$P/move/done?t=$T" >/dev/null 2>&1 \
     || { [ "$K" = k ] && curl -fsSk -X POST --max-time 20 --resolve "$D:$P:$OLD" "https://$D:$P/move/done?t=$T" >/dev/null 2>&1; }; then
    ok "The old panel ($OLD) was told to stop"
  else
    warn "The old panel could not be told: stop it there with: systemctl disable --now kanki-panel"
  fi
  rm -rf "$W"
  local ME; ME=$(pubip)
  echo; ok "Move complete!"
  echo -e "   Panel:  ${C}https://$DOMAIN:$HTTPS_PORT/admin${N}  (the same username and password as before)"
  echo "   The domain $DOMAIN must point to this server: ${ME:-the IP of this server}"
  echo "   Nodes and tunnel servers find the panel by its domain by themselves; this server's VPN uses the same keys, so the users' configs keep working."
}

# Restore the whole panel from a backup file (.kbk, or .tar.gz) uploaded to this server, also when
# the old server is gone. A panel installed here before is replaced.
restore_file(){
  local W=/root/kanki-restore F PASS
  echo; say "Restore the panel from a backup file"
  ask F "Path of the backup file on this server" "$(ls -t /root/*.kbk /root/*.tar.gz 2>/dev/null | head -1)"
  [ -f "$F" ] || die "No file at $F: upload the backup to /root first (SFTP), then run this again"
  need_repo; base_packages; download_bin
  rm -rf "$W"; mkdir -p "$W/x"; chmod 700 "$W"
  if [ "$(head -c 8 "$F")" = "Salted__" ]; then
    read -rsp "Backup passphrase: " PASS; echo
    KANKI_BK_PASS="$PASS" openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -in "$F" -out "$W/b.tgz" -pass env:KANKI_BK_PASS 2>/dev/null \
      || { rm -rf "$W"; die "Wrong passphrase or damaged file"; }
  else
    cp "$F" "$W/b.tgz"
  fi
  tar -xzf "$W/b.tgz" -C "$W/x" 2>/dev/null || { rm -rf "$W"; die "The backup is damaged"; }
  [ -f "$W/x/kanki.db" ] && [ -f "$W/x/files$ENV" ] || { rm -rf "$W"; die "The backup has no database or settings"; }
  # made on another server: its IP is replaced in the panel's addresses (see meta.json of the backup)
  local OLDIP ME0; OLDIP=$(grep -o '"ip":"[0-9.]*"' "$W/x/meta.json" 2>/dev/null | cut -d'"' -f4); ME0=$(pubip)
  [ -n "$OLDIP" ] && [ "$OLDIP" = "$ME0" ] && OLDIP=""
  restore_bundle "$W" "$OLDIP"
  rm -rf "$W"
  local ME; ME=$(pubip)
  echo; ok "Restore complete!"
  echo -e "   Panel:  ${C}https://$DOMAIN:$HTTPS_PORT/admin${N}  (the username and password of the backed up panel)"
  echo "   The domain $DOMAIN must point to this server: ${ME:-the IP of this server}"
}

if [ -n "${KANKI_MOVE:-}" ]; then move_panel; exit $?; fi
if [ -n "$KANKI_TUNNEL" ] && [ -n "$KANKI_JOIN" ]; then install_server; exit $?; fi
if [ -n "$KANKI_TUNNEL" ]; then install_tunnel_agent; exit $?; fi
if [ -n "$KANKI_JOIN" ]; then join_node; exit $?; fi

echo -e "${Y}"
echo "  =================================="
echo "        KANKI PANEL INSTALLER"
echo "  =================================="
echo -e "${N}"
echo "  1) Install main panel"
echo "  2) Install node (extra server)"
echo "  3) Update"
echo "  4) Telegram sales bot (set / change)"
echo "  5) Reset admin login"
echo "  6) Status"
echo "  7) Uninstall"
echo "  8) Change WireGuard / AmneziaWG / Hysteria2 ports"
echo "  9) Restore the panel from a backup file"
read -rp "  Choose: " CH
case "$CH" in
  1) install_panel ;;
  2) install_node ;;
  3) update ;;
  4) set_bot ;;
  5) reset_admin ;;
  6) status ;;
  7) uninstall ;;
  8) change_ports ;;
  9) restore_file ;;
  *) die "Invalid choice" ;;
esac
