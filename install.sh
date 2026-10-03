#!/usr/bin/env bash
# =====================================================================
#  Kanki Panel installer
#  bash <(curl -fsSL https://raw.githubusercontent.com/<USER>/<REPO>/main/install.sh)
#  After install you can run:  kanki
# =====================================================================
set -e
Y='\033[1;33m'; R='\033[1;31m'; N='\033[0m'; G='\033[1;32m'; C='\033[1;36m'
say(){ echo -e "${Y}>> $*${N}"; }
ok(){ echo -e "${G}[ok] $*${N}"; }
warn(){ echo -e "${R}[!] $*${N}"; }
die(){ echo -e "${R}[x] $*${N}"; exit 1; }
[ "$(id -u)" = "0" ] || die "Please run as root (sudo -i)"
command -v apt-get >/dev/null || die "Only Ubuntu / Debian are supported"

ENV_DIR=/etc/kanki; ENV=$ENV_DIR/kanki.env; BIN=/usr/local/bin/kanki-panel; TLS=$ENV_DIR/tls
mkdir -p "$ENV_DIR"; chmod 711 "$ENV_DIR"

rand(){ tr -dc 'A-Za-z0-9' </dev/urandom | head -c "${1:-24}"; }
rnum(){ shuf -i "$1"-"$2" -n 1; }
pubip(){ curl -s4 --max-time 8 https://api.ipify.org || hostname -I | awk '{print $1}'; }
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
REPO="${KANKI_REPO:-$(cat $ENV_DIR/repo 2>/dev/null || true)}"
# one-command node join: the panel (Nodes > Add node) prints a line that sets these two
KANKI_JOIN="${KANKI_JOIN:-}"; KANKI_PANEL="${KANKI_PANEL:-}"
# one-command tunnel server (Tunnels > + Server): KANKI_TUNNEL=ID:TOKEN
KANKI_TUNNEL="${KANKI_TUNNEL:-}"
envget(){ grep -m1 "^$1=" "$ENV" 2>/dev/null | cut -d= -f2-; }
free_port(){ # $1=var $2=preferred port: keep it when free, otherwise take a random free one (no questions)
  local p="$2"
  while port_busy "$p"; do p=$(rnum 20000 59999); done
  printf -v "$1" '%s' "$p"; }
need_repo(){
  if [ -z "$REPO" ]; then ask REPO "GitHub repo (e.g. username/kanki-panel)"; fi
  [ -n "$REPO" ] || die "Repo is required"
  echo "$REPO" > $ENV_DIR/repo
}

download_bin(){
  say "Downloading Kanki Panel from $REPO ..."
  local base="https://github.com/$REPO/releases/download/latest"
  curl -fL --retry 3 -o /tmp/kanki-panel "$base/kanki-panel" \
    || die "Download failed. The repo must be public and the GitHub Actions build must have succeeded."
  if curl -fsL "$base/kanki-panel.sha256" -o /tmp/kanki-panel.sha256; then
    (cd /tmp && sha256sum -c kanki-panel.sha256 >/dev/null) || die "Checksum mismatch, aborting"
  fi
  install -m 755 /tmp/kanki-panel "$BIN"
  curl -fsSL "https://raw.githubusercontent.com/$REPO/main/install.sh" -o /usr/local/bin/kanki 2>/dev/null && chmod +x /usr/local/bin/kanki || true
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
  fi
  systemctl enable -q --now awg-quick@awg0 && ok "AmneziaWG is running" || warn "AmneziaWG failed to start (the server may need a reboot)"
}

tls_perms(){
  chgrp kankitls "$TLS" $TLS/*.pem; chmod 750 "$TLS"; chmod 640 $TLS/*.pem
}

get_cert(){ # $1=domain $2=email
  say "Getting an SSL certificate for $1 ..."
  apt-get install -y -qq certbot >/dev/null
  port_busy 80 && warn "Port 80 is busy; certbot needs it free for a moment" || true
  certbot certonly --standalone -n --agree-tos -m "$2" -d "$1" \
    --pre-hook "systemctl stop caddy 2>/dev/null || true" --post-hook "systemctl start caddy 2>/dev/null || true" \
    || die "SSL failed. The domain must point DIRECTLY (no Cloudflare proxy) to this server and port 80 must be open."
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

setup_hysteria(){ # $1=auth url
  say "Installing Hysteria2 on UDP $HY2_PORT ..."
  command -v hysteria >/dev/null || bash <(curl -fsSL https://get.hy2.sh/) >/dev/null 2>&1 || { warn "Hysteria2 could not be installed"; HY2_PORT=""; return; }
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
EOF
  systemctl enable -q hysteria-server.service 2>/dev/null || true
  systemctl restart hysteria-server.service && ok "Hysteria2 is running" || warn "Hysteria2 failed to start"
}

install_caddy(){
  if ! command -v caddy >/dev/null; then
    apt-get update -qq; apt-get install -y -qq caddy >/dev/null 2>&1 || true
  fi
  if ! command -v caddy >/dev/null; then
    curl -fsSL "https://caddyserver.com/api/download?os=linux&arch=amd64" -o /usr/bin/caddy && chmod +x /usr/bin/caddy
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
  @blocked path /hy2/* /ovpn/*
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
  if command -v ufw >/dev/null && ufw status | grep -q active; then
    for p in "$@"; do [ -n "${p%%/*}" ] && ufw allow "$p" >/dev/null; done
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

ask_protocols(){
  ask_port WG_PORT "WireGuard UDP port" 51820
  ask_port AWG_PORT "AmneziaWG UDP port" 51821
  if yes_no "Install Hysteria2?" Y; then ask_port HY2_PORT "Hysteria2 UDP port" 8443; else HY2_PORT=""; fi
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
  ask_protocols
  read -rsp "Telegram sales bot token (empty = no bot): " BOT_TOKEN; echo
  BOT_ADMINS=""; [ -n "$BOT_TOKEN" ] && ask BOT_ADMINS "Bot admin numeric ID(s), comma separated"

  HY2_STATS_PORT=$(rnum 30000 39999); HY2_OBFS=$(rand 20); HY2_SECRET=$(rand 24)
  echo; say "Summary"
  echo "  Domain: $DOMAIN  HTTPS: $HTTPS_PORT  Endpoint: $ENDPOINT  Server: $LOCAL_NAME"
  echo "  WireGuard: $WG_PORT  AmneziaWG: $AWG_PORT  Hysteria2: ${HY2_PORT:-off}"
  echo "  Bot: $([ -n "$BOT_TOKEN" ] && echo yes || echo no)"
  yes_no "Start installation?" Y || exit 0
  base_packages; download_bin
  get_cert "$DOMAIN" "$EMAIL"
  setup_wireguard; setup_amneziawg
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
DATA_DIR=/var/lib/kanki
EOF
  umask 022
  setup_caddy "https://$DOMAIN:$HTTPS_PORT" "$PANEL_PORT"
  service kanki-panel serve
  open_ports 80/tcp "$HTTPS_PORT/tcp" "$WG_PORT/udp" "${AWG_PORT:+$AWG_PORT/udp}" "${HY2_PORT:+$HY2_PORT/udp}"
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
    free_port NODE_PUBLIC_PORT 2096; free_port NODE_PORT "$(rnum 20000 29999)"
    free_port WG_PORT 51820; free_port AWG_PORT 51821; free_port HY2_PORT 8443
  else
    ask DOMAIN "Node domain (recommended for TLS; empty = self-signed certificate)"
    EMAIL=""; [ -n "$DOMAIN" ] && ask EMAIL "Email for SSL"
    ask_port NODE_PUBLIC_PORT "Node API port (HTTPS)" 2096
    ask_port NODE_PORT "Internal agent port (local only)" "$(rnum 20000 29999)"
    ask_protocols
  fi
  HY2_STATS_PORT=$(rnum 30000 39999); HY2_OBFS=$(rand 20); HY2_SECRET=$(rand 24); NODE_TOKEN=$(rand 48); INSECURE=""
  base_packages; download_bin
  if [ -n "$DOMAIN" ]; then get_cert "$DOMAIN" "$EMAIL"; else self_signed; INSECURE=1; fi
  setup_wireguard; setup_amneziawg
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
DATA_DIR=/var/lib/kanki
EOF
  umask 022
  setup_caddy "https://:$NODE_PUBLIC_PORT" "$NODE_PORT"
  service kanki-node node
  open_ports "$NODE_PUBLIC_PORT/tcp" "$WG_PORT/udp" "${AWG_PORT:+$AWG_PORT/udp}" "${HY2_PORT:+$HY2_PORT/udp}"
  if [ -n "$KANKI_JOIN" ]; then register_node; return 0; fi
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
  res=$(curl -sS -m 90 -X POST -H 'Content-Type: application/json' -d "$body" "$KANKI_PANEL/join/register" 2>&1) \
    || res=$(curl -sSk -m 90 -X POST -H 'Content-Type: application/json' -d "$body" "$KANKI_PANEL/join/register" 2>&1) || true
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
  echo; say "Installing the Kanki tunnel agent for $KANKI_PANEL"
  say "Only the tunnel agent is installed here: no VPN, no web panel."
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
    echo; ok "Done! This server is connected to the panel. Open Tunnels in the panel: it shows as Connected."
    echo "   Make a tunnel there; the agent opens the ports it needs (when ufw is active)."
    echo "   If your cloud provider has its own firewall, open the tunnel port there too."
  else
    journalctl -u kanki-tunnel -n 20 --no-pager || true
    die "The tunnel agent did not start (see above)."
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

status(){
  for s in kanki-panel kanki-node kanki-tunnel caddy wg-quick@wg0 awg-quick@awg0 hysteria-server; do
    systemctl list-unit-files "$s.service" >/dev/null 2>&1 || continue
    st=$(systemctl is-active "$s" 2>/dev/null || true)
    [ "$st" = "inactive" ] && ! systemctl is-enabled "$s" >/dev/null 2>&1 && continue
    printf "  %-22s %s\n" "$s" "$st"
  done
  [ -x "$BIN" ] && echo "  version: $($BIN version)"
}

uninstall(){
  yes_no "Remove the panel, database and settings?" N || exit 0
  systemctl disable --now kanki-panel kanki-node kanki-tunnel 2>/dev/null || true
  rm -f /etc/systemd/system/kanki-panel.service /etc/systemd/system/kanki-node.service /etc/systemd/system/kanki-tunnel.service /etc/sysctl.d/90-kanki-tunnel.conf "$ENV_DIR/tunnel.env" "$BIN" /usr/local/bin/kanki
  rm -rf /var/lib/kanki "$ENV_DIR"
  systemctl daemon-reload
  ok "Removed (WireGuard / AmneziaWG / Hysteria2 / Caddy were left untouched)"
}

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
read -rp "  Choose: " CH
case "$CH" in
  1) install_panel ;;
  2) install_node ;;
  3) update ;;
  4) set_bot ;;
  5) reset_admin ;;
  6) status ;;
  7) uninstall ;;
  *) die "Invalid choice" ;;
esac
