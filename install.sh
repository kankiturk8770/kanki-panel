#!/usr/bin/env bash
# =====================================================================
#  Kanki Panel installer
#  bash <(curl -fsSL https://raw.githubusercontent.com/<USER>/<REPO>/main/install.sh)
# =====================================================================
set -e
G='\033[1;33m'; R='\033[1;31m'; N='\033[0m'; OK='\033[1;32m'
say(){ echo -e "${G}>> $*${N}"; }
ok(){ echo -e "${OK}[ok] $*${N}"; }
die(){ echo -e "${R}[x] $*${N}"; exit 1; }
[ "$(id -u)" = "0" ] || die "Lotfan ba karbar root ejra konid"

ENV_DIR=/etc/kanki; ENV=$ENV_DIR/kanki.env; BIN=/usr/local/bin/kanki-panel; TLS=$ENV_DIR/tls
mkdir -p "$ENV_DIR"; chmod 711 "$ENV_DIR"  # traversable; env file itself is 600

# ---------------- GitHub repo (binary download)
REPO="${KANKI_REPO:-$(cat $ENV_DIR/repo 2>/dev/null || true)}"
if [ -z "$REPO" ]; then
  read -rp "GitHub repo (masalan username/kanki-panel): " REPO
fi
[ -n "$REPO" ] || die "Repo khali ast"
echo "$REPO" > $ENV_DIR/repo

rand(){ tr -dc 'A-Za-z0-9' </dev/urandom | head -c "${1:-24}"; }
rnum(){ shuf -i "$1"-"$2" -n 1; }
pubip(){ curl -s4 --max-time 8 https://api.ipify.org || hostname -I | awk '{print $1}'; }

download_bin(){
  say "Download akharin noskhe Kanki Panel az $REPO ..."
  curl -fL --retry 3 -o /tmp/kanki-panel "https://github.com/$REPO/releases/download/latest/kanki-panel" \
    || die "Download nashod. Repo bayad Public bashad va build GitHub Actions movafagh bashad."
  install -m 755 /tmp/kanki-panel "$BIN"
  ok "$($BIN version)"
}

base_packages(){
  say "Nasb pishniaz-ha ..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq curl wget iptables wireguard-tools openssl ca-certificates gnupg software-properties-common \
    "linux-headers-$(uname -r)" >/dev/null 2>&1 || apt-get install -y -qq curl wget iptables wireguard-tools openssl ca-certificates gnupg software-properties-common >/dev/null
  echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-kanki.conf
  echo "net.core.rmem_max=16777216" >> /etc/sysctl.d/99-kanki.conf
  echo "net.core.wmem_max=16777216" >> /etc/sysctl.d/99-kanki.conf
  sysctl -q --system || true
}

iface_rules(){ # $1=subnet
  local ETH; ETH=$(ip route show default | awk '{print $5; exit}')
  echo "PostUp = iptables -t nat -A POSTROUTING -s $1 -o $ETH -j MASQUERADE; iptables -A FORWARD -s $1 -j ACCEPT; iptables -A FORWARD -d $1 -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -s $1 -o $ETH -j MASQUERADE; iptables -D FORWARD -s $1 -j ACCEPT; iptables -D FORWARD -d $1 -j ACCEPT"
}

setup_wireguard(){
  say "Rah-andazi WireGuard roye port $WG_PORT ..."
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
  systemctl enable -q --now wg-quick@wg0 && ok "WireGuard faal shod" || echo "[!] WireGuard rah nayoftad"
}

setup_amneziawg(){
  say "Nasb AmneziaWG (kernel module az PPA rasmi Amnezia) ..."
  if ! command -v awg >/dev/null; then
    add-apt-repository -y ppa:amnezia/ppa >/dev/null 2>&1 || true
    apt-get update -qq
    apt-get install -y -qq amneziawg amneziawg-tools >/dev/null 2>&1 || apt-get install -y -qq amneziawg-dkms amneziawg-tools >/dev/null 2>&1 || true
  fi
  if ! command -v awg >/dev/null; then echo "[!] AmneziaWG nasb nashod; faghat WireGuard va Hysteria2 faal mimanand"; return; fi
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
  systemctl enable -q --now awg-quick@awg0 && ok "AmneziaWG faal shod" || echo "[!] AmneziaWG rah nayoftad (shayad server niaz be reboot dashte bashad)"
}

get_cert(){ # $1=domain $2=email
  say "Gereftan SSL baraye $1 ..."
  apt-get install -y -qq certbot >/dev/null
  systemctl stop caddy 2>/dev/null || true
  certbot certonly --standalone -n --agree-tos -m "$2" -d "$1" \
    --pre-hook "systemctl stop caddy 2>/dev/null || true" --post-hook "systemctl start caddy 2>/dev/null || true" \
    || die "SSL gerefte nashod. Domain bayad mostaghim (bedune Cloudflare proxy) be IP in server bashad va port 80 azad bashad."
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
  getent group kankitls >/dev/null || groupadd kankitls
  chgrp kankitls "$TLS"; chmod 750 "$TLS"
  sh /etc/letsencrypt/renewal-hooks/deploy/kanki.sh
  ok "SSL gerefte shod (tamdid khodkar)"
}

self_signed(){
  mkdir -p "$TLS"; getent group kankitls >/dev/null || groupadd kankitls
  chgrp kankitls "$TLS"; chmod 750 "$TLS"
  openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=kanki" -keyout $TLS/privkey.pem -out $TLS/fullchain.pem >/dev/null 2>&1
  chgrp kankitls $TLS/*.pem; chmod 640 $TLS/*.pem
}

setup_hysteria(){ # $1=auth url
  say "Nasb Hysteria2 roye port UDP $HY2_PORT ..."
  command -v hysteria >/dev/null || bash <(curl -fsSL https://get.hy2.sh/) >/dev/null 2>&1 || { echo "[!] Hysteria2 nasb nashod"; HY2_PORT=""; return; }
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
  systemctl restart hysteria-server.service && ok "Hysteria2 faal shod" || echo "[!] Hysteria2 rah nayoftad"
}

setup_caddy(){ # $1=domain $2=https port
  say "Rah-andazi web server Caddy ..."
  rm -f /etc/apt/sources.list.d/caddy-stable.list
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
  command -v caddy >/dev/null || die "Caddy nasb nashod"
  id caddy >/dev/null 2>&1 || useradd --system --shell /usr/sbin/nologin caddy
  usermod -aG kankitls caddy
  cat > /etc/caddy/Caddyfile <<EOF
{
  auto_https off
}
https://$1:$2 {
  tls $TLS/fullchain.pem $TLS/privkey.pem
  @blocked path /hy2/* /agent/*
  respond @blocked 404
  reverse_proxy 127.0.0.1:$PANEL_PORT
}
EOF
  systemctl enable -q caddy
  systemctl restart caddy && ok "Caddy faal shod" || { journalctl -u caddy -n 15 --no-pager; echo "[!] Caddy roshan nashod (port azad ast?)"; }
}

open_ports(){
  if command -v ufw >/dev/null && ufw status | grep -q active; then
    for p in "$@"; do ufw allow "$p" >/dev/null; done
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

# =====================================================================
install_panel(){
  echo; say "Nasb panel asli"
  read -rp "Domain panel (mostaghim be IP in server): " DOMAIN
  [ -n "$DOMAIN" ] || die "Domain lazem ast"
  read -rp "Email baraye SSL: " EMAIL
  read -rp "Port HTTPS panel [443]: " HTTPS_PORT; HTTPS_PORT=${HTTPS_PORT:-443}
  if ss -tln | grep -q ":$HTTPS_PORT "; then
    echo "[!] Port $HTTPS_PORT ra barname-ye digari gerefte:"; ss -tlnp | grep ":$HTTPS_PORT "
    read -rp "Yek port digar vared konid (masalan 2053): " HTTPS_PORT
  fi
  read -rp "Username admin panel: " ADMIN_USER
  read -rsp "Password admin panel: " ADMIN_PASS; echo
  [ -n "$ADMIN_USER" ] && [ -n "$ADMIN_PASS" ] || die "Username va password lazem ast"
  read -rp "Esm in server (masalan GERMANY): " LOCAL_NAME; LOCAL_NAME=${LOCAL_NAME:-MAIN}
  read -rp "Port WireGuard [51820]: " WG_PORT; WG_PORT=${WG_PORT:-51820}
  read -rp "Port AmneziaWG [51821]: " AWG_PORT; AWG_PORT=${AWG_PORT:-51821}
  read -rp "Hysteria2 nasb shavad? [Y/n]: " HY; HY=${HY:-Y}
  if [[ "$HY" =~ ^[Yy]$ ]]; then read -rp "Port UDP Hysteria2 [8443]: " HY2_PORT; HY2_PORT=${HY2_PORT:-8443}; else HY2_PORT=""; fi
  read -rsp "Token robot Telegram (khali = bedune robot): " BOT_TOKEN; echo
  BOT_ADMINS=""; [ -n "$BOT_TOKEN" ] && read -rp "ID adadi admin(ha), ba comma: " BOT_ADMINS

  PANEL_PORT=$(rnum 20000 29999); HY2_STATS_PORT=$(rnum 30000 39999); HY2_OBFS=$(rand 20); HY2_SECRET=$(rand 24)
  base_packages; download_bin
  get_cert "$DOMAIN" "$EMAIL"
  setup_wireguard; setup_amneziawg
  [ -n "$HY2_PORT" ] && setup_hysteria "http://127.0.0.1:$PANEL_PORT/hy2/auth"
  umask 077
  cat > $ENV <<EOF
MODE=panel
DOMAIN=$DOMAIN
ENDPOINT=$DOMAIN
HTTPS_PORT=$HTTPS_PORT
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
  setup_caddy "$DOMAIN" "$HTTPS_PORT"
  service kanki-panel serve
  open_ports 80/tcp "$HTTPS_PORT/tcp" "$WG_PORT/udp" "$AWG_PORT/udp" ${HY2_PORT:+"$HY2_PORT/udp"}
  echo; ok "Nasb kamel shod!"
  echo -e "   Panel: ${G}https://$DOMAIN:$HTTPS_PORT/admin${N}"
  [ -n "$BOT_TOKEN" ] && echo "   Robot: dar Telegram /start bezanid"
}

install_node(){
  echo; say "Nasb node (server ezafe)"
  read -rp "Domain in node (baraye SSL Hysteria2; khali = bedune domain): " DOMAIN
  EMAIL=""; [ -n "$DOMAIN" ] && read -rp "Email baraye SSL: " EMAIL
  read -rp "Port API node [2096]: " NODE_PORT; NODE_PORT=${NODE_PORT:-2096}
  read -rp "Port WireGuard [51820]: " WG_PORT; WG_PORT=${WG_PORT:-51820}
  read -rp "Port AmneziaWG [51821]: " AWG_PORT; AWG_PORT=${AWG_PORT:-51821}
  read -rp "Hysteria2 nasb shavad? [Y/n]: " HY; HY=${HY:-Y}
  if [[ "$HY" =~ ^[Yy]$ ]]; then read -rp "Port UDP Hysteria2 [8443]: " HY2_PORT; HY2_PORT=${HY2_PORT:-8443}; else HY2_PORT=""; fi
  HY2_STATS_PORT=$(rnum 30000 39999); HY2_OBFS=$(rand 20); HY2_SECRET=$(rand 24); NODE_TOKEN=$(rand 40); INSECURE=""
  base_packages; download_bin
  if [ -n "$DOMAIN" ]; then get_cert "$DOMAIN" "$EMAIL"; else self_signed; INSECURE=1; fi
  setup_wireguard; setup_amneziawg
  [ -n "$HY2_PORT" ] && setup_hysteria "http://127.0.0.1:$NODE_PORT/hy2/auth"
  umask 077
  cat > $ENV <<EOF
MODE=node
DOMAIN=$DOMAIN
NODE_PORT=$NODE_PORT
NODE_TOKEN=$NODE_TOKEN
HY2_PORT=$HY2_PORT
HY2_OBFS=$HY2_OBFS
HY2_SECRET=$HY2_SECRET
HY2_STATS_PORT=$HY2_STATS_PORT
HY2_INSECURE=$INSECURE
DATA_DIR=/var/lib/kanki
EOF
  service kanki-node node
  open_ports "$NODE_PORT/tcp" "$WG_PORT/udp" "$AWG_PORT/udp" ${HY2_PORT:+"$HY2_PORT/udp"}
  IP=$(pubip)
  echo; ok "Node nasb shod! In-ha ra dar panel (Node-ha > Afzudan node) vared konid:"
  echo -e "   API address:   ${G}http://$IP:$NODE_PORT${N}"
  echo -e "   Endpoint:      ${G}${DOMAIN:-$IP}${N}"
  echo -e "   Node token:    ${G}$NODE_TOKEN${N}"
  echo "   (Amniat: port $NODE_PORT ra faghat baraye IP panel asli baz bezarid)"
}

update(){
  download_bin
  systemctl restart kanki-panel 2>/dev/null || true
  systemctl restart kanki-node 2>/dev/null || true
  ok "Update anjam shod"
}

uninstall(){
  read -rp "Hame chiz (panel, database, settings) hazf shavad? [y/N]: " Y
  [[ "$Y" =~ ^[Yy]$ ]] || exit 0
  systemctl disable --now kanki-panel kanki-node 2>/dev/null || true
  rm -f /etc/systemd/system/kanki-panel.service /etc/systemd/system/kanki-node.service "$BIN"
  rm -rf /var/lib/kanki "$ENV_DIR"
  ok "Hazf shod (WireGuard/AmneziaWG/Hysteria/Caddy dast nakhordand)"
}

echo -e "${G}"
echo "  =================================="
echo "        KANKI PANEL INSTALLER"
echo "  =================================="
echo -e "${N}"
echo "  1) Nasb panel asli"
echo "  2) Nasb node (server ezafe)"
echo "  3) Update"
echo "  4) Hazf (uninstall)"
read -rp "  Entekhab: " C
case "$C" in
  1) install_panel ;;
  2) install_node ;;
  3) update ;;
  4) uninstall ;;
  *) die "Gozine na-motabar" ;;
esac
