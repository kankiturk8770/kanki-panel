#!/usr/bin/env bash
# =====================================================================
#  Kanki Panel — نصب‌کننده
#  bash <(curl -fsSL https://raw.githubusercontent.com/<USER>/<REPO>/main/install.sh)
# =====================================================================
set -e
G='\033[1;33m'; R='\033[1;31m'; N='\033[0m'; OK='\033[1;32m'
say(){ echo -e "${G}▶ $*${N}"; }
ok(){ echo -e "${OK}✔ $*${N}"; }
die(){ echo -e "${R}✘ $*${N}"; exit 1; }
[ "$(id -u)" = "0" ] || die "با کاربر root اجرا کنید"

ENV_DIR=/etc/kanki; ENV=$ENV_DIR/kanki.env; BIN=/usr/local/bin/kanki-panel; TLS=$ENV_DIR/tls
mkdir -p "$ENV_DIR"; chmod 700 "$ENV_DIR"

# ---------------- مخزن گیت‌هاب (برای دانلود فایل اجرایی)
REPO="${KANKI_REPO:-$(cat $ENV_DIR/repo 2>/dev/null || true)}"
if [ -z "$REPO" ]; then
  read -rp "مخزن گیت‌هاب پروژه (مثلاً username/kanki-panel): " REPO
fi
[ -n "$REPO" ] || die "مخزن خالی است"
echo "$REPO" > $ENV_DIR/repo

rand(){ tr -dc 'A-Za-z0-9' </dev/urandom | head -c "${1:-24}"; }
rnum(){ shuf -i "$1"-"$2" -n 1; }
pubip(){ curl -s4 --max-time 8 https://api.ipify.org || hostname -I | awk '{print $1}'; }

download_bin(){
  say "دانلود آخرین نسخه‌ی Kanki Panel از $REPO ..."
  curl -fL --retry 3 -o /tmp/kanki-panel "https://github.com/$REPO/releases/download/latest/kanki-panel" \
    || die "دانلود نشد. مطمئن شوید مخزن عمومی است و ساخت GitHub Actions موفق بوده."
  install -m 755 /tmp/kanki-panel "$BIN"
  ok "$($BIN version)"
}

base_packages(){
  say "نصب پیش‌نیازها..."
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
  say "راه‌اندازی WireGuard روی پورت $WG_PORT ..."
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
  systemctl enable -q --now wg-quick@wg0 && ok "WireGuard فعال شد" || echo "⚠️ WireGuard راه نیفتاد"
}

setup_amneziawg(){
  say "نصب AmneziaWG (ماژول کرنل از PPA رسمی Amnezia)..."
  if ! command -v awg >/dev/null; then
    add-apt-repository -y ppa:amnezia/ppa >/dev/null 2>&1 || true
    apt-get update -qq
    apt-get install -y -qq amneziawg amneziawg-tools >/dev/null 2>&1 || apt-get install -y -qq amneziawg-dkms amneziawg-tools >/dev/null 2>&1 || true
  fi
  if ! command -v awg >/dev/null; then echo "⚠️ AmneziaWG نصب نشد؛ فقط WireGuard و Hysteria2 فعال می‌مانند"; return; fi
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
  systemctl enable -q --now awg-quick@awg0 && ok "AmneziaWG فعال شد" || echo "⚠️ AmneziaWG راه نیفتاد (ممکن است کرنل نیاز به ری‌استارت داشته باشد)"
}

get_cert(){ # $1=domain $2=email
  say "گرفتن گواهی SSL برای $1 ..."
  apt-get install -y -qq certbot >/dev/null
  systemctl stop caddy 2>/dev/null || true
  certbot certonly --standalone -n --agree-tos -m "$2" -d "$1" \
    --pre-hook "systemctl stop caddy 2>/dev/null || true" --post-hook "systemctl start caddy 2>/dev/null || true" \
    || die "گواهی گرفته نشد. دامنه باید مستقیم (بدون پروکسی Cloudflare) به IP همین سرور اشاره کند و پورت 80 آزاد باشد."
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
  sh /etc/letsencrypt/renewal-hooks/deploy/kanki.sh
  ok "گواهی SSL گرفته شد (تمدید خودکار)"
}

self_signed(){
  mkdir -p "$TLS"; getent group kankitls >/dev/null || groupadd kankitls
  openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=kanki" -keyout $TLS/privkey.pem -out $TLS/fullchain.pem >/dev/null 2>&1
  chgrp kankitls $TLS/*.pem; chmod 640 $TLS/*.pem
}

setup_hysteria(){ # $1=auth url
  say "نصب Hysteria2 روی پورت UDP $HY2_PORT ..."
  command -v hysteria >/dev/null || bash <(curl -fsSL https://get.hy2.sh/) >/dev/null 2>&1 || { echo "⚠️ Hysteria2 نصب نشد"; HY2_PORT=""; return; }
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
  systemctl restart hysteria-server.service && ok "Hysteria2 فعال شد" || echo "⚠️ Hysteria2 راه نیفتاد"
}

setup_caddy(){ # $1=domain $2=https port
  say "راه‌اندازی وب‌سرور Caddy ..."
  if ! command -v caddy >/dev/null; then
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor --yes -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' > /etc/apt/sources.list.d/caddy-stable.list
    apt-get update -qq && apt-get install -y -qq caddy >/dev/null
  fi
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
  systemctl enable -q caddy && systemctl restart caddy && ok "Caddy فعال شد"
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
  echo; say "نصب پنل اصلی"
  read -rp "🌐 دامنه‌ی پنل (باید مستقیم به IP این سرور اشاره کند): " DOMAIN
  [ -n "$DOMAIN" ] || die "دامنه لازم است"
  read -rp "📧 ایمیل برای SSL: " EMAIL
  read -rp "🔒 پورت HTTPS پنل [443]: " HTTPS_PORT; HTTPS_PORT=${HTTPS_PORT:-443}
  read -rp "👤 نام کاربری ادمین پنل: " ADMIN_USER
  read -rsp "🔑 رمز ادمین پنل: " ADMIN_PASS; echo
  [ -n "$ADMIN_USER" ] && [ -n "$ADMIN_PASS" ] || die "نام کاربری و رمز لازم است"
  read -rp "🏷  نام این سرور (مثلاً GERMANY): " LOCAL_NAME; LOCAL_NAME=${LOCAL_NAME:-MAIN}
  read -rp "🔌 پورت WireGuard [51820]: " WG_PORT; WG_PORT=${WG_PORT:-51820}
  read -rp "🔌 پورت AmneziaWG [51821]: " AWG_PORT; AWG_PORT=${AWG_PORT:-51821}
  read -rp "⚡ Hysteria2 نصب شود؟ [Y/n]: " HY; HY=${HY:-Y}
  if [[ "$HY" =~ ^[Yy]$ ]]; then read -rp "🔌 پورت UDP هیستریا [8443]: " HY2_PORT; HY2_PORT=${HY2_PORT:-8443}; else HY2_PORT=""; fi
  read -rsp "🤖 توکن ربات تلگرام (خالی = بدون ربات): " BOT_TOKEN; echo
  BOT_ADMINS=""; [ -n "$BOT_TOKEN" ] && read -rp "👑 آیدی عددی ادمین(ها) با کاما: " BOT_ADMINS

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
  echo; ok "نصب کامل شد 🎉"
  echo -e "   پنل: ${G}https://$DOMAIN:$HTTPS_PORT/admin${N}"
  [ -n "$BOT_TOKEN" ] && echo "   ربات: در تلگرام /start بزنید"
}

install_node(){
  echo; say "نصب نود (سرور اضافه)"
  read -rp "🌐 دامنه‌ی این نود (برای SSL هیستریا؛ خالی = بدون دامنه): " DOMAIN
  EMAIL=""; [ -n "$DOMAIN" ] && read -rp "📧 ایمیل برای SSL: " EMAIL
  read -rp "🔌 پورت API نود [2096]: " NODE_PORT; NODE_PORT=${NODE_PORT:-2096}
  read -rp "🔌 پورت WireGuard [51820]: " WG_PORT; WG_PORT=${WG_PORT:-51820}
  read -rp "🔌 پورت AmneziaWG [51821]: " AWG_PORT; AWG_PORT=${AWG_PORT:-51821}
  read -rp "⚡ Hysteria2 نصب شود؟ [Y/n]: " HY; HY=${HY:-Y}
  if [[ "$HY" =~ ^[Yy]$ ]]; then read -rp "🔌 پورت UDP هیستریا [8443]: " HY2_PORT; HY2_PORT=${HY2_PORT:-8443}; else HY2_PORT=""; fi
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
  echo; ok "نود نصب شد 🎉  این‌ها را در پنل (تب نودها ← افزودن نود) وارد کنید:"
  echo -e "   آدرس API:      ${G}http://$IP:$NODE_PORT${N}"
  echo -e "   آدرس اتصال:    ${G}${DOMAIN:-$IP}${N}"
  echo -e "   توکن نود:      ${G}$NODE_TOKEN${N}"
  echo "   (امنیت بیشتر: پورت $NODE_PORT را فقط برای IP پنل اصلی باز بگذارید)"
}

update(){
  download_bin
  systemctl restart kanki-panel 2>/dev/null || true
  systemctl restart kanki-node 2>/dev/null || true
  ok "به‌روزرسانی انجام شد"
}

uninstall(){
  read -rp "همه‌چیز (پنل، دیتابیس، تنظیمات) حذف شود؟ [y/N]: " Y
  [[ "$Y" =~ ^[Yy]$ ]] || exit 0
  systemctl disable --now kanki-panel kanki-node 2>/dev/null || true
  rm -f /etc/systemd/system/kanki-panel.service /etc/systemd/system/kanki-node.service "$BIN"
  rm -rf /var/lib/kanki "$ENV_DIR"
  ok "حذف شد (WireGuard/AmneziaWG/Hysteria/Caddy دست نخوردند)"
}

echo -e "${G}"
echo "  ╔══════════════════════════════════╗"
echo "  ║        KANKI PANEL INSTALLER       ║"
echo "  ╚══════════════════════════════════╝"
echo -e "${N}"
echo "  1) نصب پنل اصلی"
echo "  2) نصب نود (سرور اضافه)"
echo "  3) به‌روزرسانی"
echo "  4) حذف"
read -rp "  انتخاب: " C
case "$C" in
  1) install_panel ;;
  2) install_node ;;
  3) update ;;
  4) uninstall ;;
  *) die "گزینه نامعتبر" ;;
esac
