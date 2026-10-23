# Kanki Panel v2

Lightweight **WireGuard · AmneziaWG · Hysteria2 · KANKI MIX** panel written in Rust, with a built-in Telegram sales bot, multi-node support and a gold UI that matches the Kanki VPN Android app.


## New in 3.9 — one kind of server, one command
- **Servers** is one list: the panel runs on one server, every other server is a node. Each card shows what the server runs (VPN for users on/off and its ports, tunnels, Xray, Kanki DNS) and its health.
- **Add server** gives one command that installs everything on the new server (VPN part and server agent). What it runs is switched on in the panel. Servers made before 3.9 get their missing part with one button.
- **Unique VPN ports** on every server, so one Iran entry can tunnel all of them; **Fix ports** moves clashing ones (tunnels follow).
- **Backup** brings everything back on another server: app files, node certificate pins, the subscription domain, and the old server's IP replaced in the panel's addresses. Details: `docs/CHANGES.md`.

## New in 3.6.7 — the app's install files in the panel
- **Sales bot › App files:** upload the Kanki app (.apk) in the panel, one file per phone type (arm64, armv7, universal; read from the file name, or chosen). A new file of the same type replaces the old one. No GitHub token or download site is needed.
- **Bot:** «📱 Download app» shows a button per phone type (with which phones it is for and its size) and sends the file itself, named like `KankiVPN-1.15.1-arm64.apk`. After the first send Telegram's file id is kept, so the next customers get it at once. The account message also has the download button.
- **Subscription page:** a «Kanki VPN app» card with the version and a download button per phone type (the 64-bit one marked as recommended). Downloads go through `/sub/<code>/app/<type>`, so only subscribers get them, also through the Iran subscription server and the separate subscription domain.
- Files over 50 MB cannot be sent by a Telegram bot: they are offered on the subscription page only.

## New in 3.6.6 — ports taken by another program
- **Health** of an Xray or Kanki DNS server lists the ports that service needs but another program holds (for example Caddy or nginx left from an earlier setup on 80 / 443), with the service name and the sites it serves (from the Caddyfile / nginx sites).
- **Free the ports** (in Health): the server stops and turns off that service, then Kanki DNS / Xray restart onto the ports. Offered only for a plain service that listens from outside on nothing but those ports (HTTP/3 on the same port counts as the same site); never for Kanki's own services, SSH, Docker or the panel's own server. The confirmation names the sites that go down and the command that brings it back.
- **Emergency chat port:** the port field suggests the ports a CDN (ArvanCloud, Cloudflare) passes on: HTTP 8080, 8880, 2052, 2082, 2086, 2095 and HTTPS 2053, 2083, 2087, 2096, 8443. The chat cannot take 53 / 80 / 443 / 853 on a server that runs Kanki DNS, or the port of an Xray inbound there (and a DNS server cannot be added where the chat holds those ports).

## New in 3.6.5 — Kanki DNS keeps the phone online when DNS abroad is blocked
- A relay (inside Iran) now asks its exit, through the same hidden tunnel, for every name it does not route (before: it asked 1.1.1.1 / 8.8.8.8 directly from Iran, where answers can be blocked or altered).
- When nothing abroad answers (the tunnel and the DNS servers abroad are both cut), the server asks the data center's own DNS (from resolv.conf), so Iranian sites keep working and a phone with Private DNS never loses all of its internet. A way that fails is skipped for 20 seconds, so queries do not wait on it.
- Health (DNS server) shows where the other sites' answers came from: exit through the tunnel, DNS abroad, data center DNS.
- Ports are unchanged: 53 (UDP/TCP), 853, 443 and 80 on each DNS server, plus the relay's tunnel port (8446 by default). Update the agents on both servers of a relay (the exit answers the relay's questions from this version on; an older exit is simply skipped).

## New in 3.6.4 — KANKI MIX only in the app
- The subscription page no longer shows the KANKI MIX link, its copy button or QR code (it works only in the Kanki app, and the link is the user's own key): the row says "Only in the Kanki VPN app". The app still gets the link as before.

## New in 3.6.3 — Xray servers on the app's map
- Every Xray link in the subscription carries where its traffic leaves to the internet (country, city, map position), looked up from the panel like the VPN servers (the server itself, or the server the default outbound goes on to). The Kanki app names Xray servers by their place and shows them on the map with their flag before the first connect.
- Exit locations are checked every 10 minutes (was hourly), so a new server shows in the app soon.

## New in 3.6.2 — repair for Xray and DNS servers, who is connected with what
- **Xray and Kanki DNS server cards** (Servers) get the buttons VPN servers have: **Repair** (the server writes its service again and restarts it on its next report, within seconds; an Xray binary that is missing or broken is installed again), **Health** (running or not, last report, errors, SSL, online users / queries) and **Add to all users / Remove from all users** (ticks or unticks Xray or Kanki DNS for every user).
- **Connected now:** every user shows how they are connected right now and where: WireGuard, AmneziaWG, Hysteria2 and KANKI MIX from the VPN servers, Xray from the Xray servers, Kanki DNS from the DNS queries. Users page: a "Connected now" bar with a count per protocol (tap one to list those users), small protocol tags on each user, and the full list (protocol · server) in the user sheet. "Online" now also counts Xray and DNS use.
- Repair needs the agent of 3.6.2 on the server for the forced restart (older agents only restart a stopped service): update the tunnel servers after the panel.

## New in 3.6 — KANKI MIX
- **Our own protocol** on every VPN server, next to WireGuard / AmneziaWG / Hysteria2: game packets on a raw datagram path (no queue, sent twice in gaming mode), websites over KCP + FEC, a ChaCha20 mask with no fixed bytes. Menu: VPN services › KANKI MIX.
- The server is built into the panel: agents install and run it themselves (UDP 4000 by default, per-server ports). Every user has their own key; traffic and devices count like the other protocols. The Kanki app gets the `kanki://` link from the subscription.

## New in 3.5.2 — SSL with certbot on the server
- An Xray server or a Kanki DNS server gets its SSL by itself with certbot (domain, no e-mail). The Cloudflare / ArvanCloud API way is gone.
- Port 80 is freed by itself for certbot (Caddy, nginx, an inbound … are set aside for a few seconds and come back), also on renewal. Kanki DNS answers Let's Encrypt itself, so DNS never stops.

## New in 3.5 — a menu that opens in place, stronger Xray and DNS pages
- **Menu:** groups open in place (VPN services › All / Kanki VPN / Xray, Kanki DNS › Overview / Servers / Services / Users / Settings, Tunnels, Sales, System). On a phone there is no hamburger: a section bar under the top bar opens a drop-down of tiles (VPN: Kanki VPN and Xray side by side).
- **VPN services page:** Kanki VPN (WireGuard · AmneziaWG · Hysteria2) and Xray side by side, with Kanki DNS under them.
- **Xray:** tabs (overview, inbounds, online clients, routing, settings); per inbound traffic kept across restarts, a traffic limit and an end date, clone, reset, users with their links and QR, JSON; more options (listen address, sniffing, PROXY protocol, TLS version / unknown SNI / certificate files, REALITY xver and clock limit, WS heartbeat, XHTTP padding, mKCP tuning, fallbacks); outbounds (another server from its link, SOCKS, HTTP, JSON) and routing rules built in the panel, block ads / Iranian sites.
- **Kanki DNS:** tabs; queries, routed, cache and refused counts per server, busiest services, the addresses each user registered (and "forget addresses"), a domain checker, collapsible services with search and all on / off.
- **User form:** services as cards (Kanki VPN with its protocols and servers, Xray with its inbounds, DNS with its servers) and quick choices.

## New in 3.4 — Kanki DNS and Xray
- **Kanki DNS** (menu: Kanki DNS): a private smart DNS only your subscribers can use. Sanctioned services go through your DNS servers (an exit abroad, optionally a relay inside Iran in front of it), everything else goes direct. DNS, DoT and DoH; each DNS server gets its SSL itself with certbot.
- **Xray** (menu: Xray): VLESS / VMess / Trojan / Shadowsocks inbounds with TCP, WS, gRPC, HTTPUpgrade, XHTTP, mKCP and TLS / REALITY, on the panel server or any agent server. The clients are your own users (tick Xray on the user).
- Add node now asks for the type: VPN, Xray, DNS exit or DNS relay. Guide: `docs/DNS-XRAY-FA.md`.

## New in 3.1 — Hysteria2 tunnel between two servers
- Tunnels › + Tunnel › **⚡ Hysteria2**: the exit runs a Hysteria2 server, the entry connects to it (Salamander obfuscation, pinned certificate). Forward ports through it, or send the whole internet of the entry's VPN users (for example `10.8.0.0/24`) out from the exit. Guide: `docs/HY2-TUNNEL.md`.

## New in 2.9 — tunnel for hostile networks
- **Three new transports:** `hq` (QUIC under a random per-packet mask, nothing on the wire looks like QUIC, packet sizes hidden), `h2` (WebSocket over HTTP/2 over TLS 1.3 with browser-like ALPN / ciphers / settings, four links per TCP connection, an ordinary web page for strangers) and `dual` (`hq` first, `h2` automatically when UDP does not get through, one port number for both).
- Records on these transports carry random padding. Scanners get no answer on the UDP port.
- **Standalone mode, no panel:** `kanki-panel tunnel-run file.json` (examples in `docs/examples/`). Install it as a systemd service on two servers with `scripts/install-standalone.sh` (step-by-step guide in Persian: `docs/STANDALONE-FA.md`). See `docs/HQ-TUNNEL.md`.
- Tunnel listeners are bounded now (limited half-open connections and handshakes, 1 MiB WebSocket messages before the token is proven), and the KCP relay no longer leaks sockets and tasks.
- **The new transport code has not been compiled by its author's environment**: run `cargo test tunnel::` (the CI does) before relying on it.

## New in 2.6 — tunnel camouflage
- **KCP header fully hidden** (ChaCha20 per-datagram wrap with random padding, keyed by the token) — no KCP signature on the wire.
- **QUIC disguised as HTTP/3** (`h3` ALPN + believable SNI); also fixes QUIC tunnels that would not connect.
- **SNI spoof** for WSS with quick-pick domains in the tunnel form.

## New in 2.5
- Every user gets the lowest free number (a deleted user's number is reused). Names are English letters and digits only, 3–12 characters (like `mahtab87`); bot customers get the name they choose or the English letters of their Telegram name, and an empty name in the panel gives USER<n>. Bot trials that run out are deleted, and a trial that is bought becomes that same account.
- Sales bot: **smart plan builder** (price per GB / country / connection), expiring **discount codes**, and a **smart channel** that writes and publishes posts by itself.
- **Nightly encrypted backup** to the bot with automatic database cleaning; the panel has its own backup passphrase.
- **⚡ Smart tunnel**: tests all six transports between two servers and builds the tunnel with the best one.
- Simpler Security center and a more compact dashboard.

## New in 2.4 — Kanki Tunnel
- **Tunnels** between your servers, managed from the panel (menu: Tunnels). Users connect to the **entry** server (for example in Iran) and traffic leaves from the **exit** server abroad. The entry server runs only a tiny **tunnel agent** — no VPN, no web panel.
- **Animated map** on the Tunnels page and the Dashboard showing which server connects to which, with live state (connected / connecting / down), transport and ping.
- **Whitelist mode (`cdn`)**: reach the exit only through a CDN edge (ArvanCloud…) with its own SNI / Host, several edge IPs and a split TLS hello — see `docs/WHITELIST.md`.
- **Six transports** (plus `cdn`): `tcp`, `tcpmux`, `ws`, `wss`, `quic`, `kcp`. Both TCP and UDP are carried, so WireGuard, AmneziaWG and Hysteria2 pass through. Reverse or direct mode. Every link is encrypted (X25519 + ChaCha20-Poly1305) with the tunnel token and reconnects on its own.
- **Add a tunnel server with one command** (Tunnels > + Server); it installs only the agent and shows up as Connected within seconds. See [the install guide](docs/INSTALL.md#a-tunnel-entry-for-example-in-iran).

## New in 2.3
- The panel is called **Kanki Panel** and has its own logo (an uploaded logo still replaces it).
- **Dashboard**: every node says *Connected* / *Disconnected*, plus a **live log** (journald) with **All / Errors / Debug** tabs and a source picker.
- **Traffic & stats**: total usage, quota of limited users with percent used, live network chart, usage by protocol and node, per-user usage list.
- **Port management**: ports and service state for the main server and every node, conflict warning, ready `ufw` command, all-servers table.
- **Sales bot**: create / test / pause / edit / delete the Telegram bot, sales settings (trial, card to card, online payments, referral, messages) and plans.
- Compact user sheet: five buttons (edit, link, QR, reset, delete), one panel at a time.
- Neon accents and a soft light theme.

## Project layout
```
kanki-panel/
├── install.sh              installer + `kanki` menu (stays at root for the curl one-liner)
├── Cargo.toml
├── src/
│   ├── main.rs             startup, CLI commands, shared state
│   ├── core/               db.rs (SQLite), util.rs (crypto, TOTP, QR, helpers)
│   ├── http/               api.rs (users, nodes, configs, sub page), auth.rs (security center),
│   │                       admin.rs (system, update, bulk), backup.rs (encrypted backup, Telegram)
│   ├── vpn/                wg.rs, hy2.rs, sync.rs (node sync + traffic + limits)
│   ├── tunnel/             Kanki Tunnel: link.rs (transports + crypto), quic.rs (quic/kcp),
│   │                       hq.rs + salamander.rs (masked QUIC), h2ws.rs (WebSocket over HTTP/2),
│   │                       dual.rs (hq with h2 fallback), obfs.rs (KCP mask relay),
│   │                       mux.rs (many streams per link), engine.rs (run tunnels), agent.rs
│   │                       (tunnel-only server, standalone `tunnel-run`), panel.rs (API + in-panel
│   │                       engine), tests.rs
│   └── telegram/           bot.rs (sales bot: plans, payments, trials, referrals, admin panel)
├── assets/web/             index.html (admin panel), sub.html (subscription page)
├── docs/                   INSTALL.md, API.md, CHANGES.md, HQ-TUNNEL.md, STANDALONE-FA.md, examples/, systemd/
├── scripts/                install-standalone.sh (standalone tunnel as a systemd service)
└── .github/workflows/      release.yml (builds the binary into Releases "latest")
```

## Install
On Ubuntu 22.04 / 24.04 as root:
```bash
bash <(curl -fsSL https://raw.githubusercontent.com/kankiturk8770/kanki-panel/main/install.sh)
```
The installer is fully in English. Afterwards just run `kanki` for the menu (install / node / update / reset admin / status / uninstall).

1. Push this repo to GitHub (public). The GitHub Action builds the binary and publishes it to Releases under the `latest` tag.
2. Run the installer on the main server, choose **1**.
3. For every extra server run it again and choose **2**, then add the node in **Nodes > Add node** with the address + token it prints.

## Features
- **Dashboard** (home page): live CPU / RAM / storage / swap gauges, network speed chart (peak + total since boot), TCP / UDP connections, user counters (tap one to open the filtered Users page) and the VPN services with start / stop / restart. Refreshes every 1 / 2 / 5 / 10 s and can be paused. Nodes are listed with their online state, sync state and last contact.
- **Users**: small name boxes with a status dot. Tap one to open the user: info, subscription link, QR, configs, quick add of days / GB (Jalali date field) and the edit form. Search, status / protocol filters, sorting, select mode with bulk bar (enable, disable, reset, extend, delete) and pagination.
- **Nodes**: add a server with one command (Nodes > Add node, see below). Per node: users, last contact, sync state, Drain, Maintenance, health check, sync, repair agent, remote agent update, edit, and **Add to all users / Remove from all users**.
- **Sales bot**: lives in Telegram. Set the token at install or with `kanki` > 4; plans, prices, payments, trials and referrals are managed from the bot's admin panel.
- **Backup**: AES-256 encrypted archive (database + server keys/configs + certificates), restore with optional full server migration, scheduled Telegram backups (token, chat id auto-detect, interval, passphrase, test, send now).
- **Security center**: scoped API tokens (shown once), TOTP 2FA, active sessions with IP/device and revoke, IP allow/deny (CIDR), session lifetime, enforce 2FA, login history, audit log, brute-force lockout.
- **Settings**: panel name, FA/EN, dark / soft light, refresh interval, 5 color themes, public endpoint, subscription base URL, apply endpoint to all nodes, DNS/MTU, default protocols, AmneziaWG compatibility mode, connection-limit enforcement.
- **System**: CPU / RAM / storage / swap / network and service control live on the Dashboard. One-click self-update (header button) with sha256 verification.
- **Subscription page** `/sub/kanki-<id>-<code>` (links made by older versions keep working). Data and time rings, Jalali expiry, copyable subscription + raw links, per-node protocol cards (download / info / QR / URI) and app / support buttons (from the sales settings: App link, Support ID). `/sub/<code>/raw` for v2rayNG / Hiddify, `/sub/<code>/json` for apps.

## Add a node (one command)
1. In the panel: **Nodes > Add node** (optionally type the node's domain), then **Create join command**.
2. Paste the command on the new Ubuntu / Debian server as root. It installs only the VPN cores and the node agent (no panel) and registers itself.
3. The panel shows the node as soon as it joins. Press **Add to all users** if every user should get it.

The command is valid for one hour and one node. If the panel cannot reach the node, open the node API port (2096 unless busy) in the node's firewall and run the same command again.

## Logo
**Settings > Logo** > Choose image. It is used in the header, side menu, login page and the subscription page.

## Docs
- [Installation guide](docs/INSTALL.md)
- [REST API](docs/API.md)
- [Changelog](docs/CHANGES.md)

## CLI
```
kanki-panel reset-admin <user> <pass>   # forgot password / lost 2FA
kanki-panel reset-security              # locked out by IP policy
kanki-panel set-bot <token> <admin_ids>  # set / change the Telegram bot
kanki-panel version
```

## Notes
- The panel domain must point **directly** (no Cloudflare proxy) to the server; port 80 must be free while getting SSL.
- WireGuard/AmneziaWG can't tell devices apart, so the connection limit is enforced for Hysteria2; WG/AWG show live usage.


## AmneziaWG tunnel (v2.8.0)
A layer-3 AmneziaWG link between two servers, managed from Tunnels > + Tunnel > AmneziaWG: shared keys and obfuscation numbers made by the panel, optional hiding inside WS / WSS / CDN / QUIC / KCP / TCP Mux, exit NAT, source/destination routing and port forwarding. See `docs/AWG-TUNNEL.md`.
