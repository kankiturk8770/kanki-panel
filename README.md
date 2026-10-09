# Kanki Panel v2

Lightweight **WireGuard · AmneziaWG · Hysteria2** panel written in Rust, with a built-in Telegram sales bot, multi-node support and a gold UI that matches the Kanki VPN Android app.


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
- Users are named **USER1, USER2, …** (lowest free number; a deleted user's number is reused; bot trials are USER<n>-TEST and become USER<n> when bought).
- Sales bot: **smart plan builder** (price per GB / country / connection), expiring **discount codes**, and a **smart channel** that writes and publishes posts by itself.
- **Nightly encrypted backup** to the bot with automatic database cleaning; the panel has its own backup passphrase.
- **⚡ Smart tunnel**: tests all six transports between two servers and builds the tunnel with the best one.
- Simpler Security center and a more compact dashboard.

## New in 2.4 — Kanki Tunnel
- **Tunnels** between your servers, managed from the panel (menu: Tunnels). Users connect to the **entry** server (for example in Iran) and traffic leaves from the **exit** server abroad. The entry server runs only a tiny **tunnel agent** — no VPN, no web panel.
- **Animated map** on the Tunnels page and the Dashboard showing which server connects to which, with live state (connected / connecting / down), transport and ping.
- **Whitelist mode (`cdn`)**: reach the exit only through a CDN edge (ArvanCloud…) with its own SNI / Host, several edge IPs and a split TLS hello — see `docs/WHITELIST.md`.
- **Six transports** (plus `cdn`): `tcp`, `tcpmux`, `ws`, `wss`, `quic`, `kcp`. Both TCP and UDP are carried, so WireGuard, AmneziaWG and Hysteria2 pass through. Reverse or direct mode. Every link is encrypted (X25519 + ChaCha20-Poly1305) with the tunnel token and reconnects on its own.
- **Add a tunnel server with one command** (Tunnels > + Server); it installs only the agent and shows up as Connected within seconds. See [the install guide](docs/INSTALL.md#add-a-tunnel-server-kanki-tunnel).

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
