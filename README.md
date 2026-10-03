# Kanki Panel v2

Lightweight **WireGuard · AmneziaWG · Hysteria2** panel written in Rust, with a built-in Telegram sales bot, multi-node support and a gold UI that matches the Kanki VPN Android app.


## New in 2.4 — Kanki Tunnel
- **Tunnels** between your servers, managed from the panel (menu: Tunnels). Users connect to the **entry** server (for example in Iran) and traffic leaves from the **exit** server abroad. The entry server runs only a tiny **tunnel agent** — no VPN, no web panel.
- **Animated map** on the Tunnels page and the Dashboard showing which server connects to which, with live state (connected / connecting / down), transport and ping.
- **Six transports**: `tcp`, `tcpmux`, `ws`, `wss`, `quic`, `kcp`. Both TCP and UDP are carried, so WireGuard, AmneziaWG and Hysteria2 pass through. Reverse or direct mode. Every link is encrypted (X25519 + ChaCha20-Poly1305) with the tunnel token and reconnects on its own.
- **Add a tunnel server with one command** (Tunnels > + Server); it installs only the agent and shows up as Connected within seconds. See [the install guide](docs/INSTALL.md#add-a-tunnel-server-kanki-tunnel).

## New in 2.3
- The panel is called **Kanki Panel** and has its own logo (an uploaded logo still replaces it).
- No OpenVPN anywhere: not in the panel, not on the subscription page, not installed by `install.sh` or by node join.
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
│   │                       mux.rs (many streams per link), engine.rs (run tunnels), agent.rs
│   │                       (tunnel-only server), panel.rs (API + in-panel engine), tests.rs
│   └── telegram/           bot.rs (sales bot: plans, payments, trials, referrals, admin panel)
├── assets/web/             index.html (admin panel), sub.html (subscription page)
├── docs/                   INSTALL.md, API.md, CHANGES.md
└── .github/workflows/      release.yml (builds the binary into Releases "latest")
```

## Install
On Ubuntu 22.04 / 24.04 as root:
```bash
bash <(curl -fsSL https://raw.githubusercontent.com/<USER>/<REPO>/main/install.sh)
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
