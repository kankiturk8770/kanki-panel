# Kanki Panel v2

Lightweight **WireGuard · AmneziaWG · Hysteria2 · OpenVPN (UDP/TCP)** panel written in Rust, with a built-in Telegram sales bot, multi-node support and a gold UI that matches the Kanki VPN Android app.

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
│   ├── vpn/                wg.rs, hy2.rs, ovpn.rs, sync.rs (node sync + traffic + limits)
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
- **Dashboard** (home page): live CPU / RAM / storage / swap gauges, network speed chart (peak + total since boot), TCP / UDP connections, user counters (tap one to open the filtered Users page) and the VPN services with start / stop / restart. Refreshes every 1 / 2 / 5 / 10 s and can be paused.
- **Users**: one card per user with on/off switch, status, protocol tags, Jalali expiry + days left, connections, usage bar and 5 quick buttons (edit, link, QR, reset, delete). Search, status / protocol filters, sorting, select all + bulk bar (enable, disable, reset, extend, delete) and pagination (12 / 24 / 48 / 96). The edit sheet has a Jalali date field, quick add of days and GB, subscription link + QR, configs and a new-link button.
- **Nodes**: users, last contact, sync state (synced / config mismatch), Drain, Maintenance, health check, sync, repair agent, remote agent update, edit (name, note, "sync users without a node here", panel or custom endpoint), delete. Node API runs behind TLS (Caddy).
- **Sales bot**: lives in Telegram. Set the token at install or with `kanki` > 4; plans, prices, payments, trials and referrals are managed from the bot's admin panel.
- **Backup**: AES-256 encrypted archive (database + server keys/configs + certificates), restore with optional full server migration, scheduled Telegram backups (token, chat id auto-detect, interval, passphrase, test, send now).
- **Security center**: scoped API tokens (shown once), TOTP 2FA, active sessions with IP/device and revoke, IP allow/deny (CIDR), session lifetime, enforce 2FA, login history, audit log, brute-force lockout.
- **Settings**: panel name, FA/EN, dark/light, refresh interval, 5 color themes, public endpoint, subscription base URL, apply endpoint to all nodes, DNS/MTU, default protocols, AmneziaWG compatibility mode, OpenVPN inline credentials, connection-limit enforcement.
- **System**: CPU / RAM / storage / swap / network and service control live on the Dashboard. One-click self-update (header button) with sha256 verification.
- **Subscription page** `/sub/bub-…`: same URL format the Kanki app uses. Data and time rings, Jalali expiry, copyable subscription + raw links, per-node protocol cards (download / info / QR / URI) and app / support buttons (from the sales settings: App link, Support ID). `/sub/<code>/raw` for v2rayNG / Hiddify, `/sub/<code>/json` for apps.

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
- WireGuard/AmneziaWG can't tell devices apart, so the connection limit is enforced for OpenVPN and Hysteria2; WG/AWG show live usage.
