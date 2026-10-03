# v2.3.0

## New
- **Kanki Panel** name and a built-in logo (K with two node links). Existing panels named "KANKI VPN" are renamed on start; an uploaded logo still wins.
- **Live log on the dashboard** (`GET /api/logs`): source picker (all, panel, WireGuard, AmneziaWG, Hysteria2, Caddy), **All / Errors / Debug** tabs with counts, pause, copy, auto refresh every 5 s.
- Dashboard nodes card says **Connected / Disconnected** for every server, with an "all servers connected" summary.
- **Traffic & stats** page: total recorded usage, quota of limited users and percent used, live network chart, by protocol, by node, per-user usage list (tap opens the user).
- **Port management** page: per server (main + nodes) WireGuard / AmneziaWG / Hysteria2 / panel / node API ports with service state, public address, conflict warning, check now, copyable `ufw` command and an all-servers table.
- **Sales bot** page in the menu: create, test connection, pause / resume, edit, delete; sales settings (sales on, warnings, support, app link, required channel, welcome text, free trial, referral reward, card to card, NOWPayments, ZarinPal, wallet) and plans.
- **Backup > Transfer from BUB panel to Kanki Panel**, step 1: reads a BUB backup in the browser (gzip, tar, zip, SQLite, JSON, OpenSSL-encrypted with the passphrase) and shows a copyable report of files, tables and columns. No secrets go into the report. Step 2 (import with the same links and keys) comes once the format is confirmed.
- Neon accents on buttons, toggles and active items; new **soft light** theme (warm sand, darker gold).

## Changed
- **OpenVPN removed**: not offered by the installer or node join, gone from services, settings, user forms, configs and the subscription page. Existing users and the default protocol list lose `ovpn` on start.
- New subscription links look like `/sub/kanki-<id>-<code>`. Links made by older versions keep working.
- User sheet is compact: name, status, three small stats and five buttons (edit, link, QR, reset, delete); only one panel opens at a time.

# v2.2.0

## New
- **Add node with one command.** Nodes > Add node makes a one-time join command (valid for 1 hour). Run it as root on the new Ubuntu / Debian server: it installs only what a node needs (WireGuard, AmneziaWG, Hysteria2, OpenVPN and the node agent behind Caddy TLS, no panel UI), picks free ports by itself and registers the server in the panel. Nothing has to be copied back by hand; the panel notices the new node and offers "Add to all users". The old manual form is still there under "Add by hand".
- **Add to all users / Remove from all users** on every node card (`POST /api/nodes/:id/assign-all` and `unassign-all`). Users without a node list follow the node's `accept_all` flag, users with a list get the node id added or removed. The main server cannot be removed from all users.
- **Nodes on the Dashboard**: online / offline, sync state, user count and last contact for every node, with shortcuts to Add node and Nodes.
- **Users page uses small name boxes** (status dot + name). Tap a box to open the user: info, subscription link, QR, configs, quick add of days / GB and the edit form. Select mode (top button) gives checkboxes and the bulk bar. Page sizes 24 / 48 / 96 / 200.
- **Icons**: one consistent SVG icon set for the side menu, header, gauges and buttons instead of emoji.
- **Logo**: Settings > Logo uploads an image that is shown in the header, side menu, login page and the subscription page (stored in the `logo` setting, scaled to at most 256 px in the browser).
- `POST /api/node-join` (scope `nodes`) creates the one-time token; `POST /join/register` is the public endpoint the installer calls with it.

## Changed
- Installer: `KANKI_JOIN` + `KANKI_PANEL` switch it to non-interactive node mode (every protocol, default ports, a random free port when one is busy). Re-running the same command on a server that is already a node only registers it again.

# v2.1.0

## New
- **Dashboard** is now the home page: live CPU / RAM / storage / swap gauges, network speed chart, TCP / UDP connections, user counters and service cards with start / stop / restart. Refresh 1 / 2 / 5 / 10 s, pause button.
- `GET /api/live` (admin): cumulative CPU jiffies, memory, swap, default-route interface counters, TCP established / listening and UDP socket counts. The browser turns two samples into percentages and speeds, so the server keeps no state.
- `POST /api/services/:name/:action` with `start`, `stop`, `restart`. `web`, `panel` and `node` can only be restarted (stopping them would cut off the panel itself).
- **Users page rebuilt**: cards with toggle switch, protocol tags, Jalali dates, usage bar and 5 quick buttons; search, status / protocol filters, sorting, select all + bulk bar, pagination with page size; edit sheet with Jalali date input and quick add of days / GB.
- **Subscription page rebuilt**: data / time rings, status pill, subscription + raw links, per-node protocol cards, app / support buttons. All server-rendered hooks (`data-act`, `data-i18n`, `{{placeholders}}`) are unchanged, so the Kanki app keeps working.
- Dates are shown in the Jalali calendar with Persian digits when the language is Persian.

## Changed
- The old **System** page is gone, the Dashboard replaces it.
- `POST /api/services/:name/restart` became `POST /api/services/:name/:action`.
- After login the panel opens on the Dashboard instead of Users.
- Modals open as bottom sheets on phones; Esc closes them.

# v2.0.0

## Bugs fixed
- Traffic could be counted twice when two sync rounds overlapped (timer + user edit). Sync is now serialized.
- Connection limit was only displayed. Now enforced for OpenVPN + Hysteria2 at login time, across all nodes.
- Panel <-> node traffic (node token and every user key) went over plain HTTP with certificate checks disabled. New nodes sit behind Caddy TLS; certificates are verified unless a node is explicitly marked self-signed. Old HTTP nodes still work and show a warning.
- Admin password used a single SHA-256. Now PBKDF2-HMAC-SHA256 (120k rounds); old hashes upgrade on next login.
- Login had no rate limit and sessions never expired / lived only in memory. Now IP lockout after 6 failures, DB-backed sessions with configurable lifetime.
- Expired / disabled users stayed connected on Hysteria2 until they dropped. They are now kicked on the next sync (OpenVPN too).
- WG/AWG peers were pushed to nodes where that protocol isn't installed, so nodes looked out of sync. Fixed, plus a real sync-state indicator.
- Constant-time comparison for tokens and passwords.
- Usernames are validated (they end up in file names and OpenVPN).
- Regenerating a user's link now also rotates their WG/AWG keys.

## New
OpenVPN UDP/TCP, security center, encrypted backups + Telegram schedule, node drain/maintenance/health/repair/update, self-update, English installer with `kanki` menu, FA/EN + light/dark + color themes, redesigned subscription page.
