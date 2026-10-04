# v2.5.0

## Users: tidy USER numbering
- Every new user — made in the panel, by the bot, or by an admin in the bot — is named **USER1, USER2, …** and always takes the **lowest free number** (its id is the same number). Leave the name empty in the panel to get it.
- Deleting a user removes it completely (account, keys, unpaid orders; paid orders keep their amount but no longer point at it), so the next new user gets that number again.
- Free trials from the bot are **USER<n>-TEST**. When that person buys or renews, the **same account** becomes **USER<n>** — no second account is made.

## Sales bot
- The bot page has tabs: **Sales settings · Plans · Discount codes · Smart channel**.
- **Smart plan builder**: set a price per GB, a monthly base, a price per extra country and per extra connection, rounding and a big-plan discount; pick volumes, durations, connections and countries, see every plan with its price, then add them all (or replace the old ones) with one button. Plans can be hidden / shown in the bot. A plan with N countries puts the buyer on the N least-loaded servers.
- **Discount codes** can expire by time; used-up and expired codes are removed by themselves.
- **Smart channel**: the bot (as a channel admin) writes and publishes posts by itself — price lists from your real plans, discount campaigns with a fresh code that ends on its own, tips, how-to-connect guides, free-trial and invite posts, "why us" with live numbers, and greetings for Nowruz, Sizdah, Yalda, school opening and Black Friday (with an optional automatic discount). Texts are built from a Persian word bank so they do not repeat, the post type rotates, nothing is posted between 1 and 8 in the morning (Iran time), and every post has "buy" and "free trial" buttons. Preview, publish now, or start a campaign from the panel; the bot's admin menu has a **📢 Smart channel** section too.

## Backup
- The panel's own backup passphrase: made automatically (random) if you never set one, shown on the Backup page with copy / change. Downloads and restores use it when the passphrase box is empty, so backups are never left unencrypted.
- **Nightly backup**: every night at the time you pick (Iran time, default 03:00) the database is cleaned and compacted, then the encrypted backup is sent to the bot. "Every N hours" is still available.
- **Clean database** button: removes old login / audit rows, expired sessions and abandoned unpaid orders, then compacts the file. Users and plans are not touched.

## Smart tunnel
- **⚡ Smart tunnel** on the Tunnels page: pick two servers and it tests all six transports between them with short-lived test tunnels — real ping, TCP download and upload speed, UDP loss and ping — ranks them, names the best one (and the best for UDP / WireGuard / Hysteria2), and builds the tunnel with it in one tap. Uses six test ports (default 3990–3995, TCP + UDP) on the listening server.
- **🔁 Rotating tunnel** (tick it in the tunnel form): if the tunnel stays down for 45 s while both servers are online, the panel switches it by itself to the next transport — KCP → TCP Mux → QUIC → WS → WSS → TCP — with the balanced profile and reverse mode, and keeps trying until one connects. The card shows the last switch. With several Iran servers, a server that is off is left alone and the other tunnels keep carrying users.
- Fixed: QUIC and KCP tunnels now open their port as **UDP** in ufw (it was opened as TCP).

## Security center
- Simplified: change login, two-step login, sessions, IP restriction (folded) and recent logins. API tokens, the legacy API key and the audit list were removed from the page.

## Look
- The panel and the subscription page now use the **Vazirmatn** font for Persian (served by the panel itself at `/assets/vazirmatn.woff`, so it works without internet access to Google Fonts). English text is a little bolder with slightly wider spacing for easier reading. Font license: SIL Open Font License (`assets/web/Vazirmatn-OFL.txt`).

## Dashboard
- The network speed and connections charts are smaller again.

# v2.4.1
- **Dashboard is more compact**: smaller CPU / RAM / Storage / Swap gauges and a shorter network-speed and connections chart.
- **Dropdown menus follow the theme**: the open list of every select (filters, sort, page size, refresh…) is dark in the dark theme instead of white; no white edges when scrolling past the page.
- **Config download buttons in the user sheet** use the protocol colours (WireGuard green, AmneziaWG violet, Hysteria2 pink), same as the protocol tags.
- **Subscription page is smaller and tidier**: compact header, smaller rings and tiles, and each protocol's buttons in its own colour.

# v2.4.0

## New — Kanki Tunnel
- **Tunnels page** in the panel (menu: تانل‌ها / Tunnels). Encrypted tunnels between two of your servers: users connect to the **entry** server (for example in Iran) and traffic leaves from the **exit** server (your VPN server abroad). The entry server runs only a small **tunnel agent** — no VPN and no web panel are installed on it.
- **Animated map** on the page and a card on the dashboard: entry servers on one side, exits on the other, a flowing line per tunnel coloured by state (connected / connecting / down), with the transport and live ping on it. Updates every few seconds with no action from you.
- **Six transports**, chosen per tunnel: `tcp`, `tcpmux` (several links at once, recommended), `ws` (looks like a WebSocket, works behind a CDN), `wss` (looks like an HTTPS site), `quic` (over QUIC/UDP), `kcp` (over KCP/UDP, good on weak or lossy links). Both TCP and UDP from the user are carried, so WireGuard, AmneziaWG and Hysteria2 all pass through the tunnel.
- **Reverse or direct**: in reverse mode the exit dials the entry (recommended — the entry needs no open inbound port to the exit); in direct mode the entry dials the exit.
- **Encryption and authentication**: every link does an X25519 key exchange keyed by the tunnel token, then ChaCha20-Poly1305 on every record. A side without the right token cannot read or write a single byte. Links reconnect by themselves and a stalled link is dropped after 30 s.
- **Add a tunnel server with one command** (Tunnels > + Server): run it as root on the server; it installs the agent, turns on BBR, and the server shows up here as Connected within a few seconds. The agent keeps the last tunnel list on disk, so tunnels keep running after a reboot even if the panel is briefly unreachable.
- The panel server itself is a tunnel endpoint too (shown as the local server), running the engine in-process — no extra install.

## Fixed
- `kanki` > Update no longer prints `syntax error near unexpected token ')'` at the end: the menu script now replaces itself with an atomic rename instead of writing over the running file.

## Not yet (planned)
- Private network between servers (each server gets an internal address) and GRE links.
- Built-in speed test and automatic transport selection.

# v2.3.1

## Changed
- Installer: the default panel HTTPS port is now **2053** (was 443). On servers where another panel or website already uses 443, Caddy no longer fails with "address already in use" when you just press Enter.

# v2.3.0

## New
- **Kanki Panel** name and a built-in logo (K with two node links). Existing panels named "KANKI VPN" are renamed on start; an uploaded logo still wins.
- **Live log on the dashboard** (`GET /api/logs`): source picker (all, panel, WireGuard, AmneziaWG, Hysteria2, Caddy), **All / Errors / Debug** tabs with counts, pause, copy, auto refresh every 5 s.
- Dashboard nodes card says **Connected / Disconnected** for every server, with an "all servers connected" summary.
- **Traffic & stats** page: total recorded usage, quota of limited users and percent used, live network chart, by protocol, by node, per-user usage list (tap opens the user).
- **Port management** page: per server (main + nodes) WireGuard / AmneziaWG / Hysteria2 / panel / node API ports with service state, public address, conflict warning, check now, copyable `ufw` command and an all-servers table.
- **Sales bot** page in the menu: create, test connection, pause / resume, edit, delete; sales settings (sales on, warnings, support, app link, required channel, welcome text, free trial, referral reward, card to card, NOWPayments, ZarinPal, wallet) and plans.
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
