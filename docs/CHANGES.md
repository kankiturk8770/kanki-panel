# v2.8.1 — Tunnel servers menu, new tunnel animation, plan categories
- **Bot:** plan menus no longer repeat the plan list in the text (only the category name and one short line above the buttons); the "my services" menu text is shorter. New admin button **📌 Pin for everyone**: pin a message in your chat with the bot, tap the button, and it is copied and pinned in every user chat.
- **Smart channel:** six new post types (Story, A day with us, Question for the audience, Q&A, Short punch, Before and after), ~100 new lines, and posts that mix scene + bridge + benefit + punchline + CTA at random, adapting to the time of day and weekends. Existing channels get the new types enabled automatically once.
- **Bot:** when plans have categories, the bot first shows the categories as buttons; tapping one shows only that category's plans (with a back button to the categories). Works for new purchases and renewals.
- **Plan categories:** plans can be put in named categories (Bot and sales > Plans). Add a category when creating a plan or in the smart builder, move a plan with the folder button, rename a category from its header. The Telegram bot lists plans grouped by category.

- New side-menu page **Tunnel servers**: add/edit/delete tunnel servers there; the Tunnels page now only has tunnels.
- New tunnel map animation: glowing tubes, comet packets, return pulses, arrival ripples, orbiting node rings, dotted background; the map no longer restarts every refresh.

# v2.8.0 — AmneziaWG tunnel between servers
- **New tunnel type “AmneziaWG”** (Tunnels > + Tunnel > Tunnel type). A layer-3 link between two servers, like WireGuard, with the AmneziaWG obfuscation. It does not need the Amnezia app. The panel makes the keys and the obfuscation numbers (Jc, Jmin, Jmax, S1, S2, H1-H4, optional I1) **once and gives both ends exactly the same values**, so the “numbers differ” failure cannot happen. The agent writes `/etc/amnezia/amneziawg/kawg<id>.conf` and runs `awg-quick up`; if AmneziaWG is missing on a Debian / Ubuntu server it installs it itself (Amnezia PPA). Inside the link: entry `10.88.N.1`, exit `10.88.N.2`.
- **AmneziaWG inside any transport (the “hide” switch).** The AmneziaWG UDP can travel through WebSocket, WSS (with SNI spoof), CDN (whitelist mode, both directions), TCP Mux, QUIC or KCP. The interface then only talks to `127.0.0.1`, the engine carries the packets, and the AmneziaWG port is closed to everyone else (iptables, “no active probing”). The network only sees the chosen transport.
- **Routing through the link.** Exit NAT (masquerade); destination networks sent through the link; all traffic from chosen source networks (for example the VPN users of the entry) leaves from the exit (policy routing, the entry's own SSH is never touched); public ports of the entry sent into the link (DNAT) to the exit or to any address behind it. Networks wider than /8 are refused.
- **Obfuscation profiles:** classic, heavy (more junk packets, bigger padding), mimic QUIC (adds an I1 decoy packet, needs AmneziaWG tools 1.5+). “New obfuscation numbers” and “New keys” are applied to both ends at once. MTU and keepalive are editable.
- **Config viewer** for each side (for a server that does not run the agent) and live status: handshake, traffic and the delay through the link are shown on the tunnel card.
- Engine: the forwarded ports of an entry can listen on one address only (used to keep the wrapper on 127.0.0.1).
- **Update every agent first** (Update all): an older agent does not know AmneziaWG tunnels, and the panel refuses to save one until the agents are v2.8.0.

# v2.7.12 — tunnel form and port fixes
- **GRE link to a tunnel server:** when only GRE passes between the panel and a server, tick “Only GRE passes to this server” in + Server or Edit server and type the server's public IP. The panel builds its side by itself (interface `kgreN`, 10.77.N.1/30, rebuilt after a reboot) and the command it gives builds the other side on the server (a systemd service) and points the panel domain at the link, so the agent reaches the panel through GRE. Needs root and the `ip` tool on both servers; GRE (protocol 47) must be allowed in the cloud firewall.
- **Smart tunnel:** help text now lists what the test does, and the “nothing passed” message points to the GRE option.
- **Subscription page:** the status (Active / Expired…) is now also written into the HTML (`data-status` and the pill text). The Android app reads the page without running JavaScript, so it never saw the status and showed a red dash instead of green “Active”.
- **Tunnel port could not be edited:** the form refilled the box with a free port the moment it was cleared, so a new number could never be typed. The port now fills itself only until you type one; a cleared box stays empty.
- **Ports of the chosen server fill themselves:** pick the exit server and its VPN ports (WireGuard, AmneziaWG, Hysteria2, OpenVPN from the Nodes page) are written into the TCP / UDP boxes. The button “Ports of the exit server” does it again by hand, for any server (it was only the panel server before).
- **Same entry, several tunnels:** if the entry already uses a port (another tunnel, or its own VPN) the port is moved to a free one on the entry, written as `51821:51820`, and the form says which ones moved.
- **Free tunnel port** is now picked per protocol (UDP for QUIC / KCP) and a warning shows when the port is already used.
- **Port check on save** rewritten: tunnel port and forwarded ports are compared per server and per protocol (TCP / UDP), in both directions, and only between enabled tunnels. No more false “already used” on a different server.
- Transports: only tcpmux, tcp, ws, wss and cdn pass through networks that block UDP; WireGuard / Hysteria2 UDP travels inside them. QUIC and KCP are UDP themselves.

# v2.7.11 — build fix
- Fixed the compile error `no field 0 on type Arc<App>` in Update all (`app.0.clone()` -> `app.clone()`). It stopped the whole build, so no release was published.

# v2.7.10 — Update all fix
- **Update all** (button on the Nodes and the Tunnels page; it already existed) wrongly treated every tunnel-only server below v2.7.10 as “update by hand”, so it never updated them. The limit is now v2.7.0, the first version whose agent can update itself from the panel. One click now updates every node and every tunnel server, a machine that is both is updated once, and the panel itself last.

# v2.7.10 — Update all
- **Update all** button (Nodes and Tunnels pages): one click updates every node (they download the release themselves), asks every tunnel-only server to update from the panel (the agent downloads the panel's own binary, verifies its sha256, swaps it and restarts; no GitHub access needed on that server), and then updates the panel. A machine that is both a node and a tunnel server is recognised (same host name or same IP) and updated once, through its node; the node update now also restarts that machine's tunnel agent.
- Tunnel agents older than 2.7.10 cannot update remotely: the result lists them, run `kanki` > 3 (Update) on them once.

# v2.7.9 — change VPN ports from the panel
- **Edit node > “VPN ports (UDP)”:** change the WireGuard, AmneziaWG and Hysteria2 ports of any node (or of the panel server) from the panel. The panel sends the order to the node agent (`POST /agent/ports`); the node checks the port is free, edits its configs, applies them (WireGuard/AmneziaWG live, so connected users stay), restarts Hysteria2, opens ufw and restarts its agent. The node must run v2.7.9 (Update agent first).

# v2.7.8 — tunnel map and compact cards
- **Tunnel map:** a server that is in no tunnel (like a node that is not used yet) now sits in its own dashed row at the bottom (“Not in a tunnel”) instead of floating in the middle over the link labels. Links got four glowing particles with fading tails, and nodes get two staggered ripples.
- **Tunnel cards** are smaller: three info cells, traffic moved to the small line below, one row of three buttons, less padding.
- **Node cards** are smaller: less padding, smaller buttons and cells.

# v2.7.7 — bot plans menu, channel post bank
- **Bot plans list** is ordered by duration, then number of users, then price. The message groups the plans under “1 ماهه / 2 ماهه…”, and every button has the same short shape (duration · users · volume · price), so one-month single-user and one-month two-user plans no longer mix.
- **Channel posts:** the word bank grew a lot (about 60 tips and FAQs, 8 step-by-step guides, more hooks, benefits and calls to action), so the auto posts repeat much less.

# v2.7.6 — node as tunnel server
- **Edit node > “Also use this node as a tunnel server”:** creates the tunnel server entry for that node and shows the one-line command that installs only the tunnel agent on it (no second VPN, no web panel). Then pick the node as entry or exit when you make a tunnel.

# v2.7.5 — change service ports
- **`kanki` menu, option 8:** change the WireGuard, AmneziaWG and Hysteria2 UDP ports of a panel or node after installation (edits the configs, the env file, restarts the services, opens the firewall). The port is refused if something already listens on it. The panel reads the new ports from the node by itself.

# v2.7.4 — offline alerts
- **Telegram alert** to the bot admins when a node, tunnel server or tunnel stays down for about 90 seconds, and another one when it is back. Checked every 30 s, silent for 2 minutes after a panel restart. Switch: Settings > “Telegram alert when a node or tunnel goes offline” (on by default; needs the Telegram bot).
- Keeping the Main server free of users was already possible: edit the node and untick “Sync users without a specific node to this node”.

# v2.7.3 — CDN in both directions, simple form
- **CDN transport now works in reverse too.** If your domain is on a CDN that points to the Iran server (e.g. ArvanCloud), the foreign server connects in through the CDN; Iran only has to accept the CDN. The old direction (Iran dials a CDN in front of the exit) still works. The mode buttons are relabelled in plain words when CDN is chosen.
- **Simple CDN form:** domain + tunnel port are enough. Edge IPs, SNI names (domain fronting) and the split hello moved under “Extra disguise (optional)”. The panel states exactly what to set on the CDN for the chosen direction. A domain is required.
- “Test CDN” falls back to the domain when no edge IP is given.

# v2.7.2 — SNI spoof / CDN guide, CDN test, edge scanner
- **Guide** (small, collapsible) in the tunnel form, under Advanced and inside the CDN block: what to do when the Iran server shows offline (white IP, reverse mode, CDN mode), what SNI spoofing really is (a disguise on WSS/QUIC/CDN, not a separate tunnel; useless if the IP itself is blocked), that it carries WireGuard / AmneziaWG / Hysteria2 like any other tunnel, and what CDN fronting was (SNI = allowed name, Host = your domain). Persian and English.
- **Test CDN** button: `POST /api/tunnels/cdntest` tries every edge address x SNI name from the panel server (TLS hello with that SNI, WebSocket request with your Host) and shows OK / error and time. It proves the CDN + exit setup; the network of the entry is proven by its own tunnel.
- **Scan script** button: generates `scan.sh` filled with your Host / SNI / path / edges. Run it on the Iran (entry) server to find which IPs of a /24 range pass the WebSocket (`OK-WS`) or only reach the CDN (`REACH`).

# v2.7.1 — installer fixes
- **Installer:** the GitHub repo is built in (`kankiturk8770/kanki-panel`) and is no longer asked. A wrong value such as `kanki` (404 "Download failed") is ignored. The download URL is printed.
- **Installer:** firewall step no longer treats an inactive ufw as active, and a ufw error no longer aborts the install.
- **Release workflow:** tunnel tests no longer block publishing the release if a test is flaky on the CI runner.

# v2.7.0 — whitelist mode (CDN)
- **New transport `cdn`** for networks that only let traffic to whitelisted (domestic) addresses through. The entry (inside) never connects to the exit directly: it connects to a CDN edge that stays reachable (for example ArvanCloud) over TLS + WebSocket, and the CDN forwards the WebSocket to the exit (your origin). The exit listens on plain WebSocket on the tunnel port. It is always `direct` mode and is never part of the automatic rotation.
- **Separate SNI and Host.** The TLS handshake can say one name (`SNI`, a list is allowed, one is tried after another) while the WebSocket request says your CDN domain (`Host`).
- **Several edge addresses.** `Address to dial` can list several CDN edge IPs; every link starts on a different one and a link that fails moves to the next. A link that worked keeps its address.
- **TLS hello in tiny pieces.** The first bytes of the connection (the ClientHello with the SNI) leave in 2–7 byte segments, which defeats SNI filters that do not reassemble packets. On by default in the form; turn it off if the CDN refuses.
- Tunnel form: choose “Whitelist mode”, fill the CDN block. Guide in `docs/WHITELIST.md` (Persian). **Update the exit server's agent too** (an old agent does not know `cdn`).
- Fixed the smart-tunnel test of QUIC (the shared speed service of the exit lived on the runtime of the first test; now each test stream gets its own).

# v2.6.0 — stronger tunnel camouflage
- **KCP is now fully hidden.** KCP used to send its 24-byte header in the clear, so deep packet inspection could tell "this is KCP". Now every UDP datagram is wrapped — an 8-byte random nonce, random padding and ChaCha20 over the whole thing, keyed by the tunnel token — so from outside it is just short, random-looking UDP of changing length, with no KCP signature. The two ends unwrap it; anyone else (and any wrong token) sees noise.
- **QUIC looks like HTTP/3.** QUIC now advertises the `h3` protocol (ALPN) and uses a believable SNI (default `www.cloudflare.com`, or the SNI you set), so it blends in with normal HTTP/3 web traffic instead of announcing a custom protocol. This also fixes QUIC tunnels that would not connect in 2.5.
- **SNI spoof for WSS.** In the tunnel form (Advanced) you can set the SNI / Host; with WSS the TLS handshake then looks like an HTTPS connection to that domain (e.g. `www.google.com`). Quick-pick buttons for common domains were added. The exit accepts any SNI, so it just works.
- The default self-signed certificate for WSS now uses a believable name (`www.bing.com`) instead of an obviously custom one.

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
