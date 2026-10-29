# v3.20.1 — backup without nodepins, Iran relays without VPN, faster first load, DNS button
- **Backup** (`backup.rs` `make_archive_with`): `nodepins` goes into the archive only when it holds a pin; a panel without a self-signed node had no such folder and `tar` failed, so neither the nightly Telegram backup nor «Download backup» nor a move worked. A failed scheduled backup now also sends a Telegram message to the backup chat. Test: `a_panel_without_nodepins_still_backs_up`.
- **Iran servers** (`servers.rs` `new_server()`, `agent_only()`): a new server in Iran gets no `KANKI_JOIN`, no `KANKI_PORTS` and no held VPN ports unless «Serve VPN users» is ticked; its command installs only the server agent. «Show the command again» keeps it that way. «Install VPN» (`complete()`) still installs the VPN part by hand. Existing servers are not touched. Test: `an_iran_relay_gets_only_the_tunnel_agent`.
- **First load** (`api.rs` `maybe_gzip()`): `/admin` and `/assets/kanki-panel.js` are sent gzipped when the browser takes it (HTML 138 → 28 KB, JS 712 → 218 KB, compressed once per start, `flate2`). The script (`?v=<version>`) is cached for a year (`immutable`); the page stays `no-store`. `index.html` shows a small spinner in `#app` (in the saved theme) until the panel draws, instead of an empty black page.
- **Phone bar** (`panel.js`): Kanki DNS is its own section (`dnssec` in `SECS`, out of the Cores tabs), so its button lights up instead of «Cores». The bar no longer snaps (`scroll-snap` removed from `.k38bar`); `navMark` scrolls it only when the open button is out of sight and not while a finger is on the bar, and never moves the page. Checked with Playwright at 390 px, Persian and English: only the tapped button is `on`, the bar does not move after 500 ms, the button is fully in sight.

# v3.20.0 — tunnel domain per core
- Each core's page (WireGuard, AmneziaWG, Hysteria2, microtun, Xray) has «Second config through the tunnel» per server: one tap on an Iran server (chips of every Iran server's domain, the ones whose tunnel ends at this server first with ✓) sends only that core's second config through it. Empty = the server's own tunnel domain (Servers page). KANKI MIX keeps its own Iran address, now with the same chips; the Servers page tunnel box lists every Iran server too.
- `twin.rs`: `Opt.cores` (core -> Iran address, kept when the server's tunnel is saved), `save_core()`, `of_node_core()`, `name_of_node()`; `of_server()` is Xray's. `PUT /api/servers/<key>` takes `{ "tunnel_core": { "core": "wg|awg|hy2|mtun|xray", "host": "" } }`. `info()` gives each port its `core` and `host`, and `cores`.
- `tunnel/panel.rs` `port_entry_at()`: when Iran-1 and Iran-2 both carry a port to the server, the port of the chosen Iran server is used.
- The subscription's tunnel entry, `/sub/.../raw`, `/v2` and the config downloads take each protocol's own address; a core with its own address gets its second config even when the server's tunnel is off.

# v3.19.2 — API tokens on the Security page
- `tokNew()` / `tokDel()` in `panel.js`: the Security page lists the scoped API tokens (`/api/security` already returned them) and makes (`POST /api/security/tokens`, the token shown once) or deletes them. «Servers and tunnels» (`nodes`) is ticked by default.

# v3.19.1 — tunnel guide
- `tunGuide()` / `TGUIDE` in `panel.js`: a «? Tunnel guide» button on the Tunnels page opens a table of which tunnel suits which protocol (WireGuard · AmneziaWG: AmneziaWG link; microtun · KANKI MIX: Game; Hysteria2: Hysteria2 link; Xray and Kanki DNS: TCP Mux; with the alternatives, what to use when UDP is blocked and what to avoid). Each best tunnel opens the tunnel form with it picked (`tunEdit(null, {kind}|{transport})`).

# v3.19.0 — MIX+ removed, core buttons in the tunnel forms, microtun 2.1
- **MIX+ removed:** `src/vpn/kcores.rs`, `src/tunnel/kcore/`, the `kcore/` crate and its CI job, the `/api/kc/*` routes, the `kgame` user protocol, its port range (4100-4199), `kc_*` server info, `"kcore"` links (the subscription keeps an empty `"kcore": []` for apps that read it), `mux.rs` `Shared::public_only` (only MIX+ set it). On start the database drops `kgame` / `khq` / `kftcp` from users and default protocols and deletes `kgame_cfg`, `khq_cfg`, `kftcp_cfg`, `kc_door`, `kc_secret`. The sync request still sends `"kcore": {}` so an agent older than 3.19 stops MIX+ and closes its firewall rule; a 3.19 agent closes the old `kcore` firewall rule once.
- **Tunnel forms:** `coreChips()` / `tunCoreGroups()` / `tunSvcGroups()` in `panel.js`: one button per core of the exit server over the port boxes of the Kanki tunnel form, the AmneziaWG form (forward fields) and the multi-location form. `tunNodePorts` and the route form's port fill include microtun (`mt_port`).
- **microtun 2.1** (`src/vpn/mtun.rs`), in the random padding of the handshake so 2.0 peers ignore it: `mtD1` + device id in the init; `mtA1` + IPv4 + flags + IPv6 in the response when the init has room. Devices per user (`MtUser.max` = connection limit, 8 at most), addresses for further devices from `MtCfg.devices` (10.80.0.1/16), IPv6 from `MtCfg.address6` (fd79:4d54::1/64) when the server has a default IPv6 route (`mt_v6` in the server info), an older init timestamp taken within 120 s of the server's clock when its ephemeral key is new. User addresses moved to 10.79.0.0/16.
- Tested: unit tests (device id, addresses, clock, subnets, the database cleanup); the Rust server with three Go 2.1 clients of one user (limit 2) in network namespaces: two devices at once with 0 % loss, the third waits and gets in 20 s after one stops, a restarted client is the same device with the same address. IPv6 was not testable in the test box (its kernel has no IPv6).

# v3.18.0 — microtun
- New user protocol `mtun` with its own page (`/api/mt`, `/api/mt/users`, `/api/mt/links/<user id>`): on/off, default port 4200, per-server port/address/switch, copies of small packets (`burst_max`, `burst_delay_ms`), MTU.
- `src/vpn/mtun.rs`: the server, on plain threads, wire-compatible with the Go microtun v2 (Labo repository): AES-256-GCM, header masked with AES of the ciphertext sample, X25519 + per-user key handshake, 1024-packet replay window, a new session only after its first data packet, source-address check per user, TUN `mtun0`, forwarding and NAT rules removed again when it stops. Users and copy settings change live; port, key, address and MTU restart it.
- `src/vpn/microtun.rs`: settings, keys (`mt_obfs`, `mt_secret`, user key = HMAC of id and subscription code), user address 10.77.0.0/16 by id, `mtun` in the sync request/answer (older agents ignore it), `mt_port` / `mt_error` in the server info, `"mtun"` link in the subscription data, ports in port management (4200-4299, 42000-42999).
- Tested: the Rust server with the Go client (handshake, NAT, 20 %-loss run, traffic), and the whole panel in a test box: user created, link from the page, client connected, traffic and online counted, user removed and added back.

# v3.14.0 — Game-FEC, HQ-QUIC and FakeTCP as VPN protocols
- Three separate user protocols `kgame`, `khq`, `kftcp`, each with its own page (`/api/kc/<proto>`), settings, per-server port/address/switch and «enable for all users»; the server refuses a user on a protocol they do not have.
- New `src/tunnel/kcore/`: Game-FEC, HQ-QUIC and FakeTCP served to users as VPN cores (per-user HMAC auth after the link handshake, full proxy to public addresses only, a datagram fast path for game UDP with 1-3 copies of small packets, a replay window that drops the copies, big bodies cut into pieces). The transports are reused as they are.
- `mux.rs`: `Shared::public_only` (off by default; the tunnels leave it off). `faketcp.rs`: `socklen_t` instead of `u32` so it builds for 32-bit Android (the same type on the servers).
- Panel: Services › Kanki Cores (`/api/kcore`), `kcore` in the sync request/answer (older agents ignore it), `kc_ports` / `kc_fec` / `kc_error` in the server info, `"kcore"` links in the subscription data, `kcore` as a user protocol.
- `kcore/`: the `kanki-core` binary (server, client, ping, url), compiled from the panel's own tunnel files; CI builds it for Linux and Android and publishes it under the tag `kanki-core`.
- Tests: end to end for Game-FEC and HQ-QUIC (TCP, UDP through SOCKS5, wrong key, removed user, ping, traffic), a 15 %-loss run for the game copies, the datagram codec and the FEC relay.

# v3.9.11 — tidier tunnels, compact VPN page, one V2Ray block on the subscription page
- **Tunnel form:** only what is needed to run a tunnel shows (route, type, transport, ports; the CDN domain when CDN is picked). Disguise, profile and «More» are folded under **Advanced settings**, which opens and closes smoothly (open by itself when an edited tunnel already uses them).
- **Ports of the exit server** also fills in the exit's **Xray inbound** ports (KCP on UDP, Shadowsocks on both, the rest on TCP) and **Kanki DNS** (53 UDP/TCP, 853, 443), in the tunnel form and the multi-location route form.
- **Tunnel map, atom style:** the entry server (the one with the most tunnels, an Iran one first) is in the middle; every other server sits on one orbit around it at equal angles, joined or not. Connected tunnels are animated lines; labels are short and on the middle of the line (`HQ-QUIC • 82ms`, `KCP • 89ms`); tunnels between the same two servers share one stacked label; server names sit on the outer side.
- **VPN services page:** smaller cards, tiles and rows.
- **Subscription page:** Hysteria2 and Xray are one card: the countries, «Copy all configs» (every Hysteria2 and Xray link, one per line) and a yellow «Copy sub link» for the new combined `/sub/<code>/v2` (one Hysteria2 per server, through its tunnel when it has one, plus every Xray link).

# v3.9.10 — a shorter subscription page
- **Hysteria2:** one card with the countries as flags and one «Copy all» button: one config per country, the one through the tunnel (a server without a tunnel gives its own), one per line so v2rayNG imports them at once. No tunnel / direct columns, no per-config copy / QR.
- **Xray:** next to Hysteria2, the number of configs, «Copy sub link» (the new `/sub/<code>/xray`, only the Xray links, for v2rayNG / V2Box) and «Copy all» (one per line), instead of a row per link.
- The server sections the Kanki app reads are unchanged.

# v3.9.9 — giveaway prizes from the channel bot
- **Sales bot: giveaway prizes.** A winner of a channel giveaway opens the bot with a personal link (`/start c_…`) and gets a prize account (e.g. `ElClasicoW1`, 5 GB / 30 days) at once. The link is signed (HMAC-SHA256) with a secret shared with the channel bot, works only for the Telegram account it was made for, and only once; GB and days are inside the signature, so they can't be changed. Admins are told about every prize given.
- Set the secret once: an admin sends `/claimkey <secret>` to the bot (the message is deleted). `GIVEAWAY_SECRET` in kanki.env works too.

# v3.9.5 — the right agent versions, tunnel badges, tidier rows on phones
- **Fix: up-to-date servers showed yellow, «Agent is on an older version (v3.9.4)».** Each agent was compared with the panel server's own saved info, which was refreshed only while the panel server's VPN served users; with it off the saved version stayed old, so every updated agent looked old. Agents are now compared with the version the panel really runs, only an agent that is really older is flagged, and the panel server's own info stays fresh with its VPN off too.
- **Update all** also updates relay servers (VPN off), and right after an update (all, or one server's «Update agent») each server is read again every few seconds until it reports the new version, instead of waiting for the next sync round.
- **Tunnel badges:** a server whose configs point at an Iran entry shows «tunnel» on Servers and in the WireGuard / AmneziaWG / Hysteria2 tabs; one with a tunnel domain shows «+ tunnel».
- **Subscription: `via_proto`** on every server entry, `{ "wireguard": "tunnel", "hysteria2": "tunnel", "kankimix": "direct", … }`: where each protocol's config really points. Kanki app 1.18.3 labels Hysteria2 and WireGuard «tunnel» by it when the main configs go through Iran (before only AmneziaWG was labeled).
- **Phones:** a row's name is never cut any more (KANKI MIX rows showed «…el», «…many»); its badges go to a second line. The tunnel box lists each protocol on one line, `Iran:port → UDP port`.
- KANKI MIX's «not running» is explained in Persian.

# v3.9.4 — a tunnel copy of every config
- **Tunnel domain on Servers:** one field in a server's settings, and in «Add server»: «If this server has a tunnel, or will have one, write your Iran server's domain here». That is all: users then get, next to the direct configs (the server's own address), a second config of every protocol through that domain, made by the panel: WireGuard, AmneziaWG, Hysteria2, KANKI MIX and every Xray link of the server. Nothing is set per protocol any more. Each copy uses the port the Iran address really carries to this server (a hop that moved it, 4002 → 4001, is followed; with no Kanki tunnel in the panel for it the port stays the server's own); the box lists every port with the address and port it gets. One tap picks the first server of each tunnel that ends there. The name of these configs in the app is optional («Germany (تانل)»). AmneziaWG of the direct entry is called «direct», the copy «tunnel». KANKI MIX's own second-config fields stay, folded, to change it for KANKI MIX only.
- **WireGuard only through the tunnel:** a server with a tunnel domain gives WireGuard only as the tunnel copy (straight to a server abroad it does not pass in Iran). The WireGuard tab shows each server's tunnel address, or a hint to write the tunnel domain.
- **Every app gets them:** the copies are the server's second entry in the subscription (`<id>@tunnel`, with `via: tunnel` and `parent`), on the subscription page under their own heading, in the v2rayNG / Hiddify link (Hysteria2, WireGuard, Xray) and in the sales bot's config buttons. An app that knows only the server list shows them as a server of their own; Kanki app 1.18.2 writes «tunnel» / «direct» next to every protocol. WireGuard / AmneziaWG files of the copy end in «t» (`mahtab87-ger-at.conf`). Hysteria2 and TLS Xray links keep the server's own name as SNI; links that already go through a CDN or a typed address get no copy.

# v3.9.3 — tidy Servers, VPN services in tabs, multi-location tunnels
- **Servers page:** two boxes, servers abroad and servers in Iran. Each server is one compact row (flag, name, state, address) with an arrow. The arrow opens that server and closes the one open before; leaving the page, pressing Esc or saving closes it again. Inside are all of the server's own settings: name, location, the address other servers use, note, VPN for users, whether users without their own server list get it, the address users connect to (with one-tap choices: through each tunnel entry that carries its ports, or its own address), API address, token and certificate, health, sync, restart, update, add or remove for all users, the command again, delete. Ports and protocols are no longer on this page.
- **VPN services in tabs:** Overview · KANKI MIX · Xray · WireGuard · AmneziaWG · Hysteria2 · Anti-DPI. Each tab lists the servers that run it, abroad and Iran apart, one row per server; the arrow opens that service's settings on that server. WireGuard, AmneziaWG and Hysteria2: state, port (a port another server uses is refused), the route that brings the port (Iran → Turkey → here) or direct, obfuscation (AmneziaWG numbers, Hysteria2 password and certificate), AmneziaWG's direct name, restart, sync, health. KANKI MIX: on/off for that server, its port, route, address, the second config through the tunnel (Iran address, port, name in the app) with the route that really carries it, or a warning when no tunnel does. Xray: the server's state, certificate and errors, its inbounds (tap to edit), new inbound, edit, config, repair, health, remove. Every tab has «on / off for all users» (WireGuard, AmneziaWG, Hysteria2 and KANKI MIX too).
- **Multi-location tunnels (⛓ on the Tunnels page):** a route of three or more servers, Iran → Turkey → Germany. Users connect to the first; the traffic passes each next server and leaves from the last. Every hop is a tunnel of its own with its own transport, direction, link port and profile (KCP from Iran to Turkey, WSS from Turkey to Germany…), and its own ⚡ test (or «Test every hop»): each hop is measured like the smart tunnel and its best transport applied. The ports carried are the same on every hop and fill in from the last server (WireGuard, AmneziaWG, Hysteria2, KANKI MIX and its Xray inbounds). One option makes the last server's WireGuard, AmneziaWG and Hysteria2 configs use the first server's address; KANKI MIX's second config follows the route by itself. The route is one card on the Tunnels page (the path with each hop's transport and ping, total ping) and on the map; edit, reconnect, pause and delete work on the whole route, each hop can also be opened in the full tunnel editor. A hop that cannot be made takes the hops made before it back.
- **KANKI MIX's second config through a route** points at the first entry (Iran), not the server in the middle; when the Iran address is typed by hand, the port is the one the route really carries (a hop that moved it, 4002:4001).
- **WireGuard only through a tunnel:** plain WireGuard straight to a server abroad does not pass in Iran, so a server's WireGuard is given (app, subscription link, v2rayNG / Hiddify link, sales bot) only when its users connect through a tunnel (its address in the configs is the Iran entry, not the server itself). AmneziaWG, Hysteria2, KANKI MIX and Xray are not touched.
- **Top bar: one night / day button** instead of the four color dots; the panel's colors are chosen in Settings › Look.
- **Fix: KANKI MIX got the same port on several servers.** A server added after another one joined (before KANKI MIX was installed there) got the same KANKI MIX port; one Iran entry then could not carry both. A server now holds the port it was given from the moment it joins. Existing clashes show on Servers with «Fix ports».
- **Fix: «Ports of the exit server» in the tunnel form left out KANKI MIX.** It fills in the KANKI MIX port now (also in multi-location routes).
- **Fix:** changing a tunnel between two UDP transports on the same port (KCP → Game) was refused when the agent runs without systemd (a container, started by hand): its own port was taken for another program's.

# v3.9.2 — Servers in one column, each server's services in one place; a deleted server leaves nothing
- **Servers page:** one column of compact rows: the panel server first, then the servers abroad, the Iran servers last. A row opens with its arrow and shows everything of that server: VPN for users on/off, WireGuard, AmneziaWG, Hysteria2, KANKI MIX, Xray, Kanki DNS and its tunnels, each with its state. The scattered «+ Add Xray / + Add DNS» buttons are gone.
- **Each service of a server opens its own window:** change the port (refused when another server, or another protocol here, uses it; the service restarts on the new port), KANKI MIX on/off for that server, restart, health, install Xray or Kanki DNS on it, remove it from the server, «for all users» on or off, and the server's tunnels.
- **Deleting a server removes everything:** from the panel (the server, its users' server lists, its KANKI MIX settings, its direct name, its location) and from the server itself (VPN services and their configs, KANKI MIX, tunnels, Xray, DNS, the agents, /etc/kanki, /var/lib/kanki, the program). When tunnels use it, the panel names them and asks; confirmed, they are deleted too and the server at the other end (the Iran entry) stops them and closes their ports.
- **Sales bot shown offline while it worked:** the status came only from the long poll, which a network on the way can cut while nobody writes. Telegram is now asked every minute whether the token works; when Telegram refuses the bot (wrong token, another program using it, a webhook left on the token) the reason is shown on the bot page, and a leftover webhook is removed by itself.

# v3.9.1 — the right direct address for every server
- **Direct domains** (Servers page): the app's «Amnezia Direct» config of a server behind the Iran tunnel goes straight to the server through its own name, `<country>.<your domain>` (like `fr.kankipro.cafe`; Germany keeps `g`; a second server in the same country gets `fr2`). The page lists each name, the IP to point it at and whether it already does. The panel resolves the names every 5 minutes and gives the app a name only when it really points at that server; until then the server's own address goes out, so a direct config never reaches the wrong server (before, the app guessed the name from the server's name: two servers in one country both went to the first one). The base domain can be changed on the same page.
- The subscription data says for each server whether its AmneziaWG goes through the tunnel or straight to the server (`awg_via`, `awg_direct`): a server without a tunnel no longer shows a second, identical «direct» config in the app (Kanki app 1.17).

# v3.9.0 — one kind of server, one command, unique ports, a backup that brings everything back
- **Servers is one list.** The panel runs on one server; every other server is a node. VPN nodes, tunnel servers, Xray servers and DNS servers are no longer separate lists: each server is one card with what it runs (VPN for users on/off and its ports, tunnels, Xray, Kanki DNS, emergency chat, subscription) and its health. The separate «Tunnel servers» page is gone (its settings, GRE and firewall, open from the server card).
- **Add server = one command that installs everything:** the server agent (tunnels, Xray, Kanki DNS) and the VPN part (WireGuard, AmneziaWG, Hysteria2, KANKI MIX). Nothing else is typed on the server: what it runs is switched on in the panel. A server inside Iran is installed the same way with «VPN for users» off (a relay); it can be switched on later. The command takes the installer and the program from the panel first (GitHub second), so it works where GitHub is filtered.
- **Servers made before 3.9** (only the VPN part, or only the agent) get the missing part with one button on their card: a VPN node starts the agent next to itself; an agent server installs the VPN part by itself and shows the progress. A node and an agent of the same machine are found and shown as one server.
- **VPN ports are unique across servers.** A new server gets WireGuard, AmneziaWG, Hysteria2 and KANKI MIX ports no other server uses, so one Iran entry can tunnel the ports of every server. Clashes of existing servers are shown on Servers with **Fix ports**: the later server moves to a free port and the tunnels that carry the old port follow (users' WireGuard / AmneziaWG files of that server must be downloaded again; subscription links and the app update by themselves).
- **VPN off really is off:** a server whose VPN is switched off gets an empty user list (before, its old peers kept working).
- **Fix: servers could not reach the panel when a separate subscription domain was set.** New servers were given the subscription domain as the panel's address, and that domain only serves the subscription pages. Servers now get the panel's own domain, and the subscription domain also passes the agent paths (checked by their tokens), so servers added that way connect again.
- **Backup:** also holds the uploaded app files (download and move; not the nightly Telegram one, a bot cannot send over 50 MB), the certificates of self-signed nodes as first seen, and the IP of the server it was made on. A restore (in the panel or with installer option 9) on another server replaces the old server's IP in the panel's own addresses (tunnel address, endpoint, KANKI MIX, Xray), writes the subscription domain's Caddy site again (it was lost after a restore: subscription links broke), and checks the database before it replaces the running one. **Backup › After restore** shows whether every server came back.
- **Smart channel: no more double posts.** A post made by hand (panel or bot) shortly before a posting time now counts for that time (before, 15:58 by hand and 16:00 by schedule = two posts). The bot's «Send to channel» takes the draft once (a second tap, or Telegram sending the tap again, posted it twice). The same text is never sent twice within 15 minutes, and one post goes out at a time.
- **Sales bot:** a button tapped twice no longer makes the bot send the same message twice; approve and reject tapped together decide once (before, a delivered order could be marked rejected and the buyer told it was not approved); the last use of a discount code is not spent twice. When another program uses the same bot (the panel on the old server still running after a move: both answer customers and both post), the admins are told in Telegram and Backup shows it.
- **Sales bot › 🎁 Gift of days and GB** (to make up for an outage, or a present): to everyone (accounts that are on, not expired and not a trial) or to one account (its page in the bot). The admin sends `days GB [reason]` (Persian digits work), sees how many accounts and people it reaches, and confirms once (a second tap gives nothing more). Unlimited time or volume stays unlimited; an account over its volume gets the GB on top of what it used. Each customer gets one friendly message with the gift, the reason and what is left on each account; its text is editable in Buttons & texts.
- **Updates:** when the program file was replaced while it ran (the VPN part and the agent of one server share it), an update wrote the new version to a stray file named `kanki-panel (deleted)` instead of the program, and the panel could not hand its program to agents until it restarted. The real file is used now, and two updates of one file at once never share a temporary file.
- **Installer:** on a minimal Debian / Ubuntu image without `ss` (iproute2) every port looked free; it is installed first now.
- **Code:** the Rust checker (Clippy) gives no warnings any more: about 80 style points cleaned up with no change in behaviour (all tests pass as before).
- **Phones:** pop-ups are drawn above the bottom tab bar (it covered their last buttons: Create command, Save…). **Computers:** a window narrower than 1100 px (a laptop with display scaling) no longer gets the phone layout; the side menu scrolls on short screens.

# v3.8.2 — a backup brings the panel back on a new server, with nothing left of the install made there
- **Installer › 9) Restore the panel from a backup file:** for when the old server is gone. Upload the `.kbk` (or `.tar.gz`) to `/root`, run the installer, pick 9, give the passphrase. Everything of a panel installed there before stops; the backup's settings, database, VPN keys and ports are put in place, the VPN configs get this server's network card, Hysteria2 runs only if it ran before, a new SSL certificate is taken (or the backed up one is used), Caddy is set to the backed up panel's own port, and the panel is checked before it says done.
- **Backup › Restore with the server files** (in the panel): Caddy is now sent to the restored panel's port (before, the panel page answered 502 after the restore, because Caddy still used the port of the install made there), the VPN configs get this server's network card, and WireGuard, AmneziaWG, Hysteria2 and Caddy are restarted with the restored files.

# v3.8.1 — the panel reads its settings even with one broken line
- A single line of `/etc/kanki/kanki.env` that is not valid UTF-8 (a server name typed in another encoding) made the whole file unreadable: the panel then started on the default port 8080 while Caddy sent requests to the configured one (502, the panel page did not open). Now only that character is replaced and every setting is read.

# v3.8.0 — the AMOLED look and a menu grouped by what belongs together
- **Four looks**, picked from the dots in the top bar: gold on pure black (night), gold on pure white (day), purple on black, purple on white. Cards are flat AMOLED surfaces with a thin edge.
- **Buttons:** 3D glass, with a soft shine that moves across the main buttons.
- **Menu in groups:** Home · Customers (users, sales bot, emergency chat) · Servers & network (servers, tunnels, ports) · Services (VPN services, Kanki DNS) · Reports · System. Servers and Tunnel servers are two tabs of one section. Nothing was removed.
- **Servers:** one card per server with what runs on it (VPN, Xray, DNS, tunnels), and filters: all, abroad, Iran, DNS.
- **Phones:** a tab bar at the bottom (home, users, servers, services, more); «more» opens a sheet with every section.
- **Dashboard:** a row of quick actions (new user, add server, sales bot, backup).
- Switching day/night no longer drops the glass look until the page is reloaded.

# v3.7.7 — KANKI MIX tunnel config only when a tunnel forwards it; chat messages never stored twice
- **KANKI MIX second config (through the Iran tunnel):** offered only when an enabled tunnel really forwards the server's KANKI MIX UDP port (its exit is that server, or its entry is the server's endpoint and listens on that port), with the tunnel's own Iran address and port. Before, every server behind an Iran endpoint got one even when nothing forwarded the port, so it pointed at a dead port. An address written by hand on the KANKI MIX page is still used as it is.
- **Emergency chat:** a customer message carries the app's own number (cid); when the app sends it again because the answer was lost, the server returns the stored one instead of saving it twice (text and pictures). Needs app 1.16.3.

# v3.7.6 — crypto payments in the bot; support button
- **Why the TON wallet did not show:** crypto was offered only for plans with a dollar price, and the plan builder and the plan list never set one; the wallet switch also sat folded away and stayed off.
- **Sales bot › Crypto payment (TON / USDT)**, its own box: TON wallet address, USDT (TRC20) address, **Toman per dollar** (plans without a dollar price get one from the toman price at this rate), an extra text. Typing an address switches «accept crypto» on; a written address with the switch off is warned about.
- The buyer sees the amount in dollars and in TON at today's price, the addresses to copy, a **Pay with Tonkeeper** button with the amount filled in, then sends the receipt or TXID for the admin to approve.
- Plan list: a **$** button sets a plan's dollar price. A plan with an empty price is no longer left out.
- A payment button pressed after its method was switched off is refused; stats show the crypto income in dollars.
- **Support** in the bot is a button that opens the support chat.

# v3.7.5 — a name for the second KANKI MIX config
- **KANKI MIX › each server › Second config through the tunnel › Name in the app:** the name the app shows for the config through the Iran tunnel (empty = "<server name> (تانل)"), so the two configs of a server are told apart. Today's app shows it already: the subscription page gives the second config its own (hidden) heading, and the subscription data its own name.

# v3.7.4 — Gemini (free) for the channel writer
- **Gemini from Google AI Studio** (aistudio.google.com/apikey, free tier): keys starting with `AQ.` or `AIza` are told apart by themselves, or Gemini is picked in the form. Google's own generateContent API with the `x-goog-api-key` header. Default model `gemini-flash-latest`, then Flash Lite and 2.5 Flash / Flash Lite, then the text models the key lists (Pro and 2.0 are skipped: no free quota). A model with no free quota moves on to the next one at once.
- The form names the AI service in use and its default model.

# v3.7.3 — Settings fixed on every screen; no red errors after leaving a page
- **Settings:** fields, texts and switches were cut off on the left (on phones and narrow windows the switches of "VPN and protocols" could not be seen or used). The server grid of 3.7.0 had reused a class name of the Settings form and forced it 860px wide in eight columns; the grid has its own names now (also for its service buttons, which had changed the node service rows).
- **"Cannot set properties of null":** a page whose data came back after the admin had already moved to another page (slow server, Iran) tried to draw into a page that was gone and showed a red error. Settings and Backup check first; any such late draw is now silent everywhere.
- Narrow phones: a server name with the "Main server" badge wraps instead of being cut.

# v3.7.2 — better Persian from the channel writer
- **Writing rules in Persian** for the AI: complete, short sentences; common words only; one tone per post; no word-by-word translation; correct half-spaces and Persian punctuation.
- **A second pass as a Persian editor:** each post is read once more by the same model, which fixes broken, meaningless or mixed-up sentences and spelling. The first text is kept when the editor drops a number or changes the length too much.
- The writer thinks a little longer (gpt-oss: medium) and is less random (temperature 0.7).
- A ready "about us and how to write" text: `docs/AI-BRIEF-FA.md`.

# v3.7.1 — Groq for the channel writer
- **The AI writer works with Groq** (groq.com, `https://api.groq.com/openai/v1`, keys `gsk_…`) as well as Grok (x.ai, keys `xai-…`): the service is told by the key, or picked in the form. Groq's default model is `openai/gpt-oss-120b` (then llama-3.3-70b-versatile, gpt-oss-20b, llama-3.1-8b-instant, and the models the account lists). Model names may have a slash.
- **Phones:** the Settings page was wider than the screen (its section bar stretched the page and pulled the hidden menu into view); no page can be wider than the screen any more, wide strips scroll inside themselves.
- The key box no longer lets the browser fill in (or offer to save) the panel password, and a panel password pasted by mistake is refused.

# v3.7.0 — new shell, Grok channel writer, second KANKI MIX config
- **Menu in sections:** Dashboard, Users, Servers, VPN services, Tunnels, Sales & support, Traffic, System. A section with several pages shows them as tabs at the top: VPN services (overview, KANKI MIX, Xray, Kanki DNS, Anti-DPI), Tunnels (tunnels, tunnel servers, ports), Sales & support (sales bot, emergency chat), System (settings, backup, security). The same on phones.
- **Glass look** in dark and light: frosted cards, menu, top bar and dialogs; gold glass buttons with a light sweep, frosted secondary buttons.
- **Servers:** a grid of every server and what runs on it (WireGuard, AmneziaWG, Hysteria2, KANKI MIX, Xray, DNS, tunnels), green when running and red when stopped; a press opens that service (or Repair, Health, Sync, Ports for a VPN server).
- **Flags:** every server shows the flag of its IP's country (looked up from the panel). A server whose location was only guessed is put with the Iran or abroad servers by its IP.
- **Tunnel form:** the transports in three columns: over UDP (fast, games), over TCP (steady), advanced (hardest to block).
- **Live port check:** before a tunnel, an Xray inbound, the emergency chat or the Iran subscription port is saved, the panel asks the server what really listens there (any program, also 127.0.0.1 only) and refuses a taken port, naming what holds it; the tunnel form shows it while the ports are typed. Agents report it from 3.7.0 on.
- **KANKI MIX second config:** every user also gets a config through the Iran tunnel for each server (the Iran address whose tunnel forwards the KANKI MIX UDP port; automatic from the server's endpoint, or set per server on the KANKI MIX page, or off). In the subscription data it is `kmix_tunnel` of the server and also its own entry ("<name> (تانل)", `via: "tunnel"`, `parent`), so today's app lists it as another server.
- **Smart channel › AI writer (Grok):** paste an x.ai API key and a short brief; posts are written by Grok from the real plans, prices, discount code, trial and bot name (it must not change them). Calls are retried (network, 429, 5xx), a refused model is replaced by one the account lists, Telegram-safe HTML only (a refused format is sent again as plain text), and the built-in writer posts when Grok gives nothing. **Posting times** (Iran time, like 10:00, 16:00, 21:30) for three posts a day. "Test the key" shows a sample post.
- **Move the panel to a new server** (Backup): point the panel's domain to the new IP, press "Make the move command" and run the one command on the new server. It downloads the full backup straight from the old server by its IP (encrypted with a passphrase that is only in the command; the one-time token is valid 3 hours), puts back the database, panel settings, the WireGuard / AmneziaWG / Hysteria2 configs and keys, the certificate and the uploaded app files, gets a fresh certificate when the domain already points there, starts the panel and checks it answers; then the old panel is told to stop (no two panels for the same nodes and bot). Nodes and tunnel servers follow the domain; the users' configs keep working (same keys). The normal backup is complete too and can be restored by hand.

# v3.6.8 — what is deleted is removed from the servers too
- **Ports close when something is removed:** every port Kanki opens in ufw is now kept per service (tunnels, Kanki DNS, Xray, emergency chat, KANKI MIX, subscription link, SSL). A deleted tunnel closes its ports on both servers, a removed DNS server / Xray inbound / emergency chat closes its own, a changed port closes the old one. A port another service still needs, SSH, or a port another program listens on stays open.
- **Open ports nothing uses** (opened by an older version for something deleted since): shown in Health of each DNS / Xray server with a "Close these ports" button.
- **Removing a tunnel server removes everything there:** its DNS, Xray, emergency chat and Iran subscription settings go too; the agent stops every tunnel and service, closes its ports and uninstalls itself (after three answers in a row that it was removed).
- **Deleting a node removes it from the server:** users are cut off at once, then the node stops WireGuard, AmneziaWG, Hysteria2 and KANKI MIX, closes their ports, removes Caddy when it only fronted the node and uninstalls the node agent. The panel says when the node could not be reached.
- **Certificates of removed services** are no longer renewed (and deleted when Kanki got them and nothing else uses them).
- **SSL on Iran servers:** when port 80 is free Kanki answers Let's Encrypt itself (no second program has to bind the port); a Kanki tunnel that carries port 80 is named instead of being stopped (it stopped the agent itself); errors say the real reason (port busy and by what, no A record, port 80 not reachable from abroad, rate limit, another server answered). "Try SSL again" skips the wait after a failure (Settings › Iran subscription, Health).
- **Emergency chat:** the admin page has the panel's look (light and dark, the panel font, served by the chat itself) and read receipts on both sides: ✓ sent, ✓✓ reached the app, blue ✓✓ read. The app API gets `read_upto` and `POST /api/e/read` (see docs/EMERGENCY-FA.md).
- **Kanki DNS › PUBG and games** (new tab): every PUBG Mobile name by part (login and lobby, UC store, anti-cheat, updates), three choices (Direct, Login and lobby, Everything), a plain explanation of what goes through the server and what stays direct, and the PUBG names your users asked with an Add button for the ones that went direct. Who had PUBG Mobile on keeps every name it routed.
- **Menu:** Tunnels comes before Kanki DNS and opens on the tunnels themselves; the DNS group lists PUBG and the query log; every item has a short note on phones. In the tunnel form "More" (rotating, address to dial, target) is folded until used.

# v3.6.1 — KANKI MIX direct to the foreign server
- **KANKI MIX connects straight to each foreign server** by default: the `kanki://` link now carries the server's own address (the host of its agent URL; the main server: its DOMAIN), not the node endpoint. The endpoint is often the Iran entry of a tunnel, which added its ping to every game packet.
- **Route per server** (KANKI MIX page › Servers): "Direct (the server's own address)" or "Through the tunnel (Iran server)". With the tunnel, the link uses the node endpoint and that tunnel must forward the KANKI MIX UDP port. Each server can also have an address of its own (a domain or IP) instead of the automatic one.
- **Kanki DNS in the app:** each relay in the subscription data now has `exit` / `exit_name` (the foreign server its tunnel reaches), so the app shows it as "Iran → Germany".

# v3.6.0 — KANKI MIX
- **KANKI MIX** (menu: VPN services › KANKI MIX): our own UDP protocol, next to WireGuard, AmneziaWG and Hysteria2 on every VPN server (the main server and every node). Game UDP goes on a raw datagram path with no queue and no retransmission (in gaming mode each packet is sent twice: at 20% loss 92% arrive instead of 64%); websites go over KCP + FEC; everything is masked with ChaCha20-Poly1305 and has no fixed bytes on the wire.
- **Nothing to install:** the server binary is built into the panel; each agent writes it to its server, runs it as `kanki-mix.service` and opens the port in ufw. An agent update (or the panel update on the main server) is enough. Default UDP port 4000; each server can have its own port (KANKI MIX page, or the node's Edit › ports), clashes with WireGuard / AmneziaWG / Hysteria2 are refused.
- **A key per user:** made from the panel's secret and the user's subscription code (resetting the link gives a new key). Disabled, expired or over-quota users are cut off at once. Traffic counts toward the user's volume and devices toward the connection limit (a closed app frees its place after 5 seconds).
- **Subscription:** each server in the subscription data has `kmix` (the `kanki://key@host:port?fec=10-3&gaming=1#name` link) and `kankimix` in `protocols`; the subscription page shows it with copy and QR. Users see no IP or key in the Kanki app.
- **Settings:** on / off, default port, FEC for websites (none to very strong), gaming mode on by default in the app, extra ports (a range sent on to the main port with iptables; the app picks one at random), per-server on / off. "Enable for all users" / "Disable for all users". KANKI MIX is in the user form, the default protocols of new users, Port management, logs and repairs.

# v3.5.8 — DNS query log
- **Kanki DNS › Query log** (new tab): every name the subscribers asked, newest first or grouped by name, with the user, the DNS server, the record type and whether it went through your server (**routed**, with the service that lists it, like PUBG Mobile) or straight to the site (**direct**). Filter by user, by routed / direct and by text in the name. Useful to see which names a game really uses and which of them pass your servers (and add to their ping).
- Each DNS server keeps its last 4000 queries and the agent sends only the ones the panel has not had yet (at most 2000 per report); the panel keeps the last 50 000 in memory (a restart clears them, nothing is written to disk). "Clear" empties it. DNS servers log from v3.5.8 on (they update by themselves).

# v3.5.7 — real exit of each server for the app
- **Exit location in the app's subscription data:** each server in the `nodes` list of the subscription page's data now carries `exit_ip`, `exit_cc` (country code), `exit_city` and, when known, `exit_lat` / `exit_lon`. A config that goes through a tunnel has its endpoint on a server inside Iran, so the Kanki app guessed Iran as the destination; these fields give the address the traffic really leaves from (the VPN server itself: the panel's domain for the main server, the agent address for the others). They are looked up from the panel (outside Iran) 20 s after start and then hourly, only for new addresses or answers older than a week, and kept in the settings, so a subscription page never waits on the network. Empty strings while unknown.

# v3.5.6 — subscription link on an Iran server
- **Serve the subscription from an Iran server** (Settings › Addresses): for ISPs that block the panel's domain. Pick a tunnel server inside Iran, a domain whose A record points to it and a port (2053 by default). The panel builds a hidden Kanki tunnel from that server to itself (or reuses a tunnel of yours that already carries the panel's web port); the agent there gets SSL with certbot and serves `https://<domain>:<port>/sub/…` through the tunnel. Only the subscription pages, config downloads and assets pass, never the admin panel. A renewed certificate is picked up without a restart; SSL or port errors show in Settings.
- **Iran and abroad servers apart:** a tunnel server has a location (Inside Iran / Abroad), asked when it is added and editable. The Servers page and every server picker (tunnel form, smart tunnel, emergency chat, DNS, Xray, Iran subscription) show «Iran servers» and «Abroad servers» as two groups; the Iran subscription lists only Iran servers. Existing servers get a guess from what they do (tunnel entry, DNS relay, emergency chat → Iran; tunnel or DNS exit → abroad), marked "guessed" until confirmed in Edit.
- Once that server has served HTTPS, every subscription link (users list, Telegram bot, subscription page) uses it; before that, and when it is removed, the old address.

# v3.5.5 — one Servers page
- **Servers** (menu, right under Users) holds every server of the panel in three parts: Kanki VPN (WireGuard · AmneziaWG · Hysteria2), Xray and Kanki DNS, each with its own add button (DNS: exit server abroad, relay in Iran). The Xray and DNS pages no longer add servers; they point to Servers.
- **VPN services page** tidied: small buttons in each card's head instead of the big buttons at the bottom; Xray shows its first 5 inbounds and a link to the rest.

# v3.5.4 — Xray install fix, installs without root login

- **Xray-core install failed with "Permission denied"** on servers without `unzip`: Python's zip extraction drops the executable bit, so the new `xray` could not run. The file is now made executable before it is tested, and the download goes to `/var/lib/kanki/tmp` instead of `/tmp` (which some servers mount `noexec`).
- **A failed Xray install no longer retries every 15 seconds:** it waits 5 minutes before the next try, and the panel logs the same error once instead of on every round.
- **Install as a normal user:** `install.sh`, the `kanki` command and `install-standalone.sh` no longer stop with "Please run as root" for a user like `ubuntu`: they run themselves again with `sudo`, keeping the `KANKI_*` settings, so the one-line join commands the panel prints work as they are. A `bash <(curl ...)` start fetches the installer again into a file, since sudo cannot reopen the pipe.

# v3.5.3 — Game and FakeTCP transports, Anti-DPI menu, security hardening

**Fixes found in review (before release)**
- **Game:** with FEC on (the default) every received data packet reached KCP with 2 extra bytes in front; the length is now taken off. Tested end to end with a lost packet rebuilt.
- **FakeTCP:** the client set its RST-drop rule only after the handshake, so its kernel's RST made the server drop the link; the rule now comes first and the server ignores RST/FIN like udp2raw. A SYN no longer allocates anything (a flood of fake SYNs could lock real clients out); the peer is made on the first payload that opens with the token. Several links no longer mix their packets. iptables rules use `-w`, carry a tag, are removed exactly once and leftovers of a crashed run are cleaned at start. Standalone installs get CAP_NET_RAW and CAP_NET_ADMIN.
- **CDN transport:** offered HTTP/2 in the TLS hello and then spoke HTTP/1.1, which broke behind Cloudflare / ArvanCloud; it offers only HTTP/1.1 again.
- **Panel certificate pin:** a panel certificate that is valid for its domain (Let's Encrypt) is accepted and re-pinned, so agents installed with INSECURE=1 no longer lose the panel at the first renewal; the pin only guards certificates no CA vouches for. Deleting the pin file works without a restart.
- **Node pins** are forgotten when a node is deleted, re-joined or its address / self-signed setting changes; a pin mismatch shows as "Certificate changed" with how to fix it, instead of "Offline".
- **Hysteria2 download** goes through the pinned connection itself (no `curl -k` after a separate check); IPv6 panel addresses work.
- **Busy links** are no longer killed after 5 s waiting behind other streams: only a writer that wrote nothing for 5 s counts as dead.
- **UDP flows:** the exit evicts its least recently used flows when full (it dropped new ones), closes flows that never got a reply after 30 s, and the entry evicts in batches instead of scanning 8192 flows per packet.
- **Mask padding:** the per-server size cap no longer falls below full QUIC / KCP packets, so their sizes stay random.
- **Version gate:** game / faketcp are also kept out of auto-rotation and the smart test for agents older than 3.5.3.
- **Anti-DPI page:** the Persian text loads (it failed with "FA is not defined"); "VLESS + gRPC behind a CDN" makes a gRPC + TLS inbound (it made gRPC + REALITY, which cannot pass a CDN).

**Security hardening**
- **Certificate pinning (TOFU) closes the INSECURE MITM hole:** on installs without a domain the agent no longer accepts any certificate forever — the first panel certificate seen is pinned to `/etc/kanki/panel.pin` and any later change is refused with a clear error. The same pinning now covers the panel→node direction for nodes marked "self-signed certificate" (pins in `{data_dir}/nodepins/`), and the Hysteria2 binary downloads over `curl -k` first check the live certificate against the pin. Tokens, tunnel specs and update binaries all travel these channels, so a man-in-the-middle can no longer take root on the agents after first contact. For zero first-contact trust: copy the pin file by hand, or use a real domain and certificate.
- **Standalone tokens must have real entropy:** the UDP mask key derives from the token and the wire shows a 4-byte tag of it, so a short standalone token could be brute-forced offline; the minimum is now 24 random characters (`openssl rand -hex 24`). Panel-made tunnels already used 40 random characters.
- **UDP flood resistance:** user-facing UDP ports now cap their flow table (8192) and evict the idlest flow when full, and the exit caps its per-flow sockets the same way — a flood of forged sources can no longer exhaust file descriptors and memory.
- **A stuck link heals faster:** when a dead socket leaves the send queue full, the link is killed and reconnected after 5 seconds instead of wedging until the 30-second watchdog.
- **Fewer static fingerprints:** the throwaway self-signed certificates of the tunnel transports get a randomized name instead of the fixed `www.bing.com` / `www.cloudflare.com` (internet-wide scanners enumerate those), and the UDP mask's maximum wire size is derived from the tunnel secret (1152–1232), so the first packet's size is not the same for every Kanki server.

**Game and FakeTCP transports, Anti-DPI menu, stronger SNI spoof**
- **New transport `game` (KCP + Reed-Solomon FEC):** lost packets are rebuilt at the far end from parity shards instead of waiting for a retransmit (40–100 ms saved per loss). Configurable `data:parity` (default `8:3`, `off` = plain masked KCP), plus optional **packet duplication** for near-zero visible loss. Every packet — data and parity — is masked with the Salamander scheme, so no KCP signature shows. Made for gaming and WireGuard-over-tunnel; profile "Gaming" fits it best.
- **New transport `faketcp` (udp2raw style):** UDP inside hand-crafted TCP packets with a fake three-way handshake — to DPI it is an ordinary TCP session, but it keeps UDP behaviour (no TCP queues). KCP runs inside (MTU 1150) with the token mask on top. Needs root on both servers; the panel adds and removes the iptables RST-drop rule by itself. For where UDP is cut or throttled.
- **Smart tunnel test** now includes `game` and `faketcp`; the port-range note counts the ticked methods by itself.
- **New page: Anti-DPI tunnels** (sidebar → VPN services). One-click inbound presets — VLESS + REALITY, VLESS + XHTTP + REALITY, VLESS + WS behind a CDN, VLESS + gRPC behind a CDN, Trojan + TLS, Shadowsocks 2022 — each with a plain explanation of why it resists DPI and when to use it, plus the server-to-server transports (Hysteria2, AmneziaWG, Game, FakeTCP) and a "which one, when" guide.
- **SNI spoof strengthened:** TLS-hello fragmentation is now randomized (2–9 byte chunks, 260–620 byte hello pieces — the old fixed 220-byte pattern was itself a fingerprint); WSS and CDN dial with a **browser's cipher-suite order and ALPN**; **SNI and Host rotate** through comma-separated lists per link (a failed link moves to the next name). The in-panel guide has a step-by-step ArvanCloud walkthrough (domain, WebSocket on, origin HTTP:8080, reverse mode, Test CDN, edge scan) and a "WireGuard behind which tunnel" answer.
- Version gate: `game` and `faketcp` need both servers on 3.5.3+; older agents get a clear error.

# v3.5.2 — certbot frees port 80 by itself
- **Port 80 is handled by itself**, when the certificate is taken and on every renewal: whatever listens there (Caddy, nginx, an Xray inbound, a Docker container …) is stopped for the few seconds certbot needs and started again right after, even when certbot fails or hangs. The holder is found from `/proc` (no tools needed).
- **Kanki DNS does not stop for SSL:** it answers Let's Encrypt itself on port 80 (`certbot --webroot`), so the users' DNS keeps working while the certificate is taken or renewed.
- **Renewal that does not break:** besides certbot's own renewal, the agent checks every 12 hours and renews a certificate with fewer than 25 days left with what holds port 80 at that moment. After a renewal every service that uses the certificate is restarted (a domain can serve DNS and Xray together).
- After a failure certbot waits 10 minutes, then 20, 40 … up to a day, instead of disturbing the server every round. A program on port 80 that is not a service is named in the error instead of being killed.
- The emergency chat uses the same certbot code.

# v3.5.1 — SSL with certbot, DNS and Xray kept apart
- **SSL is taken on the server itself with certbot** (`certbot certonly --standalone -d <domain>`, no e-mail), like the emergency chat: an Xray server with its domain gets its certificate as soon as it is added (TLS inbounds with "Automatic" use it), and every Kanki DNS server gets one for its own name. certbot renews by itself; a Kanki service holding port 80 (Kanki DNS, an Xray inbound on 80) is stopped for those seconds and started again. A failure shows on the server card and is tried again after 10 minutes.
- **Removed:** certificates and DNS records through the Cloudflare / ArvanCloud API (Kanki DNS and Xray), and the "Xray DNS servers" setting. Kanki DNS and Xray no longer share any setting.
- Kanki DNS: a pasted certificate stays possible (optional); with certbot the Private DNS address is the server's name, and the user is known by the address the app registered.

# v3.5.0 — Menu that opens in place, stronger Xray and Kanki DNS
- **Menu:** the sidebar has groups that open in place: VPN services (All VPN services, Kanki VPN, Xray), Kanki DNS (Overview, DNS servers, Services, DNS users, Settings and SSL), Tunnels, Sales & support, System. On a phone the hamburger is gone: a section bar under the top bar opens a drop-down of tiles; the VPN group shows Kanki VPN and Xray side by side.
- **New page: VPN services.** Kanki VPN (nodes, users per protocol) and Xray (inbounds, online, traffic) side by side, Kanki DNS under them.
- **Xray page in tabs:** overview, inbounds (search, server filter), online clients, routing and outbounds, settings.
- **Inbounds:** traffic of each inbound kept across restarts (reset button), a traffic limit and an end date (the inbound stops by itself), clone to the next free port, users of the inbound with their links and QR, the inbound's JSON, quick setups (VLESS + REALITY, XHTTP + REALITY, WS for a CDN, gRPC + REALITY, Trojan + TLS, Shadowsocks 2022), random free port, REALITY target suggestions.
- **More inbound options:** listen address; sniffing targets, destination override and metadata only; PROXY protocol; lowest TLS version, refusing unknown SNI, certificate from files on the server; REALITY xver and largest clock difference; WebSocket heartbeat; XHTTP padding; gRPC multi mode and authority in the link; mKCP MTU / TTI / capacity / congestion; fallbacks for VLESS and Trojan over TCP.
- **Routing built in the panel:** outbounds from another server's link (vless / vmess / trojan / ss, for chaining an Iran server to one abroad), SOCKS, HTTP, direct, block or raw JSON, with a check button; rules by domain, IP, port, network, sniffed protocol, inbound and user, in order, each switchable; the default outbound; domain strategy; ready-made rules to block ads and Iranian sites. Settings: log level, Xray DNS servers, IPv4 only. All checked with the real Xray-core 26.3.27; chains carried real traffic.
- **Kanki DNS page in tabs:** overview (path of the traffic, busiest services, domain checker), servers (queries, routed, cache hits, refused, allowed addresses, version), services (collapsible sections with search and all on / off, extra domains), DNS users (addresses registered on each server, queries, copy the Private DNS address, forget addresses), settings and SSL (upstream presets).
- The DNS service now reports query counts, the busiest routed names and the allowed addresses per user; "forget addresses" makes the servers drop a user's addresses within seconds.
- **User form:** services as cards: Kanki VPN (WireGuard, AmneziaWG, Hysteria2 and the servers), Xray (the inbounds the user gets) and Kanki DNS (the DNS servers), with Everything / only one quick choices.

# v3.4.0 — Kanki DNS and Xray
- **New page: Kanki DNS.** A private smart DNS for subscribers, written for the panel (`kanki-panel dns`, service `kanki-dns`): DNS on UDP/TCP 53, DoT on 853 and DoH on 443. Names of sanctioned services resolve to the DNS server, which carries those connections on by their SNI (443) or Host (80) without decrypting them; everything else resolves normally and goes direct. No speed limit.
- **Only subscribers:** each user has a DNS token (from the subscription code). `<token>.<server>` (Android Private DNS) or `/dns-query/<token>` (DoH) knows the user and allows the address it came from for a while, so plain DNS and the relayed connections work from there too. Anybody else gets REFUSED. The app can also call `/r/<token>` when its network changes.
- **Exit and relay servers:** an exit server abroad carries the connections itself; a relay server inside Iran answers its own address and sends the connections to its exit through a hidden Kanki tunnel (any transport). Relays come first in the subscription.
- **Services:** the catalog of ~800 names in groups (games, downloads, AI, developer tools…), on/off per group, plus your own domains. List from doctor-dns (MIT, see `assets/dns/LICENSE-doctor-dns`), logos from Simple Icons.
- **Certificates by the panel:** with a Cloudflare or ArvanCloud API token the panel sets an A record for every DNS server (and `*.` it) and gets one Let's Encrypt certificate for all of them with the DNS challenge, renewed every 60 days. Nothing has to reach the Iran servers. A pasted certificate works too.
- **New page: Xray.** Inbounds like 3X-UI: VLESS, VMess, Trojan and Shadowsocks (2022) over TCP, WebSocket, gRPC, HTTPUpgrade, XHTTP or mKCP, with TLS or REALITY (keys made by the panel), share links for a CDN in front. The clients are the panel's own users who have Xray ticked (optionally only some of them per inbound); traffic is counted into their usage; no speed limit.
- Xray runs on the panel server or on any agent server; the agent installs Xray-core (from GitHub, or through the panel when GitHub is blocked), checks every config with `xray run -test` before using it and restarts only on changes.
- **Node types:** Nodes › Add node asks VPN / Xray / DNS exit / DNS relay. Users get **Xray** and **DNS** checkboxes beside WireGuard, AmneziaWG and Hysteria2.
- The subscription (page, JSON for the app, raw for v2rayNG / Hiddify) carries the Xray links and the DNS addresses.
- CI tests every branch; only `main` publishes a release.
- Guide in Persian: `docs/DNS-XRAY-FA.md`.

# v3.3.2 — Automatic update every night
- **Automatic update switch** (in the update window of the version button, and in Settings › Update): every night at **03:30 Tehran time**, if GitHub has a newer version, the panel runs "Update all" by itself: the nodes, the tunnel servers, then the panel. Components already on the newest version are left alone. The window shows the next run and the result of the last one. "Update all" by hand works as before.
- After an update the **emergency chat** moves to the new version too (before, it kept running the old binary until restarted).

# v3.3.1 — Emergency chat: automatic SSL, better admin page, fixes
- **Automatic SSL:** choose "Automatic SSL" and the Iran server gets (and renews) a Let's Encrypt certificate for the domain by itself (certbot; port 80 must be free). Other choices: SSL from the CDN (ArvanCloud), your own certificate, or plain HTTP.
- **Admin page rebuilt:** every customer listed with search, conversations first with unread counts, delivery ticks (green ✓✓ when the app has the message), a config mode (each line is sent as its own config, with a copy button), picture zoom, the main panel's look, works on phones.
- **Fix:** messages showed twice on the admin page (two refreshes at once). They were stored once.
- **Fix:** behind ArvanCloud the app sometimes said "not registered": the CDN cached answers. Every answer is now `no-store`.
- The first load shows the newest 200 messages.

# v3.3.0 — Emergency chat on a server inside Iran
- **New page: Emergency chat.** Choose a server inside Iran, a domain and a port; the panel installs a small chat server there through its agent (`kanki-panel emergency`, service `kanki-emergency`) and keeps the customer list on it while the internet works.
- Customers write from the Kanki app (text and screenshots); the admin answers and sends configs at `<domain>/admin`, from inside Iran, with the password set in the panel.
- **Signed admin messages** (ECDSA P-256): the app gets the public key from the subscription page and trusts only valid signatures, so plain HTTP cannot carry a fake config. Users are known by a hash of their code, never the code.
- HTTP or HTTPS (paste a PEM certificate and PKCS#8 key). Rate limits on guessing, sending and login. A chat that stops is started again by the panel.
- Replaces the single emergency page of 3.2.0. Guide in Persian: `docs/EMERGENCY-FA.md`.
- Tests: chat and signatures end to end, pictures, throttling; the signature is also checked with Java (as on Android).

# v3.2.1 — separate subscription domain with its own SSL
- **Settings › Addresses › Separate subscription domain:** type a domain that points to this server and press the button. The panel adds a second site to the Caddyfile (`# kanki-sub begin … end`), Caddy gets the SSL certificate by itself, and every subscription link becomes `https://<domain>/sub/<code>`.
- On that domain only `/sub/*`, `/api/config/*` and `/assets/*` are served; the admin panel is not reachable through it.
- If no certificate can be issued, the old Caddyfile is put back and nothing changes. Empty field + button = remove.
- Needs ports 80 and 443 free on the panel server, and the domain pointing directly to it (no CDN / proxy).
- `install.sh` rewrites the Caddyfile; run the setup button again after re-running it.

# v3.2.0 — Emergency address, public emergency page, tunnel-down warning
- **Emergency address:** the admin sets the domain (for example `https://chat.kanki.pro`) in the app-message card. The Kanki app shows an emergency button on its first screen and in Servers; it opens `<domain>/emergency`, and remembers the address so it works while the internet is cut.
- **Public emergency page** (`/emergency`): shows the current app message and how to connect in an emergency. It is served on whatever domain points to the panel.
- **Tunnel-down warning:** when every enabled Kanki tunnel is down, the Tunnels page says so and tells you to switch the users to the direct mode (AmneziaWG).
- Point the domain to the panel server (or its CDN) and make sure the server answers to it (Caddy site for that host).
# v3.1.3 — Hysteria2 is installed the same way as for VPN users
- **The cause** of "Hysteria2 is not installed" on the Iran server: the official installer `get.hy2.sh` first asks `api.hy2.io` for the newest version and stops when only that site is unreachable, even when GitHub works.
- **Tunnel agents now install Hysteria2 exactly like the panel does for users:** first `get.hy2.sh`; if it stops, the same GitHub file it would download (or the copy on download.hysteria.network) is installed **with the same installer** (`--local`), so the result is identical (binary, user, service files). Then, as before, the panel / the other server of the tunnel.
- The installer runs with `TERM` and `HOME` set (the agent's service had neither).
- `install.sh` uses the same fallback when it installs Hysteria2 for VPN users, so a node where `api.hy2.io` is blocked still gets Hysteria2.
- The CPU type is picked by itself; there is nothing to choose.
- Hysteria2 tunnels need agents v3.1.3 (Update all).

# v3.1.2 — Hysteria2 tunnel: installs on servers that cannot reach GitHub
- **The bug:** on a server in Iran the tunnel stopped at "Hysteria2 is not installed and could not be installed": GitHub was unreachable there and the panel only offered its own copy, which it did not have.
- **Now the binary is fetched in this order:** GitHub, then `download.hysteria.network` (a direct download, checked to be a real program and not a filter page), then **the panel**, then the official script.
- **The panel finds it for any CPU type:** its own copy, a copy it keeps in `/var/lib/kanki/hy2bin`, or it downloads it itself.
- **Servers share it:** as soon as one server of a tunnel has hysteria (for example the foreign server), it gives the panel a copy, and the Iran server gets it from the panel a few seconds later. No manual step.
- The upload only accepts a tunnel server's token (checked before the file is read) and a real program whose checksum matches.
- The tunnel card now says which server an error comes from.
- Hysteria2 tunnels need agents v3.1.2 (Update all).

# v3.1.1 — Hysteria2 tunnel: ports are always freed
- **Deleting (or disabling) a Hysteria2 tunnel frees every port on both servers**, the panel server and tunnel-agent-only servers alike: the tunnel's UDP port, the forwarded TCP / UDP ports and its stats port. The service is stopped, disabled and removed with its files; the routes of the "whole network" mode are taken down. Changing a port frees the old one at once.
- Every tunnel now has its own service and TUN name made from its whole id (before, two tunnels could share one).
- The internal stats port moved to 61001–61250, so it can never take the port of the VPN Hysteria2 (30000–39999) or one the installer picks.
- Editing a tunnel removes the routes of its old networks before the new ones are set.
- `install.sh` › Uninstall also stops and removes the Hysteria2 tunnels.
- Hysteria2 tunnels need agents v3.1.1 (Update all).
- Test: create → change port → delete with the real hysteria binary; every port is free afterwards.

# v3.1.0 — Hysteria2 tunnel between two servers
- **New tunnel type: ⚡ Hysteria2** (Tunnels › + Tunnel › Tunnel type). The exit runs a Hysteria2 server, the entry a Hysteria2 client: the official `hysteria` binary, each tunnel in its own systemd unit `kanki-hy2-<id>.service`, so the Hysteria2 that serves VPN users is not touched.
- The panel makes the password, a Salamander obfuscation password (on by default) and a self-signed certificate; the client pins the certificate's SHA-256.
- **Forwarded ports:** users connect to a port on the entry and land on the same (or another) port of the exit — TCP and UDP.
- **Whole networks through the exit:** the client's TUN carries everything coming from the listed source networks (for example the WireGuard users of the entry, `10.8.0.0/24`); only those networks are routed, SSH and the server itself are not.
- Optional Brutal speeds (Mbit/s), masquerade site, TUN MTU; "show the config" for each side; status from the exit's traffic-stats API and the client's log.
- The agents install Hysteria2 by themselves (`get.hy2.sh`, or the panel server's binary when GitHub is unreachable). Agents must be v3.1.0 (Update all). Guide in Persian: `docs/HY2-TUNNEL.md`.
- Tests: client / server config text, the route script, the certificate pin, input cleaning.

# v2.9.7 — Fix: tunnels flapping every few seconds (connect, drop, reconnect)
- **The bug:** a tunnel between two servers connected, went down a few seconds later, came back, and kept doing that on a ~5-second beat. Cause: for a node with no stored address, the panel rebuilt the peer address from the node's source IP on every report. When that IP wavered — most often a report with no `X-Forwarded-For` falling back to `127.0.0.1` — the tunnel spec changed, and the engine rebuilds a tunnel whenever its spec changes at all, so it tore the link down and set it up again every cycle.
- **Fix 1 — the listening side carries no peer address.** Only the side that dials needs the peer's address; the side that listens never uses it. It no longer carries one, so a change in the peer's seen address can't restart a listener for nothing.
- **Fix 2 — a node's address is sticky.** Once the panel has a real address for a node, a later report with no usable source IP (empty or loopback — a health check, or a proxy that didn't set `X-Forwarded-For`) no longer overwrites it. A genuinely new real address is still taken.
- No change to how tunnels connect or carry traffic; this only stops the needless teardown/rebuild. Setting an explicit address on a node (Tunnel servers → edit) was already the sure fix and still is.
- Test: the sticky-address rule (keeps a real IP through a bogus report, takes a new real one).

# v2.9.6 — Smart tunnel: pick which methods to test, and a raw-ping reference
- **Tick the methods you want.** The smart tunnel test now shows a checkbox per transport (TCP Mux, TCP, WebSocket, WSS, QUIC, KCP, HQ, H2); only the ticked ones are tested, so you can try one at a time. The test ports and the firewall note follow the number you picked.
- **Raw ping (no tunnel).** A new reference row at the top measures the plain server-to-server ping (ICMP, entry → exit) with no tunnel, so you can see the base latency of the route and how much each tunnel adds on top. It is a reference only — never scored, never picked as "best", and it carries no traffic. If `ping` is missing it says how to install it (`apt install -y iputils-ping`); if ICMP is blocked between the servers it says so.
- The raw-ping path is fully isolated from the link/mux tunnel engine (a separate task that only runs `ping`), so it cannot affect real tunnels.
- Test: the ping-output parser (avg RTT + packet loss, including a 100%-loss "no answer").

# v2.9.5 — Finished trials are removed, config names, clearer config help in the bot
- **Finished free trials are deleted** (within a minute, by the bot; the nightly clean-up does it too). Their number goes to the next new customer, so the user list stays in order (16 customer, 17 trial → deleted → the next buyer is 17). The person gets a message with a Buy button. A trial is kept while its owner has a receipt / payment waiting, so a pending purchase can still renew that same account; a trial that is bought, renewed or extended becomes a normal account and is never removed. A finished trial cannot be taken again.
- One-time fix on update: old trials that were already extended (renamed from USER<n>-TEST to USER<n>) lose their "trial" note, so they are never deleted.
- **Config names:** English letters and digits only, 3–12 characters, starting with a letter (like `mahtab87`, `erfan456`), in the panel (new user, edit, bulk = name1, name2 …), in the bot's admin "make config" and for customers. Names are unique ignoring upper / lower case. Existing names are not changed.
- **Bot:** a customer's config takes the name they chose, else the English letters and digits of their Telegram name (emoji, stickers, symbols and other alphabets dropped), else their @username; when none of these gives a name, the bot asks for one (with examples) before the trial or the plan list. New button **✏️ Rename config** under the account.
- **Config files now import in WireGuard / AmneziaWG:** those apps take the file name as the tunnel name and refuse names over 15 characters or with other characters ("Invalid name"). Files were called like `USER17-TEST-GERMANY-GAMING-amneziawg.conf`; now `mahtab87-ger-a.conf` (name, first 3 letters of the server, a = AmneziaWG / w = WireGuard).
- **Which app?** Before the config files the bot explains, in simple steps, which apps each one works with (WireGuard: WireGuard / AmneziaWG / Kanki; AmneziaWG: only Kanki or AmneziaWG — not plain WireGuard; Hysteria2: Kanki / Hiddify / v2rayNG) and how to import it. The default "config buttons" text says so too (a text you already changed in the bot stays as it is).
- Tests: the whole customer journey runs against a fake Telegram API (name prompt, trial, end of trial, number reuse, purchase over a trial, pending receipt, rename), plus name and file-name rules.

# v2.9.4 — App message from the robot, node health, tidier node cards
- **App message** (Sales bot › App message): write a message (up to 500 characters), choose how long it shows (30 minutes … 7 days, or until you remove it) and, if you want, only for some usernames. The robot on the first screen of the Kanki app shows it, and it disappears by itself when the time is over; "Remove now" takes it down at once. It travels inside the normal subscription page (`app_msg` in the page's JSON and in `/sub/…/json`), so **no extra domain or port is needed**. Needs Kanki app 1.7.3 or newer.
- **Node health:** every node now reports CPU, RAM, swap, disk, connections and uptime with its info. Each node card shows a health badge (Healthy / Under pressure / Problem) with the reasons (CPU, RAM or disk filling up, heavy swap, stopped service, config mismatch, no contact, older agent), and CPU / RAM / disk bars. The dashboard's node list shows CPU and RAM too.
- **Tidier node cards:** the buttons and the long details are folded under "Details & settings" (the arrow opens and closes them, and they stay open across auto refresh).
- Nodes on an older agent show no CPU / RAM until you press **Update agent** (or Update all).
- Cleanup: removed old copies of the source files (`src/*.rs` next to `main.rs`, `web/index.html`) that were no longer compiled, and two compiler warnings.

# v2.9.3 — Fix: AmneziaWG ports staying busy after a tunnel is deleted or moved
- **Fix (important):** the AmneziaWG worker used a `busy` flag that was only cleared at the end of its thread. If `reconcile()` ever panicked (a failed command, a bad config), the flag stayed set and the shared lock got poisoned, so **reconcile never ran again** — a deleted or moved AmneziaWG interface was never brought down and kept its UDP port (a kernel interface holds the port even across restarts). This is the "UDP port … is busy / Address already in use" you saw after deleting a tunnel or switching the server. The worker now clears the flag even on panic (a drop guard), recovers a poisoned lock instead of wedging, and isolates a panicking reconcile so one bad interface no longer stops the others (this is why it worked for one server and then broke when a second was added). Tests cover both.
- Engine tunnels (tcp/ws/wss/…) already freed their ports on delete and a busy forwarded port self-heals within a few seconds as the old socket closes; only the AmneziaWG path could stay stuck.

# v2.9.2 — No AmneziaWG installation on servers that do not use it
- **Fix:** every tunnel agent, standalone `tunnel-run` and the panel's own engine tried to install AmneziaWG at start (`add-apt-repository ppa:amnezia/ppa`, `apt-get install amneziawg…`) even when no AmneziaWG tunnel was configured. It now installs it only when an AmneziaWG tunnel is wanted. (Found by running the released binary for the standalone guide.)

# v2.9.1 — Standalone tunnel as a service, built and tested on GitHub Actions
- **`scripts/install-standalone.sh`**: installs one tunnel description (`tunnel-run` JSON) as a systemd service on a server without the panel. It downloads the latest release and verifies its checksum (or takes `KANKI_BIN`), checks the file before touching the system, creates a no-shell system user, keeps the file (it holds the secret) readable by that user only, sets UDP buffers / BBR, opens the ports in ufw and starts the service (`Restart=always`, no start limit, `NoNewPrivileges`, `ProtectSystem=strict`). `--uninstall` and `--purge` remove it. The unit is also in `docs/systemd/`. Guide in Persian: `docs/STANDALONE-FA.md`.
- `kanki-panel tunnel-run <file> --check` validates a file and prints the ports to open without starting anything. A file that still has the example placeholders (`CHANGE-ME…` token, `NODE_x_PUBLIC_IP` address) is refused: a public secret must never protect a tunnel.
- Notes: v2.9.0 was built and tested on GitHub Actions (all 51 tests pass, including hq / h2 / dual end to end); the notice about "not compiled" no longer applies.

# v2.9.0 — Tunnel transports for hostile networks (hq, h2, dual) + tunnel hardening
- **`hq`**: QUIC under a Salamander-style mask. Every UDP datagram is `salt(8) | ChaCha20(tag(4) | pad_len | random pad | QUIC datagram)`, keyed from the token: no fixed byte, random sizes, and a datagram with a wrong tag is dropped silently (a scanner gets no answer). QUIC uses BBR, a 1200-byte MTU, 5 s keep-alive and big windows.
- **`h2`**: WebSocket over HTTP/2 (RFC 8441) over TLS 1.3, with the ALPN, cipher order, HTTP/2 SETTINGS and request headers of Chrome. Four links share one TCP connection; strangers get a normal web page; HTTP/1.1 WebSocket fallback when the server has no RFC 8441.
- **`dual`**: `hq` first, `h2` when UDP does not work (1.5 s head start, then both race; UDP is remembered as bad for 90 s). The listener serves UDP and TCP on the same port number.
- **Padded records** on hq / h2 / dual: `[u16 real length][data][random pad]` inside the AEAD.
- **Standalone mode:** `kanki-panel tunnel-run file.json` runs tunnels without the panel; the file is checked and the ports to open are printed. Examples in `docs/examples/`.
- Panel: new "Hardest to block" group in the tunnel form, port checks know that `dual` uses TCP and UDP, tunnels with the new transports are refused while an agent is older than 2.9.0, the smart tunnel tests `hq` and `h2` too (16 test ports instead of 12), rotation order starts with `dual`.
- **Hardening of the existing tunnel code:**
  - listeners accept in their own tasks; TLS / WebSocket / QUIC handshakes run per connection with a limit (256 half-open, 256 token handshakes), so one slow client cannot hold the door; before, accepting was one connection at a time, so a client that connected and said nothing held the accept loop of `ws` / `wss` / `cdn` for up to 10–20 s each;
  - WebSocket messages are limited to 1 MiB before the token is proven (the library default is 64 MiB);
  - **KCP wire format changed** (the KCP mask is now the same one `hq` uses, with a check value and padding): both ends of a KCP tunnel must be updated together (Update all);
  - the KCP relay frees its sockets and tasks when a link ends and keeps a bounded peer table (before, every link left a pair of tasks and sockets behind).
- **Audit fixes in the rest of the panel:**
  - request bodies are limited to 2 MiB everywhere (the restore upload gets 128 MiB), and an unauthenticated `/api/restore` is refused before the body is read;
  - backup / restore work in private (0700) temporary folders; a restore copies only the known files, as plain files;
  - the failed-login table is pruned, and the password hash check runs off the async runtime (a burst of logins no longer stalls the panel);
  - `promote_trial` uses a parameterised query;
  - Telegram bot: a payment is claimed atomically before it is fulfilled (two taps / two callbacks cannot fulfil it twice), the referral reward is claimed atomically too, and renew / replace actions check that the service belongs to the user;
  - WireGuard: the pre-shared-key temporary file is created with mode 0600, a random name and `create_new`;
  - `install.sh`: the checksum file is mandatory; without it the install stops instead of continuing unverified;
  - release workflow: the tests are built first and must pass before a release is published (`continue-on-error` removed).
- New tests: hq / h2 / dual end to end (both modes, SNI lists), `dual` falling back to a TCP-only server, silence of the UDP port towards a scanner, wrong tokens, probes for hq and h2, mask unit tests, standalone-file checks.
- Built and tested on GitHub Actions (51 tests pass); run `cargo test tunnel::` to repeat it.

# v2.8.6 — Tunnel form tidied, SNI spoof completed
- **New tunnel form** in six numbered sections: 1 Route (entry ⇄ exit, who connects) · 2 Tunnel type · 3 Transport (grouped: looks like web traffic / encrypted TCP / over UDP / whitelist, each with TLS·SNI·UDP·HTTP tags) · 4 Disguise · 5 Ports · 6 More. Works on phones.
- **Disguise only shows what the chosen transport can use.** SNI spoof is not a separate protocol: it is the site name shown in the TLS hello, so it exists only for WSS, QUIC and CDN. WS has no TLS (Host header and path only). TCP, TCP Mux and KCP are encrypted from the first byte and have nothing to disguise; the form says so instead of showing empty boxes.
- **SNI spoof completed in the engine:**
  - several SNI names (comma separated) for WSS and QUIC too (before: CDN only). Every link takes another name and a link that fails moves to the next one.
  - "Split the TLS hello into tiny pieces" now also works for WSS (before: CDN only).
  - a separate HTTP Host header for WS and WSS (empty = the SNI).
  - quick picks for common names (google, cloudflare, bing, microsoft, apple, jsdelivr).
- New end-to-end tests: WSS with several SNI names + Host + split hello (reverse and direct), QUIC with several SNI names, WS with a Host header.
- After updating the panel press **Update all** so the tunnel agents get the new engine.

# v2.8.5 — New tunnel map animation
- The tunnel map (Tunnels page and the dashboard card) is now drawn on a canvas and keeps running between refreshes. Each connected tunnel is a glowing fibre: packets leave the entry plain, pass a lock in the middle and arrive encrypted in the tunnel colour, return packets flow back, the exit shows arrival ripples. More traffic = more packets, higher ping = slower packets. A partial tunnel flickers, a down tunnel is a red dashed line with a broken spark. Servers have a breathing halo, a turning orbit and a small satellite. Works in both themes and respects "reduce motion".
- Checked: every transport (TCP Mux, TCP, WebSocket, WSS, QUIC, KCP, CDN; direct and reverse) passes the real end-to-end tests on GitHub Actions.

# v2.8.4 — New panel look, Settings rebuilt
- **New look:** the side menu is grouped (Overview · Users & sales · Network · System) with the version / update status and logout at the bottom; a top bar shows where you are (panel › group › page), a FA/EN switch, theme, update and the signed-in admin. Every page header gets its page icon. Calmer cards, inputs with a focus ring, dotted background. Light theme and phones included.
- **Settings rebuilt** into seven sections, each with its own Save and Undo and a dot in the menu while it has unsaved changes:
  - *Appearance*: name, logo (saved at once), language, theme and colour as visual pickers, auto refresh.
  - *Addresses*: panel address (copy), public VPN host, subscription base URL, "use this address on every node", web bind/port (read only).
  - *VPN & protocols*: DNS with Cloudflare / Google / Quad9 / AdGuard presets, MTU with presets (checked: 1200–1500), AmneziaWG compatibility, Hysteria2 connection limit.
  - *New users* (new): default protocols, volume, days and connections; the "New user" form starts with these.
  - *Notifications*: server alerts, buyer warnings, daily backup to bot admins.
  - *Update & version*: current / latest version, check and install, and the **update source (GitHub repo) can now be set from the panel** (written to /etc/kanki/repo; KANKI_REPO in the environment still wins).
  - *Export & import* (new): download all settings as JSON and load them into another panel (users, nodes and keys are not in it).
- API: settings `def_gb`, `def_days`, `def_conns`; `update_repo` (GET returns the current source, PUT checks the owner/repo form); `/api/me` also returns the new-user defaults.

# v2.8.3 — Connection tutorial button, everything editable from the bot
- **Connection tutorial (🎬 آموزش‌ها):** in the bot's admin menu, tap «➕ آموزش جدید» and send the video (a gif, file, photo or plain text also works). The first line of the caption becomes the title and the whole caption is shown under the video. While there is no tutorial the button is hidden; as soon as one is saved:
  - the main menu shows «🎬 آموزش اتصال» (one tutorial: sent at once; several: a list),
  - the account message after a purchase, free trial, renewal or «سرویس‌های من» gets «🎬 آموزش اتصال و استفاده از اپ» as its first button, above the WireGuard / AmneziaWG / Hysteria2 config buttons,
  - the «📱 دانلود اپ» message gets the same button.
  Each tutorial can be previewed, renamed, given a new caption, have its video replaced, be made the main one (⭐️ first in the list, the one sent under the account message) or be deleted. Tutorials are stored as Telegram file ids in the `guides` setting, so they are part of every backup.
- **Buttons and texts (🎨 دکمه‌ها و متن‌ها):** the text of every customer button (main menu, account message, config buttons, payment methods, discount, back / main menu…) can be changed or reset to the default; main-menu buttons can also be hidden. Bot messages (welcome, menu reply, plan / category headers, trial / purchase / renewal headers, config hint, app download hint, tutorial list header) are editable too; a new message is previewed and only saved when Telegram accepts its HTML. Links (app download, support, required channel) have their own page.
- **Plans:** tapping a plan opens its page: change name, days, GB, Toman price, USD price, users, number of countries and category, turn it on/off, delete it (with confirmation). A new plan can be given a category as a 7th field.
- **Categories (📂 دسته‌بندی‌ها):** list of categories with the number of plans; rename a category (all its plans move with it) or remove it (its plans stay, without a category).
- After editing a value the bot goes back to the page it came from instead of the main admin menu.

# v2.8.2 — version bump
- Version number raised to 2.8.2 (panel, nodes and tunnel agents report 2.8.2). No other changes since v2.8.1.

# v2.8.1 — Tunnel servers menu, new tunnel animation, plan categories
- **Cleanup:** every trace of OpenVPN is removed from the code (module, auth route, sync fields, subscription page, config download, backup list, settings). The panel only has WireGuard, AmneziaWG and Hysteria2.
- **Bot:** after a purchase, free trial or "my service" the customer now gets (1) the app download link and the login code together as the recommended way, (2) the subscription link, and (3) buttons to receive manual configs one by one in a fixed order: WireGuard, AmneziaWG, Hysteria2. WireGuard/AmneziaWG arrive as files, Hysteria2 as a copyable link, one per server.
- **Bot:** the free trial can be taken only once per Telegram user (admins included). It is claimed before the account is created, so double taps cannot make two, and an existing trial account also counts.
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
