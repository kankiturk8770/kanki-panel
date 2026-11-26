# REST API

Auth header: `Authorization: Bearer <token>`. Create tokens in **Security > API tokens** and pick scopes:
`users:read`, `users:write`, `nodes`, `settings`, `backup`, `admin` (everything).

## Users
| Method | Path | Scope | Body / notes |
|---|---|---|---|
| GET | `/api/overview` | users:read | counts, online, per-protocol totals |
| GET | `/api/users` | users:read | list |
| POST | `/api/users` | users:write | `username, traffic_limit_gb, days or expires_ts, max_connections, protocols[], nodes[], notes, count` |
| PUT | `/api/users/:id` | users:write | same fields + `add_days`, `add_gb`, `enabled` |
| DELETE | `/api/users/:id` | users:write | |
| POST | `/api/users/:id/:action` | users:write | `extend {days,gb}`, `reset`, `toggle`, `enable`, `disable`, `regen` |
| POST | `/api/bulk/users` | users:write | `{ids:[..], action, days?, gb?}` |

Protocols: `wg`, `awg`, `hy2`, `kmix` (KANKI MIX). Empty `nodes` = every node that accepts unassigned users.

## Nodes
| Method | Path | Scope |
|---|---|---|
| GET / POST | `/api/nodes` | nodes |
| PUT / DELETE | `/api/nodes/:id` | nodes |
| POST | `/api/nodes/:id/{toggle,drain,maint,sync,health,repair,update}` | nodes |
| POST | `/api/nodes/:id/assign-all` | nodes | node accepts unassigned users and is added to every user that has a node list |
| POST | `/api/nodes/:id/unassign-all` | nodes | the reverse (not allowed for `local`) |
| POST | `/api/node-join` | nodes | returns `{token, expires, panel, repo}`: one-time join token, valid 1 hour |

Public (no auth): `POST /join/register` with `{token, node_token, address, endpoint, insecure, name}`. Called by the installer; the panel checks the node answers on `address`, adds it and burns the token.

## Settings & backup
| Method | Path | Scope |
|---|---|---|
| GET / PUT | `/api/settings` | settings |
| POST | `/api/backup` `{passphrase}` | backup |
| POST | `/api/restore` (file body, headers `X-Passphrase`, `X-Full: 1`) | login session |
| GET / PUT | `/api/tgbackup`, POST `/api/tgbackup/{test,send}` | backup |
| GET / PUT / DELETE | `/api/app-msg` — PUT `{text (max 500), minutes (0 = until removed), users ("" = everyone, or usernames separated by commas)}` | settings |

## System
| Method | Path | Scope | Notes |
|---|---|---|---|
| GET | `/api/system` | admin | cpu %, load, memory, disk, uptime, service states |
| GET | `/api/live` | admin | `ts` (ms), `cpu_total` / `cpu_idle` (cumulative jiffies), `mem_*`, `swap_*`, `iface`, `net_rx` / `net_tx` (cumulative bytes), `tcp_est`, `tcp_listen`, `udp`, `load`, `cores`, `uptime`. Rates = difference between two samples |
| GET | `/api/logs?src=all&n=300` | admin | live log from journald. `src`: `all`, `panel`, `wireguard`, `amneziawg`, `hysteria2`, `web`, `node`. Returns `{src, lines:[{ts, p (priority 0-7), u (unit), m}]}` |
| POST | `/api/services/:name/:action` | admin | `name`: `wireguard`, `amneziawg`, `hysteria2`, `web`, `panel`, `node`. `action`: `start`, `stop`, `restart` (`web` / `panel` / `node`: restart only) |

## Public (no auth)
| Path | What |
|---|---|
| `/sub/kanki-<id>-<code>` | subscription page (older links with another prefix keep working) |
| `/sub/kanki-<id>-<code>/raw` | base64 list for v2rayNG / Hiddify |
| `/sub/kanki-<id>-<code>/json` | JSON for apps; `app_msg` is `{id, text, until}` (unix seconds, 0 = no end) while an app message is active for this user, else `null`. The same JSON is inside the subscription page (`<script id="data">`) |
| `/api/config/:id/{wireguard,amneziawg,hysteria2}?sub=..&node=..` | config file; add `/qr` or `/uri` |

## Tunnels (Kanki Tunnel)
Scope `nodes` unless noted. Tunnel servers, tunnels and the panel's own tunnel endpoint.

| Method | Path | Notes |
|---|---|---|
| GET | `/api/tunnels` | `{servers, tunnels, panel, repo}`. Each tunnel carries `state` (`up`/`partial`/`down`/`off`), `entry_status`, `exit_status`, `dial_host`. Each server carries `online`, `host`, `version`, `last_seen` |
| POST | `/api/tunnels` | create (no `id`) or edit (with `id`). Fields: `name`, `entry`, `exit` (server ids; `local` = panel server), `mode` (`reverse`/`direct`), `transport` (`tcp`/`tcpmux`/`ws`/`wss`/`quic`/`kcp`/`cdn`), `port`, `conns`, `tcp[]`, `udp[]` (`443`, `8443:443`, `1000-1010`), `target`, `sni`, `host`, `path`, `dial`, `frag`, `enabled` (`cdn`: `dial` = CDN edge addresses, `host` = CDN domain, `sni` = TLS names, `frag` = split the TLS hello; always `direct`) |
| DELETE | `/api/tunnels/:id` | remove a tunnel |
| POST | `/api/tunnels/:id/:action` | `enable`, `disable`, `restart` (restart = new token, both sides reconnect) |
| POST | `/api/tunnels/servers` `{name, addr?}` | add a tunnel server; returns `{id, token, panel, repo}` for the join command |
| PUT | `/api/tunnels/servers/:id` `{name?, addr?, new_token?}` | edit; `id=local` sets the panel's own reachable address (`tun_local_addr`) |
| DELETE | `/api/tunnels/servers/:id` | remove (fails while tunnels still use it) |
| POST | `/tunnel/agent` | **public**: a tunnel agent reports `{id, token, version, status[]}` every 5 s and gets back `{tunnels:[Spec]}`. Unknown/removed server → `410` (agent stops its tunnels); wrong token → `403` |

## v2.5 additions
| Method | Path | Notes |
|---|---|---|
| POST | `/api/plans/bulk` `{plans:[{name,days,gb,toman,conns,countries}], replace?, rules?}` | add many plans (smart builder); `replace` deletes the old ones first |
| PUT | `/api/plans/:id` `{active?, toman?, name?}` | show / hide or edit a plan |
| GET / POST | `/api/discounts` `{code, percent, uses, hours}` | list / add codes (`hours` 0 = no end) |
| DELETE | `/api/discounts/:code` | remove a code |
| GET / PUT | `/api/channel` | smart channel settings: `on, id, hours, kinds, sign, code, auto_offer` |
| POST | `/api/channel/preview` `{kind}` | build a post (`auto` or a kind) without sending |
| POST | `/api/channel/post` `{text, kind?}` | publish to the channel |
| POST | `/api/channel/campaign` `{percent, hours, uses, post?}` | new expiring code + offer post |
| POST | `/api/db/clean` | clean and compact the database |
| GET / PUT | `/api/tgbackup` | also `mode` (`nightly`/`hours`), `at` (`03:00`, Iran time), `pass` |
| POST / GET / DELETE | `/api/tunnels/probe` | smart tunnel: start `{entry, exit, mode, port}`, read progress + ranking, stop |


## KANKI MIX
- `GET /api/kmix` (scope `nodes`): settings, every server with its port, state, users and error, user and traffic totals.
- `PUT /api/kmix` (scope `nodes`): any of `on`, `port`, `parity` (0-10), `gaming`, `hop` ("first-last" or ""), `nodes` (`{"<node id>": {"off": bool, "port": n}}`). A port that clashes with a server's WireGuard / AmneziaWG / Hysteria2 port is refused.
- `POST /api/kmix/users` (scope `users:write`): `{"on": true}` adds KANKI MIX to every user, `{"on": false}` removes it.
- Subscription data (`/sub/<code>/json`): each node has `kmix` (the `kanki://` link or null). `GET /api/config/<id>/kankimix[/qr]?sub=…&node=…` returns the link or its QR code.

## Server roles, user tiers, Xray CDN address (Phase 1)
- Server role: `POST /api/servers/:key/role` (scope `nodes`) `{"role": "gaming" | "antifilter" | "hybrid"}`. `gaming` runs only KANKI MIX, WireGuard and Kanki DNS; `antifilter` only Xray, Hysteria2 and AmneziaWG; `hybrid` (every server from before) runs everything. A core the role does not run counts as off (no service, no link); switching it on answers `409`. Servers (`GET /api/servers`) show `node.role`; `core_off` is the effective list.
- User tier: `tier` on `POST /api/users` and `PUT /api/users/:id`: `v2ray` (Xray + Hysteria2), `gaming` (WireGuard + AmneziaWG + KANKI MIX) or `combo` (everything). A new user with a tier and no `protocols` gets that tier's protocols. Users show `tier`. Existing accounts got the tier their protocols already made.
- «Give everyone» `POST /api/protocols/:proto/assign-all` (scope `users:write`) only adds the protocol to users whose tier has it. One user's own protocols can still be changed by hand.
- Bot purchases: a plan enables only its tier's cores; renewing an account with a plan of the other tier makes it `combo` and adds that tier's cores (nothing is removed).
- Xray inbound `cdn_address` (in `POST /api/xray/inbounds`): a domain behind the CDN or a clean CDN IP (then the CDN domain comes from `host` or the server's CDN domain). When set, every link, subscription line and client config of the inbound dials it; only CDN-capable inbounds (WS / HTTPUpgrade / XHTTP / gRPC, CDN ports, not REALITY / Shadowsocks) take it.
- `GET /api/xray/inbounds/:id/client/:uid` (scope `nodes`): `{link, config}`, the share link and the full Xray client config of one inbound for one user. `POST /api/xray/keys` also returns `short_ids` (2, 4, 8 and 16 hex digits) and a `uuid`.
- Subscriptions `/sub/<code>/v2`, `/xray`, `/raw`: for accounts with Xray or Hysteria2 the first line is a status entry whose name shows the remaining volume and days (refreshed on every update); headers `subscription-userinfo` and `profile-title` (`base64:` of «panel name · user»). `/sub/<code>/xjson`: every Xray link as a full client config (JSON array).

## Phase 2 additions
- `POST /api/servers/:key/cores` (scope `nodes`) `{"wg"?, "awg"?, "kmix"?, "dns"?, "xray"?, "hy2"?: bool}`: switches the given cores of one server at once (all checked first, `409` with the reason when one cannot run there). A core switched off keeps its settings (Xray inbounds, the DNS entry); Xray and DNS switched on for the first time get a server entry with nothing to type. `GET /api/servers` gives each server `switches: {role, cores: {core: {can, on, why}}}`. `POST /api/servers` takes `xray` and `dns` in `cores` too.
- Server roles: `gaming` now runs AmneziaWG as well (KANKI MIX, WireGuard, AmneziaWG, Kanki DNS). New servers stay `hybrid`; the per-core switches are the normal way to choose what a server runs.
- `GET /sub/<code>/v2qr`: QR code (SVG) of the combined V2Ray subscription link (accounts with Xray or Hysteria2).
- The account page a browser gets never shows KANKI MIX (no row, no address, nothing in its data block). The Kanki app's sealed page and `/sub/<code>/json` are unchanged.
