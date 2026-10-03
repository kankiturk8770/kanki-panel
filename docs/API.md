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

Protocols: `wg`, `awg`, `hy2`. Empty `nodes` = every node that accepts unassigned users.

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
| `/sub/kanki-<id>-<code>/json` | JSON for apps |
| `/api/config/:id/{wireguard,amneziawg,hysteria2}?sub=..&node=..` | config file; add `/qr` or `/uri` |

## Tunnels (Kanki Tunnel)
Scope `nodes` unless noted. Tunnel servers, tunnels and the panel's own tunnel endpoint.

| Method | Path | Notes |
|---|---|---|
| GET | `/api/tunnels` | `{servers, tunnels, panel, repo}`. Each tunnel carries `state` (`up`/`partial`/`down`/`off`), `entry_status`, `exit_status`, `dial_host`. Each server carries `online`, `host`, `version`, `last_seen` |
| POST | `/api/tunnels` | create (no `id`) or edit (with `id`). Fields: `name`, `entry`, `exit` (server ids; `local` = panel server), `mode` (`reverse`/`direct`), `transport` (`tcp`/`tcpmux`/`ws`/`wss`/`quic`/`kcp`), `port`, `conns`, `tcp[]`, `udp[]` (`443`, `8443:443`, `1000-1010`), `target`, `sni`, `path`, `dial`, `enabled` |
| DELETE | `/api/tunnels/:id` | remove a tunnel |
| POST | `/api/tunnels/:id/:action` | `enable`, `disable`, `restart` (restart = new token, both sides reconnect) |
| POST | `/api/tunnels/servers` `{name, addr?}` | add a tunnel server; returns `{id, token, panel, repo}` for the join command |
| PUT | `/api/tunnels/servers/:id` `{name?, addr?, new_token?}` | edit; `id=local` sets the panel's own reachable address (`tun_local_addr`) |
| DELETE | `/api/tunnels/servers/:id` | remove (fails while tunnels still use it) |
| POST | `/tunnel/agent` | **public**: a tunnel agent reports `{id, token, version, status[]}` every 5 s and gets back `{tunnels:[Spec]}`. Unknown/removed server → `410` (agent stops its tunnels); wrong token → `403` |
