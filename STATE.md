# STATE

## Phase 1 — server roles, user tiers, Xray CDN address, subscription status (done)

### Schema (forward-only, `src/core/db.rs` → `migrate_access`)
- `nodes.role TEXT NOT NULL DEFAULT 'hybrid'` — existing servers become `hybrid` (run everything, as before).
- `users.tier TEXT NOT NULL DEFAULT ''` — filled once from each account's protocols (`xray,hy2` → `v2ray`,
  WG/AWG/KANKI MIX only → `gaming`, anything else → `combo`); no protocol is removed. Idempotent on restart.

### Rules (`src/core/access.rs`)
- `Role`: `gaming` = kmix, wg, dns · `antifilter` = xray, hy2, awg · `hybrid` = all.
  Enforced as «effective off» in `cores::off_list` (sync + links), `kmix::settings`, `xray::panel::{runnable,cfg_for}`,
  `dns::panel::cfg_for`; switching a denied core on → 409 (`core`, `kmix`, Xray server/inbound, DNS server).
  The admin's own switches are never overwritten; back to `hybrid` restores them.
  An agent server is mapped to its role through its VPN node (`TServer.node`); without a node it is `hybrid`.
- `Tier`: `v2ray` = xray, hy2 · `gaming` = wg, awg, kmix · `combo` = all (incl. dns).
  Bulk «assign-all» (`api::assign_fits`) checks the tier; per-user manual edits stay free.
  Bot renewal with another tier → `combo` + union of protocols; trial → exactly the plan's tier.

### Xray
- `Inbound.cdn_address` (validated by `check_cdn_address`): links, subscription lines and client configs dial it,
  Host/SNI = the CDN domain; no direct / tunnel / server-CDN copies for that inbound.
- `client_config` / `user_client_configs`: full client JSON built from the share link (`link_outbound`), DNS from
  the panel's `dns` setting. Endpoints: `GET /api/xray/inbounds/:id/client/:uid`, `GET /sub/<code>/xjson`.
- `/api/xray/keys` adds `short_ids` and `uuid`.

### Subscription
- `/sub/<code>/{v2,xray,raw}`: status entry first (remaining GB and days, `⛔ <status>` when not active), only for
  accounts with Xray or Hysteria2; headers `subscription-userinfo` + `profile-title`. Hysteria2 links now also
  respect a switched-off (or role-denied) core.
- Domains are never hardcoded: addresses come from the Xray server settings, the node, the panel `DOMAIN` env and
  the `panel_name` setting.

### Tests
- `src/core/access.rs` (rules), `src/core/access_tests.rs` (HTTP: 401/403, bad input, role enforcement, tier
  guard incl. concurrent bulk edits, migration of an old DB, sub output), `xray::panel::cdn_tests`,
  `bot::flow_tests::purchases_follow_the_tier_and_upgrades_unlock_the_other_one`.

## Phase 2 — frontend (done)

### Backend additions for the UI
- `Role::Gaming` also runs AmneziaWG (gaming tier already had WG + AWG + KANKI MIX).
- Per-server switches for the agent cores: `access::{agent_off, set_agent_off, server_runs}` (setting `agent_core_off`);
  Xray (`xray::panel::{runnable,cfg_for}`) and DNS (`dns::panel::cfg_for`) run only where the switch is on.
- `POST /api/servers/:key/cores` (atomic, role-checked) and `switches` in `GET /api/servers`; `POST /api/servers`
  sets up Xray / DNS when ticked. `ensure_server` (Xray) / `ensure_exit` (DNS) create entries with nothing typed.
- Account page: `web_only` strips KANKI MIX from the browser page (rows and data block); `/sub/<code>/v2qr`.

### Admin panel (`assets/panel`)
- Users: «Edit» opens `userEditModal` (centered window, class `uedit`); the form has the tier selector
  (V2Ray / Gaming / Combo presets the cores) and one switch per core (Xray is a single switch, no inbound list);
  a core outside the tier is marked. «Xray users» filter tab on the Users page (`#users`, `goUsers('xray')`).
- Servers: Cores tab = six switches (`SW_CORES`, `srvCores`) posting to `/cores`; the add window has the same six.
- Xray: «Xray users» tab (`xrUsersTab`) with per-user configs (`xrUserCfgs`) and the full client config window
  (`xrClientCfg`: copy, copy link, download); the same `{ }` button in an inbound's user list; inbound form has
  «آدرس CDN (برای عبور ترافیک از CDN)» (`cdn_address`, hidden for REALITY / Shadowsocks / TCP / mKCP); the
  short-ID and key buttons use `/api/xray/keys` (`short_ids`).

### Account page (`assets/sub/sub.html`)
- Volume bar (what is left, orange < 30 %, red < 10 %), days count-down with its bar, status, connections.
- Cards only for this account's cores: V2Ray apps (sub link copy + QR + every Hysteria2 / Xray config),
  WireGuard / AmneziaWG (`.conf`, QR, keys per country), Kanki DNS. No KANKI MIX anywhere on the web page.

### Tests added
- `access_tests::one_switch_per_core_on_each_server` (401/403, bad input, atomic refusal, Xray/DNS off keeps settings),
  `api::account_page_tests` (KANKI MIX hidden for browsers, kept for the app; v2 QR access).

### Still open
- A role for an agent-only server (no VPN node yet) stays `hybrid` until its VPN part joins.
- Bot texts for the tiers.
