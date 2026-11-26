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

### Not in Phase 1
- Admin UI (servers role picker, tier selector, `cdn_address` field) and bot texts for the tiers.
- A role for an agent-only server (no VPN node yet) — it stays `hybrid` until its VPN part joins.
