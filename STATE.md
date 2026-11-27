# STATE

## 3.67.2 — bare subscription code in the header (done)
- `/sub/me[/<kind>]` with `X-Kanki-Sub: <digits>` (only the code part, 10–32 digits, no `kanki-<id>-`) finds the
  account by `Db::user_by_bare_code` (parameterized, exactly one match, constant-time compare); none or two → 404.
  The answer is the plain page (the app asks without `X-Kanki-Seal`, since the seal key needs the full code); the app
  reads the full code from it and logs in sealed as before. Test: `the_bare_code_in_the_header_finds_its_account`.
- Kanki app 1.45.1 depends on it only for bare codes; `kanki-<id>-<code>` and `/sub/h/` work on 3.65+.

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

## Phase 3 — 3.65.0: one server agent, signed requests, hashed sub links, Xray presets (done)

### Emergency chat removed
- `src/emergency/`, `assets/emergency/`, `/api/emergency*`, the `emer_*` settings (deleted by `db::migrate_access`, signing
  key and admin hash included), the sub data fields `emergency` / `emergency_key`, backup of `chat.db`, the UI page and
  translations. The Android app only parsed those fields (no UI), it tolerates their absence.
- Servers clean up after it on start (`sync::retire_emergency`, via `forget_retired`): service, unit, firewall port,
  `/etc/kanki/emergency.json`, `/var/lib/kanki/emergency`. Agents from before get `"emergency": {"mode":"off"}`.
- The logs that lived under it are their own page: `#logs` (`pLogs`); old `#emergency/...` links redirect there.

### Iran = abroad (`servers.rs`)
- `new_server(.., with_vpn)`: the VPN part is installed when it serves users or a VPN core is ticked — same rule for both
  locations (only the SSL default still differs: port 80 is often closed in Iran).
- `cores_state`: an agent server without its VPN part can switch every core (`can: true`); `vpn_part`, `installing`.
- `cores_set`: a VPN core switched on there calls `ask_vpn_install` (shared with `/complete`; agent must be connected and
  ≥ `SETUP_FROM`; cores merged into `TServer.cores`, switched on at `joined`); off removes it. `install_lock` serializes.
- Gone: `iran_relays`, `POST /api/servers/drop-iran-vpn`, the Iran-only UI branches (relay box, «relay mode» note,
  Iran-only steps, Iran-only «Remove the VPN»).

### Signed panel ↔ agent requests (`src/core/sign.rs`)
- Headers `x-kanki-ts`, `x-kanki-nonce`, `x-kanki-sig` = HMAC-SHA256(token, "kanki-sig-v1\n ts\n nonce\n METHOD\n path\n
  sha256(body)"); window `MAX_SKEW` = 300 s; replayed nonces refused (bounded cache, 50 000).
- Node: every `/agent/*` route behind `api::node_signed` (2 MiB cap). Unsigned / bare `X-Node-Token` → 401.
- Panel → node: `sync::node_call` signs; the bare token is sent only as a retry after a 401 from a node that never reported
  ≥ `SIGN_FROM` (3.65.0).
- Server agent → panel `/tunnel/agent` (`REPORT_PATH`): signed; the panel accepts the bare body token only until the server's
  first signed report (`TServer.signed` ratchet). The agent adds the token only if the panel answers 403 (older panel),
  re-tried without it every 10 min, never again once a signed report was taken.
- `/hy2/auth` (Hysteria cannot sign): loopback as before plus `?k=` key — `hy2::ensure_auth_key` adds it to Hysteria's auth URL
  once (rollback if Hysteria does not start) and keeps it in `/etc/kanki/hy2-auth.key` (0600).
- Connection reuse: `pin::{POOL_IDLE, TCP_KEEPALIVE}` on every panel/agent client; the agent reads its listeners every 15 s
  instead of every report.
- Not signed yet (token in body/header as before): `/tunnel/binary`, the hy2 tunnel binary, the Xray zip download, `auth.rs`
  agent routes.

### Subscription codes out of URLs (`src/subscription/sublink.rs`)
- `/sub/h/<hash>[/<kind>]`: hash = HMAC-SHA256(setting `sub_link_key`, code)[..40]; index cached, rebuilt at most every 5 s
  on a miss; a found user is re-checked against its current code. `v2_sub_link`, the bot, mini app and account page
  (`sub_hash`) hand out this form.
- `/sub/me[/<kind>]` with `X-Kanki-Sub: <code>` or `Authorization: Bearer <code>`.
- Both answer `Cache-Control: no-store`, `Referrer-Policy: no-referrer`; `/sub/<code>/…` keeps working.
- Still with the code in the URL: the account page's own config links (`/api/config/…?sub=`), part of the app contract.

### Xray presets (`03-xray.js`, `XR_PRESETS`)
- «REALITY مستقیم» VLESS/TCP/REALITY/vision/chrome · «مخصوص CDN» VLESS/XHTTP/TLS (marks `cdn_address`) · «مخصوص تانل ایران»
  VLESS/XHTTP auto/none · «مستقیم حرفه‌ای (Trojan)» Trojan/gRPC/TLS/fragment. No domain is filled in: the REALITY target
  and the CDN address are marked for the admin (`xrMark`); the old default/presets no longer prefill a REALITY target.
- `Inbound.fragment` (TLS only, cleared otherwise): links get `fragment=tlshello,100-200,10-20`; `client_config` adds a
  `fragment` freedom outbound and `sockopt.dialerProxy`.

### Tests
- `sign::tests` (pass once, every change refused, concurrent replay), `sign_tests` (node 401s incl. bare token, replay, body
  swap, other route, oversize 413; agent report ratchet; hy2 key), `access_tests::{an_iran_server_switches_on_vpn_cores_like_one_abroad
  (incl. two concurrent switches), the_subscription_works_without_its_code_in_the_url, the_four_xray_presets_save_and_the_fragment_reaches_the_clients}`,
  `servers::tests::iran_and_abroad_follow_the_same_rules`, `sublink::tests`, `hy2::tests::the_auth_url_gets_a_key_once`,
  migration test (emer_* deleted), `backup::tests::a_chat_database_in_an_old_backup_is_left_out`.

### Still open
- `REALITY_TARGETS` (the suggestion list in the Xray form) still names public sites; nothing is filled in from it by itself.
- Rollout order: update the panel first, then «Update all» (new nodes refuse the bare token of an older panel).

## Phase 4 — 3.66.0: the Telegram bot, clean and tier-aware (done)

### Right-to-left layout (`bot.rs`: `rtl_lines`, `rtl_body`)
- Every HTML text / caption the bot sends (`call_res`) gets U+200F in front of each line that holds Persian, so a line
  that starts with a Latin word (`1️⃣ v2rayNG …`) no longer flips and its period stays at the end. Outside every tag (a
  tapped `<code>` copies only its content); `<pre>` lines, Latin-only lines and plain-text calls are left alone; a text
  that would pass Telegram's limit (4096 / 1024) with the marks goes as it was.
- The fake Telegram of the tests strips the marks and counts them in `_rlm`.

### Purchase flow
- `SERVICES` buttons: «ضد فیلتر (V2Ray / Hysteria)», «گیمینگ (WireGuard / Amnezia / KankiMix)», «ترکیبی (همه سرویس‌ها)»; the
  lowest prices are lines of the text (`service_name`).
- Plans: one numbered line each in the text (`plan_line`), short numbered buttons (`plan_no` + `price_short`) in rows of 2
  (≤ 4 plans) or 3 (`grid`). `plan_button` is gone.
- Plan page: payment methods two a row, «کد تخفیف دارم» beside «بازگشت». Card number in `<code>` as digits only
  (`card_digits`); crypto coins three a row with a way back; prompts in short lines.
- «سرویس‌های من» / renewal: accounts two a row.

### Delivery (tier = `User::tier()`)
- `keys_text`: the Kanki activation code alone in `<code>` always; the V2Ray subscription link (hashed, `<code>`) only for
  `v2ray` / `combo` (`tier_has_sub`), first for a V2Ray account. Same in `account_text`, `delivery`, `trial_delivery`.
- `account_btn`: «🌐 صفحه‌ی حساب», a URL button to `sub_origin()/sub/h/<hash>` (origin from the panel's settings, never typed).
- `acct_kb` offers the V2Ray link only to its tiers; `cfg:<id>:v` of a gaming account answers why not.

### Setup guides
- Device menu: the tier's apps first (`tier_apps`) and marked ✅ (green), the first «(پیشنهادی)»; the tier named on top.
- v2rayNG (Android): 4 steps; buttons «دانلود مستقیم v2rayNG (arm64)» / «دانلود نسخه عمومی (Universal)» to the 2.4.2 files
  and the release page as fallback (`V2RAYNG_*`); no Google Play. The same buttons under the V2Ray link message.
- AmneziaVPN (Android): «دانلود از Google Play» (`AMNEZIA_PLAY`), 4 steps. iOS / Windows / WireGuard / Kanki app: the same short
  lines.

### Tests
- `flow_tests::the_delivery_and_the_guides_follow_the_tier` (code always, sub link only for v2ray/combo, hashed account
  button without the code, marks sent, gaming menu without V2Ray, v2rayNG buttons and URLs, AmneziaVPN Play and 4 steps),
  `persian_lines_start_right_to_left_and_nothing_else_changes`, `a_card_number_is_copied_as_digits`; the purchase tests now
  check the tier labels, the price lines, the numbered buttons and their 2–3 columns.

## Phase 5 — 3.67.0: KANKI MIX protocol 3 (server + panel), old apps unchanged (done)

### Routing hints and roaming (`internal/obfs/hints.go`, `internal/proto/hello.go`, `cmd/kanki-server/hello.go`)
- New kinds `KindHello` (0x09, client→server: session, version, caps, send time) and `KindHelloAck` (0x0A: the same +
  an 8-byte hint + its life). Both ride inside the obfs AEAD with the user's key; an old server drops unknown kinds
  silently, an old app never sends one. A hello older/newer than 2 min gets nothing (no replayed hint).
- A protocol 3 client puts the hint in front of its packets: `[8B hint][12B nonce][AEAD…]`. `Keyring.open` looks the
  hint up first (O(1) map → that one user's key), learns the new address for the answers, then the old way (known
  address, then the rate-limited scan of every key) for old clients. A hinted packet from a known address with an
  ended hint is still opened with that user's key.
- Hints: random, unique, `HintTTL` 10 min, the newest 4 per session, 200 000 in all; a removed user's hints end at
  `Keyring.Set`; expired ones pruned every minute.
- `HelloCapGaming`: every UDP flow of the session except DNS (port 53) is a game from its first packet; the session gets
  smart protection at once (`smartFromHello`: caps repair/copy/multi).

### Gaming path
- `limiter.go`: while a user's game plays (a game packet within 2 s), their TCP downloads are paced by a per-user token
  bucket on the read from the far server (TCP flow control, nothing dropped); AIMD from the app's loss reports (>15 ‰ ×0.7,
  <5 ‰ +96 KB/s, 160 KB/s–5 MB/s); no limit with no game.
- `internal/game/policy.go`: repairs in proportion to the measured loss — none under 4 ‰, else one per
  `round(1000 / (3·loss‰))` packets (1–64), at most every 2 on runs of loss, a copy at ≥ 200 ‰; down halfway per calm 4 s.
  `startPlan` (one per 16) only before the first measure or when reports stop.
- KCP: links say `fec=10-0` (parity default 0, `kmix_parity` default changed; `fec=0` alone is read by apps as 10-3).
  The server has a third listener without FEC for `KindKCP` without FEC framing (`obfs.Bare`, `FECFramed`: byte 4 =
  0xf1/0xf2), and answers framed KCP with `-fec-legacy` (the last parity above 0, setting `kmix_parity_legacy`, default 3),
  so links still on phones keep working. kcp-go also decodes either form on input.

### Panel
- Multiple Iran entries (`kmix::tunnel_entries`, `tunnel::panel::udp_entries`): every Iran server whose tunnel carries
  the KANKI MIX UDP port, nothing typed (3.61 rule kept). The first stays the `<id>@tunnel` entry; the others are entries
  `<id>~<k>@tunnel` (k = 2…4; the app reads any id ending in `@tunnel` as a tunnel entry) in the data block, the page and
  `/api/config/…kankimix?node=`; other protocols refuse them (404). The direct link's `alt` lists all of them (the app uses
  two). `NodeOpt.tun_skip` leaves an Iran server out (KANKI MIX page › Tunnel, a switch each; ids validated).
- Telemetry: Go `GET /health` (sessions, gaming, hinted, users, weighted average loss ‰ of the last minute, fec) +
  node-side `hop_state` (NAT rule really in place) → `SyncResp.kmix_health` (serde default: older nodes read as Null) on
  the signed `/agent/sync` → `kmix::note_health` (only known bounded numbers kept) → `GET /api/kmix` `servers[].health`.
  UI: status tiles «نشست‌های زنده» / «میانگین افت (بازی)», and a live line per server (sessions, gaming, fast roaming,
  loss, extra ports active).

### Tests
- Go: `hints_test.go` (O(1) roaming even with the IP's scans used up, old format beside, unknown/ended hints, removed
  user, load under `-race`), `hello_test.go` over real UDP (hello → hint, roam to a new socket, game from the first packet,
  DNS not, answers to the new address, replayed hello refused; old ping unchanged; KCP 10-0 and 10-3 both echo; limiter;
  health average), `game_test.go` (zero on clean, proportional cost, calm-down).
- Rust: `access_tests::{kmix_links_have_no_fec_and_one_entry_per_iran_tunnel, kmix_health_comes_with_the_sync_and_is_cleaned}`.

### Still open
- The client side (kanki-app `kmix-core`) does not send `KindHello` or hinted packets yet: until it does, every app uses
  the old path. The server side, the panel and the tests are ready for it.

## Phase 6 — 3.67.1: config downloads by header (done)
- `/api/config/<uid>/<proto>[/<extra>]` takes the subscription code from `X-Kanki-Sub` (or `Authorization: Bearer`)
  when `?sub=` is absent (app 1.45 never puts the code in a URL); the account must match the path's id; sealed
  answers use the same code. Tests: header ok, wrong code / other account's id / no code refused.
