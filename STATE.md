# STATE

## 3.71.0 — Phase 4: account page safety, five-tab panel, dead code out, UI bugs from the video audit (done; branch `ccr-94a1e97e-wsl617`)
Kept as they were: the HttpOnly cookie login, step-up password prompts (`/api/security/*`, backup passphrase reveal),
`POST /api/users/:id/upgrade`, the server role selector, the default-tier selector, every API the bot / mini app uses.

Account page (`assets/sub/sub.html`, `api::sub_page_of`)
- No flash: the shell stays hidden (`html:not(.ready)`) until the script filled it, a spinner meanwhile, shown anyway
  after 3 s (CSS animation) or without JS (`<noscript>`). The English labels stay in the markup (the app's fallback
  reads «Data remaining»).
- No secret in the markup: Hysteria2 / Xray rows show `scheme://••••@host:port` (`mask_uri`); their copy buttons
  fetch the link when tapped (`data-fetch`: `/api/config/<id>/hysteria2?…`, new `GET /sub/:code/xl/:i`); «copy all»
  fetches them all. The browser's data block drops `nodes[].hy2` and `xray[].link` (`web_only`); the app's sealed
  page keeps them.
- Data block: `script_json` escapes `<`, `>`, `&`, U+2028/2029 as `\uXXXX`; the template is filled in one pass
  (`fill`), so a name holding `{{DATA}}` or `</script>` cannot break out.
- Three plans: `tier` / `tier_name` in the data; a plan pill; v2ray shows only the V2Ray card, gaming WG / AWG / DNS and
  the Kanki app, vip everything. Footer translated; relative times isolated (`۲ ثانیه پیش`, «همین الان» under 5 s).

Navigation (`13-menu.js`): five sections in the side menu and the phone bar (each a fifth of the width):
Home (Dashboard, Logs) · Users · Infrastructure (Servers + role, Cores, WG, AWG, HY2, KANKI MIX, Xray, DNS, Tunnels,
Ports & firewall) · Reports (Traffic, Bot, Audit) · Settings (Settings, Security, Backup & move). Live dots only on core tabs.

Removed
- `assets/panel/js/04-antidpi.js` (the Anti-DPI page): its inbound methods are the Xray editor's presets, its
  transports the Tunnels page; `#antidpi` redirects to `#xray/inbounds`; the cores page links both.
- Settings › Export & import (`stExport`, `stImport`, `ST_SKIP`, the `io` section, the Backup page's link to it): it
  duplicated Backup and wrote payment keys to a plain JSON file.
- 772 Persian strings no script or server answer used any more (`08-translations.js` 276 KB → 184 KB); the CSS of the
  removed parts. No shop / plan / discount / channel editor was left in the web UI; their APIs stay (the mini app).

Fixes
- Dashboard: errors of the last 30 min make it «Needs attention» with a readable line (`errText`: the message, host
  and error of a Caddy JSON line, not the raw object). CPU: smoothed and held near the load average; cores from
  `/proc/cpuinfo`, else `available_parallelism`.
- One server count (`fleet()`): every machine once; «VPN exits» = VPN part that serves users (not panel / iran roles,
  not off). Dashboard KPI, panel card and the cores page use it. Node `users` = users the server really serves with
  one of its cores, `users_by` per core (same as the cores' cards). KANKI MIX: one «online now» (live sessions when
  the servers report them).
- Users: opens on «All»; plan filter chips; a VIP upgrade box in the user window (`POST /api/users/:id/upgrade`);
  amounts `12.19 GB`; money `۲,۲۵۳,۰۰۰ تومان` (`money`).
- Mobile: one core per full-width row in the user form, plan buttons stacked, dark text on the gold VIP plan; protocol
  chips wrap under the name; list rows and stat titles wrap; page tabs scroll whole; the settings save bar sits above
  the phone bar and the page has room under its last card.
- Xray: no flow (no «Vision» badge) unless VLESS + TCP + TLS/REALITY; unique names (empty = `PROTOCOL-TRANSPORT`, a used
  one `-2`, `-3`, clones too).
- DNS › Services replaces the old tab at once (icons fill in later, only if still open). Tunnels: the map's Iran tab and
  the list's server filter are one choice. Ports: every server from `/api/servers` (Iran servers without a VPN part
  from what their agent reports listening, `agent.listen`); one name per machine (a server's node takes its name).
- Times: every panel date is Tehran time (the nightly backup at 03:00 showed as 04:30 in a browser on UTC+5).
- Texts: «2FA code required» and the other 2FA answers, «توقف», «باز», «گزارش‌ها»; «لاگ اتصال‌ها» was already right.
- Speed: refresh default 15 s (setting `refresh`; panels on 5 / 10 moved once), every page timer uses it
  (`refreshMs`); pages opened again show their last data at once (`SWR`, ≤ 2 min, dropped on any change) and redraw
  when the real answer differs; grey skeletons (`skel()`) instead of «Loading…».

Tests added: `account_page_tests::{the_account_page_leaks_no_secret_and_cannot_be_broken_out_of,
template_marks_are_filled_once_and_links_are_masked}`, `access_tests::inbound_names_are_unique_and_vision_is_only_where_it_works`.
Checked in Chromium (390 px): login, the five sections and every tab, no script error; the user form; the account page.

Reports › Audit (`p_audit`, from `GET /api/security`, admin login only): the last 100 changes (method, path, status, who,
from where, when), the last 50 sign-ins, and whether the audit's hash chain is intact.

## 3.70.0 — Phase 3: bot / mini app hardening, one account with three plans, server roles (done; branch `ccr-94a1e97e-wsl617`)
Nothing a user has changes: subscription codes (old ones and the 39-digit ones of 3.69), keyed credentials, links and
every protocol an account has today stay as they are. Only the stored tier name `combo` is now `vip`.

Mini app (`src/bot/miniapp.rs`, `assets/bot/miniapp.html`)
- Init data ONLY in `X-Tg-Init` (max 4 KiB); `?init=` is gone everywhere. `INIT_MAX_AGE` 24 h → 1 h.
- `/tg/api/{buy,trial,send,upgrade,file}` are POST with a JSON body (16 KiB cap) and a one-time `X-Tg-Nonce`
  (16–64 `[A-Za-z0-9_-]`, table `tg_nonces`): missing/bad 400, replayed 409. The admin bridge (non-GET),
  `/admin/buttons` POST and `/admin/paths` POST need a nonce too. GET on a changing route → 405.
- Customer routes take only init data signed by the SALES bot token (`who`); the report bot's never names a customer.
  Admin routes check the numeric id against the list of the bot that signed (`signed_by` → `Signer`): sales routes
  (gift, bridge, buttons save, ask, preview) only sales admins signed by the sales bot; paths/monitor/buttons read
  either bot's own admins. New `GET /tg/api/admin/whoami` (the admin pages open with it instead of `/tg/api/me`).
- `/tg/api/file`: `POST {uid,p}` → one-time ticket (`tg_tickets`, 120 s, bound to tg id + account + platform,
  deleted on use with `DELETE … RETURNING`); `GET ?t=` serves it (Telegram's downloadFile cannot send headers). The
  account is re-checked to still belong to the ticket holder. Other customers' accounts are 404 on every route.
- Bridge path check: only `[A-Za-z0-9/_.-]`, ≤ 128 bytes, no `..`, `//`, trailing `/`, `%`-escapes or `\`; an id
  after a prefix is one plain segment. Emoji ids digits only; the page loads emoji pictures as header-fetched blobs.
- Gift one-time keys persisted in SQLite (`gift_nonces`), no longer an in-memory map.

Payments and deliveries (`src/bot/bot.rs`, `pay.rs`, `shop.rs`, `core/db.rs`)
- `Db::immediate` = `BEGIN IMMEDIATE` … COMMIT / ROLLBACK; `db::txn::*` are the connection-level account changes
  (create_user, renew_plan, gift, promote_trial, upgrade_tier, use_payment); `Db` methods call them.
- `fulfill` → `deliver_tx` in ONE transaction: order `done` (never from `rejected`/`failed`), account
  create/renew/trial-convert/upgrade, discount `uses_left-1`, renewal bonus, referral bank, inviter reward, offer reset.
  Any error rolls all of it back, then the order is `error` and the admins told. Upgrade plans only pay their own
  account's upgrade (`upgrade:<id>` category, checked in `deliver_tx`, `pay`, `np_start`, receipts).
- Payment ledger `pay_tx(id PK)`: TON hashes, Stars charges, `np:<id>` / `zp:<ref_id>`; recorded in the same
  transaction that moves the order out of `waiting` (`claim_payment`); backfilled from paid orders at migration.
- TON: only `finality == finalized` (missing = not final), message destination = the transaction's wallet, `recent()`
  keeps only transactions of exactly our wallet, no successful bounce, exact comment (trim only; case and inner spaces
  count), integer nanoton ≥ the order's.
- Gateways: `gateway_state` → `GwState::{Paid, Waiting, Partial, Failed, Error}` (`np_state`, `zp_state`, 15 s
  timeouts). `partially_paid` → order `partial` + customer + admins; `failed`/`expired`/`refunded`, ZarinPal -51/-54/-55/-50
  → `failed` + customer; a failed verify call decides nothing.
- Receipts: rejection sets `rejected` + `decided` time; the customer gets a clear notice; after 2 rejected receipts in
  24 h no new receipt is taken (`REJECT_LIMIT`). Trial claim + account, prize claim + account: one transaction each.
- Referrals: self, missing inviter and loops (A↔B) give nothing; reward + bank inside the delivery transaction.

Three plans, one account (`src/core/access.rs`)
- `Tier::{V2ray, Gaming, Vip}`: v2ray = xray, hy2 · gaming = kmix, awg, wg, dns · vip = all six. `combo` reads as vip.
  `Tier::clamp/outside/upgrades_to/label`. `service_protocols`: game = admin's wg/awg choice + KANKI MIX + DNS always;
  vip = every core (no longer `default_protocols`).
- Panel: `POST /api/users` without tier/protocols uses setting `default_tier` (default vip) and exactly its cores;
  protocols outside the tier → 400 on create and edit; a tier change without a list takes the new tier's cores.
  «New user» settings section = a default-tier select (`default_tier`, validated); the user form locks out-of-tier cores.
- In-place upgrade: `POST /api/users/:id/upgrade {tier:"vip"}` (users:write) and the bot button «⬆️ ارتقا به ترکیبی VIP»
  (`upg:<id>`) / mini app `POST /tg/api/upgrade`. Price = vip − own service for what is left (`shop::upgrade_price`),
  paid with a hidden plan; id, code, credentials, quota, usage and expiry unchanged; only from v2ray/gaming, once.
- Migration (`migrate_phase3`): `combo` → `vip`; any account whose tier does not cover its protocols → `vip`.

Server roles
- `Role::{Gaming, Antifilter, Hybrid, Panel, Iran}`: gaming = kmix, wg, awg, dns · antifilter = xray, hy2 · panel/iran =
  no core and no VPN user (`Db::serves`). `panel` only for node `local`. Antifilter servers that had AmneziaWG on keep it
  (`antifilter_awg_keep`, set once; `access::node_allows`). Role select in the server's Cores tab.

Tests added
- `miniapp::tests::{changes_are_one_time_posts_from_the_sales_bot_only, the_backup_download_is_a_one_time_ticket_of_ones_own_account,
  admin_routes_check_the_signing_bots_own_admins}`; `flow_tests::{one_order_delivered_at_once_many_times_gives_one_account,
  a_failed_delivery_rolls_everything_back, an_upgrade_to_vip_keeps_the_same_account, a_trial_asked_at_once_many_times_is_given_once,
  rejected_receipts_stop_more_fake_ones, referrals_never_loop, gateway_answers_map_to_one_state_each}`, the TON test (exact comment,
  permanent ledger); `pay::tests` (finality missing, bounce, wrong destination); `access_tests::{a_369_database_keeps_every_user_and_payment,
  panel_and_iran_servers_carry_no_vpn_user, the_panel_upgrades_an_account_in_place}`; tier tests rewritten.

Not done / needs the owner
- No bot flow-map source exists in either repo; nothing to fix there (the bot's own texts were updated).
- The Kanki app needs no change: gaming accounts now carry `kmix` and `dns`, which the app already unlocks from the
  subscription data.
- Telegram's `answerCallbackQuery`/receipt photos are unchanged; ZarinPal is still checked when the customer taps
  «check» (NOWPayments every minute).

## 3.69.0 — Phase 2: supply chain, mutual fleet signing, Iran relay, KANKI MIX hops, authenticated backups (done; branch `ccr-94a1e97e-wsl617`)
Nothing a user has changes: existing subscription codes, WireGuard/AWG/KANKI MIX/Hysteria2/Xray credentials and links
stay byte for byte (only accounts made or renewed from now on get the new code length and keyed credentials).

Phase 1 re-check (fixed here)
- `/api/restore` (128 MiB): a login session is checked in the middleware before the body (an API token was buffered,
  then refused). `/api/apps` (200 MiB) was already pre-auth. Test: `auth::tests::strangers_cannot_fill_the_audit`.
- Leaks found and closed: `GET /api/tgbackup` returned the backup passphrase in plaintext; `GET /api/xray/config/:id`
  and `/api/xray/inbounds/:id/json` returned REALITY `privateKey` (now `xray::panel::mask_private`). Bot/report/AI/
  payment tokens were already masked. Panel JS already used the HttpOnly cookie + `X-Kanki-Admin` and step-up.

Supply chain (`src/core/release.rs`)
- Pinned SHA-256: Hysteria2 `app/v2.14.0` (amd64/arm64/arm/386, from its hashes.txt), Xray-core `v26.11.9` (3 zips,
  from the `.dgst` files), Caddy `2.11.9` (amd64/arm64/armv7 tarballs; release publishes SHA-512, SHA-256 computed from
  the same files). install.sh carries the same values (a test compares them).
- Hysteria2 (agent `hy2t::ensure_bin`, panel `/tunnel/hy2bin`, install.sh `hy2_install`): pinned release only, hash
  checked before the file is started or moved in place; `get.hy2.sh` (remote root script) removed everywhere. An already
  installed hysteria keeps running.
- Xray (`xray::install`): pinned release only, `sha256sum -c` before unzip/exec; `/tunnel/xraybin` hands out only the
  pinned zip. An installed Xray (`latest` or the admin's version) is kept, no restart; a new install of another version
  is refused with a message.
- Caddy fallback (no distro package): pinned GitHub tarball, hash checked, then run (no caddyserver.com build).
- `/tunnel/hy2bin/put` (agent uploads): 410; the `check` call always answers `have: true`, so agents of before never upload.
- Self-update (`admin::self_update`, node `/agent/update`, agent `update_from_panel`): minisign signature (Ed25519,
  plain or BLAKE2b-prehashed) verified with the key compiled in from `KANKI_UPDATE_PUBKEY` BEFORE `swap_program` runs
  `<file> version`; the version comes from the signed trusted comment (`kanki-panel <ver>`), downgrades refused. The
  signature is kept in `/etc/kanki/kanki-panel.minisig`, served to agents (`x-minisig` on `/tunnel/binary`,
  `/dl/kanki-panel.minisig`). A build without the key updates nothing by itself and auto-update stays off
  (`GET /api/auto-update` → `signed: false`, PUT on → 409).
- Release workflow: builds with `vars.KANKI_UPDATE_PUBKEY`, signs with `secrets.MINISIGN_SECRET_KEY` (a key made with
  `minisign -G -W`), verifies, publishes `kanki-panel.minisig`; without both set the publish job fails (no unsigned release).

Signing between panel, nodes and agents (`src/core/sign.rs`)
- Replies are signed: `x-kanki-rts`, `x-kanki-rsig` = HMAC-SHA256(token, "kanki-reply-v1\n rts\n request nonce\n status\n
  sha256(body)"). Nodes sign every `/agent/*` answer (`api::node_signed`); the panel signs its answers to agent reports,
  the «gone» of a removed server (its old token kept 60 days, sealed: `tun_removed_tok`), and `/tunnel/{binary,hy2bin,xraybin}`.
- Requests to `/tunnel/{binary,hy2bin,xraybin}` are signed by 3.69 agents; the body token is taken only until that server
  signed one (`TServer.signed_dl`).
- Ratchets persisted: agent `/var/lib/kanki/agent-sig.json` (`signed_ok`: the bare token never goes with a report again;
  `panel_signs`: unsigned/bad answers refused, the token never goes in a body again). Panel `node_sig` setting (sealed)
  per node id and address: `signed` (no `X-Node-Token` fallback ever again, also across panel restarts), `replies`
  (unsigned answers refused). A re-join (`forget_node_pins`) resets a node's entry.
- Replay floor: a signed request made before the program started (or before the newest time taken before a restart,
  kept in `<data>/sig-floor-{panel,node}`) is refused, so the in-memory nonce cache no longer reopens a 300 s window.
- Rollout: panel first, then «Update all». Nodes/agents of 3.65–3.68 keep syncing (unsigned answers accepted until
  the peer once signed).

Join and pins (`src/core/pin.rs`)
- Pins are SPKI (`sha256//<base64>`, curl's `--pinnedpubkey` form) with a mode: `ca` follows CA-valid renewals, `self`
  takes only the pinned key (a CA-valid cert with another key no longer replaces a self-signed pin). Old pin files
  (cert fingerprint) are read and upgraded on their first match.
- Join tokens: panel-wide and per-server commands 15 min, single use; the agent-driven VPN install (never leaves the
  signed channel) 45 min. Commands carry `KANKI_PANEL_PIN='ca|self:sha256//…'` (the panel probes its own public
  address, `servers::panel_pin`, cached 10 min): install.sh uses `curl --pinnedpubkey` for every panel call, the agent
  starts with that pin (`PANEL_PIN` in tunnel.env), no TOFU.

Iran subscription relay (`subiran`)
- Option chosen: HMAC-authenticated relay. The relay adds `X-Kanki-Relay: v1;ts;nonce;HMAC(relay_key, ts, nonce,
  client, method, target)` (`relay_key` = HMAC of the hidden tunnel's token, sent in `SubCfg`); the panel middleware
  takes that client address for the limits only when it checks out (120 s, nonce once, floor); otherwise the header is
  dropped and the request is taken as before. Clients cannot send the header through the relay (stripped).

KANKI MIX hops through Iran tunnels
- `tunnel::panel::kmix_hop_map`: a Kanki (engine) tunnel that carries a server's main KANKI MIX port also forwards the
  server's hop range (as it reports `kmix_hop`) from the same port numbers on the entry to the main port, added at each
  sync in `specs_for`; not when any of those entry ports is used by another tunnel there, and not for other kinds.
- Links through an Iran entry carry `ports=` only when that entry forwards them (`kmix_hops_at`), else none.

Backups (`src/panel/bkcrypt.rs`)
- New format `KANKIBK2`: AES-256-GCM, PBKDF2-HMAC-SHA256 600k, header as AAD. Old openssl AES-CBC (`Salted__`) and plain
  .tar.gz are still restored. A backup is never made without a passphrase.
- Passphrase lives in `/etc/kanki/backup.pass` (0600, `BACKUP_PASS_FILE` overrides); the old `tgb_pass` setting moves
  there once (same value, old backups open) and leaves the DB. Min 12 chars for a new one (step-up), never in a GET;
  `POST /api/tgbackup/reveal` with the password shows it. Bot/report-bot backups no longer used the raw setting.
- `GET /api/backup` (plain DB) → 410. Restores unpack in Rust (`bkcrypt::unpack`): no absolute path, no `..`, no
  link/hardlink/device, nothing written through a link, entry and size caps; certbot's tree keeps only relative links.
  install.sh uses `kanki-panel backup-unpack` (any format) instead of openssl + tar. The plain archive is wiped after sealing.

Accounts (`src/core/creds.rs`)
- New and regenerated codes: 39 digits (> 128 bits); bare-code lookup takes 10–39 digits. `users.cred = 1` accounts get
  Xray UUID/password/SS-2022 key and Hysteria2 password as HMAC-SHA256 under `cred_key` (sealed setting, travels in
  backups); `cred = 0` (every existing row) keeps the old derivation exactly.

Tests added
- `bkcrypt::tests` (GCM tamper/iteration cap, pass rules, Zip-Slip/symlink/hardlink/device/duplicate), `backup::pass_tests`
  (pass out of DB and GETs, reveal step-up, 12 chars, GET /api/backup 410), `release::tests` (real Ed25519 minisign
  sigs both modes, forged comment, wrong key/id, pins vs install.sh), `sign::tests` (floor, reply binding),
  `sign_tests::{the_panel_signs_its_answers_to_the_agents, agent_downloads_are_signed_and_cannot_go_back_to_the_body_token
  (incl. concurrent replays), node_answers_are_signed_and_the_ratchet_holds}`, `pin::tests` (SPKI, self vs CA mode,
  preset, legacy upgrade, probe), `subiran::tests::the_relay_signs_its_clients_address`, `creds::tests`,
  `access_tests::kmix_hop_ports_follow_the_iran_tunnel_or_stay_out_of_its_link`, `auto_update_tests` (off without key).

Needs the owner
- Make a minisign key (`minisign -G -W`), put the secret key in the repo secret `MINISIGN_SECRET_KEY` and the public
  key line in the repo variable `KANKI_UPDATE_PUBKEY`. Until then releases do not publish and servers update by hand.
- New pins must be added to `release.rs` and install.sh together when Hysteria2/Xray/Caddy are bumped.
- Not done: L4 SNI passthrough for the relay (HMAC chosen); `age` public-key backups (AES-GCM chosen).

## 3.68.0 — Phase 1 security hardening (done; branch `ccr-94a1e97e-wsl617`)
Nothing a user has changes: same subscription codes, same WireGuard/AWG/KANKI MIX/Hysteria2/Xray keys and links.

Relay and network
- `subiran::relay` (transport-generic) forwards `/sub/me`, `/sub/*`, `/api/config/*` with X-Kanki-Sub / Device / Seal /
  Authorization untouched; 60 s idle and 10 min caps. Test `the_app_headers_pass_the_relay` (real router, sealed answer).
- Firewall loop fixed: the guard counted wg/awg/hy2 ports of switched-off cores (`cores::switched_off`) and `report()`
  closed what the guard reopened every ~64 s. Deletion is verified (`ufw status`, then by rule number); rules that
  cannot be closed go to `gave_up` for 24 h.
- Egress isolation: KANKI MIX `internal/egress` (resolve once, no loopback/private/link-local/metadata; lab override
  `KMIX_LAB_ALLOW_PRIVATE=1` keeps loopback/metadata closed), Hysteria2 ACL widened (old ACL upgraded in place), Xray
  private nets always blocked, WG/AWG `KANKI-ISO-IN`/`KANKI-ISO-FWD` chains (iptables + ip6tables, self-healing).
  KANKI-LIMIT and the TCP MSS rules are rebuilt when a ufw reload dropped them.
- SSRF guard `util::public_host/public_url`: node add/join (`ALLOW_PRIVATE_NODES=1` for one private network), CDN test,
  REALITY test, DNS transparent forwarder. AI provider URLs are constants (nothing to guard).
- Tunnels may not listen on SSH or deliver to SSH/panel/node/Xray API ports (on save). KMIX hop range avoids every
  UDP port in use. Caddy configs are validated as a temp file before they replace the live one. Subscription-domain
  block: `/tg/api/admin/*` and `/assets/panel/*` denied; `/tunnel /join /dl` kept only while pre-3.9 agents use the
  domain (30 days after the last one seen). `NODE_BIND` defaults to 127.0.0.1 when Caddy fronts the node.
- `/kdns/r/<token>` over plain HTTP still works (the Android app uses `register_http`) but answers `Deprecation: true`.

Files and secrets
- Startup: data dir and `<data>/tmp` 0700; kanki.db(-wal,-shm), kanki.env, wg0/awg0 0600; Hysteria config
  root:hysteria 0640 (its service reads it). Units get PrivateTmp + NoNewPrivileges (new installs and a drop-in).
  UMask=0077 is not used: the panel writes files caddy and hysteria read.
- `util::write_private` (0600 from the first byte, fsync, rename, owner kept); KMIX users.json atomic 0600.
- Secrets sealed at rest (`core/secrets.rs`, AES-256-GCM, `KANKI_MASTER_KEY` in kanki.env, made once): the settings in
  `SEALED_SETTINGS` and peer privkey/psk; plaintext rows sealed at start; backups/moves carry them opened.
- VACUUM snapshots only in `<data>/tmp`, zeroed and removed; backup/restore work dirs moved out of /tmp.
- PSKs go to `wg set` on stdin. `GET /api/logs` lines redacted (`util::redact` + the panel's own secrets).

Auth and abuse
- PBKDF2 via `ring` at 600k rounds; old hashes open once and are rewritten; global 2-at-a-time gate.
- Min 12-char passwords; step-up (`current`) for policy, 2FA setup/disable, API tokens; `totp_pending` 10 min;
  enabling 2FA uses up its code; global 10/10 min 2FA throttle; `force_2fa` blocks login sessions until 2FA is on.
- Admin session = `kanki_session` cookie (HttpOnly, Secure, SameSite=Strict) that counts only with
  `X-Kanki-Admin: 1`; idle end `session_idle_min` (120); `X-Kanki-Token-Login: 1` still returns a token for scripts.
- API tokens must end (1-365 days; old ones got 90 days); legacy `api_key` removed (410).
- HTTPS-only for /api, /tg/api, /move, /join; pre-auth before any body over 1 MiB and /api/apps.
- Backup, move, db clean and service actions: login sessions only. Payment keys masked in GET /api/settings.
- CSP on /admin, `sandbox` CSP on every SVG; QR input max 2048/4096 bytes; `no-store` on every /sub answer.
- Limits: /sub/:code/app 5/min, /dl 20, /move 30, /join 10, /tunnel 600 per minute; bulk users max 1000; no
  limiter exemption; `client_ip` = rightmost hop only and only a real address.
- Audit rows hash-chained (`audit_broken`, shown as `audit_intact`); strangers' 401/403 not written; sensitive
  reads, /move, /join, bot-admin changes and CLI resets audited. `/hy2/auth` fail-closed without its key file unless
  `/etc/kanki/hy2-auth.keyless` marks a deliberately keyless Hysteria.
- /move: 30 min, token in `X-Kanki-Move`, one download, command wiped on expiry. Secrets on CLI via stdin
  (`features` tells install.sh). DoH header timeout 10 s / 30 min per connection; ACME responder max 64 at once.
- Auto-removal of offline servers off by default; leftover nodes asked for 72 h.

Revocation and KANKI MIX API
- Hysteria2: users that left the allow-list are kicked at each sync. KANKI MIX reload already drops a removed
  user's addresses and hints (packets stop decrypting). Xray: removed/over-limit users are taken out via its API
  (no new connections); Xray has no API to cut an open stream.
- KMIX `/traffic?clear=1` POST only; recordings max 5 min, ~10 MiB of events.

Not done (needs a decision or a live test)
- `install.sh` `set -euo pipefail`: kept `set -e`; switching a 1000-line installer to `-u` untested could break installs.
- `curl -k` in install.sh is left only where nothing secret is sent (reachability checks).

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
