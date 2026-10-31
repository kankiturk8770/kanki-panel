//! Sync users to nodes, count traffic, enforce limits.
//! One round at a time (sync_lock) so traffic is never counted twice.
use crate::db::{Node, User};
use crate::util::now;
use crate::wg::{self, PeerSpec, PeerStat};
use crate::App;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

#[derive(Serialize, Deserialize, Default)]
pub struct SyncReq {
    #[serde(default)]
    pub wg: Vec<PeerSpec>,
    #[serde(default)]
    pub awg: Vec<PeerSpec>,
    /// sub code -> username (Hysteria2)
    #[serde(default)]
    pub hy2: HashMap<String, String>,
    /// username -> (max connections, online across all nodes)
    #[serde(default)]
    pub limits: HashMap<String, (i64, i64)>,
    /// KANKI MIX on this server (None = a panel that does not manage it: leave it as it is)
    #[serde(default)]
    pub kmix: Option<crate::kmix::KmixCfg>,
    /// MIX+ was removed: the panel always sends `{}` here, which an agent that still has MIX+ reads
    /// as "everything off" (it stops it and closes its port). Newer agents ignore it.
    #[serde(default)]
    pub kcore: Option<serde_json::Value>,
    /// microtun on this server (None = a panel that does not manage it)
    #[serde(default)]
    pub mtun: Option<crate::mtun::MtCfg>,
    /// WireGuard / AmneziaWG / Hysteria2 switched off on this server ("wg", "awg", "hy2"): stopped and
    /// their ports closed (see `cores::apply`); an older agent ignores it but gets no users for them
    #[serde(default)]
    pub off: Vec<String>,
}

#[derive(Serialize, Deserialize, Default)]
pub struct SyncResp {
    #[serde(default)]
    pub wg: HashMap<String, PeerStat>,
    #[serde(default)]
    pub awg: HashMap<String, PeerStat>,
    #[serde(default)]
    pub hy2: HashMap<String, (i64, i64)>,
    #[serde(default)]
    pub hy2_online: HashMap<String, i64>,
    /// KANKI MIX: username -> (rx, tx) since the last sync, and devices online
    #[serde(default)]
    pub kmix: HashMap<String, (i64, i64)>,
    #[serde(default)]
    pub kmix_online: HashMap<String, i64>,
    #[serde(default)]
    pub kmix_error: String,
    /// microtun: username -> (rx, tx) since the last sync, users online, what failed to start
    #[serde(default)]
    pub mtun: HashMap<String, (i64, i64)>,
    #[serde(default)]
    pub mtun_online: Vec<String>,
    #[serde(default)]
    pub mtun_error: String,
}

fn loadavg() -> String {
    std::fs::read_to_string("/proc/loadavg").unwrap_or_default().split_whitespace().take(3).collect::<Vec<_>>().join(" ")
}

/// This server's keys, ports and params (used to build client configs)
pub fn local_info(app: &App) -> Value {
    let e = &app.env;
    let g = |k: &str| e.get(k).cloned().unwrap_or_default();
    let mut v = json!({
        "wg_pub": wg::iface_pub("wg"), "wg_port": wg::listen_port("wg"),
        "awg_pub": wg::iface_pub("awg"), "awg_port": wg::listen_port("awg"),
        "awg": wg::awg_params(),
        "hy2_port": g("HY2_PORT"), "hy2_obfs": g("HY2_OBFS"), "hy2_sni": g("DOMAIN"),
        "hy2_insecure": g("HY2_INSECURE"),
        "services": crate::admin::service_states(), "version": crate::VERSION, "load": loadavg(),
        "stats": crate::admin::node_stats(),
    });
    if let (Some(o), Some(k)) = (v.as_object_mut(), crate::kmix::info().as_object()) {
        o.extend(k.clone());
    }
    if let (Some(o), Some(k)) = (v.as_object_mut(), crate::microtun::info().as_object()) {
        o.extend(k.clone());
    }
    v
}

/// `local_info` off the async workers: it runs `systemctl` for every service and reads /proc, which
/// would hold a worker thread (and every request waiting on it) for a moment on each round
pub async fn local_info_async(app: &Arc<App>) -> Value {
    let a = app.clone();
    tokio::task::spawn_blocking(move || local_info(&a)).await.unwrap_or_else(|_| json!({}))
}

/// Apply on this server
pub async fn apply_local(app: &App, req: SyncReq) -> SyncResp {
    static ACL: std::sync::Once = std::sync::Once::new();
    if !ACL.is_completed() {
        let _ = tokio::task::spawn_blocking(|| ACL.call_once(crate::hy2::ensure_acl)).await;
    }
    *app.hy2_allowed.lock().unwrap_or_else(|e| e.into_inner()) = req.hy2.clone();
    *app.limits.lock().unwrap_or_else(|e| e.into_inner()) = req.limits.clone();
    let hy2_names: HashSet<String> = req.hy2.values().cloned().collect();
    let off = req.off.clone();
    let _ = tokio::task::spawn_blocking(move || crate::cores::apply(&off)).await;
    let (wgv, awgv) = (req.wg, req.awg);
    let (w, a) = tokio::task::spawn_blocking(move || (wg::apply("wg", &wgv), wg::apply("awg", &awgv)))
        .await
        .unwrap_or_default();
    let port = app.env.get("HY2_STATS_PORT").cloned().unwrap_or_default();
    let secret = app.env.get("HY2_SECRET").cloned().unwrap_or_default();
    let hy2 = crate::hy2::traffic(&port, &secret).await;
    let hy2_online = crate::hy2::online(&port, &secret).await;
    // disconnect Hysteria2 users who are no longer allowed (expired / over quota / disabled)
    let kick: Vec<String> = hy2_online.keys().filter(|k| !hy2_names.contains(*k)).cloned().collect();
    crate::hy2::kick(&port, &secret, &kick).await;
    let mut rep: HashMap<String, i64> = HashMap::new();
    for (k, v) in hy2_online.iter() {
        *rep.entry(k.clone()).or_default() += v;
    }
    *app.reported.lock().unwrap_or_else(|e| e.into_inner()) = rep;
    let (mut kmix, mut kmix_online, mut kmix_error) = (HashMap::new(), HashMap::new(), String::new());
    if let Some(cfg) = req.kmix {
        // traffic first: a restart below would lose what was not read yet
        kmix = crate::kmix::traffic().await;
        let r = tokio::task::spawn_blocking(move || crate::kmix::apply(&cfg)).await.unwrap_or_else(|_| Err("kanki-mix apply crashed".into()));
        if let Err(e) = r {
            if last_kmix_err().lock().unwrap_or_else(|e| e.into_inner()).as_deref() != Some(e.as_str()) {
                eprintln!("kanki-mix: {}", e);
            }
            kmix_error = e;
        }
        *last_kmix_err().lock().unwrap_or_else(|e| e.into_inner()) = Some(kmix_error.clone()).filter(|e| !e.is_empty());
        kmix_online = crate::kmix::online().await;
    }
    // the firewall rule an older version opened for MIX+ is closed once
    static MIXPLUS_GONE: std::sync::Once = std::sync::Once::new();
    MIXPLUS_GONE.call_once(|| {
        tokio::task::spawn_blocking(|| crate::fw::close("kcore"));
    });
    let (mut mtun, mut mtun_online, mut mtun_error) = (HashMap::new(), vec![], String::new());
    if let Some(cfg) = req.mtun {
        (mtun, mtun_online, mtun_error) = tokio::task::spawn_blocking(move || crate::microtun::apply(cfg)).await.unwrap_or_else(|_| (HashMap::new(), vec![], "microtun apply crashed".into()));
    }
    SyncResp { wg: w, awg: a, hy2, hy2_online, kmix, kmix_online, kmix_error, mtun, mtun_online, mtun_error }
}

/// when each switched-off node was last given its empty user list
fn off_checked() -> &'static std::sync::Mutex<HashMap<String, i64>> {
    static M: std::sync::OnceLock<std::sync::Mutex<HashMap<String, i64>>> = std::sync::OnceLock::new();
    M.get_or_init(|| std::sync::Mutex::new(HashMap::new()))
}

/// the last KANKI MIX error (the same error is logged once, not every 30 s)
fn last_kmix_err() -> &'static std::sync::Mutex<Option<String>> {
    static E: std::sync::OnceLock<std::sync::Mutex<Option<String>>> = std::sync::OnceLock::new();
    E.get_or_init(|| std::sync::Mutex::new(None))
}

/// Is a WireGuard / AmneziaWG key with a recent handshake really in use? The Kanki apps "ping" every
/// server with a real handshake of the user's key (about 240 bytes, then nothing); counting that as a
/// connection for 3 minutes filled the connection limit and refused the user's real second device.
/// A key counts once it moved real data in a round (1 KB), and keeps counting while anything moves
/// (keepalives every 25 s).
fn live_peer(uid: i64, node: &str, proto: &str, moved: i64) -> bool {
    static LIVE: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<(i64, String, String)>>> = std::sync::OnceLock::new();
    let mut live = LIVE.get_or_init(Default::default).lock().unwrap_or_else(|e| e.into_inner());
    let key = (uid, node.to_string(), proto.to_string());
    let on = moved >= 1024 || (moved > 0 && live.contains(&key));
    if on {
        live.insert(key);
    } else {
        live.remove(&key);
    }
    on
}

/// How long a user may stay over the connection limit before the newest connection is shut: switching
/// server in an app keeps the old one alive for a moment, which is not a second device.
const OVER_GRACE: i64 = 45;

/// The connection limit over every server and protocol, for any app: the connections that came first
/// keep working; while the user has more than allowed, the newest ones are shut on their server (its
/// key or user taken off there) until one of the others ends. Pings and subscription views never count
/// (only connections that move data are live).
#[derive(Default)]
pub struct Limits {
    /// when each live connection (user, node, protocol) was first seen
    since: HashMap<(i64, String, String), i64>,
    /// since when each user has more live connections than allowed
    over: HashMap<i64, i64>,
    /// connections shut for each user: (node, protocol)
    shut: HashMap<i64, HashSet<(String, String)>>,
    /// the connections kept when those were shut: they open again once one of these ends
    kept: HashMap<i64, HashSet<(String, String)>>,
}

impl Limits {
    /// One sync round: `units` are the live connections (user, node, protocol, devices), `answered` the
    /// nodes that answered (the others keep what they had). True when something was shut or let in.
    pub fn round(&mut self, units: &[(i64, String, String, i64)], answered: &HashSet<String>, max: &HashMap<i64, i64>, now: i64) -> bool {
        let live: HashSet<(i64, String, String)> = units.iter().map(|(u, n, p, _)| (*u, n.clone(), p.clone())).collect();
        self.since.retain(|k, _| live.contains(k) || !answered.contains(&k.1));
        for k in &live {
            self.since.entry(k.clone()).or_insert(now);
        }
        let before = self.shut.clone();
        let mut per: HashMap<i64, Vec<(i64, String, String, i64)>> = HashMap::new();
        for (u, n, p, c) in units {
            per.entry(*u).or_default().push((self.since.get(&(*u, n.clone(), p.clone())).copied().unwrap_or(now), n.clone(), p.clone(), *c));
        }
        let users: HashSet<i64> = per.keys().copied().chain(self.shut.keys().copied()).chain(self.over.keys().copied()).collect();
        for u in users {
            let m = max.get(&u).copied().unwrap_or(0);
            let mut list = per.remove(&u).unwrap_or_default();
            let total: i64 = list.iter().map(|x| x.3).sum();
            if m <= 0 {
                self.over.remove(&u);
                self.shut.remove(&u);
                self.kept.remove(&u);
                continue;
            }
            if self.shut.contains_key(&u) {
                // what was shut opens again once one of the connections that came first has ended
                // (a node that did not answer this round counts as still connected)
                let still = |k: &(String, String)| list.iter().any(|x| x.1 == k.0 && x.2 == k.1) || !answered.contains(&k.0);
                if self.kept.get(&u).is_some_and(|k| k.iter().all(still)) && total <= m {
                    continue;
                }
                self.shut.remove(&u);
                self.kept.remove(&u);
            }
            if total < m {
                self.over.remove(&u);
                continue;
            }
            if total == m {
                self.over.remove(&u);
                continue;
            }
            let from = *self.over.entry(u).or_insert(now);
            if now - from < OVER_GRACE {
                continue;
            }
            // oldest first; ties by node and protocol so every round decides the same way
            list.sort_by(|a, b| (a.0, &a.1, &a.2).cmp(&(b.0, &b.1, &b.2)));
            // a server where some of the user's devices came first as well is left alone (shutting the
            // user there would shut those too); its own limit refuses the newest one there
            let mut kept = 0;
            for (_, n, p, c) in list {
                if kept >= m {
                    self.shut.entry(u).or_default().insert((n, p));
                } else {
                    kept += c;
                    self.kept.entry(u).or_default().insert((n, p));
                }
            }
            self.over.remove(&u);
        }
        self.shut != before
    }

    /// Is this connection shut for now?
    pub fn is_shut(&self, user: i64, node: &str, proto: &str) -> bool {
        self.shut.get(&user).is_some_and(|s| s.contains(&(node.to_string(), proto.to_string())))
    }
}

pub fn limits() -> &'static Mutex<Limits> {
    static L: std::sync::OnceLock<Mutex<Limits>> = std::sync::OnceLock::new();
    L.get_or_init(Default::default)
}

/// Live Hysteria2 sessions of a user on this server
pub async fn live_sessions(app: &App, username: &str) -> i64 {
    let port = app.env.get("HY2_STATS_PORT").cloned().unwrap_or_default();
    let secret = app.env.get("HY2_SECRET").cloned().unwrap_or_default();
    let h = crate::hy2::online(&port, &secret).await.get(username).copied().unwrap_or(0);
    h
}

/// Connection-limit check used by Hysteria2 auth
pub async fn conn_allowed(app: &App, username: &str) -> bool {
    let (max, total) = app.limits.lock().unwrap_or_else(|e| e.into_inner()).get(username).copied().unwrap_or((0, 0));
    if max <= 0 {
        return true;
    }
    let reported = app.reported.lock().unwrap_or_else(|e| e.into_inner()).get(username).copied().unwrap_or(0);
    let elsewhere = (total - reported).max(0);
    elsewhere + live_sessions(app, username).await < max
}

fn desired_for(app: &App, users: &[User], n: &Node) -> (SyncReq, Vec<(i64, String, String)>) {
    // (user_id, proto, pubkey)
    let info = crate::api::node_info(n);
    let has = |k: &str| info[k].as_str().map(|s| !s.is_empty()).unwrap_or(false);
    let off = crate::cores::off_list(app, &n.id);
    let is_off = |c: &str| off.iter().any(|x| x == c);
    let (wg_on, awg_on) = (has("wg_pub") && !is_off("wg"), has("awg_pub") && !is_off("awg"));
    let limit_on = app.db.get("conn_limit_on") != "0";
    let mut req = SyncReq::default();
    let mut map = vec![];
    let lim = limits().lock().unwrap_or_else(|e| e.into_inner());
    let shut = |u: &User, p: &str| lim.is_shut(u.id, &n.id, p);
    let here: Vec<&User> = users.iter().filter(|u| u.active() && u.on(n)).collect();
    let kmix_here: Vec<&User> = here.iter().copied().filter(|u| !shut(u, "kmix")).collect();
    let mtun_here: Vec<&User> = here.iter().copied().filter(|u| !shut(u, "mtun")).collect();
    req.kmix = Some(crate::kmix::cfg_for(app, &crate::kmix::settings(app), n, &kmix_here));
    req.kcore = Some(serde_json::json!({}));
    req.mtun = Some(crate::microtun::cfg_for(app, n, &mtun_here));
    req.off = off.clone();
    for u in users.iter().filter(|u| u.active() && u.on(n)) {
        // drain: no new users here unless explicitly assigned or already present
        if n.drain && !u.explicit_nodes() {
            let had = app.db.peer(u.id, &n.id, "wg").is_some() || app.db.peer(u.id, &n.id, "awg").is_some();
            if !had {
                continue;
            }
        }
        for (proto, on) in [("wg", wg_on), ("awg", awg_on)] {
            if !on || !u.has_proto(proto) || shut(u, proto) {
                continue;
            }
            if let Some(p) = app.db.ensure_peer(u.id, &n.id, proto) {
                let spec = PeerSpec { pubkey: p.pubkey.clone(), psk: p.psk.clone(), ip: p.ip.clone() };
                if proto == "wg" { req.wg.push(spec) } else { req.awg.push(spec) }
                map.push((u.id, proto.to_string(), p.pubkey));
            }
        }
        if u.has_proto("hy2") && !is_off("hy2") && !shut(u, "hy2") {
            req.hy2.insert(u.code.clone(), u.username.clone());
        }
        req.limits.insert(u.username.clone(), (if limit_on { u.max_conn } else { 0 }, u.online));
    }
    (req, map)
}

/// One sync round over every enabled node
pub async fn sync_all(app: &Arc<App>) {
    let _round = app.sync_lock.lock().await;
    let users = app.db.users();
    let mut online: HashMap<i64, i64> = HashMap::new();
    let mut seen: HashMap<i64, i64> = HashMap::new();
    let mut add_bytes: HashMap<i64, i64> = HashMap::new();
    let by_name: HashMap<String, i64> = users.iter().map(|u| (u.username.clone(), u.id)).collect();
    // every live connection of this round: (user, node, protocol, devices)
    let mut units: Vec<(i64, String, String, i64)> = vec![];
    let mut answered: HashSet<String> = HashSet::new();

    // a node whose VPN is switched off serves nobody: its users are taken off (an empty sync), so a
    // relay server keeps its ports free and an old peer cannot keep using it
    for n in app.db.nodes().into_iter().filter(|n| !n.enabled) {
        // the panel server's own info (version, services, load) stays fresh while its VPN is off too
        if n.id == "local" {
            let _ = app.db.exec("UPDATE nodes SET info=?1 WHERE id='local'", &[&local_info_async(app).await.to_string()]);
        }
        // once it is empty, checked again every 5 minutes (an unreachable one must not slow every round)
        {
            let mut g = off_checked().lock().unwrap_or_else(|e| e.into_inner());
            let last = g.get(&n.id).copied().unwrap_or(0);
            if n.sync_state == "off" && now() - last < 300 {
                continue;
            }
            g.insert(n.id.clone(), now());
        }
        let empty = SyncReq { kmix: Some(crate::kmix::KmixCfg::default()), kcore: Some(serde_json::json!({})), mtun: Some(Default::default()), ..Default::default() };
        let ok = if n.id == "local" { apply_local(app, empty).await; true } else { remote_sync(app, &n, &empty).await.is_ok() };
        let _ = app.db.exec("UPDATE nodes SET online=?1, sync_state='off' WHERE id=?2", &[&(ok as i64), &n.id]);
        if ok && n.id != "local" {
            if let Some(info) = remote_info(app, &n.address, &n.token, n.insecure).await {
                let _ = app.db.exec("UPDATE nodes SET info=?1, last_sync=?2 WHERE id=?3", &[&info.to_string(), &now(), &n.id]);
            }
        }
        crate::live::set_vpn(&n.id, &n.name, vec![]);
    }
    // every server is asked at the same time: one that does not answer must not hold the round (traffic,
    // limits and who is online) for everyone else
    let mut jobs = vec![];
    for mut n in app.db.nodes().into_iter().filter(|n| n.enabled) {
        let local = n.id == "local";
        if local {
            let info = local_info_async(app).await.to_string();
            let _ = app.db.exec("UPDATE nodes SET info=?1 WHERE id='local'", &[&info]);
            n.info = info;
        }
        let (req, map) = desired_for(app, &users, &n);
        jobs.push(async move {
            let want = req.wg.len() + req.awg.len();
            let resp: Result<SyncResp, String> = if local { Ok(apply_local(app, req).await) } else { remote_sync(app, &n, &req).await };
            let info = if !local && resp.is_ok() { remote_info(app, &n.address, &n.token, n.insecure).await } else { None };
            (n, map, want, resp, info)
        });
    }
    for (n, map, want, resp, info) in futures_util::future::join_all(jobs).await {
        let local = n.id == "local";
        let ok = resp.is_ok();
        let state = match &resp {
            // a pin mismatch is not just "offline": it is logged and kept apart
            Err(e) if e.contains(crate::pin::MISMATCH) => "pin mismatch",
            Err(_) => "offline",
            Ok(r) => {
                let have = map.iter().filter(|(_, proto, pk)| if proto == "wg" { r.wg.contains_key(pk) } else { r.awg.contains_key(pk) }).count();
                if have == want { "synced" } else { "mismatch" }
            }
        };
        if ok {
            let _ = app.db.exec("UPDATE nodes SET online=1, last_sync=?1, sync_state=?2 WHERE id=?3", &[&now(), &state, &n.id]);
        } else {
            let _ = app.db.exec("UPDATE nodes SET online=0, sync_state=?1 WHERE id=?2", &[&state, &n.id]);
        }
        if let (false, Some(info)) = (local, info) {
            let _ = app.db.exec("UPDATE nodes SET info=?1 WHERE id=?2", &[&info.to_string(), &n.id]);
        }
        let Ok(resp) = resp else {
            crate::live::set_vpn(&n.id, &n.name, vec![]);
            continue;
        };
        // who is connected here right now, and with which protocol (for the panel)
        let mut here: Vec<(i64, String)> = vec![];

        for (uid, proto, pubk) in map {
            let stats = if proto == "wg" { &resp.wg } else { &resp.awg };
            let Some(st) = stats.get(&pubk) else { continue };
            let mut moved = 0;
            if let Some(p) = app.db.peer(uid, &n.id, &proto) {
                let total = st.rx + st.tx;
                let prev = p.rx + p.tx;
                let delta = if total >= prev { total - prev } else { total };
                moved = delta;
                *add_bytes.entry(uid).or_default() += delta;
                let _ = app.db.exec(
                    "UPDATE peers SET rx=?1, tx=?2 WHERE user_id=?3 AND node_id=?4 AND proto=?5",
                    &[&st.rx, &st.tx, &uid, &n.id, &proto],
                );
            }
            if st.handshake > 0 && now() - st.handshake < 180 && live_peer(uid, &n.id, &proto, moved) {
                here.push((uid, proto.clone()));
                units.push((uid, n.id.clone(), proto.clone(), 1));
                *online.entry(uid).or_default() += 1;
                let e = seen.entry(uid).or_default();
                *e = (*e).max(st.handshake);
            }
        }
        for (name, (rx, tx)) in resp.hy2.iter() {
            if let Some(uid) = by_name.get(name) {
                *add_bytes.entry(*uid).or_default() += rx + tx;
            }
        }
        for (name, c, proto) in resp.hy2_online.iter().map(|(n, c)| (n, c, "hy2")).chain(resp.kmix_online.iter().map(|(n, c)| (n, c, "kmix"))).chain(resp.mtun_online.iter().map(|n| (n, &1, "mtun"))) {
            if let Some(uid) = by_name.get(name) {
                if *c > 0 {
                    here.push((*uid, proto.to_string()));
                    units.push((*uid, n.id.clone(), proto.to_string(), *c));
                    *online.entry(*uid).or_default() += c;
                    seen.insert(*uid, now());
                }
            }
        }
        for (name, (rx, tx)) in resp.kmix.iter().chain(resp.mtun.iter()) {
            if let Some(uid) = by_name.get(name) {
                *add_bytes.entry(*uid).or_default() += rx + tx;
            }
        }
        crate::kmix::note_error(&n.id, &resp.kmix_error);
        crate::live::set_vpn(&n.id, &n.name, here);
        answered.insert(n.id.clone());
    }
    let limit_on = app.db.get("conn_limit_on") != "0";
    let max: HashMap<i64, i64> = users.iter().map(|u| (u.id, if limit_on && u.active() { u.max_conn } else { 0 })).collect();
    let changed = limits().lock().unwrap_or_else(|e| e.into_inner()).round(&units, &answered, &max, now());
    if changed {
        // a connection was shut or let in again: the servers get it now, not in 30 seconds
        crate::api::spawn_sync(app);
    }

    for u in &users {
        let add = add_bytes.get(&u.id).copied().unwrap_or(0);
        let on = online.get(&u.id).copied().unwrap_or(0);
        let last = seen.get(&u.id).copied().unwrap_or(u.last_seen).max(u.last_seen);
        if add > 0 || on != u.online || last != u.last_seen {
            let _ = app.db.exec(
                "UPDATE users SET used_bytes=used_bytes+?1, online=?2, last_seen=?3 WHERE id=?4",
                &[&add, &on, &last, &u.id],
            );
        }
    }
}

/// Why a request to a node failed. A certificate pin mismatch is logged and says how to reset it
/// (otherwise the node would only show as offline).
pub fn node_err(addr: &str, e: &reqwest::Error) -> String {
    match crate::pin::mismatch_of(e) {
        Some(m) => {
            eprintln!("node {}: {}", addr, m);
            format!("{} (if the node was reinstalled: run its join command again, or remove the node and add it again)", m)
        }
        None => crate::pin::error_text(e),
    }
}

/// How long a sync or info request to a server may take
const SYNC_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(45);

async fn remote_sync(app: &App, n: &Node, req: &SyncReq) -> Result<SyncResp, String> {
    // a sync answers within seconds; the self-signed client's long timeout is for updates
    let r = app.node_client(&n.id, n.insecure).post(format!("{}/agent/sync", n.address.trim_end_matches('/')))
        .header("X-Node-Token", &n.token).json(req).timeout(SYNC_TIMEOUT).send().await.map_err(|e| node_err(&n.address, &e))?;
    if !r.status().is_success() {
        return Err(format!("the node answered {}", r.status()));
    }
    r.json::<SyncResp>().await.map_err(|e| e.to_string())
}

/// Nodes that were just told to update restart onto the new program: their info (and so the version the
/// panel shows) is read again every few seconds until they report `want`, not only at the next sync round.
pub fn refresh_after_update(app: &Arc<App>, mut nodes: Vec<Node>, want: &str) {
    if nodes.is_empty() {
        return;
    }
    let (a, want) = (app.clone(), want.to_string());
    tokio::spawn(async move {
        for _ in 0..15 {
            tokio::time::sleep(std::time::Duration::from_secs(6)).await;
            let mut left = vec![];
            for n in nodes {
                match remote_info(&a, &n.address, &n.token, n.insecure).await {
                    Some(info) => {
                        let _ = a.db.exec("UPDATE nodes SET info=?1, online=1 WHERE id=?2", &[&info.to_string(), &n.id]);
                        if !want.is_empty() && info["version"].as_str() != Some(want.as_str()) {
                            left.push(n);
                        }
                    }
                    None => left.push(n),
                }
            }
            if left.is_empty() {
                break;
            }
            nodes = left;
        }
    });
}

pub async fn remote_info(app: &App, addr: &str, token: &str, insecure: bool) -> Option<Value> {
    remote_info_res(app, addr, token, insecure).await.ok()
}

/// `remote_info` with the reason it failed
pub async fn remote_info_res(app: &App, addr: &str, token: &str, insecure: bool) -> Result<Value, String> {
    // keyed by address: for a node being added this is also the TOFU first contact
    let r = app.node_client(addr, insecure).get(format!("{}/agent/info", addr.trim_end_matches('/')))
        .header("X-Node-Token", token).timeout(SYNC_TIMEOUT).send().await.map_err(|e| node_err(addr, &e))?;
    if !r.status().is_success() {
        return Err(format!("the node answered {}", r.status()));
    }
    r.json::<Value>().await.map_err(|e| e.to_string())
}

pub async fn remote_post(app: &App, n: &Node, path: &str) -> Option<Value> {
    let r = app.node_client(&n.id, n.insecure).post(format!("{}{}", n.address.trim_end_matches('/'), path))
        .header("X-Node-Token", &n.token).timeout(std::time::Duration::from_secs(120)).send().await.ok()?;
    r.json::<Value>().await.ok()
}

pub async fn remote_post_json(app: &App, n: &Node, path: &str, body: &Value) -> Option<Value> {
    let r = app.node_client(&n.id, n.insecure).post(format!("{}{}", n.address.trim_end_matches('/'), path))
        .header("X-Node-Token", &n.token).json(body).timeout(std::time::Duration::from_secs(60)).send().await.ok()?;
    r.json::<Value>().await.ok()
}

/// Forever loop
pub async fn run(app: Arc<App>) {
    loop {
        sync_all(&app).await;
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
    }
}

#[cfg(test)]
mod live_tests {
    use super::{live_peer, Limits};
    use std::collections::{HashMap, HashSet};

    fn u(user: i64, node: &str, proto: &str) -> (i64, String, String, i64) {
        (user, node.to_string(), proto.to_string(), 1)
    }

    #[test]
    fn the_first_devices_keep_working_and_the_newest_waits() {
        let mut l = Limits::default();
        let nodes: HashSet<String> = ["de", "tr"].iter().map(|s| s.to_string()).collect();
        let max: HashMap<i64, i64> = [(1, 1)].into_iter().collect();
        // a one-connection user on Germany
        assert!(!l.round(&[u(1, "de", "wg")], &nodes, &max, 1000));
        // a second device on Turkey: allowed for the grace time (switching server is not a second device)
        assert!(!l.round(&[u(1, "de", "wg"), u(1, "tr", "hy2")], &nodes, &max, 1010));
        assert!(!l.is_shut(1, "tr", "hy2"));
        // still both after 45 s: the newest (Turkey) is shut, Germany keeps working
        assert!(l.round(&[u(1, "de", "wg"), u(1, "tr", "hy2")], &nodes, &max, 1060));
        assert!(l.is_shut(1, "tr", "hy2") && !l.is_shut(1, "de", "wg"));
        // Turkey is gone because it was shut: it stays shut while Germany is connected
        assert!(!l.round(&[u(1, "de", "wg")], &nodes, &max, 1090));
        assert!(l.is_shut(1, "tr", "hy2"));
        // Germany ends: Turkey may connect again
        assert!(l.round(&[], &nodes, &max, 1120));
        assert!(!l.is_shut(1, "tr", "hy2"));
    }

    #[test]
    fn switching_server_is_not_a_second_device() {
        let mut l = Limits::default();
        let nodes: HashSet<String> = ["de", "tr"].iter().map(|s| s.to_string()).collect();
        let max: HashMap<i64, i64> = [(1, 1)].into_iter().collect();
        l.round(&[u(1, "de", "wg")], &nodes, &max, 1000);
        // for one round both move data, then only the new one
        l.round(&[u(1, "de", "wg"), u(1, "tr", "wg")], &nodes, &max, 1030);
        l.round(&[u(1, "tr", "wg")], &nodes, &max, 1060);
        l.round(&[u(1, "tr", "wg")], &nodes, &max, 1120);
        assert!(!l.is_shut(1, "tr", "wg") && !l.is_shut(1, "de", "wg"));
    }

    #[test]
    fn two_connections_allow_two_devices() {
        let mut l = Limits::default();
        let nodes: HashSet<String> = ["de"].iter().map(|s| s.to_string()).collect();
        let max: HashMap<i64, i64> = [(1, 2), (2, 0)].into_iter().collect();
        for t in [1000, 1060, 1120] {
            l.round(&[u(1, "de", "wg"), u(1, "de", "hy2"), u(2, "de", "wg"), u(2, "de", "kmix"), u(2, "de", "hy2")], &nodes, &max, t);
        }
        // two of two: nothing shut; no limit (0): nothing shut
        assert!(!l.is_shut(1, "de", "wg") && !l.is_shut(1, "de", "hy2") && !l.is_shut(2, "de", "hy2"));
    }

    #[test]
    fn a_ping_handshake_is_not_a_connection() {
        // the apps' ping: one handshake (~240 bytes), then nothing
        assert!(!live_peer(-7, "n", "wg", 240));
        assert!(!live_peer(-7, "n", "wg", 0));
        // a real connection: data, then only keepalives while idle
        assert!(live_peer(-8, "n", "wg", 50_000));
        assert!(live_peer(-8, "n", "wg", 64));
        // disconnected: nothing moves any more
        assert!(!live_peer(-8, "n", "wg", 0));
        assert!(!live_peer(-8, "n", "wg", 64));
    }
}
