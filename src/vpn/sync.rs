//! Sync users to nodes, count traffic, enforce limits.
//! One round at a time (sync_lock) so traffic is never counted twice.
use crate::db::{Node, User};
use crate::util::now;
use crate::wg::{self, PeerSpec, PeerStat};
use crate::App;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

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
    v
}

/// Apply on this server
pub async fn apply_local(app: &App, req: SyncReq) -> SyncResp {
    *app.hy2_allowed.lock().unwrap() = req.hy2.clone();
    *app.limits.lock().unwrap() = req.limits.clone();
    let hy2_names: HashSet<String> = req.hy2.values().cloned().collect();
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
    *app.reported.lock().unwrap() = rep;
    let (mut kmix, mut kmix_online, mut kmix_error) = (HashMap::new(), HashMap::new(), String::new());
    if let Some(cfg) = req.kmix {
        // traffic first: a restart below would lose what was not read yet
        kmix = crate::kmix::traffic().await;
        let r = tokio::task::spawn_blocking(move || crate::kmix::apply(&cfg)).await.unwrap_or_else(|_| Err("kanki-mix apply crashed".into()));
        if let Err(e) = r {
            if last_kmix_err().lock().unwrap().as_deref() != Some(e.as_str()) {
                eprintln!("kanki-mix: {}", e);
            }
            kmix_error = e;
        }
        *last_kmix_err().lock().unwrap() = Some(kmix_error.clone()).filter(|e| !e.is_empty());
        kmix_online = crate::kmix::online().await;
    }
    SyncResp { wg: w, awg: a, hy2, hy2_online, kmix, kmix_online, kmix_error }
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

/// Live Hysteria2 sessions of a user on this server
pub async fn live_sessions(app: &App, username: &str) -> i64 {
    let port = app.env.get("HY2_STATS_PORT").cloned().unwrap_or_default();
    let secret = app.env.get("HY2_SECRET").cloned().unwrap_or_default();
    let h = crate::hy2::online(&port, &secret).await.get(username).copied().unwrap_or(0);
    h
}

/// Connection-limit check used by Hysteria2 auth
pub async fn conn_allowed(app: &App, username: &str) -> bool {
    let (max, total) = app.limits.lock().unwrap().get(username).copied().unwrap_or((0, 0));
    if max <= 0 {
        return true;
    }
    let reported = app.reported.lock().unwrap().get(username).copied().unwrap_or(0);
    let elsewhere = (total - reported).max(0);
    elsewhere + live_sessions(app, username).await < max
}

fn desired_for(app: &App, users: &[User], n: &Node) -> (SyncReq, Vec<(i64, String, String)>) {
    // (user_id, proto, pubkey)
    let info = crate::api::node_info(n);
    let has = |k: &str| info[k].as_str().map(|s| !s.is_empty()).unwrap_or(false);
    let (wg_on, awg_on) = (has("wg_pub"), has("awg_pub"));
    let limit_on = app.db.get("conn_limit_on") != "0";
    let mut req = SyncReq::default();
    let mut map = vec![];
    let here: Vec<&User> = users.iter().filter(|u| u.active() && u.on(n)).collect();
    req.kmix = Some(crate::kmix::cfg_for(app, &crate::kmix::settings(app), n, &here));
    for u in users.iter().filter(|u| u.active() && u.on(n)) {
        // drain: no new users here unless explicitly assigned or already present
        if n.drain && !u.explicit_nodes() {
            let had = app.db.peer(u.id, &n.id, "wg").is_some() || app.db.peer(u.id, &n.id, "awg").is_some();
            if !had {
                continue;
            }
        }
        for (proto, on) in [("wg", wg_on), ("awg", awg_on)] {
            if !on || !u.has_proto(proto) {
                continue;
            }
            if let Some(p) = app.db.ensure_peer(u.id, &n.id, proto) {
                let spec = PeerSpec { pubkey: p.pubkey.clone(), psk: p.psk.clone(), ip: p.ip.clone() };
                if proto == "wg" { req.wg.push(spec) } else { req.awg.push(spec) }
                map.push((u.id, proto.to_string(), p.pubkey));
            }
        }
        if u.has_proto("hy2") {
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

    // a node whose VPN is switched off serves nobody: its users are taken off (an empty sync), so a
    // relay server keeps its ports free and an old peer cannot keep using it
    for n in app.db.nodes().into_iter().filter(|n| !n.enabled) {
        // the panel server's own info (version, services, load) stays fresh while its VPN is off too
        if n.id == "local" {
            let _ = app.db.exec("UPDATE nodes SET info=?1 WHERE id='local'", &[&local_info(app).to_string()]);
        }
        // once it is empty, checked again every 5 minutes (an unreachable one must not slow every round)
        {
            let mut g = off_checked().lock().unwrap();
            let last = g.get(&n.id).copied().unwrap_or(0);
            if n.sync_state == "off" && now() - last < 300 {
                continue;
            }
            g.insert(n.id.clone(), now());
        }
        let empty = SyncReq { kmix: Some(crate::kmix::KmixCfg::default()), ..Default::default() };
        let ok = if n.id == "local" { apply_local(app, empty).await; true } else { remote_sync(app, &n, &empty).await.is_ok() };
        let _ = app.db.exec("UPDATE nodes SET online=?1, sync_state='off' WHERE id=?2", &[&(ok as i64), &n.id]);
        if ok && n.id != "local" {
            if let Some(info) = remote_info(app, &n.address, &n.token, n.insecure).await {
                let _ = app.db.exec("UPDATE nodes SET info=?1, last_sync=?2 WHERE id=?3", &[&info.to_string(), &now(), &n.id]);
            }
        }
        crate::live::set_vpn(&n.id, &n.name, vec![]);
    }
    for mut n in app.db.nodes().into_iter().filter(|n| n.enabled) {
        let local = n.id == "local";
        if local {
            let info = local_info(app).to_string();
            let _ = app.db.exec("UPDATE nodes SET info=?1 WHERE id='local'", &[&info]);
            n.info = info;
        }
        let (req, map) = desired_for(app, &users, &n);
        let want = req.wg.len() + req.awg.len();
        let resp: Result<SyncResp, String> = if local { Ok(apply_local(app, req).await) } else { remote_sync(app, &n, &req).await };
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
        if !local && ok {
            if let Some(info) = remote_info(app, &n.address, &n.token, n.insecure).await {
                let _ = app.db.exec("UPDATE nodes SET info=?1 WHERE id=?2", &[&info.to_string(), &n.id]);
            }
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
            if let Some(p) = app.db.peer(uid, &n.id, &proto) {
                let total = st.rx + st.tx;
                let prev = p.rx + p.tx;
                let delta = if total >= prev { total - prev } else { total };
                *add_bytes.entry(uid).or_default() += delta;
                let _ = app.db.exec(
                    "UPDATE peers SET rx=?1, tx=?2 WHERE user_id=?3 AND node_id=?4 AND proto=?5",
                    &[&st.rx, &st.tx, &uid, &n.id, &proto],
                );
            }
            if st.handshake > 0 && now() - st.handshake < 180 {
                here.push((uid, proto.clone()));
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
        for (name, c, proto) in resp.hy2_online.iter().map(|(n, c)| (n, c, "hy2")).chain(resp.kmix_online.iter().map(|(n, c)| (n, c, "kmix"))) {
            if let Some(uid) = by_name.get(name) {
                if *c > 0 {
                    here.push((*uid, proto.to_string()));
                    *online.entry(*uid).or_default() += c;
                    seen.insert(*uid, now());
                }
            }
        }
        for (name, (rx, tx)) in resp.kmix.iter() {
            if let Some(uid) = by_name.get(name) {
                *add_bytes.entry(*uid).or_default() += rx + tx;
            }
        }
        crate::kmix::note_error(&n.id, &resp.kmix_error);
        crate::live::set_vpn(&n.id, &n.name, here);
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

async fn remote_sync(app: &App, n: &Node, req: &SyncReq) -> Result<SyncResp, String> {
    let r = app.node_client(&n.id, n.insecure).post(format!("{}/agent/sync", n.address.trim_end_matches('/')))
        .header("X-Node-Token", &n.token).json(req).send().await.map_err(|e| node_err(&n.address, &e))?;
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
        .header("X-Node-Token", token).send().await.map_err(|e| node_err(addr, &e))?;
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
