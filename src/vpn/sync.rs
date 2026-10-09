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
}

fn loadavg() -> String {
    std::fs::read_to_string("/proc/loadavg").unwrap_or_default().split_whitespace().take(3).collect::<Vec<_>>().join(" ")
}

/// This server's keys, ports and params (used to build client configs)
pub fn local_info(app: &App) -> Value {
    let e = &app.env;
    let g = |k: &str| e.get(k).cloned().unwrap_or_default();
    json!({
        "wg_pub": wg::iface_pub("wg"), "wg_port": wg::listen_port("wg"),
        "awg_pub": wg::iface_pub("awg"), "awg_port": wg::listen_port("awg"),
        "awg": wg::awg_params(),
        "hy2_port": g("HY2_PORT"), "hy2_obfs": g("HY2_OBFS"), "hy2_sni": g("DOMAIN"),
        "hy2_insecure": g("HY2_INSECURE"),
        "services": crate::admin::service_states(), "version": crate::VERSION, "load": loadavg(),
        "stats": crate::admin::node_stats(),
    })
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
    SyncResp { wg: w, awg: a, hy2, hy2_online }
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

    for mut n in app.db.nodes().into_iter().filter(|n| n.enabled) {
        let local = n.id == "local";
        if local {
            let info = local_info(app).to_string();
            let _ = app.db.exec("UPDATE nodes SET info=?1 WHERE id='local'", &[&info]);
            n.info = info;
        }
        let (req, map) = desired_for(app, &users, &n);
        let want = req.wg.len() + req.awg.len();
        let resp: Option<SyncResp> = if local { Some(apply_local(app, req).await) } else { remote_sync(app, &n, &req).await };
        let ok = resp.is_some();
        let state = match &resp {
            None => "offline",
            Some(r) => {
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
        let Some(resp) = resp else { continue };

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
        for (name, c) in resp.hy2_online.iter() {
            if let Some(uid) = by_name.get(name) {
                if *c > 0 {
                    *online.entry(*uid).or_default() += c;
                    seen.insert(*uid, now());
                }
            }
        }
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

async fn remote_sync(app: &App, n: &Node, req: &SyncReq) -> Option<SyncResp> {
    let r = app.client(n.insecure).post(format!("{}/agent/sync", n.address.trim_end_matches('/')))
        .header("X-Node-Token", &n.token).json(req).send().await.ok()?;
    if !r.status().is_success() {
        return None;
    }
    r.json::<SyncResp>().await.ok()
}

pub async fn remote_info(app: &App, addr: &str, token: &str, insecure: bool) -> Option<Value> {
    let r = app.client(insecure).get(format!("{}/agent/info", addr.trim_end_matches('/')))
        .header("X-Node-Token", token).send().await.ok()?;
    if !r.status().is_success() {
        return None;
    }
    r.json::<Value>().await.ok()
}

pub async fn remote_post(app: &App, n: &Node, path: &str) -> Option<Value> {
    let r = app.client(n.insecure).post(format!("{}{}", n.address.trim_end_matches('/'), path))
        .header("X-Node-Token", &n.token).timeout(std::time::Duration::from_secs(120)).send().await.ok()?;
    r.json::<Value>().await.ok()
}

pub async fn remote_post_json(app: &App, n: &Node, path: &str, body: &Value) -> Option<Value> {
    let r = app.client(n.insecure).post(format!("{}{}", n.address.trim_end_matches('/'), path))
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
