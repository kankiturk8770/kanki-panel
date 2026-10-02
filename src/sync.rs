//! همگام‌سازی کاربران با نودها، شمارش ترافیک، اعمال محدودیت‌ها
use crate::db::User;
use crate::util::now;
use crate::wg::{self, PeerSpec, PeerStat};
use crate::App;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Serialize, Deserialize, Default)]
pub struct SyncReq {
    pub wg: Vec<PeerSpec>,
    pub awg: Vec<PeerSpec>,
    /// کد ← نام کاربری (برای Hysteria2)
    pub hy2: HashMap<String, String>,
}

#[derive(Serialize, Deserialize, Default)]
pub struct SyncResp {
    pub wg: HashMap<String, PeerStat>,
    pub awg: HashMap<String, PeerStat>,
    pub hy2: HashMap<String, (i64, i64)>,
    pub hy2_online: HashMap<String, i64>,
}

/// اطلاعات این سرور (کلیدها، پورت‌ها، پارامترها) برای ساخت کانفیگ کلاینت
pub fn local_info(app: &App) -> Value {
    let e = &app.env;
    let g = |k: &str| e.get(k).cloned().unwrap_or_default();
    json!({
        "wg_pub": wg::iface_pub("wg"), "wg_port": wg::listen_port("wg"),
        "awg_pub": wg::iface_pub("awg"), "awg_port": wg::listen_port("awg"),
        "awg": wg::awg_params(),
        "hy2_port": g("HY2_PORT"), "hy2_obfs": g("HY2_OBFS"), "hy2_sni": g("DOMAIN"),
        "hy2_insecure": g("HY2_INSECURE"),
    })
}

/// اعمال روی همین سرور
pub async fn apply_local(app: &App, req: SyncReq) -> SyncResp {
    {
        let mut m = app.hy2_allowed.lock().unwrap();
        *m = req.hy2.clone();
    }
    let (wgv, awgv) = (req.wg, req.awg);
    let (w, a) = tokio::task::spawn_blocking(move || (wg::apply("wg", &wgv), wg::apply("awg", &awgv)))
        .await
        .unwrap_or_default();
    let port = app.env.get("HY2_STATS_PORT").cloned().unwrap_or_default();
    let secret = app.env.get("HY2_SECRET").cloned().unwrap_or_default();
    SyncResp {
        wg: w,
        awg: a,
        hy2: crate::hy2::traffic(&port, &secret).await,
        hy2_online: crate::hy2::online(&port, &secret).await,
    }
}

fn desired_for(app: &App, users: &[User], node_id: &str) -> (SyncReq, Vec<(i64, String, String)>) {
    // (user_id, proto, pubkey)
    let mut req = SyncReq::default();
    let mut map = vec![];
    for u in users.iter().filter(|u| u.active() && u.on_node(node_id)) {
        for proto in ["wg", "awg"] {
            if !u.has_proto(proto) {
                continue;
            }
            if let Some(p) = app.db.ensure_peer(u.id, node_id, proto) {
                let spec = PeerSpec { pubkey: p.pubkey.clone(), psk: p.psk.clone(), ip: p.ip.clone() };
                if proto == "wg" { req.wg.push(spec) } else { req.awg.push(spec) }
                map.push((u.id, proto.to_string(), p.pubkey));
            }
        }
        if u.has_proto("hy2") {
            req.hy2.insert(u.code.clone(), u.username.clone());
        }
    }
    (req, map)
}

/// یک دور همگام‌سازی همه‌ی نودها
pub async fn sync_all(app: &Arc<App>) {
    let users = app.db.users();
    let mut online: HashMap<i64, i64> = HashMap::new();
    let mut seen: HashMap<i64, i64> = HashMap::new();
    let mut add_bytes: HashMap<i64, i64> = HashMap::new();
    let by_name: HashMap<String, i64> = users.iter().map(|u| (u.username.clone(), u.id)).collect();

    for n in app.db.nodes().into_iter().filter(|n| n.enabled) {
        let (req, map) = desired_for(app, &users, &n.id);
        let resp: Option<SyncResp> = if n.id == "local" {
            let info = local_info(app);
            let _ = app.db.exec("UPDATE nodes SET info=?1 WHERE id='local'", &[&info.to_string()]);
            Some(apply_local(app, req).await)
        } else {
            remote_sync(app, &n.address, &n.token, &req).await
        };
        let ok = resp.is_some();
        let _ = app.db.exec("UPDATE nodes SET online=?1, last_sync=?2 WHERE id=?3", &[&(ok as i64), &now(), &n.id]);
        if n.id != "local" && ok {
            if let Some(info) = remote_info(app, &n.address, &n.token).await {
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
        for (name, (rx, tx)) in &resp.hy2 {
            if let Some(uid) = by_name.get(name) {
                *add_bytes.entry(*uid).or_default() += rx + tx;
            }
        }
        for (name, c) in &resp.hy2_online {
            if let Some(uid) = by_name.get(name) {
                *online.entry(*uid).or_default() += c;
                seen.insert(*uid, now());
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

async fn remote_sync(app: &App, addr: &str, token: &str, req: &SyncReq) -> Option<SyncResp> {
    let r = app.http.post(format!("{}/agent/sync", addr.trim_end_matches('/')))
        .header("X-Node-Token", token).json(req).send().await.ok()?;
    if !r.status().is_success() {
        return None;
    }
    r.json::<SyncResp>().await.ok()
}

pub async fn remote_info(app: &App, addr: &str, token: &str) -> Option<Value> {
    let r = app.http.get(format!("{}/agent/info", addr.trim_end_matches('/')))
        .header("X-Node-Token", token).send().await.ok()?;
    if !r.status().is_success() {
        return None;
    }
    r.json::<Value>().await.ok()
}

/// حلقه‌ی همیشگی
pub async fn run(app: Arc<App>) {
    loop {
        sync_all(&app).await;
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
    }
}
