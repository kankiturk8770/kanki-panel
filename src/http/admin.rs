//! Admin extras: system stats, services, bot management, bulk actions, self-update, repair
use crate::api::{err, user_json};
use crate::guard;
use crate::App;
use axum::extract::{Path, Query, State};
use std::collections::HashMap;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Value};
use std::process::Command;
use std::sync::atomic::Ordering;
use std::sync::Arc;

type St = State<Arc<App>>;

pub const SERVICES: &[(&str, &str)] = &[
    ("wireguard", "wg-quick@wg0"),
    ("amneziawg", "awg-quick@awg0"),
    ("hysteria2", "hysteria-server"),
    ("openvpn-udp", "openvpn-server@udp"),
    ("openvpn-tcp", "openvpn-server@tcp"),
    ("web", "caddy"),
    ("panel", "kanki-panel"),
    ("node", "kanki-node"),
];

fn sh(cmd: &str, args: &[&str]) -> String {
    Command::new(cmd).args(args).output().map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string()).unwrap_or_default()
}

fn read(p: &str) -> String {
    std::fs::read_to_string(p).unwrap_or_default()
}

/// Only services that are installed (enabled or active)
pub fn service_states() -> Value {
    let v: Vec<Value> = SERVICES.iter().filter_map(|(k, unit)| {
        let enabled = sh("systemctl", &["is-enabled", *unit]);
        let st = sh("systemctl", &["is-active", *unit]);
        if enabled != "enabled" && st != "active" {
            return None;
        }
        Some(json!({"key": k, "unit": unit, "active": st == "active", "state": st}))
    }).collect();
    json!(v)
}

/// Restart VPN services that are installed; returns their new state
pub fn repair_services() -> Value {
    let mut out = vec![];
    for (k, unit) in SERVICES.iter().filter(|(k, _)| !["web", "panel", "node"].contains(k)) {
        let unit: &str = unit;
        if sh("systemctl", &["is-enabled", unit]) != "enabled" {
            continue;
        }
        let ok = Command::new("systemctl").args(["restart", unit]).status().map(|s| s.success()).unwrap_or(false);
        out.push(json!({"key": k, "unit": unit, "restarted": ok, "state": sh("systemctl", &["is-active", unit])}));
    }
    json!({"ok": true, "services": out})
}

pub fn router() -> Router<Arc<App>> {
    Router::new()
        .route("/api/system", get(system))
        .route("/api/live", get(live))
        .route("/api/services/:name/:action", post(service_action))
        .route("/api/bot", get(bot_get).put(bot_put).delete(bot_delete))
        .route("/api/bot/test", post(bot_test))
        .route("/api/bot/pause", post(bot_pause))
        .route("/api/bulk/users", post(bulk))
        .route("/api/update/check", get(update_check))
        .route("/api/update/apply", post(update_apply))
        .route("/api/qr", get(qr))
}

async fn qr(State(app): St, h: HeaderMap, Query(q): Query<HashMap<String, String>>) -> Response {
    let _ = guard!(app, h, "users:read");
    let text = q.get("text").cloned().unwrap_or_default();
    match crate::util::qr_svg(&text) {
        Some(svg) => ([(axum::http::header::CONTENT_TYPE, "image/svg+xml")], svg).into_response(),
        None => err(StatusCode::BAD_REQUEST, "too large"),
    }
}

async fn system(State(app): St, h: HeaderMap) -> Response {
    let _ = guard!(app, h, "admin");
    let load: Vec<f64> = read("/proc/loadavg").split_whitespace().take(3).filter_map(|x| x.parse().ok()).collect();
    let cpus = read("/proc/cpuinfo").lines().filter(|l| l.starts_with("processor")).count().max(1);
    let mut mt = 0f64;
    let mut ma = 0f64;
    for l in read("/proc/meminfo").lines() {
        let v: f64 = l.split_whitespace().nth(1).and_then(|x| x.parse().ok()).unwrap_or(0.0);
        if l.starts_with("MemTotal:") { mt = v; }
        if l.starts_with("MemAvailable:") { ma = v; }
    }
    let df: Vec<String> = sh("df", &["-B1", "--output=size,used", "/"]).lines().nth(1).unwrap_or("").split_whitespace().map(|s| s.to_string()).collect();
    let (dt, du): (f64, f64) = (df.first().and_then(|x| x.parse().ok()).unwrap_or(0.0), df.get(1).and_then(|x| x.parse().ok()).unwrap_or(0.0));
    let up: f64 = read("/proc/uptime").split_whitespace().next().and_then(|x| x.parse().ok()).unwrap_or(0.0);
    let iface = sh("sh", &["-c", "ip route show default | awk '{print $5; exit}'"]);
    let (mut rx, mut tx) = (0f64, 0f64);
    for l in read("/proc/net/dev").lines() {
        if let Some((name, rest)) = l.split_once(':') {
            if name.trim() == iface {
                let f: Vec<f64> = rest.split_whitespace().filter_map(|x| x.parse().ok()).collect();
                rx = *f.first().unwrap_or(&0.0);
                tx = *f.get(8).unwrap_or(&0.0);
            }
        }
    }
    Json(json!({
        "cpu": ((load.first().copied().unwrap_or(0.0) / cpus as f64) * 100.0).min(100.0).round(),
        "load": load, "cores": cpus,
        "mem_total": mt * 1024.0, "mem_used": (mt - ma) * 1024.0,
        "disk_total": dt, "disk_used": du, "uptime": up,
        "net_rx": rx, "net_tx": tx, "iface": iface,
        "services": service_states(), "version": crate::VERSION,
    })).into_response()
}

async fn service_action(State(app): St, h: HeaderMap, Path((name, action)): Path<(String, String)>) -> Response {
    let _ = guard!(app, h, "admin");
    let Some((_, unit)) = SERVICES.iter().find(|(k, _)| *k == name) else {
        return err(StatusCode::BAD_REQUEST, "unknown service");
    };
    let unit: &str = unit;
    if !["start", "stop", "restart"].contains(&action.as_str()) {
        return err(StatusCode::BAD_REQUEST, "unknown action");
    }
    if action == "restart" && unit == "kanki-panel" {
        restart_self();
        return Json(json!({"ok": true})).into_response();
    }
    // never saw off the branch the panel itself sits on: web / panel / node can only be restarted
    if action != "restart" && ["kanki-panel", "caddy", "kanki-node"].contains(&unit) {
        return err(StatusCode::BAD_REQUEST, "this service can only be restarted");
    }
    let ok = Command::new("systemctl").args([action.as_str(), unit]).status().map(|s| s.success()).unwrap_or(false);
    Json(json!({"ok": ok})).into_response()
}

/// systemd (Restart=always) brings the process back
pub fn restart_self() {
    tokio::spawn(async {
        tokio::time::sleep(std::time::Duration::from_millis(700)).await;
        std::process::exit(0)
    });
}

// ---------------------------------------------------------------- live metrics (the dashboard polls this every few seconds)
fn default_iface() -> String {
    for l in read("/proc/net/route").lines().skip(1) {
        let f: Vec<&str> = l.split_whitespace().collect();
        if f.len() > 1 && f[1] == "00000000" {
            return f[0].to_string();
        }
    }
    String::new()
}

fn is_virtual_iface(n: &str) -> bool {
    ["lo", "wg", "awg", "tun", "tap", "docker", "veth", "br-", "virbr"].iter().any(|p| n.starts_with(*p))
}

/// (name, rx bytes, tx bytes) of the interface that carries the real traffic
fn pick_iface(ifs: &[(String, f64, f64)]) -> (String, f64, f64) {
    let def = default_iface();
    if let Some(x) = ifs.iter().find(|x| x.0 == def) {
        return x.clone();
    }
    let mut best: (String, f64, f64) = (String::new(), 0.0, 0.0);
    for x in ifs {
        if is_virtual_iface(&x.0) {
            continue;
        }
        if x.1 + x.2 >= best.1 + best.2 {
            best = x.clone();
        }
    }
    best
}

/// Sockets listed in /proc/net/{tcp,udp}[6]. `state` is the hex TCP state ("01" established, "0A" listening); empty = all
fn count_socks(path: &str, state: &str) -> i64 {
    read(path)
        .lines()
        .skip(1)
        .filter(|l| state.is_empty() || l.split_whitespace().nth(3) == Some(state))
        .count() as i64
}

async fn live(State(app): St, h: HeaderMap) -> Response {
    let _ = guard!(app, h, "admin");
    // cumulative CPU jiffies: the browser turns two samples into a real CPU percentage
    let stat = read("/proc/stat");
    let cf: Vec<f64> = stat.lines().next().unwrap_or("").split_whitespace().skip(1).filter_map(|x| x.parse().ok()).collect();
    let cpu_total: f64 = cf.iter().take(8).sum();
    let cpu_idle: f64 = cf.get(3).copied().unwrap_or(0.0) + cf.get(4).copied().unwrap_or(0.0);
    let load: Vec<f64> = read("/proc/loadavg").split_whitespace().take(3).filter_map(|x| x.parse().ok()).collect();
    let cores = read("/proc/cpuinfo").lines().filter(|l| l.starts_with("processor")).count().max(1);
    let (mut mt, mut ma, mut swt, mut swf) = (0f64, 0f64, 0f64, 0f64);
    for l in read("/proc/meminfo").lines() {
        let v: f64 = l.split_whitespace().nth(1).and_then(|x| x.parse().ok()).unwrap_or(0.0);
        if l.starts_with("MemTotal:") { mt = v; }
        if l.starts_with("MemAvailable:") { ma = v; }
        if l.starts_with("SwapTotal:") { swt = v; }
        if l.starts_with("SwapFree:") { swf = v; }
    }
    let mut ifs: Vec<(String, f64, f64)> = vec![];
    for l in read("/proc/net/dev").lines() {
        if let Some((name, rest)) = l.split_once(':') {
            let f: Vec<f64> = rest.split_whitespace().filter_map(|x| x.parse().ok()).collect();
            if f.len() > 8 {
                ifs.push((name.trim().to_string(), f[0], f[8]));
            }
        }
    }
    let (iface, rx, tx) = pick_iface(&ifs);
    let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0);
    let up: f64 = read("/proc/uptime").split_whitespace().next().and_then(|x| x.parse().ok()).unwrap_or(0.0);
    let host = read("/proc/sys/kernel/hostname").trim().to_string();
    let kernel = read("/proc/sys/kernel/osrelease").trim().to_string();
    let tcp_est = count_socks("/proc/net/tcp", "01") + count_socks("/proc/net/tcp6", "01");
    let tcp_listen = count_socks("/proc/net/tcp", "0A") + count_socks("/proc/net/tcp6", "0A");
    let udp = count_socks("/proc/net/udp", "") + count_socks("/proc/net/udp6", "");
    Json(json!({
        "ts": ts, "uptime": up, "cores": cores, "load": load, "host": host, "kernel": kernel,
        "cpu_total": cpu_total, "cpu_idle": cpu_idle,
        "mem_total": mt * 1024.0, "mem_used": (mt - ma) * 1024.0,
        "swap_total": swt * 1024.0, "swap_used": (swt - swf) * 1024.0,
        "iface": iface, "net_rx": rx, "net_tx": tx,
        "tcp_est": tcp_est, "tcp_listen": tcp_listen, "udp": udp,
    })).into_response()
}

// ---------------------------------------------------------------- Telegram sales bot
fn mask(t: &str) -> String {
    if t.len() > 10 { format!("{}…{}", &t[..6], &t[t.len() - 4..]) } else { String::new() }
}

async fn bot_get(State(app): St, h: HeaderMap) -> Response {
    let _ = guard!(app, h, "settings");
    let t = crate::bot::bot_token(&app);
    let alive = app.bot_alive.load(Ordering::Relaxed);
    Json(json!({
        "token_set": !t.is_empty(), "token_masked": mask(&t), "admins": crate::bot::bot_admins_raw(&app),
        "paused": app.db.on("bot_paused"), "online": !t.is_empty() && crate::util::now() - alive < 120,
        "username": app.db.get("bot_username"), "name": app.db.get("bot_name"),
    })).into_response()
}

async fn bot_put(State(app): St, h: HeaderMap, Json(b): Json<Value>) -> Response {
    let _ = guard!(app, h, "settings");
    if let Some(t) = b["token"].as_str().map(|s| s.trim()).filter(|s| !s.is_empty()) {
        match tg_get_me(&app, t).await {
            Some(me) => {
                app.db.set("bot_token", t);
                app.db.set("bot_username", me["username"].as_str().unwrap_or(""));
                app.db.set("bot_name", me["first_name"].as_str().unwrap_or(""));
            }
            None => return err(StatusCode::BAD_REQUEST, "Telegram rejected this token"),
        }
    }
    if let Some(a) = b["admins"].as_str() {
        app.db.set("bot_admins", a.trim());
    }
    restart_self();
    Json(json!({"ok": true})).into_response()
}

async fn bot_delete(State(app): St, h: HeaderMap) -> Response {
    let _ = guard!(app, h, "settings");
    app.db.set("bot_token", "");
    app.db.set("bot_username", "");
    app.db.set("bot_name", "");
    restart_self();
    Json(json!({"ok": true})).into_response()
}

pub async fn tg_get_me(app: &App, token: &str) -> Option<Value> {
    let r = app.http.get(format!("https://api.telegram.org/bot{}/getMe", token)).send().await.ok()?;
    let v: Value = r.json().await.ok()?;
    if v["ok"].as_bool() == Some(true) { Some(v["result"].clone()) } else { None }
}

async fn bot_test(State(app): St, h: HeaderMap) -> Response {
    let _ = guard!(app, h, "settings");
    let t = crate::bot::bot_token(&app);
    if t.is_empty() {
        return err(StatusCode::BAD_REQUEST, "no bot token");
    }
    match tg_get_me(&app, &t).await {
        Some(me) => Json(json!({"ok": true, "username": me["username"], "name": me["first_name"]})).into_response(),
        None => Json(json!({"ok": false, "error": "cannot reach Telegram or token invalid"})).into_response(),
    }
}

async fn bot_pause(State(app): St, h: HeaderMap) -> Response {
    let _ = guard!(app, h, "settings");
    let v = if app.db.on("bot_paused") { "0" } else { "1" };
    app.db.set("bot_paused", v);
    Json(json!({"ok": true, "paused": v == "1"})).into_response()
}

// ---------------------------------------------------------------- bulk
async fn bulk(State(app): St, h: HeaderMap, Json(b): Json<Value>) -> Response {
    let _ = guard!(app, h, "users:write");
    let ids: Vec<i64> = b["ids"].as_array().map(|a| a.iter().filter_map(|x| x.as_i64()).collect()).unwrap_or_default();
    let action = b["action"].as_str().unwrap_or("").to_string();
    for id in &ids {
        let _ = crate::api::user_action(&app, *id, &action, &b);
    }
    let a = app.clone();
    tokio::spawn(async move { crate::sync::sync_all(&a).await });
    let users: Vec<Value> = ids.iter().filter_map(|i| app.db.user(*i)).map(|u| user_json(&app, &u)).collect();
    Json(json!({"ok": true, "count": ids.len(), "users": users})).into_response()
}

// ---------------------------------------------------------------- self-update (GitHub Releases "latest")
fn repo() -> String {
    std::env::var("KANKI_REPO").ok().filter(|s| !s.is_empty())
        .unwrap_or_else(|| read("/etc/kanki/repo").trim().to_string())
}

async fn latest_version(app: &App) -> Result<String, String> {
    let r = repo();
    if r.is_empty() {
        return Err("GitHub repo is not configured (/etc/kanki/repo)".into());
    }
    let url = format!("https://github.com/{}/releases/download/latest/version.txt", r);
    let res = app.http.get(&url).send().await.map_err(|e| e.to_string())?;
    if !res.status().is_success() {
        return Err(format!("cannot read {} ({})", url, res.status()));
    }
    Ok(res.text().await.map_err(|e| e.to_string())?.trim().to_string())
}

fn newer(latest: &str, cur: &str) -> bool {
    let p = |s: &str| -> Vec<u64> { s.trim_start_matches('v').split('.').map(|x| x.parse().unwrap_or(0)).collect() };
    p(latest) > p(cur)
}

async fn update_check(State(app): St, h: HeaderMap) -> Response {
    let _ = guard!(app, h, "admin");
    match latest_version(&app).await {
        Ok(l) => Json(json!({"current": crate::VERSION, "latest": l, "available": newer(&l, crate::VERSION)})).into_response(),
        Err(e) => Json(json!({"current": crate::VERSION, "latest": "", "available": false, "error": e})).into_response(),
    }
}

/// Download, verify sha256, swap binary, restart
pub async fn self_update(app: &App) -> Result<String, String> {
    let r = repo();
    if r.is_empty() {
        return Err("GitHub repo is not configured".into());
    }
    let base = format!("https://github.com/{}/releases/download/latest", r);
    let bin = app.http.get(format!("{}/kanki-panel", base)).timeout(std::time::Duration::from_secs(300)).send().await
        .map_err(|e| e.to_string())?;
    if !bin.status().is_success() {
        return Err(format!("download failed ({})", bin.status()));
    }
    let bytes = bin.bytes().await.map_err(|e| e.to_string())?;
    let sum = app.http.get(format!("{}/kanki-panel.sha256", base)).send().await.map_err(|e| e.to_string())?
        .text().await.map_err(|e| e.to_string())?;
    let want = sum.split_whitespace().next().unwrap_or("").to_lowercase();
    let got = {
        use sha2::{Digest, Sha256};
        let mut hs = Sha256::new();
        hs.update(&bytes);
        hex::encode(hs.finalize())
    };
    if want.is_empty() || want != got {
        return Err("checksum mismatch, update aborted".into());
    }
    let path = std::env::current_exe().map_err(|e| e.to_string())?;
    let tmp = path.with_extension("new");
    std::fs::write(&tmp, &bytes).map_err(|e| e.to_string())?;
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755));
    }
    std::fs::rename(&tmp, &path).map_err(|e| e.to_string())?;
    let v = latest_version(app).await.unwrap_or_default();
    restart_self();
    Ok(v)
}

async fn update_apply(State(app): St, h: HeaderMap) -> Response {
    if let Err(r) = crate::auth::check_session(&app, &h) {
        return r;
    }
    match self_update(&app).await {
        Ok(v) => Json(json!({"ok": true, "version": v})).into_response(),
        Err(e) => err(StatusCode::BAD_GATEWAY, &e),
    }
}
