//! Admin extras: system stats, services, security, bot config, restore, bulk actions
use crate::api::{authed_pub, user_json};
use crate::util::{hash_password, rand_token};
use crate::App;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Value};
use std::process::Command;
use std::sync::Arc;

type St = State<Arc<App>>;

const SERVICES: &[(&str, &str)] = &[
    ("wireguard", "wg-quick@wg0"),
    ("amneziawg", "awg-quick@awg0"),
    ("hysteria2", "hysteria-server"),
    ("web", "caddy"),
    ("panel", "kanki-panel"),
];

fn deny() -> Response {
    (StatusCode::UNAUTHORIZED, Json(json!({"error": "unauthorized"}))).into_response()
}

fn sh(cmd: &str, args: &[&str]) -> String {
    Command::new(cmd).args(args).output().map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string()).unwrap_or_default()
}

fn read(p: &str) -> String {
    std::fs::read_to_string(p).unwrap_or_default()
}

pub fn router() -> Router<Arc<App>> {
    Router::new()
        .route("/api/system", get(system))
        .route("/api/services/:name/restart", post(restart))
        .route("/api/security", get(security_get))
        .route("/api/security/password", post(change_password))
        .route("/api/security/apikey", post(regen_key))
        .route("/api/bot", get(bot_get).put(bot_put))
        .route("/api/restore", post(restore))
        .route("/api/users/bulk", post(bulk))
}

async fn system(State(app): St, h: HeaderMap) -> Response {
    if !authed_pub(&app, &h) { return deny(); }
    let load: Vec<f64> = read("/proc/loadavg").split_whitespace().take(3).filter_map(|x| x.parse().ok()).collect();
    let cpus = read("/proc/cpuinfo").lines().filter(|l| l.starts_with("processor")).count().max(1);
    let mut mt = 0f64; let mut ma = 0f64;
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
                rx = *f.first().unwrap_or(&0.0); tx = *f.get(8).unwrap_or(&0.0);
            }
        }
    }
    let services: Vec<Value> = SERVICES.iter().map(|(k, unit)| {
        let st = sh("systemctl", &["is-active", *unit]);
        json!({"key": k, "unit": unit, "active": st == "active", "state": st})
    }).collect();
    Json(json!({
        "cpu": ((load.first().copied().unwrap_or(0.0) / cpus as f64) * 100.0).min(100.0).round(),
        "load": load, "cores": cpus,
        "mem_total": mt * 1024.0, "mem_used": (mt - ma) * 1024.0,
        "disk_total": dt, "disk_used": du, "uptime": up,
        "net_rx": rx, "net_tx": tx, "iface": iface,
        "services": services, "version": env!("CARGO_PKG_VERSION"),
    })).into_response()
}

async fn restart(State(app): St, h: HeaderMap, Path(name): Path<String>) -> Response {
    if !authed_pub(&app, &h) { return deny(); }
    let Some((_, unit)) = SERVICES.iter().find(|(k, _)| *k == name) else {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "unknown service"}))).into_response();
    };
    if *unit == "kanki-panel" {
        tokio::spawn(async { tokio::time::sleep(std::time::Duration::from_millis(500)).await; std::process::exit(0) });
        return Json(json!({"ok": true})).into_response();
    }
    let ok = Command::new("systemctl").args(["restart", *unit]).status().map(|s| s.success()).unwrap_or(false);
    Json(json!({"ok": ok})).into_response()
}

async fn security_get(State(app): St, h: HeaderMap) -> Response {
    if !authed_pub(&app, &h) { return deny(); }
    Json(json!({"api_key": app.db.get("api_key"), "admin_user": admin_user(&app)})).into_response()
}

pub fn admin_user(app: &App) -> String {
    let u = app.db.get("admin_user");
    if u.is_empty() { app.env.get("ADMIN_USER").cloned().unwrap_or_default() } else { u }
}

pub fn admin_pass_hash(app: &App) -> String {
    let p = app.db.get("admin_pass");
    if p.is_empty() { app.env.get("ADMIN_PASS").cloned().unwrap_or_default() } else { p }
}

async fn change_password(State(app): St, h: HeaderMap, Json(b): Json<Value>) -> Response {
    if !authed_pub(&app, &h) { return deny(); }
    let user = b["username"].as_str().unwrap_or("").trim();
    let pass = b["password"].as_str().unwrap_or("");
    if pass.len() < 6 {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "password must be at least 6 characters"}))).into_response();
    }
    if !user.is_empty() { app.db.set("admin_user", user); }
    app.db.set("admin_pass", &hash_password(pass));
    app.sessions.lock().unwrap().clear();
    Json(json!({"ok": true})).into_response()
}

async fn regen_key(State(app): St, h: HeaderMap) -> Response {
    if !authed_pub(&app, &h) { return deny(); }
    let k = rand_token(40);
    app.db.set("api_key", &k);
    Json(json!({"api_key": k})).into_response()
}

async fn bot_get(State(app): St, h: HeaderMap) -> Response {
    if !authed_pub(&app, &h) { return deny(); }
    let t = crate::bot::bot_token(&app);
    let masked = if t.len() > 10 { format!("{}…{}", &t[..6], &t[t.len() - 4..]) } else { String::new() };
    Json(json!({"token_set": !t.is_empty(), "token_masked": masked, "admins": crate::bot::bot_admins_raw(&app)})).into_response()
}

async fn bot_put(State(app): St, h: HeaderMap, Json(b): Json<Value>) -> Response {
    if !authed_pub(&app, &h) { return deny(); }
    if let Some(t) = b["token"].as_str() { if !t.trim().is_empty() { app.db.set("bot_token", t.trim()); } }
    if let Some(a) = b["admins"].as_str() { app.db.set("bot_admins", a.trim()); }
    // restart the panel so the bot reloads (systemd brings it back)
    tokio::spawn(async { tokio::time::sleep(std::time::Duration::from_millis(700)).await; std::process::exit(0) });
    Json(json!({"ok": true})).into_response()
}

async fn restore(State(app): St, h: HeaderMap, body: Bytes) -> Response {
    if !authed_pub(&app, &h) { return deny(); }
    if body.len() < 100 || &body[..15] != b"SQLite format 3" {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "not a valid backup file"}))).into_response();
    }
    let dir = app.env.get("DATA_DIR").cloned().unwrap_or_else(|| "/var/lib/kanki".into());
    let path = format!("{}/restore.db", dir);
    if std::fs::write(&path, &body).is_err() {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "write failed"}))).into_response();
    }
    let _ = std::fs::rename(&path, format!("{}/kanki.db", dir));
    let _ = std::fs::remove_file(format!("{}/kanki.db-wal", dir));
    let _ = std::fs::remove_file(format!("{}/kanki.db-shm", dir));
    tokio::spawn(async { tokio::time::sleep(std::time::Duration::from_millis(500)).await; std::process::exit(0) });
    Json(json!({"ok": true})).into_response()
}

async fn bulk(State(app): St, h: HeaderMap, Json(b): Json<Value>) -> Response {
    if !authed_pub(&app, &h) { return deny(); }
    let ids: Vec<i64> = b["ids"].as_array().map(|a| a.iter().filter_map(|x| x.as_i64()).collect()).unwrap_or_default();
    let action = b["action"].as_str().unwrap_or("");
    let days = b["days"].as_i64().unwrap_or(0);
    let gb = b["gb"].as_f64().unwrap_or(0.0);
    for id in &ids {
        let _ = match action {
            "delete" => { app.db.delete_user(*id); Ok(()) }
            "enable" => app.db.exec("UPDATE users SET enabled=1 WHERE id=?1", &[id]).map(|_| ()),
            "disable" => app.db.exec("UPDATE users SET enabled=0 WHERE id=?1", &[id]).map(|_| ()),
            "reset" => app.db.exec("UPDATE users SET used_bytes=0, warned=0 WHERE id=?1", &[id]).map(|_| ()),
            "extend" => app.db.extend(*id, days, gb),
            _ => Ok(()),
        };
    }
    let a = app.clone();
    tokio::spawn(async move { crate::sync::sync_all(&a).await });
    let users: Vec<Value> = ids.iter().filter_map(|i| app.db.user(*i)).map(|u| user_json(&app, &u)).collect();
    Json(json!({"ok": true, "count": ids.len(), "users": users})).into_response()
}
