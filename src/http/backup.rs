//! Backup & restore: encrypted archive (AES-256 + PBKDF2 via openssl) with the database,
//! server keys/configs and certificates; scheduled Telegram backups.
use crate::api::err;
use crate::guard;
use crate::util::{now, rand_token, stamp};
use crate::App;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Value};
use std::process::Command;
use std::sync::Arc;

type St = State<Arc<App>>;

/// Files that make a server reproducible (keys, configs). Missing ones are skipped.
const FILES: &[&str] = &[
    "/etc/kanki/kanki.env",
    "/etc/kanki/repo",
    "/etc/wireguard/wg0.conf",
    "/etc/amnezia/amneziawg/awg0.conf",
    "/etc/hysteria/config.yaml",
    "/etc/openvpn/server/ca.crt",
    "/etc/openvpn/server/ca.key",
    "/etc/openvpn/server/server.crt",
    "/etc/openvpn/server/server.key",
    "/etc/openvpn/server/tc.key",
    "/etc/openvpn/server/udp.conf",
    "/etc/openvpn/server/tcp.conf",
    "/etc/kanki/tls/fullchain.pem",
    "/etc/kanki/tls/privkey.pem",
];

pub fn db_snapshot(app: &App) -> Option<Vec<u8>> {
    let path = format!("/tmp/kanki-db-{}.db", rand_token(8));
    app.db.with(|c| c.execute(&format!("VACUUM INTO '{}'", path), [])).ok()?;
    let b = std::fs::read(&path).ok();
    let _ = std::fs::remove_file(&path);
    b
}

fn run(cmd: &str, args: &[&str], pass: Option<&str>) -> Result<(), String> {
    let mut c = Command::new(cmd);
    c.args(args);
    if let Some(p) = pass {
        c.env("KANKI_BK_PASS", p);
    }
    let o = c.output().map_err(|e| format!("{}: {}", cmd, e))?;
    if o.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&o.stderr).trim().chars().take(300).collect())
    }
}

/// Returns (bytes, file name). Encrypted when a passphrase is given.
pub fn make_archive(app: &App, pass: &str) -> Result<(Vec<u8>, String), String> {
    let dir = format!("/tmp/kanki-bk-{}", rand_token(10));
    std::fs::create_dir_all(format!("{}/files", dir)).map_err(|e| e.to_string())?;
    let res = (|| -> Result<(Vec<u8>, String), String> {
        let db = db_snapshot(app).ok_or("database snapshot failed")?;
        std::fs::write(format!("{}/kanki.db", dir), db).map_err(|e| e.to_string())?;
        for f in FILES {
            if std::path::Path::new(f).exists() {
                let dst = format!("{}/files{}", dir, f);
                if let Some(parent) = std::path::Path::new(&dst).parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                let _ = std::fs::copy(f, &dst);
            }
        }
        let meta = json!({"version": crate::VERSION, "ts": now(), "domain": app.env.get("DOMAIN").cloned().unwrap_or_default()});
        std::fs::write(format!("{}/meta.json", dir), meta.to_string()).map_err(|e| e.to_string())?;
        let tgz = format!("{}/out.tar.gz", dir);
        run("tar", &["-czf", &tgz, "-C", &dir, "kanki.db", "files", "meta.json"], None)?;
        let name_base = format!("kanki-backup-{}", stamp(now()));
        if pass.is_empty() {
            return Ok((std::fs::read(&tgz).map_err(|e| e.to_string())?, format!("{}.tar.gz", name_base)));
        }
        let enc = format!("{}/out.kbk", dir);
        run("openssl", &["enc", "-aes-256-cbc", "-salt", "-pbkdf2", "-iter", "200000", "-in", &tgz, "-out", &enc, "-pass", "env:KANKI_BK_PASS"], Some(pass))?;
        Ok((std::fs::read(&enc).map_err(|e| e.to_string())?, format!("{}.kbk", name_base)))
    })();
    let _ = std::fs::remove_dir_all(&dir);
    res
}

/// Accepts .kbk (encrypted), .tar.gz, or a raw SQLite file from older versions
pub fn restore(app: &App, data: &[u8], pass: &str, full: bool) -> Result<String, String> {
    let dir = format!("/tmp/kanki-rs-{}", rand_token(10));
    std::fs::create_dir_all(format!("{}/x", dir)).map_err(|e| e.to_string())?;
    let res = (|| -> Result<String, String> {
        let dbfile: String;
        if data.len() > 16 && &data[..15] == b"SQLite format 3" {
            dbfile = format!("{}/kanki.db", dir);
            std::fs::write(&dbfile, data).map_err(|e| e.to_string())?;
        } else {
            let tgz = format!("{}/in.tar.gz", dir);
            if data.len() > 8 && &data[..8] == b"Salted__" {
                if pass.is_empty() {
                    return Err("this backup is encrypted, enter the passphrase".to_string());
                }
                let enc = format!("{}/in.kbk", dir);
                std::fs::write(&enc, data).map_err(|e| e.to_string())?;
                run("openssl", &["enc", "-d", "-aes-256-cbc", "-pbkdf2", "-iter", "200000", "-in", &enc, "-out", &tgz, "-pass", "env:KANKI_BK_PASS"], Some(pass))
                    .map_err(|_| "wrong passphrase or damaged file".to_string())?;
            } else if data.len() > 2 && data[0] == 0x1f && data[1] == 0x8b {
                std::fs::write(&tgz, data).map_err(|e| e.to_string())?;
            } else {
                return Err("not a Kanki backup file".to_string());
            }
            let x = format!("{}/x", dir);
            run("tar", &["-xzf", &tgz, "-C", &x], None).map_err(|_| "archive is damaged".to_string())?;
            dbfile = format!("{}/kanki.db", x);
            if full && std::path::Path::new(&format!("{}/files", x)).exists() {
                run("cp", &["-a", &format!("{}/files/.", x), "/"], None)?;
            }
        }
        let head = std::fs::read(&dbfile).map_err(|_| "database missing in backup".to_string())?;
        if head.len() < 100 || &head[..15] != b"SQLite format 3" {
            return Err("database in backup is invalid".to_string());
        }
        let ddir = app.data_dir();
        let tmp = format!("{}/restore.db", ddir);
        std::fs::write(&tmp, &head).map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, format!("{}/kanki.db", ddir)).map_err(|e| e.to_string())?;
        let _ = std::fs::remove_file(format!("{}/kanki.db-wal", ddir));
        let _ = std::fs::remove_file(format!("{}/kanki.db-shm", ddir));
        Ok(if full { "database + server files restored".to_string() } else { "database restored".to_string() })
    })();
    let _ = std::fs::remove_dir_all(&dir);
    res
}

pub fn router() -> Router<Arc<App>> {
    Router::new()
        .route("/api/backup", get(backup_legacy).post(backup_download))
        .route("/api/restore", post(restore_upload))
        .route("/api/tgbackup", get(tgb_get).put(tgb_put))
        .route("/api/tgbackup/test", post(tgb_test))
        .route("/api/tgbackup/send", post(tgb_send))
}

fn file_response(bytes: Vec<u8>, name: &str) -> Response {
    (
        [(header::CONTENT_TYPE, "application/octet-stream".to_string()),
         (header::CONTENT_DISPOSITION, format!("attachment; filename=\"{}\"", name))],
        bytes,
    ).into_response()
}

/// Old API: plain SQLite file
async fn backup_legacy(State(app): St, h: HeaderMap) -> Response {
    let _ = guard!(app, h, "backup");
    match db_snapshot(&app) {
        Some(b) => file_response(b, &format!("kanki-backup-{}.db", stamp(now()))),
        None => err(StatusCode::INTERNAL_SERVER_ERROR, "backup failed"),
    }
}

async fn backup_download(State(app): St, h: HeaderMap, Json(b): Json<Value>) -> Response {
    let _ = guard!(app, h, "backup");
    let pass = b["passphrase"].as_str().unwrap_or("").to_string();
    if !pass.is_empty() && pass.len() < 6 {
        return err(StatusCode::BAD_REQUEST, "passphrase must be at least 6 characters");
    }
    let a = app.clone();
    match tokio::task::spawn_blocking(move || make_archive(&a, &pass)).await {
        Ok(Ok((bytes, name))) => file_response(bytes, &name),
        Ok(Err(e)) => err(StatusCode::INTERNAL_SERVER_ERROR, &e),
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "backup failed"),
    }
}

async fn restore_upload(State(app): St, h: HeaderMap, body: Bytes) -> Response {
    if let Err(r) = crate::auth::check_session(&app, &h) {
        return r;
    }
    let pass = h.get("x-passphrase").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    let full = h.get("x-full").and_then(|v| v.to_str().ok()) == Some("1");
    let a = app.clone();
    let data = body.to_vec();
    match tokio::task::spawn_blocking(move || restore(&a, &data, &pass, full)).await {
        Ok(Ok(msg)) => {
            crate::admin::restart_self();
            Json(json!({"ok": true, "message": msg})).into_response()
        }
        Ok(Err(e)) => err(StatusCode::BAD_REQUEST, &e),
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "restore failed"),
    }
}

// ---------------------------------------------------------------- Telegram auto backup
fn tgb_token(app: &App) -> String {
    let t = app.db.get("tgb_token");
    if t.is_empty() { crate::bot::bot_token(app) } else { t }
}

async fn tgb_get(State(app): St, h: HeaderMap) -> Response {
    let _ = guard!(app, h, "backup");
    let t = app.db.get("tgb_token");
    Json(json!({
        "on": app.db.on("tgb_on"), "token_set": !t.is_empty(), "uses_bot_token": t.is_empty() && !crate::bot::bot_token(&app).is_empty(),
        "chat": app.db.get("tgb_chat"), "hours": app.db.get("tgb_hours"), "pass_set": !app.db.get("tgb_pass").is_empty(),
        "last": app.db.get("tgb_last").parse::<i64>().unwrap_or(0), "status": app.db.get("tgb_status"),
    })).into_response()
}

async fn tgb_put(State(app): St, h: HeaderMap, Json(b): Json<Value>) -> Response {
    let _ = guard!(app, h, "backup");
    if let Some(t) = b["token"].as_str().map(|s| s.trim()).filter(|s| !s.is_empty()) {
        app.db.set("tgb_token", t);
    }
    if let Some(c) = b["chat"].as_str() {
        app.db.set("tgb_chat", c.trim());
    }
    if let Some(hh) = b["hours"].as_i64().or_else(|| b["hours"].as_str().and_then(|s| s.parse().ok())) {
        app.db.set("tgb_hours", &hh.clamp(1, 24 * 30).to_string());
    }
    if let Some(p) = b["pass"].as_str().filter(|s| !s.is_empty()) {
        if p.len() < 6 {
            return err(StatusCode::BAD_REQUEST, "passphrase must be at least 6 characters");
        }
        app.db.set("tgb_pass", p);
    }
    if let Some(on) = b["on"].as_bool() {
        app.db.set("tgb_on", if on { "1" } else { "0" });
    }
    Json(json!({"ok": true})).into_response()
}

async fn tg_call(app: &App, token: &str, method: &str, body: Value) -> Option<Value> {
    let r = app.http.post(format!("https://api.telegram.org/bot{}/{}", token, method)).json(&body).send().await.ok()?;
    let v: Value = r.json().await.ok()?;
    if v["ok"].as_bool() == Some(true) { Some(v["result"].clone()) } else { None }
}

async fn tgb_test(State(app): St, h: HeaderMap) -> Response {
    let _ = guard!(app, h, "backup");
    let token = tgb_token(&app);
    if token.is_empty() {
        return err(StatusCode::BAD_REQUEST, "set a bot token first");
    }
    let Some(me) = tg_call(&app, &token, "getMe", json!({})).await else {
        return err(StatusCode::BAD_GATEWAY, "token invalid or Telegram unreachable");
    };
    let mut chat = app.db.get("tgb_chat");
    if chat.is_empty() {
        // the sales bot long-polls its own token, so only probe updates on a dedicated token
        if !app.db.get("tgb_token").is_empty() && app.db.get("tgb_token") != crate::bot::bot_token(&app) {
            if let Some(Value::Array(ups)) = tg_call(&app, &token, "getUpdates", json!({"limit": 50})).await {
                if let Some(id) = ups.iter().rev().find_map(|u| u["message"]["chat"]["id"].as_i64()) {
                    chat = id.to_string();
                }
            }
        }
        if chat.is_empty() {
            chat = crate::bot::bot_admins_raw(&app).split(',').next().unwrap_or("").trim().to_string();
        }
        if chat.is_empty() {
            return err(StatusCode::BAD_REQUEST, "send /start to the bot first, or fill Chat ID");
        }
        app.db.set("tgb_chat", &chat);
    }
    let sent = tg_call(&app, &token, "sendMessage", json!({"chat_id": chat, "text": "✅ Kanki Panel backup channel connected"})).await;
    Json(json!({"ok": sent.is_some(), "bot": me["username"], "chat": chat})).into_response()
}

pub async fn send_backup(app: &App) -> Result<(), String> {
    let token = tgb_token(app);
    let chat = app.db.get("tgb_chat");
    if token.is_empty() || chat.is_empty() {
        return Err("token / chat id missing".into());
    }
    let pass = app.db.get("tgb_pass");
    let (bytes, name) = make_archive(app, &pass)?;
    let caption = format!("💾 {} backup · {} · {}", app.db.get("panel_name"), crate::util::iso(now()), if pass.is_empty() { "not encrypted" } else { "encrypted" });
    let part = reqwest::multipart::Part::bytes(bytes).file_name(name);
    let form = reqwest::multipart::Form::new().text("chat_id", chat).text("caption", caption).part("document", part);
    let r = app.http.post(format!("https://api.telegram.org/bot{}/sendDocument", token)).multipart(form)
        .timeout(std::time::Duration::from_secs(180)).send().await.map_err(|e| e.to_string())?;
    let v: Value = r.json().await.map_err(|e| e.to_string())?;
    if v["ok"].as_bool() == Some(true) {
        Ok(())
    } else {
        Err(v["description"].as_str().unwrap_or("telegram error").to_string())
    }
}

async fn tgb_send(State(app): St, h: HeaderMap) -> Response {
    let _ = guard!(app, h, "backup");
    let r = send_backup(&app).await;
    record(&app, &r);
    match r {
        Ok(_) => Json(json!({"ok": true})).into_response(),
        Err(e) => err(StatusCode::BAD_GATEWAY, &e),
    }
}

fn record(app: &App, r: &Result<(), String>) {
    app.db.set("tgb_last", &now().to_string());
    app.db.set("tgb_status", &match r { Ok(_) => "ok".to_string(), Err(e) => format!("error: {}", e) });
}

pub async fn telegram_loop(app: Arc<App>) {
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        if !app.db.on("tgb_on") {
            continue;
        }
        let hours: i64 = app.db.get("tgb_hours").parse::<i64>().unwrap_or(24).max(1);
        let last: i64 = app.db.get("tgb_last").parse().unwrap_or(0);
        if now() - last < hours * 3600 {
            continue;
        }
        let r = send_backup(&app).await;
        record(&app, &r);
    }
}
