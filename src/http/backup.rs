//! Backup & restore: encrypted archive (AES-256 + PBKDF2 via openssl) with the database,
//! server keys/configs and certificates; scheduled Telegram backups.
use crate::api::err;
use crate::guard;
use crate::util::{now, rand_token, stamp};
use crate::App;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
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
    "/etc/kanki/tls/fullchain.pem",
    "/etc/kanki/tls/privkey.pem",
];

/// Creates a directory only the owner can enter. Backups hold password hashes, API keys and the
/// private keys of the VPN servers, so nothing of them may sit in a folder others can list.
fn private_dir(path: &str) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(path).map_err(|e| e.to_string())?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())
}

pub fn db_snapshot(app: &App) -> Option<Vec<u8>> {
    let dir = format!("/tmp/kanki-snap-{}", rand_token(12));
    private_dir(&dir).ok()?;
    let path = format!("{}/snap.db", dir);
    let ok = app.db.with(|c| c.execute(&format!("VACUUM INTO '{}'", path), [])).is_ok();
    let b = if ok { std::fs::read(&path).ok() } else { None };
    let _ = std::fs::remove_dir_all(&dir);
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
    make_archive_with(app, pass, false)
}

/// Plain files directly in `src` copied to `dst` (no links, no folders): the app files and the node
/// certificate pins are flat folders, and nothing else may come out of a backup.
fn copy_flat(src: &str, dst: &str) -> usize {
    let Ok(rd) = std::fs::read_dir(src) else { return 0 };
    let _ = std::fs::create_dir_all(dst);
    let mut n = 0;
    for e in rd.flatten() {
        let Ok(m) = std::fs::symlink_metadata(e.path()) else { continue };
        let name = e.file_name().to_string_lossy().to_string();
        if !m.is_file() || name.starts_with('.') || name.contains('/') {
            continue;
        }
        if std::fs::copy(e.path(), format!("{}/{}", dst, name)).is_ok() {
            n += 1;
        }
    }
    n
}

/// What a backup holds, written next to it (meta.json): the version, when, the domain and the public
/// IP of the server it was made on (a restore elsewhere replaces that IP), and counts to check it by.
fn meta(app: &App, apps: usize) -> Value {
    json!({
        "version": crate::VERSION, "ts": now(), "domain": app.env.get("DOMAIN").cloned().unwrap_or_default(),
        "ip": app.db.get("my_ip"),
        "users": app.db.count("SELECT COUNT(*) FROM users"),
        "nodes": app.db.count("SELECT COUNT(*) FROM nodes"),
        "servers": crate::tunnel::panel::servers(app).len(),
        "tunnels": crate::tunnel::panel::tunnels(app).len(),
        "apps": apps,
    })
}

/// `with_apps`: also the app install files uploaded in the panel (a download and a move take them;
/// the nightly Telegram backup does not, a bot cannot send files over 50 MB).
pub fn make_archive_with(app: &App, pass: &str, with_apps: bool) -> Result<(Vec<u8>, String), String> {
    let dir = format!("/tmp/kanki-bk-{}", rand_token(12));
    private_dir(&dir)?;
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
        let data = app.data_dir();
        // the certificates of nodes with a self-signed one, as first seen: the new server keeps
        // trusting exactly those
        let pins = copy_flat(&format!("{}/nodepins", data), &format!("{}/nodepins", dir));
        let apps = if with_apps { copy_flat(&format!("{}/apps", data), &format!("{}/apps", dir)) } else { 0 };
        std::fs::write(format!("{}/meta.json", dir), meta(app, apps).to_string()).map_err(|e| e.to_string())?;
        let tgz = format!("{}/out.tar.gz", dir);
        // a panel without a self-signed node has no nodepins folder, and tar fails on a missing item
        let mut items = vec!["kanki.db", "files", "meta.json"];
        if pins > 0 {
            items.push("nodepins");
        }
        if apps > 0 {
            items.push("apps");
        }
        let mut args = vec!["-czf", tgz.as_str(), "-C", dir.as_str()];
        args.extend(items);
        run("tar", &args, None)?;
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

/// What a restore did: a message, and the meta of the backup (Null for an old one)
pub struct Restored {
    pub message: String,
    pub meta: Value,
}

/// Accepts .kbk (encrypted), .tar.gz, or a raw SQLite file from older versions
pub fn restore(app: &App, data: &[u8], pass: &str, full: bool) -> Result<Restored, String> {
    let dir = format!("/tmp/kanki-rs-{}", rand_token(12));
    private_dir(&dir)?;
    std::fs::create_dir_all(format!("{}/x", dir)).map_err(|e| e.to_string())?;
    let res = (|| -> Result<Restored, String> {
        let dbfile: String;
        let mut meta = Value::Null;
        let mut extra: Vec<String> = vec![];
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
            meta = std::fs::read_to_string(format!("{}/meta.json", x)).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or(Value::Null);
            if full {
                // only the known server files, and only as plain files: a backup (or a file that was
                // passed off as one) must not be able to write anywhere else on this machine
                for f in FILES {
                    let src = format!("{}/files{}", x, f);
                    let is_plain = std::fs::symlink_metadata(&src).map(|m| m.is_file()).unwrap_or(false);
                    if !is_plain {
                        continue;
                    }
                    if let Some(parent) = std::path::Path::new(f).parent() {
                        let _ = std::fs::create_dir_all(parent);
                    }
                    std::fs::copy(&src, f).map_err(|e| format!("{}: {}", f, e))?;
                }
                let ddir = app.data_dir();
                let pins = copy_flat(&format!("{}/nodepins", x), &format!("{}/nodepins", ddir));
                if pins > 0 {
                    extra.push(format!("{} node certificate pins", pins));
                }
                if std::path::Path::new(&format!("{}/apps", x)).is_dir() {
                    let n = copy_flat(&format!("{}/apps", x), &format!("{}/apps", ddir));
                    if n > 0 {
                        extra.push(format!("{} app files", n));
                    }
                }
            }
        }
        let head = std::fs::read(&dbfile).map_err(|_| "database missing in backup".to_string())?;
        if head.len() < 100 || &head[..15] != b"SQLite format 3" {
            return Err("database in backup is invalid".to_string());
        }
        // the database must open and have the panel's tables (a damaged file must not replace a good one)
        {
            let c = rusqlite::Connection::open_with_flags(&dbfile, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).map_err(|_| "database in backup is invalid".to_string())?;
            let ok: Result<i64, _> = c.query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0));
            let ok2: Result<i64, _> = c.query_row("SELECT COUNT(*) FROM settings", [], |r| r.get(0));
            if ok.is_err() || ok2.is_err() {
                return Err("database in backup is damaged (no users / settings table)".to_string());
            }
        }
        let ddir = app.data_dir();
        let tmp = format!("{}/restore.db", ddir);
        std::fs::write(&tmp, &head).map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, format!("{}/kanki.db", ddir)).map_err(|e| e.to_string())?;
        let _ = std::fs::remove_file(format!("{}/kanki.db-wal", ddir));
        let _ = std::fs::remove_file(format!("{}/kanki.db-shm", ddir));
        let mut message = if full { "database + server files restored".to_string() } else { "database restored".to_string() };
        if !extra.is_empty() {
            message.push_str(&format!(" ({})", extra.join(", ")));
        }
        Ok(Restored { message, meta })
    })();
    let _ = std::fs::remove_dir_all(&dir);
    res
}

/// Marks in the restored settings file that this start follows a restore: from another server (its
/// IP is replaced in the panel's addresses, see `migrate::after_move`) or this one.
fn mark_restored(old_ip: &str) {
    let path = crate::ENV_PATH;
    let t = std::fs::read_to_string(path).unwrap_or_default();
    let mut lines: Vec<String> = t.lines().filter(|l| !l.starts_with("MOVED_FROM=") && !l.starts_with("RESTORED_AT=")).map(|l| l.to_string()).collect();
    if !old_ip.is_empty() {
        lines.push(format!("MOVED_FROM={}", old_ip));
    }
    lines.push(format!("RESTORED_AT={}", now()));
    let _ = std::fs::write(path, lines.join("\n") + "\n");
}

const CADDYFILE: &str = "/etc/caddy/Caddyfile";
const VPN_CONFS: &[&str] = &["/etc/wireguard/wg0.conf", "/etc/amnezia/amneziawg/awg0.conf"];

/// Every `reverse_proxy 127.0.0.1:<port>` of a Caddyfile sent to `port`.
fn set_proxy_port(cf: &str, port: &str) -> String {
    cf.lines().map(|l| {
        match l.find("reverse_proxy 127.0.0.1:") {
            Some(i) => {
                let head = &l[..i + "reverse_proxy 127.0.0.1:".len()];
                let rest = &l[head.len()..];
                let tail = rest.trim_start_matches(|c: char| c.is_ascii_digit());
                format!("{}{}{}", head, port, tail)
            }
            None => l.to_string(),
        }
    }).collect::<Vec<_>>().join("\n") + if cf.ends_with('\n') { "\n" } else { "" }
}

/// The network card in the NAT rules of a VPN config (`-o <card> -j MASQUERADE`) set to `eth`.
fn set_masq_iface(conf: &str, eth: &str) -> String {
    let mut out = String::new();
    let mut rest = conf;
    while let Some(i) = rest.find(" -o ") {
        let after = &rest[i + 4..];
        let end = after.find(' ').unwrap_or(after.len());
        if after[end..].starts_with(" -j MASQUERADE") {
            out.push_str(&rest[..i + 4]);
            out.push_str(eth);
            rest = &after[end..];
        } else {
            out.push_str(&rest[..i + 4]);
            rest = after;
        }
    }
    out.push_str(rest);
    out
}

/// The network card of the default route.
fn default_iface() -> String {
    for l in std::fs::read_to_string("/proc/net/route").unwrap_or_default().lines().skip(1) {
        let f: Vec<&str> = l.split_whitespace().collect();
        if f.len() > 1 && f[1] == "00000000" {
            return f[0].to_string();
        }
    }
    String::new()
}

/// After a full restore the server files are the old server's: Caddy still sends the panel's
/// requests to the port of the install made here (the panel page answered 502), and the VPN
/// configs name the old server's network card. Both are set to this server.
fn after_full_restore() {
    let env = crate::util::load_env(crate::ENV_PATH);
    if let Some(port) = env.get("PANEL_PORT").filter(|p| p.parse::<u16>().is_ok()) {
        if let Ok(cf) = std::fs::read_to_string(CADDYFILE) {
            let n = set_proxy_port(&cf, port);
            if n != cf {
                let _ = std::fs::write(CADDYFILE, n);
            }
        }
    }
    let eth = default_iface();
    if !eth.is_empty() {
        for c in VPN_CONFS {
            if let Ok(t) = std::fs::read_to_string(c) {
                let n = set_masq_iface(&t, &eth);
                if n != t {
                    let _ = std::fs::write(c, n);
                }
            }
        }
    }
}

/// The VPN services and Caddy restarted with the restored files (Hysteria2 stopped when the
/// restored settings have it off). Blocking.
fn restart_services() {
    let sc = |args: &[&str]| { let _ = Command::new("systemctl").args(args).output(); };
    if std::path::Path::new(VPN_CONFS[0]).exists() {
        sc(&["restart", "wg-quick@wg0"]);
    }
    if std::path::Path::new(VPN_CONFS[1]).exists() {
        sc(&["restart", "awg-quick@awg0"]);
    }
    let env = crate::util::load_env(crate::ENV_PATH);
    if env.get("HY2_PORT").map(|s| s.trim().is_empty()).unwrap_or(true) {
        sc(&["disable", "--now", "hysteria-server"]);
    } else {
        sc(&["restart", "hysteria-server"]);
    }
    if std::path::Path::new(CADDYFILE).exists() {
        sc(&["restart", "caddy"]);
    }
}

pub fn router() -> Router<Arc<App>> {
    Router::new()
        .route("/api/backup", get(backup_legacy).post(backup_download))
        // a backup file can be big; only a signed-in admin gets that far (see auth::middleware)
        .route("/api/restore", post(restore_upload).layer(DefaultBodyLimit::max(128 * 1024 * 1024)))
        .route("/api/restore/check", get(restore_check))
        .route("/api/tgbackup", get(tgb_get).put(tgb_put))
        .route("/api/tgbackup/test", post(tgb_test))
        .route("/api/tgbackup/send", post(tgb_send))
        .route("/api/db/clean", post(db_clean))
}

/// Keeps the database small and tidy: drops old login / audit rows, expired sessions and
/// abandoned unpaid orders, then compacts the file. Users, plans and paid orders are untouched.
pub fn clean_db(app: &App) -> Value {
    let t = now();
    let month = t - 30 * 86400;
    let week = t - 7 * 86400;
    let n = |sql: &str, p: i64| app.db.exec(sql, &[&p]).unwrap_or(0) as i64;
    let logins = n("DELETE FROM login_log WHERE ts<?1", month);
    let audit = n("DELETE FROM audit WHERE ts<?1", month);
    let sessions = n("DELETE FROM sessions WHERE expires<?1", t);
    let orders = n("DELETE FROM orders WHERE status IN ('pending','waiting','rejected','error') AND created<?1", week);
    // free trials that are over (the bot removes them within a minute; this also covers a paused bot)
    let trials = app.db.finished_trials();
    for u in &trials {
        crate::api::delete_user(app, u.id);
    }
    // peers of users that no longer exist
    let peers = app.db.exec("DELETE FROM peers WHERE user_id NOT IN (SELECT id FROM users)", &[]).unwrap_or(0) as i64;
    let before = std::fs::metadata(db_path(app)).map(|m| m.len()).unwrap_or(0);
    let _ = app.db.with(|c| c.execute_batch("PRAGMA wal_checkpoint(TRUNCATE); VACUUM; PRAGMA optimize;"));
    let after = std::fs::metadata(db_path(app)).map(|m| m.len()).unwrap_or(0);
    app.db.set("db_cleaned", &t.to_string());
    json!({"trials": trials.len(), "logins": logins, "audit": audit, "sessions": sessions, "orders": orders, "peers": peers, "before": before, "after": after})
}

fn db_path(app: &App) -> String {
    format!("{}/kanki.db", app.env.get("DATA_DIR").cloned().unwrap_or_else(|| "/var/lib/kanki".into()))
}

async fn db_clean(State(app): St, h: HeaderMap) -> Response {
    let _ = guard!(app, h, "backup");
    Json(json!({"ok": true, "result": clean_db(&app)})).into_response()
}

/// The panel's own backup passphrase; made once (random) so nightly backups are never plain.
pub fn backup_pass(app: &App) -> String {
    let p = app.db.get("tgb_pass");
    if !p.is_empty() {
        return p;
    }
    let p = rand_token(20);
    app.db.set("tgb_pass", &p);
    p
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
    // empty = the panel's own backup passphrase, so a download is never left unencrypted
    let mut pass = b["passphrase"].as_str().unwrap_or("").to_string();
    if pass.is_empty() {
        pass = backup_pass(&app);
    }
    if pass.len() < 6 {
        return err(StatusCode::BAD_REQUEST, "passphrase must be at least 6 characters");
    }
    // the app install files go in too, unless asked not to (they can be big)
    let apps = b["apps"].as_bool().unwrap_or(true);
    let a = app.clone();
    match tokio::task::spawn_blocking(move || make_archive_with(&a, &pass, apps)).await {
        Ok(Ok((bytes, name))) => file_response(bytes, &name),
        Ok(Err(e)) => err(StatusCode::INTERNAL_SERVER_ERROR, &e),
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "backup failed"),
    }
}

async fn restore_upload(State(app): St, h: HeaderMap, body: Bytes) -> Response {
    if let Err(r) = crate::auth::check_session(&app, &h) {
        return r;
    }
    let mut pass = h.get("x-passphrase").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    if pass.is_empty() {
        pass = backup_pass(&app);
    }
    let full = h.get("x-full").and_then(|v| v.to_str().ok()) == Some("1");
    let a = app.clone();
    let data = body.to_vec();
    let here = app.db.get("my_ip");
    match tokio::task::spawn_blocking(move || restore(&a, &data, &pass, full)).await {
        Ok(Ok(r)) => {
            if full {
                // the old server's files are in place now: set them to this server, then restart
                let old = r.meta["ip"].as_str().unwrap_or("").to_string();
                let moved = if !old.is_empty() && !here.is_empty() && old != here { old } else { String::new() };
                mark_restored(&moved);
                after_full_restore();
                tokio::spawn(async {
                    tokio::time::sleep(std::time::Duration::from_millis(700)).await;
                    let _ = tokio::task::spawn_blocking(restart_services).await;
                    std::process::exit(0)
                });
            } else {
                crate::admin::restart_self();
            }
            Json(json!({"ok": true, "message": r.message, "meta": r.meta})).into_response()
        }
        Ok(Err(e)) => err(StatusCode::BAD_REQUEST, &e),
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "restore failed"),
    }
}

/// After a restore: whether every server and service came back (the Backup page shows it)
async fn restore_check(State(app): St, h: HeaderMap) -> Response {
    let _ = guard!(app, h, "backup");
    let list = crate::servers::list_json(&app);
    let mut servers = vec![];
    for s in list["servers"].as_array().into_iter().flatten() {
        let agent = &s["agent"];
        let node = &s["node"];
        servers.push(json!({
            "name": s["name"], "local": s["local"],
            "agent": if agent.is_null() { Value::Null } else { agent["online"].clone() },
            "vpn": if node.is_null() { Value::Null } else { node["online"].clone() },
            "vpn_on": node["enabled"].clone(),
        }));
    }
    let services = crate::admin::service_states();
    Json(json!({
        "restored_at": app.db.get("restored_at").parse::<i64>().unwrap_or(0),
        "moved_from": app.env.get("MOVED_FROM").cloned().unwrap_or_default(),
        "servers": servers, "services": services,
        "sub_domain": app.db.get("sub_domain"),
        // the old server's panel still runs the same bot (both answer customers, both post)
        "bot_conflict": now() - app.db.get("bot_conflict").parse::<i64>().unwrap_or(0) < 300,
    }))
    .into_response()
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
        "chat": app.db.get("tgb_chat"), "hours": app.db.get("tgb_hours"), "pass_set": true, "pass": backup_pass(&app),
        "mode": if app.db.get("tgb_mode") == "hours" { "hours" } else { "nightly" }, "at": tgb_at(&app),
        "cleaned": app.db.get("db_cleaned").parse::<i64>().unwrap_or(0),
        "db_size": std::fs::metadata(db_path(&app)).map(|m| m.len()).unwrap_or(0),
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
    if let Some(m) = b["mode"].as_str() {
        app.db.set("tgb_mode", if m == "hours" { "hours" } else { "nightly" });
    }
    if let Some(at) = b["at"].as_str() {
        let ok = at.split_once(':').and_then(|(h, m)| Some((h.trim().parse::<u32>().ok()?, m.trim().parse::<u32>().ok()?))).filter(|(h, m)| *h < 24 && *m < 60);
        match ok {
            Some((h, m)) => app.db.set("tgb_at", &format!("{:02}:{:02}", h, m)),
            None => return err(StatusCode::BAD_REQUEST, "time must look like 03:00"),
        }
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

/// A text to the admin on the backup bot's chat (nothing when no bot or chat is set)
pub async fn tell_admin(app: &App, text: &str) {
    let token = tgb_token(app);
    let chat = app.db.get("tgb_chat");
    if !token.is_empty() && !chat.is_empty() {
        let _ = tg_call(app, &token, "sendMessage", json!({"chat_id": chat, "text": text})).await;
    }
}

pub async fn send_backup(app: &App) -> Result<(), String> {
    let token = tgb_token(app);
    let chat = app.db.get("tgb_chat");
    if token.is_empty() || chat.is_empty() {
        return Err("token / chat id missing".into());
    }
    // tidy first so every nightly backup is a clean database
    let c = clean_db(app);
    let pass = backup_pass(app);
    let (bytes, name) = make_archive(app, &pass)?;
    let users = app.db.count("SELECT COUNT(*) FROM users");
    let caption = format!(
        "💾 {} · بکاپ پنل\n🕒 {}\n👤 {} کاربر · 🗄 {} KB\n🔐 رمزنگاری‌شده (رمز بکاپ در پنل > بکاپ)",
        app.db.get("panel_name"), crate::util::iso(now()), users, c["after"].as_u64().unwrap_or(0) / 1024
    );
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

fn tgb_at(app: &App) -> String {
    let a = app.db.get("tgb_at");
    if a.is_empty() { "03:00".into() } else { a }
}

/// Iran time (UTC+3:30, no daylight saving) — "nightly" means the admin's night.
const TZ_OFFSET: i64 = 12600;

pub async fn telegram_loop(app: Arc<App>) {
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        if !app.db.on("tgb_on") {
            continue;
        }
        let t = now();
        if app.db.get("tgb_mode") == "hours" {
            let hours: i64 = app.db.get("tgb_hours").parse::<i64>().unwrap_or(24).max(1);
            let last: i64 = app.db.get("tgb_last").parse().unwrap_or(0);
            if t - last < hours * 3600 {
                continue;
            }
        } else {
            // once a day, at the chosen time
            let local = t + TZ_OFFSET;
            let day = local / 86400;
            let minute = (local % 86400) / 60;
            let (h, m) = tgb_at(&app).split_once(':').map(|(h, m)| (h.parse::<i64>().unwrap_or(3), m.parse::<i64>().unwrap_or(0))).unwrap_or((3, 0));
            let done: i64 = app.db.get("tgb_day").parse().unwrap_or(-1);
            if done == day || minute < h * 60 + m {
                continue;
            }
            app.db.set("tgb_day", &day.to_string());
        }
        let r = send_backup(&app).await;
        record(&app, &r);
        if let Err(e) = &r {
            // a failed nightly backup was only written on the Backup page; tell the admin too
            tell_admin(&app, &format!("⚠️ {} · بکاپ پنل ساخته نشد\n{}", app.db.get("panel_name"), e)).await;
        }
    }
}

#[cfg(test)]
mod archive_tests {
    use crate::App;
    use std::collections::HashMap;
    use std::sync::{atomic::AtomicI64, Arc, Mutex};

    #[test]
    fn a_panel_without_nodepins_still_backs_up() {
        let dir = std::env::temp_dir().join(format!("kanki-bk-test-{}", crate::util::rand_token(8)));
        std::fs::create_dir_all(&dir).unwrap();
        let db = crate::db::Db::open(dir.join("kanki.db").to_str().unwrap());
        let app = Arc::new(App {
            db,
            env: HashMap::from([("DATA_DIR".to_string(), dir.to_string_lossy().to_string())]),
            hy2_allowed: Mutex::new(HashMap::new()), limits: Mutex::new(HashMap::new()), reported: Mutex::new(HashMap::new()),
            login_fails: Mutex::new(HashMap::new()), sync_lock: tokio::sync::Mutex::new(()), bot_alive: AtomicI64::new(0),
            http: reqwest::Client::new(), http_insecure: reqwest::Client::new(), pin_clients: Mutex::new(HashMap::new()),
        });
        assert!(!dir.join("nodepins").exists());
        let (bytes, name) = super::make_archive(&app, "").expect("backup without nodepins");
        assert!(name.ends_with(".tar.gz") && !bytes.is_empty());
        // with a pin it is taken along
        std::fs::create_dir_all(dir.join("nodepins")).unwrap();
        std::fs::write(dir.join("nodepins/a.pin"), "x").unwrap();
        assert!(super::make_archive(&app, "").is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod restore_tests {
    #[test]
    fn caddy_is_sent_to_the_restored_port() {
        let cf = "{\n  auto_https off\n}\nhttps://a.b:2053 {\n  reverse_proxy 127.0.0.1:20973\n}\nsub.b:2053 {\n  reverse_proxy 127.0.0.1:20973 {\n  }\n}\n";
        let n = super::set_proxy_port(cf, "29332");
        assert!(!n.contains("20973"));
        assert_eq!(n.matches("reverse_proxy 127.0.0.1:29332").count(), 2);
        assert!(n.ends_with("}\n") && n.contains("reverse_proxy 127.0.0.1:29332 {"));
    }
    #[test]
    fn the_nat_rule_names_this_servers_card() {
        let c = "PostUp = iptables -t nat -A POSTROUTING -s 10.66.0.0/16 -o ens18 -j MASQUERADE; iptables -A FORWARD -i wg0 -o ens18 -j ACCEPT\nPostDown = iptables -t nat -D POSTROUTING -s 10.66.0.0/16 -o ens18 -j MASQUERADE\n";
        let n = super::set_masq_iface(c, "eth0");
        assert_eq!(n.matches("-o eth0 -j MASQUERADE").count(), 2);
        // only the NAT rules: a FORWARD rule with -o is left as it was
        assert!(n.contains("-o ens18 -j ACCEPT"));
    }
}
