//! Moving the whole panel to a new server (Backup › Move to a new server).
//!
//! 1. The admin points the panel's domain to the new server's IP and presses "Make the move command".
//!    The panel makes a one-time token and a passphrase (valid 3 hours) and shows one command.
//! 2. The admin runs it on the new server (a fresh Ubuntu / Debian). The installer downloads the full
//!    backup straight from this server (by this server's IP, so the domain may already point away),
//!    encrypted with the passphrase that is only in the command, never sent over the wire. It puts
//!    everything back with the same keys and settings: the database (users, nodes, tunnels, DNS,
//!    Xray, bot, plans …), the panel settings, the WireGuard / AmneziaWG / Hysteria2 configs and keys,
//!    the certificate and the uploaded app files. Then it starts the panel and checks it answers.
//! 3. The new server tells this one it is done: this panel stops (no two panels syncing the nodes or
//!    answering the bot). Nodes and tunnel servers reach the panel by its domain, so they follow by
//!    themselves once the domain points to the new IP.
use crate::api::err;
use crate::guard;
use crate::util::{now, rand_token, sha256_hex};
use crate::App;
use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;

type St = State<Arc<App>>;

/// how long a move command works
const VALID: i64 = 3 * 3600;

pub fn router() -> Router<Arc<App>> {
    Router::new()
        .route("/api/migrate", get(status).delete(cancel))
        .route("/api/migrate/start", post(start))
        // used by the new server with the one-time token (no admin session there yet); outside /api/ so
        // the panel's admin IP list does not lock the new server out
        .route("/move/bundle", get(bundle))
        .route("/move/done", post(done))
}

fn token_ok(app: &App, t: &str) -> bool {
    let want = app.db.get("mig_token");
    let exp: i64 = app.db.get("mig_exp").parse().unwrap_or(0);
    !want.is_empty() && !t.is_empty() && now() < exp && crate::util::ct_eq(&sha256_hex(t), &want)
}

/// Keeps this server's public IPv4 in the settings (refreshed every 6 hours): a backup names the
/// server it was made on, so a restore on another server knows which address to replace.
pub async fn ip_loop(app: Arc<App>) {
    loop {
        let ip = public_ip(&app).await;
        if !ip.is_empty() {
            app.db.set("my_ip", &ip);
        }
        tokio::time::sleep(std::time::Duration::from_secs(if ip.is_empty() { 600 } else { 6 * 3600 })).await;
    }
}

/// This server's public IPv4 (from outside: the panel server is not behind the filter)
pub async fn public_ip(app: &App) -> String {
    for u in ["https://api.ipify.org", "https://ipv4.icanhazip.com", "https://ifconfig.me/ip"] {
        if let Ok(r) = app.http.get(u).timeout(std::time::Duration::from_secs(6)).send().await {
            if let Ok(t) = r.text().await {
                let t = t.trim().to_string();
                if t.parse::<std::net::Ipv4Addr>().is_ok() {
                    return t;
                }
            }
        }
    }
    String::new()
}

fn command(app: &App, ip: &str, token: &str, pass: &str) -> String {
    let repo = crate::admin::repo();
    let repo = if repo.is_empty() { "kankiturk8770/kanki-panel".to_string() } else { repo };
    let domain = app.env.get("DOMAIN").cloned().unwrap_or_default();
    let port = app.env.get("HTTPS_PORT").cloned().unwrap_or_else(|| "443".into());
    format!(
        "curl -fsSL https://raw.githubusercontent.com/{}/main/install.sh -o /root/kanki-move.sh && sudo KANKI_REPO='{}' KANKI_MOVE='{}|{}|{}|{}|{}' bash /root/kanki-move.sh",
        repo, repo, domain, port, ip, token, pass
    )
}

async fn status(State(app): St, h: HeaderMap) -> Response {
    let _ = guard!(app, h, "backup");
    let exp: i64 = app.db.get("mig_exp").parse().unwrap_or(0);
    let active = !app.db.get("mig_token").is_empty() && now() < exp;
    let domain = app.env.get("DOMAIN").cloned().unwrap_or_default();
    Json(json!({
        "active": active, "expires": exp, "command": if active { app.db.get("mig_cmd") } else { String::new() },
        "fetched": app.db.get("mig_fetched").parse::<i64>().unwrap_or(0), "done": app.db.get("mig_done").parse::<i64>().unwrap_or(0),
        "new_ip": app.db.get("mig_new_ip"), "domain": domain, "port": app.env.get("HTTPS_PORT").cloned().unwrap_or_default(),
        "ip": app.db.get("mig_ip"),
    }))
    .into_response()
}

/// { ip?: this server's IP (empty = found by itself) } → the command for the new server
async fn start(State(app): St, h: HeaderMap, Json(b): Json<Value>) -> Response {
    let _ = guard!(app, h, "backup");
    if app.env.get("DOMAIN").map(|d| d.trim().is_empty()).unwrap_or(true) {
        return err(StatusCode::BAD_REQUEST, "the panel has no domain: a move needs the panel on a domain (the nodes and tunnel servers follow the domain)");
    }
    let mut ip = b["ip"].as_str().unwrap_or("").trim().to_string();
    if ip.is_empty() {
        ip = public_ip(&app).await;
    }
    if ip.parse::<std::net::IpAddr>().is_err() {
        return err(StatusCode::BAD_REQUEST, "this server's IP could not be found: write it in the box");
    }
    let token = rand_token(40);
    let pass = rand_token(32);
    app.db.set("mig_token", &sha256_hex(&token));
    app.db.set("mig_pass", &pass);
    app.db.set("mig_exp", &(now() + VALID).to_string());
    app.db.set("mig_fetched", "0");
    app.db.set("mig_done", "0");
    app.db.set("mig_new_ip", "");
    app.db.set("mig_ip", &ip);
    let cmd = command(&app, &ip, &token, &pass);
    app.db.set("mig_cmd", &cmd);
    Json(json!({ "ok": true, "command": cmd, "expires": now() + VALID, "ip": ip })).into_response()
}

async fn cancel(State(app): St, h: HeaderMap) -> Response {
    let _ = guard!(app, h, "backup");
    for k in ["mig_token", "mig_pass", "mig_exp", "mig_cmd"] {
        app.db.set(k, "");
    }
    Json(json!({ "ok": true })).into_response()
}

/// The full backup for the new server, encrypted with the move passphrase.
async fn bundle(State(app): St, h: HeaderMap, Query(q): Query<HashMap<String, String>>) -> Response {
    let t = q.get("t").cloned().unwrap_or_default();
    if !token_ok(&app, &t) {
        return (StatusCode::FORBIDDEN, "this move command is not valid (made again, cancelled, or older than 3 hours)").into_response();
    }
    let pass = app.db.get("mig_pass");
    let a = app.clone();
    match tokio::task::spawn_blocking(move || crate::backup::make_archive_with(&a, &pass, true)).await {
        Ok(Ok((bytes, _))) => {
            app.db.set("mig_fetched", &now().to_string());
            app.db.set("mig_new_ip", &crate::util::client_ip(&h));
            ([(header::CONTENT_TYPE, "application/octet-stream"), (header::CACHE_CONTROL, "no-store")], bytes).into_response()
        }
        Ok(Err(e)) => err(StatusCode::INTERNAL_SERVER_ERROR, &e),
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "backup failed"),
    }
}

/// The new server runs the panel: this one stops for good (its token is used up).
async fn done(State(app): St, Query(q): Query<HashMap<String, String>>) -> Response {
    let t = q.get("t").cloned().unwrap_or_default();
    if !token_ok(&app, &t) {
        return (StatusCode::FORBIDDEN, "not valid").into_response();
    }
    app.db.set("mig_done", &now().to_string());
    for k in ["mig_token", "mig_pass", "mig_cmd"] {
        app.db.set(k, "");
    }
    eprintln!("the panel was moved to a new server: this panel stops");
    // after the answer: stop and keep off (the VPN services of this server are left as they are)
    std::thread::spawn(|| {
        std::thread::sleep(std::time::Duration::from_secs(5));
        let _ = std::process::Command::new("sh").arg("-c").arg("systemctl disable kanki-panel 2>/dev/null; systemctl stop kanki-panel").status();
    });
    Json(json!({ "ok": true })).into_response()
}

/// Settings that can hold the panel server's own address. After a move (or a restore on another
/// server) the old server's IP in them would send users and servers to the old machine.
const ADDR_KEYS: &[&str] = &["tun_local_addr", "endpoint", "sub_base"];
/// JSON settings where the old IP is replaced by "" (= the automatic address of this server)
const ADDR_JSON_KEYS: &[&str] = &["kmix_nodes", "xray_cfg"];

/// `v` with every exact JSON string `"old"` emptied, and `old` as the host of a URL replaced by `new`
fn drop_ip(v: &str, old: &str, new: &str) -> String {
    v.replace(&format!("\"{}\"", old), "\"\"").replace(&format!("//{}:", old), &format!("//{}:", new)).replace(&format!("//{}/", old), &format!("//{}/", new))
}

/// On the new server, the first start after a move or a restore from another server: addresses that
/// named the old server are dropped (the domain is used instead).
pub fn after_move(app: &App) {
    // any restore (the Backup page shows when, and whether every server came back)
    if let Some(at) = app.env.get("RESTORED_AT").filter(|v| v.parse::<i64>().is_ok()) {
        if app.db.get("restored_seen") != *at {
            app.db.set("restored_seen", at);
            app.db.set("restored_at", at);
        }
    }
    let old = app.env.get("MOVED_FROM").cloned().unwrap_or_default();
    if old.is_empty() || app.db.get("moved_fix") == old {
        return;
    }
    let domain = app.env.get("DOMAIN").cloned().unwrap_or_default();
    for k in ADDR_KEYS {
        let v = app.db.get(k);
        if v.trim() == old {
            app.db.set(k, "");
        } else if v.contains(&old) && !domain.is_empty() {
            app.db.set(k, &drop_ip(&v, &old, &domain));
        }
    }
    for k in ADDR_JSON_KEYS {
        let v = app.db.get(k);
        if v.contains(&old) {
            app.db.set(k, &drop_ip(&v, &old, &domain));
        }
    }
    // the panel server's own node row
    let _ = app.db.exec("UPDATE nodes SET endpoint='', endpoint_mode='panel' WHERE id='local' AND endpoint=?1", &[&old]);
    for k in ["mig_token", "mig_pass", "mig_exp", "mig_cmd", "mig_fetched", "mig_done", "mig_new_ip", "mig_ip", "my_ip"] {
        app.db.set(k, "");
    }
    app.db.set("moved_fix", &old);
    app.db.set("restored_at", &now().to_string());
    eprintln!("moved from {}: addresses of the old server cleared", old);
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_old_ip_goes_from_settings() {
        let x = r#"{"servers":[{"server":"local","address":"1.2.3.4"}],"x":"1.2.3.45"}"#;
        assert_eq!(super::drop_ip(x, "1.2.3.4", "p.example.com"), r#"{"servers":[{"server":"local","address":""}],"x":"1.2.3.45"}"#);
        assert_eq!(super::drop_ip("https://1.2.3.4:2053/x", "1.2.3.4", "p.example.com"), "https://p.example.com:2053/x");
    }
}
