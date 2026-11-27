//! Moving the whole panel to a new server (Backup › Move to a new server).
//!
//! 1. The admin points the panel's domain to the new server's IP and presses "Make the move command".
//!    The panel makes a one-time token and a passphrase (valid 30 minutes, one download) and shows one command.
//! 2. The admin runs it on the new server (a fresh Ubuntu / Debian). The installer downloads the full
//!    backup straight from this server (by this server's IP, so the domain may already point away),
//!    encrypted with the passphrase that is only in the command, never sent over the wire. It puts
//!    everything back with the same keys and settings: the database (users, nodes, tunnels, DNS,
//!    Xray, bot, plans …), the panel settings, the WireGuard / AmneziaWG / Hysteria2 configs and keys,
//!    the certificate and the uploaded app files. Then it starts the panel and checks it answers.
//! 3. The new server tells this one it is done: this panel stops (no two panels syncing the nodes or
//!    answering the bot). Nodes and tunnel servers reach the panel by its domain, so they follow by
//!    themselves once the domain points to the new IP.
//!
//! Nothing written after the backup may be lost: from the moment the new server takes the backup this
//! panel is frozen (`frozen`). Changes are refused (the admin, the mini app), the bot stops reading
//! Telegram (its messages wait there for the new panel), and the rounds with the servers, the payment
//! checks, the cleanup and the channel pause (the servers keep counting traffic; the new panel reads it
//! from the backup's last values, so no byte is counted twice or missed). The freeze ends when the move
//! is cancelled, or by itself when the command expires and the new server never said it was done.
use crate::api::err;
use crate::util::{now, rand_token, sha256_hex};
use crate::App;
use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Value};
use std::sync::Arc;

type St = State<Arc<App>>;

/// how long a move command works
/// How long a move command works (3.68: 30 minutes, was 3 hours)
const VALID: i64 = 30 * 60;

static FROZEN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// The panel is being moved: the new server has (or is taking) the backup, so nothing may change here
pub fn frozen() -> bool {
    FROZEN.load(std::sync::atomic::Ordering::Relaxed)
}

fn set_frozen(app: &App, on: bool) {
    FROZEN.store(on, std::sync::atomic::Ordering::Relaxed);
    app.db.set("mig_frozen", &if on { now().to_string() } else { String::new() });
}

/// At start: a panel restarted during a move stays frozen
pub fn load_frozen(app: &App) {
    FROZEN.store(!app.db.get("mig_frozen").is_empty(), std::sync::atomic::Ordering::Relaxed);
}

/// Freezes the panel before its backup is taken: the round with the servers that is running ends first,
/// and work started a moment before (a bot message, a payment) gets a few seconds to be written.
async fn freeze(app: &App) {
    if frozen() {
        return;
    }
    set_frozen(app, true);
    eprintln!("the panel is moving to a new server: frozen (changes wait for the new panel)");
    let _round = app.sync_lock.lock().await;
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
}

/// Requests refused while the panel is frozen: every change (the admin's, an API key's, the mini app's
/// purchases and trials, a new server joining). Reading, the subscriptions, the servers' own calls and
/// Hysteria2's logins go on, and so do signing in and the move page (to cancel it).
pub fn refused_while_moving(method: &axum::http::Method, path: &str) -> bool {
    use axum::http::Method;
    if path.starts_with("/api/migrate") || path == "/api/login" || path == "/api/logout" {
        return false;
    }
    let change = method != Method::GET && method != Method::HEAD && method != Method::OPTIONS;
    (path.starts_with("/api/") && change && !path.starts_with("/api/config/"))
        || path == "/tg/api/buy"
        || path == "/tg/api/trial"
        || path == "/tg/api/upgrade"
        || (path.starts_with("/tg/api/admin/") && change)
        || path == "/join/register"
}

/// The freeze ends by itself when the command expired and the new server never said it was done (the
/// move failed or was left): the panel runs on, and the admin is told.
pub async fn freeze_loop(app: Arc<App>) {
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        if !frozen() {
            // 3.68: an expired command is wiped at once (its token hash and passphrase do not stay in the settings)
            let exp: i64 = app.db.get("mig_exp").parse().unwrap_or(0);
            if exp > 0 && now() > exp && !app.db.get("mig_cmd").is_empty() {
                for k in ["mig_token", "mig_pass", "mig_cmd", "mig_exp"] {
                    app.db.set(k, "");
                }
            }
            continue;
        }
        let exp: i64 = app.db.get("mig_exp").parse().unwrap_or(0);
        let done: i64 = app.db.get("mig_done").parse().unwrap_or(0);
        if done == 0 && now() > exp {
            set_frozen(&app, false);
            for k in ["mig_token", "mig_pass", "mig_cmd"] {
                app.db.set(k, "");
            }
            eprintln!("the move was not finished in time: the panel runs on here");
            crate::monitor::notify("⚠️ انتقال پنل تمام نشد (سرور تازه خبر نداد) و فرمانش منقضی شد: پنل روی همین سرور دوباره کار می‌کند.", None).await;
        }
    }
}

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

/// Keeps this server's public IPv4 in the settings (checked every 30 minutes): a backup names the
/// server it was made on, so a restore on another server knows which address to replace. When the
/// server itself gets a new IP (the provider changed it), the settings that named the old one are set
/// to the new address the same way as after a move (seen twice a minute apart first).
pub async fn ip_loop(app: Arc<App>) {
    loop {
        let ip = public_ip(&app).await;
        if !ip.is_empty() && !frozen() {
            let old = app.db.get("my_ip");
            if !old.is_empty() && old != ip {
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                if public_ip(&app).await == ip {
                    eprintln!("this server's IP changed from {} to {}: the addresses that named the old one are set again", old, ip);
                    forget_ip(&app, &old, &ip);
                    app.db.set("my_ip", &ip);
                    crate::monitor::notify(&format!("ℹ️ آی‌پی سرور پنل عوض شد: {} ← {}. آدرس‌هایی که آی‌پی قبلی را داشتند درست شدند.", ip, old), None).await;
                }
            } else {
                app.db.set("my_ip", &ip);
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(if ip.is_empty() { 600 } else { 1800 })).await;
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
    if let Err(r) = crate::auth::check_session(&app, &h) { return r; } // 3.68: a login session only, never an API token
    let exp: i64 = app.db.get("mig_exp").parse().unwrap_or(0);
    let active = !app.db.get("mig_token").is_empty() && now() < exp;
    let domain = app.env.get("DOMAIN").cloned().unwrap_or_default();
    Json(json!({
        "active": active, "expires": exp, "command": if active { app.db.get("mig_cmd") } else { String::new() },
        "fetched": app.db.get("mig_fetched").parse::<i64>().unwrap_or(0), "done": app.db.get("mig_done").parse::<i64>().unwrap_or(0),
        "new_ip": app.db.get("mig_new_ip"), "domain": domain, "port": app.env.get("HTTPS_PORT").cloned().unwrap_or_default(),
        "ip": app.db.get("mig_ip"), "frozen": frozen(),
    }))
    .into_response()
}

/// { ip?: this server's IP (empty = found by itself) } → the command for the new server
async fn start(State(app): St, h: HeaderMap, Json(b): Json<Value>) -> Response {
    if let Err(r) = crate::auth::check_session(&app, &h) { return r; } // 3.68: a login session only, never an API token
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
    if let Err(r) = crate::auth::check_session(&app, &h) { return r; } // 3.68: a login session only, never an API token
    for k in ["mig_token", "mig_pass", "mig_exp", "mig_cmd"] {
        app.db.set(k, "");
    }
    if frozen() {
        set_frozen(&app, false);
        eprintln!("the move was cancelled: the panel runs on here");
    }
    Json(json!({ "ok": true })).into_response()
}

/// The full backup for the new server, encrypted with the move passphrase.
/// The move token (3.68): only in the `X-Kanki-Move` header, never in a URL a proxy logs
fn move_token(h: &HeaderMap) -> String {
    h.get("x-kanki-move").and_then(|v| v.to_str().ok()).map(|v| v.trim().to_string()).unwrap_or_default()
}

async fn bundle(State(app): St, h: HeaderMap) -> Response {
    let t = move_token(&h);
    if !token_ok(&app, &t) {
        return (StatusCode::FORBIDDEN, "this move command is not valid (made again, cancelled, used, or older than 30 minutes)").into_response();
    }
    // used once: a second download (someone who saw the command) is refused
    {
        static ONE: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _g = ONE.lock().unwrap_or_else(|e| e.into_inner());
        if app.db.get("mig_fetched").parse::<i64>().unwrap_or(0) > 0 {
            return (StatusCode::FORBIDDEN, "this move command was used already: make a new one").into_response();
        }
        app.db.set("mig_fetched", &now().to_string());
    }
    let pass = app.db.get("mig_pass");
    // nothing changes here from now on: the backup is everything the new panel gets
    freeze(&app).await;
    let a = app.clone();
    match tokio::task::spawn_blocking(move || crate::backup::make_archive_with(&a, &pass, true)).await {
        Ok(Ok((bytes, _))) => {
            app.db.set("mig_new_ip", &crate::util::client_ip(&h));
            ([(header::CONTENT_TYPE, "application/octet-stream"), (header::CACHE_CONTROL, "no-store")], bytes).into_response()
        }
        Ok(Err(e)) => err(StatusCode::INTERNAL_SERVER_ERROR, &e),
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "backup failed"),
    }
}

/// The new server runs the panel: this one stops for good (its token is used up).
async fn done(State(app): St, h: HeaderMap) -> Response {
    let t = move_token(&h);
    if !token_ok(&app, &t) {
        return (StatusCode::FORBIDDEN, "not valid").into_response();
    }
    app.db.set("mig_done", &now().to_string());
    for k in ["mig_token", "mig_pass", "mig_cmd", "mig_exp"] {
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
/// (left as it is when there is no `new`: "https://:2053" would be no address at all)
fn drop_ip(v: &str, old: &str, new: &str) -> String {
    let v = v.replace(&format!("\"{}\"", old), "\"\"");
    if new.is_empty() {
        return v;
    }
    // `//old` is the URL host only when the host ends right there: at a port, a path, a query, a
    // fragment, the end of a JSON string or the end of the text ("//1.2.3.45" is another address)
    let pat = format!("//{}", old);
    let mut out = String::with_capacity(v.len());
    let mut rest = v.as_str();
    while let Some(i) = rest.find(&pat) {
        let after = &rest[i + pat.len()..];
        out.push_str(&rest[..i]);
        if after.is_empty() || after.starts_with([':', '/', '?', '#', '"']) {
            out.push_str("//");
            out.push_str(new);
        } else {
            out.push_str(&pat);
        }
        rest = after;
    }
    out.push_str(rest);
    out
}

/// On the new server, the first start after a move or a restore from another server: addresses that
/// named the old server are dropped (the domain is used instead).
pub fn after_move(app: &App) {
    // any restore (the Backup page shows when, and whether every server came back)
    if let Some(at) = app.env.get("RESTORED_AT").filter(|v| v.parse::<i64>().is_ok()) {
        if app.db.get("restored_seen") != *at {
            app.db.set("restored_seen", at);
            app.db.set("restored_at", at);
            // the backup of a move was made frozen: the restored panel runs
            for k in ["mig_frozen", "mig_token", "mig_pass", "mig_cmd", "mig_exp"] {
                app.db.set(k, "");
            }
        }
    }
    let old = app.env.get("MOVED_FROM").cloned().unwrap_or_default();
    if old.is_empty() || app.db.get("moved_fix") == old {
        return;
    }
    forget_ip(app, &old, "");
    for k in ["mig_token", "mig_pass", "mig_exp", "mig_cmd", "mig_fetched", "mig_done", "mig_new_ip", "mig_ip", "my_ip", "mig_frozen"] {
        app.db.set(k, "");
    }
    app.db.set("moved_fix", &old);
    app.db.set("restored_at", &now().to_string());
    eprintln!("moved from {}: addresses of the old server cleared", old);
}

/// The settings that named this server's old IP: a bare address is emptied (= this server, found by
/// itself), a link gets the domain (or `new` when the panel has no domain). The settings file's
/// ENDPOINT (what users connect to) that was the old IP is overridden by the domain or the new IP.
pub fn forget_ip(app: &App, old: &str, new: &str) {
    let domain = app.env.get("DOMAIN").cloned().unwrap_or_default();
    let host = if domain.is_empty() { new.to_string() } else { domain.clone() };
    if app.env.get("ENDPOINT").is_some_and(|e| e.trim() == old) && !host.is_empty() {
        let e = app.db.get("endpoint");
        if e.trim().is_empty() || e.trim() == old {
            app.db.set("endpoint", &host);
        }
    }
    for k in ADDR_KEYS {
        let v = app.db.get(k);
        if v.trim() == old {
            // the endpoint setting just set to the new host above stays
            if !(*k == "endpoint" && !host.is_empty() && app.env.get("ENDPOINT").is_some_and(|e| e.trim() == old)) {
                app.db.set(k, "");
            }
        } else if v.contains(old) && !host.is_empty() {
            app.db.set(k, &drop_ip(&v, old, &host));
        }
    }
    for k in ADDR_JSON_KEYS {
        let v = app.db.get(k);
        if v.contains(old) {
            app.db.set(k, &drop_ip(&v, old, &host));
        }
    }
    // the panel server's own node row
    let _ = app.db.exec("UPDATE nodes SET endpoint='', endpoint_mode='panel' WHERE id='local' AND endpoint=?1", &[&old]);
}

#[cfg(test)]
mod tests {
    use axum::http::Method;

    #[test]
    fn a_frozen_panel_refuses_changes_only() {
        let r = super::refused_while_moving;
        for (m, p) in [(Method::POST, "/api/users"), (Method::PUT, "/api/settings"), (Method::DELETE, "/api/users/3"), (Method::POST, "/api/sync"),
                       (Method::POST, "/tg/api/buy"), (Method::POST, "/tg/api/trial"), (Method::POST, "/tg/api/admin/panel"), (Method::POST, "/join/register"),
                       (Method::POST, "/api/restore"), (Method::PUT, "/api/bot")] {
            assert!(r(&m, p), "{} {}", m, p);
        }
        for (m, p) in [(Method::GET, "/api/users"), (Method::GET, "/sub/x/v2"), (Method::POST, "/hy2/auth"), (Method::POST, "/api/login"),
                       (Method::POST, "/api/logout"), (Method::DELETE, "/api/migrate"), (Method::GET, "/api/migrate"), (Method::GET, "/tg/api/me"),
                       (Method::GET, "/tg/api/admin/monitor"), (Method::POST, "/tunnel/agent"), (Method::GET, "/api/config/3/wg")] {
            assert!(!r(&m, p), "{} {}", m, p);
        }
    }

    #[test]
    fn a_new_ip_of_this_server_replaces_the_old_one() {
        let dir = std::env::temp_dir().join(format!("kanki-ip-{}", crate::util::rand_token(8)));
        std::fs::create_dir_all(&dir).unwrap();
        let mut env = std::collections::HashMap::new();
        env.insert("DOMAIN".to_string(), "p.example.com".to_string());
        env.insert("ENDPOINT".to_string(), "1.2.3.4".to_string());
        use std::sync::Mutex;
        let app = crate::App {
            db: crate::db::Db::open(dir.join("k.db").to_str().unwrap()), env,
            hy2_allowed: Mutex::new(Default::default()), limits: Mutex::new(Default::default()), reported: Mutex::new(Default::default()),
            login_fails: Mutex::new(Default::default()), sync_lock: tokio::sync::Mutex::new(()), bot_alive: std::sync::atomic::AtomicI64::new(0),
            http: reqwest::Client::new(), http_insecure: reqwest::Client::new(), pin_clients: Mutex::new(Default::default()),
        };
        app.db.set("sub_base", "https://1.2.3.4:2053");
        app.db.set("tun_local_addr", "1.2.3.4");
        app.db.set("kmix_nodes", r#"{"local":{"host":"1.2.3.4","tun_host":"ir.example.com"}}"#);
        super::forget_ip(&app, "1.2.3.4", "5.6.7.8");
        assert_eq!(app.db.get("sub_base"), "https://p.example.com:2053");
        assert_eq!(app.db.get("tun_local_addr"), "");
        assert_eq!(app.db.get("kmix_nodes"), r#"{"local":{"host":"","tun_host":"ir.example.com"}}"#);
        // users connected to the old IP (the settings file's ENDPOINT): now the domain
        assert_eq!(app.db.get("endpoint"), "p.example.com");
        assert_eq!(crate::api::panel_endpoint(&app), "p.example.com");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_old_ip_goes_from_settings() {
        let x = r#"{"servers":[{"server":"local","address":"1.2.3.4"}],"x":"1.2.3.45"}"#;
        assert_eq!(super::drop_ip(x, "1.2.3.4", "p.example.com"), r#"{"servers":[{"server":"local","address":""}],"x":"1.2.3.45"}"#);
        assert_eq!(super::drop_ip("https://1.2.3.4:2053/x", "1.2.3.4", "p.example.com"), "https://p.example.com:2053/x");
        // no port: at the end, before a query or a fragment; never a longer address
        assert_eq!(super::drop_ip("https://1.2.3.4", "1.2.3.4", "p.example.com"), "https://p.example.com");
        assert_eq!(super::drop_ip("https://1.2.3.4?a=1", "1.2.3.4", "p.example.com"), "https://p.example.com?a=1");
        assert_eq!(super::drop_ip("https://1.2.3.4#x", "1.2.3.4", "p.example.com"), "https://p.example.com#x");
        assert_eq!(super::drop_ip("https://1.2.3.45", "1.2.3.4", "p.example.com"), "https://1.2.3.45");
        assert_eq!(super::drop_ip(r#"{"u":"https://1.2.3.4"}"#, "1.2.3.4", "p.example.com"), r#"{"u":"https://p.example.com"}"#);
        // no domain: a URL keeps its host rather than losing it
        assert_eq!(super::drop_ip("https://1.2.3.4:2053/x", "1.2.3.4", ""), "https://1.2.3.4:2053/x");
    }
}
