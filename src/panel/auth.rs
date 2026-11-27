//! Authentication & security center: sessions, scoped API tokens, TOTP 2FA,
//! IP allow/deny policy, login history, audit log, brute-force protection.
use crate::util::{self, client_ip, now, rand_token, sha256_hex, user_agent};
use crate::App;
use axum::extract::{Path, Request, State};
use axum::http::{header, HeaderMap, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use rusqlite::OptionalExtension;
use serde_json::{json, Value};
use std::sync::Arc;

type St = State<Arc<App>>;

pub const SCOPES: &[&str] = &["users:read", "users:write", "nodes", "settings", "backup", "admin"];

pub fn deny() -> Response {
    (StatusCode::UNAUTHORIZED, Json(json!({"error": "unauthorized"}))).into_response()
}

fn bad(msg: &str) -> Response {
    (StatusCode::BAD_REQUEST, Json(json!({"error": msg}))).into_response()
}

/// The admin page's session cookie (3.68): HttpOnly, so the page's script never holds the session
pub const SESSION_COOKIE: &str = "kanki_session";
/// The header the admin page sends with every call: a cookie only counts with it, and a page of another site
/// cannot add it (CSRF)
pub const ADMIN_HEADER: &str = "x-kanki-admin";
/// A login session that was not used for this long ends (3.68; `session_idle_min` changes it)
const SESSION_IDLE_MIN: i64 = 120;

fn bearer(h: &HeaderMap) -> String {
    let t = h.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()).unwrap_or("");
    let t = t.trim_start_matches("Bearer ").trim().to_string();
    if !t.is_empty() {
        return t;
    }
    if h.get(ADMIN_HEADER).and_then(|v| v.to_str().ok()) != Some("1") {
        return String::new();
    }
    cookie(h, SESSION_COOKIE).unwrap_or_default()
}

/// One cookie's value
fn cookie(h: &HeaderMap, name: &str) -> Option<String> {
    h.get_all(header::COOKIE).iter().filter_map(|v| v.to_str().ok()).flat_map(|v| v.split(';')).find_map(|kv| {
        let (k, v) = kv.trim().split_once('=')?;
        (k == name && !v.is_empty() && v.len() <= 128 && v.bytes().all(|c| c.is_ascii_alphanumeric())).then(|| v.to_string())
    })
}

/// `Set-Cookie` of a session (`max_age` 0 = remove it)
fn session_cookie(token: &str, max_age: i64) -> String {
    format!("{}={}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age={}", SESSION_COOKIE, token, max_age)
}

fn idle_limit(app: &App) -> i64 {
    app.db.get("session_idle_min").parse::<i64>().unwrap_or(SESSION_IDLE_MIN).clamp(5, 24 * 60) * 60
}

pub fn admin_user(app: &App) -> String {
    let u = app.db.get("admin_user");
    if u.is_empty() { app.env.get("ADMIN_USER").cloned().unwrap_or_default() } else { u }
}

pub fn admin_pass_hash(app: &App) -> String {
    let p = app.db.get("admin_pass");
    if p.is_empty() { app.env.get("ADMIN_PASS").cloned().unwrap_or_default() } else { p }
}

/// Who is calling: Some((actor, scopes)) — sessions get every scope.
pub fn identify(app: &App, h: &HeaderMap) -> Option<(String, Vec<String>)> {
    identify_with(app, h, true)
}

/// The bot's mini app for admins reaches the bot's own panel routes (plans, discounts, sales settings) with this
/// key: made at start, never written anywhere, never leaves this process (`miniapp::admin_panel` checks the admin
/// and which route first). It has only the «settings» right.
pub fn internal_token() -> &'static str {
    static T: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    T.get_or_init(|| crate::util::rand_token(48))
}

/// The report bot's mini app reads the panel's state with this key (only GET of a fixed list, `miniapp::monitor`)
pub fn internal_read_token() -> &'static str {
    static T: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    T.get_or_init(|| crate::util::rand_token(48))
}

fn is_internal(h: &HeaderMap) -> bool {
    let t = bearer(h);
    util::ct_eq(&t, internal_token()) || util::ct_eq(&t, internal_read_token())
}

fn identify_with(app: &App, h: &HeaderMap, touch: bool) -> Option<(String, Vec<String>)> {
    let t = bearer(h);
    if t.is_empty() {
        return None;
    }
    if util::ct_eq(&t, internal_token()) {
        // the bot's settings, and reading the overview numbers (the bridge in `miniapp::bridge_ok` only lets
        // through its fixed list of routes, of which `/api/overview` is the only one under users:read)
        return Some(("bot-admin".into(), vec!["settings".into(), "users:read".into()]));
    }
    if util::ct_eq(&t, internal_read_token()) {
        return Some(("report-bot".into(), vec!["admin".into()]));
    }
    // 3.68: the old unrestricted `api_key` no longer opens anything (API tokens with scopes and an end replace it)
    let hash = sha256_hex(&t);
    // 3.68: a session also ends after `idle_limit` without a request (read before the database lock is taken)
    let idle_from = now() - idle_limit(app);
    let sess: Option<(String, String)> = app.db.with(|c| {
        c.query_row(
            "SELECT id, username FROM sessions WHERE hash=?1 AND expires>?2 AND last_seen>?3",
            rusqlite::params![hash, now(), idle_from],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .ok()
    });
    if let Some((id, user)) = sess {
        if touch {
            let _ = app.db.exec("UPDATE sessions SET last_seen=?1 WHERE id=?2", &[&now(), &id]);
        }
        return Some((user, vec!["admin".into()]));
    }
    let tok: Option<(i64, String, String)> = app.db.with(|c| {
        c.query_row("SELECT id, name, scopes FROM api_tokens WHERE hash=?1 AND expires>?2", rusqlite::params![hash, now()], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })
        .ok()
    });
    if let Some((id, name, scopes)) = tok {
        if touch {
            let _ = app.db.exec("UPDATE api_tokens SET last_used=?1 WHERE id=?2", &[&now(), &id]);
        }
        return Some((format!("token:{}", name), scopes.split(',').map(|s| s.trim().to_string()).collect()));
    }
    None
}

pub fn has_scope(scopes: &[String], need: &str) -> bool {
    scopes.iter().any(|s| s == "admin" || s == need || (need == "users:read" && s == "users:write"))
}

/// Route guard: Ok(actor) or a 401/403 response
#[allow(clippy::result_large_err)] // the error is the ready axum answer (401/403)
pub fn check(app: &App, h: &HeaderMap, scope: &str) -> Result<String, Response> {
    check_gate(app, h, scope, true)
}

/// `check` without the «2FA required» gate: the routes the page needs to show the security settings and turn
/// 2FA on (`/api/me`, `GET /api/security`)
#[allow(clippy::result_large_err)]
fn check_open(app: &App, h: &HeaderMap, scope: &str) -> Result<String, Response> {
    check_gate(app, h, scope, false)
}

#[allow(clippy::result_large_err)]
fn check_gate(app: &App, h: &HeaderMap, scope: &str, gate: bool) -> Result<String, Response> {
    match identify(app, h) {
        None => Err(deny()),
        // 3.68: «2FA required» means it: a login session does nothing but set up 2FA until it is on
        Some((actor, _)) if gate && is_login_session(&actor) && app.db.on("force_2fa") && !app.db.on("totp_on") => {
            Err((StatusCode::FORBIDDEN, Json(json!({"error": "2FA is required by policy: turn it on first (Security › 2FA)", "need_2fa": true}))).into_response())
        }
        Some((actor, scopes)) => {
            if has_scope(&scopes, scope) {
                Ok(actor)
            } else {
                Err((StatusCode::FORBIDDEN, Json(json!({"error": format!("missing scope {}", scope)}))).into_response())
            }
        }
    }
}

/// The actor is an admin's login session (not an API token or one of the bots' in-process keys)
fn is_login_session(actor: &str) -> bool {
    actor != "api-key" && !actor.starts_with("token:") && actor != "bot-admin" && actor != "report-bot"
}

/// Session-only guard (security-sensitive actions can't be done with API tokens)
#[allow(clippy::result_large_err)] // the error is the ready axum answer (401/403)
pub fn check_session(app: &App, h: &HeaderMap) -> Result<String, Response> {
    match identify(app, h) {
        // the in-process keys of the bots are not a login either: they may only do what their own bridge allows
        Some((actor, _)) if actor != "api-key" && !actor.starts_with("token:") && actor != "bot-admin" && actor != "report-bot" => Ok(actor),
        Some(_) => Err((StatusCode::FORBIDDEN, Json(json!({"error": "login session required"}))).into_response()),
        None => Err(deny()),
    }
}

#[macro_export]
macro_rules! guard {
    ($app:expr, $h:expr, $scope:expr) => {
        match $crate::auth::check(&$app, &$h, $scope) {
            Ok(a) => a,
            Err(r) => return r,
        }
    };
}

// ================================================================ middleware: IP policy + audit
/// The address headers are only believed when they come from Caddy on this machine. A caller that reaches the
/// panel's port straight (a `PANEL_BIND` other than 127.0.0.1) could otherwise name any address, pass the IP
/// allowlist and the login limit, or claim 127.0.0.1, which the limits leave alone.
fn trust_proxy_only(req: &mut Request) {
    let peer = req.extensions().get::<axum::extract::ConnectInfo<std::net::SocketAddr>>().map(|c| c.0.ip());
    if let Some(ip) = peer {
        if !ip.is_loopback() {
            if let Ok(v) = header::HeaderValue::from_str(&ip.to_string()) {
                req.headers_mut().insert("x-forwarded-for", v);
            }
        }
    }
}

fn is_admin_surface(path: &str) -> bool {
    (path.starts_with("/api/") && !path.starts_with("/api/config/")) || path == "/admin" || path.starts_with("/admin/")
}

pub fn ip_allowed(app: &App, ip: &str) -> bool {
    let allow = app.db.get("ip_allow");
    let deny = app.db.get("ip_deny");
    if !deny.trim().is_empty() && util::in_any(ip, &deny) {
        return false;
    }
    if !allow.trim().is_empty() && !util::in_any(ip, &allow) {
        return false;
    }
    true
}

pub async fn middleware(State(app): St, mut req: Request, next: Next) -> Response {
    // the panel is being moved to a new server: what changes here would be lost there
    if crate::migrate::frozen() && crate::migrate::refused_while_moving(req.method(), req.uri().path()) {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"error": "the panel is moving to a new server: changes wait until the move is done or cancelled (Backup › Move)"}))).into_response();
    }
    // a call from inside (the bot's admin mini app, already checked there): no address of its own to check
    if is_internal(req.headers()) {
        // the report bot only reads
        if util::ct_eq(&bearer(req.headers()), internal_read_token()) && req.method() != Method::GET {
            return deny();
        }
        // 3.68: what the bot's admin mini app changes is in the audit too
        let (method, path) = (req.method().clone(), req.uri().path().to_string());
        let res = next.run(req).await;
        if method != Method::GET {
            audit(&app, "bot-admin", method.as_str(), &path, res.status().as_u16() as i64, "internal", "");
        }
        return res;
    }
    // 3.69: the trusted Iran subscription relay signs each client's address (`subiran::relay_header`): that address
    // counts for the limits (one abusive client no longer locks out every Iranian user behind the relay). A header
    // that does not check out is dropped and the request is taken like any other.
    let target = req.uri().path_and_query().map(|p| p.as_str().to_string()).unwrap_or_default();
    let relayed = crate::subiran::verified_client(&app, req.headers(), req.method().as_str(), &target, util::now());
    req.headers_mut().remove(crate::subiran::RELAY_HEADER);
    match relayed.and_then(|ip| header::HeaderValue::from_str(&ip).ok()) {
        Some(v) => {
            req.headers_mut().insert("x-forwarded-for", v);
        }
        None => trust_proxy_only(&mut req),
    }
    let path = req.uri().path().to_string();
    if let Some(host) = req.headers().get(header::HOST).and_then(|v| v.to_str().ok()) {
        crate::subdomain::note_agent_host(&app, host, &path);
    }
    let method = req.method().clone();
    let ip = client_ip(req.headers());
    if is_admin_surface(&path) && !ip_allowed(&app, &ip) {
        return (StatusCode::FORBIDDEN, "forbidden").into_response();
    }
    // the restore (128 MiB) and app (200 MiB) uploads, and any other big body: not a byte is read for someone who
    // is not signed in (3.68: the app upload and every body over 1 MiB too)
    let big = req.headers().get(header::CONTENT_LENGTH).and_then(|v| v.to_str().ok()).and_then(|v| v.parse::<u64>().ok()).map(|n| n > 1 << 20).unwrap_or(false)
        || req.headers().get(header::TRANSFER_ENCODING).is_some();
    let upload = path == "/api/restore" || (path == "/api/apps" && req.method() == Method::POST) || (big && path.starts_with("/api/") && path != "/api/login");
    if upload && identify_with(&app, req.headers(), false).is_none() {
        return deny();
    }
    // 3.69: a restore replaces the whole panel: only a login session gets its 128 MiB read (an API token is
    // refused here, before the body, not after it was buffered)
    if path == "/api/restore" {
        if let Err(r) = check_session(&app, req.headers()) {
            return r;
        }
    }
    // 3.69: the hysteria upload of agents from before is gone (nothing an agent sends is run anywhere)
    if path == "/tunnel/hy2bin/put" {
        return (StatusCode::GONE, "gone").into_response();
    }
    // HTTPS only: Caddy says when a request came to it over plain http
    let sub = crate::limit::is_sub_path(&path);
    let plain = req.headers().get("x-forwarded-proto").and_then(|v| v.to_str().ok()).map(|v| v.eq_ignore_ascii_case("http")).unwrap_or(false);
    // 3.68: every API, the Telegram mini app's API, the move and the join paths too
    let https_only = sub || path.starts_with("/api/") || path.starts_with("/tg/api/") || path.starts_with("/move/") || path.starts_with("/join/");
    if plain && https_only {
        return (StatusCode::FORBIDDEN, "HTTPS only").into_response();
    }
    // spam and guessing: the login, and the subscription paths (an address that keeps asking for unknown codes waits)
    use crate::limit::{hit, over, LOGIN, SUB, SUB_MISS};
    if path == "/api/login" && !hit("login", &ip, LOGIN.0, LOGIN.1) {
        return (StatusCode::TOO_MANY_REQUESTS, Json(json!({"error": "too many requests, wait a minute"}))).into_response();
    }
    // 3.68: no address is exempt (a caller without a proxy header was taken for "this machine" and never limited)
    let limited = sub;
    if let Some((name, max, win)) = crate::limit::public_path_limit(&path) {
        if !hit(name, &ip, max, win) {
            return (StatusCode::TOO_MANY_REQUESTS, [(header::RETRY_AFTER, "60")], "too many requests").into_response();
        }
    }
    if limited && (over("sub_miss", &ip, SUB_MISS.0, SUB_MISS.1) || !hit("sub", &ip, SUB.0, SUB.1)) {
        return (StatusCode::TOO_MANY_REQUESTS, [(header::RETRY_AFTER, "60")], "too many requests").into_response();
    }
    let audited = (path.starts_with("/api/") && method != Method::GET && path != "/api/login" && !path.starts_with("/api/config/"))
        || sensitive_read(&method, &path)
        || path.starts_with("/move/")
        || (path.starts_with("/join/") && method != Method::GET);
    let actor = if audited { identify_with(&app, req.headers(), false).map(|a| a.0) } else { None };
    let res = next.run(req).await;
    if limited && res.headers().get("x-kanki-reason").is_some_and(|v| v == "unknown") {
        hit("sub_miss", &ip, SUB_MISS.0, SUB_MISS.1);
    }
    if audited {
        let st = res.status().as_u16() as i64;
        match actor {
            Some(a) => audit(&app, &a, method.as_str(), &path, st, &ip, ""),
            // 3.68: refused calls of someone not signed in are counted, not written: a flood of them cannot push
            // the real entries out of the 5000-row audit. Token-checked paths (/move, /join) are always written.
            None if (st == 401 || st == 403) && path.starts_with("/api/") => {
                hit("audit_anon", &ip, u32::MAX, 3600);
            }
            None => audit(&app, "anonymous", method.as_str(), &path, st, &ip, ""),
        }
    }
    res
}

/// Reads that hand out secrets: written in the audit like changes (backup, VPN server configs, a server's
/// install command)
fn sensitive_read(m: &Method, path: &str) -> bool {
    *m == Method::GET
        && (path == "/api/backup" || path.ends_with("/awgconf/entry") || path.ends_with("/awgconf/exit") || path.contains("/awgconf/") || path.contains("/hy2conf/")
            || (path.starts_with("/api/servers/") && path.ends_with("/command")))
}

/// One audit row, chained to the one before it: `chain` = sha256(chain of the last row | this row's fields), so
/// a row changed or removed in the middle shows (3.68). The last chain is read and the row written under the
/// database lock, so two requests never build on the same row.
pub fn audit(app: &App, actor: &str, method: &str, path: &str, status: i64, ip: &str, detail: &str) {
    audit_db(&app.db, actor, method, path, status, ip, detail);
}

/// `audit` on a bare database (the command line, before the panel runs)
pub fn audit_db(db: &crate::db::Db, actor: &str, method: &str, path: &str, status: i64, ip: &str, detail: &str) {
    let r: rusqlite::Result<()> = db.with(|c| {
        let prev: String = c.query_row("SELECT chain FROM audit ORDER BY id DESC LIMIT 1", [], |r| r.get(0)).optional()?.unwrap_or_default();
        let ts = now();
        let chain = audit_link(&prev, ts, actor, method, path, status, ip, detail);
        c.execute(
            "INSERT INTO audit(ts,actor,method,path,status,ip,detail,chain) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            rusqlite::params![ts, actor, method, path, status, ip, detail, chain],
        )?;
        Ok(())
    });
    if let Err(e) = r {
        eprintln!("audit: a row could not be written: {}", e);
    }
    db.note_log_row();
}

#[allow(clippy::too_many_arguments)]
fn audit_link(prev: &str, ts: i64, actor: &str, method: &str, path: &str, status: i64, ip: &str, detail: &str) -> String {
    sha256_hex(&format!("{}\u{1f}{}\u{1f}{}\u{1f}{}\u{1f}{}\u{1f}{}\u{1f}{}\u{1f}{}", prev, ts, actor, method, path, status, ip, detail))
}

/// The id of the first audit row whose chain does not follow from the row before it (None = intact). Rows
/// written before 3.68 (no chain) and the oldest kept row (its parent was trimmed) start the check.
pub fn audit_broken(app: &App) -> Option<i64> {
    type Row = (i64, i64, String, String, String, i64, String, String, String);
    let rows: Vec<Row> = app.db.with(|c| {
        let mut st = c.prepare("SELECT id,ts,actor,method,path,status,ip,detail,chain FROM audit ORDER BY id").ok()?;
        let it = st
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?, r.get(8)?)))
            .ok()?;
        Some(it.filter_map(|x| x.ok()).collect())
    })?;
    let mut prev: Option<String> = None;
    for (id, ts, actor, method, path, status, ip, detail, chain) in rows {
        if chain.is_empty() {
            prev = None;
            continue;
        }
        if let Some(p) = &prev {
            if audit_link(p, ts, &actor, &method, &path, status, &ip, &detail) != chain {
                return Some(id);
            }
        }
        prev = Some(chain);
    }
    None
}

// ================================================================ routes
pub fn router() -> Router<Arc<App>> {
    Router::new()
        .route("/api/login", post(login))
        .route("/api/logout", post(logout))
        .route("/api/me", get(me))
        .route("/api/security", get(security_get))
        .route("/api/security/password", post(change_password))
        .route("/api/security/policy", post(policy))
        .route("/api/security/apikey", post(regen_key))
        .route("/api/security/2fa/setup", post(totp_setup))
        .route("/api/security/2fa/enable", post(totp_enable))
        .route("/api/security/2fa/disable", post(totp_disable))
        .route("/api/security/revoke-others", post(revoke_others))
        .route("/api/security/sessions/:id", delete(revoke_session))
        .route("/api/security/tokens", post(token_create))
        .route("/api/security/tokens/:id", delete(token_delete))
}

fn log_login(app: &App, user: &str, ip: &str, method: &str, ok: bool) {
    let _ = app.db.exec(
        "INSERT INTO login_log(ts,username,ip,method,ok) VALUES(?1,?2,?3,?4,?5)",
        &[&now(), &user, &ip, &method, &(ok as i64)],
    );
    app.db.note_log_row();
}

/// 5 wrong logins from one address in an hour lock it for an hour from the 5th
const MAX_FAILS: u32 = 5;
const FAIL_WINDOW: i64 = 60 * 60;

fn fail(app: &App, ip: &str) {
    let mut m = app.login_fails.lock().unwrap_or_else(|e| e.into_inner());
    count_fail(&mut m, ip);
}

fn count_fail(m: &mut std::collections::HashMap<String, (u32, i64)>, ip: &str) {
    // forget old entries so the table cannot grow without limit (many source addresses)
    crate::limit::trim(m, 5000, FAIL_WINDOW, now());
    let e = m.entry(ip.to_string()).or_insert((0, now()));
    if now() - e.1 >= FAIL_WINDOW {
        *e = (0, now());
    }
    e.0 += 1;
    // the lock hour starts at the last wrong try
    if e.0 >= MAX_FAILS {
        e.1 = now();
    }
}

/// Starts a password try from `ip`: false when the address is locked. The try is counted as wrong
/// before the password is checked, so tries sent all at once cannot pass the lock while they wait for
/// PBKDF2; `undo_fail` takes it back when the password was right.
fn begin_try(app: &App, ip: &str) -> bool {
    let mut m = app.login_fails.lock().unwrap_or_else(|e| e.into_inner());
    if matches!(m.get(ip), Some((n, t)) if *n >= MAX_FAILS && now() - *t < FAIL_WINDOW) {
        return false;
    }
    count_fail(&mut m, ip);
    true
}

fn undo_fail(app: &App, ip: &str) {
    let mut m = app.login_fails.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(e) = m.get_mut(ip) {
        e.0 = e.0.saturating_sub(1);
    }
}

/// A stored hash with the same work as a real one: checked when the username is wrong, so the answer
/// takes as long as for a wrong password (the time does not tell whether the name exists).
const DUMMY_HASH: &str = "pbkdf2$600000$kankidummysalt00$0000000000000000000000000000000000000000000000000000000000000000";

/// Checks the admin password off the async worker threads (PBKDF2 takes about a tenth of a second of CPU)
/// At most this many password checks at once (each is ~0.3 s of one core): a burst of logins cannot take every
/// worker thread or the whole CPU (3.68)
const PASSWORD_CHECKS: usize = 2;

async fn password_ok(stored: &str, pass: &str) -> bool {
    static GATE: std::sync::OnceLock<tokio::sync::Semaphore> = std::sync::OnceLock::new();
    let gate = GATE.get_or_init(|| tokio::sync::Semaphore::new(PASSWORD_CHECKS));
    let Ok(_permit) = gate.acquire().await else { return false };
    let (st, pw) = (stored.to_string(), pass.to_string());
    tokio::task::spawn_blocking(move || util::check_password(&st, &pw)).await.unwrap_or(false)
}

/// Wrong 2FA codes from everywhere together (3.68): after 10 in 10 minutes no code is checked until the window
/// passes, so many addresses together cannot try the million codes either
const TOTP_FAILS: (u32, i64) = (10, 600);

fn totp_locked() -> bool {
    crate::limit::over("totp_all", "all", TOTP_FAILS.0, TOTP_FAILS.1)
}

fn totp_failed() {
    crate::limit::hit("totp_all", "all", TOTP_FAILS.0, TOTP_FAILS.1);
}

/// Checks a 2FA code and remembers its 30s step: the same code (or an older one) is not accepted twice.
fn totp_fresh(app: &App, secret: &str, code: &str) -> bool {
    static L: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _g = L.lock().unwrap_or_else(|e| e.into_inner());
    let Some(step) = util::totp_step(secret, code, now()) else { return false };
    let last: u64 = app.db.get("totp_last_step").parse().unwrap_or(0);
    if !step_is_new(step, last) {
        return false;
    }
    app.db.set("totp_last_step", &step.to_string());
    true
}

fn step_is_new(step: u64, last: u64) -> bool {
    step > last
}

/// Names the panel itself uses for API keys and tokens: an admin called like this could not do
/// session-only actions (security, 2FA, password)
pub fn reserved_admin_name(u: &str) -> bool {
    u == "api-key" || u.starts_with("token:")
}

async fn login(State(app): St, h: HeaderMap, Json(b): Json<Value>) -> Response {
    let ip = client_ip(&h);
    if !begin_try(&app, &ip) {
        return (StatusCode::TOO_MANY_REQUESTS, Json(json!({"error": "too many attempts, try again in an hour"}))).into_response();
    }
    let u = b["username"].as_str().unwrap_or("").trim().to_string();
    let p = b["password"].as_str().unwrap_or("");
    let stored = admin_pass_hash(&app);
    let name_ok = util::ct_eq(&u, &admin_user(&app)) && !stored.is_empty();
    let ok = password_ok(if name_ok { &stored } else { DUMMY_HASH }, p).await && name_ok;
    if !ok {
        // already counted as wrong by begin_try
        log_login(&app, &u, &ip, "password", false);
        tokio::time::sleep(std::time::Duration::from_millis(900)).await;
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": "invalid username or password"}))).into_response();
    }
    undo_fail(&app, &ip);
    if app.db.on("totp_on") {
        let otp = b["otp"].as_str().unwrap_or("");
        if otp.is_empty() {
            return (StatusCode::UNAUTHORIZED, Json(json!({"error": "2FA code required", "need_otp": true}))).into_response();
        }
        if totp_locked() {
            return (StatusCode::TOO_MANY_REQUESTS, Json(json!({"error": "too many wrong 2FA codes, wait 10 minutes", "need_otp": true}))).into_response();
        }
        if !totp_fresh(&app, &app.db.get("totp_secret"), otp) {
            fail(&app, &ip);
            totp_failed();
            log_login(&app, &u, &ip, "totp", false);
            return (StatusCode::UNAUTHORIZED, Json(json!({"error": "wrong 2FA code", "need_otp": true}))).into_response();
        }
    }
    // an old hash (salted SHA-256, or fewer PBKDF2 rounds) is rewritten with today's rounds
    if util::needs_rehash(&stored) {
        let pw = p.to_string();
        match tokio::task::spawn_blocking(move || util::hash_password(&pw)).await {
            Ok(h) => app.db.set("admin_pass", &h),
            Err(e) => eprintln!("login: the password hash could not be upgraded: {}", e),
        }
    }
    app.login_fails.lock().unwrap_or_else(|e| e.into_inner()).remove(&ip);
    let t = rand_token(48);
    let hours: i64 = app.db.get("session_hours").parse::<i64>().unwrap_or(24).clamp(1, 24 * 90);
    let id = rand_token(8).to_lowercase();
    let _ = app.db.exec(
        "INSERT INTO sessions(id,hash,username,ip,ua,created,last_seen,expires) VALUES(?1,?2,?3,?4,?5,?6,?6,?7)",
        &[&id, &sha256_hex(&t), &u, &ip, &user_agent(&h), &now(), &(now() + hours * 3600)],
    );
    let _ = app.db.exec("DELETE FROM sessions WHERE expires<?1 OR last_seen<?2", &[&now(), &(now() - idle_limit(&app))]);
    log_login(&app, &u, &ip, if app.db.on("totp_on") { "password+2fa" } else { "password" }, true);
    // 3.68: the admin page gets the session as an HttpOnly cookie only; a script that logs in on purpose
    // (`X-Kanki-Token-Login: 1`) still gets it in the answer
    let cookie = session_cookie(&t, hours * 3600);
    let body = if h.get("x-kanki-token-login").and_then(|v| v.to_str().ok()) == Some("1") { json!({ "ok": true, "token": t }) } else { json!({ "ok": true }) };
    ([(header::SET_COOKIE, cookie)], Json(body)).into_response()
}

async fn logout(State(app): St, h: HeaderMap) -> Response {
    let t = bearer(&h);
    if !t.is_empty() {
        let _ = app.db.exec("DELETE FROM sessions WHERE hash=?1", &[&sha256_hex(&t)]);
    }
    ([(header::SET_COOKIE, session_cookie("", 0))], Json(json!({"ok": true}))).into_response()
}

pub fn ui_settings(app: &App) -> Value {
    let g = |k: &str| app.db.get(k);
    json!({
        "panel_name": g("panel_name"), "lang": g("lang"), "theme": g("theme"), "color": g("color"),
        "refresh": g("refresh").parse::<i64>().unwrap_or(15), "version": crate::VERSION,
        "logo": g("logo"),
        "def_gb": g("def_gb"), "def_days": g("def_days"), "def_conns": g("def_conns"),
    })
}

async fn me(State(app): St, h: HeaderMap) -> Response {
    let actor = match check_open(&app, &h, "users:read") { Ok(a) => a, Err(r) => return r };
    let mut v = ui_settings(&app);
    v["user"] = json!(actor);
    v["need_2fa"] = json!(app.db.on("force_2fa") && !app.db.on("totp_on"));
    v["totp_on"] = json!(app.db.on("totp_on"));
    v["force_2fa"] = json!(app.db.on("force_2fa"));
    v["default_protocols"] = json!(app.db.get("default_protocols"));
    v["default_tier"] = json!(crate::access::Tier::parse(&app.db.get("default_tier")).unwrap_or(crate::access::Tier::Vip).as_str());
    Json(v).into_response()
}

fn current_session_id(app: &App, h: &HeaderMap) -> String {
    let hash = sha256_hex(&bearer(h));
    app.db.with(|c| c.query_row("SELECT id FROM sessions WHERE hash=?1", [hash], |r| r.get::<_, String>(0)).unwrap_or_default())
}

async fn security_get(State(app): St, h: HeaderMap) -> Response {
    if let Err(r) = check_open(&app, &h, "admin") { return r; }
    let cur = current_session_id(&app, &h);
    let (sessions, tokens, logins, audit) = app.db.with(|c| {
        let mut s = c.prepare("SELECT id,username,ip,ua,created,last_seen,expires FROM sessions WHERE expires>?1 ORDER BY last_seen DESC").unwrap();
        let sessions: Vec<Value> = s.query_map([now()], |r| Ok(json!({
            "id": r.get::<_, String>(0)?, "username": r.get::<_, String>(1)?, "ip": r.get::<_, String>(2)?,
            "ua": r.get::<_, String>(3)?, "created": r.get::<_, i64>(4)?, "last_seen": r.get::<_, i64>(5)?, "expires": r.get::<_, i64>(6)?,
        }))).unwrap().filter_map(|x| x.ok()).collect();
        let mut s = c.prepare("SELECT id,name,prefix,scopes,created,last_used FROM api_tokens ORDER BY id DESC").unwrap();
        let tokens: Vec<Value> = s.query_map([], |r| Ok(json!({
            "id": r.get::<_, i64>(0)?, "name": r.get::<_, String>(1)?, "prefix": r.get::<_, String>(2)?,
            "scopes": r.get::<_, String>(3)?, "created": r.get::<_, i64>(4)?, "last_used": r.get::<_, i64>(5)?,
        }))).unwrap().filter_map(|x| x.ok()).collect();
        let mut s = c.prepare("SELECT ts,username,ip,method,ok FROM login_log ORDER BY id DESC LIMIT 50").unwrap();
        let logins: Vec<Value> = s.query_map([], |r| Ok(json!({
            "ts": r.get::<_, i64>(0)?, "username": r.get::<_, String>(1)?, "ip": r.get::<_, String>(2)?,
            "method": r.get::<_, String>(3)?, "ok": r.get::<_, i64>(4)? == 1,
        }))).unwrap().filter_map(|x| x.ok()).collect();
        let mut s = c.prepare("SELECT ts,actor,method,path,status,ip FROM audit ORDER BY id DESC LIMIT 100").unwrap();
        let audit: Vec<Value> = s.query_map([], |r| Ok(json!({
            "ts": r.get::<_, i64>(0)?, "actor": r.get::<_, String>(1)?, "method": r.get::<_, String>(2)?,
            "path": r.get::<_, String>(3)?, "status": r.get::<_, i64>(4)?, "ip": r.get::<_, String>(5)?,
        }))).unwrap().filter_map(|x| x.ok()).collect();
        (sessions, tokens, logins, audit)
    });
    let key = app.db.get("api_key");
    let masked = if key.is_empty() { String::new() } else if key.starts_with("h:") { app.db.get("api_key_hint") } else if key.len() > 8 { format!("{}…{}", &key[..4], &key[key.len() - 4..]) } else { String::new() };
    Json(json!({
        "admin_user": admin_user(&app), "totp_on": app.db.on("totp_on"), "force_2fa": app.db.on("force_2fa"),
        "ip_allow": app.db.get("ip_allow"), "ip_deny": app.db.get("ip_deny"), "session_hours": app.db.get("session_hours"),
        "my_ip": client_ip(&h), "current_session": cur,
        // 3.68: the audit's hash chain is unbroken (no row was changed or removed in the middle)
        "audit_intact": audit_broken(&app).is_none(),
        // 3.72: Kanki DNS registration over plain HTTP (old apps) is still open
        "allow_plain_http_kdns": app.db.get("allow_plain_http_kdns") != "0",
        "sessions": sessions, "tokens": tokens, "logins": logins, "audit": audit,
        "legacy_key": masked, "scopes": SCOPES,
        // the panel listens only on this machine, behind Caddy's HTTPS (old installs listened on every address)
        "https_only": app.env.get("PANEL_BIND").map(|b| b == "127.0.0.1" || b == "::1" || b == "localhost").unwrap_or(true),
    }))
    .into_response()
}

/// The shortest admin password (3.68)
pub const MIN_PASSWORD: usize = 12;
/// How long a 2FA secret waits to be confirmed (3.68)
const TOTP_PENDING_SECS: i64 = 600;

/// Step-up for the security settings (3.68): the admin's password again in `current`, with the login's lock per
/// address, so a stolen session alone cannot change the IP policy, 2FA or make API tokens
#[allow(clippy::result_large_err)] // the error is the ready axum answer
pub(crate) async fn step_up(app: &App, h: &HeaderMap, b: &Value) -> Result<(), Response> {
    let ip = client_ip(h);
    if !begin_try(app, &ip) {
        return Err((StatusCode::TOO_MANY_REQUESTS, Json(json!({"error": "too many attempts, try again in an hour"}))).into_response());
    }
    if !password_ok(&admin_pass_hash(app), b["current"].as_str().unwrap_or("")).await {
        log_login(app, &admin_user(app), &ip, "step-up", false);
        return Err((StatusCode::FORBIDDEN, Json(json!({"error": "your current password is needed for this (wrong or missing)", "need_password": true}))).into_response());
    }
    undo_fail(app, &ip);
    Ok(())
}

async fn change_password(State(app): St, h: HeaderMap, Json(b): Json<Value>) -> Response {
    if let Err(r) = check_session(&app, &h) { return r; }
    // the same lock as the login: a stolen session cannot guess the password here either
    let ip = client_ip(&h);
    if !begin_try(&app, &ip) {
        return (StatusCode::TOO_MANY_REQUESTS, Json(json!({"error": "too many attempts, try again in an hour"}))).into_response();
    }
    let cur = b["current"].as_str().unwrap_or("");
    if !password_ok(&admin_pass_hash(&app), cur).await {
        log_login(&app, &admin_user(&app), &ip, "password-change", false);
        return bad("current password is wrong");
    }
    undo_fail(&app, &ip);
    let user = b["username"].as_str().unwrap_or("").trim();
    let pass = b["password"].as_str().unwrap_or("");
    if pass.chars().count() < MIN_PASSWORD {
        return bad(&format!("password must be at least {} characters", MIN_PASSWORD));
    }
    if reserved_admin_name(user) {
        return bad("this username is reserved, pick another");
    }
    if !user.is_empty() {
        app.db.set("admin_user", user);
    }
    let pw = pass.to_string();
    let hash = tokio::task::spawn_blocking(move || util::hash_password(&pw)).await.unwrap_or_default();
    if hash.is_empty() {
        return bad("could not save the password, try again");
    }
    app.db.set("admin_pass", &hash);
    let cur_id = current_session_id(&app, &h);
    let _ = app.db.exec("DELETE FROM sessions WHERE id<>?1", &[&cur_id]);
    Json(json!({"ok": true})).into_response()
}

async fn policy(State(app): St, h: HeaderMap, Json(b): Json<Value>) -> Response {
    if let Err(r) = check_session(&app, &h) { return r; }
    if let Err(r) = step_up(&app, &h, &b).await { return r; }
    let allow = b["ip_allow"].as_str().unwrap_or("").trim().to_string();
    let deny_l = b["ip_deny"].as_str().unwrap_or("").trim().to_string();
    let ip = client_ip(&h);
    // never lock yourself out
    if !allow.is_empty() && !util::in_any(&ip, &allow) {
        return bad(&format!("your current IP {} is not in the allow list", ip));
    }
    if !deny_l.is_empty() && util::in_any(&ip, &deny_l) {
        return bad(&format!("your current IP {} is in the deny list", ip));
    }
    let hours = b["session_hours"].as_i64().or_else(|| b["session_hours"].as_str().and_then(|s| s.parse().ok())).unwrap_or(24).clamp(1, 24 * 90);
    let force = b["force_2fa"].as_bool().unwrap_or(false);
    if force && !app.db.on("totp_on") {
        return bad("enable 2FA first, then you can enforce it");
    }
    app.db.set("ip_allow", &allow);
    app.db.set("ip_deny", &deny_l);
    app.db.set("session_hours", &hours.to_string());
    app.db.set("force_2fa", if force { "1" } else { "0" });
    Json(json!({"ok": true})).into_response()
}

async fn regen_key(State(app): St, h: HeaderMap) -> Response {
    if let Err(r) = check_session(&app, &h) { return r; }
    (StatusCode::GONE, Json(json!({"error": "the full-access API key was removed in 3.68: make an API token with only the scopes it needs (Security › API tokens)"}))).into_response()
}

/// The old full-access API key is kept only as a hash ("h:<sha256>"), like the API tokens: a copy of the
/// database (a backup) does not hand out a key that works on the panel. Only its two ends are kept to show.
pub fn set_legacy_key(db: &crate::db::Db, k: &str) {
    db.set("api_key", &format!("h:{}", sha256_hex(k)));
    db.set("api_key_hint", &if k.len() > 8 { format!("{}…{}", &k[..4], &k[k.len() - 4..]) } else { String::new() });
}

/// A signed-in admin session for the tests: its bearer token
#[cfg(test)]
pub fn test_session(app: &App) -> String {
    let t = rand_token(32);
    let _ = app.db.exec(
        "INSERT INTO sessions(id,hash,username,ip,ua,created,last_seen,expires) VALUES(?1,?2,'admin','203.0.113.1','test',?3,?3,?4)",
        &[&rand_token(8), &sha256_hex(&t), &now(), &(now() + 3600)],
    );
    t
}

/// Does `t` open the old API key (tests)
#[cfg(test)]
pub fn legacy_key_matches(db: &crate::db::Db, t: &str) -> bool {
    legacy_key_ok(&db.get("api_key"), t)
}

#[cfg(test)]
fn legacy_key_ok(stored: &str, t: &str) -> bool {
    match stored.strip_prefix("h:") {
        Some(h) => !h.is_empty() && util::ct_eq(&sha256_hex(t), h),
        None => !stored.is_empty() && util::ct_eq(t, stored),
    }
}

/// At start: a key from before 3.51 (kept as it is) is turned into its hash; none yet: one nobody knows
pub fn legacy_key_start(db: &crate::db::Db) {
    let k = db.get("api_key");
    if k.is_empty() {
        set_legacy_key(db, &rand_token(40));
        db.set("api_key_hint", "");
    } else if !k.starts_with("h:") {
        set_legacy_key(db, &k);
    }
}

async fn totp_setup(State(app): St, h: HeaderMap, b: Option<Json<Value>>) -> Response {
    if let Err(r) = check_session(&app, &h) { return r; }
    let b = b.map(|x| x.0).unwrap_or(Value::Null);
    if let Err(r) = step_up(&app, &h, &b).await { return r; }
    // a new secret only after the current one is turned off with its own code
    if app.db.on("totp_on") {
        return bad("2FA is already on; turn it off with its code first");
    }
    let secret = util::totp_secret();
    app.db.set("totp_pending", &secret);
    app.db.set("totp_pending_at", &now().to_string());
    let label = format!("{}:{}", app.db.get("panel_name"), admin_user(&app));
    let uri = format!("otpauth://totp/{}?secret={}&issuer={}&digits=6&period=30", util::pct(&label), secret, util::pct(&app.db.get("panel_name")));
    Json(json!({"secret": secret, "uri": uri, "qr": util::qr_svg(&uri).unwrap_or_default()})).into_response()
}

async fn totp_enable(State(app): St, h: HeaderMap, Json(b): Json<Value>) -> Response {
    if let Err(r) = check_session(&app, &h) { return r; }
    if app.db.on("totp_on") {
        return bad("2FA is already on; turn it off with its code first");
    }
    let pending = app.db.get("totp_pending");
    if pending.is_empty() {
        return bad("start setup first");
    }
    // 3.68: a secret waits 10 minutes to be confirmed, then setup starts again
    let at: i64 = app.db.get("totp_pending_at").parse().unwrap_or(0);
    if now() - at > TOTP_PENDING_SECS {
        app.db.set("totp_pending", "");
        return bad("the setup took longer than 10 minutes: start it again");
    }
    if totp_locked() {
        return (StatusCode::TOO_MANY_REQUESTS, Json(json!({"error": "too many wrong 2FA codes, wait 10 minutes"}))).into_response();
    }
    // the code that turns 2FA on is used up (its 30-second step cannot log in afterwards)
    if !totp_fresh(&app, &pending, b["code"].as_str().unwrap_or("")) {
        totp_failed();
        return bad("wrong code, check your phone clock");
    }
    app.db.set("totp_secret", &pending);
    app.db.set("totp_pending", "");
    app.db.set("totp_pending_at", "");
    app.db.set("totp_on", "1");
    Json(json!({"ok": true})).into_response()
}

async fn totp_disable(State(app): St, h: HeaderMap, Json(b): Json<Value>) -> Response {
    if let Err(r) = check_session(&app, &h) { return r; }
    if app.db.on("force_2fa") {
        return bad("2FA is enforced by policy; turn enforcement off first");
    }
    if let Err(r) = step_up(&app, &h, &b).await { return r; }
    if totp_locked() {
        return (StatusCode::TOO_MANY_REQUESTS, Json(json!({"error": "too many wrong 2FA codes, wait 10 minutes"}))).into_response();
    }
    if app.db.on("totp_on") && !totp_fresh(&app, &app.db.get("totp_secret"), b["code"].as_str().unwrap_or("")) {
        totp_failed();
        return bad("wrong code");
    }
    app.db.set("totp_on", "0");
    app.db.set("totp_secret", "");
    Json(json!({"ok": true})).into_response()
}

async fn revoke_others(State(app): St, h: HeaderMap) -> Response {
    if let Err(r) = check_session(&app, &h) { return r; }
    let cur = current_session_id(&app, &h);
    let _ = app.db.exec("DELETE FROM sessions WHERE id<>?1", &[&cur]);
    Json(json!({"ok": true})).into_response()
}

async fn revoke_session(State(app): St, h: HeaderMap, Path(id): Path<String>) -> Response {
    if let Err(r) = check_session(&app, &h) { return r; }
    let _ = app.db.exec("DELETE FROM sessions WHERE id=?1", &[&id]);
    Json(json!({"ok": true})).into_response()
}

async fn token_create(State(app): St, h: HeaderMap, Json(b): Json<Value>) -> Response {
    if let Err(r) = check_session(&app, &h) { return r; }
    if let Err(r) = step_up(&app, &h, &b).await { return r; }
    let name = b["name"].as_str().unwrap_or("").trim().to_string();
    if name.is_empty() {
        return bad("name required");
    }
    let scopes: Vec<String> = b["scopes"].as_array().map(|a| {
        a.iter().filter_map(|x| x.as_str()).filter(|s| SCOPES.contains(s)).map(|s| s.to_string()).collect()
    }).unwrap_or_default();
    if scopes.is_empty() {
        return bad("pick at least one scope");
    }
    // 3.68: every token ends: 1 to 365 days (90 when not given)
    let days = b["days"].as_i64().unwrap_or(90);
    if !(1..=365).contains(&days) {
        return bad("days: 1 to 365");
    }
    let expires = now() + days * 86400;
    let t = format!("kk_{}", rand_token(44));
    let prefix: String = t.chars().take(8).collect();
    let r = app.db.exec(
        "INSERT INTO api_tokens(name,hash,prefix,scopes,created,expires) VALUES(?1,?2,?3,?4,?5,?6)",
        &[&name, &sha256_hex(&t), &prefix, &scopes.join(","), &now(), &expires],
    );
    match r {
        Ok(_) => Json(json!({"token": t, "expires": expires})).into_response(),
        Err(e) => bad(&e),
    }
}

async fn token_delete(State(app): St, h: HeaderMap, Path(id): Path<i64>) -> Response {
    if let Err(r) = check_session(&app, &h) { return r; }
    let _ = app.db.exec("DELETE FROM api_tokens WHERE id=?1", &[&id]);
    Json(json!({"ok": true})).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_old_api_key_is_kept_only_as_a_hash_and_opens_nothing() {
        let app = crate::test_app();
        app.db.set("api_key", "plainlegacykey0123456789");
        legacy_key_start(&app.db);
        assert!(app.db.get("api_key").starts_with("h:") && !app.db.get("api_key").contains("plainlegacy"));
        let mut h = HeaderMap::new();
        // 3.68: the old full-access key opens nothing any more, as its plain text or its hash
        h.insert("authorization", "Bearer plainlegacykey0123456789".parse().unwrap());
        assert!(identify_with(&app, &h, false).is_none());
        h.insert("authorization", format!("Bearer {}", app.db.get("api_key")).parse().unwrap());
        assert!(identify_with(&app, &h, false).is_none());
        // a start again leaves the hash as it is
        let k = app.db.get("api_key");
        legacy_key_start(&app.db);
        assert_eq!(app.db.get("api_key"), k);
    }

    #[test]
    fn the_audit_chain_shows_a_changed_row() {
        let app = crate::test_app();
        for i in 0..5 {
            audit(&app, "admin", "POST", &format!("/api/users/{}", i), 200, "203.0.113.1", "");
        }
        assert_eq!(audit_broken(&app), None);
        let mid: i64 = app.db.with(|c| c.query_row("SELECT id FROM audit ORDER BY id LIMIT 1 OFFSET 2", [], |r| r.get(0)).unwrap());
        app.db.exec("UPDATE audit SET actor='someone-else' WHERE id=?1", &[&mid]).unwrap();
        assert_eq!(audit_broken(&app), Some(mid));
    }

    /// Refused calls of strangers are not written (a flood cannot evict the real audit rows); a signed-in change is
    #[tokio::test]
    async fn strangers_cannot_fill_the_audit() {
        use tower::ServiceExt;
        let app = crate::test_app();
        let count = || app.db.with(|c| c.query_row("SELECT COUNT(*) FROM audit", [], |r| r.get::<_, i64>(0)).unwrap());
        for _ in 0..20 {
            let r = Request::post("/api/users").header("content-type", "application/json").header("x-forwarded-for", "198.51.100.7")
                .body(axum::body::Body::from("{}")).unwrap();
            let res = crate::api::master_router(app.clone()).oneshot(r).await.unwrap();
            assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        }
        assert_eq!(count(), 0);
        // and a stranger's big upload is refused before its body is read
        let r = Request::post("/api/apps").header("content-length", "209715200").header("x-forwarded-for", "198.51.100.7")
            .body(axum::body::Body::empty()).unwrap();
        assert_eq!(crate::api::master_router(app.clone()).oneshot(r).await.unwrap().status(), StatusCode::UNAUTHORIZED);
        // the restore (128 MiB): a stranger, and an API token, are refused before a byte is read
        let r = Request::post("/api/restore").header("content-length", "134217728").header("x-forwarded-for", "198.51.100.7")
            .body(axum::body::Body::empty()).unwrap();
        assert_eq!(crate::api::master_router(app.clone()).oneshot(r).await.unwrap().status(), StatusCode::UNAUTHORIZED);
        let tok = "kk-restore-token-0123456789abcdef";
        app.db.exec("INSERT INTO api_tokens(name,hash,prefix,scopes,created,expires) VALUES('t',?1,'kk',?2,?3,?4)", &[&sha256_hex(tok), &"admin", &now(), &(now() + 3600)]).unwrap();
        let r = Request::post("/api/restore").header("content-length", "134217728").header("authorization", format!("Bearer {}", tok))
            .header("x-forwarded-for", "198.51.100.7").body(axum::body::Body::empty()).unwrap();
        assert_eq!(crate::api::master_router(app.clone()).oneshot(r).await.unwrap().status(), StatusCode::FORBIDDEN);
        let r = Request::get("/api/users").header("x-forwarded-proto", "http").header("x-forwarded-for", "198.51.100.7")
            .body(axum::body::Body::empty()).unwrap();
        assert_eq!(crate::api::master_router(app.clone()).oneshot(r).await.unwrap().status(), StatusCode::FORBIDDEN, "plain http to the API");
    }

    /// A stolen session is not enough for the security settings: the password again (step-up); and «2FA
    /// required» stops a session from doing anything else until 2FA is on
    #[tokio::test]
    async fn security_changes_need_the_password_and_forced_2fa_blocks() {
        use tower::ServiceExt;
        let app = crate::test_app();
        app.db.set("admin_user", "admin");
        app.db.set("admin_pass", &util::hash_password("the-right-password"));
        let t = test_session(&app);
        let call = |m: Method, uri: &'static str, body: Value| {
            let (app, t) = (app.clone(), t.clone());
            async move {
                let r = Request::builder().method(m).uri(uri).header("authorization", format!("Bearer {}", t)).header("content-type", "application/json")
                    .header("x-forwarded-for", "203.0.113.50").body(axum::body::Body::from(body.to_string())).unwrap();
                crate::api::master_router(app).oneshot(r).await.unwrap().status()
            }
        };
        let pol = json!({"ip_allow": "", "ip_deny": "", "session_hours": 24, "force_2fa": false});
        assert_eq!(call(Method::POST, "/api/security/policy", pol.clone()).await, StatusCode::FORBIDDEN);
        let mut wrong = pol.clone();
        wrong["current"] = json!("wrong-password");
        assert_eq!(call(Method::POST, "/api/security/policy", wrong).await, StatusCode::FORBIDDEN);
        let mut ok = pol.clone();
        ok["current"] = json!("the-right-password");
        assert_eq!(call(Method::POST, "/api/security/policy", ok).await, StatusCode::OK);
        // «2FA required» while 2FA is off (a restore, an old database): the session must turn it on first
        app.db.set("force_2fa", "1");
        // 2FA is not on yet: an ordinary admin call is refused, setting up 2FA is not
        assert_eq!(call(Method::GET, "/api/users", Value::Null).await, StatusCode::FORBIDDEN);
        assert_eq!(call(Method::POST, "/api/security/2fa/setup", json!({"current": "the-right-password"})).await, StatusCode::OK);
        // the pending secret ends after 10 minutes
        app.db.set("totp_pending_at", &(now() - TOTP_PENDING_SECS - 1).to_string());
        assert_eq!(call(Method::POST, "/api/security/2fa/enable", json!({"code": "000000"})).await, StatusCode::BAD_REQUEST);
        assert_eq!(app.db.get("totp_pending"), "");
        // a too short password is refused
        let short = json!({"current": "the-right-password", "password": "short-pass1"});
        assert_eq!(call(Method::POST, "/api/security/password", short).await, StatusCode::BAD_REQUEST);
    }

    /// The admin page's session: an HttpOnly cookie that counts only with the page's own header, and ends after
    /// it was idle
    #[tokio::test]
    async fn the_session_cookie_needs_the_admin_header_and_ends_when_idle() {
        use tower::ServiceExt;
        let app = crate::test_app();
        app.db.set("admin_user", "admin");
        app.db.set("admin_pass", &util::hash_password("the-right-password"));
        let r = Request::post("/api/login").header("content-type", "application/json").header("x-forwarded-for", "203.0.113.60")
            .body(axum::body::Body::from(json!({"username": "admin", "password": "the-right-password"}).to_string())).unwrap();
        let res = crate::api::master_router(app.clone()).oneshot(r).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let set = res.headers().get(header::SET_COOKIE).unwrap().to_str().unwrap().to_string();
        assert!(set.contains("HttpOnly") && set.contains("Secure") && set.contains("SameSite=Strict"), "{}", set);
        let body = axum::body::to_bytes(res.into_body(), 1 << 16).await.unwrap();
        assert!(!String::from_utf8_lossy(&body).contains("token"), "the page never sees the session");
        let tok = set.split(';').next().unwrap().split_once('=').unwrap().1.to_string();
        let me = |admin: bool| {
            let (app, tok) = (app.clone(), tok.clone());
            async move {
                let mut r = Request::get("/api/me").header("cookie", format!("{}={}", SESSION_COOKIE, tok)).header("x-forwarded-for", "203.0.113.60");
                if admin {
                    r = r.header(ADMIN_HEADER, "1");
                }
                crate::api::master_router(app).oneshot(r.body(axum::body::Body::empty()).unwrap()).await.unwrap().status()
            }
        };
        assert_eq!(me(true).await, StatusCode::OK);
        assert_eq!(me(false).await, StatusCode::UNAUTHORIZED, "a cookie alone (another site's form) is nothing");
        app.db.exec("UPDATE sessions SET last_seen=?1", &[&(now() - SESSION_IDLE_MIN * 60 - 5)]).unwrap();
        assert_eq!(me(true).await, StatusCode::UNAUTHORIZED, "idle too long");
    }

    #[test]
    fn an_api_token_stops_at_its_end() {
        let app = crate::test_app();
        let ins = |t: &str, exp: i64| {
            app.db.exec("INSERT INTO api_tokens(name,hash,prefix,scopes,created,expires) VALUES('t',?1,'kk',?2,?3,?4)", &[&sha256_hex(t), &"admin", &now(), &exp]).unwrap();
        };
        ins("kk_live", now() + 60);
        ins("kk_dead", now() - 1);
        ins("kk_never", 0);
        let who = |t: &str| {
            let mut h = HeaderMap::new();
            h.insert("authorization", format!("Bearer {}", t).parse().unwrap());
            identify_with(&app, &h, false).map(|x| x.0)
        };
        assert_eq!(who("kk_live").as_deref(), Some("token:t"));
        assert!(who("kk_dead").is_none() && who("kk_never").is_none());
    }

    #[test]
    fn address_headers_count_only_from_this_machine() {
        let peer = |ip: &str| {
            let mut r = Request::builder().uri("/api/login").header("x-forwarded-for", "127.0.0.1").body(axum::body::Body::empty()).unwrap();
            r.extensions_mut().insert(axum::extract::ConnectInfo(std::net::SocketAddr::new(ip.parse().unwrap(), 5000)));
            trust_proxy_only(&mut r);
            client_ip(r.headers())
        };
        assert_eq!(peer("203.0.113.9"), "203.0.113.9");
        assert_eq!(peer("127.0.0.1"), "127.0.0.1");
        // a call from inside the program (no peer): as it is
        let mut r = Request::builder().uri("/").header("x-forwarded-for", "198.51.100.1").body(axum::body::Body::empty()).unwrap();
        trust_proxy_only(&mut r);
        assert_eq!(client_ip(r.headers()), "198.51.100.1");
    }

    #[test]
    fn a_used_code_step_is_not_taken_again() {
        assert!(step_is_new(101, 100));
        assert!(!step_is_new(100, 100) && !step_is_new(99, 100));
    }

    #[test]
    fn names_of_keys_and_tokens_are_reserved() {
        assert!(reserved_admin_name("api-key") && reserved_admin_name("token:x"));
        assert!(!reserved_admin_name("admin") && !reserved_admin_name(""));
    }

    #[test]
    fn tries_at_once_still_stop_at_five() {
        let mut m = std::collections::HashMap::new();
        for _ in 0..MAX_FAILS {
            count_fail(&mut m, "1.2.3.4");
        }
        assert!(matches!(m.get("1.2.3.4"), Some((n, _)) if *n >= MAX_FAILS));
    }

    #[test]
    fn the_dummy_hash_has_the_real_work() {
        assert!(DUMMY_HASH.starts_with(&format!("pbkdf2${}$", util::PBKDF2_ITERS)));
        assert!(!util::check_password(DUMMY_HASH, "anything"));
    }
}
