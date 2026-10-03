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

fn bearer(h: &HeaderMap) -> String {
    let t = h.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()).unwrap_or("");
    t.trim_start_matches("Bearer ").trim().to_string()
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
    let t = bearer(h);
    if t.is_empty() {
        return None;
    }
    let legacy = app.db.get("api_key");
    if !legacy.is_empty() && util::ct_eq(&t, &legacy) {
        return Some(("api-key".into(), vec!["admin".into()]));
    }
    let hash = sha256_hex(&t);
    let sess: Option<(String, String)> = app.db.with(|c| {
        c.query_row("SELECT id, username FROM sessions WHERE hash=?1 AND expires>?2", rusqlite::params![hash, now()], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .ok()
    });
    if let Some((id, user)) = sess {
        let _ = app.db.exec("UPDATE sessions SET last_seen=?1 WHERE id=?2", &[&now(), &id]);
        return Some((user, vec!["admin".into()]));
    }
    let tok: Option<(i64, String, String)> = app.db.with(|c| {
        c.query_row("SELECT id, name, scopes FROM api_tokens WHERE hash=?1", rusqlite::params![hash], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })
        .ok()
    });
    if let Some((id, name, scopes)) = tok {
        let _ = app.db.exec("UPDATE api_tokens SET last_used=?1 WHERE id=?2", &[&now(), &id]);
        return Some((format!("token:{}", name), scopes.split(',').map(|s| s.trim().to_string()).collect()));
    }
    None
}

pub fn has_scope(scopes: &[String], need: &str) -> bool {
    scopes.iter().any(|s| s == "admin" || s == need || (need == "users:read" && s == "users:write"))
}

/// Route guard: Ok(actor) or a 401/403 response
pub fn check(app: &App, h: &HeaderMap, scope: &str) -> Result<String, Response> {
    match identify(app, h) {
        None => Err(deny()),
        Some((actor, scopes)) => {
            if has_scope(&scopes, scope) {
                Ok(actor)
            } else {
                Err((StatusCode::FORBIDDEN, Json(json!({"error": format!("missing scope {}", scope)}))).into_response())
            }
        }
    }
}

/// Session-only guard (security-sensitive actions can't be done with API tokens)
pub fn check_session(app: &App, h: &HeaderMap) -> Result<String, Response> {
    match identify(app, h) {
        Some((actor, _)) if actor != "api-key" && !actor.starts_with("token:") => Ok(actor),
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

pub async fn middleware(State(app): St, req: Request, next: Next) -> Response {
    let path = req.uri().path().to_string();
    let method = req.method().clone();
    let ip = client_ip(req.headers());
    if is_admin_surface(&path) && !ip_allowed(&app, &ip) {
        return (StatusCode::FORBIDDEN, "forbidden").into_response();
    }
    let audited = path.starts_with("/api/") && method != Method::GET && path != "/api/login" && !path.starts_with("/api/config/");
    let actor = if audited { identify(&app, req.headers()).map(|a| a.0).unwrap_or_else(|| "anonymous".into()) } else { String::new() };
    let res = next.run(req).await;
    if audited {
        let st = res.status().as_u16() as i64;
        let _ = app.db.exec(
            "INSERT INTO audit(ts,actor,method,path,status,ip) VALUES(?1,?2,?3,?4,?5,?6)",
            &[&now(), &actor, &method.as_str(), &path, &st, &ip],
        );
    }
    res
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
}

const MAX_FAILS: u32 = 6;
const FAIL_WINDOW: i64 = 15 * 60;

fn locked(app: &App, ip: &str) -> bool {
    let m = app.login_fails.lock().unwrap();
    matches!(m.get(ip), Some((n, t)) if *n >= MAX_FAILS && now() - *t < FAIL_WINDOW)
}

fn fail(app: &App, ip: &str) {
    let mut m = app.login_fails.lock().unwrap();
    let e = m.entry(ip.to_string()).or_insert((0, now()));
    if now() - e.1 >= FAIL_WINDOW {
        *e = (0, now());
    }
    e.0 += 1;
}

async fn login(State(app): St, h: HeaderMap, Json(b): Json<Value>) -> Response {
    let ip = client_ip(&h);
    if locked(&app, &ip) {
        return (StatusCode::TOO_MANY_REQUESTS, Json(json!({"error": "too many attempts, try again in 15 minutes"}))).into_response();
    }
    let u = b["username"].as_str().unwrap_or("").trim().to_string();
    let p = b["password"].as_str().unwrap_or("");
    let stored = admin_pass_hash(&app);
    let ok = util::ct_eq(&u, &admin_user(&app)) && !stored.is_empty() && util::check_password(&stored, p);
    if !ok {
        fail(&app, &ip);
        log_login(&app, &u, &ip, "password", false);
        tokio::time::sleep(std::time::Duration::from_millis(900)).await;
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": "invalid username or password"}))).into_response();
    }
    if app.db.on("totp_on") {
        let otp = b["otp"].as_str().unwrap_or("");
        if otp.is_empty() {
            return (StatusCode::UNAUTHORIZED, Json(json!({"error": "2FA code required", "need_otp": true}))).into_response();
        }
        if !util::totp_check(&app.db.get("totp_secret"), otp) {
            fail(&app, &ip);
            log_login(&app, &u, &ip, "totp", false);
            return (StatusCode::UNAUTHORIZED, Json(json!({"error": "wrong 2FA code", "need_otp": true}))).into_response();
        }
    }
    // transparently upgrade old sha256 hashes
    if util::is_legacy_hash(&stored) {
        app.db.set("admin_pass", &util::hash_password(p));
    }
    app.login_fails.lock().unwrap().remove(&ip);
    let t = rand_token(48);
    let hours: i64 = app.db.get("session_hours").parse::<i64>().unwrap_or(24).clamp(1, 24 * 90);
    let id = rand_token(8).to_lowercase();
    let _ = app.db.exec(
        "INSERT INTO sessions(id,hash,username,ip,ua,created,last_seen,expires) VALUES(?1,?2,?3,?4,?5,?6,?6,?7)",
        &[&id, &sha256_hex(&t), &u, &ip, &user_agent(&h), &now(), &(now() + hours * 3600)],
    );
    let _ = app.db.exec("DELETE FROM sessions WHERE expires<?1", &[&now()]);
    log_login(&app, &u, &ip, if app.db.on("totp_on") { "password+2fa" } else { "password" }, true);
    Json(json!({ "token": t })).into_response()
}

async fn logout(State(app): St, h: HeaderMap) -> Response {
    let t = bearer(&h);
    let _ = app.db.exec("DELETE FROM sessions WHERE hash=?1", &[&sha256_hex(&t)]);
    Json(json!({"ok": true})).into_response()
}

pub fn ui_settings(app: &App) -> Value {
    let g = |k: &str| app.db.get(k);
    json!({
        "panel_name": g("panel_name"), "lang": g("lang"), "theme": g("theme"), "color": g("color"),
        "refresh": g("refresh").parse::<i64>().unwrap_or(10), "version": crate::VERSION,
        "logo": g("logo"),
    })
}

async fn me(State(app): St, h: HeaderMap) -> Response {
    let actor = guard!(app, h, "users:read");
    let mut v = ui_settings(&app);
    v["user"] = json!(actor);
    v["totp_on"] = json!(app.db.on("totp_on"));
    v["force_2fa"] = json!(app.db.on("force_2fa"));
    v["default_protocols"] = json!(app.db.get("default_protocols"));
    Json(v).into_response()
}

fn current_session_id(app: &App, h: &HeaderMap) -> String {
    let hash = sha256_hex(&bearer(h));
    app.db.with(|c| c.query_row("SELECT id FROM sessions WHERE hash=?1", [hash], |r| r.get::<_, String>(0)).unwrap_or_default())
}

async fn security_get(State(app): St, h: HeaderMap) -> Response {
    let _ = guard!(app, h, "admin");
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
    let masked = if key.len() > 8 { format!("{}…{}", &key[..4], &key[key.len() - 4..]) } else { String::new() };
    Json(json!({
        "admin_user": admin_user(&app), "totp_on": app.db.on("totp_on"), "force_2fa": app.db.on("force_2fa"),
        "ip_allow": app.db.get("ip_allow"), "ip_deny": app.db.get("ip_deny"), "session_hours": app.db.get("session_hours"),
        "my_ip": client_ip(&h), "current_session": cur,
        "sessions": sessions, "tokens": tokens, "logins": logins, "audit": audit,
        "legacy_key": masked, "scopes": SCOPES,
    }))
    .into_response()
}

async fn change_password(State(app): St, h: HeaderMap, Json(b): Json<Value>) -> Response {
    if let Err(r) = check_session(&app, &h) { return r; }
    let cur = b["current"].as_str().unwrap_or("");
    if !util::check_password(&admin_pass_hash(&app), cur) {
        return bad("current password is wrong");
    }
    let user = b["username"].as_str().unwrap_or("").trim();
    let pass = b["password"].as_str().unwrap_or("");
    if pass.len() < 8 {
        return bad("password must be at least 8 characters");
    }
    if !user.is_empty() {
        app.db.set("admin_user", user);
    }
    app.db.set("admin_pass", &util::hash_password(pass));
    let cur_id = current_session_id(&app, &h);
    let _ = app.db.exec("DELETE FROM sessions WHERE id<>?1", &[&cur_id]);
    Json(json!({"ok": true})).into_response()
}

async fn policy(State(app): St, h: HeaderMap, Json(b): Json<Value>) -> Response {
    if let Err(r) = check_session(&app, &h) { return r; }
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
    let k = rand_token(40);
    app.db.set("api_key", &k);
    Json(json!({"api_key": k})).into_response()
}

async fn totp_setup(State(app): St, h: HeaderMap) -> Response {
    if let Err(r) = check_session(&app, &h) { return r; }
    let secret = util::totp_secret();
    app.db.set("totp_pending", &secret);
    let label = format!("{}:{}", app.db.get("panel_name"), admin_user(&app));
    let uri = format!("otpauth://totp/{}?secret={}&issuer={}&digits=6&period=30", util::pct(&label), secret, util::pct(&app.db.get("panel_name")));
    Json(json!({"secret": secret, "uri": uri, "qr": util::qr_svg(&uri).unwrap_or_default()})).into_response()
}

async fn totp_enable(State(app): St, h: HeaderMap, Json(b): Json<Value>) -> Response {
    if let Err(r) = check_session(&app, &h) { return r; }
    let pending = app.db.get("totp_pending");
    if pending.is_empty() {
        return bad("start setup first");
    }
    if !util::totp_check(&pending, b["code"].as_str().unwrap_or("")) {
        return bad("wrong code, check your phone clock");
    }
    app.db.set("totp_secret", &pending);
    app.db.set("totp_pending", "");
    app.db.set("totp_on", "1");
    Json(json!({"ok": true})).into_response()
}

async fn totp_disable(State(app): St, h: HeaderMap, Json(b): Json<Value>) -> Response {
    if let Err(r) = check_session(&app, &h) { return r; }
    if app.db.on("force_2fa") {
        return bad("2FA is enforced by policy; turn enforcement off first");
    }
    if app.db.on("totp_on") && !util::totp_check(&app.db.get("totp_secret"), b["code"].as_str().unwrap_or("")) {
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
    let t = format!("kk_{}", rand_token(44));
    let prefix: String = t.chars().take(8).collect();
    let r = app.db.exec(
        "INSERT INTO api_tokens(name,hash,prefix,scopes,created) VALUES(?1,?2,?3,?4,?5)",
        &[&name, &sha256_hex(&t), &prefix, &scopes.join(","), &now()],
    );
    match r {
        Ok(_) => Json(json!({"token": t})).into_response(),
        Err(e) => bad(&e),
    }
}

async fn token_delete(State(app): St, h: HeaderMap, Path(id): Path<i64>) -> Response {
    if let Err(r) = check_session(&app, &h) { return r; }
    let _ = app.db.exec("DELETE FROM api_tokens WHERE id=?1", &[&id]);
    Json(json!({"ok": true})).into_response()
}
