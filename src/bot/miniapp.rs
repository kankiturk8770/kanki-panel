//! The bot's mini app (Telegram Web App): a customer opens it from the bot and sees every account they
//! bought (data, days, subscription link, servers), and from there gets the AmneziaVPN backup or the configs.
//!
//! Who is asking comes only from Telegram's signed init data (`Telegram.WebApp.initData`), checked with
//! the bot token (core.telegram.org/bots/webapps, "Validating data received via the Mini App"); a customer
//! sees only the accounts with their own Telegram id. Every call is a GET, so the page and its API also
//! work on the subscription domain, which passes only GET and a few paths.

use crate::db::User;
use crate::util::{now, pct_decode};
use crate::App;
use axum::{
    extract::{Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::Arc;

type St = State<Arc<App>>;

/// How long a signed init data stays good (Telegram signs it when the mini app opens)
const INIT_MAX_AGE: i64 = 24 * 3600;

/// The address of the mini app: always on the panel's own address (its domain or subscription domain), never
/// on the Iran subscription relay. Telegram itself is filtered in Iran, so whoever opens the bot already gets
/// past the filter, and the relay's domain on the Iran server did not open in Telegram.
pub fn url(app: &App) -> String {
    format!("{}/tg/", crate::api::origin(app))
}

pub fn router() -> Router<Arc<App>> {
    Router::new()
        .route("/tg/", get(page))
        .route("/tg/api/me", get(me))
        .route("/tg/api/send", get(send))
        .route("/tg/api/file", get(file))
        .route("/tg/api/shop", get(shop))
        .route("/tg/api/buy", get(buy))
        .route("/tg/api/trial", get(trial))
        // the bot's admins: button texts, premium emoji and colours (3.34, bot/buttons.rs)
        .route("/tg/api/admin/buttons", get(admin_buttons).post(admin_buttons_save))
        .route("/tg/api/admin/ask", get(admin_ask))
        .route("/tg/api/admin/preview", get(admin_preview))
        .route("/tg/api/admin/emoji/:id", get(admin_emoji))
        // the bot's admins: path quality of every tunnel, and the path alerts switch (3.36)
        .route("/tg/api/admin/paths", get(admin_paths).post(admin_paths_set))
}

/// The customer of a request, only when they are one of the bot's admins
fn admin_of(app: &App, h: &HeaderMap, q: &HashMap<String, String>) -> Result<i64, Response> {
    let tg = who(app, h, q)?;
    let is = crate::bot::bot_admins_raw(app).split(',').filter_map(|x| x.trim().parse::<i64>().ok()).any(|a| a == tg);
    if is { Ok(tg) } else { Err(fail(StatusCode::FORBIDDEN, "admins only")) }
}

async fn admin_buttons(State(app): St, h: HeaderMap, Query(q): Query<HashMap<String, String>>) -> Response {
    if let Err(r) = admin_of(&app, &h, &q) { return r }
    ([(header::CACHE_CONTROL, "no-store")], Json(crate::buttons::list(&app))).into_response()
}

async fn admin_buttons_save(State(app): St, h: HeaderMap, Query(q): Query<HashMap<String, String>>, Json(b): Json<Value>) -> Response {
    if let Err(r) = admin_of(&app, &h, &q) { return r }
    match crate::buttons::save(&app, &b) {
        Ok(()) => Json(crate::buttons::list(&app)).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))).into_response(),
    }
}

/// The paths page: every server abroad with its tunnels and their loss, ping and jitter (read-only)
async fn admin_paths(State(app): St, h: HeaderMap, Query(q): Query<HashMap<String, String>>) -> Response {
    if let Err(r) = admin_of(&app, &h, &q) { return r }
    ([(header::CACHE_CONTROL, "no-store")], Json(crate::tunnel::quality::view(&app))).into_response()
}

/// The only thing the paths page changes: whether the bot sends path alerts (`{"alerts": bool}`).
/// Server offline / online alerts are always sent.
async fn admin_paths_set(State(app): St, h: HeaderMap, Query(q): Query<HashMap<String, String>>, Json(b): Json<Value>) -> Response {
    if let Err(r) = admin_of(&app, &h, &q) { return r }
    let Some(on) = b["alerts"].as_bool() else { return fail(StatusCode::BAD_REQUEST, "alerts: true or false") };
    app.db.set("path_alerts", if on { "1" } else { "0" });
    Json(crate::tunnel::quality::view(&app)).into_response()
}

/// «Set the emoji»: the bot asks this admin, in the chat, for the premium emoji of button `key`
async fn admin_ask(State(app): St, h: HeaderMap, Query(q): Query<HashMap<String, String>>) -> Response {
    let tg = match admin_of(&app, &h, &q) { Ok(t) => t, Err(r) => return r };
    let Some(bot) = crate::bot::running() else { return fail(StatusCode::SERVICE_UNAVAILABLE, "the bot is off") };
    match bot.ask_icon(q.get("key").map(|s| s.as_str()).unwrap_or(""), Some(tg)).await {
        Ok(_) => Json(json!({ "ok": true })).into_response(),
        Err(e) => (StatusCode::BAD_GATEWAY, Json(json!({ "error": e }))).into_response(),
    }
}

/// Every button, as customers see them, to this admin's chat
async fn admin_preview(State(app): St, h: HeaderMap, Query(q): Query<HashMap<String, String>>) -> Response {
    let tg = match admin_of(&app, &h, &q) { Ok(t) => t, Err(r) => return r };
    let Some(bot) = crate::bot::running() else { return fail(StatusCode::SERVICE_UNAVAILABLE, "the bot is off") };
    match bot.preview_buttons(Some(tg)).await {
        Ok(_) => Json(json!({ "ok": true })).into_response(),
        Err(e) => (StatusCode::BAD_GATEWAY, Json(json!({ "error": e }))).into_response(),
    }
}

/// The picture of a premium emoji (`init` in the query: an <img> sends no headers)
async fn admin_emoji(State(app): St, h: HeaderMap, axum::extract::Path(id): axum::extract::Path<String>, Query(q): Query<HashMap<String, String>>) -> Response {
    if let Err(r) = admin_of(&app, &h, &q) { return r }
    match crate::buttons::emoji_image(&app, &id).await {
        Some((b, kind)) => ([(header::CONTENT_TYPE, kind), (header::CACHE_CONTROL, "private, max-age=86400")], b).into_response(),
        None => fail(StatusCode::NOT_FOUND, "no picture"),
    }
}

/// The Telegram user id of a signed init data, or None when the signature does not match, it is older than
/// `max_age` seconds, or there is no user in it.
pub fn verify(token: &str, init: &str, at: i64, max_age: i64) -> Option<i64> {
    if token.is_empty() || init.is_empty() {
        return None;
    }
    let mut hash = String::new();
    let mut pairs: Vec<(String, String)> = vec![];
    for part in init.split('&') {
        let (k, v) = part.split_once('=')?;
        let v = pct_decode(v);
        if k == "hash" {
            hash = v;
        } else {
            pairs.push((pct_decode(k), v));
        }
    }
    pairs.sort();
    let check = pairs.iter().map(|(k, v)| format!("{}={}", k, v)).collect::<Vec<_>>().join("\n");
    let mut m = Hmac::<Sha256>::new_from_slice(b"WebAppData").ok()?;
    m.update(token.as_bytes());
    let secret = m.finalize().into_bytes();
    let mut m = Hmac::<Sha256>::new_from_slice(&secret).ok()?;
    m.update(check.as_bytes());
    m.verify_slice(&hex::decode(hash).ok()?).ok()?;
    let get = |k: &str| pairs.iter().find(|p| p.0 == k).map(|p| p.1.clone()).unwrap_or_default();
    let auth: i64 = get("auth_date").parse().ok()?;
    if at - auth > max_age || auth - at > 300 {
        return None;
    }
    serde_json::from_str::<Value>(&get("user")).ok()?["id"].as_i64()
}

fn fail(code: StatusCode, msg: &str) -> Response {
    (code, [(header::CACHE_CONTROL, "no-store")], Json(json!({ "error": msg }))).into_response()
}

/// The bot could not message the customer (it was blocked, or Telegram did not answer): nothing was delivered
fn undelivered() -> Response {
    (StatusCode::BAD_GATEWAY, [(header::CACHE_CONTROL, "no-store")], Json(json!({ "ok": false, "error": "not delivered" }))).into_response()
}

/// The customer of a request (init data in the X-Tg-Init header, or `init` in the query for downloads)
fn who(app: &App, h: &HeaderMap, q: &HashMap<String, String>) -> Result<i64, Response> {
    if !crate::limit::hit("tg", &crate::util::client_ip(h), 120, 60) {
        return Err(fail(StatusCode::TOO_MANY_REQUESTS, "too many requests, wait a minute"));
    }
    let init = h.get("x-tg-init").and_then(|v| v.to_str().ok()).map(|s| s.to_string()).or_else(|| q.get("init").cloned()).unwrap_or_default();
    verify(&crate::bot::bot_token(app), &init, now(), INIT_MAX_AGE).ok_or_else(|| fail(StatusCode::UNAUTHORIZED, "open this page from the bot"))
}

/// One of the customer's own accounts
fn account(app: &App, tg: i64, q: &HashMap<String, String>) -> Result<User, Response> {
    let id: i64 = q.get("uid").and_then(|x| x.parse().ok()).unwrap_or(0);
    app.db.user(id).filter(|u| u.tg_id == tg && tg != 0).ok_or_else(|| fail(StatusCode::NOT_FOUND, "account"))
}

async fn page() -> Response {
    let html = include_str!("../../assets/bot/miniapp.html").replace("{{V}}", crate::VERSION);
    ([(header::CONTENT_TYPE, "text/html; charset=utf-8"), (header::CACHE_CONTROL, "no-store")], html).into_response()
}

/// What the page shows of one account
fn account_json(app: &App, u: &User) -> Value {
    let mut protos: Vec<&str> = vec![];
    let mut servers = vec![];
    for n in crate::api::user_nodes(app, u) {
        let main = crate::api::node_protos(app, u, &n);
        let twin = crate::api::twin_protos(app, u, &n);
        for p in main.iter().chain(twin.iter()) {
            if !protos.contains(p) {
                protos.push(p);
            }
        }
        let cc = crate::exitgeo::cc(app, &n.id);
        let via_iran = crate::direct::through_tunnel(app, &n);
        if !main.is_empty() {
            servers.push(json!({ "name": n.name, "cc": cc, "iran": via_iran, "protocols": main }));
        }
        if !twin.is_empty() {
            servers.push(json!({ "name": n.name, "cc": cc, "iran": true, "protocols": twin }));
        }
    }
    let left = if u.expires_at > 0 { ((u.expires_at - now()) as f64 / 86400.0).ceil().max(0.0) as i64 } else { -1 };
    json!({
        "id": u.id, "name": u.username, "status": u.status(),
        "used_gb": (u.used_gb() * 100.0).round() / 100.0, "limit_gb": u.limit_gb,
        "expires_ts": u.expires_at, "days_left": left, "connections": u.max_conn,
        "link": format!("{}/sub/{}", crate::api::sub_origin(app), u.sub_code()),
        // "v2ray": only the subscription for v2ray apps (the page then leaves out the AmneziaWG / WireGuard parts)
        "service": u.service(),
        "v2link": crate::api::v2_sub_link(app, u),
        "code": u.sub_code(),
        "wg": protos.contains(&"wireguard"), "awg": protos.contains(&"amneziawg"), "hy2": protos.contains(&"hysteria2"),
        // an AmneziaVPN backup can be made (WireGuard, AmneziaWG or an Xray link the app reads)
        "amz": protos.contains(&"wireguard") || protos.contains(&"amneziawg") || crate::xray::panel::user_links(app, u).iter().any(|(_, l)| crate::amnezia::server(l, "").is_some()),
        // the subscription link, then every Hysteria2 and Xray link (to copy into v2rayNG / Hiddify at once)
        "links": crate::api::links_text(app, u),
        "servers": servers,
    })
}

/// The running bot (it holds the pending purchases), else a fresh one for what needs only the database
fn bot_of(app: &Arc<App>) -> Option<Arc<crate::bot::Bot>> {
    crate::bot::running().or_else(|| crate::bot::Bot::new(app.clone()))
}

/// The customer's last orders: (id, plan, toman, status, method, created)
fn orders(app: &App, tg: i64) -> Vec<Value> {
    app.db.with(|c| {
        let mut s = c.prepare("SELECT o.id, COALESCE(p.name,''), COALESCE(o.amount,''), COALESCE(o.status,''), COALESCE(o.method,''), COALESCE(o.created,0), COALESCE(o.kind,'') \
            FROM orders o LEFT JOIN plans p ON p.id=o.plan_id WHERE o.tg_id=?1 ORDER BY o.id DESC LIMIT 10").unwrap();
        let v: Vec<Value> = s.query_map([tg], |r| Ok(json!({
            "id": r.get::<_, i64>(0)?, "plan": r.get::<_, String>(1)?, "amount": r.get::<_, String>(2)?, "status": r.get::<_, String>(3)?,
            "method": r.get::<_, String>(4)?, "created": r.get::<_, i64>(5)?, "kind": r.get::<_, String>(6)?,
        }))).unwrap().filter_map(|x| x.ok()).collect();
        v
    })
}

/// GET /tg/api/me: every account of the customer, their last orders, and what the shop still needs
async fn me(State(app): St, h: HeaderMap, Query(q): Query<HashMap<String, String>>) -> Response {
    let tg = match who(&app, &h, &q) { Ok(t) => t, Err(r) => return r };
    let list: Vec<Value> = app.db.users_of_tg(tg).iter().map(|u| account_json(&app, u)).collect();
    let bot = bot_of(&app);
    let need_name = bot.as_ref().map(|b| b.needs_name(tg)).unwrap_or(false);
    let trial = bot.as_ref().map(|b| b.trial_open(tg)).unwrap_or(false);
    let apps = !crate::apps::list(&app).is_empty();
    let name_hint = bot.as_ref().and_then(|b| b.name_hint(tg)).unwrap_or_default();
    ([(header::CACHE_CONTROL, "no-store")], Json(json!({ "accounts": list, "orders": orders(&app, tg), "need_name": need_name, "name_hint": name_hint, "trial": trial,
        "android_app": apps, "app_link": app.db.get("app_link"), "win_link": app.db.get("win_link"), "support": app.db.get("support"),
        "admin": crate::bot::bot_admins_raw(&app).split(',').filter_map(|x| x.trim().parse::<i64>().ok()).any(|a| a == tg) }))).into_response()
}

/// The config name a first purchase or trial needs (sent as `name`), saved as the bot saves it
fn name_ok(bot: &crate::bot::Bot, tg: i64, q: &HashMap<String, String>) -> Result<(), Response> {
    if !bot.needs_name(tg) {
        return Ok(());
    }
    // left empty: the name made from the Telegram name, when there is one
    let typed = q.get("name").map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).or_else(|| bot.name_hint(tg));
    match typed.as_deref() {
        None => Err(fail(StatusCode::BAD_REQUEST, "name")),
        Some(n) => bot.set_name(tg, n).map(|_| ()).map_err(|e| (StatusCode::BAD_REQUEST, Json(json!({ "error": "bad name", "why": e }))).into_response()),
    }
}

/// GET /tg/api/trial (&name=..): the free trial, delivered in the chat
async fn trial(State(app): St, h: HeaderMap, Query(q): Query<HashMap<String, String>>) -> Response {
    let tg = match who(&app, &h, &q) { Ok(t) => t, Err(r) => return r };
    let Some(bot) = bot_of(&app) else { return fail(StatusCode::SERVICE_UNAVAILABLE, "the bot is off") };
    if !bot.trial_open(tg) {
        return fail(StatusCode::FORBIDDEN, "no trial");
    }
    if !bot.mini_gate(tg).await {
        return fail(StatusCode::FORBIDDEN, "join the channel");
    }
    if let Err(r) = name_ok(&bot, tg, &q) {
        return r;
    }
    if !bot.mini_trial(tg).await {
        return undelivered();
    }
    Json(json!({ "ok": true })).into_response()
}

/// GET /tg/api/send?uid=..&what=amz:i|amz:a|amz:w|cfg:w[:CC]|cfg:a[:CC]|cfg:h|cfg:l|cfg:v|app:a (l = every link with the subscription, app = the Kanki app files): the bot sends it to the customer's chat
async fn send(State(app): St, h: HeaderMap, Query(q): Query<HashMap<String, String>>) -> Response {
    let tg = match who(&app, &h, &q) { Ok(t) => t, Err(r) => return r };
    let u = match account(&app, tg, &q) { Ok(u) => u, Err(r) => return r };
    let Some(bot) = crate::bot::Bot::new(app.clone()) else { return fail(StatusCode::SERVICE_UNAVAILABLE, "the bot is off") };
    let what = q.get("what").map(|s| s.as_str()).unwrap_or("");
    match what.split_once(':') {
        Some(("amz", p)) if crate::amnezia::platform(p).is_some() => {
            if crate::amnezia::backup(&crate::api::amnezia_configs(&app, &u).await, "iOS").is_none() {
                return fail(StatusCode::NOT_FOUND, "no WireGuard or AmneziaWG config");
            }
            if !bot.send_amnezia(tg, "", &u, p).await {
                return undelivered();
            }
        }
        // cfg:w:TR / cfg:a:TR = the files of one country; cfg:v = the V2Ray subscription link with how to add it
        Some(("cfg", c)) if ["w", "a", "h", "l", "v"].contains(&c.split(':').next().unwrap_or("")) && c.len() <= 8 => {
            if !bot.send_configs(tg, "", &u, c).await {
                return undelivered();
            }
        }
        // the Kanki app's install files, as the bot's "download the app" message
        Some(("app", _)) => {
            if !bot.send_app_menu(tg).await {
                return undelivered();
            }
        }
        _ => return fail(StatusCode::BAD_REQUEST, "what"),
    }
    Json(json!({ "ok": true })).into_response()
}

/// GET /tg/api/file?uid=..&p=i|a|w&init=..: the AmneziaVPN backup as a download (Telegram's downloadFile)
async fn file(State(app): St, h: HeaderMap, Query(q): Query<HashMap<String, String>>) -> Response {
    let tg = match who(&app, &h, &q) { Ok(t) => t, Err(r) => return r };
    let u = match account(&app, tg, &q) { Ok(u) => u, Err(r) => return r };
    let Some(plat) = crate::amnezia::platform(q.get("p").map(|s| s.as_str()).unwrap_or("")) else { return fail(StatusCode::BAD_REQUEST, "p") };
    let Some(body) = crate::amnezia::backup(&crate::api::amnezia_configs(&app, &u).await, plat) else {
        return fail(StatusCode::NOT_FOUND, "no WireGuard or AmneziaWG config");
    };
    (
        [
            (header::CONTENT_TYPE, "application/octet-stream".to_string()),
            (header::CONTENT_DISPOSITION, format!("attachment; filename=\"{}\"", crate::amnezia::file_name(&u.username))),
            (header::CACHE_CONTROL, "no-store".to_string()),
        ],
        body,
    )
        .into_response()
}

/// GET /tg/api/shop: the plans on sale (with their button colour) and the custom purchase rules
async fn shop(State(app): St, h: HeaderMap, Query(q): Query<HashMap<String, String>>) -> Response {
    if let Err(r) = who(&app, &h, &q) {
        return r;
    }
    let plans: Vec<Value> = app.db.with(|c| {
        let mut s = c.prepare("SELECT id,name,COALESCE(days,0),COALESCE(gb,0),COALESCE(toman,0),COALESCE(conns,1),COALESCE(countries,0),COALESCE(category,''),COALESCE(style,''),COALESCE(service,'vip'),COALESCE(badge,''),COALESCE(old_toman,0) FROM plans WHERE active=1 ORDER BY days, conns, toman").unwrap();
        let v: Vec<Value> = s.query_map([], |r| Ok(json!({
            "id": r.get::<_, i64>(0)?, "name": r.get::<_, String>(1)?, "days": r.get::<_, i64>(2)?, "gb": r.get::<_, f64>(3)?,
            "toman": r.get::<_, i64>(4)?, "conns": r.get::<_, i64>(5)?, "countries": r.get::<_, i64>(6)?, "category": r.get::<_, String>(7)?,
            "style": r.get::<_, String>(8)?, "service": r.get::<_, String>(9)?, "badge": r.get::<_, String>(10)?, "old_toman": r.get::<_, i64>(11)?,
        }))).unwrap().filter_map(|x| x.ok()).collect();
        v
    });
    let on = app.db.on("sales_on");
    ([(header::CACHE_CONTROL, "no-store")], Json(json!({ "sales": on, "plans": plans, "custom": crate::shop::custom_json(&app.db) }))).into_response()
}

/// GET /tg/api/buy?pid=.. or ?gb=..&days=..&users=.. (&renew=<account>): the bot shows that plan and the
/// payment methods in the customer's chat
async fn buy(State(app): St, h: HeaderMap, Query(q): Query<HashMap<String, String>>) -> Response {
    let tg = match who(&app, &h, &q) { Ok(t) => t, Err(r) => return r };
    if !app.db.on("sales_on") {
        return fail(StatusCode::FORBIDDEN, "sales are off");
    }
    let n = |k: &str| q.get(k).and_then(|x| x.parse::<i64>().ok()).unwrap_or(0);
    let pid = if n("pid") > 0 {
        let on_sale: bool = app.db.with(|c| c.query_row("SELECT COUNT(*) FROM plans WHERE id=?1 AND active=1", [n("pid")], |r| r.get::<_, i64>(0)).unwrap_or(0) > 0);
        if !on_sale {
            return fail(StatusCode::NOT_FOUND, "plan");
        }
        n("pid")
    } else {
        match crate::shop::custom_plan(&app.db, n("gb"), n("days"), n("users").max(1)) {
            Ok(id) => id,
            Err(e) => return fail(StatusCode::BAD_REQUEST, &e),
        }
    };
    let Some(bot) = crate::bot::running() else { return fail(StatusCode::SERVICE_UNAVAILABLE, "the bot is off") };
    // the same gates as the bot's buttons: the required channel, and a config name before a new account
    if !bot.mini_gate(tg).await {
        return fail(StatusCode::FORBIDDEN, "join the channel");
    }
    let renewing = n("renew") > 0 && app.db.user(n("renew")).map(|u| u.tg_id == tg).unwrap_or(false);
    if !renewing {
        if let Err(r) = name_ok(&bot, tg, &q) {
            return r;
        }
    }
    if !bot.start_purchase(tg, pid, n("renew")).await {
        return undelivered();
    }
    Json(json!({ "ok": true })).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// init data signed the way Telegram signs it
    fn signed(token: &str, fields: &[(&str, &str)]) -> String {
        let mut f: Vec<(String, String)> = fields.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        f.sort();
        let check = f.iter().map(|(k, v)| format!("{}={}", k, v)).collect::<Vec<_>>().join("\n");
        let mut m = Hmac::<Sha256>::new_from_slice(b"WebAppData").unwrap();
        m.update(token.as_bytes());
        let secret = m.finalize().into_bytes();
        let mut m = Hmac::<Sha256>::new_from_slice(&secret).unwrap();
        m.update(check.as_bytes());
        let hash = hex::encode(m.finalize().into_bytes());
        let enc = |s: &str| s.bytes().map(|b| if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) { (b as char).to_string() } else { format!("%{:02X}", b) }).collect::<String>();
        let mut out: Vec<String> = fields.iter().map(|(k, v)| format!("{}={}", k, enc(v))).collect();
        out.push(format!("hash={}", hash));
        out.join("&")
    }

    #[test]
    fn only_init_data_signed_with_this_bot_token_names_a_customer() {
        let tok = "123456:ABC-test";
        let user = r#"{"id":777000111,"first_name":"علی","username":"ali_k"}"#;
        let init = signed(tok, &[("query_id", "AAH"), ("user", user), ("auth_date", "1000000")]);
        assert_eq!(verify(tok, &init, 1000100, INIT_MAX_AGE), Some(777000111));
        // another bot's token, a changed user, an old one, nothing
        assert_eq!(verify("999:other", &init, 1000100, INIT_MAX_AGE), None);
        assert_eq!(verify(tok, &init.replace("777000111", "777000112"), 1000100, INIT_MAX_AGE), None);
        assert_eq!(verify(tok, &init, 1000000 + INIT_MAX_AGE + 1, INIT_MAX_AGE), None);
        assert_eq!(verify(tok, "", 1000100, INIT_MAX_AGE), None);
        assert_eq!(verify("", &init, 1000100, INIT_MAX_AGE), None);
        assert_eq!(verify(tok, &init.replace("&hash=", "&hash=00"), 1000100, INIT_MAX_AGE), None);
    }

    #[test]
    fn the_mini_app_opens_on_the_panel_domain_even_with_the_iran_relay_on() {
        let dir = std::env::temp_dir().join(format!("kanki-mini-test-{}", crate::util::rand_token(8)));
        std::fs::create_dir_all(&dir).unwrap();
        let db = crate::db::Db::open(dir.join("kanki.db").to_str().unwrap());
        let env: HashMap<String, String> = [("DOMAIN".to_string(), "panel.example.com".to_string())].into();
        let app = App {
            db,
            env,
            hy2_allowed: std::sync::Mutex::new(HashMap::new()), limits: std::sync::Mutex::new(HashMap::new()), reported: std::sync::Mutex::new(HashMap::new()),
            login_fails: std::sync::Mutex::new(HashMap::new()), sync_lock: tokio::sync::Mutex::new(()), bot_alive: std::sync::atomic::AtomicI64::new(0),
            http: reqwest::Client::new(), http_insecure: reqwest::Client::new(), pin_clients: std::sync::Mutex::new(HashMap::new()),
        };
        app.db.set("sub_iran", r#"{"server":"ir1","domain":"sub.iran.example","port":2053,"ready":true}"#);
        // the subscription links still go through the Iran relay, the mini app does not
        assert_eq!(crate::api::sub_origin(&app), "https://sub.iran.example:2053");
        assert_eq!(url(&app), "https://panel.example.com/tg/");
        app.db.set("sub_domain", "sub.example.com");
        assert_eq!(url(&app), "https://sub.example.com/tg/");
    }

    #[test]
    fn every_link_comes_after_the_subscription_link() {
        let dir = std::env::temp_dir().join(format!("kanki-links-test-{}", crate::util::rand_token(8)));
        std::fs::create_dir_all(&dir).unwrap();
        let env: HashMap<String, String> = [("DOMAIN".to_string(), "panel.example.com".to_string())].into();
        let app = App {
            db: crate::db::Db::open(dir.join("kanki.db").to_str().unwrap()),
            env,
            hy2_allowed: std::sync::Mutex::new(HashMap::new()), limits: std::sync::Mutex::new(HashMap::new()), reported: std::sync::Mutex::new(HashMap::new()),
            login_fails: std::sync::Mutex::new(HashMap::new()), sync_lock: tokio::sync::Mutex::new(()), bot_alive: std::sync::atomic::AtomicI64::new(0),
            http: reqwest::Client::new(), http_insecure: reqwest::Client::new(), pin_clients: std::sync::Mutex::new(HashMap::new()),
        };
        let info = json!({"hy2_port": "8443"});
        app.db.exec("INSERT INTO nodes(id,name,address,endpoint,token,info,online) VALUES('local','GERMANY','de1.example.net','','',?1,1)", &[&info.to_string()]).unwrap();
        let u = app.db.create_user("mahtab87", 10.0, 30, 1, "hy2", "", "", 0).unwrap();
        let t = crate::api::links_text(&app, &u).expect("a Hysteria2 user has links");
        let lines: Vec<&str> = t.lines().collect();
        assert_eq!(lines[0], format!("https://panel.example.com/sub/{}/v2", u.sub_code()));
        assert!(lines.len() >= 2 && lines[1..].iter().all(|l| l.starts_with("hysteria2://")), "{}", t);
        // the same links the subscription itself holds, so the copied configs and the subscription agree
        assert_eq!(lines[1..].to_vec(), crate::api::v2_links(&app, &u).iter().map(|s| s.as_str()).collect::<Vec<_>>());
        // a standard link every V2Box / v2rayNG reads: the password, host:port, a slash, no empty "?", the name
        assert!(lines[1].starts_with(&format!("hysteria2://{}@", u.code)) && lines[1].ends_with(":8443/#GERMANY") && !lines[1].contains('?'), "{}", t);
        // a WireGuard-only account has no such link: no button, no file
        let w = app.db.create_user("sara12", 10.0, 30, 1, "wg", "", "", 0).unwrap();
        assert!(crate::api::links_text(&app, &w).is_none());
    }
}
