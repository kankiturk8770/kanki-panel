//! The bot's mini app (Telegram Web App): a customer opens it from the bot and sees every account they
//! bought (data, days, subscription link, servers), and from there gets the AmneziaVPN backup or the configs.
//!
//! Who is asking comes only from Telegram's signed init data (`Telegram.WebApp.initData`), checked with
//! the bot token (core.telegram.org/bots/webapps, "Validating data received via the Mini App"); a customer
//! sees only the accounts with their own Telegram id. Every call is a GET, so the page and its API also
//! work through the Iran subscription relay and the subscription domain, which pass only GET and a few paths.

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

/// The address of the mini app: on the subscription address, which is the one that opens in Iran
pub fn url(app: &App) -> String {
    format!("{}/tg/", crate::api::sub_origin(app))
}

pub fn router() -> Router<Arc<App>> {
    Router::new()
        .route("/tg/", get(page))
        .route("/tg/api/me", get(me))
        .route("/tg/api/send", get(send))
        .route("/tg/api/file", get(file))
        .route("/tg/api/shop", get(shop))
        .route("/tg/api/buy", get(buy))
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
    let html = include_str!("../../assets/web/tgapp.html").replace("{{V}}", crate::VERSION);
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
        "code": u.sub_code(),
        "wg": protos.contains(&"wireguard"), "awg": protos.contains(&"amneziawg"), "hy2": protos.contains(&"hysteria2"),
        "servers": servers,
    })
}

/// GET /tg/api/me: every account of the customer
async fn me(State(app): St, h: HeaderMap, Query(q): Query<HashMap<String, String>>) -> Response {
    let tg = match who(&app, &h, &q) { Ok(t) => t, Err(r) => return r };
    let list: Vec<Value> = app.db.users_of_tg(tg).iter().map(|u| account_json(&app, u)).collect();
    ([(header::CACHE_CONTROL, "no-store")], Json(json!({ "accounts": list }))).into_response()
}

/// GET /tg/api/send?uid=..&what=amz:i|amz:a|amz:w|cfg:w|cfg:a|cfg:h: the bot sends it to the customer's chat
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
            bot.send_amnezia(tg, "", &u, p).await;
        }
        Some(("cfg", c)) if ["w", "a", "h"].contains(&c) => bot.send_configs(tg, "", &u, c).await,
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
        let mut s = c.prepare("SELECT id,name,COALESCE(days,0),COALESCE(gb,0),COALESCE(toman,0),COALESCE(conns,1),COALESCE(countries,0),COALESCE(category,''),COALESCE(style,'') FROM plans WHERE active=1 ORDER BY days, conns, toman").unwrap();
        let v: Vec<Value> = s.query_map([], |r| Ok(json!({
            "id": r.get::<_, i64>(0)?, "name": r.get::<_, String>(1)?, "days": r.get::<_, i64>(2)?, "gb": r.get::<_, f64>(3)?,
            "toman": r.get::<_, i64>(4)?, "conns": r.get::<_, i64>(5)?, "countries": r.get::<_, i64>(6)?, "category": r.get::<_, String>(7)?,
            "style": r.get::<_, String>(8)?,
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
    bot.start_purchase(tg, pid, n("renew")).await;
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
}
