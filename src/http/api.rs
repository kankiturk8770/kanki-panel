//! Web: management API, subscription page, client configs, node agent, Hysteria2 auth
use crate::db::{Node, User};
use crate::guard;
use crate::sync::{self, SyncReq};
use crate::util::{self, esc, iso, now, pct, rand_token, valid_cfg_name};
use crate::App;
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;

type St = State<Arc<App>>;

pub fn err(code: StatusCode, msg: &str) -> Response {
    (code, Json(json!({ "error": msg }))).into_response()
}

pub(crate) fn spawn_sync(app: &Arc<App>) {
    let a = app.clone();
    tokio::spawn(async move { sync::sync_all(&a).await });
}

/// Public panel origin used in subscription links
pub fn origin(app: &App) -> String {
    // a separate subscription domain set up by the panel itself (Caddy + its own SSL) wins
    let sd = app.db.get("sub_domain");
    if !sd.trim().is_empty() {
        return format!("https://{}", sd.trim());
    }
    let base = app.db.get("sub_base");
    if !base.trim().is_empty() {
        return base.trim().trim_end_matches('/').to_string();
    }
    let domain = app.env.get("DOMAIN").cloned().unwrap_or_default();
    match app.env.get("HTTPS_PORT").map(|s| s.trim()).filter(|p| !p.is_empty() && *p != "443") {
        Some(p) => format!("https://{}:{}", domain, p),
        None => format!("https://{}", domain),
    }
}

/// Base of the subscription links: the Iran server when it serves them, otherwise `origin`
pub fn sub_origin(app: &App) -> String {
    crate::subiran::origin(app).unwrap_or_else(|| origin(app))
}

/// Public host users connect to on the main server (settings > env ENDPOINT > env DOMAIN)
pub fn panel_endpoint(app: &App) -> String {
    let s = app.db.get("endpoint");
    if !s.trim().is_empty() {
        return s.trim().to_string();
    }
    app.env.get("ENDPOINT").cloned().filter(|s| !s.is_empty()).or_else(|| app.env.get("DOMAIN").cloned()).unwrap_or_default()
}

pub fn endpoint(app: &App, n: &Node) -> String {
    if n.endpoint_mode == "panel" || n.endpoint.trim().is_empty() {
        panel_endpoint(app)
    } else {
        n.endpoint.trim().to_string()
    }
}

const NAME_ERR: &str = "name: English letters and digits only, 3-12 characters, starting with a letter (like mahtab87)";

/// File name of a WireGuard / AmneziaWG config. Both apps use the file name as the tunnel name and refuse
/// a name longer than 15 characters or with characters other than letters, digits and _ = + . -
/// (the import fails with "Invalid name"), so it is <user, up to 9>-<server, 3>-<a | w>, like mahtab87-ger-a.
pub fn conf_file_name(app: &App, u: &User, n: &Node, proto: &str) -> String {
    let nodes = user_nodes(app, u);
    let names: Vec<(&str, &str)> = nodes.iter().map(|x| (x.id.as_str(), x.name.as_str())).collect();
    conf_name(&u.username, u.id, &n.id, &n.name, &names, proto)
}

/// The file name of a config, the copy through the tunnel ending in "t" (mahtab87-ger-at): the user part
/// is one letter shorter so the name still fits WireGuard's 15
pub fn conf_file_name_via(app: &App, u: &User, n: &Node, proto: &str, tunnel: bool) -> String {
    let f = conf_file_name(app, u, n, proto);
    if tunnel { tunnel_file(&f) } else { f }
}

fn tunnel_file(f: &str) -> String {
    let stem = f.trim_end_matches(".conf");
    let mut parts = stem.rsplitn(3, '-');
    let (letter, srv, who) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""), parts.next().unwrap_or(""));
    let who: String = if stem.len() >= 15 { who.chars().take(who.chars().count().saturating_sub(1)).collect() } else { who.to_string() };
    format!("{}-{}-{}t.conf", who, srv, letter)
}

/// `nodes`: (id, name) of every server of this user, to tell apart servers whose names start the same way
fn conf_name(user: &str, uid: i64, node_id: &str, node_name: &str, nodes: &[(&str, &str)], proto: &str) -> String {
    let code = |name: &str| -> String {
        let c: String = name.chars().filter(|c| c.is_ascii_alphanumeric()).take(3).collect::<String>().to_lowercase();
        if c.is_empty() { "srv".into() } else { c }
    };
    // two servers of this user with the same first letters get a number instead of their third letter
    let mine = code(node_name);
    let mut srv = mine.clone();
    let same: Vec<&(&str, &str)> = nodes.iter().filter(|x| code(x.1) == mine).collect();
    if same.len() > 1 {
        let idx = same.iter().position(|x| x.0 == node_id).unwrap_or(0) + 1;
        srv = format!("{}{}", mine.chars().take(2).collect::<String>(), idx % 10);
    }
    let who: String = user.chars().filter(|c| c.is_ascii_alphanumeric() || "_=+.-".contains(*c)).take(9).collect();
    let who = if who.is_empty() { format!("u{}", uid) } else { who };
    format!("{}-{}-{}.conf", who, srv, if proto == "amneziawg" { "a" } else { "w" })
}

#[cfg(test)]
mod conf_name_tests {
    use super::conf_name;

    /// WireGuard / AmneziaWG: [a-zA-Z0-9_=+.-]{1,15} after ".conf" is cut off
    fn ok(f: &str) -> bool {
        let n = f.strip_suffix(".conf").unwrap();
        (1..=15).contains(&n.len()) && n.chars().all(|c| c.is_ascii_alphanumeric() || "_=+.-".contains(c))
    }

    #[test]
    fn tunnel_copies_end_in_t_and_still_fit() {
        let f = |stem: &str| super::tunnel_file(&format!("{}.conf", stem));
        assert_eq!(f("mahtab87-ger-a"), "mahtab87-ger-at.conf");
        assert_eq!(f("abcdefghi-ger-w"), "abcdefgh-ger-wt.conf");
        assert_eq!(f("u9-ab-a"), "u9-ab-at.conf");
        for x in ["mahtab87-ger-at.conf", "abcdefgh-ger-wt.conf"] {
            assert!(ok(x), "{}", x);
        }
    }

    #[test]
    fn names_fit_wireguard() {
        let nodes = [("local", "GERMANY-GAMING"), ("node-a", "Finland 1"), ("node-b", "Finland 2"), ("node-c", "🇹🇷 ترکیه")];
        assert_eq!(conf_name("mahtab87", 2, "local", "GERMANY-GAMING", &nodes, "amneziawg"), "mahtab87-ger-a.conf");
        assert_eq!(conf_name("mahtab87", 2, "node-a", "Finland 1", &nodes, "wireguard"), "mahtab87-fi1-w.conf");
        assert_eq!(conf_name("mahtab87", 2, "node-b", "Finland 2", &nodes, "wireguard"), "mahtab87-fi2-w.conf");
        assert_eq!(conf_name("mahtab87", 2, "node-c", "🇹🇷 ترکیه", &nodes, "wireguard"), "mahtab87-srv-w.conf");
        assert_eq!(conf_name("USER17-TEST", 17, "local", "GERMANY-GAMING", &nodes, "wireguard"), "USER17-TE-ger-w.conf");
        assert_eq!(conf_name("علی", 9, "local", "Main", &[("local", "Main")], "amneziawg"), "u9-mai-a.conf");
        for (id, nm) in nodes {
            for u in ["abcdefghijkl", "USER123456-TEST", "a.b_c", "x"] {
                for p in ["wireguard", "amneziawg"] {
                    let f = conf_name(u, 123456, id, nm, &nodes, p);
                    assert!(ok(&f), "{}", f);
                }
            }
        }
    }
}

pub fn valid_username(s: &str) -> bool {
    !s.is_empty() && s.len() <= 40 && s.chars().all(|c| c.is_ascii_alphanumeric() || "_-.".contains(c))
}

/// The panel page with the version on every script it loads (`/assets/kanki-hub.js?v=3.12.0`): a cache in
/// front of the panel (Cloudflare caches .js by itself) then never hands out an old copy of one of them next
/// to new ones, which drew the old look after an update.
fn admin_page() -> &'static str {
    static PAGE: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    PAGE.get_or_init(|| versioned(include_str!("../../assets/web/index.html"), crate::VERSION))
}

fn versioned(html: &str, v: &str) -> String {
    let mut out = String::with_capacity(html.len() + 512);
    let mut rest = html;
    while let Some(i) = rest.find("src=\"/assets/") {
        let (head, tail) = rest.split_at(i);
        out.push_str(head);
        let end = tail[5..].find('"').map(|e| e + 5).unwrap_or(tail.len());
        out.push_str(&tail[..end]);
        if !tail[..end].contains('?') {
            out.push_str("?v=");
            out.push_str(v);
        }
        rest = &tail[end..];
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod versioned_tests {
    #[test]
    fn every_script_gets_the_version() {
        let h = super::versioned("<script src=\"/assets/kanki-hub.js\"></script><script src=\"/assets/a.js?x=1\"></script><img src=\"/other.png\">", "3.12.0");
        assert_eq!(h, "<script src=\"/assets/kanki-hub.js?v=3.12.0\"></script><script src=\"/assets/a.js?x=1\"></script><img src=\"/other.png\">");
        let page = super::admin_page();
        assert!(page.contains("/assets/kanki-deck.js?v="));
        assert!(!page.contains("/assets/kanki-hub.js\""));
    }
}

pub fn user_json(app: &App, u: &User) -> Value {
    json!({
        "id": u.id, "username": u.username, "subscription_id": u.code, "code": u.sub_code(),
        "link": format!("{}/sub/{}", sub_origin(app), u.sub_code()),
        "traffic_limit_gb": u.limit_gb, "traffic_used_gb": (u.used_gb() * 100.0).round() / 100.0, "used_bytes": u.used_bytes,
        "expires_at": iso(u.expires_at), "expires_ts": u.expires_at,
        "max_connections": u.max_conn, "online_connections": u.online, "enabled": u.enabled,
        "status": u.status(), "protocols": u.protocols, "nodes": u.nodes, "notes": u.notes,
        "tg_id": u.tg_id, "created_at": iso(u.created_at), "last_seen_at": iso(u.last_seen), "last_seen_ts": u.last_seen,
        // connected right now: [{ "p": protocol, "s": server }]
        "live": crate::live::of(app, u.id),
    })
}

// ============================================================ routes

pub fn master_router(app: Arc<App>) -> Router {
    Router::new()
        .route("/", get(|| async { Redirect::to("/admin") }))
        .route("/admin", get(|| async {
            ([(header::CACHE_CONTROL, "no-store"), (header::X_FRAME_OPTIONS, "DENY")], Html(admin_page()))
        }))
        // Vazirmatn (SIL Open Font License), shared by the panel and the subscription page
        .route("/assets/vazirmatn.woff", get(|| async {
            ([(header::CONTENT_TYPE, "font/woff"), (header::CACHE_CONTROL, "public, max-age=2592000, immutable")],
             &include_bytes!("../../assets/web/vazirmatn.woff")[..])
        }))
        // the panel's extension script (DNS, Xray and node types): no secrets in it
        .route("/assets/kanki-ext.js", get(|| async {
            ([(header::CONTENT_TYPE, "application/javascript; charset=utf-8"), (header::CACHE_CONTROL, "no-store")], include_str!("../../assets/web/ext.js"))
        }))
        .route("/assets/kanki-xray.js", get(|| async {
            ([(header::CONTENT_TYPE, "application/javascript; charset=utf-8"), (header::CACHE_CONTROL, "no-store")], include_str!("../../assets/web/xray.js"))
        }))
        .route("/assets/kanki-dns.js", get(|| async {
            ([(header::CONTENT_TYPE, "application/javascript; charset=utf-8"), (header::CACHE_CONTROL, "no-store")], include_str!("../../assets/web/dns.js"))
        }))
        // 3.7: the new shell (menu in sections, glass look, server grid, Grok channel writer)
        .route("/assets/kanki-v37.js", get(|| async {
            ([(header::CONTENT_TYPE, "application/javascript; charset=utf-8"), (header::CACHE_CONTROL, "no-store")], include_str!("../../assets/web/v37.js"))
        }))
        // 3.8: the AMOLED look (gold / purple, night / day), 3D glass buttons, grouped menu
        .route("/assets/kanki-look.js", get(|| async {
            ([(header::CONTENT_TYPE, "application/javascript; charset=utf-8"), (header::CACHE_CONTROL, "no-store")], include_str!("../../assets/web/look.js"))
        }))
        // 3.9: one Servers page (every server is a node; its services switched on in place)
        .route("/assets/kanki-servers.js", get(|| async {
            ([(header::CONTENT_TYPE, "application/javascript; charset=utf-8"), (header::CACHE_CONTROL, "no-store")], include_str!("../../assets/web/servers.js"))
        }))
        // 3.9.3: multi-location tunnels (one tunnel per hop, made and tested together)
        .route("/assets/kanki-route.js", get(|| async {
            ([(header::CONTENT_TYPE, "application/javascript; charset=utf-8"), (header::CACHE_CONTROL, "no-store")], include_str!("../../assets/web/route.js"))
        }))
        // 3.9.3: VPN services in tabs (KANKI MIX, Xray, WireGuard, AmneziaWG, Hysteria2), a row per server
        .route("/assets/kanki-svc.js", get(|| async {
            ([(header::CONTENT_TYPE, "application/javascript; charset=utf-8"), (header::CACHE_CONTROL, "no-store")], include_str!("../../assets/web/svc.js"))
        }))
        .route("/assets/kanki-kcore.js", get(|| async {
            ([(header::CONTENT_TYPE, "application/javascript; charset=utf-8"), (header::CACHE_CONTROL, "no-store")], include_str!("../../assets/web/kcore.js"))
        }))
        .route("/assets/kanki-kmix.js", get(|| async {
            ([(header::CONTENT_TYPE, "application/javascript; charset=utf-8"), (header::CACHE_CONTROL, "no-store")], include_str!("../../assets/web/kmix.js"))
        }))
        .route("/assets/kanki-antidpi.js", get(|| async {
            ([(header::CONTENT_TYPE, "application/javascript; charset=utf-8"), (header::CACHE_CONTROL, "no-store")], include_str!("../../assets/web/antidpi.js"))
        }))
        // 3.10: the polished look (sign-in screen, dashboard numbers, user tiles with data used)
        .route("/assets/kanki-skin.js", get(|| async {
            ([(header::CONTENT_TYPE, "application/javascript; charset=utf-8"), (header::CACHE_CONTROL, "no-store")], include_str!("../../assets/web/skin.js"))
        }))
        // 3.10: where things live (menu sections, Xray in two parts, server drawers, dashboard, tunnel map)
        .route("/assets/kanki-hub.js", get(|| async {
            ([(header::CONTENT_TYPE, "application/javascript; charset=utf-8"), (header::CACHE_CONTROL, "no-store")], include_str!("../../assets/web/hub.js"))
        }))
        // 3.11: the new design (menu that folds and opens smoothly, top menu, cores rail, country chips, user cards)
        .route("/assets/kanki-deck.js", get(|| async {
            ([(header::CONTENT_TYPE, "application/javascript; charset=utf-8"), (header::CACHE_CONTROL, "no-store")], include_str!("../../assets/web/deck.js"))
        }))
        .route("/api/overview", get(overview))
        .route("/api/users", get(users_list).post(users_create))
        .route("/api/users/:id", axum::routing::put(users_update).delete(users_delete))
        .route("/api/users/:id/:action", post(users_action))
        .route("/api/nodes", get(nodes_list).post(nodes_add))
        .route("/api/nodes/:id", axum::routing::put(nodes_edit).delete(nodes_delete))
        .route("/api/nodes/:id/:action", post(nodes_action))
        .route("/api/protocols/:proto/:action", post(proto_all))
        .route("/api/node-ports/:id", post(node_ports))
        .route("/api/node-join", post(node_join_token))
        .route("/join/register", post(node_join_register))
        .route("/api/settings", get(settings_get).put(settings_put))
        .route("/api/settings/apply-endpoint", post(apply_endpoint_all))
        .route("/api/app-msg", get(app_msg_get).put(app_msg_put).delete(app_msg_delete))
        .route("/api/plans", get(plans_list).post(plans_add))
        .route("/api/plans/bulk", post(plans_bulk))
        .route("/api/plans/category", axum::routing::put(plans_cat_rename))
        .route("/api/plans/:id", axum::routing::delete(plans_delete).put(plans_update))
        .route("/api/sync", post(force_sync))
        .route("/sub/:code", get(sub_page))
        .route("/sub/:code/raw", get(sub_raw))
        .route("/sub/:code/json", get(sub_json))
        .route("/sub/:code/xray", get(sub_xray))
        .route("/sub/:code/v2", get(sub_v2))
        .route("/sub/:code/xqr/:i", get(sub_xray_qr))
        .route("/api/config/:id/:proto", get(config_file))
        .route("/api/config/:id/:proto/:extra", get(config_file_extra))
        .route("/hy2/auth", post(hy2_auth))
        .merge(crate::auth::router())
        .merge(crate::admin::router())
        .merge(crate::backup::router())
        .merge(crate::apps::router())
        .merge(crate::subdomain::router())
        .merge(crate::subiran::router())
        .merge(crate::migrate::router())
        .merge(crate::servers::router())
        .merge(crate::channel::router())
        .merge(crate::tunnel::panel::router())
        .merge(crate::dns::panel::router())
        .merge(crate::xray::panel::router())
        .merge(crate::kmix::router())
        .merge(crate::kcores::router())
        .layer(axum::middleware::from_fn_with_state(app.clone(), crate::auth::middleware))
        // 2 MiB for every route: login, join and hy2/auth are open to strangers and must not make the
        // server buffer more. Only the backup upload gets a bigger limit (see backup::router).
        .layer(axum::extract::DefaultBodyLimit::max(2 * 1024 * 1024))
        .with_state(app)
}

pub fn node_router(app: Arc<App>) -> Router {
    Router::new()
        .route("/agent/info", get(agent_info))
        .route("/agent/sync", post(agent_sync))
        .route("/agent/repair", post(agent_repair))
        .route("/agent/update", post(agent_update))
        .route("/agent/ports", post(agent_ports))
        .route("/agent/remove", post(agent_remove))
        .route("/agent/setup-tunnel", post(agent_setup_tunnel))
        .route("/hy2/auth", post(hy2_auth))
        .with_state(app)
}

// ============================================================ overview

async fn overview(State(app): St, h: HeaderMap) -> Response {
    let _ = guard!(app, h, "users:read");
    let us = app.db.users();
    let nodes = app.db.nodes();
    let sales = app.db.with(|c| {
        c.query_row("SELECT COUNT(*), COALESCE(SUM(CASE WHEN method IN ('card','zp') THEN CAST(amount AS INTEGER) END),0) FROM orders WHERE status='done'", [], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?))
        }).unwrap_or((0, 0))
    });
    let mut protos: HashMap<&str, usize> = HashMap::new();
    for p in ["wg", "awg", "hy2", "kmix", "xray", "dns"] {
        protos.insert(p, us.iter().filter(|u| u.has_proto(p)).count());
    }
    // online: a VPN session, or Xray / Kanki DNS use right now
    let online = us.iter().filter(|u| u.online > 0 || crate::live::of(&app, u.id).as_array().is_some_and(|a| !a.is_empty())).count();
    Json(json!({
        "users": us.len(), "active": us.iter().filter(|u| u.active()).count(),
        "online": online, "offline": us.len() - online,
        "traffic_gb": (us.iter().map(|u| u.used_gb()).sum::<f64>() * 10.0).round() / 10.0,
        "expired": us.iter().filter(|u| u.enabled && (u.expired() || u.over_quota())).count(),
        "disabled": us.iter().filter(|u| !u.enabled).count(),
        "nodes": nodes.len(), "nodes_online": nodes.iter().filter(|n| n.online).count(),
        "sales": sales.0, "revenue": sales.1, "protocols": protos,
    })).into_response()
}

// ============================================================ users

async fn users_list(State(app): St, h: HeaderMap) -> Response {
    let _ = guard!(app, h, "users:read");
    let v: Vec<Value> = app.db.users().iter().map(|u| user_json(&app, u)).collect();
    Json(json!(v)).into_response()
}

fn list_or(v: &Value, def: &str) -> String {
    match v {
        Value::Array(a) => a.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(","),
        Value::String(s) => s.clone(),
        _ => def.to_string(),
    }
}

fn num(v: &Value) -> Option<f64> {
    v.as_f64().or_else(|| v.as_str().and_then(|s| s.trim().parse().ok()))
}

async fn users_create(State(app): St, h: HeaderMap, Json(b): Json<Value>) -> Response {
    let _ = guard!(app, h, "users:write");
    let count = num(&b["count"]).unwrap_or(1.0).clamp(1.0, 200.0) as i64;
    let base = b["username"].as_str().unwrap_or("").trim().to_string();
    if !base.is_empty() && !valid_cfg_name(&base) {
        return err(StatusCode::BAD_REQUEST, NAME_ERR);
    }
    let gb = num(&b["traffic_limit_gb"]).or_else(|| num(&b["traffic_limit"])).unwrap_or(0.0).max(0.0);
    let days = num(&b["days"]).unwrap_or(30.0) as i64;
    let conns = num(&b["max_connections"]).unwrap_or(1.0).max(0.0) as i64;
    let protos = list_or(&b["protocols"], &app.db.get("default_protocols"));
    let nodes = list_or(&b["nodes"], "");
    let notes = b["notes"].as_str().unwrap_or("");
    let tg = b["tg_id"].as_i64().unwrap_or(0);
    let mut out = vec![];
    for i in 0..count {
        let name = if base.is_empty() {
            "auto".to_string() // USER<n>, lowest free number
        } else if count > 1 {
            // base1, base2 … (still letters and digits only, at most 12 characters)
            let suf = (i + 1).to_string();
            format!("{}{}", base.chars().take(12 - suf.len()).collect::<String>(), suf)
        } else {
            base.clone()
        };
        match app.db.create_user(&name, gb, days, conns, &protos, &nodes, notes, tg) {
            Ok(u) => {
                if let Some(ts) = b["expires_ts"].as_i64() {
                    let _ = app.db.exec("UPDATE users SET expires_at=?1 WHERE id=?2", &[&ts, &u.id]);
                }
                out.push(user_json(&app, &app.db.user(u.id).unwrap_or(u)))
            }
            Err(e) => return err(StatusCode::BAD_REQUEST, &e),
        }
    }
    spawn_sync(&app);
    Json(json!(out)).into_response()
}

async fn users_update(State(app): St, h: HeaderMap, Path(id): Path<i64>, Json(b): Json<Value>) -> Response {
    let _ = guard!(app, h, "users:write");
    let Some(u) = app.db.user(id) else { return err(StatusCode::NOT_FOUND, "not found") };
    let gb = num(&b["traffic_limit_gb"]).unwrap_or(u.limit_gb).max(0.0);
    let exp = match b["expires_ts"].as_i64() {
        Some(t) => t.max(0),
        None => match num(&b["days"]) {
            Some(d) if d > 0.0 => now() + (d as i64) * 86400,
            Some(_) => 0,
            None => u.expires_at,
        },
    };
    let conns = num(&b["max_connections"]).map(|x| x as i64).unwrap_or(u.max_conn).max(0);
    let protos = if b["protocols"].is_null() { u.protocols.clone() } else { list_or(&b["protocols"], "") };
    let nodes = if b["nodes"].is_null() { u.nodes.clone() } else { list_or(&b["nodes"], "") };
    let notes = b["notes"].as_str().unwrap_or(&u.notes).to_string();
    let enabled = b["enabled"].as_bool().unwrap_or(u.enabled) as i64;
    let mut username = u.username.clone();
    if let Some(n) = b["username"].as_str().map(|s| s.trim()).filter(|s| !s.is_empty() && *s != u.username) {
        if !valid_cfg_name(n) {
            return err(StatusCode::BAD_REQUEST, NAME_ERR);
        }
        if app.db.name_taken(n, id) {
            return err(StatusCode::BAD_REQUEST, "this name is already used by another user");
        }
        username = n.to_string();
    }
    // a trial that gets more time or data from the admin is not a trial any more (it must not be deleted when it ends)
    let changed_credit = exp != u.expires_at || (gb - u.limit_gb).abs() > f64::EPSILON;
    let r = app.db.exec(
        "UPDATE users SET username=?1, limit_gb=?2, expires_at=?3, max_conn=?4, protocols=?5, nodes=?6, notes=?7, enabled=?8, warned=0 WHERE id=?9",
        &[&username, &gb, &exp, &conns, &protos, &nodes, &notes, &enabled, &id],
    );
    if let Err(e) = r {
        return err(StatusCode::BAD_REQUEST, &e);
    }
    // quick add (days / GB) on top of the saved values
    let add_days = num(&b["add_days"]).unwrap_or(0.0) as i64;
    let add_gb = num(&b["add_gb"]).unwrap_or(0.0);
    if add_days > 0 || add_gb > 0.0 {
        let _ = app.db.extend(id, add_days, add_gb);
    }
    if add_days > 0 || add_gb > 0.0 || changed_credit {
        app.db.promote_trial(id);
    }
    spawn_sync(&app);
    Json(user_json(&app, &app.db.user(id).unwrap_or(u))).into_response()
}

async fn users_delete(State(app): St, h: HeaderMap, Path(id): Path<i64>) -> Response {
    let _ = guard!(app, h, "users:write");
    app.db.delete_user(id);
    spawn_sync(&app);
    Json(json!({ "ok": true })).into_response()
}

pub fn user_action(app: &App, id: i64, action: &str, b: &Value) -> Result<(), String> {
    match action {
        "extend" => app.db.extend(id, num(&b["days"]).unwrap_or(0.0) as i64, num(&b["gb"]).unwrap_or(0.0)).map(|_| app.db.promote_trial(id)),
        "reset" | "reset-traffic" => app.db.exec("UPDATE users SET used_bytes=0, warned=0 WHERE id=?1", &[&id]).map(|_| ()),
        "toggle" | "freeze" => app.db.exec("UPDATE users SET enabled=1-enabled WHERE id=?1", &[&id]).map(|_| ()),
        "enable" => app.db.exec("UPDATE users SET enabled=1 WHERE id=?1", &[&id]).map(|_| ()),
        "disable" => app.db.exec("UPDATE users SET enabled=0 WHERE id=?1", &[&id]).map(|_| ()),
        "regen" => {
            let _ = app.db.exec("DELETE FROM peers WHERE user_id=?1", &[&id]);
            app.db.exec("UPDATE users SET code=?1 WHERE id=?2", &[&util::rand_digits(19), &id]).map(|_| ())
        }
        "delete" => {
            app.db.delete_user(id);
            Ok(())
        }
        _ => Err("unknown action".into()),
    }
}

async fn users_action(State(app): St, h: HeaderMap, Path((id, action)): Path<(i64, String)>, body: Option<Json<Value>>) -> Response {
    let _ = guard!(app, h, "users:write");
    let b = body.map(|j| j.0).unwrap_or(Value::Null);
    if let Err(e) = user_action(&app, id, &action, &b) {
        return err(StatusCode::BAD_REQUEST, &e);
    }
    spawn_sync(&app);
    match app.db.user(id) {
        Some(u) => Json(user_json(&app, &u)).into_response(),
        None => Json(json!({"ok": true})).into_response(),
    }
}

// ============================================================ nodes

pub fn node_info(n: &Node) -> Value {
    serde_json::from_str(&n.info).unwrap_or(json!({}))
}

pub(crate) fn node_json(app: &App, n: &Node, users: &[User]) -> Value {
    let info_pub = node_info(n);
    let assigned = users.iter().filter(|u| u.on(n)).count();
    json!({
        "id": n.id, "name": n.name, "address": n.address, "endpoint": n.endpoint, "endpoint_mode": n.endpoint_mode,
        "effective_endpoint": endpoint(app, n), "enabled": n.enabled, "online": n.online, "last_sync": n.last_sync,
        "note": n.note, "insecure": n.insecure, "drain": n.drain, "maint": n.maint, "accept_all": n.accept_all,
        "sync_state": n.sync_state, "users": assigned, "info": info_pub,
        "plain_http": n.id != "local" && n.address.starts_with("http://"),
        // the country of the server's IP (its flag in the panel); empty while unknown
        "cc": crate::exitgeo::cc(app, &n.id),
    })
}

async fn nodes_list(State(app): St, h: HeaderMap) -> Response {
    let _ = guard!(app, h, "nodes");
    let users = app.db.users();
    let v: Vec<Value> = app.db.nodes().iter().map(|n| node_json(&app, n, &users)).collect();
    Json(json!(v)).into_response()
}

async fn nodes_add(State(app): St, h: HeaderMap, Json(b): Json<Value>) -> Response {
    let _ = guard!(app, h, "nodes");
    let name = b["name"].as_str().unwrap_or("").trim().to_string();
    let addr = b["address"].as_str().unwrap_or("").trim().trim_end_matches('/').to_string();
    let endpoint = b["endpoint"].as_str().unwrap_or("").trim().to_string();
    let token = b["token"].as_str().unwrap_or("").trim().to_string();
    let insecure = b["insecure"].as_bool().unwrap_or(false);
    if name.is_empty() || addr.is_empty() || token.is_empty() {
        return err(StatusCode::BAD_REQUEST, "name, API address and token are required");
    }
    if !addr.starts_with("http://") && !addr.starts_with("https://") {
        return err(StatusCode::BAD_REQUEST, "API address must start with https:// (or http:// for old nodes)");
    }
    let info = match sync::remote_info_res(&app, &addr, &token, insecure).await {
        Ok(i) => i,
        Err(e) if e.contains(crate::pin::MISMATCH) => return err(StatusCode::BAD_GATEWAY, &e),
        Err(_) => return err(StatusCode::BAD_GATEWAY, "cannot reach the node (check address / token / firewall / certificate)"),
    };
    let id = format!("node-{}", rand_token(10).to_lowercase());
    let mode = if endpoint.is_empty() { "panel" } else { "custom" };
    let r = app.db.exec(
        "INSERT INTO nodes(id,name,address,endpoint,token,info,online,insecure,endpoint_mode,note) VALUES(?1,?2,?3,?4,?5,?6,1,?7,?8,?9)",
        &[&id, &name, &addr, &endpoint, &token, &info.to_string(), &(insecure as i64), &mode, &b["note"].as_str().unwrap_or("")],
    );
    if let Err(e) = r {
        return err(StatusCode::BAD_REQUEST, &e);
    }
    if insecure {
        // the certificate seen just now is the one later syncs expect
        app.adopt_node_pin(&addr, &id);
    }
    spawn_sync(&app);
    Json(json!({ "ok": true, "id": id })).into_response()
}

async fn nodes_edit(State(app): St, h: HeaderMap, Path(id): Path<String>, Json(b): Json<Value>) -> Response {
    let _ = guard!(app, h, "nodes");
    let Some(n) = app.db.node(&id) else { return err(StatusCode::NOT_FOUND, "not found") };
    let name = b["name"].as_str().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).unwrap_or(n.name.clone());
    let note = b["note"].as_str().unwrap_or(&n.note).to_string();
    let accept = b["accept_all"].as_bool().unwrap_or(n.accept_all) as i64;
    let mode = match b["endpoint_mode"].as_str() { Some("panel") => "panel", Some("custom") => "custom", _ => n.endpoint_mode.as_str() }.to_string();
    let ep = b["endpoint"].as_str().map(|s| s.trim().to_string()).unwrap_or(n.endpoint.clone());
    let addr = b["address"].as_str().map(|s| s.trim().trim_end_matches('/').to_string()).filter(|s| !s.is_empty()).unwrap_or(n.address.clone());
    let token = b["token"].as_str().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).unwrap_or(n.token.clone());
    let insecure = b["insecure"].as_bool().unwrap_or(n.insecure) as i64;
    let r = app.db.exec(
        "UPDATE nodes SET name=?1, note=?2, accept_all=?3, endpoint_mode=?4, endpoint=?5, address=?6, token=?7, insecure=?8 WHERE id=?9",
        &[&name, &note, &accept, &mode, &ep, &addr, &token, &insecure, &id],
    );
    if let Err(e) = r {
        return err(StatusCode::BAD_REQUEST, &e);
    }
    // another server (or certificate setting): its old pins would refuse it
    if addr != n.address || (insecure != 0) != n.insecure {
        app.forget_node_pins(&id, &n.address);
        app.forget_node_pins(&id, &addr);
    }
    spawn_sync(&app);
    Json(json!({"ok": true})).into_response()
}

async fn nodes_delete(State(app): St, h: HeaderMap, Path(id): Path<String>) -> Response {
    let _ = guard!(app, h, "nodes");
    if id == "local" {
        return err(StatusCode::BAD_REQUEST, "the main server cannot be deleted");
    }
    let n = delete_node(&app, &id);
    let name = n.as_ref().map(|n| n.name.clone()).unwrap_or_default();
    let steps = n.iter().map(|n| crate::tunnel::panel::node_step(&n.id, &n.name)).collect();
    let rid = crate::tunnel::panel::track("node", &name, steps);
    if let Some(n) = n {
        spawn_node_removal(&app, n);
    }
    Json(json!({ "ok": true, "removal": rid })).into_response()
}

/// A node that was deleted while it did not answer: it is asked again until it removes itself
#[derive(Serialize, Deserialize, Clone)]
struct Leftover {
    id: String,
    name: String,
    address: String,
    token: String,
    insecure: bool,
    at: i64,
}

fn leftovers(app: &App) -> Vec<Leftover> {
    serde_json::from_str(&app.db.get("nodes_leftover")).unwrap_or_default()
}

fn save_leftovers(app: &App, v: &[Leftover]) {
    app.db.set("nodes_leftover", &serde_json::to_string(v).unwrap_or_else(|_| "[]".into()));
}

/// Asks the node to cut its users off, stop KANKI MIX, remove its VPN services, close their ports and
/// uninstall its agent (3.6.8+). True when the node confirmed it.
async fn remove_remote(app: &Arc<App>, n: &Node) -> bool {
    let empty = SyncReq { kmix: Some(crate::kmix::KmixCfg::default()), kcore: Some(Default::default()), ..Default::default() };
    let synced = sync::remote_post_json(app, n, "/agent/sync", &json!(empty)).await.is_some();
    synced && sync::remote_post(app, n, "/agent/remove").await.map(|v| v["ok"].as_bool() == Some(true)).unwrap_or(false)
}

/// Removes a deleted node from its server in the background; when it does not answer it is kept
/// and asked again (see `leftover_loop`)
pub(crate) fn spawn_node_removal(app: &Arc<App>, n: Node) {
    let app = app.clone();
    tokio::spawn(async move {
        if remove_remote(&app, &n).await {
            app.forget_node_pins(&n.id, &n.address);
            crate::tunnel::panel::note_node(&n.id, "done");
            return;
        }
        crate::tunnel::panel::note_node(&n.id, "off");
        let mut l = leftovers(&app);
        l.retain(|x| x.id != n.id);
        l.push(Leftover { id: n.id.clone(), name: n.name.clone(), address: n.address.clone(), token: n.token.clone(), insecure: n.insecure, at: now() });
        save_leftovers(&app, &l);
    });
}

/// Every minute the deleted nodes that did not answer are asked again to remove themselves, for ten
/// minutes (a server gone for good is not asked forever); one whose address belongs to a node added
/// again is left alone
pub async fn leftover_loop(app: Arc<App>) {
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        let list = leftovers(&app);
        if list.is_empty() {
            continue;
        }
        let used: Vec<String> = app.db.nodes().into_iter().map(|n| n.address).collect();
        let tried: Vec<String> = list.iter().map(|x| x.id.clone()).collect();
        let mut keep = vec![];
        for x in list {
            if now() - x.at > 600 || used.contains(&x.address) {
                continue;
            }
            let n = Node { id: x.id.clone(), name: x.name.clone(), address: x.address.clone(), token: x.token.clone(), insecure: x.insecure, ..Default::default() };
            if remove_remote(&app, &n).await {
                app.forget_node_pins(&n.id, &n.address);
                crate::tunnel::panel::note_node(&n.id, "done");
            } else {
                keep.push(x);
            }
        }
        // a node deleted while this ran is not lost
        let mut now_list = leftovers(&app);
        now_list.retain(|x| keep.iter().any(|k| k.id == x.id) || !tried.contains(&x.id));
        save_leftovers(&app, &now_list);
    }
}

/// Removes a VPN node from the panel right away (its users, KANKI MIX settings, direct name …) and
/// gives it back, so its server can be told to remove itself (`spawn_node_removal`).
pub(crate) fn delete_node(app: &Arc<App>, id: &str) -> Option<Node> {
    let n = app.db.node(id);
    let _ = app.db.exec("DELETE FROM nodes WHERE id=?1", &[&id]);
    let _ = app.db.exec("DELETE FROM peers WHERE node_id=?1", &[&id]);
    // nothing of it stays in the panel: users' server lists, its KANKI MIX settings, its direct name,
    // where its traffic left to
    for u in app.db.users().into_iter().filter(|u| u.nodes.split(',').any(|x| x.trim() == id)) {
        let left: Vec<&str> = u.nodes.split(',').map(|x| x.trim()).filter(|x| !x.is_empty() && *x != id).collect();
        // a user who had only this server moves to the panel server (an empty list would mean "every server")
        let list = if left.is_empty() { "local".to_string() } else { left.join(",") };
        let _ = app.db.exec("UPDATE users SET nodes=?1 WHERE id=?2", &[&list, &u.id]);
    }
    crate::kmix::forget_node(app, id);
    crate::direct::forget(app, id);
    crate::exitgeo::forget(app, &[id.to_string()]);
    crate::live::forget(id);
    crate::servers::node_gone(app, id);
    n
}

/// Changes the WireGuard / AmneziaWG / Hysteria2 ports of a node (or of the panel server) in one go
async fn node_ports(State(app): St, h: HeaderMap, Path(id): Path<String>, Json(b): Json<Value>) -> Response {
    let _ = guard!(app, h, "nodes");
    let Some(n) = app.db.node(&id) else { return err(StatusCode::NOT_FOUND, "not found") };
    let r = if n.id == "local" { Some(crate::admin::set_ports(&b)) } else { sync::remote_post_json(&app, &n, "/agent/ports", &b).await };
    spawn_sync(&app);
    match r {
        Some(v) => Json(v).into_response(),
        None => err(StatusCode::BAD_GATEWAY, "the node did not answer: update the node agent first (Update agent), then try again"),
    }
}

async fn nodes_action(State(app): St, h: HeaderMap, Path((id, action)): Path<(String, String)>) -> Response {
    let _ = guard!(app, h, "nodes");
    let Some(n) = app.db.node(&id) else { return err(StatusCode::NOT_FOUND, "not found") };
    match action.as_str() {
        "toggle" => { let _ = app.db.exec("UPDATE nodes SET enabled=1-enabled WHERE id=?1", &[&id]); }
        "drain" => { let _ = app.db.exec("UPDATE nodes SET drain=1-drain WHERE id=?1", &[&id]); spawn_sync(&app); }
        "maint" | "maintenance" => { let _ = app.db.exec("UPDATE nodes SET maint=1-maint WHERE id=?1", &[&id]); spawn_sync(&app); }
        "sync" => { sync::sync_all(&app).await; }
        "assign-all" | "unassign-all" => {
            let add = action == "assign-all";
            if !add && id == "local" {
                return err(StatusCode::BAD_REQUEST, "the main server cannot be removed from all users");
            }
            // users without a node list follow the node's accept_all flag, users with a list need the id in it
            let _ = app.db.exec("UPDATE nodes SET accept_all=?1 WHERE id=?2", &[&(add as i64), &id]);
            for u in app.db.users() {
                if !u.explicit_nodes() {
                    continue;
                }
                let mut list: Vec<String> = u.nodes.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect();
                let has = list.contains(&id);
                if add && !has {
                    list.push(id.clone());
                } else if !add && has {
                    list.retain(|x| *x != id);
                } else {
                    continue;
                }
                let joined = list.join(",");
                let _ = app.db.exec("UPDATE users SET nodes=?1 WHERE id=?2", &[&joined, &u.id]);
            }
            spawn_sync(&app);
        }
        "health" => {
            let t0 = std::time::Instant::now();
            let info = if n.id == "local" { Ok(sync::local_info(&app)) } else { sync::remote_info_res(&app, &n.address, &n.token, n.insecure).await };
            let ms = t0.elapsed().as_millis() as i64;
            return match info {
                Ok(i) => Json(json!({"ok": true, "ms": ms, "services": i["services"], "version": i["version"], "load": i["load"]})).into_response(),
                Err(e) => Json(json!({"ok": false, "ms": ms, "error": e})).into_response(),
            };
        }
        "repair" => {
            let r = if n.id == "local" { Some(crate::admin::repair_services()) } else { sync::remote_post(&app, &n, "/agent/repair").await };
            spawn_sync(&app);
            return Json(json!({"ok": r.is_some(), "result": r})).into_response();
        }
        "update" => {
            if n.id == "local" {
                return err(StatusCode::BAD_REQUEST, "use the panel update button for the main server");
            }
            let r = sync::remote_post(&app, &n, "/agent/update").await;
            let ok = r.as_ref().map(|v| v["ok"].as_bool().unwrap_or(false)).unwrap_or(false);
            if ok {
                let want = r.as_ref().and_then(|v| v["version"].as_str().map(|x| x.to_string())).unwrap_or_default();
                sync::refresh_after_update(&app, vec![n.clone()], &want);
            }
            return Json(json!({"ok": ok, "result": r})).into_response();
        }
        _ => return err(StatusCode::BAD_REQUEST, "unknown action"),
    }
    Json(json!({"ok": true})).into_response()
}

/// Ticks (or unticks) a protocol that is not tied to a VPN node (Xray, Kanki DNS) for every user.
/// Their servers take the new user list on their next report, within a few seconds.
async fn proto_all(State(app): St, h: HeaderMap, Path((proto, action)): Path<(String, String)>) -> Response {
    let _ = guard!(app, h, "users:write");
    if !matches!(proto.as_str(), "xray" | "dns" | "wg" | "awg" | "hy2" | "kmix") {
        return err(StatusCode::BAD_REQUEST, "unknown protocol");
    }
    let add = match action.as_str() {
        "assign-all" => true,
        "unassign-all" => false,
        _ => return err(StatusCode::BAD_REQUEST, "unknown action"),
    };
    let mut changed = 0;
    for u in app.db.users() {
        let Some(list) = toggle_proto(&u.protocols, &proto, add) else { continue };
        let _ = app.db.exec("UPDATE users SET protocols=?1 WHERE id=?2", &[&list, &u.id]);
        changed += 1;
    }
    spawn_sync(&app);
    Json(json!({ "ok": true, "changed": changed })).into_response()
}

/// The protocol list with `p` added or removed; None when it is already that way.
fn toggle_proto(list: &str, p: &str, add: bool) -> Option<String> {
    let mut v: Vec<&str> = list.split(',').map(|x| x.trim()).filter(|x| !x.is_empty()).collect();
    let has = v.contains(&p);
    if add == has {
        return None;
    }
    if add {
        v.push(p);
    } else {
        v.retain(|x| *x != p);
    }
    Some(v.join(","))
}

#[cfg(test)]
mod proto_all_tests {
    use super::toggle_proto;

    #[test]
    fn adds_and_removes_one_protocol() {
        assert_eq!(toggle_proto("wg,awg", "xray", true).as_deref(), Some("wg,awg,xray"));
        assert_eq!(toggle_proto("wg,xray,awg", "xray", false).as_deref(), Some("wg,awg"));
        assert_eq!(toggle_proto("", "dns", true).as_deref(), Some("dns"));
        assert_eq!(toggle_proto("dns", "dns", false).as_deref(), Some(""));
    }

    #[test]
    fn leaves_users_that_already_match() {
        assert_eq!(toggle_proto("wg,xray", "xray", true), None);
        assert_eq!(toggle_proto("wg", "dns", false), None);
        // a name that only contains the protocol is a different protocol
        assert_eq!(toggle_proto("xray2", "xray", false), None);
    }
}

// ============================================================ node join (one-time token)

/// Admin: make a one-time token (valid for 1 hour). The new server runs the installer with it and registers itself.
async fn node_join_token(State(app): St, h: HeaderMap) -> Response {
    let _ = guard!(app, h, "nodes");
    let token = rand_token(40);
    let exp = now() + 3600;
    app.db.set("join_token", &token);
    app.db.set("join_expires", &exp.to_string());
    Json(json!({ "token": token, "expires": exp, "panel": crate::servers::panel_url(&app), "repo": crate::admin::repo() })).into_response()
}

/// Public: called by the installer on the new server once its agent runs. The one-time token is the only credential.
async fn node_join_register(State(app): St, Json(b): Json<Value>) -> Response {
    let given = b["token"].as_str().unwrap_or("").trim().to_string();
    // the token of one server added in Servers (its VPN part), or the panel-wide one of Add node
    let server = crate::servers::join_server(&app, &given);
    if server.is_none() {
        let want = app.db.get("join_token");
        let exp: i64 = app.db.get("join_expires").parse().unwrap_or(0);
        if want.is_empty() || given.is_empty() || !util::ct_eq(&given, &want) || exp < now() {
            return err(StatusCode::FORBIDDEN, "the join token is wrong, already used or expired");
        }
    }
    let name = server.as_ref().map(|s| s.name.clone()).unwrap_or_else(|| b["name"].as_str().unwrap_or("").trim().to_string());
    let addr = b["address"].as_str().unwrap_or("").trim().trim_end_matches('/').to_string();
    let endpoint = b["endpoint"].as_str().unwrap_or("").trim().to_string();
    let token = b["node_token"].as_str().unwrap_or("").trim().to_string();
    let insecure = b["insecure"].as_bool().unwrap_or(false);
    if token.is_empty() || !addr.starts_with("https://") {
        return err(StatusCode::BAD_REQUEST, "address (https://...) and node_token are required");
    }
    let name = if name.is_empty() { format!("node-{}", rand_token(4).to_lowercase()) } else { name };
    // the same server registering twice (re-run after a firewall fix, or a reinstall with a new
    // self-signed certificate) updates its row instead of adding a copy, with fresh pins
    let existing = app.db.nodes().into_iter().find(|n| n.address == addr).map(|n| n.id);
    if let Some(id) = &existing {
        app.forget_node_pins(id, &addr);
    }
    let Some(info) = sync::remote_info(&app, &addr, &token, insecure).await else {
        return err(StatusCode::BAD_GATEWAY, "the panel cannot reach the node (open the node API port in its firewall, then run the same command again)");
    };
    let mode = if endpoint.is_empty() { "panel" } else { "custom" };
    // a server added in Servers says whether its VPN serves users (a relay in Iran: off)
    let enabled = server.as_ref().map(|s| s.vpn).unwrap_or(true) as i64;
    let id = match existing {
        Some(id) => {
            let _ = app.db.exec(
                "UPDATE nodes SET token=?1, endpoint=?2, endpoint_mode=?3, insecure=?4, info=?5, online=1 WHERE id=?6",
                &[&token, &endpoint, &mode, &(insecure as i64), &info.to_string(), &id],
            );
            id
        }
        None => {
            let id = format!("node-{}", rand_token(10).to_lowercase());
            let r = app.db.exec(
                "INSERT INTO nodes(id,name,address,endpoint,token,info,online,insecure,endpoint_mode,note,enabled) VALUES(?1,?2,?3,?4,?5,?6,1,?7,?8,?9,?10)",
                &[&id, &name, &addr, &endpoint, &token, &info.to_string(), &(insecure as i64), &mode, &"joined with a one-time token", &enabled],
            );
            if let Err(e) = r {
                return err(StatusCode::BAD_REQUEST, &e);
            }
            id
        }
    };
    if insecure {
        app.adopt_node_pin(&addr, &id);
    }
    // one use only
    match &server {
        Some(s) => crate::servers::joined(&app, &s.id, &id),
        None => app.db.set("join_token", ""),
    }
    // a new server never shares a VPN port with another one (a tunnel entry could not carry both)
    let a = app.clone();
    let nid = id.clone();
    tokio::spawn(async move {
        let _ = crate::servers::fix_ports_of(&a, Some(&nid)).await;
        sync::sync_all(&a).await;
    });
    Json(json!({ "ok": true, "id": id })).into_response()
}

// ============================================================ settings / plans

pub const SETTING_KEYS: &[&str] = &[
    "dns", "mtu", "default_protocols", "sales_on", "trial_on", "trial_gb", "trial_days", "card_on", "card_number", "card_holder",
    "wallet_on", "wallet_text", "ton_address", "usdt_address", "usd_rate", "np_on", "np_key", "np_coins", "zp_on", "zp_merchant", "zp_callback", "support", "app_link",
    "welcome", "ref_gb", "ref_days", "warn_on", "backup_on", "channel",
    "panel_name", "lang", "theme", "color", "refresh", "endpoint", "sub_base", "awg_compat", "conn_limit_on", "tg_alerts", "logo", "price_rules",
    // v2.8.4: ready values of the "New user" form
    "def_gb", "def_days", "def_conns",
];

/// "owner/repo" with only the characters GitHub allows
fn valid_repo(r: &str) -> bool {
    let mut it = r.split('/');
    let ok = |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.');
    matches!((it.next(), it.next(), it.next()), (Some(a), Some(b), None) if ok(a) && ok(b))
}

async fn settings_get(State(app): St, h: HeaderMap) -> Response {
    let _ = guard!(app, h, "settings");
    let mut m = serde_json::Map::new();
    for k in SETTING_KEYS {
        m.insert(k.to_string(), json!(app.db.get(k)));
    }
    m.insert("sub_domain".into(), json!(app.db.get("sub_domain")));
    m.insert("web_bind".into(), json!(app.env.get("PANEL_BIND").cloned().unwrap_or_else(|| "127.0.0.1".into())));
    m.insert("web_port".into(), json!(app.env.get("PANEL_PORT").cloned().unwrap_or_default()));
    m.insert("domain".into(), json!(app.env.get("DOMAIN").cloned().unwrap_or_default()));
    m.insert("https_port".into(), json!(app.env.get("HTTPS_PORT").cloned().unwrap_or_else(|| "443".into())));
    // update source: /etc/kanki/repo, unless KANKI_REPO is set in the environment
    m.insert("update_repo".into(), json!(crate::admin::repo()));
    m.insert("repo_env".into(), json!(std::env::var("KANKI_REPO").map(|s| !s.is_empty()).unwrap_or(false)));
    Json(Value::Object(m)).into_response()
}

async fn settings_put(State(app): St, h: HeaderMap, Json(b): Json<Value>) -> Response {
    let _ = guard!(app, h, "settings");
    if let Some(o) = b.as_object() {
        if let Some(r) = o.get("update_repo").and_then(|v| v.as_str()) {
            let r = r.trim().trim_start_matches("https://github.com/").trim_end_matches('/').trim_end_matches(".git");
            if r.is_empty() {
                let _ = std::fs::remove_file("/etc/kanki/repo");
            } else if valid_repo(r) {
                let _ = std::fs::create_dir_all("/etc/kanki");
                if let Err(e) = std::fs::write("/etc/kanki/repo", format!("{}\n", r)) {
                    return err(StatusCode::INTERNAL_SERVER_ERROR, &format!("cannot write /etc/kanki/repo: {}", e));
                }
            } else {
                return err(StatusCode::BAD_REQUEST, "update source must look like owner/repo");
            }
        }
        for (k, v) in o {
            if SETTING_KEYS.contains(&k.as_str()) {
                let s = match v { Value::String(s) => s.clone(), Value::Bool(x) => if *x { "1".into() } else { "0".into() }, other => other.to_string() };
                app.db.set(k, s.trim());
            }
        }
    }
    spawn_sync(&app);
    Json(json!({ "ok": true })).into_response()
}

async fn apply_endpoint_all(State(app): St, h: HeaderMap) -> Response {
    let _ = guard!(app, h, "settings");
    let _ = app.db.exec("UPDATE nodes SET endpoint_mode='panel'", &[]);
    Json(json!({"ok": true})).into_response()
}

// ============================================================ message for the Kanki app (shown by its robot)

/// The app message for this user, or None when there is none, it has run out, or it is meant for other users
fn app_msg(app: &App, username: &str) -> Option<Value> {
    let text = app.db.get("app_msg");
    if text.trim().is_empty() {
        return None;
    }
    let until: i64 = app.db.get("app_msg_until").parse().unwrap_or(0);
    if until > 0 && now() >= until {
        return None;
    }
    let to = app.db.get("app_msg_users");
    if !to.trim().is_empty() && !to.split(|c: char| c == ',' || c.is_whitespace()).any(|x| x.eq_ignore_ascii_case(username)) {
        return None;
    }
    Some(json!({ "id": app.db.get("app_msg_id"), "text": text, "until": until }))
}

async fn app_msg_get(State(app): St, h: HeaderMap) -> Response {
    let _ = guard!(app, h, "settings");
    let until: i64 = app.db.get("app_msg_until").parse().unwrap_or(0);
    let text = app.db.get("app_msg");
    let active = !text.trim().is_empty() && (until == 0 || now() < until);
    Json(json!({ "text": text, "until": until, "users": app.db.get("app_msg_users"), "active": active, "now": now() })).into_response()
}

/// { text, minutes (0 = until removed), users ("" = everyone, or usernames separated by commas) }
async fn app_msg_put(State(app): St, h: HeaderMap, Json(b): Json<Value>) -> Response {
    let _ = guard!(app, h, "settings");
    let text = b["text"].as_str().unwrap_or("").trim().to_string();
    if text.is_empty() {
        return err(StatusCode::BAD_REQUEST, "the message is empty");
    }
    if text.chars().count() > 500 {
        return err(StatusCode::BAD_REQUEST, "the message is longer than 500 characters");
    }
    let minutes = b["minutes"].as_i64().unwrap_or(60).clamp(0, 60 * 24 * 30);
    let users: Vec<String> = b["users"].as_str().unwrap_or("")
        .split(|c: char| c == ',' || c.is_whitespace()).filter(|x| !x.is_empty()).map(|x| x.to_string()).collect();
    if let Some(bad) = users.iter().find(|x| !valid_username(x)) {
        return err(StatusCode::BAD_REQUEST, &format!("not a username: {}", bad));
    }
    let until = if minutes == 0 { 0 } else { now() + minutes * 60 };
    app.db.set("app_msg", &text);
    app.db.set("app_msg_until", &until.to_string());
    app.db.set("app_msg_users", &users.join(","));
    // a new id makes the app show it again even to users who closed the previous message
    app.db.set("app_msg_id", &format!("{}-{}", now(), rand_token(4)));
    Json(json!({ "ok": true, "until": until })).into_response()
}

async fn app_msg_delete(State(app): St, h: HeaderMap) -> Response {
    let _ = guard!(app, h, "settings");
    app.db.set("app_msg", "");
    app.db.set("app_msg_until", "0");
    Json(json!({ "ok": true })).into_response()
}

async fn plans_list(State(app): St, h: HeaderMap) -> Response {
    let _ = guard!(app, h, "settings");
    let v: Vec<Value> = app.db.with(|c| {
        let mut s = c.prepare("SELECT id,name,COALESCE(days,0),COALESCE(gb,0),COALESCE(toman,0),COALESCE(usd,0),COALESCE(conns,1),COALESCE(active,1),COALESCE(countries,0),COALESCE(category,'') FROM plans ORDER BY toman").unwrap();
        let rows: Vec<Value> = s.query_map([], |r| {
            Ok(json!({ "id": r.get::<_, i64>(0)?, "name": r.get::<_, String>(1)?, "days": r.get::<_, i64>(2)?,
                "gb": r.get::<_, f64>(3)?, "toman": r.get::<_, i64>(4)?, "usd": r.get::<_, f64>(5)?,
                "conns": r.get::<_, i64>(6)?, "active": r.get::<_, i64>(7)? == 1, "countries": r.get::<_, i64>(8)?, "category": r.get::<_, String>(9)? }))
        }).unwrap().filter_map(|x| x.ok()).collect();
        rows
    });
    Json(json!(v)).into_response()
}

fn insert_plan(app: &App, b: &Value) -> Result<usize, String> {
    let name = b["name"].as_str().map(|s| s.trim()).filter(|s| !s.is_empty()).unwrap_or("Plan").to_string();
    let cat = b["category"].as_str().map(|s| s.trim().to_string()).unwrap_or_default();
    app.db.exec(
        "INSERT INTO plans(name,days,gb,toman,usd,conns,countries,active,category) VALUES(?1,?2,?3,?4,?5,?6,?7,1,?8)",
        &[&name, &(num(&b["days"]).unwrap_or(30.0) as i64), &num(&b["gb"]).unwrap_or(0.0).max(0.0),
          &(num(&b["toman"]).unwrap_or(0.0).max(0.0) as i64), &num(&b["usd"]).unwrap_or(0.0).max(0.0),
          &(num(&b["conns"]).unwrap_or(1.0).max(1.0) as i64), &(num(&b["countries"]).unwrap_or(0.0).max(0.0) as i64), &cat],
    )
}

async fn plans_add(State(app): St, h: HeaderMap, Json(b): Json<Value>) -> Response {
    let _ = guard!(app, h, "settings");
    match insert_plan(&app, &b) {
        Ok(_) => Json(json!({ "ok": true })).into_response(),
        Err(e) => err(StatusCode::BAD_REQUEST, &e),
    }
}

/// Smart plan builder: many plans at once (the panel computes the prices).
async fn plans_bulk(State(app): St, h: HeaderMap, Json(b): Json<Value>) -> Response {
    let _ = guard!(app, h, "settings");
    if b["replace"].as_bool() == Some(true) {
        let _ = app.db.exec("DELETE FROM plans", &[]);
    }
    let mut n = 0;
    for p in b["plans"].as_array().cloned().unwrap_or_default() {
        if insert_plan(&app, &p).is_ok() {
            n += 1;
        }
    }
    if let Some(r) = b.get("rules").filter(|r| r.is_object()) {
        app.db.set("price_rules", &r.to_string());
    }
    Json(json!({ "ok": true, "added": n })).into_response()
}

async fn plans_update(State(app): St, h: HeaderMap, Path(id): Path<i64>, Json(b): Json<Value>) -> Response {
    let _ = guard!(app, h, "settings");
    if let Some(a) = b["active"].as_bool() {
        let _ = app.db.exec("UPDATE plans SET active=?1 WHERE id=?2", &[&(a as i64), &id]);
    }
    if let Some(t) = num(&b["toman"]) {
        let _ = app.db.exec("UPDATE plans SET toman=?1 WHERE id=?2", &[&(t.max(0.0) as i64), &id]);
    }
    if let Some(u) = num(&b["usd"]) {
        let _ = app.db.exec("UPDATE plans SET usd=?1 WHERE id=?2", &[&((u.max(0.0) * 100.0).round() / 100.0), &id]);
    }
    if let Some(cat) = b["category"].as_str() {
        let _ = app.db.exec("UPDATE plans SET category=?1 WHERE id=?2", &[&cat.trim().to_string(), &id]);
    }
    if let Some(nm) = b["name"].as_str().map(|s| s.trim()).filter(|s| !s.is_empty()) {
        let _ = app.db.exec("UPDATE plans SET name=?1 WHERE id=?2", &[&nm.to_string(), &id]);
    }
    Json(json!({ "ok": true })).into_response()
}

/// Rename a plan category (from = "" renames the uncategorised plans, to = "" removes the category).
async fn plans_cat_rename(State(app): St, h: HeaderMap, Json(b): Json<Value>) -> Response {
    let _ = guard!(app, h, "settings");
    let from = b["from"].as_str().unwrap_or("").trim().to_string();
    let to = b["to"].as_str().unwrap_or("").trim().to_string();
    let _ = app.db.exec("UPDATE plans SET category=?1 WHERE COALESCE(category,'')=?2", &[&to, &from]);
    Json(json!({ "ok": true })).into_response()
}

async fn plans_delete(State(app): St, h: HeaderMap, Path(id): Path<i64>) -> Response {
    let _ = guard!(app, h, "settings");
    let _ = app.db.exec("DELETE FROM plans WHERE id=?1", &[&id]);
    Json(json!({ "ok": true })).into_response()
}

async fn force_sync(State(app): St, h: HeaderMap) -> Response {
    let _ = guard!(app, h, "nodes");
    sync::sync_all(&app).await;
    Json(json!({ "ok": true })).into_response()
}

// ============================================================ subscription page (Kanki app)

/// "<prefix>-<id>-<code>": new links use the kanki prefix, links made by older versions keep working
pub(crate) fn parse_code(code: &str) -> Option<(i64, String)> {
    let (prefix, rest) = code.split_once('-')?;
    if prefix.is_empty() || !prefix.chars().all(|c| c.is_ascii_alphabetic()) {
        return None;
    }
    let (id, c) = rest.split_once('-')?;
    Some((id.parse().ok()?, c.to_string()))
}

fn hy2_uri(app: &App, u: &User, n: &Node) -> Option<String> {
    hy2_link(app, u, n, None)
}

/// The Hysteria2 link, straight to the server or through its tunnel (`tw`)
fn hy2_link(app: &App, u: &User, n: &Node, tw: Option<&crate::twin::Twin>) -> Option<String> {
    let info = node_info(n);
    let port = info["hy2_port"].as_str().unwrap_or("");
    if port.is_empty() || !u.has_proto("hy2") {
        return None;
    }
    let mut q = vec![];
    let mut sni = info["hy2_sni"].as_str().unwrap_or("").to_string();
    // through the tunnel the address is the Iran one: the certificate is still the server's own name
    let ep = endpoint(app, n);
    if sni.is_empty() && tw.is_some() && ep.parse::<std::net::IpAddr>().is_err() && !ep.contains(':') {
        sni = ep.clone();
    }
    if !sni.is_empty() {
        q.push(format!("sni={}", sni));
    }
    if info["hy2_insecure"].as_str() == Some("1") {
        q.push("insecure=1".into());
    }
    let obfs = info["hy2_obfs"].as_str().unwrap_or("");
    if !obfs.is_empty() {
        q.push(format!("obfs=salamander&obfs-password={}", pct(obfs)));
    }
    let (addr, name) = match tw {
        Some(t) => (t.addr(t.port(app, port.parse().unwrap_or(0), false)), format!("{} (Tunnel)", n.name)),
        None => (format!("{}:{}", ep, port), n.name.clone()),
    };
    Some(format!("hysteria2://{}@{}/?{}#{}", u.code, addr, q.join("&"), pct(&name)))
}

pub fn user_nodes(app: &App, u: &User) -> Vec<Node> {
    app.db.nodes().into_iter().filter(|n| n.usable() && u.on(n)).collect()
}

/// Which protocols this user can actually use on this node. WireGuard only when the server is
/// reached through a tunnel: plain WireGuard straight to a server abroad does not pass in Iran.
pub fn node_protos(app: &App, u: &User, n: &Node) -> Vec<&'static str> {
    let info = node_info(n);
    let mut v = vec![];
    let has = |k: &str| info[k].as_str().map(|s| !s.is_empty()).unwrap_or(false);
    if u.has_proto("wg") && has("wg_pub") && crate::direct::through_tunnel(app, n) { v.push("wireguard"); }
    if u.has_proto("awg") && has("awg_pub") { v.push("amneziawg"); }
    if u.has_proto("hy2") && has("hy2_port") { v.push("hysteria2"); }
    if u.has_proto("kmix") && info["kmix_port"].as_u64().is_some() { v.push("kankimix"); }
    v
}

/// What a server's second entry (its configs through the tunnel) offers this user: every protocol when
/// the server has a tunnel (Servers page), else only KANKI MIX's own second config (KANKI MIX page).
/// WireGuard is here even when the main entry has none: through the tunnel it passes.
pub fn twin_protos(app: &App, u: &User, n: &Node) -> Vec<&'static str> {
    let kmix = crate::kmix::link_tunnel(app, u, n).is_some();
    if crate::twin::of_node(app, n).is_none() {
        return if kmix { vec!["kankimix"] } else { vec![] };
    }
    let info = node_info(n);
    let has = |k: &str| info[k].as_str().map(|s| !s.is_empty()).unwrap_or(false);
    let mut v = vec![];
    if u.has_proto("wg") && has("wg_pub") { v.push("wireguard"); }
    if u.has_proto("awg") && has("awg_pub") { v.push("amneziawg"); }
    if u.has_proto("hy2") && has("hy2_port") { v.push("hysteria2"); }
    if kmix { v.push("kankimix"); }
    v
}

/// { protocol: "tunnel" | "direct" } of one subscription entry (`twin`: the copies through the tunnel)
fn via_proto(app: &App, n: &Node, protos: &[&str], twin: bool) -> Value {
    let ep = if crate::direct::through_tunnel(app, n) { "tunnel" } else { "direct" };
    let kmix = if crate::kmix::settings(app).nodes.get(&n.id).map(|o| o.route == "tunnel").unwrap_or(false) { "tunnel" } else { "direct" };
    let m: serde_json::Map<String, Value> =
        protos.iter().map(|p| (p.to_string(), json!(if twin { "tunnel" } else if *p == "kankimix" { kmix } else { ep }))).collect();
    Value::Object(m)
}

/// The name of a server's second entry in the app
pub fn twin_name(app: &App, n: &Node) -> String {
    crate::twin::of_node(app, n).map(|t| t.name).unwrap_or_else(|| crate::kmix::tunnel_name(app, n))
}

/// id of the second (through the tunnel) entry of a server in the subscription data
pub const TUNNEL_SUFFIX: &str = "@tunnel";

fn sub_data(app: &App, u: &User) -> Value {
    let mut nodes: Vec<Value> = vec![];
    for n in user_nodes(app, u).iter() {
        let tun = crate::kmix::link_tunnel(app, u, n);
        let mut v = json!({
            "id": n.id, "name": n.name, "main": n.id == "local", "protocols": node_protos(app, u, n),
            "hy2": hy2_uri(app, u, n),
            // KANKI MIX: kanki://key@host:port?fec=10-3… (Null = not for this user / not on this server)
            "kmix": crate::kmix::link(app, u, n),
            // the second KANKI MIX config, through the Iran tunnel (Null = none)
            "kmix_tunnel": tun,
            // Kanki Cores: [{kind: game|hq|faketcp, title, url: kcore://…}] (empty = none here)
            "kcore": crate::kcores::links(app, u, n),
        });
        // the real exit of this server's configs (a tunnel endpoint is in Iran; the traffic leaves here)
        if let (Some(o), Some(e)) = (v.as_object_mut(), crate::exitgeo::fields(app, &n.id).as_object()) {
            o.extend(e.clone());
        }
        // each protocol of this entry: "tunnel" when its config points at an Iran entry, "direct" when at the
        // server itself (the app labels them; KANKI MIX has its own address setting)
        v["via_proto"] = via_proto(app, n, node_protos(app, u, n).as_slice(), false);
        // AmneziaWG: whether its endpoint goes through the tunnel or straight to the server, and the address
        // of the second, direct config ("" = none; the app no longer guesses it from the server's name)
        if v["protocols"].as_array().map(|a| a.iter().any(|p| p == "amneziawg")).unwrap_or(false) {
            let (via, direct) = crate::direct::awg(app, n);
            v["awg_via"] = json!(via);
            v["awg_direct"] = json!(direct);
        }
        // the configs through the tunnel are the server's second entry, so every app (one that knows only
        // "kmix" too) lists them as a server of their own; "via" and "parent" tell a newer app they are the
        // tunnel configs of that server
        let tp = twin_protos(app, u, n);
        if !tp.is_empty() {
            let tw = crate::twin::of_node(app, n);
            let mut e = v.clone();
            e["id"] = json!(format!("{}{}", n.id, TUNNEL_SUFFIX));
            e["name"] = json!(twin_name(app, n));
            e["main"] = json!(false);
            e["protocols"] = json!(tp);
            e["hy2"] = if tp.contains(&"hysteria2") { json!(hy2_link(app, u, n, tw.as_ref())) } else { Value::Null };
            e["kmix"] = json!(tun);
            e["kmix_tunnel"] = Value::Null;
            // the cores are reached on the server's own address (the main entry)
            e["kcore"] = json!([]);
            e["via"] = json!("tunnel");
            e["via_proto"] = via_proto(app, n, &tp, true);
            e["parent"] = json!(n.id);
            if let Some(o) = e.as_object_mut() {
                o.remove("awg_via");
                o.remove("awg_direct");
            }
            // its AmneziaWG goes through the tunnel and has no direct copy (the main entry is the direct one)
            if tp.contains(&"amneziawg") {
                e["awg_via"] = json!("tunnel");
                e["awg_direct"] = json!("");
            }
            nodes.push(v);
            nodes.push(e);
        } else {
            nodes.push(v);
        }
    }
    json!({
        "id": u.id, "username": u.username, "sub": u.sub_code(), "status": u.status(), "active": u.active(),
        "limit_gb": u.limit_gb, "used_gb": u.used_gb(), "expires_ts": u.expires_at, "created_ts": u.created_at,
        "online": u.online, "max_conn": u.max_conn, "last_seen_ts": u.last_seen,
        "panel_name": app.db.get("panel_name"), "version": crate::VERSION, "nodes": nodes,
        "support": app.db.get("support"), "app_link": app.db.get("app_link"),
        // the app's install files uploaded in the panel (download addresses for this subscriber)
        "apps": crate::apps::sub_info(app, &u.sub_code()),
        "logo": app.db.get("logo"),
        // the subscription link's base when an Iran server serves it (empty = the page's own address)
        "sub_base": crate::subiran::origin(app).unwrap_or_default(),
        "app_msg": app_msg(app, &u.username),
        // the emergency chat on the server inside Iran, and the key that signs the admin's messages
        "emergency": crate::tunnel::panel::emer_url(app),
        "emergency_key": crate::tunnel::panel::emer_pub(app),
        // Kanki DNS: the user's token and each DNS server's addresses (Null = no DNS for this user)
        "dns": crate::dns::panel::sub_info(app, u),
        // Xray share links of this user (Null = no Xray)
        "xray": crate::xray::panel::sub_info(app, u),
    })
}

/// One protocol of one server on the subscription page (`tunnel`: its copy through the server's tunnel)
fn proto_row(app: &App, u: &User, n: &Node, p: &str, tunnel: bool) -> String {
    let sub = u.sub_code();
    let (title, letter) = match p { "wireguard" => ("WireGuard", "W"), "amneziawg" => ("AmneziaWG", "A"), "kankimix" => ("KANKI MIX", "K"), _ => ("Hysteria2", "H") };
    let node = format!("{}{}", esc(&n.id), if tunnel { TUNNEL_SUFFIX } else { "" });
    let base = format!("/api/config/{}/{}?sub={}&amp;node={}", u.id, p, sub, node);
    let mut btns = String::new();
    match p {
        // KANKI MIX works only in the Kanki app: the page shows no link, copy or QR (the link is the user's
        // own key; there is no other app to paste it in). The app finds the address of the link text in the
        // hidden tag, as it found the QR button's before.
        "kankimix" => {
            let link = if tunnel { crate::kmix::link_tunnel(app, u, n) } else { crate::kmix::link(app, u, n) };
            if link.is_some() {
                btns.push_str(&format!(
                    "<i hidden{} data-url=\"/api/config/{}/kankimix?sub={}&amp;node={}\"></i>",
                    if tunnel { " data-via=\"tunnel\"" } else { "" }, u.id, sub, node
                ));
                btns.push_str("<p class=\"apponly\" data-i18n=\"app_only\">Only in the Kanki VPN app</p>");
            }
        }
        "hysteria2" => {
            let tw = if tunnel { crate::twin::of_node(app, n) } else { None };
            if let Some(hu) = hy2_link(app, u, n, tw.as_ref()) {
                btns.push_str(&format!("<code class=\"uri\">{}</code>", esc(&hu)));
                btns.push_str(&format!("<button class=\"b2\" data-act=\"copy\" data-text=\"{}\" data-i18n=\"copy_uri\">Copy URI</button>", esc(&hu)));
                btns.push_str(&format!("<button class=\"b2\" data-act=\"qr\" data-url=\"/api/config/{}/{}/qr?sub={}&amp;node={}\" data-i18n=\"qr\">QR Code</button>", u.id, p, sub, node));
            }
        }
        _ => {
            btns.push_str(&format!("<a class=\"btn\" href=\"{}\" data-i18n=\"dl_conf\">Download config</a>", base));
            btns.push_str(&format!("<button class=\"b2\" data-act=\"info\" data-url=\"{}\" data-i18n=\"show_info\">Show info</button>", base));
            btns.push_str(&format!("<button class=\"b2\" data-act=\"qr\" data-url=\"/api/config/{}/{}/qr?sub={}&amp;node={}\" data-i18n=\"qr\">QR Code</button>", u.id, p, sub, node));
            if p == "wireguard" {
                btns.push_str(&format!("<button class=\"b2\" data-act=\"uri\" data-url=\"/api/config/{}/{}/uri?sub={}&amp;node={}\" data-i18n=\"get_uri\">Get URI</button>", u.id, p, sub, node));
            }
        }
    }
    format!(
        "<div class=\"row proto\" data-proto=\"{p}\"><div class=\"ph\"><i class=\"pl pl-{p}\">{l}</i><div><b>{t}</b><small>{p}</small></div></div><div class=\"acts\">{b}</div></div>",
        p = p, l = letter, t = title, b = btns
    )
}

async fn sub_page(State(app): St, Path(code): Path<String>) -> Response {
    let Some((id, c)) = parse_code(&code) else { return (StatusCode::NOT_FOUND, "not found").into_response() };
    let Some(u) = app.db.user_by_code(id, &c) else { return (StatusCode::NOT_FOUND, "not found").into_response() };
    let sub = u.sub_code();
    // server-rendered config links keep the exact URL format the Kanki Android app reads
    let mut nodes_html = String::new();
    for n in user_nodes(&app, &u) {
        let rows: String = node_protos(&app, &u, &n).into_iter().map(|p| proto_row(&app, &u, &n, p, false)).collect();
        if !rows.is_empty() {
            nodes_html.push_str(&format!(
                "<section class=\"node\" data-node=\"{}\"><h3>{}<small data-i18n=\"{}\"></small></h3>{}</section>",
                esc(&n.id), esc(&n.name), if n.id == "local" { "main_server" } else { "node" }, rows
            ));
        }
        // the configs through the server's tunnel: its second entry, under its own heading (the app names
        // each config by the last heading before it)
        let rows: String = twin_protos(&app, &u, &n).into_iter().map(|p| proto_row(&app, &u, &n, p, true)).collect();
        if !rows.is_empty() {
            nodes_html.push_str(&format!(
                "<section class=\"node\" data-node=\"{}{}\" data-via=\"tunnel\"><h3>{}<small data-i18n=\"tunnel\"></small></h3>{}</section>",
                esc(&n.id), TUNNEL_SUFFIX, esc(&twin_name(&app, &n)), rows
            ));
        }
    }
    // Xray links (copy / QR) and the user's Kanki DNS addresses
    let xl = crate::xray::panel::user_links(&app, &u);
    if !xl.is_empty() {
        let mut rows = String::new();
        for (i, (name, l)) in xl.iter().enumerate() {
            let proto = l.split("://").next().unwrap_or("xray").to_uppercase();
            rows.push_str(&format!(
                "<div class=\"row proto\" data-proto=\"xray\"><div class=\"ph\"><i class=\"pl pl-xray\">X</i><div><b>{}</b><small>{}</small></div></div><div class=\"acts\"><code class=\"uri\">{}</code><button class=\"b2\" data-act=\"copy\" data-text=\"{}\" data-i18n=\"copy_uri\">Copy URI</button><button class=\"b2\" data-act=\"qr\" data-url=\"/sub/{}/xqr/{}\" data-i18n=\"qr\">QR Code</button></div></div>",
                esc(if name.is_empty() { &proto } else { name }), esc(&proto), esc(l), esc(l), sub, i
            ));
        }
        nodes_html.push_str(&format!("<section class=\"node\" data-node=\"xray\"><h3>Xray</h3>{}</section>", rows));
    }
    let dns = crate::dns::panel::sub_info(&app, &u);
    if let Some(list) = dns["servers"].as_array().filter(|l| !l.is_empty()) {
        let mut rows = String::new();
        for x in list {
            let s = |k: &str| x[k].as_str().unwrap_or("").to_string();
            let mut acts = String::new();
            for (label, v) in [("Private DNS (DoT)", s("dot")), ("DoH", s("doh")), ("DNS", s("ip"))] {
                if !v.is_empty() {
                    acts.push_str(&format!("<code class=\"uri\">{}: {}</code><button class=\"b2\" data-act=\"copy\" data-text=\"{}\" data-i18n=\"copy\">Copy</button>", label, esc(&v), esc(&v)));
                }
            }
            let title = if s("note").is_empty() { s("name") } else { format!("{} · {}", s("name"), s("note")) };
            rows.push_str(&format!("<div class=\"row proto\" data-proto=\"dns\"><div class=\"ph\"><i class=\"pl pl-dns\">D</i><div><b>{}</b><small>{}</small></div></div><div class=\"acts\">{}</div></div>", esc(&title), esc(&s("role")), acts));
        }
        nodes_html.push_str(&format!("<section class=\"node\" data-node=\"dns\"><h3>Kanki DNS</h3>{}</section>", rows));
    }
    let data = serde_json::to_string(&sub_data(&app, &u)).unwrap_or_default().replace("</", "<\\/");
    let page = include_str!("../../assets/web/sub.html")
        .replace("{{TITLE}}", &esc(&u.username))
        .replace("{{SUB}}", &sub)
        .replace("{{STATUS}}", u.status())
        .replace("{{EXP}}", &iso(u.expires_at))
        .replace("{{LIM}}", &format!("{:.6}", u.limit_gb))
        .replace("{{USED}}", &format!("{:.6}", u.used_gb()))
        .replace("{{NODES}}", &nodes_html)
        .replace("{{DATA}}", &data);
    ([(header::CACHE_CONTROL, "no-store")], Html(page)).into_response()
}

/// QR code of the user's i-th Xray link
async fn sub_xray_qr(State(app): St, Path((code, i)): Path<(String, usize)>) -> Response {
    let Some((id, c)) = parse_code(&code) else { return (StatusCode::NOT_FOUND, "not found").into_response() };
    let Some(u) = app.db.user_by_code(id, &c) else { return (StatusCode::NOT_FOUND, "not found").into_response() };
    let Some((_, l)) = crate::xray::panel::user_links(&app, &u).into_iter().nth(i) else { return (StatusCode::NOT_FOUND, "not found").into_response() };
    match util::qr_svg(&l) {
        Some(svg) => ([(header::CONTENT_TYPE, "image/svg+xml".to_string()), (header::CACHE_CONTROL, "no-store".to_string())], svg).into_response(),
        None => (StatusCode::PAYLOAD_TOO_LARGE, "too large for a QR code").into_response(),
    }
}

async fn sub_json(State(app): St, Path(code): Path<String>) -> Response {
    let Some((id, c)) = parse_code(&code) else { return err(StatusCode::NOT_FOUND, "not found") };
    let Some(u) = app.db.user_by_code(id, &c) else { return err(StatusCode::NOT_FOUND, "not found") };
    Json(sub_data(&app, &u)).into_response()
}

/// The combined subscription the page offers for v2rayNG / V2Box: one Hysteria2 link per server (through
/// its tunnel when it has one, like the page shows) and every Xray link (base64)
async fn sub_v2(State(app): St, Path(code): Path<String>) -> Response {
    let Some((id, c)) = parse_code(&code) else { return (StatusCode::NOT_FOUND, "").into_response() };
    let Some(u) = app.db.user_by_code(id, &c) else { return (StatusCode::NOT_FOUND, "").into_response() };
    let mut lines: Vec<String> = vec![];
    for n in user_nodes(&app, &u) {
        let tw = crate::twin::of_node(&app, &n);
        let hy = if twin_protos(&app, &u, &n).contains(&"hysteria2") { hy2_link(&app, &u, &n, tw.as_ref()) } else { None };
        lines.extend(hy.or_else(|| hy2_uri(&app, &u, &n)));
    }
    lines.extend(crate::xray::panel::user_links(&app, &u).into_iter().map(|x| x.1));
    let total = (u.limit_gb * 1_073_741_824.0) as i64;
    let info = format!("upload=0; download={}; total={}; expire={}", u.used_bytes.max(0), total, u.expires_at);
    ([(header::HeaderName::from_static("subscription-userinfo"), info), (header::CONTENT_TYPE, "text/plain; charset=utf-8".to_string())],
     util::b64(lines.join("\n").as_bytes())).into_response()
}

/// Subscription of only the user's Xray links (base64, for v2rayNG / V2Box)
async fn sub_xray(State(app): St, Path(code): Path<String>) -> Response {
    let Some((id, c)) = parse_code(&code) else { return (StatusCode::NOT_FOUND, "").into_response() };
    let Some(u) = app.db.user_by_code(id, &c) else { return (StatusCode::NOT_FOUND, "").into_response() };
    let lines: Vec<String> = crate::xray::panel::user_links(&app, &u).into_iter().map(|x| x.1).collect();
    let total = (u.limit_gb * 1_073_741_824.0) as i64;
    let info = format!("upload=0; download={}; total={}; expire={}", u.used_bytes.max(0), total, u.expires_at);
    ([(header::HeaderName::from_static("subscription-userinfo"), info), (header::CONTENT_TYPE, "text/plain; charset=utf-8".to_string())],
     util::b64(lines.join("\n").as_bytes())).into_response()
}

/// Raw subscription for v2rayNG / Hiddify (Hysteria2 + WireGuard URIs, base64)
async fn sub_raw(State(app): St, Path(code): Path<String>) -> Response {
    let Some((id, c)) = parse_code(&code) else { return (StatusCode::NOT_FOUND, "").into_response() };
    let Some(u) = app.db.user_by_code(id, &c) else { return (StatusCode::NOT_FOUND, "").into_response() };
    let mut lines: Vec<String> = vec![];
    for n in user_nodes(&app, &u) {
        if let Some(h) = hy2_uri(&app, &u, &n) {
            lines.push(h);
        }
        // WireGuard only through a tunnel (see node_protos)
        if node_protos(&app, &u, &n).contains(&"wireguard") {
            if let Some(w) = wg_uri(&app, &u, &n, None) {
                lines.push(w);
            }
        }
        // the copies through the server's tunnel
        let tp = twin_protos(&app, &u, &n);
        let tw = crate::twin::of_node(&app, &n);
        if tp.contains(&"hysteria2") {
            lines.extend(hy2_link(&app, &u, &n, tw.as_ref()));
        }
        if tp.contains(&"wireguard") {
            lines.extend(wg_uri(&app, &u, &n, tw.as_ref()));
        }
    }
    lines.extend(crate::xray::panel::user_links(&app, &u).into_iter().map(|x| x.1));
    let used = u.used_bytes.max(0);
    let total = (u.limit_gb * 1_073_741_824.0) as i64;
    let info = format!("upload=0; download={}; total={}; expire={}", used, total, u.expires_at);
    ([(header::HeaderName::from_static("subscription-userinfo"), info), (header::CONTENT_TYPE, "text/plain; charset=utf-8".to_string())],
     util::b64(lines.join("\n").as_bytes())).into_response()
}

/// The WireGuard link, to the server's endpoint or through its tunnel (`tw`)
fn wg_uri(app: &App, u: &User, n: &Node, tw: Option<&crate::twin::Twin>) -> Option<String> {
    let info = node_info(n);
    let spub = info["wg_pub"].as_str().filter(|s| !s.is_empty())?.to_string();
    let port = info["wg_port"].as_str().unwrap_or("").to_string();
    let peer = app.db.ensure_peer(u.id, &n.id, "wg")?;
    let (addr, name) = match tw {
        Some(t) => (t.addr(t.port(app, port.parse().unwrap_or(0), false)), format!("{}-{}-tunnel", n.name, u.username)),
        None => (format!("{}:{}", endpoint(app, n), port), format!("{}-{}", n.name, u.username)),
    };
    Some(format!(
        "wireguard://{}@{}?publickey={}&presharedkey={}&address={}&mtu={}#{}",
        pct(&peer.privkey), addr, pct(&spub), pct(&peer.psk), pct(&format!("{}/32", peer.ip)),
        app.db.get("mtu"), pct(&name)
    ))
}

async fn config_file_extra(st: St, Path((id, proto, extra)): Path<(i64, String, String)>, q: Query<HashMap<String, String>>) -> Response {
    build_config(st, id, proto, q.0, &extra).await
}

async fn config_file(st: St, Path((id, proto)): Path<(i64, String)>, q: Query<HashMap<String, String>>) -> Response {
    build_config(st, id, proto, q.0, "").await
}

fn text_conf(s: String) -> Response {
    ([(header::CONTENT_TYPE, "text/plain; charset=utf-8".to_string())], s).into_response()
}

/// For the sales bot: the config of one protocol on one server -> (file name, text).
/// `tunnel`: the copy through the server's tunnel.
pub async fn bot_config(app: &Arc<App>, u: &User, n: &Node, proto: &str, tunnel: bool) -> Option<(String, String)> {
    let mut q: HashMap<String, String> = HashMap::new();
    q.insert("sub".to_string(), u.sub_code().to_string());
    q.insert("node".to_string(), if tunnel { format!("{}{}", n.id, TUNNEL_SUFFIX) } else { n.id.clone() });
    let resp = build_config(State(app.clone()), u.id, proto.to_string(), q, "").await;
    if resp.status() != StatusCode::OK {
        return None;
    }
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20).await.ok()?;
    let text = String::from_utf8(bytes.to_vec()).ok()?;
    Some((conf_file_name_via(app, u, n, proto, tunnel), text))
}

async fn build_config(State(app): St, id: i64, proto: String, q: HashMap<String, String>, extra: &str) -> Response {
    let sub = q.get("sub").cloned().unwrap_or_default();
    let code = parse_code(&sub).map(|x| x.1).unwrap_or(sub);
    let Some(u) = app.db.user_by_code(id, &code) else { return (StatusCode::NOT_FOUND, "not found").into_response() };
    let node_id = q.get("node").cloned().unwrap_or_else(|| "local".into());
    // the second KANKI MIX entry of a server: the same server, the link through the tunnel
    let (node_id, via_tunnel) = match node_id.strip_suffix(TUNNEL_SUFFIX) {
        Some(b) => (b.to_string(), true),
        None => (node_id, q.get("via").map(|v| v == "tunnel").unwrap_or(false)),
    };
    let Some(n) = app.db.node(&node_id) else { return (StatusCode::NOT_FOUND, "node").into_response() };
    if !u.on(&n) {
        return (StatusCode::FORBIDDEN, "node not allowed").into_response();
    }
    let info = node_info(&n);
    let qr = |s: &str| -> Response {
        match util::qr_svg(s) {
            Some(svg) => ([(header::CONTENT_TYPE, "image/svg+xml".to_string())], svg).into_response(),
            None => (StatusCode::PAYLOAD_TOO_LARGE, "too large for a QR code").into_response(),
        }
    };
    // the copy through the server's tunnel: its Iran address and the port that address carries here
    let tw = if via_tunnel && proto != "kankimix" {
        match crate::twin::of_node(&app, &n) {
            Some(t) => Some(t),
            None => return (StatusCode::NOT_FOUND, "this server has no tunnel").into_response(),
        }
    } else {
        None
    };
    if proto == "hysteria2" {
        let s = hy2_link(&app, &u, &n, tw.as_ref()).unwrap_or_default();
        return if extra == "qr" { qr(&s) } else { text_conf(s) };
    }
    if proto == "kankimix" {
        let link = if via_tunnel { crate::kmix::link_tunnel(&app, &u, &n) } else { crate::kmix::link(&app, &u, &n) };
        let Some(s) = link else { return (StatusCode::NOT_FOUND, "KANKI MIX is not on for this user / server").into_response() };
        return if extra == "qr" { qr(&s) } else { text_conf(s) };
    }
    let p = match proto.as_str() { "amneziawg" => "awg", "wireguard" => "wg", _ => return (StatusCode::NOT_FOUND, "proto").into_response() };
    if !u.has_proto(p) {
        return (StatusCode::FORBIDDEN, "protocol not allowed").into_response();
    }
    if p == "wg" && extra == "uri" {
        return text_conf(wg_uri(&app, &u, &n, tw.as_ref()).unwrap_or_default());
    }
    let spub = info[format!("{}_pub", p)].as_str().unwrap_or("").to_string();
    let port = info[format!("{}_port", p)].as_str().unwrap_or("").to_string();
    if spub.is_empty() {
        return (StatusCode::NOT_FOUND, "protocol not installed on this server").into_response();
    }
    let Some(peer) = app.db.ensure_peer(u.id, &n.id, p) else { return (StatusCode::INTERNAL_SERVER_ERROR, "keys").into_response() };
    let mut s = format!(
        "[Interface]\nPrivateKey = {}\nAddress = {}/32\nDNS = {}\nMTU = {}\n",
        peer.privkey, peer.ip, app.db.get("dns"), app.db.get("mtu")
    );
    if p == "awg" {
        let compat = app.db.on("awg_compat");
        let classic = ["Jc", "Jmin", "Jmax", "S1", "S2", "H1", "H2", "H3", "H4"];
        if let Some(arr) = info["awg"].as_array() {
            for kv in arr {
                if let (Some(k), Some(v)) = (kv[0].as_str(), kv[1].as_str()) {
                    if compat && !classic.contains(&k) {
                        continue;
                    }
                    s.push_str(&format!("{} = {}\n", k, v));
                }
            }
        }
    }
    let ep = match &tw {
        Some(t) => t.addr(t.port(&app, port.parse().unwrap_or(0), false)),
        None => format!("{}:{}", endpoint(&app, &n), port),
    };
    s.push_str(&format!(
        "\n[Peer]\nPublicKey = {}\nPresharedKey = {}\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = {}\nPersistentKeepalive = 25\n",
        spub, peer.psk, ep
    ));
    if extra == "qr" {
        return qr(&s);
    }
    if extra == "text" {
        return text_conf(s);
    }
    let fname = conf_file_name_via(&app, &u, &n, &proto, tw.is_some());
    ([(header::CONTENT_TYPE, "text/plain; charset=utf-8".to_string()),
      (header::CONTENT_DISPOSITION, format!("attachment; filename=\"{}\"", fname))], s).into_response()
}

// ============================================================ Hysteria2 auth (local only, blocked at Caddy)

async fn hy2_auth(State(app): St, Json(b): Json<Value>) -> Response {
    let auth = b["auth"].as_str().unwrap_or("").to_string();
    let name = app.hy2_allowed.lock().unwrap().get(&auth).cloned();
    if let Some(n) = name {
        if sync::conn_allowed(&app, &n).await {
            return Json(json!({ "ok": true, "id": n })).into_response();
        }
    }
    Json(json!({ "ok": false })).into_response()
}

// ============================================================ node agent

fn node_authed(app: &App, h: &HeaderMap) -> bool {
    let t = h.get("X-Node-Token").and_then(|v| v.to_str().ok()).unwrap_or("");
    match app.env.get("NODE_TOKEN") {
        Some(want) if !want.is_empty() && !t.is_empty() => util::ct_eq(t, want),
        _ => false,
    }
}

async fn agent_info(State(app): St, h: HeaderMap) -> Response {
    if !node_authed(&app, &h) {
        return err(StatusCode::UNAUTHORIZED, "bad token");
    }
    Json(sync::local_info(&app)).into_response()
}

async fn agent_sync(State(app): St, h: HeaderMap, Json(req): Json<SyncReq>) -> Response {
    if !node_authed(&app, &h) {
        return err(StatusCode::UNAUTHORIZED, "bad token");
    }
    Json(sync::apply_local(&app, req).await).into_response()
}

async fn agent_repair(State(app): St, h: HeaderMap) -> Response {
    if !node_authed(&app, &h) {
        return err(StatusCode::UNAUTHORIZED, "bad token");
    }
    Json(crate::admin::repair_services()).into_response()
}

async fn agent_ports(State(app): St, h: HeaderMap, Json(b): Json<Value>) -> Response {
    if !node_authed(&app, &h) {
        return err(StatusCode::UNAUTHORIZED, "bad token");
    }
    Json(crate::admin::set_ports(&b)).into_response()
}

/// The panel deleted this node: everything the node runs is removed (just after this answer)
async fn agent_remove(State(app): St, h: HeaderMap) -> Response {
    if !node_authed(&app, &h) {
        return err(StatusCode::UNAUTHORIZED, "bad token");
    }
    std::thread::spawn(crate::admin::remove_node);
    Json(json!({"ok": true})).into_response()
}

/// The panel asks this node to run the server agent too (tunnels, Xray, Kanki DNS on the same machine)
async fn agent_setup_tunnel(State(app): St, h: HeaderMap, Json(b): Json<Value>) -> Response {
    if !node_authed(&app, &h) {
        return err(StatusCode::UNAUTHORIZED, "bad token");
    }
    let (panel, id, token) = (b["panel"].as_str().unwrap_or(""), b["id"].as_str().unwrap_or(""), b["token"].as_str().unwrap_or(""));
    let insecure = b["insecure"].as_bool().unwrap_or(false);
    let r = tokio::task::spawn_blocking({
        let (p, i, t) = (panel.to_string(), id.to_string(), token.to_string());
        move || crate::admin::setup_tunnel_agent(&p, &i, &t, insecure)
    })
    .await
    .unwrap_or(Err("setup crashed".into()));
    match r {
        Ok(()) => Json(json!({"ok": true})).into_response(),
        Err(e) => Json(json!({"ok": false, "error": e})).into_response(),
    }
}

async fn agent_update(State(app): St, h: HeaderMap) -> Response {
    if !node_authed(&app, &h) {
        return err(StatusCode::UNAUTHORIZED, "bad token");
    }
    match crate::admin::self_update(&app).await {
        Ok(v) => {
            // the tunnel agent of this machine (when there is one) runs the same file: restart it onto the new one
            let _ = std::process::Command::new("systemctl").args(["restart", "kanki-tunnel"]).spawn();
            Json(json!({"ok": true, "version": v})).into_response()
        }
        Err(e) => Json(json!({"ok": false, "error": e})).into_response(),
    }
}
