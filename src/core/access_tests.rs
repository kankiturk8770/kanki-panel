//! Server roles, user tiers and the «give everyone» guard, through the real HTTP API (auth included).
use crate::access::{Role, Tier};
use crate::App;
use axum::http::{Method, Request, StatusCode};
use serde_json::{json, Value};
use std::sync::Arc;
use tower::ServiceExt;

/// A node that answers nothing (its syncs fail at once), with every VPN core reported installed
fn add_node(app: &App, id: &str) {
    let info = r#"{"wg_pub":"k","wg_port":"51820","awg_pub":"k","awg_port":"51821","hy2_port":"8443"}"#;
    app.db
        .exec("INSERT INTO nodes(id,name,address,endpoint,token,endpoint_mode,info) VALUES(?1,?1,'https://127.0.0.1:9','','t','panel',?2)", &[&id, &info])
        .unwrap();
}

fn token(app: &App, scopes: &str) -> String {
    let t = format!("tok-{}", crate::util::rand_token(20));
    app.db
        .exec("INSERT INTO api_tokens(name,hash,prefix,scopes,created,last_used,expires) VALUES('t',?1,'tok',?2,0,0,?3)", &[&crate::util::sha256_hex(&t), &scopes, &(crate::util::now() + 3600)])
        .unwrap();
    format!("Bearer {}", t)
}

async fn call(app: &Arc<App>, m: Method, uri: &str, auth: Option<&str>, body: Option<Value>) -> (StatusCode, Value) {
    let mut r = Request::builder().method(m).uri(uri).header("content-type", "application/json");
    if let Some(a) = auth {
        r = r.header("authorization", a);
    }
    let b = body.map(|v| v.to_string()).unwrap_or_default();
    let res = crate::api::master_router(app.clone()).oneshot(r.body(axum::body::Body::from(b)).unwrap()).await.unwrap();
    let st = res.status();
    let bytes = axum::body::to_bytes(res.into_body(), 1 << 20).await.unwrap();
    (st, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

fn user(app: &App, name: &str, protos: &str, tier: Tier) -> i64 {
    let u = app.db.create_user(name, 10.0, 30, 1, protos, "", "", 0).unwrap();
    app.db.exec("UPDATE users SET tier=?1 WHERE id=?2", &[&tier.as_str(), &u.id]).unwrap();
    u.id
}

#[tokio::test]
async fn the_role_api_refuses_strangers_and_bad_input() {
    let app = crate::test_app();
    add_node(&app, "n1");
    let path = "/api/servers/node:n1/role";
    let (st, _) = call(&app, Method::POST, path, None, Some(json!({"role": "gaming"}))).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    let weak = token(&app, "users:read");
    let (st, _) = call(&app, Method::POST, path, Some(&weak), Some(json!({"role": "gaming"}))).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    let admin = token(&app, "nodes");
    for bad in [json!({"role": "root"}), json!({}), json!({"role": 7}), json!({"role": "gaming' OR '1'='1"})] {
        let (st, _) = call(&app, Method::POST, path, Some(&admin), Some(bad.clone())).await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{}", bad);
    }
    let (st, _) = call(&app, Method::POST, "/api/servers/node:ghost/role", Some(&admin), Some(json!({"role": "gaming"}))).await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    // nothing above changed the role
    assert_eq!(crate::access::node_role(&app, "n1"), Role::Hybrid);
    let (st, v) = call(&app, Method::POST, path, Some(&admin), Some(json!({"role": "gaming"}))).await;
    assert_eq!((st, v["role"].as_str()), (StatusCode::OK, Some("gaming")));
}

#[tokio::test]
async fn a_role_switches_off_what_it_does_not_run_and_hybrid_gives_it_back() {
    let app = crate::test_app();
    add_node(&app, "n1");
    let admin = token(&app, "nodes");
    let set_role = |r: &'static str| {
        let (app, admin) = (app.clone(), admin.clone());
        async move { call(&app, Method::POST, "/api/servers/node:n1/role", Some(&admin), Some(json!({ "role": r }))).await.0 }
    };
    let core = |c: &'static str, on: bool| {
        let (app, admin) = (app.clone(), admin.clone());
        async move { call(&app, Method::POST, "/api/servers/node:n1/core", Some(&admin), Some(json!({ "core": c, "on": on }))).await.0 }
    };
    let kmix = |on: bool| {
        let (app, admin) = (app.clone(), admin.clone());
        async move { call(&app, Method::POST, "/api/servers/node:n1/kmix", Some(&admin), Some(json!({ "on": on }))).await.0 }
    };
    let u = app.db.user(user(&app, "mixed", "wg,awg,hy2,kmix", Tier::Combo)).unwrap();
    let n = || app.db.node("n1").unwrap();
    assert!(crate::api::node_protos(&app, &u, &n()).contains(&"hysteria2"));

    // gaming: Hysteria2 off (no link either) and it cannot be switched on; AmneziaWG is a gaming core too
    assert_eq!(set_role("gaming").await, StatusCode::OK);
    assert_eq!(crate::cores::off_list(&app, "n1"), vec!["hy2"]);
    assert_eq!(core("hy2", true).await, StatusCode::CONFLICT);
    assert_eq!(core("awg", true).await, StatusCode::OK);
    assert_eq!(core("wg", true).await, StatusCode::OK);
    assert_eq!(kmix(true).await, StatusCode::OK);
    assert!(crate::kmix::settings(&app).node_on("n1"));
    let p = crate::api::node_protos(&app, &u, &n());
    assert!(!p.contains(&"hysteria2") && p.contains(&"amneziawg"), "{:?}", p);
    // the admin's own switch is not touched by the role (switching a core off is always allowed)
    assert_eq!(core("hy2", false).await, StatusCode::OK);
    assert_eq!(core("hy2", true).await, StatusCode::CONFLICT);
    assert!(crate::cores::load(&app).get("n1").map(|l| l.contains(&"hy2".to_string())).unwrap_or(false));

    // antifilter: WireGuard and KANKI MIX off
    assert_eq!(set_role("antifilter").await, StatusCode::OK);
    assert_eq!(crate::cores::off_list(&app, "n1"), vec!["hy2", "wg"]);
    assert_eq!(kmix(true).await, StatusCode::CONFLICT);
    assert!(!crate::kmix::settings(&app).node_on("n1"));
    // saving the KANKI MIX page meanwhile does not turn the role's «off» into the admin's own
    let (st, _) = call(&app, Method::PUT, "/api/kmix", Some(&admin), Some(json!({ "nodes": { "n1": { "off": true } } }))).await;
    assert_eq!(st, StatusCode::OK);
    let saved: Value = serde_json::from_str(&app.db.get("kmix_nodes")).unwrap_or(Value::Null);
    assert_ne!(saved["n1"]["off"].as_bool(), Some(true), "{}", saved);

    // hybrid again: only what the admin switched off stays off
    assert_eq!(set_role("hybrid").await, StatusCode::OK);
    assert_eq!(crate::cores::off_list(&app, "n1"), vec!["hy2"]);
    assert!(crate::kmix::settings(&app).node_on("n1"));
    assert_eq!(core("hy2", true).await, StatusCode::OK);
    assert!(crate::cores::off_list(&app, "n1").is_empty());
}

#[tokio::test]
async fn xray_and_dns_follow_the_role_of_their_machine() {
    let app = crate::test_app();
    add_node(&app, "local");
    add_node(&app, "n2");
    let mut list = crate::tunnel::panel::servers(&app);
    list.push(crate::tunnel::panel::TServer { id: "a2".into(), name: "NL".into(), node: "n2".into(), ..Default::default() });
    crate::tunnel::panel::save_servers(&app, &list);
    assert_eq!(crate::access::server_role(&app, "a2"), Role::Hybrid);
    let admin = token(&app, "nodes");
    let xs = crate::xray::panel::XraySettings {
        on: true,
        servers: vec![crate::xray::panel::XServer { server: "local".into(), address: "203.0.113.9".into(), ..Default::default() }],
        inbounds: vec![crate::xray::panel::Inbound {
            id: "ib1".into(), enabled: true, server: "local".into(), protocol: "vless".into(), port: 2096, network: "ws".into(),
            security: "none".into(), path: "/w".into(), ..Default::default()
        }],
        secret: "s".into(),
        ..Default::default()
    };
    app.db.set("xray_cfg", &serde_json::to_string(&xs).unwrap());
    let u = app.db.user(user(&app, "xr", "xray,hy2", Tier::V2ray)).unwrap();
    assert!(crate::xray::panel::cfg_for(&app, "local").is_some());
    assert_eq!(crate::xray::panel::user_links(&app, &u).len(), 1);

    app.db.exec("UPDATE nodes SET role='gaming' WHERE id='local'", &[]).unwrap();
    // a gaming machine runs no Xray: no config, no links, no new Xray server or inbound on it
    assert!(crate::xray::panel::cfg_for(&app, "local").is_none());
    assert!(crate::xray::panel::user_links(&app, &u).is_empty());
    let (st, _) = call(&app, Method::POST, "/api/xray/servers", Some(&admin), Some(json!({"server": "local", "address": "203.0.113.9"}))).await;
    assert_eq!(st, StatusCode::CONFLICT);
    let (st, _) = call(&app, Method::POST, "/api/xray/inbounds", Some(&admin),
        Some(json!({"server": "local", "protocol": "vless", "port": 2097, "network": "ws", "security": "none", "enabled": true}))).await;
    assert_eq!(st, StatusCode::CONFLICT);

    // an antifilter machine runs no Kanki DNS (its agent server is found through its VPN node)
    app.db.exec("UPDATE nodes SET role='antifilter' WHERE id='n2'", &[]).unwrap();
    assert_eq!(crate::access::server_role(&app, "a2"), Role::Antifilter);
    let (st, _) = call(&app, Method::POST, "/api/dns/servers", Some(&admin), Some(json!({"server": "a2", "role": "exit"}))).await;
    assert_eq!(st, StatusCode::CONFLICT);
    assert!(crate::dns::panel::cfg_for(&app, "a2").is_none());
}

#[tokio::test]
async fn give_everyone_only_reaches_the_tiers_that_have_the_core() {
    let app = crate::test_app();
    let v2 = user(&app, "vtwo", "xray,hy2", Tier::V2ray);
    let gm = user(&app, "gamer", "wg,awg", Tier::Gaming);
    let co = user(&app, "combo", "hy2", Tier::Combo);
    let (st, _) = call(&app, Method::POST, "/api/protocols/wg/assign-all", None, None).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    let weak = token(&app, "users:read");
    let (st, _) = call(&app, Method::POST, "/api/protocols/wg/assign-all", Some(&weak), None).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    let admin = token(&app, "users:write");
    let has = |id: i64, p: &str| app.db.user(id).unwrap().has_proto(p);

    let (st, v) = call(&app, Method::POST, "/api/protocols/kmix/assign-all", Some(&admin), None).await;
    assert_eq!((st, v["changed"].as_i64()), (StatusCode::OK, Some(2)));
    assert!(!has(v2, "kmix") && has(gm, "kmix") && has(co, "kmix"));
    call(&app, Method::POST, "/api/protocols/wg/assign-all", Some(&admin), None).await;
    assert!(!has(v2, "wg") && has(gm, "wg") && has(co, "wg"));
    call(&app, Method::POST, "/api/protocols/xray/assign-all", Some(&admin), None).await;
    assert!(has(v2, "xray") && !has(gm, "xray") && has(co, "xray"));
    call(&app, Method::POST, "/api/protocols/dns/assign-all", Some(&admin), None).await;
    assert!(!has(v2, "dns") && !has(gm, "dns") && has(co, "dns"));

    // the admin may still tick WireGuard on one V2Ray account by hand; its tier stays and keeps guarding
    let (st, v) = call(&app, Method::PUT, &format!("/api/users/{}", v2), Some(&admin), Some(json!({"protocols": "xray,hy2,wg"}))).await;
    assert_eq!((st, v["tier"].as_str()), (StatusCode::OK, Some("v2ray")));
    assert!(has(v2, "wg"));
    call(&app, Method::POST, "/api/protocols/awg/assign-all", Some(&admin), None).await;
    assert!(!has(v2, "awg"));
    // a bad tier is refused, a good one is kept
    let (st, _) = call(&app, Method::PUT, &format!("/api/users/{}", gm), Some(&admin), Some(json!({"tier": "admin"}))).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    let (st, _) = call(&app, Method::PUT, &format!("/api/users/{}", gm), Some(&admin), Some(json!({"tier": ["combo"]}))).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert_eq!(app.db.user(gm).unwrap().tier(), Tier::Gaming);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_give_everyone_never_crosses_a_tier() {
    let app = crate::test_app();
    let mut v2s = vec![];
    let mut gms = vec![];
    for i in 0..15 {
        v2s.push(user(&app, &format!("v{}", i), "xray", Tier::V2ray));
        gms.push(user(&app, &format!("g{}", i), "wg", Tier::Gaming));
    }
    let admin = token(&app, "users:write");
    let mut tasks = vec![];
    for (round, id) in v2s.iter().copied().enumerate().take(4) {
        for p in ["wg", "awg", "kmix", "xray", "hy2", "dns"] {
            let (app, admin) = (app.clone(), admin.clone());
            tasks.push(tokio::spawn(async move {
                let act = if round % 2 == 0 { "assign-all" } else { "unassign-all" };
                call(&app, Method::POST, &format!("/api/protocols/{}/{}", p, act), Some(&admin), None).await.0
            }));
        }
        // edits of single users at the same time
        let (app2, admin2) = (app.clone(), admin.clone());
        tasks.push(tokio::spawn(async move { call(&app2, Method::PUT, &format!("/api/users/{}", id), Some(&admin2), Some(json!({"notes": "busy"}))).await.0 }));
    }
    for t in tasks {
        assert_eq!(t.await.unwrap(), StatusCode::OK);
    }
    call(&app, Method::POST, "/api/protocols/wg/assign-all", Some(&admin), None).await;
    call(&app, Method::POST, "/api/protocols/xray/assign-all", Some(&admin), None).await;
    for id in &v2s {
        let u = app.db.user(*id).unwrap();
        assert!(["wg", "awg", "kmix", "dns"].iter().all(|p| !u.has_proto(p)), "{}: {}", u.username, u.protocols);
        assert_eq!(u.tier(), Tier::V2ray);
    }
    for id in &gms {
        let u = app.db.user(*id).unwrap();
        assert!(["xray", "hy2", "dns"].iter().all(|p| !u.has_proto(p)), "{}: {}", u.username, u.protocols);
        assert!(u.has_proto("wg"));
    }
}

#[tokio::test]
async fn new_users_take_the_protocols_of_their_tier() {
    let app = crate::test_app();
    let admin = token(&app, "users:write");
    let (st, v) = call(&app, Method::POST, "/api/users", Some(&admin), Some(json!({"username": "vonly", "tier": "v2ray"}))).await;
    assert_eq!(st, StatusCode::OK, "{}", v);
    assert_eq!((v[0]["protocols"].as_str(), v[0]["tier"].as_str()), (Some("xray,hy2"), Some("v2ray")));
    let (st, v) = call(&app, Method::POST, "/api/users", Some(&admin), Some(json!({"username": "gonly", "tier": "gaming"}))).await;
    assert_eq!((st, v[0]["protocols"].as_str(), v[0]["tier"].as_str()), (StatusCode::OK, Some("wg,awg,kmix"), Some("gaming")));
    // no tier: the panel's default list, and the tier it makes
    let (_, v) = call(&app, Method::POST, "/api/users", Some(&admin), Some(json!({"username": "plain"}))).await;
    assert_eq!(v[0]["tier"].as_str(), Some("combo"));
    let before = app.db.users().len();
    let (st, _) = call(&app, Method::POST, "/api/users", Some(&admin), Some(json!({"username": "bad", "tier": "everything"}))).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert_eq!(app.db.users().len(), before);
}

#[test]
fn an_old_database_gets_roles_and_tiers_without_losing_a_service() {
    let dir = std::env::temp_dir().join(format!("kanki-mig-{}", crate::util::rand_token(8)));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("kanki.db");
    {
        // the tables as a panel before 3.64 had them
        let c = rusqlite::Connection::open(&path).unwrap();
        c.execute_batch(
            "CREATE TABLE users(id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, code TEXT, limit_gb REAL DEFAULT 0,
                used_bytes INTEGER DEFAULT 0, expires_at INTEGER DEFAULT 0, max_conn INTEGER DEFAULT 1, enabled INTEGER DEFAULT 1,
                protocols TEXT DEFAULT 'wg,awg,hy2', nodes TEXT DEFAULT '', notes TEXT DEFAULT '', tg_id INTEGER DEFAULT 0,
                created_at INTEGER DEFAULT 0, last_seen INTEGER DEFAULT 0, online INTEGER DEFAULT 0, warned INTEGER DEFAULT 0);
             CREATE TABLE nodes(id TEXT PRIMARY KEY, name TEXT, address TEXT, endpoint TEXT, token TEXT,
                enabled INTEGER DEFAULT 1, online INTEGER DEFAULT 0, last_sync INTEGER DEFAULT 0, info TEXT DEFAULT '{}');
             INSERT INTO users(username,code,protocols) VALUES('a','1','xray,hy2'),('b','2','wg,awg,kmix'),('c','3','wg,awg,hy2,kmix'),('d','4','');
             INSERT INTO nodes(id,name,address,endpoint,token) VALUES('n1','DE','https://x','','t');
             CREATE TABLE settings(k TEXT PRIMARY KEY, v TEXT);
             INSERT INTO settings VALUES('emer_sign','private key'),('emer_admin','hash'),('emerald','kept');",
        )
        .unwrap();
    }
    let by_name = |db: &crate::db::Db| {
        let mut v = db.users();
        v.sort_by(|a, b| a.username.cmp(&b.username));
        v
    };
    let tiers = |db: &crate::db::Db| by_name(db).iter().map(|u| (u.username.clone(), u.tier_raw.clone())).collect::<Vec<_>>();
    let db = crate::db::Db::open(path.to_str().unwrap());
    let want = vec![("a".to_string(), "v2ray".to_string()), ("b".into(), "gaming".into()), ("c".into(), "combo".into()), ("d".into(), "combo".into())];
    assert_eq!(tiers(&db), want);
    assert_eq!(db.node("n1").unwrap().role(), Role::Hybrid);
    // the emergency chat's secrets are gone (3.65); other settings stay
    assert_eq!(db.get("emer_sign"), "");
    assert_eq!(db.get("emer_admin"), "");
    assert_eq!(db.get("emerald"), "kept");
    // nobody lost a protocol, and a second start changes nothing
    assert_eq!(by_name(&db).iter().map(|u| u.protocols.clone()).collect::<Vec<_>>(), vec!["xray,hy2", "wg,awg,kmix", "wg,awg,hy2,kmix", ""]);
    db.exec("UPDATE users SET tier='combo' WHERE username='a'", &[]).unwrap();
    drop(db);
    let db = crate::db::Db::open(path.to_str().unwrap());
    assert_eq!(by_name(&db)[0].tier(), Tier::Combo);
}

/// GET `uri`: status, headers, body
async fn get_raw(app: &Arc<App>, uri: &str) -> (StatusCode, axum::http::HeaderMap, String) {
    let r = Request::get(uri).header("user-agent", "v2rayNG/1.9").body(axum::body::Body::empty()).unwrap();
    let res = crate::api::master_router(app.clone()).oneshot(r).await.unwrap();
    let (st, h) = (res.status(), res.headers().clone());
    let b = axum::body::to_bytes(res.into_body(), 1 << 20).await.unwrap();
    (st, h, String::from_utf8_lossy(&b).to_string())
}

fn lines_of(body: &str) -> Vec<String> {
    let raw = crate::tunnel::link::b64decode(body.trim()).unwrap_or_default();
    String::from_utf8(raw).unwrap().lines().filter(|l| !l.is_empty()).map(|l| l.to_string()).collect()
}

fn with_xray(app: &App) {
    let xs = crate::xray::panel::XraySettings {
        on: true,
        servers: vec![crate::xray::panel::XServer { server: "local".into(), address: "203.0.113.9".into(), ..Default::default() }],
        inbounds: vec![crate::xray::panel::Inbound {
            id: "ib1".into(), remark: "DE".into(), enabled: true, server: "local".into(), protocol: "vless".into(), port: 2096,
            network: "ws".into(), security: "none".into(), path: "/w".into(), ..Default::default()
        }],
        secret: "s".into(),
        ..Default::default()
    };
    app.db.set("xray_cfg", &serde_json::to_string(&xs).unwrap());
}

#[tokio::test]
async fn the_sub_link_starts_with_the_live_status_and_keeps_the_app_headers() {
    let app = crate::test_app();
    with_xray(&app);
    app.db.set("panel_name", "Test Panel");
    let id = user(&app, "nima", "xray,hy2", Tier::V2ray);
    app.db.exec("UPDATE users SET used_bytes=?1 WHERE id=?2", &[&(4_831_838_208i64), &id]).unwrap(); // 4.5 GB
    let u = app.db.user(id).unwrap();
    let (st, h, body) = get_raw(&app, &format!("/sub/{}/v2", u.sub_code())).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(h["subscription-userinfo"], format!("upload=0; download=4831838208; total=10737418240; expire={}", u.expires_at).as_str());
    let title = h["profile-title"].to_str().unwrap().strip_prefix("base64:").unwrap().to_string();
    assert_eq!(String::from_utf8(crate::tunnel::link::b64decode(&title).unwrap()).unwrap(), "Test Panel · nima");
    let lines = lines_of(&body);
    assert_eq!(lines.len(), 2, "{:?}", lines);
    assert!(lines[0].starts_with("vless://00000000-0000-0000-0000-000000000000@127.0.0.1:1?"), "{}", lines[0]);
    assert_eq!(crate::util::pct_decode(lines[0].rsplit_once('#').unwrap().1), "📊 5.50 GB left · ⏳ 30 days");
    assert!(lines[1].contains("@203.0.113.9:2096"), "{}", lines[1]);
    // the other base64 subscriptions start with it too
    for p in ["xray", "raw"] {
        let (_, _, b) = get_raw(&app, &format!("/sub/{}/{}", u.sub_code(), p)).await;
        assert!(lines_of(&b)[0].contains("127.0.0.1:1?"), "{}", p);
    }
    // full client configs of the same links
    let (st, h, body) = get_raw(&app, &format!("/sub/{}/xjson", u.sub_code())).await;
    assert_eq!(st, StatusCode::OK);
    assert!(h.contains_key("subscription-userinfo"));
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v[0]["outbounds"][0]["settings"]["vnext"][0]["address"], "203.0.113.9");
}

#[tokio::test]
async fn the_sub_link_shows_only_what_the_account_has() {
    let app = crate::test_app();
    with_xray(&app);
    // gaming only: no Xray, no Hysteria2, so no status entry and no line at all
    let g = app.db.user(user(&app, "gamer", "wg,awg,kmix", Tier::Gaming)).unwrap();
    let (st, _, body) = get_raw(&app, &format!("/sub/{}/v2", g.sub_code())).await;
    assert_eq!(st, StatusCode::OK);
    assert!(lines_of(&body).is_empty(), "{:?}", lines_of(&body));
    // a frozen account: only the status entry (it says why), no working config
    let f = user(&app, "frozen", "xray", Tier::V2ray);
    app.db.exec("UPDATE users SET enabled=0 WHERE id=?1", &[&f]).unwrap();
    let f = app.db.user(f).unwrap();
    let (_, _, body) = get_raw(&app, &format!("/sub/{}/v2", f.sub_code())).await;
    let l = lines_of(&body);
    assert_eq!(l.len(), 1, "{:?}", l);
    assert!(crate::util::pct_decode(l[0].rsplit_once('#').unwrap().1).starts_with("⛔ Disabled"));
    // no limits: infinity, not zero
    let free = user(&app, "free", "xray", Tier::V2ray);
    app.db.exec("UPDATE users SET limit_gb=0, expires_at=0 WHERE id=?1", &[&free]).unwrap();
    assert_eq!(crate::api::status_name(&app.db.user(free).unwrap(), crate::util::now()), "📊 ∞ left · ⏳ ∞ days");
    // a wrong code or another user's number with this code: nothing
    let (st, _, _) = get_raw(&app, &format!("/sub/kanki-{}-{}/v2", g.id, f.code)).await;
    assert_ne!(st, StatusCode::OK);
    let (st, _, _) = get_raw(&app, "/sub/kanki-1-%27%20OR%201=1/v2").await;
    assert_ne!(st, StatusCode::OK);
}

#[tokio::test]
async fn one_switch_per_core_on_each_server() {
    let app = crate::test_app();
    add_node(&app, "local");
    add_node(&app, "n2");
    let mut list = crate::tunnel::panel::servers(&app);
    list.push(crate::tunnel::panel::TServer { id: "a2".into(), name: "NL".into(), node: "n2".into(), ..Default::default() });
    crate::tunnel::panel::save_servers(&app, &list);
    let admin = token(&app, "nodes");
    let set = |key: &'static str, b: Value| {
        let (app, admin) = (app.clone(), admin.clone());
        async move { call(&app, Method::POST, &format!("/api/servers/{}/cores", key), Some(&admin), Some(b)).await }
    };
    // strangers and bad input change nothing
    let (st, _) = call(&app, Method::POST, "/api/servers/a2/cores", None, Some(json!({"wg": false}))).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    let weak = token(&app, "users:write");
    let (st, _) = call(&app, Method::POST, "/api/servers/a2/cores", Some(&weak), Some(json!({"wg": false}))).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    for bad in [json!({"wg": "yes"}), json!({"openvpn": true}), json!([true]), json!({"wg": 1})] {
        assert_eq!(set("a2", bad.clone()).await.0, StatusCode::BAD_REQUEST, "{}", bad);
    }
    assert_eq!(set("ghost", json!({"wg": true})).await.0, StatusCode::NOT_FOUND);
    // every core on a hybrid server: Xray and DNS get their entries with nothing typed
    let (st, v) = set("a2", json!({"wg": true, "awg": true, "kmix": true, "dns": true, "xray": true, "hy2": true})).await;
    assert_eq!(st, StatusCode::OK, "{}", v);
    for c in ["wg", "awg", "kmix", "dns", "xray", "hy2"] {
        assert_eq!(v["state"]["cores"][c]["on"], true, "{}: {}", c, v);
    }
    assert!(crate::xray::panel::has_server(&app, "a2") && crate::dns::panel::has_server(&app, "a2"));
    // Xray off keeps its server entry and inbounds; it just stops (no config for the agent)
    let mut xs = crate::xray::panel::settings(&app);
    xs.on = true;
    xs.inbounds.push(crate::xray::panel::Inbound { id: "i2".into(), enabled: true, server: "a2".into(), protocol: "vless".into(), port: 2096, network: "ws".into(), security: "none".into(), ..Default::default() });
    app.db.set("xray_cfg", &serde_json::to_string(&xs).unwrap());
    assert!(crate::xray::panel::cfg_for(&app, "a2").is_some());
    let (st, v) = set("a2", json!({"xray": false, "dns": false, "hy2": false})).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!((v["state"]["cores"]["xray"]["on"].as_bool(), v["state"]["cores"]["hy2"]["on"].as_bool()), (Some(false), Some(false)));
    assert!(crate::xray::panel::cfg_for(&app, "a2").is_none() && crate::dns::panel::cfg_for(&app, "a2").is_none());
    assert_eq!(crate::xray::panel::settings(&app).inbounds.len(), 1);
    assert!(crate::cores::is_off(&app, "n2", "hy2"));
    let (_, v) = set("a2", json!({"xray": true})).await;
    assert_eq!(v["state"]["cores"]["xray"]["on"], true);
    assert!(crate::xray::panel::cfg_for(&app, "a2").is_some());
    // a role still has the last word: nothing changes when one asked core is not allowed
    app.db.exec("UPDATE nodes SET role='gaming' WHERE id='n2'", &[]).unwrap();
    let (st, _) = set("a2", json!({"wg": false, "hy2": true})).await;
    assert_eq!(st, StatusCode::CONFLICT);
    assert!(!crate::cores::is_off(&app, "n2", "wg"));
    // a server without its VPN part (3.65): a VPN core switched on installs it, which needs its agent
    // connected; this one never reported, so it is refused and nothing is asked
    let mut list = crate::tunnel::panel::servers(&app);
    list.push(crate::tunnel::panel::TServer { id: "a3".into(), name: "IR".into(), ..Default::default() });
    crate::tunnel::panel::save_servers(&app, &list);
    assert_eq!(set("a3", json!({"wg": true})).await.0, StatusCode::CONFLICT);
    assert_eq!(set("a3", json!({"xray": true})).await.0, StatusCode::OK);
    // the servers list carries every switch
    let (_, l) = call(&app, Method::GET, "/api/servers", Some(&admin), None).await;
    let a3 = l["servers"].as_array().unwrap().iter().find(|s| s["key"] == "a3").unwrap().clone();
    assert_eq!((a3["switches"]["cores"]["xray"]["on"].as_bool(), a3["switches"]["cores"]["wg"]["can"].as_bool()), (Some(true), Some(true)));
    assert_eq!((a3["switches"]["cores"]["wg"]["on"].as_bool(), a3["switches"]["vpn_part"].as_bool()), (Some(false), Some(false)));
}

/// 3.65: a server inside Iran without its VPN part has the same six switches as one abroad: a VPN core
/// switched on asks its agent to install the VPN part, and starts when it joins
#[tokio::test]
async fn an_iran_server_switches_on_vpn_cores_like_one_abroad() {
    let app = crate::test_app();
    let mut list = crate::tunnel::panel::servers(&app);
    list.push(crate::tunnel::panel::TServer { id: "ir65".into(), name: "Tehran".into(), loc: "iran".into(), token: "t".repeat(40), ..Default::default() });
    crate::tunnel::panel::save_servers(&app, &list);
    let admin = token(&app, "nodes");
    // strangers and a weak token change nothing
    let (st, _) = call(&app, Method::POST, "/api/servers/ir65/cores", None, Some(json!({"wg": true}))).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    let weak = token(&app, "users:write");
    let (st, _) = call(&app, Method::POST, "/api/servers/ir65/cores", Some(&weak), Some(json!({"wg": true}))).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    // the agent is not connected: refused, nothing asked
    let (st, _) = call(&app, Method::POST, "/api/servers/ir65/cores", Some(&admin), Some(json!({"wg": true}))).await;
    assert_eq!(st, StatusCode::CONFLICT);
    assert!(crate::tunnel::panel::servers(&app).iter().any(|s| s.id == "ir65" && s.join.is_empty() && s.cores.is_empty()));
    // every switch can be flipped, the VPN ones too
    let st0 = crate::servers::cores_state(&app, "ir65");
    for c in ["wg", "awg", "kmix", "dns", "xray", "hy2"] {
        assert_eq!(st0["cores"][c]["can"], true, "{}: {}", c, st0);
    }
    crate::tunnel::panel::test_seen("ir65", crate::VERSION);
    // two switches flipped at the same time: both are asked for, one install
    let (a, b) = tokio::join!(
        call(&app, Method::POST, "/api/servers/ir65/cores", Some(&admin), Some(json!({"wg": true}))),
        call(&app, Method::POST, "/api/servers/ir65/cores", Some(&admin), Some(json!({"kmix": true}))),
    );
    assert_eq!((a.0, b.0), (StatusCode::OK, StatusCode::OK), "{} {}", a.1, b.1);
    let s = crate::tunnel::panel::servers(&app).into_iter().find(|s| s.id == "ir65").unwrap();
    assert_eq!(s.cores, vec!["wg".to_string(), "kmix".to_string()]);
    assert!(s.vpn && s.setup_at > 0 && s.join.len() == 40 && s.ports.len() == 4);
    let st1 = crate::servers::cores_state(&app, "ir65");
    assert_eq!((st1["installing"].as_bool(), st1["cores"]["wg"]["on"].as_bool(), st1["cores"]["awg"]["on"].as_bool()), (Some(true), Some(true), Some(false)));
    // one switched off again before it joins: it does not start
    let (st, _) = call(&app, Method::POST, "/api/servers/ir65/cores", Some(&admin), Some(json!({"wg": false}))).await;
    assert_eq!(st, StatusCode::OK);
    let s = crate::tunnel::panel::servers(&app).into_iter().find(|s| s.id == "ir65").unwrap();
    assert_eq!(s.cores, vec!["kmix".to_string()]);
    // the same join token: the running install was not asked twice
    assert_eq!(s.join.len(), 40);
}

/// GET `uri` with extra headers: status, headers, body
async fn get_with(app: &Arc<App>, uri: &str, hs: &[(&str, &str)]) -> (StatusCode, axum::http::HeaderMap, String) {
    let mut r = Request::get(uri).header("user-agent", "v2rayNG/1.9");
    for (k, v) in hs {
        r = r.header(*k, *v);
    }
    let res = crate::api::master_router(app.clone()).oneshot(r.body(axum::body::Body::empty()).unwrap()).await.unwrap();
    let (st, h) = (res.status(), res.headers().clone());
    let b = axum::body::to_bytes(res.into_body(), 1 << 20).await.unwrap();
    (st, h, String::from_utf8_lossy(&b).to_string())
}

/// 3.65: the same subscription without the code in the URL: a hashed link (the one the panel hands out) and
/// the code in a header; wrong hashes, codes and kinds get the plain miss answer
#[tokio::test]
async fn the_subscription_works_without_its_code_in_the_url() {
    let app = crate::test_app();
    with_xray(&app);
    let id = user(&app, "hashuser", "xray,hy2", Tier::V2ray);
    let other = user(&app, "hashother", "xray,hy2", Tier::V2ray);
    let u = app.db.user(id).unwrap();
    let (st, _, by_code) = get_raw(&app, &format!("/sub/{}/v2", u.sub_code())).await;
    assert_eq!(st, StatusCode::OK);
    // the link the panel gives: no code in it, the same lines
    let link = crate::api::v2_sub_link(&app, &u);
    assert!(!link.contains(&u.code) && link.contains("/sub/h/"), "{}", link);
    let path = &link[link.find("/sub/h/").unwrap()..];
    let (st, h, body) = get_raw(&app, path).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(lines_of(&body), lines_of(&by_code));
    assert_eq!((h["cache-control"].to_str().unwrap(), h["referrer-policy"].to_str().unwrap()), ("no-store", "no-referrer"));
    assert!(h.contains_key("subscription-userinfo"));
    // the code in a header, nothing in the URL
    for hs in [[("x-kanki-sub", u.sub_code())], [("authorization", format!("Bearer {}", u.sub_code()))]] {
        let (st, _, body) = get_with(&app, "/sub/me/v2", &[(hs[0].0, hs[0].1.as_str())]).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(lines_of(&body), lines_of(&by_code));
    }
    // the hash of one account never opens another; a guessed hash, a wrong code, no header, an unknown kind:
    // the same plain 404
    let o = app.db.user(other).unwrap();
    let oh = crate::sublink::hash_of(&app, &o);
    let (_, _, ob) = get_raw(&app, &format!("/sub/h/{}/v2", oh)).await;
    assert_ne!(lines_of(&ob), lines_of(&by_code));
    let wrong_code = format!("kanki-{}-0000000000000000000", u.id);
    for (uri, hs) in [
        (format!("/sub/h/{}/v2", "0".repeat(40)), vec![]),
        (format!("/sub/h/{}/v2", &oh[..39]), vec![]),
        (format!("{}/admin", path.trim_end_matches("/v2")), vec![]),
        ("/sub/me/v2".to_string(), vec![]),
        ("/sub/me/v2".to_string(), vec![("x-kanki-sub", wrong_code.as_str())]),
        ("/sub/me/v2".to_string(), vec![("x-kanki-sub", "kanki-1-x/../../api")]),
    ] {
        let (st, _, _) = get_with(&app, &uri, &hs).await;
        assert_eq!(st, StatusCode::NOT_FOUND, "{} {:?}", uri, hs);
    }
    // a new code: the old hashed link stops at once
    app.db.exec("UPDATE users SET code='9999999999999999999' WHERE id=?1", &[&id]).unwrap();
    let (st, _, _) = get_raw(&app, path).await;
    assert_eq!(st, StatusCode::NOT_FOUND);
}

/// 3.65: the four presets of the Xray inbound window, as the window sends them, are taken as they are;
/// the TLS fragment of the Trojan preset reaches the links and the full client configs, and never stays on
/// an inbound without TLS
#[tokio::test]
async fn the_four_xray_presets_save_and_the_fragment_reaches_the_clients() {
    let app = crate::test_app();
    let xs = crate::xray::panel::XraySettings {
        on: true,
        servers: vec![crate::xray::panel::XServer { server: "local".into(), address: "srv.example.net".into(), ssl: true, ..Default::default() }],
        secret: "s".into(),
        ..Default::default()
    };
    app.db.set("xray_cfg", &serde_json::to_string(&xs).unwrap());
    let admin = token(&app, "nodes");
    let presets = [
        // REALITY: the target and its names are the admin's to type (no domain is put in for them)
        json!({"remark": "reality", "enabled": true, "server": "local", "protocol": "vless", "port": 21443, "network": "tcp", "security": "reality", "flow": "xtls-rprx-vision", "fp": "chrome", "dest": "", "names": ""}),
        json!({"remark": "cdn", "enabled": true, "server": "local", "protocol": "vless", "port": 21444, "network": "xhttp", "security": "tls", "acme": true, "mode": "auto", "path": "/xh", "fp": "chrome", "alpn": "h2,http/1.1"}),
        json!({"remark": "iran-tunnel", "enabled": true, "server": "local", "protocol": "vless", "port": 21445, "network": "xhttp", "security": "none", "mode": "auto", "path": "/t"}),
        json!({"remark": "trojan-pro", "enabled": true, "server": "local", "protocol": "trojan", "port": 21446, "network": "grpc", "security": "tls", "acme": true, "service": "tg", "fp": "chrome", "fragment": true}),
    ];
    // a stranger and a weak token cannot add one
    let (st, _) = call(&app, Method::POST, "/api/xray/inbounds", None, Some(presets[2].clone())).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    // REALITY without its target is refused (the window marks the two fields); with them it is taken
    let (st, v) = call(&app, Method::POST, "/api/xray/inbounds", Some(&admin), Some(presets[0].clone())).await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "{}", v);
    let mut reality = presets[0].clone();
    reality["dest"] = json!("target.example.org:443");
    reality["names"] = json!("target.example.org");
    reality["fragment"] = json!(true);
    for b in [reality, presets[1].clone(), presets[2].clone(), presets[3].clone()] {
        let (st, v) = call(&app, Method::POST, "/api/xray/inbounds", Some(&admin), Some(b.clone())).await;
        assert_eq!(st, StatusCode::OK, "{}: {}", b["remark"], v);
    }
    let s = crate::xray::panel::settings(&app);
    let by = |r: &str| s.inbounds.iter().find(|i| i.remark == r).cloned().unwrap();
    let r = by("reality");
    assert_eq!((r.flow.as_str(), r.fp.as_str(), r.network.as_str(), r.fragment), ("xtls-rprx-vision", "chrome", "tcp", false));
    assert!(!r.private.is_empty() && !r.public.is_empty() && !r.short_ids.is_empty());
    let c = by("cdn");
    assert!(c.acme && c.network == "xhttp" && c.security == "tls");
    let t = by("iran-tunnel");
    assert_eq!((t.security.as_str(), t.mode.as_str()), ("none", "auto"));
    let tp = by("trojan-pro");
    assert!(tp.fragment && tp.security == "tls");
    // the links and the client configs of a user
    let id = user(&app, "presetuser", "xray", Tier::V2ray);
    let u = app.db.user(id).unwrap();
    let links = crate::xray::panel::user_links(&app, &u);
    let tl = links.iter().find(|l| l.1.starts_with("trojan://")).map(|l| l.1.clone()).unwrap_or_else(|| panic!("{:?}", links));
    assert!(tl.contains("fragment=tlshello,100-200,10-20") && tl.contains("type=grpc") && tl.contains("security=tls"), "{}", tl);
    assert!(links.iter().filter(|l| !l.1.starts_with("trojan://")).all(|l| !l.1.contains("fragment=")), "{:?}", links);
    let rl = links.iter().find(|l| l.1.contains("security=reality")).map(|l| l.1.clone()).unwrap();
    assert!(rl.contains("flow=xtls-rprx-vision") && rl.contains("fp=chrome"), "{}", rl);
    let cfg = crate::xray::panel::client_config(&app, "t", &tl).unwrap();
    let outs = cfg["outbounds"].as_array().unwrap();
    let frag = outs.iter().find(|o| o["tag"] == "fragment").expect("a fragment outbound");
    assert_eq!(frag["settings"]["fragment"], json!({"packets": "tlshello", "length": "100-200", "interval": "10-20"}));
    assert_eq!(outs[0]["streamSettings"]["sockopt"]["dialerProxy"], "fragment");
    // a link without it gets no fragment outbound; a malformed fragment is not copied into a config
    let plain = crate::xray::panel::client_config(&app, "r", &rl).unwrap();
    assert!(plain["outbounds"].as_array().unwrap().iter().all(|o| o["tag"] != "fragment"));
    let bad = tl.replace("fragment=tlshello,100-200,10-20", "fragment=tlshello,1;rm,1");
    let c2 = crate::xray::panel::client_config(&app, "b", &bad).unwrap();
    assert!(c2["outbounds"].as_array().unwrap().iter().all(|o| o["tag"] != "fragment"));
}

/// 3.67: KANKI MIX's links carry no FEC unless the admin sets it (fec=10-0, which every app reads as «no
/// parity»), the server keeps the old parity for links still on phones, and every Iran server whose tunnel carries
/// the port is a separate entry the user can pick (the first one stays the `@tunnel` entry of before)
#[tokio::test]
async fn kmix_links_have_no_fec_and_one_entry_per_iran_tunnel() {
    let app = crate::test_app();
    let info = r#"{"kmix_port":4000}"#;
    app.db.exec("INSERT INTO nodes(id,name,address,endpoint,token,endpoint_mode,info) VALUES('n1','Germany','https://de.example.net:9','de.example.net','t','panel',?1)", &[&info]).unwrap();
    let mut list = crate::tunnel::panel::servers(&app);
    for (id, name, addr, node) in [("kde", "DE", "de.example.net", "n1"), ("kir1", "Tehran", "ir1.example.net", ""), ("kir2", "Shiraz", "ir2.example.net", "")] {
        list.push(crate::tunnel::panel::TServer { id: id.into(), name: name.into(), addr: addr.into(), node: node.into(), ..Default::default() });
        crate::tunnel::panel::test_seen(id, crate::VERSION);
    }
    crate::tunnel::panel::save_servers(&app, &list);
    let t1 = crate::tunnel::panel::Tunnel { id: "t1".into(), entry: "kir1".into(), exit: "kde".into(), enabled: true, udp: vec!["4000".into()], ..Default::default() };
    let t2 = crate::tunnel::panel::Tunnel { id: "t2".into(), entry: "kir2".into(), exit: "kde".into(), enabled: true, udp: vec!["4100:4000".into()], ..Default::default() };
    crate::tunnel::panel::save_tunnels(&app, &[t1, t2]);
    let u = app.db.create_user("mixer", 10.0, 30, 1, "kmix", "", "", 0).unwrap();
    let n = app.db.node("n1").unwrap();
    // no FEC by default, in a form every app reads (fec=0 alone would be read as 10-3); the server is told the old
    // parity for links already on phones
    let direct = crate::kmix::link(&app, &u, &n).unwrap();
    assert!(direct.contains("fec=10-0") && !direct.contains("fec=10-3"), "{}", direct);
    let s = crate::kmix::settings(&app);
    let cfg = crate::kmix::cfg_for(&app, &s, &n, &[&u]);
    assert_eq!((cfg.parity, cfg.legacy_parity), (0, 3));
    // both Iran entries are other paths of the direct config
    let alt = crate::util::pct("ir1.example.net:4000,ir2.example.net:4100");
    assert!(direct.contains(&format!("alt={}", alt)), "{}", direct);
    // the first Iran entry is the `@tunnel` entry as before, the second its own entry
    assert!(crate::kmix::link_tunnel(&app, &u, &n).unwrap().contains("@ir1.example.net:4000?"));
    let extra = crate::kmix::link_tunnels(&app, &u, &n);
    assert_eq!(extra.len(), 1, "{:?}", extra);
    assert_eq!(extra[0].0, "n1~2@tunnel");
    assert!(extra[0].1.contains("Shiraz") && extra[0].2.contains("@ir2.example.net:4100?") && extra[0].2.contains("via=tunnel"), "{:?}", extra);
    // the Kanki app downloads it by its entry id; another protocol has no second Iran entry
    let base = format!("/api/config/{}/kankimix?sub={}&node=", u.id, u.code);
    let (st, body) = get_text(&app, &format!("{}n1~2%40tunnel", base)).await;
    assert_eq!(st, StatusCode::OK);
    assert!(body.contains("@ir2.example.net:4100?"), "{}", body);
    let (st, _) = get_text(&app, &format!("/api/config/{}/wireguard?sub={}&node=n1~2%40tunnel", u.id, u.code)).await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    // app 1.45: the code in X-Kanki-Sub instead of the URL; another account's id with it, a wrong or a missing code: nothing
    let hdr = format!("/api/config/{}/kankimix?node=n1~2%40tunnel", u.id);
    let (st, _, body) = get_with(&app, &hdr, &[("x-kanki-sub", u.code.as_str())]).await;
    assert_eq!(st, StatusCode::OK);
    assert!(body.contains("@ir2.example.net:4100?"), "{}", body);
    let other = format!("/api/config/{}/kankimix?node=n1~2%40tunnel", u.id + 1000);
    for (uri, code) in [(hdr.as_str(), "kanki-1-wrongcode"), (other.as_str(), u.code.as_str()), (hdr.as_str(), "bad code!")] {
        let (st, _, body) = get_with(&app, uri, &[("x-kanki-sub", code)]).await;
        assert_ne!(st, StatusCode::OK, "{} {}", uri, code);
        assert!(!body.contains("kanki://"), "{}", body);
    }
    let (st, _, _) = get_with(&app, &hdr, &[]).await;
    assert_ne!(st, StatusCode::OK);
    for bad in ["n1~9%40tunnel", "n1~x%40tunnel", "~2%40tunnel"] {
        let (st, _) = get_text(&app, &format!("{}{}", base, bad)).await;
        assert_ne!(st, StatusCode::OK, "{}", bad);
    }
    // the subscription data: the extra entry is a tunnel entry of n1
    let data = crate::api::sub_data_for_tests(&app, &u);
    let e = data["nodes"].as_array().unwrap().iter().find(|x| x["id"] == "n1~2@tunnel").unwrap();
    assert_eq!((e["via"].as_str(), e["parent"].as_str(), e["protocols"][0].as_str()), (Some("tunnel"), Some("n1"), Some("kankimix")));
    // the admin leaves Shiraz out: no extra entry, one alt
    let mut nodes = s.nodes.clone();
    nodes.insert("n1".into(), crate::kmix::NodeOpt { tun_skip: vec!["kir2".into()], ..Default::default() });
    app.db.set("kmix_nodes", &serde_json::to_string(&nodes).unwrap());
    assert!(crate::kmix::link_tunnels(&app, &u, &n).is_empty());
    assert!(!crate::kmix::link(&app, &u, &n).unwrap().contains("ir2.example.net"));
    // FEC set again: the links say it, and it becomes the parity kept for later
    let admin = token(&app, "nodes");
    let (st, _) = call(&app, Method::PUT, "/api/kmix", Some(&admin), Some(json!({"parity": 5}))).await;
    assert_eq!(st, StatusCode::OK);
    let s = crate::kmix::settings(&app);
    assert_eq!((s.parity, s.legacy_parity), (5, 5));
    let (st, _) = call(&app, Method::PUT, "/api/kmix", Some(&admin), Some(json!({"parity": 0, "nodes": {"n1": {"tun_skip": ["kir2", "bad id;rm"]}}}))).await;
    assert_eq!(st, StatusCode::OK);
    let s = crate::kmix::settings(&app);
    assert_eq!((s.parity, s.legacy_parity), (0, 5));
    assert_eq!(s.nodes["n1"].tun_skip, vec!["kir2".to_string()]);
}

async fn get_text(app: &Arc<App>, uri: &str) -> (StatusCode, String) {
    let res = crate::api::master_router(app.clone()).oneshot(Request::get(uri).body(axum::body::Body::empty()).unwrap()).await.unwrap();
    let st = res.status();
    let b = axum::body::to_bytes(res.into_body(), 1 << 20).await.unwrap();
    (st, String::from_utf8_lossy(&b).to_string())
}

/// 3.67: a server's KANKI MIX health rides its (signed) sync answer; only known, bounded numbers are kept and
/// shown on the KANKI MIX page; an older node sends none and its answer still reads
#[tokio::test]
async fn kmix_health_comes_with_the_sync_and_is_cleaned() {
    let old: crate::sync::SyncResp = serde_json::from_str(r#"{"kmix":{},"now":1}"#).unwrap();
    assert!(old.kmix_health.is_null());
    let raw = json!({"sessions": 12, "gaming": 5, "hinted": 4, "users": 40, "loss_permille": 7, "loss_sessions": 9,
        "fec_parity": 0, "fec_legacy": 3, "hop": {"want": "4001-4010<script>", "active": true}, "extra": "<b>x</b>"});
    crate::kmix::note_health("hn1", &raw);
    let h = crate::kmix::health_of("hn1");
    assert_eq!((h["sessions"].as_i64(), h["gaming"].as_i64(), h["loss_permille"].as_i64()), (Some(12), Some(5), Some(7)));
    assert_eq!((h["hop"]["want"].as_str(), h["hop"]["active"].as_bool()), (Some("4001-4010"), Some(true)));
    assert!(h.get("extra").is_none() && h["at"].as_i64().unwrap_or(0) > 0);
    // nonsense numbers are dropped, not shown
    crate::kmix::note_health("hn1", &json!({"sessions": -4, "loss_permille": 5000}));
    let h = crate::kmix::health_of("hn1");
    assert!(h["sessions"].is_null() && h["loss_permille"].is_null());
    // a sync answer without it forgets it
    crate::kmix::note_health("hn1", &Value::Null);
    assert!(crate::kmix::health_of("hn1").is_null());
    // the page lists it per server (admin only)
    let app = crate::test_app();
    app.db.exec("INSERT INTO nodes(id,name,address,endpoint,token,endpoint_mode,info) VALUES('hn2','DE','https://x:9','x','t','panel','{\"kmix_port\":4000}')", &[]).unwrap();
    crate::kmix::note_health("hn2", &raw);
    let (st, _) = call(&app, Method::GET, "/api/kmix", None, None).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    let admin = token(&app, "nodes");
    let (st, v) = call(&app, Method::GET, "/api/kmix", Some(&admin), None).await;
    assert_eq!(st, StatusCode::OK);
    let s = v["servers"].as_array().unwrap().iter().find(|x| x["id"] == "hn2").unwrap();
    assert_eq!(s["health"]["hinted"], 4);
}

/// 3.67.2: an app may send only the digits of the code; the page (not sealed) names the full code, and digits that
/// are wrong, shared by two accounts or not digits at all get the plain miss answer
#[tokio::test]
async fn the_bare_code_in_the_header_finds_its_account() {
    let app = crate::test_app();
    with_xray(&app);
    let id = user(&app, "bareuser", "xray,hy2", Tier::V2ray);
    let u = app.db.user(id).unwrap();
    let (st, _, page) = get_with(&app, "/sub/me", &[("x-kanki-sub", u.code.as_str())]).await;
    assert_eq!(st, StatusCode::OK);
    assert!(page.contains(&u.sub_code()), "the page names the full code");
    let (st, _, v2) = get_with(&app, "/sub/me/v2", &[("x-kanki-sub", u.code.as_str())]).await;
    assert_eq!(st, StatusCode::OK);
    assert!(!v2.is_empty());
    // two accounts with the same digits: neither is given
    let twin = user(&app, "baretwin", "xray,hy2", Tier::V2ray);
    app.db.exec("UPDATE users SET code=?1 WHERE id=?2", &[&u.code, &twin]).unwrap();
    for bad in [u.code.as_str(), "0000000000000000000", "123", "12345678901234567890123456789012345"] {
        let (st, _, _) = get_with(&app, "/sub/me", &[("x-kanki-sub", bad)]).await;
        assert_eq!(st, StatusCode::NOT_FOUND, "{}", bad);
    }
}

/// 3.69: a Kanki tunnel that carries a server's KANKI MIX port carries its hop ports too (the Iran entry forwards
/// 4001-4010 to the main port), and the link through it keeps `ports=`; where an entry cannot forward them (a port
/// already taken there, another tunnel kind) the link has no `ports=` at all
#[tokio::test]
async fn kmix_hop_ports_follow_the_iran_tunnel_or_stay_out_of_its_link() {
    let app = crate::test_app();
    let info = r#"{"kmix_port":4000,"kmix_hop":"4001-4010"}"#;
    app.db.exec("INSERT INTO nodes(id,name,address,endpoint,token,endpoint_mode,info) VALUES('h1','Germany','https://de.example.net:9','de.example.net','t','panel',?1)", &[&info]).unwrap();
    let mut list = crate::tunnel::panel::servers(&app);
    for (id, name, addr, node) in [("hde", "DE", "de.example.net", "h1"), ("hir1", "Tehran", "ir1.example.net", ""), ("hir2", "Shiraz", "ir2.example.net", "")] {
        list.push(crate::tunnel::panel::TServer { id: id.into(), name: name.into(), addr: addr.into(), node: node.into(), ..Default::default() });
        crate::tunnel::panel::test_seen(id, crate::VERSION);
    }
    crate::tunnel::panel::save_servers(&app, &list);
    let t1 = crate::tunnel::panel::Tunnel { id: "h1t".into(), entry: "hir1".into(), exit: "hde".into(), enabled: true, udp: vec!["4000".into()], ..Default::default() };
    let t2 = crate::tunnel::panel::Tunnel { id: "h2t".into(), entry: "hir2".into(), exit: "hde".into(), enabled: true, udp: vec!["4100:4000".into()], ..Default::default() };
    // another tunnel at the Shiraz entry already listens on 4005: that entry cannot take the hop range
    let t3 = crate::tunnel::panel::Tunnel { id: "h3t".into(), entry: "hir2".into(), exit: "hde".into(), enabled: true, udp: vec!["4005:51820".into()], ..Default::default() };
    crate::tunnel::panel::save_tunnels(&app, &[t1, t2, t3]);
    let u = app.db.create_user("hopper", 10.0, 30, 1, "kmix", "", "", 0).unwrap();
    let n = app.db.node("h1").unwrap();
    // what the Tehran agent runs: the main port and every hop port to the main port
    let spec = crate::tunnel::panel::specs_for(&app, "hir1").into_iter().find(|s| s.id == "h1t").unwrap();
    let ports = crate::tunnel::engine::parse_ports(&spec.udp);
    assert!(ports.contains(&(4000, 4000)));
    for h in 4001..=4010u16 {
        assert!(ports.contains(&(h, 4000)), "{} in {:?}", h, spec.udp);
    }
    // the exit runs the same list (it delivers each to the main port)
    let exit = crate::tunnel::panel::specs_for(&app, "hde").into_iter().find(|s| s.id == "h1t").unwrap();
    assert_eq!(exit.udp, spec.udp);
    // Shiraz: nothing added
    let spec2 = crate::tunnel::panel::specs_for(&app, "hir2").into_iter().find(|s| s.id == "h2t").unwrap();
    assert_eq!(spec2.udp, vec!["4100:4000".to_string()]);
    // the links: the direct one and the Tehran one hop, the Shiraz one does not offer ports that lead nowhere
    assert!(crate::kmix::link(&app, &u, &n).unwrap().contains("ports=4001-4010"));
    let tehran = crate::kmix::link_tunnel(&app, &u, &n).unwrap();
    assert!(tehran.contains("@ir1.example.net:4000?") && tehran.contains("ports=4001-4010"), "{}", tehran);
    let extra = crate::kmix::link_tunnels(&app, &u, &n);
    let shiraz = &extra.iter().find(|e| e.2.contains("@ir2.example.net:4100?")).unwrap().2;
    assert!(!shiraz.contains("ports="), "{}", shiraz);
    // a tunnel of another kind (KANKI-UP: one udp2raw pair per port) carries only what it lists
    let mut tl = crate::tunnel::panel::tunnels(&app);
    if let Some(t) = tl.iter_mut().find(|t| t.id == "h1t") {
        t.kind = "kup".into();
    }
    crate::tunnel::panel::save_tunnels(&app, &tl);
    assert!(crate::tunnel::panel::kmix_hop_map(&app, &crate::tunnel::panel::tunnels(&app)[0]).is_empty());
    let tehran = crate::kmix::link_tunnel(&app, &u, &n).unwrap_or_default();
    assert!(!tehran.contains("ports="), "{}", tehran);
    // a server without a hop range: nothing to forward
    app.db.exec("UPDATE nodes SET info=?1 WHERE id='h1'", &[&r#"{"kmix_port":4000}"#]).unwrap();
    let mut tl = crate::tunnel::panel::tunnels(&app);
    if let Some(t) = tl.iter_mut().find(|t| t.id == "h1t") {
        t.kind = String::new();
    }
    crate::tunnel::panel::save_tunnels(&app, &tl);
    let spec = crate::tunnel::panel::specs_for(&app, "hir1").into_iter().find(|s| s.id == "h1t").unwrap();
    assert_eq!(spec.udp, vec!["4000".to_string()]);
}
