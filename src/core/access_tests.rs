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
        .exec("INSERT INTO api_tokens(name,hash,prefix,scopes,created,last_used) VALUES('t',?1,'tok',?2,0,0)", &[&crate::util::sha256_hex(&t), &scopes])
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

    // gaming: Hysteria2 and AmneziaWG off (no link either), and they cannot be switched on
    assert_eq!(set_role("gaming").await, StatusCode::OK);
    assert_eq!(crate::cores::off_list(&app, "n1"), vec!["awg", "hy2"]);
    assert_eq!(core("hy2", true).await, StatusCode::CONFLICT);
    assert_eq!(core("awg", true).await, StatusCode::CONFLICT);
    assert_eq!(core("wg", true).await, StatusCode::OK);
    assert_eq!(kmix(true).await, StatusCode::OK);
    assert!(crate::kmix::settings(&app).node_on("n1"));
    let p = crate::api::node_protos(&app, &u, &n());
    assert!(!p.contains(&"hysteria2") && !p.contains(&"amneziawg"), "{:?}", p);
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
             INSERT INTO nodes(id,name,address,endpoint,token) VALUES('n1','DE','https://x','','t');",
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
