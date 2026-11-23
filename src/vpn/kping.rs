//! KPING: the game core, in the panel. Like KANKI MIX and microtun it runs on every VPN server where it is on
//! (KPING › servers, or the installer's list of cores): the server's node agent runs the relay on a public UDP port
//! and the exit behind it on 127.0.0.1 (`kpingd`, `kping0`, NAT out). The app dials the server directly, or the
//! server's Iran address when its tunnel carries the KPING port (the second config, like every core). Only users
//! with the KPING protocol get it, and only the Kanki app receives its config (inside the sealed subscription,
//! never on the subscription page, in links or the bot). Nothing here is tied to one game.
//! Until 3.57 KPING had routes of its own (an Iran relay and an exit joined by a tunnel); they are gone (3.58).
use crate::db::User;
use crate::kpingd::{ExitCfg, KUser, KpCfg, RelayCfg};
use crate::App;
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Sha256;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex, OnceLock};

pub const PROTO: &str = "kping";
pub const NAME: &str = "KPING";
/// UDP port of KPING on an exit (127.0.0.1 only: the tunnel delivers there)
pub const DEFAULT_PORT: u16 = 4300;
/// UDP port the app dials on each server (the relay; servers may have their own)
pub const DEFAULT_ENTRY_PORT: u16 = 24300;
/// users get 10.81.0.2 … by id (microtun is 10.79, its devices 10.80)
const BASE: u32 = u32::from_be_bytes([10, 81, 0, 0]);

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(default)]
pub struct Settings {
    pub on: bool,
    /// UDP port of KPING on the exits (127.0.0.1)
    pub port: u16,
    /// MTU when automatic MTU is off
    pub mtu: u16,
    /// one path: the relay sends the second copy to the phone this many ms after the first (0 = none)
    pub dup_ms: u16,
    /// Iran ↔ abroad: the second copy of every packet this many ms after the first (0 = one copy)
    pub tun_dup_ms: u16,
    /// parity: one repair packet per this many packets (0 = none). 2: a lost packet is rebuilt as soon as
    /// the next one arrives, so it is late by one packet at most
    pub fec: u8,
    /// the public UDP port of the relay on each server (servers may have their own, `nodes`)
    pub public: u16,
    /// per server: off there, its own port
    pub nodes: HashMap<String, NodeOpt>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(default)]
pub struct NodeOpt {
    /// KPING off on this server only
    pub off: bool,
    /// this server's own public port (0 = `public`)
    pub port: u16,
}

impl Default for Settings {
    fn default() -> Self {
        Settings { on: true, port: DEFAULT_PORT, mtu: 1332, dup_ms: 10, tun_dup_ms: 20, fec: 2, public: DEFAULT_ENTRY_PORT, nodes: HashMap::new() }
    }
}

impl Settings {
    pub fn node_on(&self, nid: &str) -> bool {
        self.on && !self.nodes.get(nid).map(|o| o.off).unwrap_or(false)
    }
    pub fn node_port(&self, nid: &str) -> u16 {
        self.nodes.get(nid).map(|o| o.port).filter(|p| *p > 0).unwrap_or(self.public)
    }
}

/// KPING's public port on server `nid`
pub fn set_node_port(app: &App, nid: &str, port: u16) {
    let mut s = settings(app);
    s.nodes.entry(nid.to_string()).or_default().port = port;
    save(app, &s);
}

/// KPING off (or on again) on server `nid` only
pub fn set_node_off(app: &App, nid: &str, off: bool) {
    let mut s = settings(app);
    s.nodes.entry(nid.to_string()).or_default().off = off;
    save(app, &s);
}

pub fn settings(app: &App) -> Settings {
    let mut s: Settings = serde_json::from_str(&app.db.get("kping_cfg")).unwrap_or_default();
    if s.port == 0 {
        s.port = DEFAULT_PORT;
    }
    if s.public == 0 {
        s.public = DEFAULT_ENTRY_PORT;
    }
    s.mtu = s.mtu.clamp(1200, 1500);
    s.dup_ms = s.dup_ms.min(20);
    s.tun_dup_ms = s.tun_dup_ms.min(30);
    s.fec = s.fec.min(crate::kpingd::MAX_GROUP as u8);
    s
}

fn save(app: &App, s: &Settings) {
    app.db.set("kping_cfg", &serde_json::to_string(s).unwrap_or_default());
}

/// A removed VPN server: its own KPING setting goes with it
pub fn forget_node(app: &App, id: &str) {
    let mut s = settings(app);
    if s.nodes.remove(id).is_some() {
        save(app, &s);
    }
}

// ------------------------------------------------------------------ keys, addresses, MTU

pub fn obfs(app: &App) -> String {
    crate::microtun::kept_hex(app, "kp_obfs")
}

/// The user's key (64 hex): HMAC-SHA256(KPING secret, user id + subscription code)
pub fn user_key(app: &App, u: &User) -> String {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(crate::microtun::kept_hex(app, "kp_secret").as_bytes()).expect("hmac key");
    m.update(format!("kping|{}|{}", u.id, u.code).as_bytes());
    hex::encode(m.finalize().into_bytes())
}

fn ip_of_id(id: i64) -> Option<Ipv4Addr> {
    let id = u32::try_from(id).ok().filter(|i| (1..=65533).contains(i))?;
    Some(Ipv4Addr::from(BASE + id + 1))
}

/// MTU of the phone and of `kping0`: the safe budget minus IPv4, UDP and KPING's 20 bytes. The Game-FEC
/// tunnel cuts its own packets, so it takes nothing more.
pub fn mtu(app: &App, s: &Settings) -> u16 {
    if !crate::mtu::auto(app) {
        return s.mtu;
    }
    crate::mtu::safe(crate::mtu::budget(app), crate::mtu::IPV4 + crate::mtu::UDP + crate::kpingd::OVERHEAD as u16).0
}

/// Users who get KPING
fn users_of(users: &[User]) -> Vec<&User> {
    users.iter().filter(|u| u.active() && u.has_proto(PROTO)).collect()
}

fn kusers(app: &App, users: &[User]) -> Vec<KUser> {
    users_of(users)
        .into_iter()
        .filter_map(|u| Some(KUser { uid: u32::try_from(u.id).ok()?, name: u.username.clone(), key: user_key(app, u), ip: ip_of_id(u.id)?.to_string() }))
        .collect()
}

/// What a tunnel agent runs of KPING: nothing since 3.58 (KPING runs in the node agent of each VPN server, like the
/// other cores); an older agent still running a route's relay or exit stops it
pub fn cfg_for(_app: &App, _sid: &str) -> KpCfg {
    KpCfg::default()
}

/// What VPN server `n` runs: its relay on the public port, the exit behind it on 127.0.0.1 (nothing when KPING is
/// off there). `users`: the users of this server still allowed in by the connection limit.
pub fn cfg_for_node(app: &App, n: &crate::db::Node, users: &[&User]) -> KpCfg {
    let s = settings(app);
    if !s.node_on(&n.id) {
        return KpCfg { obfs: obfs(app), relays: vec![], exit: None };
    }
    let owned: Vec<User> = users.iter().map(|u| (*u).clone()).collect();
    let users = kusers(app, &owned);
    KpCfg {
        obfs: obfs(app),
        relays: vec![RelayCfg {
            port: s.node_port(&n.id), to: s.port, more: vec![], dup_ms: s.dup_ms, tun_dup_ms: 0,
            users: users.iter().map(|u| KUser { ip: String::new(), ..u.clone() }).collect(),
        }],
        exit: Some(ExitCfg { port: s.port, mtu: mtu(app, &s), fec: s.fec, tun_dup_ms: 0, users }),
    }
}

/// 3.58.1, once: the routes of 3.37-3.57 (an Iran relay and a tunnel of their own) are gone for good. A route
/// left in the settings still made its tunnel listen on 127.0.0.1 only (users could not reach it) and kept its
/// ports out of the firewall; saving the settings again drops them (the field is no longer read).
pub fn drop_routes(app: &App) {
    if app.db.get("kping_routes_gone") == "1" {
        return;
    }
    let s = settings(app);
    save(app, &s);
    app.db.set("kping_routes_gone", "1");
}


// ------------------------------------------------------------------ what the servers report

/// sid -> (when, report)
fn reports() -> &'static Mutex<HashMap<String, (i64, Value)>> {
    static R: OnceLock<Mutex<HashMap<String, (i64, Value)>>> = OnceLock::new();
    R.get_or_init(Default::default)
}

/// A VPN server's KPING report (`node`: its id): traffic counts on the user, online users are seen now. A server
/// speaks only for itself and only while KPING is on there (`serves`), and only for the users with KPING.
pub fn ingest(app: &App, node: &str, st: &Value, serves: bool) {
    if st.is_null() || !serves {
        reports().lock().unwrap_or_else(|e| e.into_inner()).remove(node);
        return;
    }
    let now = crate::util::now();
    let mut st = st.clone();
    // every KPING user of the panel, not only the ones let in right now: the last traffic of a user who was just
    // shut by the connection limit, expired or ran out of data still counts
    let allowed: std::collections::HashSet<i64> = app.db.users().iter().filter(|u| u.has_proto(PROTO)).map(|u| u.id).collect();
    if let Some(x) = st.get_mut("exit").and_then(|x| x.as_object_mut()) {
        if let Some(u) = x.get_mut("users").and_then(|u| u.as_object_mut()) {
            u.retain(|k, _| k.parse::<i64>().map(|id| allowed.contains(&id)).unwrap_or(false));
        }
        if let Some(o) = x.get_mut("online").and_then(|o| o.as_array_mut()) {
            o.retain(|v| v.as_i64().map(|id| allowed.contains(&id)).unwrap_or(false));
        }
    }
    reports().lock().unwrap_or_else(|e| e.into_inner()).insert(node.to_string(), (now, st.clone()));
    let x = &st["exit"];
    crate::dns::panel::count_usage(app, &format!("kping_prev_{}", node), x);
    for id in x["online"].as_array().into_iter().flatten().filter_map(|v| v.as_i64()) {
        let _ = app.db.exec("UPDATE users SET last_seen=?1 WHERE id=?2", &[&now, &id]);
    }
}

/// KPING in the account's connection limit (all cores and servers together): each user a server saw in the last
/// minute is one device on that server. Also the servers that answered.
pub fn live_units(now: i64) -> (Vec<(i64, String, String, i64)>, std::collections::HashSet<String>) {
    let r = reports().lock().unwrap_or_else(|e| e.into_inner());
    let mut units = vec![];
    let mut answered = std::collections::HashSet::new();
    for (node, (_, v)) in r.iter().filter(|(_, (t, _))| now - t < 60) {
        answered.insert(node.clone());
        for id in v["exit"]["online"].as_array().into_iter().flatten().filter_map(|x| x.as_i64()) {
            units.push((id, node.clone(), PROTO.to_string(), 1));
        }
    }
    (units, answered)
}

fn enc(s: &str) -> String {
    s.bytes()
        .map(|b| if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) { (b as char).to_string() } else { format!("%{:02X}", b) })
        .collect()
}

/// `kping://<key>@host:port?uid=&obfs=&ip=&mtu=&fec=#name`
#[allow(clippy::too_many_arguments)]
pub fn to_url(key: &str, dial: &str, uid: u32, obfs: &str, ip: Ipv4Addr, mtu: u16, fec: u8, name: &str) -> String {
    format!("kping://{}@{}?uid={}&obfs={}&ip={}&mtu={}&fec={}#{}", key, dial, uid, obfs, ip, mtu, fec, enc(name))
}

/// KPING for the Kanki app (only inside the sealed subscription). Null = not for this user.
/// [{ id, node, name, url, via, …exit country }]: each server of the user where KPING is on, straight to it, and
/// through its Iran address when the server's tunnel carries the KPING port (node `<id>@tunnel`, like every core).
pub fn sub_info(app: &App, u: &User) -> Value {
    let s = settings(app);
    if !s.on || !u.active() || !u.has_proto(PROTO) {
        return Value::Null;
    }
    let (Some(ip), Ok(uid)) = (ip_of_id(u.id), u32::try_from(u.id)) else { return Value::Null };
    let (key, ob, m) = (user_key(app, u), obfs(app), mtu(app, &s));
    let mut out = vec![];
    for n in crate::api::user_nodes(app, u) {
        if !s.node_on(&n.id) || crate::api::node_info(&n)["kp_port"].is_null() {
            continue;
        }
        let port = s.node_port(&n.id);
        let host = crate::api::endpoint(app, &n);
        let direct = if host.contains(':') && !host.starts_with('[') { format!("[{}]:{}", host, port) } else { format!("{}:{}", host, port) };
        let mut push = |node: String, dial: String, via: &str| {
            let name = format!("{} · {}", n.name, NAME);
            let mut v = json!({ "id": format!("{}/{}", node, PROTO), "node": node, "name": n.name, "via": via,
                "url": to_url(&key, &dial, uid, &ob, ip, m, s.fec, &name) });
            if let (Some(o), Some(e)) = (v.as_object_mut(), crate::exitgeo::fields(app, &n.id).as_object()) {
                o.extend(e.clone());
            }
            out.push(v);
        };
        // through the tunnel the server answers on its own address only when it is not behind one already
        if !crate::direct::through_tunnel(app, &n) {
            push(n.id.clone(), direct, "direct");
        }
        if let Some(t) = crate::twin::of_node_core(app, &n, PROTO) {
            if let Some(p) = t.carried(app, port, false) {
                push(format!("{}{}", n.id, crate::api::TUNNEL_SUFFIX), t.addr(p), "tunnel");
            }
        }
    }
    if out.is_empty() { Value::Null } else { json!(out) }
}

// ------------------------------------------------------------------ panel API

type St = State<Arc<App>>;

pub fn router() -> Router<Arc<App>> {
    Router::new()
        .route("/api/kping", get(get_all).put(put_settings))
        .route("/api/kping/servers/:id", post(node_set))
        .route("/api/kping/users", post(user_set))
}

fn bad(m: &str) -> Response {
    (StatusCode::BAD_REQUEST, Json(json!({ "error": m }))).into_response()
}

fn port_of(v: &Value) -> Option<u16> {
    v.as_u64().or_else(|| v.as_str().and_then(|x| x.trim().parse().ok())).filter(|p| *p > 0 && *p <= 65535).map(|p| p as u16)
}

async fn get_all(State(app): St, h: HeaderMap) -> Response {
    let _ = crate::guard!(app, h, "nodes");
    let s = settings(&app);
    let users = app.db.users();
    let r = reports().lock().unwrap_or_else(|e| e.into_inner()).clone();
    let now = crate::util::now();
    let servers: Vec<Value> = app
        .db
        .nodes()
        .iter()
        // a server whose VPN is off (the panel server without VPN) runs no KPING: not listed (3.58.1)
        .filter(|n| n.enabled)
        .map(|n| {
            let info = crate::api::node_info(n);
            let rep = r.get(&n.id).filter(|(t, _)| now - t < 120).map(|(_, v)| v.clone());
            let relay = rep.as_ref().and_then(|v| v["relays"].as_array().and_then(|a| a.first().cloned())).unwrap_or(Value::Null);
            let exit = rep.as_ref().map(|v| v["exit"].clone()).unwrap_or(Value::Null);
            let tw = crate::twin::of_node_core(&app, n, PROTO).and_then(|t| t.carried(&app, s.node_port(&n.id), false).map(|p| t.addr(p)));
            json!({
                "id": n.id, "name": n.name, "online": n.online, "on": s.node_on(&n.id), "port": s.node_port(&n.id),
                // an older node agent (before 3.58) knows nothing of KPING: it never says it runs
                "runs": !info["kp_port"].is_null(), "knows": !info["kp_port"].is_null() || rep.is_some(),
                "relay_error": relay["error"].as_str(), "exit_error": exit["error"].as_str(),
                "online_users": exit["online"].as_array().map(|a| a.len()).unwrap_or(0),
                "direct": format!("{}:{}", crate::api::endpoint(&app, n), s.node_port(&n.id)),
                // why there is no copy through Iran: the server has no tunnel at all, or no tunnel carries this port
                "tunnel_why": if tw.is_some() { Value::Null } else if crate::twin::name_of_node(&app, n).is_none() { json!("no_tunnel") } else { json!("not_carried") },
                "tunnel": tw,
            })
        })
        .collect();
    let with = users_of(&users);
    Json(json!({
        "settings": s, "servers": servers, "mtu_now": mtu(&app, &s), "mtu_auto": app.db.get("mtu_auto") != "0",
        "users": with.len(), "online": with.iter().filter(|u| u.online > 0).count(),
        "user_list": users.iter().map(|u| json!({ "id": u.id, "name": u.username, "has": u.has_proto(PROTO), "active": u.active() })).collect::<Vec<_>>(),
    }))
    .into_response()
}

/// { on?, port? }: KPING on one server
async fn node_set(State(app): St, h: HeaderMap, Path(id): Path<String>, Json(b): Json<Value>) -> Response {
    let _ = crate::guard!(app, h, "nodes");
    if !app.db.nodes().iter().any(|n| n.id == id) {
        return (StatusCode::NOT_FOUND, Json(json!({ "error": "unknown server" }))).into_response();
    }
    // everything is checked first and saved together: a refused port must not leave KPING switched on half-way
    let port = if b["port"].is_null() {
        None
    } else {
        let Some(p) = port_of(&b["port"]) else { return bad("the port must be 1-65535") };
        // only this server's own ports count: another server may use the same number (3.58.1)
        if p != settings(&app).node_port(&id) && crate::servers::taken_on(&app, &id).contains(&p) {
            return bad("this port is already used on this server");
        }
        Some(p)
    };
    if let Some(on) = b["on"].as_bool() {
        set_node_off(&app, &id, !on);
    }
    if let Some(p) = port {
        if p != settings(&app).node_port(&id) {
            set_node_port(&app, &id, p);
        }
    }
    Json(json!({ "ok": true })).into_response()
}

async fn put_settings(State(app): St, h: HeaderMap, Json(b): Json<Value>) -> Response {
    let _ = crate::guard!(app, h, "nodes");
    let mut s = settings(&app);
    if let Some(on) = b["on"].as_bool() {
        s.on = on;
    }
    if !b["public"].is_null() {
        match port_of(&b["public"]) {
            Some(p) => s.public = p,
            None => return bad("the port must be 1-65535"),
        }
    }
    if let Some(v) = b["mtu"].as_u64() {
        if !(1200..=1500).contains(&v) {
            return bad("MTU must be 1200-1500");
        }
        s.mtu = v as u16;
    }
    if let Some(v) = b["dup_ms"].as_u64() {
        s.dup_ms = v.min(20) as u16;
    }
    if let Some(v) = b["tun_dup_ms"].as_u64() {
        s.tun_dup_ms = v.min(30) as u16;
    }
    if let Some(v) = b["fec"].as_u64() {
        s.fec = v.min(crate::kpingd::MAX_GROUP as u64) as u8;
    }
    save(&app, &s);
    Json(json!({ "ok": true, "settings": s })).into_response()
}

/// { id, on }: KPING for one user
async fn user_set(State(app): St, h: HeaderMap, Json(b): Json<Value>) -> Response {
    let _ = crate::guard!(app, h, "users:write");
    let on = b["on"].as_bool().unwrap_or(true);
    let Some(u) = b["id"].as_i64().and_then(|id| app.db.users().into_iter().find(|u| u.id == id)) else { return bad("unknown user") };
    if on && ip_of_id(u.id).is_none() {
        return bad("KPING gives addresses to user numbers 1-65533 only");
    }
    let mut list: Vec<String> = u.protocols.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect();
    if on != list.iter().any(|x| x == PROTO) {
        if on { list.push(PROTO.into()) } else { list.retain(|x| x != PROTO) }
        let _ = app.db.exec("UPDATE users SET protocols=?1 WHERE id=?2", &[&list.join(","), &u.id]);
    }
    Json(json!({ "ok": true })).into_response()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn addresses_do_not_meet_microtun() {
        assert_eq!(ip_of_id(1), Some(Ipv4Addr::new(10, 81, 0, 2)));
        assert!(ip_of_id(0).is_none() && ip_of_id(65534).is_none());
        assert_ne!(crate::kpingd::SERVER_ADDR, "10.79.0.1/16");
    }

    /// A server where KPING is not on, or a user without KPING, puts no traffic or "online" on an account
    #[test]
    fn a_report_counts_only_from_a_kping_server_and_for_its_users() {
        let app = test_app();
        let u = app.db.create_user("victim", 10.0, 30, 1, "wg", "", "", 0).unwrap();
        let rep = json!({ "exit": { "run": "r1", "users": { u.id.to_string(): [5_000_000_000i64, 0] }, "online": [u.id] } });
        ingest(&app, "stranger", &rep, false);
        ingest(&app, "local", &rep, true);
        let after = app.db.user(u.id).unwrap();
        assert_eq!((after.used_bytes, after.last_seen), (u.used_bytes, u.last_seen));
        assert!(live_units(crate::util::now()).0.iter().all(|x| x.0 != u.id));
    }

    pub(crate) fn test_app() -> Arc<App> {
        use std::sync::atomic::AtomicI64;
        let dir = std::env::temp_dir().join(format!("kanki-kping-test-{}", crate::util::rand_token(8)));
        std::fs::create_dir_all(&dir).unwrap();
        Arc::new(App {
            db: crate::db::Db::open(dir.join("kanki.db").to_str().unwrap()),
            env: std::collections::HashMap::from([("DOMAIN".to_string(), "fi.example.com".to_string())]),
            hy2_allowed: Mutex::new(Default::default()), limits: Mutex::new(Default::default()), reported: Mutex::new(Default::default()),
            login_fails: Mutex::new(Default::default()), sync_lock: tokio::sync::Mutex::new(()), bot_alive: AtomicI64::new(0),
            http: reqwest::Client::new(), http_insecure: reqwest::Client::new(), pin_clients: Mutex::new(Default::default()),
        })
    }

    async fn call(app: &Arc<App>, method: &str, uri: &str, body: Value) -> (StatusCode, Value) {
        use tower::ServiceExt;
        let r = axum::http::Request::builder().method(method).uri(uri).header("authorization", "Bearer test-key").header("content-type", "application/json")
            .body(axum::body::Body::from(body.to_string())).unwrap();
        let res = crate::api::master_router(app.clone()).oneshot(r).await.unwrap();
        let st = res.status();
        let b = axum::body::to_bytes(res.into_body(), 1 << 22).await.unwrap();
        (st, serde_json::from_slice(&b).unwrap_or(Value::Null))
    }

    /// KPING runs on a server like a core: the relay on its public port and the exit on 127.0.0.1, only for users
    /// with KPING, nothing where it is off; the app gets the server straight and through its tunnel
    #[tokio::test]
    async fn kping_runs_on_every_server_like_a_core() {
        let app = test_app();
        app.db.set("api_key", "test-key");
        let u = app.db.create_user("gamer", 10.0, 30, 1, "wg,kping", "", "", 0).unwrap();
        let v = app.db.create_user("plain", 10.0, 30, 1, "wg", "", "", 0).unwrap();
        app.db.exec("INSERT INTO nodes(id,name,address,endpoint,token,info,online) VALUES('local','Main','','fi.example.com','',?1,1)", &[&json!({ "kp_port": "24300" }).to_string()]).unwrap();
        let n = app.db.nodes().into_iter().find(|n| n.id == "local").unwrap();
        let (uu, vv) = (app.db.user(u.id).unwrap(), app.db.user(v.id).unwrap());
        let c = cfg_for_node(&app, &n, &[&uu, &vv]);
        assert_eq!(c.relays.len(), 1);
        assert_eq!((c.relays[0].port, c.relays[0].to), (DEFAULT_ENTRY_PORT, DEFAULT_PORT));
        let e = c.exit.as_ref().unwrap();
        assert_eq!(e.port, DEFAULT_PORT);
        assert_eq!(e.users.iter().map(|x| x.uid as i64).collect::<Vec<_>>(), vec![u.id]);
        assert!(c.relays[0].users.iter().all(|x| x.ip.is_empty()));
        // the app's config: straight to the server
        let si = sub_info(&app, &uu);
        let a = si.as_array().unwrap();
        assert_eq!(a.len(), 1);
        assert_eq!(a[0]["node"], "local");
        assert_eq!(a[0]["via"], "direct");
        assert!(a[0]["url"].as_str().unwrap().starts_with("kping://") && a[0]["url"].as_str().unwrap().contains(":24300?"));
        assert!(sub_info(&app, &vv).is_null());
        // off on this server: nothing runs, the app gets nothing
        let (st, _) = call(&app, "POST", "/api/kping/servers/local", json!({ "on": false })).await;
        assert_eq!(st, StatusCode::OK);
        let c = cfg_for_node(&app, &n, &[&uu]);
        assert!(c.relays.is_empty() && c.exit.is_none());
        assert!(sub_info(&app, &uu).is_null());
        let (st, _) = call(&app, "POST", "/api/kping/servers/nope", json!({ "on": true })).await;
        assert_eq!(st, StatusCode::NOT_FOUND);
        // a tunnel agent runs nothing of KPING any more
        assert!(cfg_for(&app, "local").relays.is_empty() && cfg_for(&app, "local").exit.is_none());
    }

    #[tokio::test]
    async fn kping_comes_through_the_tunnel_of_its_server() {
        let app = test_app();
        let u = app.db.create_user("gamer", 10.0, 30, 1, "wg,kping", "", "", 0).unwrap();
        app.db.exec("INSERT INTO nodes(id,name,address,endpoint,token,info,online) VALUES('de','Germany','de.example.com','de.example.com','t',?1,1)", &[&json!({ "kp_port": "24300", "wg_port": "51820" }).to_string()]).unwrap();
        let srv = json!([{ "id": "ir1", "name": "Iran", "token": "x", "addr": "ir.example.com" }, { "id": "s-de", "name": "Germany", "token": "y", "node": "de" }]);
        app.db.set("tun_servers", &srv.to_string());
        app.db.set("srv_tunnel", &json!({ "s-de": { "on": true, "host": "ir.example.com" } }).to_string());
        let uu = app.db.user(u.id).unwrap();
        let vias = |app: &App| sub_info(app, &uu).as_array().map(|a| a.iter().map(|x| (x["node"].as_str().unwrap().to_string(), x["via"].as_str().unwrap().to_string(), x["url"].as_str().unwrap().to_string())).collect::<Vec<_>>()).unwrap_or_default();
        // a tunnel that carries the KPING port: a second config through Iran, on the tunnel's own port
        app.db.set("tun_list", &json!([{ "id": "t1", "name": "g", "entry": "ir1", "exit": "s-de", "transport": "game", "enabled": true, "udp": ["51820", "24400:24300"] }]).to_string());
        let v = vias(&app);
        assert_eq!(v.len(), 2, "{:?}", v);
        assert_eq!((v[0].0.as_str(), v[0].1.as_str()), ("de", "direct"));
        assert_eq!((v[1].0.as_str(), v[1].1.as_str()), ("de@tunnel", "tunnel"));
        assert!(v[1].2.contains("ir.example.com:24400"), "{}", v[1].2);
        // tunnels that do not carry it: straight only
        app.db.set("tun_list", &json!([{ "id": "t1", "name": "g", "entry": "ir1", "exit": "s-de", "transport": "game", "enabled": true, "udp": ["51820"] }]).to_string());
        assert_eq!(vias(&app).len(), 1);
    }
}
