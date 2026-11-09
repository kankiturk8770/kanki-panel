//! KPING: the hidden game core. Only a few users the admin ticks get it, only the Kanki app receives
//! its config (inside the sealed subscription, never on the subscription page, in links or the bot),
//! and the app sends only PUBG (plus the DNS and Google services the game logs in with) through it.
//!
//! The path: app → Iran server (UDP port of its own) → its own reverse Game-FEC tunnel → exit server
//! abroad → the game. The phone's packets are encrypted end to end (phone ↔ exit) with the light
//! microtun format (28 bytes per packet, a masked header: no fixed bytes on the wire, small packets
//! sent twice); the Iran server only carries them on. The exit runs a second microtun server of its
//! own: interface `kping0`, its own subnet and keys, its port closed in the firewall (it is reached only
//! through the tunnel), so KPING never mixes with WireGuard, AmneziaWG, microtun or their users.
use crate::db::{Node, User};
use crate::microtun::{kept_hex, Applied, Runner};
use crate::mtun::{MtCfg, MtUser};
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
use std::net::Ipv4Addr;
use std::sync::Arc;

pub const PROTO: &str = "kping";
pub const NAME: &str = "KPING";
pub const IFACE: &str = "kping0";
/// UDP port of the KPING server on an exit (reached only through the tunnel)
pub const DEFAULT_PORT: u16 = 4300;
/// UDP port the app dials on the Iran server, and the port of the tunnel itself there
pub const DEFAULT_ENTRY_PORT: u16 = 24300;
pub const DEFAULT_TUNNEL_PORT: u16 = 24301;
/// the exit's tunnel address; users get 10.81.0.2 … by id (microtun is 10.79, its devices 10.80)
const SERVER_ADDR: &str = "10.81.0.1/16";
const BASE: u32 = u32::from_be_bytes([10, 81, 0, 0]);
const DEVICES_ADDR: &str = "10.82.0.1/16";
/// FEC of the tunnel: 8 packets + 3 repair packets (any 3 of 11 may be lost)
const FEC: &str = "8:3";

/// One way in: users dial `iran`, its tunnel brings them to `exit`
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(default)]
pub struct Route {
    pub id: String,
    /// the VPN server abroad that runs KPING (node id)
    pub exit: String,
    /// the Iran server users connect to (tunnel server id)
    pub iran: String,
    /// address the app dials ("" = the Iran server's own address)
    pub host: String,
    /// UDP port the app dials on the Iran server
    pub port: u16,
    /// the tunnel's own port on the Iran server (the exit dials it: reverse)
    pub tunnel_port: u16,
    /// the tunnel built for this route ("" = not built yet)
    pub tunnel: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(default)]
pub struct Settings {
    pub on: bool,
    /// UDP port of KPING on the exits
    pub port: u16,
    /// MTU when automatic MTU is off
    pub mtu: u16,
    /// IP packets up to this size are sent twice, phone ↔ exit (0 = never)
    pub burst_max: u16,
    pub burst_delay_ms: u16,
    pub routes: Vec<Route>,
}

impl Default for Settings {
    fn default() -> Self {
        // game packets are small; up to 1000 bytes every one goes twice (the mobile leg loses most)
        Settings { on: true, port: DEFAULT_PORT, mtu: 1324, burst_max: 1000, burst_delay_ms: 2, routes: vec![] }
    }
}

impl Settings {
    /// whether server `nid` runs KPING (it is the exit of a route)
    pub fn exit_here(&self, nid: &str) -> bool {
        self.on && self.routes.iter().any(|r| r.exit == nid)
    }
}

pub fn settings(app: &App) -> Settings {
    let mut s: Settings = serde_json::from_str(&app.db.get("kping_cfg")).unwrap_or_default();
    if s.port == 0 {
        s.port = DEFAULT_PORT;
    }
    s.mtu = s.mtu.clamp(1200, 1500);
    s.burst_max = s.burst_max.min(1500);
    s.burst_delay_ms = s.burst_delay_ms.min(50);
    s
}

fn save(app: &App, s: &Settings) {
    app.db.set("kping_cfg", &serde_json::to_string(s).unwrap_or_default());
}

/// A removed server's routes go with it
pub fn forget_node(app: &App, nid: &str) {
    let mut s = settings(app);
    let n = s.routes.len();
    s.routes.retain(|r| r.exit != nid);
    if s.routes.len() != n {
        save(app, &s);
    }
}

// ------------------------------------------------------------------ keys, addresses, MTU

pub fn obfs(app: &App) -> String {
    kept_hex(app, "kp_obfs")
}

/// The user's key (64 hex): HMAC-SHA256(KPING secret, user id + subscription code)
pub fn user_key(app: &App, u: &User) -> String {
    let mut m = Hmac::<Sha256>::new_from_slice(kept_hex(app, "kp_secret").as_bytes()).expect("hmac key");
    m.update(format!("kping|{}|{}", u.id, u.code).as_bytes());
    hex::encode(m.finalize().into_bytes())
}

fn ip_of_id(id: i64) -> Option<Ipv4Addr> {
    let id = u32::try_from(id).ok().filter(|i| (1..=65533).contains(i))?;
    Some(Ipv4Addr::from(BASE + id + 1))
}

/// MTU of the phone and of `kping0`: the safe budget minus IPv4, UDP and the microtun header. The
/// Game-FEC tunnel cuts its own packets, so it takes nothing more.
pub fn mtu(app: &App, s: &Settings) -> u16 {
    if !crate::mtu::auto(app) {
        return s.mtu;
    }
    crate::mtu::safe(crate::mtu::budget(app), crate::mtu::IPV4 + crate::mtu::UDP + crate::mtu::MTUN).0
}

/// Users who get KPING
fn users_of(users: &[User]) -> Vec<&User> {
    users.iter().filter(|u| u.active() && u.has_proto(PROTO)).collect()
}

/// What server `n` runs (`users`: every user; `max` the devices each may have now, None = none:
/// at the connection limit elsewhere)
pub fn cfg_for(app: &App, n: &Node, users: &[User], max: impl Fn(&User) -> Option<u32>) -> MtCfg {
    let s = settings(app);
    if !s.exit_here(&n.id) {
        return MtCfg::default();
    }
    let users = users_of(users)
        .into_iter()
        .filter_map(|u| Some(MtUser { name: u.username.clone(), key: user_key(app, u), ip: ip_of_id(u.id)?.to_string(), max: max(u)? }))
        .collect();
    MtCfg {
        port: s.port,
        obfs: obfs(app),
        address: SERVER_ADDR.into(),
        devices: DEVICES_ADDR.into(),
        address6: String::new(),
        mtu: mtu(app, &s),
        burst_max: s.burst_max,
        burst_delay_ms: s.burst_delay_ms,
        users,
        iface: IFACE.into(),
        // only its tunnel delivers here (to 127.0.0.1): nothing from outside reaches the port
        local_only: true,
    }
}

// ------------------------------------------------------------------ the app's config

/// Where the app dials a route: (host, port)
fn dial(app: &App, r: &Route) -> String {
    let host = if r.host.trim().is_empty() {
        crate::tunnel::panel::dial_addr(app, &r.iran, r.port)
    } else {
        let h = r.host.trim();
        if h.contains(':') && !h.starts_with('[') { format!("[{}]:{}", h, r.port) } else { format!("{}:{}", h, r.port) }
    };
    host
}

/// KPING for the Kanki app (only inside the sealed subscription). Null = not for this user.
/// [{ id, name, url, …exit country }]: `url` is a `mtun://` link the app's microtun core runs as is.
pub fn sub_info(app: &App, u: &User) -> Value {
    let s = settings(app);
    if !s.on || !u.active() || !u.has_proto(PROTO) {
        return Value::Null;
    }
    let Some(ip) = ip_of_id(u.id) else { return Value::Null };
    let nodes = app.db.nodes();
    let tunnels = crate::tunnel::panel::tunnels(app);
    let mut out = vec![];
    for r in &s.routes {
        let Some(n) = nodes.iter().find(|n| n.id == r.exit && n.usable()) else { continue };
        // only what the exit says it runs, and only once its tunnel exists
        if crate::api::node_info(n)["kp_port"].as_u64().is_none() || !tunnels.iter().any(|t| t.id == r.tunnel && t.enabled) {
            continue;
        }
        let ms = crate::microtun::Settings { mtu: mtu(app, &s), burst_max: s.burst_max, burst_delay_ms: s.burst_delay_ms, ..Default::default() };
        let name = format!("{} · {}", n.name, NAME);
        let url = crate::microtun::to_url(&user_key(app, u), &dial(app, r), &obfs(app), ip, &ms, &name);
        let mut v = json!({ "id": r.id, "name": n.name, "url": url });
        if let (Some(o), Some(e)) = (v.as_object_mut(), crate::exitgeo::fields(app, &n.id).as_object()) {
            o.extend(e.clone());
        }
        out.push(v);
    }
    if out.is_empty() { Value::Null } else { json!(out) }
}

// ------------------------------------------------------------------ on the server (agent / main)

static KP: Runner = Runner::new(PROTO, false);

/// Brings KPING on this server to `cfg`
pub fn apply(cfg: MtCfg) -> Applied {
    KP.apply(cfg)
}

/// What this server reports (merged into its info)
pub fn info() -> Value {
    let (port, _, err) = KP.state();
    json!({ "kp_port": if port > 0 { json!(port) } else { Value::Null }, "kp_error": err })
}

// ------------------------------------------------------------------ panel API

type St = State<Arc<App>>;

pub fn router() -> Router<Arc<App>> {
    Router::new()
        .route("/api/kping", get(get_all).put(put_settings))
        .route("/api/kping/routes", post(route_save))
        .route("/api/kping/routes/:id", axum::routing::delete(route_del))
        .route("/api/kping/routes/:id/tunnel", post(route_tunnel))
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
    let nodes = app.db.nodes();
    let users = app.db.users();
    let locs = crate::tunnel::panel::server_locs(&app);
    let tservers = crate::tunnel::panel::servers(&app);
    let live = crate::tunnel::panel::live_quality(&app);
    let tsv_name = |id: &str| if id == "local" { "Main".to_string() } else { tservers.iter().find(|x| x.id == id).map(|x| x.name.clone()).unwrap_or_default() };
    let routes: Vec<Value> = s
        .routes
        .iter()
        .map(|r| {
            let n = nodes.iter().find(|n| n.id == r.exit);
            let info = n.map(crate::api::node_info).unwrap_or(Value::Null);
            let tun = live.iter().find(|x| x.0.id == r.tunnel);
            json!({
                "route": r,
                "exit_name": n.map(|n| n.name.clone()).unwrap_or_default(),
                "exit_online": n.map(|n| n.id == "local" || n.online).unwrap_or(false),
                "exit_port": info["kp_port"], "exit_error": info["kp_error"].as_str().filter(|e| !e.is_empty()),
                // an older agent knows nothing of KPING: it never reports `kp_port`
                "exit_knows": info.get("kp_error").is_some(),
                "exit_sid": crate::twin::sid_of_node(&app, &r.exit),
                "iran_name": tsv_name(&r.iran),
                "dial": dial(&app, r),
                "tunnel_built": tun.is_some(),
                "tunnel_up": tun.map(|x| x.1).unwrap_or(false),
                "tunnel_q": tun.and_then(|x| x.2.clone()),
            })
        })
        .collect();
    let exits: Vec<Value> = nodes
        .iter()
        .filter(|n| n.usable())
        .map(|n| json!({ "id": n.id, "name": n.name, "online": n.id == "local" || n.online, "sid": crate::twin::sid_of_node(&app, &n.id) }))
        .collect();
    let irans: Vec<Value> = std::iter::once(("local".to_string(), tsv_name("local")))
        .chain(tservers.iter().map(|x| (x.id.clone(), x.name.clone())))
        .filter(|(id, _)| locs.get(id).map(|l| l.0 == "iran").unwrap_or(false))
        .map(|(id, name)| json!({ "id": id, "name": name }))
        .collect();
    let with = users_of(&users);
    Json(json!({
        "settings": s, "routes": routes, "exits": exits, "irans": irans, "mtu_now": mtu(&app, &s),
        "users": with.len(), "online": with.iter().filter(|u| u.online > 0).count(),
        "user_list": users.iter().map(|u| json!({ "id": u.id, "name": u.username, "has": u.has_proto(PROTO), "active": u.active() })).collect::<Vec<_>>(),
    }))
    .into_response()
}

async fn put_settings(State(app): St, h: HeaderMap, Json(b): Json<Value>) -> Response {
    let _ = crate::guard!(app, h, "nodes");
    let mut s = settings(&app);
    if let Some(on) = b["on"].as_bool() {
        s.on = on;
    }
    if !b["port"].is_null() {
        match port_of(&b["port"]) {
            Some(p) => s.port = p,
            None => return bad("the port must be 1-65535"),
        }
    }
    if let Some(v) = b["mtu"].as_u64() {
        if !(1200..=1500).contains(&v) {
            return bad("MTU must be 1200-1500");
        }
        s.mtu = v as u16;
    }
    if let Some(v) = b["burst_max"].as_u64() {
        s.burst_max = v.min(1500) as u16;
    }
    if let Some(v) = b["burst_delay_ms"].as_u64() {
        s.burst_delay_ms = v.min(50) as u16;
    }
    if let Err(e) = port_clash(&app, &s) {
        return bad(&e);
    }
    save(&app, &s);
    crate::api::spawn_sync(&app);
    Json(json!({ "ok": true, "settings": s })).into_response()
}

/// KPING's port on an exit must not be the port of another UDP core there
fn port_clash(app: &App, s: &Settings) -> Result<(), String> {
    let km = crate::kmix::settings(app);
    let mt = crate::microtun::settings(app);
    for n in app.db.nodes().iter().filter(|n| s.exit_here(&n.id)) {
        if km.node_on(&n.id) && km.node_port(&n.id) == s.port {
            return Err(format!("KANKI MIX already uses port {} on {}", s.port, n.name));
        }
        if mt.node_on(&n.id) && mt.node_port(&n.id) == s.port {
            return Err(format!("microtun already uses port {} on {}", s.port, n.name));
        }
        let info = crate::api::node_info(n);
        for k in ["wg_port", "awg_port", "hy2_port"] {
            if info[k].as_str().and_then(|p| p.trim().parse::<u16>().ok()) == Some(s.port) {
                return Err(format!("port {} is already used on {}", s.port, n.name));
            }
        }
    }
    Ok(())
}

/// { id?, exit, iran, host, port, tunnel_port }
async fn route_save(State(app): St, h: HeaderMap, Json(b): Json<Value>) -> Response {
    let _ = crate::guard!(app, h, "nodes");
    let mut s = settings(&app);
    let id = b["id"].as_str().unwrap_or("").trim().to_string();
    let mut r = if id.is_empty() {
        Route { id: crate::util::rand_token(8).to_lowercase(), port: DEFAULT_ENTRY_PORT, tunnel_port: DEFAULT_TUNNEL_PORT, ..Default::default() }
    } else {
        match s.routes.iter().find(|r| r.id == id) {
            Some(r) => r.clone(),
            None => return bad("route not found"),
        }
    };
    let str_of = |k: &str| b[k].as_str().map(|x| x.trim().to_string());
    if let Some(v) = str_of("exit") {
        r.exit = v;
    }
    if let Some(v) = str_of("iran") {
        r.iran = v;
    }
    if let Some(v) = str_of("host") {
        if !v.is_empty() && !crate::twin::valid_host(&v) {
            return bad("the address must be a domain or an IP");
        }
        r.host = v;
    }
    if !b["port"].is_null() {
        match port_of(&b["port"]) {
            Some(p) => r.port = p,
            None => return bad("the port must be 1-65535"),
        }
    }
    if !b["tunnel_port"].is_null() {
        match port_of(&b["tunnel_port"]) {
            Some(p) => r.tunnel_port = p,
            None => return bad("the port must be 1-65535"),
        }
    }
    if !app.db.nodes().iter().any(|n| n.id == r.exit) {
        return bad("choose the server abroad");
    }
    if crate::twin::sid_of_node(&app, &r.exit).is_empty() {
        return bad("this server abroad has no tunnel agent yet");
    }
    let known = r.iran == "local" || crate::tunnel::panel::servers(&app).iter().any(|x| x.id == r.iran);
    if !known {
        return bad("choose the Iran server");
    }
    if r.port == r.tunnel_port {
        return bad("the users' port and the tunnel port must differ");
    }
    if s.routes.iter().any(|x| x.id != r.id && x.iran == r.iran && [x.port, x.tunnel_port].iter().any(|p| *p == r.port || *p == r.tunnel_port)) {
        return bad("another KPING route already uses this port on this Iran server");
    }
    if s.routes.iter().any(|x| x.id != r.id && x.exit == r.exit && x.iran == r.iran) {
        return bad("this Iran server already leads to this server");
    }
    match s.routes.iter_mut().find(|x| x.id == r.id) {
        Some(x) => *x = r.clone(),
        None => s.routes.push(r.clone()),
    }
    if let Err(e) = port_clash(&app, &s) {
        return bad(&e);
    }
    save(&app, &s);
    crate::api::spawn_sync(&app);
    Json(json!({ "ok": true, "route": r })).into_response()
}

async fn route_del(State(app): St, h: HeaderMap, Path(id): Path<String>) -> Response {
    let _ = crate::guard!(app, h, "nodes");
    let mut s = settings(&app);
    let Some(r) = s.routes.iter().find(|r| r.id == id).cloned() else { return bad("route not found") };
    s.routes.retain(|x| x.id != id);
    save(&app, &s);
    crate::api::spawn_sync(&app);
    // its tunnel is removed by the page (the Tunnels page's own removal, with its steps)
    Json(json!({ "ok": true, "tunnel": r.tunnel })).into_response()
}

/// The tunnel of a route: reverse (the exit dials Iran), Game-FEC 8:3, only the users' UDP port
/// (Iran `port` → exit KPING port). Built again in place when it exists.
fn tunnel_body(app: &App, s: &Settings, r: &Route) -> Value {
    let exit_name = app.db.nodes().into_iter().find(|n| n.id == r.exit).map(|n| n.name).unwrap_or_default();
    json!({
        "id": r.tunnel, "name": format!("{} · {}", NAME, exit_name),
        "entry": r.iran, "exit": crate::twin::sid_of_node(app, &r.exit),
        "mode": "reverse", "transport": "game", "fec": FEC, "dup": false,
        "port": r.tunnel_port, "conns": 1, "tcp": [], "udp": [format!("{}:{}", r.port, s.port)],
        "auto": false, "enabled": true,
    })
}

async fn route_tunnel(State(app): St, h: HeaderMap, Path(id): Path<String>) -> Response {
    let _ = crate::guard!(app, h, "nodes");
    let s = settings(&app);
    let Some(mut r) = s.routes.iter().find(|r| r.id == id).cloned() else { return bad("route not found") };
    // a tunnel removed on the Tunnels page is made again
    if !r.tunnel.is_empty() && !crate::tunnel::panel::tunnels(&app).iter().any(|t| t.id == r.tunnel) {
        r.tunnel.clear();
    }
    let resp = crate::tunnel::panel::save_json(app.clone(), h, tunnel_body(&app, &s, &r)).await;
    if resp.status() != StatusCode::OK {
        return resp;
    }
    let Ok(body) = axum::body::to_bytes(resp.into_body(), 1 << 16).await else { return bad("the tunnel was not saved") };
    let tid = serde_json::from_slice::<Value>(&body).ok().and_then(|v| v["id"].as_str().map(String::from)).unwrap_or_default();
    let mut s = settings(&app);
    if let Some(x) = s.routes.iter_mut().find(|x| x.id == id) {
        x.tunnel = tid.clone();
    }
    save(&app, &s);
    crate::api::spawn_sync(&app);
    Json(json!({ "ok": true, "tunnel": tid })).into_response()
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
        crate::api::spawn_sync(&app);
    }
    Json(json!({ "ok": true })).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_do_not_meet_microtun() {
        assert_eq!(ip_of_id(1), Some(Ipv4Addr::new(10, 81, 0, 2)));
        assert!(ip_of_id(0).is_none() && ip_of_id(65534).is_none());
        assert_ne!(SERVER_ADDR, "10.79.0.1/16");
    }

    fn test_app() -> Arc<App> {
        use std::sync::{atomic::AtomicI64, Mutex};
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

    /// A route and its tunnel from the panel page: the tunnel goes through every check of the Tunnels page
    /// and carries only the users' port, reverse, Game-FEC 8:3
    #[tokio::test]
    async fn one_button_builds_the_routes_own_tunnel() {
        let app = test_app();
        app.db.set("api_key", "test-key");
        app.db.exec("INSERT INTO nodes(id,name,address,endpoint,token,info,online) VALUES('de','Germany','de.example.com','de.example.com','t','{}',1)", &[]).unwrap();
        let srv = json!([{ "id": "ir1", "name": "Tehran", "token": "x", "addr": "ir.example.com", "loc": "iran" }, { "id": "s-de", "name": "Germany", "token": "y", "node": "de" }]);
        app.db.set("tun_servers", &srv.to_string());
        // the Iran server is offered, the exit needs its tunnel agent
        let (st, v) = call(&app, "GET", "/api/kping", Value::Null).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(v["irans"][0]["id"], "ir1");
        assert!(v["exits"].as_array().unwrap().iter().any(|x| x["id"] == "de" && x["sid"] == "s-de"));
        let (st, v) = call(&app, "POST", "/api/kping/routes", json!({ "exit": "de", "iran": "ir1" })).await;
        assert_eq!(st, StatusCode::OK, "{}", v);
        let rid = v["route"]["id"].as_str().unwrap().to_string();
        // the same pair twice, or a clash of ports, is refused
        let (st, _) = call(&app, "POST", "/api/kping/routes", json!({ "exit": "de", "iran": "ir1" })).await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
        let (st, v) = call(&app, "POST", &format!("/api/kping/routes/{}/tunnel", rid), Value::Null).await;
        assert_eq!(st, StatusCode::OK, "{}", v);
        let tid = v["tunnel"].as_str().unwrap().to_string();
        let t = crate::tunnel::panel::tunnels(&app).into_iter().find(|t| t.id == tid).unwrap();
        assert_eq!((t.entry.as_str(), t.exit.as_str(), t.mode.as_str(), t.transport.as_str(), t.fec.as_str(), t.port), ("ir1", "s-de", "reverse", "game", "8:3", DEFAULT_TUNNEL_PORT));
        assert_eq!(t.udp, vec![format!("{}:{}", DEFAULT_ENTRY_PORT, DEFAULT_PORT)]);
        assert!(t.tcp.is_empty());
        assert_eq!(settings(&app).routes[0].tunnel, tid);
        // building again keeps the same tunnel
        let (_, v) = call(&app, "POST", &format!("/api/kping/routes/{}/tunnel", rid), Value::Null).await;
        assert_eq!(v["tunnel"], tid.as_str());
        assert_eq!(crate::tunnel::panel::tunnels(&app).len(), 1);
        // testers: only by the admin, one by one
        let u = app.db.create_user("GAMER", 10.0, 30, 1, "wg", "", "", 0).unwrap();
        let (st, _) = call(&app, "POST", "/api/kping/users", json!({ "id": u.id, "on": true })).await;
        assert_eq!(st, StatusCode::OK);
        assert!(app.db.user(u.id).unwrap().has_proto(PROTO));
        let (_, v) = call(&app, "GET", "/api/kping", Value::Null).await;
        assert_eq!(v["users"], 1);
        // the route goes, its tunnel id comes back for the page to remove it
        let (_, v) = call(&app, "DELETE", &format!("/api/kping/routes/{}", rid), Value::Null).await;
        assert_eq!(v["tunnel"], tid.as_str());
        assert!(settings(&app).routes.is_empty());
    }

    #[test]
    fn only_exits_run_it() {
        let mut s = Settings::default();
        s.routes.push(Route { id: "r".into(), exit: "de".into(), iran: "ir".into(), ..Default::default() });
        assert!(s.exit_here("de") && !s.exit_here("ir") && !s.exit_here("local"));
        s.on = false;
        assert!(!s.exit_here("de"));
    }
}

/// The whole way on this machine, as on the real servers: microtun (`mtun0`) and KPING (`kping0`) side by
/// side, a reverse Game-FEC tunnel (Iran port 23300 → KPING 23310), and the link of a tester written to
/// $KPING_LINK for the app's own client to dial (`scripts/kping-client`: `go build` there, then run it with the link file). Needs root.
#[cfg(test)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn kping_live() {
    use crate::tunnel::engine::{Running, Spec};
    let obfs = "ab".repeat(32);
    let key = "cd".repeat(32);
    let user = |ip: &str| vec![MtUser { name: "gamer".into(), key: key.clone(), ip: ip.into(), max: 2 }];
    let base = MtCfg { obfs: obfs.clone(), mtu: 1324, burst_max: 1000, burst_delay_ms: 2, ..Default::default() };
    let mt = MtCfg { port: 23320, address: "10.79.0.1/16".into(), users: user("10.79.0.2"), ..base.clone() };
    let kp = MtCfg { port: 23310, address: SERVER_ADDR.into(), devices: DEVICES_ADDR.into(), users: user("10.81.0.2"), iface: IFACE.into(), local_only: true, ..base };
    let a = crate::microtun::apply(mt);
    let b = apply(kp);
    assert!(a.2.is_empty() && b.2.is_empty(), "microtun: {} KPING: {}", a.2, b.2);
    let common = Spec {
        id: "kp".into(), name: "KPING".into(), mode: "reverse".into(), transport: "game".into(), port: 23301,
        token: "token-for-tests-0123456789".into(), conns: 1, udp: vec!["23300:23310".into()], target: "127.0.0.1".into(),
        fec: "8:3".into(), remote: "127.0.0.1:23301".into(), ..Default::default()
    };
    let entry = Running::start(Spec { role: "entry".into(), ..common.clone() });
    let exit = Running::start(Spec { role: "exit".into(), ..common });
    for _ in 0..100 {
        if entry.status().links > 0 && exit.status().links > 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(entry.status().links > 0, "the tunnel did not connect: {:?}", entry.status().error);
    let ms = crate::microtun::Settings { mtu: 1324, burst_max: 1000, burst_delay_ms: 2, ..Default::default() };
    let link = crate::microtun::to_url(&key, "127.0.0.1:23300", &obfs, Ipv4Addr::new(10, 81, 0, 2), &ms, "Test · KPING");
    std::fs::write(std::env::var("KPING_LINK").unwrap_or("/tmp/kping.link".into()), &link).unwrap();
    println!("READY {}", link);
    let secs: u64 = std::env::var("KPING_SECS").ok().and_then(|s| s.parse().ok()).unwrap_or(40);
    tokio::time::sleep(std::time::Duration::from_secs(secs)).await;
    let (tr, on, _) = apply(MtCfg { port: 23310, address: SERVER_ADDR.into(), devices: DEVICES_ADDR.into(), users: user("10.81.0.2"), iface: IFACE.into(), local_only: true, obfs: obfs.clone(), mtu: 1324, burst_max: 1000, burst_delay_ms: 2, ..Default::default() });
    println!("KPING traffic {:?} online {:?}; tunnel entry {:?}", tr, on, entry.status());
    // nothing of it went to microtun
    let (mt_tr, _, _) = crate::microtun::apply(MtCfg { port: 23320, address: "10.79.0.1/16".into(), users: user("10.79.0.2"), obfs, mtu: 1324, burst_max: 1000, burst_delay_ms: 2, ..Default::default() });
    println!("microtun traffic {:?}", mt_tr);
    apply(MtCfg::default());
    crate::microtun::apply(MtCfg::default());
    entry.stop();
    exit.stop();
}
