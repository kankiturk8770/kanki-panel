//! KPING: the hidden game core, in the panel. Only a few users the admin ticks get it, only the Kanki app
//! receives its config (inside the sealed subscription, never on the subscription page, in links or the
//! bot), and the app sends only PUBG (plus the DNS and Google services the game logs in with) through it.
//!
//! The path: phone → Iran server (the KPING relay, a public UDP port) → its own reverse Game-FEC tunnel
//! → the exit server abroad (`kping0`, NAT out) → the game. Relay and exit run in the tunnel agent of
//! those servers (`kpingd`): an exit needs no VPN part, only the agent (`agent_only` servers, added from
//! the KPING page). Plain UDP with copies and light parity, not microtun: see `kpingd` for the wire.
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
/// UDP port the app dials on the Iran server, and the port of the tunnel itself there (the tunnel's own
/// entry for KPING is the next one, on 127.0.0.1)
pub const DEFAULT_ENTRY_PORT: u16 = 24300;
pub const DEFAULT_TUNNEL_PORT: u16 = 24301;
/// users get 10.81.0.2 … by id (microtun is 10.79, its devices 10.80)
const BASE: u32 = u32::from_be_bytes([10, 81, 0, 0]);
/// FEC of the tunnel: 8 packets + 3 repair packets (any 3 of 11 may be lost)
const FEC: &str = "8:3";

/// One way in: users dial `iran`, its tunnel brings them to `exit`
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(default)]
pub struct Route {
    pub id: String,
    /// the server abroad that runs the exit (tunnel server id; any server with the tunnel agent)
    pub exit: String,
    /// the Iran server users connect to (tunnel server id)
    pub iran: String,
    /// address the app dials ("" = the Iran server's own address)
    pub host: String,
    /// UDP port the app dials on the Iran server (the relay)
    pub port: u16,
    /// the tunnel's own port on the Iran server (the exit dials it: reverse); the tunnel takes KPING's
    /// packets on the next port, on 127.0.0.1
    pub tunnel_port: u16,
    /// the tunnel built for this route ("" = not built yet)
    pub tunnel: String,
    /// a second tunnel to the same exit (its own port, its own UDP flow): every packet goes through both
    /// and the first copy wins, so a stall or a throttled flow on one of them costs nothing ("" = none)
    pub tunnel2: String,
    /// that tunnel's own port on the Iran server (0 = not chosen yet: the first tunnel's port + 2)
    pub tunnel2_port: u16,
}

impl Route {
    /// the tunnel's entry for KPING on the Iran server (127.0.0.1 only)
    pub fn inner(&self) -> u16 {
        self.tunnel_port.wrapping_add(1)
    }
    pub fn port2(&self) -> u16 {
        if self.tunnel2_port == 0 { self.tunnel_port.wrapping_add(2) } else { self.tunnel2_port }
    }
    /// the second tunnel's entry for KPING on the Iran server
    pub fn inner2(&self) -> u16 {
        self.port2().wrapping_add(1)
    }
    /// every port this route takes on its Iran server
    fn ports(&self) -> Vec<u16> {
        let mut v = vec![self.port, self.tunnel_port, self.inner()];
        if !self.tunnel2.is_empty() || self.tunnel2_port != 0 {
            v.extend([self.port2(), self.inner2()]);
        }
        v
    }
}

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
    pub routes: Vec<Route>,
}

impl Default for Settings {
    fn default() -> Self {
        Settings { on: true, port: DEFAULT_PORT, mtu: 1332, dup_ms: 10, tun_dup_ms: 20, fec: 2, routes: vec![] }
    }
}

pub fn settings(app: &App) -> Settings {
    let mut s: Settings = serde_json::from_str(&app.db.get("kping_cfg")).unwrap_or_default();
    if s.port == 0 {
        s.port = DEFAULT_PORT;
    }
    s.mtu = s.mtu.clamp(1200, 1500);
    s.dup_ms = s.dup_ms.min(20);
    s.tun_dup_ms = s.tun_dup_ms.min(30);
    s.fec = s.fec.min(crate::kpingd::MAX_GROUP as u8);
    // 3.37-3.38 kept the exit as a VPN node id: now it is the tunnel server of that machine
    let tservers = crate::tunnel::panel::servers(app);
    for r in s.routes.iter_mut() {
        if r.exit != "local" && !tservers.iter().any(|x| x.id == r.exit) {
            let sid = crate::twin::sid_of_node(app, &r.exit);
            if !sid.is_empty() {
                r.exit = sid;
            }
        }
    }
    s
}

fn save(app: &App, s: &Settings) {
    app.db.set("kping_cfg", &serde_json::to_string(s).unwrap_or_default());
}

/// A removed server (tunnel server or VPN node) takes its routes with it
/// One route goes (its server is gone)
pub fn forget_route(app: &App, id: &str) {
    let mut s = settings(app);
    let n = s.routes.len();
    s.routes.retain(|r| r.id != id);
    if s.routes.len() != n {
        save(app, &s);
    }
}

pub fn forget_node(app: &App, id: &str) {
    let mut s = settings(app);
    let n = s.routes.len();
    let sid = crate::twin::sid_of_node(app, id);
    s.routes.retain(|r| r.exit != id && r.iran != id && (sid.is_empty() || r.exit != sid));
    if s.routes.len() != n {
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
    // a user at the account's connection limit whose devices are elsewhere is not let in here
    let shut: Vec<i64> = {
        let l = crate::sync::limits().lock().unwrap_or_else(|e| e.into_inner());
        users.iter().filter(|u| l.shut_proto(u.id, PROTO)).map(|u| u.id).collect()
    };
    users_of(users)
        .into_iter()
        .filter(|u| !shut.contains(&u.id))
        .filter_map(|u| Some(KUser { uid: u32::try_from(u.id).ok()?, name: u.username.clone(), key: user_key(app, u), ip: ip_of_id(u.id)?.to_string() }))
        .collect()
}

/// What tunnel server `sid` runs: the relays of routes that start there, the exit when routes end there
pub fn cfg_for(app: &App, sid: &str) -> KpCfg {
    let s = settings(app);
    if !s.on || !s.routes.iter().any(|r| r.iran == sid || r.exit == sid) {
        return KpCfg::default();
    }
    let users = kusers(app, &app.db.users());
    let relays = s
        .routes
        .iter()
        .filter(|r| r.iran == sid && !r.tunnel.is_empty())
        .map(|r| RelayCfg { port: r.port, to: r.inner(), more: if r.tunnel2.is_empty() { vec![] } else { vec![r.inner2()] }, dup_ms: s.dup_ms, tun_dup_ms: s.tun_dup_ms, users: users.iter().map(|u| KUser { ip: String::new(), ..u.clone() }).collect() })
        .collect();
    let exit = s.routes.iter().any(|r| r.exit == sid).then(|| ExitCfg { port: s.port, mtu: mtu(app, &s), fec: s.fec, tun_dup_ms: s.tun_dup_ms, users: users.clone() });
    KpCfg { obfs: obfs(app), relays, exit }
}

/// The tunnel of a KPING route takes its packets only on 127.0.0.1 (the relay sits in front of it)
pub fn is_tunnel(app: &App, tid: &str) -> bool {
    settings(app).routes.iter().any(|r| r.tunnel == tid || (!r.tunnel2.is_empty() && r.tunnel2 == tid))
}

// ------------------------------------------------------------------ what the servers report

/// sid -> (when, report)
fn reports() -> &'static Mutex<HashMap<String, (i64, Value)>> {
    static R: OnceLock<Mutex<HashMap<String, (i64, Value)>>> = OnceLock::new();
    R.get_or_init(Default::default)
}

/// A server's KPING report: traffic counts on the user, online users are seen now
pub fn ingest(app: &App, sid: &str, st: &Value) {
    if st.is_null() {
        reports().lock().unwrap_or_else(|e| e.into_inner()).remove(sid);
        return;
    }
    let now = crate::util::now();
    reports().lock().unwrap_or_else(|e| e.into_inner()).insert(sid.to_string(), (now, st.clone()));
    let x = &st["exit"];
    crate::dns::panel::count_usage(app, &format!("kping_prev_{}", sid), x);
    for id in x["online"].as_array().into_iter().flatten().filter_map(|v| v.as_i64()) {
        let _ = app.db.exec("UPDATE users SET last_seen=?1 WHERE id=?2", &[&now, &id]);
    }
}

/// KPING in the account's connection limit (all cores and servers together): each user an exit saw in
/// the last minute is one device on "kp:<server>". Also the servers that answered.
pub fn live_units(now: i64) -> (Vec<(i64, String, String, i64)>, std::collections::HashSet<String>) {
    let r = reports().lock().unwrap_or_else(|e| e.into_inner());
    let mut units = vec![];
    let mut answered = std::collections::HashSet::new();
    for (sid, (t, v)) in r.iter().filter(|(_, (t, _))| now - t < 60) {
        let _ = t;
        let node = format!("kp:{}", sid);
        answered.insert(node.clone());
        for id in v["exit"]["online"].as_array().into_iter().flatten().filter_map(|x| x.as_i64()) {
            units.push((id, node.clone(), PROTO.to_string(), 1));
        }
    }
    (units, answered)
}

/// The last report of `sid` when fresh (a minute)
fn report_of(sid: &str) -> Option<Value> {
    let r = reports().lock().unwrap_or_else(|e| e.into_inner());
    r.get(sid).filter(|(t, _)| crate::util::now() - t < 60).map(|(_, v)| v.clone())
}

/// (exit runs, its error)
fn exit_state(sid: &str) -> (bool, String) {
    match report_of(sid) {
        Some(v) => (v["exit"]["port"].as_u64().is_some(), v["exit"]["error"].as_str().unwrap_or("").to_string()),
        None => (false, String::new()),
    }
}

/// the relay of `port` on `sid`: its status, or Null
fn relay_state(sid: &str, port: u16) -> Value {
    report_of(sid).and_then(|v| v["relays"].as_array().and_then(|a| a.iter().find(|x| x["port"].as_u64() == Some(port as u64)).cloned())).unwrap_or(Value::Null)
}

fn online(sid: &str) -> bool {
    sid == "local" || crate::tunnel::panel::agent_state(sid).is_some_and(|x| crate::util::now() - x.0 < 30)
}

// ------------------------------------------------------------------ the app's config

/// Where the app dials a route: "host:port"
fn dial(app: &App, r: &Route) -> String {
    if r.host.trim().is_empty() {
        crate::tunnel::panel::dial_addr(app, &r.iran, r.port)
    } else {
        let h = r.host.trim();
        if h.contains(':') && !h.starts_with('[') { format!("[{}]:{}", h, r.port) } else { format!("{}:{}", h, r.port) }
    }
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

fn exit_name(app: &App, sid: &str) -> String {
    let n = crate::tunnel::panel::server_names(app).get(sid).cloned().filter(|n| !n.is_empty());
    n.unwrap_or_else(|| if sid == "local" { app.env.get("LOCAL_NAME").cloned().unwrap_or_else(|| "Main".into()) } else { sid.to_string() })
}

/// KPING for the Kanki app (only inside the sealed subscription). Null = not for this user.
/// [{ id, node, name, url, …exit country }]
pub fn sub_info(app: &App, u: &User) -> Value {
    let s = settings(app);
    if !s.on || !u.active() || !u.has_proto(PROTO) {
        return Value::Null;
    }
    let (Some(ip), Ok(uid)) = (ip_of_id(u.id), u32::try_from(u.id)) else { return Value::Null };
    let tunnels = crate::tunnel::panel::tunnels(app);
    let tservers = crate::tunnel::panel::servers(app);
    let mut out = vec![];
    for r in &s.routes {
        // only once its tunnel exists
        if !tunnels.iter().any(|t| t.id == r.tunnel && t.enabled) {
            continue;
        }
        let ename = exit_name(app, &r.exit);
        let node = if r.exit == "local" { "local".to_string() } else { tservers.iter().find(|x| x.id == r.exit).map(|x| x.node.clone()).unwrap_or_default() };
        let name = format!("{} · {}", ename, NAME);
        let url = to_url(&user_key(app, u), &dial(app, r), uid, &obfs(app), ip, mtu(app, &s), s.fec, &name);
        // `node`: the VPN server of that machine (when it has one), so the app lists KPING under it
        let mut v = json!({ "id": r.id, "node": node, "name": ename, "url": url });
        if !node.is_empty() {
            if let (Some(o), Some(e)) = (v.as_object_mut(), crate::exitgeo::fields(app, &node).as_object()) {
                o.extend(e.clone());
            }
        }
        out.push(v);
    }
    if out.is_empty() { Value::Null } else { json!(out) }
}

// ------------------------------------------------------------------ panel API

type St = State<Arc<App>>;

pub fn router() -> Router<Arc<App>> {
    Router::new()
        .route("/api/kping", get(get_all).put(put_settings))
        .route("/api/kping/routes", post(route_save))
        .route("/api/kping/routes/:id", axum::routing::delete(route_del))
        .route("/api/kping/routes/:id/tunnel", post(route_tunnel))
        .route("/api/kping/routes/:id/tunnel2", post(route_tunnel2).delete(route_tunnel2_del))
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
    let locs = crate::tunnel::panel::server_locs(&app);
    let names = crate::tunnel::panel::server_names(&app);
    let tservers = crate::tunnel::panel::servers(&app);
    let live = crate::tunnel::panel::live_quality(&app);
    let name_of = |id: &str| names.get(id).cloned().filter(|n| !n.is_empty()).unwrap_or_else(|| if id == "local" { app.env.get("LOCAL_NAME").cloned().unwrap_or_else(|| "Main".into()) } else { String::new() });
    let routes: Vec<Value> = s
        .routes
        .iter()
        .map(|r| {
            let tun = live.iter().find(|x| x.0.id == r.tunnel);
            let tun2 = live.iter().find(|x| !r.tunnel2.is_empty() && x.0.id == r.tunnel2);
            let (runs, err) = exit_state(&r.exit);
            let rep = report_of(&r.exit);
            json!({
                "route": r,
                "exit_name": name_of(&r.exit),
                "exit_online": online(&r.exit),
                "exit_runs": runs, "exit_error": (!err.is_empty()).then_some(err),
                // an older agent knows nothing of KPING v2: online, yet it never reports it
                "exit_knows": rep.is_some() || !online(&r.exit),
                "exit_stats": rep.map(|v| v["exit"].clone()).unwrap_or(Value::Null),
                "iran_name": name_of(&r.iran),
                "iran_online": online(&r.iran),
                "relay": relay_state(&r.iran, r.port),
                "dial": dial(&app, r),
                "tunnel_built": tun.is_some(),
                "tunnel_up": tun.map(|x| x.1).unwrap_or(false),
                "tunnel_q": tun.and_then(|x| x.2.clone()),
                "tunnel2_built": tun2.is_some(),
                "tunnel2_up": tun2.map(|x| x.1).unwrap_or(false),
            })
        })
        .collect();
    let all: Vec<(String, String)> = std::iter::once(("local".to_string(), name_of("local"))).chain(tservers.iter().map(|x| (x.id.clone(), x.name.clone()))).collect();
    let is_iran = |id: &str| locs.get(id).map(|l| l.0 == "iran").unwrap_or(false);
    let exits: Vec<Value> = all
        .iter()
        .filter(|(id, _)| !is_iran(id))
        .map(|(id, name)| {
            let t = tservers.iter().find(|x| &x.id == id);
            json!({ "id": id, "name": name, "online": online(id), "sid": id, "agent_only": t.map(|t| t.node.is_empty()).unwrap_or(false) })
        })
        .collect();
    let irans: Vec<Value> = all.iter().filter(|(id, _)| is_iran(id)).map(|(id, name)| json!({ "id": id, "name": name, "online": online(id) })).collect();
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
    let tservers = crate::tunnel::panel::servers(&app);
    let known = |id: &str| id == "local" || tservers.iter().any(|x| x.id == id);
    let str_of = |k: &str| b[k].as_str().map(|x| x.trim().to_string());
    if let Some(v) = str_of("exit") {
        // a VPN node id from an older page: its tunnel server
        let sid = crate::twin::sid_of_node(&app, &v);
        r.exit = if !known(&v) && !sid.is_empty() { sid } else { v };
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
        match port_of(&b["tunnel_port"]).filter(|p| *p < 65535) {
            Some(p) => r.tunnel_port = p,
            None => return bad("the port must be 1-65534"),
        }
    }
    if !b["tunnel2_port"].is_null() {
        match port_of(&b["tunnel2_port"]).filter(|p| *p < 65535) {
            Some(p) => r.tunnel2_port = p,
            None => return bad("the port must be 1-65534"),
        }
    }
    if !known(&r.exit) {
        return bad("choose the server abroad");
    }
    if !known(&r.iran) {
        return bad("choose the Iran server");
    }
    if r.exit == r.iran {
        return bad("the Iran server and the server abroad must differ");
    }
    let mine = r.ports();
    if mine.iter().enumerate().any(|(i, p)| mine[..i].contains(p)) {
        return bad("the users' port and the tunnel ports must differ");
    }
    if s.routes.iter().any(|x| x.id != r.id && x.iran == r.iran && x.ports().iter().any(|p| mine.contains(p))) {
        return bad("another KPING route already uses this port on this Iran server");
    }
    if s.routes.iter().any(|x| x.id != r.id && x.exit == r.exit && x.iran == r.iran) {
        return bad("this Iran server already leads to this server");
    }
    match s.routes.iter_mut().find(|x| x.id == r.id) {
        Some(x) => *x = r.clone(),
        None => s.routes.push(r.clone()),
    }
    save(&app, &s);
    Json(json!({ "ok": true, "route": r })).into_response()
}

async fn route_del(State(app): St, h: HeaderMap, Path(id): Path<String>) -> Response {
    let _ = crate::guard!(app, h, "nodes");
    let mut s = settings(&app);
    let Some(r) = s.routes.iter().find(|r| r.id == id).cloned() else { return bad("route not found") };
    s.routes.retain(|x| x.id != id);
    save(&app, &s);
    // its tunnels are removed by the page (the Tunnels page's own removal, with its steps)
    Json(json!({ "ok": true, "tunnel": r.tunnel, "tunnel2": r.tunnel2 })).into_response()
}

/// The tunnel of a route: reverse (the exit dials Iran), Game-FEC 8:3, only KPING's UDP (Iran
/// 127.0.0.1:`inner` → exit 127.0.0.1:KPING port). Built again in place when it exists.
fn tunnel_body(app: &App, s: &Settings, r: &Route) -> Value {
    json!({
        "id": r.tunnel, "name": format!("{} · {}", NAME, exit_name(app, &r.exit)),
        "entry": r.iran, "exit": r.exit,
        "mode": "reverse", "transport": "game", "fec": FEC, "dup": false,
        "port": r.tunnel_port, "conns": 1, "tcp": [], "udp": [format!("{}:{}", r.inner(), s.port)],
        "auto": false, "enabled": true,
    })
}

/// The second tunnel of a route: the same as the first, on its own port and KPING entry
fn tunnel2_body(app: &App, s: &Settings, r: &Route) -> Value {
    json!({
        "id": r.tunnel2, "name": format!("{} 2 · {}", NAME, exit_name(app, &r.exit)),
        "entry": r.iran, "exit": r.exit,
        "mode": "reverse", "transport": "game", "fec": FEC, "dup": false,
        "port": r.port2(), "conns": 1, "tcp": [], "udp": [format!("{}:{}", r.inner2(), s.port)],
        "auto": false, "enabled": true,
    })
}

async fn route_tunnel2(State(app): St, h: HeaderMap, Path(id): Path<String>) -> Response {
    let _ = crate::guard!(app, h, "nodes");
    let s = settings(&app);
    let Some(mut r) = s.routes.iter().find(|r| r.id == id).cloned() else { return bad("route not found") };
    if r.tunnel.is_empty() {
        return bad("build the route's first tunnel first");
    }
    if !r.tunnel2.is_empty() && !crate::tunnel::panel::tunnels(&app).iter().any(|t| t.id == r.tunnel2) {
        r.tunnel2.clear();
    }
    if r.tunnel2_port == 0 {
        r.tunnel2_port = r.port2();
    }
    let mine = r.ports();
    if s.routes.iter().any(|x| x.id != r.id && x.iran == r.iran && x.ports().iter().any(|p| mine.contains(p))) {
        return bad("another KPING route already uses the second tunnel's port on this Iran server");
    }
    let resp = crate::tunnel::panel::save_json(app.clone(), h, tunnel2_body(&app, &s, &r)).await;
    if resp.status() != StatusCode::OK {
        return resp;
    }
    let Ok(body) = axum::body::to_bytes(resp.into_body(), 1 << 16).await else { return bad("the tunnel was not saved") };
    let tid = serde_json::from_slice::<Value>(&body).ok().and_then(|v| v["id"].as_str().map(String::from)).unwrap_or_default();
    let mut s = settings(&app);
    if let Some(x) = s.routes.iter_mut().find(|x| x.id == id) {
        x.tunnel2 = tid.clone();
        x.tunnel2_port = r.tunnel2_port;
    }
    save(&app, &s);
    Json(json!({ "ok": true, "tunnel2": tid })).into_response()
}

/// The route goes back to one tunnel; the page removes the tunnel itself (its id comes back)
async fn route_tunnel2_del(State(app): St, h: HeaderMap, Path(id): Path<String>) -> Response {
    let _ = crate::guard!(app, h, "nodes");
    let mut s = settings(&app);
    let Some(x) = s.routes.iter_mut().find(|x| x.id == id) else { return bad("route not found") };
    let tid = std::mem::take(&mut x.tunnel2);
    save(&app, &s);
    Json(json!({ "ok": true, "tunnel2": tid })).into_response()
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
        assert_ne!(crate::kpingd::SERVER_ADDR, "10.79.0.1/16");
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

    /// A route and its tunnel from the panel page: the exit is any server with the tunnel agent (here one
    /// added from the KPING page, agent only), the tunnel goes through every check of the Tunnels page and
    /// carries only KPING's inner port, reverse, Game-FEC 8:3; each server gets its part of the config
    #[tokio::test]
    async fn one_button_builds_the_routes_own_tunnel() {
        let app = test_app();
        app.db.set("api_key", "test-key");
        let srv = json!([{ "id": "ir1", "name": "Tehran", "token": "x", "addr": "ir.example.com", "loc": "iran" }]);
        app.db.set("tun_servers", &srv.to_string());
        // a new exit abroad: only the agent, no VPN part to install
        let (st, v) = call(&app, "POST", "/api/servers", json!({ "name": "Frankfurt", "loc": "abroad", "agent_only": true })).await;
        assert_eq!(st, StatusCode::OK, "{}", v);
        let de = v["id"].as_str().unwrap().to_string();
        let cmd = v["command"].as_str().unwrap();
        assert!(!cmd.contains("KANKI_JOIN"), "an agent-only server installs no VPN part: {}", cmd);
        let (st, v) = call(&app, "GET", "/api/kping", Value::Null).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(v["irans"][0]["id"], "ir1");
        assert!(v["exits"].as_array().unwrap().iter().any(|x| x["id"] == de.as_str() && x["agent_only"] == true));
        let (st, v) = call(&app, "POST", "/api/kping/routes", json!({ "exit": de, "iran": "ir1" })).await;
        assert_eq!(st, StatusCode::OK, "{}", v);
        let rid = v["route"]["id"].as_str().unwrap().to_string();
        // the same pair twice is refused
        let (st, _) = call(&app, "POST", "/api/kping/routes", json!({ "exit": de, "iran": "ir1" })).await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
        // no relay until the tunnel is built
        assert!(cfg_for(&app, "ir1").relays.is_empty());
        let (st, v) = call(&app, "POST", &format!("/api/kping/routes/{}/tunnel", rid), Value::Null).await;
        assert_eq!(st, StatusCode::OK, "{}", v);
        let tid = v["tunnel"].as_str().unwrap().to_string();
        let t = crate::tunnel::panel::tunnels(&app).into_iter().find(|t| t.id == tid).unwrap();
        assert_eq!((t.entry.as_str(), t.exit.as_str(), t.mode.as_str(), t.transport.as_str(), t.fec.as_str(), t.port), ("ir1", de.as_str(), "reverse", "game", "8:3", DEFAULT_TUNNEL_PORT));
        assert_eq!(t.udp, vec![format!("{}:{}", DEFAULT_TUNNEL_PORT + 1, DEFAULT_PORT)]);
        assert!(t.tcp.is_empty());
        // the tunnel's KPING port listens on 127.0.0.1 only: the relay is the way in
        let spec = crate::tunnel::panel::specs_of(&app, "ir1").into_iter().find(|s| s.id == tid).unwrap();
        assert_eq!(spec.bind, "127.0.0.1");
        // building again keeps the same tunnel
        let (_, v) = call(&app, "POST", &format!("/api/kping/routes/{}/tunnel", rid), Value::Null).await;
        assert_eq!(v["tunnel"], tid.as_str());
        assert_eq!(crate::tunnel::panel::tunnels(&app).len(), 1);
        // v3: a second tunnel to the same exit, on its own port; the relay gets its entry as a second way in
        let (st, v) = call(&app, "POST", &format!("/api/kping/routes/{}/tunnel2", rid), Value::Null).await;
        assert_eq!(st, StatusCode::OK, "{}", v);
        let tid2 = v["tunnel2"].as_str().unwrap().to_string();
        assert_ne!(tid2, tid);
        let t2 = crate::tunnel::panel::tunnels(&app).into_iter().find(|t| t.id == tid2).unwrap();
        assert_eq!((t2.transport.as_str(), t2.port), ("game", DEFAULT_TUNNEL_PORT + 2));
        assert_eq!(t2.udp, vec![format!("{}:{}", DEFAULT_TUNNEL_PORT + 3, DEFAULT_PORT)]);
        assert!(is_tunnel(&app, &tid2));
        // a route whose ports meet the second tunnel's is refused
        let (st, _) = call(&app, "POST", "/api/kping/routes", json!({ "exit": "local", "iran": "ir1", "port": DEFAULT_TUNNEL_PORT + 3, "tunnel_port": 26000 })).await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
        // removing it: the route goes back to one tunnel, its id comes back for the page
        let (_, v) = call(&app, "DELETE", &format!("/api/kping/routes/{}/tunnel2", rid), Value::Null).await;
        assert_eq!(v["tunnel2"], tid2.as_str());
        let (_, v) = call(&app, "POST", &format!("/api/kping/routes/{}/tunnel2", rid), Value::Null).await;
        let tid2 = v["tunnel2"].as_str().unwrap().to_string();
        // testers: only by the admin, one by one
        let u = app.db.create_user("GAMER", 10.0, 30, 1, "wg", "", "", 0).unwrap();
        let (st, _) = call(&app, "POST", "/api/kping/users", json!({ "id": u.id, "on": true })).await;
        assert_eq!(st, StatusCode::OK);
        let u = app.db.user(u.id).unwrap();
        assert!(u.has_proto(PROTO));
        // the Iran server relays on the users' port into the tunnel; the exit has the user and the address
        let ir = cfg_for(&app, "ir1");
        assert_eq!(ir.relays.len(), 1);
        assert_eq!((ir.relays[0].port, ir.relays[0].to), (DEFAULT_ENTRY_PORT, DEFAULT_TUNNEL_PORT + 1));
        assert_eq!(ir.relays[0].more, vec![DEFAULT_TUNNEL_PORT + 3]);
        assert_eq!(ir.relays[0].users[0].uid as i64, u.id);
        assert!(ir.exit.is_none());
        let ex = cfg_for(&app, &de);
        assert!(ex.relays.is_empty());
        let x = ex.exit.unwrap();
        assert_eq!((x.port, x.users[0].ip.clone()), (DEFAULT_PORT, ip_of_id(u.id).unwrap().to_string()));
        assert_eq!(x.users[0].key, ir.relays[0].users[0].key);
        // the app's link
        let info = sub_info(&app, &u);
        let url = info[0]["url"].as_str().unwrap();
        assert!(url.starts_with(&format!("kping://{}@ir.example.com:{}?uid={}&", user_key(&app, &u), DEFAULT_ENTRY_PORT, u.id)), "{}", url);
        // traffic and online from the exit's report
        let before = u.used_bytes;
        ingest(&app, &de, &json!({ "relays": [], "exit": { "port": DEFAULT_PORT, "run": "r1", "users": { u.id.to_string(): [5000, 3000, 2000] }, "online": [u.id] } }));
        assert_eq!(app.db.user(u.id).unwrap().used_bytes - before, 5000);
        let (_, v) = call(&app, "GET", "/api/kping", Value::Null).await;
        assert_eq!(v["users"], 1);
        assert_eq!(v["routes"][0]["exit_runs"], true);
        // the route goes, its tunnel id comes back for the page to remove it
        let (_, v) = call(&app, "DELETE", &format!("/api/kping/routes/{}", rid), Value::Null).await;
        assert_eq!(v["tunnel"], tid.as_str());
        assert_eq!(v["tunnel2"], tid2.as_str());
        assert!(settings(&app).routes.is_empty());
        assert_eq!(cfg_for(&app, &de), KpCfg::default());
    }

    #[test]
    fn an_old_route_moves_to_the_tunnel_server() {
        let app = test_app();
        app.db.set("tun_servers", &json!([{ "id": "s-de", "name": "Germany", "token": "y", "node": "de" }]).to_string());
        app.db.set("kping_cfg", &json!({ "routes": [{ "id": "r", "exit": "de", "iran": "ir" }] }).to_string());
        assert_eq!(settings(&app).routes[0].exit, "s-de");
    }
}
