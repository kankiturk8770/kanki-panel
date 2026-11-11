//! microtun in the panel: the light game VPN (28 bytes per packet, small packets sent twice) as a
//! protocol of its own, ticked per user like KANKI MIX; user protocol `mtun`. Every VPN server runs it
//! inside its agent (`mtun.rs`) on a UDP port of its own with interface `mtun0` and NAT.
//!
//! The panel keeps the header mask key (`mt_obfs`, shared by all servers) and a secret from which
//! each user's key is made (`mt_secret` + user id + subscription code: a new link is a new key).
//! Every user has a fixed tunnel address, 10.79.0.0/16 by user id, the same on every server;
//! a second, third … device gets one of 10.80.0.0/16 from the server, and IPv6 (fd79:4d54::/64) where
//! the server has it.
use crate::db::{Node, User};
use crate::mtun::{MtCfg, MtUser, Server};
use crate::App;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Sha256;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Mutex;

pub const PROTO: &str = "mtun";
pub const NAME: &str = "microtun";
pub const DEFAULT_PORT: u16 = 4200;
/// the server's tunnel address; users get 10.79.0.2 … by id (10.77.N.0/30 are the GRE links of the
/// tunnels, 10.66 / 10.67 WireGuard and AmneziaWG)
const SERVER_ADDR: &str = "10.79.0.1/16";
const BASE: u32 = u32::from_be_bytes([10, 79, 0, 0]);
/// the subnet of a user's second, third … device (each server gives them out by itself)
const DEVICES_ADDR: &str = "10.80.0.1/16";
/// IPv6 in the tunnel, where the server has IPv6: a device's address is this prefix + its IPv4
const SERVER_ADDR6: &str = "fd79:4d54::1/64";

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct NodeOpt {
    /// microtun off on this server only
    pub off: bool,
    /// this server's own port (0 = the default port)
    pub port: u16,
    /// address the app dials instead of the server's own ("" = automatic)
    pub host: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(default)]
pub struct Settings {
    pub on: bool,
    pub port: u16,
    pub mtu: u16,
    /// IP packets up to this size are sent twice (0 = never)
    pub burst_max: u16,
    /// delay of the second copy
    pub burst_delay_ms: u16,
    pub nodes: HashMap<String, NodeOpt>,
}

impl Default for Settings {
    fn default() -> Self {
        Settings { on: true, port: DEFAULT_PORT, mtu: 1420, burst_max: 300, burst_delay_ms: 2, nodes: HashMap::new() }
    }
}

impl Settings {
    pub fn node_on(&self, node_id: &str) -> bool {
        self.on && !self.nodes.get(node_id).map(|o| o.off).unwrap_or(false)
    }
    pub fn node_port(&self, node_id: &str) -> u16 {
        self.nodes.get(node_id).map(|o| o.port).filter(|p| *p > 0).unwrap_or(self.port)
    }
}

pub fn settings(app: &App) -> Settings {
    let mut s: Settings = serde_json::from_str(&app.db.get("mtun_cfg")).unwrap_or_default();
    if s.port == 0 {
        s.port = DEFAULT_PORT;
    }
    s.mtu = s.mtu.clamp(1200, 1500);
    s.burst_max = s.burst_max.min(1500);
    s.burst_delay_ms = s.burst_delay_ms.min(50);
    s
}

fn save(app: &App, s: &Settings) {
    app.db.set("mtun_cfg", &serde_json::to_string(s).unwrap_or_default());
}

/// A removed server's microtun settings go with it
pub fn forget_node(app: &App, node_id: &str) {
    let mut s = settings(app);
    if s.nodes.remove(node_id).is_some() {
        save(app, &s);
    }
}

/// The node ids microtun keeps settings for
pub fn node_ids(app: &App) -> Vec<String> {
    settings(app).nodes.keys().cloned().collect()
}

/// Gives server `node_id` its own port (it moves there on its next sync).
pub fn set_node_port(app: &App, node_id: &str, port: u16) {
    let mut s = settings(app);
    s.nodes.entry(node_id.to_string()).or_default().port = port;
    save(app, &s);
}

/// microtun off (or on again) on server `node_id` only
pub fn set_node_off(app: &App, node_id: &str, off: bool) {
    let mut s = settings(app);
    s.nodes.entry(node_id.to_string()).or_default().off = off;
    save(app, &s);
}

// ------------------------------------------------------------------ keys and addresses

static SECRET_LOCK: Mutex<()> = Mutex::new(());

/// 32 random bytes as hex, made once and kept in the database (and so in its backups)
pub(crate) fn kept_hex(app: &App, key: &str) -> String {
    let _g = SECRET_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let s = app.db.get(key);
    if s.len() == 64 {
        return s;
    }
    let mut b = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut b);
    let s = hex::encode(b);
    app.db.set(key, &s);
    s
}

pub fn obfs(app: &App) -> String {
    kept_hex(app, "mt_obfs")
}

/// The user's key (64 hex): HMAC-SHA256(panel secret, user id + subscription code)
pub fn user_key(app: &App, u: &User) -> String {
    let mut m = Hmac::<Sha256>::new_from_slice(kept_hex(app, "mt_secret").as_bytes()).expect("hmac key");
    m.update(format!("microtun|{}|{}", u.id, u.code).as_bytes());
    hex::encode(m.finalize().into_bytes())
}

/// The user's tunnel address (None for ids that do not fit the /16)
pub fn user_ip(u: &User) -> Option<Ipv4Addr> {
    ip_of_id(u.id)
}

fn ip_of_id(id: i64) -> Option<Ipv4Addr> {
    let id = u32::try_from(id).ok().filter(|i| (1..=65533).contains(i))?;
    Some(Ipv4Addr::from(BASE + id + 1))
}

/// What one server runs (users = the active users of this server)
pub fn cfg_for(app: &App, n: &Node, users: &[&User]) -> MtCfg {
    let s = settings(app);
    if !s.node_on(&n.id) {
        return MtCfg::default();
    }
    let limit_on = app.db.get("conn_limit_on") != "0";
    let users = users
        .iter()
        .filter(|u| u.has_proto(PROTO))
        .filter_map(|u| {
            // devices at the same time: the user's connection limit, when the panel enforces one
            let max = if limit_on { u.max_conn.max(0) as u32 } else { 0 };
            Some(MtUser { name: u.username.clone(), key: user_key(app, u), ip: user_ip(u)?.to_string(), max })
        })
        .collect();
    MtCfg {
        port: s.node_port(&n.id),
        obfs: obfs(app),
        address: SERVER_ADDR.into(),
        devices: DEVICES_ADDR.into(),
        address6: SERVER_ADDR6.into(),
        // automatic MTU: the smallest of this server's microtun configs (direct / through Iran)
        mtu: crate::mtu::server(app, n, PROTO).unwrap_or(s.mtu),
        burst_max: s.burst_max,
        burst_delay_ms: s.burst_delay_ms,
        users,
        iface: String::new(),
        local_only: false,
    }
}

// ------------------------------------------------------------------ links

fn pct(s: &str) -> String {
    s.bytes().map(|c| if c.is_ascii_alphanumeric() || b"-_.~".contains(&c) { (c as char).to_string() } else { format!("%{:02X}", c) }).collect()
}

/// mtun://KEY@host:port?obfs=…&ip=10.79.0.2/16&mtu=1420&burst=300&delay=2#name
/// (`microtun client -url '…'` takes it as it is)
pub fn to_url(key: &str, server: &str, obfs: &str, ip: Ipv4Addr, s: &Settings, name: &str) -> String {
    format!(
        "mtun://{}@{}?obfs={}&ip={}/16&mtu={}&burst={}&delay={}#{}",
        key, server, obfs, ip, s.mtu, s.burst_max, s.burst_delay_ms, pct(name)
    )
}

fn host_of(app: &App, s: &Settings, n: &Node) -> String {
    let h = s.nodes.get(&n.id).map(|o| o.host.trim().to_string()).unwrap_or_default();
    if !h.is_empty() {
        return h;
    }
    let d = crate::kmix::direct_host(app, n);
    if d.is_empty() || d == "127.0.0.1" { crate::api::endpoint(app, n) } else { d }
}

/// The user's link on one server (None = not for this user / not running there). `tunnel`: through
/// the server's Iran tunnel (the tunnel must forward this UDP port).
pub fn link(app: &App, u: &User, n: &Node, tunnel: bool) -> Option<String> {
    if !u.has_proto(PROTO) || !u.active() {
        return None;
    }
    let s = settings(app);
    if !s.node_on(&n.id) {
        return None;
    }
    // only what the server says it runs (an older agent reports nothing)
    let port = crate::api::node_info(n)["mt_port"].as_u64().filter(|p| *p > 0)? as u16;
    let (server, label) = if tunnel {
        let t = crate::twin::of_node_core(app, n, "mtun")?;
        (t.addr(t.port(app, port, false)), format!("{} · {}", t.name, NAME))
    } else {
        let host = host_of(app, &s, n);
        if host.is_empty() {
            return None;
        }
        let host = if host.contains(':') && !host.starts_with('[') { format!("[{}]", host) } else { host };
        (format!("{}:{}", host, port), format!("{} · {}", n.name, NAME))
    };
    let s = Settings { mtu: crate::mtu::client(app, n, PROTO, tunnel), ..s };
    Some(to_url(&user_key(app, u), &server, &obfs(app), user_ip(u)?, &s, &label))
}

// ------------------------------------------------------------------ on the server (agent / main)

struct Running {
    srv: Server,
    /// traffic already reported (the counters run from the start of `srv`)
    told: HashMap<String, (i64, i64)>,
}

/// One server of this kind on this machine: microtun, and KPING (`kping.rs`) on an interface of its own
pub struct Runner {
    /// firewall group and log name ("mtun", "kping")
    proto: &'static str,
    /// open its port in the firewall (KPING is reached only through its own tunnel: kept closed)
    open: bool,
    run: Mutex<Option<Running>>,
    /// the error of the last start ("" = none)
    err: Mutex<String>,
}

/// What `apply` reports: traffic since the last call, users online, what failed
pub type Applied = (HashMap<String, (i64, i64)>, Vec<String>, String);

impl Runner {
    pub const fn new(proto: &'static str, open: bool) -> Runner {
        Runner { proto, open, run: Mutex::new(None), err: Mutex::new(String::new()) }
    }

    fn set_err(&self, e: &str) {
        *self.err.lock().unwrap_or_else(|e| e.into_inner()) = e.to_string();
    }

    /// Brings this server to `cfg` (blocking: it may set up the interface and NAT).
    pub fn apply(&self, cfg: MtCfg) -> Applied {
        let mut g = self.run.lock().unwrap_or_else(|e| e.into_inner());
        let traffic = g.as_mut().map(deltas).unwrap_or_default();
        if !cfg.on() {
            if g.take().is_some() {
                crate::fw::close(self.proto);
            }
            self.set_err("");
            return (traffic, vec![], String::new());
        }
        let restart = g.as_ref().map(|r| r.srv.needs_restart(&cfg)).unwrap_or(true);
        if restart {
            *g = None; // the old one frees its port and interface first
            match Server::start(&cfg) {
                Ok(srv) => {
                    if self.open {
                        crate::fw::sync(self.proto, vec![crate::fw::rule(cfg.port, true)]);
                    }
                    *g = Some(Running { srv, told: HashMap::new() });
                    self.set_err("");
                }
                Err(e) => {
                    if *self.err.lock().unwrap_or_else(|e| e.into_inner()) != e {
                        eprintln!("{}: did not start: {}", self.proto, e);
                    }
                    self.set_err(&e);
                    return (traffic, vec![], e);
                }
            }
        } else if let Some(r) = g.as_mut() {
            if r.srv.cfg != cfg {
                r.srv.set(&cfg);
            }
        }
        let online = g.as_ref().map(|r| r.srv.online()).unwrap_or_default();
        (traffic, online, String::new())
    }

    /// The UDP port this server runs on here now (None = not running)
    pub fn port(&self) -> Option<u16> {
        self.run.lock().unwrap_or_else(|e| e.into_inner()).as_ref().map(|r| r.srv.cfg.port)
    }

    /// (port that really runs (0 = none), IPv6 in the tunnel, last error)
    pub fn state(&self) -> (u16, bool, String) {
        let (port, v6) = self.run.try_lock().ok().and_then(|g| g.as_ref().map(|r| (r.srv.cfg.port, r.srv.has_v6()))).unwrap_or((0, false));
        (port, v6, self.err.lock().map(|e| e.clone()).unwrap_or_default())
    }
}

static MT: Runner = Runner::new(PROTO, true);

/// Brings microtun on this server to `cfg`
pub fn apply(cfg: MtCfg) -> Applied {
    MT.apply(cfg)
}

fn deltas(r: &mut Running) -> HashMap<String, (i64, i64)> {
    let now = r.srv.traffic();
    let mut out = HashMap::new();
    for (name, (rx, tx)) in &now {
        let (prx, ptx) = r.told.get(name).copied().unwrap_or((0, 0));
        // a user removed and added again starts from 0
        let d = if *rx >= prx && *tx >= ptx { (rx - prx, tx - ptx) } else { (*rx, *tx) };
        if d.0 + d.1 > 0 {
            out.insert(name.clone(), d);
        }
    }
    r.told = now;
    out
}

/// The UDP port microtun runs on here now (None = not running)
pub fn running_port() -> Option<u16> {
    MT.port()
}

/// What this server reports (merged into its info): the port that really runs, or why not
pub fn info() -> Value {
    let (port, v6, err) = MT.state();
    json!({ "mt_port": if port > 0 { json!(port) } else { Value::Null }, "mt_v6": v6, "mt_error": err, "mt": true })
}

// ------------------------------------------------------------------ panel API

type St = axum::extract::State<std::sync::Arc<App>>;

pub fn router() -> axum::Router<std::sync::Arc<App>> {
    use axum::routing::{get, post};
    axum::Router::new()
        .route("/api/mt", get(get_all).put(put_settings))
        .route("/api/mt/users", post(all_users))
        .route("/api/mt/links/:uid", get(user_links))
}

fn bad(m: &str) -> axum::response::Response {
    use axum::response::IntoResponse;
    (axum::http::StatusCode::BAD_REQUEST, axum::Json(json!({ "error": m }))).into_response()
}

async fn get_all(axum::extract::State(app): St, h: axum::http::HeaderMap) -> axum::response::Response {
    use axum::response::IntoResponse;
    let _ = crate::guard!(app, h, "nodes");
    let s = settings(&app);
    let users = app.db.users();
    let with: Vec<&User> = users.iter().filter(|u| u.has_proto(PROTO)).collect();
    let servers: Vec<Value> = app
        .db
        .nodes()
        .iter()
        .map(|n| {
            let info = crate::api::node_info(n);
            json!({
                "id": n.id, "name": n.name, "main": n.id == "local", "online": n.id == "local" || n.online,
                "on": s.node_on(&n.id), "want_port": s.node_port(&n.id), "host": host_of(&app, &s, n),
                "port": info["mt_port"], "v6": info["mt_v6"], "reports": info["mt"].as_bool().unwrap_or(false),
                "error": info["mt_error"].as_str().filter(|e| !e.is_empty()), "version": info["version"],
                "users": with.iter().filter(|u| u.active() && u.on(n)).count(),
            })
        })
        .collect();
    axum::Json(json!({
        "proto": PROTO, "settings": s, "servers": servers, "users": with.len(), "users_total": users.len(),
        "online": with.iter().filter(|u| u.online > 0).count(),
        "traffic_gb": (with.iter().map(|u| u.used_gb()).sum::<f64>() * 10.0).round() / 10.0,
        "user_list": users.iter().map(|u| json!({ "id": u.id, "name": u.username, "has": u.has_proto(PROTO) })).collect::<Vec<_>>(),
    }))
    .into_response()
}

fn port_of(v: &Value) -> Option<u16> {
    v.as_u64().or_else(|| v.as_str().and_then(|x| x.trim().parse().ok())).filter(|p| *p > 0 && *p <= 65535).map(|p| p as u16)
}

async fn put_settings(axum::extract::State(app): St, h: axum::http::HeaderMap, axum::Json(b): axum::Json<Value>) -> axum::response::Response {
    use axum::response::IntoResponse;
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
    if let Some(n) = b["nodes"].as_object() {
        let mut m = HashMap::new();
        for (id, v) in n {
            let o = NodeOpt { off: v["off"].as_bool().unwrap_or(false), port: port_of(&v["port"]).unwrap_or(0), host: v["host"].as_str().unwrap_or("").trim().to_string() };
            if o.off || o.port > 0 || !o.host.is_empty() {
                m.insert(id.clone(), o);
            }
        }
        s.nodes = m;
    }
    // KANKI MIX is the other UDP protocol that sits beside it on every server
    let km = crate::kmix::settings(&app);
    let hop = crate::kmix::hop_range(&km.hop);
    for n in app.db.nodes() {
        if s.node_on(&n.id) && km.node_on(&n.id) && s.node_port(&n.id) == km.node_port(&n.id) {
            return bad(&format!("KANKI MIX already uses port {} on {}", s.node_port(&n.id), n.name));
        }
        // the extra ports of KANKI MIX are sent to KANKI MIX: microtun cannot sit inside them
        if let Some((a, z)) = hop.filter(|(a, z)| s.node_on(&n.id) && km.node_on(&n.id) && (*a..=*z).contains(&s.node_port(&n.id))) {
            return bad(&format!("the port {} on {} is inside the KANKI MIX extra ports {}-{}", s.node_port(&n.id), n.name, a, z));
        }
    }
    save(&app, &s);
    crate::api::spawn_sync(&app);
    axum::Json(json!({ "ok": true, "settings": s })).into_response()
}

/// { on }: microtun for every user (on) or for nobody (off)
async fn all_users(axum::extract::State(app): St, h: axum::http::HeaderMap, axum::Json(b): axum::Json<Value>) -> axum::response::Response {
    use axum::response::IntoResponse;
    let _ = crate::guard!(app, h, "users:write");
    let on = b["on"].as_bool().unwrap_or(true);
    let mut changed = 0;
    for u in app.db.users() {
        let mut list: Vec<String> = u.protocols.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect();
        if on == list.iter().any(|x| x == PROTO) {
            continue;
        }
        if on { list.push(PROTO.into()) } else { list.retain(|x| x != PROTO) }
        let _ = app.db.exec("UPDATE users SET protocols=?1 WHERE id=?2", &[&list.join(","), &u.id]);
        changed += 1;
    }
    crate::api::spawn_sync(&app);
    axum::Json(json!({ "ok": true, "changed": changed })).into_response()
}

/// A user's links on every server (for testing with the Linux client): [{server, url, tunnel}]
async fn user_links(axum::extract::State(app): St, h: axum::http::HeaderMap, axum::extract::Path(uid): axum::extract::Path<i64>) -> axum::response::Response {
    use axum::response::IntoResponse;
    let _ = crate::guard!(app, h, "users:read");
    let Some(u) = app.db.users().into_iter().find(|u| u.id == uid) else { return bad("unknown user") };
    let mut out = vec![];
    for n in crate::api::user_nodes(&app, &u) {
        for tunnel in [false, true] {
            if let Some(url) = link(&app, &u, &n, tunnel) {
                out.push(json!({ "server": n.name, "tunnel": tunnel, "url": url }));
            }
        }
    }
    let why = if !u.has_proto(PROTO) {
        "microtun is not ticked for this user"
    } else if !u.active() {
        "this user is not active"
    } else if user_ip(&u).is_none() {
        // the tunnel addresses (10.79.0.0/16) are by user id: existing users keep theirs
        "microtun gives tunnel addresses to user numbers 1-65533 only; this user's number is higher"
    } else if out.is_empty() {
        "no server runs microtun for this user yet (update the agents, wait a minute)"
    } else {
        ""
    };
    axum::Json(json!({ "links": out, "why": why })).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_format() {
        let s = Settings::default();
        let u = to_url(&"ab".repeat(32), "de.example.com:4200", &"cd".repeat(32), Ipv4Addr::new(10, 79, 0, 2), &s, "Germany · microtun");
        assert!(u.starts_with(&format!("mtun://{}@de.example.com:4200?obfs=", "ab".repeat(32))));
        assert!(u.contains("&ip=10.79.0.2/16&mtu=1420&burst=300&delay=2#Germany%20%C2%B7%20microtun"));
    }

    #[test]
    fn user_numbers_past_the_subnet_get_no_address() {
        assert_eq!(ip_of_id(1), Some(Ipv4Addr::new(10, 79, 0, 2)));
        assert_eq!(ip_of_id(65533), Some(Ipv4Addr::new(10, 79, 255, 254)));
        assert!(ip_of_id(65534).is_none());
    }

    #[test]
    fn ports_per_server() {
        let mut s = Settings::default();
        s.nodes.insert("n1".into(), NodeOpt { port: 4201, ..Default::default() });
        s.nodes.insert("n2".into(), NodeOpt { off: true, ..Default::default() });
        assert_eq!(s.node_port("n1"), 4201);
        assert_eq!(s.node_port("local"), 4200);
        assert!(s.node_on("n1") && !s.node_on("n2"));
    }
}
