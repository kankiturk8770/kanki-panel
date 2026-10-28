//! Three VPN protocols of our own for the Kanki app, each a section of its own like KANKI MIX:
//! **Game-FEC** (`kgame`), **HQ-QUIC** (`khq`) and **FakeTCP** (`kftcp`). They run on every VPN
//! server on ports of their own, apart from the tunnels; only the transport code is shared with
//! the tunnels (`tunnel::kcore`).
//!
//! Each protocol has its own switch, port and options, and is ticked per user like any other
//! protocol. The panel keeps one secret (`kc_door`, the mask and handshake key the servers share);
//! each sync sends a server its `CoreCfg` and the agent runs the protocols inside its own process.
//! Every user has their own key (from the panel's secret and the subscription code); the app gets
//! a `kcore://` link per protocol and server from the subscription.
use crate::db::{Node, User};
use crate::tunnel::kcore;
use crate::tunnel::kcore::client::ClientCfg;
use crate::tunnel::kcore::server::{CoreCfg, CoreServer, CoreUser};
use crate::util::rand_token;
use crate::App;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::Mutex;

/// (user protocol, core, default port, name)
pub const PROTOS: [(&str, &str, u16, &str); 3] = [("kgame", "game", 4100, "Game-FEC"), ("khq", "hq", 4101, "HQ-QUIC"), ("kftcp", "faketcp", 4102, "FakeTCP")];

/// the core of a user protocol ("kgame" -> "game")
pub fn core_of(proto: &str) -> Option<&'static str> {
    PROTOS.iter().find(|p| p.0 == proto).map(|p| p.1)
}

/// the user protocol of a core ("game" -> "kgame")
pub fn proto_of(core: &str) -> Option<&'static str> {
    PROTOS.iter().find(|p| p.1 == core).map(|p| p.0)
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct NodeOpt {
    /// this protocol off on this server only
    pub off: bool,
    /// this server's own port (0 = the default port)
    pub port: u16,
    /// address the app dials instead of the server's own ("" = automatic)
    pub host: String,
}

/// The settings of one protocol.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(default)]
pub struct Settings {
    pub on: bool,
    pub port: u16,
    /// Game-FEC: FEC of the stream ("8:3", "off")
    pub fec: String,
    /// Game-FEC, HQ-QUIC: copies of each small game packet (1-3)
    pub copies: u8,
    /// HQ-QUIC: the name in the TLS hello
    pub sni: String,
    pub nodes: HashMap<String, NodeOpt>,
}

impl Default for Settings {
    fn default() -> Self {
        Settings { on: true, port: 0, fec: "8:3".into(), copies: 2, sni: String::new(), nodes: HashMap::new() }
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

/// The settings of protocol `proto` ("kgame" | "khq" | "kftcp")
pub fn settings(app: &App, proto: &str) -> Settings {
    let def = PROTOS.iter().find(|p| p.0 == proto).map(|p| p.2).unwrap_or(0);
    let mut s: Settings = serde_json::from_str(&app.db.get(&format!("{}_cfg", proto))).unwrap_or_default();
    if s.port == 0 {
        s.port = def;
    }
    s.fec = valid_fec(&s.fec).unwrap_or_else(|| "8:3".into());
    s.copies = s.copies.clamp(1, 3);
    s
}

fn save(app: &App, proto: &str, s: &Settings) {
    app.db.set(&format!("{}_cfg", proto), &serde_json::to_string(s).unwrap_or_default());
}

/// "8:3" / "off" as Game-FEC takes it, else None
pub fn valid_fec(s: &str) -> Option<String> {
    let s = s.trim();
    if s == "off" {
        return Some(s.into());
    }
    let (a, b) = s.split_once(':')?;
    let (a, b): (u8, u8) = (a.trim().parse().ok()?, b.trim().parse().ok()?);
    ((1..=32).contains(&a) && (1..=16).contains(&b)).then(|| format!("{}:{}", a, b))
}

// ------------------------------------------------------------------ keys

static SECRET_LOCK: Mutex<()> = Mutex::new(());

/// A value made once and kept in the database (and so in its backups)
fn kept(app: &App, key: &str, len: usize) -> String {
    let _g = SECRET_LOCK.lock().unwrap();
    let s = app.db.get(key);
    if !s.is_empty() {
        return s;
    }
    let s = rand_token(len);
    app.db.set(key, &s);
    s
}

/// The shared secret of the protocols (mask and link handshake)
pub fn door(app: &App) -> String {
    kept(app, "kc_door", 32)
}

/// The user's key (64 hex): HMAC-SHA256(panel secret, user id + subscription code). A new
/// subscription code is a new key. The same key for all three protocols.
pub fn user_key(app: &App, u: &User) -> String {
    let mut m = Hmac::<Sha256>::new_from_slice(kept(app, "kc_secret", 48).as_bytes()).expect("hmac key");
    m.update(format!("kcore|{}|{}", u.id, u.code).as_bytes());
    hex::encode(m.finalize().into_bytes())
}

/// What one server should run (users = the active users of this server)
pub fn cfg_for(app: &App, n: &Node, users: &[&User]) -> CoreCfg {
    let all: Vec<(&str, &str, Settings)> = PROTOS.iter().map(|p| (p.0, p.1, settings(app, p.0))).collect();
    let on: Vec<&(&str, &str, Settings)> = all.iter().filter(|(_, _, s)| s.node_on(&n.id)).collect();
    if on.is_empty() {
        return CoreCfg::default();
    }
    let port = |core: &str| on.iter().find(|x| x.1 == core).map(|x| x.2.node_port(&n.id)).unwrap_or(0);
    let game = all.iter().find(|x| x.1 == "game").map(|x| x.2.clone()).unwrap_or_default();
    let limit_on = app.db.get("conn_limit_on") != "0";
    let users = users
        .iter()
        .filter_map(|u| {
            let cores: Vec<String> = on.iter().filter(|x| u.has_proto(x.0)).map(|x| x.1.to_string()).collect();
            (!cores.is_empty()).then(|| CoreUser { name: u.username.clone(), key: user_key(app, u), max: if limit_on { u.max_conn } else { 0 }, cores })
        })
        .collect();
    CoreCfg { door: door(app), game: port("game"), hq: port("hq"), faketcp: port("faketcp"), fec: game.fec.clone(), copies: game.copies, users }
}

// ------------------------------------------------------------------ links

/// The address the app dials for this server
fn host_of(app: &App, s: &Settings, n: &Node) -> String {
    let h = s.nodes.get(&n.id).map(|o| o.host.trim().to_string()).unwrap_or_default();
    if !h.is_empty() {
        return h;
    }
    let d = crate::kmix::direct_host(app, n);
    if d.is_empty() || d == "127.0.0.1" { crate::api::endpoint(app, n) } else { d }
}

/// The user's link of protocol `proto` on one server (None = not for this user / not running there)
pub fn link(app: &App, u: &User, n: &Node, proto: &str) -> Option<String> {
    let (core, name) = PROTOS.iter().find(|p| p.0 == proto).map(|p| (p.1, p.3))?;
    if !u.has_proto(proto) || !u.active() {
        return None;
    }
    let s = settings(app, proto);
    if !s.node_on(&n.id) {
        return None;
    }
    // only what the server says it runs (an older agent reports nothing)
    let info = crate::api::node_info(n);
    let port = info["kc_ports"][core].as_u64().filter(|p| *p > 0)?;
    let host = host_of(app, &s, n);
    if host.is_empty() {
        return None;
    }
    let host = if host.contains(':') && !host.starts_with('[') { format!("[{}]", host) } else { host };
    let c = ClientCfg {
        kind: core.to_string(),
        server: format!("{}:{}", host, port),
        door: door(app),
        user: u.username.clone(),
        key: user_key(app, u),
        sni: if core == "hq" { s.sni.clone() } else { String::new() },
        fec: if core == "game" { info["kc_fec"].as_str().unwrap_or(&s.fec).to_string() } else { String::new() },
        copies: s.copies,
        datagrams: true,
    };
    Some(c.to_url(&format!("{} · {}", n.name, name)))
}

/// All the user's links on one server: [{proto, kind, title, url}]
pub fn links(app: &App, u: &User, n: &Node) -> Vec<Value> {
    PROTOS
        .iter()
        .filter_map(|p| link(app, u, n, p.0).map(|url| json!({ "proto": p.0, "kind": p.1, "title": p.3, "url": url })))
        .collect()
}

// ------------------------------------------------------------------ on the server (agent / main)

struct Running {
    srv: CoreServer,
    /// traffic already reported (the counters run from the start of `srv`)
    told: HashMap<String, (i64, i64)>,
    cfg: CoreCfg,
}

fn running() -> &'static tokio::sync::Mutex<Option<Running>> {
    static R: std::sync::OnceLock<tokio::sync::Mutex<Option<Running>>> = std::sync::OnceLock::new();
    R.get_or_init(|| tokio::sync::Mutex::new(None))
}

/// The firewall rules: UDP for Game-FEC and HQ-QUIC, TCP for FakeTCP
fn fw_rules(c: &CoreCfg) -> Vec<String> {
    let mut v = vec![];
    if c.game > 0 {
        v.push(crate::fw::rule(c.game, true));
    }
    if c.hq > 0 {
        v.push(crate::fw::rule(c.hq, true));
    }
    if c.faketcp > 0 {
        v.push(crate::fw::rule(c.faketcp, false));
    }
    v
}

/// What `apply` reports: traffic since the last call, devices online (user, protocol, count), errors
pub type Applied = (HashMap<String, (i64, i64)>, Vec<(String, String, i64)>, String);

/// Brings this server to `cfg`: starts, restarts or stops the protocols and sets the users.
pub async fn apply(cfg: CoreCfg) -> Applied {
    let mut g = running().lock().await;
    let mut traffic = HashMap::new();
    // what the old server counted is reported before it may stop
    if let Some(r) = g.as_mut() {
        traffic = deltas(r);
    }
    if !cfg.any_on() {
        if g.take().is_some() {
            let _ = tokio::task::spawn_blocking(|| crate::fw::close("kcore")).await;
        }
        return (traffic, vec![], String::new());
    }
    let restart = g.as_ref().map(|r| r.srv.needs_restart(&cfg)).unwrap_or(true);
    if restart {
        // the old listeners free their ports first
        *g = None;
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        let srv = CoreServer::start(&cfg).await;
        for (k, e) in &srv.errors {
            eprintln!("{}: did not start: {}", kcore::title(k), e);
        }
        let rules = fw_rules(&cfg);
        let _ = tokio::task::spawn_blocking(move || crate::fw::sync("kcore", rules)).await;
        *g = Some(Running { srv, told: HashMap::new(), cfg: cfg.clone() });
    } else if let Some(r) = g.as_mut() {
        if r.cfg.users != cfg.users {
            r.srv.set_users(&cfg.users);
            r.cfg = cfg.clone();
        }
    }
    let r = g.as_ref().unwrap();
    let errors = r.srv.errors.iter().map(|(k, e)| format!("{}: {}", kcore::title(k), e)).collect::<Vec<_>>().join("; ");
    let online = r.srv.online_by_core().into_iter().filter_map(|(u, k, c)| proto_of(&k).map(|p| (u, p.to_string(), c))).collect();
    (traffic, online, errors)
}

fn deltas(r: &mut Running) -> HashMap<String, (i64, i64)> {
    let now = r.srv.traffic();
    let mut out = HashMap::new();
    for (name, (rx, tx)) in &now {
        let (prx, ptx) = r.told.get(name).copied().unwrap_or((0, 0));
        let d = ((rx - prx).max(0), (tx - ptx).max(0));
        if d.0 + d.1 > 0 {
            out.insert(name.clone(), d);
        }
    }
    r.told = now;
    out
}

/// What this server reports about the protocols (merged into its info): the ports that really
/// run, and what failed to start, per core
pub fn info() -> Value {
    let Ok(g) = running().try_lock() else { return json!({}) };
    match g.as_ref() {
        Some(r) => {
            let failed: Vec<&str> = r.srv.errors.iter().map(|(k, _)| k.as_str()).collect();
            let ports: serde_json::Map<String, Value> = [("game", r.cfg.game), ("hq", r.cfg.hq), ("faketcp", r.cfg.faketcp)]
                .iter()
                .filter(|(k, p)| *p > 0 && !failed.contains(k))
                .map(|(k, p)| (k.to_string(), json!(p)))
                .collect();
            let errors: serde_json::Map<String, Value> = r.srv.errors.iter().map(|(k, e)| (k.clone(), json!(e))).collect();
            json!({ "kc_ports": ports, "kc_fec": r.cfg.fec, "kc_errors": errors })
        }
        None => json!({ "kc_ports": {} }),
    }
}

// ------------------------------------------------------------------ panel API

type St = axum::extract::State<std::sync::Arc<App>>;
type Proto = axum::extract::Path<String>;

pub fn router() -> axum::Router<std::sync::Arc<App>> {
    use axum::routing::{get, post};
    axum::Router::new().route("/api/kc/:proto", get(get_all).put(put_settings)).route("/api/kc/:proto/users", post(all_users))
}

fn bad(m: &str) -> axum::response::Response {
    use axum::response::IntoResponse;
    (axum::http::StatusCode::BAD_REQUEST, axum::Json(json!({ "error": m }))).into_response()
}

async fn get_all(axum::extract::State(app): St, h: axum::http::HeaderMap, axum::extract::Path(proto): Proto) -> axum::response::Response {
    use axum::response::IntoResponse;
    let _ = crate::guard!(app, h, "nodes");
    let Some(core) = core_of(&proto) else { return bad("unknown protocol") };
    let s = settings(&app, &proto);
    let users = app.db.users();
    let with: Vec<&User> = users.iter().filter(|u| u.has_proto(&proto)).collect();
    let servers: Vec<Value> = app
        .db
        .nodes()
        .iter()
        .map(|n| {
            let info = crate::api::node_info(n);
            json!({
                "id": n.id, "name": n.name, "main": n.id == "local", "online": n.id == "local" || n.online,
                "on": s.node_on(&n.id), "want_port": s.node_port(&n.id), "host": host_of(&app, &s, n),
                "port": info["kc_ports"][core], "reports": !info["kc_ports"].is_null(),
                "error": info["kc_errors"][core], "version": info["version"],
                "users": with.iter().filter(|u| u.active() && u.on(n)).count(),
            })
        })
        .collect();
    axum::Json(json!({
        "proto": proto, "core": core, "settings": s, "servers": servers, "users": with.len(), "users_total": users.len(),
        "online": with.iter().filter(|u| u.online > 0).count(),
        "traffic_gb": (with.iter().map(|u| u.used_gb()).sum::<f64>() * 10.0).round() / 10.0,
    }))
    .into_response()
}

fn port_of(v: &Value) -> Option<u16> {
    v.as_u64().or_else(|| v.as_str().and_then(|x| x.trim().parse().ok())).filter(|p| *p > 0 && *p <= 65535).map(|p| p as u16)
}

async fn put_settings(axum::extract::State(app): St, h: axum::http::HeaderMap, axum::extract::Path(proto): Proto, axum::Json(b): axum::Json<Value>) -> axum::response::Response {
    use axum::response::IntoResponse;
    let _ = crate::guard!(app, h, "nodes");
    let Some(core) = core_of(&proto) else { return bad("unknown protocol") };
    let mut s = settings(&app, &proto);
    if let Some(on) = b["on"].as_bool() {
        s.on = on;
    }
    if !b["port"].is_null() {
        match port_of(&b["port"]) {
            Some(p) => s.port = p,
            None => return bad("the port must be 1-65535"),
        }
    }
    if let Some(f) = b["fec"].as_str() {
        match valid_fec(f) {
            Some(f) => s.fec = f,
            None => return bad("FEC is data:parity, like 8:3, or off"),
        }
    }
    if let Some(c) = b["copies"].as_u64() {
        s.copies = c.clamp(1, 3) as u8;
    }
    if let Some(x) = b["sni"].as_str() {
        s.sni = x.trim().to_string();
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
    // the three run side by side on every server: each needs a port of its own there
    for p in PROTOS.iter().filter(|p| p.1 != core) {
        let o = settings(&app, p.0);
        for n in app.db.nodes() {
            if s.node_on(&n.id) && o.node_on(&n.id) && s.node_port(&n.id) == o.node_port(&n.id) {
                return bad(&format!("{} already uses port {} on {}", p.3, s.node_port(&n.id), n.name));
            }
        }
    }
    save(&app, &proto, &s);
    crate::api::spawn_sync(&app);
    axum::Json(json!({ "ok": true, "settings": s })).into_response()
}

/// { on }: this protocol for every user (on) or for nobody (off)
async fn all_users(axum::extract::State(app): St, h: axum::http::HeaderMap, axum::extract::Path(proto): Proto, axum::Json(b): axum::Json<Value>) -> axum::response::Response {
    use axum::response::IntoResponse;
    let _ = crate::guard!(app, h, "users:write");
    if core_of(&proto).is_none() {
        return bad("unknown protocol");
    }
    let on = b["on"].as_bool().unwrap_or(true);
    let mut changed = 0;
    for u in app.db.users() {
        let mut list: Vec<String> = u.protocols.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect();
        if on == list.iter().any(|x| *x == proto) {
            continue;
        }
        if on { list.push(proto.clone()) } else { list.retain(|x| *x != proto) }
        let _ = app.db.exec("UPDATE users SET protocols=?1 WHERE id=?2", &[&list.join(","), &u.id]);
        changed += 1;
    }
    crate::api::spawn_sync(&app);
    axum::Json(json!({ "ok": true, "changed": changed })).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fec_values() {
        assert_eq!(valid_fec("8:3").as_deref(), Some("8:3"));
        assert_eq!(valid_fec(" 4 : 2 ").as_deref(), Some("4:2"));
        assert_eq!(valid_fec("off").as_deref(), Some("off"));
        assert!(valid_fec("0:3").is_none());
        assert!(valid_fec("8").is_none());
        assert!(valid_fec("99:3").is_none());
    }

    #[test]
    fn protocols_and_cores() {
        assert_eq!(core_of("kgame"), Some("game"));
        assert_eq!(core_of("khq"), Some("hq"));
        assert_eq!(core_of("kftcp"), Some("faketcp"));
        assert_eq!(proto_of("faketcp"), Some("kftcp"));
        assert_eq!(core_of("kmix"), None);
        let mut s = Settings { port: 4100, ..Default::default() };
        s.nodes.insert("n1".into(), NodeOpt { port: 5100, ..Default::default() });
        s.nodes.insert("n2".into(), NodeOpt { off: true, ..Default::default() });
        assert_eq!(s.node_port("n1"), 5100);
        assert_eq!(s.node_port("local"), 4100);
        assert!(s.node_on("n1") && !s.node_on("n2"));
    }
}
