//! Kanki Cores in the panel: the tunnel transports Game-FEC, HQ-QUIC and FakeTCP as VPN cores for
//! the Kanki app (the cores themselves are `tunnel::kcore`).
//!
//! The panel keeps the settings (which cores, their ports, FEC, game packet copies) and one secret
//! (`kc_door`, the mask and handshake key every server shares). Each sync sends a server its
//! `CoreCfg`; the agent runs the cores inside its own process, so nothing is installed. Every user
//! has their own key (made from the panel's secret and the subscription code); the app gets one
//! `kcore://` link per core and server from the subscription.
use crate::db::{Node, User};
use crate::tunnel::kcore::client::ClientCfg;
use crate::tunnel::kcore::server::{CoreCfg, CoreServer, CoreUser};
use crate::tunnel::kcore::{self, KINDS};
use crate::util::rand_token;
use crate::App;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::Mutex;

pub const DEFAULT_PORTS: [(&str, u16); 3] = [("game", 4100), ("hq", 4101), ("faketcp", 4102)];

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct NodeOpt {
    /// the cores off on this server only
    pub off: bool,
    /// address the app dials instead of the server's own ("" = automatic)
    pub host: String,
}

#[derive(Clone, Debug)]
pub struct Settings {
    pub on: bool,
    /// core -> port (0 = that core is off)
    pub ports: HashMap<String, u16>,
    pub fec: String,
    pub copies: u8,
    /// `hq`: the name in the TLS hello
    pub sni: String,
    pub nodes: HashMap<String, NodeOpt>,
}

pub fn settings(app: &App) -> Settings {
    let db = &app.db;
    let saved: HashMap<String, u16> = serde_json::from_str(&db.get("kc_ports")).unwrap_or_default();
    let ports = DEFAULT_PORTS.iter().map(|(k, p)| (k.to_string(), saved.get(*k).copied().unwrap_or(*p))).collect();
    Settings {
        // new: off until the admin turns it on
        on: db.get("kc_on") == "1",
        ports,
        fec: valid_fec(&db.get("kc_fec")).unwrap_or_else(|| "8:3".into()),
        copies: db.get("kc_copies").parse().ok().filter(|c| (1..=3).contains(c)).unwrap_or(2),
        sni: db.get("kc_sni"),
        nodes: serde_json::from_str(&db.get("kc_nodes")).unwrap_or_default(),
    }
}

/// "8:3" / "off" as the game core takes it, else None
pub fn valid_fec(s: &str) -> Option<String> {
    let s = s.trim();
    if s == "off" {
        return Some(s.into());
    }
    let (a, b) = s.split_once(':')?;
    let (a, b): (u8, u8) = (a.trim().parse().ok()?, b.trim().parse().ok()?);
    ((1..=32).contains(&a) && (1..=16).contains(&b)).then(|| format!("{}:{}", a, b))
}

impl Settings {
    pub fn node_on(&self, node_id: &str) -> bool {
        self.on && !self.nodes.get(node_id).map(|o| o.off).unwrap_or(false)
    }
    pub fn port(&self, kind: &str) -> u16 {
        self.ports.get(kind).copied().unwrap_or(0)
    }
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

/// The shared secret of the cores (mask and link handshake)
pub fn door(app: &App) -> String {
    kept(app, "kc_door", 32)
}

/// Who may use the cores: users with KANKI MIX or with Kanki Cores ticked (both are app-only)
pub fn user_on(u: &User) -> bool {
    u.has_proto("kcore") || u.has_proto("kmix")
}

/// The user's key (64 hex): HMAC-SHA256(panel secret, user id + subscription code). A new
/// subscription code is a new key.
pub fn user_key(app: &App, u: &User) -> String {
    let mut m = Hmac::<Sha256>::new_from_slice(kept(app, "kc_secret", 48).as_bytes()).expect("hmac key");
    m.update(format!("kcore|{}|{}", u.id, u.code).as_bytes());
    hex::encode(m.finalize().into_bytes())
}

/// What one server should run (users = the active users of this server)
pub fn cfg_for(app: &App, s: &Settings, n: &Node, users: &[&User]) -> CoreCfg {
    if !s.node_on(&n.id) {
        return CoreCfg::default();
    }
    let limit_on = app.db.get("conn_limit_on") != "0";
    let users = users
        .iter()
        .filter(|u| user_on(u))
        .map(|u| CoreUser { name: u.username.clone(), key: user_key(app, u), max: if limit_on { u.max_conn } else { 0 } })
        .collect();
    CoreCfg { door: door(app), game: s.port("game"), hq: s.port("hq"), faketcp: s.port("faketcp"), fec: s.fec.clone(), copies: s.copies, users }
}

// ------------------------------------------------------------------ links

/// The address the app dials for this server's cores
fn host_of(app: &App, s: &Settings, n: &Node) -> String {
    let h = s.nodes.get(&n.id).map(|o| o.host.trim().to_string()).unwrap_or_default();
    if !h.is_empty() {
        return h;
    }
    let d = crate::kmix::direct_host(app, n);
    if d.is_empty() || d == "127.0.0.1" { crate::api::endpoint(app, n) } else { d }
}

/// The user's links on one server: [{kind, title, url}] for each core the server really runs.
pub fn links(app: &App, u: &User, n: &Node) -> Vec<Value> {
    if !user_on(u) || !u.active() {
        return vec![];
    }
    let s = settings(app);
    if !s.node_on(&n.id) {
        return vec![];
    }
    let info = crate::api::node_info(n);
    let host = host_of(app, &s, n);
    if host.is_empty() {
        return vec![];
    }
    let host = if host.contains(':') && !host.starts_with('[') { format!("[{}]", host) } else { host };
    let (door, key) = (door(app), user_key(app, u));
    KINDS
        .iter()
        .filter_map(|k| {
            // only what the server says it runs (an older agent reports nothing)
            let port = info["kc_ports"][*k].as_u64().filter(|p| *p > 0)?;
            let c = ClientCfg {
                kind: k.to_string(),
                server: format!("{}:{}", host, port),
                door: door.clone(),
                user: u.username.clone(),
                key: key.clone(),
                sni: if *k == "hq" { s.sni.clone() } else { String::new() },
                fec: if *k == "game" { info["kc_fec"].as_str().unwrap_or(&s.fec).to_string() } else { String::new() },
                copies: s.copies,
                datagrams: true,
            };
            let title = kcore::title(k);
            Some(json!({ "kind": k, "title": title, "url": c.to_url(&format!("{} · {}", n.name, title)) }))
        })
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

/// The firewall rules of the cores: UDP for game and hq, TCP for faketcp
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

/// Brings this server to `cfg`: starts, restarts or stops the cores and sets the users. Returns
/// (traffic since the last call per user, devices online per user, errors).
pub async fn apply(cfg: CoreCfg) -> (HashMap<String, (i64, i64)>, HashMap<String, i64>, String) {
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
        return (traffic, HashMap::new(), String::new());
    }
    let restart = g.as_ref().map(|r| r.srv.needs_restart(&cfg)).unwrap_or(true);
    if restart {
        // the old listeners free their ports first
        *g = None;
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        let srv = CoreServer::start(&cfg).await;
        for (k, e) in &srv.errors {
            eprintln!("kanki cores: {} did not start: {}", k, e);
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
    (traffic, r.srv.online(), errors)
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

/// What this server reports about its cores (merged into its info)
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
            json!({
                "kc_ports": ports, "kc_fec": r.cfg.fec,
                "kc_error": r.srv.errors.iter().map(|(k, e)| format!("{}: {}", kcore::title(k), e)).collect::<Vec<_>>().join("; "),
            })
        }
        None => json!({ "kc_ports": {} }),
    }
}

// ------------------------------------------------------------------ panel API

type St = axum::extract::State<std::sync::Arc<App>>;

pub fn router() -> axum::Router<std::sync::Arc<App>> {
    use axum::routing::get;
    axum::Router::new().route("/api/kcore", get(get_all).put(put_settings))
}

fn settings_json(s: &Settings) -> Value {
    json!({ "on": s.on, "ports": s.ports, "fec": s.fec, "copies": s.copies, "sni": s.sni, "nodes": s.nodes })
}

async fn get_all(axum::extract::State(app): St, h: axum::http::HeaderMap) -> axum::response::Response {
    use axum::response::IntoResponse;
    let _ = crate::guard!(app, h, "nodes");
    let s = settings(&app);
    let users = app.db.users();
    let with: Vec<&User> = users.iter().filter(|u| user_on(u)).collect();
    let servers: Vec<Value> = app
        .db
        .nodes()
        .iter()
        .map(|n| {
            let info = crate::api::node_info(n);
            json!({
                "id": n.id, "name": n.name, "main": n.id == "local", "online": n.id == "local" || n.online,
                "on": s.node_on(&n.id), "host": host_of(&app, &s, n), "opt": s.nodes.get(&n.id).cloned().unwrap_or_default(),
                "ports": info["kc_ports"], "error": info["kc_error"], "version": info["version"],
                "users": with.iter().filter(|u| u.active() && u.on(n)).count(),
            })
        })
        .collect();
    axum::Json(json!({
        "settings": settings_json(&s), "servers": servers, "users": with.len(), "users_total": users.len(),
        "online": with.iter().filter(|u| u.online > 0).count(),
        "kinds": KINDS.iter().map(|k| json!({"kind": k, "title": kcore::title(k)})).collect::<Vec<_>>(),
    }))
    .into_response()
}

async fn put_settings(axum::extract::State(app): St, h: axum::http::HeaderMap, axum::Json(b): axum::Json<Value>) -> axum::response::Response {
    use axum::response::IntoResponse;
    let _ = crate::guard!(app, h, "nodes");
    let bad = |m: &str| (axum::http::StatusCode::BAD_REQUEST, axum::Json(json!({ "error": m }))).into_response();
    if let Some(on) = b["on"].as_bool() {
        app.db.set("kc_on", if on { "1" } else { "0" });
    }
    if let Some(p) = b["ports"].as_object() {
        let mut m: HashMap<String, u16> = HashMap::new();
        for k in KINDS {
            let v = &p[*k];
            let port = v.as_u64().or_else(|| v.as_str().and_then(|x| x.trim().parse().ok())).unwrap_or(0);
            if port > 65535 {
                return bad("the port must be 1-65535 (0 = off)");
            }
            m.insert(k.to_string(), port as u16);
        }
        let used: Vec<u16> = m.values().copied().filter(|p| *p > 0).collect();
        if (1..used.len()).any(|i| used[..i].contains(&used[i])) {
            return bad("every core needs its own port");
        }
        app.db.set("kc_ports", &serde_json::to_string(&m).unwrap_or_default());
    }
    if let Some(f) = b["fec"].as_str() {
        match valid_fec(f) {
            Some(f) => app.db.set("kc_fec", &f),
            None => return bad("FEC is data:parity, like 8:3, or off"),
        }
    }
    if let Some(c) = b["copies"].as_u64() {
        app.db.set("kc_copies", &c.clamp(1, 3).to_string());
    }
    if let Some(s) = b["sni"].as_str() {
        app.db.set("kc_sni", s.trim());
    }
    if let Some(n) = b["nodes"].as_object() {
        let mut m: HashMap<String, NodeOpt> = serde_json::from_str(&app.db.get("kc_nodes")).unwrap_or_default();
        for (id, v) in n {
            let o = NodeOpt { off: v["off"].as_bool().unwrap_or(false), host: v["host"].as_str().unwrap_or("").trim().to_string() };
            if o.off || !o.host.is_empty() {
                m.insert(id.clone(), o);
            } else {
                m.remove(id);
            }
        }
        app.db.set("kc_nodes", &serde_json::to_string(&m).unwrap_or_default());
    }
    let a = app.clone();
    tokio::spawn(async move { crate::sync::sync_all(&a).await });
    axum::Json(json!({ "ok": true, "settings": settings_json(&settings(&app)) })).into_response()
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
}
