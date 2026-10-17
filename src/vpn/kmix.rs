//! KANKI MIX: our own UDP protocol, next to WireGuard / AmneziaWG / Hysteria2 on every VPN server.
//! Game UDP rides a raw datagram path (no queue, no retransmission, sent twice in gaming mode) and TCP
//! rides KCP + FEC, all under a ChaCha20-Poly1305 mask that has no fixed bytes on the wire.
//!
//! The server is the Go `kanki-server` from the private kanki-mix repository. Its binary is built into
//! the panel (assets/bin/kanki-mix-server) and each agent writes it to its own server, so nodes need no
//! reinstall: an agent update is enough. Every user has their own key, made from the panel's secret and
//! the user's subscription code (a new code = a new key). The server tells users apart by which key opens
//! their packets; nothing on the wire names the user.
use crate::db::{Node, User};
use crate::util::rand_token;
use crate::App;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::Mutex;

static BIN_BYTES: &[u8] = include_bytes!("../../assets/bin/kanki-mix-server");
const BIN: &str = "/usr/local/bin/kanki-mix-server";
const DIR: &str = "/etc/kanki/kmix";
const USERS_FILE: &str = "/etc/kanki/kmix/users.json";
const ENV_FILE: &str = "/etc/kanki/kmix/env";
const API_FILE: &str = "/etc/kanki/kmix/api.json";
const STATE_FILE: &str = "/etc/kanki/kmix/state.json";
pub const UNIT_NAME: &str = "kanki-mix.service";
const UNIT: &str = "/etc/systemd/system/kanki-mix.service";
/// comment on our port-range iptables rules, so only ours are ever touched
const HOP_TAG: &str = "kanki-mix-hop";
pub const DEFAULT_PORT: u16 = 4000;
/// FEC data shards; parity is a setting (0 = no FEC)
const FEC_DATA: u8 = 10;

// ------------------------------------------------------------------ what the panel sends a server

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(default)]
pub struct KmixUser {
    pub name: String,
    pub key: String,
    /// devices at the same time (0 = no limit)
    pub max: i64,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(default)]
pub struct KmixCfg {
    pub on: bool,
    pub port: u16,
    pub parity: u8,
    /// extra UDP ports "first-last" sent on to `port` (the app picks one at random), "" = none
    pub hop: String,
    pub users: Vec<KmixUser>,
}

// ------------------------------------------------------------------ panel settings

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct NodeOpt {
    /// KANKI MIX off on this server only
    pub off: bool,
    /// this server's own port (0 = the default port)
    pub port: u16,
    /// how the app reaches this server: "" = direct, to the server's own address (lowest ping);
    /// "tunnel" = through the server's endpoint (the Iran entry; its tunnel must forward the UDP port)
    pub route: String,
    /// address the app dials instead of the automatic one ("" = automatic)
    pub host: String,
}

#[derive(Clone, Debug)]
pub struct Settings {
    pub on: bool,
    pub port: u16,
    pub parity: u8,
    pub hop: String,
    /// gaming mode (each game packet sent twice) on by default in the app
    pub gaming: bool,
    pub nodes: HashMap<String, NodeOpt>,
}

pub fn settings(app: &App) -> Settings {
    let db = &app.db;
    Settings {
        on: db.get("kmix_on") != "0",
        port: db.get("kmix_port").parse().ok().filter(|p| *p > 0).unwrap_or(DEFAULT_PORT),
        parity: db.get("kmix_parity").parse().ok().filter(|p| *p <= 10).unwrap_or(3),
        hop: valid_hop(&db.get("kmix_hop")).unwrap_or_default(),
        gaming: db.get("kmix_gaming") != "0",
        nodes: serde_json::from_str(&db.get("kmix_nodes")).unwrap_or_default(),
    }
}

/// "4001-4010" -> Some((4001, 4010)); at most 1000 ports, never port 0
pub fn hop_range(s: &str) -> Option<(u16, u16)> {
    let (a, b) = s.trim().split_once('-')?;
    let (a, b): (u16, u16) = (a.trim().parse().ok()?, b.trim().parse().ok()?);
    (a > 0 && b > a && b - a < 1000).then_some((a, b))
}

pub fn valid_hop(s: &str) -> Option<String> {
    hop_range(s).map(|(a, b)| format!("{}-{}", a, b))
}

impl Settings {
    pub fn node_on(&self, node_id: &str) -> bool {
        self.on && !self.nodes.get(node_id).map(|o| o.off).unwrap_or(false)
    }
    pub fn node_port(&self, node_id: &str) -> u16 {
        self.nodes.get(node_id).map(|o| o.port).filter(|p| *p > 0).unwrap_or(self.port)
    }
    pub fn node_tunnel(&self, node_id: &str) -> bool {
        self.nodes.get(node_id).map(|o| o.route == "tunnel").unwrap_or(false)
    }
}

/// The server's own public address: the host of its agent URL (the main server: its DOMAIN).
/// Not the node endpoint, which for tunnelled servers is the Iran entry.
pub fn direct_host(app: &App, n: &Node) -> String {
    if n.id == "local" {
        return app.env.get("DOMAIN").cloned().unwrap_or_default().trim().to_string();
    }
    let rest = n.address.trim().split("://").last().unwrap_or("");
    let hostport = rest.split('/').next().unwrap_or("").rsplit('@').next().unwrap_or("");
    if let Some(v6) = hostport.strip_prefix('[') {
        return v6.split(']').next().unwrap_or("").to_string();
    }
    hostport.split(':').next().unwrap_or("").to_string()
}

/// The address the app dials for KANKI MIX on this server
pub fn link_host(app: &App, s: &Settings, n: &Node) -> String {
    let opt = s.nodes.get(&n.id).cloned().unwrap_or_default();
    if !opt.host.trim().is_empty() {
        return opt.host.trim().to_string();
    }
    if opt.route == "tunnel" {
        return crate::api::endpoint(app, n);
    }
    let d = direct_host(app, n);
    if d.is_empty() || d == "127.0.0.1" { crate::api::endpoint(app, n) } else { d }
}

/// a host name or IP the panel accepts as a KANKI MIX address
fn valid_host(h: &str) -> bool {
    !h.is_empty() && h.len() <= 253 && h.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']'))
}

// ------------------------------------------------------------------ per-user keys

static SECRET_LOCK: Mutex<()> = Mutex::new(());

/// The panel's secret: made once, kept in the database (and so in its backups)
fn secret(app: &App) -> String {
    let _g = SECRET_LOCK.lock().unwrap();
    let s = app.db.get("kmix_secret");
    if !s.is_empty() {
        return s;
    }
    let s = rand_token(48);
    app.db.set("kmix_secret", &s);
    s
}

/// The user's KANKI MIX key (64 hex): HMAC-SHA256(panel secret, user id + subscription code)
pub fn user_key(app: &App, u: &User) -> String {
    derive_key(&secret(app), u.id, &u.code)
}

fn derive_key(secret: &str, id: i64, code: &str) -> String {
    let mut m = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("hmac key");
    m.update(format!("kmix|{}|{}", id, code).as_bytes());
    hex::encode(m.finalize().into_bytes())
}

/// What one server should run (users = the active users of this server)
pub fn cfg_for(app: &App, s: &Settings, n: &Node, users: &[&User]) -> KmixCfg {
    if !s.node_on(&n.id) {
        return KmixCfg { on: false, ..Default::default() };
    }
    let limit_on = app.db.get("conn_limit_on") != "0";
    let users = users
        .iter()
        .filter(|u| u.has_proto("kmix"))
        .map(|u| KmixUser { name: u.username.clone(), key: user_key(app, u), max: if limit_on { u.max_conn } else { 0 } })
        .collect();
    KmixCfg { on: true, port: s.node_port(&n.id), parity: s.parity, hop: s.hop.clone(), users }
}

/// The last apply error of each server (shown on the KANKI MIX page)
fn errors() -> &'static Mutex<HashMap<String, String>> {
    static E: std::sync::OnceLock<Mutex<HashMap<String, String>>> = std::sync::OnceLock::new();
    E.get_or_init(|| Mutex::new(HashMap::new()))
}

pub fn note_error(node_id: &str, e: &str) {
    let mut g = errors().lock().unwrap();
    if e.is_empty() {
        g.remove(node_id);
    } else {
        g.insert(node_id.to_string(), e.to_string());
    }
}

pub fn error_of(node_id: &str) -> String {
    errors().lock().unwrap().get(node_id).cloned().unwrap_or_default()
}

// ------------------------------------------------------------------ links

/// The user's kanki:// link for one server (None = no KANKI MIX for this user there)
pub fn link(app: &App, u: &User, n: &Node) -> Option<String> {
    if !u.has_proto("kmix") || !u.active() {
        return None;
    }
    let s = settings(app);
    if !s.node_on(&n.id) {
        return None;
    }
    let info = crate::api::node_info(n);
    // the port the server really runs (it reports it); an older agent without KANKI MIX has none
    let port = info["kmix_port"].as_u64().filter(|p| *p > 0)?;
    let parity = info["kmix_parity"].as_u64().unwrap_or(s.parity as u64);
    let mut q = format!("fec={}-{}", FEC_DATA, parity);
    if let Some(h) = info["kmix_hop"].as_str().filter(|h| !h.is_empty()) {
        q.push_str(&format!("&ports={}", h));
    }
    if s.gaming {
        q.push_str("&gaming=1");
    }
    let host = link_host(app, &s, n);
    let host = if host.contains(':') && !host.starts_with('[') { format!("[{}]", host) } else { host };
    Some(format!("kanki://{}@{}:{}?{}#{}", user_key(app, u), host, port, q, crate::util::pct(&n.name)))
}

// ------------------------------------------------------------------ on the server (agent / main)

fn sh(cmd: &str) -> (bool, String) {
    match std::process::Command::new("sh").arg("-c").arg(cmd).stdin(std::process::Stdio::null()).output() {
        Ok(o) => {
            let mut t = String::from_utf8_lossy(&o.stdout).to_string();
            t.push_str(&String::from_utf8_lossy(&o.stderr));
            (o.status.success(), t.trim().to_string())
        }
        Err(e) => (false, e.to_string()),
    }
}

/// Writes the file only when the text differs. true = written.
fn write_if_changed(path: &str, text: &str, mode: u32) -> Result<bool, String> {
    if std::fs::read_to_string(path).map(|t| t == text).unwrap_or(false) {
        return Ok(false);
    }
    let tmp = format!("{}.new", path);
    std::fs::write(&tmp, text).map_err(|e| format!("cannot write {}: {}", path, e))?;
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode));
    }
    std::fs::rename(&tmp, path).map_err(|e| format!("cannot write {}: {}", path, e))?;
    Ok(true)
}

/// The built-in server binary on disk. true = it was (re)written.
fn ensure_bin() -> Result<bool, String> {
    if std::fs::read(BIN).map(|b| b == BIN_BYTES).unwrap_or(false) {
        return Ok(false);
    }
    let tmp = format!("{}.new", BIN);
    std::fs::write(&tmp, BIN_BYTES).map_err(|e| format!("cannot write {}: {}", BIN, e))?;
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755));
    }
    std::fs::rename(&tmp, BIN).map_err(|e| format!("cannot write {}: {}", BIN, e))?;
    Ok(true)
}

/// The local stats API of this server: (port, secret), made once
fn api_conf() -> Result<(u16, String), String> {
    if let Ok(t) = std::fs::read_to_string(API_FILE) {
        let v: Value = serde_json::from_str(&t).unwrap_or(Value::Null);
        if let (Some(p), Some(s)) = (v["port"].as_u64(), v["secret"].as_str()) {
            if p > 0 && !s.is_empty() {
                return Ok((p as u16, s.to_string()));
            }
        }
    }
    use rand::Rng;
    let port: u16 = rand::thread_rng().gen_range(40000..49000);
    let s = rand_token(32);
    write_if_changed(API_FILE, &json!({ "port": port, "secret": s }).to_string(), 0o600)?;
    Ok((port, s))
}

/// Who holds a UDP port (empty = free, or held by KANKI MIX itself)
fn udp_port_owner(port: u16) -> String {
    let (_, out) = sh(&format!("ss -Hlunp 'sport = :{}' 2>/dev/null", port));
    if out.is_empty() || out.contains("kanki-mix-serve") {
        return String::new();
    }
    out.split("users:((\"").nth(1).and_then(|r| r.split('"').next()).unwrap_or("another program").to_string()
}

/// Our port-range rules in iptables (nat PREROUTING): exactly `want` or none
fn sync_hop(want: Option<(u16, u16, u16)>) {
    if !sh("command -v iptables").0 {
        return;
    }
    let (_, rules) = sh("iptables -t nat -S PREROUTING 2>/dev/null");
    let ours: Vec<&str> = rules.lines().filter(|l| l.contains(HOP_TAG)).collect();
    let want_rule = want.map(|(a, b, to)| {
        format!("-A PREROUTING -p udp -m udp --dport {}:{} -m comment --comment {} -j REDIRECT --to-ports {}", a, b, HOP_TAG, to)
    });
    for r in &ours {
        if Some(r.to_string()) != want_rule {
            let _ = sh(&format!("iptables -t nat {}", r.replacen("-A ", "-D ", 1)));
        }
    }
    if let (Some(rule), Some((a, b, _))) = (want_rule, want) {
        if !ours.iter().any(|r| *r == rule) {
            let _ = sh(&format!("iptables -t nat {}", rule));
            if sh("ufw status 2>/dev/null | grep -q 'Status: active'").0 {
                let _ = sh(&format!("ufw allow {}:{}/udp >/dev/null 2>&1", a, b));
            }
        }
    }
}

/// Stops and removes KANKI MIX from this server (the binary stays, it is small)
fn remove() {
    if std::path::Path::new(UNIT).exists() {
        eprintln!("kanki-mix: stopping");
        let _ = sh(&format!("systemctl disable --now -q {} 2>&1", UNIT_NAME));
        let _ = std::fs::remove_file(UNIT);
        let _ = sh("systemctl daemon-reload");
    }
    sync_hop(None);
    let _ = std::fs::remove_file(STATE_FILE);
}

/// Keep KANKI MIX on this server in step with the panel. Blocking.
pub fn apply(c: &KmixCfg) -> Result<(), String> {
    if !c.on {
        remove();
        return Ok(());
    }
    let port = if c.port > 0 { c.port } else { DEFAULT_PORT };
    let parity = c.parity.min(10);
    std::fs::create_dir_all(DIR).map_err(|e| format!("cannot make {}: {}", DIR, e))?;
    let bin_changed = ensure_bin()?;
    let (api_port, api_secret) = api_conf()?;
    let env_changed = write_if_changed(ENV_FILE, &format!("KANKI_API_SECRET={}\n", api_secret), 0o600)?;
    let users = serde_json::to_string(&json!({ "users": c.users })).map_err(|e| e.to_string())?;
    let users_changed = write_if_changed(USERS_FILE, &users, 0o600)?;
    let unit = format!(
        "# written by kanki-panel\n[Unit]\nDescription=KANKI MIX (Kanki VPN)\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nEnvironmentFile={env}\nExecStart={bin} -listen :{port} -users {users} -api 127.0.0.1:{api} -fec-data {d} -fec-parity {p}\nRestart=always\nRestartSec=3\nLimitNOFILE=1048576\n\n[Install]\nWantedBy=multi-user.target\n",
        env = ENV_FILE, bin = BIN, port = port, users = USERS_FILE, api = api_port, d = FEC_DATA, p = parity
    );
    let unit_changed = write_if_changed(UNIT, &unit, 0o644)?;
    if unit_changed {
        let _ = sh("systemctl daemon-reload");
        let _ = sh(&format!("systemctl enable -q {}", UNIT_NAME));
    }
    let hop = hop_range(&c.hop).filter(|(a, b)| !(*a..=*b).contains(&port));
    sync_hop(hop.map(|(a, b)| (a, b, port)));
    let state = json!({ "port": port, "parity": parity, "hop": hop.map(|(a, b)| format!("{}-{}", a, b)).unwrap_or_default() });
    let _ = write_if_changed(STATE_FILE, &state.to_string(), 0o644);

    let active = sh(&format!("systemctl is-active --quiet {}", UNIT_NAME)).0;
    if unit_changed || bin_changed || env_changed || !active {
        if !active {
            let owner = udp_port_owner(port);
            if !owner.is_empty() {
                return Err(format!("UDP port {} is used by {}: pick another KANKI MIX port", port, owner));
            }
        }
        let (ok, out) = sh(&format!("systemctl restart {} 2>&1", UNIT_NAME));
        if !ok {
            return Err(format!("systemctl restart kanki-mix: {}", out.lines().last().unwrap_or("")));
        }
        eprintln!("kanki-mix: (re)started on udp {}", port);
    } else if users_changed {
        // the server reads the users again without dropping anyone else
        let _ = sh(&format!("systemctl kill -s HUP {}", UNIT_NAME));
    }
    if sh("ufw status 2>/dev/null | grep -q 'Status: active'").0 {
        let _ = sh(&format!("ufw allow {}/udp >/dev/null 2>&1", port));
    }
    Ok(())
}

/// The stats API of this server, when KANKI MIX runs here
fn api_here() -> Option<(String, String)> {
    if !std::path::Path::new(UNIT).exists() {
        return None;
    }
    let v: Value = serde_json::from_str(&std::fs::read_to_string(API_FILE).ok()?).ok()?;
    Some((v["port"].as_u64()?.to_string(), v["secret"].as_str()?.to_string()))
}

/// Per-user traffic since the last read: username -> (rx, tx) bytes on the wire
pub async fn traffic() -> HashMap<String, (i64, i64)> {
    match api_here() {
        Some((p, s)) => crate::hy2::traffic(&p, &s).await,
        None => HashMap::new(),
    }
}

/// Devices online per user
pub async fn online() -> HashMap<String, i64> {
    match api_here() {
        Some((p, s)) => crate::hy2::online(&p, &s).await,
        None => HashMap::new(),
    }
}

/// What this server reports about KANKI MIX (for the links and the panel)
pub fn info() -> Value {
    let st: Value = std::fs::read_to_string(STATE_FILE).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or(Value::Null);
    if st.is_null() || !std::path::Path::new(UNIT).exists() {
        return json!({});
    }
    let active = sh(&format!("systemctl is-active --quiet {}", UNIT_NAME)).0;
    let mut v = json!({
        "kmix_port": st["port"], "kmix_parity": st["parity"], "kmix_hop": st["hop"], "kmix_active": active,
        "kmix_users": std::fs::read_to_string(USERS_FILE).ok().and_then(|t| serde_json::from_str::<Value>(&t).ok())
            .and_then(|v| v["users"].as_array().map(|a| a.len())).unwrap_or(0),
    });
    if !active {
        v["kmix_error"] = json!(sh(&format!("journalctl -u {} -n 5 --no-pager -o cat 2>/dev/null", UNIT_NAME)).1.lines().last().unwrap_or("not running").to_string());
    }
    v
}

// ------------------------------------------------------------------ admin API (the KANKI MIX page)

type St = axum::extract::State<std::sync::Arc<App>>;

pub fn router() -> axum::Router<std::sync::Arc<App>> {
    use axum::routing::{get, post};
    axum::Router::new()
        .route("/api/kmix", get(get_all).put(put_settings))
        .route("/api/kmix/users", post(all_users))
}

fn settings_json(s: &Settings) -> Value {
    json!({ "on": s.on, "port": s.port, "parity": s.parity, "hop": s.hop, "gaming": s.gaming, "nodes": s.nodes })
}

async fn get_all(axum::extract::State(app): St, h: axum::http::HeaderMap) -> axum::response::Response {
    use axum::response::IntoResponse;
    let _ = crate::guard!(app, h, "nodes");
    let s = settings(&app);
    let users = app.db.users();
    let with: Vec<&User> = users.iter().filter(|u| u.has_proto("kmix")).collect();
    let servers: Vec<Value> = app.db.nodes().iter().map(|n| {
        let info = crate::api::node_info(n);
        let here = with.iter().filter(|u| u.active() && u.on(n)).count();
        let e = error_of(&n.id);
        let error = if e.is_empty() { info["kmix_error"].clone() } else { json!(e) };
        json!({
            "id": n.id, "name": n.name, "main": n.id == "local", "online": n.id == "local" || n.online,
            "endpoint": link_host(&app, &s, n), "direct_host": direct_host(&app, n), "tunnel_host": crate::api::endpoint(&app, n),
            "route": if s.node_tunnel(&n.id) { "tunnel" } else { "direct" },
            "on": s.node_on(&n.id), "want_port": s.node_port(&n.id),
            "port": info["kmix_port"], "parity": info["kmix_parity"], "hop": info["kmix_hop"],
            "active": info["kmix_active"], "installed": !info["kmix_port"].is_null(), "users": here,
            "error": error,
            "version": info["version"],
            // the other UDP ports of this server (a clash with them is refused)
            "used_ports": [info["wg_port"], info["awg_port"], info["hy2_port"]],
        })
    }).collect();
    let online = with.iter().filter(|u| u.online > 0).count();
    axum::Json(json!({
        "settings": settings_json(&s), "servers": servers, "users": with.len(), "users_total": users.len(),
        "online": online, "traffic_gb": (with.iter().map(|u| u.used_gb()).sum::<f64>() * 10.0).round() / 10.0,
    })).into_response()
}

fn port_of(v: &Value) -> Option<u16> {
    v.as_u64().or_else(|| v.as_str().and_then(|x| x.trim().parse().ok())).filter(|p| *p > 0 && *p <= 65535).map(|p| p as u16)
}

async fn put_settings(axum::extract::State(app): St, h: axum::http::HeaderMap, axum::Json(b): axum::Json<Value>) -> axum::response::Response {
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    let _ = crate::guard!(app, h, "nodes");
    let cur = settings(&app);
    let port = if b["port"].is_null() { cur.port } else { match port_of(&b["port"]) { Some(p) => p, None => return crate::api::err(StatusCode::BAD_REQUEST, "the port must be 1-65535") } };
    let parity = if b["parity"].is_null() { cur.parity } else { match b["parity"].as_u64().or_else(|| b["parity"].as_str().and_then(|x| x.parse().ok())) { Some(p) if p <= 10 => p as u8, _ => return crate::api::err(StatusCode::BAD_REQUEST, "FEC parity must be 0-10") } };
    let hop = match b["hop"].as_str().map(|x| x.trim()) {
        None => cur.hop.clone(),
        Some("") => String::new(),
        Some(x) => match valid_hop(x) { Some(v) => v, None => return crate::api::err(StatusCode::BAD_REQUEST, "extra ports: first-last, like 4001-4010 (at most 1000 ports)") },
    };
    let mut nodes = cur.nodes.clone();
    if let Some(o) = b["nodes"].as_object() {
        nodes.clear();
        for (id, v) in o {
            let host = v["host"].as_str().unwrap_or("").trim().to_string();
            if !host.is_empty() && !valid_host(&host) {
                return crate::api::err(StatusCode::BAD_REQUEST, "address: a domain or an IP, like de.example.com");
            }
            let route = if v["route"].as_str() == Some("tunnel") { "tunnel".to_string() } else { String::new() };
            let opt = NodeOpt { off: v["off"].as_bool().unwrap_or(false), port: port_of(&v["port"]).unwrap_or(0), route, host };
            if opt.off || opt.port > 0 || !opt.route.is_empty() || !opt.host.is_empty() {
                nodes.insert(id.clone(), opt);
            }
        }
    }
    // a port that clashes with WireGuard / AmneziaWG / Hysteria2 of a server, or inside the extra ports
    let next = Settings { on: b["on"].as_bool().unwrap_or(cur.on), port, parity, hop, gaming: b["gaming"].as_bool().unwrap_or(cur.gaming), nodes };
    for n in app.db.nodes() {
        if !next.node_on(&n.id) {
            continue;
        }
        let p = next.node_port(&n.id);
        let info = crate::api::node_info(&n);
        for (k, name) in [("wg_port", "WireGuard"), ("awg_port", "AmneziaWG"), ("hy2_port", "Hysteria2")] {
            if port_of(&info[k]) == Some(p) {
                return crate::api::err(StatusCode::BAD_REQUEST, &format!("{}: UDP port {} is already {}", n.name, p, name));
            }
        }
        if let Some((a, z)) = hop_range(&next.hop) {
            if (a..=z).contains(&p) {
                return crate::api::err(StatusCode::BAD_REQUEST, &format!("{}: the port {} is inside the extra ports", n.name, p));
            }
        }
    }
    let db = &app.db;
    db.set("kmix_on", if next.on { "1" } else { "0" });
    db.set("kmix_port", &next.port.to_string());
    db.set("kmix_parity", &next.parity.to_string());
    db.set("kmix_hop", &next.hop);
    db.set("kmix_gaming", if next.gaming { "1" } else { "0" });
    db.set("kmix_nodes", &serde_json::to_string(&next.nodes).unwrap_or_else(|_| "{}".into()));
    crate::api::spawn_sync(&app);
    axum::Json(json!({ "ok": true, "settings": settings_json(&next) })).into_response()
}

/// KANKI MIX for every user (on: true) or for nobody (on: false)
async fn all_users(axum::extract::State(app): St, h: axum::http::HeaderMap, axum::Json(b): axum::Json<Value>) -> axum::response::Response {
    use axum::response::IntoResponse;
    let _ = crate::guard!(app, h, "users:write");
    let on = b["on"].as_bool().unwrap_or(true);
    let mut changed = 0;
    for u in app.db.users() {
        let mut list: Vec<String> = u.protocols.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect();
        let has = list.iter().any(|x| x == "kmix");
        if on == has {
            continue;
        }
        if on { list.push("kmix".into()) } else { list.retain(|x| x != "kmix") }
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
    fn route_and_host_options() {
        let mut s = Settings { on: true, port: 4000, parity: 3, hop: String::new(), gaming: true, nodes: HashMap::new() };
        assert!(!s.node_tunnel("de"));
        s.nodes.insert("de".into(), NodeOpt { route: "tunnel".into(), ..Default::default() });
        assert!(s.node_tunnel("de"));
        assert!(valid_host("de.example.com") && valid_host("1.2.3.4") && valid_host("[2001:db8::1]"));
        assert!(!valid_host("") && !valid_host("a b") && !valid_host("x/y"));
    }

    #[test]
    fn hop_ranges() {
        assert_eq!(hop_range("4001-4010"), Some((4001, 4010)));
        assert_eq!(hop_range(" 5000 - 5999 "), Some((5000, 5999)));
        assert_eq!(hop_range("4010-4001"), None);
        assert_eq!(hop_range("0-10"), None);
        assert_eq!(hop_range("1000-3000"), None); // more than 1000 ports
        assert_eq!(hop_range("abc"), None);
        assert_eq!(hop_range(""), None);
    }

    #[test]
    fn user_keys() {
        let k = derive_key("panel-secret", 7, "1234567890");
        // 32 bytes as hex: what kanki-server and the app expect
        assert_eq!(k.len(), 64);
        assert!(k.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        // the same user gets the same key on every server and every sync
        assert_eq!(k, derive_key("panel-secret", 7, "1234567890"));
        // a new subscription code (link reset), another user or another panel: another key
        assert_ne!(k, derive_key("panel-secret", 7, "1234567891"));
        assert_ne!(k, derive_key("panel-secret", 8, "1234567890"));
        assert_ne!(k, derive_key("other-secret", 7, "1234567890"));
    }

    #[test]
    fn settings_per_node() {
        let mut s = Settings { on: true, port: 4000, parity: 3, hop: String::new(), gaming: true, nodes: HashMap::new() };
        s.nodes.insert("n1".into(), NodeOpt { off: false, port: 5000, ..Default::default() });
        s.nodes.insert("n2".into(), NodeOpt { off: true, port: 0, ..Default::default() });
        assert_eq!(s.node_port("n1"), 5000);
        assert_eq!(s.node_port("local"), 4000);
        assert!(s.node_on("n1") && s.node_on("local") && !s.node_on("n2"));
        s.on = false;
        assert!(!s.node_on("n1") && !s.node_on("local"));
    }

    #[test]
    fn binary_is_built_in() {
        // the Go server for linux/amd64 must be inside the panel (ELF header)
        assert!(BIN_BYTES.len() > 1_000_000 && BIN_BYTES.starts_with(b"\x7fELF"));
    }
}
