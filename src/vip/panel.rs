//! VIP tunnel in the panel: its own list (`vip_tunnels`), its own page (`#vip`) and its own API
//! (`/api/vip`). Each tunnel is between two servers of the panel (tunnel servers or the panel's own); the
//! panel gives each side its `VipSpec` with the agent's report (`agent_report` › `vip`) and keeps what the
//! sides say about it (`note`).

use super::{VipSpec, VipStatus};
use crate::api::err;
use crate::guard;
use crate::util::{now, rand_token};
use crate::App;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

/// agents older than this do not know the VIP tunnel
pub const MIN_AGENT: &str = "3.44.0";
const MODES: &[&str] = &["gaming", "balanced", "speed"];
const STREAMS: &[&str] = &["", "h2", "wss", "ws", "tcp", "cdn"];

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(default)]
pub struct VipTunnel {
    pub id: String,
    pub name: String,
    pub entry: String,
    pub exit: String,
    /// "exit" (the exit dials the entry: the usual way out of Iran) | "entry"
    pub dialer: String,
    /// the address the dialer uses for the listener ("" = the server's own)
    pub dial: String,
    pub secret: String,
    pub mode: String,
    pub stealth: u8,
    pub pq: bool,
    pub port: u16,
    pub hop: u8,
    pub hop_secs: u16,
    pub udp_paths: u8,
    pub ftcp_port: u16,
    pub s_kind: String,
    pub s_port: u16,
    pub s_sni: String,
    pub s_host: String,
    pub s_path: String,
    pub s_frag: bool,
    pub s_dial: String,
    pub tcp: Vec<String>,
    pub udp: Vec<String>,
    pub target: String,
    pub mtu: u16,
    pub burst: u8,
    pub rt_max: u16,
    pub rekey_secs: u32,
    pub enabled: bool,
    pub created: i64,
}

impl VipTunnel {
    fn listener(&self) -> &str {
        if self.dialer == "entry" { &self.exit } else { &self.entry }
    }
    /// The ports this tunnel holds: (server, port, udp)
    pub fn needs(&self) -> Vec<(String, u16, bool)> {
        let mut v = vec![];
        let l = self.listener().to_string();
        if self.port > 0 {
            for i in 0..self.hop.clamp(1, 32) as u16 {
                v.push((l.clone(), self.port.saturating_add(i), true));
            }
        }
        if self.ftcp_port > 0 {
            v.push((l.clone(), self.ftcp_port, false));
        }
        if !self.s_kind.is_empty() && self.s_port > 0 {
            v.push((l.clone(), self.s_port, false));
        }
        for (a, _) in crate::tunnel::engine::parse_ports(&self.tcp) {
            v.push((self.entry.clone(), a, false));
        }
        for (a, _) in crate::tunnel::engine::parse_ports(&self.udp) {
            v.push((self.entry.clone(), a, true));
        }
        v
    }
}

pub fn tunnels(app: &App) -> Vec<VipTunnel> {
    serde_json::from_str(&app.db.get("vip_tunnels")).unwrap_or_default()
}

fn save_all(app: &App, v: &[VipTunnel]) {
    app.db.set("vip_tunnels", &serde_json::to_string(v).unwrap_or_else(|_| "[]".into()));
}

/// The ports VIP tunnels hold on server `sid` (for the other tunnels' checks): (port, udp, tunnel name)
pub fn ports_on(app: &App, sid: &str, except: &str) -> Vec<(u16, bool, String)> {
    tunnels(app)
        .into_iter()
        .filter(|t| t.enabled && t.id != except)
        .flat_map(|t| t.needs().into_iter().filter(|x| x.0 == sid).map(move |x| (x.1, x.2, t.name.clone())).collect::<Vec<_>>())
        .collect()
}

/// The tunnels whose ports lead somewhere, as the rest of the panel follows them (second configs through
/// a tunnel, the port pages): entry, exit and forwarded ports
pub fn as_routes(app: &App) -> Vec<crate::tunnel::panel::Tunnel> {
    tunnels(app)
        .into_iter()
        .filter(|t| t.enabled)
        .map(|t| crate::tunnel::panel::Tunnel { id: format!("vip-{}", t.id), name: t.name, entry: t.entry, exit: t.exit, tcp: t.tcp, udp: t.udp, target: t.target, enabled: true, kind: "vip".into(), ..Default::default() })
        .collect()
}

/// What server `sid` runs
pub fn specs_for(app: &App, sid: &str) -> Vec<VipSpec> {
    let mut out = vec![];
    for t in tunnels(app) {
        if !t.enabled || t.entry == t.exit || (t.entry != sid && t.exit != sid) {
            continue;
        }
        let role = if t.entry == sid { "entry" } else { "exit" };
        let dials = (t.dialer == "entry") == (role == "entry");
        let remote = if dials {
            if t.dial.trim().is_empty() { crate::tunnel::panel::host_of(app, t.listener()) } else { t.dial.trim().to_string() }
        } else {
            String::new()
        };
        out.push(VipSpec {
            id: t.id.clone(),
            name: t.name.clone(),
            role: role.into(),
            dials,
            remote,
            secret: t.secret.clone(),
            mode: t.mode.clone(),
            stealth: t.stealth,
            pq: t.pq,
            port: t.port,
            hop: t.hop,
            hop_secs: t.hop_secs,
            udp_paths: t.udp_paths,
            ftcp_port: t.ftcp_port,
            s_kind: t.s_kind.clone(),
            s_port: t.s_port,
            s_sni: t.s_sni.clone(),
            s_host: t.s_host.clone(),
            s_path: t.s_path.clone(),
            s_frag: t.s_frag,
            s_dial: t.s_dial.clone(),
            tcp: t.tcp.clone(),
            udp: t.udp.clone(),
            target: t.target.clone(),
            bind: String::new(),
            mtu: t.mtu,
            burst: t.burst,
            rt_max: t.rt_max,
            rekey_secs: t.rekey_secs,
        });
    }
    out
}

// ------------------------------------------------------------------ what the servers say

/// server -> (when, its VIP tunnels)
fn reports() -> &'static Mutex<HashMap<String, (i64, Vec<VipStatus>)>> {
    static R: OnceLock<Mutex<HashMap<String, (i64, Vec<VipStatus>)>>> = OnceLock::new();
    R.get_or_init(Default::default)
}

/// A server's report (`Null` from an older agent: nothing known)
pub fn note(sid: &str, v: &Value) {
    let Ok(list) = serde_json::from_value::<Vec<VipStatus>>(v.clone()) else { return };
    reports().lock().unwrap_or_else(|e| e.into_inner()).insert(sid.to_string(), (now(), list));
}

pub fn note_list(sid: &str, list: Vec<VipStatus>) {
    reports().lock().unwrap_or_else(|e| e.into_inner()).insert(sid.to_string(), (now(), list));
}

fn status_of(sid: &str, id: &str) -> Option<VipStatus> {
    let r = reports().lock().unwrap_or_else(|e| e.into_inner());
    r.get(sid).filter(|(t, _)| now() - t < 30).and_then(|(_, l)| l.iter().find(|s| s.id == id).cloned())
}

/// For the alerts: (key, name, up) of every enabled tunnel whose two servers report now
pub fn health(app: &App) -> Vec<(String, String, bool)> {
    tunnels(app)
        .into_iter()
        .filter(|t| t.enabled)
        .filter_map(|t| {
            let (a, b) = (status_of(&t.entry, &t.id)?, status_of(&t.exit, &t.id)?);
            // worded like the other tunnels: «cut» / «connected again»
            Some((format!("tu:vip-{}", t.id), format!("تانل VIP {}", t.name), a.up && b.up))
        })
        .collect()
}

// ------------------------------------------------------------------ API

type St = State<Arc<App>>;

pub fn router() -> Router<Arc<App>> {
    Router::new()
        .route("/api/vip", get(list).post(save))
        .route("/api/vip/:id", delete(del))
        .route("/api/vip/:id/:action", post(action))
}

fn online(sid: &str) -> (bool, String) {
    if sid == "local" {
        return (true, crate::VERSION.to_string());
    }
    match crate::tunnel::panel::agent_state(sid) {
        Some((at, ver, _, _)) => (now() - at < 30, ver),
        None => (false, String::new()),
    }
}

fn servers_json(app: &App) -> Vec<Value> {
    let locs = crate::tunnel::panel::server_locs(app);
    let names = crate::tunnel::panel::server_names(app);
    let local = app.env.get("LOCAL_NAME").cloned().filter(|s| !s.is_empty()).unwrap_or_else(|| "Main".into());
    std::iter::once(("local".to_string(), local))
        .chain(crate::tunnel::panel::servers(app).into_iter().map(|s| (s.id, s.name)))
        .map(|(id, name)| {
            let (on, ver) = online(&id);
            let name = if name.is_empty() { names.get(&id).cloned().unwrap_or(id.clone()) } else { name };
            json!({ "id": id, "name": name, "online": on, "version": ver, "knows": id == "local" || ver.is_empty() || !crate::admin::newer(MIN_AGENT, &ver),
                    "loc": locs.get(&id).map(|l| l.0.clone()).unwrap_or_default(), "host": crate::tunnel::panel::host_of(app, &id) })
        })
        .collect()
}

async fn list(State(app): St, h: HeaderMap) -> Response {
    let _ = guard!(app, h, "nodes");
    let list: Vec<Value> = tunnels(&app)
        .into_iter()
        .map(|t| {
            let (se, sx) = (status_of(&t.entry, &t.id), status_of(&t.exit, &t.id));
            let mut v = serde_json::to_value(&t).unwrap_or(Value::Null);
            // the secret never leaves the panel through its pages
            v["secret"] = json!("");
            json!({ "t": v, "entry": se, "exit": sx, "up": se.as_ref().is_some_and(|s| s.up) && sx.as_ref().is_some_and(|s| s.up) })
        })
        .collect();
    Json(json!({ "tunnels": list, "servers": servers_json(&app), "min_agent": MIN_AGENT })).into_response()
}

fn clean_list(v: &Value) -> Vec<String> {
    let raw: Vec<String> = match v {
        Value::Array(a) => a.iter().filter_map(|x| x.as_str().map(|s| s.to_string()).or_else(|| x.as_u64().map(|n| n.to_string()))).collect(),
        Value::String(s) => s.split([',', ' ', '\n']).map(|x| x.to_string()).collect(),
        _ => vec![],
    };
    raw.into_iter().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()
}

fn text(v: &Value, max: usize) -> String {
    v.as_str().unwrap_or("").trim().chars().filter(|c| !c.is_control() && !"<>\"'`".contains(*c)).take(max).collect()
}

/// A host the dialer may write (a domain or an IP, or a list of them for a CDN)
fn host_ok(s: &str) -> bool {
    s.is_empty() || s.chars().all(|c| c.is_ascii_alphanumeric() || ".-:[]_,; ".contains(c))
}

/// Applies the form to `t` and checks it alone (not against the other tunnels)
pub fn apply_body(t: &mut VipTunnel, b: &Value) -> Result<(), String> {
    let u = |k: &str| b[k].as_u64();
    if b.get("name").is_some() {
        t.name = text(&b["name"], 60);
    }
    for (k, f) in [("entry", &mut t.entry), ("exit", &mut t.exit)] {
        if b.get(k).is_some() {
            *f = text(&b[k], 40);
        }
    }
    if b.get("dialer").is_some() {
        t.dialer = if b["dialer"].as_str() == Some("entry") { "entry".into() } else { "exit".into() };
    }
    if b.get("mode").is_some() {
        let m = b["mode"].as_str().unwrap_or("");
        if !MODES.contains(&m) {
            return Err("unknown mode".into());
        }
        t.mode = m.into();
    }
    if let Some(v) = u("stealth") {
        t.stealth = v.min(2) as u8;
    }
    if let Some(v) = b["pq"].as_bool() {
        t.pq = v;
    }
    if let Some(v) = b["enabled"].as_bool() {
        t.enabled = v;
    }
    if let Some(v) = b["s_frag"].as_bool() {
        t.s_frag = v;
    }
    let port = |k: &str| -> Result<Option<u16>, String> {
        match &b[k] {
            Value::Null => Ok(None),
            v => {
                let n = v.as_u64().or_else(|| v.as_str().and_then(|x| x.trim().parse().ok())).unwrap_or(u64::MAX);
                if n > 65535 { Err(format!("{}: a port is 0-65535", k)) } else { Ok(Some(n as u16)) }
            }
        }
    };
    if let Some(p) = port("port")? {
        t.port = p;
    }
    if let Some(p) = port("ftcp_port")? {
        t.ftcp_port = p;
    }
    if let Some(p) = port("s_port")? {
        t.s_port = p;
    }
    if let Some(v) = u("hop") {
        t.hop = v.clamp(1, 32) as u8;
    }
    if let Some(v) = u("hop_secs") {
        t.hop_secs = if v == 0 { 0 } else { v.clamp(5, 3600) as u16 };
    }
    if let Some(v) = u("udp_paths") {
        t.udp_paths = v.clamp(1, 4) as u8;
    }
    if let Some(v) = u("mtu") {
        t.mtu = if v == 0 { 0 } else { v.clamp(1200, 1472) as u16 };
    }
    if let Some(v) = u("burst") {
        t.burst = match v {
            1 | 2 | 4 | 8 => v as u8,
            _ => 4,
        };
    }
    if let Some(v) = u("rt_max") {
        t.rt_max = if v == 0 { 0 } else { v.clamp(64, 1400) as u16 };
    }
    if let Some(v) = u("rekey_secs") {
        t.rekey_secs = if v == 0 { 0 } else { v.clamp(60, 86400) as u32 };
    }
    if b.get("s_kind").is_some() {
        let k = b["s_kind"].as_str().unwrap_or("");
        if !STREAMS.contains(&k) {
            return Err("unknown stream path".into());
        }
        t.s_kind = k.into();
    }
    for (k, f) in [("s_sni", &mut t.s_sni), ("s_host", &mut t.s_host), ("s_dial", &mut t.s_dial), ("dial", &mut t.dial), ("target", &mut t.target)] {
        if b.get(k).is_some() {
            let v = text(&b[k], 400);
            if !host_ok(&v) {
                return Err(format!("{}: only names and addresses", k));
            }
            *f = v;
        }
    }
    if b.get("s_path").is_some() {
        t.s_path = text(&b["s_path"], 120).chars().filter(|c| !c.is_whitespace()).collect();
    }
    if b.get("tcp").is_some() {
        t.tcp = clean_list(&b["tcp"]);
    }
    if b.get("udp").is_some() {
        t.udp = clean_list(&b["udp"]);
    }
    // the tunnel as a whole
    if t.entry.is_empty() || t.exit.is_empty() {
        return Err("choose both servers".into());
    }
    if t.entry == t.exit {
        return Err("the two servers must differ".into());
    }
    if t.port == 0 && t.ftcp_port == 0 && (t.s_kind.is_empty() || t.s_port == 0) {
        return Err("turn on at least one path".into());
    }
    if t.port > 0 && t.port as u32 + t.hop.clamp(1, 32) as u32 - 1 > 65535 {
        return Err("the UDP ports go past 65535".into());
    }
    if t.s_kind == "cdn" && t.s_host.is_empty() {
        return Err("the CDN path needs the domain set up on the CDN".into());
    }
    let (tcp, udp) = (crate::tunnel::engine::parse_ports(&t.tcp), crate::tunnel::engine::parse_ports(&t.udp));
    if tcp.is_empty() && udp.is_empty() {
        return Err("forward at least one port".into());
    }
    if udp.len() > 255 {
        return Err("at most 255 UDP ports".into());
    }
    // the same port twice on the listener: the paths and the forwarded ports of the entry
    let mine = t.needs();
    for (i, a) in mine.iter().enumerate() {
        if mine[..i].contains(a) {
            return Err(format!("{} port {} is used twice in this tunnel", if a.2 { "UDP" } else { "TCP" }, a.1));
        }
    }
    Ok(())
}

fn defaults() -> VipTunnel {
    VipTunnel {
        id: rand_token(10).to_lowercase(),
        secret: rand_token(48),
        dialer: "exit".into(),
        mode: "gaming".into(),
        stealth: 1,
        pq: true,
        port: 0,
        hop: 8,
        hop_secs: 30,
        udp_paths: 2,
        burst: 4,
        enabled: true,
        created: now(),
        ..Default::default()
    }
}

/// The ports the rest of the panel has set up on server `sid`, whether they listen yet or not: the Kanki
/// tunnels (with Kanki DNS's relay tunnel and the Iran subscription's), Kanki DNS, the emergency chat, KPING,
/// the Xray inbounds and the VPN cores of the machine. (port, udp, who)
pub fn others_on(app: &App, sid: &str) -> Vec<(u16, bool, String)> {
    let mut v: Vec<(u16, bool, String)> = vec![];
    let names: HashMap<String, String> = crate::tunnel::panel::kanki_tunnels(app).into_iter().map(|t| (t.id, t.name)).collect();
    for s in crate::tunnel::panel::specs_of(app, sid) {
        let who = format!("the tunnel \"{}\"", names.get(&s.id).cloned().unwrap_or(s.name.clone()));
        if let Some(a) = &s.awg {
            if a.open_udp > 0 {
                v.push((a.open_udp, true, who.clone()));
            }
        } else if let Some(y) = &s.hy2 {
            if y.role == "exit" && y.listen > 0 {
                v.push((y.listen, true, who.clone()));
            }
        } else if s.listens() && s.port > 0 {
            let (tcp, udp) = match s.transport.as_str() {
                "quic" | "kcp" | "hq" | "game" => (false, true),
                "dual" => (true, true),
                _ => (true, false),
            };
            if tcp {
                v.push((s.port, false, who.clone()));
            }
            if udp {
                v.push((s.port, true, who.clone()));
            }
        }
        if s.role == "entry" {
            v.extend(crate::tunnel::engine::parse_ports(&s.tcp).into_iter().map(|(a, _)| (a, false, who.clone())));
            v.extend(crate::tunnel::engine::parse_ports(&s.udp).into_iter().map(|(a, _)| (a, true, who.clone())));
        }
    }
    if let Some((c, _)) = crate::dns::panel::cfg_for(app, sid) {
        for (p, udp) in [(c.dns_port, true), (c.dns_port, false), (c.dot_port, false), (c.https_port, false), (c.http_port, false)] {
            if p > 0 {
                v.push((p, udp, "Kanki DNS".into()));
            }
        }
    }
    if app.db.get("emer_server") == sid {
        if let Some((c, _)) = crate::tunnel::panel::emer_cfg(app) {
            v.push((c.port, false, "the emergency chat".into()));
        }
    }
    let kp = crate::kping::settings(app);
    if kp.on {
        for r in kp.routes.iter().filter(|r| r.iran == sid) {
            v.extend(r.ports().into_iter().map(|p| (p, true, "KPING".to_string())));
        }
        if kp.routes.iter().any(|r| r.exit == sid) {
            v.push((kp.port, true, "KPING".into()));
        }
    }
    for ib in crate::xray::panel::settings(app).inbounds.iter().filter(|i| i.server == sid && i.port > 0) {
        v.push((ib.port, ib.network == "kcp", "Xray".into()));
    }
    // the VPN part of the machine: WireGuard, AmneziaWG, Hysteria2, KANKI MIX
    if let Some(ts) = crate::tunnel::panel::servers(app).into_iter().find(|x| x.id == sid) {
        for (p, who) in ts.ports.iter().zip(["WireGuard", "AmneziaWG", "Hysteria2", "KANKI MIX"]) {
            if *p > 0 {
                v.push((*p, true, who.to_string()));
            }
        }
    }
    v
}

/// Is a port of `t` taken on its server: by another VIP tunnel, a Kanki tunnel, or (live) another program
fn clash(app: &App, t: &VipTunnel, old: Option<&VipTunnel>) -> Option<String> {
    let own: Vec<(String, u16, bool)> = old.filter(|o| o.enabled).map(|o| o.needs()).unwrap_or_default();
    for (sid, port, udp) in t.needs() {
        let proto = if udp { "UDP" } else { "TCP" };
        if let Some(x) = ports_on(app, &sid, &t.id).into_iter().find(|x| x.0 == port && x.1 == udp) {
            return Some(format!("{} port {} is already used by the VIP tunnel \"{}\"", proto, port, x.2));
        }
        if let Some(n) = others_on(app, &sid).into_iter().find(|x| x.0 == port && x.1 == udp).map(|x| x.2) {
            return Some(format!("{} port {} is already used by {}", proto, port, n));
        }
        if own.contains(&(sid.clone(), port, udp)) {
            continue;
        }
        if let Some(e) = crate::tunnel::panel::port_busy(app, &sid, port, udp, &[]) {
            return Some(e);
        }
    }
    None
}

async fn save(State(app): St, h: HeaderMap, Json(b): Json<Value>) -> Response {
    let _ = guard!(app, h, "nodes");
    let mut list = tunnels(&app);
    let id = b["id"].as_str().unwrap_or("").to_string();
    let old = list.iter().find(|x| x.id == id).cloned();
    let mut t = match (&old, id.is_empty()) {
        (_, true) => defaults(),
        (Some(o), false) => o.clone(),
        (None, false) => return err(StatusCode::NOT_FOUND, "VIP tunnel not found"),
    };
    if let Err(e) = apply_body(&mut t, &b) {
        return err(StatusCode::BAD_REQUEST, &e);
    }
    let known = |s: &str| s == "local" || crate::tunnel::panel::servers(&app).iter().any(|x| x.id == s);
    if !known(&t.entry) || !known(&t.exit) {
        return err(StatusCode::BAD_REQUEST, "unknown server");
    }
    if t.name.is_empty() {
        t.name = crate::tunnel::panel::default_tunnel_name(&app, &t.entry, &t.exit);
    }
    if t.name.is_empty() {
        t.name = format!("VIP-{}", &t.id[..4.min(t.id.len())]);
    }
    if t.enabled {
        if let Some(e) = clash(&app, &t, old.as_ref()) {
            return err(StatusCode::CONFLICT, &e);
        }
    }
    match list.iter_mut().find(|x| x.id == t.id) {
        Some(x) => *x = t.clone(),
        None => list.push(t.clone()),
    }
    save_all(&app, &list);
    Json(json!({ "ok": true, "id": t.id })).into_response()
}

async fn del(State(app): St, h: HeaderMap, Path(id): Path<String>) -> Response {
    let _ = guard!(app, h, "nodes");
    let mut list = tunnels(&app);
    let n = list.len();
    list.retain(|x| x.id != id);
    if list.len() == n {
        return err(StatusCode::NOT_FOUND, "VIP tunnel not found");
    }
    save_all(&app, &list);
    Json(json!({ "ok": true })).into_response()
}

/// on | off | secret (a new secret: both sides take it on their next report)
async fn action(State(app): St, h: HeaderMap, Path((id, a)): Path<(String, String)>) -> Response {
    let _ = guard!(app, h, "nodes");
    let mut list = tunnels(&app);
    let Some(i) = list.iter().position(|x| x.id == id) else { return err(StatusCode::NOT_FOUND, "VIP tunnel not found") };
    match a.as_str() {
        "on" => {
            let mut t = list[i].clone();
            t.enabled = true;
            if let Some(e) = clash(&app, &t, None) {
                return err(StatusCode::CONFLICT, &e);
            }
            list[i] = t;
        }
        "off" => list[i].enabled = false,
        "secret" => list[i].secret = rand_token(48),
        _ => return err(StatusCode::BAD_REQUEST, "unknown action"),
    }
    save_all(&app, &list);
    Json(json!({ "ok": true })).into_response()
}

/// A removed server takes its VIP tunnels with it
pub fn forget_server(app: &App, sid: &str) {
    let mut list = tunnels(app);
    let n = list.len();
    list.retain(|t| t.entry != sid && t.exit != sid);
    if list.len() != n {
        save_all(app, &list);
    }
    reports().lock().unwrap_or_else(|e| e.into_inner()).remove(sid);
}

/// The names of the VIP tunnels that use server `sid`
pub fn using(app: &App, sid: &str) -> Vec<String> {
    tunnels(app).into_iter().filter(|t| t.entry == sid || t.exit == sid).map(|t| format!("VIP {}", t.name)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kping::tests::test_app;

    async fn call(app: &Arc<App>, method: &str, uri: &str, body: Value) -> (StatusCode, Value) {
        use tower::ServiceExt;
        let r = axum::http::Request::builder().method(method).uri(uri).header("authorization", "Bearer test-key").header("content-type", "application/json").body(axum::body::Body::from(body.to_string())).unwrap();
        let res = crate::api::master_router(app.clone()).oneshot(r).await.unwrap();
        let st = res.status();
        let b = axum::body::to_bytes(res.into_body(), 1 << 22).await.unwrap();
        (st, serde_json::from_slice(&b).unwrap_or(Value::Null))
    }

    /// From the page to both servers: the form is checked, the secret never comes back to the page, each side
    /// gets its own part (the exit dials the Iran server's address, the Iran server listens), the Kanki
    /// tunnels and the second configs follow its ports, and a port another tunnel holds is refused both ways
    #[tokio::test]
    async fn a_vip_tunnel_from_the_page_to_both_servers() {
        let app = test_app();
        app.db.set("api_key", "test-key");
        app.db.set("tun_servers", &json!([{ "id": "ir1", "name": "Tehran", "token": "x", "addr": "ir.example.com", "loc": "iran" }]).to_string());
        let good = json!({ "entry": "ir1", "exit": "local", "mode": "gaming", "port": 24400, "hop": 4, "hop_secs": 30, "udp_paths": 2, "ftcp_port": 24420, "s_kind": "h2", "s_port": 24443, "udp": ["51820"], "tcp": ["8443:443"] });
        // the form alone
        for (bad, why) in [
            (json!({ "entry": "ir1", "exit": "ir1", "port": 24400, "udp": ["1"] }), "differ"),
            (json!({ "entry": "ir1", "exit": "local", "udp": ["1"] }), "at least one path"),
            (json!({ "entry": "ir1", "exit": "local", "port": 24400 }), "forward at least one port"),
            (json!({ "entry": "ir1", "exit": "local", "port": 65530, "hop": 8, "udp": ["1"] }), "65535"),
            (json!({ "entry": "ir1", "exit": "local", "s_kind": "cdn", "s_port": 80, "udp": ["1"] }), "CDN"),
            (json!({ "entry": "ir1", "exit": "local", "port": 24400, "ftcp_port": 24400, "udp": ["24400"] }), "twice"),
            (json!({ "entry": "ir1", "exit": "local", "port": 24400, "mode": "turbo", "udp": ["1"] }), "mode"),
            (json!({ "entry": "nope", "exit": "local", "port": 24400, "udp": ["1"] }), "unknown server"),
        ] {
            let (st, v) = call(&app, "POST", "/api/vip", bad).await;
            assert_eq!(st, StatusCode::BAD_REQUEST);
            assert!(v["error"].as_str().unwrap_or("").contains(why), "{} / {}", v, why);
        }
        let (st, v) = call(&app, "POST", "/api/vip", good.clone()).await;
        assert_eq!(st, StatusCode::OK, "{}", v);
        let id = v["id"].as_str().unwrap().to_string();
        // the page never sees the secret
        let (_, l) = call(&app, "GET", "/api/vip", json!({})).await;
        assert_eq!(l["tunnels"][0]["t"]["secret"], "");
        assert_eq!(l["tunnels"][0]["t"]["name"], "Tehran-Main");
        assert!(tunnels(&app)[0].secret.len() >= 40);
        // each side its part
        let ir = specs_for(&app, "ir1");
        let ex = specs_for(&app, "local");
        assert_eq!((ir.len(), ex.len()), (1, 1));
        assert!(ir[0].entry() && !ir[0].dials && ir[0].remote.is_empty());
        assert!(!ex[0].entry() && ex[0].dials && ex[0].remote == "ir.example.com");
        assert_eq!(ir[0].secret, ex[0].secret);
        assert_eq!(ir[0].paths(), ex[0].paths());
        assert_eq!(ir[0].paths().len(), 4);
        // the Iran server opens its UDP range, the fake-TCP and web ports and the users' ports; the exit nothing
        let rules = ir[0].open_rules();
        for r in ["24400/udp", "24403/udp", "24420/tcp", "24443/tcp", "51820/udp", "8443/tcp"] {
            assert!(rules.contains(&r.to_string()), "{} in {:?}", r, rules);
        }
        assert!(!rules.contains(&"24404/udp".to_string()));
        assert!(ex[0].open_rules().is_empty());
        // the second configs follow it: UDP 51820 of the exit comes in on the Iran server
        assert_eq!(crate::tunnel::panel::port_entry(&app, "local", 51820, false), Some(("ir1".to_string(), 51820)));
        assert_eq!(crate::tunnel::panel::port_entry(&app, "local", 443, true), Some(("ir1".to_string(), 8443)));
        // a second VIP tunnel on the same ports is refused
        let (st, v) = call(&app, "POST", "/api/vip", good.clone()).await;
        assert_eq!(st, StatusCode::CONFLICT, "{}", v);
        // a Kanki tunnel that wants one of its ports too
        let (st, v) = call(&app, "POST", "/api/tunnels", json!({ "entry": "ir1", "exit": "local", "transport": "tcp", "port": 24443, "tcp": ["9000"] })).await;
        assert_eq!(st, StatusCode::CONFLICT, "{}", v);
        assert!(v["error"].as_str().unwrap().contains("VIP"), "{}", v);
        // off: nothing runs, the ports are free
        let (st, _) = call(&app, "POST", &format!("/api/vip/{}/off", id), json!({})).await;
        assert_eq!(st, StatusCode::OK);
        assert!(specs_for(&app, "ir1").is_empty() && ports_on(&app, "ir1", "").is_empty());
        // a new secret, then the server goes and takes the tunnel with it
        let old = tunnels(&app)[0].secret.clone();
        call(&app, "POST", &format!("/api/vip/{}/secret", id), json!({})).await;
        assert_ne!(tunnels(&app)[0].secret, old);
        assert!(crate::tunnel::panel::delete_server(&app, "ir1", false).is_err(), "a server with a VIP tunnel is not removed alone");
        crate::tunnel::panel::delete_server(&app, "ir1", true).unwrap();
        assert!(tunnels(&app).is_empty());
    }

    /// The VIP tunnel stays out of the way of everything else on a server, and everything else out of its way:
    /// the VPN cores' ports, KPING, Xray and the Kanki tunnels are refused to it, KPING and Xray are refused
    /// its ports, its firewall rules are its own, and the list the MTU is worked out from does not change
    #[tokio::test]
    async fn the_vip_tunnel_and_the_rest_of_the_panel_keep_apart() {
        let app = test_app();
        app.db.set("api_key", "test-key");
        app.db.set("tun_servers", &json!([{ "id": "ir1", "name": "Tehran", "token": "x", "addr": "ir.example.com", "loc": "iran", "ports": [51820, 51821, 4433, 4434] }]).to_string());
        app.db.set("kping_cfg", &json!({ "on": true, "routes": [{ "id": "r1", "exit": "local", "iran": "ir1", "port": 24300, "tunnel_port": 24301 }] }).to_string());
        let mut xs = crate::xray::panel::settings(&app);
        xs.inbounds = serde_json::from_value(json!([{ "id": "x1", "server": "ir1", "protocol": "vless", "port": 9443, "network": "tcp", "enabled": true }])).unwrap();
        app.db.set("xray_cfg", &serde_json::to_string(&xs).unwrap());
        let mtu_list = serde_json::to_string(&crate::tunnel::panel::tunnels(&app)).unwrap();
        let base = |port: u16, udp: &str, tcp: &str| json!({ "entry": "ir1", "exit": "local", "port": port, "hop": 4, "udp": [udp], "tcp": [tcp] });
        for (body, who) in [
            (base(51818, "5000", "6000"), "WireGuard"),
            (base(24298, "5000", "6000"), "KPING"),
            (base(24400, "5000", "9443"), "Xray"),
            (base(4430, "5000", "6000"), "Hysteria2"),
        ] {
            let (st, v) = call(&app, "POST", "/api/vip", body).await;
            assert_eq!(st, StatusCode::CONFLICT, "{}", v);
            assert!(v["error"].as_str().unwrap().contains(who), "{} / {}", v, who);
        }
        let (st, v) = call(&app, "POST", "/api/vip", base(24400, "5000", "6000")).await;
        assert_eq!(st, StatusCode::OK, "{}", v);
        // the others are refused its ports
        let (st, v) = call(&app, "POST", "/api/kping/routes", json!({ "id": "r1", "exit": "local", "iran": "ir1", "port": 24402, "tunnel_port": 24410 })).await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{}", v);
        assert!(v["error"].as_str().unwrap().contains("VIP"), "{}", v);
        let (st, v) = call(&app, "POST", "/api/kping/routes", json!({ "id": "r1", "exit": "local", "iran": "ir1", "port": 25000, "tunnel_port": 25001 })).await;
        assert_ne!(st, StatusCode::BAD_REQUEST, "{}", v);
        let (st, v) = call(&app, "POST", "/api/tunnels", json!({ "entry": "ir1", "exit": "local", "transport": "game", "port": 24401, "udp": ["7000"] })).await;
        assert_eq!(st, StatusCode::CONFLICT, "{}", v);
        let (st, v) = call(&app, "POST", "/api/tunnels", json!({ "entry": "ir1", "exit": "local", "transport": "tcp", "port": 23000, "tcp": ["6000"] })).await;
        assert_eq!(st, StatusCode::CONFLICT, "a forwarded port of the VIP tunnel: {}", v);
        let (st, v) = call(&app, "POST", "/api/tunnels", json!({ "entry": "ir1", "exit": "local", "transport": "tcp", "port": 23000, "tcp": ["6001"] })).await;
        assert_eq!(st, StatusCode::OK, "{}", v);
        // the list the MTU is worked out from is the Kanki tunnels only: a VIP tunnel is not in it (it cuts its
        // own packets to fit, so the cores' MTU stays what it was)
        let now_list: Vec<crate::tunnel::panel::Tunnel> = crate::tunnel::panel::tunnels(&app);
        assert!(now_list.iter().all(|t| t.kind != "vip"));
        assert_eq!(serde_json::from_str::<Vec<Value>>(&mtu_list).unwrap().len() + 1, now_list.len());
        // its firewall rules: only its own ports, under its own owner (the Kanki tunnels keep theirs)
        let ir = specs_for(&app, "ir1");
        let rules = ir[0].open_rules();
        assert_eq!(rules.len(), 4 + 2, "{:?}", rules);
        assert!(rules.iter().all(|r| ["24400/udp", "24401/udp", "24402/udp", "24403/udp", "5000/udp", "6000/tcp"].contains(&r.as_str())));
        // the Kanki tunnel's spec for the same server is the same as without the VIP tunnel
        assert!(crate::tunnel::panel::specs_of(&app, "ir1").iter().all(|s| s.port != 24400));
    }
}
