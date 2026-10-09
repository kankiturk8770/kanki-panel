//! Tunnels in the panel: tunnel servers (lightweight agents, no VPN on them), tunnels between two
//! servers, the endpoint agents talk to, and the copy of the engine that runs on the panel itself.

use super::awg::{self, AwgCfg, AwgSpec};
use super::engine::{parse_ports, Manager, Spec, Status};
use crate::api::err;
use crate::guard;
use crate::util::{self, now, rand_token};
use crate::App;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

type St = State<Arc<App>>;

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct TServer {
    pub id: String,
    pub name: String,
    pub token: String,
    /// address other servers dial (domain or IP); empty = the IP the agent was seen from
    pub addr: String,
    pub created: i64,
    /// GRE link to this server, for when only GRE passes between it and the panel: its public IPv4
    /// (empty = no GRE), the link number (the link uses 10.77.N.0/30) and an optional IPv4 of the
    /// panel server (empty = resolved from the panel address)
    pub gre_ip: String,
    pub gre_n: u8,
    pub gre_panel_ip: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct Tunnel {
    pub id: String,
    pub name: String,
    pub entry: String,
    pub exit: String,
    pub mode: String,
    pub transport: String,
    pub port: u16,
    pub conns: u32,
    pub token: String,
    pub tcp: Vec<String>,
    pub udp: Vec<String>,
    pub target: String,
    pub sni: String,
    /// cdn transport: the domain set up on the CDN (HTTP Host header)
    pub host: String,
    pub path: String,
    pub dial: String,
    /// cdn transport: split the TLS ClientHello into tiny segments
    pub frag: bool,
    pub enabled: bool,
    pub created: i64,
    /// rotating tunnel: if it stays down, switch to the next transport in `order`
    pub auto: bool,
    pub order: Vec<String>,
    /// last automatic switch (shown in the panel)
    pub switched: i64,
    pub switch_note: String,
    /// "" = a Kanki tunnel (ports through an encrypted link); "awg" = an AmneziaWG link between the
    /// two servers (a layer-3 interface); "awgwrap" is only used inside the panel for the engine
    /// tunnel that carries an AmneziaWG link's UDP
    pub kind: String,
    pub awg: AwgCfg,
}

/// Every transport a tunnel can use (the panel accepts nothing else).
pub const TRANSPORTS: &[&str] = &["tcp", "tcpmux", "ws", "wss", "quic", "kcp", "cdn", "hq", "h2", "dual"];
/// Agents older than this run `hq` / `h2` / `dual` as plain TCP (they do not know the names), so
/// a tunnel with one of them is refused while an agent is older.
const NEW_TRANSPORTS_FROM: &str = "2.9.0";

fn is_new_transport(tr: &str) -> bool {
    matches!(tr, "hq" | "h2" | "dual")
}

/// (TCP, UDP): the protocols the tunnel port of a transport occupies on the listening server.
/// `dual` listens on both, on the same port number.
fn port_protos(tr: &str) -> (bool, bool) {
    match tr {
        "quic" | "kcp" | "hq" => (false, true),
        "dual" => (true, true),
        _ => (true, false),
    }
}

/// Default rotation: `dual` first (QUIC under a mask with an HTTP/2 fallback on the same port),
/// then KCP (balanced, reverse) and the others. A tunnel that is down moves to the next one.
pub const AUTO_ORDER: &[&str] = &["dual", "kcp", "tcpmux", "quic", "ws", "wss", "tcp"];
/// a tunnel that is down this long (both servers online) moves to the next transport
const AUTO_AFTER: i64 = 45;

#[derive(Clone, Default)]
struct Seen {
    at: i64,
    version: String,
    ip: String,
    status: Vec<Status>,
}

fn seen() -> &'static Mutex<HashMap<String, Seen>> {
    static S: OnceLock<Mutex<HashMap<String, Seen>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(HashMap::new()))
}

fn load<T: for<'de> Deserialize<'de>>(app: &App, key: &str) -> Vec<T> {
    serde_json::from_str(&app.db.get(key)).unwrap_or_default()
}

fn servers(app: &App) -> Vec<TServer> {
    load(app, "tun_servers")
}

fn tunnels(app: &App) -> Vec<Tunnel> {
    load(app, "tun_list")
}

fn save_servers(app: &App, v: &[TServer]) {
    app.db.set("tun_servers", &serde_json::to_string(v).unwrap_or_else(|_| "[]".into()));
}

fn save_tunnels(app: &App, v: &[Tunnel]) {
    app.db.set("tun_list", &serde_json::to_string(v).unwrap_or_else(|_| "[]".into()));
}

fn local_name(app: &App) -> String {
    app.env.get("LOCAL_NAME").cloned().filter(|s| !s.is_empty()).unwrap_or_else(|| "Main".into())
}

/// The address other servers use to reach server `sid`.
fn host_of(app: &App, sid: &str) -> String {
    if sid == "local" {
        let a = app.db.get("tun_local_addr");
        if !a.trim().is_empty() {
            return a.trim().to_string();
        }
        return app.env.get("DOMAIN").cloned().unwrap_or_default();
    }
    let s = servers(app).into_iter().find(|s| s.id == sid);
    if let Some(s) = s {
        if !s.addr.trim().is_empty() {
            return s.addr.trim().to_string();
        }
    }
    seen().lock().unwrap().get(sid).map(|x| x.ip.clone()).unwrap_or_default()
}

fn hostport(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{}]:{}", host, port)
    } else {
        format!("{}:{}", host, port)
    }
}

/// cdn transport: the addresses the dialer connects to, comma separated. Each item is an edge IP
/// or name, with a port if written ("1.2.3.4:443"), otherwise 443. Without any address the CDN
/// domain itself is used (it resolves to the edge, but DNS can be filtered: IPs are safer).
fn cdn_remote(t: &Tunnel) -> String {
    let src = [t.dial.as_str(), t.host.as_str(), t.sni.as_str()].into_iter().find(|x| !x.trim().is_empty()).unwrap_or("");
    let mut out = vec![];
    for item in src.split(|c: char| c == ',' || c == ';' || c.is_whitespace()).map(|x| x.trim()).filter(|x| !x.is_empty()) {
        let has_port = match item.rsplit_once(':') {
            // "1.2.3.4:443", "name:443", "[::1]:443" — but not a bare IPv6 address
            Some((h, p)) => !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) && (!h.contains(':') || h.ends_with(']')),
            None => false,
        };
        out.push(if has_port { item.to_string() } else { hostport(item, 443) });
    }
    out.join(",")
}

/// The tunnels server `sid` has to run.
fn specs_for(app: &App, sid: &str) -> Vec<Spec> {
    let mut out = vec![];
    // an AmneziaWG link that travels inside a Kanki transport gets one more (engine) tunnel that
    // carries its UDP: entry 127.0.0.1:wrap_port -> exit 127.0.0.1:port
    let mut all: Vec<Tunnel> = vec![];
    for t in tunnels(app) {
        if t.kind == "awg" && t.awg.wrap {
            let mut w = t.clone();
            w.id = format!("{}~w", t.id);
            w.kind = "awgwrap".into();
            w.tcp = vec![];
            w.udp = vec![format!("{}:{}", t.awg.wrap_port, t.awg.port)];
            w.target = "127.0.0.1".into();
            w.auto = false;
            all.push(w);
        }
        all.push(t);
    }
    for t in all {
        if !t.enabled || (t.entry != sid && t.exit != sid) || t.entry == t.exit {
            continue;
        }
        let role = if t.entry == sid { "entry" } else { "exit" };
        if t.kind == "awg" {
            let a = awg_spec(app, &t, role);
            out.push(Spec { id: t.id.clone(), name: t.name.clone(), role: role.into(), transport: "awg".into(), awg: Some(a), ..Default::default() });
            continue;
        }
        let mode = if t.mode == "direct" { "direct" } else { "reverse" };
        // the side that listens is the entry in reverse mode and the exit in direct mode
        let listener = if mode == "reverse" { &t.entry } else { &t.exit };
        let host = if !t.dial.trim().is_empty() { t.dial.trim().to_string() } else { host_of(app, listener) };
        // cdn: the dialer goes to the CDN edge (port 443 unless written), not to the origin port
        let remote = if t.transport == "cdn" { cdn_remote(&t) } else { hostport(&host, t.port) };
        out.push(Spec {
            id: t.id.clone(),
            name: t.name.clone(),
            role: role.into(),
            mode: mode.into(),
            transport: t.transport.clone(),
            port: t.port,
            remote,
            token: t.token.clone(),
            conns: t.conns,
            sni: t.sni.clone(),
            host: t.host.clone(),
            frag: t.frag,
            path: t.path.clone(),
            tcp: t.tcp.clone(),
            udp: t.udp.clone(),
            target: t.target.clone(),
            cert: String::new(),
            key: String::new(),
            probe: false,
            bind: if t.kind == "awgwrap" { "127.0.0.1".into() } else { String::new() },
            awg: None,
        });
    }
    // a running smart-tunnel test adds one short-lived test tunnel per transport and per direction:
    // reverse (the exit dials the entry) on the first six ports, direct (the entry dials the exit)
    // on the next six
    if let Some(p) = probe_job().lock().unwrap().clone() {
        if !p.finished && now() - p.started < PROBE_MAX && (p.entry == sid || p.exit == sid) {
            let role = if p.entry == sid { "entry" } else { "exit" };
            for (mi, mode) in PROBE_MODES.iter().enumerate() {
                let listener = if *mode == "direct" { &p.exit } else { &p.entry };
                let host = host_of(app, listener);
                for (i, tr) in PROBE_TRANSPORTS.iter().enumerate() {
                    let port = p.port + (mi * PROBE_TRANSPORTS.len() + i) as u16;
                    out.push(Spec {
                        id: format!("probe-{}-{}-{}", p.id, mode, tr),
                        name: format!("test {} {}", mode, tr),
                        role: role.into(),
                        mode: mode.to_string(),
                        transport: tr.to_string(),
                        port,
                        remote: hostport(&host, port),
                        token: p.token.clone(),
                        conns: 2,
                        sni: String::new(),
                        host: String::new(),
                        frag: false,
                        path: "/".into(),
                        tcp: vec![],
                        udp: vec![],
                        target: String::new(),
                        cert: String::new(),
                        key: String::new(),
                        probe: true,
                        bind: String::new(),
                        awg: None,
                    });
                }
            }
        }
    }
    out
}

// ------------------------------------------------------------------ AmneziaWG link

/// what one side of an AmneziaWG tunnel runs
fn awg_spec(app: &App, t: &Tunnel, role: &str) -> AwgSpec {
    let c = &t.awg;
    let entry = role == "entry";
    let mode = if t.mode == "direct" { "direct" } else { "reverse" };
    let listener = if mode == "reverse" { &t.entry } else { &t.exit };
    let me = if entry { &t.entry } else { &t.exit };
    let (endpoint, open_udp) = if c.wrap {
        // the engine carries the UDP; the interface only talks to this machine
        (if entry { format!("127.0.0.1:{}", c.wrap_port) } else { String::new() }, 0)
    } else if me == listener {
        (String::new(), c.port)
    } else {
        let host = if !t.dial.trim().is_empty() { t.dial.trim().to_string() } else { host_of(app, listener) };
        (hostport(&host, c.port), 0)
    };
    AwgSpec {
        tid: t.id.clone(),
        iface: awg::iface_name(&t.id),
        role: role.into(),
        private: if entry { c.entry_priv.clone() } else { c.exit_priv.clone() },
        peer_pub: if entry { c.exit_pub.clone() } else { c.entry_pub.clone() },
        psk: c.psk.clone(),
        address: format!("{}/30", if entry { c.entry_ip() } else { c.exit_ip() }),
        peer_ip: if entry { c.exit_ip() } else { c.entry_ip() },
        listen: c.port,
        endpoint,
        keepalive: c.keepalive,
        mtu: c.mtu_or_default(),
        params: c.params.clone(),
        lockdown: c.wrap && c.lockdown,
        nat_exit: c.nat_exit,
        routes: if entry { c.routes.clone() } else { vec![] },
        src_routes: if entry { c.src_routes.clone() } else { vec![] },
        fwd_tcp: if entry { c.fwd_tcp.clone() } else { vec![] },
        fwd_udp: if entry { c.fwd_udp.clone() } else { vec![] },
        fwd_target: c.fwd_target.clone(),
        open_udp,
        table: 20000 + c.n as u32,
    }
}

/// a network wider than /8 sent through the link would also catch the server's own SSH / panel traffic
fn awg_wide_check(list: Vec<String>) -> Result<Vec<String>, String> {
    for c in &list {
        let bits: u8 = c.split_once('/').and_then(|x| x.1.parse().ok()).unwrap_or(32);
        if bits < 8 {
            return Err(format!("{} is too wide: it would also catch the server's own connections (SSH, the panel). Use /8 or narrower, or route by source network instead", c));
        }
    }
    Ok(list)
}

/// reads the AmneziaWG part of the form: makes keys and obfuscation numbers the first time
fn awg_apply_body(list: &[Tunnel], t: &mut Tunnel, a: &Value) -> Result<(), String> {
    let mut c = t.awg.clone();
    if c.n == 0 {
        let used: HashSet<u8> = list.iter().filter(|o| o.kind == "awg" && o.id != t.id).map(|o| o.awg.n).collect();
        c.n = (1..=250u8).find(|n| !used.contains(n)).ok_or("too many AmneziaWG tunnels")?;
    }
    if c.entry_priv.is_empty() || c.exit_priv.is_empty() || a["regen_keys"].as_bool() == Some(true) {
        let (ep, eb) = awg::gen_keypair();
        let (xp, xb) = awg::gen_keypair();
        c.entry_priv = ep;
        c.entry_pub = eb;
        c.exit_priv = xp;
        c.exit_pub = xb;
        c.psk = awg::gen_psk();
    }
    if let Some(p) = a["profile"].as_str() {
        let p = if ["classic", "heavy", "mimic"].contains(&p) { p } else { "classic" };
        if p != c.profile {
            c.profile = p.into();
            c.params.clear();
        }
    }
    if c.params.is_empty() || a["regen_params"].as_bool() == Some(true) {
        c.params = awg::gen_params(&c.profile);
    }
    if let Some(v) = a["port"].as_u64() {
        c.port = v.min(65535) as u16;
    }
    if c.port == 0 {
        return Err("the AmneziaWG port is required".into());
    }
    if let Some(v) = a["wrap"].as_bool() {
        c.wrap = v;
    }
    if let Some(v) = a["mtu"].as_u64() {
        c.mtu = if v == 0 { 0 } else { v.clamp(1000, 1500) as u16 };
    }
    if let Some(v) = a["keepalive"].as_u64() {
        c.keepalive = v.min(600) as u16;
    }
    if let Some(v) = a["lockdown"].as_bool() {
        c.lockdown = v;
    }
    if let Some(v) = a["nat_exit"].as_bool() {
        c.nat_exit = v;
    }
    if a.get("routes").is_some() {
        c.routes = awg_wide_check(awg::clean_cidrs(&clean_list(&a["routes"])))?;
    }
    if a.get("src_routes").is_some() {
        c.src_routes = awg_wide_check(awg::clean_cidrs(&clean_list(&a["src_routes"])))?;
    }
    if a.get("fwd_tcp").is_some() {
        c.fwd_tcp = clean_list(&a["fwd_tcp"]);
    }
    if a.get("fwd_udp").is_some() {
        c.fwd_udp = clean_list(&a["fwd_udp"]);
    }
    if let Some(v) = a["fwd_target"].as_str() {
        let v = v.trim();
        if !v.is_empty() && v.parse::<std::net::Ipv4Addr>().is_err() {
            return Err("the forward target must be an IPv4 address".into());
        }
        c.fwd_target = v.to_string();
    }
    if let Some(v) = a["wrap_port"].as_u64() {
        c.wrap_port = v.min(65535) as u16;
    }
    if c.wrap && c.wrap_port == 0 {
        c.wrap_port = 41000 + c.n as u16;
    }
    if c.wrap && c.wrap_port == c.port {
        return Err("the local port of the wrapper must differ from the AmneziaWG port".into());
    }
    t.auto = false;
    t.tcp = vec![];
    if c.wrap {
        if !TRANSPORTS.contains(&t.transport.as_str()) {
            t.transport = "tcpmux".into();
        }
        t.udp = vec![format!("{}:{}", c.wrap_port, c.port)];
        t.target = "127.0.0.1".into();
    } else {
        t.transport = "awg".into();
        t.port = 0;
        t.udp = vec![];
    }
    t.awg = c;
    Ok(())
}

/// `hq` / `h2` / `dual` need an agent that knows them: an older one would treat the name as plain
/// TCP and the two ends would never agree. (Agents that have not reported yet are let through.)
fn transport_checks(app: &App, t: &Tunnel) -> Result<(), String> {
    if !t.enabled || !is_new_transport(&t.transport) {
        return Ok(());
    }
    let names: HashMap<String, String> = servers(app).into_iter().map(|s| (s.id, s.name)).collect();
    let sn = seen().lock().unwrap();
    for sid in [&t.entry, &t.exit] {
        if let Some(x) = sn.get(sid.as_str()) {
            if !x.version.is_empty() && ver_lt(&x.version, NEW_TRANSPORTS_FROM) {
                return Err(format!(
                    "the agent of \"{}\" is v{}: update it first (Update all), it does not know the {} transport",
                    names.get(sid.as_str()).cloned().unwrap_or_default(),
                    x.version,
                    t.transport
                ));
            }
        }
    }
    Ok(())
}

/// agents must know AmneziaWG; the UDP ports of the link must be free on both servers
fn awg_checks(app: &App, list: &[Tunnel], t: &Tunnel) -> Result<(), String> {
    let names: HashMap<String, String> = servers(app).into_iter().map(|s| (s.id, s.name)).collect();
    if t.enabled {
        let sn = seen().lock().unwrap();
        for sid in [&t.entry, &t.exit] {
            if sid == "local" {
                continue;
            }
            if let Some(x) = sn.get(sid.as_str()) {
                if !x.version.is_empty() && ver_lt(&x.version, "2.8.0") {
                    return Err(format!("the agent of \"{}\" is v{}: update it first (Update all), it does not know AmneziaWG tunnels", names.get(sid.as_str()).cloned().unwrap_or_default(), x.version));
                }
            }
        }
    }
    for sid in [&t.entry, &t.exit] {
        let mut used: HashMap<u16, String> = HashMap::new();
        for o in list.iter().filter(|o| o.id != t.id && o.enabled) {
            let l = if o.mode == "direct" { &o.exit } else { &o.entry };
            if o.kind == "awg" {
                if o.entry == *sid || o.exit == *sid {
                    used.insert(o.awg.port, o.name.clone());
                }
                if o.awg.wrap && o.entry == *sid {
                    used.insert(o.awg.wrap_port, o.name.clone());
                }
                if o.awg.wrap && l == sid && port_protos(&o.transport).1 {
                    used.insert(o.port, o.name.clone());
                }
            } else {
                if l == sid && port_protos(&o.transport).1 {
                    used.insert(o.port, o.name.clone());
                }
                if o.entry == *sid {
                    for (a, _) in parse_ports(&o.udp) {
                        used.insert(a, o.name.clone());
                    }
                }
            }
        }
        let mut mine = vec![t.awg.port];
        if t.awg.wrap && *sid == t.entry {
            mine.push(t.awg.wrap_port);
        }
        for p in mine {
            if let Some(n) = used.get(&p) {
                return Err(format!("UDP port {} is already used by the tunnel \"{}\"", p, n));
            }
        }
    }
    Ok(())
}

/// "2.7.12" < "2.8.0"
fn ver_lt(a: &str, b: &str) -> bool {
    let p = |v: &str| -> Vec<u32> { v.trim_start_matches('v').split('.').map(|x| x.parse().unwrap_or(0)).collect() };
    p(a) < p(b)
}

async fn awg_conf(State(app): St, h: HeaderMap, Path((id, side)): Path<(String, String)>) -> Response {
    let _ = guard!(app, h, "nodes");
    let Some(t) = tunnels(&app).into_iter().find(|t| t.id == id && t.kind == "awg") else { return err(StatusCode::NOT_FOUND, "tunnel not found") };
    let role = if side == "exit" { "exit" } else { "entry" };
    let body = awg::render(&awg_spec(&app, &t, role));
    Json(json!({ "conf": body, "side": role, "file": format!("{}-{}.conf", awg::iface_name(&t.id), role) })).into_response()
}

// ------------------------------------------------------------------ smart tunnel (test every transport)

const PROBE_TRANSPORTS: &[&str] = &["tcpmux", "tcp", "ws", "wss", "quic", "kcp", "hq", "h2"];
/// both directions are measured: the side that listens differs, so the ports differ too
const PROBE_MODES: &[&str] = &["reverse", "direct"];
/// a test never runs longer than this (seconds)
const PROBE_MAX: i64 = 150;

#[derive(Clone, Default)]
struct ProbeJob {
    id: String,
    entry: String,
    exit: String,
    mode: String,
    port: u16,
    token: String,
    started: i64,
    finished: bool,
    results: Vec<Value>,
}

fn probe_job() -> &'static Mutex<Option<ProbeJob>> {
    static P: OnceLock<Mutex<Option<ProbeJob>>> = OnceLock::new();
    P.get_or_init(|| Mutex::new(None))
}

/// Score 0 to 100 for each profile. Ping, TCP speed (download 60 %, upload 40 %, 80 Mbps counts as
/// full marks) and UDP loss are weighed differently: gaming wants low ping and clean UDP, "speed"
/// wants throughput, "balanced" sits between. A transport whose UDP does not work keeps a low UDP
/// part (fine for TCP-only use); one that moved no data scores 0.
fn probe_scores(r: &Value) -> Value {
    let down = r["down_mbps"].as_f64().unwrap_or(0.0);
    let up = r["up_mbps"].as_f64().unwrap_or(0.0);
    if down <= 0.0 && up <= 0.0 {
        return json!({"gaming": 0, "balanced": 0, "speed": 0});
    }
    let ping = r["ping_ms"].as_f64().unwrap_or(500.0);
    let ping_s = (1.0 - ping / 400.0).clamp(0.0, 1.0);
    let speed_s = ((down * 0.6 + up * 0.4) / 80.0).clamp(0.0, 1.0);
    let udp_s = match r["udp_loss"].as_f64() {
        Some(l) => (1.0 - l / 100.0).clamp(0.0, 1.0).powi(2),
        None => 0.3,
    };
    let f = |wp: f64, ws: f64, wu: f64| (100.0 * (wp * ping_s + ws * speed_s + wu * udp_s)).round();
    json!({"gaming": f(0.45, 0.15, 0.40), "balanced": f(0.30, 0.40, 0.30), "speed": f(0.10, 0.70, 0.20)})
}

async fn probe_start(State(app): St, h: HeaderMap, Json(b): Json<Value>) -> Response {
    let _ = guard!(app, h, "nodes");
    let entry = b["entry"].as_str().unwrap_or("").to_string();
    let exit = b["exit"].as_str().unwrap_or("").to_string();
    let known = |id: &str| id == "local" || servers(&app).iter().any(|s| s.id == id);
    if entry.is_empty() || exit.is_empty() || entry == exit || !known(&entry) || !known(&exit) {
        return err(StatusCode::BAD_REQUEST, "pick two different servers");
    }
    let port = b["port"].as_u64().unwrap_or(3990).clamp(1024, 64000) as u16;
    // the test ports must not collide with a tunnel that already listens there (on either server)
    let span = (PROBE_TRANSPORTS.len() * PROBE_MODES.len()) as u16;
    for t in tunnels(&app) {
        let l = if t.mode == "direct" { &t.exit } else { &t.entry };
        if (*l == entry || *l == exit) && t.port >= port && t.port < port + span {
            return err(StatusCode::BAD_REQUEST, &format!("port {} is used by tunnel {}; pick another test port", t.port, t.name));
        }
    }
    let job = ProbeJob {
        id: rand_token(6).to_lowercase(),
        entry,
        exit,
        mode: "both".into(),
        port,
        token: rand_token(32),
        started: now(),
        finished: false,
        results: vec![],
    };
    let id = job.id.clone();
    *probe_job().lock().unwrap() = Some(job);
    Json(json!({"ok": true, "id": id, "transports": PROBE_TRANSPORTS, "modes": PROBE_MODES})).into_response()
}

async fn probe_get(State(app): St, h: HeaderMap) -> Response {
    let _ = guard!(app, h, "nodes");
    let mut g = probe_job().lock().unwrap();
    let Some(p) = g.as_mut() else { return Json(json!({"job": null})).into_response() };
    let t = now();
    if !p.finished {
        let seen = seen().lock().unwrap().clone();
        let entry_st = seen.get(&p.entry).map(|x| x.status.clone()).unwrap_or_default();
        let exit_st = seen.get(&p.exit).map(|x| x.status.clone()).unwrap_or_default();
        let mut all_done = true;
        let mut res = vec![];
        for (mi, mode) in PROBE_MODES.iter().enumerate() {
            for (i, tr) in PROBE_TRANSPORTS.iter().enumerate() {
                let sid = format!("probe-{}-{}-{}", p.id, mode, tr);
                let es = entry_st.iter().find(|s| s.id == sid);
                let xs = exit_st.iter().find(|s| s.id == sid);
                let mut r = es.and_then(|s| s.probe.clone()).unwrap_or_else(|| json!({"done": false, "stage": "starting"}));
                if r["done"].as_bool() != Some(true) {
                    all_done = false;
                }
                r["mode"] = json!(mode);
                r["transport"] = json!(tr);
                r["port"] = json!(p.port + (mi * PROBE_TRANSPORTS.len() + i) as u16);
                r["links"] = json!(es.map(|s| s.links).unwrap_or(0).max(xs.map(|s| s.links).unwrap_or(0)));
                if r["error"].is_null() {
                    let e = es.map(|s| s.error.clone()).filter(|e| !e.is_empty()).or_else(|| xs.map(|s| s.error.clone()).filter(|e| !e.is_empty()));
                    if let Some(e) = e {
                        r["last_error"] = json!(e);
                    }
                }
                r["scores"] = probe_scores(&r);
                res.push(r);
            }
        }
        p.results = res;
        if all_done || t - p.started >= PROBE_MAX {
            // stop the test tunnels; keep the results on screen
            p.finished = true;
        }
    }
    Json(json!({"job": {
        "id": p.id, "entry": p.entry, "exit": p.exit, "mode": p.mode, "port": p.port,
        "started": p.started, "elapsed": t - p.started, "max": PROBE_MAX, "finished": p.finished,
        "results": p.results.clone(),
    }}))
    .into_response()
}

async fn probe_stop(State(app): St, h: HeaderMap) -> Response {
    let _ = guard!(app, h, "nodes");
    if let Some(p) = probe_job().lock().unwrap().as_mut() {
        p.finished = true;
    }
    Json(json!({"ok": true})).into_response()
}

// ------------------------------------------------------------------ rotating tunnels

fn down_since() -> &'static Mutex<HashMap<String, i64>> {
    static D: OnceLock<Mutex<HashMap<String, i64>>> = OnceLock::new();
    D.get_or_init(|| Mutex::new(HashMap::new()))
}

/// For rotating tunnels: when both servers are online but the tunnel has had no link for
/// AUTO_AFTER seconds, switch to the next transport (balanced profile, reverse mode). A tunnel
/// whose server is offline is left alone: the other tunnels keep carrying the users meanwhile.
fn rotate_tick(app: &App) {
    let t = now();
    let seen = seen().lock().unwrap().clone();
    let fresh = |sid: &str| seen.get(sid).map(|x| t - x.at < 20).unwrap_or(false);
    let mut list = tunnels(app);
    let mut changed = false;
    let mut ds = down_since().lock().unwrap();
    for tu in list.iter_mut() {
        if !tu.enabled || !tu.auto || tu.transport == "cdn" {
            ds.remove(&tu.id);
            continue;
        }
        let links = |sid: &str| seen.get(sid).and_then(|x| x.status.iter().find(|s| s.id == tu.id).map(|s| s.links)).unwrap_or(0);
        let both_online = fresh(&tu.entry) && fresh(&tu.exit);
        let up = links(&tu.entry) > 0 && links(&tu.exit) > 0;
        if up || !both_online {
            ds.remove(&tu.id);
            continue;
        }
        let since = *ds.entry(tu.id.clone()).or_insert(t);
        // give a fresh switch time to connect
        if t - since < AUTO_AFTER || t - tu.switched < AUTO_AFTER {
            continue;
        }
        let order: Vec<String> = if tu.order.is_empty() { AUTO_ORDER.iter().map(|x| x.to_string()).collect() } else { tu.order.clone() };
        let pos = order.iter().position(|x| *x == tu.transport);
        let next = match pos {
            Some(i) => order[(i + 1) % order.len()].clone(),
            None => order[0].clone(),
        };
        if next == tu.transport {
            continue;
        }
        tu.switch_note = format!("{} → {}", tu.transport, next);
        tu.transport = next;
        tu.mode = "reverse".into();
        tu.conns = 4;
        tu.switched = t;
        ds.insert(tu.id.clone(), t);
        changed = true;
    }
    drop(ds);
    if changed {
        save_tunnels(app, &list);
    }
}

// ------------------------------------------------------------------ the engine on the panel server

pub async fn local_loop(app: Arc<App>) {
    let mgr = Manager::default();
    let opened = Mutex::new(HashSet::new());
    loop {
        let specs = specs_for(&app, "local");
        let ps = specs.clone();
        let set = std::mem::take(&mut *opened.lock().unwrap());
        let set = tokio::task::spawn_blocking(move || {
            let m = Mutex::new(set);
            super::agent::open_ports(&ps, &m);
            m.into_inner().unwrap_or_default()
        })
        .await
        .unwrap_or_default();
        *opened.lock().unwrap() = set;
        mgr.apply(specs).await;
        let st = mgr.statuses().await;
        seen().lock().unwrap().insert(
            "local".into(),
            Seen { at: now(), version: crate::VERSION.into(), ip: host_of(&app, "local"), status: st },
        );
        rotate_tick(&app);
        let want: Vec<(u8, String)> = servers(&app)
            .iter()
            .filter(|x| x.gre_n > 0 && x.gre_ip.parse::<std::net::Ipv4Addr>().is_ok())
            .map(|x| (x.gre_n, x.gre_ip.clone()))
            .collect();
        let _ = tokio::task::spawn_blocking(move || gre_ensure(&want)).await;
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}


/// (key, display name, ok) for every tunnel server and every tunnel that can be judged right now.
/// Used by the Telegram alerts. A tunnel is only judged when both of its servers are reporting.
pub fn health(app: &App) -> Vec<(String, String, bool)> {
    let seen = seen().lock().unwrap().clone();
    let t = now();
    let fresh = |sid: &str| sid == "local" || seen.get(sid).map(|x| t - x.at < 20).unwrap_or(false);
    let mut out = vec![];
    for sv in servers(app) {
        out.push((format!("ts:{}", sv.id), format!("سرور تانل {}", sv.name), fresh(&sv.id)));
    }
    for tu in tunnels(app) {
        if !tu.enabled || !fresh(&tu.entry) || !fresh(&tu.exit) {
            continue;
        }
        let links = |sid: &str| seen.get(sid).and_then(|x| x.status.iter().find(|q| q.id == tu.id).map(|q| q.links)).unwrap_or(0);
        out.push((format!("tu:{}", tu.id), format!("تانل {}", tu.name), links(&tu.entry) > 0 && links(&tu.exit) > 0));
    }
    out
}

/// Tries the CDN path from the panel: for every edge address (and SNI name) it connects, does the
/// TLS hello with that SNI, sends the WebSocket request with the Host header and reports whether the
/// CDN passed it to the origin. No tunnel is needed. Note: this runs on the panel server, not on the
/// entry, so it proves the CDN + origin setup; the network of the entry is proven by its tunnel.
async fn cdn_test(State(app): St, h: HeaderMap, Json(b): Json<Value>) -> Response {
    let _ = guard!(app, h, "nodes");
    let list = |k: &str| -> Vec<String> {
        b[k].as_str()
            .unwrap_or("")
            .split(|c: char| c == ',' || c.is_whitespace())
            .map(|x| x.trim().to_string())
            .filter(|x| !x.is_empty())
            .collect()
    };
    let edges: Vec<String> = list("edges")
        .into_iter()
        .map(|e| if e.contains(':') { e } else { format!("{}:443", e) })
        .collect();
    if edges.is_empty() {
        return err(StatusCode::BAD_REQUEST, "add at least one CDN edge address");
    }
    let mut snis = list("sni");
    if snis.is_empty() {
        snis.push(String::new());
    }
    let host = b["host"].as_str().unwrap_or("").trim().to_string();
    let path = b["path"].as_str().unwrap_or("/").trim().to_string();
    let frag = b["frag"].as_bool().unwrap_or(true);
    let mut tasks = vec![];
    'outer: for e in edges.iter() {
        for sni in snis.iter() {
            if tasks.len() >= 24 {
                break 'outer;
            }
            let (e, sni, host, path) = (e.clone(), sni.clone(), host.clone(), path.clone());
            tasks.push(tokio::spawn(async move {
                let t0 = std::time::Instant::now();
                let r = tokio::time::timeout(
                    Duration::from_secs(15),
                    super::link::dial("cdn", &e, &sni, &host, &path, "", frag),
                )
                .await;
                let ms = t0.elapsed().as_millis() as u64;
                match r {
                    Ok(Ok(_)) => json!({"edge": e, "sni": sni, "ok": true, "ms": ms}),
                    Ok(Err(er)) => json!({"edge": e, "sni": sni, "ok": false, "ms": ms, "error": er.to_string()}),
                    Err(_) => json!({"edge": e, "sni": sni, "ok": false, "ms": ms, "error": "timeout"}),
                }
            }));
        }
    }
    let mut out = vec![];
    for t in tasks {
        if let Ok(v) = t.await {
            out.push(v);
        }
    }
    Json(json!({"results": out})).into_response()
}

// ------------------------------------------------------------------ routes

pub fn router() -> Router<Arc<App>> {
    Router::new()
        .route("/api/tunnels", get(list).post(save))
        .route("/api/tunnels/cdntest", post(cdn_test))
        .route("/api/tunnels/probe", get(probe_get).post(probe_start).delete(probe_stop))
        .route("/api/tunnels/servers", post(server_add))
        .route("/api/tunnels/servers/:id", delete(server_del).put(server_edit))
        .route("/api/tunnels/:id", delete(tunnel_del))
        .route("/api/tunnels/:id/awgconf/:side", get(awg_conf))
        .route("/api/tunnels/:id/:action", post(tunnel_action))
        .route("/tunnel/agent", post(agent_report))
        .route("/tunnel/binary", post(agent_binary))
        .route("/api/update-all", post(update_all))
}

fn status_json(st: Option<&Status>) -> Value {
    match st {
        Some(s) => serde_json::to_value(s).unwrap_or(Value::Null),
        None => Value::Null,
    }
}

async fn list(State(app): St, h: HeaderMap) -> Response {
    let _ = guard!(app, h, "nodes");
    let seen = seen().lock().unwrap().clone();
    let t = now();
    let mut srv = vec![json!({
        "id": "local", "name": local_name(&app), "local": true, "addr": app.db.get("tun_local_addr"),
        "host": host_of(&app, "local"), "online": true, "last_seen": t, "version": crate::VERSION,
    })];
    for s in servers(&app) {
        let x = seen.get(&s.id).cloned().unwrap_or_default();
        srv.push(json!({
            "id": s.id, "name": s.name, "local": false, "addr": s.addr, "host": host_of(&app, &s.id),
            "ip": x.ip, "online": x.at > 0 && t - x.at < 20, "last_seen": x.at, "version": x.version,
            "gre_ip": s.gre_ip, "gre_n": s.gre_n, "gre_panel_ip": s.gre_panel_ip,
        }));
    }
    let mut tl = vec![];
    for tu in tunnels(&app) {
        let es = seen.get(&tu.entry).and_then(|x| x.status.iter().find(|s| s.id == tu.id).cloned());
        let xs = seen.get(&tu.exit).and_then(|x| x.status.iter().find(|s| s.id == tu.id).cloned());
        let fresh = |sid: &str| seen.get(sid).map(|x| t - x.at < 20).unwrap_or(false);
        let up = es.as_ref().map(|s| s.links > 0).unwrap_or(false) && xs.as_ref().map(|s| s.links > 0).unwrap_or(false) && fresh(tu.entry.as_str()) && fresh(tu.exit.as_str());
        let state = if !tu.enabled {
            "off"
        } else if up {
            "up"
        } else if es.as_ref().map(|s| s.links > 0).unwrap_or(false) || xs.as_ref().map(|s| s.links > 0).unwrap_or(false) {
            "partial"
        } else {
            "down"
        };
        let mut v = serde_json::to_value(&tu).unwrap_or(Value::Null);
        if tu.kind == "awg" {
            for k in ["entry_priv", "exit_priv", "psk"] {
                v["awg"][k] = json!("");
            }
            v["awg"]["entry_ip"] = json!(tu.awg.entry_ip());
            v["awg"]["exit_ip"] = json!(tu.awg.exit_ip());
            let wid = format!("{}~w", tu.id);
            let w = |sid: &str| seen.get(sid).and_then(|x| x.status.iter().find(|s| s.id == wid).cloned());
            v["wrap_entry"] = status_json(w(&tu.entry).as_ref());
            v["wrap_exit"] = status_json(w(&tu.exit).as_ref());
        }
        v["state"] = json!(state);
        v["entry_status"] = status_json(es.as_ref());
        v["exit_status"] = status_json(xs.as_ref());
        v["dial_host"] = json!(if !tu.dial.trim().is_empty() { tu.dial.clone() } else { host_of(&app, if tu.mode == "direct" { &tu.exit } else { &tu.entry }) });
        tl.push(v);
    }
    Json(json!({ "servers": srv, "tunnels": tl, "panel": crate::api::origin(&app), "repo": crate::admin::repo() })).into_response()
}

fn clean_list(v: &Value) -> Vec<String> {
    let raw: Vec<String> = match v {
        Value::Array(a) => a.iter().filter_map(|x| x.as_str().map(|s| s.to_string()).or_else(|| x.as_u64().map(|n| n.to_string()))).collect(),
        Value::String(s) => s.split(|c| c == ',' || c == ' ' || c == '\n').map(|x| x.to_string()).collect(),
        _ => vec![],
    };
    raw.into_iter().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()
}

/// Create (no id) or edit (with id) a tunnel.
async fn save(State(app): St, h: HeaderMap, Json(b): Json<Value>) -> Response {
    let _ = guard!(app, h, "nodes");
    let mut list = tunnels(&app);
    let id = b["id"].as_str().unwrap_or("").to_string();
    let mut t = if id.is_empty() {
        Tunnel { id: rand_token(10).to_lowercase(), token: rand_token(40), enabled: true, created: now(), ..Default::default() }
    } else {
        match list.iter().find(|x| x.id == id) {
            Some(x) => x.clone(),
            None => return err(StatusCode::NOT_FOUND, "tunnel not found"),
        }
    };
    let s = |k: &str| b[k].as_str().unwrap_or("").trim().to_string();
    if b.get("name").is_some() {
        t.name = s("name");
    }
    if b.get("entry").is_some() {
        t.entry = s("entry");
    }
    if b.get("exit").is_some() {
        t.exit = s("exit");
    }
    if b.get("mode").is_some() {
        t.mode = if s("mode") == "direct" { "direct".into() } else { "reverse".into() };
    }
    if b.get("transport").is_some() {
        let tr = s("transport");
        t.transport = if TRANSPORTS.contains(&tr.as_str()) { tr } else { "tcpmux".into() };
    }
    if let Some(p) = b["port"].as_u64() {
        t.port = p.min(65535) as u16;
    }
    if let Some(c) = b["conns"].as_u64() {
        t.conns = c.clamp(1, 16) as u32;
    }
    if b.get("tcp").is_some() {
        t.tcp = clean_list(&b["tcp"]);
    }
    if b.get("udp").is_some() {
        t.udp = clean_list(&b["udp"]);
    }
    for k in ["target", "sni", "path", "dial", "host"] {
        if b.get(k).is_some() {
            let v = s(k);
            match k {
                "target" => t.target = v,
                "sni" => t.sni = v,
                "path" => t.path = v,
                "host" => t.host = v,
                _ => t.dial = v,
            }
        }
    }
    if let Some(f) = b["frag"].as_bool() {
        t.frag = f;
    }
    if let Some(e) = b["enabled"].as_bool() {
        t.enabled = e;
    }
    if let Some(a) = b["auto"].as_bool() {
        t.auto = a;
    }
    if b["order"].is_array() || b["order"].is_string() {
        let o: Vec<String> = clean_list(&b["order"]).into_iter().filter(|x| AUTO_ORDER.contains(&x.as_str()) || x == "hq" || x == "h2").collect();
        t.order = o;
    }
    if t.name.is_empty() {
        t.name = format!("tunnel-{}", &t.id[..4.min(t.id.len())]);
    }
    if t.transport.is_empty() {
        t.transport = "tcpmux".into();
    }
    if t.mode.is_empty() {
        t.mode = "reverse".into();
    }
    if t.conns == 0 {
        t.conns = 4;
    }
    if t.transport == "cdn" {
        // both directions work: "direct" = the CDN points to the exit and the entry dials the CDN;
        // "reverse" = the CDN points to the entry (e.g. an Iranian CDN in front of the Iran server)
        // and the exit dials the CDN. Either way the side that dials only ever talks to the CDN.
        if t.host.trim().is_empty() && t.sni.trim().is_empty() && t.dial.trim().is_empty() {
            return err(StatusCode::BAD_REQUEST, "enter the domain you put on the CDN");
        }
        t.auto = false;
        if t.path.is_empty() {
            t.path = "/".into();
        }
    }
    if b.get("kind").is_some() {
        t.kind = if s("kind") == "awg" { "awg".into() } else { String::new() };
    }
    if t.kind == "awg" {
        if let Err(e) = awg_apply_body(&list, &mut t, &b["awg"]) {
            return err(StatusCode::BAD_REQUEST, &e);
        }
    }
    // checks
    let known: Vec<String> = std::iter::once("local".to_string()).chain(servers(&app).into_iter().map(|s| s.id)).collect();
    if !known.contains(&t.entry) || !known.contains(&t.exit) {
        return err(StatusCode::BAD_REQUEST, "choose the entry and the exit server");
    }
    if t.entry == t.exit {
        return err(StatusCode::BAD_REQUEST, "the entry and the exit must be two different servers");
    }
    if let Err(e) = transport_checks(&app, &t) {
        return err(StatusCode::CONFLICT, &e);
    }
    if t.kind == "awg" {
        if let Err(e) = awg_checks(&app, &list, &t) {
            return err(StatusCode::CONFLICT, &e);
        }
        if !t.awg.wrap {
            if let Some(x) = list.iter_mut().find(|x| x.id == t.id) {
                *x = t.clone();
            } else {
                list.push(t.clone());
            }
            save_tunnels(&app, &list);
            return Json(json!({ "ok": true, "id": t.id })).into_response();
        }
    }
    if t.port == 0 {
        return err(StatusCode::BAD_REQUEST, "the tunnel port is required");
    }
    if parse_ports(&t.tcp).is_empty() && parse_ports(&t.udp).is_empty() {
        return err(StatusCode::BAD_REQUEST, "add at least one TCP or UDP port to forward");
    }
    // Ports each server must listen on, per protocol: the tunnel port on the listening side
    // (UDP for quic / kcp / hq, TCP for the rest, both for dual) and the forwarded ports on the entry. Two enabled
    // tunnels may not need the same port of the same protocol on the same server.
    let listener = if t.mode == "direct" { t.exit.clone() } else { t.entry.clone() };
    let mine_tcp: Vec<u16> = parse_ports(&t.tcp).into_iter().map(|p| p.0).collect();
    let mine_udp: Vec<u16> = parse_ports(&t.udp).into_iter().map(|p| p.0).collect();
    let my_pr = port_protos(&t.transport);
    // does a tunnel port (of a transport with these protocols) hit one of these forwarded ports?
    let hits = |pr: (bool, bool), port: u16, tcp: &[u16], udp: &[u16]| (pr.0 && tcp.contains(&port)) || (pr.1 && udp.contains(&port));
    if listener == t.entry {
        if my_pr.0 && mine_tcp.contains(&t.port) {
            return err(StatusCode::BAD_REQUEST, "the tunnel port is also in the forwarded TCP ports");
        }
        if my_pr.1 && mine_udp.contains(&t.port) {
            return err(StatusCode::BAD_REQUEST, "the tunnel port is also in the forwarded UDP ports");
        }
    }
    for o in list.iter().filter(|o| o.id != t.id && o.enabled && !(o.kind == "awg" && !o.awg.wrap)) {
        let o_listener: String = if o.mode == "direct" { o.exit.clone() } else { o.entry.clone() };
        let o_pr = port_protos(&o.transport);
        let o_tcp: Vec<u16> = parse_ports(&o.tcp).into_iter().map(|p| p.0).collect();
        let o_udp: Vec<u16> = parse_ports(&o.udp).into_iter().map(|p| p.0).collect();
        // tunnel port against the tunnel port of the other one (a protocol both use)
        if o_listener == listener && ((my_pr.0 && o_pr.0) || (my_pr.1 && o_pr.1)) && o.port == t.port {
            return err(StatusCode::CONFLICT, &format!("port {} is already used by the tunnel \"{}\"", t.port, o.name));
        }
        // my tunnel port against the ports the other one opens on its entry
        if o.entry == listener && hits(my_pr, t.port, &o_tcp, &o_udp) {
            return err(StatusCode::CONFLICT, &format!("port {} is already used by the tunnel \"{}\"", t.port, o.name));
        }
        // the tunnel port of the other one against the ports I open on my entry
        if t.entry == o_listener && hits(o_pr, o.port, &mine_tcp, &mine_udp) {
            return err(StatusCode::CONFLICT, &format!("port {} is already used by the tunnel \"{}\"", o.port, o.name));
        }
        // forwarded ports against forwarded ports on the same entry
        if o.entry == t.entry {
            if let Some(p) = mine_tcp.iter().find(|p| o_tcp.contains(p)) {
                return err(StatusCode::CONFLICT, &format!("TCP port {} is already used by the tunnel \"{}\"", p, o.name));
            }
            if let Some(p) = mine_udp.iter().find(|p| o_udp.contains(p)) {
                return err(StatusCode::CONFLICT, &format!("UDP port {} is already used by the tunnel \"{}\"", p, o.name));
            }
        }
    }
    if let Some(x) = list.iter_mut().find(|x| x.id == t.id) {
        *x = t.clone();
    } else {
        list.push(t.clone());
    }
    save_tunnels(&app, &list);
    Json(json!({ "ok": true, "id": t.id })).into_response()
}

async fn tunnel_del(State(app): St, h: HeaderMap, Path(id): Path<String>) -> Response {
    let _ = guard!(app, h, "nodes");
    let mut list = tunnels(&app);
    let n = list.len();
    list.retain(|t| t.id != id);
    if list.len() == n {
        return err(StatusCode::NOT_FOUND, "tunnel not found");
    }
    save_tunnels(&app, &list);
    Json(json!({ "ok": true })).into_response()
}

async fn tunnel_action(State(app): St, h: HeaderMap, Path((id, action)): Path<(String, String)>) -> Response {
    let _ = guard!(app, h, "nodes");
    let mut list = tunnels(&app);
    let Some(t) = list.iter_mut().find(|t| t.id == id) else { return err(StatusCode::NOT_FOUND, "tunnel not found") };
    match action.as_str() {
        "enable" => t.enabled = true,
        "disable" => t.enabled = false,
        // a new token makes both sides drop their links and make new ones
        "restart" | "rekey" => {
            t.token = rand_token(40);
            // a new pre-shared key makes both ends bring the AmneziaWG interface down and up again
            if t.kind == "awg" {
                t.awg.psk = awg::gen_psk();
            }
        }
        // AmneziaWG: new obfuscation numbers / new keys, sent to both sides at once
        "awg-params" if t.kind == "awg" => t.awg.params = awg::gen_params(&t.awg.profile),
        "awg-keys" if t.kind == "awg" => {
            let (ep, eb) = awg::gen_keypair();
            let (xp, xb) = awg::gen_keypair();
            t.awg.entry_priv = ep;
            t.awg.entry_pub = eb;
            t.awg.exit_priv = xp;
            t.awg.exit_pub = xb;
            t.awg.psk = awg::gen_psk();
        }
        _ => return err(StatusCode::BAD_REQUEST, "unknown action"),
    }
    save_tunnels(&app, &list);
    Json(json!({ "ok": true })).into_response()
}

// ------------------------------------------------------------------ GRE link to a tunnel server

fn gre_applied() -> &'static Mutex<HashMap<u8, String>> {
    static G: OnceLock<Mutex<HashMap<u8, String>>> = OnceLock::new();
    G.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Makes the panel side of every GRE link exist: interface kgreN, address 10.77.N.1/30. Links that
/// are no longer wanted are removed. Safe to call every few seconds; it only acts on a difference.
fn gre_ensure(want: &[(u8, String)]) {
    use std::process::Command;
    let run = |args: &[&str]| Command::new("ip").args(args).output().map(|o| o.status.success()).unwrap_or(false);
    let existing: Vec<String> = match Command::new("ip").args(["-o", "link", "show"]).output() {
        Ok(o) => String::from_utf8_lossy(&o.stdout)
            .lines()
            .filter_map(|l| {
                let name = l.split_whitespace().nth(1)?.trim_end_matches(':');
                Some(name.split('@').next().unwrap_or(name).to_string())
            })
            .filter(|n| n.starts_with("kgre"))
            .collect(),
        Err(_) => return,
    };
    if existing.is_empty() && want.is_empty() {
        return;
    }
    let mut ap = gre_applied().lock().unwrap();
    for name in &existing {
        if !want.iter().any(|(n, _)| format!("kgre{}", n) == *name) {
            run(&["link", "del", name.as_str()]);
        }
    }
    ap.retain(|n, _| want.iter().any(|(w, _)| w == n));
    for (n, remote) in want {
        let name = format!("kgre{}", n);
        let exists = existing.contains(&name);
        if exists && ap.get(n).map(|r| r == remote).unwrap_or(false) {
            continue;
        }
        if exists {
            run(&["link", "del", name.as_str()]);
        }
        let addr = format!("10.77.{}.1/30", n);
        let ok = run(&["tunnel", "add", name.as_str(), "mode", "gre", "remote", remote.as_str(), "ttl", "255"])
            && run(&["addr", "add", addr.as_str(), "dev", name.as_str()])
            && run(&["link", "set", name.as_str(), "mtu", "1400", "up"]);
        if ok {
            // best effort: let the GRE packets of that server through ufw
            let _ = Command::new("ufw").args(["allow", "from", remote.as_str(), "proto", "gre"]).output();
            ap.insert(*n, remote.clone());
        }
    }
}

/// IPv4 of the panel server, as the other end of a GRE link must dial it
async fn panel_ipv4(app: &App, over: &str) -> String {
    if over.parse::<std::net::Ipv4Addr>().is_ok() {
        return over.to_string();
    }
    let origin = crate::api::origin(app);
    let host = origin.trim_start_matches("https://").trim_start_matches("http://").split('/').next().unwrap_or("").to_string();
    let name = host.split(':').next().unwrap_or("").to_string();
    if name.parse::<std::net::Ipv4Addr>().is_ok() {
        return name;
    }
    let resolved = match tokio::net::lookup_host((name.as_str(), 443)).await {
        Ok(it) => it
            .filter_map(|a| match a {
                std::net::SocketAddr::V4(v) => Some(v.ip().to_string()),
                _ => None,
            })
            .next()
            .unwrap_or_default(),
        Err(_) => String::new(),
    };
    resolved
}

/// What the page needs to build the other end of the GRE link (null when the server has none)
async fn gre_info(app: &App, s: &TServer) -> Value {
    if s.gre_n == 0 || s.gre_ip.is_empty() {
        return Value::Null;
    }
    let origin = crate::api::origin(app);
    let host = origin.trim_start_matches("https://").trim_start_matches("http://").split('/').next().unwrap_or("").to_string();
    let (name, port) = match host.split_once(':') {
        Some((a, b)) => (a.to_string(), b.to_string()),
        None => (host.clone(), String::new()),
    };
    let is_ip = name.parse::<std::net::Ipv4Addr>().is_ok();
    let panel_ip = panel_ipv4(app, &s.gre_panel_ip).await;
    json!({ "n": s.gre_n, "ip": s.gre_ip, "panel_ip": panel_ip, "domain": name, "port": port, "is_ip": is_ip })
}

/// Applies the GRE fields of a request to a server. A missing key leaves the link as it is; an empty
/// gre_ip turns it off. Returns an error text for an address that is not an IPv4.
fn gre_apply_body(list: &mut Vec<TServer>, id: &str, b: &Value) -> Result<(), String> {
    let used: Vec<u8> = list.iter().filter(|x| x.id != id).map(|x| x.gre_n).collect();
    let Some(s) = list.iter_mut().find(|x| x.id == id) else { return Ok(()) };
    if let Some(v) = b["gre_ip"].as_str() {
        let v = v.trim();
        if v.is_empty() {
            s.gre_ip.clear();
            s.gre_n = 0;
            s.gre_panel_ip.clear();
        } else {
            if v.parse::<std::net::Ipv4Addr>().is_err() {
                return Err("the GRE address must be an IPv4 address like 1.2.3.4".into());
            }
            s.gre_ip = v.to_string();
            if s.gre_n == 0 {
                s.gre_n = (1..=250u8).find(|n| !used.contains(n)).unwrap_or(1);
            }
        }
    }
    if let Some(v) = b["gre_panel_ip"].as_str() {
        let v = v.trim();
        if !v.is_empty() && v.parse::<std::net::Ipv4Addr>().is_err() {
            return Err("the panel IP must be an IPv4 address like 1.2.3.4".into());
        }
        s.gre_panel_ip = v.to_string();
    }
    Ok(())
}

async fn server_add(State(app): St, h: HeaderMap, Json(b): Json<Value>) -> Response {
    let _ = guard!(app, h, "nodes");
    let mut list = servers(&app);
    let name = b["name"].as_str().unwrap_or("").trim().to_string();
    let s = TServer {
        id: format!("t{}", rand_token(7).to_lowercase()),
        name: if name.is_empty() { format!("server-{}", list.len() + 1) } else { name },
        token: rand_token(40),
        addr: b["addr"].as_str().unwrap_or("").trim().to_string(),
        created: now(),
        ..Default::default()
    };
    list.push(s.clone());
    if let Err(e) = gre_apply_body(&mut list, &s.id, &b) {
        return err(StatusCode::BAD_REQUEST, &e);
    }
    save_servers(&app, &list);
    let s = list.iter().find(|x| x.id == s.id).cloned().unwrap_or(s);
    let gre = gre_info(&app, &s).await;
    Json(json!({ "ok": true, "id": s.id, "token": s.token, "name": s.name, "panel": crate::api::origin(&app), "repo": crate::admin::repo(), "gre": gre })).into_response()
}

async fn server_edit(State(app): St, h: HeaderMap, Path(id): Path<String>, Json(b): Json<Value>) -> Response {
    let _ = guard!(app, h, "nodes");
    if id == "local" {
        if let Some(a) = b["addr"].as_str() {
            app.db.set("tun_local_addr", a.trim());
        }
        return Json(json!({ "ok": true })).into_response();
    }
    let mut list = servers(&app);
    let Some(s) = list.iter_mut().find(|s| s.id == id) else { return err(StatusCode::NOT_FOUND, "server not found") };
    if let Some(n) = b["name"].as_str() {
        if !n.trim().is_empty() {
            s.name = n.trim().to_string();
        }
    }
    if let Some(a) = b["addr"].as_str() {
        s.addr = a.trim().to_string();
    }
    let token = if b["new_token"].as_bool().unwrap_or(false) {
        s.token = rand_token(40);
        Some(s.token.clone())
    } else {
        None
    };
    if let Err(e) = gre_apply_body(&mut list, &id, &b) {
        return err(StatusCode::BAD_REQUEST, &e);
    }
    save_servers(&app, &list);
    let cur = list.iter().find(|x| x.id == id).cloned().unwrap_or_default();
    let gre = gre_info(&app, &cur).await;
    Json(json!({ "ok": true, "token": token, "panel": crate::api::origin(&app), "repo": crate::admin::repo(), "gre": gre })).into_response()
}

async fn server_del(State(app): St, h: HeaderMap, Path(id): Path<String>) -> Response {
    let _ = guard!(app, h, "nodes");
    if id == "local" {
        return err(StatusCode::BAD_REQUEST, "the panel server cannot be removed");
    }
    let used: Vec<String> = tunnels(&app).into_iter().filter(|t| t.entry == id || t.exit == id).map(|t| t.name).collect();
    if !used.is_empty() {
        return err(StatusCode::CONFLICT, &format!("delete its tunnels first: {}", used.join(", ")));
    }
    let mut list = servers(&app);
    list.retain(|s| s.id != id);
    save_servers(&app, &list);
    seen().lock().unwrap().remove(&id);
    Json(json!({ "ok": true })).into_response()
}

/// Public: a tunnel agent reports its tunnels and gets the list it should run.
async fn agent_report(State(app): St, h: HeaderMap, Json(b): Json<Value>) -> Response {
    let id = b["id"].as_str().unwrap_or("").to_string();
    let token = b["token"].as_str().unwrap_or("").to_string();
    let Some(s) = servers(&app).into_iter().find(|s| s.id == id) else {
        // unknown or removed: the agent stops its tunnels
        return (StatusCode::GONE, "this server is not in the panel any more").into_response();
    };
    if token.is_empty() || !util::ct_eq(&token, &s.token) {
        return err(StatusCode::FORBIDDEN, "wrong token");
    }
    let status: Vec<Status> = serde_json::from_value(b["status"].clone()).unwrap_or_default();
    let ip = util::client_ip(&h);
    seen().lock().unwrap().insert(
        id.clone(),
        Seen { at: now(), version: b["version"].as_str().unwrap_or("").to_string(), ip, status },
    );
    let ver = b["version"].as_str().unwrap_or("");
    let until = app.db.get("tun_update_until").parse::<i64>().unwrap_or(0);
    let update = now() < until && !ver.is_empty() && ver != crate::VERSION;
    Json(json!({ "tunnels": specs_for(&app, &id), "update": update })).into_response()
}

/// The panel's own binary for a tunnel agent that was asked to update (same file everywhere)
async fn agent_binary(State(app): St, Json(b): Json<Value>) -> Response {
    let id = b["id"].as_str().unwrap_or("").to_string();
    let token = b["token"].as_str().unwrap_or("").to_string();
    let Some(s) = servers(&app).into_iter().find(|s| s.id == id) else {
        return (StatusCode::GONE, "unknown server").into_response();
    };
    if token.is_empty() || !util::ct_eq(&token, &s.token) {
        return err(StatusCode::FORBIDDEN, "wrong token");
    }
    if now() >= app.db.get("tun_update_until").parse::<i64>().unwrap_or(0) {
        return err(StatusCode::CONFLICT, "no update was requested");
    }
    if b["arch"].as_str().unwrap_or("") != std::env::consts::ARCH {
        return err(StatusCode::CONFLICT, "this server has a different CPU type than the panel; update it by hand");
    }
    let Ok(path) = std::env::current_exe() else { return err(StatusCode::INTERNAL_SERVER_ERROR, "no binary") };
    let Ok(bytes) = std::fs::read(&path) else { return err(StatusCode::INTERNAL_SERVER_ERROR, "cannot read the binary") };
    let sum = {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(&bytes);
        hex::encode(h.finalize())
    };
    (StatusCode::OK, [("x-sha256", sum)], bytes).into_response()
}

/// One click: updates every node, asks every tunnel-only server to update from the panel, then the
/// panel itself. A machine that is both a node and a tunnel server is updated once (through its node).
async fn update_all(State(app): St, h: HeaderMap) -> Response {
    let _ = guard!(app, h, "admin");
    let latest = crate::admin::latest_version(&app).await.unwrap_or_default();
    let target = if latest.is_empty() { crate::VERSION.to_string() } else { latest.clone() };
    let panel_old = !latest.is_empty() && crate::admin::newer(&latest, crate::VERSION);
    let seen_now = seen().lock().unwrap().clone();
    let srv = servers(&app);
    let mut covered: HashSet<String> = HashSet::new();
    let mut jobs = vec![];
    for n in app.db.nodes().into_iter().filter(|n| n.id != "local" && n.enabled) {
        let host = n
            .address
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .split(|c| c == '/' || c == ':')
            .next()
            .unwrap_or("")
            .to_lowercase();
        let ips: Vec<String> = match tokio::net::lookup_host((host.as_str(), 443u16)).await {
            Ok(it) => it.map(|a| a.ip().to_string()).collect(),
            Err(_) => vec![],
        };
        for s in srv.iter() {
            let ip = seen_now.get(&s.id).map(|x| x.ip.clone()).unwrap_or_default();
            if s.addr.trim().to_lowercase() == host || (!ip.is_empty() && ips.contains(&ip)) {
                covered.insert(s.id.clone());
            }
        }
        let cur = serde_json::from_str::<Value>(&n.info).ok().and_then(|v| v["version"].as_str().map(|x| x.to_string())).unwrap_or_default();
        if !cur.is_empty() && cur == target {
            continue;
        }
        let a = app.clone();
        jobs.push(tokio::spawn(async move {
            let r = crate::sync::remote_post(&a, &n, "/agent/update").await;
            let ok = r.as_ref().map(|v| v["ok"].as_bool().unwrap_or(false)).unwrap_or(false);
            let e = r.as_ref().and_then(|v| v["error"].as_str().map(|x| x.to_string())).unwrap_or_default();
            json!({ "name": n.name, "ok": ok, "error": e })
        }));
    }
    // tunnel-only servers: agents from v2.7.0 on update themselves from the panel; older ones need the command once
    let mut flagged: Vec<String> = vec![];
    let mut manual: Vec<String> = vec![];
    for s in srv.iter().filter(|s| !covered.contains(&s.id)) {
        let Some(x) = seen_now.get(&s.id) else { continue };
        if now() - x.at >= 20 || x.version.is_empty() || x.version == target {
            continue;
        }
        // the agent code that updates itself from the panel exists since 2.7.0
        if crate::admin::newer("2.7.0", &x.version) {
            manual.push(s.name.clone());
        } else {
            flagged.push(s.name.clone());
        }
    }
    if !flagged.is_empty() {
        app.db.set("tun_update_until", &(now() + 900).to_string());
    }
    let mut nodes_out = vec![];
    for j in jobs {
        if let Ok(v) = j.await {
            nodes_out.push(v);
        }
    }
    let mut panel_msg = json!("current");
    if panel_old {
        panel_msg = match crate::admin::self_update(&app).await {
            Ok(v) => json!(format!("updating to {}", v)),
            Err(e) => json!(format!("failed: {}", e)),
        };
    }
    let covered_names: Vec<String> = srv.iter().filter(|s| covered.contains(&s.id)).map(|s| s.name.clone()).collect();
    Json(json!({ "ok": true, "latest": latest, "panel": panel_msg, "nodes": nodes_out, "agents": flagged, "manual": manual, "also_nodes": covered_names })).into_response()
}
