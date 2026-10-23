//! Tunnels in the panel: tunnel servers (lightweight agents, no VPN on them), tunnels between two
//! servers, the endpoint agents talk to, and the copy of the engine that runs on the panel itself.

use super::awg::{self, AwgCfg, AwgSpec};
use super::hy2t::{self, Hy2Cfg, Hy2Spec};
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
    /// "iran" | "abroad" ("" = not set yet: guessed from what the server does)
    pub loc: String,
    /// the VPN node of the same machine ("" = none, or not found yet): one server in the panel
    pub node: String,
    /// one-time token the VPN part of this machine joins with ("" = none pending) and when it ends
    pub join: String,
    pub join_exp: i64,
    /// the VPN serves users once it joins (off for a relay that only carries tunnels)
    pub vpn: bool,
    /// UDP ports the VPN part is to use, unique among all servers: [WireGuard, AmneziaWG, Hysteria2, KANKI MIX]
    pub ports: Vec<u16>,
    /// domain of the machine (for a real certificate of its VPN part; "" = self-signed)
    pub domain: String,
    /// when the panel asked the agent to install the VPN part (0 = not asked)
    pub setup_at: i64,
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
    /// kind "hy2": a Hysteria2 link (the exit runs the server, the entry the client)
    pub hy2: Hy2Cfg,
    /// game transport: FEC "data:parity" ("8:3"; "off" disables) and packet duplication
    pub fec: String,
    pub dup: bool,
}

/// Every transport a tunnel can use (the panel accepts nothing else).
pub const TRANSPORTS: &[&str] = &["tcp", "tcpmux", "ws", "wss", "quic", "kcp", "cdn", "hq", "h2", "dual", "game", "faketcp"];
/// Agents older than this run `hq` / `h2` / `dual` as plain TCP (they do not know the names), so
/// a tunnel with one of them is refused while an agent is older.
const NEW_TRANSPORTS_FROM: &str = "2.9.0";
/// `game` and `faketcp` exist from this agent version on.
const GAME_TRANSPORTS_FROM: &str = "3.5.3";

fn is_new_transport(tr: &str) -> bool {
    matches!(tr, "hq" | "h2" | "dual" | "game" | "faketcp")
}

/// the agent version a transport needs
fn transport_min_version(tr: &str) -> &'static str {
    if matches!(tr, "game" | "faketcp") {
        GAME_TRANSPORTS_FROM
    } else {
        NEW_TRANSPORTS_FROM
    }
}

/// whether an agent of version `ver` knows transport `tr` (an unknown version is let through)
fn agent_knows(ver: &str, tr: &str) -> bool {
    !is_new_transport(tr) || ver.is_empty() || !ver_lt(ver, transport_min_version(tr))
}

/// (TCP, UDP): the protocols the tunnel port of a transport occupies on the listening server.
/// `dual` listens on both, on the same port number.
fn port_protos(tr: &str) -> (bool, bool) {
    match tr {
        "quic" | "kcp" | "hq" | "hy2" | "game" => (false, true),
        "dual" => (true, true),
        // faketcp carries UDP inside fake TCP packets: the port is a TCP port on the wire
        "faketcp" => (true, false),
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
    /// the emergency chat on this server (Null when it does not run one)
    emergency: Value,
    /// the firewall ports Kanki opened here, and the open ones nothing uses (see `fw::report`)
    fw: Value,
    /// every port listened on from outside: [[port, udp, program, unit], ...] (Null = older agent)
    listen: Value,
    /// the VPN install the panel asked for: {state, code, tail} (Null = none)
    setup: Value,
}

fn seen() -> &'static Mutex<HashMap<String, Seen>> {
    static S: OnceLock<Mutex<HashMap<String, Seen>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(HashMap::new()))
}

fn load<T: for<'de> Deserialize<'de>>(app: &App, key: &str) -> Vec<T> {
    serde_json::from_str(&app.db.get(key)).unwrap_or_default()
}

pub(crate) fn servers(app: &App) -> Vec<TServer> {
    load(app, "tun_servers")
}

pub(crate) fn tunnels(app: &App) -> Vec<Tunnel> {
    load(app, "tun_list")
}

pub(crate) fn save_servers(app: &App, v: &[TServer]) {
    app.db.set("tun_servers", &serde_json::to_string(v).unwrap_or_else(|_| "[]".into()));
}

pub(crate) fn save_tunnels(app: &App, v: &[Tunnel]) {
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
        if t.kind == "hy2" {
            let y = hy2_spec(app, &t, role);
            out.push(Spec { id: t.id.clone(), name: t.name.clone(), role: role.into(), transport: "hy2".into(), hy2: Some(y), ..Default::default() });
            continue;
        }
        let mode = if t.mode == "direct" { "direct" } else { "reverse" };
        // the side that listens is the entry in reverse mode and the exit in direct mode
        let listener = if mode == "reverse" { &t.entry } else { &t.exit };
        let listens = sid == listener;
        // only the dialer uses `remote`. Giving the listener a `remote` (which it never dials) let a
        // change in the peer's seen address restart its listener for nothing -> the 4-5 s flap.
        let remote = if listens {
            String::new()
        } else {
            let host = if !t.dial.trim().is_empty() { t.dial.trim().to_string() } else { host_of(app, listener) };
            // cdn: the dialer goes to the CDN edge (port 443 unless written), not to the origin port
            if t.transport == "cdn" { cdn_remote(&t) } else { hostport(&host, t.port) }
        };
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
            hy2: None,
            fec: t.fec.clone(),
            dup: t.dup,
        });
    }
    // a running smart-tunnel test adds one short-lived test tunnel per transport and per direction:
    // reverse (the exit dials the entry) on the first six ports, direct (the entry dials the exit)
    // on the next six
    if let Some(p) = probe_job().lock().unwrap().clone() {
        if !p.finished && now() - p.started < PROBE_MAX && (p.entry == sid || p.exit == sid) {
            let role = if p.entry == sid { "entry" } else { "exit" };
            // the raw ping has no tunnel: only the entry acts, pinging the exit host directly
            if p.baseline && p.entry == sid {
                out.push(Spec {
                    id: format!("probe-{}-baseline", p.id),
                    name: "baseline ping".into(),
                    role: "entry".into(),
                    mode: "direct".into(),
                    transport: "baseline".into(),
                    port: 0,
                    remote: host_of(app, &p.exit),
                    token: p.token.clone(),
                    conns: 1,
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
                    hy2: None,
                    fec: String::new(),
                    dup: false,
                });
            }
            for (mi, mode) in PROBE_MODES.iter().enumerate() {
                let listener = if *mode == "direct" { &p.exit } else { &p.entry };
                let host = host_of(app, listener);
                for (i, tr) in p.transports.iter().enumerate() {
                    let port = p.port + (mi * p.transports.len() + i) as u16;
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
                        hy2: None,
                        fec: String::new(),
                        dup: false,
                    });
                }
            }
        }
    }
    // Kanki DNS: the tunnel from a relay inside Iran to its exit abroad
    out.extend(crate::dns::panel::relay_specs(app, sid));
    // the subscription on an Iran server: the tunnel from there to the panel
    out.extend(crate::subiran::specs(app, sid));
    out
}

/// What the panel last heard from agent `sid`: (when, version, address, VPN install state).
pub(crate) fn agent_state(sid: &str) -> Option<(i64, String, String, Value)> {
    seen().lock().unwrap().get(sid).map(|x| (x.at, x.version.clone(), x.ip.clone(), x.setup.clone()))
}

/// The tunnels server `sid` runs (for the port checks of other features).
pub(crate) fn specs_of(app: &App, sid: &str) -> Vec<Spec> {
    specs_for(app, sid)
}

/// The admin's tunnels.
pub(crate) fn kanki_tunnels(app: &App) -> Vec<Tunnel> {
    tunnels(app)
}

/// Open links of tunnel `id` on server `sid` at its last report.
pub(crate) fn links_of(sid: &str, id: &str) -> usize {
    seen().lock().unwrap().get(sid).and_then(|x| x.status.iter().find(|s| s.id == id).map(|s| s.links)).unwrap_or(0)
}

/// The address an agent server last reported from (DNS answers it for routed names).
pub(crate) fn seen_ip(sid: &str) -> Option<String> {
    seen().lock().unwrap().get(sid).map(|x| x.ip.clone()).filter(|x| !x.is_empty())
}

/// "host:port" other servers dial server `sid` on.
pub(crate) fn dial_addr(app: &App, sid: &str, port: u16) -> String {
    hostport(&host_of(app, sid), port)
}

/// "iran" or "abroad" when written, else "".
fn clean_loc(v: &str) -> String {
    if v == "iran" || v == "abroad" { v.to_string() } else { String::new() }
}

/// Where a server whose location is not set probably is, from what it does: a DNS relay, the emergency
/// chat, the Iran subscription and a tunnel entry are inside Iran; a DNS exit or a tunnel exit is abroad.
pub(crate) fn guess_loc(sid: &str, list: &[Tunnel], dns_role: &str, iran_jobs: bool) -> String {
    if dns_role == "relay" || iran_jobs || list.iter().any(|t| t.entry == sid && t.exit != sid) {
        "iran".into()
    } else if dns_role == "exit" || list.iter().any(|t| t.exit == sid) {
        "abroad".into()
    } else {
        String::new()
    }
}

/// id -> (location, guessed) of every server, the panel's own ("local") included.
pub(crate) fn server_locs(app: &App) -> HashMap<String, (String, bool)> {
    let list = tunnels(app);
    let dns = crate::dns::panel::settings(app);
    let mut m = HashMap::new();
    let local = clean_loc(&app.db.get("tun_local_loc"));
    m.insert("local".to_string(), if local.is_empty() { ("abroad".to_string(), true) } else { (local, false) });
    for s in servers(app) {
        let set = clean_loc(&s.loc);
        if !set.is_empty() {
            m.insert(s.id, (set, false));
            continue;
        }
        let role = dns.servers.iter().find(|x| x.server == s.id).map(|x| x.role.clone()).unwrap_or_default();
        let jobs = app.db.get("emer_server") == s.id || crate::subiran::settings(app).server == s.id;
        m.insert(s.id.clone(), (guess_loc(&s.id, &list, &role, jobs), true));
    }
    // a server's IP country beats a guess (an Iran IP = Iran server, any other = abroad)
    let ccs = crate::exitgeo::all_cc(app);
    for (id, v) in m.iter_mut() {
        if v.1 {
            if let Some(c) = ccs.get(&crate::exitgeo::srv_key(id)).filter(|c| c.len() == 2) {
                *v = (if c == "IR" { "iran".into() } else { "abroad".into() }, false);
            }
        }
    }
    m
}

/// id -> name of every agent server.
pub(crate) fn server_names(app: &App) -> HashMap<String, String> {
    servers(app).into_iter().map(|s| (s.id, s.name)).collect()
}

/// The address to remember for a node: keep the real one we already have when a new report arrives
/// with no usable source IP (empty or loopback), so a node's tunnels are not restarted for nothing.
fn sticky_ip(prev: &str, fresh: &str) -> String {
    let bogus = fresh.is_empty() || fresh == "127.0.0.1";
    let good_prev = !prev.is_empty() && prev != "127.0.0.1";
    if bogus && good_prev { prev.to_string() } else { fresh.to_string() }
}

#[cfg(test)]
mod flap_tests {
    use super::sticky_ip;

    #[test]
    fn keeps_a_real_address_through_a_bogus_report() {
        // first real report sets it
        assert_eq!(sticky_ip("", "5.5.5.5"), "5.5.5.5");
        // a report with no X-Forwarded-For (-> 127.0.0.1) must NOT overwrite the real one
        assert_eq!(sticky_ip("5.5.5.5", "127.0.0.1"), "5.5.5.5");
        assert_eq!(sticky_ip("5.5.5.5", ""), "5.5.5.5");
        // a genuinely new real address is taken
        assert_eq!(sticky_ip("5.5.5.5", "6.6.6.6"), "6.6.6.6");
        // with nothing good yet, use whatever came (even loopback, for a truly local node)
        assert_eq!(sticky_ip("", "127.0.0.1"), "127.0.0.1");
        assert_eq!(sticky_ip("127.0.0.1", "6.6.6.6"), "6.6.6.6");
    }
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
/// The rotation `order` is checked too: the tunnel may switch to any of its entries.
fn transport_checks(app: &App, t: &Tunnel) -> Result<(), String> {
    if !t.enabled || !std::iter::once(&t.transport).chain(t.order.iter()).any(|tr| is_new_transport(tr)) {
        return Ok(());
    }
    let names: HashMap<String, String> = servers(app).into_iter().map(|s| (s.id, s.name)).collect();
    let sn = seen().lock().unwrap();
    for tr in std::iter::once(&t.transport).chain(t.order.iter()) {
        for sid in [&t.entry, &t.exit] {
            if let Some(x) = sn.get(sid.as_str()) {
                if !agent_knows(&x.version, tr) {
                    return Err(format!(
                        "the agent of \"{}\" is v{}: update it first (Update all), it does not know the {} transport{}",
                        names.get(sid.as_str()).cloned().unwrap_or_default(),
                        x.version,
                        tr,
                        if *tr == t.transport { "" } else { " (in the rotation order)" }
                    ));
                }
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

// ------------------------------------------------------------------ Hysteria2 link

/// Agents from this version on know Hysteria2 links (an older one would run the name as plain TCP).
const HY2_FROM: &str = "3.1.3";

/// what one side of a Hysteria2 tunnel runs
fn hy2_spec(app: &App, t: &Tunnel, role: &str) -> Hy2Spec {
    let c = &t.hy2;
    let entry = role == "entry";
    let host = if !t.dial.trim().is_empty() { t.dial.trim().to_string() } else { host_of(app, &t.exit) };
    Hy2Spec {
        tid: t.id.clone(),
        name: t.name.clone(),
        role: role.into(),
        listen: c.port,
        server: if entry { hostport(&host, c.port) } else { String::new() },
        auth: c.auth.clone(),
        obfs: c.obfs.clone(),
        cert: if entry { String::new() } else { c.cert.clone() },
        key: if entry { String::new() } else { c.key.clone() },
        masq: if entry { String::new() } else { c.masq.clone() },
        pin: if entry { c.pin.clone() } else { String::new() },
        sni: if entry { c.sni.clone() } else { String::new() },
        up_mbps: c.up_mbps,
        down_mbps: c.down_mbps,
        fwd_tcp: if entry { t.tcp.clone() } else { vec![] },
        fwd_udp: if entry { t.udp.clone() } else { vec![] },
        target: if entry { t.target.clone() } else { String::new() },
        src_routes: if entry { c.src_routes.clone() } else { vec![] },
        n: c.n,
        mtu: c.mtu,
        // 61001..61250: outside Linux's ephemeral range and the 20000-59999 range the installer
        // picks its random ports from (the VPN Hysteria2 stats port is 30000-39999)
        stats_port: if entry { 0 } else { 61000 + c.n as u16 },
        // the stats API only listens on 127.0.0.1 of the exit; its secret is derived from the password
        stats_secret: if entry { String::new() } else { format!("s{}", &c.auth[..c.auth.len().min(24)]) },
    }
}

/// reads the Hysteria2 part of the form: makes the passwords and the certificate the first time
fn hy2_apply_body(list: &[Tunnel], t: &mut Tunnel, a: &Value) -> Result<(), String> {
    let mut c = t.hy2.clone();
    if c.n == 0 {
        let used: HashSet<u8> = list.iter().filter(|o| o.kind == "hy2" && o.id != t.id).map(|o| o.hy2.n).collect();
        c.n = (1..=250u8).find(|n| !used.contains(n)).ok_or("too many Hysteria2 tunnels")?;
    }
    if let Some(v) = a["port"].as_u64() {
        c.port = v.min(65535) as u16;
    }
    if c.port == 0 {
        return Err("the Hysteria2 UDP port is required".into());
    }
    if let Some(v) = a["sni"].as_str() {
        let h = hy2t::clean_host(v);
        c.sni = if h.is_empty() { "www.bing.com".into() } else { h };
    }
    if let Some(v) = a["masq"].as_str() {
        let u = hy2t::clean_url(v);
        if !v.trim().is_empty() && u.is_empty() {
            return Err("the masquerade site must be an https:// address".into());
        }
        c.masq = u;
    }
    if c.auth.is_empty() || a["regen"].as_bool() == Some(true) {
        c.auth = rand_token(32);
    }
    if let Some(v) = a["obfs"].as_bool() {
        if !v {
            c.obfs.clear();
        } else if c.obfs.is_empty() {
            c.obfs = rand_token(24);
        }
    } else if t.hy2.auth.is_empty() {
        // new tunnel without a choice: obfuscation on (no QUIC / HTTP/3 signature on the wire)
        c.obfs = rand_token(24);
    }
    if a["regen"].as_bool() == Some(true) && !c.obfs.is_empty() {
        c.obfs = rand_token(24);
    }
    if c.cert.is_empty() || c.pin.is_empty() || a["regen"].as_bool() == Some(true) || c.sni != t.hy2.sni {
        let (cert, key, pin) = hy2t::gen_cert(&c.sni)?;
        c.cert = cert;
        c.key = key;
        c.pin = pin;
    }
    if let Some(v) = a["up_mbps"].as_u64() {
        c.up_mbps = v.min(100_000) as u32;
    }
    if let Some(v) = a["down_mbps"].as_u64() {
        c.down_mbps = v.min(100_000) as u32;
    }
    if let Some(v) = a["mtu"].as_u64() {
        c.mtu = if v == 0 { 1400 } else { v.clamp(1200, 1500) as u16 };
    }
    if a.get("src_routes").is_some() {
        c.src_routes = awg_wide_check(awg::clean_cidrs(&clean_list(&a["src_routes"])))?;
    }
    // Hysteria2 is always client (entry) -> server (exit)
    t.mode = "direct".into();
    t.transport = "hy2".into();
    t.port = c.port;
    t.conns = 1;
    t.auto = false;
    t.hy2 = c;
    Ok(())
}

/// agents must know Hysteria2 links
fn hy2_checks(app: &App, t: &Tunnel) -> Result<(), String> {
    if !t.enabled {
        return Ok(());
    }
    let names: HashMap<String, String> = servers(app).into_iter().map(|s| (s.id, s.name)).collect();
    let sn = seen().lock().unwrap();
    for sid in [&t.entry, &t.exit] {
        if sid == "local" {
            continue;
        }
        if let Some(x) = sn.get(sid.as_str()) {
            if !x.version.is_empty() && ver_lt(&x.version, HY2_FROM) {
                return Err(format!("the agent of \"{}\" is v{}: update it first (Update all), it does not know Hysteria2 tunnels", names.get(sid.as_str()).cloned().unwrap_or_default(), x.version));
            }
        }
    }
    Ok(())
}

async fn hy2_conf(State(app): St, h: HeaderMap, Path((id, side)): Path<(String, String)>) -> Response {
    let _ = guard!(app, h, "nodes");
    let Some(t) = tunnels(&app).into_iter().find(|t| t.id == id && t.kind == "hy2") else { return err(StatusCode::NOT_FOUND, "tunnel not found") };
    let role = if side == "exit" { "exit" } else { "entry" };
    let sp = hy2_spec(&app, &t, role);
    let mut body = hy2t::render(&sp);
    if role == "exit" {
        body.push_str(&format!("\n# --- {}/{}.crt ---\n{}\n# --- {}/{}.key ---\n{}", hy2t::CONF_DIR, sp.unit(), t.hy2.cert, hy2t::CONF_DIR, sp.unit(), t.hy2.key));
    }
    Json(json!({ "conf": body, "side": role, "file": format!("{}.yaml", sp.unit()) })).into_response()
}

/// The hysteria binary for a CPU type: the panel server's own (same type), a copy kept in
/// CACHE_DIR (downloaded by the panel or given by another server), or downloaded now.
async fn hy2bin_bytes(arch: &str, fetch: bool) -> Option<Vec<u8>> {
    let a = hy2t::arch_name(arch)?;
    if arch == std::env::consts::ARCH {
        for p in ["/usr/local/bin/hysteria", "/usr/bin/hysteria"] {
            if let Ok(b) = tokio::fs::read(p).await {
                if hy2t::looks_like_binary(&b) {
                    return Some(b);
                }
            }
        }
    }
    let cache = format!("{}/hysteria-linux-{}", hy2t::CACHE_DIR, a);
    if let Ok(b) = tokio::fs::read(&cache).await {
        if hy2t::looks_like_binary(&b) {
            return Some(b);
        }
    }
    if !fetch {
        return None;
    }
    // one download at a time (two agents asking at once must not download twice)
    static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    let _g = LOCK.lock().await;
    if let Ok(b) = tokio::fs::read(&cache).await {
        if hy2t::looks_like_binary(&b) {
            return Some(b);
        }
    }
    let http = reqwest::Client::builder().timeout(Duration::from_secs(180)).build().ok()?;
    for url in hy2t::download_urls(arch) {
        match http.get(&url).send().await {
            Ok(r) if r.status().is_success() => match r.bytes().await {
                Ok(b) if hy2t::looks_like_binary(&b) => {
                    let _ = tokio::fs::create_dir_all(hy2t::CACHE_DIR).await;
                    let _ = tokio::fs::write(&cache, &b).await;
                    eprintln!("hy2 tunnel: downloaded {} for the agents", url);
                    return Some(b.to_vec());
                }
                Ok(_) => eprintln!("hy2 tunnel: {} is not a program (filtered?)", url),
                Err(e) => eprintln!("hy2 tunnel: {}: {}", url, e),
            },
            Ok(r) => eprintln!("hy2 tunnel: {}: {}", url, r.status()),
            Err(e) => eprintln!("hy2 tunnel: {}: {}", url, e),
        }
    }
    None
}

/// a tunnel server's id and token are right (used before a big upload is read)
pub fn agent_token_ok(app: &App, id: &str, token: &str) -> bool {
    !token.is_empty() && servers(app).into_iter().any(|s| s.id == id && util::ct_eq(token, &s.token))
}

#[allow(clippy::result_large_err)] // the error is the ready axum answer (401/403)
fn agent_ok(app: &App, id: &str, token: &str) -> Result<(), Response> {
    let Some(s) = servers(app).into_iter().find(|s| s.id == id) else {
        return Err((StatusCode::GONE, "unknown server").into_response());
    };
    if token.is_empty() || !util::ct_eq(token, &s.token) {
        return Err(err(StatusCode::FORBIDDEN, "wrong token"));
    }
    Ok(())
}

/// Public (agent token): the hysteria binary for a tunnel server that cannot download it itself.
/// With "check": only says whether the panel already has one for that CPU type.
async fn agent_hy2bin(State(app): St, Json(b): Json<Value>) -> Response {
    if let Err(r) = agent_ok(&app, b["id"].as_str().unwrap_or(""), b["token"].as_str().unwrap_or("")) {
        return r;
    }
    let arch = b["arch"].as_str().unwrap_or("").to_string();
    if b["check"].as_bool() == Some(true) {
        return Json(json!({ "have": hy2bin_bytes(&arch, false).await.is_some() })).into_response();
    }
    let Some(bytes) = hy2bin_bytes(&arch, true).await else {
        return err(StatusCode::NOT_FOUND, "the panel has no hysteria for this CPU type and cannot download it either");
    };
    let sum = {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(&bytes);
        hex::encode(h.finalize())
    };
    (StatusCode::OK, [("x-sha256", sum)], bytes).into_response()
}

/// Public (agent token): a tunnel server that has hysteria gives the panel a copy for the others
async fn agent_hy2bin_put(State(app): St, h: HeaderMap, body: axum::body::Bytes) -> Response {
    let hv = |k: &str| h.get(k).and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    if let Err(r) = agent_ok(&app, &hv("x-id"), &hv("x-token")) {
        return r;
    }
    let Some(a) = hy2t::arch_name(&hv("x-arch")) else { return err(StatusCode::BAD_REQUEST, "unknown CPU type") };
    let sum = {
        use sha2::{Digest, Sha256};
        let mut s = Sha256::new();
        s.update(&body);
        hex::encode(s.finalize())
    };
    if !hy2t::looks_like_binary(&body) || sum != hv("x-sha256").to_lowercase() {
        return err(StatusCode::BAD_REQUEST, "not a hysteria binary");
    }
    let cache = format!("{}/hysteria-linux-{}", hy2t::CACHE_DIR, a);
    if !std::path::Path::new(&cache).exists() {
        let _ = tokio::fs::create_dir_all(hy2t::CACHE_DIR).await;
        let tmp = format!("{}.part", cache);
        if tokio::fs::write(&tmp, &body).await.is_ok() {
            let _ = tokio::fs::rename(&tmp, &cache).await;
        }
    }
    Json(json!({ "ok": true })).into_response()
}

// ------------------------------------------------------------------ smart tunnel (test every transport)

const PROBE_TRANSPORTS: &[&str] = &["tcpmux", "tcp", "ws", "wss", "quic", "kcp", "hq", "h2", "game", "faketcp"];
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
    /// which transports this run tests (a subset of PROBE_TRANSPORTS the admin ticked)
    transports: Vec<String>,
    /// also measure the raw server-to-server ping (no tunnel) as a reference
    baseline: bool,
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
    // which transports to test: the ones the admin ticked, or all of them
    let all: Vec<String> = PROBE_TRANSPORTS.iter().map(|x| x.to_string()).collect();
    let transports: Vec<String> = match b["transports"].as_array() {
        Some(a) => {
            let picked: Vec<String> = a.iter().filter_map(|x| x.as_str())
                .filter(|x| PROBE_TRANSPORTS.contains(x)).map(|x| x.to_string()).collect();
            if picked.is_empty() { all } else { picked }
        }
        None => all,
    };
    // an agent too old for a transport would run it as plain TCP and report plain-TCP numbers
    // under its name: such transports are left out of the test
    let (transports, skipped): (Vec<String>, Vec<String>) = {
        let sn = seen().lock().unwrap();
        let ver = |sid: &str| sn.get(sid).map(|x| x.version.clone()).unwrap_or_default();
        let (ve, vx) = (ver(&entry), ver(&exit));
        transports.into_iter().partition(|tr| agent_knows(&ve, tr) && agent_knows(&vx, tr))
    };
    if transports.is_empty() {
        return err(StatusCode::BAD_REQUEST, &format!("the agents are too old for {}: update them first (Update all)", skipped.join(", ")));
    }
    let baseline = b["baseline"].as_bool().unwrap_or(true);
    // the test ports must not collide with a tunnel that already listens there (on either server)
    let span = (transports.len() * PROBE_MODES.len()) as u16;
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
        transports: transports.clone(),
        baseline,
    };
    let id = job.id.clone();
    *probe_job().lock().unwrap() = Some(job);
    let note = if skipped.is_empty() {
        String::new()
    } else {
        format!("not tested, an agent is too old for them (update it first): {}", skipped.join(", "))
    };
    Json(json!({"ok": true, "id": id, "transports": transports, "skipped": skipped, "note": note, "baseline": baseline, "modes": PROBE_MODES})).into_response()
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
        if p.baseline {
            let sid = format!("probe-{}-baseline", p.id);
            let mut r = entry_st.iter().find(|s| s.id == sid).and_then(|s| s.probe.clone())
                .unwrap_or_else(|| json!({"done": false, "stage": "testing"}));
            if r["done"].as_bool() != Some(true) {
                all_done = false;
            }
            r["baseline"] = json!(true);
            r["transport"] = json!("baseline");
            r["mode"] = json!("baseline");
            res.push(r);
        }
        for (mi, mode) in PROBE_MODES.iter().enumerate() {
            for (i, tr) in p.transports.iter().enumerate() {
                let sid = format!("probe-{}-{}-{}", p.id, mode, tr);
                let es = entry_st.iter().find(|s| s.id == sid);
                let xs = exit_st.iter().find(|s| s.id == sid);
                let mut r = es.and_then(|s| s.probe.clone()).unwrap_or_else(|| json!({"done": false, "stage": "starting"}));
                if r["done"].as_bool() != Some(true) {
                    all_done = false;
                }
                r["mode"] = json!(mode);
                r["transport"] = json!(tr);
                r["port"] = json!(p.port + (mi * p.transports.len() + i) as u16);
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
        if !tu.enabled || !tu.auto || tu.transport == "cdn" || !tu.kind.is_empty() {
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
        // only transports both agents know (an older agent would run the name as plain TCP)
        let ver = |sid: &str| seen.get(sid).map(|x| x.version.as_str()).unwrap_or("");
        let Some(next) = next_transport(&order, &tu.transport, |tr| agent_knows(ver(&tu.entry), tr) && agent_knows(ver(&tu.exit), tr)) else {
            continue;
        };
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

/// the transport after `cur` in `order` that `ok` allows (wrapping around), or None
fn next_transport(order: &[String], cur: &str, ok: impl Fn(&str) -> bool) -> Option<String> {
    let start = order.iter().position(|x| x == cur).map(|i| i + 1).unwrap_or(0);
    (0..order.len()).map(|k| &order[(start + k) % order.len()]).find(|x| ok(x.as_str()) && x.as_str() != cur).cloned()
}

// ------------------------------------------------------------------ the engine on the panel server

pub async fn local_loop(app: Arc<App>) {
    let mgr = Manager::default();
    loop {
        let specs = specs_for(&app, "local");
        let ps = specs.clone();
        // stopped first, so the ports of a deleted tunnel are free when they are closed
        mgr.apply(specs).await;
        let _ = tokio::task::spawn_blocking(move || super::agent::open_ports(&ps)).await;
        let st = mgr.statuses().await;
        seen().lock().unwrap().insert(
            "local".into(),
            Seen { at: now(), version: crate::VERSION.into(), ip: host_of(&app, "local"), status: st, emergency: Value::Null, fw: Value::Null, listen: Value::Null, setup: Value::Null },
        );
        // the emergency chat may run on the panel server itself
        let want = if app.db.get("emer_server") == "local" { emer_cfg(&app) } else { None };
        let st = tokio::task::spawn_blocking(move || {
            let r = match &want {
                // a new config, or the chat stopped: (re)install and start it
                Some((c, ver)) if crate::emergency::applied_ver() != *ver || !crate::emergency::running() => crate::emergency::deploy(Some((c, ver))),
                Some(_) => Ok(()),
                None => crate::emergency::deploy(None),
            };
            let mut s = crate::emergency::status();
            if let Err(e) = r {
                s["error"] = json!(e);
            }
            s
        })
        .await
        .unwrap_or(Value::Null);
        if let Some(x) = seen().lock().unwrap().get_mut("local") {
            x.emergency = st;
        }
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
                    super::link::dial("cdn", &e, &sni, &host, &path, "", frag, super::game::GameOpts::default()),
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
        .route("/api/tunnels/servers/:id/free-ports", post(server_free_ports))
        .route("/api/tunnels/servers/:id/ssl-retry", post(server_ssl_retry))
        .route("/api/tunnels/servers/:id/ports", get(server_ports))
        .route("/api/tunnels/servers/:id/firewall", get(server_fw).post(server_fw_close))
        .route("/api/tunnels/:id", delete(tunnel_del))
        .route("/api/tunnels/:id/awgconf/:side", get(awg_conf))
        .route("/api/tunnels/:id/hy2conf/:side", get(hy2_conf))
        .route("/api/tunnels/:id/:action", post(tunnel_action))
        .route("/tunnel/agent", post(agent_report))
        .route("/tunnel/binary", post(agent_binary))
        .route("/tunnel/hy2bin", post(agent_hy2bin))
        // a hysteria binary is ~20 MB (the rest of the panel keeps the 2 MiB limit)
        .route("/tunnel/hy2bin/put", post(agent_hy2bin_put).layer(axum::extract::DefaultBodyLimit::max(64 * 1024 * 1024)))
        .route("/api/update-all", post(update_all))
        .route("/api/auto-update", get(auto_update_get).put(auto_update_put))
        .route("/api/emergency", get(emer_get).put(emer_put))
        .route("/api/emergency/rekey", post(emer_rekey))
}

fn status_json(st: Option<&Status>) -> Value {
    match st {
        Some(s) => serde_json::to_value(s).unwrap_or(Value::Null),
        None => Value::Null,
    }
}

/// KANKI MIX's second config: the Iran address and port of an enabled tunnel that really forwards
/// UDP `port` (None = no tunnel forwards it, so no second config that would point at a dead port).
/// A tunnel whose exit is the machine of the node (`node_id` / `node_host`) is preferred; else one whose
/// entry is `entry_host` (the node's endpoint) and listens on that UDP port.
pub fn udp_forward(app: &App, node_id: &str, node_host: &str, entry_host: &str, port: u16) -> Option<(String, u16)> {
    let list: Vec<Tunnel> = tunnels(app).into_iter().filter(|t| t.enabled && t.kind != "awg" && t.kind != "awgwrap").collect();
    let addr = |sid: &str| seen_ip(sid).filter(|_| sid != "local").unwrap_or_else(|| host_of(app, sid));
    for t in &list {
        let exit_here = (t.exit == "local" && node_id == "local")
            || (!node_host.is_empty() && (addr(&t.exit) == node_host || host_of(app, &t.exit) == node_host || t.target == node_host));
        if !exit_here {
            continue;
        }
        if let Some((a, _)) = crate::tunnel::engine::parse_ports(&t.udp).into_iter().find(|(_, b)| *b == port) {
            let h = host_of(app, &t.entry);
            if !h.is_empty() {
                return Some((h, a));
            }
        }
    }
    if entry_host.is_empty() {
        return None;
    }
    for t in &list {
        if addr(&t.entry) != entry_host && host_of(app, &t.entry) != entry_host {
            continue;
        }
        if crate::tunnel::engine::parse_ports(&t.udp).iter().any(|(a, b)| *a == port && *b == port) {
            return Some((entry_host.to_string(), port));
        }
    }
    None
}

/// (server id, its public address) of every tunnel server and the panel server, for their flags
pub fn server_hosts(app: &App) -> Vec<(String, String)> {
    let mut v = vec![("local".to_string(), host_of(app, "local"))];
    for s in servers(app) {
        let h = seen_ip(&s.id).unwrap_or_else(|| host_of(app, &s.id));
        v.push((s.id.clone(), h));
    }
    v.retain(|(_, h)| !h.is_empty());
    v
}

async fn list(State(app): St, h: HeaderMap) -> Response {
    let _ = guard!(app, h, "nodes");
    let seen = seen().lock().unwrap().clone();
    let t = now();
    let locs = server_locs(&app);
    let ccs = crate::exitgeo::all_cc(&app);
    let cc_of = |id: &str| ccs.get(&crate::exitgeo::srv_key(id)).cloned().unwrap_or_default();
    let mut srv = vec![json!({
        "id": "local", "name": local_name(&app), "local": true, "addr": app.db.get("tun_local_addr"),
        "host": host_of(&app, "local"), "online": true, "last_seen": t, "version": crate::VERSION,
        "loc": locs.get("local").map(|x| x.0.clone()).unwrap_or_default(), "loc_guess": locs.get("local").map(|x| x.1).unwrap_or(true), "cc": cc_of("local"),
    })];
    for s in servers(&app) {
        let x = seen.get(&s.id).cloned().unwrap_or_default();
        srv.push(json!({
            "id": s.id, "name": s.name, "local": false, "addr": s.addr, "host": host_of(&app, &s.id),
            "ip": x.ip, "online": x.at > 0 && t - x.at < 20, "last_seen": x.at, "version": x.version,
            "gre_ip": s.gre_ip, "gre_n": s.gre_n, "gre_panel_ip": s.gre_panel_ip,
            "loc": locs.get(&s.id).map(|x| x.0.clone()).unwrap_or_default(), "loc_guess": locs.get(&s.id).map(|x| x.1).unwrap_or(true), "cc": cc_of(&s.id),
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
        if tu.kind == "hy2" {
            for k in ["auth", "obfs", "cert", "key"] {
                v["hy2"][k] = json!("");
            }
            v["hy2"]["obfs_on"] = json!(!tu.hy2.obfs.is_empty());
        }
        v["state"] = json!(state);
        v["entry_status"] = status_json(es.as_ref());
        v["exit_status"] = status_json(xs.as_ref());
        v["dial_host"] = json!(if !tu.dial.trim().is_empty() { tu.dial.clone() } else { host_of(&app, if tu.mode == "direct" { &tu.exit } else { &tu.entry }) });
        tl.push(v);
    }
    Json(json!({ "servers": srv, "tunnels": tl, "panel": crate::servers::panel_url(&app), "repo": crate::admin::repo() })).into_response()
}

fn clean_list(v: &Value) -> Vec<String> {
    let raw: Vec<String> = match v {
        Value::Array(a) => a.iter().filter_map(|x| x.as_str().map(|s| s.to_string()).or_else(|| x.as_u64().map(|n| n.to_string()))).collect(),
        Value::String(s) => s.split([',', ' ', '\n']).map(|x| x.to_string()).collect(),
        _ => vec![],
    };
    raw.into_iter().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()
}

/// The ports server `sid` listens on from outside right now: (port, udp, program, unit). None = not
/// known (an agent older than 3.7.0, or no report yet).
pub(crate) fn listening_on(sid: &str) -> Option<Vec<(u16, bool, String, String)>> {
    if sid == "local" {
        return Some(crate::certbot::listeners());
    }
    let sn = seen().lock().unwrap();
    let x = sn.get(sid)?;
    if now() - x.at > 60 {
        return None;
    }
    let a = x.listen.as_array()?;
    Some(
        a.iter()
            .filter_map(|e| Some((e[0].as_u64()? as u16, e[1].as_bool()?, e[2].as_str().unwrap_or("").to_string(), e[3].as_str().unwrap_or("").to_string())))
            .collect(),
    )
}

/// A port another program holds on server `sid` right now (live): its name for the error, None when it
/// is free, held by `own` (the service that will use it), or the server has not said.
pub(crate) fn port_busy(app: &App, sid: &str, port: u16, udp: bool, own: &[&str]) -> Option<String> {
    let l = listening_on(sid)?;
    let (_, prog, unit) = l.into_iter().map(|(p, u, prog, unit)| ((p, u), prog, unit)).find(|(k, _, _)| *k == (port, udp))?;
    if own.contains(&unit.as_str()) {
        return None;
    }
    let srv = if sid == "local" { local_name(app) } else { server_names(app).get(sid).cloned().unwrap_or(sid.to_string()) };
    Some(format!("{} port {} on {} is already used by {}: pick another port", if udp { "UDP" } else { "TCP" }, port, srv, holder_name(&prog, &unit)))
}

/// What a program holding a port is called in an error
fn holder_name(prog: &str, unit: &str) -> String {
    match unit {
        "kanki-dns.service" => "Kanki DNS".into(),
        "kanki-xray.service" => "Xray".into(),
        "kanki-emergency.service" => "the emergency chat".into(),
        "kanki-mix.service" => "KANKI MIX".into(),
        "kanki-tunnel.service" => "another Kanki tunnel or the subscription link".into(),
        "kanki-panel.service" => "the panel itself or one of its tunnels".into(),
        "" if prog == "kernel" => "WireGuard / AmneziaWG".into(),
        "" if prog == "?" || prog.is_empty() => "another program".into(),
        "" => prog.to_string(),
        u => format!("{} ({})", prog, u.trim_end_matches(".service")),
    }
}

/// Ports tunnel `t` listens on, per server: (server, port, udp)
fn tunnel_needs(t: &Tunnel) -> Vec<(String, u16, bool)> {
    let mut v = vec![];
    // AmneziaWG and Hysteria2 links listen in their own programs (checked by the other tunnels' rules)
    if t.kind == "hy2" || (t.kind == "awg" && !t.awg.wrap) {
        return v;
    }
    let listener = if t.mode == "direct" { t.exit.clone() } else { t.entry.clone() };
    let (tcp, udp) = port_protos(&t.transport);
    if t.port > 0 {
        if tcp {
            v.push((listener.clone(), t.port, false));
        }
        if udp {
            v.push((listener.clone(), t.port, true));
        }
    }
    for (p, _) in parse_ports(&t.tcp) {
        v.push((t.entry.clone(), p, false));
    }
    for (p, _) in parse_ports(&t.udp) {
        v.push((t.entry.clone(), p, true));
    }
    v
}

/// Is a port the tunnel needs already held on its server by something else? (live, from the
/// servers' own reports). The tunnel's own ports (when it is edited) do not count.
fn live_clash(app: &App, t: &Tunnel, old: Option<&Tunnel>) -> Option<String> {
    let names = server_names(app);
    let own: Vec<(String, u16, bool)> = old.filter(|o| o.enabled).map(tunnel_needs).unwrap_or_default();
    for (sid, port, udp) in tunnel_needs(t) {
        let Some(l) = listening_on(&sid) else { continue };
        for (p, u, prog, unit) in l {
            if p != port || u != udp {
                continue;
            }
            let ours = unit == "kanki-tunnel.service" || unit.starts_with("kanki-hy2-") || (sid == "local" && unit == "kanki-panel.service");
            if ours && own.contains(&(sid.clone(), port, udp)) {
                continue;
            }
            let srv = if sid == "local" { local_name(app) } else { names.get(&sid).cloned().unwrap_or(sid.clone()) };
            return Some(format!("{} port {} on {} is already used by {}: pick another port", if udp { "UDP" } else { "TCP" }, port, srv, holder_name(&prog, &unit)));
        }
    }
    None
}

/// Live check from the tunnel form: which of these ports are taken on a server
/// GET /api/tunnels/servers/:id/ports → { known: bool, used: [{port, proto, by}] }
async fn server_ports(State(app): St, h: HeaderMap, Path(id): Path<String>) -> Response {
    let _ = guard!(app, h, "nodes");
    match listening_on(&id) {
        None => Json(json!({ "known": false, "used": [] })).into_response(),
        Some(l) => Json(json!({
            "known": true,
            "used": l.into_iter().map(|(p, u, prog, unit)| json!({ "port": p, "proto": if u { "udp" } else { "tcp" }, "by": holder_name(&prog, &unit), "kanki": unit.starts_with("kanki") })).collect::<Vec<_>>(),
        }))
        .into_response(),
    }
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
    if b.get("fec").is_some() {
        let f = s("fec");
        // "8:3" style, 1-64 data and 1-32 parity shards, or "off"
        if f.is_empty() || f == "off" || f.split(':').all(|x| x.trim().parse::<u8>().map(|v| v <= 64).unwrap_or(false)) {
            t.fec = f;
        }
    }
    if let Some(d) = b["dup"].as_bool() {
        t.dup = d;
    }
    if let Some(e) = b["enabled"].as_bool() {
        t.enabled = e;
    }
    if let Some(a) = b["auto"].as_bool() {
        t.auto = a;
    }
    if b["order"].is_array() || b["order"].is_string() {
        let o: Vec<String> = clean_list(&b["order"]).into_iter().filter(|x| AUTO_ORDER.contains(&x.as_str()) || matches!(x.as_str(), "hq" | "h2" | "game" | "faketcp")).collect();
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
        t.kind = match s("kind").as_str() {
            "awg" => "awg".into(),
            "hy2" => "hy2".into(),
            _ => String::new(),
        };
    }
    if t.kind == "hy2" {
        if let Err(e) = hy2_apply_body(&list, &mut t, &b["hy2"]) {
            return err(StatusCode::BAD_REQUEST, &e);
        }
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
    if t.kind == "hy2" {
        if let Err(e) = hy2_checks(&app, &t) {
            return err(StatusCode::CONFLICT, &e);
        }
    }
    if t.port == 0 {
        return err(StatusCode::BAD_REQUEST, "the tunnel port is required");
    }
    let hy2_src = t.kind == "hy2" && !t.hy2.src_routes.is_empty();
    if !hy2_src && parse_ports(&t.tcp).is_empty() && parse_ports(&t.udp).is_empty() {
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
    // what the servers themselves say: a port another program (or another Kanki service) holds
    if t.enabled {
        let old = list.iter().find(|x| x.id == t.id).cloned();
        if let Some(e) = live_clash(&app, &t, old.as_ref()) {
            return err(StatusCode::CONFLICT, &e);
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
            // a new password makes both ends restart their Hysteria2 service
            if t.kind == "hy2" {
                t.hy2.auth = rand_token(32);
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
    let origin = crate::servers::panel_url(app);
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
    let origin = crate::servers::panel_url(app);
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
fn gre_apply_body(list: &mut [TServer], id: &str, b: &Value) -> Result<(), String> {
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
        loc: clean_loc(b["loc"].as_str().unwrap_or("")),
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
    Json(json!({ "ok": true, "id": s.id, "token": s.token, "name": s.name, "panel": crate::servers::panel_url(&app), "repo": crate::admin::repo(), "gre": gre })).into_response()
}

async fn server_edit(State(app): St, h: HeaderMap, Path(id): Path<String>, Json(b): Json<Value>) -> Response {
    let _ = guard!(app, h, "nodes");
    if id == "local" {
        if let Some(a) = b["addr"].as_str() {
            app.db.set("tun_local_addr", a.trim());
        }
        if let Some(l) = b["loc"].as_str() {
            app.db.set("tun_local_loc", &clean_loc(l));
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
    if let Some(l) = b["loc"].as_str() {
        s.loc = clean_loc(l);
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
    Json(json!({ "ok": true, "token": token, "panel": crate::servers::panel_url(&app), "repo": crate::admin::repo(), "gre": gre })).into_response()
}

/// Services the admin asked to stop on a server because they hold ports Kanki DNS or Xray need there
/// (sent with the server's next report; the server checks each one again before it stops it).
fn frees() -> &'static Mutex<HashMap<String, Vec<String>>> {
    static S: OnceLock<Mutex<HashMap<String, Vec<String>>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Servers asked to try SSL again at once (sent with their next report)
fn ssl_retries() -> &'static Mutex<std::collections::HashSet<String>> {
    static S: OnceLock<Mutex<std::collections::HashSet<String>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(std::collections::HashSet::new()))
}

/// Firewall rules the admin asked to close on a server (open in ufw, nothing uses them)
fn fw_closes() -> &'static Mutex<HashMap<String, Vec<String>>> {
    static S: OnceLock<Mutex<HashMap<String, Vec<String>>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(HashMap::new()))
}

/// "Try SSL again": the server forgets the waits after earlier certbot failures (every SSL of that server)
pub(crate) fn ask_ssl_retry(id: &str) {
    ssl_retries().lock().unwrap().insert(id.to_string());
}

async fn server_ssl_retry(State(app): St, h: HeaderMap, Path(id): Path<String>) -> Response {
    let _ = guard!(app, h, "nodes");
    if id == "local" {
        let _ = tokio::task::spawn_blocking(crate::certbot::retry_now).await;
        return Json(json!({ "ok": true })).into_response();
    }
    if !servers(&app).iter().any(|s| s.id == id) {
        return err(StatusCode::NOT_FOUND, "unknown server");
    }
    ask_ssl_retry(&id);
    Json(json!({ "ok": true })).into_response()
}

/// The firewall of a server: { owners: { tunnels: [...], dns: [...] }, unused: ["8443/tcp"] }
async fn server_fw(State(app): St, h: HeaderMap, Path(id): Path<String>) -> Response {
    let _ = guard!(app, h, "nodes");
    let v = if id == "local" { tokio::task::spawn_blocking(crate::fw::report).await.unwrap_or_default() } else { seen().lock().unwrap().get(&id).map(|x| x.fw.clone()).unwrap_or(Value::Null) };
    Json(v).into_response()
}

/// { rules: ["8443/tcp"] }: close firewall ports nothing uses (the server checks each one again)
async fn server_fw_close(State(app): St, h: HeaderMap, Path(id): Path<String>, Json(b): Json<Value>) -> Response {
    let _ = guard!(app, h, "nodes");
    let rules: Vec<String> = b["rules"].as_array().into_iter().flatten().filter_map(|r| r.as_str()).filter(|r| crate::fw::valid_rule(r)).map(|r| r.to_string()).collect();
    if rules.is_empty() {
        return err(StatusCode::BAD_REQUEST, "no port to close");
    }
    if id == "local" {
        let _ = tokio::task::spawn_blocking(move || crate::fw::close_unused(&rules)).await;
        return Json(json!({ "ok": true })).into_response();
    }
    if !servers(&app).iter().any(|s| s.id == id) {
        return err(StatusCode::NOT_FOUND, "unknown server");
    }
    fw_closes().lock().unwrap().insert(id, rules);
    Json(json!({ "ok": true })).into_response()
}

/// { units: ["caddy.service"] } (Health › Free the ports)
async fn server_free_ports(State(app): St, h: HeaderMap, Path(id): Path<String>, Json(b): Json<Value>) -> Response {
    let _ = guard!(app, h, "nodes");
    if id == "local" {
        // on the panel's own server a web server usually fronts the panel itself
        return err(StatusCode::BAD_REQUEST, "on the panel's own server stop it by hand (systemctl disable --now <service>)");
    }
    if !servers(&app).iter().any(|s| s.id == id) {
        return err(StatusCode::NOT_FOUND, "unknown server");
    }
    let units: Vec<String> = b["units"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|u| u.as_str())
        .filter(|u| u.ends_with(".service") && !u.starts_with("kanki") && u.len() < 100 && u.bytes().all(|c| c.is_ascii_alphanumeric() || b"@._-".contains(&c)))
        .map(|u| u.to_string())
        .collect();
    if units.is_empty() {
        return err(StatusCode::BAD_REQUEST, "no service to stop");
    }
    frees().lock().unwrap().insert(id, units);
    Json(json!({ "ok": true })).into_response()
}

async fn server_del(State(app): St, h: HeaderMap, Path(id): Path<String>) -> Response {
    let _ = guard!(app, h, "nodes");
    match delete_server(&app, &id, false) {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err((code, e)) => err(code, &e),
    }
}

/// Removes an agent server from the panel. Its agent sees it is gone, removes what Kanki installed
/// (tunnels, Kanki DNS, Xray, emergency chat, subscription listener), closes the firewall ports it
/// opened and uninstalls itself. Refused while tunnels still use it.
pub(crate) fn delete_server(app: &App, id: &str, with_tunnels: bool) -> Result<(), (StatusCode, String)> {
    if id == "local" {
        return Err((StatusCode::BAD_REQUEST, "the panel server cannot be removed".into()));
    }
    let used: Vec<String> = tunnels(app).into_iter().filter(|t| t.entry == id || t.exit == id).map(|t| t.name).collect();
    if !used.is_empty() && !with_tunnels {
        return Err((StatusCode::CONFLICT, format!("delete its tunnels first: {}", used.join(", "))));
    }
    if !used.is_empty() {
        // the tunnels go too: the server at the other end (the Iran entry) stops them on its next report
        // and closes the ports they used
        let mut tl = tunnels(app);
        tl.retain(|t| t.entry != id && t.exit != id);
        save_tunnels(app, &tl);
    }
    let mut list = servers(app);
    if !list.iter().any(|s| s.id == id) {
        return Err((StatusCode::NOT_FOUND, "unknown server".into()));
    }
    list.retain(|s| s.id != id);
    save_servers(app, &list);
    crate::dns::panel::forget_server(app, id);
    crate::xray::panel::forget_server(app, id);
    crate::subiran::forget_server(app, id);
    if app.db.get("emer_server") == id {
        app.db.set("emer_server", "");
    }
    crate::exitgeo::forget(app, &[crate::exitgeo::srv_key(id), crate::exitgeo::xray_key(id)]);
    seen().lock().unwrap().remove(id);
    Ok(())
}

// ------------------------------------------------------------------ emergency chat (runs on a server inside Iran)

/// The config the chosen server runs, and its version (a hash, so it is sent only on change)
pub(crate) fn emer_cfg(app: &App) -> Option<(crate::emergency::EmerCfg, String)> {
    if app.db.get("emer_on") != "1" || app.db.get("emer_sign").is_empty() || app.db.get("emer_admin").is_empty() {
        return None;
    }
    let users = app
        .db
        .users()
        .into_iter()
        .map(|u| crate::emergency::EUser { h: crate::emergency::user_hash(&u.sub_code()), u: u.username })
        .collect();
    let c = crate::emergency::EmerCfg {
        port: app.db.get("emer_port").parse().unwrap_or(0),
        cert: if emer_ssl(app) == "manual" { app.db.get("emer_cert") } else { String::new() },
        key: if emer_ssl(app) == "manual" { app.db.get("emer_key") } else { String::new() },
        admin_hash: app.db.get("emer_admin"),
        sign_key: app.db.get("emer_sign"),
        name: app.db.get("panel_name"),
        users,
        acme_domain: if emer_ssl(app) == "auto" { app.db.get("emer_domain") } else { String::new() },
    };
    if c.port == 0 {
        return None;
    }
    let ver = util::sha256_hex(&serde_json::to_string(&c).unwrap_or_default());
    Some((c, ver))
}

/// "auto" (Let's Encrypt on the Iran server), "cdn" (the CDN does HTTPS, the server plain HTTP),
/// "manual" (pasted PEM) or "http"
fn emer_ssl(app: &App) -> String {
    let m = app.db.get("emer_ssl");
    if !m.is_empty() {
        return m;
    }
    if app.db.get("emer_cert").is_empty() { "http".into() } else { "manual".into() }
}

/// The address the app talks to: http(s)://domain[:port]. Empty when the chat is off.
pub(crate) fn emer_url(app: &App) -> String {
    if app.db.get("emer_on") != "1" {
        return String::new();
    }
    let mode = emer_ssl(app);
    if mode == "cdn" {
        let d = app.db.get("emer_domain");
        return if d.is_empty() { String::new() } else { format!("https://{}", d) };
    }
    let tls = mode == "auto" || mode == "manual";
    let port: u16 = app.db.get("emer_port").parse().unwrap_or(0);
    let d = app.db.get("emer_domain");
    if d.is_empty() || port == 0 {
        return String::new();
    }
    let def = if tls { 443 } else { 80 };
    format!("{}://{}{}", if tls { "https" } else { "http" }, d, if port == def { String::new() } else { format!(":{}", port) })
}

/// Ports Kanki DNS listens on: the emergency chat cannot use them on a DNS server.
pub(crate) const DNS_PORTS: [u16; 4] = [53, 80, 443, 853];

/// The emergency chat's port when the chat is on and runs on server `sid`.
pub(crate) fn emer_port_on(app: &App, sid: &str) -> Option<u16> {
    (app.db.get("emer_on") == "1" && app.db.get("emer_server") == sid).then(|| app.db.get("emer_port").parse().ok()).flatten()
}

/// Ports a CDN (ArvanCloud, Cloudflare) passes on: HTTP and HTTPS. Suggested for the emergency chat.
const CDN_PORTS: &str = "HTTP: 80, 8080, 8880, 2052, 2082, 2086, 2095 · HTTPS: 443, 2053, 2083, 2087, 2096, 8443";

/// The public key the app checks admin messages with (empty when the chat is off)
pub(crate) fn emer_pub(app: &App) -> String {
    if app.db.get("emer_on") != "1" { String::new() } else { app.db.get("emer_pub") }
}

async fn emer_get(State(app): St, h: HeaderMap) -> Response {
    let _ = guard!(app, h, "settings");
    let sid = app.db.get("emer_server");
    let st = seen().lock().unwrap().get(&sid).map(|x| x.emergency.clone()).unwrap_or(Value::Null);
    let users = app.db.users().len();
    Json(json!({
        "on": app.db.get("emer_on") == "1", "server": sid, "domain": app.db.get("emer_domain"),
        "port": app.db.get("emer_port").parse::<u16>().unwrap_or(0), "tls": !app.db.get("emer_cert").is_empty(), "ssl": emer_ssl(&app),
        "has_password": !app.db.get("emer_admin").is_empty(), "url": emer_url(&app), "status": st, "customers": users,
        "key": app.db.get("emer_pub").chars().rev().take(12).collect::<String>(),
    }))
    .into_response()
}

fn host_ok(d: &str) -> bool {
    if d.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    !d.is_empty()
        && d.len() <= 253
        && d.contains('.')
        && d.split('.').all(|l| !l.is_empty() && l.len() <= 63 && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') && !l.starts_with('-') && !l.ends_with('-'))
}

/// { on, server, domain, port, cert, key, password, clear_tls }. Everything is checked first;
/// nothing is saved when one value is wrong.
async fn emer_put(State(app): St, h: HeaderMap, Json(b): Json<Value>) -> Response {
    let _ = guard!(app, h, "settings");
    let s = |k: &str| b[k].as_str().unwrap_or("").trim().to_string();
    let on = b["on"].as_bool().unwrap_or(false);
    let server = if b.get("server").is_some() { s("server") } else { app.db.get("emer_server") };
    if on && !(server == "local" || servers(&app).iter().any(|x| x.id == server)) {
        return err(StatusCode::BAD_REQUEST, "choose the server inside Iran");
    }
    let domain = if b.get("domain").is_some() {
        s("domain").trim_start_matches("https://").trim_start_matches("http://").trim_end_matches('/').to_lowercase()
    } else {
        app.db.get("emer_domain")
    };
    if !domain.is_empty() && !host_ok(&domain) {
        return err(StatusCode::BAD_REQUEST, "enter a domain like chat.example.com");
    }
    let port = match b["port"].as_u64() {
        Some(p) if p == 0 || p > 65535 || p == 22 => return err(StatusCode::BAD_REQUEST, "choose a port between 1 and 65535 (not 22)"),
        Some(p) => p.to_string(),
        None => app.db.get("emer_port"),
    };
    let (cert, key) = (s("cert"), s("key"));
    let tls = if !cert.is_empty() || !key.is_empty() {
        if !cert.contains("BEGIN CERTIFICATE") {
            return err(StatusCode::BAD_REQUEST, "the certificate must be PEM (-----BEGIN CERTIFICATE-----)");
        }
        if !key.contains("BEGIN PRIVATE KEY") {
            return err(StatusCode::BAD_REQUEST, "the key must be PKCS#8 PEM (-----BEGIN PRIVATE KEY-----). Convert it: openssl pkcs8 -topk8 -nocrypt -in key.pem");
        }
        Some((cert, key))
    } else if b["clear_tls"].as_bool() == Some(true) {
        Some((String::new(), String::new()))
    } else {
        None
    };
    let pw = b["password"].as_str().unwrap_or("");
    if !pw.is_empty() && pw.chars().count() < 10 {
        return err(StatusCode::BAD_REQUEST, "the password must be at least 10 characters");
    }
    // the port must be free on that server: Kanki DNS (53, 80, 443, 853) and Xray inbounds run there too
    if on {
        let p: u16 = port.parse().unwrap_or(0);
        let dns = crate::dns::panel::settings(&app);
        if dns.on && dns.servers.iter().any(|x| x.server == server) && DNS_PORTS.contains(&p) {
            return err(StatusCode::BAD_REQUEST, &format!("Kanki DNS runs on this server and needs ports 53, 80, 443 and 853: choose another port for the chat ({})", CDN_PORTS));
        }
        let xr = crate::xray::panel::settings(&app);
        if xr.on && xr.inbounds.iter().any(|ib| ib.enabled && ib.server == server && ib.port == p) {
            return err(StatusCode::BAD_REQUEST, &format!("an Xray inbound uses port {} on this server: choose another port for the chat ({})", p, CDN_PORTS));
        }
        if let Some(e) = port_busy(&app, &server, p, false, &["kanki-emergency.service"]) {
            return err(StatusCode::CONFLICT, &e);
        }
    }
    if on {
        if pw.is_empty() && app.db.get("emer_admin").is_empty() {
            return err(StatusCode::BAD_REQUEST, "set the admin password of the emergency chat");
        }
        if domain.is_empty() || port.is_empty() {
            return err(StatusCode::BAD_REQUEST, "enter the domain and the port");
        }
    }
    let sign = if app.db.get("emer_sign").is_empty() {
        match crate::emergency::gen_sign_key() {
            Ok(k) => Some(k),
            Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, &e),
        }
    } else {
        None
    };
    let ssl = s("ssl");
    if !ssl.is_empty() && !["auto", "cdn", "manual", "http"].contains(&ssl.as_str()) {
        return err(StatusCode::BAD_REQUEST, "unknown SSL mode");
    }
    if ssl == "auto" && domain.parse::<std::net::IpAddr>().is_ok() {
        return err(StatusCode::BAD_REQUEST, "automatic SSL needs a domain, not an IP");
    }
    if ssl == "manual" && tls.as_ref().map(|t| t.0.is_empty()).unwrap_or(app.db.get("emer_cert").is_empty()) {
        return err(StatusCode::BAD_REQUEST, "paste the certificate and the key, or choose another SSL mode");
    }
    // all checked: save
    if !ssl.is_empty() {
        app.db.set("emer_ssl", &ssl);
    }
    app.db.set("emer_server", &server);
    app.db.set("emer_domain", &domain);
    app.db.set("emer_port", &port);
    if let Some((c, k)) = tls {
        app.db.set("emer_cert", &c);
        app.db.set("emer_key", &k);
    }
    if !pw.is_empty() {
        app.db.set("emer_admin", &util::hash_password(pw));
    }
    if let Some((k, p)) = sign {
        app.db.set("emer_sign", &k);
        app.db.set("emer_pub", &p);
    }
    app.db.set("emer_on", if on { "1" } else { "" });
    Json(json!({ "ok": true, "url": emer_url(&app) })).into_response()
}

/// a new signing key: apps trust it after they refresh their subscription (while the internet works)
async fn emer_rekey(State(app): St, h: HeaderMap) -> Response {
    let _ = guard!(app, h, "settings");
    match crate::emergency::gen_sign_key() {
        Ok((k, p)) => {
            app.db.set("emer_sign", &k);
            app.db.set("emer_pub", &p);
            Json(json!({ "ok": true })).into_response()
        }
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, &e),
    }
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
    let fresh_ip = util::client_ip(&h);
    {
        let mut sn = seen().lock().unwrap();
        let prev = sn.get(&id).map(|x| x.ip.clone()).unwrap_or_default();
        let ip = sticky_ip(&prev, &fresh_ip);
        sn.insert(id.clone(), Seen { at: now(), version: b["version"].as_str().unwrap_or("").to_string(), ip, status, emergency: b["emergency"].clone(), fw: b["fw"].clone(), listen: b["listen"].clone(), setup: b["setup"].clone() });
    }
    let ver = b["version"].as_str().unwrap_or("");
    let until = app.db.get("tun_update_until").parse::<i64>().unwrap_or(0);
    let update = now() < until && !ver.is_empty() && ver != crate::VERSION;
    // the emergency chat: only the chosen server runs it; the config is sent only when it changed
    let emergency = match (app.db.get("emer_server") == id).then(|| emer_cfg(&app)).flatten() {
        // same config and running: nothing to do (a stopped chat gets the config again, so it restarts)
        Some((_, v)) if b["emer_ver"].as_str() == Some(v.as_str()) && b["emergency"]["active"].as_bool() == Some(true) => json!({ "mode": "keep" }),
        Some((c, v)) => json!({ "mode": "set", "ver": v, "cfg": c }),
        None => json!({ "mode": "off" }),
    };
    // Kanki DNS: usage since the last report, and the config when it changed
    crate::dns::panel::ingest(&app, &id, &b["dns"]);
    // a repair asked in the panel: the config goes again with "force", so the server restarts it
    let dns_force = crate::dns::panel::take_repair(&id);
    let dns = match crate::dns::panel::cfg_for(&app, &id) {
        Some((_, v)) if !dns_force && b["dns_ver"].as_str() == Some(v.as_str()) && b["dns"]["active"].as_bool() == Some(true) => json!({ "mode": "keep" }),
        Some((c, v)) => json!({ "mode": "set", "ver": v, "cfg": c, "force": dns_force }),
        None => json!({ "mode": "off" }),
    };
    crate::subiran::ingest(&app, &id, &b["subsrv"]);
    crate::xray::panel::ingest(&app, &id, &b["xray"]);
    let xray_force = crate::xray::panel::take_repair(&id);
    let xray = match crate::xray::panel::cfg_for(&app, &id) {
        Some((_, v)) if !xray_force && b["xray_ver"].as_str() == Some(v.as_str()) && b["xray"]["active"].as_bool() == Some(true) => json!({ "mode": "keep" }),
        Some((c, v)) => json!({ "mode": "set", "ver": v, "cfg": c, "force": xray_force }),
        None => json!({ "mode": "off" }),
    };
    let subsrv = crate::subiran::cfg_for(&app, &id);
    // services to stop for our ports (asked in Health)
    let free = frees().lock().unwrap().remove(&id).unwrap_or_default();
    let ssl_retry = ssl_retries().lock().unwrap().remove(&id);
    let fw_close = fw_closes().lock().unwrap().remove(&id).unwrap_or_default();
    // the VPN part of this machine, when the admin asked for it (sent until the agent says it started)
    let setup = crate::servers::setup_for(&app, &s, &b["setup"]);
    Json(json!({ "tunnels": specs_for(&app, &id), "update": update, "emergency": emergency, "dns": dns, "xray": xray, "subsrv": subsrv, "free": free, "ssl_retry": ssl_retry, "fw_close": fw_close, "setup": setup, "panel": crate::servers::panel_url(&app) })).into_response()
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
    let Ok(path) = crate::util::exe_path() else { return err(StatusCode::INTERNAL_SERVER_ERROR, "no binary") };
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
    Json(run_update_all(&app).await).into_response()
}

/// "Update all": the nodes, the tunnel servers (they take the panel's binary), then the panel itself.
/// Used by the button and by the nightly automatic update.
pub(crate) async fn run_update_all(app: &Arc<App>) -> Value {
    let app = app.clone();
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
            .split(['/', ':'])
            .next()
            .unwrap_or("")
            .to_lowercase();
        let ips: Vec<String> = match tokio::net::lookup_host((host.as_str(), 443u16)).await {
            Ok(it) => it.map(|a| a.ip().to_string()).collect(),
            Err(_) => vec![],
        };
        for s in srv.iter() {
            let ip = seen_now.get(&s.id).map(|x| x.ip.clone()).unwrap_or_default();
            if s.node == n.id || s.addr.trim().to_lowercase() == host || (!ip.is_empty() && ips.contains(&ip)) {
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
    json!({ "ok": true, "latest": latest, "panel": panel_msg, "nodes": nodes_out, "agents": flagged, "manual": manual, "also_nodes": covered_names })
}

// ------------------------------------------------------------------ automatic update every night at 03:30 (Tehran)

/// Tehran is UTC+3:30 all year (no summer time since 2022): 03:30 there is 00:00 UTC.
const TEHRAN_OFFSET: i64 = 3 * 3600 + 1800;

/// (day number, minute of the day) in Tehran time
fn tehran_now() -> (i64, i64) {
    let t = now() + TEHRAN_OFFSET;
    (t / 86400, (t % 86400) / 60)
}

/// the next 03:30 Tehran time, as a unix timestamp
fn next_run_ts() -> i64 {
    let t = now() + TEHRAN_OFFSET;
    let mut run = (t / 86400) * 86400 + 210 * 60;
    if run <= t {
        run += 86400;
    }
    run - TEHRAN_OFFSET
}

/// Checks once a minute; between 03:30 and 04:00 Tehran time, once a day, runs "Update all" when the
/// switch is on. Components already on the newest version are left alone.
pub async fn auto_update_loop(app: Arc<App>) {
    loop {
        tokio::time::sleep(Duration::from_secs(60)).await;
        if app.db.get("auto_update") != "1" {
            continue;
        }
        let (day, minute) = tehran_now();
        if !(210..240).contains(&minute) || app.db.get("auto_update_day") == day.to_string() {
            continue;
        }
        // marked first: the panel restarts itself during the update and must not run it twice
        app.db.set("auto_update_day", &day.to_string());
        let latest = crate::admin::latest_version(&app).await.unwrap_or_default();
        let msg = if latest.is_empty() {
            "GitHub could not be reached; nothing was updated".to_string()
        } else {
            let r = run_update_all(&app).await;
            let nodes = r["nodes"].as_array().map(|a| a.len()).unwrap_or(0);
            let agents = r["agents"].as_array().map(|a| a.len()).unwrap_or(0);
            format!("v{}: panel {}, {} node(s), {} tunnel server(s)", latest, r["panel"].as_str().unwrap_or(""), nodes, agents)
        };
        eprintln!("automatic update: {}", msg);
        app.db.set("auto_update_last", &json!({ "ts": now(), "msg": msg }).to_string());
    }
}

async fn auto_update_get(State(app): St, h: HeaderMap) -> Response {
    let _ = guard!(app, h, "admin");
    let last: Value = serde_json::from_str(&app.db.get("auto_update_last")).unwrap_or(Value::Null);
    Json(json!({ "on": app.db.get("auto_update") == "1", "next": next_run_ts(), "last": last })).into_response()
}

async fn auto_update_put(State(app): St, h: HeaderMap, Json(b): Json<Value>) -> Response {
    let _ = guard!(app, h, "admin");
    let on = b["on"].as_bool().unwrap_or(false);
    app.db.set("auto_update", if on { "1" } else { "" });
    Json(json!({ "ok": true, "on": on, "next": next_run_ts() })).into_response()
}

#[cfg(test)]
mod auto_update_tests {
    #[test]
    fn next_run_is_0330_tehran_within_a_day() {
        let n = super::next_run_ts();
        let now = crate::util::now();
        // 03:30 Tehran (UTC+3:30) is midnight UTC
        assert_eq!(n % 86400, 0);
        assert!(n > now && n <= now + 86400);
        let (_, minute) = super::tehran_now();
        assert!((0..1440).contains(&minute));
    }
}

#[cfg(test)]
mod version_gate_tests {
    use super::{agent_knows, guess_loc, next_transport, Tunnel};

    #[test]
    fn location_is_guessed_from_what_a_server_does() {
        let t = |e: &str, x: &str| Tunnel { entry: e.into(), exit: x.into(), ..Default::default() };
        let list = vec![t("ir", "de"), t("ir2", "local")];
        assert_eq!(guess_loc("ir", &list, "", false), "iran");
        assert_eq!(guess_loc("ir2", &list, "", false), "iran");
        assert_eq!(guess_loc("de", &list, "", false), "abroad");
        assert_eq!(guess_loc("x", &list, "relay", false), "iran");
        assert_eq!(guess_loc("x", &list, "exit", false), "abroad");
        assert_eq!(guess_loc("x", &list, "", true), "iran");
        assert_eq!(guess_loc("x", &list, "", false), "");
    }

    #[test]
    fn old_agents_do_not_get_game_or_faketcp() {
        assert!(!agent_knows("3.5.2", "game"));
        assert!(!agent_knows("3.5.2", "faketcp"));
        assert!(agent_knows("3.5.3", "game"));
        assert!(agent_knows("3.6.0", "faketcp"));
        assert!(agent_knows("3.5.2", "hq"));
        assert!(!agent_knows("2.8.0", "hq"));
        assert!(agent_knows("1.0.0", "tcp"));
        // not reported yet
        assert!(agent_knows("", "game"));
    }

    #[test]
    fn rotation_skips_transports_an_agent_does_not_know() {
        let order: Vec<String> = ["kcp", "game", "faketcp", "tcp"].iter().map(|x| x.to_string()).collect();
        let old = |tr: &str| agent_knows("3.5.2", tr);
        assert_eq!(next_transport(&order, "kcp", old).as_deref(), Some("tcp"));
        assert_eq!(next_transport(&order, "tcp", old).as_deref(), Some("kcp"));
        let new = |tr: &str| agent_knows("3.5.3", tr);
        assert_eq!(next_transport(&order, "kcp", new).as_deref(), Some("game"));
        // current transport not in the list: start from the top
        assert_eq!(next_transport(&order, "ws", old).as_deref(), Some("kcp"));
        // nothing else allowed
        let only: Vec<String> = vec!["kcp".into(), "game".into()];
        assert_eq!(next_transport(&only, "kcp", old), None);
    }
}
