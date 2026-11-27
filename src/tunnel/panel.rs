//! Tunnels in the panel: tunnel servers (lightweight agents, no VPN on them), tunnels between two
//! servers, the endpoint agents talk to, and the copy of the engine that runs on the panel itself.

use super::awg::{self, AwgCfg, AwgSpec};
use super::hy2t::{self, Hy2Cfg, Hy2Spec};
use super::kfwd::{FwdCfg, FwdSpec};
use super::kup::{KupCfg, KupSpec};
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
    /// «without SSL» when it was added: the installer takes a self-signed certificate (KANKI_SSL=0)
    pub no_ssl: bool,
    /// the firewall guard: ufw on with only Kanki's ports and SSH open (`fw::guard_tick`)
    pub fw_guard: bool,
    /// the machine is being replaced (a dead or filtered server moved to a new one): the next join with
    /// `join` updates the existing node `node` instead of adding one, and keeps its cores and ports
    pub replace: bool,
    /// the cores chosen when the server was added (wg, awg, hy2, kmix): switched on when it
    /// joins, the rest stay off. Empty = a server from before: everything installed and off, as always.
    pub cores: Vec<String>,
    /// its agent has sent a signed report (3.65): from then on an unsigned one (the bare token of an
    /// older agent) is refused for it
    pub signed: bool,
    /// 3.69: its agent signed a download request (program, Hysteria2, Xray): the token in the body is refused for
    /// it from then on
    pub signed_dl: bool,
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
    /// kind "fwd": a direct tunnel in the kernel (iptables straight to the exit, or a GRE link)
    #[serde(default, skip_serializing_if = "fwd_unset")]
    pub fwd: FwdCfg,
    /// kind "kup": KANKI-UP, the official udp2raw between the two servers (one pair per UDP port; the exit's raw
    /// ports are `port`, `port + 1`, …)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kup: Option<KupCfg>,
    /// game transport: FEC "data:parity" ("8:3"; "off" disables) and packet duplication
    pub fec: String,
    pub dup: bool,
    /// a multi-location route (Iran → Turkey → Germany) is one tunnel per hop; its hops share this id
    /// ("" = a tunnel of its own). `hop` is the place on the route, 0 = the hop from the first entry.
    pub chain: String,
    pub hop: u8,
    /// the route's name, the same on every hop
    pub chain_name: String,
    /// Game-FEC Pro (`game` with FEC "auto"): the core it carries (`PROFILES`): "kmix" gives the game FEC and
    /// sends the KCP of KANKI MIX without; "wg" or "" the same Game-FEC Pro for that core
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub profile: String,
}

fn fwd_unset(f: &FwdCfg) -> bool {
    f.mode.is_empty() && f.n == 0
}

/// Direct tunnels (kind "fwd") exist from this agent version on: an older one would run them as a Kanki tunnel
const FWD_FROM: &str = "3.59.0";
/// KANKI-UP tunnels (kind "kup") exist from this agent version on
const KUP_FROM: &str = "3.61.0";
/// (3.63) agents measure the ping and loss of KANKI-UP, Hysteria2, AmneziaWG and direct tunnels from this version on
const METER_FROM: &str = "3.63.0";

/// The other server's address for a direct tunnel: the public IPv4 it reports from (a name may sit behind a CDN)
fn fwd_peer(app: &App, sid: &str) -> String {
    // (3.63.2) the last address seen is kept: after a panel restart the entry may ask before the exit reported,
    // and a written name (or a name that resolves elsewhere) would rewrite the tunnel there and restart it,
    // twice. A server that moved reports its new address within seconds.
    let key = format!("tun_peer_ip:{}", sid);
    if let Some(ip) = seen_ip(sid).filter(|ip| ip.parse::<std::net::Ipv4Addr>().is_ok()) {
        if app.db.get(&key) != ip && !crate::migrate::frozen() {
            app.db.set(&key, &ip);
        }
        return ip;
    }
    let kept = app.db.get(&key);
    if kept.parse::<std::net::Ipv4Addr>().is_ok() {
        return kept;
    }
    host_of(app, sid)
}

/// The cores a Game-FEC Pro tunnel can be shaped for
pub const PROFILES: &[&str] = &["", "kmix", "wg"];
/// Game-FEC Pro (FEC "auto", a profile) exists from this agent version on: an older end would drop its
/// plain payloads
const GAME_PRO_FROM: &str = "3.57.0";
/// where a tunnel without a port of its own starts looking for a free one
const AUTO_TUNNEL_PORT: u16 = 20000;

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
    /// the firewall ports Kanki opened here, and the open ones nothing uses (see `fw::report`)
    fw: Value,
    /// every port listened on from outside: [[port, udp, program, unit], ...] (Null = older agent)
    listen: Value,
    /// the VPN install the panel asked for: {state, code, tail} (Null = none)
    setup: Value,
    /// CPU, memory, disk, uptime and sockets of the machine (`admin::node_stats`; Null = older agent)
    stats: Value,
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

/// 3.57.0: the VIP tunnel is gone; the list an older panel kept goes too (nothing is carried over)
pub fn drop_vip(app: &App) {
    let _ = app.db.exec("DELETE FROM settings WHERE k='vip_tunnels'", &[]);
    // 3.60: microtun and KPING are gone; a Game-FEC Pro tunnel shaped for one of them is a plain one now
    let mut l = tunnels(app);
    let mut changed = false;
    for t in l.iter_mut().filter(|t| !PROFILES.contains(&t.profile.as_str())) {
        t.profile.clear();
        changed = true;
    }
    // 3.63: KANKI-UP tunnels made before get their measuring pair (a free raw port on the exit)
    for i in 0..l.len() {
        if l[i].kind == "kup" && l[i].kup.as_ref().is_some_and(|c| c.probe_port == 0 && c.raw_mode != "icmp") {
            let mut t = l[i].clone();
            kup_probe_port(app, &mut t);
            if t.kup.as_ref().is_some_and(|c| c.probe_port > 0) {
                l[i] = t;
                changed = true;
                // the list saved at once: the next one's free port sees this one
                save_tunnels(app, &l);
            }
        }
    }
    if changed {
        save_tunnels(app, &l);
    }
    crate::twin::drop_retired(app);
}

/// The name of a tunnel nobody named, always one shape (3.58.1): the Iran server (short, "IRAN 2" ← "IR2"),
/// the abroad server, then the core it carries or its kind ("IR2-ENGLAND-KMIX"); entry first when both are
/// on the same side.
pub(crate) fn default_tunnel_name(app: &App, entry: &str, exit: &str, tag: &str) -> String {
    if entry.is_empty() || exit.is_empty() {
        return String::new();
    }
    let list = servers(app);
    let name = |id: &str| {
        if id == "local" {
            return local_name(app);
        }
        list.iter().find(|s| s.id == id).map(|s| s.name.trim().to_string()).filter(|n| !n.is_empty()).unwrap_or_else(|| id.to_string())
    };
    let locs = server_locs(app);
    let iran = |id: &str| locs.get(id).map(|l| l.0 == "iran").unwrap_or(false);
    let (a, b) = if iran(exit) && !iran(entry) { (exit, entry) } else { (entry, exit) };
    let part = |s: String| -> String { s.to_uppercase().split_whitespace().collect::<Vec<_>>().join("") };
    let short = |s: String| -> String {
        let u = part(s);
        match u.strip_prefix("IRAN") {
            Some(rest) if rest.chars().all(|c| c.is_ascii_digit() || c == '-') => format!("IR{}", rest.trim_start_matches('-')),
            _ => u,
        }
    };
    let first = if iran(a) { short(name(a)) } else { part(name(a)) };
    let mut n = format!("{}-{}", first, part(name(b)));
    if !tag.is_empty() {
        n.push('-');
        n.push_str(&tag.to_uppercase());
    }
    let n: String = n.chars().filter(|c| !c.is_control() && !"<>\"".contains(*c)).collect();
    n.chars().take(60).collect()
}

fn local_name(app: &App) -> String {
    app.env.get("LOCAL_NAME").cloned().filter(|s| !s.is_empty()).unwrap_or_else(|| "Main".into())
}

/// The address other servers use to reach server `sid`.
pub(crate) fn host_of(app: &App, sid: &str) -> String {
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
    seen().lock().unwrap_or_else(|e| e.into_inner()).get(sid).map(|x| x.ip.clone()).unwrap_or_default()
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
pub(crate) fn specs_for(app: &App, sid: &str) -> Vec<Spec> {
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
    if let Some(p) = probe_job().lock().unwrap_or_else(|e| e.into_inner()).as_ref() {
        if !p.finished && now() - p.started < PROBE_MAX {
            all.extend(p.extras.iter().cloned());
        }
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
        if t.kind == "fwd" {
            let peer = fwd_peer(app, if role == "entry" { &t.exit } else { &t.entry });
            let f = FwdSpec { tid: t.id.clone(), role: role.into(), mode: t.fwd.mode.clone(), peer, n: t.fwd.n, tcp: t.tcp.clone(), udp: t.udp.clone(), target: t.target.clone() };
            out.push(Spec { id: t.id.clone(), name: t.name.clone(), role: role.into(), transport: "fwd".into(), tcp: t.tcp.clone(), udp: t.udp.clone(), fwd: Some(f), ..Default::default() });
            continue;
        }
        if t.kind == "kup" {
            let k = kup_specs(app, &t, role);
            out.push(Spec { id: t.id.clone(), name: t.name.clone(), role: role.into(), mode: "direct".into(), transport: "kup".into(), udp: t.udp.clone(), kup: Some(k), ..Default::default() });
            continue;
        }
        if t.kind == "hy2" {
            let y = hy2_spec(app, &t, role);
            out.push(Spec { id: t.id.clone(), name: t.name.clone(), role: role.into(), transport: "hy2".into(), hy2: Some(y), ..Default::default() });
            continue;
        }
        // 3.69: a Kanki tunnel that carries a server's KANKI MIX port carries its hop ports too (client port
        // hopping through the Iran entry); worked out at each sync from what the server runs
        let mut udp = t.udp.clone();
        udp.extend(kmix_hop_map(app, &t).into_iter().map(|(a, b)| format!("{}:{}", a, b)));
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
            udp,
            target: t.target.clone(),
            cert: String::new(),
            key: String::new(),
            probe: false,
            bind: if t.kind == "awgwrap" { "127.0.0.1".into() } else { String::new() },
            awg: None,
            hy2: None,
            fwd: None,
            kup: None,
            fec: t.fec.clone(),
            dup: t.dup,
            profile: if t.transport == "game" { t.profile.clone() } else { String::new() },
        });
    }
    // a running smart-tunnel test adds one short-lived test tunnel per transport and per direction:
    // reverse (the exit dials the entry) on the first six ports, direct (the entry dials the exit)
    // on the next six
    if let Some(p) = probe_job().lock().unwrap_or_else(|e| e.into_inner()).clone() {
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
                    fwd: None,
                    kup: None,
                    fec: String::new(),
                    dup: false,
                    profile: String::new(),
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
                        fwd: None,
                        kup: None,
                        fec: String::new(),
                        dup: false,
                        profile: String::new(),
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
/// The machine stats a tunnel server last sent (Null = none yet, or an older agent)
/// The last warnings and errors each agent reported (server id -> [{ts, p, u, m}])
fn agent_logs() -> &'static Mutex<HashMap<String, Value>> {
    static L: OnceLock<Mutex<HashMap<String, Value>>> = OnceLock::new();
    L.get_or_init(Default::default)
}

pub(crate) fn agent_log_lines(sid: &str) -> Value {
    agent_logs().lock().unwrap_or_else(|e| e.into_inner()).get(sid).cloned().unwrap_or_else(|| json!([]))
}

pub(crate) fn agent_stats(sid: &str) -> Value {
    seen().lock().unwrap_or_else(|e| e.into_inner()).get(sid).map(|x| x.stats.clone()).unwrap_or(Value::Null)
}

/// One server asked to update (Servers > ⋯ > Update): until when it may take the panel's program
fn update_one_until(app: &App, sid: &str) -> i64 {
    serde_json::from_str::<HashMap<String, i64>>(&app.db.get("tun_update_one")).unwrap_or_default().get(sid).copied().unwrap_or(0)
}

/// Lets one tunnel server (an Iran server too) take the panel's program in the next 15 minutes
pub(crate) fn ask_update_one(app: &App, sid: &str) {
    let t = now();
    let mut m: HashMap<String, i64> = serde_json::from_str(&app.db.get("tun_update_one")).unwrap_or_default();
    m.retain(|_, until| *until > t);
    m.insert(sid.to_string(), t + 900);
    app.db.set("tun_update_one", &serde_json::to_string(&m).unwrap_or_else(|_| "{}".into()));
}

pub(crate) fn agent_state(sid: &str) -> Option<(i64, String, String, Value)> {
    seen().lock().unwrap_or_else(|e| e.into_inner()).get(sid).map(|x| (x.at, x.version.clone(), x.ip.clone(), x.setup.clone()))
}

/// Tests: agent `sid` reported just now with `version`
#[cfg(test)]
pub(crate) fn test_seen(sid: &str, version: &str) {
    seen().lock().unwrap_or_else(|e| e.into_inner()).insert(sid.to_string(), Seen { at: now(), version: version.to_string(), ..Default::default() });
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
    seen().lock().unwrap_or_else(|e| e.into_inner()).get(sid).and_then(|x| x.status.iter().find(|s| s.id == id).map(|s| s.links)).unwrap_or(0)
}

/// What server `sid` last reported about its tunnel `id` (None = it does not run it, or never reported)
pub(crate) fn status_of(sid: &str, id: &str) -> Option<super::engine::Status> {
    seen().lock().unwrap_or_else(|e| e.into_inner()).get(sid).and_then(|x| x.status.iter().find(|s| s.id == id).cloned())
}

/// The address an agent server last reported from (DNS answers it for routed names).
pub(crate) fn seen_ip(sid: &str) -> Option<String> {
    seen().lock().unwrap_or_else(|e| e.into_inner()).get(sid).map(|x| x.ip.clone()).filter(|x| !x.is_empty())
}

/// "host:port" other servers dial server `sid` on.
pub(crate) fn dial_addr(app: &App, sid: &str, port: u16) -> String {
    hostport(&host_of(app, sid), port)
}

/// "iran" or "abroad" when written, else "".
fn clean_loc(v: &str) -> String {
    if v == "iran" || v == "abroad" { v.to_string() } else { String::new() }
}

/// Where a server whose location is not set probably is, from what it does: a DNS relay, the Iran
/// subscription and a tunnel entry are inside Iran; a DNS exit or a tunnel exit is abroad.
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
        let jobs = crate::subiran::settings(app).server == s.id;
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
    let names: HashMap<String, String> = servers(app).into_iter().map(|s| (s.id, s.name)).collect();
    let sn = seen().lock().unwrap_or_else(|e| e.into_inner());
    // Game-FEC Pro sends payloads an older agent drops: both ends must be new
    if t.enabled && t.transport == "game" && t.fec == "auto" {
        for sid in [&t.entry, &t.exit] {
            if let Some(x) = sn.get(sid.as_str()) {
                if !x.version.is_empty() && ver_lt(&x.version, GAME_PRO_FROM) {
                    return Err(format!("the agent of \"{}\" is v{}: update it first (Update all), Game-FEC Pro needs {}", names.get(sid.as_str()).cloned().unwrap_or_default(), x.version, GAME_PRO_FROM));
                }
            }
        }
    }
    if !t.enabled || !std::iter::once(&t.transport).chain(t.order.iter()).any(|tr| is_new_transport(tr)) {
        return Ok(());
    }
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
        let sn = seen().lock().unwrap_or_else(|e| e.into_inner());
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
        // the measuring forward (UDP; the stats API on the same number is TCP)
        probe: 61000 + c.n as u16,
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
/// The direct tunnel part of a request: the mode, and for GRE a link number no other direct tunnel uses
fn fwd_apply_body(list: &[Tunnel], t: &mut Tunnel, f: &Value) -> Result<(), String> {
    if let Some(m) = f["mode"].as_str() {
        t.fwd.mode = m.to_string();
    }
    if t.fwd.mode.is_empty() {
        t.fwd.mode = "nat".into();
    }
    if !matches!(t.fwd.mode.as_str(), "nat" | "gre") {
        return Err("the direct tunnel is nat or gre".into());
    }
    t.transport = "fwd".into();
    t.port = 0;
    t.auto = false;
    t.mode = "direct".into();
    if t.fwd.gre() {
        if t.fwd.n == 0 {
            let used: HashSet<u8> = list.iter().filter(|o| o.kind == "fwd" && o.id != t.id).map(|o| o.fwd.n).collect();
            t.fwd.n = (1..=250u8).find(|n| !used.contains(n)).ok_or("every GRE link number is in use")?;
        }
    } else {
        t.fwd.n = 0;
    }
    if !t.target.trim().is_empty() && t.target.trim().parse::<std::net::Ipv4Addr>().is_err() {
        return Err("the target on the exit must be an IPv4 address".into());
    }
    Ok(())
}

/// KANKI-UP: the udp2raw pair of every forwarded UDP port of tunnel `t` on server `role`. The exit's raw port
/// of the i-th UDP port is `port + i`; the entry dials the exit's public IPv4 (or the address written in `dial`).
fn kup_specs(app: &App, t: &Tunnel, role: &str) -> Vec<KupSpec> {
    let cfg = t.kup.clone().unwrap_or_default();
    let exit_host = if !t.dial.trim().is_empty() { t.dial.trim().to_string() } else { fwd_peer(app, &t.exit) };
    let mut v: Vec<KupSpec> = parse_ports(&t.udp)
        .into_iter()
        .enumerate()
        .map(|(i, (a, b))| {
            let raw = t.port.saturating_add(i as u16);
            let (listen, host, port) = if role == "entry" { (a, exit_host.clone(), raw) } else { (raw, t.target.trim().to_string(), b) };
            KupSpec { tid: t.id.clone(), name: t.name.clone(), role: role.into(), idx: i as u16, listen, host, port, cfg: cfg.clone(), probe: false }
        })
        .collect();
    // (3.63) the small measuring pair: ping, loss and jitter through the tunnel (the agents pick its local ends)
    if cfg.probe_port > 0 && cfg.raw_mode != "icmp" && (!v.is_empty() || t.id.starts_with("probe-")) {
        let (listen, host, port) = if role == "entry" { (0, exit_host, cfg.probe_port) } else { (cfg.probe_port, String::new(), 0) };
        v.push(KupSpec { tid: t.id.clone(), name: t.name.clone(), role: role.into(), idx: v.len() as u16, listen, host, port, cfg, probe: true });
    }
    v
}

/// (3.63) The raw port of a KANKI-UP's measuring pair on the exit: kept while it is still free and out of the
/// tunnel's own row, else the first free one after the row (ICMP has no ports: none)
fn kup_probe_port(app: &App, t: &mut Tunnel) {
    let Some(c) = t.kup.as_mut() else { return };
    let n = parse_ports(&t.udp).len() as u16;
    if c.raw_mode == "icmp" || t.port == 0 || n == 0 {
        c.probe_port = 0;
        return;
    }
    let row = t.port..t.port.saturating_add(n);
    if c.probe_port > 0 && !row.contains(&c.probe_port) {
        return;
    }
    c.probe_port = free_ports(app, &t.exit, t.port.saturating_add(n), 1).filter(|p| !row.contains(p)).unwrap_or(0);
}

/// The KANKI-UP part of a request: udp2raw's options (only the known values), a key made here the first time.
/// UDP only, one udp2raw pair per port; ICMP has no port numbers, so it carries one port.
fn kup_apply_body(t: &mut Tunnel, k: &Value) -> Result<(), String> {
    let mut c = t.kup.clone().unwrap_or_default();
    let s = |n: &str| k[n].as_str().map(|v| v.trim().to_string());
    if let Some(v) = s("raw_mode") {
        c.raw_mode = v;
    }
    if let Some(v) = s("cipher") {
        c.cipher = v;
    }
    if let Some(v) = s("auth") {
        c.auth = v;
    }
    if let Some(v) = k["seq_mode"].as_u64() {
        c.seq_mode = v.min(255) as u8;
    }
    if let Some(v) = k["fix_gro"].as_bool() {
        c.fix_gro = v;
    }
    if let Some(v) = k["anti_replay"].as_bool() {
        c.anti_replay = v;
    }
    if let Some(v) = k["hb_len"].as_u64() {
        c.hb_len = v.min(65535) as u16;
    }
    if let Some(v) = k["mtu_warn"].as_u64() {
        c.mtu_warn = v.min(65535) as u16;
    }
    if let Some(v) = k["sock_buf"].as_u64() {
        c.sock_buf = v.min(65535) as u16;
    }
    if let Some(v) = k["force_sock_buf"].as_bool() {
        c.force_sock_buf = v;
    }
    if let Some(v) = k["lower_level"].as_bool() {
        c.lower_level = v;
    }
    // a key is never sent back to the browser: empty keeps the one there is; "new_key" makes another
    if k["new_key"].as_bool() == Some(true) || !super::kup::key_ok(&c.key) {
        c.key = rand_token(32);
    }
    c.check()?;
    t.transport = "kup".into();
    t.mode = "direct".into();
    t.auto = false;
    t.order.clear();
    if !t.tcp.is_empty() {
        return Err("KANKI-UP carries UDP ports only (WireGuard, AmneziaWG, KANKI MIX, Hysteria2 …): remove the TCP ports".into());
    }
    let n = parse_ports(&t.udp).len();
    if n > super::kup::MAX_PORTS {
        return Err(format!("KANKI-UP carries at most {} UDP ports", super::kup::MAX_PORTS));
    }
    if c.raw_mode == "icmp" && n > 1 {
        return Err("in ICMP mode KANKI-UP carries one UDP port (ICMP has no port numbers): make one tunnel per port".into());
    }
    if t.port > 0 && (t.port as usize) + n.max(1) - 1 > 65535 {
        return Err("the raw ports of the exit go past 65535: pick a smaller first port".into());
    }
    if !t.target.trim().is_empty() && t.target.trim().parse::<std::net::Ipv4Addr>().is_err() {
        return Err("the target on the exit must be an IPv4 address".into());
    }
    if !t.dial.trim().is_empty() && super::kfwd::resolve(t.dial.trim()).is_none() && !t.dial.trim().chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-') {
        return Err("the exit address is an IPv4 address or a domain".into());
    }
    t.kup = Some(c);
    Ok(())
}

/// Both ends must know KANKI-UP
fn kup_checks(app: &App, t: &Tunnel) -> Result<(), String> {
    if !t.enabled {
        return Ok(());
    }
    let names: HashMap<String, String> = servers(app).into_iter().map(|s| (s.id, s.name)).collect();
    let sn = seen().lock().unwrap_or_else(|e| e.into_inner());
    for sid in [&t.entry, &t.exit] {
        if sid == "local" {
            continue;
        }
        if let Some(x) = sn.get(sid.as_str()) {
            if !x.version.is_empty() && ver_lt(&x.version, KUP_FROM) {
                return Err(format!("the agent of \"{}\" is v{}: update it first (Update all), KANKI-UP needs {}", names.get(sid.as_str()).cloned().unwrap_or_default(), x.version, KUP_FROM));
            }
        }
    }
    Ok(())
}

/// Both ends must know direct tunnels; the two servers must be different machines
fn fwd_checks(app: &App, t: &Tunnel) -> Result<(), String> {
    let names: HashMap<String, String> = servers(app).into_iter().map(|s| (s.id, s.name)).collect();
    let sn = seen().lock().unwrap_or_else(|e| e.into_inner());
    for sid in [&t.entry, &t.exit] {
        if sid == "local" {
            continue;
        }
        if let Some(x) = sn.get(sid.as_str()) {
            if !x.version.is_empty() && ver_lt(&x.version, FWD_FROM) {
                return Err(format!("the agent of \"{}\" is v{}: update it first (Update all), a direct tunnel needs {}", names.get(sid.as_str()).cloned().unwrap_or_default(), x.version, FWD_FROM));
            }
        }
    }
    drop(sn);
    if parse_ports(&t.tcp).is_empty() && parse_ports(&t.udp).is_empty() {
        return Err("add at least one TCP or UDP port to forward".into());
    }
    let (a, b) = (fwd_peer(app, &t.entry), fwd_peer(app, &t.exit));
    if !a.is_empty() && a == b {
        return Err("the entry and the exit are the same machine".into());
    }
    Ok(())
}

fn hy2_checks(app: &App, t: &Tunnel) -> Result<(), String> {
    if !t.enabled {
        return Ok(());
    }
    let names: HashMap<String, String> = servers(app).into_iter().map(|s| (s.id, s.name)).collect();
    let sn = seen().lock().unwrap_or_else(|e| e.into_inner());
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

/// The hysteria binary for a CPU type, 3.69: only the pinned release (`release::hy2_sha256`): the panel server's own
/// copy when it is exactly that file, a copy kept in CACHE_DIR that still has the pinned hash, or downloaded now
/// from the pinned release (and checked before it is kept).
async fn hy2bin_bytes(arch: &str, fetch: bool) -> Option<Vec<u8>> {
    let a = hy2t::arch_name(arch)?;
    let want = crate::release::hy2_sha256(a)?;
    if arch == std::env::consts::ARCH {
        for p in ["/usr/local/bin/hysteria", "/usr/bin/hysteria"] {
            if let Ok(b) = tokio::fs::read(p).await {
                if crate::release::matches(&b, want) {
                    return Some(b);
                }
            }
        }
    }
    let cache = format!("{}/hysteria-linux-{}-{}", hy2t::CACHE_DIR, a, crate::release::HY2_VERSION);
    let cached = || async {
        match tokio::fs::read(&cache).await {
            Ok(b) if crate::release::matches(&b, want) => Some(b),
            _ => None,
        }
    };
    if let Some(b) = cached().await {
        return Some(b);
    }
    if !fetch {
        return None;
    }
    // one download at a time (two agents asking at once must not download twice)
    static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    let _g = LOCK.lock().await;
    if let Some(b) = cached().await {
        return Some(b);
    }
    let http = reqwest::Client::builder().timeout(Duration::from_secs(180)).build().ok()?;
    for url in hy2t::download_urls(arch) {
        match http.get(&url).send().await {
            Ok(r) if r.status().is_success() => match r.bytes().await {
                Ok(b) if crate::release::matches(&b, want) => {
                    if let Err(e) = tokio::fs::create_dir_all(hy2t::CACHE_DIR).await {
                        eprintln!("hy2 tunnel: {}: {}", hy2t::CACHE_DIR, e);
                    } else if let Err(e) = tokio::fs::write(&cache, &b).await {
                        eprintln!("hy2 tunnel: {}: {}", cache, e);
                    }
                    eprintln!("hy2 tunnel: downloaded {} (pinned SHA-256 checked) for the agents", url);
                    return Some(b.to_vec());
                }
                Ok(_) => eprintln!("hy2 tunnel: {} is not the pinned release (filtered or changed?): not used", url),
                Err(e) => eprintln!("hy2 tunnel: {}: {}", url, e),
            },
            Ok(r) => eprintln!("hy2 tunnel: {}: {}", url, r.status()),
            Err(e) => eprintln!("hy2 tunnel: {}: {}", url, e),
        }
    }
    None
}

/// 3.69: a server agent's download request (`/tunnel/binary`, `/tunnel/hy2bin`, `/tunnel/xraybin`): signed with
/// its token (`sign`, path `path`), or, until that server once signed one, the token in the body as before.
/// The server on success.
#[allow(clippy::result_large_err)] // the error is the ready axum answer
pub(crate) fn agent_dl_auth(app: &App, h: &HeaderMap, path: &str, raw: &[u8], b: &Value) -> Result<TServer, Response> {
    let id = b["id"].as_str().unwrap_or("");
    let Some(s) = servers(app).into_iter().find(|s| s.id == id) else {
        return Err((StatusCode::GONE, "unknown server").into_response());
    };
    if crate::sign::is_signed(h) {
        if let Err(r) = crate::sign::verify(&s.token, h, "POST", path, raw, now()) {
            return Err(err(StatusCode::UNAUTHORIZED, r.text()));
        }
        if !s.signed_dl {
            let mut list = servers(app);
            if let Some(x) = list.iter_mut().find(|x| x.id == s.id) {
                x.signed_dl = true;
                save_servers(app, &list);
            }
        }
        return Ok(s);
    }
    if s.signed_dl {
        return Err(err(StatusCode::UNAUTHORIZED, crate::sign::Refusal::Unsigned.text()));
    }
    let token = b["token"].as_str().unwrap_or("");
    if token.is_empty() || !util::ct_eq(token, &s.token) {
        return Err(err(StatusCode::FORBIDDEN, "wrong token"));
    }
    Ok(s)
}

/// 3.69: the answer to a signed request of a server agent is signed too (its token, bound to the request's
/// nonce, the status and the body); an answer to an unsigned one (an agent from before) is left unsigned
pub(crate) fn signed_answer(token: &str, h: &HeaderMap, status: StatusCode, headers: &[(&'static str, String)], body: Vec<u8>) -> Response {
    let sig = crate::sign::nonce_of(h).map(|n| crate::sign::reply_headers(token, &n, status.as_u16(), &body)).unwrap_or_default();
    let mut res = (status, body).into_response();
    for (k, v) in headers.iter().chain(sig.iter()) {
        if let Ok(v) = axum::http::HeaderValue::from_str(v) {
            res.headers_mut().insert(*k, v);
        }
    }
    res
}

/// `signed_answer` of a JSON value
pub(crate) fn signed_json(token: &str, h: &HeaderMap, status: StatusCode, v: &Value) -> Response {
    signed_answer(token, h, status, &[("content-type", "application/json".to_string())], serde_json::to_vec(v).unwrap_or_default())
}

/// a tunnel server's id and token are right (used before a big upload is read)
pub fn agent_token_ok(app: &App, id: &str, token: &str) -> bool {
    !token.is_empty() && servers(app).into_iter().any(|s| s.id == id && util::ct_eq(token, &s.token))
}


/// Public (agent token): the hysteria binary for a tunnel server that cannot download it itself.
/// With "check": only says whether the panel already has one for that CPU type.
pub const HY2BIN_PATH: &str = "/tunnel/hy2bin";

async fn agent_hy2bin(State(app): St, h: HeaderMap, raw: axum::body::Bytes) -> Response {
    let Ok(b) = serde_json::from_slice::<Value>(&raw) else { return err(StatusCode::BAD_REQUEST, "send JSON") };
    let s = match agent_dl_auth(&app, &h, HY2BIN_PATH, &raw, &b) {
        Ok(s) => s,
        Err(r) => return r,
    };
    let arch = b["arch"].as_str().unwrap_or("").to_string();
    // 3.69: an agent from before asks whether the panel has a copy, then uploads its own when it has none. Nothing
    // is ever taken from an agent (it would run as root on every other server): the answer is always «have»,
    // the panel gets the pinned release itself when one is asked for
    if b["check"].as_bool() == Some(true) {
        return signed_json(&s.token, &h, StatusCode::OK, &json!({ "have": true }));
    }
    let Some(bytes) = hy2bin_bytes(&arch, true).await else {
        return err(StatusCode::NOT_FOUND, "the panel has no hysteria for this CPU type and cannot download it either");
    };
    let sum = crate::release::sha256_hex(&bytes);
    signed_answer(&s.token, &h, StatusCode::OK, &[("x-sha256", sum)], bytes)
}

// ------------------------------------------------------------------ smart tunnel (test every transport)

const PROBE_TRANSPORTS: &[&str] = &["tcpmux", "tcp", "ws", "wss", "quic", "kcp", "hq", "h2", "game", "faketcp"];
/// (3.63) the other tunnel kinds a test can try, entry → exit: each one a real tunnel of that kind for the time of
/// the test, measured with 20 small UDP packets through it (KANKI-UP, Hysteria2) or pings through its link (AmneziaWG,
/// GRE). They carry no test download: ping, loss and jitter only, what a game feels. Direct NAT adds nothing to the
/// line, so the raw ping is its number.
const PROBE_KINDS: &[&str] = &["kup-faketcp", "kup-udp", "kup-easy-faketcp", "hy2", "awg", "gre"];
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
    /// (3.63) the other kinds: a tunnel of each, made for the test (keys and all), dropped when it ends
    extras: Vec<Tunnel>,
}

/// A tunnel of another kind for a test (`kind` one of PROBE_KINDS), on `port`, with its own keys
fn probe_extra(app: &App, id: &str, kind: &str, entry: &str, exit: &str, port: u16) -> Result<Tunnel, String> {
    let mut t = Tunnel {
        id: format!("probe-{}-x-{}", id, kind.replace('-', "")),
        name: format!("test {}", kind),
        entry: entry.into(),
        exit: exit.into(),
        enabled: true,
        mode: "direct".into(),
        port,
        token: rand_token(32),
        ..Default::default()
    };
    let list = tunnels(app);
    match kind {
        "hy2" => {
            t.kind = "hy2".into();
            hy2_apply_body(&list, &mut t, &json!({ "port": port, "obfs": true }))?;
        }
        "awg" => {
            t.kind = "awg".into();
            awg_apply_body(&list, &mut t, &json!({ "port": port }))?;
        }
        "gre" => {
            t.kind = "fwd".into();
            fwd_apply_body(&list, &mut t, &json!({ "mode": "gre" }))?;
        }
        k => {
            let m = k.strip_prefix("kup-").ok_or("unknown kind")?;
            t.kind = "kup".into();
            kup_apply_body(&mut t, &json!({ "raw_mode": m }))?;
            t.port = port;
            if let Some(c) = t.kup.as_mut() {
                c.probe_port = port;
            }
        }
    }
    Ok(t)
}

/// (3.63) one udp-only measurement → the shape of a transport's result (no download, so no speed scores)
fn probe_extra_result(q: Option<&Value>, error: &str, waited: i64) -> Value {
    match q {
        Some(q) if q["loss"].as_f64().unwrap_or(100.0) < 100.0 => {
            let ping = q["ping"].as_f64().unwrap_or(0.0);
            let loss = q["loss"].as_f64().unwrap_or(0.0);
            let ping_s = (1.0 - ping / 400.0).clamp(0.0, 1.0);
            let udp_s = (1.0 - loss / 100.0).clamp(0.0, 1.0).powi(2);
            let g = (100.0 * (0.53 * ping_s + 0.47 * udp_s)).round();
            json!({ "done": true, "udp_only": true, "ping_ms": q["ping"], "udp_ping_ms": q["ping"], "udp_loss": loss, "jitter": q["jit"],
                "scores": { "gaming": g, "balanced": Value::Null, "speed": Value::Null } })
        }
        _ if waited >= 90 => json!({ "done": true, "udp_only": true, "error": if error.is_empty() { "nothing came back through the tunnel" } else { error },
            "scores": { "gaming": 0, "balanced": Value::Null, "speed": Value::Null } }),
        _ => json!({ "done": false, "stage": "testing" }),
    }
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

/// What a smart test was asked for: (Kanki transports, other kinds). Nothing named = all; only other kinds ticked
/// (3.63.1: KANKI-UP alone) = no Kanki transport at all, not all of them
fn probe_wanted(b: &Value) -> (Vec<String>, Vec<String>) {
    let kinds: Vec<String> = match b["kinds"].as_array() {
        Some(a) => a.iter().filter_map(|x| x.as_str()).filter(|x| PROBE_KINDS.contains(x)).map(|x| x.to_string()).collect(),
        None => PROBE_KINDS.iter().map(|x| x.to_string()).collect(),
    };
    let picked_kinds = b["kinds"].as_array().is_some() && !kinds.is_empty();
    let transports: Vec<String> = match b["transports"].as_array() {
        Some(a) => {
            let picked: Vec<String> = a.iter().filter_map(|x| x.as_str()).filter(|x| PROBE_TRANSPORTS.contains(x)).map(|x| x.to_string()).collect();
            if picked.is_empty() && !picked_kinds { PROBE_TRANSPORTS.iter().map(|x| x.to_string()).collect() } else { picked }
        }
        None => PROBE_TRANSPORTS.iter().map(|x| x.to_string()).collect(),
    };
    (transports, kinds)
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
    let (transports, kinds_wanted) = probe_wanted(&b);
    let kinds_only = !kinds_wanted.is_empty() && b["kinds"].as_array().is_some();
    // an agent too old for a transport would run it as plain TCP and report plain-TCP numbers
    // under its name: such transports are left out of the test
    let (transports, skipped): (Vec<String>, Vec<String>) = {
        let sn = seen().lock().unwrap_or_else(|e| e.into_inner());
        let ver = |sid: &str| sn.get(sid).map(|x| x.version.clone()).unwrap_or_default();
        let (ve, vx) = (ver(&entry), ver(&exit));
        transports.into_iter().partition(|tr| agent_knows(&ve, tr) && agent_knows(&vx, tr))
    };
    if transports.is_empty() && !kinds_only {
        return err(StatusCode::BAD_REQUEST, &format!("the agents are too old for {}: update them first (Update all)", skipped.join(", ")));
    }
    let baseline = b["baseline"].as_bool().unwrap_or(true);
    // (3.63) the other kinds asked for (none = all), each only where both agents measure them
    let kinds = kinds_wanted;
    let (kinds, too_old): (Vec<String>, Vec<String>) = {
        let sn = seen().lock().unwrap_or_else(|e| e.into_inner());
        let ok = |sid: &str| sid == "local" || sn.get(sid).map(|x| !x.version.is_empty() && !ver_lt(&x.version, METER_FROM)).unwrap_or(false);
        let both = ok(&entry) && ok(&exit);
        kinds.into_iter().partition(|_| both)
    };
    if transports.is_empty() && kinds.is_empty() {
        // which server it is, by name: not reporting at all, or an agent older than the measuring
        let sn = seen().lock().unwrap_or_else(|e| e.into_inner());
        let names: HashMap<String, String> = servers(&app).into_iter().map(|s| (s.id, s.name)).collect();
        let why: Vec<String> = [&entry, &exit]
            .into_iter()
            .filter(|sid| sid.as_str() != "local")
            .filter_map(|sid| {
                let n = names.get(sid.as_str()).cloned().unwrap_or_else(|| sid.to_string());
                match sn.get(sid.as_str()) {
                    None => Some(format!("\"{}\" is not connected", n)),
                    Some(x) if x.version.is_empty() || ver_lt(&x.version, METER_FROM) => Some(format!("\"{}\" runs agent v{}", n, if x.version.is_empty() { "?" } else { &x.version })),
                    _ => None,
                }
            })
            .collect();
        return err(StatusCode::BAD_REQUEST, &format!("these tests need agent {} on both servers ({}): update them first (Update all)", METER_FROM, why.join(", ")));
    }
    let skipped: Vec<String> = skipped.into_iter().chain(too_old).collect();
    // the test ports must not collide with a tunnel that already listens there (on either server)
    let span = (transports.len() * PROBE_MODES.len() + kinds.len()) as u16;
    for t in tunnels(&app) {
        let l = if t.mode == "direct" { &t.exit } else { &t.entry };
        if (*l == entry || *l == exit) && t.port >= port && t.port < port + span {
            return err(StatusCode::BAD_REQUEST, &format!("port {} is used by tunnel {}; pick another test port", t.port, t.name));
        }
    }
    // … nor a port another tunnel forwards there, nor one a program holds there now (the test listens on
    // TCP and UDP of each port on both servers)
    for t in tunnels(&app).into_iter().filter(|t| t.enabled && (t.entry == entry || t.entry == exit)) {
        if let Some(p) = parse_ports(&t.tcp).into_iter().chain(parse_ports(&t.udp)).map(|x| x.0).find(|p| *p >= port && *p < port + span) {
            return err(StatusCode::BAD_REQUEST, &format!("port {} is used by tunnel {}; pick another test port", p, t.name));
        }
    }
    for sid in [&entry, &exit] {
        for p in port..port + span {
            if let Some(e) = port_busy(&app, sid, p, false, &[]).or_else(|| port_busy(&app, sid, p, true, &[])) {
                return err(StatusCode::BAD_REQUEST, &e);
            }
        }
    }
    let jid = rand_token(6).to_lowercase();
    let mut extras = vec![];
    for (i, k) in kinds.iter().enumerate() {
        let p = port + (transports.len() * PROBE_MODES.len() + i) as u16;
        match probe_extra(&app, &jid, k, &entry, &exit, p) {
            Ok(t) => extras.push(t),
            Err(e) => return err(StatusCode::BAD_REQUEST, &format!("{}: {}", k, e)),
        }
    }
    let job = ProbeJob {
        id: jid,
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
        extras,
    };
    let id = job.id.clone();
    *probe_job().lock().unwrap_or_else(|e| e.into_inner()) = Some(job);
    let note = if skipped.is_empty() {
        String::new()
    } else {
        format!("not tested, an agent is too old for them (update it first): {}", skipped.join(", "))
    };
    Json(json!({"ok": true, "id": id, "transports": transports, "kinds": kinds, "skipped": skipped, "note": note, "baseline": baseline, "modes": PROBE_MODES})).into_response()
}

async fn probe_get(State(app): St, h: HeaderMap) -> Response {
    let _ = guard!(app, h, "nodes");
    let mut g = probe_job().lock().unwrap_or_else(|e| e.into_inner());
    let Some(p) = g.as_mut() else { return Json(json!({"job": null})).into_response() };
    let t = now();
    if !p.finished {
        let seen = seen().lock().unwrap_or_else(|e| e.into_inner()).clone();
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
        for x in &p.extras {
            let es = entry_st.iter().find(|s| s.id == x.id);
            let xs = exit_st.iter().find(|s| s.id == x.id);
            let e = es.map(|s| s.error.clone()).filter(|e| !e.is_empty()).or_else(|| xs.map(|s| s.error.clone()).filter(|e| !e.is_empty())).unwrap_or_default();
            let mut r = probe_extra_result(es.and_then(|s| s.quality.as_ref()), &e, t - p.started);
            if r["done"].as_bool() != Some(true) {
                all_done = false;
            }
            let k = x.id.rsplit('-').next().unwrap_or("").to_string();
            r["mode"] = json!("direct");
            r["transport"] = json!(PROBE_KINDS.iter().find(|z| z.replace('-', "") == k).copied().unwrap_or(""));
            r["kind"] = json!(true);
            r["port"] = json!(x.port);
            r["links"] = json!(es.map(|s| s.links).unwrap_or(0).max(xs.map(|s| s.links).unwrap_or(0)));
            res.push(r);
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
    if let Some(p) = probe_job().lock().unwrap_or_else(|e| e.into_inner()).as_mut() {
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
    let seen = seen().lock().unwrap_or_else(|e| e.into_inner()).clone();
    let fresh = |sid: &str| seen.get(sid).map(|x| t - x.at < 20).unwrap_or(false);
    let mut list = tunnels(app);
    let list_before = list.clone();
    let mut changed = false;
    let mut ds = down_since().lock().unwrap_or_else(|e| e.into_inner());
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
        // … and only a transport whose port is free there (tcp → kcp moves the port to UDP, where another
        // tunnel, a forwarded port, a VIP tunnel or a service may already be)
        let snapshot = list_before.clone();
        let Some(next) = next_transport(&order, &tu.transport, |tr| agent_knows(ver(&tu.entry), tr) && agent_knows(ver(&tu.exit), tr) && !rotate_clash(app, &snapshot, tu, tr)) else {
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

/// Would tunnel `tu`, switched to transport `tr` (and to reverse mode, as a switch does), need a port that is
/// taken on its listening server: by another tunnel (its own port or a forwarded one), by its own forwarded
/// ports, or (as the server last said) by another program?
fn rotate_clash(app: &App, list: &[Tunnel], tu: &Tunnel, tr: &str) -> bool {
    let listener = &tu.entry;
    let (tcp, udp) = port_protos(tr);
    let port = tu.port;
    let fwd = |l: &[String]| -> Vec<u16> { parse_ports(l).into_iter().map(|p| p.0).collect() };
    if (tcp && fwd(&tu.tcp).contains(&port)) || (udp && fwd(&tu.udp).contains(&port)) {
        return true;
    }
    for o in list.iter().filter(|o| o.id != tu.id && o.enabled && !(o.kind == "awg" && !o.awg.wrap)) {
        let o_listener = if o.mode == "direct" { &o.exit } else { &o.entry };
        let (ot, ou) = port_protos(&o.transport);
        if o_listener == listener && o.port == port && ((tcp && ot) || (udp && ou)) {
            return true;
        }
        if &o.entry == listener && ((tcp && fwd(&o.tcp).contains(&port)) || (udp && fwd(&o.udp).contains(&port))) {
            return true;
        }
    }
    // a protocol the tunnel does not hold now: whoever listens there is someone else
    let (now_tcp, now_udp) = if tu.mode == "direct" { (false, false) } else { port_protos(&tu.transport) };
    (tcp && !now_tcp && port_busy(app, listener, port, false, &[]).is_some()) || (udp && !now_udp && port_busy(app, listener, port, true, &[]).is_some())
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
        note_report("local", &st, false, false);
        seen().lock().unwrap_or_else(|e| e.into_inner()).insert(
            "local".into(),
            Seen { at: now(), version: crate::VERSION.into(), ip: host_of(&app, "local"), status: st, fw: Value::Null, listen: Value::Null, setup: Value::Null, stats: Value::Null },
        );
        // the newest live measurements of every tunnel, for the path-quality report
        super::quality::ingest(&app);
        // the firewall guard of the panel's own server
        let g = tokio::task::spawn_blocking(|| crate::fw::report()["guard"].clone()).await.unwrap_or(Value::Null);
        let (fw_want, fw_confirm) = guard_answer(&app, "local", &g);
        let fw_fresh = guard_fresh().lock().unwrap_or_else(|e| e.into_inner()).remove("local");
        let _ = tokio::task::spawn_blocking(move || {
            if fw_fresh {
                crate::fw::guard_reset_note();
            }
            crate::fw::guard_tick(Some(fw_want), fw_confirm)
        })
        .await;
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
pub fn health(app: &App, offline_nodes: &HashSet<String>) -> Vec<(String, String, bool, String)> {
    let seen = seen().lock().unwrap_or_else(|e| e.into_inner()).clone();
    let t = now();
    let fresh = |sid: &str| sid == "local" || seen.get(sid).map(|x| t - x.at < 20).unwrap_or(false);
    let mut out = vec![];
    for sv in servers(app) {
        // the tunnel agent of a VPN server that is down itself: the server's own alert says it once
        if !sv.node.is_empty() && offline_nodes.contains(&sv.node) {
            continue;
        }
        out.push((format!("ts:{}", sv.id), format!("سرور تانل {}", sv.name), fresh(&sv.id), sv.node.clone()));
    }
    for tu in tunnels(app) {
        // a tunnel is only judged while both its servers are up (else their own alert says it)
        if !tu.enabled || !fresh(&tu.entry) || !fresh(&tu.exit) {
            continue;
        }
        let st = |sid: &str| seen.get(sid).and_then(|x| x.status.iter().find(|q| q.id == tu.id).cloned());
        let (en, ex) = (st(&tu.entry), st(&tu.exit));
        let up = en.as_ref().is_some_and(|q| q.links > 0) && ex.as_ref().is_some_and(|q| q.links > 0);
        out.push((format!("tu:{}", tu.id), format!("تانل {}", tu.name), up, String::new()));
        // its round trip (measured by the entry): too high is an alert of its own
        let rtt = [en, ex].iter().flatten().map(|q| q.rtt_ms).max().unwrap_or(0);
        if up && rtt > 0 {
            out.push((format!("tp:{}", tu.id), format!("تانل {}", tu.name), rtt < TUNNEL_SLOW_MS, rtt.to_string()));
        }
    }
    out
}

/// For the path-quality report (`quality.rs`): every enabled tunnel, whether it is up (both servers
/// reporting and both holding a link) and the entry's last live measurement (None when it is older than
/// 3 minutes, or the entry runs an agent without the measurement).
pub(crate) fn live_quality(app: &App) -> Vec<(Tunnel, bool, Option<Value>)> {
    let seen = seen().lock().unwrap_or_else(|e| e.into_inner()).clone();
    let t = now();
    let fresh = |sid: &str| sid == "local" || seen.get(sid).map(|x| t - x.at < 20).unwrap_or(false);
    let st = |sid: &str, tid: &str| seen.get(sid).and_then(|x| x.status.iter().find(|q| q.id == tid).cloned());
    tunnels(app)
        .into_iter()
        .filter(|tu| tu.enabled)
        .map(|tu| {
            let (en, ex) = (st(&tu.entry, &tu.id), st(&tu.exit, &tu.id));
            let up = fresh(&tu.entry) && fresh(&tu.exit) && en.as_ref().is_some_and(|q| q.links > 0) && ex.as_ref().is_some_and(|q| q.links > 0);
            let q = en.and_then(|q| q.quality).filter(|q| q["at"].as_i64().map(|a| t - a < 180).unwrap_or(false));
            (tu, up, q)
        })
        .collect()
}

/// tunnel id -> (links on the datagram lane, live links), from the entry's last report
pub(crate) fn live_lanes(app: &App) -> HashMap<String, (usize, usize)> {
    let seen = seen().lock().unwrap_or_else(|e| e.into_inner()).clone();
    tunnels(app)
        .into_iter()
        .filter_map(|tu| {
            let st = seen.get(&tu.entry).and_then(|x| x.status.iter().find(|q| q.id == tu.id).cloned())?;
            Some((tu.id, (st.lanes, st.links)))
        })
        .collect()
}

/// The names of a tunnel's two servers, the Iran one first
pub(crate) fn pair_names(app: &App, entry: &str, exit: &str) -> (String, String) {
    let list = servers(app);
    let name = |id: &str| {
        if id == "local" {
            return local_name(app);
        }
        list.iter().find(|s| s.id == id).map(|s| s.name.trim().to_string()).filter(|n| !n.is_empty()).unwrap_or_else(|| id.to_string())
    };
    let locs = server_locs(app);
    let iran = |id: &str| locs.get(id).map(|l| l.0 == "iran").unwrap_or(false);
    if iran(exit) && !iran(entry) {
        (name(exit), name(entry))
    } else {
        (name(entry), name(exit))
    }
}

/// A tunnel whose round trip stays at least this high is reported to the admins
pub const TUNNEL_SLOW_MS: u64 = 800;

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
    // 3.68 SSRF guard: a CDN edge is a public address, never this server or a private network
    for e in &edges {
        let (h, p) = e.rsplit_once(':').map(|(h, p)| (h, p.parse::<u16>().unwrap_or(443))).unwrap_or((e.as_str(), 443));
        if let Err(why) = crate::util::public_host(h, p, false).await {
            return err(StatusCode::BAD_REQUEST, &format!("{}: {}", e, why));
        }
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
        .route("/api/tunnels/servers/:id/health", get(server_health))
        .route("/api/tunnels/servers/:id/agent/:act", post(server_agent_act))
        .route("/api/tunnels/servers/:id/ports", get(server_ports))
        .route("/api/tunnels/servers/:id/firewall", get(server_fw).post(server_fw_close))
        .route("/api/tunnels/servers/:id/firewall-guard", post(server_guard))
        .route("/api/firewall/guard", get(guard_list).post(guard_all))
        .route("/api/tunnels/:id", delete(tunnel_del))
        .route("/api/removals/:id", get(removal_get))
        .route("/api/tunnels/:id/awgconf/:side", get(awg_conf))
        .route("/api/tunnels/:id/hy2conf/:side", get(hy2_conf))
        .route("/api/tunnels/:id/:action", post(tunnel_action))
        .route("/tunnel/agent", post(agent_report))
        .route("/tunnel/binary", post(agent_binary))
        .route("/tunnel/hy2bin", post(agent_hy2bin))
        // a hysteria binary is ~20 MB (the rest of the panel keeps the 2 MiB limit)
        .route("/api/update-all", post(update_all))
        .route("/api/auto-update", get(auto_update_get).put(auto_update_put))
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
///
/// A multi-location route (Iran → Turkey → Germany: one tunnel per hop) is followed back to its first
/// entry: the app dials Iran, whose port reaches Turkey, whose same port reaches Germany.
pub fn udp_forward(app: &App, node_id: &str, node_host: &str, entry_host: &str, port: u16) -> Option<(String, u16)> {
    let list: Vec<Tunnel> = route_list(app);
    let addr = |sid: &str| seen_ip(sid).filter(|_| sid != "local").unwrap_or_else(|| host_of(app, sid));
    for t in &list {
        let exit_here = (t.exit == "local" && node_id == "local")
            || (!node_host.is_empty() && (addr(&t.exit) == node_host || host_of(app, &t.exit) == node_host || t.target == node_host));
        if !exit_here {
            continue;
        }
        if let Some((a, _)) = crate::tunnel::engine::parse_ports(&t.udp).into_iter().find(|(_, b)| *b == port) {
            let (sid, p) = walk_back(&list, &t.entry, a).pop().unwrap_or_else(|| (t.entry.clone(), a));
            let h = host_of(app, &sid);
            if !h.is_empty() {
                return Some((h, p));
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

/// From server `sid`, where UDP `port` arrives, back through the hops of a multi-location route: the
/// tunnel whose exit is `sid` and that forwards some entry port to `port`, then the one before it…
/// [(sid, port), (the server before, its port), …, (the first entry, its port)].
fn walk_back(list: &[Tunnel], sid: &str, port: u16) -> Vec<(String, u16)> {
    walk_back_by(list, sid, port, false)
}

/// `walk_back` for a TCP port (`tcp`) or a UDP one
fn walk_back_by(list: &[Tunnel], sid: &str, port: u16, tcp: bool) -> Vec<(String, u16)> {
    let mut back = vec![(sid.to_string(), port)];
    // a route has a few hops; a loop of tunnels (A → B → A) stops where it started
    for _ in 0..8 {
        let (cur, p) = back.last().cloned().unwrap_or_default();
        let prev = list.iter().find_map(|t| {
            let ports = if tcp { &t.tcp } else { &t.udp };
            (t.exit == cur && !back.iter().any(|(s, _)| *s == t.entry))
                .then(|| crate::tunnel::engine::parse_ports(ports).into_iter().find(|(_, b)| *b == p).map(|(a, _)| (t.entry.clone(), a)))
                .flatten()
        });
        match prev {
            Some(x) => back.push(x),
            None => break,
        }
    }
    back
}

/// The servers a UDP port of server `sid` comes in through, first entry first (["Iran", "Turkey"]),
/// and the port on the first entry. None = no tunnel brings it there.
pub fn udp_route(app: &App, sid: &str, port: u16) -> Option<(Vec<String>, u16)> {
    let list: Vec<Tunnel> = route_list(app);
    let back = walk_back(&list, sid, port);
    let first = back.last().map(|x| x.1).unwrap_or(port);
    (back.len() > 1).then(|| (back[1..].iter().rev().map(|(s, _)| server_name(app, s)).collect(), first))
}

/// The first entry of the tunnels that bring TCP or UDP `port` to server `sid`, and the port there.
/// None = no Kanki tunnel carries it.
pub fn port_entry(app: &App, sid: &str, port: u16, tcp: bool) -> Option<(String, u16)> {
    let list: Vec<Tunnel> = route_list(app);
    let back = walk_back_by(&list, sid, port, tcp);
    (back.len() > 1).then(|| back.last().cloned()).flatten()
}

/// `port_entry`, preferring the tunnels whose first entry is `host` (an Iran server's address): when
/// Iran-1 and Iran-2 both carry the port here, each may give it another port.
pub fn port_entry_at(app: &App, sid: &str, port: u16, tcp: bool, host: &str) -> Option<(String, u16)> {
    let list: Vec<Tunnel> = route_list(app);
    let srv = servers(app);
    let is_host = |e: &str| {
        !host.is_empty() && (host_of(app, e) == host || seen_ip(e).as_deref() == Some(host) || srv.iter().any(|s| s.id == e && s.domain.eq_ignore_ascii_case(host)))
    };
    for t in list.iter().filter(|t| t.exit == sid) {
        let ports = if tcp { &t.tcp } else { &t.udp };
        let Some((a, _)) = crate::tunnel::engine::parse_ports(ports).into_iter().find(|(_, b)| *b == port) else { continue };
        let first = walk_back_by(&list, &t.entry, a, tcp).pop().unwrap_or_else(|| (t.entry.clone(), a));
        if is_host(&first.0) {
            return Some(first);
        }
    }
    // 3.58.1: an address was asked for and no tunnel from it brings the port: not «some other Iran server's
    // tunnel», which made a config pointing at an Iran server that does not carry the port at all
    if !host.is_empty() && (list.iter().any(|t| is_host(&t.entry)) || srv.iter().any(|s| is_host(&s.id))) {
        return None;
    }
    port_entry(app, sid, port, tcp)
}

/// Every Iran entry whose tunnel brings UDP `port` to server `sid`, one per entry server, in the order of the
/// tunnels: (entry server id, the port it gives there). Empty = no tunnel carries the port (panel 3.67: each is
/// a separate KANKI MIX entry of the server).
pub fn udp_entries(app: &App, sid: &str, port: u16) -> Vec<(String, u16)> {
    let list: Vec<Tunnel> = route_list(app);
    let mut out: Vec<(String, u16)> = vec![];
    for t in list.iter().filter(|t| t.exit == sid) {
        let Some((a, _)) = crate::tunnel::engine::parse_ports(&t.udp).into_iter().find(|(_, b)| *b == port) else { continue };
        let first = walk_back_by(&list, &t.entry, a, false).pop().unwrap_or_else(|| (t.entry.clone(), a));
        if !out.iter().any(|x| x.0 == first.0) {
            out.push(first);
        }
    }
    out
}

/// 3.69: the KANKI MIX hop ports tunnel `t` carries besides the main port, as (entry port, port on the exit). When
/// the tunnel is a Kanki tunnel (the engine forwards any UDP list) that carries the main KANKI MIX port of the
/// server at its exit, every hop port of that server (`kmix_hop`, as the server reports it runs) is forwarded
/// from the same port number on the entry to the main port. Nothing when one of those entry ports is already
/// used by another tunnel at that entry or by the tunnel itself: then the link through it has no `ports=` (the
/// client never hops onto a port that leads nowhere).
pub fn kmix_hop_map(app: &App, t: &Tunnel) -> Vec<(u16, u16)> {
    if !t.enabled || !t.kind.is_empty() || t.entry == t.exit {
        return vec![];
    }
    let nid = if t.exit == "local" { "local".to_string() } else { servers(app).into_iter().find(|s| s.id == t.exit).map(|s| s.node).unwrap_or_default() };
    if nid.is_empty() || !crate::kmix::settings(app).node_on(&nid) {
        return vec![];
    }
    let Some(n) = app.db.node(&nid) else { return vec![] };
    let info = crate::api::node_info(&n);
    let Some(port) = info["kmix_port"].as_u64().and_then(|p| u16::try_from(p).ok()).filter(|p| *p > 0) else { return vec![] };
    let Some((a, b)) = info["kmix_hop"].as_str().and_then(crate::kmix::hop_range) else { return vec![] };
    let own = crate::tunnel::engine::parse_ports(&t.udp);
    if !own.iter().any(|(_, x)| *x == port) {
        return vec![];
    }
    // the entry ports already taken there: this tunnel's own and every other tunnel's at the same entry
    let mut taken: std::collections::HashSet<u16> = own.iter().map(|(x, _)| *x).collect();
    for o in tunnels(app).into_iter().filter(|o| o.enabled && o.id != t.id && o.entry == t.entry) {
        taken.extend(crate::tunnel::engine::parse_ports(&o.udp).into_iter().map(|(x, _)| x));
        if o.kind == "awg" {
            taken.extend(crate::tunnel::engine::parse_ports(&o.awg.fwd_udp).into_iter().map(|(x, _)| x));
        }
    }
    if (a..=b).any(|h| taken.contains(&h)) {
        return vec![];
    }
    (a..=b).map(|h| (h, port)).collect()
}

/// The hop range a client may use at the Iran entry `host` (port `tport`) that leads to KANKI MIX `port` of node
/// `nid` ("4001-4010"), when the tunnel there forwards it (`kmix_hop_map`)
pub fn kmix_hops_at(app: &App, nid: &str, host: &str, tport: u16, port: u16) -> Option<String> {
    let sid = crate::twin::sid_of_node(app, nid);
    if sid.is_empty() {
        return None;
    }
    tunnels(app).into_iter().filter(|t| t.exit == sid && host_of(app, &t.entry) == host).find_map(|t| {
        let carries = crate::tunnel::engine::parse_ports(&t.udp).into_iter().any(|(a, b)| a == tport && b == port);
        let hops = kmix_hop_map(app, &t);
        match (carries, hops.first(), hops.last()) {
            (true, Some(f), Some(l)) => Some(format!("{}-{}", f.0, l.0)),
            _ => None,
        }
    })
}

/// Some Kanki port tunnel (not a layer-3 AmneziaWG one, which carries every port) ends at server `sid`.
/// A server with one carries only the ports its tunnels list: a second config on any other port would
/// lead nowhere. A server with none has its tunnel set up elsewhere (or a layer-3 one): its ports stay.
pub fn has_port_tunnels(app: &App, sid: &str) -> bool {
    route_list(app).iter().any(|t| t.exit == sid)
}

/// The tunnels whose ports can be followed from one server to the next: the enabled port tunnels (every kind:
/// Kanki, KANKI-UP, direct, Hysteria2), and the ports an AmneziaWG link forwards into itself when they land on its
/// exit (no other target). A layer-3 AmneziaWG link without forwarded ports carries no port of its own.
fn route_list(app: &App) -> Vec<Tunnel> {
    tunnels(app)
        .into_iter()
        .filter(|t| t.enabled && t.kind != "awgwrap")
        .filter_map(|t| {
            if t.kind != "awg" {
                return Some(t);
            }
            if !t.awg.fwd_target.trim().is_empty() || (t.awg.fwd_tcp.is_empty() && t.awg.fwd_udp.is_empty()) {
                return None;
            }
            let mut x = t.clone();
            x.tcp = t.awg.fwd_tcp.clone();
            x.udp = t.awg.fwd_udp.clone();
            Some(x)
        })
        .collect()
}


/// The address of the first server of the tunnels (or the route) that end at server `sid`: the Iran
/// entry users would connect to. "" = no tunnel ends there.
pub fn entry_host(app: &App, sid: &str) -> String {
    let list: Vec<Tunnel> = route_list(app);
    let mut cur = sid.to_string();
    let mut seen_ids = vec![cur.clone()];
    for _ in 0..8 {
        match list.iter().find(|t| t.exit == cur && !seen_ids.contains(&t.entry)) {
            Some(t) => {
                cur = t.entry.clone();
                seen_ids.push(cur.clone());
            }
            None => break,
        }
    }
    if cur == sid { String::new() } else { host_of(app, &cur) }
}

fn server_name(app: &App, sid: &str) -> String {
    if sid == "local" {
        return local_name(app);
    }
    servers(app).into_iter().find(|s| s.id == sid).map(|s| s.name).unwrap_or_else(|| sid.to_string())
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
    let seen = seen().lock().unwrap_or_else(|e| e.into_inner()).clone();
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
            // 3.71: its VPN node (one machine counted once on every page)
            "node": s.node,
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
        if tu.kind == "kup" {
            // the key stays on the servers
            v["kup"]["key"] = json!("");
        }
        if tu.kind == "fwd" {
            v["fwd"]["entry_ip"] = json!(tu.fwd.entry_ip());
            v["fwd"]["exit_ip"] = json!(tu.fwd.exit_ip());
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
        // (3.63) a side that cannot count what passes (the Hysteria2 client) shows the other side's numbers,
        // turned around: what the exit got is what the entry sent
        let none = |x: &Value| x["rx_bytes"].as_u64().unwrap_or(0) == 0 && x["tx_bytes"].as_u64().unwrap_or(0) == 0;
        if v["entry_status"].is_object() && v["exit_status"].is_object() && none(&v["entry_status"]) && !none(&v["exit_status"]) {
            v["entry_status"]["tx_bytes"] = v["exit_status"]["rx_bytes"].clone();
            v["entry_status"]["rx_bytes"] = v["exit_status"]["tx_bytes"].clone();
        }
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
    let sn = seen().lock().unwrap_or_else(|e| e.into_inner());
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
    // KANKI-UP: the exit's raw ports (TCP or UDP by the raw mode; ICMP none) and the entry's UDP ports
    if t.kind == "kup" {
        let c = t.kup.clone().unwrap_or_default();
        let n = parse_ports(&t.udp).len();
        if t.port > 0 && (c.on_tcp() || c.on_udp()) {
            for i in 0..n {
                if let Some(p) = t.port.checked_add(i as u16) {
                    v.push((t.exit.clone(), p, c.on_udp()));
                }
            }
            if c.probe_port > 0 {
                v.push((t.exit.clone(), c.probe_port, c.on_udp()));
            }
        }
        for (p, _) in parse_ports(&t.udp) {
            v.push((t.entry.clone(), p, true));
        }
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
            // the agent itself, also when it runs without systemd (a container, started by hand): no unit
            let ours = unit == "kanki-tunnel.service" || unit.starts_with("kanki-hy2-") || unit.starts_with("kanki-up-") || (sid == "local" && unit == "kanki-panel.service")
                || (unit.is_empty() && prog == "kanki-panel");
            if ours && (own.contains(&(sid.clone(), port, udp))) {
                continue;
            }
            let srv = if sid == "local" { local_name(app) } else { names.get(&sid).cloned().unwrap_or(sid.clone()) };
            return Some(format!("{} port {} on {} is already used by {}: pick another port", if udp { "UDP" } else { "TCP" }, port, srv, holder_name(&prog, &unit)));
        }
    }
    None
}

/// The ports a server holds or will hold: what its tunnels listen on and forward there, and what it reported
/// listening on a moment ago (`ss`, every program)
pub(crate) fn ports_on_server(app: &App, sid: &str) -> HashSet<u16> {
    let mut t: HashSet<u16> = HashSet::new();
    for tu in tunnels(app).iter().filter(|x| x.enabled) {
        t.extend(tunnel_needs(tu).into_iter().filter(|x| x.0 == sid).map(|x| x.1));
    }
    if let Some(l) = listening_on(sid) {
        t.extend(l.into_iter().map(|x| x.0));
    }
    t
}

/// Every port any server reported holding (for the panel-wide list of taken ports)
pub(crate) fn held_anywhere(app: &App) -> HashSet<u16> {
    let mut t: HashSet<u16> = HashSet::new();
    for sid in std::iter::once("local".to_string()).chain(servers(app).into_iter().map(|s| s.id)) {
        if let Some(l) = listening_on(&sid) {
            t.extend(l.into_iter().map(|x| x.0));
        }
    }
    t
}

/// The first `need` free ports in a row on server `sid`, from `from` up: free of what that server holds or
/// will hold (`ports_on_server`) and of every VPN core port of the panel (a tunnel may carry any of them
/// through this server later). None when 2000 tries found nothing.
pub(crate) fn free_ports(app: &App, sid: &str, from: u16, need: u16) -> Option<u16> {
    let mut busy = ports_on_server(app, sid);
    busy.extend(crate::servers::all_taken(app));
    let need = need.max(1);
    let mut p = from.max(1024);
    for _ in 0..2000 {
        let end = p.checked_add(need - 1)?;
        if (p..=end).all(|x| !busy.contains(&x)) {
            return Some(p);
        }
        p = p.checked_add(1)?;
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
/// A game tunnel's FEC as typed: empty (the default), "off" / "0", or "data:parity" with 1-64 data and 1-32
/// parity shards
pub(crate) fn fec_ok(f: &str) -> bool {
    if f.is_empty() || f == "off" || f == "0" || f == "auto" {
        return true;
    }
    let Some((d, p)) = f.split_once(':') else { return false };
    matches!(d.trim().parse::<u8>(), Ok(1..=64)) && matches!(p.trim().parse::<u8>(), Ok(1..=32))
}

/// The ports a user tunnel may not use: (entry ports it may not listen on, exit ports it may not deliver to)
pub fn management_ports(app: &App) -> (Vec<u16>, Vec<u16>) {
    let env_port = |k: &str, d: u16| app.env.get(k).and_then(|p| p.trim().parse::<u16>().ok()).filter(|p| *p > 0).unwrap_or(d);
    let entry = vec![22];
    let mut exit = vec![22, env_port("PANEL_PORT", 8080), env_port("NODE_PORT", 2096), 29332, crate::xray::API_PORT];
    exit.sort_unstable();
    exit.dedup();
    (entry, exit)
}

/// Why these port lists of a tunnel are refused (None = fine)
fn management_forward(app: &App, tcp: &[String], udp: &[String]) -> Option<String> {
    let (entry, exit) = management_ports(app);
    for (proto, list) in [("tcp", tcp), ("udp", udp)] {
        for (a, b) in parse_ports(list) {
            if proto == "tcp" && entry.contains(&a) {
                return Some(format!("port {}/tcp is SSH on the entry server: a tunnel cannot listen there", a));
            }
            if proto == "tcp" && exit.contains(&b) {
                return Some(format!("port {}/tcp is a management port (SSH, panel or node agent): a tunnel cannot deliver there", b));
            }
        }
    }
    None
}

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
    // 3.68: a tunnel never takes the entry's SSH port and never delivers to the exit's management ports (SSH, the
    // panel, the node agent): a forward there would hand the panel or the shell to anyone who reaches the entry
    if let Some(why) = management_forward(&app, &t.tcp, &t.udp) {
        return err(StatusCode::BAD_REQUEST, &why);
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
        // "8:3" style, 1-64 data and 1-32 parity shards, or "off" ("0:3", "8:0" and "1:2:3" were let through)
        if !fec_ok(&f) {
            return err(StatusCode::BAD_REQUEST, "FEC is data:parity like 8:3 (data 1-64, parity 1-32) or off");
        }
        t.fec = f;
    }
    if let Some(d) = b["dup"].as_bool() {
        t.dup = d;
    }
    if b.get("profile").is_some() {
        let p = s("profile");
        if !PROFILES.contains(&p.as_str()) {
            return err(StatusCode::BAD_REQUEST, "unknown core profile");
        }
        t.profile = p;
    }
    // Game-FEC Pro: the line decides the repairs, so no fixed copy on top
    if t.transport == "game" && t.fec == "auto" {
        t.dup = false;
    }
    if t.transport != "game" || t.fec != "auto" {
        t.profile.clear();
    }
    if b.get("chain").is_some() {
        t.chain = s("chain").chars().filter(|c| c.is_ascii_alphanumeric()).take(16).collect();
    }
    if let Some(n) = b["hop"].as_u64() {
        t.hop = n.min(15) as u8;
    }
    if b.get("chain_name").is_some() {
        t.chain_name = s("chain_name").chars().filter(|c| !c.is_control() && !"<>\"".contains(*c)).take(40).collect();
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
        let tag = if !t.profile.is_empty() { t.profile.clone() } else { t.kind.clone() };
        t.name = default_tunnel_name(&app, &t.entry, &t.exit, &tag);
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
            "fwd" => "fwd".into(),
            "kup" => "kup".into(),
            _ => String::new(),
        };
    }
    if t.kind == "fwd" {
        if let Err(e) = fwd_apply_body(&list, &mut t, &b["fwd"]) {
            return err(StatusCode::BAD_REQUEST, &e);
        }
    } else {
        t.fwd = FwdCfg::default();
    }
    if t.kind == "kup" {
        if let Err(e) = kup_apply_body(&mut t, &b["kup"]) {
            return err(StatusCode::BAD_REQUEST, &e);
        }
    } else {
        t.kup = None;
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
    if t.kind == "fwd" {
        if let Err(e) = fwd_checks(&app, &t) {
            return err(StatusCode::CONFLICT, &e);
        }
    }
    if t.kind == "kup" {
        if let Err(e) = kup_checks(&app, &t) {
            return err(StatusCode::CONFLICT, &e);
        }
    }
    // no port written: the first one nothing holds on the listening server (and no VPN core uses anywhere)
    if t.port == 0 && t.kind != "hy2" && t.kind != "fwd" {
        let listener = if t.mode == "direct" { t.exit.clone() } else { t.entry.clone() };
        // KANKI-UP: one raw port per UDP port, in a row
        let need = if t.kind == "kup" { parse_ports(&t.udp).len().max(1) as u16 } else { 1 };
        if let Some(p) = free_ports(&app, &listener, AUTO_TUNNEL_PORT, need) {
            t.port = p;
        }
    }
    if t.port == 0 && t.kind != "fwd" {
        return err(StatusCode::BAD_REQUEST, "the tunnel port is required");
    }
    if t.kind == "kup" {
        kup_probe_port(&app, &mut t);
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
    if listener == t.entry && t.port > 0 && t.kind != "kup" {
        if my_pr.0 && mine_tcp.contains(&t.port) {
            return err(StatusCode::BAD_REQUEST, "the tunnel port is also in the forwarded TCP ports");
        }
        if my_pr.1 && mine_udp.contains(&t.port) {
            return err(StatusCode::BAD_REQUEST, "the tunnel port is also in the forwarded UDP ports");
        }
    }
    for o in list.iter().filter(|o| o.id != t.id && o.enabled && !(o.kind == "awg" && !o.awg.wrap)) {
        // KANKI-UP holds a row of raw ports: every port either tunnel needs, on each server, by protocol
        if t.kind == "kup" || o.kind == "kup" {
            // ICMP has no port numbers: one ICMP KANKI-UP per exit server takes its echo packets
            let icmp = |x: &Tunnel| x.kind == "kup" && x.kup.as_ref().map(|c| c.raw_mode == "icmp").unwrap_or(false);
            if icmp(&t) && icmp(o) && o.exit == t.exit {
                return err(StatusCode::CONFLICT, &format!("the exit already has an ICMP KANKI-UP: \"{}\" (ICMP has no ports, one per server)", o.name));
            }
            let theirs = tunnel_needs(o);
            if let Some((_, p, udp)) = tunnel_needs(&t).into_iter().find(|x| theirs.contains(x)) {
                return err(StatusCode::CONFLICT, &format!("{} port {} is already used by the tunnel \"{}\"", if udp { "UDP" } else { "TCP" }, p, o.name));
            }
            continue;
        }
        let o_listener: String = if o.mode == "direct" { o.exit.clone() } else { o.entry.clone() };
        let o_pr = port_protos(&o.transport);
        let o_tcp: Vec<u16> = parse_ports(&o.tcp).into_iter().map(|p| p.0).collect();
        let o_udp: Vec<u16> = parse_ports(&o.udp).into_iter().map(|p| p.0).collect();
        // tunnel port against the tunnel port of the other one (a protocol both use)
        if t.port > 0 && o_listener == listener && ((my_pr.0 && o_pr.0) || (my_pr.1 && o_pr.1)) && o.port == t.port {
            return err(StatusCode::CONFLICT, &format!("port {} is already used by the tunnel \"{}\"", t.port, o.name));
        }
        // my tunnel port against the ports the other one opens on its entry
        if t.port > 0 && o.entry == listener && hits(my_pr, t.port, &o_tcp, &o_udp) {
            return err(StatusCode::CONFLICT, &format!("port {} is already used by the tunnel \"{}\"", t.port, o.name));
        }
        // the tunnel port of the other one against the ports I open on my entry
        if o.port > 0 && t.entry == o_listener && hits(o_pr, o.port, &mine_tcp, &mine_udp) {
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

// ------------------------------------------------------------------ the firewall guard

/// What the panel saw just before it asked a server for the guard: the tunnels up then (they must stay
/// up) and when; the server's node must sync after that too
#[derive(Clone)]
struct GuardWatch {
    /// when the panel first saw the guard on and not confirmed yet (the panel's clock; 0 = not yet)
    seen_on: i64,
    tunnels_up: Vec<String>,
}

fn guard_watch() -> &'static Mutex<HashMap<String, GuardWatch>> {
    static G: OnceLock<Mutex<HashMap<String, GuardWatch>>> = OnceLock::new();
    G.get_or_init(Default::default)
}

/// servers that get `fw_fresh` once (a press of the switch: an earlier failure note is forgotten)
fn guard_fresh() -> &'static Mutex<HashSet<String>> {
    static G: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    G.get_or_init(Default::default)
}

/// the panel waits this long after the guard went on before it judges (the node syncs every few seconds)
const GUARD_SETTLE: i64 = 25;
/// … and gives up this long after it (well before the server's own `fw::GUARD_CONFIRM_SECS`)
const GUARD_GIVE_UP: i64 = 120;

/// whether the guard is asked for server `sid`
pub fn guard_wanted(app: &App, sid: &str) -> bool {
    if sid == "local" {
        return app.db.get("fw_guard_local") == "1";
    }
    servers(app).iter().any(|s| s.id == sid && s.fw_guard)
}

fn set_guard(app: &App, sid: &str, on: bool) {
    if sid == "local" {
        app.db.set("fw_guard_local", if on { "1" } else { "0" });
        return;
    }
    let mut list = servers(app);
    if let Some(s) = list.iter_mut().find(|s| s.id == sid) {
        s.fw_guard = on;
    }
    save_servers(app, &list);
}

/// the tunnels of `sid` that are up now (both servers reporting, both holding a link)
fn tunnels_up_of(app: &App, sid: &str) -> Vec<String> {
    live_quality(app).into_iter().filter(|(t, up, _)| *up && (t.entry == sid || t.exit == sid)).map(|(t, _, _)| t.id).collect()
}

/// The panel's answer about the guard to server `sid` that reported `g` (`fw::Guard`): (asked for it,
/// confirm it works). It confirms once the server's node synced after the guard went on and every tunnel
/// that was up before is up again; it gives up (and turns the switch off) when that does not happen.
fn guard_answer(app: &App, sid: &str, g: &Value) -> (bool, bool) {
    let want = guard_wanted(app, sid);
    if !want {
        guard_watch().lock().unwrap_or_else(|e| e.into_inner()).remove(sid);
        return (false, false);
    }
    let (on, confirmed) = (g["on"].as_bool() == Some(true), g["confirmed"].as_bool() == Some(true));
    let note = g["note"].as_str().unwrap_or("");
    // the server could not, or rolled it back: the switch goes off and says why
    if !on && !note.is_empty() {
        set_guard(app, sid, false);
        app.db.set(&format!("fw_guard_note_{}", sid), note);
        guard_watch().lock().unwrap_or_else(|e| e.into_inner()).remove(sid);
        return (false, false);
    }
    if !on || confirmed {
        return (true, false);
    }
    let t = now();
    // times on the panel's own clock (the server's may differ)
    let watch = {
        let mut gw = guard_watch().lock().unwrap_or_else(|e| e.into_inner());
        // a panel restarted meanwhile knows no tunnels from before: only the VPN part is checked
        let w = gw.entry(sid.to_string()).or_insert(GuardWatch { seen_on: 0, tunnels_up: vec![] });
        if w.seen_on == 0 {
            w.seen_on = t;
        }
        w.clone()
    };
    let since = watch.seen_on;
    if t - since < GUARD_SETTLE {
        return (true, false);
    }
    // the VPN part of the machine: the panel reached it after the firewall went on
    let node_id = if sid == "local" { String::new() } else { servers(app).into_iter().find(|s| s.id == sid).map(|s| s.node).unwrap_or_default() };
    let node_ok = node_id.is_empty() || app.db.node(&node_id).map(|n| !n.enabled || (n.online && n.last_sync >= since)).unwrap_or(true);
    let up = tunnels_up_of(app, sid);
    let tunnels_ok = watch.tunnels_up.iter().all(|id| up.contains(id));
    if node_ok && tunnels_ok {
        guard_watch().lock().unwrap_or_else(|e| e.into_inner()).remove(sid);
        return (true, true);
    }
    if t - since > GUARD_GIVE_UP {
        let why = if !node_ok { "the panel could not reach this server's VPN part with the firewall on" } else { "a tunnel of this server did not come back with the firewall on" };
        set_guard(app, sid, false);
        app.db.set(&format!("fw_guard_note_{}", sid), why);
        guard_watch().lock().unwrap_or_else(|e| e.into_inner()).remove(sid);
        // the switch is off: the server turns ufw off on this very answer
        return (false, false);
    }
    (true, false)
}

/// { on }: the guard of one server ("local" = the panel's own)
async fn server_guard(State(app): St, h: HeaderMap, Path(id): Path<String>, Json(b): Json<Value>) -> Response {
    if let Err(r) = crate::auth::check_session(&app, &h) {
        return r;
    }
    let on = b["on"].as_bool().unwrap_or(false);
    if id != "local" && !servers(&app).iter().any(|s| s.id == id) {
        return err(StatusCode::NOT_FOUND, "unknown server");
    }
    guard_switch(&app, &id, on);
    Json(json!({ "ok": true })).into_response()
}

fn guard_switch(app: &App, id: &str, on: bool) {
    set_guard(app, id, on);
    app.db.set(&format!("fw_guard_note_{}", id), "");
    if on {
        guard_watch().lock().unwrap_or_else(|e| e.into_inner()).insert(id.to_string(), GuardWatch { seen_on: 0, tunnels_up: tunnels_up_of(app, id) });
        guard_fresh().lock().unwrap_or_else(|e| e.into_inner()).insert(id.to_string());
    }
}

/// { on }: the guard of every server at once (the panel's own included)
async fn guard_all(State(app): St, h: HeaderMap, Json(b): Json<Value>) -> Response {
    if let Err(r) = crate::auth::check_session(&app, &h) {
        return r;
    }
    let on = b["on"].as_bool().unwrap_or(false);
    let ids: Vec<String> = std::iter::once("local".to_string()).chain(servers(&app).into_iter().map(|s| s.id)).collect();
    for id in &ids {
        guard_switch(&app, id, on);
    }
    Json(json!({ "ok": true, "servers": ids.len() })).into_response()
}

/// the guard of every server, for the panel page: {id: {want, note, guard, active, ufw}}
async fn guard_list(State(app): St, h: HeaderMap) -> Response {
    let _ = guard!(app, h, "nodes");
    let sn = seen().lock().unwrap_or_else(|e| e.into_inner()).clone();
    let local_fw = tokio::task::spawn_blocking(crate::fw::report).await.unwrap_or_default();
    let mut out = serde_json::Map::new();
    let mut add = |id: &str, name: &str, fw: &Value, version: &str| {
        out.insert(id.to_string(), json!({
            "name": name, "want": guard_wanted(&app, id), "note": app.db.get(&format!("fw_guard_note_{}", id)),
            "guard": fw["guard"], "active": fw["active"], "ufw": fw["ufw"], "version": version, "ports": fw["ports"],
            // an agent older than 3.38.0 reports no guard: it cannot do it yet
            "knows": fw.get("guard").is_some(),
        }));
    };
    add("local", &local_name(&app), &local_fw, crate::VERSION);
    for s in servers(&app) {
        let x = sn.get(&s.id);
        add(&s.id, &s.name, x.map(|x| &x.fw).unwrap_or(&Value::Null), x.map(|x| x.version.as_str()).unwrap_or(""));
    }
    Json(Value::Object(out)).into_response()
}

/// Saves a tunnel from another part of the panel with every check of the Tunnels page
#[allow(dead_code)]
pub(crate) async fn save_json(app: Arc<App>, h: HeaderMap, b: Value) -> Response {
    save(State(app), h, Json(b)).await
}

async fn tunnel_del(State(app): St, h: HeaderMap, Path(id): Path<String>) -> Response {
    let _ = guard!(app, h, "nodes");
    match remove_tunnel(&app, &id) {
        Some(rid) => Json(json!({ "ok": true, "removal": rid })).into_response(),
        None => err(StatusCode::NOT_FOUND, "tunnel not found"),
    }
}

/// A tunnel goes, with the removal steps on its servers (their id; None = no such tunnel)
pub fn remove_tunnel(app: &App, id: &str) -> Option<String> {
    let mut list = tunnels(app);
    let n = list.len();
    list.retain(|t| t.id != id);
    if list.len() == n {
        return None;
    }
    let gone: Vec<Tunnel> = tunnels(app).into_iter().filter(|t| t.id == id).collect();
    save_tunnels(app, &list);
    let name = gone.first().map(|t| t.name.clone()).unwrap_or_default();
    Some(track("tunnel", &name, tunnel_steps(app, &gone, "")))
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
    let mut ap = gre_applied().lock().unwrap_or_else(|e| e.into_inner());
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
    crate::servers::panel_pin(&app).await;
    Json(json!({ "ok": true, "id": s.id, "token": s.token, "name": s.name, "panel": crate::servers::panel_url(&app), "repo": crate::admin::repo(), "gre": gre, "pin": crate::servers::panel_pin_word() })).into_response()
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
    crate::servers::panel_pin(&app).await;
    Json(json!({ "ok": true, "token": token, "panel": crate::servers::panel_url(&app), "repo": crate::admin::repo(), "gre": gre, "pin": crate::servers::panel_pin_word() })).into_response()
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

/// What the admin asked a server's agent to do on its next report: "sync" (apply everything again now) or
/// "restart" (stop its tunnels, then start them again)
fn agent_asks() -> &'static Mutex<HashMap<String, HashSet<String>>> {
    static S: OnceLock<Mutex<HashMap<String, HashSet<String>>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(HashMap::new()))
}

/// POST /api/tunnels/servers/:id/agent/sync | restart (an agent older than 3.57.0 does not know them: it
/// keeps doing its usual round, which applies everything every five seconds anyway)
async fn server_agent_act(State(app): St, h: HeaderMap, Path((id, act)): Path<(String, String)>) -> Response {
    let _ = guard!(app, h, "nodes");
    if act != "sync" && act != "restart" {
        return err(StatusCode::NOT_FOUND, "unknown action");
    }
    if !servers(&app).iter().any(|s| s.id == id) {
        return err(StatusCode::NOT_FOUND, "unknown server");
    }
    agent_asks().lock().unwrap_or_else(|e| e.into_inner()).entry(id).or_default().insert(act);
    Json(json!({ "ok": true })).into_response()
}

/// GET /api/tunnels/servers/:id/health: what the server's agent said last: when, its version, each tunnel
/// (links, error), the firewall and the machine, and what needs a look
async fn server_health(State(app): St, h: HeaderMap, Path(id): Path<String>) -> Response {
    let _ = guard!(app, h, "nodes");
    let Some(srv) = servers(&app).into_iter().find(|s| s.id == id) else { return err(StatusCode::NOT_FOUND, "unknown server") };
    let sn = seen().lock().unwrap_or_else(|e| e.into_inner());
    let Some(x) = sn.get(&id) else {
        return Json(json!({ "online": false, "seen": false, "issues": ["the agent never reported: run the server's command"] })).into_response();
    };
    let age = now() - x.at;
    let names: HashMap<String, String> = tunnels(&app).into_iter().map(|t| (t.id, t.name)).collect();
    let tl: Vec<Value> = x
        .status
        .iter()
        .filter(|s| !s.id.starts_with("probe-"))
        .map(|s| json!({ "id": s.id, "name": names.get(&s.id).cloned().unwrap_or_else(|| s.id.clone()), "role": s.role, "links": s.links, "want": s.want, "rtt_ms": s.rtt_ms, "error": s.error, "transport": s.transport }))
        .collect();
    let mut issues: Vec<String> = vec![];
    if age > 60 {
        issues.push(format!("no report for {} s", age));
    }
    for t in tl.iter().filter(|t| t["links"].as_u64() == Some(0)) {
        issues.push(format!("tunnel {}: no link{}", t["name"].as_str().unwrap_or(""), t["error"].as_str().filter(|e| !e.is_empty()).map(|e| format!(" ({})", e)).unwrap_or_default()));
    }
    if !x.version.is_empty() && ver_lt(&x.version, crate::VERSION) {
        issues.push(format!("agent v{} is older than the panel (v{})", x.version, crate::VERSION));
    }
    Json(json!({
        "online": age <= 60, "seen": true, "age": age, "version": x.version, "ip": x.ip, "loc": srv.loc,
        "tunnels": tl, "fw": x.fw, "stats": x.stats, "issues": issues,
    }))
    .into_response()
}

/// "Try SSL again": the server forgets the waits after earlier certbot failures (every SSL of that server)
pub(crate) fn ask_ssl_retry(id: &str) {
    ssl_retries().lock().unwrap_or_else(|e| e.into_inner()).insert(id.to_string());
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
    let v = if id == "local" { tokio::task::spawn_blocking(crate::fw::report).await.unwrap_or_default() } else { seen().lock().unwrap_or_else(|e| e.into_inner()).get(&id).map(|x| x.fw.clone()).unwrap_or(Value::Null) };
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
    fw_closes().lock().unwrap_or_else(|e| e.into_inner()).insert(id, rules);
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
    frees().lock().unwrap_or_else(|e| e.into_inner()).insert(id, units);
    Json(json!({ "ok": true })).into_response()
}

async fn server_del(State(app): St, h: HeaderMap, Path(id): Path<String>) -> Response {
    let _ = guard!(app, h, "nodes");
    let st = step(&app, &id, "server", "");
    match delete_server(&app, &id, false) {
        Ok(()) => Json(json!({ "ok": true, "removal": track("server", &st.name.clone(), vec![st]) })).into_response(),
        Err((code, e)) => err(code, &e),
    }
}

/// Removes an agent server from the panel. Its agent sees it is gone, removes what Kanki installed
/// (tunnels, Kanki DNS, Xray, subscription listener), closes the firewall ports it
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
    let Some(token) = list.iter().find(|s| s.id == id).map(|s| s.token.clone()) else {
        return Err((StatusCode::NOT_FOUND, "unknown server".into()));
    };
    list.retain(|s| s.id != id);
    save_servers(app, &list);
    mark_removed(app, id, &token);
    crate::dns::panel::forget_server(app, id);
    crate::xray::panel::forget_server(app, id);
    crate::access::forget_agent(app, id);
    crate::subiran::forget_server(app, id);
    crate::exitgeo::forget(app, &[crate::exitgeo::srv_key(id), crate::exitgeo::xray_key(id)]);
    seen().lock().unwrap_or_else(|e| e.into_inner()).remove(id);
    Ok(())
}

/// Server `id` signs its reports from now on: unsigned ones are refused for it
fn mark_signed(app: &App, id: &str) {
    let mut list = servers(app);
    if let Some(x) = list.iter_mut().find(|x| x.id == id && !x.signed) {
        x.signed = true;
        save_servers(app, &list);
        eprintln!("server {}: its agent signs its reports, unsigned ones are refused from now on", id);
    }
}

/// The path a server agent signs its report for (the same behind any proxy or CDN)
pub const REPORT_PATH: &str = "/tunnel/agent";

/// Public: a tunnel agent reports its tunnels and gets the list it should run. The report is signed with
/// the server's token (3.65, `sign`); an agent from before sends the bare token in the body, which is
/// taken only until that server has once sent a signed report.
async fn agent_report(State(app): St, h: HeaderMap, raw: axum::body::Bytes) -> Response {
    let Ok(b) = serde_json::from_slice::<Value>(&raw) else { return err(StatusCode::BAD_REQUEST, "send a JSON report") };
    let id = b["id"].as_str().unwrap_or("").to_string();
    let token = b["token"].as_str().unwrap_or("").to_string();
    let Some(s) = servers(&app).into_iter().find(|s| s.id == id) else {
        // removed here: the agent stops its tunnels and uninstalls. Unknown (never added here): it is
        // told nothing that makes it remove anything
        if was_removed(&app, &id) {
            note_gone(&id);
            // 3.69: signed with its old token when the report was (the agent only trusts a signed «gone» then)
            if let Some(tok) = removed_token(&app, &id).filter(|t| crate::sign::verify(t, &h, "POST", REPORT_PATH, &raw, now()).is_ok()) {
                return signed_answer(&tok, &h, StatusCode::GONE, &[], b"this server is not in the panel any more".to_vec());
            }
            return (StatusCode::GONE, "this server is not in the panel any more").into_response();
        }
        return (StatusCode::NOT_FOUND, "this panel does not know this server").into_response();
    };
    if crate::sign::is_signed(&h) {
        if let Err(r) = crate::sign::verify(&s.token, &h, "POST", REPORT_PATH, &raw, now()) {
            return err(StatusCode::UNAUTHORIZED, r.text());
        }
        if !s.signed {
            mark_signed(&app, &id);
        }
    } else if s.signed {
        return err(StatusCode::UNAUTHORIZED, crate::sign::Refusal::Unsigned.text());
    } else if token.is_empty() || !util::ct_eq(&token, &s.token) {
        return err(StatusCode::FORBIDDEN, "wrong token");
    }
    let status: Vec<Status> = serde_json::from_value(b["status"].clone()).unwrap_or_default();
    note_report(&id, &status, b["xray"]["active"].as_bool() == Some(true), b["dns"]["active"].as_bool() == Some(true));
    crate::srvtraffic::note(&app, &format!("a:{id}"), &b["stats"]["net"]);
    if b["logs"].is_array() {
        agent_logs().lock().unwrap_or_else(|e| e.into_inner()).insert(id.clone(), b["logs"].clone());
    }
    // through the panel's CDN domain the address is a CDN edge's, not the server's: the last real one stays
    let via_cdn = crate::cdn::came_through(&app, &h);
    let fresh_ip = if via_cdn { String::new() } else { util::client_ip(&h) };
    {
        let mut sn = seen().lock().unwrap_or_else(|e| e.into_inner());
        let prev = sn.get(&id).map(|x| x.ip.clone()).unwrap_or_default();
        let ip = if via_cdn { prev } else { sticky_ip(&prev, &fresh_ip) };
        sn.insert(id.clone(), Seen { at: now(), version: b["version"].as_str().unwrap_or("").to_string(), ip, status, fw: b["fw"].clone(), listen: b["listen"].clone(), setup: b["setup"].clone(), stats: b["stats"].clone() });
    }
    let ver = b["version"].as_str().unwrap_or("");
    let until = app.db.get("tun_update_until").parse::<i64>().unwrap_or(0).max(update_one_until(&app, &id));
    let update = now() < until && !ver.is_empty() && ver != crate::VERSION;
    // the emergency chat is gone (3.65): an agent from before stops it until it updates
    let emergency = json!({ "mode": "off" });
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
    let free = frees().lock().unwrap_or_else(|e| e.into_inner()).remove(&id).unwrap_or_default();
    let ssl_retry = ssl_retries().lock().unwrap_or_else(|e| e.into_inner()).remove(&id);
    let asks = agent_asks().lock().unwrap_or_else(|e| e.into_inner()).remove(&id).unwrap_or_default();
    let fw_close = fw_closes().lock().unwrap_or_else(|e| e.into_inner()).remove(&id).unwrap_or_default();
    let (fw_guard, fw_confirm) = guard_answer(&app, &id, &b["fw"]["guard"]);
    let fw_fresh = guard_fresh().lock().unwrap_or_else(|e| e.into_inner()).remove(&id);
    // the VPN part of this machine, when the admin asked for it (sent until the agent says it started)
    let setup = crate::servers::setup_for(&app, &s, &b["setup"]);
    let (xray_block, xray_drop) = (crate::xray::panel::shut_on(&id), crate::xray::panel::ip_blocks(&id));
    // "kping": {} tells an agent older than 3.60 to stop a KPING relay or exit it still runs (gone in 3.60), and
    // "vip": [] one older than 3.57.0 to stop its VIP tunnels
    signed_json(&s.token, &h, StatusCode::OK, &json!({ "kping": {}, "vip": [], "tunnels": specs_for(&app, &id), "update": update, "emergency": emergency, "dns": dns, "xray": xray, "xray_block": xray_block, "xray_drop": xray_drop, "subsrv": subsrv, "free": free, "ssl_retry": ssl_retry, "resync": asks.contains("sync"), "restart": asks.contains("restart"), "fw_close": fw_close, "fw_guard": fw_guard, "fw_confirm": fw_confirm, "fw_fresh": fw_fresh, "setup": setup, "panel": crate::servers::panel_url(&app), "panel_alt": crate::cdn::url(&app).into_iter().collect::<Vec<_>>() }))
}

/// The panel's own binary for a tunnel agent that was asked to update (same file everywhere)
pub const BINARY_PATH: &str = "/tunnel/binary";

async fn agent_binary(State(app): St, h: HeaderMap, raw: axum::body::Bytes) -> Response {
    let Ok(b) = serde_json::from_slice::<Value>(&raw) else { return err(StatusCode::BAD_REQUEST, "send JSON") };
    let s = match agent_dl_auth(&app, &h, BINARY_PATH, &raw, &b) {
        Ok(s) => s,
        Err(r) => return r,
    };
    let id = s.id.clone();
    if now() >= app.db.get("tun_update_until").parse::<i64>().unwrap_or(0).max(update_one_until(&app, &id)) {
        return err(StatusCode::CONFLICT, "no update was requested");
    }
    if b["arch"].as_str().unwrap_or("") != std::env::consts::ARCH {
        return err(StatusCode::CONFLICT, "this server has a different CPU type than the panel; update it by hand");
    }
    let Ok(path) = crate::util::exe_path() else { return err(StatusCode::INTERNAL_SERVER_ERROR, "no binary") };
    let Ok(bytes) = std::fs::read(&path) else { return err(StatusCode::INTERNAL_SERVER_ERROR, "cannot read the binary") };
    let sum = crate::release::sha256_hex(&bytes);
    // 3.69: the release signature goes along (the agent checks it with its own built-in key); the panel checks
    // first that it is the signature of this very file, so a stale one is not handed out
    let sig = crate::release::own_signature().filter(|s| crate::release::verify_update(&bytes, s).is_ok());
    let Some(sig) = sig else {
        return err(StatusCode::CONFLICT, "this panel's program has no release signature (installed by hand): update the panel first, then the servers");
    };
    signed_answer(&s.token, &h, StatusCode::OK, &[("x-sha256", sum), ("x-minisig", crate::util::b64(sig.as_bytes()))], bytes)
}

/// One click: updates every node, asks every tunnel-only server to update from the panel, then the
/// panel itself. A machine that is both a node and a tunnel server is updated once (through its node).
async fn update_all(State(app): St, h: HeaderMap) -> Response {
    // it updates the panel itself too: a login session, like Update › apply (an API token cannot)
    if let Err(r) = crate::auth::check_session(&app, &h) {
        return r;
    }
    Json(run_update_all(&app).await).into_response()
}

/// "Update all": the nodes, the tunnel servers (they take the panel's binary), then the panel itself.
/// Used by the button and by the nightly automatic update.
pub(crate) async fn run_update_all(app: &Arc<App>) -> Value {
    let app = app.clone();
    let latest = crate::admin::latest_version(&app).await.unwrap_or_default();
    let target = if latest.is_empty() { crate::VERSION.to_string() } else { latest.clone() };
    let panel_old = !latest.is_empty() && crate::admin::newer(&latest, crate::VERSION);
    let seen_now = seen().lock().unwrap_or_else(|e| e.into_inner()).clone();
    let srv = servers(&app);
    let mut covered: HashSet<String> = HashSet::new();
    // node id -> the tunnel servers of the same machine (when its own update fails, their agent takes over)
    let mut machine: HashMap<String, Vec<String>> = HashMap::new();
    let mut jobs = vec![];
    // every node, a relay whose VPN serves nobody too (it runs the same program)
    for n in app.db.nodes().into_iter().filter(|n| n.id != "local") {
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
                machine.entry(n.id.clone()).or_default().push(s.id.clone());
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
            (ok.then(|| n.clone()), n.id.clone(), json!({ "name": n.name, "ok": ok, "error": e }))
        }));
    }
    let mut nodes_out = vec![];
    let mut restarting = vec![];
    for j in jobs {
        if let Ok((n, nid, v)) = j.await {
            // the node takes its update from GitHub; where GitHub cannot be reached (often inside Iran) it
            // fails, and the tunnel agent of the same machine takes the panel's own program instead
            // (the node restarts onto it with the agent: they run the same file)
            if n.is_none() {
                for sid in machine.get(&nid).into_iter().flatten() {
                    covered.remove(sid);
                }
            }
            nodes_out.push(v);
            restarting.extend(n);
        }
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
    crate::sync::refresh_after_update(&app, restarting, &target);
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
        // 3.69: nothing updates by itself in a build without the release signing key
        if crate::migrate::frozen() || app.db.get("auto_update") != "1" || !crate::release::signing_active() {
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
    let signed = crate::release::signing_active();
    Json(json!({ "on": signed && app.db.get("auto_update") == "1", "signed": signed, "next": next_run_ts(), "last": last })).into_response()
}

async fn auto_update_put(State(app): St, h: HeaderMap, Json(b): Json<Value>) -> Response {
    let _ = guard!(app, h, "admin");
    let on = b["on"].as_bool().unwrap_or(false);
    // 3.69: off until signed updates are active in this build (an unsigned file would run as root every night)
    if on && !crate::release::signing_active() {
        return err(StatusCode::CONFLICT, "automatic update needs a build with the release signing key (signed updates): update by hand for now");
    }
    app.db.set("auto_update", if on { "1" } else { "" });
    Json(json!({ "ok": true, "on": on, "next": next_run_ts() })).into_response()
}

#[cfg(test)]
mod auto_update_tests {
    /// A build without the release key (every test build) keeps the automatic update off, even when asked
    #[tokio::test]
    async fn automatic_update_stays_off_without_signed_updates() {
        use tower::ServiceExt;
        assert!(!crate::release::signing_active());
        let app = crate::test_app();
        app.db.set("auto_update", "1");
        let t = crate::auth::test_session(&app);
        let call = |m: &str, body: &str| {
            let (app, t) = (app.clone(), t.clone());
            let r = axum::http::Request::builder().method(m).uri("/api/auto-update").header("authorization", format!("Bearer {}", t))
                .header("content-type", "application/json").header("x-forwarded-for", "203.0.113.70").body(axum::body::Body::from(body.to_string())).unwrap();
            async move {
                let res = crate::api::master_router(app).oneshot(r).await.unwrap();
                let st = res.status();
                let b = axum::body::to_bytes(res.into_body(), 1 << 16).await.unwrap();
                (st, serde_json::from_slice::<serde_json::Value>(&b).unwrap_or_default())
            }
        };
        let (st, v) = call("GET", "").await;
        assert_eq!((st.as_u16(), v["on"].as_bool(), v["signed"].as_bool()), (200, Some(false), Some(false)));
        let (st, _) = call("PUT", r#"{"on":true}"#).await;
        assert_eq!(st.as_u16(), 409);
        // a self update refuses before it downloads anything
        app.db.set("auto_update", "");
        assert!(crate::admin::self_update(&app).await.unwrap_err().contains("signing key"));
    }

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

#[cfg(test)]
mod route_tests {
    use super::{walk_back, walk_back_by, Tunnel};

    fn hop(e: &str, x: &str, udp: &[&str]) -> Tunnel {
        Tunnel { entry: e.into(), exit: x.into(), udp: udp.iter().map(|s| s.to_string()).collect(), enabled: true, ..Default::default() }
    }

    #[test]
    fn a_multi_location_route_is_followed_to_its_first_entry() {
        // Iran → Turkey → Germany; on the Turkey hop the port moved (4002 on Turkey to 4001 on Germany)
        let list = vec![hop("ir", "tr", &["51824", "4002"]), hop("tr", "de", &["51824", "4002:4001"])];
        assert_eq!(walk_back(&list, "de", 4001), vec![("de".to_string(), 4001), ("tr".to_string(), 4002), ("ir".to_string(), 4002)]);
        assert_eq!(walk_back(&list, "de", 51824).last().cloned(), Some(("ir".to_string(), 51824)));
        // a port no tunnel carries stays where it is
        assert_eq!(walk_back(&list, "de", 8445), vec![("de".to_string(), 8445)]);
        // one hop only
        assert_eq!(walk_back(&list, "tr", 4002).last().cloned(), Some(("ir".to_string(), 4002)));
    }

    #[test]
    fn tcp_ports_follow_their_own_lists() {
        let mut a = hop("ir", "tr", &["4002"]);
        a.tcp = vec!["443:8443".into()];
        let mut b = hop("tr", "de", &["4002"]);
        b.tcp = vec!["8443:2083".into()];
        let list = vec![a, b];
        assert_eq!(walk_back_by(&list, "de", 2083, true).last().cloned(), Some(("ir".to_string(), 443)));
        // the UDP list does not carry it
        assert_eq!(walk_back_by(&list, "de", 2083, false).len(), 1);
    }

    #[test]
    fn a_loop_of_tunnels_does_not_go_round_forever() {
        let list = vec![hop("a", "b", &["5000"]), hop("b", "a", &["5000"])];
        assert_eq!(walk_back(&list, "b", 5000), vec![("b".to_string(), 5000), ("a".to_string(), 5000)]);
    }
}


// ------------------------------------------------------------------ what a removal left to do on each server

/// One server's part of a removal: "tunnel" (it stops the tunnel and closes its ports), "server"
/// (its agent removes everything Kanki installed and uninstalls itself) or "node" (the VPN part:
/// its services, their ports and its agent). state: wait, done; a server not heard from is shown "off".
#[derive(Serialize, Clone, Debug)]
pub(crate) struct Step {
    pub server: String,
    pub name: String,
    pub what: String,
    pub tunnel: String,
    pub state: String,
    /// the last time the server was heard from (0 = never)
    ping: i64,
    gone: u32,
}

#[derive(Serialize, Clone, Debug)]
pub(crate) struct Removal {
    pub id: String,
    pub kind: String,
    pub name: String,
    pub at: i64,
    pub steps: Vec<Step>,
}

fn removals() -> &'static Mutex<HashMap<String, Removal>> {
    static R: OnceLock<Mutex<HashMap<String, Removal>>> = OnceLock::new();
    R.get_or_init(|| Mutex::new(HashMap::new()))
}

/// A server's name and when it was last heard from, for a step
pub(crate) fn step(app: &App, server: &str, what: &str, tunnel: &str) -> Step {
    let name = if server == "local" { local_name(app) } else { servers(app).into_iter().find(|s| s.id == server).map(|s| s.name).unwrap_or_else(|| server.to_string()) };
    let ping = seen().lock().unwrap_or_else(|e| e.into_inner()).get(server).map(|x| x.at).unwrap_or(0);
    // the panel server stops its own Xray / DNS right away
    let state = if server == "local" && (what == "xray" || what == "dns") { "done" } else { "wait" };
    Step { server: server.into(), name, what: what.into(), tunnel: tunnel.into(), state: state.into(), ping, gone: 0 }
}

/// A step whose server is not a tunnel server (a VPN node): the caller sets its state
pub(crate) fn node_step(id: &str, name: &str) -> Step {
    Step { server: format!("node:{}", id), name: name.into(), what: "node".into(), tunnel: String::new(), state: "wait".into(), ping: now(), gone: 0 }
}

/// Starts following a removal; the id is given to the admin page, which asks how far it got
pub(crate) fn track(kind: &str, name: &str, steps: Vec<Step>) -> String {
    let id = rand_token(12);
    let mut r = removals().lock().unwrap_or_else(|e| e.into_inner());
    // an hour is long enough to look at it
    r.retain(|_, x| now() - x.at < 3600);
    r.insert(id.clone(), Removal { id: id.clone(), kind: kind.into(), name: name.into(), at: now(), steps });
    id
}

/// The tunnels of a server, each as a step on the server at its other end
pub(crate) fn tunnel_steps(app: &App, list: &[Tunnel], except: &str) -> Vec<Step> {
    let mut out = vec![];
    for t in list {
        for sid in [&t.entry, &t.exit] {
            if sid != except {
                out.push(step(app, sid, "tunnel", &t.id));
            }
        }
    }
    out
}

/// A server reported what it runs: the tunnels it no longer runs, and Xray / Kanki DNS when they
/// stopped, are done
fn note_report(server: &str, status: &[Status], xray_on: bool, dns_on: bool) {
    let mut r = removals().lock().unwrap_or_else(|e| e.into_inner());
    for x in r.values_mut() {
        for s in x.steps.iter_mut().filter(|s| s.server == server) {
            let left = match s.what.as_str() {
                "tunnel" => status.iter().any(|st| st.id == s.tunnel),
                "xray" => xray_on,
                "dns" => dns_on,
                _ => continue,
            };
            s.ping = now();
            if s.state != "done" && !left {
                s.state = "done".into();
            }
        }
    }
}

/// The servers deleted in this panel (id -> when), kept 60 days. Only these are told "gone" (and so
/// uninstall themselves): a server this panel simply does not know (a fresh install in the middle of a
/// move, a restore of an older backup, another panel) is left running.
fn removed_ids(app: &App) -> std::collections::HashMap<String, i64> {
    serde_json::from_str(&app.db.get("tun_removed")).unwrap_or_default()
}

fn mark_removed(app: &App, id: &str, token: &str) {
    let mut m = removed_ids(app);
    m.retain(|_, t| now() - *t < 60 * 86400);
    m.insert(id.to_string(), now());
    app.db.set("tun_removed", &serde_json::to_string(&m).unwrap_or_else(|_| "{}".into()));
    // 3.69: its token is kept as long (sealed at rest), so the «gone» answer can be signed: an agent that knows the
    // panel signs uninstalls itself only on a signed one, never on one a man in the middle made up
    let mut t: std::collections::HashMap<String, String> = serde_json::from_str(&app.db.get("tun_removed_tok")).unwrap_or_default();
    t.retain(|k, _| m.contains_key(k));
    t.insert(id.to_string(), token.to_string());
    app.db.set("tun_removed_tok", &serde_json::to_string(&t).unwrap_or_else(|_| "{}".into()));
}

/// The token a removed server had (to sign the «gone» answer with)
fn removed_token(app: &App, id: &str) -> Option<String> {
    let t: std::collections::HashMap<String, String> = serde_json::from_str(&app.db.get("tun_removed_tok")).unwrap_or_default();
    t.get(id).cloned().filter(|x| !x.is_empty())
}

pub(crate) fn was_removed(app: &App, id: &str) -> bool {
    removed_ids(app).contains_key(id)
}

/// A removed server asked again: after three answers its agent removes everything and uninstalls
fn note_gone(server: &str) {
    let mut r = removals().lock().unwrap_or_else(|e| e.into_inner());
    for x in r.values_mut() {
        for s in x.steps.iter_mut().filter(|s| s.server == server && s.what == "server") {
            s.ping = now();
            s.gone += 1;
            if s.gone >= 3 {
                s.state = "done".into();
            }
        }
    }
}

/// Sets the state of a node's step in every removal that waits on it
pub(crate) fn note_node(id: &str, state: &str) {
    let key = format!("node:{}", id);
    let mut r = removals().lock().unwrap_or_else(|e| e.into_inner());
    for x in r.values_mut() {
        for s in x.steps.iter_mut().filter(|s| s.server == key && s.state != "done") {
            s.state = state.into();
            s.ping = now();
        }
    }
}

/// How far a removal got; a step whose server was not heard from for 30 seconds is "off" (it is done
/// when the server comes back: the tunnel is not in its list any more, a removed server is told so)
pub(crate) fn removal(id: &str) -> Option<Removal> {
    let mut x = removals().lock().unwrap_or_else(|e| e.into_inner()).get(id).cloned()?;
    for s in x.steps.iter_mut() {
        if s.state != "done" && s.what != "node" && now() - s.ping > 30 {
            s.state = "off".into();
        }
    }
    Some(x)
}

async fn removal_get(State(app): St, h: HeaderMap, Path(id): Path<String>) -> Response {
    let _ = guard!(app, h, "nodes");
    match removal(&id) {
        Some(x) => Json(json!(x)).into_response(),
        None => err(StatusCode::NOT_FOUND, "unknown removal"),
    }
}

#[cfg(test)]
mod removal_tests {
    use super::*;

    fn st(server: &str, what: &str, tunnel: &str) -> Step {
        Step { server: server.into(), name: server.into(), what: what.into(), tunnel: tunnel.into(), state: "wait".into(), ping: now(), gone: 0 }
    }

    #[test]
    fn steps_finish_as_servers_report() {
        let rid = track("server", "x", vec![st("rt_a", "server", ""), st("rt_b", "tunnel", "rt_t1"), st("rt_c", "xray", "")]);
        let running = Status { id: "rt_t1".into(), ..Default::default() };
        note_report("rt_b", std::slice::from_ref(&running), false, false);
        note_report("rt_c", &[], true, false);
        note_gone("rt_a");
        note_gone("rt_a");
        let r = removal(&rid).unwrap();
        assert!(r.steps.iter().all(|s| s.state == "wait"));
        note_report("rt_b", &[], false, false);
        note_report("rt_c", &[], false, false);
        note_gone("rt_a");
        let r = removal(&rid).unwrap();
        assert!(r.steps.iter().all(|s| s.state == "done"), "{:?}", r.steps);
    }

    #[test]
    fn a_silent_server_shows_off() {
        let mut s = st("rt_off", "tunnel", "t");
        s.ping = now() - 120;
        let rid = track("tunnel", "t", vec![s]);
        assert_eq!(removal(&rid).unwrap().steps[0].state, "off");
    }
}

#[cfg(test)]
mod quality_tests {
    //! «📡 وضعیت مسیرها»: the live measurements the entries report become one verdict per server pair
    use super::*;
    use std::sync::atomic::AtomicI64;

    fn test_app() -> Arc<App> {
        let dir = std::env::temp_dir().join(format!("kanki-pq-test-{}", rand_token(8)));
        std::fs::create_dir_all(&dir).unwrap();
        let db = crate::db::Db::open(dir.join("kanki.db").to_str().unwrap());
        Arc::new(App {
            db,
            env: HashMap::from([("DOMAIN".to_string(), "fi.example.com".to_string())]),
            hy2_allowed: Mutex::new(HashMap::new()), limits: Mutex::new(HashMap::new()), reported: Mutex::new(HashMap::new()),
            login_fails: Mutex::new(HashMap::new()), sync_lock: tokio::sync::Mutex::new(()), bot_alive: AtomicI64::new(0),
            http: reqwest::Client::new(), http_insecure: reqwest::Client::new(), pin_clients: Mutex::new(HashMap::new()),
        })
    }

    /// the two servers report: every tunnel up, the entry with one measurement of (loss, jitter) each
    fn report(at: i64, q: &[(f64, f64)]) {
        let tid = |i: usize| format!("pqt{}", i);
        let entry: Vec<Status> = q.iter().enumerate().map(|(i, (loss, jit))| Status {
            id: tid(i), role: "entry".into(), links: 2,
            quality: Some(json!({"at": at, "n": 20, "loss": loss, "ping": 75, "jit": jit, "max": 90})), ..Default::default()
        }).collect();
        let exit: Vec<Status> = (0..q.len()).map(|i| Status { id: tid(i), role: "exit".into(), links: 2, ..Default::default() }).collect();
        let mut sn = seen().lock().unwrap();
        for (sid, status) in [("pq_ir", entry), ("pq_de", exit)] {
            sn.insert(sid.into(), Seen { at: now(), status, ..Default::default() });
        }
    }

    /// a tunnel nobody named always gets one shape: the Iran server short, the abroad server, the core
    #[test]
    fn unnamed_tunnels_get_one_shape() {
        let app = test_app();
        save_servers(&app, &[
            TServer { id: "nm_en".into(), name: "England".into(), loc: "abroad".into(), ..Default::default() },
            TServer { id: "nm_ir".into(), name: "IRAN 2".into(), loc: "iran".into(), ..Default::default() },
        ]);
        assert_eq!(default_tunnel_name(&app, "nm_ir", "nm_en", "kmix"), "IR2-ENGLAND-KMIX");
        // the abroad server dialling in: still the Iran one first
        assert_eq!(default_tunnel_name(&app, "nm_en", "nm_ir", "game"), "IR2-ENGLAND-GAME");
        assert_eq!(default_tunnel_name(&app, "nm_ir", "nm_en", ""), "IR2-ENGLAND");
        assert_eq!(default_tunnel_name(&app, "", "nm_en", "wg"), "");
    }

    #[test]
    fn a_lossy_path_is_one_alert_and_every_tunnel_shows() {
        let app = test_app();
        save_servers(&app, &[
            TServer { id: "pq_de".into(), name: "GERMANY".into(), loc: "abroad".into(), ..Default::default() },
            TServer { id: "pq_ir".into(), name: "IRAN1".into(), loc: "iran".into(), ..Default::default() },
        ]);
        let tu = |i: usize, name: &str, tr: &str| Tunnel { id: format!("pqt{}", i), name: name.into(), entry: "pq_ir".into(), exit: "pq_de".into(), transport: tr.into(), enabled: true, ..Default::default() };
        save_tunnels(&app, &[tu(0, "IR1-GERMANY-WG", "game"), tu(1, "IR1-GERMANY-AWG", "game"), tu(2, "IR1-GERMANY-HQ", "hq")]);
        // not enough minutes yet: nothing is judged
        let t = now();
        report(t - 170, &[(0.0, 2.0), (0.0, 2.0), (0.0, 2.0)]);
        super::super::quality::ingest(&app);
        assert!(super::super::quality::health(&app).is_empty());
        assert!(super::super::quality::report(&app).contains("هنوز داده نیست"));
        // six minutes where two of the three tunnels lose 10 %: one alert for the whole path
        for k in 0..6 {
            report(t - 160 + k * 30, &[(10.0, 40.0), (12.0, 35.0), (0.0, 2.0)]);
            super::super::quality::ingest(&app);
        }
        let h = super::super::quality::health(&app);
        assert_eq!(h.len(), 1, "{:?}", h);
        assert_eq!((h[0].0.as_str(), h[0].1.as_str(), h[0].2), ("pq:pq_de|pq_ir", "IRAN1 ↔ GERMANY", false));
        let r = super::super::quality::report(&app);
        assert!(r.contains("🔴 <b>IRAN1 ↔ GERMANY</b>") && r.contains("IR1-GERMANY-HQ · HQ-QUIC") && r.contains("🟢 IR1-GERMANY-HQ"), "{}", r);
        assert!(r.chars().count() < 4096);
        // the exit stops reporting a link of one tunnel: it shows as cut
        {
            let mut sn = seen().lock().unwrap();
            sn.get_mut("pq_de").unwrap().status[2].links = 0;
        }
        assert!(super::super::quality::report(&app).contains("🔴 IR1-GERMANY-HQ · HQ-QUIC: قطع"));
        // the mini app's page: one card for the server abroad with its three tunnels, from IRAN1
        let v = super::super::quality::view(&app);
        let sv = v["servers"].as_array().unwrap();
        assert_eq!(sv.len(), 1, "{}", v);
        assert_eq!((sv[0]["name"].as_str(), sv[0]["id"].as_str(), sv[0]["state"].as_str()), (Some("GERMANY"), Some("pq_de"), Some("bad")));
        let ts = sv[0]["tunnels"].as_array().unwrap();
        assert_eq!(ts.len(), 3);
        assert!(ts.iter().all(|t| t["from"] == "IRAN1"));
        let hq = ts.iter().find(|t| t["name"] == "IR1-GERMANY-HQ").unwrap();
        assert_eq!((hq["up"].as_bool(), hq["transport"].as_str()), (Some(false), Some("HQ-QUIC")));
        let wg = ts.iter().find(|t| t["name"] == "IR1-GERMANY-WG").unwrap();
        assert_eq!((wg["now"]["level"].as_str(), wg["now"]["ping"].as_u64()), (Some("bad"), Some(75)));
        // path alerts: on by default, the switch turns them off (server alerts do not depend on it)
        assert_eq!(v["alerts"], true);
        app.db.set("path_alerts", "0");
        assert!(!super::super::quality::alerts_on(&app));
        assert_eq!(super::super::quality::view(&app)["alerts"], false);
    }

    #[test]
    fn the_verdict_needs_a_clear_improvement() {
        use super::super::quality::{judge, pair_agg, Agg};
        let a = |loss: f64| Agg { n: 6, loss, ping: 75, jit: 5.0, max: 90 };
        // 2.5 % after a bad spell is not yet good
        assert!(judge(true, &pair_agg(&[a(2.5)]).unwrap()));
        assert!(!judge(true, &pair_agg(&[a(0.5)]).unwrap()));
    }
}

#[cfg(test)]
mod guard_tests {
    use super::*;

    fn test_app() -> Arc<App> {
        use std::sync::atomic::AtomicI64;
        let dir = std::env::temp_dir().join(format!("kanki-guard-test-{}", rand_token(8)));
        std::fs::create_dir_all(&dir).unwrap();
        Arc::new(App {
            db: crate::db::Db::open(dir.join("kanki.db").to_str().unwrap()),
            env: HashMap::from([("DOMAIN".to_string(), "fi.example.com".to_string())]),
            hy2_allowed: Mutex::new(Default::default()), limits: Mutex::new(Default::default()), reported: Mutex::new(Default::default()),
            login_fails: Mutex::new(Default::default()), sync_lock: tokio::sync::Mutex::new(()), bot_alive: AtomicI64::new(0),
            http: reqwest::Client::new(), http_insecure: reqwest::Client::new(), pin_clients: Mutex::new(Default::default()),
        })
    }

    /// The panel confirms only once the server's VPN part synced after the firewall went on; a server
    /// that stays unreachable gets the switch turned off (and the reason kept)
    #[test]
    fn the_panel_confirms_or_rolls_back() {
        let app = test_app();
        app.db.exec("INSERT INTO nodes(id,name,address,endpoint,token,info,online,last_sync) VALUES('n1','DE','https://de:1','de','t','{}',1,0)", &[]).unwrap();
        save_servers(&app, &[TServer { id: "g1".into(), name: "DE".into(), node: "n1".into(), ..Default::default() }]);
        // not asked: nothing
        assert_eq!(guard_answer(&app, "g1", &json!({})), (false, false));
        guard_switch(&app, "g1", true);
        assert!(guard_wanted(&app, "g1"));
        // the server has not turned it on yet, then has: asked, not confirmed (too soon)
        assert_eq!(guard_answer(&app, "g1", &json!({ "on": false })), (true, false));
        let on = json!({ "on": true, "confirmed": false, "since": 1 });
        assert_eq!(guard_answer(&app, "g1", &on), (true, false));
        // settled, but the node did not sync since: still waiting
        guard_watch().lock().unwrap().get_mut("g1").unwrap().seen_on = now() - GUARD_SETTLE - 1;
        assert_eq!(guard_answer(&app, "g1", &on), (true, false));
        // the panel reached the node afterwards: confirmed
        app.db.exec("UPDATE nodes SET last_sync=?1 WHERE id='n1'", &[&now()]).unwrap();
        assert_eq!(guard_answer(&app, "g1", &on), (true, true));
        // a second run: the node never answers again → given up, the switch off, the reason kept
        guard_switch(&app, "g1", true);
        app.db.exec("UPDATE nodes SET online=0 WHERE id='n1'", &[]).unwrap();
        assert_eq!(guard_answer(&app, "g1", &on), (true, false));
        guard_watch().lock().unwrap().get_mut("g1").unwrap().seen_on = now() - GUARD_GIVE_UP - 1;
        assert_eq!(guard_answer(&app, "g1", &on), (false, false));
        assert!(!guard_wanted(&app, "g1"));
        assert!(app.db.get("fw_guard_note_g1").contains("could not reach"));
        // the server rolled back by itself: the switch goes off with its reason
        guard_switch(&app, "g1", true);
        assert_eq!(guard_answer(&app, "g1", &json!({ "on": false, "note": "rolled back: the panel did not see this server working with the firewall on" })), (false, false));
        assert!(!guard_wanted(&app, "g1") && app.db.get("fw_guard_note_g1").starts_with("rolled back"));
        // the panel's own server has its own switch
        guard_switch(&app, "local", true);
        assert!(guard_wanted(&app, "local"));
    }
}

#[cfg(test)]
mod fec_tests {
    #[test]
    fn only_a_real_fec_is_taken() {
        for ok in ["", "off", "0", "8:3", "8:1", "64:32", "8 : 3"] {
            assert!(super::fec_ok(ok), "{}", ok);
        }
        for bad in ["0:3", "8:0", "1:2:3", "8", "65:3", "8:33", "a:b", "8:"] {
            assert!(!super::fec_ok(bad), "{}", bad);
        }
    }
}

#[cfg(test)]
mod rotate_tests {
    use super::*;
    use std::sync::atomic::AtomicI64;

    fn tun(id: &str, entry: &str, tr: &str, port: u16, udp: &[&str]) -> Tunnel {
        Tunnel { id: id.into(), name: id.into(), entry: entry.into(), exit: "de".into(), mode: "reverse".into(), transport: tr.into(), port, enabled: true, udp: udp.iter().map(|x| x.to_string()).collect(), ..Default::default() }
    }

    /// A tunnel that switches by itself skips a transport whose port is taken on the protocol it moves to
    #[test]
    fn a_switch_does_not_take_a_used_port() {
        let dir = std::env::temp_dir().join(format!("kanki-rot-test-{}", rand_token(8)));
        std::fs::create_dir_all(&dir).unwrap();
        let db = crate::db::Db::open(dir.join("kanki.db").to_str().unwrap());
        let app = Arc::new(App {
            db, env: HashMap::new(),
            hy2_allowed: Mutex::new(HashMap::new()), limits: Mutex::new(HashMap::new()), reported: Mutex::new(HashMap::new()),
            login_fails: Mutex::new(HashMap::new()), sync_lock: tokio::sync::Mutex::new(()), bot_alive: AtomicI64::new(0),
            http: reqwest::Client::new(), http_insecure: reqwest::Client::new(), pin_clients: Mutex::new(HashMap::new()),
        });
        // a TCP tunnel on 5000; on the same Iran server another tunnel forwards UDP 5000 (and one listens on UDP 6000)
        let me = tun("me", "ir", "tcp", 5000, &["51820:51820"]);
        let other = tun("o", "ir", "tcp", 7000, &["5000:5000"]);
        let list = vec![me.clone(), other];
        assert!(rotate_clash(&app, &list, &me, "kcp"));
        assert!(rotate_clash(&app, &list, &me, "dual"));
        assert!(!rotate_clash(&app, &list, &me, "ws"));
        // its own forwarded UDP port is the tunnel port
        let me2 = tun("me2", "ir", "tcp", 51820, &["51820:51820"]);
        assert!(rotate_clash(&app, std::slice::from_ref(&me2), &me2, "kcp"));
        // another server: free
        let far = tun("far", "ir2", "tcp", 5000, &[]);
        assert!(!rotate_clash(&app, &list, &far, "kcp"));
        let order: Vec<String> = ["kcp", "dual", "ws"].iter().map(|x| x.to_string()).collect();
        assert_eq!(next_transport(&order, "tcp", |tr| !rotate_clash(&app, &list, &me, tr)).as_deref(), Some("ws"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod fwd_tests {
    use super::*;
    use std::sync::atomic::AtomicI64;

    /// A direct tunnel: both ends get their spec with the other server's real address, GRE links get their own
    /// numbers, old agents are refused, and the cores' second config through Iran follows its ports like any tunnel
    #[test]
    fn a_direct_tunnel_reaches_both_servers_and_carries_its_ports() {
        let dir = std::env::temp_dir().join(format!("kanki-fwd-test-{}", rand_token(8)));
        std::fs::create_dir_all(&dir).unwrap();
        let app = Arc::new(App {
            db: crate::db::Db::open(dir.join("kanki.db").to_str().unwrap()), env: HashMap::new(),
            hy2_allowed: Mutex::new(HashMap::new()), limits: Mutex::new(HashMap::new()), reported: Mutex::new(HashMap::new()),
            login_fails: Mutex::new(HashMap::new()), sync_lock: tokio::sync::Mutex::new(()), bot_alive: AtomicI64::new(0),
            http: reqwest::Client::new(), http_insecure: reqwest::Client::new(), pin_clients: Mutex::new(HashMap::new()),
        });
        save_servers(&app, &[
            TServer { id: "fw_ir".into(), name: "IRAN".into(), loc: "iran".into(), addr: "ir.example.com".into(), ..Default::default() },
            TServer { id: "fw_de".into(), name: "DE".into(), addr: "de.example.com".into(), ..Default::default() },
        ]);
        {
            let mut sn = seen().lock().unwrap();
            sn.insert("fw_ir".into(), Seen { at: now(), ip: "198.51.100.10".into(), version: "3.59.0".into(), ..Default::default() });
            sn.insert("fw_de".into(), Seen { at: now(), ip: "203.0.113.20".into(), version: "3.59.0".into(), ..Default::default() });
        }
        let mut t = Tunnel { id: "fwa".into(), name: "d".into(), entry: "fw_ir".into(), exit: "fw_de".into(), kind: "fwd".into(), enabled: true, udp: vec!["4000".into()], tcp: vec!["8443:443".into()], ..Default::default() };
        fwd_apply_body(&[], &mut t, &json!({ "mode": "gre" })).unwrap();
        assert!(t.fwd.gre() && t.fwd.n == 1 && t.port == 0 && t.transport == "fwd");
        // a second GRE tunnel gets another link number; a bad mode or target is refused
        let mut t2 = Tunnel { id: "fwb".into(), kind: "fwd".into(), ..t.clone() };
        t2.fwd = FwdCfg::default();
        fwd_apply_body(&[t.clone()], &mut t2, &json!({ "mode": "gre" })).unwrap();
        assert_eq!(t2.fwd.n, 2);
        assert!(fwd_apply_body(&[], &mut t2.clone(), &json!({ "mode": "rathole" })).is_err());
        let mut bad = t.clone();
        bad.target = "1.2.3.4; reboot".into();
        assert!(fwd_apply_body(&[], &mut bad, &json!({})).is_err());
        assert!(fwd_checks(&app, &t).is_ok());
        save_tunnels(&app, &[t.clone()]);
        // each end: its own spec with the other server's public IPv4, not its name
        let e = specs_for(&app, "fw_ir").into_iter().find(|s| s.id == "fwa").unwrap();
        let f = e.fwd.unwrap();
        assert_eq!((f.role.as_str(), f.peer.as_str(), f.n, f.mode.as_str()), ("entry", "203.0.113.20", 1, "gre"));
        let x = specs_for(&app, "fw_de").into_iter().find(|s| s.id == "fwa").unwrap().fwd.unwrap();
        assert_eq!((x.role.as_str(), x.peer.as_str()), ("exit", "198.51.100.10"));
        // the second config of a core on UDP 4000 of the exit goes through the Iran server, like any tunnel
        assert_eq!(port_entry_at(&app, "fw_de", 4000, false, ""), Some(("fw_ir".to_string(), 4000)));
        assert_eq!(port_entry_at(&app, "fw_de", 443, true, ""), Some(("fw_ir".to_string(), 8443)));
        // an agent too old for it
        seen().lock().unwrap().get_mut("fw_de").unwrap().version = "3.58.1".into();
        assert!(fwd_checks(&app, &t).unwrap_err().contains("3.59.0"));
    }

    /// KANKI-UP: a udp2raw pair per UDP port with a row of raw ports on the exit, the same options on both ends,
    /// a key that stays, only known values, UDP only, old agents refused, and the cores' ports followed through Iran
    #[test]
    fn a_kanki_up_tunnel_gives_each_port_its_udp2raw_pair() {
        let dir = std::env::temp_dir().join(format!("kanki-kup-test-{}", rand_token(8)));
        std::fs::create_dir_all(&dir).unwrap();
        let app = Arc::new(App {
            db: crate::db::Db::open(dir.join("kanki.db").to_str().unwrap()), env: HashMap::new(),
            hy2_allowed: Mutex::new(HashMap::new()), limits: Mutex::new(HashMap::new()), reported: Mutex::new(HashMap::new()),
            login_fails: Mutex::new(HashMap::new()), sync_lock: tokio::sync::Mutex::new(()), bot_alive: AtomicI64::new(0),
            http: reqwest::Client::new(), http_insecure: reqwest::Client::new(), pin_clients: Mutex::new(HashMap::new()),
        });
        save_servers(&app, &[
            TServer { id: "ku_ir".into(), name: "IRAN".into(), loc: "iran".into(), addr: "ir.example.com".into(), ..Default::default() },
            TServer { id: "ku_tr".into(), name: "TR".into(), addr: "tr.example.com".into(), ..Default::default() },
        ]);
        {
            let mut sn = seen().lock().unwrap();
            sn.insert("ku_ir".into(), Seen { at: now(), ip: "198.51.100.11".into(), version: KUP_FROM.into(), ..Default::default() });
            sn.insert("ku_tr".into(), Seen { at: now(), ip: "203.0.113.21".into(), version: KUP_FROM.into(), ..Default::default() });
        }
        let mut t = Tunnel { id: "kua".into(), name: "u".into(), entry: "ku_ir".into(), exit: "ku_tr".into(), kind: "kup".into(), enabled: true, port: 29000, udp: vec!["51820".into(), "4000".into(), "1443:443".into()], ..Default::default() };
        kup_apply_body(&mut t, &json!({ "raw_mode": "faketcp", "seq_mode": 4 })).unwrap();
        let key = t.kup.clone().unwrap().key;
        assert!(crate::tunnel::kup::key_ok(&key) && t.transport == "kup" && t.mode == "direct");
        // an edit without a key keeps it; "new_key" makes another
        kup_apply_body(&mut t, &json!({ "key": "" })).unwrap();
        assert_eq!(t.kup.clone().unwrap().key, key);
        let mut t2 = t.clone();
        kup_apply_body(&mut t2, &json!({ "new_key": true })).unwrap();
        assert_ne!(t2.kup.unwrap().key, key);
        // UDP only, one port in ICMP mode, only known values
        assert!(kup_apply_body(&mut Tunnel { tcp: vec!["443".into()], ..t.clone() }, &json!({})).is_err());
        assert!(kup_apply_body(&mut t.clone(), &json!({ "raw_mode": "icmp" })).is_err());
        assert!(kup_apply_body(&mut t.clone(), &json!({ "raw_mode": "faketcp\n--clear" })).is_err());
        assert!(kup_apply_body(&mut t.clone(), &json!({ "cipher": "rc4" })).is_err());
        assert!(kup_apply_body(&mut Tunnel { target: "1.2.3.4; reboot".into(), ..t.clone() }, &json!({})).is_err());
        assert!(kup_apply_body(&mut Tunnel { port: 65535, ..t.clone() }, &json!({})).is_err());
        assert!(kup_checks(&app, &t).is_ok());
        save_tunnels(&app, &[t.clone()]);
        // the entry listens on the users' UDP ports (in port order) and dials the exit's public IPv4 on port + i
        let e = specs_for(&app, "ku_ir").into_iter().find(|s| s.id == "kua").unwrap().kup.unwrap();
        assert_eq!(e.iter().map(|w| (w.listen, w.host.as_str(), w.port)).collect::<Vec<_>>(), vec![(1443, "203.0.113.21", 29000), (4000, "203.0.113.21", 29001), (51820, "203.0.113.21", 29002)]);
        // the exit listens on the raw ports and hands the datagrams to the cores on 127.0.0.1
        let x = specs_for(&app, "ku_tr").into_iter().find(|s| s.id == "kua").unwrap().kup.unwrap();
        assert_eq!(x.iter().map(|w| (w.listen, w.host.as_str(), w.port)).collect::<Vec<_>>(), vec![(29000, "", 443), (29001, "", 4000), (29002, "", 51820)]);
        assert!(e.iter().chain(x.iter()).all(|w| w.cfg == e[0].cfg && w.cfg.seq_mode == 4 && w.cfg.key == key));
        // what it holds: TCP 29000-29002 on the exit (faketcp), UDP 51820/4000/1443 on the entry
        let needs = tunnel_needs(&t);
        assert!(needs.contains(&("ku_tr".into(), 29002, false)) && needs.contains(&("ku_ir".into(), 1443, true)) && !needs.contains(&("ku_tr".into(), 29003, false)));
        // the second config of KANKI MIX (UDP 4000 of the exit) and WireGuard go through the Iran server
        assert_eq!(port_entry_at(&app, "ku_tr", 4000, false, ""), Some(("ku_ir".to_string(), 4000)));
        assert_eq!(port_entry_at(&app, "ku_tr", 443, false, ""), Some(("ku_ir".to_string(), 1443)));
        // (3.63) the measuring pair: the next free raw port on the exit, its own udp2raw on both sides
        let mut tp = t.clone();
        kup_probe_port(&app, &mut tp);
        assert_eq!(tp.kup.as_ref().unwrap().probe_port, 29003);
        save_tunnels(&app, &[tp.clone()]);
        let e = specs_for(&app, "ku_ir").into_iter().find(|s| s.id == "kua").unwrap().kup.unwrap();
        let pe = e.iter().find(|w| w.probe).unwrap();
        assert_eq!((pe.listen, pe.port, e.iter().filter(|w| !w.probe).count()), (0, 29003, 3));
        let x = specs_for(&app, "ku_tr").into_iter().find(|s| s.id == "kua").unwrap().kup.unwrap();
        let px = x.iter().find(|w| w.probe).unwrap();
        assert_eq!((px.listen, px.port), (29003, 0));
        assert!(tunnel_needs(&tp).contains(&("ku_tr".into(), 29003, false)));
        // kept on the next save; ICMP mode has none
        kup_probe_port(&app, &mut tp);
        assert_eq!(tp.kup.as_ref().unwrap().probe_port, 29003);
        let mut ti = Tunnel { udp: vec!["51820".into()], ..tp.clone() };
        kup_apply_body(&mut ti, &json!({ "raw_mode": "icmp" })).unwrap();
        kup_probe_port(&app, &mut ti);
        assert_eq!(ti.kup.as_ref().unwrap().probe_port, 0);
        assert!(!specs_for(&app, "ku_ir").into_iter().any(|s| s.kup.is_some_and(|k| k.iter().any(|w| w.probe && w.cfg.raw_mode == "icmp"))));
        save_tunnels(&app, &[t.clone()]);
        // (3.63) the smart test's other kinds: a real tunnel of each, with its own keys and port
        let mut ids = vec![];
        for (i, k) in PROBE_KINDS.iter().enumerate() {
            let x = probe_extra(&app, "abc123", k, "ku_ir", "ku_tr", 39000 + i as u16).unwrap_or_else(|e| panic!("{}: {}", k, e));
            assert!(x.id.starts_with("probe-abc123-x-") && x.enabled && x.entry == "ku_ir");
            match x.kind.as_str() {
                "kup" => assert_eq!(x.kup.as_ref().unwrap().probe_port, 39000 + i as u16),
                "hy2" => assert!(x.hy2.port == 39000 + i as u16 && !x.hy2.auth.is_empty() && !x.hy2.pin.is_empty()),
                "awg" => assert!(x.awg.port == 39000 + i as u16 && !x.awg.entry_priv.is_empty()),
                "fwd" => assert!(x.fwd.gre() && x.fwd.n > 0),
                o => panic!("{}", o),
            }
            ids.push(x.id);
        }
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), PROBE_KINDS.len());
        // what one run through it means: ping and loss, a game score, nothing for download
        let r = probe_extra_result(Some(&json!({ "n": 20, "loss": 5.0, "ping": 80, "jit": 2.5 })), "", 10);
        assert!(r["done"].as_bool().unwrap() && r["udp_loss"].as_f64() == Some(5.0) && r["scores"]["gaming"].as_f64().unwrap() > 50.0 && r["scores"]["speed"].is_null());
        assert_eq!(probe_extra_result(None, "", 10)["done"].as_bool(), Some(false));
        assert!(probe_extra_result(Some(&json!({ "loss": 100.0 })), "x", 95)["error"].as_str() == Some("x"));
        // (3.63.1) KANKI-UP alone: no Kanki transport is added behind its back
        let (tr, kd) = probe_wanted(&json!({ "transports": [], "kinds": ["kup-faketcp", "kup-udp"] }));
        assert!(tr.is_empty() && kd == vec!["kup-faketcp".to_string(), "kup-udp".to_string()]);
        let (tr, kd) = probe_wanted(&json!({ "transports": ["game"], "kinds": [] }));
        assert!(tr == vec!["game".to_string()] && kd.is_empty());
        let (tr, kd) = probe_wanted(&json!({}));
        assert_eq!((tr.len(), kd.len()), (PROBE_TRANSPORTS.len(), PROBE_KINDS.len()));
        let (tr, _) = probe_wanted(&json!({ "transports": [], "kinds": [] }));
        assert_eq!(tr.len(), PROBE_TRANSPORTS.len());
        // an agent too old for it
        seen().lock().unwrap().get_mut("ku_tr").unwrap().version = "3.60.1".into();
        assert!(kup_checks(&app, &t).unwrap_err().contains(KUP_FROM));
    }
}
