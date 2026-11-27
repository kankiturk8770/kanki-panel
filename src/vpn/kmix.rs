//! KANKI MIX: our own UDP protocol, next to WireGuard / AmneziaWG / Hysteria2 on every VPN server.
//! Game UDP rides a raw datagram path (no queue, no retransmission, sent twice in gaming mode) and TCP
//! rides KCP + FEC, all under a ChaCha20-Poly1305 mask that has no fixed bytes on the wire.
//!
//! The server is the Go `kanki-server`, its source in this repository (`src/vpn/kmix-server`, built by
//! its `build.sh` and by CI into assets/bin/kanki-mix-server). The binary is built into the panel
//! and each agent writes it to its own server, so nodes need no
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
    /// the parity of KCP that still comes with FEC (links apps hold from before FEC went off); 0 = 3
    pub legacy_parity: u8,
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
    /// the second config, through the tunnel: the Iran address (domain or IP) whose tunnel forwards the
    /// KANKI MIX UDP port to this server ("" = the server's endpoint, when it is not its own address)
    pub tun_host: String,
    /// the UDP port on that Iran address (0 = the same port as the server)
    pub tun_port: u16,
    /// no second config for this server
    pub tun_off: bool,
    /// the name of the second config in the app ("" = "<server name> (تانل)")
    pub tun_name: String,
    /// the Iran servers (tunnel server ids) whose tunnels also carry the port but are not offered as an entry of
    /// their own (panel 3.67; the first one is the second config above)
    pub tun_skip: Vec<String>,
}

/// One Iran entry of a server's KANKI MIX: the Iran server, its address and the port it gives (panel 3.67)
#[derive(Clone, Debug, PartialEq)]
pub struct TunEntry {
    /// the Iran server's id ("" = not known: an address given by the server's endpoint)
    pub sid: String,
    pub host: String,
    pub port: u16,
    /// its name in the app
    pub name: String,
}

/// At most this many Iran entries a server offers (the first is the second config of before)
pub const MAX_TUN_ENTRIES: usize = 4;

#[derive(Clone, Debug)]
pub struct Settings {
    pub on: bool,
    pub port: u16,
    /// FEC parity of the links (KCP of apps from before KindKCPPlain); 0 = no FEC (the default, panel 3.67)
    pub parity: u8,
    /// the last parity above 0 (the links apps may still hold): KCP that comes with FEC is answered with it
    pub legacy_parity: u8,
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
        // FEC for TCP is off unless set (3.67): KCP resends by itself, parity only cost bandwidth; newer apps use
        // KCP without FEC anyway (KindKCPPlain)
        parity: db.get("kmix_parity").parse().ok().filter(|p| *p <= 10).unwrap_or(0),
        legacy_parity: db.get("kmix_parity_legacy").parse().ok().filter(|p| *p > 0 && *p <= 10).unwrap_or(3),
        hop: valid_hop(&db.get("kmix_hop")).unwrap_or_default(),
        gaming: db.get("kmix_gaming") != "0",
        nodes: role_nodes(app, serde_json::from_str(&db.get("kmix_nodes")).unwrap_or_default()),
    }
}

/// The per-server options with KANKI MIX off on every server whose role does not run it (not saved:
/// the server's own switch comes back when its role allows KANKI MIX again)
fn role_nodes(app: &App, mut m: HashMap<String, NodeOpt>) -> HashMap<String, NodeOpt> {
    for n in app.db.nodes().into_iter().filter(|n| !n.role().allows("kmix")) {
        m.entry(n.id).or_default().off = true;
    }
    m
}

/// Gives server `node_id` its own KANKI MIX port (it moves there on its next sync).
pub fn set_node_port(app: &App, node_id: &str, port: u16) {
    let mut m: HashMap<String, NodeOpt> = serde_json::from_str(&app.db.get("kmix_nodes")).unwrap_or_default();
    m.entry(node_id.to_string()).or_default().port = port;
    app.db.set("kmix_nodes", &serde_json::to_string(&m).unwrap_or_else(|_| "{}".into()));
}

/// KANKI MIX off (or on again) on server `node_id` only
pub fn set_node_off(app: &App, node_id: &str, off: bool) {
    let mut m: HashMap<String, NodeOpt> = serde_json::from_str(&app.db.get("kmix_nodes")).unwrap_or_default();
    m.entry(node_id.to_string()).or_default().off = off;
    app.db.set("kmix_nodes", &serde_json::to_string(&m).unwrap_or_else(|_| "{}".into()));
}

/// The node ids KANKI MIX keeps settings for
pub fn node_ids(app: &App) -> Vec<String> {
    serde_json::from_str::<HashMap<String, NodeOpt>>(&app.db.get("kmix_nodes")).map(|m| m.into_keys().collect()).unwrap_or_default()
}

/// A removed server's KANKI MIX settings go with it
pub fn forget_node(app: &App, node_id: &str) {
    let mut m: HashMap<String, NodeOpt> = serde_json::from_str(&app.db.get("kmix_nodes")).unwrap_or_default();
    if m.remove(node_id).is_some() {
        app.db.set("kmix_nodes", &serde_json::to_string(&m).unwrap_or_else(|_| "{}".into()));
    }
}

/// The second (tunnel) config of `node_id` follows its port when it used the old one.
pub fn move_tunnel_port(app: &App, node_id: &str, old: u16, new: u16) {
    let mut m: HashMap<String, NodeOpt> = serde_json::from_str(&app.db.get("kmix_nodes")).unwrap_or_default();
    if let Some(o) = m.get_mut(node_id) {
        if o.tun_port == old {
            o.tun_port = new;
            app.db.set("kmix_nodes", &serde_json::to_string(&m).unwrap_or_else(|_| "{}".into()));
        }
    }
}

/// "4001-4010" -> Some((4001, 4010)); at most 1000 ports, never port 0
pub fn hop_range(s: &str) -> Option<(u16, u16)> {
    let (a, b) = s.trim().split_once('-')?;
    let (a, b): (u16, u16) = (a.trim().parse().ok()?, b.trim().parse().ok()?);
    (a > 0 && b > a && b - a < 1000).then_some((a, b))
}

/// Does the range a-b hold one of these ports?
fn hop_holds(a: u16, b: u16, ports: &[u16]) -> bool {
    ports.iter().any(|p| (a..=b).contains(p))
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

/// The second config's address and port (None = no second config for this server): the Iran address
/// set for it, else the server's endpoint when that is an Iran entry (not the server's own address).
pub fn tunnel_target(app: &App, s: &Settings, n: &Node, port: u16) -> Option<(String, u16)> {
    let opt = s.nodes.get(&n.id).cloned().unwrap_or_default();
    if opt.tun_off {
        return None;
    }
    // the Iran server whose tunnel carries the KANKI MIX port, and the port it gives it there (3.61: never typed)
    if let Some(t) = crate::twin::of_node_port(app, n, port) {
        if let Some(p) = t.carried(app, port, false) {
            return Some((t.host, p));
        }
    }
    let ep = crate::api::endpoint(app, n);
    let ep_host = ep.trim().trim_start_matches('[').split(']').next().unwrap_or("").to_string();
    let ep_host = if ep.contains('[') { ep_host } else { ep.split(':').next().unwrap_or("").to_string() };
    let primary = link_host(app, s, n);
    let direct = direct_host(app, n);
    if ep_host.is_empty() || ep_host == direct || ep_host == primary || ep_host == "127.0.0.1" {
        return None;
    }
    // only when a tunnel really forwards the KANKI MIX UDP port (else the config would point at a
    // dead port); the address and port are the tunnel's own entry
    let node_host = if n.id == "local" { String::new() } else { crate::exitgeo::host_of_url(&n.address) };
    crate::tunnel::panel::udp_forward(app, &n.id, &node_host, &ep_host, port)
}

/// The tunnels that bring UDP `port` to server `n`: the servers on the way, first entry first, and the
/// port on that first entry. None = no Kanki tunnel carries it there.
pub fn route_of(app: &App, n: &Node, port: u16) -> Option<(Vec<String>, u16)> {
    let sid = if n.id == "local" {
        "local".to_string()
    } else {
        crate::tunnel::panel::servers(app).into_iter().find(|s| s.node == n.id).map(|s| s.id)?
    };
    crate::tunnel::panel::udp_route(app, &sid, port)
}

/// 3.61: the Iran addresses and ports typed for KANKI MIX's second config go (the tunnels give them)
pub fn forget_tunnel_hosts(app: &App) {
    let mut m: HashMap<String, NodeOpt> = serde_json::from_str(&app.db.get("kmix_nodes")).unwrap_or_default();
    let mut changed = false;
    for o in m.values_mut() {
        if !o.tun_host.is_empty() || o.tun_port > 0 {
            o.tun_host.clear();
            o.tun_port = 0;
            changed = true;
        }
    }
    if changed {
        m.retain(|_, o| o.off || o.port > 0 || !o.route.is_empty() || !o.host.is_empty() || o.tun_off || !o.tun_name.is_empty());
        app.db.set("kmix_nodes", &serde_json::to_string(&m).unwrap_or_else(|_| "{}".into()));
    }
}

/// a host name or IP the panel accepts as a KANKI MIX address
fn valid_host(h: &str) -> bool {
    !h.is_empty() && h.len() <= 253 && h.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']'))
}

// ------------------------------------------------------------------ per-user keys

static SECRET_LOCK: Mutex<()> = Mutex::new(());

/// The panel's secret: made once, kept in the database (and so in its backups)
fn secret(app: &App) -> String {
    let _g = SECRET_LOCK.lock().unwrap_or_else(|e| e.into_inner());
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
    KmixCfg { on: true, port: s.node_port(&n.id), parity: s.parity, legacy_parity: s.legacy_parity, hop: s.hop.clone(), users }
}

/// The last apply error of each server (shown on the KANKI MIX page)
fn errors() -> &'static Mutex<HashMap<String, String>> {
    static E: std::sync::OnceLock<Mutex<HashMap<String, String>>> = std::sync::OnceLock::new();
    E.get_or_init(|| Mutex::new(HashMap::new()))
}

pub fn note_error(node_id: &str, e: &str) {
    let mut g = errors().lock().unwrap_or_else(|e| e.into_inner());
    if e.is_empty() {
        g.remove(node_id);
    } else {
        g.insert(node_id.to_string(), e.to_string());
    }
}

pub fn error_of(node_id: &str) -> String {
    errors().lock().unwrap_or_else(|e| e.into_inner()).get(node_id).cloned().unwrap_or_default()
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
    // multipath (app 1.44): the Iran tunnel entries of this server are other paths of the same config (3.67: every
    // one offered, the app takes the first two)
    let alts: Vec<String> = tunnel_entries(app, &s, n, port as u16).into_iter().map(|e| bracket_host(&e.host) + ":" + &e.port.to_string()).collect();
    if !alts.is_empty() {
        q.push_str(&format!("&alt={}", crate::util::pct(&alts.join(","))));
    }
    Some(format!("kanki://{}@{}:{}?{}#{}", user_key(app, u), host, port, q, crate::util::pct(&n.name)))
}

/// The name of a server's second (through the tunnel) config, as the app shows it
pub fn tunnel_name(app: &App, n: &Node) -> String {
    let s = settings(app);
    let name = s.nodes.get(&n.id).map(|o| o.tun_name.trim().to_string()).unwrap_or_default();
    crate::twin::named(&n.name, &name)
}

/// An IPv6 address in brackets, anything else as it is
fn bracket_host(h: &str) -> String {
    if h.contains(':') && !h.starts_with('[') { format!("[{}]", h) } else { h.to_string() }
}

/// Every Iran entry of server `n` for KANKI MIX `port`, the second config of before first (its address the way it
/// always was found), then the other Iran servers whose tunnels carry the same port, minus the ones the admin
/// left out; at most MAX_TUN_ENTRIES. Nothing is typed: every address comes from the tunnels (3.61).
pub fn tunnel_entries(app: &App, s: &Settings, n: &Node, port: u16) -> Vec<TunEntry> {
    let opt = s.nodes.get(&n.id).cloned().unwrap_or_default();
    let Some((host, tport)) = tunnel_target(app, s, n, port) else { return vec![] };
    let sid = crate::twin::sid_of_node(app, &n.id);
    let all = if sid.is_empty() { vec![] } else { crate::tunnel::panel::udp_entries(app, &sid, port) };
    let names = crate::tunnel::panel::server_names(app);
    let first_sid = all.iter().find(|(e, _)| crate::tunnel::panel::host_of(app, e) == host).map(|x| x.0.clone()).unwrap_or_default();
    let mut out = vec![TunEntry { sid: first_sid, host: host.clone(), port: tport, name: tunnel_name(app, n) }];
    for (e, p) in all {
        if out.len() >= MAX_TUN_ENTRIES {
            break;
        }
        let h = crate::tunnel::panel::host_of(app, &e);
        if h.is_empty() || out.iter().any(|x| x.host == h || x.sid == e) || opt.tun_skip.iter().any(|x| x == &e) {
            continue;
        }
        let via = names.get(&e).cloned().unwrap_or_else(|| e.clone());
        out.push(TunEntry { sid: e, host: h, port: p, name: crate::twin::named(&n.name, &format!("تانل {}", via)) });
    }
    out
}

/// The user's link through Iran entry `e` of server `n`: the same key and options as the direct one, the entry's
/// address, and the server itself as the other path
fn link_via(app: &App, u: &User, n: &Node, e: &TunEntry, display: &str) -> Option<String> {
    let first = link(app, u, n)?;
    let q = first.split_once('?').map(|x| x.1).unwrap_or("").split('#').next().unwrap_or("");
    // the extra ports exist on the server, not on the Iran address; the other path of this one is the server itself
    let direct = first.split_once('@').map(|x| x.1).unwrap_or("").split('?').next().unwrap_or("").to_string();
    let alt = format!("alt={}", crate::util::pct(&direct));
    let mut q: Vec<&str> = q.split('&').filter(|p| !p.starts_with("ports=") && !p.starts_with("alt=")).collect();
    q.push(&alt);
    Some(format!("kanki://{}@{}:{}?{}&via=tunnel#{}", user_key(app, u), bracket_host(&e.host), e.port, q.join("&"), crate::util::pct(display)))
}

/// The other Iran entries of a server, each its own entry in the subscription (3.67): (entry id in the
/// subscription, its name, the user's link). The first Iran entry stays the server's `@tunnel` entry.
pub fn link_tunnels(app: &App, u: &User, n: &Node) -> Vec<(String, String, String)> {
    let s = settings(app);
    let Some(port) = crate::api::node_info(n)["kmix_port"].as_u64().filter(|p| *p > 0) else { return vec![] };
    tunnel_entries(app, &s, n, port as u16)
        .into_iter()
        .enumerate()
        .skip(1)
        .filter_map(|(i, e)| link_via(app, u, n, &e, &e.name).map(|l| (extra_id(&n.id, i + 1), e.name.clone(), l)))
        .collect()
}

/// The subscription id of Iran entry `k` (2, 3 …) of server `nid`: "<nid>~<k>@tunnel" (an app reads every id that
/// ends in "@tunnel" as a tunnel entry)
pub fn extra_id(nid: &str, k: usize) -> String {
    format!("{}~{}{}", nid, k, crate::api::TUNNEL_SUFFIX)
}

/// The server and the entry number of an extra entry id without its "@tunnel" ("n2~3" -> ("n2", 3))
pub fn parse_extra(id: &str) -> Option<(&str, usize)> {
    let (nid, k) = id.rsplit_once('~')?;
    let k: usize = k.parse().ok().filter(|k| (2..=MAX_TUN_ENTRIES).contains(k))?;
    (!nid.is_empty()).then_some((nid, k))
}

/// The user's link through Iran entry `k` (2, 3 …) of server `n`
pub fn link_tunnel_k(app: &App, u: &User, n: &Node, k: usize) -> Option<String> {
    let s = settings(app);
    let port = crate::api::node_info(n)["kmix_port"].as_u64().filter(|p| *p > 0)? as u16;
    let e = tunnel_entries(app, &s, n, port).into_iter().nth(k.checked_sub(1)?)?;
    link_via(app, u, n, &e, &e.name)
}

/// The user's second link for one server, through the tunnel (the Iran address): the same key and
/// options as the first, another address. None = no second config there.
pub fn link_tunnel(app: &App, u: &User, n: &Node) -> Option<String> {
    let first = link(app, u, n)?;
    let s = settings(app);
    let info = crate::api::node_info(n);
    let port = info["kmix_port"].as_u64().filter(|p| *p > 0)? as u16;
    let (host, tport) = tunnel_target(app, &s, n, port)?;
    let host = bracket_host(&host);
    let q = first.split_once('?').map(|x| x.1).unwrap_or("").split('#').next().unwrap_or("");
    // the extra ports exist on the server, not on the Iran address; the other path of this one is the server itself
    let direct = first.split_once('@').map(|x| x.1).unwrap_or("").split('?').next().unwrap_or("").to_string();
    let alt = format!("alt={}", crate::util::pct(&direct));
    let mut q: Vec<&str> = q.split('&').filter(|p| !p.starts_with("ports=") && !p.starts_with("alt=")).collect();
    q.push(&alt);
    Some(format!("kanki://{}@{}:{}?{}&via=tunnel#{}", user_key(app, u), host, tport, q.join("&"), crate::util::pct(&format!("{} (Tunnel)", n.name))))
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
    // 3.68: the temp file has its final mode from its first byte (users.json holds every user's key: 0600,
    // never readable by others for a moment), is synced, then renamed over the old one
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = format!("{}.{}.new", path, std::process::id());
    let res = (|| -> std::io::Result<()> {
        let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(mode).open(&tmp)?;
        {
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(std::fs::Permissions::from_mode(mode))?;
        }
        f.write_all(text.as_bytes())?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)
    })();
    if let Err(e) = res {
        if let Err(r) = std::fs::remove_file(&tmp) {
            if r.kind() != std::io::ErrorKind::NotFound {
                eprintln!("kmix: {} could not be removed: {}", tmp, r);
            }
        }
        return Err(format!("cannot write {}: {}", path, e));
    }
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
    if let Some(rule) = want_rule {
        if !ours.iter().any(|r| *r == rule) {
            let _ = sh(&format!("iptables -t nat {}", rule));
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
    crate::fw::close("kmix");
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
    let legacy = if c.legacy_parity == 0 { 3 } else { c.legacy_parity.min(10) };
    std::fs::create_dir_all(DIR).map_err(|e| format!("cannot make {}: {}", DIR, e))?;
    let bin_changed = ensure_bin()?;
    let (api_port, api_secret) = api_conf()?;
    let env_changed = write_if_changed(ENV_FILE, &format!("KANKI_API_SECRET={}\n", api_secret), 0o600)?;
    let users = serde_json::to_string(&json!({ "users": c.users })).map_err(|e| e.to_string())?;
    let users_changed = write_if_changed(USERS_FILE, &users, 0o600)?;
    let unit = format!(
        "# written by kanki-panel\n[Unit]\nDescription=KANKI MIX (Kanki VPN)\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nEnvironmentFile={env}\nExecStart={bin} -listen :{port} -users {users} -api 127.0.0.1:{api} -fec-data {d} -fec-parity {p} -fec-legacy {l}\nRestart=always\nRestartSec=3\nLimitNOFILE=1048576\n\n[Install]\nWantedBy=multi-user.target\n",
        env = ENV_FILE, bin = BIN, port = port, users = USERS_FILE, api = api_port, d = FEC_DATA, p = parity, l = legacy
    );
    let unit_changed = write_if_changed(UNIT, &unit, 0o644)?;
    if unit_changed {
        let _ = sh("systemctl daemon-reload");
        let _ = sh(&format!("systemctl enable -q {}", UNIT_NAME));
    }
    // the extra ports never take this server's own port or the port of WireGuard / AmneziaWG
    // 3.68: and no UDP port anything else on this server uses (Hysteria2, DNS, tunnels, Xray, SSH: every rule of
    // the firewall state and every listener), so the REDIRECT never swallows another service's packets
    let taken: Vec<u16> = ["wg", "awg"]
        .iter()
        .filter_map(|p| crate::wg::listen_port(p).trim().parse().ok())
        .chain([port])
        .chain(crate::fw::udp_ports_in_use("kmix"))
        .collect();
    let hop = hop_range(&c.hop).filter(|(a, b)| !hop_holds(*a, *b, &taken));
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
    // the port and the extra ports (an old port or range is closed again)
    let mut rules = vec![crate::fw::rule(port, true)];
    if let Some((a, b)) = hop {
        rules.push(format!("{}:{}/udp", a, b));
    }
    crate::fw::sync("kmix", rules);
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
        Some((p, s)) => crate::hy2::traffic_by(&p, &s, true).await,
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

/// The game recorder of this server's KANKI MIX (`record.go` in the server): `action` start (with `user`
/// and `secs`), stop, clear, get (the report) or raw (the report and every packet, for a download)
pub async fn record_local(b: &Value) -> Value {
    let Some((port, secret)) = api_here() else { return json!({"error": "KANKI MIX is not running on this server"}) };
    static C: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    let c = C.get_or_init(|| reqwest::Client::builder().timeout(std::time::Duration::from_secs(30)).build().unwrap_or_default());
    let base = format!("http://127.0.0.1:{}", port);
    let req = match b["action"].as_str().unwrap_or("get") {
        "start" => c.post(format!("{}/record/start", base)).json(&json!({"user": b["user"], "secs": b["secs"]})),
        "stop" => c.post(format!("{}/record/stop", base)),
        "clear" => c.post(format!("{}/record/clear", base)),
        "raw" => c.get(format!("{}/record?raw=1", base)),
        _ => c.get(format!("{}/record", base)),
    };
    let r = match req.header("Authorization", secret).send().await {
        Ok(r) => r,
        Err(e) => return json!({"error": format!("KANKI MIX did not answer: {}", e.without_url())}),
    };
    // a server not updated yet has no recorder
    if r.status() == reqwest::StatusCode::NOT_FOUND {
        return json!({"error": "old"});
    }
    if !r.status().is_success() {
        return json!({"error": format!("KANKI MIX: HTTP {}", r.status().as_u16())});
    }
    r.json::<Value>().await.unwrap_or_else(|_| json!({"error": "KANKI MIX sent no JSON"}))
}

/// KANKI MIX's live health on this server for the panel (3.67): what its /health says (sessions, gaming
/// sessions, sessions with routing hints, the loss the apps measured on the game's answers, the FEC), and whether
/// the extra ports really lead to it (the NAT rule is in place). Null when KANKI MIX does not run here; an older
/// server without /health gives only the extra ports.
pub async fn health() -> Value {
    let Some((port, secret)) = api_here() else { return Value::Null };
    static C: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    let c = C.get_or_init(|| reqwest::Client::builder().timeout(std::time::Duration::from_secs(3)).build().unwrap_or_default());
    let mut v = match c.get(format!("http://127.0.0.1:{}/health", port)).header("Authorization", secret).send().await {
        Ok(r) if r.status().is_success() => r.json::<Value>().await.unwrap_or_else(|_| json!({})),
        Ok(_) => json!({ "old": true }),
        Err(e) => json!({ "error": e.without_url().to_string() }),
    };
    let hop = tokio::task::spawn_blocking(hop_state).await.unwrap_or_else(|_| json!({ "want": "", "active": false }));
    v["hop"] = hop;
    v
}

/// The extra ports this server should forward and whether the NAT rule doing it is there. Blocking.
fn hop_state() -> Value {
    let st: Value = std::fs::read_to_string(STATE_FILE).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or(Value::Null);
    let want = st["hop"].as_str().unwrap_or("").to_string();
    let active = !want.is_empty()
        && sh("iptables -t nat -S PREROUTING 2>/dev/null").1.lines().any(|l| l.contains(HOP_TAG) && l.contains(&format!("--dport {}", want.replace('-', ":"))));
    json!({ "want": want, "active": active })
}

/// The last health each server reported (in memory: the next sync brings it again)
fn healths() -> &'static Mutex<HashMap<String, (i64, Value)>> {
    static H: std::sync::OnceLock<Mutex<HashMap<String, (i64, Value)>>> = std::sync::OnceLock::new();
    H.get_or_init(|| Mutex::new(HashMap::new()))
}

/// A server's sync answer carried its KANKI MIX health (Null = none: forgotten)
pub fn note_health(node_id: &str, v: &Value) {
    let mut g = healths().lock().unwrap_or_else(|e| e.into_inner());
    if v.is_null() {
        g.remove(node_id);
    } else {
        g.insert(node_id.to_string(), (crate::util::now(), clean_health(v)));
    }
}

/// Only the known numbers of a health answer, bounded (it comes from the server; it is shown in the panel)
fn clean_health(v: &Value) -> Value {
    let n = |k: &str| v[k].as_i64().filter(|x| (0..=10_000_000).contains(x)).map(Value::from).unwrap_or(Value::Null);
    let want: String = v["hop"]["want"].as_str().unwrap_or("").chars().filter(|c| c.is_ascii_digit() || *c == '-').take(11).collect();
    json!({
        "sessions": n("sessions"), "gaming": n("gaming"), "hinted": n("hinted"), "users": n("users"),
        "loss_permille": v["loss_permille"].as_i64().filter(|x| (0..=1000).contains(x)), "loss_sessions": n("loss_sessions"),
        "fec_parity": n("fec_parity"), "fec_legacy": n("fec_legacy"),
        "hop": { "want": want, "active": v["hop"]["active"].as_bool().unwrap_or(false) },
        "old": v["old"].as_bool().unwrap_or(false),
    })
}

/// The last health of a server and when it came (Null = none yet)
pub fn health_of(node_id: &str) -> Value {
    match healths().lock().unwrap_or_else(|e| e.into_inner()).get(node_id) {
        Some((at, v)) => {
            let mut v = v.clone();
            v["at"] = json!(at);
            v
        }
        None => Value::Null,
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
        .route("/api/kmix/record", post(record_api))
}

/// The game recorder (KANKI MIX › Game recorder): `{action, node, user, secs}`. start / stop / clear go to
/// every server running KANKI MIX (the user may connect to any of them); get answers each server's
/// report; raw is one server's packets for a download.
async fn record_api(axum::extract::State(app): St, h: axum::http::HeaderMap, axum::Json(b): axum::Json<Value>) -> axum::response::Response {
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    let _ = crate::guard!(app, h, "nodes");
    let action = b["action"].as_str().unwrap_or("get").to_string();
    if !matches!(action.as_str(), "start" | "stop" | "clear" | "get" | "raw") {
        return crate::api::err(StatusCode::BAD_REQUEST, "unknown action");
    }
    let users = app.db.users();
    let names: Vec<String> = users.iter().filter(|u| u.has_proto("kmix")).map(|u| u.username.clone()).collect();
    let mut body = json!({"action": action});
    if action == "start" {
        let user = b["user"].as_str().unwrap_or("").trim().to_string();
        if !names.contains(&user) {
            return crate::api::err(StatusCode::BAD_REQUEST, "pick a user that has KANKI MIX");
        }
        // 3.68: a recording stops by itself after 5 minutes at most (the server caps it too)
        let secs = b["secs"].as_u64().unwrap_or(300).clamp(60, 300);
        body = json!({"action": "start", "user": user, "secs": secs});
    }
    let want = b["node"].as_str().unwrap_or("").to_string();
    let nodes: Vec<Node> = app.db.nodes().into_iter().filter(|n| {
        let installed = n.id == "local" || crate::api::node_info(n)["kmix_port"].as_u64().is_some();
        (want.is_empty() || n.id == want) && installed && (n.id == "local" || n.online)
    }).collect();
    if action == "raw" && (want.is_empty() || nodes.is_empty()) {
        return crate::api::err(StatusCode::BAD_REQUEST, "pick a server");
    }
    let asks = nodes.iter().map(|n| {
        let (app, body) = (app.clone(), body.clone());
        async move {
            let r = if n.id == "local" {
                record_local(&body).await
            } else {
                crate::sync::remote_post_json(&app, n, "/agent/kmix/record", &body).await.unwrap_or_else(|| json!({"error": "the server did not answer"}))
            };
            (n.id.clone(), n.name.clone(), r)
        }
    });
    let answers = futures_util::future::join_all(asks).await;
    if action == "raw" {
        return axum::Json(answers.into_iter().next().map(|x| x.2).unwrap_or(Value::Null)).into_response();
    }
    let servers: Vec<Value> = answers.into_iter().map(|(id, name, r)| {
        let mut v = json!({"id": id, "name": name});
        if let Some(e) = r["error"].as_str() {
            v["error"] = json!(e);
        } else {
            v["report"] = r["report"].clone();
        }
        v
    }).collect();
    axum::Json(json!({"servers": servers, "users": names})).into_response()
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
            // the second config through the tunnel: (address, port) it uses, or Null
            "second": info["kmix_port"].as_u64().and_then(|p| tunnel_target(&app, &s, n, p as u16)).map(|(h, p)| json!({"host": h, "port": p})),
            // the Kanki tunnels that bring this server's port (["Iran", "Turkey"]), Null = none: a typed
            // Iran address then needs a forward made some other way
            "route_via": info["kmix_port"].as_u64().and_then(|p| route_of(&app, n, p as u16)).map(|(v, p)| json!({"via": v, "port": p})),
            // 3.67: every Iran entry that carries the port (the first is the second config), with whether it is offered
            "entries": info["kmix_port"].as_u64().map(|p| entries_json(&app, &s, n, p as u16)).unwrap_or_else(|| json!([])),
            "on": s.node_on(&n.id), "want_port": s.node_port(&n.id),
            "port": info["kmix_port"], "parity": info["kmix_parity"], "hop": info["kmix_hop"],
            "active": info["kmix_active"], "installed": !info["kmix_port"].is_null(), "users": here,
            "error": error,
            "version": info["version"],
            // the other UDP ports of this server (a clash with them is refused)
            "used_ports": [info["wg_port"], info["awg_port"], info["hy2_port"]],
            // 3.67: live numbers from the server's last sync (Null = none yet, or an older server)
            "health": health_of(&n.id),
        })
    }).collect();
    let online = with.iter().filter(|u| u.online > 0).count();
    axum::Json(json!({
        "settings": settings_json(&s), "servers": servers, "users": with.len(), "users_total": users.len(),
        "online": online, "traffic_gb": (with.iter().map(|u| u.used_gb()).sum::<f64>() * 10.0).round() / 10.0,
    })).into_response()
}

/// The Iran entries of a server for the KANKI MIX page: each that carries the port, the ones the admin left out too
/// (`on` false), so they can be switched back on
fn entries_json(app: &App, s: &Settings, n: &Node, port: u16) -> Value {
    let skip = s.nodes.get(&n.id).map(|o| o.tun_skip.clone()).unwrap_or_default();
    let mut all = s.clone();
    if let Some(o) = all.nodes.get_mut(&n.id) {
        o.tun_skip.clear();
    }
    json!(tunnel_entries(app, &all, n, port)
        .into_iter()
        .enumerate()
        .map(|(i, e)| json!({ "sid": e.sid, "host": e.host, "port": e.port, "name": e.name, "first": i == 0, "on": !skip.contains(&e.sid) }))
        .collect::<Vec<_>>())
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
    // the saved per-server options (not the ones a server's role switched off for now)
    let saved: HashMap<String, NodeOpt> = serde_json::from_str(&app.db.get("kmix_nodes")).unwrap_or_default();
    let mut nodes = saved.clone();
    if let Some(o) = b["nodes"].as_object() {
        nodes.clear();
        for (id, v) in o {
            let host = v["host"].as_str().unwrap_or("").trim().to_string();
            if !host.is_empty() && !valid_host(&host) {
                return crate::api::err(StatusCode::BAD_REQUEST, "address: a domain or an IP, like de.example.com");
            }
            let route = if v["route"].as_str() == Some("tunnel") { "tunnel".to_string() } else { String::new() };
            // 3.61: the Iran address and port of the second config come from the tunnels, never typed
            let tun_host = String::new();
            let tun_name: String = v["tun_name"].as_str().unwrap_or("").trim().chars().filter(|c| !c.is_control() && !"<>\"&".contains(*c)).take(40).collect();
            let opt = NodeOpt {
                off: v["off"].as_bool().unwrap_or(false), port: port_of(&v["port"]).unwrap_or(0), route, host,
                tun_host, tun_port: 0, tun_off: v["tun_off"].as_bool().unwrap_or(false),
                tun_name,
                // the Iran servers not offered as an entry of their own: ids of tunnel servers only, a few
                tun_skip: v["tun_skip"].as_array().map(|a| {
                    a.iter().filter_map(|x| x.as_str()).map(|x| x.trim().to_string())
                        .filter(|x| !x.is_empty() && x.len() <= 40 && x.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'))
                        .take(16).collect()
                }).unwrap_or_default(),
            };
            if opt.off || opt.port > 0 || !opt.route.is_empty() || !opt.host.is_empty() || !opt.tun_host.is_empty() || opt.tun_port > 0 || opt.tun_off || !opt.tun_name.is_empty() || !opt.tun_skip.is_empty() {
                nodes.insert(id.clone(), opt);
            }
        }
    }
    // a server whose role does not run KANKI MIX shows it off; that is not the admin's own switch
    for n in app.db.nodes().into_iter().filter(|n| !n.role().allows("kmix")) {
        let own = saved.get(&n.id).map(|o| o.off).unwrap_or(false);
        if let Some(o) = nodes.get_mut(&n.id) {
            o.off = own;
        }
    }
    // a port that clashes with WireGuard / AmneziaWG / Hysteria2 of a server, or inside the extra ports
    // the last parity above 0 is kept: links apps still hold may carry it (the server answers them with it)
    let legacy_parity = if parity > 0 { parity } else { cur.legacy_parity };
    let next = Settings { on: b["on"].as_bool().unwrap_or(cur.on), port, parity, legacy_parity, hop, gaming: b["gaming"].as_bool().unwrap_or(cur.gaming), nodes };
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
            // the extra ports are taken by KANKI MIX: another protocol's port inside them stops working
            let others = [("wg_port", "WireGuard"), ("awg_port", "AmneziaWG"), ("hy2_port", "Hysteria2")].into_iter().map(|(k, name)| (port_of(&info[k]), name));
            for (q, name) in others {
                if let Some(q) = q.filter(|q| (a..=z).contains(q)) {
                    return crate::api::err(StatusCode::BAD_REQUEST, &format!("{}: the extra ports {}-{} hold UDP port {} of {}", n.name, a, z, q, name));
                }
            }
        }
    }
    let db = &app.db;
    db.set("kmix_on", if next.on { "1" } else { "0" });
    db.set("kmix_port", &next.port.to_string());
    db.set("kmix_parity", &next.parity.to_string());
    db.set("kmix_parity_legacy", &next.legacy_parity.to_string());
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
        if on == has || (on && !crate::api::assign_fits(&app, &u, "kmix")) {
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

    /// The game recorder API: only a user that has KANKI MIX can be recorded, a wrong action is refused
    #[tokio::test]
    async fn recorder_asks_only_for_kmix_users() {
        use tower::ServiceExt;
        let app = crate::test_app();
        let key = crate::auth::test_session(&app);
        let call = |b: Value| {
            let app = app.clone();
            let key = key.clone();
            async move {
                let r = axum::http::Request::builder().method("POST").uri("/api/kmix/record").header("authorization", format!("Bearer {}", key))
                    .header("content-type", "application/json").body(axum::body::Body::from(b.to_string())).unwrap();
                let res = crate::api::master_router(app).oneshot(r).await.unwrap();
                let st = res.status();
                let b = axum::body::to_bytes(res.into_body(), 1 << 20).await.unwrap();
                (st, serde_json::from_slice::<Value>(&b).unwrap_or(Value::Null))
            }
        };
        let (st, _) = call(json!({"action": "rm -rf"})).await;
        assert_eq!(st, axum::http::StatusCode::BAD_REQUEST);
        let (st, v) = call(json!({"action": "start", "user": "nobody"})).await;
        assert_eq!(st, axum::http::StatusCode::BAD_REQUEST, "{}", v);
        let (st, _) = call(json!({"action": "raw"})).await;
        assert_eq!(st, axum::http::StatusCode::BAD_REQUEST);
        let (st, v) = call(json!({"action": "get"})).await;
        assert_eq!(st, axum::http::StatusCode::OK);
        assert!(v["users"].as_array().unwrap().is_empty() && v["servers"].is_array(), "{}", v);
        // a server without KANKI MIX says so instead of failing the page
        if !std::path::Path::new(UNIT).exists() {
            assert!(record_local(&json!({"action": "get"})).await["error"].as_str().unwrap().contains("not running"));
        }
    }

    #[test]
    fn route_and_host_options() {
        let mut s = Settings { on: true, port: 4000, parity: 3, legacy_parity: 3, hop: String::new(), gaming: true, nodes: HashMap::new() };
        assert!(!s.node_tunnel("de"));
        s.nodes.insert("de".into(), NodeOpt { route: "tunnel".into(), ..Default::default() });
        assert!(s.node_tunnel("de"));
        assert!(valid_host("de.example.com") && valid_host("1.2.3.4") && valid_host("[2001:db8::1]"));
        assert!(!valid_host("") && !valid_host("a b") && !valid_host("x/y"));
    }

    #[test]
    fn hop_ranges_keep_off_other_ports() {
        assert!(hop_holds(4001, 4010, &[51820, 4005]));
        assert!(!hop_holds(4001, 4010, &[51820, 4000, 4011]));
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
        let mut s = Settings { on: true, port: 4000, parity: 3, legacy_parity: 3, hop: String::new(), gaming: true, nodes: HashMap::new() };
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
