//! The VIP tunnel: one tunnel over several carriers at once.
//!
//! Between two servers (entry = where users connect, exit = where the ports lead) it keeps **several paths
//! open at the same time**: UDP on ports that change (`hop`), UDP inside fake TCP packets, and a stream
//! link of the Kanki engine (TLS / HTTP/2, WebSocket, a CDN). When one of them is throttled or cut, the
//! others carry on: there is nothing to reconnect.
//!
//! What it carries is split in two classes. **Realtime** (small UDP packets: games, calls, WireGuard
//! keepalives) leaves at once, never waits for a lost packet, takes the two best paths at the same time
//! when the mode asks for it, and is protected by sliding-window repairs (`kprlc`): the first copy wins.
//! **Bulk** (big UDP packets, and every TCP connection, which travels as QUIC streams on top) takes the
//! best path, with repairs only when that path loses packets, spread over interleaved lanes so a short
//! outage costs each lane little.
//!
//! Every path is measured all the time (ping, jitter, loss, from the tunnel's own packets), and the paths
//! are ranked by `ping + 3·jitter + 20·loss%`. See `crypto` for the keys and the packet, `wire` for the
//! frames, `core` for the session, `path` for the carriers, `flows` for the users' ports and `panel` for
//! the panel's side.

pub mod core;
pub mod crypto;
pub mod flows;
pub mod panel;
pub mod path;
pub mod wire;

#[cfg(test)]
mod tests;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::OnceLock;

/// the largest VIP packet on a UDP path when the tunnel says nothing (IPv4 + UDP on top: 1448 on the wire)
pub const DEFAULT_MTU: u16 = 1420;
/// the largest VIP packet inside one fake TCP segment (`faketcp` cuts at 1300)
pub const FTCP_MTU: usize = 1300;
/// UDP packets up to this size are realtime when the tunnel says nothing
pub const DEFAULT_RT_MAX: u16 = 512;
/// the keys are made again this often when the tunnel says nothing (seconds)
pub const DEFAULT_REKEY: u32 = 600;

/// One side of a VIP tunnel, as the panel gives it to a server
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
#[serde(default)]
pub struct VipSpec {
    pub id: String,
    pub name: String,
    /// "entry" | "exit"
    pub role: String,
    /// this side dials the other (the other one listens)
    pub dials: bool,
    /// dialer: the listener's address (a domain or an IP, no port)
    pub remote: String,
    /// the tunnel's secret (the same on both sides)
    pub secret: String,
    /// "gaming" | "balanced" | "speed"
    pub mode: String,
    /// filler in the packets: 0 none, 1 a little, 2 more
    pub stealth: u8,
    /// ML-KEM-768 next to X25519 in the handshake
    pub pq: bool,
    /// the first UDP port on the listener (0 = no UDP path)
    pub port: u16,
    /// how many UDP ports the listener holds, from `port` up (1-32)
    pub hop: u8,
    /// the dialer moves each UDP path to another of those ports this often (seconds; 0 = never)
    pub hop_secs: u16,
    /// UDP paths at the same time (0-4)
    pub udp_paths: u8,
    /// the port of the fake-TCP path on the listener (0 = none)
    pub ftcp_port: u16,
    /// the stream path: "" (none) | "h2" | "wss" | "ws" | "tcp" | "cdn", its port on the listener, and the
    /// names the dialer writes (see `tunnel::engine::Spec`)
    pub s_kind: String,
    pub s_port: u16,
    pub s_sni: String,
    pub s_host: String,
    pub s_path: String,
    pub s_frag: bool,
    /// `cdn`: the edge addresses the dialer connects to
    pub s_dial: String,
    /// forwarded ports: "443" or "8443:443" (port on the entry : port on the exit)
    pub tcp: Vec<String>,
    pub udp: Vec<String>,
    /// exit: the host the forwarded ports are reached on ("" = 127.0.0.1)
    pub target: String,
    /// entry: the address the forwarded ports listen on ("" = every address)
    pub bind: String,
    /// the largest VIP packet on a UDP path (0 = `DEFAULT_MTU`)
    pub mtu: u16,
    /// bulk repairs: interleaved lanes (1, 2, 4 or 8; 0 = 4)
    pub burst: u8,
    /// UDP packets up to this size are realtime (0 = `DEFAULT_RT_MAX`)
    pub rt_max: u16,
    /// new keys this often (seconds; 0 = `DEFAULT_REKEY`)
    pub rekey_secs: u32,
}

/// The carrier of one path
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PathKind {
    Udp,
    Ftcp,
    Stream,
}

impl VipSpec {
    /// The paths of this tunnel, in the order both sides number them
    pub fn paths(&self) -> Vec<PathKind> {
        let mut v = vec![];
        if self.port > 0 {
            v.extend(std::iter::repeat_n(PathKind::Udp, self.udp_paths.clamp(1, 4) as usize));
        }
        if self.ftcp_port > 0 {
            v.push(PathKind::Ftcp);
        }
        if !self.s_kind.is_empty() && self.s_port > 0 {
            v.push(PathKind::Stream);
        }
        v
    }
    pub fn hops(&self) -> u16 {
        self.hop.clamp(1, 32) as u16
    }
    pub fn udp_mtu(&self) -> usize {
        (if self.mtu == 0 { DEFAULT_MTU } else { self.mtu }).clamp(1200, 1472) as usize
    }
    pub fn rt_limit(&self) -> usize {
        (if self.rt_max == 0 { DEFAULT_RT_MAX } else { self.rt_max }).min(1400) as usize
    }
    /// log2 of the bulk lanes
    pub fn stride_bits(&self) -> u32 {
        match self.burst {
            1 => 0,
            2 => 1,
            8 => 3,
            _ => 2,
        }
    }
    pub fn rekey(&self) -> u64 {
        (if self.rekey_secs == 0 { DEFAULT_REKEY } else { self.rekey_secs }) as u64
    }
    pub fn entry(&self) -> bool {
        self.role == "entry"
    }
    pub fn target_host(&self) -> String {
        let t = self.target.trim();
        if t.is_empty() { "127.0.0.1".into() } else { t.to_string() }
    }
    pub fn bind_host(&self) -> String {
        let b = self.bind.trim();
        if b.is_empty() { "0.0.0.0".into() } else { b.to_string() }
    }
    /// What this side opens to the outside: ["port/udp", "port/tcp", …] (the firewall's rules)
    pub fn open_rules(&self) -> Vec<String> {
        let mut v = vec![];
        if !self.dials {
            if self.port > 0 {
                for i in 0..self.hops() {
                    v.push(crate::fw::rule(self.port.saturating_add(i), true));
                }
            }
            if self.ftcp_port > 0 {
                v.push(crate::fw::rule(self.ftcp_port, false));
            }
            if !self.s_kind.is_empty() && self.s_port > 0 {
                v.push(crate::fw::rule(self.s_port, false));
            }
        }
        if self.entry() && !self.bind.trim().starts_with("127.") {
            for (a, _) in crate::tunnel::engine::parse_ports(&self.tcp) {
                v.push(crate::fw::rule(a, false));
            }
            for (a, _) in crate::tunnel::engine::parse_ports(&self.udp) {
                v.push(crate::fw::rule(a, true));
            }
        }
        v
    }
}

/// One path, as its side sees it
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct PathStatus {
    pub id: u8,
    /// "udp" | "ftcp" | "stream"
    pub kind: String,
    /// 2 = up, 1 = no answer for a moment, 0 = down
    pub state: u8,
    /// carries the realtime class right now (0 = no, 1 = first, 2 = the copy)
    pub rank: u8,
    pub rtt_ms: f64,
    pub jit_ms: f64,
    /// what the other side did not get of what this side sent (%)
    pub loss: f64,
    pub tx_pk: u64,
    pub rx_pk: u64,
    /// the listener's port this path uses now (a UDP path moves)
    pub port: u16,
    pub error: String,
}

/// One running VIP tunnel, as its side reports it to the panel
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct VipStatus {
    pub id: String,
    pub role: String,
    /// keys are made and at least one path answers
    pub up: bool,
    /// when this session started (unix seconds; 0 = none)
    pub since: i64,
    pub error: String,
    pub paths: Vec<PathStatus>,
    /// the handshake used ML-KEM
    pub pq: bool,
    pub rekeys: u64,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    /// realtime: packets sent, second copies, repairs sent; packets that arrived, came twice, were rebuilt
    pub rt_tx: u64,
    pub rt_copies: u64,
    pub rt_fix_tx: u64,
    pub rt_rx: u64,
    pub rt_dups: u64,
    pub rt_fixed: u64,
    pub bulk_tx: u64,
    pub bulk_fix_tx: u64,
    pub bulk_rx: u64,
    pub bulk_fixed: u64,
    /// realtime packets the other side never got, after copies and repairs (%)
    pub rt_resid: f64,
    /// packets that were not ours (scanners, noise): dropped without an answer
    pub junk: u64,
    /// TCP connections carried now, and UDP flows
    pub streams: u64,
    pub udp_flows: u64,
    /// entry: the tunnel as a game sees it over the last minute: {n, ping, jit, loss}
    pub quality: Option<serde_json::Value>,
    /// game priority is holding the bulk class back right now (bytes per second; 0 = no)
    pub guard_bps: u64,
}

/// Keeps the running VIP tunnels equal to the wanted list
#[derive(Default)]
struct Manager {
    running: tokio::sync::Mutex<HashMap<String, core::Running>>,
}

fn manager() -> &'static Manager {
    static M: OnceLock<Manager> = OnceLock::new();
    M.get_or_init(Manager::default)
}

/// Runs exactly these tunnels (a changed one is started again). Inside the tokio runtime.
pub async fn apply(specs: Vec<VipSpec>) {
    let mut run = manager().running.lock().await;
    let keys: Vec<String> = run.keys().cloned().collect();
    for k in keys {
        let keep = specs.iter().any(|s| s.id == k && run.get(&k).map(|r| r.spec() == s && !r.dead()).unwrap_or(false));
        if !keep {
            if let Some(r) = run.remove(&k) {
                eprintln!("VIP tunnel {}: {}", k, if r.dead() { "its session ended, starting it again" } else { "stopped" });
                r.stop();
            }
        }
    }
    for s in specs {
        if s.id.is_empty() || run.contains_key(&s.id) || s.paths().is_empty() {
            continue;
        }
        eprintln!("VIP tunnel {} ({}): starting as {}, {}", s.name, s.id, s.role, if s.dials { "dialing" } else { "listening" });
        run.insert(s.id.clone(), core::Running::start(s));
    }
}

pub async fn statuses() -> Vec<VipStatus> {
    manager().running.lock().await.values().map(|r| r.status()).collect()
}

/// The firewall rules of these tunnels on this server (blocking: it may call ufw)
pub fn open_ports(specs: &[VipSpec]) {
    crate::fw::sync("vip", specs.iter().flat_map(|s| s.open_rules()));
}

const CACHE: &str = "/var/lib/kanki/vip.json";

/// The agent: the last list the panel gave, so the tunnels come back after a reboot without the panel
pub async fn from_disk() -> String {
    let Ok(t) = std::fs::read_to_string(CACHE) else { return String::new() };
    if let Ok(specs) = serde_json::from_str::<Vec<VipSpec>>(&t) {
        if !specs.is_empty() {
            eprintln!("starting {} saved VIP tunnel(s)", specs.len());
        }
        let ps = specs.clone();
        apply(specs).await;
        let _ = tokio::task::spawn_blocking(move || open_ports(&ps)).await;
        return t;
    }
    String::new()
}

/// The agent: the list the panel just gave (`last`: its text as kept on disk)
pub async fn from_panel(v: &serde_json::Value, last: &mut String) {
    let Ok(specs) = serde_json::from_value::<Vec<VipSpec>>(v.clone()) else { return };
    let text = serde_json::to_string(&specs).unwrap_or_default();
    if text != *last {
        let _ = std::fs::create_dir_all("/var/lib/kanki");
        if specs.is_empty() {
            let _ = std::fs::remove_file(CACHE);
        } else {
            let _ = std::fs::write(CACHE, &text);
            // the secret of a tunnel is in it
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(CACHE, std::fs::Permissions::from_mode(0o600));
        }
        *last = text;
    }
    let ps = specs.clone();
    apply(specs).await;
    let _ = tokio::task::spawn_blocking(move || open_ports(&ps)).await;
}
