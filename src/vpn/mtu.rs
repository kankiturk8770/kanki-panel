//! Safe MTU of every user config, worked out from the cores and the tunnels on the way.
//!
//! A user's packet crosses two legs:
//!
//! ```text
//!  phone ──(mobile network, ~1420-1440)──> Iran entry ──(tunnel)──> server abroad
//!  phone ──(mobile network)──────────────────────────────────────> server abroad   (direct)
//! ```
//!
//! **Leg 1** (the mobile network) is the tight one: the whole outer IPv4 packet of the core
//! (IPv4 20 + UDP 8 + the core's own header + the inner packet) must stay under `budget`
//! (setting `mtu_budget`, 1380 by default: well under what Iran's mobile networks pass, so no
//! router there ever cuts it). So the MTU of the config = `budget - overhead(core)`.
//!
//! **Leg 2** (the tunnel between the servers) only matters when it is a *layer-3 link*:
//! * an AmneziaWG tunnel (`kind = "awg"`) forwards the ports with DNAT, so the user's whole outer
//!   packet goes into the link's interface. Bigger than the interface MTU = cut in pieces. So the
//!   budget of that path is `min(budget, link MTU)`.
//! * every other tunnel (tcp, tcpmux, ws, wss, cdn, h2, dual, quic, hq, kcp, game, faketcp, and the
//!   Hysteria2 link) carries the user's datagram as bytes of a stream (mux over a reliable link) or as
//!   QUIC datagrams the Hysteria client splits by itself. They cut a big datagram into their own
//!   packets (at most 1232 + 28 on the wire for the UDP ones, 1300 + 40 for faketcp), so the IP
//!   layer never fragments, whatever the client sends. FEC only adds whole parity packets (bandwidth),
//!   not bytes to a packet. They put no limit on the client MTU.
//!
//! Applied (setting `mtu_auto`, on by default; off = the hand-set `mtu` and microtun MTU as before):
//! * WireGuard / AmneziaWG configs and links (`api::wg_uri`, the config file, the Amnezia backup);
//! * microtun links (`mtu=` in `mtun://`);
//! * the servers' own interfaces (`wg0`, `awg0`, `mtun0`) on every sync, so the server → phone
//!   direction is just as small (a bigger packet from the internet is cut *inside* the tunnel and
//!   each piece travels in a packet of its own; the mobile network never sees a fragment).
//!
//! Nothing is stored per user: the MTU is worked out when a config is made, so a tunnel that goes
//! from FakeTCP to an AmneziaWG link (or back) changes every config on the next subscription
//! refresh and every server on the next sync, by itself.
//!
//! Not set here: Hysteria2 (QUIC sets "don't fragment" and sizes its own packets; the panel only
//! checks it fits), KANKI MIX (its Go server, `src/vpn/kmix-server`, never sends a UDP
//! payload over 1332 = 1380 even on IPv6: `obfs.MaxWire`) and Xray (TCP,
//! the kernel sizes it; an mKCP inbound never goes over 1352, see `xray::panel::stream`).
//!
//! Older configs (MTU 1380 or 1420) keep working: a server takes in packets bigger than its
//! interface MTU, and TCP through `wg0` / `awg0` / `mtun0` is clamped to it both ways (`mss_rules`).
use crate::db::Node;
use crate::App;
use serde_json::{json, Value};
use std::collections::HashMap;

pub const IPV4: u16 = 20;
pub const UDP: u16 = 8;
pub const TCP: u16 = 20;
/// WireGuard data packet: type + reserved 4, receiver 4, counter 8, Poly1305 tag 16
pub const WG: u16 = 32;
/// microtun data packet: index 4 + counter 8, GCM tag 16 (`mtun::OVERHEAD`)
pub const MTUN: u16 = crate::mtun::OVERHEAD as u16;
/// Hysteria2's Salamander mask: 8 bytes of salt
pub const SALAMANDER: u16 = 8;
/// below this an interface loses IPv6 (RFC 8200), so a config never goes lower
pub const MIN: u16 = 1280;
pub const DEFAULT_BUDGET: u16 = 1380;
/// the largest datagram of the UDP tunnel transports on their own wire (`salamander::MAX_WIRE`)
const UDP_WIRE: u16 = 1232;
/// the largest UDP payload KANKI MIX sends (`kmix-server/internal/obfs` MaxWire): 1380 with IPv6
pub const KMIX_WIRE: u16 = 1332;
/// the largest payload of one faketcp segment (`faketcp::MAX_SEG`)
const FAKETCP_SEG: u16 = 1300;

/// The cores whose configs carry an MTU the panel sets
pub const CORES: [&str; 3] = ["wg", "awg", "mtun"];

/// Automatic MTU on (the default)
pub fn auto(app: &App) -> bool {
    app.db.get("mtu_auto") != "0"
}

/// The largest outer IPv4 packet allowed on the mobile network
pub fn budget(app: &App) -> u16 {
    app.db.get("mtu_budget").trim().parse::<u16>().ok().filter(|b| (1300..=1500).contains(b)).unwrap_or(DEFAULT_BUDGET)
}

/// AmneziaWG 2: junk bytes in front of every data packet (`S4`, 0 when not set)
pub fn awg_pad(n: &Node) -> u16 {
    let info = crate::api::node_info(n);
    let s4 = info["awg"].as_array().and_then(|a| a.iter().find(|kv| kv[0].as_str() == Some("S4")).and_then(|kv| kv[1].as_str().map(|s| s.trim().to_string())));
    s4.and_then(|s| s.parse::<u16>().ok()).unwrap_or(0).min(256)
}

/// Bytes a core puts around one inner packet on the mobile network, outer IPv4 + UDP included
pub fn overhead(core: &str, awg_pad: u16) -> Option<u16> {
    match core {
        "wg" => Some(IPV4 + UDP + WG),
        "awg" => Some(IPV4 + UDP + WG + awg_pad),
        "mtun" => Some(IPV4 + UDP + MTUN),
        _ => None,
    }
}

/// The MTU of a config for a path that takes outer packets up to `cap` bytes, and whether it really
/// fits (false = the path is so small that even the 1280 floor is cut: fix the tunnel)
pub fn safe(cap: u16, overhead: u16) -> (u16, bool) {
    let m = cap.saturating_sub(overhead);
    (m.max(MIN).min(1500), m >= MIN)
}

// ------------------------------------------------------------------ the tunnels on the way

/// One tunnel on the path of a port
#[derive(Clone, Debug, PartialEq)]
pub struct Hop {
    pub name: String,
    /// "faketcp", "kcp", …, "awg" (AmneziaWG link), "hy2" (Hysteria2 link)
    pub transport: String,
    /// a layer-3 link: the user's whole packet goes into an interface of this MTU
    pub iface: Option<u16>,
    /// the largest packet of the tunnel itself on its wire (0 = sized by the kernel / QUIC)
    pub wire: u16,
    /// FEC "data:parity" of the game transport: parity / data more bandwidth, no bigger packet
    pub fec: Option<(u16, u16)>,
}

fn hop_of(t: &crate::tunnel::panel::Tunnel) -> Hop {
    let name = t.name.clone();
    if t.kind == "awg" {
        let m = t.awg.mtu_or_default();
        let wire = if t.awg.wrap { 0 } else { m + IPV4 + UDP + WG };
        let transport = if t.awg.wrap { format!("awg+{}", t.transport) } else { "awg".into() };
        return Hop { name, transport, iface: Some(m), wire, fec: None };
    }
    if t.kind == "hy2" {
        return Hop { name, transport: "hy2".into(), iface: None, wire: 0, fec: None };
    }
    let tr = t.transport.as_str();
    let wire = match tr {
        "quic" | "hq" | "kcp" | "game" => UDP_WIRE + IPV4 + UDP,
        "faketcp" => FAKETCP_SEG + IPV4 + TCP,
        _ => 0,
    };
    let fec = (tr == "game").then(|| fec_of(&t.fec)).flatten();
    Hop { name, transport: tr.to_string(), iface: None, wire, fec }
}

/// "8:3" → (8, 3); "off" / "" → None
pub fn fec_of(s: &str) -> Option<(u16, u16)> {
    let (d, p) = s.split_once(':')?;
    let (d, p) = (d.trim().parse::<u16>().ok()?, p.trim().parse::<u16>().ok()?);
    (d > 0 && p > 0).then_some((d, p))
}

/// The UDP ports a tunnel brings from its entry to its exit, (entry port, exit port)
fn udp_ports(t: &crate::tunnel::panel::Tunnel) -> Vec<(u16, u16)> {
    let list = if t.kind == "awg" { &t.awg.fwd_udp } else { &t.udp };
    crate::tunnel::engine::parse_ports(list)
}

/// Every chain of tunnels that brings UDP `port` to server `sid`, each from the exit back to the
/// first entry. A port that more than one entry brings counts all of them: the config must fit the
/// smallest one.
pub fn chains(list: &[crate::tunnel::panel::Tunnel], sid: &str, port: u16) -> Vec<Vec<Hop>> {
    let mut out = vec![];
    // (server, port there, hops so far, servers seen)
    let mut todo = vec![(sid.to_string(), port, Vec::<Hop>::new(), vec![sid.to_string()])];
    while let Some((cur, p, hops, seen)) = todo.pop() {
        let prev: Vec<_> = list
            .iter()
            .filter(|t| t.enabled && t.kind != "awgwrap" && t.exit == cur && !seen.contains(&t.entry))
            .filter_map(|t| udp_ports(t).into_iter().find(|(_, b)| *b == p).map(|(a, _)| (t, a)))
            .collect();
        if prev.is_empty() || hops.len() >= 8 {
            if !hops.is_empty() {
                out.push(hops);
            }
            continue;
        }
        for (t, a) in prev {
            let mut h = hops.clone();
            h.push(hop_of(t));
            let mut s = seen.clone();
            s.push(t.entry.clone());
            todo.push((t.entry.clone(), a, h, s));
        }
    }
    out
}

/// The outer-packet budget of a path: the mobile network's, made smaller by any layer-3 link
pub fn cap_of(budget: u16, hops: &[Hop]) -> u16 {
    hops.iter().filter_map(|h| h.iface).fold(budget, u16::min)
}

// ------------------------------------------------------------------ per server and core

/// What one config of one core on one server gets
#[derive(Clone, Debug)]
pub struct Plan {
    pub core: String,
    /// through an Iran tunnel (false = straight to the server)
    pub via: bool,
    /// the tunnels on the way (the smallest chain when there are more)
    pub hops: Vec<Hop>,
    pub cap: u16,
    pub overhead: u16,
    pub mtu: u16,
    pub fits: bool,
}

impl Plan {
    pub fn json(&self) -> Value {
        let hops: Vec<Value> = self
            .hops
            .iter()
            .map(|h| json!({ "name": h.name, "transport": h.transport, "iface": h.iface, "wire": h.wire, "fec": h.fec.map(|(d, p)| format!("{}:{}", d, p)), "fec_pct": h.fec.map(|(d, p)| p as u32 * 100 / d as u32) }))
            .collect();
        json!({ "core": self.core, "via": if self.via { "tunnel" } else { "direct" }, "hops": hops, "cap": self.cap, "overhead": self.overhead, "mtu": self.mtu, "wire": self.mtu + self.overhead, "fits": self.fits })
    }
}

/// The UDP port of a core on a server (None = it does not run there)
fn core_port(app: &App, n: &Node, core: &str) -> Option<u16> {
    let info = crate::api::node_info(n);
    let num = |k: &str| info[k].as_str().and_then(|s| s.parse::<u16>().ok()).or_else(|| info[k].as_u64().map(|p| p as u16)).filter(|p| *p > 0);
    match core {
        "wg" => num("wg_port"),
        "awg" => num("awg_port"),
        "mtun" => num("mt_port").or_else(|| {
            let s = crate::microtun::settings(app);
            s.node_on(&n.id).then(|| s.node_port(&n.id))
        }),
        _ => None,
    }
}

/// The plan of a core's config on a server, `via` = the copy through the server's Iran tunnel
pub fn plan(app: &App, n: &Node, core: &str, via: bool) -> Option<Plan> {
    let list = crate::tunnel::panel::tunnels(app);
    plan_with(app, &list, n, core, via)
}

fn plan_with(app: &App, list: &[crate::tunnel::panel::Tunnel], n: &Node, core: &str, via: bool) -> Option<Plan> {
    let oh = overhead(core, if core == "awg" { awg_pad(n) } else { 0 })?;
    let b = budget(app);
    // the main configs of a server whose address is an Iran entry go through the tunnel too
    let via = via || crate::direct::through_tunnel(app, n);
    let mut hops = vec![];
    let mut cap = b;
    if via {
        let sid = crate::twin::sid_of_node(app, &n.id);
        if let (false, Some(port)) = (sid.is_empty(), core_port(app, n, core)) {
            for c in chains(list, &sid, port) {
                let c_cap = cap_of(b, &c);
                if c_cap < cap || hops.is_empty() {
                    cap = cap.min(c_cap);
                    hops = c;
                }
            }
        }
    }
    let (mtu, fits) = safe(cap, oh);
    Some(Plan { core: core.into(), via, hops, cap, overhead: oh, mtu, fits })
}

/// The hand-set MTU (automatic MTU off)
fn manual(app: &App, core: &str) -> u16 {
    if core == "mtun" {
        return crate::microtun::settings(app).mtu;
    }
    app.db.get("mtu").trim().parse::<u16>().ok().filter(|m| (576..=9000).contains(m)).unwrap_or(1380)
}

/// The MTU a config of `core` on server `n` gets (`via`: the copy through its Iran tunnel)
pub fn client(app: &App, n: &Node, core: &str, via: bool) -> u16 {
    if !auto(app) {
        return manual(app, core);
    }
    plan(app, n, core, via).map(|p| p.mtu).unwrap_or_else(|| manual(app, core))
}

/// The MTU of a core's own interface on server `n`: the smallest of its configs (direct and through
/// the tunnel), so what the server sends back fits the phone's path too. None = automatic MTU off.
pub fn server(app: &App, n: &Node, core: &str) -> Option<u16> {
    if !auto(app) {
        return None;
    }
    let list = crate::tunnel::panel::tunnels(app);
    let direct = plan_with(app, &list, n, core, false)?;
    let via = crate::twin::of_node_core(app, n, core).and_then(|_| plan_with(app, &list, n, core, true));
    Some(via.map(|v| v.mtu.min(direct.mtu)).unwrap_or(direct.mtu))
}

/// interface -> MTU for the sync of server `n`. Automatic MTU off: every interface with 0, which
/// takes our TCP MSS rules away and leaves the MTU as it is.
pub fn ifaces(app: &App, n: &Node) -> HashMap<String, u16> {
    let mut m = HashMap::new();
    for (core, iface) in [("wg", "wg0"), ("awg", "awg0"), ("mtun", crate::mtun::IFACE)] {
        m.insert(iface.to_string(), server(app, n, core).unwrap_or(0));
    }
    m
}

/// The interfaces `apply_ifaces` may touch; microtun sets the MTU of its own (`MtCfg.mtu`)
const IFACES: [&str; 3] = ["wg0", "awg0", crate::mtun::IFACE];
/// comment on our TCP MSS rules, so only ours are ever removed
const MSS_TAG: &str = "kanki-mtu";

/// The TCP MSS rules of an interface (`tool` = iptables / ip6tables): every TCP connection through it
/// is made with segments that fit its MTU, both ways. So an older config with a bigger MTU (1380,
/// 1420) still gets every download in whole packets, without waiting for "packet too big" answers that
/// some sites never send.
fn mss_rules(tool: &str, iface: &str, mtu: u16) -> Vec<Vec<String>> {
    let mss = mtu.saturating_sub(if tool == "ip6tables" { 60 } else { 40 }).to_string();
    let tag = format!("{}-{}", MSS_TAG, iface);
    ["-i", "-o"]
        .iter()
        .map(|dir| {
            [tool, "-t", "mangle", "-A", "FORWARD", dir, iface, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-m", "comment", "--comment", &tag, "-j", "TCPMSS", "--set-mss", &mss]
                .iter()
                .map(|x| x.to_string())
                .collect()
        })
        .collect()
}

fn run_quiet(args: &[String]) -> bool {
    std::process::Command::new(&args[0]).args(&args[1..]).output().map(|o| o.status.success()).unwrap_or(false)
}

/// Removes every rule of ours for `iface` from the mangle FORWARD chain of `tool`
fn mss_clear(tool: &str, iface: &str) {
    let tag = format!("{}-{}", MSS_TAG, iface);
    let Ok(out) = std::process::Command::new(tool).args(["-t", "mangle", "-S", "FORWARD"]).output() else { return };
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        // only whole rules with our own comment: "-A FORWARD ... --comment kanki-mtu-wg0 ..."
        if !line.starts_with("-A FORWARD ") || !line.split_whitespace().any(|w| w.trim_matches('"') == tag) {
            continue;
        }
        let mut a: Vec<String> = vec![tool.into(), "-t".into(), "mangle".into(), "-D".into()];
        a.extend(line.split_whitespace().skip(1).map(|w| w.trim_matches('"').to_string()));
        let _ = run_quiet(&a);
    }
}

/// What the agent did last (interface -> MTU): the rules are rewritten only when it changes
fn applied() -> &'static std::sync::Mutex<HashMap<String, u16>> {
    static M: std::sync::OnceLock<std::sync::Mutex<HashMap<String, u16>>> = std::sync::OnceLock::new();
    M.get_or_init(Default::default)
}

/// On a server: give `wg0` / `awg0` the MTU the panel worked out (only when it differs, only
/// interfaces that exist; a restart of wg-quick puts its own value back until the next sync), and
/// clamp TCP to it on `wg0`, `awg0` and `mtun0`. 0 = automatic MTU off: our rules go, the MTU stays.
pub fn apply_ifaces(want: &HashMap<String, u16>) {
    for (iface, mtu) in want {
        let mtu = *mtu;
        if !IFACES.contains(&iface.as_str()) || (mtu != 0 && !(MIN..=1500).contains(&mtu)) {
            continue;
        }
        if mtu != 0 && iface != crate::mtun::IFACE {
            if let Ok(cur) = std::fs::read_to_string(format!("/sys/class/net/{}/mtu", iface)) {
                if cur.trim().parse::<u16>().ok() != Some(mtu) {
                    let ok = std::process::Command::new("ip").args(["link", "set", "dev", iface, "mtu", &mtu.to_string()]).status().map(|s| s.success()).unwrap_or(false);
                    if !ok {
                        eprintln!("mtu: could not set {} to {}", iface, mtu);
                    }
                }
            }
        }
        let mut done = applied().lock().unwrap_or_else(|e| e.into_inner());
        if done.get(iface) == Some(&mtu) {
            continue;
        }
        for tool in ["iptables", "ip6tables"] {
            mss_clear(tool, iface);
            if mtu != 0 {
                for r in mss_rules(tool, iface, mtu) {
                    if !run_quiet(&r) && tool == "iptables" {
                        eprintln!("mtu: could not add the TCP MSS rule of {}", iface);
                    }
                }
            }
        }
        done.insert(iface.clone(), mtu);
    }
}

// ------------------------------------------------------------------ the panel's report

/// Bytes each layer adds (for the report): (name, bytes, what it is)
pub fn layers() -> Value {
    json!([
        { "name": "IPv4", "bytes": IPV4, "kind": "base" },
        { "name": "UDP", "bytes": UDP, "kind": "base" },
        { "name": "WireGuard", "bytes": WG, "kind": "core" },
        { "name": "AmneziaWG", "bytes": WG, "plus": "S4", "kind": "core" },
        { "name": "microtun", "bytes": MTUN, "kind": "core" },
        { "name": "KANKI MIX", "bytes": KMIX_WIRE + IPV4 + UDP, "kind": "core", "wire": true },
        { "name": "Hysteria2 (Salamander)", "bytes": SALAMANDER, "plus": "QUIC", "kind": "core" },
        { "name": "AmneziaWG link", "bytes": IPV4 + UDP + WG, "kind": "tunnel", "cuts": false },
        { "name": "KCP / QUIC / hq / game", "bytes": UDP_WIRE + IPV4 + UDP, "kind": "tunnel", "cuts": true, "wire": true },
        { "name": "FakeTCP", "bytes": FAKETCP_SEG + IPV4 + TCP, "kind": "tunnel", "cuts": true, "wire": true },
    ])
}

/// Everything the panel would give: per server, per core, direct and through the tunnel
pub fn report(app: &App) -> Value {
    let list = crate::tunnel::panel::tunnels(app);
    let mut rows = vec![];
    for n in app.db.nodes() {
        for core in CORES {
            let Some(d) = plan_with(app, &list, &n, core, false) else { continue };
            if core_port(app, &n, core).is_none() {
                continue;
            }
            let mut r = d.json();
            r["node"] = json!(n.name);
            r["node_id"] = json!(n.id);
            rows.push(r);
            if crate::twin::of_node_core(app, &n, core).is_some() && !d.via {
                if let Some(v) = plan_with(app, &list, &n, core, true) {
                    let mut r = v.json();
                    r["node"] = json!(n.name);
                    r["node_id"] = json!(n.id);
                    rows.push(r);
                }
            }
        }
    }
    // Xray mKCP inbounds: their own packet size is set on the inbound; only checked here
    let b = budget(app);
    let xray: Vec<Value> = crate::xray::panel::settings(app)
        .inbounds
        .iter()
        .filter(|ib| ib.enabled && ib.network == "kcp")
        .map(|ib| {
            // the config of the inbound never goes over 1352 (`xray::panel::stream`); 0 = Xray's own 1350
            let m = if ib.kcp_mtu == 0 { 1350 } else { ib.kcp_mtu.min(1352) };
            json!({ "id": ib.id, "mtu": m, "wire": m + (IPV4 + UDP) as u32, "fits": m + ((IPV4 + UDP) as u32) <= b as u32 })
        })
        .collect();
    json!({ "auto": auto(app), "budget": b, "manual": manual(app, "wg"), "manual_mtun": manual(app, "mtun"), "layers": layers(), "rows": rows, "xray_kcp": xray })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tunnel::panel::Tunnel;
    use serde_json::json;

    fn tun(id: &str, entry: &str, exit: &str, transport: &str, udp: &[&str]) -> Tunnel {
        Tunnel { id: id.into(), name: id.into(), entry: entry.into(), exit: exit.into(), transport: transport.into(), enabled: true, udp: udp.iter().map(|s| s.to_string()).collect(), ..Default::default() }
    }

    #[test]
    fn the_numbers_of_each_core() {
        assert_eq!(overhead("wg", 0), Some(60));
        assert_eq!(overhead("awg", 0), Some(60));
        assert_eq!(overhead("awg", 16), Some(76));
        assert_eq!(overhead("mtun", 0), Some(56));
        assert_eq!(overhead("hy2", 0), None);
        // 1380 on the mobile network: WireGuard 1320, microtun 1324
        assert_eq!(safe(1380, 60), (1320, true));
        assert_eq!(safe(1380, 56), (1324, true));
        // a path too small for 1280 keeps 1280 and says it does not fit
        assert_eq!(safe(1280, 60), (1280, false));
    }

    #[test]
    fn a_whole_packet_never_passes_the_budget() {
        for b in [1300u16, 1380, 1420, 1500] {
            for (core, pad) in [("wg", 0), ("awg", 0), ("awg", 32), ("mtun", 0)] {
                let oh = overhead(core, pad).unwrap();
                let (m, fits) = safe(b, oh);
                if fits {
                    assert!(m + oh <= b, "{} {} {}", core, b, m);
                }
            }
        }
    }

    #[test]
    fn only_a_layer3_link_makes_the_path_smaller() {
        let mut awg = tun("a", "ir", "de", "", &[]);
        awg.kind = "awg".into();
        awg.awg.fwd_udp = vec!["51820".into()];
        awg.awg.mtu = 1300;
        let list = vec![tun("k", "ir", "de", "faketcp", &["4200"]), tun("g", "ir", "de", "game", &["4300:4200"]), awg];
        // faketcp and game cut the datagram themselves: the budget stays
        let c = chains(&list, "de", 4200);
        assert_eq!(c.len(), 2);
        assert!(c.iter().all(|h| cap_of(1380, h) == 1380));
        assert_eq!(c.iter().find(|h| h[0].transport == "game").unwrap()[0].wire, 1260);
        // the AmneziaWG link puts the whole packet in a 1300 interface
        let c = chains(&list, "de", 51820);
        assert_eq!(c.len(), 1);
        assert_eq!(cap_of(1380, &c[0]), 1300);
        assert_eq!(safe(cap_of(1380, &c[0]), 60), (1280, false));
        // a port no tunnel brings has no chain
        assert!(chains(&list, "de", 9999).is_empty());
    }

    #[test]
    fn a_route_of_two_hops_is_followed_to_its_first_entry() {
        let mut awg = tun("b", "tr", "de", "", &[]);
        awg.kind = "awg".into();
        awg.awg.fwd_udp = vec!["5000:4200".into()];
        awg.awg.wrap = true;
        let list = vec![tun("a", "ir", "tr", "kcp", &["6000:5000"]), awg];
        let c = chains(&list, "de", 4200);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].len(), 2);
        // a wrapped link is 1280 unless set: microtun gets the floor and is told it does not fit
        assert_eq!(cap_of(1380, &c[0]), 1280);
        assert_eq!(c[0][0].transport, "awg+");
        // a loop of tunnels stops
        let lp = vec![tun("x", "a", "b", "kcp", &["1"]), tun("y", "b", "a", "kcp", &["1"])];
        assert_eq!(chains(&lp, "a", 1).len(), 1);
    }

    #[test]
    fn tcp_is_clamped_to_the_mtu_both_ways() {
        let r = mss_rules("iptables", "wg0", 1320);
        assert_eq!(r.len(), 2);
        assert!(r.iter().all(|x| x.ends_with(&["--set-mss".to_string(), "1280".to_string()]) && x.contains(&"kanki-mtu-wg0".to_string())));
        assert!(r[0].contains(&"-i".to_string()) && r[1].contains(&"-o".to_string()));
        assert!(mss_rules("ip6tables", "mtun0", 1324)[0].ends_with(&["--set-mss".to_string(), "1264".to_string()]));
    }

    /// On a real machine (root, in a network namespace of its own):
    /// `unshare -n sh -c 'ip link add wg0 type dummy; cargo test mtu_live -- --ignored'`
    #[test]
    #[ignore]
    fn mtu_live() {
        let rules = || String::from_utf8_lossy(&std::process::Command::new("iptables").args(["-t", "mangle", "-S", "FORWARD"]).output().unwrap().stdout).to_string();
        apply_ifaces(&HashMap::from([("wg0".to_string(), 1320), ("mtun0".to_string(), 1324), ("eth0".to_string(), 1300)]));
        assert_eq!(std::fs::read_to_string("/sys/class/net/wg0/mtu").unwrap().trim(), "1320");
        let r = rules();
        assert_eq!(r.matches("kanki-mtu-wg0").count(), 2, "{}", r);
        assert_eq!(r.matches("--set-mss 1280").count(), 2);
        assert_eq!(r.matches("kanki-mtu-mtun0").count(), 2);
        assert!(!r.contains("eth0"));
        // a new value replaces the rules, no second copy
        apply_ifaces(&HashMap::from([("wg0".to_string(), 1300)]));
        let r = rules();
        assert_eq!(r.matches("kanki-mtu-wg0").count(), 2, "{}", r);
        assert!(r.contains("--set-mss 1260") && !r.contains("--set-mss 1280"));
        assert_eq!(std::fs::read_to_string("/sys/class/net/wg0/mtu").unwrap().trim(), "1300");
        // off: the rules go, the MTU stays
        apply_ifaces(&HashMap::from([("wg0".to_string(), 0), ("mtun0".to_string(), 0)]));
        assert!(!rules().contains("kanki-mtu"), "{}", rules());
        assert_eq!(std::fs::read_to_string("/sys/class/net/wg0/mtu").unwrap().trim(), "1300");
    }

    #[test]
    fn kmix_server_matches() {
        let src = include_str!("kmix-server/internal/obfs/obfs.go");
        assert!(src.contains(&format!("MaxWire    = {}", KMIX_WIRE)), "KMIX_WIRE must follow the Go server");
        assert!(KMIX_WIRE + 40 + UDP <= DEFAULT_BUDGET);
    }

    #[test]
    fn fec_is_read() {
        assert_eq!(fec_of("8:3"), Some((8, 3)));
        assert_eq!(fec_of("off"), None);
        assert_eq!(fec_of("8:0"), None);
    }

    fn test_app() -> std::sync::Arc<crate::App> {
        use std::sync::{atomic::AtomicI64, Mutex};
        let dir = std::env::temp_dir().join(format!("kanki-mtu-test-{}", crate::util::rand_token(8)));
        std::fs::create_dir_all(&dir).unwrap();
        let db = crate::db::Db::open(dir.join("kanki.db").to_str().unwrap());
        std::sync::Arc::new(crate::App {
            db,
            env: HashMap::from([("DOMAIN".to_string(), "fi.example.com".to_string())]),
            hy2_allowed: Mutex::new(HashMap::new()), limits: Mutex::new(HashMap::new()), reported: Mutex::new(HashMap::new()),
            login_fails: Mutex::new(HashMap::new()), sync_lock: tokio::sync::Mutex::new(()), bot_alive: AtomicI64::new(0),
            http: reqwest::Client::new(), http_insecure: reqwest::Client::new(), pin_clients: Mutex::new(HashMap::new()),
        })
    }

    fn mtu_line(text: &str) -> String {
        text.lines().find(|l| l.starts_with("MTU = ")).unwrap_or("").to_string()
    }

    /// The whole way: a server, a user, its tunnel; the config files the panel hands out
    #[tokio::test]
    async fn configs_get_the_mtu_of_their_path_and_follow_the_tunnel() {
        let app = test_app();
        let info = json!({ "wg_pub": "d2dwdWI=", "wg_port": "51820", "awg_pub": "YXdncHVi", "awg_port": "51821", "mt_port": 4200,
            "awg": [["Jc", "4"], ["S1", "20"], ["S2", "30"], ["S4", "16"], ["H1", "1"], ["H2", "2"], ["H3", "3"], ["H4", "4"]] });
        app.db.exec("INSERT INTO nodes(id,name,address,endpoint,token,info) VALUES('de','Germany','de.example.com','de.example.com','t',?1)", &[&info.to_string()]).unwrap();
        let u = app.db.create_user("ali", 10.0, 30, 1, "wg,awg,mtun", "", "", 0).unwrap();
        let n = app.db.node("de").unwrap();
        let conf = |proto: &'static str, tunnel: bool| {
            let (app, u, n) = (app.clone(), u.clone(), n.clone());
            async move { crate::api::bot_config(&app, &u, &n, proto, tunnel).await.map(|x| x.1).unwrap_or_default() }
        };
        // straight to the server: 1380 - 60 (WireGuard), - 76 (AmneziaWG with S4 = 16)
        // keys made here (the `wg` program is not needed for the test)
        for (proto, ip) in [("wg", "10.66.0.2"), ("awg", "10.67.0.2")] {
            app.db.exec("INSERT INTO peers(user_id,node_id,proto,privkey,pubkey,psk,ip) VALUES(?1,'de',?2,'cHJpdg==','cHVi','cHNr',?3)", &[&u.id, &proto, &ip]).unwrap();
        }
        // (plain WireGuard is given only through Iran: it does not pass straight to a server abroad)
        assert_eq!(client(&app, &n, "wg", false), 1320);
        assert_eq!(mtu_line(&conf("amneziawg", false).await), "MTU = 1304");
        assert_eq!(client(&app, &n, "mtun", false), 1324);
        // the server and an Iran server with a FakeTCP tunnel bringing every port: still 1380
        let srv = json!([{ "id": "ir1", "name": "Iran", "token": "x", "addr": "ir.example.com" }, { "id": "s-de", "name": "Germany", "token": "y", "node": "de" }]);
        app.db.set("tun_servers", &srv.to_string());
        let ft = json!([{ "id": "t1", "name": "ft", "entry": "ir1", "exit": "s-de", "transport": "faketcp", "enabled": true, "udp": ["51820", "51821", "4200"] }]);
        app.db.set("tun_list", &ft.to_string());
        app.db.set("srv_tunnel", &json!({ "s-de": { "on": true, "host": "ir.example.com" } }).to_string());
        assert!(crate::twin::of_node_core(&app, &n, "wg").is_some());
        // a tunnel that does not carry a core's port: no second config for that core (it would never connect)
        app.db.set("tun_list", &json!([{ "id": "t1", "name": "ft", "entry": "ir1", "exit": "s-de", "transport": "faketcp", "enabled": true, "udp": ["51820", "4200"] }]).to_string());
        assert!(crate::twin::of_node_core(&app, &n, "wg").is_some());
        assert!(crate::twin::of_node_core(&app, &n, "awg").is_none());
        app.db.set("tun_list", &ft.to_string());
        let wg_t = conf("wireguard", true).await;
        assert!(wg_t.contains("Endpoint = ir.example.com:51820"), "{}", wg_t);
        assert_eq!(mtu_line(&wg_t), "MTU = 1320");
        // the tunnel becomes an AmneziaWG link of MTU 1340: the tunnel configs follow, by themselves
        let awg = json!([{ "id": "t1", "name": "awg", "entry": "ir1", "exit": "s-de", "kind": "awg", "enabled": true,
            "awg": { "n": 1, "mtu": 1340, "fwd_udp": ["51820", "51821", "4200"] } }]);
        app.db.set("tun_list", &awg.to_string());
        assert_eq!(mtu_line(&conf("wireguard", true).await), "MTU = 1280");
        assert_eq!(mtu_line(&conf("amneziawg", true).await), "MTU = 1280");
        assert_eq!(mtu_line(&conf("amneziawg", false).await), "MTU = 1304");
        let p = plan(&app, &n, "mtun", true).unwrap();
        assert_eq!((p.cap, p.mtu, p.fits), (1340, 1284, true));
        let link = crate::microtun::link(&app, &u, &n, true).unwrap_or_default();
        assert!(link.contains("@ir.example.com:4200?") && link.contains("&mtu=1284&"), "{}", link);
        assert!(crate::microtun::link(&app, &u, &n, false).unwrap().contains("&mtu=1324&"));
        // the server's own interfaces: the smallest of its configs
        let f = ifaces(&app, &n);
        assert_eq!((f["wg0"], f["awg0"], f["mtun0"]), (1280, 1280, 1284));
        // the report says why
        let r = report(&app);
        assert!(r["rows"].as_array().unwrap().iter().any(|x| x["via"] == "tunnel" && x["hops"][0]["transport"] == "awg" && x["cap"] == 1340));
        // automatic MTU off: the hand-set MTU everywhere, and our interface rules taken away
        app.db.set("mtu_auto", "0");
        app.db.set("mtu", "1400");
        assert_eq!(mtu_line(&conf("wireguard", true).await), "MTU = 1400");
        assert!(ifaces(&app, &n).values().all(|v| *v == 0));
        // a smaller limit for the mobile network
        app.db.set("mtu_auto", "1");
        app.db.set("mtu_budget", "1360");
        assert_eq!(mtu_line(&conf("amneziawg", false).await), "MTU = 1284");
        // a limit out of range is not taken
        app.db.set("mtu_budget", "900");
        assert_eq!(budget(&app), DEFAULT_BUDGET);
    }
}
