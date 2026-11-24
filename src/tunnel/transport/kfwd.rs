//! Direct tunnel: the kernel moves the packets, no program in the way, nothing added to them.
//!
//! Two modes, both made only of `iptables` and `ip` rules on the servers:
//!   - `nat`: the entry forwards its ports straight to the exit's address (DNAT + MASQUERADE). Zero bytes
//!     added, zero copies in user space; needs the entry to reach the exit's address (Iran → abroad).
//!   - `gre`: a GRE link between the two servers (kernel, 24 bytes a packet, no encryption), the entry
//!     forwards its ports into the link. For when the exit's ports are filtered but GRE passes.
//! Every rule lives in chains of its own (`KFWD-*`), rebuilt as a whole when the wanted tunnels change,
//! so a tunnel that goes leaves nothing behind. Commands run without a shell, with values checked here.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{Ipv4Addr, ToSocketAddrs};
use std::process::{Command, Stdio};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

const GRE_PREFIX: &str = "kfg";
const CHAINS: &[(&str, &str, &str)] = &[
    // (table, our chain, the built-in chain it hangs from)
    ("nat", "KFWD-PRE", "PREROUTING"),
    ("nat", "KFWD-POST", "POSTROUTING"),
    ("filter", "KFWD-FWD", "FORWARD"),
    ("filter", "KFWD-IN", "INPUT"),
    ("mangle", "KFWD-MSS", "FORWARD"),
];

// ------------------------------------------------------------------ what the panel stores

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
#[serde(default)]
pub struct FwdCfg {
    /// "nat" (straight to the exit's address) | "gre" (through a GRE link)
    pub mode: String,
    /// gre: the link uses 10.89.N.0/30 (entry .1, exit .2)
    pub n: u8,
}

impl FwdCfg {
    pub fn gre(&self) -> bool {
        self.mode == "gre"
    }
    pub fn entry_ip(&self) -> String {
        format!("10.89.{}.1", self.n)
    }
    pub fn exit_ip(&self) -> String {
        format!("10.89.{}.2", self.n)
    }
}

// ------------------------------------------------------------------ what an agent gets

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
#[serde(default)]
pub struct FwdSpec {
    pub tid: String,
    /// "entry" | "exit"
    pub role: String,
    /// "nat" | "gre"
    pub mode: String,
    /// the other server's address (IPv4 or a name; the agent resolves it)
    pub peer: String,
    pub n: u8,
    /// entry: forwarded ports "443" or "8443:443"
    pub tcp: Vec<String>,
    pub udp: Vec<String>,
    /// where the ports go (empty = the exit itself)
    pub target: String,
}

impl FwdSpec {
    pub fn gre(&self) -> bool {
        self.mode == "gre"
    }
    fn iface(&self) -> String {
        format!("{}{}", GRE_PREFIX, self.n)
    }
    fn own_ip(&self) -> String {
        format!("10.89.{}.{}", self.n, if self.role == "entry" { 1 } else { 2 })
    }
    fn peer_inner(&self) -> String {
        format!("10.89.{}.{}", self.n, if self.role == "entry" { 2 } else { 1 })
    }
}

fn host_ok(h: &str) -> bool {
    !h.is_empty() && h.len() <= 253 && h.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
}

/// the other server's IPv4 (a name is looked up; an IPv6-only name is not usable here)
fn resolve(h: &str) -> Option<Ipv4Addr> {
    let h = h.trim().trim_start_matches('[').trim_end_matches(']');
    let h = h.rsplit_once(':').filter(|(_, p)| p.chars().all(|c| c.is_ascii_digit())).map(|(a, _)| a).unwrap_or(h);
    if let Ok(ip) = h.parse::<Ipv4Addr>() {
        return Some(ip);
    }
    if !host_ok(h) {
        return None;
    }
    (h, 0).to_socket_addrs().ok()?.find_map(|a| match a.ip() {
        std::net::IpAddr::V4(v) => Some(v),
        _ => None,
    })
}

/// One `iptables` call: (table, arguments)
type Rule = (&'static str, Vec<String>);

fn s(v: &[&str]) -> Vec<String> {
    v.iter().map(|x| x.to_string()).collect()
}

/// The rules of one tunnel on this server, given the other server's IPv4. Pure: the tests read it.
pub fn rules(w: &FwdSpec, peer: Ipv4Addr) -> Vec<Rule> {
    let mut out: Vec<Rule> = vec![];
    let peer = peer.to_string();
    if w.gre() {
        // GRE packets of the other server only
        out.push(("filter", s(&["-A", "KFWD-IN", "-p", "gre", "-s", &peer, "-j", "ACCEPT"])));
        // what comes in through the link reaches this server (the cores listen on every address)
        out.push(("filter", s(&["-A", "KFWD-IN", "-i", &w.iface(), "-j", "ACCEPT"])));
        // TCP through the link: segments that fit its MTU, never a black hole
        out.push(("mangle", s(&["-A", "KFWD-MSS", "-o", &w.iface(), "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"])));
    }
    let target = w.target.trim().parse::<Ipv4Addr>().ok();
    if w.role == "exit" {
        // gre with a target beyond the exit: what came through the link goes on from here
        if let (true, Some(t)) = (w.gre(), target) {
            let t = t.to_string();
            let net = format!("10.89.{}.0/30", w.n);
            out.push(("filter", s(&["-A", "KFWD-FWD", "-i", &w.iface(), "-d", &t, "-j", "ACCEPT"])));
            out.push(("filter", s(&["-A", "KFWD-FWD", "-o", &w.iface(), "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"])));
            out.push(("nat", s(&["-A", "KFWD-POST", "-s", &net, "-d", &t, "-j", "MASQUERADE"])));
        }
        return out;
    }
    // the entry: its ports to the exit (its address, or its end of the link), or the target
    let dest = match (target, w.gre()) {
        (Some(t), _) => t.to_string(),
        (None, true) => w.peer_inner(),
        (None, false) => peer.clone(),
    };
    for (proto, list) in [("tcp", &w.tcp), ("udp", &w.udp)] {
        for (a, b) in crate::tunnel::engine::parse_ports(list) {
            let (a, b) = (a.to_string(), b.to_string());
            out.push(("nat", s(&["-A", "KFWD-PRE", "-p", proto, "--dport", &a, "-m", "addrtype", "--dst-type", "LOCAL", "-j", "DNAT", "--to-destination", &format!("{}:{}", dest, b)])));
            out.push(("filter", s(&["-A", "KFWD-FWD", "-p", proto, "-d", &dest, "--dport", &b, "-j", "ACCEPT"])));
            // the exit answers this server, which hands the answer back to the user
            if w.gre() && target.is_none() {
                out.push(("nat", s(&["-A", "KFWD-POST", "-o", &w.iface(), "-p", proto, "-d", &dest, "--dport", &b, "-j", "SNAT", "--to-source", &w.own_ip()])));
            } else {
                out.push(("nat", s(&["-A", "KFWD-POST", "-p", proto, "-d", &dest, "--dport", &b, "-j", "MASQUERADE"])));
            }
        }
    }
    if !w.tcp.is_empty() || !w.udp.is_empty() {
        out.push(("filter", s(&["-A", "KFWD-FWD", "-d", &dest, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"])));
        out.push(("filter", s(&["-A", "KFWD-FWD", "-s", &dest, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"])));
    }
    if let (true, Some(t)) = (w.gre(), target) {
        // a target beyond the exit is reached through the link
        out.push(("route", vec![t.to_string()]));
    }
    out
}

// ------------------------------------------------------------------ running it

#[derive(Default)]
struct Shared {
    want: Vec<FwdSpec>,
    applied: Option<Vec<FwdSpec>>,
    stamp: Option<Instant>,
    errors: HashMap<String, String>,
    rtt: HashMap<String, u64>,
    peers: HashMap<String, Ipv4Addr>,
    since: HashMap<String, u64>,
}

fn shared() -> &'static Mutex<Shared> {
    static S: OnceLock<Mutex<Shared>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(Shared::default()))
}

fn guard() -> std::sync::MutexGuard<'static, Shared> {
    shared().lock().unwrap_or_else(|e| e.into_inner())
}

fn run(prog: &str, args: &[String]) -> (bool, String) {
    match Command::new(prog).args(args).stdin(Stdio::null()).output() {
        Ok(o) => {
            let mut t = String::from_utf8_lossy(&o.stdout).to_string();
            t.push_str(&String::from_utf8_lossy(&o.stderr));
            (o.status.success(), t.trim().to_string())
        }
        Err(e) => (false, e.to_string()),
    }
}

fn ipt(table: &str, args: &[String]) -> (bool, String) {
    let mut a = vec!["-w".to_string(), "-t".to_string(), table.to_string()];
    a.extend_from_slice(args);
    run("iptables", &a)
}

/// our chains exist and hang from the built-in ones (once); `empty` = no tunnel: they go away
fn chains(empty: bool) {
    for (table, ch, from) in CHAINS {
        let jump = s(&[from, "-j", ch]);
        if empty {
            while ipt(table, &[vec!["-D".to_string()], jump.clone()].concat()).0 {}
            let _ = ipt(table, &s(&["-F", ch]));
            let _ = ipt(table, &s(&["-X", ch]));
            continue;
        }
        let _ = ipt(table, &s(&["-N", ch]));
        let _ = ipt(table, &s(&["-F", ch]));
        if !ipt(table, &[vec!["-C".to_string()], jump.clone()].concat()).0 {
            let _ = ipt(table, &[vec!["-I".to_string()], jump.clone()].concat());
        }
    }
}

/// our jumps stay first in the built-in chains: a firewall turned on later (ufw) puts its own in front,
/// and its default "deny" would then drop the GRE packets or the forwarded ports before our rules see them
fn keep_first() {
    for (table, ch, from) in CHAINS {
        let (_, list) = ipt(table, &s(&["-S", from]));
        let first = list.lines().find(|l| l.starts_with("-A "));
        if first.map(|l| l.trim() == format!("-A {} -j {}", from, ch)).unwrap_or(false) {
            continue;
        }
        let jump = s(&[from, "-j", ch]);
        while ipt(table, &[vec!["-D".to_string()], jump.clone()].concat()).0 {}
        let _ = ipt(table, &[vec!["-I".to_string()], jump].concat());
    }
}

/// GRE interfaces: the wanted ones exist with the right peer, the others go
fn gre_links(want: &[(FwdSpec, Ipv4Addr)]) -> HashMap<String, String> {
    let mut err = HashMap::new();
    let (_, list) = run("ip", &s(&["-o", "link", "show"]));
    let have: Vec<String> = list
        .lines()
        .filter_map(|l| l.split(':').nth(1).map(|x| x.trim().split('@').next().unwrap_or("").to_string()))
        .filter(|n| n.starts_with(GRE_PREFIX) && n[GRE_PREFIX.len()..].chars().all(|c| c.is_ascii_digit()))
        .collect();
    for n in &have {
        if !want.iter().any(|(w, _)| w.gre() && &w.iface() == n) {
            let _ = run("ip", &s(&["link", "del", n]));
        }
    }
    if want.iter().any(|(w, _)| w.gre()) {
        // the GRE module is not always loaded
        let _ = run("modprobe", &s(&["ip_gre"]));
    }
    for (w, peer) in want.iter().filter(|(w, _)| w.gre()) {
        let name = w.iface();
        let (_, d) = run("ip", &s(&["-d", "link", "show", &name]));
        let right = d.contains(&format!("remote {}", peer));
        if !right {
            let _ = run("ip", &s(&["link", "del", &name]));
            let (ok, out) = run("ip", &s(&["tunnel", "add", &name, "mode", "gre", "remote", &peer.to_string(), "ttl", "255"]));
            if !ok {
                let why = out.lines().last().unwrap_or("ip tunnel add failed");
                err.insert(w.tid.clone(), if why.contains("No such device") || why.contains("not supported") {
                    "the kernel of this server has no GRE (ip_gre): use the NAT mode, or another server".to_string()
                } else {
                    format!("GRE link: {}", why)
                });
                continue;
            }
        }
        let _ = run("ip", &s(&["addr", "replace", &format!("{}/30", w.own_ip()), "dev", &name]));
        let _ = run("ip", &s(&["link", "set", &name, "mtu", "1476", "up"]));
    }
    err
}

fn reconcile() {
    let want = guard().want.clone();
    let mut errors: HashMap<String, String> = HashMap::new();
    let mut ready: Vec<(FwdSpec, Ipv4Addr)> = vec![];
    for w in &want {
        match resolve(&w.peer) {
            Some(ip) => ready.push((w.clone(), ip)),
            // the exit of a nat tunnel never needs the entry's address
            None if !w.gre() && w.role == "exit" => ready.push((w.clone(), Ipv4Addr::UNSPECIFIED)),
            None => {
                errors.insert(w.tid.clone(), format!("the address of the other server ({}) is not known", w.peer));
            }
        }
    }
    let applied = {
        let g = guard();
        g.applied.clone()
    };
    let peers_now: HashMap<String, Ipv4Addr> = ready.iter().map(|(w, ip)| (w.tid.clone(), *ip)).collect();
    // a round that failed somewhere is tried again (a module loaded, an address learned since)
    let same = applied.as_ref() == Some(&want) && guard().peers == peers_now && guard().errors.values().all(|e| e.is_empty()) && errors.is_empty();
    if !same {
        if want.is_empty() {
            chains(true);
            gre_links(&[]);
        } else {
            let _ = run("sysctl", &s(&["-w", "net.ipv4.ip_forward=1"]));
            errors.extend(gre_links(&ready));
            chains(false);
            for (w, peer) in &ready {
                if errors.contains_key(&w.tid) {
                    continue;
                }
                for (table, args) in rules(w, *peer) {
                    if table == "route" {
                        let _ = run("ip", &s(&["route", "replace", &format!("{}/32", args[0]), "dev", &w.iface()]));
                        continue;
                    }
                    let (ok, out) = ipt(table, &args);
                    if !ok {
                        errors.insert(w.tid.clone(), format!("iptables: {}", out.lines().last().unwrap_or("failed")));
                    }
                }
                guard().since.entry(w.tid.clone()).or_insert(crate::util::now() as u64);
            }
        }
        let mut g = guard();
        g.applied = Some(want.clone());
        g.peers = peers_now;
        g.errors = errors.clone();
    } else {
        if !want.is_empty() {
            keep_first();
        }
        let mut g = guard();
        for (k, v) in errors {
            g.errors.insert(k, v);
        }
    }
    // delay to the other server: through the link (gre) or straight (nat)
    for (w, peer) in ready.iter().filter(|(_, p)| !p.is_unspecified()) {
        let to = if w.gre() { w.peer_inner() } else { peer.to_string() };
        let (_, out) = run("ping", &s(&["-c", "1", "-W", "1", &to]));
        let rtt = out.split("time=").nth(1).and_then(|x| x.split_whitespace().next()).and_then(|x| x.parse::<f64>().ok());
        let mut g = guard();
        match rtt {
            Some(v) => {
                g.rtt.insert(w.tid.clone(), v.round().max(1.0) as u64);
            }
            None => {
                g.rtt.remove(&w.tid);
            }
        }
    }
}

/// Called every few seconds with the direct tunnels of this server; the work runs on a thread of its own
pub fn set_desired(want: Vec<FwdSpec>) {
    // only values that can go into the commands as they are
    let want: Vec<FwdSpec> = want
        .into_iter()
        .filter(|w| matches!(w.mode.as_str(), "nat" | "gre") && matches!(w.role.as_str(), "entry" | "exit") && (!w.gre() || (1..=250).contains(&w.n)))
        .filter(|w| host_ok(w.peer.trim().trim_start_matches('[').trim_end_matches(']').rsplit_once(':').map(|x| x.0).unwrap_or(w.peer.trim())) || w.peer.parse::<Ipv4Addr>().is_ok())
        .map(|mut w| {
            if !w.target.trim().is_empty() && w.target.trim().parse::<Ipv4Addr>().is_err() {
                w.target.clear();
            }
            w
        })
        .collect();
    let run_now = {
        let mut g = guard();
        let changed = g.want != want;
        let stale = g.stamp.map(|t| t.elapsed() > Duration::from_secs(15)).unwrap_or(true);
        if changed {
            g.want = want;
        }
        changed || stale
    };
    if !run_now {
        return;
    }
    guard().stamp = Some(Instant::now());
    std::thread::spawn(|| {
        let _ = std::panic::catch_unwind(reconcile);
    });
}

/// status of every wanted direct tunnel, shaped like the engine's status
pub fn statuses() -> Vec<super::engine::Status> {
    let g = guard();
    let now = crate::util::now() as u64;
    g.want
        .iter()
        .map(|w| {
            let err = g.errors.get(&w.tid).cloned().unwrap_or_default();
            let rtt = g.rtt.get(&w.tid).cloned();
            // nat: the rules are the tunnel (the other server needs nothing); gre: the link must answer
            let alive = err.is_empty() && g.applied.as_ref().is_some_and(|a| a.contains(w)) && (!w.gre() || rtt.is_some());
            let error = if !err.is_empty() {
                err
            } else if !alive && w.gre() {
                "GRE link is up, waiting for the other server (GRE may be blocked between them)".into()
            } else {
                String::new()
            };
            super::engine::Status {
                id: w.tid.clone(),
                role: w.role.clone(),
                links: if alive { 1 } else { 0 },
                want: 1,
                rtt_ms: if alive { rtt.unwrap_or(0) } else { 0 },
                rx_bytes: 0,
                tx_bytes: 0,
                streams: 0,
                udp_flows: 0,
                error,
                since: if alive { g.since.get(&w.tid).cloned().unwrap_or(now) } else { 0 },
                transport: if w.gre() { "gre".into() } else { "nat".into() },
                listening: false,
                probe: None,
                quality: None,
                lanes: 0,
                bulk_flows: 0,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn joined(r: &[Rule]) -> Vec<String> {
        r.iter().map(|(t, a)| format!("{} {}", t, a.join(" "))).collect()
    }

    /// nat: the entry's ports go straight to the exit's address, the answers come back through the entry
    #[test]
    fn nat_forwards_the_ports_to_the_exit() {
        let w = FwdSpec { tid: "t1".into(), role: "entry".into(), mode: "nat".into(), peer: "203.0.113.7".into(), tcp: vec!["8443:443".into()], udp: vec!["4000".into()], ..Default::default() };
        let r = joined(&rules(&w, "203.0.113.7".parse().unwrap()));
        assert!(r.iter().any(|x| x.contains("KFWD-PRE -p tcp --dport 8443") && x.ends_with("--to-destination 203.0.113.7:443")));
        assert!(r.iter().any(|x| x.contains("KFWD-PRE -p udp --dport 4000") && x.ends_with("203.0.113.7:4000")));
        assert!(r.iter().any(|x| x.contains("KFWD-POST -p udp -d 203.0.113.7 --dport 4000 -j MASQUERADE")));
        // only packets for this server itself: traffic passing through it is never taken
        assert!(r.iter().filter(|x| x.contains("DNAT")).all(|x| x.contains("--dst-type LOCAL")));
        // the exit of a nat tunnel has nothing to do
        let e = FwdSpec { role: "exit".into(), ..w.clone() };
        assert!(rules(&e, "198.51.100.1".parse().unwrap()).is_empty());
    }

    /// gre: the ports go into the link to the exit's end of it; GRE only from the other server
    #[test]
    fn gre_goes_through_the_link() {
        let w = FwdSpec { tid: "t2".into(), role: "entry".into(), mode: "gre".into(), peer: "203.0.113.7".into(), n: 3, udp: vec!["4000".into()], ..Default::default() };
        let r = joined(&rules(&w, "203.0.113.7".parse().unwrap()));
        assert!(r.iter().any(|x| x.ends_with("--to-destination 10.89.3.2:4000")));
        assert!(r.iter().any(|x| x.contains("-p gre -s 203.0.113.7 -j ACCEPT")));
        assert!(r.iter().any(|x| x.contains("-o kfg3") && x.contains("SNAT --to-source 10.89.3.1")));
        assert!(r.iter().any(|x| x.contains("TCPMSS")));
        let e = FwdSpec { role: "exit".into(), ..w.clone() };
        let re = joined(&rules(&e, "198.51.100.1".parse().unwrap()));
        assert!(re.iter().any(|x| x.contains("-p gre -s 198.51.100.1")) && !re.iter().any(|x| x.contains("DNAT")));
    }

    /// values that are not addresses or ports never reach a command
    #[test]
    fn only_clean_values_reach_the_commands() {
        let bad = FwdSpec { tid: "x".into(), role: "entry".into(), mode: "nat".into(), peer: "1.2.3.4; reboot".into(), tcp: vec!["443; rm -rf /".into()], target: "1.2.3.4 -j ACCEPT".into(), ..Default::default() };
        set_desired(vec![bad.clone()]);
        assert!(guard().want.is_empty(), "a peer with a shell in it is refused");
        let w = FwdSpec { peer: "203.0.113.7".into(), ..bad };
        let r = joined(&rules(&FwdSpec { target: String::new(), ..w }, "203.0.113.7".parse().unwrap()));
        assert!(!r.iter().any(|x| x.contains("rm") || x.contains(';')));
        assert!(resolve("1.2.3.4; reboot").is_none() && resolve("203.0.113.7:443") == Some("203.0.113.7".parse().unwrap()));
    }
}

/// The real thing in network namespaces (scripts/kfwd_lab.sh): applies the tunnel of KFWD_LAB (json FwdSpec) in the
/// namespace it runs in, waits for the file KFWD_STOP, then removes it and checks nothing of it is left.
#[cfg(test)]
mod lab {
    use super::*;

    #[test]
    #[ignore]
    fn kfwd_lab() {
        let Ok(spec) = std::env::var("KFWD_LAB") else { return };
        let w: FwdSpec = serde_json::from_str(&spec).expect("KFWD_LAB json");
        let stop = std::env::var("KFWD_STOP").unwrap_or_else(|_| "/tmp/kfwd.stop".into());
        set_desired(vec![w.clone()]);
        let t0 = Instant::now();
        loop {
            std::thread::sleep(Duration::from_millis(300));
            let st = statuses();
            if std::path::Path::new(&stop).exists() || t0.elapsed() > Duration::from_secs(120) {
                eprintln!("kfwd lab {}: status {:?}", w.role, st.first().map(|s| (s.links, s.rtt_ms, s.error.clone())));
                break;
            }
        }
        guard().stamp = None;
        set_desired(vec![]);
        std::thread::sleep(Duration::from_secs(2));
        let (_, rules) = run("iptables-save", &[]);
        let (_, links) = run("ip", &s(&["-o", "link", "show"]));
        assert!(!rules.contains("KFWD"), "rules left behind:\n{}", rules);
        assert!(!links.contains("kfg"), "links left behind:\n{}", links);
        eprintln!("kfwd lab {}: clean after removal", w.role);
    }
}
