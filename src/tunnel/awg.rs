//! AmneziaWG tunnel between two servers (a layer-3 link, like WireGuard).
//!
//! The panel keeps one `AwgCfg` per tunnel (keys, obfuscation numbers, routing options) and hands
//! every side its own `AwgSpec`. The agent writes `/etc/amnezia/amneziawg/<iface>.conf` and brings
//! it up with `awg-quick` (kernel module or amneziawg-go). The obfuscation numbers are generated
//! once by the panel and sent to both sides, so they are always identical.
//!
//! Advanced: the AmneziaWG UDP can travel inside any Kanki transport (ws / wss / cdn / tcpmux /
//! quic / kcp). Then the engine carries the UDP and the interface only talks to 127.0.0.1.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

pub const CONF_DIR: &str = "/etc/amnezia/amneziawg";
const PREFIX: &str = "kawg";

/// Owner names of the kanki jobs that run AmneziaWG interfaces (also their single-instance lock
/// names, see `instance.rs`). A standalone `tunnel-run` uses "tunnel-run-<hash of its file>".
pub const OWNER_PANEL: &str = "panel";
pub const OWNER_AGENT: &str = "tunnel-agent";
/// first line of every interface file: which job wrote it
const OWNER_LINE: &str = "# owner: ";
/// An interface whose owner is not running is left alone this long before another job removes it
/// or takes it over. Covers a restart or an update of the owner (a few seconds) with a wide margin,
/// and still frees the UDP port of a job that is gone for good.
const ORPHAN_GRACE: Duration = Duration::from_secs(90);

static OWNER: OnceLock<String> = OnceLock::new();

/// Which job this process is (set once at start). Every interface file it writes carries this name,
/// and it only ever brings down or removes interfaces that are its own (or truly abandoned).
pub fn set_owner(name: &str) {
    let _ = OWNER.set(name.to_string());
}

fn owner() -> &'static str {
    OWNER.get().map(|s| s.as_str()).unwrap_or("kanki")
}

// ------------------------------------------------------------------ what the panel stores

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(default)]
pub struct AwgCfg {
    /// subnet number: the link uses 10.88.N.0/30 (entry .1, exit .2)
    pub n: u8,
    /// UDP port of the interface (plain: on the listening side; wrapped: loopback only)
    pub port: u16,
    pub entry_priv: String,
    pub entry_pub: String,
    pub exit_priv: String,
    pub exit_pub: String,
    pub psk: String,
    /// "classic" | "heavy" | "mimic" (needs awg-tools 1.5 or newer: adds I1 decoy packets)
    pub profile: String,
    pub params: BTreeMap<String, String>,
    pub mtu: u16,
    pub keepalive: u16,
    /// carry the AmneziaWG UDP inside the chosen Kanki transport
    pub wrap: bool,
    /// wrapped: the local UDP port on the entry that the engine listens on
    pub wrap_port: u16,
    /// wrapped: drop AmneziaWG packets that do not come from the machine itself (no active probing)
    pub lockdown: bool,
    /// exit: masquerade what comes out of the link
    pub nat_exit: bool,
    /// entry: destination networks sent through the link ("1.1.1.1/32", "8.8.0.0/16")
    pub routes: Vec<String>,
    /// entry: all traffic coming FROM these networks (for example the VPN users 10.8.0.0/24) leaves through the link
    pub src_routes: Vec<String>,
    /// entry: public ports sent into the link ("443" or "8443:443")
    pub fwd_tcp: Vec<String>,
    pub fwd_udp: Vec<String>,
    /// where forwarded ports go (empty = the exit's address inside the link)
    pub fwd_target: String,
}

impl Default for AwgCfg {
    fn default() -> Self {
        AwgCfg {
            n: 0,
            port: 0,
            entry_priv: String::new(),
            entry_pub: String::new(),
            exit_priv: String::new(),
            exit_pub: String::new(),
            psk: String::new(),
            profile: "classic".into(),
            params: BTreeMap::new(),
            mtu: 0,
            keepalive: 25,
            wrap: false,
            wrap_port: 0,
            lockdown: true,
            nat_exit: true,
            routes: vec![],
            src_routes: vec![],
            fwd_tcp: vec![],
            fwd_udp: vec![],
            fwd_target: String::new(),
        }
    }
}

impl AwgCfg {
    pub fn entry_ip(&self) -> String {
        format!("10.88.{}.1", self.n)
    }
    pub fn exit_ip(&self) -> String {
        format!("10.88.{}.2", self.n)
    }
    pub fn mtu_or_default(&self) -> u16 {
        if self.mtu >= 1000 && self.mtu <= 1500 {
            self.mtu
        } else if self.wrap {
            1280
        } else {
            1380
        }
    }
}

// ------------------------------------------------------------------ what an agent gets

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
#[serde(default)]
pub struct AwgSpec {
    /// id of the tunnel (the status is reported under it)
    pub tid: String,
    /// name of the interface, for example kawg1a2b3c4d
    pub iface: String,
    /// "entry" | "exit"
    pub role: String,
    pub private: String,
    pub peer_pub: String,
    pub psk: String,
    /// own address inside the link, "10.88.1.1/30"
    pub address: String,
    pub peer_ip: String,
    pub listen: u16,
    /// empty = wait for the other side
    pub endpoint: String,
    pub keepalive: u16,
    pub mtu: u16,
    pub params: BTreeMap<String, String>,
    pub lockdown: bool,
    pub nat_exit: bool,
    pub routes: Vec<String>,
    pub src_routes: Vec<String>,
    pub fwd_tcp: Vec<String>,
    pub fwd_udp: Vec<String>,
    pub fwd_target: String,
    /// UDP port to open in the firewall (0 = none)
    pub open_udp: u16,
    /// routing table used for the source rules
    pub table: u32,
}

pub fn iface_name(tid: &str) -> String {
    let s: String = tid.chars().filter(|c| c.is_ascii_alphanumeric()).take(8).collect::<String>().to_lowercase();
    format!("{}{}", PREFIX, s)
}

// ------------------------------------------------------------------ keys, base64, numbers

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn b64(data: &[u8]) -> String {
    let mut out = String::new();
    for ch in data.chunks(3) {
        let b = [ch[0], *ch.get(1).unwrap_or(&0), *ch.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(B64[((n >> 18) & 63) as usize] as char);
        out.push(B64[((n >> 12) & 63) as usize] as char);
        out.push(if ch.len() > 1 { B64[((n >> 6) & 63) as usize] as char } else { '=' });
        out.push(if ch.len() > 2 { B64[(n & 63) as usize] as char } else { '=' });
    }
    out
}

/// (private, public), both base64, like `wg genkey` / `wg pubkey`
pub fn gen_keypair() -> (String, String) {
    use rand::RngCore;
    let mut k = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut k);
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
    let p = x25519_dalek::x25519(k, x25519_dalek::X25519_BASEPOINT_BYTES);
    (b64(&k), b64(&p))
}

pub fn gen_psk() -> String {
    use rand::RngCore;
    let mut k = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut k);
    b64(&k)
}

fn rnd(lo: u32, hi: u32) -> u32 {
    use rand::Rng;
    rand::thread_rng().gen_range(lo..=hi)
}

fn hexs(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

/// Obfuscation numbers. Both ends must have exactly the same values.
/// classic = AmneziaWG 1.0 numbers; heavy = more junk packets and bigger paddings;
/// mimic = classic + I1 (a decoy packet that looks like a QUIC Initial before every handshake).
pub fn gen_params(profile: &str) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    let (jc, jmin, jspan) = match profile {
        "heavy" => (rnd(8, 12), rnd(60, 120), rnd(500, 900)),
        _ => (rnd(4, 8), rnd(40, 80), rnd(300, 700)),
    };
    let jmax = (jmin + jspan).min(1200);
    let (s1, mut s2) = match profile {
        "heavy" => (rnd(40, 150), rnd(40, 150)),
        _ => (rnd(15, 100), rnd(15, 100)),
    };
    let s1 = s1;
    // the two paddings must differ and S1 + 56 must not equal S2 (the packets would look alike)
    while s2 == s1 || s1 + 56 == s2 {
        s2 = rnd(15, 150);
    }
    // header types: four different numbers above 4 (1..4 are the plain WireGuard types)
    let mut h: Vec<u32> = vec![];
    while h.len() < 4 {
        let v = rnd(5, 2_000_000_000);
        if !h.contains(&v) {
            h.push(v);
        }
    }
    m.insert("Jc".into(), jc.to_string());
    m.insert("Jmin".into(), jmin.to_string());
    m.insert("Jmax".into(), jmax.to_string());
    m.insert("S1".into(), s1.to_string());
    m.insert("S2".into(), s2.to_string());
    for (i, v) in h.iter().enumerate() {
        m.insert(format!("H{}", i + 1), v.to_string());
    }
    if profile == "mimic" {
        use rand::RngCore;
        // QUIC long header (version 1) + random connection ids + a timestamp
        let mut cid = [0u8; 8];
        rand::rngs::OsRng.fill_bytes(&mut cid);
        m.insert("I1".into(), format!("<b 0xc00000000108{}00><r {}><t>", hexs(&cid), rnd(180, 400)));
    }
    m
}

// ------------------------------------------------------------------ config text

fn cidr_ok(s: &str) -> bool {
    let (a, b) = match s.split_once('/') {
        Some((a, b)) => (a, b.parse::<u8>().ok()),
        None => (s, Some(32)),
    };
    a.parse::<std::net::Ipv4Addr>().is_ok() && b.map(|x| x <= 32).unwrap_or(false)
}

/// "1.2.3.4" -> "1.2.3.4/32"; anything that is not an IPv4 network is dropped
pub fn clean_cidrs(list: &[String]) -> Vec<String> {
    let mut out = vec![];
    for it in list {
        for p in it.split(|c: char| c == ',' || c.is_whitespace()) {
            let p = p.trim();
            if p.is_empty() || !cidr_ok(p) {
                continue;
            }
            let v = if p.contains('/') { p.to_string() } else { format!("{}/32", p) };
            if !out.contains(&v) {
                out.push(v);
            }
        }
    }
    out
}

fn fwd_pairs(list: &[String]) -> Vec<(u16, u16)> {
    super::engine::parse_ports(list)
}

/// "10.88.3.1" -> "10.88.3.0/30"
fn net30(ip: &str) -> String {
    match ip.rsplit_once('.') {
        Some((a, _)) => format!("{}.0/30", a),
        None => format!("{}/30", ip),
    }
}

fn target_of(s: &AwgSpec) -> String {
    let t = s.fwd_target.trim();
    if t.is_empty() { s.peer_ip.clone() } else { t.to_string() }
}

/// the text of the .conf file (also what the panel offers for download)
pub fn render(s: &AwgSpec) -> String {
    let mut c = String::new();
    c.push_str("# written by kanki-panel: changes are overwritten\n[Interface]\n");
    c.push_str(&format!("PrivateKey = {}\nAddress = {}\nListenPort = {}\nMTU = {}\nTable = off\n", s.private, s.address, s.listen, s.mtu));
    for (k, v) in &s.params {
        c.push_str(&format!("{} = {}\n", k, v));
    }
    let mut up: Vec<String> = vec![];
    let mut down: Vec<String> = vec![];
    let mut both = |add: String, del: String| {
        up.push(add);
        down.push(del);
    };
    let ipt = |a: &str| format!("iptables {} || true", a);
    // let the traffic through the interface
    both(ipt("-I FORWARD -i %i -j ACCEPT"), ipt("-D FORWARD -i %i -j ACCEPT"));
    both(ipt("-I FORWARD -o %i -j ACCEPT"), ipt("-D FORWARD -o %i -j ACCEPT"));
    if s.lockdown {
        // wrapped: the interface is only for the machine itself; nobody can probe the port
        let r = format!("-p udp --dport {} ! -i lo -j DROP", s.listen);
        both(ipt(&format!("-I INPUT {}", r)), ipt(&format!("-D INPUT {}", r)));
    }
    if s.role == "exit" {
        if s.nat_exit {
            let r = format!("-t nat -A POSTROUTING -s {} ! -o %i -j MASQUERADE", net30(&s.peer_ip));
            both(ipt(&r), ipt(&r.replace("-A POSTROUTING", "-D POSTROUTING")));
        }
    } else {
        let any = !s.routes.is_empty() || !s.src_routes.is_empty() || !s.fwd_tcp.is_empty() || !s.fwd_udp.is_empty();
        if any {
            // the exit only knows the address of this end; everything else is hidden behind it
            let r = "-t nat -A POSTROUTING -o %i -j MASQUERADE".to_string();
            both(ipt(&r), ipt(&r.replace("-A POSTROUTING", "-D POSTROUTING")));
        }
        for r in &s.routes {
            both(format!("ip route replace {} dev %i || true", r), format!("ip route del {} dev %i || true", r));
        }
        if !s.src_routes.is_empty() {
            both(format!("ip route replace default dev %i table {} || true", s.table), format!("ip route flush table {} || true", s.table));
            for r in &s.src_routes {
                both(format!("ip rule add from {} table {} priority 1{} || true", r, s.table, s.table % 1000), format!("ip rule del from {} table {} priority 1{} || true", r, s.table, s.table % 1000));
            }
        }
        let tgt = target_of(s);
        if (!s.fwd_tcp.is_empty() || !s.fwd_udp.is_empty()) && tgt != s.peer_ip {
            both(format!("ip route replace {}/32 dev %i || true", tgt), format!("ip route del {}/32 dev %i || true", tgt));
        }
        for (proto, list) in [("tcp", &s.fwd_tcp), ("udp", &s.fwd_udp)] {
            for (a, b) in fwd_pairs(list) {
                let r = format!("-t nat -A PREROUTING -p {} --dport {} -j DNAT --to-destination {}:{}", proto, a, tgt, b);
                both(ipt(&r), ipt(&r.replace("-A PREROUTING", "-D PREROUTING")));
            }
        }
    }
    c.push_str("PostUp = sysctl -w net.ipv4.ip_forward=1 >/dev/null || true\n");
    for l in &up {
        c.push_str(&format!("PostUp = {}\n", l));
    }
    for l in down.iter().rev() {
        c.push_str(&format!("PostDown = {}\n", l));
    }
    c.push_str(&format!("\n[Peer]\nPublicKey = {}\nPresharedKey = {}\n", s.peer_pub, s.psk));
    let mut allowed = vec![format!("{}/32", s.peer_ip)];
    if s.role == "entry" {
        allowed.extend(s.routes.iter().cloned());
        if !s.src_routes.is_empty() {
            allowed.push("0.0.0.0/0".into());
        }
        let tgt = target_of(s);
        if tgt != s.peer_ip && !s.fwd_tcp.iter().chain(s.fwd_udp.iter()).all(|x| x.trim().is_empty()) {
            allowed.push(format!("{}/32", tgt));
        }
    } else {
        // the exit accepts whatever the entry sends (it is all behind the entry's one address)
        allowed = vec![format!("{}/32", s.peer_ip)];
    }
    allowed.dedup();
    c.push_str(&format!("AllowedIPs = {}\n", allowed.join(", ")));
    if !s.endpoint.is_empty() {
        c.push_str(&format!("Endpoint = {}\n", s.endpoint));
    }
    if s.keepalive > 0 {
        c.push_str(&format!("PersistentKeepalive = {}\n", s.keepalive));
    }
    c
}

// ------------------------------------------------------------------ who owns an interface

/// What is written to disk: the owner line, then the config.
fn file_text(owner: &str, s: &AwgSpec) -> String {
    format!("{}{}\n{}", OWNER_LINE, owner, render(s))
}

/// (owner, config without the owner line). Files written before v2.9.8 have no owner line.
fn split_owner(text: &str) -> (Option<String>, &str) {
    match text.strip_prefix(OWNER_LINE) {
        Some(rest) => {
            let (first, body) = rest.split_once('\n').unwrap_or((rest, ""));
            let o = first.trim();
            (if o.is_empty() { None } else { Some(o.to_string()) }, body)
        }
        None => (None, text),
    }
}

/// Whether this process may touch an interface that has a file on disk.
#[derive(Debug, Clone, PartialEq)]
enum Claim {
    /// ours, or abandoned long enough: manage it (write, bring up, bring down, remove)
    Ours,
    /// another kanki job on this machine runs it right now: never touch it
    Theirs(String),
    /// its owner is not running: (owner, seconds left) before it becomes ours
    Orphan(String, u64),
}

/// The ownership rule. Before v2.9.8 every job removed every `kawg*` interface it did not want
/// itself, so two jobs on one server (two panels, or the panel and a tunnel agent) tore down each
/// other's interfaces and brought their own back up, over and over.
/// * a file with our name is ours;
/// * a file with no owner (written before v2.9.8) is ours at once when we want it (we take it
///   over without restarting it); otherwise it is treated as abandoned;
/// * a file of another job is left alone while that job runs (or while we cannot tell);
/// * a file whose owner is not running becomes ours after [`ORPHAN_GRACE`], so the UDP port of a
///   job that is gone for good is still freed.
fn claim(file_owner: Option<&str>, me: &str, wanted: bool, alive: Option<bool>, orphan_for: Duration) -> Claim {
    match file_owner {
        Some(o) if o == me => Claim::Ours,
        None if wanted => Claim::Ours,
        Some(o) if alive != Some(false) => Claim::Theirs(o.to_string()),
        _ if orphan_for >= ORPHAN_GRACE => Claim::Ours,
        _ => Claim::Orphan(
            file_owner.unwrap_or("an older kanki-panel").to_string(),
            (ORPHAN_GRACE - orphan_for).as_secs().max(1),
        ),
    }
}

// ------------------------------------------------------------------ running it

#[derive(Default)]
struct Shared {
    want: Vec<AwgSpec>,
    stamp: Option<Instant>,
    errors: HashMap<String, String>,
    rtt: HashMap<String, u64>,
    installed: Option<Result<(), String>>,
    since: HashMap<String, u64>,
    /// interface -> when it was first seen without a running owner
    orphan_since: HashMap<String, Instant>,
    /// wanted interfaces this process is not running (another job has them): no stats for them
    not_ours: HashSet<String>,
}

fn shared() -> &'static Mutex<Shared> {
    static S: OnceLock<Mutex<Shared>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(Shared::default()))
}

fn busy() -> &'static AtomicBool {
    static B: AtomicBool = AtomicBool::new(false);
    &B
}

/// Locks the shared state, recovering the data even if a previous panic poisoned the lock. A
/// wedged lock must never stop reconcile from running again: if it did, a removed AmneziaWG
/// interface would never be brought down and would keep its UDP port (a kernel interface holds the
/// port across restarts), which is exactly the "the port stays busy after I delete the tunnel" bug.
fn guard() -> std::sync::MutexGuard<'static, Shared> {
    shared().lock().unwrap_or_else(|e| e.into_inner())
}

/// Clears the `busy` flag whatever happens to the worker thread (even a panic inside reconcile),
/// so the next `set_desired` can always start a fresh reconcile instead of being locked out forever.
struct BusyGuard;
impl Drop for BusyGuard {
    fn drop(&mut self) {
        busy().store(false, Ordering::SeqCst);
    }
}

fn sh(cmd: &str) -> (bool, String) {
    match Command::new("sh").arg("-c").arg(cmd).stdin(Stdio::null()).output() {
        Ok(o) => {
            let mut t = String::from_utf8_lossy(&o.stdout).to_string();
            t.push_str(&String::from_utf8_lossy(&o.stderr));
            (o.status.success(), t.trim().to_string())
        }
        Err(e) => (false, e.to_string()),
    }
}

fn have(tool: &str) -> bool {
    sh(&format!("command -v {} >/dev/null 2>&1", tool)).0
}

/// installs AmneziaWG (and iptables) on Debian / Ubuntu the first time it is needed
fn ensure_tools() -> Result<(), String> {
    if have("awg-quick") && have("awg") && have("iptables") && have("ip") {
        return Ok(());
    }
    if !have("apt-get") {
        return Err("awg-quick is not installed (only Debian / Ubuntu are installed automatically). Install amneziawg-tools and amneziawg-go / the kernel module".into());
    }
    eprintln!("awg tunnel: installing AmneziaWG ...");
    let script = "export DEBIAN_FRONTEND=noninteractive; \
        (command -v add-apt-repository >/dev/null 2>&1 || apt-get install -y -qq software-properties-common >/dev/null 2>&1); \
        add-apt-repository -y ppa:amnezia/ppa >/dev/null 2>&1; apt-get update -qq >/dev/null 2>&1; \
        apt-get install -y -qq iproute2 iptables >/dev/null 2>&1; \
        apt-get install -y -qq amneziawg amneziawg-tools >/dev/null 2>&1 || apt-get install -y -qq amneziawg-dkms amneziawg-tools >/dev/null 2>&1 || apt-get install -y -qq amneziawg-tools >/dev/null 2>&1";
    let _ = sh(script);
    if have("awg-quick") && have("awg") {
        Ok(())
    } else {
        Err("could not install AmneziaWG automatically: run apt install amneziawg amneziawg-tools on this server".into())
    }
}

fn up_now(iface: &str) -> bool {
    sh(&format!("awg show {} >/dev/null 2>&1", iface)).0
}

fn conf_path(iface: &str) -> String {
    format!("{}/{}.conf", CONF_DIR, iface)
}

fn reconcile() {
    let want = guard().want.clone();
    let tools = if want.is_empty() {
        // no AmneziaWG interface is wanted: do not touch the system (before, every tunnel server
        // added the Amnezia PPA and installed its packages at start even if it never ran an AmneziaWG link)
        Ok(())
    } else {
        let cached = guard().installed.clone();
        match cached {
            Some(Ok(())) => Ok(()),
            _ => {
                let r = ensure_tools();
                guard().installed = Some(r.clone());
                r
            }
        }
    };
    let me = owner().to_string();
    let wanted = |i: &str| want.iter().any(|w| w.iface == i);

    // every kawg interface file on this machine and who wrote it
    let mut files: Vec<(String, Option<String>)> = vec![];
    if let Ok(rd) = std::fs::read_dir(CONF_DIR) {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if let Some(i) = name.strip_suffix(".conf") {
                if i.starts_with(PREFIX) {
                    let text = std::fs::read_to_string(e.path()).unwrap_or_default();
                    files.push((i.to_string(), split_owner(&text).0));
                }
            }
        }
    }

    // which of them this process may touch (see `claim`)
    let now = Instant::now();
    let mut claims: HashMap<String, Claim> = HashMap::new();
    for (iface, fo) in &files {
        let alive = match fo.as_deref() {
            Some(o) if o != me => crate::instance::alive(o),
            _ => Some(false),
        };
        let first = guard().orphan_since.get(iface).cloned();
        let c = claim(fo.as_deref(), &me, wanted(iface), alive, first.map(|t| now - t).unwrap_or(Duration::ZERO));
        match &c {
            Claim::Orphan(o, left) => {
                if first.is_none() {
                    eprintln!("awg tunnel {}: its owner ({}) is not running; it is removed or taken over in {} s unless that comes back", iface, o, left);
                    guard().orphan_since.insert(iface.clone(), now);
                }
            }
            _ => {
                guard().orphan_since.remove(iface);
            }
        }
        claims.insert(iface.clone(), c);
    }
    guard().orphan_since.retain(|k, _| files.iter().any(|(i, _)| i == k));

    // interfaces that are not wanted any more: only our own ones (or abandoned ones) go
    for (iface, fo) in &files {
        if wanted(iface) || claims.get(iface) != Some(&Claim::Ours) {
            continue;
        }
        match fo.as_deref() {
            Some(o) if o == me => eprintln!("awg tunnel {}: removing", iface),
            Some(o) => eprintln!("awg tunnel {}: removing (its owner {} stopped long ago)", iface, o),
            None => eprintln!("awg tunnel {}: removing (left over from an older version)", iface),
        }
        let _ = sh(&format!("awg-quick down {} 2>&1", iface));
        let _ = std::fs::remove_file(conf_path(iface));
    }

    let mut not_ours: HashSet<String> = HashSet::new();
    for w in &want {
        let mut err = String::new();
        match (&tools, claims.get(&w.iface)) {
            (_, Some(Claim::Theirs(o))) => {
                // another kanki job on this server runs this very interface: leave it alone, or the
                // two would take it from each other every few seconds
                not_ours.insert(w.iface.clone());
                err = format!(
                    "another kanki job on this server ({}) already runs {}; it is left alone. A tunnel cannot have both \
                     ends on one server: if this machine is also added as a tunnel server, remove that entry",
                    o, w.iface
                );
            }
            (_, Some(Claim::Orphan(o, left))) => {
                not_ours.insert(w.iface.clone());
                err = format!("{} was run by {}, which is not running now: taking it over in {} s", w.iface, o, left);
            }
            (Err(e), _) => err = e.clone(),
            (Ok(()), _) => {
                let text = file_text(&me, w);
                let path = conf_path(&w.iface);
                let old = std::fs::read_to_string(&path).ok();
                let same = old.as_deref() == Some(text.as_str());
                // same config, only the owner line differs (a file from before v2.9.8): no restart needed
                let same_conf = old.as_deref().map(|t| split_owner(t).1 == render(w)).unwrap_or(false);
                let up = up_now(&w.iface);
                if up && !same && same_conf {
                    if let Err(e) = std::fs::write(&path, &text) {
                        err = format!("cannot write {}: {}", path, e);
                    } else {
                        let _ = sh(&format!("chmod 600 {}", path));
                    }
                } else if !same || !up {
                    let _ = std::fs::create_dir_all(CONF_DIR);
                    if up {
                        let _ = sh(&format!("awg-quick down {} 2>&1", w.iface));
                    }
                    if let Err(e) = std::fs::write(&path, &text) {
                        err = format!("cannot write {}: {}", path, e);
                    } else {
                        let _ = sh(&format!("chmod 600 {}", path));
                        let (ok, out) = sh(&format!("awg-quick up {} 2>&1", w.iface));
                        if !ok {
                            let line = out.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or("awg-quick failed").to_string();
                            err = format!("awg-quick up: {}", line);
                            let _ = sh(&format!("awg-quick down {} 2>&1", w.iface));
                        } else {
                            eprintln!("awg tunnel {}: up", w.iface);
                            guard().since.insert(w.iface.clone(), crate::util::now() as u64);
                        }
                    }
                }
                if err.is_empty() {
                    // delay to the other end of the link (only meaningful once it answers)
                    let (ok, out) = sh(&format!("ping -c 1 -W 1 -I {} {} 2>/dev/null | sed -n 's/.*time=\\([0-9.]*\\) ms.*/\\1/p'", w.iface, w.peer_ip));
                    if ok {
                        if let Ok(v) = out.trim().parse::<f64>() {
                            guard().rtt.insert(w.iface.clone(), v.round() as u64);
                        }
                    }
                }
            }
        }
        guard().errors.insert(w.iface.clone(), err);
    }
    guard().not_ours = not_ours;
}

/// Called every few seconds with the interfaces this server should have. Work runs on a background
/// thread (the first run may install packages), so the agent keeps reporting meanwhile.
pub fn set_desired(want: Vec<AwgSpec>) {
    let run = {
        let mut s = guard();
        let changed = s.want != want;
        let stale = s.stamp.map(|t| t.elapsed() > Duration::from_secs(20)).unwrap_or(true);
        if changed {
            s.want = want;
        }
        changed || stale
    };
    if !run {
        return;
    }
    if busy().swap(true, Ordering::SeqCst) {
        return;
    }
    std::thread::spawn(|| {
        // the flag is cleared on the way out no matter what (see BusyGuard)
        let _reset = BusyGuard;
        loop {
            let before = guard().want.clone();
            // a panic inside reconcile (a failed command, a bad config) must not kill the worker and
            // leave `busy` stuck: catch it, record the time, and carry on with the next round
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(reconcile));
            guard().stamp = Some(Instant::now());
            if r.is_err() {
                // a reconcile that panicked will keep panicking on the same input: stop looping and
                // wait for the next set_desired rather than spin
                break;
            }
            if guard().want == before {
                break;
            }
        }
    });
}

/// status of every wanted interface, shaped like the engine's status so the panel treats it alike
pub fn statuses() -> Vec<super::engine::Status> {
    let (want, errors, rtt, since, not_ours) = {
        let s = guard();
        (s.want.clone(), s.errors.clone(), s.rtt.clone(), s.since.clone(), s.not_ours.clone())
    };
    let now = crate::util::now();
    let mut out = vec![];
    for w in want {
        // an interface another job runs: its counters are not this tunnel's, so report it as down
        // with the reason instead of borrowing that job's handshake
        let dump = if not_ours.contains(&w.iface) { String::new() } else { sh(&format!("awg show {} dump 2>/dev/null", w.iface)).1 };
        let mut hs = 0i64;
        let (mut rx, mut tx) = (0u64, 0u64);
        for line in dump.lines().skip(1) {
            let f: Vec<&str> = line.split('\t').collect();
            if f.len() >= 7 {
                hs = f[4].parse().unwrap_or(0);
                rx = f[5].parse().unwrap_or(0);
                tx = f[6].parse().unwrap_or(0);
            }
        }
        let alive = hs > 0 && now - hs < 180;
        let mut e = errors.get(&w.iface).cloned().unwrap_or_default();
        if e.is_empty() && !alive && !dump.is_empty() {
            e = "interface is up, waiting for the other side (handshake)".into();
        }
        out.push(super::engine::Status {
            id: w.tid.clone(),
            role: w.role.clone(),
            links: if alive { 1 } else { 0 },
            want: 1,
            rtt_ms: if alive { rtt.get(&w.iface).cloned().unwrap_or(0) } else { 0 },
            rx_bytes: rx,
            tx_bytes: tx,
            streams: 0,
            udp_flows: 0,
            error: e,
            since: if alive { since.get(&w.iface).cloned().unwrap_or(0) } else { 0 },
            transport: "awg".into(),
            listening: w.endpoint.is_empty(),
            probe: None,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The core of the port-leak fix: a panic that poisons the shared lock must not wedge the
    /// AmneziaWG worker. `guard()` has to keep handing back the data so reconcile can run again and
    /// bring down removed interfaces (otherwise their UDP ports stay held forever).
    #[test]
    fn a_poisoned_lock_does_not_wedge_the_worker() {
        // poison the lock on purpose, the way a real panic inside a held guard would
        let _ = std::panic::catch_unwind(|| {
            let _g = shared().lock().unwrap();
            panic!("boom while holding the lock");
        });
        assert!(shared().lock().is_err(), "the lock must now be poisoned for the test to mean anything");

        // guard() must still work (recover the data), not panic
        let before = guard().want.len();
        guard().stamp = Some(Instant::now());
        assert_eq!(guard().want.len(), before, "guard() recovered the data after poisoning");
    }

    fn spec() -> AwgSpec {
        AwgSpec {
            tid: "t1".into(),
            iface: "kawgt1".into(),
            role: "exit".into(),
            address: "10.88.1.2/30".into(),
            peer_ip: "10.88.1.1".into(),
            listen: 51900,
            mtu: 1380,
            ..Default::default()
        }
    }

    /// The bug of v2.9.7: two jobs on one server (PIDs 499002 and 499035 in the log) each removed the
    /// other's interface because it was not in their own list. Now a file of another running job is
    /// never ours, whatever we want.
    #[test]
    fn another_running_job_keeps_its_interface() {
        let any = Duration::from_secs(3600);
        assert_eq!(claim(Some("tunnel-agent"), "panel", false, Some(true), any), Claim::Theirs("tunnel-agent".into()), "not wanted by us: not removed");
        assert_eq!(claim(Some("tunnel-agent"), "panel", true, Some(true), any), Claim::Theirs("tunnel-agent".into()), "wanted by both: not taken over");
        assert_eq!(claim(Some("panel"), "tunnel-agent", false, Some(true), any), Claim::Theirs("panel".into()), "the same the other way round");
        // cannot tell whether it runs: leave it alone too
        assert_eq!(claim(Some("tunnel-agent"), "panel", false, None, any), Claim::Theirs("tunnel-agent".into()));
    }

    #[test]
    fn own_interfaces_are_managed_as_before() {
        assert_eq!(claim(Some("panel"), "panel", true, Some(false), Duration::ZERO), Claim::Ours);
        assert_eq!(claim(Some("panel"), "panel", false, Some(false), Duration::ZERO), Claim::Ours, "a tunnel we deleted goes at once");
        // a file from before v2.9.8 that we want is taken over at once (and not restarted)
        assert_eq!(claim(None, "panel", true, Some(false), Duration::ZERO), Claim::Ours);
    }

    /// The port-leak fix of v2.9.3 must still hold: an interface of a job that is gone for good is
    /// freed, just not during the few seconds that job needs to restart.
    #[test]
    fn an_abandoned_interface_is_freed_after_the_grace_period() {
        let c = claim(Some("tunnel-agent"), "panel", false, Some(false), Duration::ZERO);
        assert!(matches!(c, Claim::Orphan(ref o, s) if o == "tunnel-agent" && s == ORPHAN_GRACE.as_secs()), "{:?}", c);
        assert!(matches!(claim(Some("tunnel-agent"), "panel", false, Some(false), Duration::from_secs(10)), Claim::Orphan(_, 80)), "a restart is waited for");
        assert_eq!(claim(Some("tunnel-agent"), "panel", false, Some(false), ORPHAN_GRACE), Claim::Ours, "then it is removed");
        assert_eq!(claim(Some("tunnel-agent"), "panel", true, Some(false), ORPHAN_GRACE), Claim::Ours, "or taken over when we want it");
        // a leftover of an older version nobody wants
        assert!(matches!(claim(None, "panel", false, Some(false), Duration::ZERO), Claim::Orphan(_, _)));
        assert_eq!(claim(None, "panel", false, Some(false), ORPHAN_GRACE), Claim::Ours);
    }

    #[test]
    fn the_owner_line_round_trips_and_does_not_change_the_config() {
        let s = spec();
        let text = file_text("tunnel-agent", &s);
        assert!(text.starts_with("# owner: tunnel-agent\n"));
        let (o, body) = split_owner(&text);
        assert_eq!(o.as_deref(), Some("tunnel-agent"));
        assert_eq!(body, render(&s), "the config itself is exactly what the panel offers for download");
        // a file written before v2.9.8
        let old = render(&s);
        let (o, body) = split_owner(&old);
        assert_eq!(o, None);
        assert_eq!(body, old);
        // the owner line is a comment, so awg-quick ignores it
        assert!(text.lines().next().unwrap().starts_with('#'));
    }

    /// The busy flag must be released even if the worker thread unwinds, so the next set_desired is
    /// never locked out.
    #[test]
    fn busy_guard_always_clears_the_flag() {
        busy().store(false, Ordering::SeqCst);
        let _ = std::panic::catch_unwind(|| {
            let _reset = BusyGuard;
            busy().store(true, Ordering::SeqCst);
            panic!("worker blew up");
        });
        assert!(!busy().load(Ordering::SeqCst), "busy must be false again after a panic in the worker");
    }
}
