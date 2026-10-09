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
use std::collections::{BTreeMap, HashMap};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

pub const CONF_DIR: &str = "/etc/amnezia/amneziawg";
const PREFIX: &str = "kawg";

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

// ------------------------------------------------------------------ running it

#[derive(Default)]
struct Shared {
    want: Vec<AwgSpec>,
    stamp: Option<Instant>,
    errors: HashMap<String, String>,
    rtt: HashMap<String, u64>,
    installed: Option<Result<(), String>>,
    since: HashMap<String, u64>,
}

fn shared() -> &'static Mutex<Shared> {
    static S: OnceLock<Mutex<Shared>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(Shared::default()))
}

fn busy() -> &'static AtomicBool {
    static B: AtomicBool = AtomicBool::new(false);
    &B
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
    let want = shared().lock().unwrap().want.clone();
    let tools = if want.is_empty() {
        // no AmneziaWG interface is wanted: do not touch the system (before, every tunnel server
        // added the Amnezia PPA and installed its packages at start even if it never ran an AmneziaWG link)
        Ok(())
    } else {
        let cached = shared().lock().unwrap().installed.clone();
        match cached {
            Some(Ok(())) => Ok(()),
            _ => {
                let r = ensure_tools();
                shared().lock().unwrap().installed = Some(r.clone());
                r
            }
        }
    };
    // interfaces that are not wanted any more
    if let Ok(rd) = std::fs::read_dir(CONF_DIR) {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if let Some(i) = name.strip_suffix(".conf") {
                if i.starts_with(PREFIX) && !want.iter().any(|w| w.iface == i) {
                    eprintln!("awg tunnel {}: removing", i);
                    let _ = sh(&format!("awg-quick down {} 2>&1", i));
                    let _ = std::fs::remove_file(e.path());
                }
            }
        }
    }
    for w in &want {
        let mut err = String::new();
        match &tools {
            Err(e) => err = e.clone(),
            Ok(()) => {
                let text = render(w);
                let path = conf_path(&w.iface);
                let same = std::fs::read_to_string(&path).map(|t| t == text).unwrap_or(false);
                let up = up_now(&w.iface);
                if !same || !up {
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
                            shared().lock().unwrap().since.insert(w.iface.clone(), crate::util::now() as u64);
                        }
                    }
                }
                if err.is_empty() {
                    // delay to the other end of the link (only meaningful once it answers)
                    let (ok, out) = sh(&format!("ping -c 1 -W 1 -I {} {} 2>/dev/null | sed -n 's/.*time=\\([0-9.]*\\) ms.*/\\1/p'", w.iface, w.peer_ip));
                    if ok {
                        if let Ok(v) = out.trim().parse::<f64>() {
                            shared().lock().unwrap().rtt.insert(w.iface.clone(), v.round() as u64);
                        }
                    }
                }
            }
        }
        shared().lock().unwrap().errors.insert(w.iface.clone(), err);
    }
}

/// Called every few seconds with the interfaces this server should have. Work runs on a background
/// thread (the first run may install packages), so the agent keeps reporting meanwhile.
pub fn set_desired(want: Vec<AwgSpec>) {
    let run = {
        let mut s = shared().lock().unwrap();
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
        loop {
            let before = shared().lock().unwrap().want.clone();
            reconcile();
            shared().lock().unwrap().stamp = Some(Instant::now());
            if shared().lock().unwrap().want == before {
                break;
            }
        }
        busy().store(false, Ordering::SeqCst);
    });
}

/// status of every wanted interface, shaped like the engine's status so the panel treats it alike
pub fn statuses() -> Vec<super::engine::Status> {
    let (want, errors, rtt, since) = {
        let s = shared().lock().unwrap();
        (s.want.clone(), s.errors.clone(), s.rtt.clone(), s.since.clone())
    };
    let now = crate::util::now();
    let mut out = vec![];
    for w in want {
        let (_, dump) = sh(&format!("awg show {} dump 2>/dev/null", w.iface));
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
