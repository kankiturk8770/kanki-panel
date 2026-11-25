//! KANKI-UP: the official udp2raw (wangyu-/udp2raw, release 20230206.0) between two servers.
//!
//! udp2raw takes UDP on one side and sends it to the other side inside raw packets that look like TCP
//! (FakeTCP), UDP or ICMP, encrypted and authenticated with a shared key. Nothing waits for a lost packet
//! (no retransmission): a line that drops or throttles UDP carries the game as it is.
//!
//! One udp2raw pair per forwarded UDP port: the entry (client, `-c`) listens on the users' UDP port and
//! sends to the exit's raw port `port + i`; the exit (server, `-s`) gives what arrives to the target
//! (`127.0.0.1:<port>` of the core, or the target address). Each one runs under its own systemd unit
//! `kanki-up-<tunnel>-<i>.service` with its options in a file only root reads (the key never shows in `ps`).
//!
//! The binary is the official one, carried inside kanki-panel (gzip) and checked against the SHA-256 of
//! the release file before it is written; nothing is downloaded on the servers.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Read;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// `udp2raw_amd64` of release 20230206.0 (git e5ecd33), gzip -9
static BIN_GZ: &[u8] = include_bytes!("../../../assets/bin/udp2raw_amd64.gz");
/// SHA-256 of that file as published on GitHub (udp2raw_binaries.tar.gz of 20230206.0)
pub const BIN_SHA256: &str = "c81c7699194188172f37f747cdeba9fb54214bc4b3ba2d85cfdfccd5f7f70c3c";
pub const BIN: &str = "/usr/local/lib/kanki/udp2raw";
pub const CONF_DIR: &str = "/etc/kanki/kup";
const UNIT_DIR: &str = "/etc/systemd/system";
const PREFIX: &str = "kanki-up-";
/// UDP ports one tunnel carries (one udp2raw pair each)
pub const MAX_PORTS: usize = 32;

pub const RAW_MODES: &[&str] = &["faketcp", "easy-faketcp", "udp", "icmp"];
pub const CIPHERS: &[&str] = &["aes128cbc", "aes128cfb", "xor", "none"];
pub const AUTHS: &[&str] = &["md5", "hmac_sha1", "crc32", "simple", "none"];

// ------------------------------------------------------------------ what the panel stores

/// The options of udp2raw that must be the same on both sides, plus the tuning ones. The defaults are
/// udp2raw's own, except `fix_gro` (on: servers with GRO merge packets and udp2raw drops them).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(default)]
pub struct KupCfg {
    /// --raw-mode: faketcp | easy-faketcp | udp | icmp
    pub raw_mode: String,
    /// -k: the shared key (made by the panel)
    pub key: String,
    /// --cipher-mode
    pub cipher: String,
    /// --auth-mode
    pub auth: String,
    /// --seq-mode (faketcp): 0 static … 3 an almost real seq/ack (default), 4 like 3 without window scale
    pub seq_mode: u8,
    /// --fix-gro
    pub fix_gro: bool,
    /// false = --disable-anti-replay
    pub anti_replay: bool,
    /// --hb-len: heartbeat length (0 = udp2raw's own)
    pub hb_len: u16,
    /// --mtu-warn
    pub mtu_warn: u16,
    /// --sock-buf in KB (10-10240)
    pub sock_buf: u16,
    /// --force-sock-buf
    pub force_sock_buf: bool,
    /// --lower-level auto: send at layer 2 (past the local firewall)
    pub lower_level: bool,
    /// (3.63) the exit's raw port of the small measuring pair (0 = none; ICMP mode never has one)
    pub probe_port: u16,
}

impl Default for KupCfg {
    fn default() -> Self {
        KupCfg {
            raw_mode: "faketcp".into(),
            key: String::new(),
            cipher: "aes128cbc".into(),
            auth: "md5".into(),
            seq_mode: 3,
            fix_gro: true,
            anti_replay: true,
            hb_len: 0,
            mtu_warn: 1375,
            sock_buf: 1024,
            force_sock_buf: false,
            lower_level: false,
            probe_port: 0,
        }
    }
}

impl KupCfg {
    /// Only values udp2raw knows reach its options file
    pub fn check(&self) -> Result<(), String> {
        if !RAW_MODES.contains(&self.raw_mode.as_str()) {
            return Err("the raw mode is faketcp, easy-faketcp, udp or icmp".into());
        }
        if !CIPHERS.contains(&self.cipher.as_str()) {
            return Err("the cipher is aes128cbc, aes128cfb, xor or none".into());
        }
        if !AUTHS.contains(&self.auth.as_str()) {
            return Err("the authentication is md5, hmac_sha1, crc32, simple or none".into());
        }
        if self.seq_mode > 4 {
            return Err("the seq mode is 0 to 4".into());
        }
        if self.hb_len > 1500 {
            return Err("the heartbeat length is 0 to 1500".into());
        }
        if !(576..=1500).contains(&self.mtu_warn) {
            return Err("the MTU warning is 576 to 1500".into());
        }
        if !(10..=10240).contains(&self.sock_buf) {
            return Err("the socket buffer is 10 to 10240 KB".into());
        }
        if !key_ok(&self.key) {
            return Err("the key is 16 to 64 letters and digits".into());
        }
        Ok(())
    }
    /// faketcp and easy-faketcp are TCP on the wire, udp is UDP, icmp has no port
    pub fn on_tcp(&self) -> bool {
        self.raw_mode.ends_with("faketcp")
    }
    pub fn on_udp(&self) -> bool {
        self.raw_mode == "udp"
    }
    /// easy-faketcp: a real TCP connection of the kernel (the exit's port is opened in the firewall)
    pub fn easy(&self) -> bool {
        self.raw_mode == "easy-faketcp"
    }
}

pub fn key_ok(k: &str) -> bool {
    (16..=64).contains(&k.len()) && k.chars().all(|c| c.is_ascii_alphanumeric())
}

// ------------------------------------------------------------------ what an agent gets

/// One udp2raw of a tunnel on this server
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
#[serde(default)]
pub struct KupSpec {
    pub tid: String,
    pub name: String,
    /// "entry" (udp2raw -c) | "exit" (udp2raw -s)
    pub role: String,
    /// the place of this port in the tunnel (0 …)
    pub idx: u16,
    /// entry: the users' UDP port; exit: the raw port
    pub listen: u16,
    /// entry: the exit's address (IPv4 or a name, resolved here) and raw port; exit: the target and port
    pub host: String,
    pub port: u16,
    pub cfg: KupCfg,
    /// (3.63) the measuring pair: the entry listens on 127.0.0.1 (a port it picks), the exit hands to this
    /// agent's echo; nothing of the users passes through it
    pub probe: bool,
}

impl KupSpec {
    pub fn unit(&self) -> String {
        if self.probe {
            format!("{}{}-p", PREFIX, short(&self.tid))
        } else {
            format!("{}{}-{}", PREFIX, short(&self.tid), self.idx)
        }
    }
}

fn short(tid: &str) -> String {
    tid.chars().filter(|c| c.is_ascii_alphanumeric()).take(16).collect::<String>().to_lowercase()
}

fn host_ok(h: &str) -> bool {
    !h.is_empty() && h.len() <= 253 && h.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
}

/// The options file (`--conf-file`): one option per line, values checked before (letters, digits, dots)
pub fn conf_text(s: &KupSpec, remote_ip: &str) -> String {
    let c = &s.cfg;
    let mut l: Vec<String> = vec![];
    l.push(if s.role == "exit" { "-s".into() } else { "-c".into() });
    // the measuring pair's entry is only for this machine
    l.push(format!("-l {}:{}", if s.probe && s.role == "entry" { "127.0.0.1" } else { "0.0.0.0" }, s.listen));
    l.push(format!("-r {}:{}", remote_ip, s.port));
    l.push(format!("-k {}", c.key));
    l.push(format!("--raw-mode {}", c.raw_mode));
    l.push(format!("--cipher-mode {}", c.cipher));
    l.push(format!("--auth-mode {}", c.auth));
    // the rule that keeps the kernel from answering the raw packets (RST / port unreachable): added,
    // watched and taken away again by udp2raw itself. easy-faketcp uses a real TCP connection of the
    // kernel instead, so it must have no such rule (udp2raw's own warning).
    if !c.easy() {
        l.push("--keep-rule".into());
        l.push("--wait-lock".into());
    }
    if c.on_tcp() {
        l.push(format!("--seq-mode {}", c.seq_mode));
    }
    if c.fix_gro {
        l.push("--fix-gro".into());
    }
    if !c.anti_replay {
        l.push("--disable-anti-replay".into());
    }
    if c.hb_len > 0 {
        l.push(format!("--hb-len {}", c.hb_len));
    }
    l.push(format!("--mtu-warn {}", c.mtu_warn));
    l.push(format!("--sock-buf {}", c.sock_buf));
    if c.force_sock_buf {
        l.push("--force-sock-buf".into());
    }
    if c.lower_level {
        l.push("--lower-level auto".into());
    }
    l.push("--retry-on-error".into());
    l.push("--log-level 4".into());
    l.push("--disable-color".into());
    let mut t = String::from("# written by kanki-panel (KANKI-UP): changes are overwritten\n");
    for x in l {
        t.push_str(&x);
        t.push('\n');
    }
    t
}

fn conf_path(s: &KupSpec) -> String {
    format!("{}/{}.conf", CONF_DIR, s.unit())
}

fn unit_text(s: &KupSpec) -> String {
    format!(
        "# written by kanki-panel: changes are overwritten\n[Unit]\nDescription=KANKI-UP tunnel {} ({} {}{})\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nExecStart={} --conf-file {}\nRestart=always\nRestartSec=3\nLimitNOFILE=65536\nNoNewPrivileges=yes\nPrivateTmp=yes\nProtectHome=yes\n\n[Install]\nWantedBy=multi-user.target\n",
        s.name.replace(['\r', '\n'], " "),
        s.role,
        s.idx,
        if s.probe { ", measuring" } else { "" },
        BIN,
        conf_path(s)
    )
}

// ------------------------------------------------------------------ the binary

fn sha256_hex(b: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(b).iter().map(|x| format!("{:02x}", x)).collect()
}

/// The official binary at `BIN`: written when missing or different, never anything else
fn ensure_bin() -> Result<(), String> {
    if std::fs::read(BIN).map(|b| sha256_hex(&b) == BIN_SHA256).unwrap_or(false) {
        return Ok(());
    }
    let mut bytes = vec![];
    flate2::read::GzDecoder::new(BIN_GZ).read_to_end(&mut bytes).map_err(|e| format!("udp2raw: {}", e))?;
    if sha256_hex(&bytes) != BIN_SHA256 {
        return Err("udp2raw: the carried binary does not match the official release".into());
    }
    let dir = std::path::Path::new(BIN).parent().unwrap_or(std::path::Path::new("/usr/local/lib"));
    std::fs::create_dir_all(dir).map_err(|e| format!("udp2raw: {}", e))?;
    let tmp = format!("{}.new", BIN);
    std::fs::write(&tmp, &bytes).map_err(|e| format!("udp2raw: {}", e))?;
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755));
    std::fs::rename(&tmp, BIN).map_err(|e| format!("udp2raw: {}", e))?;
    Ok(())
}

// ------------------------------------------------------------------ running it

#[derive(Default)]
struct Shared {
    want: Vec<KupSpec>,
    stamp: Option<Instant>,
    errors: HashMap<String, String>,
    since: HashMap<String, u64>,
    /// tunnel id -> the 127.0.0.1 port its measuring pair listens on here (picked once)
    local: HashMap<String, u16>,
}

fn shared() -> &'static Mutex<Shared> {
    static S: OnceLock<Mutex<Shared>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(Shared::default()))
}

fn guard() -> std::sync::MutexGuard<'static, Shared> {
    shared().lock().unwrap_or_else(|e| e.into_inner())
}

fn busy() -> &'static AtomicBool {
    static B: AtomicBool = AtomicBool::new(false);
    &B
}

struct BusyGuard;
impl Drop for BusyGuard {
    fn drop(&mut self) {
        busy().store(false, Ordering::SeqCst);
    }
}

/// a command without a shell
fn run(prog: &str, args: &[&str]) -> (bool, String) {
    match Command::new(prog).args(args).stdin(Stdio::null()).output() {
        Ok(o) => {
            let mut t = String::from_utf8_lossy(&o.stdout).to_string();
            t.push_str(&String::from_utf8_lossy(&o.stderr));
            (o.status.success(), t.trim().to_string())
        }
        Err(e) => (false, e.to_string()),
    }
}

fn write_if_changed(path: &str, text: &str, mode: u32) -> Result<bool, String> {
    if std::fs::read_to_string(path).map(|t| t == text).unwrap_or(false) {
        return Ok(false);
    }
    std::fs::write(path, text).map_err(|e| format!("cannot write {}: {}", path, e))?;
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
    Ok(true)
}

fn active(unit: &str) -> bool {
    run("systemctl", &["is-active", "--quiet", &format!("{}.service", unit)]).0
}

fn apply_one(s: &KupSpec) -> Result<(), String> {
    s.cfg.check()?;
    // the measuring pair: a local port here (entry) or this agent's echo (exit)
    let mut s = s.clone();
    if s.probe {
        if s.role == "entry" {
            let p = { guard().local.get(&s.tid).copied() };
            s.listen = match p {
                Some(p) => p,
                None => {
                    let p = super::meter::free_local_port();
                    guard().local.insert(s.tid.clone(), p);
                    p
                }
            };
        } else {
            s.host.clear();
            s.port = super::meter::echo_any();
        }
    }
    let s = &s;
    // udp2raw wants an address: the entry looks the exit up here (a name may move to another address)
    let ip = if s.role == "entry" {
        super::kfwd::resolve(&s.host).ok_or_else(|| format!("the address of the exit ({}) is not known", s.host))?.to_string()
    } else {
        let t = s.host.trim();
        if t.is_empty() { "127.0.0.1".to_string() } else { t.parse::<std::net::Ipv4Addr>().map_err(|_| "the target must be an IPv4 address".to_string())?.to_string() }
    };
    if s.listen == 0 || s.port == 0 {
        return Err("a port of the tunnel is missing".into());
    }
    std::fs::create_dir_all(CONF_DIR).map_err(|e| format!("cannot make {}: {}", CONF_DIR, e))?;
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(CONF_DIR, std::fs::Permissions::from_mode(0o700));
    let u = s.unit();
    let changed = write_if_changed(&conf_path(s), &conf_text(s, &ip), 0o600)?;
    let unit_changed = write_if_changed(&format!("{}/{}.service", UNIT_DIR, u), &unit_text(s), 0o644)?;
    if unit_changed {
        let _ = run("systemctl", &["daemon-reload"]);
        let _ = run("systemctl", &["enable", "-q", &format!("{}.service", u)]);
    }
    if changed || unit_changed || !active(&u) {
        let (ok, out) = run("systemctl", &["restart", &format!("{}.service", u)]);
        if !ok {
            return Err(format!("systemctl restart {}: {}", u, out.lines().last().unwrap_or("")));
        }
        eprintln!("KANKI-UP {} ({} {}): started", s.name, s.role, s.idx);
        guard().since.insert(u, crate::util::now() as u64);
    }
    Ok(())
}

fn remove_unit(u: &str) {
    eprintln!("KANKI-UP {}: removing", u);
    // a normal stop: udp2raw takes its own iptables rule away on SIGTERM
    let _ = run("systemctl", &["disable", "--now", "-q", &format!("{}.service", u)]);
    let _ = run("systemctl", &["reset-failed", "-q", &format!("{}.service", u)]);
    let _ = std::fs::remove_file(format!("{}/{}.service", UNIT_DIR, u));
    let _ = std::fs::remove_file(format!("{}/{}.conf", CONF_DIR, u));
    let _ = run("systemctl", &["daemon-reload"]);
}

/// rules a udp2raw left behind (killed, not stopped): only when no udp2raw of ours runs any more
fn clear_leftovers() {
    let (_, rules) = run("iptables-save", &[]);
    if rules.contains("udp2rawDwrW") && std::path::Path::new(BIN).exists() {
        let _ = run(BIN, &["--clear", "--wait-lock"]);
    }
}

// ------------------------------------------------------------------ what passes (3.63)

/// The chain that counts the users' bytes on the entry: one rule per port and way, no target (it only counts)
const ACCT: &str = "KANKI-KUPACCT";

fn ipt(args: &[&str]) -> (bool, String) {
    let mut a = vec!["-w"];
    a.extend_from_slice(args);
    run("iptables", &a)
}

/// comment -> the rule's match, for every users' port of the entries here
fn acct_wanted(want: &[KupSpec]) -> Vec<(String, Vec<String>)> {
    let mut v = vec![];
    for w in want.iter().filter(|w| w.role == "entry" && !w.probe && w.listen > 0) {
        for (way, flag) in [("in", "--dport"), ("out", "--sport")] {
            let c = format!("kup:{}:{}:{}", short(&w.tid), w.idx, way);
            v.push((c.clone(), vec!["-p".into(), "udp".into(), flag.into(), w.listen.to_string(), "-m".into(), "comment".into(), "--comment".into(), c]));
        }
    }
    v
}

/// The counting rules follow the tunnels; the counters of a rule that stays are kept
fn account(want: &[KupSpec]) {
    let rules = acct_wanted(want);
    let (has, listed) = ipt(&["-S", ACCT]);
    if rules.is_empty() {
        if has {
            for ch in ["INPUT", "OUTPUT"] {
                while ipt(&["-D", ch, "-j", ACCT]).0 {}
            }
            let _ = ipt(&["-F", ACCT]);
            let _ = ipt(&["-X", ACCT]);
        }
        return;
    }
    if !has {
        let _ = ipt(&["-N", ACCT]);
    }
    for ch in ["INPUT", "OUTPUT"] {
        if !ipt(&["-C", ch, "-j", ACCT]).0 {
            let _ = ipt(&["-I", ch, "1", "-j", ACCT]);
        }
    }
    let prefix = format!("-A {} ", ACCT);
    let mut present: Vec<String> = vec![];
    for l in listed.lines().filter(|l| l.starts_with(&prefix)) {
        let c = l.split("--comment ").nth(1).map(|x| x.split_whitespace().next().unwrap_or("").trim_matches('"').to_string()).unwrap_or_default();
        if rules.iter().any(|(k, _)| *k == c) && !present.contains(&c) {
            present.push(c);
        } else {
            // a port gone (or a rule twice): the same words after -A, with -D
            let args: Vec<&str> = l[prefix.len()..].split_whitespace().collect();
            let mut d = vec!["-D", ACCT];
            d.extend(args);
            let _ = ipt(&d);
        }
    }
    for (_, m) in rules.iter().filter(|(c, _)| !present.contains(c)) {
        let mut a: Vec<&str> = vec!["-A", ACCT];
        a.extend(m.iter().map(|x| x.as_str()));
        let _ = ipt(&a);
    }
}

/// tunnel (short id) -> (bytes from the users into the tunnel, bytes back to them)
fn counters() -> HashMap<String, (u64, u64)> {
    let mut m: HashMap<String, (u64, u64)> = HashMap::new();
    let (ok, out) = ipt(&["-nvxL", ACCT]);
    if !ok {
        return m;
    }
    for l in out.lines() {
        let Some(c) = l.split("/* ").nth(1).and_then(|x| x.split(" */").next()) else { continue };
        let f: Vec<&str> = c.split(':').collect();
        if f.len() != 4 || f[0] != "kup" {
            continue;
        }
        let bytes: u64 = l.split_whitespace().nth(1).and_then(|b| b.parse().ok()).unwrap_or(0);
        let e = m.entry(f[1].to_string()).or_default();
        if f[3] == "in" {
            e.0 += bytes;
        } else {
            e.1 += bytes;
        }
    }
    m
}

/// What the meter measures: the measuring pair's local end (a UDP echo through the tunnel), or in ICMP mode
/// (one pair only, ICMP has no ports) ICMP to the exit: the same packets the tunnel sends
fn meter_targets(want: &[KupSpec]) {
    let local = guard().local.clone();
    let mut t: Vec<(String, super::meter::Target)> = vec![];
    for w in want.iter().filter(|w| w.role == "entry") {
        if w.probe {
            if let Some(p) = local.get(&w.tid) {
                t.push((w.tid.clone(), super::meter::Target::Udp(std::net::SocketAddr::from(([127, 0, 0, 1], *p)))));
            }
        } else if w.idx == 0 && w.cfg.raw_mode == "icmp" {
            if let Some(ip) = super::kfwd::resolve(&w.host) {
                t.push((w.tid.clone(), super::meter::Target::Ping(ip.to_string())));
            }
        }
    }
    super::meter::set_targets("kup", t);
}

fn reconcile() {
    let want = guard().want.clone();
    let mut removed = false;
    if let Ok(rd) = std::fs::read_dir(UNIT_DIR) {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if let Some(u) = name.strip_suffix(".service") {
                if u.starts_with(PREFIX) && !want.iter().any(|w| w.unit() == u) {
                    remove_unit(u);
                    removed = true;
                }
            }
        }
    }
    if want.is_empty() {
        if removed || guard().stamp.is_none() {
            clear_leftovers();
        }
        account(&want);
        meter_targets(&want);
        return;
    }
    let bin = ensure_bin();
    for w in &want {
        let err = match &bin {
            Err(e) => e.clone(),
            Ok(()) => apply_one(w).err().unwrap_or_default(),
        };
        guard().errors.insert(w.unit(), err);
    }
    account(&want);
    meter_targets(&want);
}

/// Called every few seconds with the KANKI-UP pairs this server should run; the work runs on a thread
pub fn set_desired(want: Vec<KupSpec>) {
    // only clean values ever reach a file: ids, names and addresses checked here
    let want: Vec<KupSpec> = want
        .into_iter()
        .filter(|w| !short(&w.tid).is_empty() && matches!(w.role.as_str(), "entry" | "exit") && w.cfg.check().is_ok())
        .filter(|w| if w.role == "entry" { host_ok(&w.host) } else { w.host.is_empty() || w.host.parse::<std::net::Ipv4Addr>().is_ok() })
        .collect();
    let run_now = {
        let mut g = guard();
        let changed = g.want != want;
        let stale = g.stamp.map(|t| t.elapsed() > Duration::from_secs(20)).unwrap_or(true);
        if changed {
            g.want = want;
        }
        (changed || stale) && !(g.want.is_empty() && g.stamp.is_some() && !changed)
    };
    if !run_now || busy().swap(true, Ordering::SeqCst) {
        return;
    }
    std::thread::spawn(|| {
        let _reset = BusyGuard;
        loop {
            let before = guard().want.clone();
            let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(reconcile));
            guard().stamp = Some(Instant::now());
            if r.is_err() || guard().want == before {
                break;
            }
        }
    });
}

/// Is this udp2raw connected? From its own log since it last started: the client says "client_ready"
/// and "back to client_idle"; the server "server_ready" for every entry that finished the handshake.
pub fn ready_from_log(role: &str, log: &str) -> (bool, String) {
    let lines: Vec<&str> = log.lines().collect();
    let start = lines.iter().rposition(|l| l.contains("Started KANKI-UP")).map(|i| i + 1).unwrap_or(0);
    let lines = &lines[start..];
    let (ok, bad) = if role == "entry" { ("to client_ready", "back to client_idle") } else { ("changed state to server_ready", "changed state to server_nothing") };
    let last_ok = lines.iter().rposition(|l| l.contains(ok));
    let last_bad = lines.iter().rposition(|l| l.contains(bad));
    let up = match (last_ok, last_bad) {
        (Some(a), Some(b)) => a > b,
        (Some(_), None) => true,
        _ => false,
    };
    let err = if up {
        String::new()
    } else {
        lines.iter().rev().find(|l| l.contains("[FATAL]") || l.contains("[ERROR]")).map(|l| l.chars().take(300).collect()).unwrap_or_default()
    };
    (up, err)
}

pub fn statuses() -> Vec<super::engine::Status> {
    let (want, errors, since) = {
        let s = guard();
        (s.want.clone(), s.errors.clone(), s.since.clone())
    };
    let bytes = counters();
    // one status per tunnel: its pairs together (the measuring pair is not one of them)
    let mut by: Vec<(String, String, Vec<KupSpec>)> = vec![];
    for w in want.into_iter().filter(|w| !w.probe) {
        match by.iter_mut().find(|x| x.0 == w.tid && x.1 == w.role) {
            Some(x) => x.2.push(w),
            None => by.push((w.tid.clone(), w.role.clone(), vec![w])),
        }
    }
    let mut out = vec![];
    for (tid, role, list) in by {
        let mut up = 0usize;
        let mut err = String::new();
        let mut first = 0u64;
        for w in &list {
            let u = w.unit();
            let e = errors.get(&u).cloned().unwrap_or_default();
            if !e.is_empty() {
                err = e;
                continue;
            }
            if !active(&u) {
                err = "the udp2raw service is not running".into();
                continue;
            }
            let (_, log) = run("journalctl", &["-u", &format!("{}.service", u), "-n", "80", "--no-pager", "-o", "cat"]);
            let (ok, le) = ready_from_log(&role, &log);
            if ok {
                up += 1;
                let s = since.get(&u).cloned().unwrap_or(0);
                first = if first == 0 { s } else { first.min(s) };
            } else if err.is_empty() {
                err = if !le.is_empty() {
                    le
                } else if role == "exit" {
                    "listening, waiting for the entry to connect".into()
                } else {
                    "connecting to the exit ...".into()
                };
            }
        }
        let all = up == list.len();
        // measured on the entry; the exit shows the same ping (its own side knows no more)
        let q = if role == "entry" { super::meter::get(&tid) } else { None };
        let rtt = if up > 0 { super::meter::rtt(&tid) } else { 0 };
        let (into, back) = bytes.get(&short(&tid)).copied().unwrap_or((0, 0));
        out.push(super::engine::Status {
            id: tid,
            role: role.clone(),
            links: up,
            want: list.len(),
            rtt_ms: rtt,
            rx_bytes: back,
            tx_bytes: into,
            streams: 0,
            udp_flows: 0,
            error: if all { String::new() } else { err },
            since: if up > 0 { first } else { 0 },
            transport: "kup".into(),
            listening: role == "exit",
            probe: None,
            quality: q,
            lanes: 0,
            bulk_flows: 0,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(role: &str) -> KupSpec {
        KupSpec {
            tid: "abcdef1234".into(),
            name: "ir-de".into(),
            role: role.into(),
            idx: 1,
            listen: if role == "entry" { 51820 } else { 29001 },
            host: if role == "entry" { "203.0.113.7".into() } else { String::new() },
            port: if role == "entry" { 29001 } else { 51820 },
            cfg: KupCfg { key: "a1b2c3d4e5f60718293a4b5c6d7e8f90".into(), ..Default::default() },
            probe: false,
        }
    }

    /// (3.63) the measuring pair: its entry only on 127.0.0.1, a unit of its own, never counted as a users' port
    #[test]
    fn the_measuring_pair_stays_on_this_machine() {
        let mut e = spec("entry");
        e.probe = true;
        e.listen = 40123;
        let c = conf_text(&e, "203.0.113.7");
        assert!(c.contains("-l 127.0.0.1:40123") && !c.contains("0.0.0.0"), "{}", c);
        assert!(e.unit().ends_with("-p"));
        assert_ne!(e.unit(), spec("entry").unit());
        // the users' pairs are counted, the measuring one is not
        let rules = acct_wanted(&[spec("entry"), e, spec("exit")]);
        assert_eq!(rules.len(), 2, "{:?}", rules);
        assert!(rules[0].1.contains(&"--dport".to_string()) && rules[0].1.contains(&"51820".to_string()));
        assert!(rules[1].1.contains(&"--sport".to_string()));
    }

    /// the options file has the same common options on both sides and the right direction on each
    #[test]
    fn both_sides_get_the_same_common_options() {
        let c = conf_text(&spec("entry"), "203.0.113.7");
        let s = conf_text(&spec("exit"), "127.0.0.1");
        assert!(c.contains("\n-c\n") && c.contains("-l 0.0.0.0:51820") && c.contains("-r 203.0.113.7:29001"));
        assert!(s.contains("\n-s\n") && s.contains("-l 0.0.0.0:29001") && s.contains("-r 127.0.0.1:51820"));
        for line in ["-k a1b2c3d4e5f60718293a4b5c6d7e8f90", "--raw-mode faketcp", "--cipher-mode aes128cbc", "--auth-mode md5", "--seq-mode 3", "--fix-gro", "--keep-rule"] {
            assert!(c.contains(line) && s.contains(line), "{}", line);
        }
        // udp mode has no seq-mode; anti-replay off is written
        let mut u = spec("entry");
        u.cfg.raw_mode = "udp".into();
        u.cfg.anti_replay = false;
        let t = conf_text(&u, "203.0.113.7");
        assert!(!t.contains("--seq-mode") && t.contains("--disable-anti-replay"));
        // easy-faketcp: a real TCP connection, so no iptables rule of udp2raw
        let mut e = spec("exit");
        e.cfg.raw_mode = "easy-faketcp".into();
        assert!(!conf_text(&e, "127.0.0.1").contains("--keep-rule"));
        assert_eq!(spec("entry").unit(), "kanki-up-abcdef1234-1");
    }

    /// a value udp2raw does not know, or one that could add an option, never reaches the file
    #[test]
    fn only_known_values_are_taken() {
        let mut c = KupCfg { key: "a1b2c3d4e5f60718293a4b5c6d7e8f90".into(), ..Default::default() };
        assert!(c.check().is_ok());
        c.raw_mode = "faketcp\n--lower-level eth0".into();
        assert!(c.check().is_err());
        c = KupCfg { key: "short".into(), ..Default::default() };
        assert!(c.check().is_err());
        c = KupCfg { key: "a1b2c3d4e5f60718 --clear".into(), ..Default::default() };
        assert!(c.check().is_err());
        let mut bad = spec("entry");
        bad.host = "1.2.3.4\n-s".into();
        set_desired(vec![bad]);
        assert!(guard().want.is_empty(), "an address with a new line is refused");
    }

    /// connected or not, from udp2raw's own log lines
    #[test]
    fn the_log_says_when_it_is_connected() {
        let c = "[INFO]state changed from client_idle to client_tcp_handshake\n[INFO]changed state from to client_handshake2 to client_ready\n";
        assert!(ready_from_log("entry", c).0);
        let back = format!("{}[INFO]state back to client_idle from  client_ready bc of server-->client direction timeout\n", c);
        assert!(!ready_from_log("entry", &back).0);
        // an older run before the last start does not count
        let restarted = format!("{}Started KANKI-UP tunnel x (entry 0).\n[INFO]state changed from client_idle to client_tcp_handshake\n", c);
        assert!(!ready_from_log("entry", &restarted).0);
        assert!(ready_from_log("exit", "[INFO][1.2.3.4:5]changed state to server_ready\n").0);
        let (up, err) = ready_from_log("exit", "[FATAL]bind fail\n");
        assert!(!up && err.contains("bind fail"));
    }

    /// the carried binary is the official file of the release
    #[test]
    fn the_carried_binary_is_the_official_one() {
        let mut b = vec![];
        flate2::read::GzDecoder::new(BIN_GZ).read_to_end(&mut b).unwrap();
        assert_eq!(sha256_hex(&b), BIN_SHA256);
        assert!(b.starts_with(b"\x7fELF"));
    }
}

/// The real thing (scripts/kup_lab.sh): writes the options files the agents would write for one pair into
/// KUP_LAB (a directory), with the exit at KUP_EXIT and a raw mode from KUP_MODE
#[cfg(test)]
mod lab {
    use super::*;

    #[test]
    #[ignore]
    fn kup_lab_files() {
        let Ok(dir) = std::env::var("KUP_LAB") else { return };
        let exit = std::env::var("KUP_EXIT").unwrap_or_else(|_| "10.77.0.2".into());
        let mode = std::env::var("KUP_MODE").unwrap_or_else(|_| "faketcp".into());
        let cfg = KupCfg { key: "a1b2c3d4e5f60718293a4b5c6d7e8f90".into(), raw_mode: mode, ..Default::default() };
        cfg.check().unwrap();
        let e = KupSpec { tid: "lab".into(), name: "lab".into(), role: "entry".into(), idx: 0, listen: 51820, host: exit.clone(), port: 29000, cfg: cfg.clone(), probe: false };
        let x = KupSpec { tid: "lab".into(), name: "lab".into(), role: "exit".into(), idx: 0, listen: 29000, host: String::new(), port: 51820, cfg, probe: false };
        std::fs::write(format!("{}/entry.conf", dir), conf_text(&e, &exit)).unwrap();
        std::fs::write(format!("{}/exit.conf", dir), conf_text(&x, "127.0.0.1")).unwrap();
        // (3.63) the measuring pair: entry 127.0.0.1:41000, exit raw 29099, to an echo on the exit's 127.0.0.1:51821
        let pe = KupSpec { tid: "lab".into(), name: "lab".into(), role: "entry".into(), idx: 1, listen: 41000, host: exit.clone(), port: 29099, cfg: e.cfg.clone(), probe: true };
        let px = KupSpec { tid: "lab".into(), name: "lab".into(), role: "exit".into(), idx: 1, listen: 29099, host: String::new(), port: 51821, cfg: e.cfg.clone(), probe: true };
        std::fs::write(format!("{}/pentry.conf", dir), conf_text(&pe, &exit)).unwrap();
        std::fs::write(format!("{}/pexit.conf", dir), conf_text(&px, "127.0.0.1")).unwrap();
    }

    /// Run inside the entry's namespace of scripts/kup_lab.sh: the counting rules and the meter through the
    /// measuring pair (KUP_METER=1)
    #[test]
    #[ignore]
    fn kup_meter_lab() {
        if std::env::var("KUP_METER").is_err() {
            return;
        }
        let mut e = KupSpec { tid: "lab".into(), name: "lab".into(), role: "entry".into(), idx: 0, listen: 51820, host: "10.77.0.2".into(), port: 29000, ..Default::default() };
        e.cfg.key = "a1b2c3d4e5f60718293a4b5c6d7e8f90".into();
        account(&[e.clone()]);
        let q = crate::tunnel::meter::udp_series("127.0.0.1:41000".parse().unwrap()).unwrap();
        println!("measured through the pair: {}", q);
        // users' packets to the entry port, then the counters
        let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        s.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
        for _ in 0..100 {
            s.send_to(&[7u8; 100], "127.0.0.1:51820").unwrap();
            let mut b = [0u8; 200];
            let _ = s.recv_from(&mut b);
        }
        println!("counted: {:?}", counters());
        account(&[]);
        println!("after: {:?}", run("iptables", &["-S", ACCT]).0);
    }
}
