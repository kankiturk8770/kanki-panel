//! Hysteria2 tunnel between two servers.
//!
//! The exit (for example the server abroad) runs a Hysteria2 server on one UDP port; the entry (for
//! example the Iran server) runs a Hysteria2 client that dials it. Both are the official `hysteria`
//! binary (installed by itself when missing), each under its own systemd unit
//! `kanki-hy2-<id>.service`, so this does not touch the Hysteria2 that serves VPN users.
//!
//! What goes through the link:
//! * forwarded ports: users connect to a port on the entry and land on a port of the exit (for
//!   example the WireGuard / Hysteria2 of the exit server, so their configs point to the entry);
//! * the internet of whole networks: everything coming from, say, the WireGuard users of the entry
//!   (10.8.0.0/24) goes into a TUN interface of the client and leaves from the exit.
//!
//! The panel makes the passwords and a self-signed certificate once; the client pins the
//! certificate's SHA-256, so nobody in the middle can pose as the exit.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

pub const CONF_DIR: &str = "/etc/kanki/hy2tun";
const UNIT_DIR: &str = "/etc/systemd/system";
const PREFIX: &str = "kanki-hy2-";

// ------------------------------------------------------------------ what the panel stores

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(default)]
pub struct Hy2Cfg {
    /// link number (TUN addresses, routing table, stats port)
    pub n: u8,
    /// UDP port of the Hysteria2 server on the exit
    pub port: u16,
    pub auth: String,
    /// Salamander password; empty = no obfuscation (the traffic then looks like HTTP/3)
    pub obfs: String,
    pub cert: String,
    pub key: String,
    /// sha256 of the certificate (hex), checked by the client
    pub pin: String,
    /// TLS server name the client sends
    pub sni: String,
    /// Brutal speed in Mbit/s (0 = BBR, adapts by itself)
    pub up_mbps: u32,
    pub down_mbps: u32,
    /// the site a stranger sees when opening the port as HTTP/3 (no obfuscation)
    pub masq: String,
    /// entry: all traffic coming FROM these networks leaves from the exit (TUN)
    pub src_routes: Vec<String>,
    pub mtu: u16,
}

impl Default for Hy2Cfg {
    fn default() -> Self {
        Hy2Cfg {
            n: 0,
            port: 0,
            auth: String::new(),
            obfs: String::new(),
            cert: String::new(),
            key: String::new(),
            pin: String::new(),
            sni: "www.bing.com".into(),
            up_mbps: 0,
            down_mbps: 0,
            masq: "https://www.bing.com/".into(),
            src_routes: vec![],
            mtu: 1400,
        }
    }
}

// ------------------------------------------------------------------ what an agent gets

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
#[serde(default)]
pub struct Hy2Spec {
    pub tid: String,
    pub name: String,
    /// "entry" (client) | "exit" (server)
    pub role: String,
    /// exit: UDP port to listen on
    pub listen: u16,
    /// entry: "host:port" of the exit
    pub server: String,
    pub auth: String,
    pub obfs: String,
    /// exit only
    pub cert: String,
    pub key: String,
    pub masq: String,
    /// entry only
    pub pin: String,
    pub sni: String,
    pub up_mbps: u32,
    pub down_mbps: u32,
    /// entry: forwarded ports ("443" or "8443:443") and where they go on the exit
    pub fwd_tcp: Vec<String>,
    pub fwd_udp: Vec<String>,
    pub target: String,
    /// entry: source networks sent into the TUN
    pub src_routes: Vec<String>,
    pub n: u8,
    pub mtu: u16,
    /// exit: local traffic stats API
    pub stats_port: u16,
    pub stats_secret: String,
}

impl Hy2Spec {
    pub fn unit(&self) -> String {
        unit_name(&self.tid)
    }
    pub fn tun(&self) -> String {
        format!("khy{}", short(&self.tid))
    }
    pub fn table(&self) -> u32 {
        21000 + self.n as u32
    }
}

fn short(tid: &str) -> String {
    // the whole id (panel ids are 10 characters): two tunnels never share a unit or a TUN name.
    // 12 at most keeps the TUN name ("khy" + id) inside Linux's 15-character limit.
    tid.chars().filter(|c| c.is_ascii_alphanumeric()).take(12).collect::<String>().to_lowercase()
}

pub fn unit_name(tid: &str) -> String {
    format!("{}{}", PREFIX, short(tid))
}

// ------------------------------------------------------------------ secrets and certificate

/// (cert pem, key pem, sha256 of the certificate as hex)
pub fn gen_cert(name: &str) -> Result<(String, String, String), String> {
    let ck = rcgen::generate_simple_self_signed(vec![name.to_string()]).map_err(|e| e.to_string())?;
    let pin = {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(ck.cert.der());
        hex::encode(h.finalize())
    };
    Ok((ck.cert.pem(), ck.key_pair.serialize_pem(), pin))
}

/// a host name for SNI / masquerade: letters, digits, dots and dashes only
pub fn clean_host(s: &str) -> String {
    s.trim().chars().filter(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '-').take(253).collect()
}

/// an https:// address for the masquerade (empty when it is not one)
pub fn clean_url(s: &str) -> String {
    let s = s.trim();
    let Some(rest) = s.strip_prefix("https://") else { return String::new() };
    let host = rest.split('/').next().unwrap_or("");
    let h = clean_host(host);
    if h.is_empty() || h != host {
        return String::new();
    }
    format!("https://{}/", h)
}

// ------------------------------------------------------------------ config text

fn q(s: &str) -> String {
    // every value we write is made of safe characters, but quote it anyway
    format!("\"{}\"", s.replace('\\', "").replace('"', ""))
}

fn conf_path(s: &Hy2Spec) -> String {
    format!("{}/{}.yaml", CONF_DIR, s.unit())
}

/// the Hysteria2 YAML of one side (also what the panel shows)
pub fn render(s: &Hy2Spec) -> String {
    let mut c = String::from("# written by kanki-panel: changes are overwritten\n");
    let obfs = |c: &mut String| {
        if !s.obfs.is_empty() {
            c.push_str(&format!("obfs:\n  type: salamander\n  salamander:\n    password: {}\n", q(&s.obfs)));
        }
    };
    let bw = |c: &mut String| {
        if s.up_mbps > 0 || s.down_mbps > 0 {
            c.push_str("bandwidth:\n");
            if s.up_mbps > 0 {
                c.push_str(&format!("  up: {} mbps\n", s.up_mbps));
            }
            if s.down_mbps > 0 {
                c.push_str(&format!("  down: {} mbps\n", s.down_mbps));
            }
        }
    };
    if s.role == "exit" {
        c.push_str(&format!("listen: :{}\n", s.listen));
        c.push_str(&format!("tls:\n  cert: {}/{}.crt\n  key: {}/{}.key\n", CONF_DIR, s.unit(), CONF_DIR, s.unit()));
        c.push_str(&format!("auth:\n  type: password\n  password: {}\n", q(&s.auth)));
        obfs(&mut c);
        // the exit's limits are the client's opposite: its "up" is the entry's download
        if s.up_mbps > 0 || s.down_mbps > 0 {
            c.push_str("bandwidth:\n");
            if s.down_mbps > 0 {
                c.push_str(&format!("  up: {} mbps\n", s.down_mbps));
            }
            if s.up_mbps > 0 {
                c.push_str(&format!("  down: {} mbps\n", s.up_mbps));
            }
        }
        c.push_str("quic:\n  initStreamReceiveWindow: 16777216\n  maxStreamReceiveWindow: 16777216\n  initConnReceiveWindow: 33554432\n  maxConnReceiveWindow: 33554432\n  maxIdleTimeout: 30s\n  maxIncomingStreams: 4096\n");
        if s.obfs.is_empty() && !s.masq.is_empty() {
            c.push_str(&format!("masquerade:\n  type: proxy\n  proxy:\n    url: {}\n    rewriteHost: true\n", q(&s.masq)));
        }
        if s.stats_port > 0 {
            c.push_str(&format!("trafficStats:\n  listen: 127.0.0.1:{}\n  secret: {}\n", s.stats_port, q(&s.stats_secret)));
        }
        return c;
    }
    c.push_str(&format!("server: {}\nauth: {}\n", q(&s.server), q(&s.auth)));
    c.push_str("tls:\n");
    if !s.sni.is_empty() {
        c.push_str(&format!("  sni: {}\n", q(&s.sni)));
    }
    // self-signed: the pinned hash is what is checked
    c.push_str(&format!("  insecure: true\n  pinSHA256: {}\n", q(&s.pin)));
    obfs(&mut c);
    bw(&mut c);
    c.push_str("quic:\n  initStreamReceiveWindow: 16777216\n  maxStreamReceiveWindow: 16777216\n  initConnReceiveWindow: 33554432\n  maxConnReceiveWindow: 33554432\n  maxIdleTimeout: 30s\n  keepAlivePeriod: 10s\n");
    c.push_str("fastOpen: true\n");
    let target = if s.target.trim().is_empty() { "127.0.0.1".to_string() } else { s.target.trim().to_string() };
    let tpairs = super::engine::parse_ports(&s.fwd_tcp);
    if !tpairs.is_empty() {
        c.push_str("tcpForwarding:\n");
        for (a, b) in tpairs {
            c.push_str(&format!("  - listen: 0.0.0.0:{}\n    remote: {}\n", a, q(&format!("{}:{}", target, b))));
        }
    }
    let upairs = super::engine::parse_ports(&s.fwd_udp);
    if !upairs.is_empty() {
        c.push_str("udpForwarding:\n");
        for (a, b) in upairs {
            c.push_str(&format!("  - listen: 0.0.0.0:{}\n    remote: {}\n    timeout: 120s\n", a, q(&format!("{}:{}", target, b))));
        }
    }
    if !s.src_routes.is_empty() {
        // no `route` section: Hysteria adds no routes by itself, the up script routes only the
        // listed source networks into the TUN (the server's own traffic and SSH are not touched)
        c.push_str(&format!(
            "tun:\n  name: {}\n  mtu: {}\n  timeout: 5m\n  address:\n    ipv4: 100.99.{}.1/30\n    ipv6: \"fdcb:99:{:x}::1/126\"\n",
            q(&s.tun()),
            if s.mtu >= 1200 && s.mtu <= 1500 { s.mtu } else { 1400 },
            s.n,
            s.n
        ));
    }
    c
}

/// shell script run after the client starts / stops: routes the source networks into the TUN
fn route_script(s: &Hy2Spec, up: bool) -> String {
    let tun = s.tun();
    let t = s.table();
    let prio = 12000 + s.n as u32;
    let mut c = String::from("#!/bin/sh\n# written by kanki-panel\n");
    for r in &s.src_routes {
        c.push_str(&format!("while ip rule del from {} table {} priority {} 2>/dev/null; do :; done\n", r, t, prio));
    }
    c.push_str(&format!("ip route flush table {} 2>/dev/null\n", t));
    c.push_str(&format!("iptables -D FORWARD -i {} -j ACCEPT 2>/dev/null\niptables -D FORWARD -o {} -j ACCEPT 2>/dev/null\n", tun, tun));
    if up {
        c.push_str(&format!("i=0; while [ $i -lt 60 ] && ! ip link show {} >/dev/null 2>&1; do sleep 0.5; i=$((i+1)); done\n", tun));
        c.push_str("sysctl -qw net.ipv4.ip_forward=1\nsysctl -qw net.ipv4.conf.all.rp_filter=2\nsysctl -qw net.ipv4.conf.default.rp_filter=2\n");
        c.push_str(&format!("sysctl -qw net.ipv4.conf.{}.rp_filter=2\n", tun));
        c.push_str(&format!("ip route replace default dev {} table {}\n", tun, t));
        for r in &s.src_routes {
            c.push_str(&format!("ip rule add from {} table {} priority {}\n", r, t, prio));
        }
        c.push_str(&format!("iptables -I FORWARD -i {} -j ACCEPT\niptables -I FORWARD -o {} -j ACCEPT\n", tun, tun));
    }
    c.push_str("exit 0\n");
    c
}

fn unit_text(s: &Hy2Spec, bin: &str) -> String {
    let mode = if s.role == "exit" { "server" } else { "client" };
    let mut c = format!(
        "# written by kanki-panel: changes are overwritten\n[Unit]\nDescription=Kanki Hysteria2 tunnel {} ({})\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nEnvironment=HYSTERIA_DISABLE_UPDATE_CHECK=1\nExecStart={} {} -c {}\n",
        s.name.replace('\n', " "),
        s.role,
        bin,
        mode,
        conf_path(s)
    );
    if s.role == "entry" && !s.src_routes.is_empty() {
        c.push_str(&format!("ExecStartPost=/bin/sh {}/{}-up.sh\nExecStopPost=/bin/sh {}/{}-down.sh\n", CONF_DIR, s.unit(), CONF_DIR, s.unit()));
    }
    c.push_str("Restart=always\nRestartSec=3\nLimitNOFILE=1048576\n\n[Install]\nWantedBy=multi-user.target\n");
    c
}

// ------------------------------------------------------------------ running it

#[derive(Default)]
struct Shared {
    want: Vec<Hy2Spec>,
    stamp: Option<Instant>,
    errors: HashMap<String, String>,
    since: HashMap<String, u64>,
    bin: Option<Result<String, String>>,
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

fn find_bin() -> Option<String> {
    for p in ["/usr/local/bin/hysteria", "/usr/bin/hysteria"] {
        if std::path::Path::new(p).exists() {
            return Some(p.into());
        }
    }
    let (ok, out) = sh("command -v hysteria");
    if ok && !out.is_empty() { Some(out.lines().next().unwrap_or("").to_string()) } else { None }
}

/// Hysteria2 release name of a CPU type ("x86_64" -> "amd64")
pub fn arch_name(arch: &str) -> Option<&'static str> {
    Some(match arch {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        "arm" => "arm",
        "x86" => "386",
        "riscv64" => "riscv64",
        "s390x" => "s390x",
        "loongarch64" => "loong64",
        _ => return None,
    })
}

/// where the binary is downloaded from: GitHub, then the project's own download server
pub fn download_urls(arch: &str) -> Vec<String> {
    let Some(a) = arch_name(arch) else { return vec![] };
    vec![
        format!("https://github.com/apernet/hysteria/releases/latest/download/hysteria-linux-{}", a),
        format!("https://download.hysteria.network/app/latest/hysteria-linux-{}", a),
    ]
}

/// a real Linux program of a sane size (a filtered network often answers with an HTML page)
pub fn looks_like_binary(b: &[u8]) -> bool {
    b.len() > 3_000_000 && b.starts_with(b"\x7fELF")
}

pub const CACHE_DIR: &str = "/var/lib/kanki/hy2bin";

fn sha256_hex(b: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b);
    hex::encode(h.finalize())
}

/// checks a downloaded file and moves it to /usr/local/bin/hysteria
fn take(tmp: &str) -> bool {
    let ok = std::fs::read(tmp).map(|b| looks_like_binary(&b)).unwrap_or(false) && {
        let _ = sh(&format!("chmod 755 {}", tmp));
        sh(&format!("{} version 2>&1 | grep -qi version", tmp)).0
    };
    if ok {
        let _ = std::fs::create_dir_all("/usr/local/bin");
        ok && sh(&format!("mv -f {} /usr/local/bin/hysteria", tmp)).0
    } else {
        let _ = std::fs::remove_file(tmp);
        false
    }
}

fn agent_env() -> Option<(String, String, String, bool)> {
    let env = crate::util::load_env(super::agent::ENV_FILE);
    let panel = env.get("PANEL_URL").cloned().unwrap_or_default().trim_end_matches('/').to_string();
    let id = env.get("AGENT_ID").cloned().unwrap_or_default();
    let token = env.get("AGENT_TOKEN").cloned().unwrap_or_default();
    if panel.is_empty() || id.is_empty() || token.is_empty() {
        return None;
    }
    Some((panel, id, token, env.get("INSECURE").map(|v| v == "1").unwrap_or(false)))
}

/// One POST to the panel through the agent's own client (CA-checked, or pinned to
/// /etc/kanki/panel.pin with INSECURE=1), so the connection whose certificate is checked is the
/// one that carries the data. Returns the `x-sha256` header and the body. Runs on the reconcile
/// thread, which has no async runtime of its own.
fn panel_post(insecure: bool, timeout: Duration, url: &str, headers: &[(&str, String)], body: Vec<u8>) -> Result<(String, Vec<u8>), String> {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|e| e.to_string())?;
    rt.block_on(async {
        let mut rq = super::agent::panel_client(insecure, timeout).post(url).body(body);
        for (k, v) in headers {
            rq = rq.header(*k, v.as_str());
        }
        let r = rq.send().await.map_err(|e| crate::pin::error_text(&e))?;
        if !r.status().is_success() {
            return Err(format!("the panel answered {}", r.status()));
        }
        let sum = r.headers().get("x-sha256").and_then(|v| v.to_str().ok()).unwrap_or("").trim().to_lowercase();
        let b = r.bytes().await.map_err(|e| crate::pin::error_text(&e))?;
        Ok((sum, b.to_vec()))
    })
}

/// asks the panel for the binary of this CPU type (it has its own, a cached one, or downloads it)
fn from_panel(tmp: &str) -> Result<(), String> {
    let Some((panel, id, token, insecure)) = agent_env() else { return Err("not a tunnel agent".into()) };
    let body = serde_json::json!({ "id": id, "token": token, "arch": std::env::consts::ARCH }).to_string();
    let json = [("content-type", "application/json".to_string())];
    let (want, bytes) = panel_post(insecure, Duration::from_secs(300), &format!("{}/tunnel/hy2bin", panel), &json, body.into_bytes())
        .map_err(|e| format!("the panel did not give it ({})", e))?;
    if want.is_empty() || want != sha256_hex(&bytes) {
        return Err("the file from the panel was damaged on the way".into());
    }
    std::fs::write(tmp, &bytes).map_err(|e| format!("cannot write {}: {}", tmp, e))
}

/// the official installer (the same `get.hy2.sh` the panel's install.sh uses), saved to a file;
/// GitHub's copy of the same script when get.hy2.sh cannot be reached
fn fetch_installer() -> Option<String> {
    let path = "/tmp/kanki-hy2-install.sh";
    for url in ["https://get.hy2.sh/", "https://raw.githubusercontent.com/apernet/hysteria/master/scripts/install_server.sh"] {
        if sh(&format!("curl -fsSL --connect-timeout 10 --max-time 60 -o {} '{}' 2>&1", path, url)).0
            && std::fs::read_to_string(path).map(|t| t.starts_with("#!") && t.contains("hysteria")).unwrap_or(false)
        {
            return Some(path.into());
        }
    }
    let _ = std::fs::remove_file(path);
    None
}

/// runs the installer the way a root shell would (it uses tput and $HOME; the agent's service has neither)
fn run_installer(script: &str, args: &str) -> String {
    let (_, out) = sh(&format!("TERM=dumb HOME=/root bash {} {} 2>&1", script, args));
    // its last error line, without colour codes
    out.lines()
        .rev()
        .find(|l| l.contains("error") || l.contains("rror:"))
        .map(|l| l.chars().filter(|c| !c.is_control()).collect::<String>().replace("[0m", "").replace("[31m", ""))
        .unwrap_or_default()
}

/// Gets the official binary onto this server, the same way the panel installs Hysteria2 for users:
/// 1. the official installer `get.hy2.sh`, exactly like install.sh does;
/// 2. the same GitHub file that installer downloads (also download.hysteria.network), installed
///    with the same installer (`--local`): the installer first asks api.hy2.io for the newest
///    version and gives up when only that site is unreachable, even if GitHub works;
/// 3. the panel (its own copy, one given by the other server of the tunnel, or one it downloads).
fn ensure_bin() -> Result<String, String> {
    if let Some(b) = find_bin() {
        return Ok(b);
    }
    eprintln!("hy2 tunnel: installing Hysteria2 ...");
    let mut why = vec![];
    let script = fetch_installer();
    match &script {
        Some(sc) => {
            let e = run_installer(sc, "");
            if let Some(b) = find_bin() {
                eprintln!("hy2 tunnel: installed with get.hy2.sh");
                return Ok(b);
            }
            why.push(format!("get.hy2.sh: {}", if e.is_empty() { "failed".into() } else { e }));
        }
        None => why.push("get.hy2.sh: unreachable".into()),
    }
    let tmp = "/usr/local/bin/.hysteria.kanki-new";
    let _ = std::fs::create_dir_all("/usr/local/bin");
    let install = |tmp: &str| -> bool {
        if let Some(sc) = &script {
            let ok = std::fs::read(tmp).map(|b| looks_like_binary(&b)).unwrap_or(false);
            if ok {
                let _ = run_installer(sc, &format!("--local {}", tmp));
                if find_bin().is_some() {
                    let _ = std::fs::remove_file(tmp);
                    return true;
                }
            }
        }
        take(tmp)
    };
    for url in download_urls(std::env::consts::ARCH) {
        let (ok, out) = sh(&format!("curl -fsSL --connect-timeout 10 --max-time 180 -o {} '{}' 2>&1", tmp, url));
        if ok && install(tmp) {
            eprintln!("hy2 tunnel: installed from {}", url);
            return find_bin().ok_or_else(|| "install failed".to_string());
        }
        let _ = std::fs::remove_file(tmp);
        why.push(format!("{}: {}", url.split('/').nth(2).unwrap_or(""), if ok { "not a program (filtered?)".to_string() } else { out.lines().last().unwrap_or("unreachable").trim().to_string() }));
    }
    // a copy the panel server keeps for its agents (when this server is the panel itself)
    if let Some(a) = arch_name(std::env::consts::ARCH) {
        let c = format!("{}/hysteria-linux-{}", CACHE_DIR, a);
        if std::path::Path::new(&c).exists() && sh(&format!("cp -f {} {}", c, tmp)).0 && install(tmp) {
            return find_bin().ok_or_else(|| "install failed".to_string());
        }
    }
    match from_panel(tmp) {
        Ok(()) if install(tmp) => {
            eprintln!("hy2 tunnel: installed from the panel");
            return find_bin().ok_or_else(|| "install failed".to_string());
        }
        Ok(()) => why.push("panel: the file is not a working program".into()),
        Err(e) => why.push(format!("panel: {}", e)),
    }
    Err(format!(
        "Hysteria2 could not be installed on this server ({}). It is installed by itself as soon as one source works: once the other server of the tunnel has it, it is passed on through the panel.",
        why.join("; ")
    ))
}

/// After this server has the binary: give the panel a copy if it has none for this CPU type, so
/// servers that cannot download it (Iran) get it from the panel. Once per run.
fn share_with_panel(bin: &str) {
    static DONE: AtomicBool = AtomicBool::new(false);
    if DONE.load(Ordering::SeqCst) {
        return;
    }
    let Some((panel, id, token, insecure)) = agent_env() else {
        DONE.store(true, Ordering::SeqCst);
        return;
    };
    let url = format!("{}/tunnel/hy2bin", panel);
    let body = serde_json::json!({ "id": id, "token": token, "arch": std::env::consts::ARCH, "check": true }).to_string();
    let json = [("content-type", "application/json".to_string())];
    let out = match panel_post(insecure, Duration::from_secs(20), &url, &json, body.into_bytes()) {
        Ok((_, out)) => out,
        Err(e) => {
            if e.contains(crate::pin::MISMATCH) {
                eprintln!("hy2 tunnel: not sharing the binary: {}", e);
            }
            return; // an older panel or no answer: try again next round
        }
    };
    let have = serde_json::from_slice::<serde_json::Value>(&out).ok().and_then(|v| v["have"].as_bool()).unwrap_or(true);
    if !have {
        let Ok(bytes) = std::fs::read(bin) else { return };
        if !looks_like_binary(&bytes) {
            DONE.store(true, Ordering::SeqCst);
            return;
        }
        let headers = [
            ("x-id", id),
            ("x-token", token),
            ("x-arch", std::env::consts::ARCH.to_string()),
            ("x-sha256", sha256_hex(&bytes)),
            ("content-type", "application/octet-stream".to_string()),
        ];
        if panel_post(insecure, Duration::from_secs(600), &format!("{}/put", url), &headers, bytes).is_err() {
            return;
        }
        eprintln!("hy2 tunnel: gave the panel a copy of hysteria for the other servers");
    }
    DONE.store(true, Ordering::SeqCst);
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
    sh(&format!("systemctl is-active --quiet {}.service", unit)).0
}

fn apply_one(s: &Hy2Spec, bin: &str) -> Result<(), String> {
    let _ = std::fs::create_dir_all(CONF_DIR);
    let u = s.unit();
    let mut changed = false;
    // routes of the previous settings go before new ones are written (the new unit may have no
    // stop script any more, or a different list of networks)
    let down = format!("{}/{}-down.sh", CONF_DIR, u);
    let new_down = if s.role == "entry" && !s.src_routes.is_empty() { Some(route_script(s, false)) } else { None };
    if let Ok(old) = std::fs::read_to_string(&down) {
        if new_down.as_deref() != Some(old.as_str()) {
            let _ = sh(&format!("sh {} 2>&1", down));
            let _ = std::fs::remove_file(&down);
            let _ = std::fs::remove_file(format!("{}/{}-up.sh", CONF_DIR, u));
            changed = true;
        }
    }
    if s.role == "exit" {
        changed |= write_if_changed(&format!("{}/{}.crt", CONF_DIR, u), &s.cert, 0o600)?;
        changed |= write_if_changed(&format!("{}/{}.key", CONF_DIR, u), &s.key, 0o600)?;
    } else if !s.src_routes.is_empty() {
        changed |= write_if_changed(&format!("{}/{}-up.sh", CONF_DIR, u), &route_script(s, true), 0o700)?;
        changed |= write_if_changed(&format!("{}/{}-down.sh", CONF_DIR, u), &route_script(s, false), 0o700)?;
    }
    changed |= write_if_changed(&conf_path(s), &render(s), 0o600)?;
    let unit_changed = write_if_changed(&format!("{}/{}.service", UNIT_DIR, u), &unit_text(s, bin), 0o644)?;
    if unit_changed {
        let _ = sh("systemctl daemon-reload");
        let _ = sh(&format!("systemctl enable -q {}.service", u));
    }
    if changed || unit_changed || !active(&u) {
        let (ok, out) = sh(&format!("systemctl restart {}.service 2>&1", u));
        if !ok {
            return Err(format!("systemctl restart {}: {}", u, out.lines().last().unwrap_or("")));
        }
        eprintln!("hy2 tunnel {} ({}): started", s.name, s.role);
        guard().since.insert(u, crate::util::now() as u64);
    }
    Ok(())
}

fn remove_unit(u: &str) {
    eprintln!("hy2 tunnel {}: removing", u);
    let _ = sh(&format!("systemctl disable --now -q {}.service 2>&1", u));
    // stopped for sure (frees the UDP port and the forwarded ports) even if disable failed
    let _ = sh(&format!("systemctl kill -q {}.service 2>&1; systemctl reset-failed -q {}.service 2>&1", u, u));
    let down = format!("{}/{}-down.sh", CONF_DIR, u);
    if std::path::Path::new(&down).exists() {
        let _ = sh(&format!("sh {} 2>&1", down));
    }
    let _ = std::fs::remove_file(format!("{}/{}.service", UNIT_DIR, u));
    for ext in [".yaml", ".crt", ".key", "-up.sh", "-down.sh"] {
        let _ = std::fs::remove_file(format!("{}/{}{}", CONF_DIR, u, ext));
    }
    let _ = sh("systemctl daemon-reload");
}

fn reconcile() {
    let want = guard().want.clone();
    // units that are not wanted any more
    if let Ok(rd) = std::fs::read_dir(UNIT_DIR) {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if let Some(u) = name.strip_suffix(".service") {
                if u.starts_with(PREFIX) && !want.iter().any(|w| w.unit() == u) {
                    remove_unit(u);
                }
            }
        }
    }
    if want.is_empty() {
        return;
    }
    let bin = {
        let cached = guard().bin.clone();
        match cached {
            Some(Ok(b)) if std::path::Path::new(&b).exists() => Ok(b),
            _ => {
                let r = ensure_bin();
                guard().bin = Some(r.clone());
                r
            }
        }
    };
    if let Ok(b) = &bin {
        share_with_panel(b);
    }
    for w in &want {
        let err = match &bin {
            Err(e) => e.clone(),
            Ok(b) => apply_one(w, b).err().unwrap_or_default(),
        };
        guard().errors.insert(w.unit(), err);
    }
}

/// Called every few seconds with the Hysteria2 tunnels this server should run.
pub fn set_desired(want: Vec<Hy2Spec>) {
    let run = {
        let mut s = guard();
        let changed = s.want != want;
        let stale = s.stamp.map(|t| t.elapsed() > Duration::from_secs(20)).unwrap_or(true);
        if changed {
            s.want = want;
        }
        // nothing wanted and nothing was ever wanted: do not scan the system every time
        (changed || stale) && !(s.want.is_empty() && s.stamp.is_some() && !changed)
    };
    if !run || busy().swap(true, Ordering::SeqCst) {
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

/// exit: (connected clients, rx, tx) from the server's local stats API
fn exit_stats(s: &Hy2Spec) -> Option<(i64, u64, u64)> {
    if s.stats_port == 0 {
        return None;
    }
    let get = |path: &str| -> Option<serde_json::Value> {
        let (ok, out) = sh(&format!("curl -fsS --max-time 2 -H 'Authorization: {}' http://127.0.0.1:{}/{}", s.stats_secret.replace('\'', ""), s.stats_port, path));
        if ok { serde_json::from_str(&out).ok() } else { None }
    };
    let online: i64 = get("online")?.as_object().map(|o| o.values().filter_map(|v| v.as_i64()).sum()).unwrap_or(0);
    let (mut rx, mut tx) = (0u64, 0u64);
    if let Some(o) = get("traffic").and_then(|v| v.as_object().cloned()) {
        for v in o.values() {
            rx += v["rx"].as_u64().unwrap_or(0);
            tx += v["tx"].as_u64().unwrap_or(0);
        }
    }
    Some((online, rx, tx))
}

/// entry: is the client connected? (its log says "connected to server" after the last failure)
fn entry_state(unit: &str) -> (bool, String) {
    let (_, log) = sh(&format!("journalctl -u {}.service -n 200 --no-pager -o cat 2>/dev/null", unit));
    let lines: Vec<&str> = log.lines().collect();
    let last_ok = lines.iter().rposition(|l| l.contains("connected to server"));
    let last_bad = lines.iter().rposition(|l| l.contains("FATAL") || l.contains("failed to initialize client") || l.contains("Started Kanki") || l.contains("connect error"));
    let up = match (last_ok, last_bad) {
        (Some(a), Some(b)) => a > b,
        (Some(_), None) => true,
        _ => false,
    };
    let err = if up {
        String::new()
    } else {
        lines.iter().rev().find(|l| l.contains("FATAL") || l.contains("ERROR")).map(|l| l.chars().take(300).collect()).unwrap_or_default()
    };
    (up, err)
}

pub fn statuses() -> Vec<super::engine::Status> {
    let (want, errors, since) = {
        let s = guard();
        (s.want.clone(), s.errors.clone(), s.since.clone())
    };
    let mut out = vec![];
    for w in want {
        let u = w.unit();
        let mut e = errors.get(&u).cloned().unwrap_or_default();
        let is_active = active(&u);
        let (links, rx, tx) = if !is_active {
            if e.is_empty() {
                e = "the Hysteria2 service is not running".into();
            }
            (0, 0, 0)
        } else if w.role == "exit" {
            match exit_stats(&w) {
                Some((n, rx, tx)) => {
                    if n == 0 && e.is_empty() {
                        e = "listening, waiting for the entry to connect".into();
                    }
                    (if n > 0 { 1 } else { 0 }, rx, tx)
                }
                None => (1, 0, 0),
            }
        } else {
            let (up, le) = entry_state(&u);
            if !up && e.is_empty() {
                e = if le.is_empty() { "connecting to the exit ...".into() } else { le };
            }
            if up && !w.src_routes.is_empty() && !sh(&format!("ip link show {} >/dev/null 2>&1", w.tun())).0 {
                e = "connected, but the TUN interface is missing".into();
            }
            (if up { 1 } else { 0 }, 0, 0)
        };
        out.push(super::engine::Status {
            id: w.tid.clone(),
            role: w.role.clone(),
            links,
            want: 1,
            rtt_ms: 0,
            rx_bytes: rx,
            tx_bytes: tx,
            streams: 0,
            udp_flows: 0,
            error: if links > 0 && w.role == "exit" { String::new() } else { e },
            since: if links > 0 { since.get(&u).cloned().unwrap_or(0) } else { 0 },
            transport: "hy2".into(),
            listening: w.role == "exit",
            probe: None,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(role: &str) -> Hy2Spec {
        Hy2Spec {
            tid: "abcdef1234".into(),
            name: "t".into(),
            role: role.into(),
            listen: 8443,
            server: "1.2.3.4:8443".into(),
            auth: "pw".into(),
            obfs: "ob".into(),
            pin: "aa".into(),
            sni: "www.bing.com".into(),
            fwd_tcp: vec!["443".into(), "8080:80".into()],
            fwd_udp: vec!["51820".into()],
            src_routes: vec!["10.8.0.0/24".into()],
            n: 3,
            mtu: 1400,
            stats_port: 37003,
            stats_secret: "s".into(),
            ..Default::default()
        }
    }

    #[test]
    fn client_config_has_forwards_and_tun() {
        let c = render(&spec("entry"));
        assert!(c.contains("server: \"1.2.3.4:8443\""));
        assert!(c.contains("pinSHA256: \"aa\""));
        assert!(c.contains("salamander"));
        assert!(c.contains("listen: 0.0.0.0:8080\n    remote: \"127.0.0.1:80\""));
        assert!(c.contains("udpForwarding:\n  - listen: 0.0.0.0:51820"));
        assert!(c.contains("name: \"khyabcdef1234\""));
        assert!(!c.contains("route:"), "Hysteria must not add routes by itself");
    }

    #[test]
    fn server_config_has_tls_auth_and_stats() {
        let c = render(&spec("exit"));
        assert!(c.contains("listen: :8443"));
        assert!(c.contains("type: password"));
        assert!(c.contains("trafficStats:\n  listen: 127.0.0.1:37003"));
        assert!(!c.contains("tcpForwarding"));
    }

    #[test]
    fn route_script_only_touches_listed_sources() {
        let up = route_script(&spec("entry"), true);
        assert!(up.contains("ip rule add from 10.8.0.0/24 table 21003"));
        assert!(up.contains("ip route replace default dev khyabcdef1234 table 21003"));
        let down = route_script(&spec("entry"), false);
        assert!(!down.contains("ip rule add"));
    }

    #[test]
    fn cert_pin_is_sha256_hex() {
        let (c, k, p) = gen_cert("www.bing.com").unwrap();
        assert!(c.contains("BEGIN CERTIFICATE") && k.contains("PRIVATE KEY"));
        assert_eq!(p.len(), 64);
    }

    #[test]
    fn hosts_and_urls_are_cleaned() {
        assert_eq!(clean_host(" www.bing.com\"; rm "), "www.bing.comrm");
        assert_eq!(clean_url("https://www.bing.com/x"), "https://www.bing.com/");
        assert_eq!(clean_url("http://a.com"), "");
    }
}
