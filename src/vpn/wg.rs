//! کنترل WireGuard و AmneziaWG با ابزارهای wg/awg
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Write;
use std::process::{Command, Stdio};

pub const WG_IF: &str = "wg0";
pub const AWG_IF: &str = "awg0";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerSpec {
    pub pubkey: String,
    pub psk: String,
    pub ip: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PeerStat {
    pub rx: i64,
    pub tx: i64,
    pub handshake: i64,
    /// the addresses this key was used from in the last minute, oldest first (an older node sends none)
    #[serde(default)]
    pub eps: Vec<Ep>,
    /// how many times the key's address changed in the last minute: one device that changes network
    /// changes it once, two devices with the same config keep taking it from each other
    #[serde(default)]
    pub flips: u32,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct Ep {
    pub at: String,
    pub first: i64,
    pub last: i64,
}

#[derive(Default)]
struct Track {
    eps: Vec<Ep>,
    cur: String,
    flips: std::collections::VecDeque<i64>,
}

fn tracks() -> &'static std::sync::Mutex<HashMap<(String, String), Track>> {
    static T: std::sync::OnceLock<std::sync::Mutex<HashMap<(String, String), Track>>> = std::sync::OnceLock::new();
    T.get_or_init(Default::default)
}

/// Every 2 seconds: from which address each key sends (`wg show <if> endpoints`)
fn start_sampler() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        std::thread::spawn(|| loop {
            for proto in ["wg", "awg"] {
                if !available(proto) {
                    continue;
                }
                let (t, i) = tool(proto);
                let out = run(t, &["show", i, "endpoints"], None).unwrap_or_default();
                note_endpoints(proto, &out, crate::util::now());
            }
            std::thread::sleep(std::time::Duration::from_secs(2));
        });
    });
}

fn note_endpoints(proto: &str, out: &str, now: i64) {
    let mut tr = tracks().lock().unwrap_or_else(|e| e.into_inner());
    for line in out.lines() {
        let Some((k, at)) = line.split_once('\t') else { continue };
        if at.trim().is_empty() || at.contains("(none)") {
            continue;
        }
        let t = tr.entry((proto.to_string(), k.to_string())).or_default();
        let at = at.trim().to_string();
        if t.cur != at {
            if !t.cur.is_empty() {
                t.flips.push_back(now);
            }
            t.cur = at.clone();
        }
        match t.eps.iter_mut().find(|e| e.at == at) {
            Some(e) => e.last = now,
            None => t.eps.push(Ep { at, first: now, last: now }),
        }
        t.eps.retain(|e| now - e.last < 60);
        while t.flips.front().is_some_and(|f| now - f >= 60) {
            t.flips.pop_front();
        }
    }
    tr.retain(|_, t| t.eps.iter().any(|e| now - e.last < 60));
}

/// Addresses blocked by the connection limit (extra devices on one config): "proto address"
pub fn set_blocked(list: &[String]) {
    static LAST: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());
    let mut want: Vec<String> = list.iter().filter(|x| block_rule(x).is_some()).cloned().collect();
    want.sort();
    let mut last = LAST.lock().unwrap_or_else(|e| e.into_inner());
    if *last == want {
        return;
    }
    const CH: &str = "KANKI-LIMIT";
    for t in ["iptables", "ip6tables"] {
        let sh = |a: &str| Command::new("sh").arg("-c").arg(format!("{} -w {} 2>/dev/null", t, a)).status().map(|s| s.success()).unwrap_or(false);
        let _ = sh(&format!("-N {}", CH));
        let _ = sh(&format!("-F {}", CH));
        if !sh(&format!("-C INPUT -p udp -j {}", CH)) {
            let _ = sh(&format!("-I INPUT -p udp -j {}", CH));
        }
    }
    for x in &want {
        if let Some((t, rule)) = block_rule(x) {
            let _ = Command::new("sh").arg("-c").arg(format!("{} -w -A {} {} -j DROP 2>/dev/null", t, CH, rule)).status();
        }
    }
    *last = want;
}

/// "wg 1.2.3.4:5678" -> (iptables, "-p udp -s 1.2.3.4 --sport 5678 --dport <port of wg>")
fn block_rule(x: &str) -> Option<(&'static str, String)> {
    let (proto, at) = x.split_once(' ')?;
    if proto != "wg" && proto != "awg" {
        return None;
    }
    let sa: std::net::SocketAddr = at.parse().ok()?;
    let port: u16 = listen_port(proto).trim().parse().ok()?;
    let t = if sa.is_ipv6() { "ip6tables" } else { "iptables" };
    Some((t, format!("-p udp -s {} --sport {} --dport {}", sa.ip(), sa.port(), port)))
}

fn run(cmd: &str, args: &[&str], stdin: Option<&str>) -> Option<String> {
    let mut c = Command::new(cmd);
    c.args(args).stdout(Stdio::piped()).stderr(Stdio::null());
    if stdin.is_some() {
        c.stdin(Stdio::piped());
    }
    let mut ch = c.spawn().ok()?;
    if let Some(s) = stdin {
        if let Some(mut i) = ch.stdin.take() {
            let _ = i.write_all(s.as_bytes());
        }
    }
    let out = ch.wait_with_output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

pub fn genkey() -> Option<(String, String)> {
    let p = run("wg", &["genkey"], None)?;
    let pubk = run("wg", &["pubkey"], Some(&p))?;
    Some((p, pubk))
}

pub fn genpsk() -> Option<String> {
    run("wg", &["genpsk"], None)
}

fn tool(proto: &str) -> (&'static str, &'static str) {
    if proto == "awg" {
        ("awg", AWG_IF)
    } else {
        ("wg", WG_IF)
    }
}

/// اینترفیس روشن است؟
pub fn available(proto: &str) -> bool {
    let (t, i) = tool(proto);
    run(t, &["show", i, "public-key"], None).is_some()
}

pub fn iface_pub(proto: &str) -> String {
    let (t, i) = tool(proto);
    run(t, &["show", i, "public-key"], None).unwrap_or_default()
}

pub fn listen_port(proto: &str) -> String {
    let (t, i) = tool(proto);
    run(t, &["show", i, "listen-port"], None).unwrap_or_default()
}

/// آمار پیرها: کلید عمومی ← (rx, tx, آخرین هندشیک)
pub fn dump(proto: &str) -> HashMap<String, PeerStat> {
    start_sampler();
    let (t, i) = tool(proto);
    let mut m = HashMap::new();
    if let Some(out) = run(t, &["show", i, "dump"], None) {
        for line in out.lines().skip(1) {
            let f: Vec<&str> = line.split('\t').collect();
            if f.len() >= 7 {
                let (eps, flips) = tracks()
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .get(&(proto.to_string(), f[0].to_string()))
                    .map(|t| {
                        let mut e = t.eps.clone();
                        e.sort_by_key(|x| x.first);
                        (e, t.flips.len() as u32)
                    })
                    .unwrap_or_default();
                m.insert(
                    f[0].to_string(),
                    PeerStat {
                        handshake: f[4].parse().unwrap_or(0),
                        rx: f[5].parse().unwrap_or(0),
                        tx: f[6].parse().unwrap_or(0),
                        eps,
                        flips,
                    },
                );
            }
        }
    }
    m
}

/// پیرهای اینترفیس را دقیقاً برابر لیست خواسته‌شده می‌کند و آمار را برمی‌گرداند
pub fn apply(proto: &str, desired: &[PeerSpec]) -> HashMap<String, PeerStat> {
    if !available(proto) {
        return HashMap::new();
    }
    let (t, i) = tool(proto);
    let current = dump(proto);
    let want: HashMap<&str, &PeerSpec> = desired.iter().map(|p| (p.pubkey.as_str(), p)).collect();
    for k in current.keys() {
        if !want.contains_key(k.as_str()) {
            let _ = run(t, &["set", i, "peer", k.as_str(), "remove"], None);
        }
    }
    for p in desired {
        if current.contains_key(&p.pubkey) {
            continue;
        }
        // the key file is created for the owner only (0600) and never overwrites an existing file
        let path = format!("/tmp/kanki-psk-{}", crate::util::rand_token(16));
        let wrote = {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .and_then(|mut f| f.write_all(p.psk.as_bytes()))
                .is_ok()
        };
        if wrote {
            let allowed = format!("{}/32", p.ip);
            let _ = run(t, &["set", i, "peer", p.pubkey.as_str(), "preshared-key", path.as_str(), "allowed-ips", allowed.as_str()], None);
            let _ = std::fs::remove_file(&path);
        }
    }
    dump(proto)
}

/// پارامترهای مخفی‌سازی AmneziaWG از فایل کانفیگ سرور
pub fn awg_params() -> Vec<(String, String)> {
    let keys = ["Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4", "I1", "I2", "I3", "I4", "I5"];
    let mut out = vec![];
    if let Ok(t) = std::fs::read_to_string("/etc/amnezia/amneziawg/awg0.conf") {
        for line in t.lines() {
            if let Some((k, v)) = line.split_once('=') {
                let k = k.trim();
                if keys.contains(&k) {
                    out.push((k.to_string(), v.trim().to_string()));
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod ep_tests {
    use super::*;

    #[test]
    fn two_devices_on_one_key_keep_changing_its_address() {
        let k = "KEYTEST2DEV";
        for (i, at) in ["1.1.1.1:1000", "2.2.2.2:2000", "1.1.1.1:1000", "2.2.2.2:2000"].iter().enumerate() {
            note_endpoints("wg", &format!("{}\t{}\n", k, at), 1000 + i as i64 * 2);
        }
        let tr = tracks().lock().unwrap();
        let t = tr.get(&("wg".to_string(), k.to_string())).unwrap();
        assert_eq!(t.eps.len(), 2);
        assert_eq!(t.flips.len(), 3);
    }

    #[test]
    fn a_blocked_address_is_a_firewall_rule_only_when_it_is_one() {
        assert!(block_rule("wg 1.2.3.4:5; rm -rf /").is_none());
        assert!(block_rule("xray 1.2.3.4:5").is_none());
    }
}
