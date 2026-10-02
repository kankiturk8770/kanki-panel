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
    let (t, i) = tool(proto);
    let mut m = HashMap::new();
    if let Some(out) = run(t, &["show", i, "dump"], None) {
        for line in out.lines().skip(1) {
            let f: Vec<&str> = line.split('\t').collect();
            if f.len() >= 7 {
                m.insert(
                    f[0].to_string(),
                    PeerStat {
                        handshake: f[4].parse().unwrap_or(0),
                        rx: f[5].parse().unwrap_or(0),
                        tx: f[6].parse().unwrap_or(0),
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
        let path = format!("/tmp/kanki-psk-{}", crate::util::rand_token(8));
        if std::fs::write(&path, &p.psk).is_ok() {
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
