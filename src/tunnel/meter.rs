//! The live ping, loss and jitter of the tunnels that are not Kanki's own engine (3.63.0): KANKI-UP
//! (udp2raw), Hysteria2, AmneziaWG and the direct NAT / GRE tunnels. The Kanki engine measures inside its
//! own links (`engine::quality_task`); these run as other programs or in the kernel, so they are measured
//! from outside, the closest way to what a game feels:
//!
//! - `Target::Udp`: 20 packets of 64 bytes, 50 ms apart, through the tunnel itself to an echo on the exit
//!   (KANKI-UP through a small udp2raw pair of its own, Hysteria2 through a UDP forward of its own) and back;
//! - `Target::Ping`: 10 ICMP pings, 0.2 s apart (AmneziaWG through the link's inner address, GRE likewise,
//!   NAT and ICMP-mode KANKI-UP to the other server: the same line the packets take).
//!
//! Once a minute per tunnel, one tunnel after the other on a thread of its own: about 1.3 KB each way.
//! The result has the shape of `probe::summarize` ({n, loss, ping, jit, max, at}), so the panel, the
//! tunnel list and the bot's path report read it as they read the engine's.

use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};
use std::process::{Command, Stdio};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// how often each tunnel is measured
const EVERY: Duration = Duration::from_secs(60);
/// packets of one UDP run
const N: u64 = 20;

#[derive(Clone, Debug, PartialEq)]
pub enum Target {
    /// an echo reachable through the tunnel (a local address of this server)
    Udp(SocketAddr),
    /// ICMP to an address (only letters, digits, dots and colons)
    Ping(String),
}

#[derive(Default)]
struct State {
    /// owner ("kup", "hy2", "awg", "fwd") -> tunnel id -> what to measure
    targets: HashMap<String, HashMap<String, Target>>,
    /// tunnel id -> last result
    results: HashMap<String, Value>,
    /// tunnel id -> when it was measured last
    last: HashMap<String, Instant>,
}

fn state() -> std::sync::MutexGuard<'static, State> {
    static S: OnceLock<Mutex<State>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(State::default())).lock().unwrap_or_else(|e| e.into_inner())
}

/// The tunnels one owner wants measured now (the list replaces the owner's last one)
pub fn set_targets(owner: &str, list: Vec<(String, Target)>) {
    let list: HashMap<String, Target> = list.into_iter().filter(|(_, t)| target_ok(t)).collect();
    {
        let mut s = state();
        let gone: Vec<String> = s.targets.get(owner).map(|m| m.keys().filter(|k| !list.contains_key(*k)).cloned().collect()).unwrap_or_default();
        for k in gone {
            s.results.remove(&k);
            s.last.remove(&k);
        }
        s.targets.insert(owner.to_string(), list);
    }
    start();
}

/// The last measurement of a tunnel, if it is fresh (3 minutes)
pub fn get(tid: &str) -> Option<Value> {
    let now = crate::util::now();
    state().results.get(tid).filter(|v| v["at"].as_i64().map(|a| now - a < 180).unwrap_or(false)).cloned()
}

/// The ping of a tunnel from its last measurement (0 = unknown or nothing came back)
pub fn rtt(tid: &str) -> u64 {
    get(tid).and_then(|v| if v["loss"].as_f64().unwrap_or(100.0) < 100.0 { v["ping"].as_u64() } else { None }).unwrap_or(0)
}

fn target_ok(t: &Target) -> bool {
    match t {
        Target::Udp(a) => a.ip().is_loopback() && a.port() > 0,
        Target::Ping(h) => !h.is_empty() && h.len() <= 64 && h.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == ':'),
    }
}

fn start() {
    static STARTED: OnceLock<()> = OnceLock::new();
    if STARTED.set(()).is_err() {
        return;
    }
    std::thread::spawn(|| {
        // spread the first runs a little after the agent starts
        std::thread::sleep(Duration::from_secs(10));
        loop {
            let due: Vec<(String, Target)> = {
                let s = state();
                s.targets
                    .values()
                    .flat_map(|m| m.iter())
                    .filter(|(k, _)| {
                        let every = if k.starts_with("probe-") && s.results.get(*k).map(|r| r["loss"].as_f64().unwrap_or(100.0) >= 100.0).unwrap_or(true) {
                            // a smart-test tunnel: again and again until it answers (its handshake may take a moment)
                            Duration::from_secs(4)
                        } else {
                            EVERY
                        };
                        s.last.get(*k).map(|t| t.elapsed() >= every).unwrap_or(true)
                    })
                    .map(|(k, t)| (k.clone(), t.clone()))
                    .collect()
            };
            for (tid, t) in due {
                let r = std::panic::catch_unwind(|| measure(&t)).ok().flatten();
                let mut s = state();
                // still wanted? (removed while it was being measured: dropped)
                if !s.targets.values().any(|m| m.get(&tid) == Some(&t)) {
                    continue;
                }
                s.last.insert(tid.clone(), Instant::now());
                match r {
                    Some(mut v) => {
                        v["at"] = json!(crate::util::now());
                        s.results.insert(tid, v);
                    }
                    None => {
                        s.results.remove(&tid);
                    }
                }
            }
            std::thread::sleep(Duration::from_secs(3));
        }
    });
}

fn measure(t: &Target) -> Option<Value> {
    match t {
        Target::Udp(a) => udp_series(*a),
        Target::Ping(h) => ping_series(h),
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// 20 packets of 64 bytes through the tunnel to the echo and back (seq and send time in the first 16 bytes)
pub fn udp_series(to: SocketAddr) -> Option<Value> {
    let sock = UdpSocket::bind("127.0.0.1:0").ok()?;
    sock.connect(to).ok()?;
    let start = now_ms();
    let mut got: Vec<Option<u64>> = vec![None; N as usize];
    let mut buf = [0u8; 256];
    let mut read = |sock: &UdpSocket, got: &mut Vec<Option<u64>>, until: Instant| {
        while Instant::now() < until {
            let left = until.saturating_duration_since(Instant::now()).max(Duration::from_millis(1));
            let _ = sock.set_read_timeout(Some(left));
            match sock.recv(&mut buf) {
                Ok(k) if k >= 16 => {
                    let i = u64::from_be_bytes(buf[0..8].try_into().unwrap_or([0; 8]));
                    let t0 = u64::from_be_bytes(buf[8..16].try_into().unwrap_or([0; 8]));
                    if t0 >= start && i < N && got[i as usize].is_none() {
                        got[i as usize] = Some(now_ms().saturating_sub(t0));
                    }
                }
                Ok(_) => {}
                // nothing (yet), or the local udp2raw / hysteria is not there: keep waiting until the end
                Err(_) => std::thread::sleep(Duration::from_millis(2)),
            }
        }
    };
    for i in 0..N {
        let mut p = [0u8; 64];
        p[0..8].copy_from_slice(&i.to_be_bytes());
        p[8..16].copy_from_slice(&now_ms().to_be_bytes());
        let _ = sock.send(&p);
        read(&sock, &mut got, Instant::now() + Duration::from_millis(50));
    }
    read(&sock, &mut got, Instant::now() + Duration::from_millis(super::probe::LATE_MS));
    Some(super::probe::summarize(&got))
}

/// 10 ICMP pings 0.2 s apart; the same shape as a UDP run
pub fn ping_series(host: &str) -> Option<Value> {
    let o = Command::new("ping").args(["-n", "-q", "-c", "10", "-i", "0.2", "-W", "1", host]).stdin(Stdio::null()).output().ok()?;
    parse_ping(&String::from_utf8_lossy(&o.stdout))
}

/// `ping -q` summary → {n, loss, ping, jit, max} (jit = mdev)
pub fn parse_ping(out: &str) -> Option<Value> {
    let line = out.lines().find(|l| l.contains("packets transmitted"))?;
    let sent: u64 = line.split_whitespace().next()?.parse().ok()?;
    let loss: f64 = line.split(',').find(|p| p.contains("packet loss"))?.trim().split('%').next()?.trim().parse().ok()?;
    let (avg, max, mdev) = match out.lines().find(|l| l.contains("min/avg/max")) {
        Some(l) => {
            let v: Vec<f64> = l.split('=').nth(1)?.trim().split(' ').next()?.split('/').filter_map(|x| x.parse().ok()).collect();
            (v.get(1).copied().unwrap_or(0.0), v.get(2).copied().unwrap_or(0.0), v.get(3).copied().unwrap_or(0.0))
        }
        None => (0.0, 0.0, 0.0),
    };
    Some(json!({ "n": sent, "loss": (loss * 10.0).round() / 10.0, "ping": avg.round() as u64, "jit": (mdev * 10.0).round() / 10.0, "max": max.round() as u64 }))
}

// ------------------------------------------------------------------ the echo on the exit

fn echoes() -> std::sync::MutexGuard<'static, HashMap<u16, ()>> {
    static E: OnceLock<Mutex<HashMap<u16, ()>>> = OnceLock::new();
    E.get_or_init(|| Mutex::new(HashMap::new())).lock().unwrap_or_else(|e| e.into_inner())
}

fn serve_echo(sock: UdpSocket) {
    std::thread::spawn(move || {
        let mut buf = [0u8; 512];
        loop {
            if let Ok((k, from)) = sock.recv_from(&mut buf) {
                // only the measuring packets: small, from this machine (udp2raw / hysteria on loopback)
                if k >= 16 && k <= 256 && from.ip().is_loopback() {
                    let _ = sock.send_to(&buf[..k], from);
                }
            }
        }
    });
}

/// An echo on 127.0.0.1:`port` (Hysteria2: the port the panel gave the tunnel); false when it cannot listen
pub fn echo_on(port: u16) -> bool {
    if port == 0 {
        return false;
    }
    let mut e = echoes();
    if e.contains_key(&port) {
        return true;
    }
    match UdpSocket::bind(("127.0.0.1", port)) {
        Ok(s) => {
            serve_echo(s);
            e.insert(port, ());
            true
        }
        Err(_) => false,
    }
}

/// One echo on a free port of 127.0.0.1 for this agent (KANKI-UP's measuring pairs end there)
pub fn echo_any() -> u16 {
    static P: OnceLock<u16> = OnceLock::new();
    *P.get_or_init(|| match UdpSocket::bind("127.0.0.1:0") {
        Ok(s) => {
            let p = s.local_addr().map(|a| a.port()).unwrap_or(0);
            serve_echo(s);
            p
        }
        Err(_) => 0,
    })
}

/// A free UDP port of 127.0.0.1 right now (a local end of a measuring pair)
pub fn free_local_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0").ok().and_then(|s| s.local_addr().ok()).map(|a| a.port()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_ping_summary_is_read() {
        let ok = "--- 1.2.3.4 ping statistics ---\n10 packets transmitted, 9 received, 10% packet loss, time 1810ms\nrtt min/avg/max/mdev = 40.1/42.3/48.0/1.25 ms\n";
        let v = parse_ping(ok).unwrap();
        assert_eq!((v["n"].as_u64(), v["loss"].as_f64(), v["ping"].as_u64(), v["jit"].as_f64(), v["max"].as_u64()), (Some(10), Some(10.0), Some(42), Some(1.3), Some(48)));
        let dead = "10 packets transmitted, 0 received, 100% packet loss, time 9000ms\n";
        assert_eq!(parse_ping(dead).unwrap()["loss"].as_f64(), Some(100.0));
        assert!(parse_ping("ping: unknown host").is_none());
    }

    #[test]
    fn a_udp_run_through_an_echo_has_no_loss() {
        let p = echo_any();
        assert!(p > 0);
        let v = udp_series(SocketAddr::from(([127, 0, 0, 1], p))).unwrap();
        assert_eq!(v["n"].as_u64(), Some(20));
        assert_eq!(v["loss"].as_f64(), Some(0.0), "{}", v);
        // nothing listening: all lost, not an error
        let free = free_local_port();
        let v = udp_series(SocketAddr::from(([127, 0, 0, 1], free))).unwrap();
        assert_eq!(v["loss"].as_f64(), Some(100.0));
    }

    #[test]
    fn only_local_echoes_and_plain_hosts_are_measured() {
        assert!(target_ok(&Target::Udp("127.0.0.1:4000".parse().unwrap())));
        assert!(!target_ok(&Target::Udp("8.8.8.8:53".parse().unwrap())));
        assert!(target_ok(&Target::Ping("10.89.1.2".into())));
        assert!(!target_ok(&Target::Ping("1.2.3.4; reboot".into())));
        assert!(!target_ok(&Target::Ping("-f".into())));
    }
}
