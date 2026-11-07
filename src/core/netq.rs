//! Low-latency network settings of every Kanki server (panel, VPN node, tunnel agent).
//!
//! Games care less about the raw ping than about the ping staying flat. On a busy server the
//! game's small UDP packets wait behind other people's downloads in the network card's queue
//! (bufferbloat): the ping jumps from 60 to 150 ms for a moment. These settings keep the queues
//! short and fair, so a small packet never waits long:
//!
//! * `fq` on the outgoing card: every flow gets its own queue and a flow that sends little (a game,
//!   a tunnel ping) goes ahead of a flow that sends a lot (a download).
//! * BBR for TCP, and TCP keeps only a small backlog of unsent data in the kernel
//!   (`tcp_notsent_lowat`), so the TCP tunnels do not build their own queue.
//! * bigger default UDP socket buffers: a burst is not dropped before the tunnel reads it.
//!
//! Applied once at start (every server restarts with the nightly update), written to
//! `/etc/sysctl.d/91-kanki-game.conf` so a reboot keeps them. Nothing here opens a port or changes a
//! firewall rule. Each step that fails is skipped and logged; it never stops the program.
//! `KANKI_NETQ=off` in the environment turns all of it off.

use std::process::{Command, Stdio};

pub const CONF: &str = "/etc/sysctl.d/91-kanki-game.conf";

/// The kernel settings (key, value). BBR is added only when the kernel has it.
const SETTINGS: &[(&str, &str)] = &[
    ("net.core.default_qdisc", "fq"),
    ("net.core.rmem_max", "16777216"),
    ("net.core.wmem_max", "16777216"),
    // UDP sockets (the game tunnels, WireGuard, Hysteria) start with 1 MB instead of ~200 KB
    ("net.core.rmem_default", "1048576"),
    ("net.core.wmem_default", "1048576"),
    ("net.ipv4.udp_rmem_min", "16384"),
    ("net.ipv4.udp_wmem_min", "16384"),
    // packets that arrive faster than the CPU takes them wait here instead of being dropped
    ("net.core.netdev_max_backlog", "8192"),
    // TCP keeps at most 128 KB unsent in the kernel: less queueing inside the TCP tunnels
    ("net.ipv4.tcp_notsent_lowat", "131072"),
    // a link that was quiet for a moment starts again at full speed
    ("net.ipv4.tcp_slow_start_after_idle", "0"),
    // finds a working packet size when a path drops big packets silently
    ("net.ipv4.tcp_mtu_probing", "1"),
];

fn proc_path(key: &str) -> String {
    format!("/proc/sys/{}", key.replace('.', "/"))
}

fn quiet(cmd: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(cmd).args(args).stdin(Stdio::null()).stderr(Stdio::null()).output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn bbr_available() -> bool {
    let has = || std::fs::read_to_string("/proc/sys/net/ipv4/tcp_available_congestion_control").map(|s| s.split_whitespace().any(|c| c == "bbr")).unwrap_or(false);
    if has() {
        return true;
    }
    let _ = Command::new("modprobe").arg("tcp_bbr").stdin(Stdio::null()).stderr(Stdio::null()).status();
    has()
}

/// What the settings file says (the order of `SETTINGS`, then BBR)
pub fn conf_text(bbr: bool) -> String {
    let mut s = String::from("# Kanki: short, fair network queues for games (written by kanki-panel; do not edit)\n");
    for (k, v) in SETTINGS {
        s.push_str(&format!("{} = {}\n", k, v));
    }
    if bbr {
        s.push_str("net.ipv4.tcp_congestion_control = bbr\n");
    }
    s
}

/// The `tc` commands that put `fq` on a card whose queues are still the old first-come-first-served
/// `pfifo_fast` (`tc qdisc show` output in, argument lists out). A card already on fq, fq_codel or
/// cake, and a virtual card with no queue, are left alone. A multi-queue card (`mq`) keeps `mq`;
/// only its sub-queues change.
pub fn qdisc_fixes(dev: &str, show: &str) -> Vec<Vec<String>> {
    let mut out = Vec::new();
    for line in show.lines() {
        let w: Vec<&str> = line.split_whitespace().collect();
        if w.len() < 2 || w[0] != "qdisc" || !(w[1] == "pfifo_fast" || w[1] == "pfifo") {
            continue;
        }
        if w.contains(&"root") {
            out.push(vec!["qdisc".into(), "replace".into(), "dev".into(), dev.into(), "root".into(), "fq".into()]);
            // the root holds every queue: nothing more to do
            return out;
        }
        if let Some(i) = w.iter().position(|x| *x == "parent") {
            if let Some(p) = w.get(i + 1) {
                out.push(vec!["qdisc".into(), "replace".into(), "dev".into(), dev.into(), "parent".into(), p.to_string(), "fq".into()]);
            }
        }
    }
    out
}

/// The card the default route leaves through ("dev X" of `ip route show default`)
pub fn default_dev(routes: &str) -> Option<String> {
    let w: Vec<&str> = routes.split_whitespace().collect();
    let i = w.iter().position(|x| *x == "dev")?;
    w.get(i + 1).map(|s| s.to_string())
}

/// Applies everything (blocking; call from `spawn_blocking`). Only as root on Linux.
pub fn apply() {
    if std::env::var("KANKI_NETQ").map(|v| v == "off" || v == "0").unwrap_or(false) {
        return;
    }
    if !cfg!(target_os = "linux") || unsafe { libc::geteuid() } != 0 {
        return;
    }
    let bbr = bbr_available();
    let mut set = 0;
    let all = SETTINGS.iter().copied().chain(if bbr { Some(("net.ipv4.tcp_congestion_control", "bbr")) } else { None });
    for (k, v) in all {
        let p = proc_path(k);
        let Ok(cur) = std::fs::read_to_string(&p) else { continue };
        if cur.trim() == v {
            continue;
        }
        if std::fs::write(&p, v).is_ok() {
            set += 1;
        } else {
            eprintln!("netq: could not set {}", k);
        }
    }
    let text = conf_text(bbr);
    if std::fs::read_to_string(CONF).ok().as_deref() != Some(text.as_str()) {
        if let Err(e) = std::fs::write(CONF, &text) {
            eprintln!("netq: could not write {}: {}", CONF, e);
        }
    }
    // default_qdisc only reaches cards created after it: the card that is already up gets fq here
    let mut fixed = 0;
    if let Some(dev) = quiet("ip", &["-o", "route", "show", "default"]).as_deref().and_then(default_dev) {
        if let Some(show) = quiet("tc", &["qdisc", "show", "dev", &dev]) {
            for args in qdisc_fixes(&dev, &show) {
                let a: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
                if quiet("tc", &a).is_some() {
                    fixed += 1;
                } else {
                    eprintln!("netq: could not put fq on {}", dev);
                }
            }
        }
    }
    if set > 0 || fixed > 0 {
        eprintln!("netq: low-latency network settings applied ({} kernel setting(s), {} queue(s))", set, fixed);
    }
}

/// Runs `apply` in the background (it shells out to `ip`/`tc`, so not on the async threads)
pub fn spawn() {
    tokio::task::spawn_blocking(apply);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_old_queues_get_fq() {
        let one = "qdisc pfifo_fast 0: root refcnt 2 bands 3 priomap 1 2 2 2 1 2 0 0 1 1 1 1 1 1 1 1\n";
        assert_eq!(qdisc_fixes("eth0", one), vec![vec!["qdisc", "replace", "dev", "eth0", "root", "fq"]]);
        let mq = "qdisc mq 0: root\nqdisc pfifo_fast 0: parent :2 bands 3\nqdisc pfifo_fast 0: parent :1 bands 3\n";
        let f = qdisc_fixes("ens3", mq);
        assert_eq!(f.len(), 2);
        assert_eq!(f[0], vec!["qdisc", "replace", "dev", "ens3", "parent", ":2", "fq"]);
        // already fair, or no queue at all: nothing to do
        for ok in ["qdisc fq 8001: root refcnt 2 limit 10000p", "qdisc mq 0: root\nqdisc fq 0: parent :1 limit 10000p", "qdisc fq_codel 0: root", "qdisc cake 8001: root", "qdisc noqueue 0: root refcnt 2", ""] {
            assert!(qdisc_fixes("eth0", ok).is_empty(), "{}", ok);
        }
    }

    #[test]
    fn default_card_and_conf() {
        assert_eq!(default_dev("default via 10.0.0.1 dev ens3 proto dhcp src 10.0.0.5 metric 100").as_deref(), Some("ens3"));
        assert_eq!(default_dev(""), None);
        let c = conf_text(true);
        assert!(c.contains("net.core.default_qdisc = fq\n") && c.ends_with("net.ipv4.tcp_congestion_control = bbr\n"));
        assert!(!conf_text(false).contains("bbr"));
        // never touches forwarding or the firewall
        assert!(!c.contains("forward") && !c.contains("rp_filter"));
    }
}
