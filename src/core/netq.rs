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
    journal_cap();
}

/// (3.58.1) The system log may not fill a small disk: journald keeps at most 200 MB (a 1 GB journal was seen
/// on a 1-core server). Written once; journald is told only when the file changed.
pub const JOURNAL_CONF: &str = "/etc/systemd/journald.conf.d/90-kanki.conf";
pub const JOURNAL_TEXT: &str = "# written by kanki-panel: the system log stays small\n[Journal]\nSystemMaxUse=200M\nRuntimeMaxUse=50M\n";

fn journal_cap() {
    if !std::path::Path::new("/etc/systemd").is_dir() {
        return;
    }
    if std::fs::read_to_string(JOURNAL_CONF).ok().as_deref() == Some(JOURNAL_TEXT) {
        return;
    }
    let _ = std::fs::create_dir_all("/etc/systemd/journald.conf.d");
    if std::fs::write(JOURNAL_CONF, JOURNAL_TEXT).is_err() {
        eprintln!("netq: could not write {}", JOURNAL_CONF);
        return;
    }
    let _ = quiet("systemctl", &["restart", "systemd-journald"]);
    // the old log above the new cap goes now, not only when it rotates
    let _ = quiet("journalctl", &["--vacuum-size=200M"]);
}

/// Runs `apply` in the background (it shells out to `ip`/`tc`, so not on the async threads)
pub fn spawn() {
    tokio::task::spawn_blocking(apply);
}

// ------------------------------------------------------------------ the game mark
// KANKI MIX tells its game datagrams from KCP (the app's TCP) and sends the game packets with DSCP EF; a
// Game-FEC Pro tunnel on the same server reads the mark (`recv_tos`) and gives repairs to those packets only,
// so the users' TCP is never sent twice.

/// DSCP EF, the game mark
pub(crate) const GAME_TOS: i32 = 0xb8;
#[cfg(test)]
/// the kernel refused the mark once: packets go plain from then on
static MARK_BROKEN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);


/// Sends one packet, with the game mark when `game` (KANKI MIX does it in Go; the tests stand in for it)
#[cfg(test)]
pub(crate) fn send_to_marked(sock: &std::net::UdpSocket, pkt: &[u8], to: std::net::SocketAddr, game: bool) {
    if game && !MARK_BROKEN.load(std::sync::atomic::Ordering::Relaxed) {
        match send_marked(sock, pkt, to) {
            Ok(()) => return,
            Err(e) if matches!(e.raw_os_error(), Some(libc::EINVAL) | Some(libc::EOPNOTSUPP) | Some(libc::EPERM)) => MARK_BROKEN.store(true, std::sync::atomic::Ordering::Relaxed),
            Err(_) => {}
        }
    }
    let _ = sock.send_to(pkt, to);
}

#[cfg(test)]
/// sendmsg with IP_TOS (an IPv4 destination, also on a dual-stack socket) or IPV6_TCLASS
fn send_marked(sock: &std::net::UdpSocket, pkt: &[u8], to: std::net::SocketAddr) -> std::io::Result<()> {
    use std::net::IpAddr;
    use std::os::fd::AsRawFd;
    let v4 = match to {
        std::net::SocketAddr::V4(_) => true,
        std::net::SocketAddr::V6(a) => a.ip().to_ipv4_mapped().is_some(),
    };
    let local_v6 = sock.local_addr().map(|a| a.is_ipv6()).unwrap_or(false);
    // the destination as the socket's own family
    let sa: socket2::SockAddr = match (to, local_v6) {
        (std::net::SocketAddr::V4(a), true) => std::net::SocketAddr::new(IpAddr::V6(a.ip().to_ipv6_mapped()), a.port()).into(),
        _ => to.into(),
    };
    let (level, typ) = if v4 { (libc::IPPROTO_IP, libc::IP_TOS) } else { (libc::IPPROTO_IPV6, libc::IPV6_TCLASS) };
    // SAFETY: CMSG_SPACE of one int is a constant
    let space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::c_int>() as u32) } as usize;
    let mut ctl = vec![0u8; space];
    let mut iov = libc::iovec { iov_base: pkt.as_ptr() as *mut libc::c_void, iov_len: pkt.len() };
    // SAFETY: msghdr is plain data; every pointer below lives until sendmsg returns
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = sa.as_ptr() as *mut libc::c_void;
    msg.msg_namelen = sa.len();
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = ctl.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = space as _;
    // SAFETY: the control buffer holds exactly one cmsg of one int (CMSG_SPACE above)
    unsafe {
        let c = libc::CMSG_FIRSTHDR(&msg);
        (*c).cmsg_level = level;
        (*c).cmsg_type = typ;
        (*c).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<libc::c_int>() as u32) as _;
        std::ptr::write_unaligned(libc::CMSG_DATA(c) as *mut libc::c_int, GAME_TOS);
    }
    // SAFETY: a valid socket and a filled msghdr
    let r = unsafe { libc::sendmsg(sock.as_raw_fd(), &msg, 0) };
    if r < 0 { Err(std::io::Error::last_os_error()) } else { Ok(()) }
}

/// Asks the kernel for the TOS / traffic class of every packet this socket receives
pub(crate) fn want_tos(fd: std::os::fd::RawFd) {
    let one: libc::c_int = 1;
    for (level, opt) in [(libc::IPPROTO_IP, libc::IP_RECVTOS), (libc::IPPROTO_IPV6, libc::IPV6_RECVTCLASS)] {
        // SAFETY: an int option on a socket the caller owns; a failure (the other family) is fine
        unsafe { libc::setsockopt(fd, level, opt, &one as *const _ as *const libc::c_void, std::mem::size_of::<libc::c_int>() as u32) };
    }
}

/// One datagram from a connected socket and its TOS (None = the kernel gave none). Non-blocking: WouldBlock
/// when nothing is waiting.
pub(crate) fn recv_tos(fd: std::os::fd::RawFd, buf: &mut [u8]) -> std::io::Result<(usize, Option<u8>)> {
    let mut ctl = [0u64; 16];
    let mut iov = libc::iovec { iov_base: buf.as_mut_ptr() as *mut libc::c_void, iov_len: buf.len() };
    // SAFETY: plain data; the pointers live until recvmsg returns
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = ctl.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = std::mem::size_of_val(&ctl) as _;
    // SAFETY: a valid socket and a filled msghdr
    let n = unsafe { libc::recvmsg(fd, &mut msg, libc::MSG_DONTWAIT) };
    if n < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut tos = None;
    // SAFETY: walking the control messages the kernel wrote into ctl
    unsafe {
        let mut c = libc::CMSG_FIRSTHDR(&msg);
        while !c.is_null() {
            let (l, t) = ((*c).cmsg_level, (*c).cmsg_type);
            if (l == libc::IPPROTO_IP && t == libc::IP_TOS) || (l == libc::IPPROTO_IPV6 && t == libc::IPV6_TCLASS) {
                let d = libc::CMSG_DATA(c);
                // IP_TOS comes as one byte, IPV6_TCLASS as an int
                tos = Some(if l == libc::IPPROTO_IP { *d } else { std::ptr::read_unaligned(d as *const libc::c_int) as u8 });
            }
            c = libc::CMSG_NXTHDR(&msg, c);
        }
    }
    Ok((n as usize, tos))
}

/// The packet carries the game mark (the DSCP part of the TOS byte)
pub(crate) fn is_game_tos(tos: u8) -> bool {
    tos & 0xfc == GAME_TOS as u8
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

    /// A game packet leaves marked, another one plain; the receiver reads the mark of each
    #[test]
    fn the_game_mark_goes_through() {
        use std::os::fd::AsRawFd;
        let rx = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        want_tos(rx.as_raw_fd());
        let tx = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let to = rx.local_addr().unwrap();
        send_to_marked(&tx, b"game", to, true);
        send_to_marked(&tx, b"tcp", to, false);
        rx.set_read_timeout(Some(std::time::Duration::from_secs(2))).unwrap();
        let mut b = [0u8; 64];
        let mut got = vec![];
        while got.len() < 2 {
            match recv_tos(rx.as_raw_fd(), &mut b) {
                Ok((n, tos)) => got.push((b[..n].to_vec(), tos)),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => std::thread::sleep(std::time::Duration::from_millis(5)),
                Err(e) => panic!("{}", e),
            }
        }
        assert_eq!(got[0], (b"game".to_vec(), Some(0xb8)));
        assert_eq!(got[1], (b"tcp".to_vec(), Some(0)));
        assert!(is_game_tos(0xb8) && is_game_tos(0xb9) && !is_game_tos(0));
    }
}
