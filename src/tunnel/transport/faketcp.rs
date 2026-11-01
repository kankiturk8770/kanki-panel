//! `faketcp`: UDP traffic inside fake TCP packets (the udp2raw idea), for networks that throttle,
//! cut or suspect UDP — on the wire there is only a normal-looking TCP session on one port.
//!
//! Both ends craft IP/TCP headers by hand over raw sockets (root / CAP_NET_RAW needed, which the
//! tunnel agents have). A fake three-way handshake (SYN, SYN-ACK, ACK) opens a "connection", then
//! every payload travels as a PSH-ACK segment with plausible sequence numbers. The payload itself
//! is masked with the same Salamander-style mask as `hq`/`kcp` (`salamander.rs`), so a DPI box
//! sees a TCP flow carrying random-looking bytes with no fixed pattern.
//!
//! The kernel knows nothing about these packets and would answer them with RST; like udp2raw we
//! drop our own outgoing RSTs for the fake port with one iptables rule (best effort — without it
//! the link still works, the RSTs just leak). KCP then runs over this channel through a private
//! loopback socket, exactly like the `kcp` transport runs over the UDP obfuscation relay.
//!
//! IPv4 only.

use super::link::{Bag, BoxIo, Inbox, Res};
use super::salamander::Mask;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::fd::RawFd;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;

/// a client that sent nothing for this long is forgotten
const PEER_IDLE: Duration = Duration::from_secs(90);
/// most clients one server channel serves at the same time
const MAX_PEERS: usize = 512;
/// largest payload in one fake segment (stays under a 1500-byte path MTU with headers)
const MAX_SEG: usize = 1300;

const FLAG_FIN: u8 = 0x01;
const FLAG_SYN: u8 = 0x02;
const FLAG_RST: u8 = 0x04;
const FLAG_PSH: u8 = 0x08;
const FLAG_ACK: u8 = 0x10;

// ------------------------------------------------------------------ packet crafting

fn checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn tcp_checksum(src: Ipv4Addr, dst: Ipv4Addr, tcp: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(12 + tcp.len() + 1);
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.push(0);
    pseudo.push(libc::IPPROTO_TCP as u8);
    pseudo.extend_from_slice(&(tcp.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(tcp);
    checksum(&pseudo)
}

/// Builds one IPv4 + TCP packet. IP total length and checksum are filled by the kernel
/// (IPPROTO_RAW implies IP_HDRINCL); the TCP checksum is ours.
fn build_packet(src: SocketAddrV4, dst: SocketAddrV4, seq: u32, ack: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
    let mut tcp = Vec::with_capacity(20 + payload.len());
    tcp.extend_from_slice(&src.port().to_be_bytes());
    tcp.extend_from_slice(&dst.port().to_be_bytes());
    tcp.extend_from_slice(&seq.to_be_bytes());
    tcp.extend_from_slice(&ack.to_be_bytes());
    tcp.push(5 << 4); // data offset: 5 x 32 bit
    tcp.push(flags);
    tcp.extend_from_slice(&65535u16.to_be_bytes()); // window
    tcp.extend_from_slice(&[0, 0]); // checksum (filled below)
    tcp.extend_from_slice(&[0, 0]); // urgent
    tcp.extend_from_slice(payload);
    let sum = tcp_checksum(*src.ip(), *dst.ip(), &tcp);
    tcp[16..18].copy_from_slice(&sum.to_be_bytes());
    let mut ip = Vec::with_capacity(20 + tcp.len());
    ip.push(0x45); // v4, 5 x 32 bit header
    ip.push(0); // dscp/ecn
    ip.extend_from_slice(&((20 + tcp.len()) as u16).to_be_bytes());
    ip.extend_from_slice(&rand::random::<u16>().to_be_bytes()); // id
    ip.extend_from_slice(&0x4000u16.to_be_bytes()); // don't fragment
    ip.push(64); // ttl
    ip.push(libc::IPPROTO_TCP as u8);
    ip.extend_from_slice(&[0, 0]); // ip checksum: the kernel fills it
    ip.extend_from_slice(&src.ip().octets());
    ip.extend_from_slice(&dst.ip().octets());
    ip.extend_from_slice(&tcp);
    ip
}

/// (src, dst, seq, ack, flags, payload)
type Packet<'a> = (SocketAddrV4, SocketAddrV4, u32, u32, u8, &'a [u8]);

/// Parses an IPv4 + TCP packet: (src, dst, seq, ack, flags, payload) or None.
fn parse_packet(b: &[u8]) -> Option<Packet<'_>> {
    if b.len() < 40 || b[0] >> 4 != 4 {
        return None;
    }
    let ihl = (b[0] & 0x0f) as usize * 4;
    if ihl < 20 || b.len() < ihl + 20 || b[9] != libc::IPPROTO_TCP as u8 {
        return None;
    }
    let total = u16::from_be_bytes([b[2], b[3]]) as usize;
    if total < ihl + 20 || b.len() < total {
        return None;
    }
    let src = Ipv4Addr::new(b[12], b[13], b[14], b[15]);
    let dst = Ipv4Addr::new(b[16], b[17], b[18], b[19]);
    let t = &b[ihl..total];
    let sport = u16::from_be_bytes([t[0], t[1]]);
    let dport = u16::from_be_bytes([t[2], t[3]]);
    let seq = u32::from_be_bytes([t[4], t[5], t[6], t[7]]);
    let ack = u32::from_be_bytes([t[8], t[9], t[10], t[11]]);
    let off = ((t[12] >> 4) as usize) * 4;
    if off < 20 || t.len() < off {
        return None;
    }
    let flags = t[13];
    Some((SocketAddrV4::new(src, sport), SocketAddrV4::new(dst, dport), seq, ack, flags, &t[off..]))
}

// ------------------------------------------------------------------ raw sockets

struct Raw {
    send_fd: RawFd,
    recv: tokio::io::unix::AsyncFd<RawFd>,
}

impl Drop for Raw {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.send_fd);
            libc::close(*self.recv.get_ref());
        }
    }
}

fn raw_pair() -> std::io::Result<Raw> {
    unsafe {
        let send_fd = libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_RAW);
        if send_fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let recv_fd = libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_TCP);
        if recv_fd < 0 {
            let e = std::io::Error::last_os_error();
            libc::close(send_fd);
            return Err(e);
        }
        let one: libc::c_int = 1;
        libc::setsockopt(send_fd, libc::IPPROTO_IP, libc::IP_HDRINCL, &one as *const _ as *const libc::c_void, 4);
        let nonblock = |fd: RawFd| {
            let fl = libc::fcntl(fd, libc::F_GETFL);
            libc::fcntl(fd, libc::F_SETFL, fl | libc::O_NONBLOCK);
        };
        nonblock(send_fd);
        nonblock(recv_fd);
        match tokio::io::unix::AsyncFd::new(recv_fd) {
            Ok(recv) => Ok(Raw { send_fd, recv }),
            Err(e) => {
                libc::close(send_fd);
                libc::close(recv_fd);
                Err(e)
            }
        }
    }
}

impl Raw {
    async fn send(&self, dst: SocketAddrV4, pkt: &[u8]) -> std::io::Result<()> {
        let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        sa.sin_family = libc::AF_INET as libc::sa_family_t;
        sa.sin_port = dst.port().to_be();
        sa.sin_addr = libc::in_addr { s_addr: u32::from_be_bytes(dst.ip().octets()).to_be() };
        let r = unsafe {
            libc::sendto(self.send_fd, pkt.as_ptr() as *const libc::c_void, pkt.len(), 0, &sa as *const _ as *const libc::sockaddr, std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t)
        };
        if r < 0 {
            // a raw send can block momentarily; wait and try once more
            tokio::time::sleep(Duration::from_millis(2)).await;
            let r = unsafe {
                libc::sendto(self.send_fd, pkt.as_ptr() as *const libc::c_void, pkt.len(), 0, &sa as *const _ as *const libc::sockaddr, std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t)
            };
            if r < 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
        Ok(())
    }

    /// The next incoming TCP packet (any port).
    async fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            let mut g = self.recv.readable().await?;
            match g.try_io(|fd| {
                let n = unsafe { libc::recv(*fd.get_ref(), buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
                if n < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(r) => return r,
                Err(_) => continue,
            }
        }
    }
}

// ------------------------------------------------------------------ iptables (drop our own RSTs)

/// Every rule we add carries this comment plus our process id (`kanki-faketcp-<pid>`), so the
/// rules a killed or crashed process left behind can be found and removed later.
const RULE_TAG: &str = "kanki-faketcp";

/// The rule (chain and match, without -I/-D) that drops our RSTs for `port`.
fn rst_rule(port: u16, pid: u32) -> Vec<String> {
    format!("OUTPUT -p tcp --sport {} --tcp-flags RST RST -m comment --comment {}-{} -j DROP", port, RULE_TAG, pid).split(' ').map(|x| x.to_string()).collect()
}

/// Runs `iptables -w <cmd> <rule>`; the error says why it did not work. `-w` waits for the
/// xtables lock instead of failing when another program holds it.
fn iptables(cmd: &str, rule: &[String]) -> Result<(), String> {
    match std::process::Command::new("iptables").arg("-w").arg(cmd).args(rule).output() {
        Ok(o) if o.status.success() => Ok(()),
        Ok(o) => Err(String::from_utf8_lossy(&o.stderr).trim().to_string()),
        Err(e) => Err(format!("cannot run iptables: {}", e)),
    }
}

/// From an `iptables -S OUTPUT` listing: our tagged rules whose process is gone (as rules for
/// `iptables -D`). Rules of other programs and of running processes are left alone.
fn stale_rules(listing: &str, alive: impl Fn(u32) -> bool) -> Vec<Vec<String>> {
    let mut out = vec![];
    for line in listing.lines() {
        let words: Vec<String> = line.split_whitespace().map(|w| w.trim_matches('"').to_string()).collect();
        if words.first().map(|w| w.as_str()) != Some("-A") {
            continue;
        }
        let pid = words.windows(2).find(|w| w[0] == "--comment").and_then(|w| w[1].strip_prefix(RULE_TAG)).and_then(|r| r.strip_prefix('-')).and_then(|p| p.parse::<u32>().ok());
        match pid {
            Some(pid) if !alive(pid) => out.push(words[1..].to_vec()),
            _ => {}
        }
    }
    out
}

/// Whether process `pid` still runs (a process we may not signal still runs).
fn pid_alive(pid: u32) -> bool {
    if pid == std::process::id() {
        return true;
    }
    let r = unsafe { libc::kill(pid as libc::pid_t, 0) };
    r == 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
}

static PURGE: std::sync::Once = std::sync::Once::new();
/// set once this process added a rule
static ADDED_ANY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// On SIGTERM (systemd stop, update): remove this process's own rules, since `Drop` does not run.
pub fn remove_own_rules() {
    if !ADDED_ANY.load(std::sync::atomic::Ordering::Relaxed) {
        return;
    }
    let Ok(o) = std::process::Command::new("iptables").args(["-w", "-S", "OUTPUT"]).output() else { return };
    let me = std::process::id();
    for rule in stale_rules(&String::from_utf8_lossy(&o.stdout), |p| p != me) {
        let _ = iptables("-D", &rule);
    }
}

/// Removes the rules of earlier processes: SIGTERM or a crash skips `Drop`, and the random client
/// ports would pile up over restarts and updates. Runs once per process, before our first rule.
fn purge_stale() {
    let Ok(o) = std::process::Command::new("iptables").args(["-w", "-S", "OUTPUT"]).output() else { return };
    if !o.status.success() {
        return;
    }
    for rule in stale_rules(&String::from_utf8_lossy(&o.stdout), pid_alive) {
        let _ = iptables("-D", &rule);
    }
}

/// Keeps the kernel's RSTs for the fake port from reaching the peer. Best effort: without this
/// the link still works (both ends ignore RSTs), but the RSTs are a tell. The rule is removed on
/// drop.
pub struct RstGuard {
    rule: Vec<String>,
    added: bool,
}

impl RstGuard {
    fn add(port: u16) -> RstGuard {
        PURGE.call_once(purge_stale);
        let rule = rst_rule(port, std::process::id());
        // always our own copy, even when an equal rule is there (the same tunnel being restarted):
        // each guard deletes exactly one, so an old guard can never take the new one's rule
        let added = match iptables("-I", &rule) {
            Ok(()) => {
                ADDED_ANY.store(true, std::sync::atomic::Ordering::Relaxed);
                true
            }
            Err(e) => {
                eprintln!("faketcp: cannot add the iptables rule that hides our RSTs on port {} ({}); the link still works, but the RSTs are visible. It needs root, or CAP_NET_ADMIN and CAP_NET_RAW", port, e);
                false
            }
        };
        RstGuard { rule, added }
    }
}

impl Drop for RstGuard {
    fn drop(&mut self) {
        if self.added {
            let _ = iptables("-D", &self.rule);
        }
    }
}

// ------------------------------------------------------------------ client

/// Client side of a fake-TCP channel: a private loopback UDP socket for KCP, carried to the
/// server in fake TCP segments.
pub struct FtClient {
    pub local: SocketAddr,
    tasks: Vec<JoinHandle<()>>,
    _rst: RstGuard,
}

impl Drop for FtClient {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

/// One established fake connection: sequence numbers and the server address.
#[derive(Clone, Copy)]
struct FtConn {
    server: SocketAddrV4,
    me: SocketAddrV4,
    /// our next sequence number
    seq: u32,
    /// the server's next sequence number (what we acknowledge)
    ack: u32,
}

/// Whether a segment from `src` to `dst` belongs to our link: from the server, to our fake port.
/// The raw socket sees every TCP packet of the machine, also those of the tunnel's other links.
fn for_link(src: SocketAddrV4, dst: SocketAddrV4, server: SocketAddrV4, my_port: u16) -> bool {
    src == server && dst.port() == my_port
}

/// Connects to the `faketcp` server at `remote` (host:port) and returns the loopback address KCP
/// should dial. The fake handshake is retried a few times.
pub async fn client(remote: SocketAddr, token: &str) -> Res<FtClient> {
    let SocketAddr::V4(server) = remote else {
        return Err("faketcp needs an IPv4 address for the other side".into());
    };
    let raw = Arc::new(raw_pair().map_err(|e| format!("raw sockets failed (faketcp needs root or CAP_NET_RAW): {}", e))?);
    let mask = Arc::new(Mask::new(token));
    // our fake source port: fixed for the life of this link
    let my_port: u16 = 20000 + (rand::random::<u16>() % 20000);
    let my_ip = {
        // which local address would reach the server: ask the routing table via a UDP socket
        let probe = UdpSocket::bind("0.0.0.0:0").await?;
        probe.connect(server).await?;
        match probe.local_addr()? {
            SocketAddr::V4(a) => *a.ip(),
            _ => return Err("the route to the server is not IPv4".into()),
        }
    };
    let me = SocketAddrV4::new(my_ip, my_port);
    // the rule goes in before the SYN: otherwise our kernel answers the SYN-ACK with a RST
    let rst = RstGuard::add(my_port);
    // fake three-way handshake
    let iss = rand::random::<u32>();
    let mut conn: Option<FtConn> = None;
    for _ in 0..4 {
        let syn = build_packet(me, server, iss, 0, FLAG_SYN, &[]);
        raw.send(server, &syn).await?;
        let t0 = Instant::now();
        let mut buf = vec![0u8; 65535];
        while t0.elapsed() < Duration::from_secs(4) {
            let n = match tokio::time::timeout(Duration::from_millis(500), raw.recv(&mut buf)).await {
                Ok(Ok(n)) => n,
                Ok(Err(_)) => continue,
                Err(_) => continue,
            };
            let Some((src, dst, seq, _ack, flags, _pl)) = parse_packet(&buf[..n]) else { continue };
            // a RST is not the answer either: the server's kernel sends one when its rule is missing
            if !for_link(src, dst, server, my_port) || flags & FLAG_RST != 0 {
                continue;
            }
            if flags & (FLAG_SYN | FLAG_ACK) == (FLAG_SYN | FLAG_ACK) {
                let c = FtConn { server, me, seq: iss.wrapping_add(1), ack: seq.wrapping_add(1) };
                let ackp = build_packet(me, server, c.seq, c.ack, FLAG_ACK, &[]);
                raw.send(server, &ackp).await?;
                conn = Some(c);
                break;
            }
        }
        if conn.is_some() {
            break;
        }
    }
    let Some(conn) = conn else {
        return Err("faketcp handshake failed (is the port open, and does the server run faketcp?)".into());
    };

    let inner = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
    let local = inner.local_addr()?;
    let kcp_addr: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
    let state = Arc::new(Mutex::new(conn));

    // KCP -> mask -> fake TCP segment
    let (inner1, raw1, mask1, ka1, st1) = (inner.clone(), raw.clone(), mask.clone(), kcp_addr.clone(), state.clone());
    let out_task = tokio::spawn(async move {
        let mut a = vec![0u8; 65535];
        let mut w: Vec<u8> = Vec::with_capacity(2048);
        loop {
            let Ok((n, from)) = inner1.recv_from(&mut a).await else { break };
            *ka1.lock().unwrap_or_else(|e| e.into_inner()) = Some(from);
            let mut off = 0;
            while off < n {
                let take = (n - off).min(MAX_SEG);
                w.clear();
                mask1.seal(&a[off..off + take], &mut w);
                let mut c = *st1.lock().unwrap_or_else(|e| e.into_inner());
                let pkt = build_packet(c.me, c.server, c.seq, c.ack, FLAG_PSH | FLAG_ACK, &w);
                if raw1.send(c.server, &pkt).await.is_err() {
                    break;
                }
                c.seq = c.seq.wrapping_add(w.len() as u32);
                *st1.lock().unwrap_or_else(|e| e.into_inner()) = c;
                off += take;
            }
        }
    });
    // fake TCP segment -> unmask -> KCP
    let in_task = tokio::spawn(async move {
        let mut b = vec![0u8; 65535];
        loop {
            let n = match raw.recv(&mut b).await {
                Ok(n) => n,
                Err(_) => {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                    continue;
                }
            };
            let Some((src, dst, seq, _ack, flags, pl)) = parse_packet(&b[..n]) else { continue };
            if !for_link(src, dst, server, my_port) || pl.is_empty() {
                continue;
            }
            if flags & (FLAG_RST | FLAG_FIN) != 0 {
                continue;
            }
            let mut p = pl.to_vec();
            let Some((s, e)) = mask.open(&mut p) else { continue };
            // acknowledge only segments that really are ours
            state.lock().unwrap_or_else(|e| e.into_inner()).ack = seq.wrapping_add(pl.len() as u32);
            let dst = *kcp_addr.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(dst) = dst {
                let _ = inner.send_to(&p[s..e], dst).await;
            }
        }
    });
    Ok(FtClient { local, tasks: vec![out_task, in_task], _rst: rst })
}

// ------------------------------------------------------------------ server

/// One fake connection as the server keeps it: its loopback socket toward KCP, the pump that
/// carries KCP's answers back, and the fake sequence numbers.
struct FtPeer {
    sock: Arc<UdpSocket>,
    last: Instant,
    pump: JoinHandle<()>,
    /// the client's next sequence number (what we acknowledge)
    ack: Arc<Mutex<u32>>,
}

/// Server side of the fake-TCP channel: owns the raw sockets, unwraps segments and relays the
/// payloads between the clients and the local KCP listener.
pub struct ServerFt {
    tasks: Vec<JoinHandle<()>>,
    peers: Arc<Mutex<HashMap<SocketAddrV4, FtPeer>>>,
    _rst: RstGuard,
}

impl Drop for ServerFt {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
        for (_, p) in self.peers.lock().unwrap_or_else(|e| e.into_inner()).drain() {
            p.pump.abort();
        }
    }
}

/// Client-bound pump: KCP -> mask -> fake TCP segment, for one client.
async fn ft_pump(sock: Arc<UdpSocket>, raw: Arc<Raw>, mask: Arc<Mask>, cli: SocketAddrV4, srv: SocketAddrV4, seq: Arc<Mutex<u32>>, ack: Arc<Mutex<u32>>) {
    let mut b = vec![0u8; 65535];
    let mut w: Vec<u8> = Vec::with_capacity(2048);
    loop {
        let n = match sock.recv(&mut b).await {
            Ok(n) => n,
            Err(_) => break,
        };
        let mut off = 0;
        while off < n {
            let take = (n - off).min(MAX_SEG);
            w.clear();
            mask.seal(&b[off..off + take], &mut w);
            let sq = {
                let mut g = seq.lock().unwrap_or_else(|e| e.into_inner());
                let s = *g;
                *g = g.wrapping_add(w.len() as u32);
                s
            };
            let ak = *ack.lock().unwrap_or_else(|e| e.into_inner());
            let pkt = build_packet(srv, cli, sq, ak, FLAG_PSH | FLAG_ACK, &w);
            if raw.send(cli, &pkt).await.is_err() {
                break;
            }
            off += take;
        }
    }
}

/// The SYN-ACK from `srv` answering a SYN from `cli` with sequence number `seq`; `iss` is our
/// first sequence number. Nothing is kept: the client's first data segment brings `iss + 1` back
/// in its ack field.
fn syn_ack(srv: SocketAddrV4, cli: SocketAddrV4, seq: u32, iss: u32) -> Vec<u8> {
    build_packet(srv, cli, iss, seq.wrapping_add(1), FLAG_SYN | FLAG_ACK, &[])
}

/// Listens for fake-TCP clients on TCP port `port` and relays them to the KCP listener at
/// `kcp_local`.
pub async fn server(port: u16, token: &str, kcp_local: SocketAddr) -> Res<ServerFt> {
    let raw = Arc::new(raw_pair().map_err(|e| format!("raw sockets failed (faketcp needs root or CAP_NET_RAW): {}", e))?);
    let mask = Arc::new(Mask::new(token));
    let rst = RstGuard::add(port);
    let peers: Arc<Mutex<HashMap<SocketAddrV4, FtPeer>>> = Arc::new(Mutex::new(HashMap::new()));

    let (raw1, mask1, peers1) = (raw.clone(), mask.clone(), peers.clone());
    let main = tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            let n = match raw1.recv(&mut buf).await {
                Ok(n) => n,
                Err(_) => {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                    continue;
                }
            };
            let Some((src, dst, seq, ack, flags, pl)) = parse_packet(&buf[..n]) else { continue };
            if dst.port() != port {
                continue;
            }
            // a new fake connection: answer it without keeping anything, so spoofed SYNs cost
            // nothing; the client becomes a peer with its first segment that unmasks
            if flags & FLAG_SYN != 0 && flags & FLAG_ACK == 0 {
                let _ = raw1.send(src, &syn_ack(dst, src, seq, rand::random())).await;
                continue;
            }
            // like udp2raw, RST and FIN are ignored: anyone can forge them, and the client's kernel
            // may send RSTs too. A client that is gone is forgotten by the idle timeout.
            if flags & (FLAG_RST | FLAG_FIN) != 0 || pl.is_empty() {
                continue;
            }
            let mut plv = pl.to_vec();
            let Some((s, e)) = mask1.open(&mut plv) else { continue };
            let next_ack = seq.wrapping_add(pl.len() as u32);
            let known = match peers1.lock().unwrap_or_else(|e| e.into_inner()).get_mut(&src) {
                Some(p) => {
                    p.last = Instant::now();
                    *p.ack.lock().unwrap_or_else(|e| e.into_inner()) = next_ack;
                    Some(p.sock.clone())
                }
                None => None,
            };
            let sock = match known {
                Some(sock) => sock,
                None => {
                    if peers1.lock().unwrap_or_else(|e| e.into_inner()).len() >= MAX_PEERS {
                        continue;
                    }
                    let Ok(sock) = UdpSocket::bind("127.0.0.1:0").await else { continue };
                    if sock.connect(kcp_local).await.is_err() {
                        continue;
                    }
                    let sock = Arc::new(sock);
                    // our sequence numbers go on from what the client acknowledges (our iss + 1)
                    let sq = Arc::new(Mutex::new(ack));
                    let ak = Arc::new(Mutex::new(next_ack));
                    let pump = tokio::spawn(ft_pump(sock.clone(), raw1.clone(), mask1.clone(), src, SocketAddrV4::new(*dst.ip(), port), sq, ak.clone()));
                    peers1.lock().unwrap_or_else(|e| e.into_inner()).insert(src, FtPeer { sock: sock.clone(), last: Instant::now(), pump, ack: ak });
                    sock
                }
            };
            let _ = sock.send(&plv[s..e]).await;
        }
    });

    // forget clients that went quiet (and clients whose pump died)
    let peers2 = peers.clone();
    let reaper = tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(15)).await;
            let mut g = peers2.lock().unwrap_or_else(|e| e.into_inner());
            g.retain(|_, p| {
                let keep = !p.pump.is_finished() && p.last.elapsed() < PEER_IDLE;
                if !keep {
                    p.pump.abort();
                }
                keep
            });
        }
    });

    Ok(ServerFt { tasks: vec![main, reaper], peers, _rst: rst })
}

// ------------------------------------------------------------------ engine glue

fn ft_kcp_config() -> tokio_kcp::KcpConfig {
    tokio_kcp::KcpConfig {
        stream: true,
        nodelay: tokio_kcp::KcpNoDelayConfig::fastest(),
        // the fake TCP headers (40 bytes) plus the mask head and padding must fit the wire budget
        mtu: 1150,
        wnd_size: (1024, 1024),
        session_expire: Duration::from_secs(45),
        ..Default::default()
    }
}

/// Starts a `faketcp` listener: KCP on a private loopback socket, the fake-TCP channel on the
/// public TCP port.
pub async fn serve_faketcp(port: u16, token: &str, out: Inbox, sem: Arc<tokio::sync::Semaphore>) -> Res<Bag> {
    let mut inner = tokio_kcp::KcpListener::bind(ft_kcp_config(), "127.0.0.1:0").await?;
    let local = inner.local_addr()?;
    let relay = server(port, token, local).await?;
    let task = tokio::spawn(async move {
        let _relay = relay;
        loop {
            let stream = match inner.accept().await {
                Ok((s, _)) => s,
                Err(_) => {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    continue;
                }
            };
            let Ok(permit) = sem.clone().try_acquire_owned() else {
                drop(stream);
                continue;
            };
            let io: BoxIo = Box::new(super::quic::KcpHeld { stream, _permit: permit });
            if out.send((super::link::Raw::Stream(io), "faketcp".to_string())).await.is_err() {
                break;
            }
        }
    });
    Ok(Bag { tasks: vec![task], endpoints: vec![] })
}

/// Dials a `faketcp` server through the fake-TCP channel.
pub async fn dial_faketcp(remote: &str, token: &str) -> Res<BoxIo> {
    let addr: SocketAddr = tokio::net::lookup_host(remote).await?.next().ok_or("cannot resolve the tunnel address")?;
    let relay = client(addr, token).await?;
    let stream = tokio::time::timeout(Duration::from_secs(12), tokio_kcp::KcpStream::connect(&ft_kcp_config(), relay.local))
        .await
        .map_err(|_| "faketcp connect timeout")??;
    Ok(Box::new(FtIo { stream, _relay: relay }))
}

/// A KCP stream that also owns its fake-TCP relay.
pub struct FtIo {
    stream: tokio_kcp::KcpStream,
    _relay: FtClient,
}

impl tokio::io::AsyncRead for FtIo {
    fn poll_read(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &mut tokio::io::ReadBuf<'_>) -> std::task::Poll<std::io::Result<()>> {
        tokio::io::AsyncRead::poll_read(std::pin::Pin::new(&mut self.stream), cx, buf)
    }
}
impl tokio::io::AsyncWrite for FtIo {
    fn poll_write(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &[u8]) -> std::task::Poll<std::io::Result<usize>> {
        tokio::io::AsyncWrite::poll_write(std::pin::Pin::new(&mut self.stream), cx, buf)
    }
    fn poll_flush(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        tokio::io::AsyncWrite::poll_flush(std::pin::Pin::new(&mut self.stream), cx)
    }
    fn poll_shutdown(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        tokio::io::AsyncWrite::poll_shutdown(std::pin::Pin::new(&mut self.stream), cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> SocketAddrV4 {
        s.parse().unwrap()
    }

    #[test]
    fn packet_roundtrip_and_checksum() {
        let (a, b) = (addr("10.0.0.1:20001"), addr("10.0.0.2:443"));
        let pkt = build_packet(a, b, 7, 9, FLAG_PSH | FLAG_ACK, b"hello");
        let (src, dst, seq, ack, flags, pl) = parse_packet(&pkt).unwrap();
        assert_eq!((src, dst, seq, ack, flags, pl), (a, b, 7, 9, FLAG_PSH | FLAG_ACK, &b"hello"[..]));
        // a correct TCP checksum sums to zero over the pseudo header
        assert_eq!(tcp_checksum(*a.ip(), *b.ip(), &pkt[20..]), 0);
    }

    #[test]
    fn syn_ack_is_built_from_the_syn_alone() {
        let (srv, cli) = (addr("10.0.0.2:443"), addr("10.0.0.1:20001"));
        let pkt = syn_ack(srv, cli, u32::MAX, 1000);
        let (src, dst, seq, ack, flags, pl) = parse_packet(&pkt).unwrap();
        assert_eq!((src, dst), (srv, cli));
        assert_eq!(seq, 1000);
        // the client's sequence number + 1, wrapping
        assert_eq!(ack, 0);
        assert_eq!(flags, FLAG_SYN | FLAG_ACK);
        assert!(pl.is_empty());
    }

    #[test]
    fn link_filter_wants_server_and_our_port() {
        let (srv, me) = (addr("10.0.0.2:443"), 20001);
        assert!(for_link(srv, addr("10.0.0.1:20001"), srv, me));
        // another link of the same tunnel: same server, other port
        assert!(!for_link(srv, addr("10.0.0.1:20002"), srv, me));
        assert!(!for_link(addr("10.0.0.3:443"), addr("10.0.0.1:20001"), srv, me));
        assert!(!for_link(addr("10.0.0.2:444"), addr("10.0.0.1:20001"), srv, me));
    }

    #[test]
    fn rule_is_tagged_with_port_and_pid() {
        let r = rst_rule(20001, 42).join(" ");
        assert_eq!(r, "OUTPUT -p tcp --sport 20001 --tcp-flags RST RST -m comment --comment kanki-faketcp-42 -j DROP");
    }

    #[test]
    fn purge_takes_only_our_rules_of_dead_processes() {
        let listing = "-P OUTPUT ACCEPT\n\
            -A OUTPUT -p tcp -m tcp --sport 20001 --tcp-flags RST RST -m comment --comment kanki-faketcp-100 -j DROP\n\
            -A OUTPUT -p tcp -m tcp --sport 20002 --tcp-flags RST RST -m comment --comment kanki-faketcp-200 -j DROP\n\
            -A OUTPUT -p tcp -m tcp --sport 20003 --tcp-flags RST RST -m comment --comment \"kanki-faketcp-300\" -j DROP\n\
            -A OUTPUT -p tcp -m tcp --sport 22 -m comment --comment ssh -j ACCEPT\n\
            -A OUTPUT -p tcp -m comment --comment kanki-faketcp-x -j DROP\n\
            -A OUTPUT -p tcp -m tcp --sport 9 --tcp-flags RST RST -j DROP\n";
        let stale = stale_rules(listing, |pid| pid == 200);
        assert_eq!(stale.len(), 2);
        assert_eq!(stale[0].join(" "), "OUTPUT -p tcp -m tcp --sport 20001 --tcp-flags RST RST -m comment --comment kanki-faketcp-100 -j DROP");
        assert_eq!(stale[1][stale[1].len() - 3], "kanki-faketcp-300");
    }

    #[test]
    fn our_own_process_is_alive() {
        assert!(pid_alive(std::process::id()));
    }
}
