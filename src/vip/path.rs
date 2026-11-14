//! VIP tunnel: the carriers. Each path is one way packets get between the two servers:
//!
//! - **udp**: plain UDP. The listener holds `hop` ports; the dialer moves every UDP path to another of them
//!   (and to a new source port) every `hop_secs`, so no single UDP flow lives long enough to be throttled.
//! - **ftcp**: the same packets inside fake TCP segments (`tunnel::faketcp`), for networks that cut UDP.
//! - **stream**: one link of the Kanki engine (`tunnel::link`: HTTP/2, WebSocket, TLS, a CDN), for networks
//!   where only web traffic passes. A packet is one record.
//!
//! A carrier only moves bytes; the session (`core`) opens them. On the listening side the session also
//! learns where to answer each path from the packets that open.

use super::{PathKind, VipSpec};
use crate::tunnel::link;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// Where a packet goes out. A UDP socket is written through a plain non-blocking handle: tokio's own
/// `try_send` refuses until the socket has been polled once, which would drop the first packets of a new
/// socket.
#[derive(Clone)]
pub enum Out {
    Udp(Arc<std::net::UdpSocket>, SocketAddr),
    Stream(mpsc::Sender<Vec<u8>>),
}

/// A UDP socket with big buffers: tokio's half for reading, a plain handle for writing
pub fn udp_bind(addr: SocketAddr) -> std::io::Result<(Arc<UdpSocket>, Arc<std::net::UdpSocket>)> {
    use socket2::{Domain, Protocol, Socket, Type};
    let s = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
    let _ = s.set_recv_buffer_size(4 << 20);
    let _ = s.set_send_buffer_size(4 << 20);
    s.bind(&addr.into())?;
    s.set_nonblocking(true)?;
    let std: std::net::UdpSocket = s.into();
    let tx = std.try_clone()?;
    Ok((Arc::new(UdpSocket::from_std(std)?), Arc::new(tx)))
}

impl Out {
    /// Never waits: a full socket or link drops the packet (the session's repairs and copies cover it)
    pub fn send(&self, b: Vec<u8>) -> bool {
        match self {
            Out::Udp(s, to) => s.send_to(&b, *to).is_ok(),
            Out::Stream(tx) => tx.try_send(b).is_ok(),
        }
    }
    pub fn same(&self, o: &Out) -> bool {
        match (self, o) {
            (Out::Udp(a, x), Out::Udp(b, y)) => Arc::ptr_eq(a, b) && x == y,
            (Out::Stream(a), Out::Stream(b)) => a.same_channel(b),
            _ => false,
        }
    }
}

/// A packet that came in, and how to answer on the carrier it came from
pub struct In {
    pub data: Vec<u8>,
    pub reply: Out,
}

/// What the session knows of each path's carrier
#[derive(Default)]
pub struct Slot {
    pub out: Option<Out>,
    /// the listener's port the path uses now
    pub port: u16,
    pub error: String,
}

pub type Slots = Arc<Mutex<Vec<Slot>>>;

fn set(slots: &Slots, i: usize, f: impl FnOnce(&mut Slot)) {
    if let Some(s) = slots.lock().unwrap_or_else(|e| e.into_inner()).get_mut(i) {
        f(s);
    }
}

fn now_ms() -> u64 {
    crate::tunnel::mux::now_ms()
}

/// Reads one UDP socket into the session until it is aborted (`tx`: its writing handle, for the answers)
fn reader(sock: Arc<UdpSocket>, tx: Arc<std::net::UdpSocket>, inbound: mpsc::Sender<In>, seen: Option<Arc<AtomicU64>>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            match sock.recv_from(&mut buf).await {
                Ok((n, from)) => {
                    if let Some(s) = &seen {
                        s.store(now_ms(), Ordering::Relaxed);
                    }
                    // a full queue means the session is behind: this packet is lost like on the wire
                    let _ = inbound.try_send(In { data: buf[..n].to_vec(), reply: Out::Udp(tx.clone(), from) });
                }
                // an ICMP error of an earlier send, or the like
                Err(_) => tokio::time::sleep(Duration::from_millis(5)).await,
            }
        }
    })
}

async fn resolve(host: &str, port: u16, v4_only: bool) -> Result<SocketAddr, String> {
    let h = host.trim().trim_start_matches('[').trim_end_matches(']');
    let all: Vec<SocketAddr> = tokio::net::lookup_host((h, port)).await.map_err(|e| format!("cannot resolve {}: {}", h, e))?.collect();
    all.iter().find(|a| a.is_ipv4()).or(if v4_only { None } else { all.first() }).copied().ok_or_else(|| format!("{} has no usable address", h))
}

/// Starts every carrier of this side; the tasks live until aborted
pub fn start(spec: &VipSpec, psk: &[u8; 32], inbound: mpsc::Sender<In>, slots: Slots) -> Vec<JoinHandle<()>> {
    let kinds = spec.paths();
    let mut tasks = vec![];
    let udp: Vec<usize> = kinds.iter().enumerate().filter(|(_, k)| **k == PathKind::Udp).map(|(i, _)| i).collect();
    for (i, k) in kinds.iter().enumerate() {
        let (spec, inbound, slots) = (spec.clone(), inbound.clone(), slots.clone());
        match k {
            PathKind::Udp if spec.dials => tasks.push(tokio::spawn(udp_dialer(spec, i, inbound, slots))),
            PathKind::Ftcp if spec.dials => tasks.push(tokio::spawn(ftcp_dialer(spec, super::crypto::sub_token(psk, "ftcp"), i, inbound, slots))),
            PathKind::Ftcp => tasks.push(tokio::spawn(ftcp_listener(spec, super::crypto::sub_token(psk, "ftcp"), i, inbound, slots))),
            PathKind::Stream if spec.dials => tasks.push(tokio::spawn(stream_dialer(spec, super::crypto::sub_token(psk, "stream"), i, inbound, slots))),
            PathKind::Stream => tasks.push(tokio::spawn(stream_listener(spec, super::crypto::sub_token(psk, "stream"), i, inbound, slots))),
            PathKind::Udp => {}
        }
    }
    if !spec.dials && !udp.is_empty() {
        tasks.push(tokio::spawn(udp_listener(spec.clone(), udp, inbound, slots)));
    }
    tasks
}

// ------------------------------------------------------------------ udp

/// The listener: every port of the hop range, all feeding the session
async fn udp_listener(spec: VipSpec, ids: Vec<usize>, inbound: mpsc::Sender<In>, slots: Slots) {
    let mut readers = Guard(vec![]);
    let mut missing: Vec<u16> = (0..spec.hops()).map(|i| spec.port.saturating_add(i)).collect();
    loop {
        let mut still = vec![];
        for p in missing {
            match udp_bind(SocketAddr::from(([0, 0, 0, 0], p))) {
                Ok((s, tx)) => readers.0.push(reader(s, tx, inbound.clone(), None)),
                Err(_) => still.push(p),
            }
        }
        let err = if still.is_empty() { String::new() } else { format!("UDP port {} is busy", still.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", ")) };
        for &i in &ids {
            let e = err.clone();
            set(&slots, i, |s| s.error = e);
        }
        if still.is_empty() {
            // the readers live as long as this task (aborting it drops them with it)
            std::future::pending::<()>().await;
        }
        missing = still;
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

/// Aborts its tasks when dropped (a dropped JoinHandle alone would leave its task running)
pub(super) struct Guard(pub(super) Vec<JoinHandle<()>>);

impl Drop for Guard {
    fn drop(&mut self) {
        for t in &self.0 {
            t.abort();
        }
    }
}

/// One UDP path of the dialer: a new socket and another port of the range every `hop_secs`
async fn udp_dialer(spec: VipSpec, i: usize, inbound: mpsc::Sender<In>, slots: Slots) {
    let hops = spec.hops();
    // the reader of the socket in use (aborted with this task)
    let mut cur = Guard(vec![]);
    // the paths start spread over the range (path 0 on the first port, path 1 on the second …)
    let mut idx = (i as u16) % hops;
    let mut resolved: Option<(SocketAddr, std::time::Instant)> = None;
    loop {
        // the address is looked up again every few minutes (a domain may move)
        let base = match resolved {
            Some((a, at)) if at.elapsed() < Duration::from_secs(300) => Ok(a),
            _ => resolve(&spec.remote, spec.port, false).await,
        };
        let base = match base {
            Ok(a) => {
                if resolved.map(|r| r.0) != Some(a) || resolved.is_none_or(|r| r.1.elapsed() >= Duration::from_secs(300)) {
                    resolved = Some((a, std::time::Instant::now()));
                }
                a
            }
            Err(e) => {
                set(&slots, i, |s| s.error = e);
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
        };
        let bind: SocketAddr = if base.is_ipv6() { "[::]:0".parse().expect("addr") } else { "0.0.0.0:0".parse().expect("addr") };
        let (sock, tx) = match udp_bind(bind) {
            Ok(x) => x,
            Err(e) => {
                set(&slots, i, |s| s.error = format!("UDP socket: {}", e));
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
        };
        let port = spec.port.saturating_add(idx);
        let to = SocketAddr::new(base.ip(), port);
        let r = reader(sock, tx.clone(), inbound.clone(), None);
        set(&slots, i, |s| {
            s.out = Some(Out::Udp(tx, to));
            s.port = port;
            s.error.clear();
        });
        // the old socket keeps listening a little: answers already on their way still arrive
        if let Some(old) = cur.0.pop() {
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(4)).await;
                old.abort();
            });
        }
        cur.0.push(r);
        if spec.hop_secs == 0 {
            std::future::pending::<()>().await;
        }
        // a little random, so the paths do not all move at the same moment
        let secs = spec.hop_secs.max(5) as u64;
        let wait = secs * 1000 * 3 / 4 + rand::random::<u64>() % (secs * 1000 / 2 + 1);
        tokio::time::sleep(Duration::from_millis(wait)).await;
        if hops > 1 {
            idx = (idx + 1 + rand::random::<u16>() % (hops - 1)) % hops;
        }
    }
}

// ------------------------------------------------------------------ fake TCP

/// The listener: the fake-TCP relay of `tunnel::faketcp` delivers every client to one loopback socket
async fn ftcp_listener(spec: VipSpec, token: String, i: usize, inbound: mpsc::Sender<In>, slots: Slots) {
    loop {
        let (sock, tx) = match udp_bind("127.0.0.1:0".parse().expect("addr")) {
            Ok(x) => x,
            Err(e) => {
                set(&slots, i, |s| s.error = e.to_string());
                tokio::time::sleep(Duration::from_secs(10)).await;
                continue;
            }
        };
        let local = match sock.local_addr() {
            Ok(a) => a,
            Err(_) => continue,
        };
        match crate::tunnel::faketcp::server(spec.ftcp_port, &token, local).await {
            Ok(relay) => {
                set(&slots, i, |s| {
                    s.port = spec.ftcp_port;
                    s.error.clear();
                });
                let _r = Guard(vec![reader(sock, tx, inbound.clone(), None)]);
                let _relay = relay;
                std::future::pending::<()>().await;
            }
            Err(e) => {
                set(&slots, i, |s| s.error = e.to_string());
                tokio::time::sleep(Duration::from_secs(15)).await;
            }
        }
    }
}

/// The dialer: a fake TCP connection, made again when nothing came through it for a while
async fn ftcp_dialer(spec: VipSpec, token: String, i: usize, inbound: mpsc::Sender<In>, slots: Slots) {
    loop {
        let addr = match resolve(&spec.remote, spec.ftcp_port, true).await {
            Ok(a) => a,
            Err(e) => {
                set(&slots, i, |s| s.error = e);
                tokio::time::sleep(Duration::from_secs(10)).await;
                continue;
            }
        };
        let relay = match crate::tunnel::faketcp::client(addr, &token).await {
            Ok(r) => r,
            Err(e) => {
                set(&slots, i, |s| {
                    s.out = None;
                    s.error = e.to_string();
                });
                tokio::time::sleep(Duration::from_secs(10)).await;
                continue;
            }
        };
        let Ok((sock, tx)) = udp_bind("127.0.0.1:0".parse().expect("addr")) else { continue };
        let seen = Arc::new(AtomicU64::new(now_ms()));
        let r = Guard(vec![reader(sock, tx.clone(), inbound.clone(), Some(seen.clone()))]);
        set(&slots, i, |s| {
            s.out = Some(Out::Udp(tx, relay.local));
            s.port = spec.ftcp_port;
            s.error.clear();
        });
        // the session pings every path at least once a second: 20 s of silence = this connection is gone
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            if now_ms().saturating_sub(seen.load(Ordering::Relaxed)) > 20_000 {
                break;
            }
        }
        set(&slots, i, |s| {
            s.out = None;
            s.error = "no answer through fake TCP: connecting again".into();
        });
        drop(r);
        drop(relay);
    }
}

// ------------------------------------------------------------------ stream (a Kanki engine link)

/// `cdn` and `h2` pad their records (both ends decide it from the kind)
fn padded(kind: &str) -> bool {
    kind == "h2"
}

/// Carries one encrypted link: records out from the channel, records in to the session
async fn carry(tx: link::Tx, mut rx: link::Rx, inbound: mpsc::Sender<In>) -> (mpsc::Sender<Vec<u8>>, JoinHandle<()>, JoinHandle<()>) {
    let (ch, mut q) = mpsc::channel::<Vec<u8>>(512);
    let mut tx = tx;
    let writer = tokio::spawn(async move {
        while let Some(b) = q.recv().await {
            if tx.send(&b).await.is_err() {
                break;
            }
        }
        tx.close().await;
    });
    let back = ch.clone();
    let reader = tokio::spawn(async move {
        while let Ok(b) = rx.recv().await {
            let _ = inbound.try_send(In { data: b, reply: Out::Stream(back.clone()) });
        }
    });
    (ch, writer, reader)
}

async fn stream_listener(spec: VipSpec, token: String, i: usize, inbound: mpsc::Sender<In>, slots: Slots) {
    let gopt = crate::tunnel::game::GameOpts::parse("", false);
    let mut l = loop {
        match link::Listener::bind(&spec.s_kind, spec.s_port, "", "", &token, gopt).await {
            Ok(l) => break l,
            Err(e) => {
                set(&slots, i, |s| s.error = format!("TCP port {}: {}", spec.s_port, e));
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    };
    set(&slots, i, |s| {
        s.port = spec.s_port;
        s.error.clear();
    });
    let pad = padded(&spec.s_kind);
    let mut live: Vec<Guard> = vec![];
    loop {
        let Ok((raw, _peer)) = l.accept().await else {
            tokio::time::sleep(Duration::from_millis(200)).await;
            continue;
        };
        // a wrong token or a scanner fails here and costs nothing more
        let Ok((tx, rx, _)) = link::handshake(raw, &token, false, pad).await else { continue };
        let (_, w, r) = carry(tx, rx, inbound.clone()).await;
        live.retain(|g| !g.0.iter().any(|t| t.is_finished()));
        // the newest links stay; an old one the dialer gave up on goes
        while live.len() >= 4 {
            live.remove(0);
        }
        live.push(Guard(vec![w, r]));
    }
}

async fn stream_dialer(spec: VipSpec, token: String, i: usize, inbound: mpsc::Sender<In>, slots: Slots) {
    let gopt = crate::tunnel::game::GameOpts::parse("", false);
    let pad = padded(&spec.s_kind);
    // a CDN is reached on its edges (port 443 unless written), anything else on the listener's port
    let remotes: Vec<String> = if spec.s_kind == "cdn" {
        let src = [spec.s_dial.as_str(), spec.s_host.as_str(), spec.s_sni.as_str()].into_iter().find(|x| !x.trim().is_empty()).unwrap_or("");
        src.split(|c: char| c == ',' || c == ';' || c.is_whitespace())
            .map(|x| x.trim())
            .filter(|x| !x.is_empty())
            .map(|x| if x.rsplit_once(':').is_some_and(|(h, p)| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) && (!h.contains(':') || h.ends_with(']'))) { x.to_string() } else { hostport(x, 443) })
            .collect()
    } else {
        vec![hostport(&spec.remote, spec.s_port)]
    };
    if remotes.is_empty() {
        set(&slots, i, |s| s.error = "the CDN path has no address".into());
        return;
    }
    let mut attempt = 0usize;
    let mut wait = 1u64;
    loop {
        let remote = remotes[attempt % remotes.len()].clone();
        let r = async {
            let raw = link::dial(&spec.s_kind, &remote, &spec.s_sni, &spec.s_host, &spec.s_path, &token, spec.s_frag, gopt).await.map_err(|e| e.to_string())?;
            link::handshake(raw, &token, true, pad).await.map_err(|e| e.to_string())
        }
        .await;
        match r {
            Ok((tx, rx, _)) => {
                let (ch, w, rd) = carry(tx, rx, inbound.clone()).await;
                set(&slots, i, |s| {
                    s.out = Some(Out::Stream(ch));
                    s.port = spec.s_port;
                    s.error.clear();
                });
                wait = 1;
                let g = Guard(vec![w, rd]);
                while !g.0.iter().any(|t| t.is_finished()) {
                    tokio::time::sleep(Duration::from_millis(250)).await;
                }
                drop(g);
                set(&slots, i, |s| {
                    s.out = None;
                    s.error = format!("{}: the link closed", remote);
                });
            }
            Err(e) => {
                set(&slots, i, |s| {
                    s.out = None;
                    s.error = format!("{}: {}", remote, e);
                });
                attempt += 1;
            }
        }
        tokio::time::sleep(Duration::from_secs(wait)).await;
        wait = (wait * 2).min(10);
    }
}

fn hostport(host: &str, port: u16) -> String {
    let h = host.trim();
    if h.contains(':') && !h.starts_with('[') { format!("[{}]:{}", h, port) } else { format!("{}:{}", h, port) }
}
