//! VIP tunnel: the users' side. The entry takes the forwarded ports (UDP datagrams one by one, TCP
//! connections as streams of one QUIC connection that runs *inside* the tunnel), the exit delivers them to
//! the target. QUIC gives the TCP connections their own resends and congestion control (BBR), so a lost
//! packet of one download never holds up another connection, and a path change or a short outage does not
//! cut a connection (QUIC waits up to a minute).

use super::VipSpec;
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, Endpoint, EndpointConfig, TokioRuntime, TransportConfig, UdpPoller};
use std::collections::{HashMap, HashSet};
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// toward the other side
pub enum Up {
    Udp { pidx: u8, flow: u32, data: Vec<u8> },
    Quic(Vec<u8>),
}

/// from the other side
pub enum Down {
    Udp { pidx: u8, flow: u32, data: Vec<u8> },
    Quic(Vec<u8>),
}

#[derive(Default)]
pub struct Counters {
    pub streams: AtomicU64,
    pub udp_flows: AtomicU64,
}

/// most UDP flows of one tunnel at a time (a flood of new sources evicts the idlest instead of growing)
const MAX_FLOWS: usize = 8192;
const FLOW_IDLE: Duration = Duration::from_secs(180);

/// the two ends of the QUIC connection inside the tunnel (only addresses for quinn: nothing listens there)
const ENTRY_ADDR: &str = "127.0.0.1:1";
const EXIT_ADDR: &str = "127.0.0.1:2";

pub fn start(spec: &VipSpec, up: mpsc::Sender<Up>, down: mpsc::Receiver<Down>, counters: Arc<Counters>) -> Vec<JoinHandle<()>> {
    let (qin_tx, qin_rx) = mpsc::channel::<Vec<u8>>(4096);
    let mut tasks = vec![];
    let udp_ports = crate::tunnel::engine::parse_ports(&spec.udp);
    let tcp_ports = crate::tunnel::engine::parse_ports(&spec.tcp);
    if spec.entry() {
        let back: Back = Arc::new(Mutex::new(HashMap::new()));
        for (pidx, (a, _)) in udp_ports.iter().enumerate().take(255) {
            tasks.push(tokio::spawn(entry_udp(spec.bind_host(), *a, pidx as u8, up.clone(), back.clone(), counters.clone())));
        }
        tasks.push(tokio::spawn(entry_down(down, back, qin_tx)));
        if !tcp_ports.is_empty() {
            let sock = Arc::new(VSock::new(up, qin_rx, EXIT_ADDR, ENTRY_ADDR));
            let conn: Shared = Arc::new(tokio::sync::Mutex::new(None));
            let ep = match client_endpoint(sock) {
                Ok(e) => e,
                Err(e) => {
                    eprintln!("VIP tunnel {}: QUIC inside the tunnel did not start: {}", spec.id, e);
                    return tasks;
                }
            };
            for (a, b) in tcp_ports {
                tasks.push(tokio::spawn(entry_tcp(spec.bind_host(), a, b, ep.clone(), conn.clone(), counters.clone())));
            }
        }
    } else {
        let target = spec.target_host();
        let udp_to: Vec<u16> = udp_ports.iter().map(|x| x.1).collect();
        tasks.push(tokio::spawn(exit_down(down, target.clone(), udp_to, up.clone(), qin_tx, counters.clone())));
        let allowed: HashSet<u16> = tcp_ports.iter().map(|x| x.1).collect();
        if !allowed.is_empty() {
            let sock = Arc::new(VSock::new(up, qin_rx, ENTRY_ADDR, EXIT_ADDR));
            match server_endpoint(sock) {
                Ok(ep) => tasks.push(tokio::spawn(exit_tcp(ep, target, allowed, counters))),
                Err(e) => eprintln!("VIP tunnel {}: QUIC inside the tunnel did not start: {}", spec.id, e),
            }
        }
    }
    tasks
}

// ------------------------------------------------------------------ UDP

/// flow -> (the port's socket, the user's address, last packet)
type Back = Arc<Mutex<HashMap<u32, (Arc<std::net::UdpSocket>, SocketAddr, Instant)>>>;

static NEXT_FLOW: AtomicU64 = AtomicU64::new(1);

async fn entry_udp(bind: String, port: u16, pidx: u8, up: mpsc::Sender<Up>, back: Back, counters: Arc<Counters>) {
    let (sock, tx) = loop {
        let addr = match tokio::net::lookup_host((bind.as_str(), port)).await.ok().and_then(|mut a| a.next()) {
            Some(a) => a,
            None => SocketAddr::from(([0, 0, 0, 0], port)),
        };
        match super::path::udp_bind(addr) {
            Ok(x) => break x,
            Err(e) => {
                eprintln!("VIP tunnel: UDP port {} is busy: {}", port, e);
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    };
    let mut flows: HashMap<SocketAddr, (u32, Instant)> = HashMap::new();
    let mut buf = vec![0u8; 65535];
    let mut clean = Instant::now();
    loop {
        let Ok((n, from)) = sock.recv_from(&mut buf).await else { continue };
        let now = Instant::now();
        let id = match flows.get_mut(&from) {
            Some(f) => {
                f.1 = now;
                f.0
            }
            None => {
                if flows.len() >= MAX_FLOWS {
                    let mut b = back.lock().unwrap_or_else(|e| e.into_inner());
                    let mut v: Vec<(SocketAddr, u32, Instant)> = flows.iter().map(|(a, f)| (*a, f.0, f.1)).collect();
                    v.sort_by_key(|x| x.2);
                    for (a, fid, _) in v.into_iter().take(MAX_FLOWS / 8) {
                        flows.remove(&a);
                        b.remove(&fid);
                        counters.udp_flows.fetch_sub(1, Ordering::Relaxed);
                    }
                }
                let id = NEXT_FLOW.fetch_add(1, Ordering::Relaxed) as u32;
                flows.insert(from, (id, now));
                counters.udp_flows.fetch_add(1, Ordering::Relaxed);
                id
            }
        };
        back.lock().unwrap_or_else(|e| e.into_inner()).insert(id, (tx.clone(), from, now));
        let _ = up.try_send(Up::Udp { pidx, flow: id, data: buf[..n].to_vec() });
        if now.duration_since(clean) > Duration::from_secs(60) {
            clean = now;
            let old: Vec<(SocketAddr, u32)> = flows.iter().filter(|(_, f)| now.duration_since(f.1) > FLOW_IDLE).map(|(a, f)| (*a, f.0)).collect();
            let mut b = back.lock().unwrap_or_else(|e| e.into_inner());
            for (a, fid) in old {
                flows.remove(&a);
                b.remove(&fid);
                counters.udp_flows.fetch_sub(1, Ordering::Relaxed);
            }
        }
    }
}

/// entry: answers to the users, and QUIC's packets to its socket
async fn entry_down(mut down: mpsc::Receiver<Down>, back: Back, qin: mpsc::Sender<Vec<u8>>) {
    while let Some(d) = down.recv().await {
        match d {
            Down::Udp { flow, data, .. } => {
                let to = back.lock().unwrap_or_else(|e| e.into_inner()).get(&flow).map(|x| (x.0.clone(), x.1));
                if let Some((s, a)) = to {
                    let _ = s.send_to(&data, a);
                }
            }
            Down::Quic(d) => {
                let _ = qin.try_send(d);
            }
        }
    }
}

/// exit: one socket per user flow toward the target, its answers back into the tunnel
async fn exit_down(mut down: mpsc::Receiver<Down>, target: String, ports: Vec<u16>, up: mpsc::Sender<Up>, qin: mpsc::Sender<Vec<u8>>, counters: Arc<Counters>) {
    struct F {
        sock: Arc<std::net::UdpSocket>,
        last: Instant,
        pump: JoinHandle<()>,
    }
    // a flow that goes (idle, evicted, the tunnel stopped) takes its reader with it
    impl Drop for F {
        fn drop(&mut self) {
            self.pump.abort();
        }
    }
    let mut flows: HashMap<(u8, u32), F> = HashMap::new();
    let mut clean = Instant::now();
    let mut addrs: HashMap<u16, SocketAddr> = HashMap::new();
    while let Some(d) = down.recv().await {
        let now = Instant::now();
        match d {
            Down::Quic(d) => {
                let _ = qin.try_send(d);
            }
            Down::Udp { pidx, flow, data } => {
                let Some(&port) = ports.get(pidx as usize) else { continue };
                if let Some(f) = flows.get_mut(&(pidx, flow)) {
                    f.last = now;
                    let _ = f.sock.send(&data);
                    continue;
                }
                let to = match addrs.get(&port) {
                    Some(a) => *a,
                    None => {
                        let Ok(Some(a)) = tokio::net::lookup_host((target.as_str(), port)).await.map(|mut i| i.next()) else { continue };
                        addrs.insert(port, a);
                        a
                    }
                };
                if flows.len() >= MAX_FLOWS {
                    let mut v: Vec<((u8, u32), Instant)> = flows.iter().map(|(k, f)| (*k, f.last)).collect();
                    v.sort_by_key(|x| x.1);
                    for (k, _) in v.into_iter().take(MAX_FLOWS / 8) {
                        if flows.remove(&k).is_some() {
                            counters.udp_flows.fetch_sub(1, Ordering::Relaxed);
                        }
                    }
                }
                let bind: SocketAddr = if to.is_ipv6() { "[::]:0".parse().expect("addr") } else { "0.0.0.0:0".parse().expect("addr") };
                let Ok((s2, sock)) = super::path::udp_bind(bind) else { continue };
                if sock.connect(to).is_err() {
                    continue;
                }
                let _ = sock.send(&data);
                let up2 = up.clone();
                let pump = tokio::spawn(async move {
                    let mut b = vec![0u8; 65535];
                    loop {
                        match s2.recv(&mut b).await {
                            Ok(n) => {
                                let _ = up2.try_send(Up::Udp { pidx, flow, data: b[..n].to_vec() });
                            }
                            Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
                        }
                    }
                });
                flows.insert((pidx, flow), F { sock, last: now, pump });
                counters.udp_flows.fetch_add(1, Ordering::Relaxed);
            }
        }
        if now.duration_since(clean) > Duration::from_secs(60) {
            clean = now;
            flows.retain(|_, f| {
                let keep = now.duration_since(f.last) < FLOW_IDLE;
                if !keep {
                    counters.udp_flows.fetch_sub(1, Ordering::Relaxed);
                }
                keep
            });
            addrs.clear();
        }
    }
}

// ------------------------------------------------------------------ TCP as QUIC streams inside the tunnel

type Shared = Arc<tokio::sync::Mutex<Option<quinn::Connection>>>;

async fn entry_tcp(bind: String, port: u16, to: u16, ep: Endpoint, conn: Shared, counters: Arc<Counters>) {
    let l = loop {
        match TcpListener::bind((bind.as_str(), port)).await {
            Ok(l) => break l,
            Err(e) => {
                eprintln!("VIP tunnel: TCP port {} is busy: {}", port, e);
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    };
    loop {
        let Ok((user, _)) = l.accept().await else {
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
        };
        let _ = user.set_nodelay(true);
        let (ep, conn, counters) = (ep.clone(), conn.clone(), counters.clone());
        tokio::spawn(async move {
            let Some(c) = connection(&ep, &conn).await else { return };
            let Ok((mut send, recv)) = c.open_bi().await else {
                // a connection that died under us: the next user connection makes a new one
                *conn.lock().await = None;
                return;
            };
            if send.write_all(&to.to_be_bytes()).await.is_err() {
                return;
            }
            counters.streams.fetch_add(1, Ordering::Relaxed);
            let mut q = tokio::io::join(recv, send);
            let mut user = user;
            let _ = tokio::io::copy_bidirectional(&mut user, &mut q).await;
            counters.streams.fetch_sub(1, Ordering::Relaxed);
        });
    }
}

/// The QUIC connection to the exit, made when the first user connection needs it (and again after it died)
async fn connection(ep: &Endpoint, conn: &Shared) -> Option<quinn::Connection> {
    let mut g = conn.lock().await;
    if let Some(c) = g.as_ref() {
        if c.close_reason().is_none() {
            return Some(c.clone());
        }
    }
    let addr: SocketAddr = EXIT_ADDR.parse().ok()?;
    let c = tokio::time::timeout(Duration::from_secs(15), ep.connect(addr, "kanki-vip").ok()?).await.ok()?.ok()?;
    *g = Some(c.clone());
    Some(c)
}

async fn exit_tcp(ep: Endpoint, target: String, allowed: HashSet<u16>, counters: Arc<Counters>) {
    let allowed = Arc::new(allowed);
    let target = Arc::new(target);
    while let Some(inc) = ep.accept().await {
        let (allowed, target, counters) = (allowed.clone(), target.clone(), counters.clone());
        tokio::spawn(async move {
            let Ok(c) = inc.await else { return };
            while let Ok((send, mut recv)) = c.accept_bi().await {
                let (allowed, target, counters) = (allowed.clone(), target.clone(), counters.clone());
                tokio::spawn(async move {
                    let mut p = [0u8; 2];
                    if tokio::time::timeout(Duration::from_secs(10), recv.read_exact(&mut p)).await.ok().and_then(|r| r.ok()).is_none() {
                        return;
                    }
                    let port = u16::from_be_bytes(p);
                    // only what this tunnel forwards
                    if !allowed.contains(&port) {
                        return;
                    }
                    let Ok(Ok(mut t)) = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect((target.as_str(), port))).await else { return };
                    let _ = t.set_nodelay(true);
                    counters.streams.fetch_add(1, Ordering::Relaxed);
                    let mut q = tokio::io::join(recv, send);
                    let _ = tokio::io::copy_bidirectional(&mut t, &mut q).await;
                    counters.streams.fetch_sub(1, Ordering::Relaxed);
                });
            }
        });
    }
}

fn transport() -> Arc<TransportConfig> {
    let mut t = TransportConfig::default();
    t.keep_alive_interval(Some(Duration::from_secs(4)));
    // a connection outlives a minute of outage: the tunnel's paths come back under it
    t.max_idle_timeout(Some(Duration::from_secs(60).try_into().expect("idle timeout")));
    t.stream_receive_window((8u32 * 1024 * 1024).into());
    t.receive_window((48u32 * 1024 * 1024).into());
    t.send_window(48 * 1024 * 1024);
    t.max_concurrent_bidi_streams(4096u32.into());
    t.max_concurrent_uni_streams(0u32.into());
    // every path of the tunnel takes 1200 bytes of QUIC in one packet
    t.initial_mtu(1200);
    t.min_mtu(1200);
    t.mtu_discovery_config(None);
    t.enable_segmentation_offload(false);
    t.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
    Arc::new(t)
}

fn client_endpoint(sock: Arc<VSock>) -> Result<Endpoint, String> {
    let mut ep = Endpoint::new_with_abstract_socket(EndpointConfig::default(), None, sock, Arc::new(TokioRuntime)).map_err(|e| e.to_string())?;
    ep.set_default_client_config(crate::tunnel::quic::client_config(transport()).map_err(|e| e.to_string())?);
    Ok(ep)
}

fn server_endpoint(sock: Arc<VSock>) -> Result<Endpoint, String> {
    let cfg = crate::tunnel::quic::server_config(transport()).map_err(|e| e.to_string())?;
    Endpoint::new_with_abstract_socket(EndpointConfig::default(), Some(cfg), sock, Arc::new(TokioRuntime)).map_err(|e| e.to_string())
}

/// A UDP socket for quinn whose datagrams travel in the tunnel
struct VSock {
    out: mpsc::Sender<Up>,
    inbox: Mutex<mpsc::Receiver<Vec<u8>>>,
    peer: SocketAddr,
    me: SocketAddr,
}

impl VSock {
    fn new(out: mpsc::Sender<Up>, inbox: mpsc::Receiver<Vec<u8>>, peer: &str, me: &str) -> VSock {
        VSock { out, inbox: Mutex::new(inbox), peer: peer.parse().expect("addr"), me: me.parse().expect("addr") }
    }
}

impl std::fmt::Debug for VSock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VSock").finish_non_exhaustive()
    }
}

#[derive(Debug)]
struct Ready;

impl UdpPoller for Ready {
    fn poll_writable(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncUdpSocket for VSock {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(Ready)
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        let seg = match transmit.segment_size {
            Some(s) if s > 0 => s,
            _ => transmit.contents.len().max(1),
        };
        for c in transmit.contents.chunks(seg) {
            // a full tunnel queue drops it: QUIC sends it again like any lost packet
            let _ = self.out.try_send(Up::Quic(c.to_vec()));
        }
        Ok(())
    }

    fn poll_recv(&self, cx: &mut Context, bufs: &mut [IoSliceMut<'_>], meta: &mut [RecvMeta]) -> Poll<io::Result<usize>> {
        let mut rx = self.inbox.lock().unwrap_or_else(|e| e.into_inner());
        let max = bufs.len().min(meta.len());
        let mut n = 0;
        while n < max {
            let d = if n == 0 {
                match rx.poll_recv(cx) {
                    Poll::Ready(Some(d)) => d,
                    Poll::Ready(None) => return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "the tunnel stopped"))),
                    Poll::Pending => return Poll::Pending,
                }
            } else {
                match rx.try_recv() {
                    Ok(d) => d,
                    Err(_) => break,
                }
            };
            let buf: &mut [u8] = &mut bufs[n];
            if d.len() > buf.len() {
                continue;
            }
            buf[..d.len()].copy_from_slice(&d);
            meta[n] = RecvMeta { addr: self.peer, len: d.len(), stride: d.len(), ..Default::default() };
            n += 1;
        }
        if n == 0 {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        Poll::Ready(Ok(n))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.me)
    }
}
