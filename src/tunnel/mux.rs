//! Kanki Tunnel mux: many user connections (TCP streams and UDP flows) over one encrypted link.
//!
//! Frame = [type u8][id u32 BE][payload]. Only the entry opens streams. Every stream has its own
//! flow-control window, so a slow user never blocks the others. UDP packets carry their target,
//! so the exit needs no extra setup message. PING/PONG measure the round trip and find dead links.

use super::link::{Rx, Tx};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{mpsc, watch, Semaphore};

const OPEN: u8 = 1;
const DATA: u8 = 2;
const FIN: u8 = 3;
const WIN: u8 = 4;
const RST: u8 = 5;
const UDP: u8 = 6;
const PING: u8 = 8;
const PONG: u8 = 9;

/// bytes one stream may have in flight before the other side says it has written them
const WINDOW: usize = 512 * 1024;
const CHUNK: usize = 16 * 1024;

pub fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

fn frame(t: u8, id: u32, payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(5 + payload.len());
    f.push(t);
    f.extend_from_slice(&id.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

/// Counters shared by every link of one tunnel side.
#[derive(Default)]
pub struct Shared {
    pub rx_bytes: AtomicU64,
    pub tx_bytes: AtomicU64,
    pub streams: AtomicU64,
    /// entry: UDP flow id -> (the listening socket, the user's address)
    pub udp_back: Mutex<HashMap<u32, (Arc<UdpSocket>, SocketAddr, u64)>>,
    /// exit: the only "host:port" targets the entry may ask for (empty = any)
    pub allowed: Mutex<HashSet<String>>,
}

impl Shared {
    fn may_dial(&self, target: &str) -> bool {
        let a = self.allowed.lock().unwrap();
        a.is_empty() || a.contains(target)
    }
}

struct Slot {
    data: Option<mpsc::UnboundedSender<Vec<u8>>>,
    credit: Arc<Semaphore>,
}

pub struct Session {
    out: mpsc::Sender<Vec<u8>>,
    slots: Mutex<HashMap<u32, Slot>>,
    next_id: AtomicU32,
    entry: bool,
    pub shared: Arc<Shared>,
    pub rtt_ms: AtomicU64,
    last_rx: AtomicU64,
    alive: AtomicBool,
    dead_tx: watch::Sender<bool>,
    /// exit: UDP flow id -> socket that talks to the target
    udp_out: Mutex<HashMap<u32, Arc<UdpSocket>>>,
    pub transport: String,
    pub since: u64,
}

impl Session {
    /// Starts the reader, writer and keepalive tasks of a link and returns the session.
    pub fn start(tx: Tx, rx: Rx, entry: bool, shared: Arc<Shared>, transport: &str) -> Arc<Session> {
        let (out, out_rx) = mpsc::channel::<Vec<u8>>(1024);
        let (dead_tx, _) = watch::channel(false);
        let s = Arc::new(Session {
            out,
            slots: Mutex::new(HashMap::new()),
            next_id: AtomicU32::new(1),
            entry,
            shared,
            rtt_ms: AtomicU64::new(0),
            last_rx: AtomicU64::new(now_ms()),
            alive: AtomicBool::new(true),
            dead_tx,
            udp_out: Mutex::new(HashMap::new()),
            transport: transport.to_string(),
            since: now_ms(),
        });
        tokio::spawn(writer(s.clone(), tx, out_rx));
        tokio::spawn(reader(s.clone(), rx));
        tokio::spawn(keepalive(s.clone()));
        s
    }

    pub fn is_alive(&self) -> bool {
        self.alive.load(Ordering::Relaxed)
    }

    /// Waits until the link is gone.
    pub async fn closed(&self) {
        let mut w = self.dead_tx.subscribe();
        loop {
            if *w.borrow() || !self.is_alive() {
                return;
            }
            if w.changed().await.is_err() {
                return;
            }
        }
    }

    pub fn kill(&self) {
        if self.alive.swap(false, Ordering::Relaxed) {
            self.dead_tx.send_replace(true);
            let mut slots = self.slots.lock().unwrap();
            for (_, s) in slots.drain() {
                s.credit.close();
            }
            self.udp_out.lock().unwrap().clear();
        }
    }

    async fn send(&self, f: Vec<u8>) -> bool {
        if !self.is_alive() {
            return false;
        }
        self.out.send(f).await.is_ok()
    }

    fn add_slot(&self, id: u32) -> (mpsc::UnboundedReceiver<Vec<u8>>, Arc<Semaphore>) {
        let (tx, rx) = mpsc::unbounded_channel();
        let credit = Arc::new(Semaphore::new(WINDOW));
        self.slots.lock().unwrap().insert(id, Slot { data: Some(tx), credit: credit.clone() });
        (rx, credit)
    }

    fn remove(&self, id: u32) {
        if let Some(s) = self.slots.lock().unwrap().remove(&id) {
            s.credit.close();
        }
    }

    /// entry: carries a user's TCP connection to `target` (dialed on the exit)
    pub async fn open_tcp(self: &Arc<Self>, user: TcpStream, target: &str) {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (rx, credit) = self.add_slot(id);
        if !self.send(frame(OPEN, id, target.as_bytes())).await {
            self.remove(id);
            return;
        }
        pipe(self.clone(), id, user, rx, credit).await;
    }

    /// entry: one UDP packet of flow `id` to `target`
    pub async fn send_udp(&self, id: u32, target: &str, data: &[u8]) -> bool {
        let t = target.as_bytes();
        let mut p = Vec::with_capacity(1 + t.len() + data.len());
        p.push(t.len() as u8);
        p.extend_from_slice(t);
        p.extend_from_slice(data);
        self.shared.tx_bytes.fetch_add(data.len() as u64, Ordering::Relaxed);
        self.send(frame(UDP, id, &p)).await
    }

    fn deliver(&self, id: u32, data: Vec<u8>) {
        let slots = self.slots.lock().unwrap();
        if let Some(Some(tx)) = slots.get(&id).map(|s| s.data.as_ref()) {
            let _ = tx.send(data);
        }
    }

    fn fin(&self, id: u32) {
        if let Some(s) = self.slots.lock().unwrap().get_mut(&id) {
            s.data = None;
        }
    }

    fn rst(&self, id: u32) {
        if let Some(s) = self.slots.lock().unwrap().get_mut(&id) {
            s.data = None;
            s.credit.close();
        }
    }

    fn window(&self, id: u32, n: usize) {
        if let Some(s) = self.slots.lock().unwrap().get(&id) {
            s.credit.add_permits(n);
        }
    }
}

async fn writer(s: Arc<Session>, mut tx: Tx, mut out_rx: mpsc::Receiver<Vec<u8>>) {
    let mut dead = s.dead_tx.subscribe();
    loop {
        tokio::select! {
            f = out_rx.recv() => {
                let Some(f) = f else { break };
                if tx.send(&f).await.is_err() {
                    break;
                }
            }
            _ = dead.changed() => break,
        }
    }
    s.kill();
    tx.close().await;
}

async fn reader(s: Arc<Session>, mut rx: Rx) {
    let mut dead = s.dead_tx.subscribe();
    loop {
        let r = tokio::select! {
            r = rx.recv() => r,
            _ = dead.changed() => break,
        };
        let Ok(f) = r else { break };
        if f.len() < 5 {
            break;
        }
        s.last_rx.store(now_ms(), Ordering::Relaxed);
        let t = f[0];
        let id = u32::from_be_bytes([f[1], f[2], f[3], f[4]]);
        let p = &f[5..];
        match t {
            DATA => {
                s.shared.rx_bytes.fetch_add(p.len() as u64, Ordering::Relaxed);
                s.deliver(id, p.to_vec());
            }
            WIN if p.len() == 4 => s.window(id, u32::from_be_bytes([p[0], p[1], p[2], p[3]]) as usize),
            FIN => s.fin(id),
            RST => s.rst(id),
            OPEN if !s.entry => {
                let target = String::from_utf8_lossy(p).to_string();
                let (rx_d, credit) = s.add_slot(id);
                tokio::spawn(exit_open(s.clone(), id, target, rx_d, credit));
            }
            UDP => {
                if p.is_empty() {
                    continue;
                }
                let tl = p[0] as usize;
                if p.len() < 1 + tl {
                    continue;
                }
                let data = &p[1 + tl..];
                if s.entry {
                    // a reply from the target: back to the user
                    s.shared.rx_bytes.fetch_add(data.len() as u64, Ordering::Relaxed);
                    let back = s.shared.udp_back.lock().unwrap().get(&id).map(|(sock, addr, _)| (sock.clone(), *addr));
                    if let Some((sock, addr)) = back {
                        let _ = sock.try_send_to(data, addr);
                    }
                } else {
                    let target = String::from_utf8_lossy(&p[1..1 + tl]).to_string();
                    exit_udp(&s, id, &target, data).await;
                }
            }
            PING => {
                let _ = s.send(frame(PONG, 0, p)).await;
            }
            PONG if p.len() == 8 => {
                let t0 = u64::from_be_bytes([p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7]]);
                s.rtt_ms.store(now_ms().saturating_sub(t0), Ordering::Relaxed);
            }
            _ => {}
        }
    }
    s.kill();
}

async fn keepalive(s: Arc<Session>) {
    let mut dead = s.dead_tx.subscribe();
    loop {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(8)) => {}
            _ = dead.changed() => return,
        }
        if !s.is_alive() {
            return;
        }
        if now_ms().saturating_sub(s.last_rx.load(Ordering::Relaxed)) > 30_000 {
            // nothing came back for 30 s: the path is stalled, give the link up so a new one is made
            s.kill();
            return;
        }
        let _ = s.send(frame(PING, 0, &now_ms().to_be_bytes())).await;
    }
}

/// exit: dials the target of a stream the entry opened
async fn exit_open(s: Arc<Session>, id: u32, target: String, rx: mpsc::UnboundedReceiver<Vec<u8>>, credit: Arc<Semaphore>) {
    if !s.shared.may_dial(&target) {
        let _ = s.send(frame(RST, id, &[])).await;
        s.remove(id);
        return;
    }
    match tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(target.as_str())).await {
        Ok(Ok(tcp)) => {
            let _ = tcp.set_nodelay(true);
            pipe(s, id, tcp, rx, credit).await;
        }
        _ => {
            let _ = s.send(frame(RST, id, &[])).await;
            s.remove(id);
        }
    }
}

/// exit: sends a UDP packet to its target, opening a socket for a new flow
async fn exit_udp(s: &Arc<Session>, id: u32, target: &str, data: &[u8]) {
    let existing = s.udp_out.lock().unwrap().get(&id).cloned();
    let sock = match existing {
        Some(x) => x,
        None => {
            if !s.shared.may_dial(target) {
                return;
            }
            let bind = if target.starts_with('[') { "[::]:0" } else { "0.0.0.0:0" };
            let Ok(sock) = UdpSocket::bind(bind).await else { return };
            if sock.connect(target).await.is_err() {
                return;
            }
            let sock = Arc::new(sock);
            s.udp_out.lock().unwrap().insert(id, sock.clone());
            tokio::spawn(exit_udp_back(s.clone(), id, sock.clone()));
            sock
        }
    };
    s.shared.rx_bytes.fetch_add(data.len() as u64, Ordering::Relaxed);
    let _ = sock.send(data).await;
}

async fn exit_udp_back(s: Arc<Session>, id: u32, sock: Arc<UdpSocket>) {
    let mut buf = vec![0u8; 65536];
    let mut dead = s.dead_tx.subscribe();
    loop {
        let r = tokio::select! {
            r = tokio::time::timeout(Duration::from_secs(180), sock.recv(&mut buf)) => r,
            _ = dead.changed() => break,
        };
        match r {
            Ok(Ok(n)) => {
                let mut p = Vec::with_capacity(1 + n);
                p.push(0);
                p.extend_from_slice(&buf[..n]);
                s.shared.tx_bytes.fetch_add(n as u64, Ordering::Relaxed);
                if !s.send(frame(UDP, id, &p)).await {
                    break;
                }
            }
            _ => break,
        }
    }
    s.udp_out.lock().unwrap().remove(&id);
}

/// Copies one TCP connection both ways through the mux, with flow control.
async fn pipe(s: Arc<Session>, id: u32, tcp: TcpStream, mut rx: mpsc::UnboundedReceiver<Vec<u8>>, credit: Arc<Semaphore>) {
    if !s.is_alive() {
        s.remove(id);
        return;
    }
    s.shared.streams.fetch_add(1, Ordering::Relaxed);
    let (mut r, mut w) = tcp.into_split();
    let s1 = s.clone();
    let up = async move {
        let mut buf = vec![0u8; CHUNK];
        let mut dead = s1.dead_tx.subscribe();
        loop {
            let n = tokio::select! {
                res = r.read(&mut buf) => match res { Ok(0) | Err(_) => break, Ok(n) => n },
                _ = dead.changed() => break,
            };
            match credit.acquire_many(n as u32).await {
                Ok(p) => p.forget(),
                Err(_) => break,
            }
            s1.shared.tx_bytes.fetch_add(n as u64, Ordering::Relaxed);
            if !s1.send(frame(DATA, id, &buf[..n])).await {
                break;
            }
        }
        let _ = s1.send(frame(FIN, id, &[])).await;
    };
    let s2 = s.clone();
    let down = async move {
        while let Some(d) = rx.recv().await {
            let n = d.len();
            if w.write_all(&d).await.is_err() {
                // the user is gone: tell the other side to stop sending
                let _ = s2.send(frame(RST, id, &[])).await;
                break;
            }
            let _ = s2.send(frame(WIN, id, &(n as u32).to_be_bytes())).await;
        }
        let _ = w.shutdown().await;
    };
    tokio::join!(up, down);
    s.remove(id);
    s.shared.streams.fetch_sub(1, Ordering::Relaxed);
}
