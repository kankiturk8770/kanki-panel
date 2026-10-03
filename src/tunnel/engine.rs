//! Kanki Tunnel engine: runs the tunnels this server is part of.
//!
//! entry = the server users connect to (for example in Iran); exit = the server that reaches the
//! targets (for example the VPN server abroad). In `reverse` mode the exit dials the entry, in
//! `direct` mode the entry dials the exit. Links reconnect by themselves; a stalled link is
//! dropped after 30 s and a new one is made.

use super::link::{self, Res};
use super::mux::{now_ms, Session, Shared};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::{TcpListener, UdpSocket};
use tokio::task::JoinHandle;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
#[serde(default)]
pub struct Spec {
    pub id: String,
    pub name: String,
    /// "entry" | "exit"
    pub role: String,
    /// "reverse" (exit dials entry) | "direct" (entry dials exit)
    pub mode: String,
    /// "tcp" | "tcpmux" | "ws" | "wss" | "quic" | "kcp"
    pub transport: String,
    /// tunnel port on the listening side
    pub port: u16,
    /// dialing side: "host:port" of the listening side
    pub remote: String,
    pub token: String,
    /// parallel links (tcpmux / ws / wss)
    pub conns: u32,
    pub sni: String,
    pub path: String,
    /// forwarded ports: "443" or "8443:443" (port on the entry : port on the exit)
    pub tcp: Vec<String>,
    pub udp: Vec<String>,
    /// exit: the host the forwarded ports are reached on
    pub target: String,
    /// wss listener: certificate files (empty = self-signed)
    pub cert: String,
    pub key: String,
}

impl Spec {
    pub fn listens(&self) -> bool {
        (self.role == "entry" && self.mode != "direct") || (self.role == "exit" && self.mode == "direct")
    }
    fn links(&self) -> u32 {
        match self.transport.as_str() {
            "tcp" => 1,
            _ => self.conns.clamp(1, 16),
        }
    }
    fn target_host(&self) -> String {
        let t = self.target.trim();
        if t.is_empty() { "127.0.0.1".into() } else { t.to_string() }
    }
}

/// "443" -> (443, 443); "8443:443" -> (8443, 443); "1000-1005" -> six pairs
pub fn parse_ports(list: &[String]) -> Vec<(u16, u16)> {
    let mut out = vec![];
    for item in list {
        for part in item.split(',') {
            let p = part.trim();
            if p.is_empty() {
                continue;
            }
            if let Some((a, b)) = p.split_once(':') {
                if let (Ok(a), Ok(b)) = (a.trim().parse::<u16>(), b.trim().parse::<u16>()) {
                    if a > 0 && b > 0 {
                        out.push((a, b));
                    }
                }
            } else if let Some((a, b)) = p.split_once('-') {
                if let (Ok(a), Ok(b)) = (a.trim().parse::<u16>(), b.trim().parse::<u16>()) {
                    if a > 0 && a <= b && b - a < 512 {
                        for x in a..=b {
                            out.push((x, x));
                        }
                    }
                }
            } else if let Ok(a) = p.parse::<u16>() {
                if a > 0 {
                    out.push((a, a));
                }
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct Status {
    pub id: String,
    pub role: String,
    pub links: usize,
    pub want: usize,
    pub rtt_ms: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub streams: u64,
    pub udp_flows: usize,
    pub error: String,
    pub since: u64,
    pub transport: String,
    pub listening: bool,
}

struct State {
    sessions: Mutex<Vec<Arc<Session>>>,
    shared: Arc<Shared>,
    error: Mutex<String>,
    rr: AtomicUsize,
    next_udp: AtomicU32,
}

impl State {
    fn set_err(&self, e: impl ToString) {
        *self.error.lock().unwrap() = e.to_string();
    }
    fn add(&self, s: Arc<Session>) {
        self.sessions.lock().unwrap().push(s);
        self.error.lock().unwrap().clear();
    }
    fn drop_dead(&self) {
        self.sessions.lock().unwrap().retain(|s| s.is_alive());
    }
    fn pick(&self, key: usize) -> Option<Arc<Session>> {
        let v = self.sessions.lock().unwrap();
        let alive: Vec<&Arc<Session>> = v.iter().filter(|s| s.is_alive()).collect();
        if alive.is_empty() {
            return None;
        }
        Some(alive[key % alive.len()].clone())
    }
    async fn wait_pick(&self, key: usize) -> Option<Arc<Session>> {
        for _ in 0..40 {
            if let Some(s) = self.pick(key) {
                return Some(s);
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        None
    }
}

pub struct Running {
    pub spec: Spec,
    state: Arc<State>,
    tasks: Vec<JoinHandle<()>>,
}

impl Running {
    pub fn start(spec: Spec) -> Running {
        let shared = Arc::new(Shared::default());
        if spec.role == "exit" {
            // the exit only dials what this tunnel forwards
            let host = spec.target_host();
            let mut allow = HashSet::new();
            for (_, b) in parse_ports(&spec.tcp).into_iter().chain(parse_ports(&spec.udp)) {
                allow.insert(format!("{}:{}", host, b));
            }
            *shared.allowed.lock().unwrap() = allow;
        }
        let state = Arc::new(State {
            sessions: Mutex::new(vec![]),
            shared,
            error: Mutex::new(String::new()),
            rr: AtomicUsize::new(0),
            next_udp: AtomicU32::new(1),
        });
        let mut tasks = vec![];
        if spec.listens() {
            tasks.push(tokio::spawn(listen_loop(spec.clone(), state.clone())));
        } else {
            for i in 0..spec.links() {
                tasks.push(tokio::spawn(dial_loop(spec.clone(), state.clone(), i)));
            }
        }
        if spec.role == "entry" {
            let host = spec.target_host();
            for (a, b) in parse_ports(&spec.tcp) {
                tasks.push(tokio::spawn(user_tcp(a, format!("{}:{}", host, b), state.clone())));
            }
            for (a, b) in parse_ports(&spec.udp) {
                tasks.push(tokio::spawn(user_udp(a, format!("{}:{}", host, b), state.clone())));
            }
        }
        Running { spec, state, tasks }
    }

    pub fn stop(self) {
        for t in &self.tasks {
            t.abort();
        }
        for s in self.state.sessions.lock().unwrap().drain(..) {
            s.kill();
        }
        self.state.shared.udp_back.lock().unwrap().clear();
    }

    pub fn status(&self) -> Status {
        let v = self.state.sessions.lock().unwrap();
        let alive: Vec<&Arc<Session>> = v.iter().filter(|s| s.is_alive()).collect();
        let rtts: Vec<u64> = alive.iter().map(|s| s.rtt_ms.load(Ordering::Relaxed)).filter(|r| *r > 0).collect();
        let sh = &self.state.shared;
        Status {
            id: self.spec.id.clone(),
            role: self.spec.role.clone(),
            links: alive.len(),
            want: self.spec.links() as usize,
            rtt_ms: if rtts.is_empty() { 0 } else { rtts.iter().sum::<u64>() / rtts.len() as u64 },
            rx_bytes: sh.rx_bytes.load(Ordering::Relaxed),
            tx_bytes: sh.tx_bytes.load(Ordering::Relaxed),
            streams: sh.streams.load(Ordering::Relaxed),
            udp_flows: sh.udp_back.lock().unwrap().len(),
            error: self.state.error.lock().unwrap().clone(),
            since: alive.iter().map(|s| s.since).min().unwrap_or(0) / 1000,
            transport: self.spec.transport.clone(),
            listening: self.spec.listens(),
        }
    }
}

async fn run_link(spec: &Spec, state: &Arc<State>, raw: link::Raw, client: bool) -> Res<()> {
    let (tx, rx) = link::handshake(raw, &spec.token, client).await?;
    let s = Session::start(tx, rx, spec.role == "entry", state.shared.clone(), &spec.transport);
    state.add(s.clone());
    s.closed().await;
    state.drop_dead();
    Ok(())
}

async fn listen_loop(spec: Spec, state: Arc<State>) {
    let mut l = loop {
        match link::Listener::bind(&spec.transport, spec.port, &spec.cert, &spec.key).await {
            Ok(l) => break l,
            Err(e) => {
                state.set_err(format!("cannot listen on port {}: {}", spec.port, e));
                tokio::time::sleep(Duration::from_secs(3)).await;
            }
        }
    };
    {
        let mut e = state.error.lock().unwrap();
        if e.starts_with("cannot listen") {
            e.clear();
        }
    }
    let spec = Arc::new(spec);
    loop {
        let (raw, peer) = match l.accept().await {
            Ok(x) => x,
            Err(_) => {
                tokio::time::sleep(Duration::from_millis(200)).await;
                continue;
            }
        };
        let (spec, state) = (spec.clone(), state.clone());
        tokio::spawn(async move {
            if let Err(e) = run_link(&spec, &state, raw, false).await {
                // wrong tokens from scanners are not worth showing; real failures are
                let m = e.to_string();
                if !m.contains("bad record") && !m.contains("bad hello") {
                    state.set_err(format!("{}: {}", peer, m));
                }
            }
        });
    }
}

async fn dial_loop(spec: Spec, state: Arc<State>, n: u32) {
    // links start a little apart so they do not all hit the other side at once
    tokio::time::sleep(Duration::from_millis(150 * n as u64)).await;
    let mut wait = 1u64;
    loop {
        let t0 = now_ms();
        match link::dial(&spec.transport, &spec.remote, &spec.sni, &spec.path).await {
            Ok(raw) => match run_link(&spec, &state, raw, true).await {
                Ok(()) => {}
                Err(e) => state.set_err(e),
            },
            Err(e) => state.set_err(format!("{}: {}", spec.remote, e)),
        }
        // a link that lived for a while resets the back-off
        if now_ms().saturating_sub(t0) > 20_000 {
            wait = 1;
        }
        tokio::time::sleep(Duration::from_secs(wait)).await;
        wait = (wait * 2).min(10);
    }
}

async fn user_tcp(port: u16, target: String, state: Arc<State>) {
    let addr = format!("0.0.0.0:{}", port);
    let l = loop {
        match TcpListener::bind(&addr).await {
            Ok(l) => break l,
            Err(e) => {
                state.set_err(format!("TCP port {} is busy: {}", port, e));
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    };
    let target = Arc::new(target);
    loop {
        let Ok((user, _)) = l.accept().await else {
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
        };
        let _ = user.set_nodelay(true);
        let (state, target) = (state.clone(), target.clone());
        tokio::spawn(async move {
            let key = state.rr.fetch_add(1, Ordering::Relaxed);
            if let Some(s) = state.wait_pick(key).await {
                s.open_tcp(user, &target).await;
            }
        });
    }
}

async fn user_udp(port: u16, target: String, state: Arc<State>) {
    let addr = format!("0.0.0.0:{}", port);
    let sock = loop {
        match UdpSocket::bind(&addr).await {
            Ok(s) => break Arc::new(s),
            Err(e) => {
                state.set_err(format!("UDP port {} is busy: {}", port, e));
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    };
    let mut flows: HashMap<SocketAddr, (u32, u64)> = HashMap::new();
    let mut buf = vec![0u8; 65536];
    let mut last_clean = now_ms();
    loop {
        let Ok((n, from)) = sock.recv_from(&mut buf).await else { continue };
        let now = now_ms();
        let id = match flows.get_mut(&from) {
            Some(f) => {
                f.1 = now;
                f.0
            }
            None => {
                let id = state.next_udp.fetch_add(1, Ordering::Relaxed);
                flows.insert(from, (id, now));
                id
            }
        };
        state.shared.udp_back.lock().unwrap().insert(id, (sock.clone(), from, now));
        // one flow stays on one link, so its packets keep their order
        if let Some(s) = state.pick(id as usize) {
            s.send_udp(id, &target, &buf[..n]).await;
        }
        if now.saturating_sub(last_clean) > 60_000 {
            last_clean = now;
            let old: Vec<(SocketAddr, u32)> = flows.iter().filter(|(_, f)| now.saturating_sub(f.1) > 180_000).map(|(a, f)| (*a, f.0)).collect();
            let mut back = state.shared.udp_back.lock().unwrap();
            for (a, id) in old {
                flows.remove(&a);
                back.remove(&id);
            }
        }
    }
}

/// Keeps the running tunnels equal to the wanted list.
pub struct Manager {
    running: tokio::sync::Mutex<HashMap<String, Running>>,
}

impl Default for Manager {
    fn default() -> Self {
        Manager { running: tokio::sync::Mutex::new(HashMap::new()) }
    }
}

impl Manager {
    pub async fn apply(&self, specs: Vec<Spec>) {
        let mut run = self.running.lock().await;
        let keys: Vec<String> = run.keys().cloned().collect();
        for k in keys {
            let keep = specs.iter().any(|s| s.id == k && run.get(&k).map(|r| &r.spec == s).unwrap_or(false));
            if !keep {
                if let Some(r) = run.remove(&k) {
                    eprintln!("tunnel {}: stopped", k);
                    r.stop();
                }
            }
        }
        for s in specs {
            if s.id.is_empty() || run.contains_key(&s.id) {
                continue;
            }
            eprintln!("tunnel {} ({}): starting as {} over {}", s.name, s.id, s.role, s.transport);
            run.insert(s.id.clone(), Running::start(s));
        }
    }

    pub async fn statuses(&self) -> Vec<Status> {
        self.running.lock().await.values().map(|r| r.status()).collect()
    }
}
