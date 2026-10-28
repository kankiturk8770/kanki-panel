//! The app side of the cores: one link to the server (made again by itself when it drops), TCP
//! streams over the mux and UDP flows over the datagram fast path or the mux.

use super::super::game::GameOpts;
use super::super::link::{self, Raw, Res};
use super::super::mux::{now_ms, Session, Shared};
use super::dgram::{self, DgLink};
use super::{gamec, Welcome, HELLO, NO, OK};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// Everything the app needs to reach one core (what a `kcore://` link carries).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ClientCfg {
    /// "game" (MIX+)
    pub kind: String,
    /// "host:port" of the server
    pub server: String,
    pub door: String,
    pub user: String,
    pub key: String,
    /// `game`: FEC of the KCP stream, as on the server ("" = 8:3)
    pub fec: String,
    /// copies of a small game datagram (1-3)
    pub copies: u8,
    /// false = all UDP over the stream (no fast path)
    pub datagrams: bool,
}

fn pct_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Some(v) = s.get(i + 1..i + 3).and_then(|h| u8::from_str_radix(h, 16).ok()) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

fn pct_encode(s: &str) -> String {
    let mut o = String::new();
    for c in s.bytes() {
        if c.is_ascii_alphanumeric() || b"-_.~".contains(&c) {
            o.push(c as char);
        } else {
            o.push_str(&format!("%{:02X}", c));
        }
    }
    o
}

impl ClientCfg {
    /// `kcore://user:key@host:port?type=game&door=…&fec=8:3&copies=2#name`
    pub fn parse(url: &str) -> Res<(ClientCfg, String)> {
        let rest = url.trim().strip_prefix("kcore://").ok_or("not a kcore:// link")?;
        let (rest, name) = match rest.split_once('#') {
            Some((a, b)) => (a, pct_decode(b)),
            None => (rest, String::new()),
        };
        let (rest, query) = rest.split_once('?').unwrap_or((rest, ""));
        let (cred, server) = rest.rsplit_once('@').ok_or("no user in the link")?;
        let (user, key) = cred.split_once(':').ok_or("no key in the link")?;
        let mut c = ClientCfg { server: server.trim_end_matches('/').to_string(), user: pct_decode(user), key: pct_decode(key), copies: 2, datagrams: true, ..Default::default() };
        for kv in query.split('&').filter(|x| !x.is_empty()) {
            let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
            let v = pct_decode(v);
            match k {
                "type" => c.kind = v,
                "door" => c.door = v,
                "fec" => c.fec = v,
                "copies" => c.copies = v.parse().unwrap_or(2),
                "dg" => c.datagrams = v != "0",
                _ => {}
            }
        }
        if !super::KINDS.contains(&c.kind.as_str()) {
            return Err(format!("unknown core type '{}'", c.kind).into());
        }
        if c.door.is_empty() || c.user.is_empty() || c.key.is_empty() || !c.server.contains(':') {
            return Err("the link misses the server, the user, the key or the door".into());
        }
        c.copies = c.copies.clamp(1, 3);
        Ok((c, name))
    }

    pub fn to_url(&self, name: &str) -> String {
        let mut q = format!("type={}&door={}", self.kind, pct_encode(&self.door));
        if !self.fec.is_empty() && self.kind == "game" {
            q.push_str(&format!("&fec={}", pct_encode(&self.fec)));
        }
        q.push_str(&format!("&copies={}", self.copies.clamp(1, 3)));
        let mut u = format!("kcore://{}:{}@{}?{}", pct_encode(&self.user), pct_encode(&self.key), self.server, q);
        if !name.is_empty() {
            u.push('#');
            u.push_str(&pct_encode(name));
        }
        u
    }
}

/// One live link: the mux session and maybe the datagram path.
pub struct Link {
    pub session: Arc<Session>,
    pub dg: Option<Arc<DgLink>>,
    tasks: Vec<JoinHandle<()>>,
}

impl Drop for Link {
    fn drop(&mut self) {
        self.session.kill();
        for t in &self.tasks {
            t.abort();
        }
    }
}

/// Where the answers of one UDP flow go: the SOCKS relay socket and the app's address there.
struct Flow {
    relay: Arc<UdpSocket>,
    to: Mutex<SocketAddr>,
    /// the SOCKS UDP header of the flow's target, put in front of every answer
    head: Vec<u8>,
    /// the flow goes as datagrams (decided by its first packet, then kept: one flow, one path,
    /// so the target always sees the same source port)
    dg: bool,
    last: AtomicU64,
    /// receives the flow's answers that came over the mux
    back: JoinHandle<()>,
}

pub struct Client {
    pub cfg: ClientCfg,
    pub shared: Arc<Shared>,
    cur: Mutex<Option<Arc<Link>>>,
    dialing: tokio::sync::Mutex<()>,
    flows: Mutex<HashMap<u32, Arc<Flow>>>,
    next_flow: AtomicU32,
    /// sends the mux's UDP answers to the flows' own loopback sockets
    back_tx: Arc<UdpSocket>,
    pub last_error: Mutex<String>,
}

/// most UDP flows at once (each holds one loopback socket)
const MAX_FLOWS: usize = 2048;

impl Client {
    pub async fn new(cfg: ClientCfg) -> Res<Arc<Client>> {
        Ok(Arc::new(Client {
            cfg,
            shared: Arc::new(Shared::default()),
            cur: Mutex::new(None),
            dialing: tokio::sync::Mutex::new(()),
            flows: Mutex::new(HashMap::new()),
            next_flow: AtomicU32::new(1),
            back_tx: Arc::new(UdpSocket::bind("127.0.0.1:0").await?),
            last_error: Mutex::new(String::new()),
        }))
    }

    /// The live link, if any (does not dial).
    pub fn current(&self) -> Option<Arc<Link>> {
        self.cur.lock().unwrap().clone().filter(|l| l.session.is_alive())
    }

    /// The live link, dialing a new one when there is none.
    pub async fn link(self: &Arc<Self>) -> Res<Arc<Link>> {
        if let Some(l) = self.current() {
            return Ok(l);
        }
        let _g = self.dialing.lock().await;
        if let Some(l) = self.current() {
            return Ok(l);
        }
        match tokio::time::timeout(Duration::from_secs(20), self.dial()).await {
            Ok(Ok(l)) => {
                let l = Arc::new(l);
                *self.cur.lock().unwrap() = Some(l.clone());
                self.last_error.lock().unwrap().clear();
                Ok(l)
            }
            Ok(Err(e)) => {
                *self.last_error.lock().unwrap() = e.to_string();
                Err(e)
            }
            Err(_) => {
                *self.last_error.lock().unwrap() = "connect timeout".into();
                Err("connect timeout".into())
            }
        }
    }

    /// Keeps a link up: dials at once, and again whenever it drops (with a short back-off).
    pub async fn keep_up(self: Arc<Self>) {
        let mut wait = 300u64;
        loop {
            match self.link().await {
                Ok(l) => {
                    wait = 300;
                    l.session.closed().await;
                }
                Err(_) => {
                    tokio::time::sleep(Duration::from_millis(wait)).await;
                    wait = (wait * 2).min(5_000);
                }
            }
        }
    }

    async fn dial(self: &Arc<Self>) -> Res<Link> {
        let c = &self.cfg;
        let addr: SocketAddr = tokio::net::lookup_host(c.server.as_str()).await?.next().ok_or("cannot resolve the server")?;
        let (dtx, mut drx) = mpsc::channel::<Vec<u8>>(1024);
        let (io, sock, mask) = gamec::dial(addr, &c.door, GameOpts::parse(&c.fec, false), dtx).await?;
        let wire = dgram::Wire::Udp { sock, mask, to: Mutex::new(None) };
        let (mut tx, mut rx) = link::handshake(Raw::Stream(io), &c.door, true, false).await?;
        let want_dg = c.datagrams;
        let auth = super::make_auth(&c.user, &c.key, want_dg);
        let mut m = HELLO.to_vec();
        m.extend_from_slice(&serde_json::to_vec(&auth)?);
        tx.send(&m).await?;
        let ans = tokio::time::timeout(Duration::from_secs(10), rx.recv()).await.map_err(|_| "the server did not answer")??;
        if let Some(why) = ans.strip_prefix(NO) {
            return Err(format!("refused: {}", String::from_utf8_lossy(why)).into());
        }
        let w: Welcome = serde_json::from_slice(ans.strip_prefix(OK).ok_or("bad answer")?)?;
        let session = Session::start(tx, rx, true, self.shared.clone());

        let mut tasks = vec![];
        let mut dg = None;
        if want_dg && w.sid != 0 {
            let mut key = [0u8; 32];
            if hex::decode_to_slice(&w.dk, &mut key).is_ok() {
                let max = dgram::GAME_MAX_BODY.min(w.dm as usize);
                let link = Arc::new(DgLink::new(w.sid, &key, true, wire, c.copies, max));
                let (me, l2) = (self.clone(), link.clone());
                tasks.push(tokio::spawn(async move {
                    while let Some(d) = drx.recv().await {
                        me.on_datagram(&l2, &d);
                    }
                }));
                dg = Some(link);
            }
        }
        Ok(Link { session, dg, tasks })
    }

    fn on_datagram(&self, link: &DgLink, d: &[u8]) {
        if let Some(b) = link.open(d) {
            if let Some((id, data)) = dgram::parse_down(&b) {
                self.shared.rx_bytes.fetch_add(data.len() as u64, Ordering::Relaxed);
                self.deliver(id, data);
            }
        }
    }

    /// An answer of flow `id` back to the app, with the SOCKS header of its target.
    fn deliver(&self, id: u32, data: &[u8]) {
        let Some(f) = self.flows.lock().unwrap().get(&id).cloned() else { return };
        f.last.store(now_ms(), Ordering::Relaxed);
        let mut p = Vec::with_capacity(f.head.len() + data.len());
        p.extend_from_slice(&f.head);
        p.extend_from_slice(data);
        let to = *f.to.lock().unwrap();
        let _ = f.relay.try_send_to(&p, to);
    }

    /// TCP: the app's connection to `target` ("ip:port"), carried to the server.
    pub async fn open_tcp(self: &Arc<Self>, s: TcpStream, target: &str) {
        if let Ok(l) = self.link().await {
            l.session.open_tcp(s, target).await;
        }
    }

    /// A new UDP flow towards `target` for a SOCKS relay. `first` decides its path.
    pub async fn new_flow(self: &Arc<Self>, relay: Arc<UdpSocket>, to: SocketAddr, head: Vec<u8>, first: usize) -> Res<u32> {
        let id = self.next_flow.fetch_add(1, Ordering::Relaxed);
        let back = UdpSocket::bind("127.0.0.1:0").await?;
        let back_addr = back.local_addr()?;
        let max = self.current().and_then(|l| l.dg.as_ref().map(|d| d.max_body)).unwrap_or(if self.cfg.datagrams { dgram::GAME_MAX_BODY } else { 0 });
        // body = flow (4) + target length (1) + target (up to ~47) + data
        let dg = max > 0 && first + 5 + 47 <= max;
        let me = Arc::downgrade(self);
        let task = tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            while let Ok(n) = back.recv(&mut buf).await {
                let Some(me) = me.upgrade() else { break };
                me.deliver(id, &buf[..n]);
            }
        });
        let f = Arc::new(Flow { relay, to: Mutex::new(to), head, dg, last: AtomicU64::new(now_ms()), back: task });
        {
            let mut flows = self.flows.lock().unwrap();
            if flows.len() >= MAX_FLOWS {
                let old: Vec<u32> = super::super::mux::oldest_eighth(flows.iter().map(|(k, f)| (*k, f.last.load(Ordering::Relaxed))));
                for k in old {
                    if let Some(f) = flows.remove(&k) {
                        f.back.abort();
                        self.shared.udp_back.lock().unwrap().remove(&k);
                    }
                }
            }
            flows.insert(id, f);
        }
        self.shared.udp_back.lock().unwrap().insert(id, (self.back_tx.clone(), back_addr, now_ms()));
        Ok(id)
    }

    /// One UDP packet of flow `id` to `target`.
    pub async fn send_udp(self: &Arc<Self>, id: u32, target: &str, from: SocketAddr, data: &[u8]) {
        let Some(f) = self.flows.lock().unwrap().get(&id).cloned() else { return };
        *f.to.lock().unwrap() = from;
        f.last.store(now_ms(), Ordering::Relaxed);
        let Ok(l) = self.link().await else { return };
        if f.dg {
            if let Some(d) = &l.dg {
                if d.send(&dgram::up_body(id, target, data)) {
                    self.shared.tx_bytes.fetch_add(data.len() as u64, Ordering::Relaxed);
                }
                // too big for a datagram on a datagram flow: dropped like a lost packet (a second
                // path would give the target a second source port)
                return;
            }
        }
        l.session.send_udp(id, target, data).await;
    }

    pub fn close_flow(&self, id: u32) {
        if let Some(f) = self.flows.lock().unwrap().remove(&id) {
            f.back.abort();
        }
        self.shared.udp_back.lock().unwrap().remove(&id);
    }

    /// last use of a flow (ms)
    pub fn flow_last(&self, id: u32) -> Option<u64> {
        self.flows.lock().unwrap().get(&id).map(|f| f.last.load(Ordering::Relaxed))
    }

    /// {"up", "rtt", "rx", "tx", "error"} for the app
    pub fn status(&self) -> serde_json::Value {
        let l = self.current();
        serde_json::json!({
            "up": l.is_some(),
            "kind": self.cfg.kind,
            "rtt": l.as_ref().map(|l| l.session.rtt_ms.load(Ordering::Relaxed)).unwrap_or(0),
            "fast": l.as_ref().map(|l| l.dg.is_some()).unwrap_or(false),
            "rx": self.shared.rx_bytes.load(Ordering::Relaxed),
            "tx": self.shared.tx_bytes.load(Ordering::Relaxed),
            "error": self.last_error.lock().unwrap().clone(),
        })
    }
}

impl Client {
    /// Round trip of one small UDP packet through the link to the server and back (the server's
    /// echo inside the tunnel, `kanki:echo`), in ms. None = no answer within 2 s.
    pub async fn echo_rtt(self: &Arc<Self>) -> Option<u64> {
        let l = self.link().await.ok()?;
        let sock = UdpSocket::bind("127.0.0.1:0").await.ok()?;
        let id = self.next_flow.fetch_add(1, Ordering::Relaxed);
        self.shared.udp_back.lock().unwrap().insert(id, (self.back_tx.clone(), sock.local_addr().ok()?, now_ms()));
        let t0 = std::time::Instant::now();
        let stamp = rand::random::<u64>().to_be_bytes();
        let mut got = None;
        if l.session.send_udp(id, super::super::probe::ECHO, &stamp).await {
            let mut b = [0u8; 64];
            if let Ok(Ok(n)) = tokio::time::timeout(Duration::from_secs(2), sock.recv(&mut b)).await {
                if b[..n] == stamp {
                    got = Some((t0.elapsed().as_millis() as u64).max(1));
                }
            }
        }
        self.shared.udp_back.lock().unwrap().remove(&id);
        got
    }
}

/// Dials once and measures the round trip inside the link (best of three), for the app's server
/// list. Returns milliseconds.
pub async fn ping(cfg: ClientCfg) -> Res<u64> {
    let c = Client::new(cfg).await?;
    c.link().await?;
    let mut best: Option<u64> = None;
    for _ in 0..3 {
        if let Some(r) = c.echo_rtt().await {
            best = Some(best.map_or(r, |b: u64| b.min(r)));
        }
    }
    let r = best.ok_or("no answer through the link");
    if let Some(l) = c.current() {
        l.session.kill();
    }
    Ok(r?)
}
