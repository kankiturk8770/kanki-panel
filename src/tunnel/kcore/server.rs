//! The server side of the cores: the listeners, the users, and the exit of the game datagrams.

use super::super::game::GameOpts;
use super::super::link::{self, BoxIo, Raw, Res};
use super::super::mux::{now_ms, Session, Shared};
use super::dgram::{self, DgLink};
use super::{gamec, Auth, Welcome, HELLO, NO, OK};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(default)]
pub struct CoreUser {
    pub name: String,
    pub key: String,
    /// devices at the same time (0 = no limit)
    pub max: i64,
    /// the cores this user may use ("game"); empty = all of them
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub cores: Vec<String>,
}

/// What a server runs. A port of 0 = that core is off.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(default)]
pub struct CoreCfg {
    /// the secret of the mask and the link handshake (the same for every user of this server)
    pub door: String,
    /// MIX+ (the Game-FEC transport, UDP)
    pub game: u16,
    /// FEC of the game core's KCP stream: "data:parity", "" = 8:3, "off"
    pub fec: String,
    /// copies of a small game datagram (1-3, 0 = 2)
    pub copies: u8,
    /// the cores with the game datagram fast path ("game"); off = UDP inside the stream, exactly
    /// like the tunnels do
    #[serde(default)]
    pub fast: Vec<String>,
    pub users: Vec<CoreUser>,
}

impl CoreCfg {
    pub fn any_on(&self) -> bool {
        !self.door.is_empty() && self.game > 0
    }
    /// what needs the listeners to start again when it changes (users change in place)
    fn listen_key(&self) -> (String, u16, String, u8, Vec<String>) {
        (self.door.clone(), self.game, self.fec.clone(), self.copies, self.fast.clone())
    }
    pub fn copies(&self) -> u8 {
        if self.copies == 0 { 2 } else { self.copies.min(3) }
    }
}

/// One user while the server runs: their counters (in `shared`) and live sessions.
struct Slot {
    key: String,
    max: i64,
    cores: Vec<String>,
    shared: Arc<Shared>,
    /// (session id, the session, when it started)
    live: Mutex<Vec<(u64, Arc<Session>, &'static str)>>,
}

impl Slot {
    fn new(u: &CoreUser) -> Slot {
        let shared = Arc::new(Shared::default());
        shared.public_only.store(true, Ordering::Relaxed);
        Slot { key: u.key.clone(), max: u.max, cores: u.cores.clone(), shared, live: Mutex::new(vec![]) }
    }
    fn kill_all(&self) {
        for (_, s, _) in self.live.lock().unwrap().drain(..) {
            s.kill();
        }
    }
}

struct State {
    door: String,
    copies: u8,
    fast: Vec<String>,
    users: RwLock<HashMap<String, Arc<Slot>>>,
    /// auth nonces seen in the last minutes (an auth is good once)
    seen: Mutex<HashMap<String, u64>>,
    hub: Arc<gamec::Hub>,
}

/// A connection ready for the link handshake, with what its core gives the datagram path.
enum Conn {
    Game(Raw),
}

/// The running cores of this server. Dropping it stops them and frees the ports.
pub struct CoreServer {
    key: (String, u16, String, u8, Vec<String>),
    state: Arc<State>,
    tasks: Vec<JoinHandle<()>>,
    _relay: Option<gamec::Relay>,
    /// what failed to start (a port in use …), by core
    pub errors: Vec<(String, String)>,
}

impl Drop for CoreServer {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
        for s in self.state.users.read().unwrap().values() {
            s.kill_all();
        }
    }
}

impl CoreServer {
    /// Starts the cores of `cfg`. A core that cannot start is skipped and named in `errors`.
    pub async fn start(cfg: &CoreCfg) -> CoreServer {
        let state = Arc::new(State {
            door: cfg.door.clone(),
            copies: cfg.copies(),
            fast: cfg.fast.clone(),
            users: RwLock::new(HashMap::new()),
            seen: Mutex::new(HashMap::new()),
            hub: Arc::new(gamec::Hub::default()),
        });
        let mut me = CoreServer { key: cfg.listen_key(), state: state.clone(), tasks: vec![], _relay: None, errors: vec![] };
        me.set_users(&cfg.users);
        let (tx, mut rx) = mpsc::channel::<(Conn, &'static str)>(64);

        if cfg.game > 0 {
            match start_game(cfg, state.hub.clone(), tx.clone()).await {
                Ok((relay, task)) => {
                    me._relay = Some(relay);
                    me.tasks.push(task);
                }
                Err(e) => me.errors.push(("game".into(), e.to_string())),
            }
        }
        drop(tx);
        let st = state.clone();
        me.tasks.push(tokio::spawn(async move {
            while let Some((c, kind)) = rx.recv().await {
                tokio::spawn(serve_conn(st.clone(), c, kind));
            }
        }));
        let st = state.clone();
        me.tasks.push(tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(30)).await;
                let now = super::now_secs();
                st.seen.lock().unwrap().retain(|_, t| now.saturating_sub(*t) < 2 * super::AUTH_SKEW_SECS + 60);
                // drop the sessions that ended
                for s in st.users.read().unwrap().values() {
                    s.live.lock().unwrap().retain(|(_, x, _)| x.is_alive());
                }
            }
        }));
        me
    }

    /// The listeners have to start again for this config (users alone change in place).
    pub fn needs_restart(&self, cfg: &CoreCfg) -> bool {
        self.key != cfg.listen_key()
    }

    /// New user list: a user whose key changed or who is gone is cut off at once.
    pub fn set_users(&self, users: &[CoreUser]) {
        let mut map = self.state.users.write().unwrap();
        let mut next: HashMap<String, Arc<Slot>> = HashMap::new();
        for u in users.iter().filter(|u| !u.name.is_empty() && !u.key.is_empty()) {
            let slot = match map.remove(&u.name) {
                // a new key or other cores: the old sessions end (they may be on a core taken away)
                Some(old) if old.key == u.key && old.cores == u.cores => {
                    if old.max == u.max {
                        old
                    } else {
                        // same counters and sessions, new limit
                        let s = Arc::new(Slot { key: old.key.clone(), max: u.max, cores: old.cores.clone(), shared: old.shared.clone(), live: Mutex::new(std::mem::take(&mut *old.live.lock().unwrap())) });
                        s
                    }
                }
                Some(old) => {
                    old.kill_all();
                    Arc::new(Slot::new(u))
                }
                None => Arc::new(Slot::new(u)),
            };
            next.insert(u.name.clone(), slot);
        }
        for (_, gone) in map.drain() {
            gone.kill_all();
        }
        *map = next;
    }

    /// Bytes (received from the user, sent to the user) per user since the server started.
    pub fn traffic(&self) -> HashMap<String, (i64, i64)> {
        self.state
            .users
            .read()
            .unwrap()
            .iter()
            .map(|(n, s)| (n.clone(), (s.shared.tx_bytes.load(Ordering::Relaxed) as i64, s.shared.rx_bytes.load(Ordering::Relaxed) as i64)))
            .collect()
    }

    /// Devices connected now, per user (users with none are left out).
    #[allow(dead_code)]
    pub fn online(&self) -> HashMap<String, i64> {
        self.state
            .users
            .read()
            .unwrap()
            .iter()
            .filter_map(|(n, s)| {
                let c = s.live.lock().unwrap().iter().filter(|(_, x, _)| x.is_alive()).count() as i64;
                (c > 0).then(|| (n.clone(), c))
            })
            .collect()
    }

    /// Devices connected now, per user and core: (user, core, count).
    pub fn online_by_core(&self) -> Vec<(String, String, i64)> {
        let mut out = vec![];
        for (n, s) in self.state.users.read().unwrap().iter() {
            let mut m: HashMap<&str, i64> = HashMap::new();
            for (_, x, k) in s.live.lock().unwrap().iter() {
                if x.is_alive() {
                    *m.entry(k).or_default() += 1;
                }
            }
            out.extend(m.into_iter().map(|(k, c)| (n.clone(), k.to_string(), c)));
        }
        out
    }
}

async fn start_game(cfg: &CoreCfg, hub: Arc<gamec::Hub>, tx: mpsc::Sender<(Conn, &'static str)>) -> Res<(gamec::Relay, JoinHandle<()>)> {
    let g = GameOpts::parse(&cfg.fec, false);
    let mut inner = tokio_kcp::KcpListener::bind(gamec::kcp_config(), "127.0.0.1:0").await?;
    let local = inner.local_addr()?;
    let relay = gamec::relay(cfg.game, &cfg.door, local, g, hub).await?;
    let task = tokio::spawn(async move {
        loop {
            let stream = match inner.accept().await {
                Ok((s, _)) => s,
                Err(_) => {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    continue;
                }
            };
            let io: BoxIo = Box::new(stream);
            if tx.send((Conn::Game(Raw::Stream(io)), "game")).await.is_err() {
                break;
            }
        }
    });
    Ok((relay, task))
}

/// Checks an auth: the user, the MAC, the time, and that the nonce is new.
fn check(st: &State, a: &Auth, kind: &str) -> Result<Arc<Slot>, &'static str> {
    let slot = st.users.read().unwrap().get(&a.u).cloned().ok_or("unknown user")?;
    if !slot.cores.is_empty() && !slot.cores.iter().any(|c| c == kind) {
        return Err("this protocol is not on for this user");
    }
    let now = super::now_secs();
    if now.abs_diff(a.t) > super::AUTH_SKEW_SECS {
        return Err("clock");
    }
    let want = super::auth_mac(&slot.key, &a.u, a.t, &a.n);
    // constant time: the MAC must not leak how many bytes were right
    if want.len() != a.m.len() || want.bytes().zip(a.m.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) != 0 {
        return Err("bad key");
    }
    if a.n.len() != 32 || st.seen.lock().unwrap().insert(a.n.clone(), now).is_some() {
        return Err("replay");
    }
    Ok(slot)
}

async fn serve_conn(st: Arc<State>, c: Conn, kind: &'static str) {
    let Conn::Game(raw) = c;
    let Ok((mut tx, mut rx)) = link::handshake(raw, &st.door, false, false).await else { return };
    let Ok(Ok(first)) = tokio::time::timeout(Duration::from_secs(10), rx.recv()).await else { return };
    let Some(body) = first.strip_prefix(HELLO) else { return };
    let Ok(auth) = serde_json::from_slice::<Auth>(body) else { return };
    let slot = match check(&st, &auth, kind) {
        Ok(s) => s,
        Err(why) => {
            let mut m = NO.to_vec();
            m.extend_from_slice(why.as_bytes());
            let _ = tx.send(&m).await;
            // a moment before closing, so the answer gets out
            tokio::time::sleep(Duration::from_millis(300)).await;
            return;
        }
    };

    // the datagram path of this session (when the app wants it and it is on for this core)
    let mut sid = 0u64;
    let mut key = [0u8; 32];
    let mut dg: Option<(Arc<DgLink>, mpsc::Receiver<Vec<u8>>)> = None;
    let mut dm = 0usize;
    if auth.d && st.fast.iter().any(|k| k == kind) {
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut key);
        sid = rand::random::<u64>() | 1;
        if kind == "game" {
            dg = st.hub.open(sid, &key, st.copies);
            dm = dgram::GAME_MAX_BODY;
        }
        if dg.is_none() {
            sid = 0;
        }
    }
    let w = Welcome { sid, dk: if sid != 0 { hex::encode(key) } else { String::new() }, dm: dm as u32 };
    let mut m = OK.to_vec();
    m.extend_from_slice(&serde_json::to_vec(&w).unwrap_or_default());
    if tx.send(&m).await.is_err() {
        st.hub.close(sid);
        return;
    }

    let session = Session::start(tx, rx, false, slot.shared.clone());
    let tag = rand::random::<u64>();
    {
        let mut live = slot.live.lock().unwrap();
        live.retain(|(_, x, _)| x.is_alive());
        live.push((tag, session.clone(), kind));
        // over the device limit: the oldest device makes room
        if slot.max > 0 {
            while live.len() as i64 > slot.max {
                let (_, old, _) = live.remove(0);
                old.kill();
            }
        }
    }
    let exit = dg.map(|(link, inbox)| tokio::spawn(dg_exit(link, inbox, session.clone(), slot.shared.clone())));
    session.closed().await;
    if let Some(e) = exit {
        e.abort();
    }
    st.hub.close(sid);
    slot.live.lock().unwrap().retain(|(t, _, _)| *t != tag);
}

/// most UDP flows of one session over the datagram path
const MAX_FLOWS: usize = 512;
const FLOW_IDLE_NEW: u64 = 30_000;
const FLOW_IDLE: u64 = 180_000;

struct Flow {
    sock: Arc<UdpSocket>,
    last: Arc<std::sync::atomic::AtomicU64>,
    task: JoinHandle<()>,
}

/// The exit of a session's game datagrams: one connected socket per flow, the answers straight back.
async fn dg_exit(link: Arc<DgLink>, mut inbox: mpsc::Receiver<Vec<u8>>, session: Arc<Session>, shared: Arc<Shared>) {
    let mut flows: HashMap<u32, Flow> = HashMap::new();
    while let Some(b) = inbox.recv().await {
        let Some((id, target, data)) = dgram::parse_up(&b) else { continue };
        let now = now_ms();
        let live = flows.get(&id).filter(|f| !f.task.is_finished()).map(|f| {
            f.last.store(now, Ordering::Relaxed);
            f.sock.clone()
        });
        let sock = match live {
            Some(s) => s,
            None => {
                if !super::public_target(target) {
                    continue;
                }
                if flows.len() >= MAX_FLOWS {
                    flows.retain(|_, f| !f.task.is_finished());
                    if flows.len() >= MAX_FLOWS {
                        let old: Vec<u32> = super::super::mux::oldest_eighth(flows.iter().map(|(k, f)| (*k, f.last.load(Ordering::Relaxed))));
                        for k in old {
                            if let Some(f) = flows.remove(&k) {
                                f.task.abort();
                            }
                        }
                    }
                }
                let bind = if target.starts_with('[') { "[::]:0" } else { "0.0.0.0:0" };
                let Ok(sock) = UdpSocket::bind(bind).await else { continue };
                if sock.connect(target).await.is_err() {
                    continue;
                }
                dgram::tune_udp(&sock);
                let sock = Arc::new(sock);
                let last = Arc::new(std::sync::atomic::AtomicU64::new(now));
                let task = tokio::spawn(dg_back(link.clone(), session.clone(), id, sock.clone(), last.clone(), shared.clone()));
                if let Some(old) = flows.insert(id, Flow { sock: sock.clone(), last, task }) {
                    old.task.abort();
                }
                sock
            }
        };
        shared.rx_bytes.fetch_add(data.len() as u64, Ordering::Relaxed);
        let _ = sock.send(data).await;
    }
    for (_, f) in flows {
        f.task.abort();
    }
}

async fn dg_back(link: Arc<DgLink>, session: Arc<Session>, id: u32, sock: Arc<UdpSocket>, last: Arc<std::sync::atomic::AtomicU64>, shared: Arc<Shared>) {
    let mut buf = vec![0u8; 65536];
    let mut replied = false;
    loop {
        match tokio::time::timeout(Duration::from_secs(10), sock.recv(&mut buf)).await {
            Ok(Ok(n)) => {
                replied = true;
                last.store(now_ms(), Ordering::Relaxed);
                // an answer too big for a datagram (a large DNS answer, a QUIC packet) takes the
                // stream: a UDP frame of the mux with the same flow id reaches the same flow
                if link.send(&dgram::down_body(id, &buf[..n])) {
                    shared.tx_bytes.fetch_add(n as u64, Ordering::Relaxed);
                } else if !session.send_udp(id, "", &buf[..n]).await {
                    return;
                }
            }
            Ok(Err(_)) => {
                // ICMP unreachable: the flow stays until it idles out
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(_) => {
                let limit = if replied { FLOW_IDLE } else { FLOW_IDLE_NEW };
                if now_ms().saturating_sub(last.load(Ordering::Relaxed)) > limit {
                    return;
                }
            }
        }
    }
}
