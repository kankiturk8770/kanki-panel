//! The Kanki DNS server: answers DNS (UDP/TCP 53, DoT 853, DoH on 443), sends the names of routed
//! services to itself, and carries those connections on (SNI on 443, Host on 80) without decrypting
//! them. Only subscribers are served: a client is known by the token in its DoT / DoH address, and the
//! address it used becomes allowed for plain DNS and for the relayed connections for a while.
use super::sni::{self, Head, Hello};
use super::wire::{self, Question};
use super::{DnsCfg, DnsUser};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

const IDLE: Duration = Duration::from_secs(600);
const HELLO_WAIT: Duration = Duration::from_secs(10);
const MAX_CONNS: usize = 8192;
const CACHE_MAX: usize = 50_000;
/// a way of answering that failed is not tried again for this long
const WAY_PAUSE: Duration = Duration::from_secs(20);

/// What the live configuration looks like once prepared for fast lookups.
pub struct Live {
    pub cfg: DnsCfg,
    routed: HashSet<String>,
    by_token: HashMap<String, DnsUser>,
    by_id: HashMap<i64, DnsUser>,
    answer: Vec<Ipv4Addr>,
    upstreams: Vec<SocketAddr>,
    /// the data center's own resolvers (from resolv.conf): the last way out, they keep Iranian names
    /// working when nothing abroad answers
    system: Vec<SocketAddr>,
}

impl Live {
    pub fn new(cfg: DnsCfg) -> Live {
        let routed = cfg.domains.iter().map(|d| d.trim().trim_matches('.').to_ascii_lowercase()).filter(|d| !d.is_empty()).collect();
        let by_token = cfg.users.iter().filter(|u| !u.token.is_empty()).map(|u| (u.token.to_ascii_lowercase(), u.clone())).collect();
        let by_id = cfg.users.iter().map(|u| (u.id, u.clone())).collect();
        let answer: Vec<Ipv4Addr> = cfg.answer_ip.split(',').filter_map(|s| s.trim().parse().ok()).collect();
        let mut upstreams: Vec<SocketAddr> = cfg
            .upstreams
            .iter()
            .filter_map(|s| {
                let s = s.trim();
                s.parse::<SocketAddr>().ok().or_else(|| s.parse::<IpAddr>().ok().map(|ip| SocketAddr::new(ip, 53)))
            })
            .collect();
        if upstreams.is_empty() {
            upstreams = vec!["1.1.1.1:53".parse().unwrap(), "8.8.8.8:53".parse().unwrap()];
        }
        let system = system_resolvers(&upstreams, &answer);
        Live { cfg, routed, by_token, by_id, answer, upstreams, system }
    }

    /// Is this name (or one of its parents) a routed service?
    pub fn routed(&self, name: &str) -> bool {
        self.routed_by(name).is_some()
    }

    /// The listed name that routes `name` (itself or one of its parents).
    pub fn routed_by<'a>(&self, name: &'a str) -> Option<&'a str> {
        let mut n = name;
        loop {
            if self.routed.contains(n) {
                return Some(n);
            }
            {
                let i = n.find('.')?;
                n = &n[i + 1..]
            }
        }
    }

    /// Is this name the server's own (its DoT / DoH name, or `<token>.` that name)?
    fn own(&self, name: &str) -> bool {
        let h = self.cfg.host.as_str();
        !h.is_empty() && (name == h || name.strip_suffix(h).map(|p| p.ends_with('.')).unwrap_or(false))
    }

    /// The user whose token is the first label of `<token>.<host>`.
    fn user_of_name(&self, name: &str) -> Option<&DnsUser> {
        let h = self.cfg.host.as_str();
        let token = name.strip_suffix(h)?.strip_suffix('.')?;
        self.by_token.get(token)
    }
}

#[derive(Default)]
pub struct UserStat {
    pub bytes: AtomicU64,
    pub queries: AtomicU64,
}

#[derive(Default)]
struct Gate {
    /// ip -> (user, allowed until)
    ips: HashMap<IpAddr, (i64, Instant)>,
    /// user -> its addresses, oldest first
    order: HashMap<i64, VecDeque<IpAddr>>,
}

struct CacheEntry {
    resp: Vec<u8>,
    at: Instant,
    ttl: u32,
}

pub struct Engine {
    pub live: RwLock<Arc<Live>>,
    gate: Mutex<Gate>,
    stats: Mutex<HashMap<i64, Arc<UserStat>>>,
    cache: Mutex<HashMap<(String, u16, u16), CacheEntry>>,
    rate: Mutex<HashMap<IpAddr, (f64, Instant)>>,
    pub conns: AtomicUsize,
    pub errors: Mutex<Vec<String>>,
    /// queries answered: all, routed to us, from the cache, refused (not a subscriber)
    pub q_total: AtomicU64,
    pub q_routed: AtomicU64,
    pub q_cache: AtomicU64,
    pub q_refused: AtomicU64,
    /// routed queries per listed name (the busiest services)
    top: Mutex<HashMap<String, u64>>,
    /// the latest queries of subscribers (for the panel's query log), oldest first
    qlog: Mutex<VecDeque<QLog>>,
    qseq: AtomicU64,
    /// other names answered: through the tunnel by the exit (relay), by the upstream resolvers, by
    /// the data center's resolvers
    pub q_exit: AtomicU64,
    pub q_direct: AtomicU64,
    pub q_local: AtomicU64,
    /// when the exit (through the tunnel) and the upstream resolvers last failed to answer: they are
    /// skipped for a while, so a dead way does not make every query wait
    down: Mutex<HashMap<&'static str, Instant>>,
}

/// One logged query: who asked which name, and the listed name that routed it ("" = answered as is)
#[derive(Clone, Debug, PartialEq)]
pub struct QLog {
    pub seq: u64,
    pub ts: i64,
    pub uid: i64,
    pub name: String,
    pub qtype: u16,
    pub routed: String,
}

/// queries kept on a server between two reports to the panel
pub const QLOG_KEEP: usize = 4000;

impl Engine {
    pub fn new(cfg: DnsCfg) -> Arc<Engine> {
        Arc::new(Engine {
            live: RwLock::new(Arc::new(Live::new(cfg))),
            gate: Mutex::new(Gate::default()),
            stats: Mutex::new(HashMap::new()),
            cache: Mutex::new(HashMap::new()),
            rate: Mutex::new(HashMap::new()),
            conns: AtomicUsize::new(0),
            errors: Mutex::new(vec![]),
            q_total: AtomicU64::new(0),
            q_routed: AtomicU64::new(0),
            q_cache: AtomicU64::new(0),
            q_refused: AtomicU64::new(0),
            top: Mutex::new(HashMap::new()),
            qlog: Mutex::new(VecDeque::new()),
            qseq: AtomicU64::new(0),
            q_exit: AtomicU64::new(0),
            q_direct: AtomicU64::new(0),
            q_local: AtomicU64::new(0),
            down: Mutex::new(HashMap::new()),
        })
    }

    fn log_query(&self, uid: i64, name: &str, qtype: u16, routed: Option<&str>) {
        let seq = self.qseq.fetch_add(1, Ordering::Relaxed) + 1;
        let mut l = self.qlog.lock().unwrap_or_else(|e| e.into_inner());
        if l.len() >= QLOG_KEEP {
            l.pop_front();
        }
        l.push_back(QLog { seq, ts: crate::util::now(), uid, name: name.to_string(), qtype, routed: routed.unwrap_or("").to_string() });
    }

    /// The logged queries after `seq` (oldest first).
    pub fn qlog_after(&self, seq: u64) -> Vec<QLog> {
        self.qlog.lock().unwrap_or_else(|e| e.into_inner()).iter().filter(|q| q.seq > seq).cloned().collect()
    }

    pub fn qlog_last(&self) -> u64 {
        self.qseq.load(Ordering::Relaxed)
    }

    pub fn live(&self) -> Arc<Live> {
        self.live.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn reload(&self, cfg: DnsCfg) {
        let old = self.live();
        // a user whose addresses the admin cleared (a new epoch) must register again
        let kicked: Vec<i64> = cfg.users.iter().filter(|u| old.by_id.get(&u.id).map(|o| o.epoch != u.epoch).unwrap_or(false)).map(|u| u.id).collect();
        *self.live.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(Live::new(cfg));
        if !kicked.is_empty() {
            let mut g = self.gate.lock().unwrap_or_else(|e| e.into_inner());
            g.ips.retain(|_, v| !kicked.contains(&v.0));
            for id in kicked {
                g.order.remove(&id);
            }
        }
    }

    /// The addresses allowed right now, per user.
    pub fn ips_snapshot(&self) -> HashMap<i64, Vec<String>> {
        let now = Instant::now();
        let g = self.gate.lock().unwrap_or_else(|e| e.into_inner());
        let mut out: HashMap<i64, Vec<String>> = HashMap::new();
        for (ip, (uid, until)) in g.ips.iter() {
            if *until > now {
                out.entry(*uid).or_default().push(ip.to_string());
            }
        }
        out
    }

    /// The busiest routed names (at most `n`).
    pub fn top(&self, n: usize) -> Vec<(String, u64)> {
        let mut v: Vec<(String, u64)> = self.top.lock().unwrap_or_else(|e| e.into_inner()).iter().map(|(k, v)| (k.clone(), *v)).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        v.truncate(n);
        v
    }

    pub fn stat(&self, uid: i64) -> Arc<UserStat> {
        self.stats.lock().unwrap_or_else(|e| e.into_inner()).entry(uid).or_default().clone()
    }

    pub fn stats_snapshot(&self) -> HashMap<i64, (u64, u64)> {
        self.stats.lock().unwrap_or_else(|e| e.into_inner()).iter().map(|(k, v)| (*k, (v.bytes.load(Ordering::Relaxed), v.queries.load(Ordering::Relaxed)))).collect()
    }

    pub fn allowed_count(&self) -> usize {
        let now = Instant::now();
        self.gate.lock().unwrap_or_else(|e| e.into_inner()).ips.values().filter(|x| x.1 > now).count()
    }

    fn note_err(&self, e: String) {
        eprintln!("{}", e);
        let mut v = self.errors.lock().unwrap_or_else(|e| e.into_inner());
        if !v.contains(&e) {
            // errors that name an address differ each time: keep the newest few, not all of them
            if v.len() >= 50 {
                v.remove(0);
            }
            v.push(e);
        }
    }

    // ------------------------------------------------------------------ who may use the server

    /// The user an address belongs to right now.
    pub fn who(&self, ip: IpAddr) -> Option<i64> {
        let live = self.live();
        let g = self.gate.lock().unwrap_or_else(|e| e.into_inner());
        let (uid, until) = g.ips.get(&canon(ip))?;
        (*until > Instant::now() && live.by_id.contains_key(uid)).then_some(*uid)
    }

    /// Allow `ip` for user `uid` (a newer address pushes out the oldest past the user's limit).
    pub fn allow(&self, ip: IpAddr, uid: i64) {
        let ip = canon(ip);
        let live = self.live();
        let Some(u) = live.by_id.get(&uid) else { return };
        let hours = if live.cfg.ip_hours == 0 { 12 } else { live.cfg.ip_hours.min(24 * 30) };
        let until = Instant::now() + Duration::from_secs(hours * 3600);
        let mut g = self.gate.lock().unwrap_or_else(|e| e.into_inner());
        // the address may have belonged to someone else (shared mobile address): it moves
        if let Some((old, _)) = g.ips.insert(ip, (uid, until)) {
            if old != uid {
                if let Some(q) = g.order.get_mut(&old) {
                    q.retain(|x| *x != ip);
                }
            }
        }
        let q = g.order.entry(uid).or_default();
        q.retain(|x| *x != ip);
        q.push_back(ip);
        let max = u.max_ips as usize;
        let mut drop = vec![];
        while max > 0 && q.len() > max {
            if let Some(x) = q.pop_front() {
                drop.push(x);
            }
        }
        for x in drop {
            if g.ips.get(&x).map(|e| e.0) == Some(uid) {
                g.ips.remove(&x);
            }
        }
    }

    fn sweep(&self) {
        let now = Instant::now();
        {
            let mut g = self.gate.lock().unwrap_or_else(|e| e.into_inner());
            g.ips.retain(|_, v| v.1 > now);
            let Gate { ips, order } = &mut *g;
            for q in order.values_mut() {
                q.retain(|ip| ips.contains_key(ip));
            }
            order.retain(|_, q| !q.is_empty());
        }
        self.rate.lock().unwrap_or_else(|e| e.into_inner()).retain(|_, v| now.duration_since(v.1) < Duration::from_secs(60));
        let mut c = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        c.retain(|_, e| now.duration_since(e.at).as_secs() < e.ttl as u64);
    }

    /// Plain DNS from one address: at most ~100 queries a second (a burst of 300).
    fn rate_ok(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let mut r = self.rate.lock().unwrap_or_else(|e| e.into_inner());
        let e = r.entry(ip).or_insert((300.0, now));
        let add = now.duration_since(e.1).as_secs_f64() * 100.0;
        e.0 = (e.0 + add).min(300.0);
        e.1 = now;
        if e.0 >= 1.0 {
            e.0 -= 1.0;
            true
        } else {
            false
        }
    }

    // ------------------------------------------------------------------ answering

    /// The reply to one DNS message from user `who` (None = not a subscriber: REFUSED).
    pub async fn answer(&self, req: &[u8], who: Option<i64>) -> Option<Vec<u8>> {
        let Some(q) = wire::parse_query(req) else { return wire::error_for(req, wire::FORMERR) };
        let live = self.live();
        // the server's own names are answered for everybody (a DoT client resolves them first)
        if live.own(&q.name) {
            return Some(match q.qtype {
                wire::A if !live.answer.is_empty() => wire::answer_a(req, &q, &live.answer, 300),
                _ => wire::empty(req, &q, wire::NOERROR),
            });
        }
        let Some(uid) = who else {
            self.q_refused.fetch_add(1, Ordering::Relaxed);
            return Some(wire::empty(req, &q, wire::REFUSED));
        };
        self.stat(uid).queries.fetch_add(1, Ordering::Relaxed);
        self.q_total.fetch_add(1, Ordering::Relaxed);
        let by = if q.qclass == 1 && !live.answer.is_empty() { live.routed_by(&q.name) } else { None };
        self.log_query(uid, &q.name, q.qtype, by);
        if let Some(by) = by {
            if q.qtype == wire::A {
                self.q_routed.fetch_add(1, Ordering::Relaxed);
                let mut t = self.top.lock().unwrap_or_else(|e| e.into_inner());
                if t.len() < 5000 || t.contains_key(by) {
                    *t.entry(by.to_string()).or_default() += 1;
                }
            }
            match q.qtype {
                wire::A => return Some(wire::answer_a(req, &q, &live.answer, 60)),
                // no IPv6 and no HTTPS/SVCB hints: the client must come to us over IPv4
                wire::AAAA | wire::HTTPS | wire::SVCB => return Some(wire::empty(req, &q, wire::NOERROR)),
                _ => {}
            }
        }
        Some(match self.forward(req, &q, &live).await {
            Some(r) => r,
            None => wire::empty(req, &q, wire::SERVFAIL),
        })
    }

    /// Upstream answer (from the cache when fresh), with the client's id and question.
    async fn forward(&self, req: &[u8], q: &Question, live: &Live) -> Option<Vec<u8>> {
        let key = (q.name.clone(), q.qtype, q.qclass);
        let hit = {
            let c = self.cache.lock().unwrap_or_else(|e| e.into_inner());
            c.get(&key).and_then(|e| {
                let age = e.at.elapsed().as_secs();
                (age < e.ttl as u64).then(|| {
                    let mut r = e.resp.clone();
                    wire::age_ttls(&mut r, age as u32);
                    r
                })
            })
        };
        let mut r = match hit {
            Some(r) => {
                self.q_cache.fetch_add(1, Ordering::Relaxed);
                r
            }
            None => {
                let r = self.resolve(req, live).await?;
                let rc = wire::rcode(&r);
                if rc == wire::NOERROR || rc == 3 {
                    if let Some(ttl) = wire::min_ttl(&r, 60) {
                        let ttl = ttl.clamp(10, 3600);
                        let mut c = self.cache.lock().unwrap_or_else(|e| e.into_inner());
                        if c.len() >= CACHE_MAX {
                            let now = Instant::now();
                            c.retain(|_, e| now.duration_since(e.at).as_secs() < e.ttl as u64);
                            if c.len() >= CACHE_MAX {
                                c.clear();
                            }
                        }
                        c.insert(key, CacheEntry { resp: r.clone(), at: Instant::now(), ttl });
                    }
                }
                r
            }
        };
        // the client's own id and the exact spelling of its question (0x20 randomisation)
        r[0..2].copy_from_slice(&req[0..2]);
        if r.len() >= q.end && r[12..q.end].eq_ignore_ascii_case(&req[12..q.end]) {
            r[12..q.end].copy_from_slice(&req[12..q.end]);
        }
        Some(r)
    }

    /// The answer for a name we do not route.
    /// 1) a relay (inside Iran) asks its exit through the tunnel: DNS from abroad, not blocked or
    ///    altered on the way, and it keeps working when DNS servers abroad are blocked from Iran
    /// 2) the upstream resolvers (1.1.1.1, 8.8.8.8, …) directly
    /// 3) the data center's own resolvers: when nothing abroad answers (the international internet
    ///    is cut), Iranian names still resolve, so a phone that uses us never loses all of its internet
    async fn resolve(&self, req: &[u8], live: &Live) -> Option<Vec<u8>> {
        if live.cfg.role == "relay" && !live.cfg.exit_addr.is_empty() && self.up("exit") {
            match via_exit(&live.cfg.exit_addr, &live.cfg.relay_key, req).await {
                Some(r) => {
                    self.q_exit.fetch_add(1, Ordering::Relaxed);
                    return Some(r);
                }
                None => self.mark_down("exit"),
            }
        }
        if live.system.is_empty() || self.up("upstream") {
            if let Some(r) = upstream(&live.upstreams, req).await {
                self.q_direct.fetch_add(1, Ordering::Relaxed);
                return Some(r);
            }
            if live.system.is_empty() {
                return None;
            }
            self.mark_down("upstream");
        }
        let r = upstream(&live.system, req).await?;
        self.q_local.fetch_add(1, Ordering::Relaxed);
        Some(r)
    }

    /// Is this way worth trying (it has not failed in the last few seconds)?
    fn up(&self, way: &'static str) -> bool {
        self.down.lock().unwrap_or_else(|e| e.into_inner()).get(way).map(|t| t.elapsed() >= WAY_PAUSE).unwrap_or(true)
    }

    fn mark_down(&self, way: &'static str) {
        self.down.lock().unwrap_or_else(|e| e.into_inner()).insert(way, Instant::now());
    }

    /// The IPv4 addresses of a routed name, from the upstream resolvers (never our own answer).
    async fn lookup(&self, name: &str) -> Vec<Ipv4Addr> {
        let live = self.live();
        let req = wire::build_query(rand::random(), name, wire::A);
        let Some(q) = wire::parse_query(&req) else { return vec![] };
        match self.forward(&req, &q, &live).await {
            Some(r) => wire::a_records(&r).into_iter().filter(|ip| public_v4(*ip) && !live.answer.contains(ip)).collect(),
            None => vec![],
        }
    }
}

/// IPv4-mapped IPv6 addresses count as the IPv4 they carry.
fn canon(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        x => x,
    }
}

fn public_v4(ip: Ipv4Addr) -> bool {
    !(ip.is_private() || ip.is_loopback() || ip.is_link_local() || ip.is_unspecified() || ip.is_broadcast() || ip.is_multicast() || ip.octets()[0] == 100 && (ip.octets()[1] & 0xC0) == 64 || ip.octets()[0] == 0 || ip.octets()[0] >= 240)
}

/// One query to the upstream resolvers: the first one, then the next ones after a short wait.
async fn upstream(ups: &[SocketAddr], req: &[u8]) -> Option<Vec<u8>> {
    let id: u16 = rand::random();
    let mut pkt = req.to_vec();
    pkt[0..2].copy_from_slice(&id.to_be_bytes());
    let sock = UdpSocket::bind(if ups[0].is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }).await.ok()?;
    let deadline = Instant::now() + Duration::from_millis(2500);
    let mut next = 0usize;
    let mut buf = vec![0u8; 4096];
    loop {
        if next < ups.len().min(3) {
            let _ = sock.send_to(&pkt, ups[next]).await;
            next += 1;
        }
        let wait = if next < ups.len().min(3) { Duration::from_millis(400) } else { deadline.saturating_duration_since(Instant::now()) };
        let until = Instant::now() + wait;
        loop {
            let left = until.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            match tokio::time::timeout(left, sock.recv_from(&mut buf)).await {
                Ok(Ok((n, from))) => {
                    let r = &buf[..n];
                    if !ups.contains(&from) || n < 12 || r[0..2] != id.to_be_bytes() || r[2] & 0x80 == 0 {
                        continue;
                    }
                    let mut out = if wire::truncated(r) { tcp_query(from, &pkt).await.unwrap_or_else(|| r.to_vec()) } else { r.to_vec() };
                    out[0..2].copy_from_slice(&req[0..2]);
                    return Some(out);
                }
                Ok(Err(_)) => break,
                Err(_) => break,
            }
        }
        if Instant::now() >= deadline {
            return None;
        }
    }
}

async fn tcp_query(to: SocketAddr, pkt: &[u8]) -> Option<Vec<u8>> {
    let f = async {
        let mut s = TcpStream::connect(to).await.ok()?;
        let mut m = (pkt.len() as u16).to_be_bytes().to_vec();
        m.extend_from_slice(pkt);
        s.write_all(&m).await.ok()?;
        let len = s.read_u16().await.ok()? as usize;
        let mut r = vec![0u8; len];
        s.read_exact(&mut r).await.ok()?;
        Some(r)
    };
    tokio::time::timeout(Duration::from_secs(3), f).await.ok().flatten()
}

// ------------------------------------------------------------------ binding

/// Local IPv4 addresses (for when the wildcard address is taken, e.g. by systemd-resolved on 53).
fn local_v4() -> Vec<Ipv4Addr> {
    let out = std::process::Command::new("ip").args(["-4", "-o", "addr", "show"]).output();
    let Ok(o) = out else { return vec![] };
    String::from_utf8_lossy(&o.stdout)
        .lines()
        .filter_map(|l| l.split_whitespace().skip_while(|w| *w != "inet").nth(1))
        .filter_map(|c| c.split('/').next()?.parse::<Ipv4Addr>().ok())
        .filter(|ip| !ip.is_loopback())
        .collect()
}

async fn bind_tcp(port: u16) -> Result<Vec<TcpListener>, String> {
    match TcpListener::bind(("0.0.0.0", port)).await {
        Ok(l) => Ok(vec![l]),
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
            let mut v = vec![];
            for ip in local_v4() {
                if let Ok(l) = TcpListener::bind((ip, port)).await {
                    v.push(l);
                }
            }
            if v.is_empty() { Err(format!("TCP port {} is used by another program", port)) } else { Ok(v) }
        }
        Err(e) => Err(format!("TCP port {}: {}", port, e)),
    }
}

async fn bind_udp(port: u16) -> Result<Vec<UdpSocket>, String> {
    match UdpSocket::bind(("0.0.0.0", port)).await {
        Ok(s) => Ok(vec![s]),
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
            let mut v = vec![];
            for ip in local_v4() {
                if let Ok(s) = UdpSocket::bind((ip, port)).await {
                    v.push(s);
                }
            }
            if v.is_empty() { Err(format!("UDP port {} is used by another program", port)) } else { Ok(v) }
        }
        Err(e) => Err(format!("UDP port {}: {}", port, e)),
    }
}

// ------------------------------------------------------------------ listeners

pub async fn serve(eng: Arc<Engine>) {
    let cfg = eng.live().cfg.clone();
    let tls = tls_config(&cfg).map_err(|e| eng.note_err(format!("TLS certificate: {} (DoT and DoH are off)", e))).ok();
    {
        let e = eng.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;
                e.sweep();
            }
        });
    }
    if cfg.dns_port > 0 {
        match bind_udp(cfg.dns_port).await {
            Ok(v) => v.into_iter().for_each(|s| {
                tokio::spawn(udp_loop(eng.clone(), Arc::new(s)));
            }),
            Err(e) => eng.note_err(e),
        }
        match bind_tcp(cfg.dns_port).await {
            Ok(v) => v.into_iter().for_each(|l| {
                tokio::spawn(accept_loop(eng.clone(), l, Kind::Dns53));
            }),
            Err(e) => eng.note_err(e),
        }
    }
    if let Some(t) = tls.clone() {
        if cfg.dot_port > 0 {
            match bind_tcp(cfg.dot_port).await {
                Ok(v) => v.into_iter().for_each(|l| {
                    tokio::spawn(accept_loop(eng.clone(), l, Kind::Dot(t.clone())));
                }),
                Err(e) => eng.note_err(e),
            }
        }
    }
    if cfg.https_port > 0 {
        match bind_tcp(cfg.https_port).await {
            Ok(v) => v.into_iter().for_each(|l| {
                tokio::spawn(accept_loop(eng.clone(), l, Kind::Https(tls.clone())));
            }),
            Err(e) => eng.note_err(e),
        }
    }
    if cfg.http_port > 0 {
        match bind_tcp(cfg.http_port).await {
            Ok(v) => v.into_iter().for_each(|l| {
                tokio::spawn(accept_loop(eng.clone(), l, Kind::Http));
            }),
            Err(e) => eng.note_err(e),
        }
    }
    if cfg.role == "exit" && cfg.intake_port > 0 {
        match TcpListener::bind(("127.0.0.1", cfg.intake_port)).await {
            Ok(l) => {
                tokio::spawn(accept_loop(eng.clone(), l, Kind::Intake));
            }
            Err(e) => eng.note_err(format!("relay intake port {}: {}", cfg.intake_port, e)),
        }
    }
}

/// Is this certificate + key usable? (checked by the panel before it is saved)
pub fn check_tls(cfg: &DnsCfg) -> Result<(), String> {
    tls_config(cfg).map(|_| ())
}

fn tls_config(cfg: &DnsCfg) -> Result<Arc<rustls::ServerConfig>, String> {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    if cfg.cert.trim().is_empty() || cfg.key.trim().is_empty() {
        return Err("no certificate yet".into());
    }
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(cfg.cert.as_bytes()).filter_map(|c| c.ok()).collect();
    if certs.is_empty() {
        return Err("no certificate in the PEM".into());
    }
    let key = PrivateKeyDer::from_pem_slice(cfg.key.as_bytes()).map_err(|e| format!("private key: {:?}", e))?;
    let mut c = rustls::ServerConfig::builder_with_provider(crate::tunnel::link::provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| e.to_string())?;
    c.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec(), b"dot".to_vec()];
    Ok(Arc::new(c))
}

async fn udp_loop(eng: Arc<Engine>, sock: Arc<UdpSocket>) {
    let busy = Arc::new(tokio::sync::Semaphore::new(4096));
    let mut buf = vec![0u8; 4096];
    loop {
        let Ok((n, from)) = sock.recv_from(&mut buf).await else { continue };
        let ip = canon(from.ip());
        if !eng.rate_ok(ip) {
            continue;
        }
        let Ok(permit) = busy.clone().try_acquire_owned() else { continue };
        let pkt = buf[..n].to_vec();
        let (eng, sock) = (eng.clone(), sock.clone());
        tokio::spawn(async move {
            let who = eng.who(ip);
            if let Some(mut r) = eng.answer(&pkt, who).await {
                // plain UDP without EDNS: 512 bytes, the client retries over TCP
                if r.len() > 1232 {
                    let Some(q) = wire::parse_query(&pkt) else { return };
                    let rc = wire::rcode(&r);
                    r = wire::empty(&pkt, &q, rc);
                    r[2] |= 0x02;
                }
                let _ = sock.send_to(&r, from).await;
            }
            drop(permit);
        });
    }
}

#[derive(Clone)]
enum Kind {
    Dns53,
    Dot(Arc<rustls::ServerConfig>),
    Https(Option<Arc<rustls::ServerConfig>>),
    Http,
    Intake,
}

struct ConnGuard(Arc<Engine>);
impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.0.conns.fetch_sub(1, Ordering::Relaxed);
    }
}

async fn accept_loop(eng: Arc<Engine>, l: TcpListener, kind: Kind) {
    loop {
        let Ok((s, peer)) = l.accept().await else {
            tokio::time::sleep(Duration::from_millis(50)).await;
            continue;
        };
        if eng.conns.load(Ordering::Relaxed) >= MAX_CONNS {
            continue;
        }
        eng.conns.fetch_add(1, Ordering::Relaxed);
        let g = ConnGuard(eng.clone());
        let (eng, kind) = (eng.clone(), kind.clone());
        let _ = s.set_nodelay(true);
        tokio::spawn(async move {
            let ip = canon(peer.ip());
            match kind {
                Kind::Dns53 => {
                    let who = eng.who(ip);
                    dns_stream(&eng, s, who, Duration::from_secs(30)).await
                }
                Kind::Dot(t) => dot(&eng, s, ip, t).await,
                Kind::Https(t) => https(&eng, s, ip, t).await,
                Kind::Http => http(&eng, s, ip).await,
                Kind::Intake => intake(&eng, s).await,
            }
            drop(g);
        });
    }
}

/// DNS over a stream: 2-byte length, message, repeated (TCP 53 and DoT).
async fn dns_stream<S: AsyncRead + AsyncWrite + Unpin>(eng: &Engine, mut s: S, who: Option<i64>, idle: Duration) {
    loop {
        let Ok(Ok(len)) = tokio::time::timeout(idle, s.read_u16()).await else { return };
        let mut m = vec![0u8; len as usize];
        if !matches!(tokio::time::timeout(Duration::from_secs(10), s.read_exact(&mut m)).await, Ok(Ok(_))) {
            return;
        }
        let Some(r) = eng.answer(&m, who).await else { continue };
        let mut out = (r.len() as u16).to_be_bytes().to_vec();
        out.extend_from_slice(&r);
        if s.write_all(&out).await.is_err() {
            return;
        }
    }
}

async fn dot(eng: &Arc<Engine>, s: TcpStream, ip: IpAddr, t: Arc<rustls::ServerConfig>) {
    let acc = tokio_rustls::TlsAcceptor::from(t);
    let Ok(Ok(tls)) = tokio::time::timeout(HELLO_WAIT, acc.accept(s)).await else { return };
    let name = tls.get_ref().1.server_name().map(|x| x.to_ascii_lowercase()).unwrap_or_default();
    let live = eng.live();
    let who = match live.user_of_name(&name) {
        Some(u) => {
            eng.allow(ip, u.id);
            Some(u.id)
        }
        None => eng.who(ip),
    };
    drop(live);
    dns_stream(eng, tls, who, Duration::from_secs(60)).await;
}

/// Bytes already read in front of the rest of a stream.
pub struct Prefixed<S> {
    pre: Vec<u8>,
    pos: usize,
    inner: S,
}

impl<S: AsyncRead + Unpin> AsyncRead for Prefixed<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        if self.pos < self.pre.len() {
            let n = (self.pre.len() - self.pos).min(buf.remaining());
            let p = self.pos;
            buf.put_slice(&self.pre[p..p + n]);
            self.pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Prefixed<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Read until the TLS ClientHello is complete; (bytes read, server name).
async fn read_hello(s: &mut TcpStream) -> Option<(Vec<u8>, String)> {
    let mut buf = Vec::with_capacity(2048);
    let f = async {
        let mut tmp = [0u8; 4096];
        loop {
            let n = s.read(&mut tmp).await.ok()?;
            if n == 0 {
                return None;
            }
            buf.extend_from_slice(&tmp[..n]);
            match sni::client_hello_sni(&buf) {
                Hello::Name(name) => return Some(name),
                Hello::More if buf.len() < sni::MAX_HELLO => continue,
                _ => return None,
            }
        }
    };
    let name = tokio::time::timeout(HELLO_WAIT, f).await.ok()??;
    Some((buf, name))
}

async fn read_head(s: &mut TcpStream) -> Option<(Vec<u8>, String, String)> {
    let mut buf = Vec::with_capacity(1024);
    let f = async {
        let mut tmp = [0u8; 2048];
        loop {
            let n = s.read(&mut tmp).await.ok()?;
            if n == 0 {
                return None;
            }
            buf.extend_from_slice(&tmp[..n]);
            match sni::http_host(&buf) {
                Head::Req(h, p) => return Some((h, p)),
                Head::More => continue,
                Head::Bad => return None,
            }
        }
    };
    let (h, p) = tokio::time::timeout(HELLO_WAIT, f).await.ok()??;
    Some((buf, h, p))
}

/// Port 443: our own name gets DoH, a routed name of a subscriber is carried on, the rest is closed.
async fn https(eng: &Arc<Engine>, mut s: TcpStream, ip: IpAddr, tls: Option<Arc<rustls::ServerConfig>>) {
    let Some((pre, name)) = read_hello(&mut s).await else { return };
    let live = eng.live();
    if live.own(&name) || name.is_empty() {
        let Some(t) = tls else { return };
        drop(live);
        let acc = tokio_rustls::TlsAcceptor::from(t);
        let Ok(Ok(stream)) = tokio::time::timeout(HELLO_WAIT, acc.accept(Prefixed { pre, pos: 0, inner: s })).await else { return };
        super::doh::serve(eng.clone(), stream, ip).await;
        return;
    }
    let Some(uid) = eng.who(ip) else { return };
    if !live.routed(&name) {
        return;
    }
    drop(live);
    carry(eng, s, pre, &name, 443, Some(eng.stat(uid))).await;
}

/// Port 80: a subscriber's request for a routed host is carried on; `/kdns/r/<token>` registers.
async fn http(eng: &Arc<Engine>, mut s: TcpStream, ip: IpAddr) {
    let Some((pre, host, path)) = read_head(&mut s).await else { return };
    // Let's Encrypt checking this server's name for certbot (webroot): DNS keeps running meanwhile
    if let Some(body) = crate::certbot::challenge(&path) {
        let resp = format!("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body);
        let _ = s.write_all(resp.as_bytes()).await;
        return;
    }
    let live = eng.live();
    if live.own(&host) || host.parse::<IpAddr>().is_ok() {
        let body = match path.strip_prefix("/kdns/r/").map(|t| t.trim_end_matches('/').to_ascii_lowercase()) {
            Some(t) => match live.by_token.get(&t) {
                Some(u) => {
                    let id = u.id;
                    drop(live);
                    eng.allow(ip, id);
                    format!("{{\"ok\":true,\"ip\":\"{}\"}}", ip)
                }
                None => "{\"ok\":false}".into(),
            },
            None => "{\"ok\":false}".into(),
        };
        let resp = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body);
        let _ = s.write_all(resp.as_bytes()).await;
        return;
    }
    let Some(uid) = eng.who(ip) else {
        let _ = s.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await;
        return;
    };
    if !live.routed(&host) {
        return;
    }
    drop(live);
    carry(eng, s, pre, &host, 80, Some(eng.stat(uid))).await;
}

/// The exit end of a relay: "KDNS1 <key> <port>\n", then the client's bytes as they came.
async fn intake(eng: &Arc<Engine>, mut s: TcpStream) {
    let mut line = Vec::with_capacity(128);
    let ok = tokio::time::timeout(HELLO_WAIT, async {
        let mut b = [0u8; 1];
        while line.len() < 200 {
            if s.read_exact(&mut b).await.is_err() {
                return false;
            }
            if b[0] == b'\n' {
                return true;
            }
            line.push(b[0]);
        }
        false
    })
    .await
    .unwrap_or(false);
    if !ok {
        return;
    }
    let text = String::from_utf8_lossy(&line).to_string();
    let mut it = text.split(' ');
    let (Some("KDNS1"), Some(key), Some(port)) = (it.next(), it.next(), it.next()) else { return };
    let live = eng.live();
    if live.cfg.relay_key.is_empty() || !crate::util::ct_eq(key, &live.cfg.relay_key) {
        return;
    }
    drop(live);
    if port == "53" {
        relay_queries(eng, s).await;
        return;
    }
    let (pre, name, port) = match port {
        "443" => match read_hello(&mut s).await {
            Some((p, n)) => (p, n, 443),
            None => return,
        },
        "80" => match read_head(&mut s).await {
            Some((p, h, _)) => (p, h, 80),
            None => return,
        },
        _ => return,
    };
    if !eng.live().routed(&name) {
        return;
    }
    carry(eng, s, pre, &name, port, None).await;
}

/// The exit answering its relay's queries for names it does not route (DNS over TCP: a 2-byte
/// length, then the message). Answered from the cache or the upstream resolvers, never with our own
/// address.
async fn relay_queries(eng: &Arc<Engine>, mut s: TcpStream) {
    loop {
        let Ok(Ok(len)) = tokio::time::timeout(Duration::from_secs(30), s.read_u16()).await else { return };
        let mut req = vec![0u8; len as usize];
        if tokio::time::timeout(HELLO_WAIT, s.read_exact(&mut req)).await.map(|r| r.is_err()).unwrap_or(true) {
            return;
        }
        let Some(q) = wire::parse_query(&req) else { return };
        let live = eng.live();
        let r = eng.forward(&req, &q, &live).await.unwrap_or_else(|| wire::empty(&req, &q, wire::SERVFAIL));
        let mut out = (r.len() as u16).to_be_bytes().to_vec();
        out.extend_from_slice(&r);
        if s.write_all(&out).await.is_err() {
            return;
        }
    }
}

/// One query of a relay to its exit through the tunnel (None when the exit does not answer).
async fn via_exit(addr: &str, key: &str, req: &[u8]) -> Option<Vec<u8>> {
    let f = async {
        let mut s = TcpStream::connect(addr).await.ok()?;
        let mut m = format!("KDNS1 {} 53\n", key).into_bytes();
        m.extend_from_slice(&(req.len() as u16).to_be_bytes());
        m.extend_from_slice(req);
        s.write_all(&m).await.ok()?;
        let len = s.read_u16().await.ok()? as usize;
        let mut r = vec![0u8; len];
        s.read_exact(&mut r).await.ok()?;
        (r.len() >= 12 && r[0..2] == req[0..2]).then_some(r)
    };
    tokio::time::timeout(Duration::from_millis(2500), f).await.ok().flatten()
}

/// The data center's resolvers from resolv.conf (systemd-resolved's real ones first), IPv4 only,
/// without the upstream resolvers already used and without this server itself.
fn system_resolvers(upstreams: &[SocketAddr], own: &[Ipv4Addr]) -> Vec<SocketAddr> {
    let text = ["/run/systemd/resolve/resolv.conf", "/etc/resolv.conf"].iter().filter_map(|f| std::fs::read_to_string(f).ok()).collect::<Vec<_>>().join("\n");
    parse_resolv(&text, upstreams, own)
}

fn parse_resolv(text: &str, upstreams: &[SocketAddr], own: &[Ipv4Addr]) -> Vec<SocketAddr> {
    let mut v: Vec<SocketAddr> = vec![];
    let mut stub = None;
    for l in text.lines() {
        let mut w = l.split_whitespace();
        if w.next() != Some("nameserver") {
            continue;
        }
        let Some(ip) = w.next().and_then(|x| x.parse::<Ipv4Addr>().ok()) else { continue };
        // systemd-resolved's stub: only when it is the only one (it asks the real ones itself)
        if ip == Ipv4Addr::new(127, 0, 0, 53) {
            stub = Some(SocketAddr::new(IpAddr::V4(ip), 53));
            continue;
        }
        let a = SocketAddr::new(IpAddr::V4(ip), 53);
        if ip.is_loopback() || ip.is_unspecified() || own.contains(&ip) || upstreams.contains(&a) || v.contains(&a) {
            continue;
        }
        v.push(a);
    }
    if v.is_empty() {
        v.extend(stub);
    }
    v
}

/// Carry a client connection to `name:port` (through the exit when this server is a relay).
async fn carry(eng: &Arc<Engine>, client: TcpStream, pre: Vec<u8>, name: &str, port: u16, stat: Option<Arc<UserStat>>) {
    let live = eng.live();
    let up = if live.cfg.role == "relay" {
        let addr = live.cfg.exit_addr.clone();
        let key = live.cfg.relay_key.clone();
        drop(live);
        let Ok(Ok(mut u)) = tokio::time::timeout(Duration::from_secs(8), TcpStream::connect(&addr)).await else { return };
        if u.write_all(format!("KDNS1 {} {}\n", key, port).as_bytes()).await.is_err() {
            return;
        }
        u
    } else {
        drop(live);
        let mut got = None;
        for ip in eng.lookup(name).await.into_iter().take(4) {
            if let Ok(Ok(u)) = tokio::time::timeout(Duration::from_secs(6), TcpStream::connect((ip, port))).await {
                got = Some(u);
                break;
            }
        }
        let Some(u) = got else { return };
        u
    };
    let _ = up.set_nodelay(true);
    let mut up = up;
    if up.write_all(&pre).await.is_err() {
        return;
    }
    if let Some(st) = &stat {
        st.bytes.fetch_add(pre.len() as u64, Ordering::Relaxed);
    }
    pump(client, up, stat).await;
}

/// Copy both ways until both sides are done (or nothing moves for IDLE), counting the bytes.
async fn pump(a: TcpStream, b: TcpStream, stat: Option<Arc<UserStat>>) {
    let (mut ar, mut aw) = a.into_split();
    let (mut br, mut bw) = b.into_split();
    let s1 = stat.clone();
    let up = async move {
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            match tokio::time::timeout(IDLE, ar.read(&mut buf)).await {
                Ok(Ok(n)) if n > 0 => {
                    if bw.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                    if let Some(s) = &s1 {
                        s.bytes.fetch_add(n as u64, Ordering::Relaxed);
                    }
                }
                _ => break,
            }
        }
        let _ = bw.shutdown().await;
    };
    let down = async move {
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            match tokio::time::timeout(IDLE, br.read(&mut buf)).await {
                Ok(Ok(n)) if n > 0 => {
                    if aw.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                    if let Some(s) = &stat {
                        s.bytes.fetch_add(n as u64, Ordering::Relaxed);
                    }
                }
                _ => break,
            }
        }
        let _ = aw.shutdown().await;
    };
    tokio::join!(up, down);
}

#[cfg(test)]
mod tests {

    use super::*;

    fn cfg() -> DnsCfg {
        DnsCfg {
            role: "exit".into(),
            host: "de.dns.example.com".into(),
            answer_ip: "203.0.113.7".into(),
            upstreams: vec!["127.0.0.1:9".into()],
            domains: vec!["playstation.net".into(), "Example.ORG.".into()],
            users: vec![
                DnsUser { id: 1, name: "a".into(), token: "aaaa1111".into(), max_ips: 2, ..Default::default() },
                DnsUser { id: 2, name: "b".into(), token: "bbbb2222".into(), max_ips: 0, ..Default::default() },
            ],
            ..Default::default()
        }
    }

    #[test]
    fn routing_and_names() {
        let l = Live::new(cfg());
        assert!(l.routed("playstation.net"));
        assert!(l.routed("gs2.ww.prod.dl.playstation.net"));
        assert!(l.routed("www.example.org"));
        assert!(!l.routed("notplaystation.net"));
        assert!(!l.routed("net"));
        assert!(l.own("de.dns.example.com"));
        assert!(l.own("aaaa1111.de.dns.example.com"));
        assert!(!l.own("xde.dns.example.com"));
        assert_eq!(l.user_of_name("aaaa1111.de.dns.example.com").map(|u| u.id), Some(1));
        assert!(l.user_of_name("zzzz.de.dns.example.com").is_none());
        assert!(l.user_of_name("de.dns.example.com").is_none());
    }

    #[test]
    fn gate_limits_addresses() {
        let e = Engine::new(cfg());
        let ip = |n: u8| IpAddr::V4(Ipv4Addr::new(198, 51, 100, n));
        assert_eq!(e.who(ip(1)), None);
        e.allow(ip(1), 1);
        e.allow(ip(2), 1);
        assert_eq!((e.who(ip(1)), e.who(ip(2))), (Some(1), Some(1)));
        // a third address pushes out the oldest (limit 2)
        e.allow(ip(3), 1);
        assert_eq!((e.who(ip(1)), e.who(ip(3))), (None, Some(1)));
        // a shared address moves to the user who used it last
        e.allow(ip(3), 2);
        assert_eq!(e.who(ip(3)), Some(2));
        // unknown users are never allowed; a removed user loses access at once
        e.allow(ip(9), 77);
        assert_eq!(e.who(ip(9)), None);
        let mut c = cfg();
        c.users.retain(|u| u.id != 2);
        e.reload(c);
        assert_eq!(e.who(ip(3)), None);
        assert_eq!(e.who(ip(2)), Some(1));
        // IPv4-mapped IPv6 is the same address
        let mapped: IpAddr = "::ffff:198.51.100.2".parse().unwrap();
        assert_eq!(e.who(mapped), Some(1));
    }

    #[tokio::test]
    async fn answers_without_upstream() {
        let e = Engine::new(cfg());
        let q = wire::build_query(5, "dl.playstation.net", wire::A);
        // strangers are refused
        assert_eq!(wire::rcode(&e.answer(&q, None).await.unwrap()), wire::REFUSED);
        let r = e.answer(&q, Some(1)).await.unwrap();
        assert_eq!(wire::a_records(&r), vec![Ipv4Addr::new(203, 0, 113, 7)]);
        let r6 = e.answer(&wire::build_query(6, "dl.playstation.net", wire::AAAA), Some(1)).await.unwrap();
        assert_eq!((wire::rcode(&r6), r6[7]), (wire::NOERROR, 0));
        // the server's own name is answered for anyone
        let own = e.answer(&wire::build_query(7, "aaaa1111.de.dns.example.com", wire::A), None).await.unwrap();
        assert_eq!(wire::a_records(&own), vec![Ipv4Addr::new(203, 0, 113, 7)]);
        assert_eq!(e.stats_snapshot().get(&1).map(|x| x.1), Some(2));
        // garbage gets FORMERR or nothing, never a panic
        let mut bad = q.clone();
        bad[12] = 0xC0;
        assert_eq!(e.answer(&bad, Some(1)).await.map(|r| wire::rcode(&r)), Some(wire::FORMERR));
    }

    #[tokio::test]
    async fn counts_queries_and_forgets_kicked_users() {
        let e = Engine::new(cfg());
        let q = wire::build_query(5, "dl.playstation.net", wire::A);
        e.answer(&q, None).await;
        e.answer(&q, Some(1)).await;
        e.answer(&q, Some(1)).await;
        assert_eq!((e.q_total.load(Ordering::Relaxed), e.q_routed.load(Ordering::Relaxed), e.q_refused.load(Ordering::Relaxed)), (2, 2, 1));
        assert_eq!(e.top(5), vec![("playstation.net".to_string(), 2)]);
        // only subscribers' queries are logged, with the listed name that routed them
        let log = e.qlog_after(0);
        assert_eq!(log.len(), 2);
        assert_eq!((log[0].uid, log[0].name.as_str(), log[0].qtype, log[0].routed.as_str()), (1, "dl.playstation.net", wire::A, "playstation.net"));
        assert_eq!(e.qlog_after(log[0].seq).len(), 1);
        let ip: IpAddr = "198.51.100.9".parse().unwrap();
        e.allow(ip, 1);
        e.allow("198.51.100.10".parse().unwrap(), 2);
        assert_eq!(e.ips_snapshot().get(&1), Some(&vec!["198.51.100.9".to_string()]));
        // the same users again: nothing is forgotten
        e.reload(cfg());
        assert_eq!(e.who(ip), Some(1));
        // a new epoch for user 1: only user 1 must register again
        let mut c = cfg();
        c.users[0].epoch = 1;
        e.reload(c);
        assert_eq!(e.who(ip), None);
        assert_eq!(e.who("198.51.100.10".parse().unwrap()), Some(2));
    }

    #[tokio::test]
    async fn forwards_and_caches() {
        // a fake upstream that answers every A query with 192.0.2.1 and counts what it got
        let up = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = up.local_addr().unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let h2 = hits.clone();
        tokio::spawn(async move {
            let mut b = [0u8; 1500];
            loop {
                let (n, from) = up.recv_from(&mut b).await.unwrap();
                h2.fetch_add(1, Ordering::Relaxed);
                let q = wire::parse_query(&b[..n]).unwrap();
                let r = wire::answer_a(&b[..n], &q, &[Ipv4Addr::new(192, 0, 2, 1)], 120);
                up.send_to(&r, from).await.unwrap();
            }
        });
        let mut c = cfg();
        c.upstreams = vec![addr.to_string()];
        let e = Engine::new(c);
        let q = wire::build_query(0x4242, "Www.Other.COM", wire::A);
        let r = e.answer(&q, Some(2)).await.unwrap();
        assert_eq!(&r[0..2], &[0x42, 0x42]);
        assert_eq!(wire::a_records(&r), vec![Ipv4Addr::new(192, 0, 2, 1)]);
        // second time from the cache, with the new id and the client's spelling
        let q2 = wire::build_query(0x0101, "wWw.other.com", wire::A);
        let r2 = e.answer(&q2, Some(2)).await.unwrap();
        assert_eq!(&r2[0..2], &[0x01, 0x01]);
        assert_eq!(&r2[12..q2.len()], &q2[12..]);
        assert_eq!(hits.load(Ordering::Relaxed), 1);
        // the lookup used for relaying shares the cache, and never dials private addresses
        assert_eq!(e.lookup("www.other.com").await, vec![Ipv4Addr::new(192, 0, 2, 1)]);
        assert_eq!(hits.load(Ordering::Relaxed), 1);
        for ip in ["10.1.2.3", "127.0.0.1", "192.168.1.1", "100.64.0.1", "169.254.1.1", "0.1.2.3", "255.255.255.255"] {
            assert!(!public_v4(ip.parse().unwrap()), "{}", ip);
        }
        assert!(public_v4("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn data_center_resolvers_from_resolv_conf() {
        let up: Vec<SocketAddr> = vec!["1.1.1.1:53".parse().unwrap()];
        let own = vec![Ipv4Addr::new(5, 6, 7, 8)];
        let t = "# comment\nnameserver 127.0.0.53\nnameserver 185.51.200.2\nnameserver 1.1.1.1\nnameserver 5.6.7.8\nnameserver ::1\nnameserver 185.51.200.2\nsearch x";
        assert_eq!(parse_resolv(t, &up, &own), vec!["185.51.200.2:53".parse::<SocketAddr>().unwrap()]);
        // only systemd-resolved's stub: it is used
        assert_eq!(parse_resolv("nameserver 127.0.0.53\n", &up, &own), vec!["127.0.0.53:53".parse::<SocketAddr>().unwrap()]);
        assert!(parse_resolv("nameserver 127.0.0.1\n", &up, &own).is_empty());
    }


    /// A fake resolver that answers every A query with `ip`.
    async fn fake_resolver(ip: Ipv4Addr) -> SocketAddr {
        let up = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = up.local_addr().unwrap();
        tokio::spawn(async move {
            let mut b = [0u8; 1500];
            loop {
                let Ok((n, from)) = up.recv_from(&mut b).await else { continue };
                let q = wire::parse_query(&b[..n]).unwrap();
                let _ = up.send_to(&wire::answer_a(&b[..n], &q, &[ip], 120), from).await;
            }
        });
        addr
    }

    #[tokio::test]
    async fn relay_asks_its_exit_then_the_data_center() {
        // the exit: its own upstream answers 192.0.2.1, its relay intake listens on a local port
        let mut xc = cfg();
        xc.upstreams = vec![fake_resolver(Ipv4Addr::new(192, 0, 2, 1)).await.to_string()];
        xc.relay_key = "k3y".into();
        let exit = Engine::new(xc);
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let intake_addr = l.local_addr().unwrap();
        tokio::spawn(accept_loop(exit.clone(), l, Kind::Intake));
        // the relay: its direct upstream would answer 192.0.2.2, but the exit comes first
        let mut rc = cfg();
        rc.role = "relay".into();
        rc.upstreams = vec![fake_resolver(Ipv4Addr::new(192, 0, 2, 2)).await.to_string()];
        rc.exit_addr = intake_addr.to_string();
        rc.relay_key = "k3y".into();
        let relay = Engine::new(rc.clone());
        let r = relay.answer(&wire::build_query(0x1111, "www.other.com", wire::A), Some(1)).await.unwrap();
        assert_eq!(&r[0..2], &[0x11, 0x11]);
        assert_eq!(wire::a_records(&r), vec![Ipv4Addr::new(192, 0, 2, 1)]);
        assert_eq!(relay.q_exit.load(Ordering::Relaxed), 1);
        // a routed name is still answered with the relay's own address
        let r = relay.answer(&wire::build_query(1, "dl.playstation.net", wire::A), Some(1)).await.unwrap();
        assert_eq!(wire::a_records(&r), vec![Ipv4Addr::new(203, 0, 113, 7)]);
        // a wrong key gets nothing from the exit, so the relay falls back to its upstream
        let mut bad = rc.clone();
        bad.relay_key = "wrong".into();
        let relay2 = Engine::new(bad);
        let r = relay2.answer(&wire::build_query(2, "www.other.com", wire::A), Some(1)).await.unwrap();
        assert_eq!(wire::a_records(&r), vec![Ipv4Addr::new(192, 0, 2, 2)]);

        // nothing abroad answers (no exit, upstream dead): the data center's resolver does
        let dead = TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap();
        let mut cut = rc.clone();
        cut.exit_addr = dead.to_string();
        cut.upstreams = vec!["127.0.0.1:9".into()];
        let relay3 = Engine::new(cut.clone());
        let mut live = Live::new(cut);
        live.system = vec![fake_resolver(Ipv4Addr::new(192, 0, 2, 3)).await];
        *relay3.live.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(live);
        let r = relay3.answer(&wire::build_query(3, "www.irani.ir", wire::A), Some(1)).await.unwrap();
        assert_eq!(wire::a_records(&r), vec![Ipv4Addr::new(192, 0, 2, 3)]);
        // the dead ways are skipped for a while: the next name does not wait for them
        let t = Instant::now();
        let r = relay3.answer(&wire::build_query(4, "www.digikala.com", wire::A), Some(1)).await.unwrap();
        assert_eq!(wire::a_records(&r), vec![Ipv4Addr::new(192, 0, 2, 3)]);
        assert!(t.elapsed() < Duration::from_millis(800), "{:?}", t.elapsed());
        assert_eq!(relay3.q_local.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn relays_a_routed_connection() {
        // an "origin" that answers whatever it gets with "pong:" + the first 3 bytes
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let oaddr = origin.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = origin.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut b = [0u8; 3];
                    s.read_exact(&mut b).await.unwrap();
                    s.write_all(b"pong:").await.unwrap();
                    s.write_all(&b).await.unwrap();
                });
            }
        });
        // the exit intake forwards to the origin through `carry` -> use pump directly for the byte path
        let a = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let aaddr = a.local_addr().unwrap();
        let stat = Arc::new(UserStat::default());
        let st2 = stat.clone();
        tokio::spawn(async move {
            let (c, _) = a.accept().await.unwrap();
            let u = TcpStream::connect(oaddr).await.unwrap();
            pump(c, u, Some(st2)).await;
        });
        let mut c = TcpStream::connect(aaddr).await.unwrap();
        c.write_all(b"abc").await.unwrap();
        let mut got = [0u8; 8];
        c.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"pong:abc");
        drop(c);
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(stat.bytes.load(Ordering::Relaxed), 11);
    }
}
