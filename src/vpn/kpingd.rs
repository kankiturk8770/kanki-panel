//! KPING v2 on the servers: the relay (Iran) and the exit (abroad). Both run inside the tunnel agent.
//!
//! Plain UDP, no stream and no retransmission: a lost game packet is old news, so nothing waits for it.
//! Every packet is sent more than once instead (the phone on each of its paths, Wi-Fi and mobile data, or
//! twice a few ms apart on one path), the first copy that arrives wins and the rest are dropped, and a
//! light XOR parity rebuilds one lost packet of a small group. TCP inside (logins) does its own
//! retransmission.
//!
//! Wire (20 bytes on top of the IP packet):
//! `[uid 4 | sess 2 | seq 4 | kind 1 | aux 1]` masked, then the IP packet as it is, then an 8-byte tag.
//! - tag  = HMAC-SHA256(user key, plain header ‖ payload)[..8]: only the user's own key makes packets
//! - mask = AES-256(obfs, tag ‖ "KPNG" ‖ 0000)[..12] XOR the header: no fixed bytes on the wire
//! - kind: DATA 1, PARITY 2, PING 3, PONG 4; + 0x80 from the server to the phone
//! - PING (aux = path id): payload = [the phone's clock in ms 8 | copy delay ms 1 | flags 1], the last two
//!   optional (the phone tunes them to its line: 0xff = this server's own; flags bit 0 = a delayed copy on
//!   every path, not only when there is one). A new session is taken only from a PING within 2 minutes of
//!   this server's clock, so old packets cannot start one again.
//! - PONG (aux = paths): payload = [the PING's clock 8 | n 1 | n × (path id 1 | its copies that came
//!   first 4 | its copies 4)] since the session began: what each path saved
//! - DATA from the phone: aux = path id (low 4 bits) | the parity group the phone wants back (high 4 bits:
//!   0 = this server's own, 1 = none, 2-8 = a repair packet per that many)
//! - PARITY (aux = n): payload = [first seq 4 | xor of the lengths 2 | xor of the n payloads, padded]
//!   over the n DATA packets first … first+n-1 (n ≤ 8; sent when the group is full or 8 ms idle)
//!
//! The payload is not encrypted (the game encrypts its own): the leg phone → Iran is domestic, and Iran
//! → abroad goes inside the encrypted Game-FEC tunnel.
//!
//! Relay (Iran, public UDP port): checks every packet, drops the copies, sends one copy into the
//! tunnel (127.0.0.1:`to`, the tunnel's entry); what comes back goes to every path of that session
//! (one path: twice, `dup_ms` apart). Between Iran and abroad every packet goes twice too, `tun_dup_ms`
//! apart (the tunnel's own FEC sends a lone game packet's repair shards right behind it, so one short
//! outage of that link takes them all); the other side drops the second copy. Exit (abroad, 127.0.0.1 only: the tunnel delivers there): drops
//! copies, rebuilds with parity, writes the IP packet to `kping0` (NAT out); packets for a user go back
//! the way that user's last packet came, with parity of their own.
//!
//! Plain threads, no async, like microtun.
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes256;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Sha256;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fs::File;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex, OnceLock};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::kprlc;

pub const HDR: usize = 12;
pub const TAG: usize = 8;
/// bytes KPING adds to each IP packet
pub const OVERHEAD: usize = HDR + TAG;
pub const DOWN: u8 = 0x80;
pub const DATA: u8 = 1;
pub const PARITY: u8 = 2;
pub const PING: u8 = 3;
pub const PONG: u8 = 4;
/// v3: a sliding-window repair (`kprlc`), the radio's keep-awake filler (dropped here), a tunnel probe
pub const REPAIR: u8 = 5;
pub const FILL: u8 = 6;
pub const PROBE: u8 = 7;
/// PING byte 10 / PONG's trailing caps: this end speaks v3
pub const CAP_RLC: u8 = 1;
/// DATA aux high bits 9-15: a v3 phone asks the exit for this many repairs per packet
pub const DOWN_RATIOS: [f64; 7] = [0.25, 0.5, 0.75, 1.0, 1.5, 2.0, 3.0];
pub const IFACE: &str = "kping0";
pub const SERVER_ADDR: &str = "10.81.0.1/16";
/// largest parity group
pub const MAX_GROUP: usize = 8;
/// a session's PING must be this close to the server's clock (ms)
const FRESH_MS: i64 = 120_000;
/// a path that sent nothing this long is dropped
const PATH_IDLE: Duration = Duration::from_secs(30);
/// a session that sent nothing this long is forgotten
const SESS_IDLE: Duration = Duration::from_secs(180);
const MAX_PATHS: usize = 4;
const MAX_SESS: usize = 4;
/// a parity group that got no new packet this long is sent as it is (a game sends every 15-30 ms)
const GROUP_IDLE: Duration = Duration::from_millis(8);
const WIN: u32 = 1024;
const MAX_PKT: usize = 2048;
/// a tunnel that answered no probe for this long is left out (the other one carries everything)
const TUN_DEAD: Duration = Duration::from_secs(3);
const PROBE_EVERY: Duration = Duration::from_millis(250);

type Mac8 = Hmac<Sha256>;

// ------------------------------------------------------------------ the wire

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hdr {
    pub uid: u32,
    pub sess: u16,
    pub seq: u32,
    pub kind: u8,
    pub aux: u8,
}

impl Hdr {
    fn bytes(&self) -> [u8; HDR] {
        let mut b = [0u8; HDR];
        b[..4].copy_from_slice(&self.uid.to_be_bytes());
        b[4..6].copy_from_slice(&self.sess.to_be_bytes());
        b[6..10].copy_from_slice(&self.seq.to_be_bytes());
        b[10] = self.kind;
        b[11] = self.aux;
        b
    }
    fn from(b: &[u8]) -> Hdr {
        Hdr {
            uid: u32::from_be_bytes([b[0], b[1], b[2], b[3]]),
            sess: u16::from_be_bytes([b[4], b[5]]),
            seq: u32::from_be_bytes([b[6], b[7], b[8], b[9]]),
            kind: b[10],
            aux: b[11],
        }
    }
}

/// The key that masks every header (one for all users)
pub struct Obfs(Aes256);

impl Obfs {
    pub fn new(hex_key: &str) -> Option<Obfs> {
        let k: [u8; 32] = hex::decode(hex_key.trim()).ok()?.try_into().ok()?;
        Some(Obfs(Aes256::new(&k.into())))
    }
    fn mask(&self, tag: &[u8]) -> [u8; HDR] {
        let mut b = [0u8; 16];
        b[..TAG].copy_from_slice(&tag[..TAG]);
        b[8..12].copy_from_slice(b"KPNG");
        let mut blk = b.into();
        self.0.encrypt_block(&mut blk);
        let mut m = [0u8; HDR];
        m.copy_from_slice(&blk[..HDR]);
        m
    }
}

/// A user's key, ready to tag packets
#[derive(Clone)]
pub struct UKey(Mac8);

impl UKey {
    pub fn new(hex_key: &str) -> Option<UKey> {
        let k = hex::decode(hex_key.trim()).ok().filter(|k| k.len() == 32)?;
        Some(UKey(<Mac8 as Mac>::new_from_slice(&k).ok()?))
    }
    fn tag(&self, hdr: &[u8], payload: &[u8]) -> [u8; TAG] {
        let mut m = self.0.clone();
        m.update(hdr);
        m.update(payload);
        let full = m.finalize().into_bytes();
        let mut t = [0u8; TAG];
        t.copy_from_slice(&full[..TAG]);
        t
    }
}

/// The key of the probes between the relay and the exit (uid 0): made from the obfs key, so only KPING's
/// own servers make them
pub fn probe_key(obfs: &str) -> UKey {
    use sha2::Digest;
    let h = Sha256::digest(format!("kping-probe|{}", obfs.trim()).as_bytes());
    UKey::new(&hex::encode(h)).expect("32 bytes")
}

/// One packet on the wire
pub fn seal(o: &Obfs, k: &UKey, h: &Hdr, payload: &[u8]) -> Vec<u8> {
    let hb = h.bytes();
    let tag = k.tag(&hb, payload);
    let m = o.mask(&tag);
    let mut out = Vec::with_capacity(OVERHEAD + payload.len());
    out.extend(hb.iter().zip(m.iter()).map(|(a, b)| a ^ b));
    out.extend_from_slice(payload);
    out.extend_from_slice(&tag);
    out
}

/// The header of a packet (not checked yet: anyone with the obfs key reads it)
pub fn peek(o: &Obfs, pkt: &[u8]) -> Option<Hdr> {
    if pkt.len() < OVERHEAD {
        return None;
    }
    let m = o.mask(&pkt[pkt.len() - TAG..]);
    let mut hb = [0u8; HDR];
    for i in 0..HDR {
        hb[i] = pkt[i] ^ m[i];
    }
    Some(Hdr::from(&hb))
}

/// Whether the packet was made with this key; its payload
pub fn open<'a>(k: &UKey, h: &Hdr, pkt: &'a [u8]) -> Option<&'a [u8]> {
    let payload = &pkt[HDR..pkt.len() - TAG];
    let want = k.tag(&h.bytes(), payload);
    let got = &pkt[pkt.len() - TAG..];
    // constant time
    let diff = want.iter().zip(got).fold(0u8, |a, (x, y)| a | (x ^ y));
    (diff == 0).then_some(payload)
}

// ------------------------------------------------------------------ copies and parity

/// The last 1024 sequence numbers: the first copy passes, the others not
#[derive(Default, Clone)]
pub struct Window {
    top: Option<u32>,
    bits: [u64; (WIN / 64) as usize],
}

impl Window {
    fn bit(&mut self, seq: u32) -> (usize, u64) {
        let i = (seq % WIN) as usize;
        (i / 64, 1u64 << (i % 64))
    }
    /// true the first time `seq` is seen
    pub fn take(&mut self, seq: u32) -> bool {
        match self.top {
            None => self.top = Some(seq),
            Some(top) if seq > top => {
                // clear the slots between the old top and seq
                let gap = seq - top;
                if gap >= WIN {
                    self.bits = [0; (WIN / 64) as usize];
                } else {
                    for s in top + 1..seq {
                        let (w, b) = self.bit(s);
                        self.bits[w] &= !b;
                    }
                }
                let (w, b) = self.bit(seq);
                self.bits[w] &= !b;
                self.top = Some(seq);
            }
            Some(top) if top - seq >= WIN => return false,
            _ => {}
        }
        let (w, b) = self.bit(seq);
        if self.bits[w] & b != 0 {
            return false;
        }
        self.bits[w] |= b;
        true
    }
    pub fn has(&self, seq: u32) -> bool {
        match self.top {
            Some(top) if seq <= top && top - seq < WIN => {
                let i = (seq % WIN) as usize;
                self.bits[i / 64] & (1u64 << (i % 64)) != 0
            }
            _ => false,
        }
    }
}

/// The sending side of the parity: groups of up to `k` DATA packets
pub struct FecTx {
    k: usize,
    first: u32,
    n: usize,
    len_x: u16,
    x: Vec<u8>,
    last: Instant,
}

impl FecTx {
    pub fn new(k: usize) -> FecTx {
        FecTx { k: k.min(MAX_GROUP), first: 0, n: 0, len_x: 0, x: vec![], last: Instant::now() }
    }
    /// A DATA packet went out; the parity payload when its group is full
    pub fn add(&mut self, seq: u32, payload: &[u8]) -> Option<(u8, Vec<u8>)> {
        if self.k < 2 {
            return None;
        }
        if self.n > 0 && seq != self.first.wrapping_add(self.n as u32) {
            // a gap in the numbers (should not happen): start again
            self.n = 0;
        }
        if self.n == 0 {
            self.first = seq;
            self.len_x = 0;
            self.x.clear();
        }
        self.len_x ^= payload.len() as u16;
        if self.x.len() < payload.len() {
            self.x.resize(payload.len(), 0);
        }
        for (a, b) in self.x.iter_mut().zip(payload) {
            *a ^= b;
        }
        self.n += 1;
        self.last = Instant::now();
        if self.n >= self.k { self.take() } else { None }
    }
    /// The parity of a group that has been waiting too long
    pub fn flush(&mut self) -> Option<(u8, Vec<u8>)> {
        if self.n >= 1 && self.last.elapsed() >= GROUP_IDLE { self.take() } else { None }
    }
    fn take(&mut self) -> Option<(u8, Vec<u8>)> {
        let n = self.n;
        self.n = 0;
        // a single packet's parity is just a copy of it: worth it only in a group
        if n < 2 {
            return None;
        }
        let mut p = Vec::with_capacity(6 + self.x.len());
        p.extend_from_slice(&self.first.to_be_bytes());
        p.extend_from_slice(&self.len_x.to_be_bytes());
        p.extend_from_slice(&self.x);
        Some((n as u8, p))
    }
}

/// The receiving side: the last DATA payloads and the parities still missing one packet
#[derive(Default)]
pub struct FecRx {
    got: BTreeMap<u32, Vec<u8>>,
    wait: VecDeque<(u32, u8, u16, Vec<u8>)>,
}

impl FecRx {
    const KEEP: usize = 128;
    /// A DATA packet arrived; a packet rebuilt with it (seq, payload), if any
    pub fn data(&mut self, seq: u32, payload: &[u8], win: &Window) -> Option<(u32, Vec<u8>)> {
        self.got.insert(seq, payload.to_vec());
        while self.got.len() > Self::KEEP {
            self.got.pop_first();
        }
        self.solve(win)
    }
    pub fn parity(&mut self, n: u8, payload: &[u8], win: &Window) -> Option<(u32, Vec<u8>)> {
        if payload.len() < 6 || !(2..=MAX_GROUP as u8).contains(&n) {
            return None;
        }
        let first = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
        let len_x = u16::from_be_bytes([payload[4], payload[5]]);
        self.wait.push_back((first, n, len_x, payload[6..].to_vec()));
        while self.wait.len() > 16 {
            self.wait.pop_front();
        }
        self.solve(win)
    }
    fn solve(&mut self, win: &Window) -> Option<(u32, Vec<u8>)> {
        let mut out = None;
        self.wait.retain(|(first, n, len_x, x)| {
            if out.is_some() {
                return true;
            }
            let seqs: Vec<u32> = (0..*n as u32).map(|i| first.wrapping_add(i)).collect();
            let missing: Vec<u32> = seqs.iter().copied().filter(|s| !win.has(*s)).collect();
            match missing.len() {
                0 => false,
                1 => {
                    // every other payload must still be here
                    let others: Vec<&Vec<u8>> = seqs.iter().filter(|s| **s != missing[0]).filter_map(|s| self.got.get(s)).collect();
                    if others.len() != *n as usize - 1 {
                        return false;
                    }
                    let mut len = *len_x;
                    let mut p = x.clone();
                    for o in others {
                        len ^= o.len() as u16;
                        for (a, b) in p.iter_mut().zip(o.iter()) {
                            *a ^= b;
                        }
                    }
                    let len = len as usize;
                    if len == 0 || len > p.len() {
                        return false;
                    }
                    p.truncate(len);
                    out = Some((missing[0], p));
                    false
                }
                // two or more lost: wait for more (a late copy may still come)
                _ => true,
            }
        });
        out
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

// ------------------------------------------------------------------ config

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(default)]
pub struct KUser {
    pub uid: u32,
    pub name: String,
    /// 64 hex
    pub key: String,
    /// the address of the phone inside (exit only)
    pub ip: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(default)]
pub struct RelayCfg {
    /// public UDP port the phones dial
    pub port: u16,
    /// the tunnel's entry on 127.0.0.1
    pub to: u16,
    /// more tunnels to the same exit (their entries on 127.0.0.1): every packet goes on each live one,
    /// the exit keeps the first copy
    pub more: Vec<u16>,
    /// one path: the second copy to the phone goes this many ms after the first (0 = no second copy)
    pub dup_ms: u16,
    /// into the tunnel: the second copy this many ms after the first (0 = one copy)
    pub tun_dup_ms: u16,
    pub users: Vec<KUser>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(default)]
pub struct ExitCfg {
    /// UDP port on 127.0.0.1 (the tunnel delivers there)
    pub port: u16,
    pub mtu: u16,
    /// parity group towards the phone (0 = none)
    pub fec: u8,
    /// back into the tunnel: the second copy this many ms after the first (0 = one copy)
    pub tun_dup_ms: u16,
    pub users: Vec<KUser>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(default)]
pub struct KpCfg {
    pub obfs: String,
    pub relays: Vec<RelayCfg>,
    pub exit: Option<ExitCfg>,
}


fn bind_udp(public: bool, port: u16) -> Result<UdpSocket, String> {
    let s = if public { UdpSocket::bind(("::", port)).or_else(|_| UdpSocket::bind(("0.0.0.0", port))) } else { UdpSocket::bind(("127.0.0.1", port)) }
        .map_err(|e| format!("UDP {}: {}", port, e))?;
    s.set_read_timeout(Some(Duration::from_millis(300))).ok();
    Ok(s)
}

fn spawn(name: &str, f: impl FnOnce() + Send + 'static) -> JoinHandle<()> {
    std::thread::Builder::new().name(name.into()).spawn(f).expect("thread")
}

// ------------------------------------------------------------------ the relay (Iran)

struct RPath {
    addr: SocketAddr,
    id: u8,
    last: Instant,
    /// its DATA copies that came first / all its DATA copies
    first: u32,
    total: u32,
}

struct RSess {
    /// DATA, PARITY, PING, REPAIR
    win: [Window; 4],
    /// what came back from the exit (DATA, PARITY, REPAIR): its second copy is dropped here
    down: [Window; 3],
    paths: Vec<RPath>,
    last: Instant,
    /// the phone's own choice of the copy delay (None = the server's)
    dup_ms: Option<u16>,
    /// a delayed copy on every path, not only when there is one
    every: bool,
}

impl RSess {
    fn new() -> RSess {
        RSess { win: Default::default(), down: Default::default(), paths: vec![], last: Instant::now(), dup_ms: None, every: false }
    }
    fn note_path(&mut self, from: SocketAddr, id: u8, may_add: bool) -> Option<&mut RPath> {
        let now = Instant::now();
        self.last = now;
        if let Some(i) = self.paths.iter().position(|p| p.addr == from) {
            let p = &mut self.paths[i];
            p.id = id;
            p.last = now;
            return Some(p);
        }
        if !may_add {
            return None;
        }
        // a path that moved (a new NAT port) takes the place of its old address
        self.paths.retain(|p| p.id != id || p.id == 0);
        if self.paths.len() >= MAX_PATHS {
            self.paths.sort_by_key(|p| p.last);
            self.paths.remove(0);
        }
        self.paths.push(RPath { addr: from, id, last: now, first: 0, total: 0 });
        self.paths.last_mut()
    }
    fn live_paths(&self) -> Vec<SocketAddr> {
        self.paths.iter().filter(|p| p.last.elapsed() < PATH_IDLE).map(|p| p.addr).collect()
    }
}

struct RUser {
    key: UKey,
    sess: HashMap<u16, RSess>,
}

/// One tunnel to the exit, as its probes find it
#[derive(Default, Clone)]
struct TunQ {
    rtt_ms: f64,
    /// the last probes: answered or not
    ring: VecDeque<bool>,
    last_ans: Option<Instant>,
    sent: HashMap<u32, Instant>,
}

impl TunQ {
    fn loss(&self) -> f64 {
        if self.ring.is_empty() {
            return 0.0;
        }
        100.0 * self.ring.iter().filter(|a| !**a).count() as f64 / self.ring.len() as f64
    }
    fn live(&self) -> bool {
        self.last_ans.is_some_and(|t| t.elapsed() < TUN_DEAD)
    }
}

struct RShared {
    obfs: Obfs,
    probe: UKey,
    public: UdpSocket,
    /// one socket per tunnel entry
    ups: Vec<UdpSocket>,
    tq: Mutex<Vec<TunQ>>,
    users: Mutex<HashMap<u32, RUser>>,
    dup_ms: AtomicU64,
    stop: AtomicBool,
    pkts: AtomicU64,
    dups: AtomicU64,
    bad: AtomicU64,
    dly: Mutex<mpsc::Sender<(Instant, Vec<u8>, SocketAddr)>>,
    tun_dup: AtomicU64,
    /// second copies into the tunnels (the tunnel index rides in the address' port)
    dly_up: Mutex<mpsc::Sender<(Instant, Vec<u8>, SocketAddr)>>,
}

impl RShared {
    /// the tunnels to use now: those that answer; when none does, all of them (one may still pass)
    fn live_ups(&self) -> Vec<usize> {
        let tq = self.tq.lock().unwrap_or_else(|e| e.into_inner());
        let live: Vec<usize> = (0..self.ups.len()).filter(|i| tq.get(*i).is_some_and(|q| q.live())).collect();
        if live.is_empty() { (0..self.ups.len()).collect() } else { live }
    }
    /// the best tunnel's round trip and loss (for the phone's PONG)
    fn best_tun(&self) -> (u16, u16) {
        let tq = self.tq.lock().unwrap_or_else(|e| e.into_inner());
        tq.iter()
            .filter(|q| q.live())
            .map(|q| (q.rtt_ms.round() as u16, (q.loss() * 10.0).round() as u16))
            .min_by_key(|x| x.0 as u32 + 3 * x.1 as u32)
            .unwrap_or((0, 0))
    }
    fn send_up(&self, pkt: &[u8], from: SocketAddr) {
        let d = self.tun_dup.load(Ordering::Relaxed);
        for i in self.live_ups() {
            let _ = self.ups[i].send(pkt);
            if d > 0 {
                let mut tag = from;
                tag.set_port(i as u16);
                let _ = self.dly_up.lock().unwrap_or_else(|e| e.into_inner()).send((Instant::now() + Duration::from_millis(d), pkt.to_vec(), tag));
            }
        }
    }
}

pub struct Relay {
    sh: Arc<RShared>,
    threads: Vec<JoinHandle<()>>,
    pub cfg: RelayCfg,
}

impl Relay {
    pub fn start(obfs: &str, cfg: &RelayCfg) -> Result<Relay, String> {
        let o = Obfs::new(obfs).ok_or("bad obfs key")?;
        let public = bind_udp(true, cfg.port)?;
        let mut ups = vec![];
        for to in std::iter::once(cfg.to).chain(cfg.more.iter().copied().filter(|p| *p != cfg.to)) {
            let up = UdpSocket::bind(("127.0.0.1", 0)).map_err(|e| format!("UDP: {}", e))?;
            up.connect(("127.0.0.1", to)).map_err(|e| format!("tunnel {}: {}", to, e))?;
            up.set_read_timeout(Some(Duration::from_millis(300))).ok();
            ups.push(up);
        }
        let (tx, rx) = mpsc::channel();
        let (utx, urx) = mpsc::channel();
        let n = ups.len();
        let sh = Arc::new(RShared {
            obfs: o,
            probe: probe_key(obfs),
            public,
            ups,
            tq: Mutex::new(vec![TunQ::default(); n]),
            users: Mutex::new(HashMap::new()),
            dup_ms: AtomicU64::new(0),
            stop: AtomicBool::new(false),
            pkts: AtomicU64::new(0),
            dups: AtomicU64::new(0),
            bad: AtomicU64::new(0),
            dly: Mutex::new(tx),
            tun_dup: AtomicU64::new(0),
            dly_up: Mutex::new(utx),
        });
        let mut r = Relay { sh: sh.clone(), threads: vec![], cfg: cfg.clone() };
        r.set(cfg);
        let s = sh.clone();
        r.threads.push(spawn("kp-relay-in", move || relay_in(&s)));
        for i in 0..n {
            let s = sh.clone();
            r.threads.push(spawn("kp-relay-back", move || relay_back(&s, i)));
        }
        let s = sh.clone();
        r.threads.push(spawn("kp-relay-probe", move || relay_probe(&s)));
        let s = sh.clone();
        r.threads.push(spawn("kp-relay-dup", move || delayer(&s.stop, rx, |p, to| {
            let _ = s.public.send_to(p, to);
        })));
        let s = sh;
        r.threads.push(spawn("kp-relay-tdup", move || delayer(&s.stop, urx, |p, tag| {
            if let Some(u) = s.ups.get(tag.port() as usize) {
                let _ = u.send(p);
            }
        })));
        Ok(r)
    }

    /// the tunnels of this relay changed: it starts again
    pub fn needs_restart(&self, cfg: &RelayCfg) -> bool {
        self.cfg.port != cfg.port || self.cfg.to != cfg.to || self.cfg.more != cfg.more
    }

    /// users and the copy delay, live: a user whose key stays keeps their sessions
    pub fn set(&mut self, cfg: &RelayCfg) {
        self.sh.dup_ms.store(cfg.dup_ms.min(50) as u64, Ordering::Relaxed);
        self.sh.tun_dup.store(cfg.tun_dup_ms.min(50) as u64, Ordering::Relaxed);
        let mut users = self.sh.users.lock().unwrap_or_else(|e| e.into_inner());
        let mut next = HashMap::new();
        for u in &cfg.users {
            let Some(key) = UKey::new(&u.key) else { continue };
            let sess = match self.cfg.users.iter().find(|x| x.uid == u.uid && x.key == u.key) {
                Some(_) => users.remove(&u.uid).map(|x| x.sess).unwrap_or_default(),
                None => HashMap::new(),
            };
            next.insert(u.uid, RUser { key, sess });
        }
        *users = next;
        self.cfg = cfg.clone();
    }

    pub fn status(&self) -> Value {
        let users = self.sh.users.lock().unwrap_or_else(|e| e.into_inner());
        let live: Vec<&RSess> = users.values().flat_map(|u| u.sess.values()).filter(|s| s.last.elapsed() < Duration::from_secs(60)).collect();
        let tq = self.sh.tq.lock().unwrap_or_else(|e| e.into_inner());
        let tunnels: Vec<Value> = tq.iter().map(|q| json!({ "rtt": (q.rtt_ms * 10.0).round() / 10.0, "loss": (q.loss() * 10.0).round() / 10.0, "up": q.live() })).collect();
        json!({
            "port": self.cfg.port, "to": self.cfg.to, "tunnels": tunnels,
            "online": users.values().filter(|u| u.sess.values().any(|s| s.last.elapsed() < Duration::from_secs(60))).count(),
            "paths": live.iter().map(|s| s.live_paths().len()).sum::<usize>(),
            "pkts": self.sh.pkts.load(Ordering::Relaxed), "dups": self.sh.dups.load(Ordering::Relaxed), "bad": self.sh.bad.load(Ordering::Relaxed),
        })
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.sh.stop.store(true, Ordering::Relaxed);
        // wakes the delay thread
        let _ = self.sh.dly.lock().map(|t| t.send((Instant::now(), vec![], "127.0.0.1:9".parse().expect("addr"))));
        let _ = self.sh.dly_up.lock().map(|t| t.send((Instant::now(), vec![], "127.0.0.1:9".parse().expect("addr"))));
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
    }
}

/// phone → relay: check, drop copies, one copy into each tunnel; PING gets its PONG here
fn relay_in(sh: &RShared) {
    let mut buf = vec![0u8; MAX_PKT];
    while !sh.stop.load(Ordering::Relaxed) {
        let Ok((n, from)) = sh.public.recv_from(&mut buf) else { continue };
        let pkt = &buf[..n];
        let Some(h) = peek(&sh.obfs, pkt) else { continue };
        if h.kind & DOWN != 0 {
            continue;
        }
        let mut users = sh.users.lock().unwrap_or_else(|e| e.into_inner());
        let Some(u) = users.get_mut(&h.uid) else {
            sh.bad.fetch_add(1, Ordering::Relaxed);
            continue;
        };
        let Some(payload) = open(&u.key, &h, pkt) else {
            sh.bad.fetch_add(1, Ordering::Relaxed);
            continue;
        };
        let slot = match h.kind {
            DATA => 0,
            PARITY => 1,
            PING => 2,
            REPAIR => 3,
            FILL => {
                // the radio's keep-awake: only keeps a known path alive
                if let Some(s) = u.sess.get_mut(&h.sess) {
                    s.note_path(from, h.aux & 0x0f, false);
                }
                continue;
            }
            _ => continue,
        };
        if !u.sess.contains_key(&h.sess) {
            // only a fresh PING starts a session
            if h.kind != PING || payload.len() < 8 {
                continue;
            }
            let ts = i64::from_be_bytes(payload[..8].try_into().unwrap_or_default());
            if (now_ms() - ts).abs() > FRESH_MS {
                sh.bad.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            u.sess.retain(|_, s| s.last.elapsed() < SESS_IDLE);
            if u.sess.len() >= MAX_SESS {
                if let Some(old) = u.sess.iter().min_by_key(|(_, s)| s.last).map(|(k, _)| *k) {
                    u.sess.remove(&old);
                }
            }
            u.sess.insert(h.sess, RSess::new());
        }
        let key = u.key.clone();
        let Some(s) = u.sess.get_mut(&h.sess) else { continue };
        let first = s.win[slot].take(h.seq);
        // a path is learned from a packet seen for the first time (a copy only keeps a known path alive)
        let path_id = match h.kind {
            PING | DATA | REPAIR => h.aux & 0x0f,
            _ => 0,
        };
        if let Some(p) = s.note_path(from, path_id, first) {
            if h.kind == DATA {
                p.total += 1;
                p.first += first as u32;
            }
        }
        if !first {
            sh.dups.fetch_add(1, Ordering::Relaxed);
            continue;
        }
        sh.pkts.fetch_add(1, Ordering::Relaxed);
        if h.kind == PING {
            if payload.len() >= 10 {
                s.dup_ms = (payload[8] != 0xff).then_some(payload[8].min(50) as u16);
                s.every = payload[9] & 1 != 0;
            }
            let live = s.live_paths().len() as u8;
            let mut body = payload[..8].to_vec();
            let paths: Vec<&RPath> = s.paths.iter().filter(|p| p.last.elapsed() < PATH_IDLE).collect();
            body.push(paths.len() as u8);
            for p in paths {
                body.push(p.id);
                body.extend_from_slice(&p.first.to_be_bytes());
                body.extend_from_slice(&p.total.to_be_bytes());
            }
            drop(users);
            // v3: caps, and the tunnel's round trip (ms) and loss (‰) — a v2 phone reads none of it
            let (rtt, loss) = sh.best_tun();
            body.push(CAP_RLC);
            body.extend_from_slice(&rtt.to_be_bytes());
            body.extend_from_slice(&loss.to_be_bytes());
            let pong = Hdr { uid: h.uid, sess: h.sess, seq: h.seq, kind: PONG | DOWN, aux: live };
            let _ = sh.public.send_to(&seal(&sh.obfs, &key, &pong, &body), from);
            continue;
        }
        drop(users);
        sh.send_up(pkt, from);
    }
}

/// exit → relay through tunnel `i`: to every path of the session (one path: twice); probe answers
fn relay_back(sh: &RShared, i: usize) {
    let mut buf = vec![0u8; MAX_PKT];
    while !sh.stop.load(Ordering::Relaxed) {
        let Ok(n) = sh.ups[i].recv(&mut buf) else { continue };
        let pkt = &buf[..n];
        let Some(h) = peek(&sh.obfs, pkt) else { continue };
        if h.kind & DOWN == 0 {
            continue;
        }
        if h.kind == PROBE | DOWN && h.uid == 0 {
            if open(&sh.probe, &h, pkt).is_some() {
                let mut tq = sh.tq.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(q) = tq.get_mut(i) {
                    if let Some(at) = q.sent.remove(&h.seq) {
                        let rtt = at.elapsed().as_secs_f64() * 1000.0;
                        q.rtt_ms = if q.rtt_ms == 0.0 { rtt } else { q.rtt_ms + (rtt - q.rtt_ms) / 8.0 };
                        q.last_ans = Some(Instant::now());
                        q.ring.push_back(true);
                        while q.ring.len() > 40 {
                            q.ring.pop_front();
                        }
                    }
                }
            }
            continue;
        }
        let (paths, dup, every) = {
            let mut users = sh.users.lock().unwrap_or_else(|e| e.into_inner());
            let Some(u) = users.get_mut(&h.uid) else { continue };
            if open(&u.key, &h, pkt).is_none() {
                continue;
            }
            let Some(s) = u.sess.get_mut(&h.sess) else { continue };
            // the exit's second copy of the same packet (or its copy through the other tunnel) goes no further
            let slot = match h.kind & !DOWN {
                PARITY => 1,
                REPAIR => 2,
                _ => 0,
            };
            if !s.down[slot].take(h.seq) {
                continue;
            }
            (s.live_paths(), s.dup_ms, s.every)
        };
        for p in &paths {
            let _ = sh.public.send_to(pkt, p);
        }
        let ms = dup.map(|d| d as u64).unwrap_or_else(|| sh.dup_ms.load(Ordering::Relaxed));
        if ms > 0 && (paths.len() == 1 || every) {
            let at = Instant::now() + Duration::from_millis(ms);
            let tx = sh.dly.lock().unwrap_or_else(|e| e.into_inner());
            for p in &paths {
                let _ = tx.send((at, pkt.to_vec(), *p));
            }
        }
    }
}

/// a probe into every tunnel four times a second: which tunnel is alive, its round trip and loss
fn relay_probe(sh: &RShared) {
    let mut seq: u32 = 0;
    while !sh.stop.load(Ordering::Relaxed) {
        std::thread::sleep(PROBE_EVERY);
        for (i, up) in sh.ups.iter().enumerate() {
            seq = seq.wrapping_add(1);
            {
                let mut tq = sh.tq.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(q) = tq.get_mut(i) {
                    // unanswered for a second: lost
                    let gone: Vec<u32> = q.sent.iter().filter(|(_, t)| t.elapsed() > Duration::from_secs(1)).map(|(s, _)| *s).collect();
                    for s in gone {
                        q.sent.remove(&s);
                        q.ring.push_back(false);
                    }
                    while q.ring.len() > 40 {
                        q.ring.pop_front();
                    }
                    q.sent.insert(seq, Instant::now());
                }
            }
            let h = Hdr { uid: 0, sess: 0, seq, kind: PROBE, aux: i as u8 };
            let _ = up.send(&seal(&sh.obfs, &sh.probe, &h, &[0u8; 8]));
        }
    }
}

/// second copies, each at its time
fn delayer(stop: &AtomicBool, rx: mpsc::Receiver<(Instant, Vec<u8>, SocketAddr)>, send: impl Fn(&[u8], SocketAddr)) {
    while let Ok((at, pkt, to)) = rx.recv() {
        if stop.load(Ordering::Relaxed) {
            return;
        }
        let now = Instant::now();
        if at > now {
            std::thread::sleep(at - now);
        }
        send(&pkt, to);
    }
}

// ------------------------------------------------------------------ the exit (abroad)

/// how the exit protects a packet going down to the phone: (deadline, share of the repairs); None: as it is
fn down_class(p: &[u8]) -> Option<(Duration, f64)> {
    if p.len() < 20 || p[0] >> 4 != 4 {
        return None;
    }
    let ihl = (p[0] & 0x0f) as usize * 4;
    match p[9] {
        // the game's UDP (and DNS): small datagrams; a big or bulk one goes as it is
        17 if p.len() <= 1000 => Some((Duration::from_millis(150), 1.0)),
        1 => Some((Duration::from_millis(500), 0.5)),
        6 if p.len() >= ihl + 14 => {
            let off = (p[ihl + 12] >> 4) as usize * 4;
            let flags = p[ihl + 13];
            // SYN, FIN, RST, bare ACKs: a lost one costs a whole retransmission timeout
            (flags & 0x07 != 0 || p.len() <= ihl + off).then_some((Duration::from_millis(1500), 0.5))
        }
        _ => None,
    }
}

struct XSess {
    sess: u16,
    /// where the tunnels deliver this session's packets (one per tunnel): the downlink goes back on each
    froms: Vec<(SocketAddr, Instant)>,
    /// DATA, PARITY, REPAIR
    win: [Window; 3],
    rx_fec: FecRx,
    rx_rlc: kprlc::RlcRx,
    down_seq: u32,
    down_pseq: u32,
    tx_fec: FecTx,
    // v3 down: repairs over the phone's protected packets
    rlc: bool,
    ratio: f64,
    tx_rlc: kprlc::RlcTx,
    credit: f64,
    pending: u32,
    last_data: Option<Instant>,
    gap_ms: f64,
    rseq: u32,
}

impl XSess {
    fn new(sess: u16, from: SocketAddr, k: usize) -> XSess {
        XSess {
            sess,
            froms: vec![(from, Instant::now())],
            win: Default::default(),
            rx_fec: FecRx::default(),
            rx_rlc: kprlc::RlcRx::default(),
            down_seq: 0,
            down_pseq: 0,
            tx_fec: FecTx::new(k),
            rlc: false,
            ratio: 0.0,
            tx_rlc: kprlc::RlcTx::default(),
            credit: 0.0,
            pending: 0,
            last_data: None,
            gap_ms: 0.0,
            rseq: 0,
        }
    }
    fn note_from(&mut self, from: SocketAddr) {
        let now = Instant::now();
        match self.froms.iter_mut().find(|(a, _)| *a == from) {
            Some(x) => x.1 = now,
            None => self.froms.push((from, now)),
        }
        self.froms.retain(|(_, t)| t.elapsed() < TUN_DEAD * 2);
        if self.froms.len() > 4 {
            self.froms.sort_by_key(|x| std::cmp::Reverse(x.1));
            self.froms.truncate(4);
        }
    }
    fn tos(&self) -> Vec<SocketAddr> {
        self.froms.iter().filter(|(_, t)| t.elapsed() < TUN_DEAD).map(|x| x.0).collect()
    }
    /// a v3 repair is due: spread between the game's packets, at once when two are owed, or now that the
    /// stream paused (its tail)
    fn repair_due(&self, now: Instant) -> bool {
        let Some(last) = self.last_data else { return false };
        if !self.rlc || self.credit <= 0.0 {
            return false;
        }
        let since = now.duration_since(last).as_secs_f64() * 1000.0;
        let spread = (self.gap_ms / 3.0).clamp(2.0, 8.0);
        self.credit >= 2.0 || (self.credit >= 1.0 && since >= spread) || (self.pending > 0 && since >= (self.gap_ms * 0.75).max(8.0))
    }
}

struct XUser {
    uid: u32,
    name: String,
    key: UKey,
    ip: Ipv4Addr,
    cur: Option<XSess>,
    rx: u64,
    tx: u64,
    last: Option<Instant>,
}

struct XShared {
    obfs: Obfs,
    probe: UKey,
    sock: UdpSocket,
    tun: File,
    users: Mutex<HashMap<u32, XUser>>,
    fec: AtomicU64,
    stop: AtomicBool,
    fixed: AtomicU64,
    pkts: AtomicU64,
    repairs: AtomicU64,
    tun_dup: AtomicU64,
    dly: Mutex<mpsc::Sender<(Instant, Vec<u8>, SocketAddr)>>,
}

impl XShared {
    /// back into every tunnel of the session, and the second copy later
    fn send(&self, pkt: Vec<u8>, tos: &[SocketAddr]) {
        let d = self.tun_dup.load(Ordering::Relaxed);
        for to in tos {
            let _ = self.sock.send_to(&pkt, to);
            if d > 0 {
                let _ = self.dly.lock().unwrap_or_else(|e| e.into_inner()).send((Instant::now() + Duration::from_millis(d), pkt.clone(), *to));
            }
        }
    }
}

pub struct Exit {
    sh: Arc<XShared>,
    threads: Vec<JoinHandle<()>>,
    undo: Vec<Vec<String>>,
    pub cfg: ExitCfg,
}

impl Exit {
    pub fn start(obfs: &str, cfg: &ExitCfg) -> Result<Exit, String> {
        use crate::mtun::{ipt, nat_rules, open_tun, run, subnet_of};
        let o = Obfs::new(obfs).ok_or("bad obfs key")?;
        let sock = bind_udp(false, cfg.port)?;
        let tun = open_tun(IFACE)?;
        run(&["ip", "addr", "replace", SERVER_ADDR, "dev", IFACE])?;
        run(&["ip", "link", "set", "dev", IFACE, "mtu", &cfg.mtu.clamp(576, 1500).to_string(), "up"])?;
        std::fs::write("/proc/sys/net/ipv4/ip_forward", "1").map_err(|e| format!("ip_forward: {}", e))?;
        let mut undo: Vec<Vec<String>> = vec![];
        for r in nat_rules("iptables", &subnet_of(SERVER_ADDR).ok_or("bad address")?, IFACE) {
            if ipt("-C", &r).is_ok() {
                continue;
            }
            if let Err(e) = ipt("-I", &r) {
                for u in undo.iter().rev() {
                    let _ = ipt("-D", u);
                }
                return Err(e);
            }
            undo.push(r);
        }
        let (tx, rx) = mpsc::channel();
        let sh = Arc::new(XShared {
            obfs: o,
            probe: probe_key(obfs),
            sock,
            tun,
            users: Mutex::new(HashMap::new()),
            fec: AtomicU64::new(0),
            stop: AtomicBool::new(false),
            fixed: AtomicU64::new(0),
            pkts: AtomicU64::new(0),
            repairs: AtomicU64::new(0),
            tun_dup: AtomicU64::new(0),
            dly: Mutex::new(tx),
        });
        let mut x = Exit { sh: sh.clone(), threads: vec![], undo, cfg: cfg.clone() };
        x.set(cfg);
        let s = sh.clone();
        x.threads.push(spawn("kp-exit-in", move || exit_in(&s)));
        let s = sh.clone();
        x.threads.push(spawn("kp-exit-tun", move || exit_tun(&s)));
        let s = sh.clone();
        x.threads.push(spawn("kp-exit-fec", move || exit_flush(&s)));
        let s = sh;
        x.threads.push(spawn("kp-exit-dup", move || delayer(&s.stop, rx, |p, to| {
            let _ = s.sock.send_to(p, to);
        })));
        Ok(x)
    }

    pub fn needs_restart(&self, cfg: &ExitCfg) -> bool {
        self.cfg.port != cfg.port || self.cfg.mtu != cfg.mtu
    }

    pub fn set(&mut self, cfg: &ExitCfg) {
        self.sh.fec.store(cfg.fec.min(MAX_GROUP as u8) as u64, Ordering::Relaxed);
        self.sh.tun_dup.store(cfg.tun_dup_ms.min(50) as u64, Ordering::Relaxed);
        let mut users = self.sh.users.lock().unwrap_or_else(|e| e.into_inner());
        let mut next = HashMap::new();
        let mut taken = std::collections::HashSet::new();
        for u in &cfg.users {
            let (Some(key), Ok(ip)) = (UKey::new(&u.key), u.ip.parse::<Ipv4Addr>()) else { continue };
            if !taken.insert(ip) {
                continue;
            }
            let old = users.remove(&u.uid).filter(|o| o.ip == ip && self.cfg.users.iter().any(|x| x.uid == u.uid && x.key == u.key));
            let (cur, rx, tx, last) = old.map(|o| (o.cur, o.rx, o.tx, o.last)).unwrap_or((None, 0, 0, None));
            next.insert(u.uid, XUser { uid: u.uid, name: u.name.clone(), key, ip, cur, rx, tx, last });
        }
        *users = next;
        self.cfg = cfg.clone();
    }

    /// {port, users: {uid: [bytes]}, online: [uid], fixed, pkts, repairs}
    pub fn status(&self) -> Value {
        let users = self.sh.users.lock().unwrap_or_else(|e| e.into_inner());
        let mut by = serde_json::Map::new();
        let mut on = vec![];
        let mut names = serde_json::Map::new();
        for u in users.values() {
            by.insert(u.uid.to_string(), json!([u.rx + u.tx, u.rx, u.tx]));
            names.insert(u.uid.to_string(), json!(u.name));
            if u.last.is_some_and(|t| t.elapsed() < Duration::from_secs(60)) {
                on.push(u.uid);
            }
        }
        json!({ "port": self.cfg.port, "users": by, "names": names, "online": on, "fixed": self.sh.fixed.load(Ordering::Relaxed),
            "pkts": self.sh.pkts.load(Ordering::Relaxed), "repairs": self.sh.repairs.load(Ordering::Relaxed) })
    }
}

impl Drop for Exit {
    fn drop(&mut self) {
        self.sh.stop.store(true, Ordering::Relaxed);
        let _ = self.sh.dly.lock().map(|t| t.send((Instant::now(), vec![], "127.0.0.1:9".parse().expect("addr"))));
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
        for r in self.undo.iter().rev() {
            let _ = crate::mtun::ipt("-D", r);
        }
        let _ = crate::mtun::run(&["ip", "link", "del", IFACE]);
    }
}

fn v4_src(p: &[u8]) -> Option<Ipv4Addr> {
    (p.len() >= 20 && p[0] >> 4 == 4).then(|| Ipv4Addr::new(p[12], p[13], p[14], p[15]))
}

fn v4_dst(p: &[u8]) -> Option<Ipv4Addr> {
    (p.len() >= 20 && p[0] >> 4 == 4).then(|| Ipv4Addr::new(p[16], p[17], p[18], p[19]))
}

/// relay → exit: drop copies, rebuild with parity or repairs, into `kping0`; probes are answered
fn exit_in(sh: &XShared) {
    let mut buf = vec![0u8; MAX_PKT];
    let mut tun = &sh.tun;
    while !sh.stop.load(Ordering::Relaxed) {
        let Ok((n, from)) = sh.sock.recv_from(&mut buf) else { continue };
        let pkt = &buf[..n];
        let Some(h) = peek(&sh.obfs, pkt) else { continue };
        if h.kind == PROBE && h.uid == 0 {
            if open(&sh.probe, &h, pkt).is_some() {
                let back = Hdr { kind: PROBE | DOWN, ..h };
                let _ = sh.sock.send_to(&seal(&sh.obfs, &sh.probe, &back, &[0u8; 8]), from);
            }
            continue;
        }
        if h.kind & DOWN != 0 || !(h.kind == DATA || h.kind == PARITY || h.kind == REPAIR) {
            continue;
        }
        let mut users = sh.users.lock().unwrap_or_else(|e| e.into_inner());
        let Some(u) = users.get_mut(&h.uid) else { continue };
        let Some(payload) = open(&u.key, &h, pkt) else { continue };
        // the newest session of the user takes over (the relay only lets fresh ones in)
        if u.cur.as_ref().map(|s| s.sess) != Some(h.sess) {
            let k = sh.fec.load(Ordering::Relaxed) as usize;
            u.cur = Some(XSess::new(h.sess, from, k));
        }
        let ip = u.ip;
        let Some(s) = u.cur.as_mut() else { continue };
        s.note_from(from);
        let now = Instant::now();
        let mut out: Vec<Vec<u8>> = vec![];
        match h.kind {
            DATA => {
                // what the phone wants back: 0 = this server's parity, 1 = none, 2-8 a parity group (v2),
                // 9-15 v3 repairs at that rate
                match h.aux >> 4 {
                    w @ 9..=15 => {
                        s.rlc = true;
                        s.ratio = DOWN_RATIOS[(w - 9) as usize];
                        if s.tx_fec.k != 0 {
                            s.tx_fec = FecTx::new(0);
                        }
                    }
                    w => {
                        s.rlc = false;
                        let want = match w {
                            0 => sh.fec.load(Ordering::Relaxed) as usize,
                            1 => 0,
                            k => k as usize,
                        };
                        if s.tx_fec.k != want.min(MAX_GROUP) {
                            s.tx_fec = FecTx::new(want);
                        }
                    }
                }
                if !s.win[0].take(h.seq) {
                    continue;
                }
                out.push(payload.to_vec());
                let mut more = s.rx_rlc.data(h.seq, payload, now);
                if let Some((seq, p)) = s.rx_fec.data(h.seq, payload, &s.win[0]) {
                    if s.win[0].take(seq) {
                        sh.fixed.fetch_add(1, Ordering::Relaxed);
                        more.extend(s.rx_rlc.data(seq, &p, now));
                        out.push(p);
                    }
                }
                for (seq, p) in more {
                    if s.win[0].take(seq) {
                        sh.fixed.fetch_add(1, Ordering::Relaxed);
                        out.push(p);
                    }
                }
            }
            PARITY => {
                if !s.win[1].take(h.seq) {
                    continue;
                }
                if let Some((seq, p)) = s.rx_fec.parity(h.aux, payload, &s.win[0]) {
                    if s.win[0].take(seq) {
                        sh.fixed.fetch_add(1, Ordering::Relaxed);
                        for (q, x) in s.rx_rlc.data(seq, &p, now) {
                            if s.win[0].take(q) {
                                out.push(x);
                            }
                        }
                        out.push(p);
                    }
                }
            }
            _ => {
                if !s.win[2].take(h.seq) {
                    continue;
                }
                for (seq, p) in s.rx_rlc.repair(payload, now) {
                    if s.win[0].take(seq) {
                        sh.fixed.fetch_add(1, Ordering::Relaxed);
                        out.push(p);
                    }
                }
            }
        }
        for p in out {
            // only the user's own address goes out
            if v4_src(&p) != Some(ip) {
                continue;
            }
            u.rx += p.len() as u64;
            u.last = Some(Instant::now());
            sh.pkts.fetch_add(1, Ordering::Relaxed);
            let _ = tun.write(&p);
        }
    }
}

/// `kping0` → the user's session, with parity (v2) or repairs (v3)
fn exit_tun(sh: &XShared) {
    let mut buf = vec![0u8; 65536];
    let mut tun = &sh.tun;
    let fd = std::os::fd::AsRawFd::as_raw_fd(&sh.tun);
    while !sh.stop.load(Ordering::Relaxed) {
        // wait at most 300 ms, so a stop is seen
        let mut pfd = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
        // SAFETY: one valid pollfd for the duration of the call
        if unsafe { libc::poll(&mut pfd, 1, 300) } <= 0 {
            continue;
        }
        let Ok(n) = tun.read(&mut buf) else { continue };
        let p = &buf[..n];
        let Some(dst) = v4_dst(p) else { continue };
        let mut users = sh.users.lock().unwrap_or_else(|e| e.into_inner());
        let Some(u) = users.values_mut().find(|u| u.ip == dst) else { continue };
        let Some(s) = u.cur.as_mut() else { continue };
        let seq = s.down_seq;
        s.down_seq = s.down_seq.wrapping_add(1);
        let tos = s.tos();
        let pkt = seal(&sh.obfs, &u.key, &Hdr { uid: u.uid, sess: s.sess, seq, kind: DATA | DOWN, aux: 0 }, p);
        sh.send(pkt, &tos);
        u.tx += p.len() as u64;
        if s.rlc {
            if let Some((ttl, w)) = down_class(p) {
                let now = Instant::now();
                s.tx_rlc.add(seq, p, now + ttl);
                s.credit = (s.credit + s.ratio * w).min(6.0);
                s.pending += 1;
                if let Some(last) = s.last_data {
                    s.gap_ms += (now.duration_since(last).as_secs_f64() * 1000.0 - s.gap_ms) / 8.0;
                }
                s.last_data = Some(now);
            }
        } else if let Some((n, par)) = s.tx_fec.add(seq, p) {
            let pseq = s.down_pseq;
            s.down_pseq = s.down_pseq.wrapping_add(1);
            let pk = seal(&sh.obfs, &u.key, &Hdr { uid: u.uid, sess: s.sess, seq: pseq, kind: PARITY | DOWN, aux: n }, &par);
            sh.send(pk, &tos);
        }
    }
}

/// parity of groups that waited too long (v2), and the paced repairs (v3)
fn exit_flush(sh: &XShared) {
    while !sh.stop.load(Ordering::Relaxed) {
        std::thread::sleep(Duration::from_millis(2));
        let now = Instant::now();
        let mut users = sh.users.lock().unwrap_or_else(|e| e.into_inner());
        for u in users.values_mut() {
            let (uid, key) = (u.uid, u.key.clone());
            let Some(s) = u.cur.as_mut() else { continue };
            if let Some((n, par)) = s.tx_fec.flush() {
                let pseq = s.down_pseq;
                s.down_pseq = s.down_pseq.wrapping_add(1);
                let pk = seal(&sh.obfs, &key, &Hdr { uid, sess: s.sess, seq: pseq, kind: PARITY | DOWN, aux: n }, &par);
                sh.send(pk, &s.tos());
            }
            if s.repair_due(now) {
                match s.tx_rlc.repair(now, kprlc::MAX_WIN) {
                    Some(rep) => {
                        let rseq = s.rseq;
                        s.rseq = s.rseq.wrapping_add(1);
                        s.credit -= 1.0;
                        s.pending = 0;
                        sh.repairs.fetch_add(1, Ordering::Relaxed);
                        let pk = seal(&sh.obfs, &key, &Hdr { uid, sess: s.sess, seq: rseq, kind: REPAIR | DOWN, aux: 0 }, &rep);
                        sh.send(pk, &s.tos());
                    }
                    // every packet it would cover is dead: nothing owed
                    None => s.credit = 0.0,
                }
            }
        }
    }
}

// ------------------------------------------------------------------ what runs on this server

#[derive(Default)]
struct Running {
    obfs: String,
    relays: Vec<(Relay, String)>,
    exit: Option<Exit>,
    exit_err: String,
    errs: Vec<(u16, String)>,
}

fn running() -> &'static Mutex<Running> {
    static R: OnceLock<Mutex<Running>> = OnceLock::new();
    R.get_or_init(Default::default)
}

/// one id per start of this program: the panel counts traffic from zero when it changes
fn run_id() -> &'static str {
    static R: OnceLock<String> = OnceLock::new();
    R.get_or_init(|| crate::util::rand_token(10))
}

const CACHE: &str = "/var/lib/kanki/kping.json";

/// The last config, so KPING comes back after a reboot even when the panel cannot be reached
pub fn from_disk() {
    if let Some(c) = std::fs::read_to_string(CACHE).ok().and_then(|t| serde_json::from_str::<KpCfg>(&t).ok()) {
        apply(c);
    }
}

/// Brings KPING on this server to `cfg` (blocking). Opens the relays' ports in the firewall.
pub fn apply(cfg: KpCfg) {
    let mut r = running().lock().unwrap_or_else(|e| e.into_inner());
    if r.obfs != cfg.obfs {
        r.relays.clear();
        r.exit = None;
        r.obfs = cfg.obfs.clone();
    }
    // relays: the same ports keep running with the new users
    let mut keep = vec![];
    let mut errs = vec![];
    let old = std::mem::take(&mut r.relays);
    let mut old: Vec<Option<(Relay, String)>> = old.into_iter().map(Some).collect();
    for c in &cfg.relays {
        if let Some(slot) = old.iter_mut().find(|x| x.as_ref().is_some_and(|(x, _)| !x.needs_restart(c))) {
            let (mut x, e) = slot.take().expect("found");
            x.set(c);
            keep.push((x, e));
            continue;
        }
        // a port that changed is free first
        old.retain(|x| x.as_ref().is_none_or(|(x, _)| x.cfg.port != c.port));
        match Relay::start(&cfg.obfs, c) {
            Ok(x) => keep.push((x, String::new())),
            Err(e) => errs.push((c.port, e)),
        }
    }
    drop(old);
    r.relays = keep;
    r.errs = errs;
    match &cfg.exit {
        None => {
            r.exit = None;
            r.exit_err.clear();
        }
        Some(c) => {
            if r.exit.as_ref().is_some_and(|x| x.needs_restart(c)) {
                r.exit = None;
            }
            match r.exit.as_mut() {
                Some(x) => x.set(c),
                None => match Exit::start(&cfg.obfs, c) {
                    Ok(x) => {
                        r.exit = Some(x);
                        r.exit_err.clear();
                    }
                    Err(e) => r.exit_err = e,
                },
            }
        }
    }
    let ports: Vec<String> = cfg.relays.iter().map(|c| format!("{}/udp", c.port)).collect();
    drop(r);
    crate::fw::sync("kping", ports);
    let text = serde_json::to_string(&cfg).unwrap_or_default();
    if std::fs::read_to_string(CACHE).ok().as_deref() != Some(text.as_str()) {
        let _ = std::fs::create_dir_all("/var/lib/kanki");
        let _ = std::fs::write(CACHE, text);
    }
}

/// What runs here, for the panel (Null = nothing)
pub fn report() -> Value {
    let r = running().lock().unwrap_or_else(|e| e.into_inner());
    if r.relays.is_empty() && r.exit.is_none() && r.errs.is_empty() && r.exit_err.is_empty() {
        return Value::Null;
    }
    let mut relays: Vec<Value> = r.relays.iter().map(|(x, _)| x.status()).collect();
    relays.extend(r.errs.iter().map(|(p, e)| json!({ "port": p, "error": e })));
    let mut exit = r.exit.as_ref().map(|x| x.status()).unwrap_or(Value::Null);
    if !r.exit_err.is_empty() {
        exit = json!({ "error": r.exit_err });
    }
    if exit.is_object() {
        exit["run"] = json!(run_id());
    }
    json!({ "relays": relays, "exit": exit })
}


#[cfg(test)]
mod tests {
    use super::*;

    fn keys() -> (Obfs, UKey) {
        (Obfs::new(&"ab".repeat(32)).unwrap(), UKey::new(&"cd".repeat(32)).unwrap())
    }

    /// A fixed packet, so the phone's code (Go) can check it makes the very same bytes
    #[test]
    fn wire_vector() {
        let (o, k) = keys();
        let h = Hdr { uid: 7, sess: 0x1234, seq: 42, kind: DATA, aux: 1 };
        let pkt = seal(&o, &k, &h, b"hello");
        assert_eq!(pkt.len(), 5 + OVERHEAD);
        assert_eq!(hex::encode(&pkt), "43aaf90a2dbcbefbbc162ade68656c6c6f93669fa32522c2df");
        let got = peek(&o, &pkt).unwrap();
        assert_eq!(got, h);
        assert_eq!(open(&k, &got, &pkt), Some(&b"hello"[..]));
        // one bit changed anywhere: refused
        for i in 0..pkt.len() {
            let mut bad = pkt.clone();
            bad[i] ^= 1;
            let ok = peek(&o, &bad).map(|h| open(&k, &h, &bad).is_some()).unwrap_or(false);
            assert!(!ok, "byte {}", i);
        }
        // another user's key: refused
        let other = UKey::new(&"ef".repeat(32)).unwrap();
        assert!(open(&other, &got, &pkt).is_none());
        // no fixed bytes: two packets that differ only in seq share no header byte position pattern
        let p2 = seal(&o, &k, &Hdr { seq: 43, ..h }, b"hello");
        assert_ne!(pkt[..HDR], p2[..HDR]);
    }

    #[test]
    fn copies_pass_once() {
        let mut w = Window::default();
        assert!(w.take(5) && !w.take(5));
        assert!(w.take(3) && !w.take(3));
        assert!(w.take(2000) && !w.take(5) && !w.take(2000));
        assert!(w.take(1999) && w.has(1999) && !w.has(1998));
        assert!(w.take(1998));
        // far behind the newest: refused
        assert!(!w.take(900));
    }

    #[test]
    fn parity_rebuilds_one_lost_packet() {
        let pkts: Vec<Vec<u8>> = (0..4u8).map(|i| vec![i + 1; 20 + i as usize * 7]).collect();
        let mut tx = FecTx::new(4);
        let mut par = None;
        for (i, p) in pkts.iter().enumerate() {
            par = tx.add(100 + i as u32, p);
        }
        let (n, par) = par.expect("full group");
        assert_eq!(n, 4);
        // packet 102 is lost; the parity comes before the last one
        let mut win = Window::default();
        let mut rx = FecRx::default();
        for s in [100u32, 101] {
            assert!(win.take(s));
            assert!(rx.data(s, &pkts[(s - 100) as usize], &win).is_none());
        }
        assert!(rx.parity(n, &par, &win).is_none());
        assert!(win.take(103));
        let (seq, p) = rx.data(103, &pkts[3], &win).expect("rebuilt");
        assert_eq!((seq, &p), (102, &pkts[2]));
        // nothing lost: nothing rebuilt
        let mut win = Window::default();
        let mut rx = FecRx::default();
        for (i, p) in pkts.iter().enumerate() {
            win.take(100 + i as u32);
            rx.data(100 + i as u32, p, &win);
        }
        assert!(rx.parity(n, &par, &win).is_none());
    }

    #[test]
    fn a_waiting_group_goes_out_after_a_while() {
        let mut tx = FecTx::new(4);
        assert!(tx.add(1, b"aaa").is_none() && tx.add(2, b"bbbbb").is_none());
        assert!(tx.flush().is_none());
        std::thread::sleep(GROUP_IDLE + Duration::from_millis(5));
        let (n, p) = tx.flush().expect("flushed");
        assert_eq!(n, 2);
        assert_eq!(&p[..4], &1u32.to_be_bytes());
        // the next group starts fresh
        assert!(tx.add(3, b"c").is_none());
    }

    /// a tunnel's next packet that is not one of the relay's probes
    fn recv_np(t: &UdpSocket, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        let o = Obfs::new(&"ab".repeat(32)).unwrap();
        let until = Instant::now() + Duration::from_millis(500);
        loop {
            if Instant::now() > until {
                return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "nothing but probes"));
            }
            let (n, a) = t.recv_from(buf)?;
            if peek(&o, &buf[..n]).is_some_and(|h| h.kind == PROBE && h.uid == 0) {
                continue;
            }
            return Ok((n, a));
        }
    }

    /// v3: every packet goes into both tunnels; the probes find the tunnel that answers, the PONG says
    /// v3 and that tunnel's round trip; what comes back through either tunnel reaches the phone once
    #[test]
    fn two_tunnels_and_probes() {
        let (o, k) = keys();
        let t1 = UdpSocket::bind("127.0.0.1:0").unwrap();
        let t2 = UdpSocket::bind("127.0.0.1:0").unwrap();
        for t in [&t1, &t2] {
            t.set_read_timeout(Some(Duration::from_millis(600))).unwrap();
        }
        let port = 20000 + (rand::random::<u16>() % 20000);
        let cfg = RelayCfg {
            port, to: t1.local_addr().unwrap().port(), more: vec![t2.local_addr().unwrap().port()], dup_ms: 0, tun_dup_ms: 0,
            users: vec![KUser { uid: 7, name: "gamer".into(), key: "cd".repeat(32), ip: String::new() }],
        };
        let relay = Relay::start(&"ab".repeat(32), &cfg).unwrap();
        let probe = probe_key(&"ab".repeat(32));
        // tunnel 2 answers the probes (an exit behind it), tunnel 1 stays silent
        let mut buf = [0u8; 2048];
        let mut answered = 0;
        let mut back2 = None;
        let until = Instant::now() + Duration::from_secs(2);
        while Instant::now() < until && answered < 3 {
            if let Ok((n, from)) = t2.recv_from(&mut buf) {
                let h = peek(&o, &buf[..n]).unwrap();
                if h.kind == PROBE && h.uid == 0 && open(&probe, &h, &buf[..n]).is_some() {
                    let a = seal(&o, &probe, &Hdr { kind: PROBE | DOWN, ..h }, &[0u8; 8]);
                    t2.send_to(&a, from).unwrap();
                    back2 = Some(from);
                    answered += 1;
                }
            }
        }
        assert!(answered >= 3, "no probes into tunnel 2");
        let phone = UdpSocket::bind("127.0.0.1:0").unwrap();
        phone.set_read_timeout(Some(Duration::from_millis(600))).unwrap();
        let dst = format!("127.0.0.1:{}", port);
        let ping = seal(&o, &k, &Hdr { uid: 7, sess: 3, seq: 0, kind: PING, aux: 1 }, &[&now_ms().to_be_bytes()[..], &[0xff, 0, CAP_RLC]].concat());
        phone.send_to(&ping, &dst).unwrap();
        let (n, _) = phone.recv_from(&mut buf).unwrap();
        let h = peek(&o, &buf[..n]).unwrap();
        let body = open(&k, &h, &buf[..n]).unwrap().to_vec();
        let rest = &body[9 + body[8] as usize * 9..];
        assert_eq!(rest[0] & CAP_RLC, CAP_RLC, "the PONG says v3");
        // only tunnel 2 answers: the data goes there (tunnel 1 counts as dead once it misses its probes)
        let d = seal(&o, &k, &Hdr { uid: 7, sess: 3, seq: 1, kind: REPAIR, aux: 1 }, b"repair");
        phone.send_to(&d, &dst).unwrap();
        let (n, _) = recv_np(&t2, &mut buf).expect("a v3 repair into the tunnel");
        assert_eq!(&buf[..n], &d[..]);
        // the same downlink packet back through both tunnels: the phone gets it once
        let down = seal(&o, &k, &Hdr { uid: 7, sess: 3, seq: 0, kind: DATA | DOWN, aux: 0 }, b"reply");
        t2.send_to(&down, back2.unwrap()).unwrap();
        let (n, _) = phone.recv_from(&mut buf).expect("the reply");
        assert_eq!(&buf[..n], &down[..]);
        let st = relay.status();
        assert_eq!(st["tunnels"].as_array().unwrap().len(), 2);
        assert_eq!(st["tunnels"][1]["up"], true);
        drop(relay);
    }

    /// The relay on this machine (no root needed): a fresh PING starts a session and is answered, an old
    /// one is not; copies go into the tunnel once; what comes back goes to both paths
    #[test]
    fn relay_takes_one_copy_and_answers_both_paths() {
        let (o, k) = keys();
        let tunnel = UdpSocket::bind("127.0.0.1:0").unwrap();
        tunnel.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
        let to = tunnel.local_addr().unwrap().port();
        let port = 20000 + (rand::random::<u16>() % 20000);
        let cfg = RelayCfg { port, to, more: vec![], dup_ms: 2, tun_dup_ms: 0, users: vec![KUser { uid: 7, name: "gamer".into(), key: "cd".repeat(32), ip: String::new() }] };
        let relay = Relay::start(&"ab".repeat(32), &cfg).unwrap();
        let wifi = UdpSocket::bind("127.0.0.1:0").unwrap();
        let cell = UdpSocket::bind("127.0.0.1:0").unwrap();
        for s in [&wifi, &cell] {
            s.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
        }
        let dst = format!("127.0.0.1:{}", port);
        let mut buf = [0u8; 2048];
        // an old PING: no answer, no session
        let old = seal(&o, &k, &Hdr { uid: 7, sess: 9, seq: 0, kind: PING, aux: 1 }, &(now_ms() - 600_000).to_be_bytes());
        wifi.send_to(&old, &dst).unwrap();
        assert!(wifi.recv_from(&mut buf).is_err());
        // data before a session: dropped
        let d0 = seal(&o, &k, &Hdr { uid: 7, sess: 9, seq: 0, kind: DATA, aux: 1 }, b"early");
        wifi.send_to(&d0, &dst).unwrap();
        assert!(recv_np(&tunnel, &mut buf).is_err());
        // a fresh PING on each path
        for (i, s) in [&wifi, &cell].iter().enumerate() {
            let ping = seal(&o, &k, &Hdr { uid: 7, sess: 9, seq: i as u32, kind: PING, aux: i as u8 + 1 }, &now_ms().to_be_bytes());
            s.send_to(&ping, &dst).unwrap();
            let (n, _) = s.recv_from(&mut buf).expect("pong");
            let h = peek(&o, &buf[..n]).unwrap();
            assert_eq!((h.kind, h.seq), (PONG | DOWN, i as u32));
        }
        // the same packet on both paths: one copy into the tunnel
        let d = seal(&o, &k, &Hdr { uid: 7, sess: 9, seq: 1, kind: DATA, aux: 1 }, b"game");
        wifi.send_to(&d, &dst).unwrap();
        cell.send_to(&d, &dst).unwrap();
        let (n, back) = recv_np(&tunnel, &mut buf).expect("into the tunnel");
        assert_eq!(&buf[..n], &d[..]);
        assert!(recv_np(&tunnel, &mut buf).is_err(), "a copy went into the tunnel twice");
        // the next PING's answer says what each path brought: one copy came first, on one path
        let ping = seal(&o, &k, &Hdr { uid: 7, sess: 9, seq: 5, kind: PING, aux: 1 }, &[&now_ms().to_be_bytes()[..], &[0xff, 0]].concat());
        wifi.send_to(&ping, &dst).unwrap();
        let (n, _) = wifi.recv_from(&mut buf).expect("pong");
        let (_, body) = { let h = peek(&o, &buf[..n]).unwrap(); (h, open(&k, &h, &buf[..n]).unwrap().to_vec()) };
        assert_eq!(body[8], 2);
        let per = |i: usize| (body[9 + i * 9], u32::from_be_bytes(body[10 + i * 9..14 + i * 9].try_into().unwrap()), u32::from_be_bytes(body[14 + i * 9..18 + i * 9].try_into().unwrap()));
        assert_eq!(per(0).1 + per(1).1, 1, "one copy came first");
        assert_eq!((per(0).2, per(1).2), (1, 1));
        // a forged packet (wrong key): not into the tunnel
        let bad = seal(&o, &UKey::new(&"ef".repeat(32)).unwrap(), &Hdr { uid: 7, sess: 9, seq: 2, kind: DATA, aux: 1 }, b"x");
        wifi.send_to(&bad, &dst).unwrap();
        assert!(recv_np(&tunnel, &mut buf).is_err());
        // the answer goes to both paths
        let down = seal(&o, &k, &Hdr { uid: 7, sess: 9, seq: 0, kind: DATA | DOWN, aux: 0 }, b"reply");
        tunnel.send_to(&down, back).unwrap();
        for s in [&wifi, &cell] {
            let (n, _) = s.recv_from(&mut buf).expect("reply on each path");
            assert_eq!(&buf[..n], &down[..]);
        }
        let st = relay.status();
        assert_eq!((st["online"].as_u64(), st["paths"].as_u64(), st["dups"].as_u64()), (Some(1), Some(2), Some(1)));
        drop(relay);
    }
}

/// The servers of the lab (`scripts/kping_lab.sh` sets up the phone's paths and the game, and runs the
/// clients): KPING's relay and exit with a real reverse Game-FEC tunnel between them, and microtun behind
/// a tunnel of its own the same way, both on this machine. Needs root.
#[cfg(test)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn kping_lab() {
    use crate::mtun::{MtCfg, MtUser};
    use crate::tunnel::engine::{Running, Spec};
    let obfs = "ab".repeat(32);
    let key = "cd".repeat(32);
    let dir = std::env::var("LAB_DIR").unwrap_or("/tmp".into());
    let user = KUser { uid: 1, name: "gamer".into(), key: key.clone(), ip: "10.81.0.2".into() };
    let tdup: u16 = std::env::var("KP_TUN_DUP_MS").ok().and_then(|s| s.parse().ok()).unwrap_or(20);
    let dup: u16 = std::env::var("KP_DUP_MS").ok().and_then(|s| s.parse().ok()).unwrap_or(2);
    let relay = Relay::start(&obfs, &RelayCfg { port: 24300, to: 24302, more: vec![], dup_ms: dup, tun_dup_ms: tdup, users: vec![user.clone()] }).expect("relay");
    let fec: u8 = std::env::var("LAB_FEC").ok().and_then(|s| s.parse().ok()).unwrap_or(2);
    let exit = Exit::start(&obfs, &ExitCfg { port: 4300, mtu: 1332, fec, tun_dup_ms: tdup, users: vec![user] }).expect("exit");
    let mt = MtCfg {
        port: 4200, obfs: obfs.clone(), address: "10.79.0.1/16".into(), mtu: 1324, burst_max: 1000, burst_delay_ms: 2,
        users: vec![MtUser { name: "gamer".into(), key: key.clone(), ip: "10.79.0.2".into(), max: 2 }], local_only: true, ..Default::default()
    };
    let (_, _, e) = crate::microtun::apply(mt.clone());
    assert!(e.is_empty(), "microtun: {}", e);
    let tun = |id: &str, port: u16, udp: &str, bind: &str| Spec {
        id: id.into(), name: id.into(), mode: "reverse".into(), transport: "game".into(), port, token: "token-for-tests-0123456789".into(), conns: 1,
        udp: vec![udp.into()], target: "127.0.0.1".into(), fec: "8:3".into(), remote: std::env::var(format!("LAB_TUN_{}", id)).unwrap_or(format!("127.0.0.1:{}", port)), bind: bind.into(), ..Default::default()
    };
    let mut run = vec![];
    for s in [tun("kp", 24301, "24302:4300", "127.0.0.1"), tun("mt", 24401, "24400:4200", "")] {
        run.push(Running::start(Spec { role: "entry".into(), ..s.clone() }));
        run.push(Running::start(Spec { role: "exit".into(), ..s }));
    }
    for _ in 0..100 {
        if run.iter().all(|r| r.status().links > 0) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(run.iter().all(|r| r.status().links > 0), "a tunnel did not connect");
    let kl = crate::kping::to_url(&key, "10.200.1.1:24300", 1, &obfs, Ipv4Addr::new(10, 81, 0, 2), 1332, fec, "lab");
    let ms = crate::microtun::Settings { mtu: 1324, burst_max: 1000, burst_delay_ms: 2, ..Default::default() };
    let ml = crate::microtun::to_url(&key, &std::env::var("MT_DIAL").unwrap_or("127.0.0.1:25400".into()), &obfs, Ipv4Addr::new(10, 79, 0, 2), &ms, "lab");
    std::fs::write(format!("{}/kping.link", dir), kl).unwrap();
    std::fs::write(format!("{}/mtun.link", dir), ml).unwrap();
    println!("READY");
    let secs: u64 = std::env::var("LAB_SECS").ok().and_then(|s| s.parse().ok()).unwrap_or(300);
    tokio::time::sleep(Duration::from_secs(secs)).await;
    println!("relay {}", relay.status());
    println!("exit {}", exit.status());
    crate::microtun::apply(MtCfg::default());
    for r in run {
        r.stop();
    }
}
