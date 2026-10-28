//! microtun on a VPN server: a light game VPN over a TUN interface (28 bytes per packet, WireGuard
//! 32). The same wire format as the standalone Go microtun v2 (its server and Linux client live in
//! `microtun/`), so the Go client and the Kanki app speak to this server.
//!
//! Wire: [idx 4 | counter 8] masked with AES(obfs, first 16 bytes of the ciphertext), then
//! AES-256-GCM with the unmasked header as nonce and AD. idx 0 is a handshake: X25519 ephemerals
//! sealed with keys from the user's own key, session keys = HKDF(shared, salt = user key). Small
//! IP packets are sent twice (`burst_max`, `burst_delay_ms`); the replay window drops the copy.
//!
//! Plain threads, no async: a game packet goes TUN → seal → socket without waking a runtime.
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes256;
use aes_gcm::aead::{Aead, AeadInPlace, Payload};
use aes_gcm::{Aes256Gcm, Nonce, Tag};
use hkdf::Hkdf;
use rand::{Rng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::os::fd::AsRawFd;
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, RwLock, Weak};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use x25519_dalek::{EphemeralSecret, PublicKey};

const HDR: usize = 12;
const TAG: usize = 16;
pub const OVERHEAD: usize = HDR + TAG;
const INIT_BODY: usize = 32 + 8 + 4;
const RESP_BODY: usize = 32 + 4 + 4;
const MAX_PAD: usize = 64;
const MAX_IP: usize = 65535;
const MAX_COUNTER: u64 = 1 << 60;
const REJECT_AFTER: Duration = Duration::from_secs(180);
const PENDING_FOR: Duration = Duration::from_secs(6);
const WINDOW: u64 = 1024;
pub const IFACE: &str = "mtun0";

/// What one server runs (sent by the panel on every sync)
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(default)]
pub struct MtCfg {
    /// UDP port; 0 = off on this server
    pub port: u16,
    /// header mask key, 64 hex (shared by the server and its users)
    pub obfs: String,
    /// the server's tunnel address with prefix ("10.77.0.1/16")
    pub address: String,
    pub mtu: u16,
    pub burst_max: u16,
    pub burst_delay_ms: u16,
    pub users: Vec<MtUser>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct MtUser {
    pub name: String,
    /// the user's own key, 64 hex
    pub key: String,
    /// the user's tunnel IPv4: packets from this user must carry it as source
    pub ip: String,
}

impl MtCfg {
    pub fn on(&self) -> bool {
        self.port > 0
    }
    /// settings that need a new socket / interface (users and burst change live)
    fn base_differs(&self, o: &MtCfg) -> bool {
        self.port != o.port || self.obfs != o.obfs || self.address != o.address || self.mtu != o.mtu
    }
}

fn key32(hex_key: &str) -> Option<[u8; 32]> {
    hex::decode(hex_key.trim()).ok()?.try_into().ok()
}

// ------------------------------------------------------------------ crypto

fn mask(obfs: &Aes256, pkt: &mut [u8]) {
    let mut b = aes::Block::clone_from_slice(&pkt[HDR..HDR + 16]);
    obfs.encrypt_block(&mut b);
    for i in 0..HDR {
        pkt[i] ^= b[i];
    }
}

fn hkdf32(salt: Option<&[u8]>, ikm: &[u8], info: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    Hkdf::<Sha256>::new(salt, ikm).expand(info, &mut out).expect("32 bytes");
    out
}

struct PskKeys {
    psk: [u8; 32],
    init: Aes256Gcm,
    resp: Aes256Gcm,
}

impl PskKeys {
    fn new(psk: [u8; 32]) -> Self {
        let init = Aes256Gcm::new(&hkdf32(None, &psk, b"microtun v2 init").into());
        let resp = Aes256Gcm::new(&hkdf32(None, &psk, b"microtun v2 resp").into());
        PskKeys { psk, init, resp }
    }
}

fn derive(shared: &[u8], psk: &[u8], eph_c: &[u8], eph_s: &[u8], idx_c: u32, idx_s: u32) -> ([u8; 32], [u8; 32]) {
    let mut h = Sha256::new();
    h.update(eph_c);
    h.update(eph_s);
    h.update(idx_c.to_be_bytes());
    h.update(idx_s.to_be_bytes());
    let th = h.finalize();
    let info = |dir: &str| [format!("microtun v2 {}", dir).as_bytes(), th.as_slice()].concat();
    (hkdf32(Some(psk), shared, &info("c2s")), hkdf32(Some(psk), shared, &info("s2c")))
}

fn rand_idx() -> u32 {
    loop {
        let v = rand::thread_rng().next_u32();
        if v != 0 {
            return v;
        }
    }
}

struct Init {
    eph: [u8; 32],
    ts: u64,
    idx: u32,
}

/// pkt is unmasked
fn parse_init(k: &PskKeys, pkt: &[u8]) -> Option<Init> {
    let hdr = &pkt[..HDR];
    let pt = k.init.decrypt(Nonce::from_slice(hdr), Payload { msg: &pkt[HDR..], aad: hdr }).ok()?;
    if pt.len() < INIT_BODY {
        return None;
    }
    Some(Init {
        eph: pt[..32].try_into().ok()?,
        ts: u64::from_be_bytes(pt[32..40].try_into().ok()?),
        idx: u32::from_be_bytes(pt[40..44].try_into().ok()?),
    })
}

/// a masked response, never larger than the init it answers (no amplification)
fn build_resp(obfs: &Aes256, k: &PskKeys, eph_s: &[u8; 32], idx_s: u32, idx_c: u32, eph_c: &[u8], init_len: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let room = init_len.saturating_sub(HDR + RESP_BODY + TAG).min(MAX_PAD);
    let pad = rng.gen_range(0..=room);
    let mut pt = Vec::with_capacity(RESP_BODY + pad);
    pt.extend_from_slice(eph_s);
    pt.extend_from_slice(&idx_s.to_be_bytes());
    pt.extend_from_slice(&idx_c.to_be_bytes());
    pt.resize(RESP_BODY + pad, 0);
    rng.fill_bytes(&mut pt[RESP_BODY..]);
    let mut hdr = [0u8; HDR];
    rng.fill_bytes(&mut hdr[4..]);
    let aad = [&hdr[..], eph_c].concat();
    let ct = k.resp.encrypt(Nonce::from_slice(&hdr), Payload { msg: &pt, aad: &aad }).expect("seal");
    let mut pkt = [&hdr[..], &ct].concat();
    mask(obfs, &mut pkt);
    pkt
}

struct Replay {
    seen: bool,
    max: u64,
    bits: [u64; (WINDOW / 64) as usize],
}

impl Replay {
    fn new() -> Self {
        Replay { seen: false, max: 0, bits: [0; (WINDOW / 64) as usize] }
    }
    fn bit(c: u64) -> (usize, u64) {
        (((c / 64) % (WINDOW / 64)) as usize, 1 << (c % 64))
    }
    fn accept(&mut self, c: u64) -> bool {
        let (w, b) = Self::bit(c);
        if !self.seen {
            self.seen = true;
            self.max = c;
            self.bits[w] |= b;
            return true;
        }
        if c > self.max {
            if c - self.max >= WINDOW {
                self.bits = [0; (WINDOW / 64) as usize];
            } else {
                for x in self.max + 1..c {
                    let (xw, xb) = Self::bit(x);
                    self.bits[xw] &= !xb;
                }
            }
            self.max = c;
            self.bits[w] |= b;
            return true;
        }
        if self.max - c >= WINDOW || self.bits[w] & b != 0 {
            return false;
        }
        self.bits[w] |= b;
        true
    }
}

struct Session {
    local: u32,
    remote: u32,
    send: Aes256Gcm,
    recv: Aes256Gcm,
    ctr: AtomicU64,
    rw: Mutex<Replay>,
    born: Instant,
    peer: Weak<Peer>,
}

impl Session {
    fn expired(&self) -> bool {
        self.born.elapsed() >= REJECT_AFTER
    }
    /// seals buf[HDR..HDR+n] in place (buf has TAG spare bytes) and masks: the datagram
    fn seal<'a>(&self, obfs: &Aes256, buf: &'a mut [u8], n: usize) -> Option<&'a [u8]> {
        let c = self.ctr.fetch_add(1, Ordering::Relaxed);
        if c >= MAX_COUNTER || self.expired() {
            return None;
        }
        buf[..4].copy_from_slice(&self.remote.to_be_bytes());
        buf[4..HDR].copy_from_slice(&c.to_be_bytes());
        let (hdr, rest) = buf.split_at_mut(HDR);
        let tag = self.send.encrypt_in_place_detached(Nonce::from_slice(hdr), hdr, &mut rest[..n]).ok()?;
        rest[n..n + TAG].copy_from_slice(&tag);
        let pkt = &mut buf[..HDR + n + TAG];
        mask(obfs, pkt);
        Some(pkt)
    }
    /// opens an unmasked data packet in place: the plaintext length
    fn open(&self, pkt: &mut [u8]) -> Option<usize> {
        if self.expired() {
            return None;
        }
        let n = pkt.len() - OVERHEAD;
        let c = u64::from_be_bytes(pkt[4..HDR].try_into().ok()?);
        let (hdr, rest) = pkt.split_at_mut(HDR);
        let (body, tag) = rest.split_at_mut(n);
        self.recv.decrypt_in_place_detached(Nonce::from_slice(hdr), hdr, body, Tag::from_slice(tag)).ok()?;
        self.rw.lock().unwrap().accept(c).then_some(n)
    }
}

#[derive(Default)]
struct PeerState {
    last_ts: u64,
    prev: Option<Arc<Session>>,
    pending: Option<Arc<Session>>,
}

struct Peer {
    name: String,
    key_hex: String,
    ip: Ipv4Addr,
    keys: PskKeys,
    endpoint: Mutex<Option<SocketAddr>>,
    current: RwLock<Option<Arc<Session>>>,
    st: Mutex<PeerState>,
    rx: AtomicU64,
    tx: AtomicU64,
    /// unix seconds of the last authenticated packet
    last_rx: AtomicI64,
}

fn now_secs() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

// ------------------------------------------------------------------ the server

#[derive(Default)]
struct Peers {
    list: Vec<Arc<Peer>>,
    by_ip: HashMap<Ipv4Addr, Arc<Peer>>,
}

struct Shared {
    obfs: Aes256,
    sock: UdpSocket,
    tun: File,
    peers: RwLock<Peers>,
    sessions: RwLock<HashMap<u32, Arc<Session>>>,
    burst_max: AtomicUsize,
    burst_delay: AtomicU64,
    dup: Mutex<mpsc::Sender<(Instant, Vec<u8>, SocketAddr)>>,
    stop: AtomicBool,
}

pub struct Server {
    sh: Arc<Shared>,
    threads: Vec<JoinHandle<()>>,
    undo: Vec<Vec<String>>,
    pub cfg: MtCfg,
}

fn run(args: &[&str]) -> Result<(), String> {
    let out = Command::new(args[0]).args(&args[1..]).output().map_err(|e| format!("{}: {}", args[0], e))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!("{}: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim()))
    }
}

fn open_tun(name: &str) -> Result<File, String> {
    const TUNSETIFF: libc::c_ulong = 0x400454ca;
    let f = std::fs::OpenOptions::new().read(true).write(true).open("/dev/net/tun").map_err(|e| format!("/dev/net/tun: {}", e))?;
    let mut req = [0u8; 40];
    req[..name.len()].copy_from_slice(name.as_bytes());
    req[16..18].copy_from_slice(&(0x0001u16 | 0x1000).to_ne_bytes()); // IFF_TUN | IFF_NO_PI
    // SAFETY: req is a valid, large enough ifreq for TUNSETIFF and lives across the call
    let r = unsafe { libc::ioctl(f.as_raw_fd(), TUNSETIFF as _, req.as_mut_ptr()) };
    if r < 0 {
        return Err(format!("TUNSETIFF: {}", std::io::Error::last_os_error()));
    }
    Ok(f)
}

/// iptables rules for forwarding + NAT of the tunnel subnet: (table, chain, spec)
fn nat_rules(subnet: &str) -> Vec<Vec<String>> {
    let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    vec![
        s(&["-t", "nat", "POSTROUTING", "-s", subnet, "!", "-o", IFACE, "-j", "MASQUERADE"]),
        s(&["-t", "filter", "FORWARD", "-i", IFACE, "-j", "ACCEPT"]),
        s(&["-t", "filter", "FORWARD", "-o", IFACE, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"]),
        s(&["-t", "mangle", "FORWARD", "-o", IFACE, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"]),
    ]
}

fn ipt(op: &str, r: &[String]) -> Result<(), String> {
    let mut a: Vec<&str> = vec!["iptables", &r[0], &r[1], op, &r[2]];
    a.extend(r[3..].iter().map(|x| x.as_str()));
    run(&a)
}

/// "10.77.0.1/16" -> ("10.77.0.0/16")
fn subnet_of(address: &str) -> Option<String> {
    let (ip, bits) = address.split_once('/')?;
    let ip: Ipv4Addr = ip.parse().ok()?;
    let bits: u32 = bits.parse().ok().filter(|b| *b <= 30)?;
    let m = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
    Some(format!("{}/{}", Ipv4Addr::from(u32::from(ip) & m), bits))
}

impl Server {
    pub fn start(cfg: &MtCfg) -> Result<Server, String> {
        let obfs = key32(&cfg.obfs).ok_or("bad obfs key")?;
        let subnet = subnet_of(&cfg.address).ok_or("bad tunnel address")?;
        let sock = UdpSocket::bind(("::", cfg.port)).or_else(|_| UdpSocket::bind(("0.0.0.0", cfg.port))).map_err(|e| format!("UDP {}: {}", cfg.port, e))?;
        sock.set_read_timeout(Some(Duration::from_millis(500))).ok();
        let tun = open_tun(IFACE)?;
        run(&["ip", "addr", "replace", &cfg.address, "dev", IFACE])?;
        run(&["ip", "link", "set", "dev", IFACE, "mtu", &cfg.mtu.clamp(576, 9000).to_string(), "up"])?;
        let mut undo = vec![];
        std::fs::write("/proc/sys/net/ipv4/ip_forward", "1").map_err(|e| format!("ip_forward: {}", e))?;
        for r in nat_rules(&subnet) {
            if ipt("-C", &r).is_ok() {
                continue;
            }
            ipt("-I", &r)?;
            undo.push(r);
        }
        let (dtx, drx) = mpsc::channel();
        let sh = Arc::new(Shared {
            obfs: Aes256::new(&obfs.into()),
            sock,
            tun,
            peers: RwLock::new(Peers::default()),
            sessions: RwLock::new(HashMap::new()),
            burst_max: AtomicUsize::new(0),
            burst_delay: AtomicU64::new(0),
            dup: Mutex::new(dtx),
            stop: AtomicBool::new(false),
        });
        let mut srv = Server { sh: sh.clone(), threads: vec![], undo, cfg: cfg.clone() };
        srv.set(cfg);
        let spawn = |name: &str, f: Box<dyn FnOnce() + Send>| std::thread::Builder::new().name(name.into()).spawn(f).expect("thread");
        let s = sh.clone();
        srv.threads.push(spawn("mtun-tun", Box::new(move || tun_loop(&s))));
        let s = sh.clone();
        srv.threads.push(spawn("mtun-udp", Box::new(move || udp_loop(&s))));
        let s = sh.clone();
        srv.threads.push(spawn("mtun-dup", Box::new(move || dup_loop(&s, drx))));
        let s = sh;
        srv.threads.push(spawn("mtun-gc", Box::new(move || janitor(&s))));
        Ok(srv)
    }

    pub fn needs_restart(&self, cfg: &MtCfg) -> bool {
        self.cfg.base_differs(cfg)
    }

    /// users and burst settings, live: users whose key and IP stay keep their sessions
    pub fn set(&mut self, cfg: &MtCfg) {
        let sh = &self.sh;
        sh.burst_max.store(cfg.burst_max as usize, Ordering::Relaxed);
        sh.burst_delay.store(cfg.burst_delay_ms as u64, Ordering::Relaxed);
        let old: HashMap<(String, Ipv4Addr), Arc<Peer>> = sh.peers.read().unwrap().list.iter().map(|p| ((p.key_hex.clone(), p.ip), p.clone())).collect();
        let mut next = Peers::default();
        for u in &cfg.users {
            let (Some(k), Ok(ip)) = (key32(&u.key), u.ip.parse::<Ipv4Addr>()) else { continue };
            if next.by_ip.contains_key(&ip) {
                continue;
            }
            let p = old.get(&(u.key.trim().to_string(), ip)).cloned().unwrap_or_else(|| {
                Arc::new(Peer {
                    name: u.name.clone(),
                    key_hex: u.key.trim().to_string(),
                    ip,
                    keys: PskKeys::new(k),
                    endpoint: Mutex::new(None),
                    current: RwLock::new(None),
                    st: Mutex::new(PeerState::default()),
                    rx: AtomicU64::new(0),
                    tx: AtomicU64::new(0),
                    last_rx: AtomicI64::new(0),
                })
            });
            next.by_ip.insert(ip, p.clone());
            next.list.push(p);
        }
        // sessions of users who left are dropped at once
        let keep: std::collections::HashSet<*const Peer> = next.list.iter().map(Arc::as_ptr).collect();
        sh.sessions.write().unwrap().retain(|_, s| s.peer.upgrade().map(|p| keep.contains(&Arc::as_ptr(&p))).unwrap_or(false));
        *sh.peers.write().unwrap() = next;
        self.cfg = cfg.clone();
    }

    /// (rx, tx) bytes per user name since the start
    pub fn traffic(&self) -> HashMap<String, (i64, i64)> {
        let mut m = HashMap::new();
        for p in &self.sh.peers.read().unwrap().list {
            let e = m.entry(p.name.clone()).or_insert((0, 0));
            e.0 += p.rx.load(Ordering::Relaxed) as i64;
            e.1 += p.tx.load(Ordering::Relaxed) as i64;
        }
        m
    }

    /// users who sent something in the last minute
    pub fn online(&self) -> Vec<String> {
        let t = now_secs();
        self.sh.peers.read().unwrap().list.iter().filter(|p| t - p.last_rx.load(Ordering::Relaxed) < 60).map(|p| p.name.clone()).collect()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.sh.stop.store(true, Ordering::Relaxed);
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
        for r in self.undo.iter().rev() {
            let _ = ipt("-D", r);
        }
    }
}

fn ip_dst(p: &[u8]) -> Option<Ipv4Addr> {
    (p.len() >= 20 && p[0] >> 4 == 4).then(|| Ipv4Addr::new(p[16], p[17], p[18], p[19]))
}

fn ip_src(p: &[u8]) -> Option<Ipv4Addr> {
    (p.len() >= 20 && p[0] >> 4 == 4).then(|| Ipv4Addr::new(p[12], p[13], p[14], p[15]))
}

fn send_burst(sh: &Shared, pkt: &[u8], ip_len: usize, to: SocketAddr) {
    let _ = sh.sock.send_to(pkt, to);
    let max = sh.burst_max.load(Ordering::Relaxed);
    if max == 0 || ip_len > max {
        return;
    }
    let delay = sh.burst_delay.load(Ordering::Relaxed);
    if delay == 0 {
        let _ = sh.sock.send_to(pkt, to);
    } else {
        let _ = sh.dup.lock().unwrap().send((Instant::now() + Duration::from_millis(delay), pkt.to_vec(), to));
    }
}

/// the second copies, in order (every copy waits the same delay, so a queue is enough)
fn dup_loop(sh: &Shared, rx: mpsc::Receiver<(Instant, Vec<u8>, SocketAddr)>) {
    while !sh.stop.load(Ordering::Relaxed) {
        let Ok((due, pkt, to)) = rx.recv_timeout(Duration::from_millis(500)) else { continue };
        let now = Instant::now();
        if due > now {
            std::thread::sleep(due - now);
        }
        let _ = sh.sock.send_to(&pkt, to);
    }
}

fn tun_loop(sh: &Shared) {
    let mut buf = vec![0u8; HDR + MAX_IP + TAG];
    let mut tun = &sh.tun;
    let fd = sh.tun.as_raw_fd();
    while !sh.stop.load(Ordering::Relaxed) {
        let mut pfd = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
        // SAFETY: one valid pollfd for the duration of the call
        if unsafe { libc::poll(&mut pfd, 1, 500) } <= 0 {
            continue;
        }
        let n = match tun.read(&mut buf[HDR..HDR + MAX_IP]) {
            Ok(n) if n > 0 => n,
            _ => continue,
        };
        let Some(dst) = ip_dst(&buf[HDR..HDR + n]) else { continue };
        let Some(p) = sh.peers.read().unwrap().by_ip.get(&dst).cloned() else { continue };
        let (Some(sess), Some(ep)) = (p.current.read().unwrap().clone(), *p.endpoint.lock().unwrap()) else { continue };
        if let Some(pkt) = sess.seal(&sh.obfs, &mut buf, n) {
            p.tx.fetch_add(n as u64, Ordering::Relaxed);
            send_burst(sh, pkt, n, ep);
        }
    }
}

fn udp_loop(sh: &Shared) {
    let mut buf = vec![0u8; MAX_IP + OVERHEAD];
    let mut tun = &sh.tun;
    while !sh.stop.load(Ordering::Relaxed) {
        let (n, from) = match sh.sock.recv_from(&mut buf) {
            Ok(x) => x,
            Err(_) => continue,
        };
        if n < OVERHEAD {
            continue;
        }
        let pkt = &mut buf[..n];
        mask(&sh.obfs, pkt);
        let idx = u32::from_be_bytes([pkt[0], pkt[1], pkt[2], pkt[3]]);
        if idx == 0 {
            handle_init(sh, pkt, from);
            continue;
        }
        let Some(sess) = sh.sessions.read().unwrap().get(&idx).cloned() else { continue };
        let Some(len) = sess.open(pkt) else { continue };
        let Some(p) = sess.peer.upgrade() else { continue };
        let is_current = p.current.read().unwrap().as_ref().map(|c| Arc::ptr_eq(c, &sess)).unwrap_or(false);
        if !is_current {
            confirm(sh, &p, &sess);
        }
        {
            let mut ep = p.endpoint.lock().unwrap();
            if *ep != Some(from) {
                *ep = Some(from);
            }
        }
        p.last_rx.store(now_secs(), Ordering::Relaxed);
        if len == 0 {
            keepalive(sh, &p); // answered, so the client tells a dead server from a quiet one
            continue;
        }
        let ip = &pkt[HDR..HDR + len];
        if ip_src(ip) != Some(p.ip) {
            continue; // a user may only send from their own tunnel address
        }
        p.rx.fetch_add(len as u64, Ordering::Relaxed);
        let _ = tun.write(ip);
    }
}

fn keepalive(sh: &Shared, p: &Peer) {
    let (Some(sess), Some(ep)) = (p.current.read().unwrap().clone(), *p.endpoint.lock().unwrap()) else { return };
    let mut buf = [0u8; OVERHEAD];
    if let Some(pkt) = sess.seal(&sh.obfs, &mut buf, 0) {
        let _ = sh.sock.send_to(pkt, ep);
    }
}

fn handle_init(sh: &Shared, pkt: &[u8], from: SocketAddr) {
    let found = {
        let peers = sh.peers.read().unwrap();
        peers.list.iter().find_map(|p| parse_init(&p.keys, pkt).map(|m| (p.clone(), m)))
    };
    let Some((p, m)) = found else { return };
    let mut st = p.st.lock().unwrap();
    if m.ts <= st.last_ts {
        return; // a replayed or stale init
    }
    let eph = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
    let eph_pub = PublicKey::from(&eph).to_bytes();
    let shared = eph.diffie_hellman(&PublicKey::from(m.eph));
    if !shared.was_contributory() {
        return;
    }
    st.last_ts = m.ts;
    let mut sessions = sh.sessions.write().unwrap();
    let mut idx = rand_idx();
    while sessions.contains_key(&idx) {
        idx = rand_idx();
    }
    let (c2s, s2c) = derive(shared.as_bytes(), &p.keys.psk, &m.eph, &eph_pub, m.idx, idx);
    let sess = Arc::new(Session {
        local: idx,
        remote: m.idx,
        send: Aes256Gcm::new(&s2c.into()),
        recv: Aes256Gcm::new(&c2s.into()),
        ctr: AtomicU64::new(0),
        rw: Mutex::new(Replay::new()),
        born: Instant::now(),
        peer: Arc::downgrade(&p),
    });
    if let Some(old) = st.pending.take() {
        sessions.remove(&old.local);
    }
    sessions.insert(idx, sess.clone());
    st.pending = Some(sess);
    drop(sessions);
    drop(st);
    let resp = build_resp(&sh.obfs, &p.keys, &eph_pub, idx, m.idx, &m.eph, pkt.len());
    let _ = sh.sock.send_to(&resp, from);
}

/// a pending session becomes current once the client sent data with it: a replayed init never
/// displaces a working session
fn confirm(sh: &Shared, p: &Peer, sess: &Arc<Session>) {
    let mut st = p.st.lock().unwrap();
    if !st.pending.as_ref().map(|x| Arc::ptr_eq(x, sess)).unwrap_or(false) {
        return; // data on the previous session
    }
    if let Some(prev) = st.prev.take() {
        sh.sessions.write().unwrap().remove(&prev.local);
    }
    let mut cur = p.current.write().unwrap();
    st.prev = cur.take();
    *cur = st.pending.take();
}

fn janitor(sh: &Shared) {
    let mut last = Instant::now();
    while !sh.stop.load(Ordering::Relaxed) {
        std::thread::sleep(Duration::from_millis(500));
        if last.elapsed() < Duration::from_secs(5) {
            continue;
        }
        last = Instant::now();
        let peers = sh.peers.read().unwrap().list.clone();
        for p in peers {
            let mut st = p.st.lock().unwrap();
            let mut gone = vec![];
            if st.prev.as_ref().map(|s| s.expired()).unwrap_or(false) {
                gone.extend(st.prev.take().map(|s| s.local));
            }
            if st.pending.as_ref().map(|s| s.born.elapsed() > PENDING_FOR).unwrap_or(false) {
                gone.extend(st.pending.take().map(|s| s.local));
            }
            let mut cur = p.current.write().unwrap();
            if cur.as_ref().map(|s| s.expired()).unwrap_or(false) {
                gone.extend(cur.take().map(|s| s.local));
            }
            let mut sessions = sh.sessions.write().unwrap();
            for i in gone {
                sessions.remove(&i);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A client side written against the Go microtun v2 wire format
    fn build_init(obfs: &Aes256, k: &PskKeys, eph: &[u8; 32], ts: u64, idx: u32) -> Vec<u8> {
        let mut body = eph.to_vec();
        body.extend_from_slice(&ts.to_be_bytes());
        body.extend_from_slice(&idx.to_be_bytes());
        let mut hdr = [0u8; HDR];
        rand::thread_rng().fill_bytes(&mut hdr[4..]);
        let ct = k.init.encrypt(Nonce::from_slice(&hdr), Payload { msg: &body, aad: &hdr }).unwrap();
        let mut pkt = [&hdr[..], &ct].concat();
        mask(obfs, &mut pkt);
        pkt
    }

    #[test]
    fn handshake_and_data() {
        let obfs = Aes256::new(&[7u8; 32].into());
        let k = PskKeys::new([9u8; 32]);
        let ce = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
        let ce_pub = PublicKey::from(&ce).to_bytes();
        let mut init = build_init(&obfs, &k, &ce_pub, 1, 5);
        mask(&obfs, &mut init);
        assert_eq!(&init[..4], &[0, 0, 0, 0]);
        let m = parse_init(&k, &init).expect("init opens");
        assert_eq!((m.ts, m.idx), (1, 5));
        assert!(parse_init(&PskKeys::new([8u8; 32]), &init).is_none());

        let se = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
        let se_pub = PublicKey::from(&se).to_bytes();
        let mut resp = build_resp(&obfs, &k, &se_pub, 77, 5, &ce_pub, init.len());
        assert!(resp.len() <= init.len());
        mask(&obfs, &mut resp);
        let aad = [&resp[..HDR], &ce_pub[..]].concat();
        let pt = k.resp.decrypt(Nonce::from_slice(&resp[..HDR]), Payload { msg: &resp[HDR..], aad: &aad }).unwrap();
        assert_eq!(&pt[32..40], &[0, 0, 0, 77, 0, 0, 0, 5]);

        let sh_s = se.diffie_hellman(&PublicKey::from(m.eph));
        let sh_c = ce.diffie_hellman(&PublicKey::from(se_pub));
        let (c2s, s2c) = derive(sh_s.as_bytes(), &k.psk, &m.eph, &se_pub, 5, 77);
        let (c2s_c, s2c_c) = derive(sh_c.as_bytes(), &k.psk, &ce_pub, &se_pub, 5, 77);
        assert_eq!((c2s, s2c), (c2s_c, s2c_c));

        let mk = |send: [u8; 32], recv: [u8; 32], local, remote| Session {
            local,
            remote,
            send: Aes256Gcm::new(&send.into()),
            recv: Aes256Gcm::new(&recv.into()),
            ctr: AtomicU64::new(0),
            rw: Mutex::new(Replay::new()),
            born: Instant::now(),
            peer: Weak::new(),
        };
        let client = mk(c2s, s2c, 5, 77);
        let server = mk(s2c, c2s, 77, 5);
        let mut buf = vec![0u8; HDR + 3 + TAG];
        buf[HDR..HDR + 3].copy_from_slice(b"hey");
        let wire = client.seal(&obfs, &mut buf, 3).unwrap().to_vec();
        assert_eq!(wire.len(), 3 + OVERHEAD);
        let mut p = wire.clone();
        mask(&obfs, &mut p);
        assert_eq!(u32::from_be_bytes(p[..4].try_into().unwrap()), 77);
        assert_eq!(server.open(&mut p), Some(3));
        assert_eq!(&p[HDR..HDR + 3], b"hey");
        let mut p = wire.clone();
        mask(&obfs, &mut p);
        assert_eq!(server.open(&mut p), None, "a duplicate is dropped");
    }

    #[test]
    fn replay_window() {
        let mut r = Replay::new();
        for c in [0, 1, 2, 5, 4, 3] {
            assert!(r.accept(c));
        }
        for c in [0, 3, 5] {
            assert!(!r.accept(c));
        }
        assert!(r.accept(5 + WINDOW - 1));
        assert!(!r.accept(5));
        assert!(r.accept(6) && !r.accept(6));
    }

    #[test]
    fn subnets() {
        assert_eq!(subnet_of("10.77.0.1/16").as_deref(), Some("10.77.0.0/16"));
        assert_eq!(subnet_of("10.77.0.1"), None);
    }
}

/// Runs a server from the JSON in $MTUN_CFG for $MTUN_SECS seconds, printing traffic at the end
/// (interop check against the Go client: `cargo test mtun_live -- --ignored --nocapture`)
#[cfg(test)]
#[test]
#[ignore]
fn mtun_live() {
    let cfg: MtCfg = serde_json::from_str(&std::fs::read_to_string(std::env::var("MTUN_CFG").unwrap()).unwrap()).unwrap();
    let srv = Server::start(&cfg).expect("start");
    let secs: u64 = std::env::var("MTUN_SECS").ok().and_then(|s| s.parse().ok()).unwrap_or(30);
    std::thread::sleep(Duration::from_secs(secs));
    println!("traffic {:?} online {:?}", srv.traffic(), srv.online());
}
