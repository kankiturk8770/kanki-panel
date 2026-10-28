//! microtun on a VPN server: a light game VPN over a TUN interface (28 bytes per packet, WireGuard
//! 32). The same wire format as the standalone Go microtun v2 (its server and Linux client live in
//! `microtun/`), so the Go client and the Kanki app speak to this server.
//!
//! Wire: [idx 4 | counter 8] masked with AES(obfs, first 16 bytes of the ciphertext), then
//! AES-256-GCM with the unmasked header as nonce and AD. idx 0 is a handshake: X25519 ephemerals
//! sealed with keys from the user's own key, session keys = HKDF(shared, salt = user key). Small
//! IP packets are sent twice (`burst_max`, `burst_delay_ms`); the replay window drops the copy.
//!
//! v2.1, inside the random padding of the handshakes (so v2 clients and servers ignore it):
//! - the init may carry `mtD1` + a device id (8 bytes): each device of a user is a peer of its own
//!   with its own sessions and address, up to the user's device limit (the least recently used one
//!   goes, once it has been silent for `IDLE_GIVES_WAY`). A client without it is device 0 and has
//!   the user's own address, as in v2.
//! - the response then carries `mtA1` + the device's IPv4 + a flag + its IPv6 (flag bit 0), when the
//!   init left room for it (a response is never larger than its init).
//! - an init whose timestamp is not newer than the device's last one is still taken when it is
//!   within `FRESH` of this server's clock and its ephemeral key was not seen before: a client whose
//!   clock went back reconnects instead of waiting for its clock to catch up.
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
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::File;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
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
/// init: device id follows
const EXT_DEV: &[u8; 4] = b"mtD1";
/// response: the device's addresses follow (IPv4, flags, IPv6)
const EXT_ADDR: &[u8; 4] = b"mtA1";
const EXT_ADDR_LEN: usize = 4 + 4 + 1 + 16;
/// an older init timestamp is taken within this much of our clock (nanoseconds)
const FRESH: u64 = 120_000_000_000;
/// how long an init's ephemeral key is remembered (longer than the FRESH window both ways)
const SEEN_FOR: Duration = Duration::from_secs(300);
/// devices per user when the panel sets no limit
const MAX_DEVICES: usize = 8;
/// a device of a user at their limit gives way to a new one only after this long without a packet
/// (clients send a keepalive every 10 s): a device in use is never pushed out, so devices past the
/// limit wait instead of throwing each other out in turn
const IDLE_GIVES_WAY: i64 = 20;

/// What one server runs (sent by the panel on every sync)
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(default)]
pub struct MtCfg {
    /// UDP port; 0 = off on this server
    pub port: u16,
    /// header mask key, 64 hex (shared by the server and its users)
    pub obfs: String,
    /// the server's tunnel address with prefix ("10.79.0.1/16"); users have their own address in it
    pub address: String,
    /// the server's address in the subnet of the users' second, third … devices ("10.80.0.1/16";
    /// "" = one device per user)
    pub devices: String,
    /// the server's IPv6 in the tunnel ("fd79:4d54::1/64"; "" = IPv4 only). Used only when this
    /// server has IPv6 itself; a device's IPv6 is the prefix + its IPv4.
    pub address6: String,
    pub mtu: u16,
    pub burst_max: u16,
    pub burst_delay_ms: u16,
    pub users: Vec<MtUser>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(default)]
pub struct MtUser {
    pub name: String,
    /// the user's own key, 64 hex
    pub key: String,
    /// the user's tunnel IPv4 (of their first device): packets from it must carry it as source
    pub ip: String,
    /// devices at the same time (0 = no limit from the panel)
    pub max: u32,
}

impl MtCfg {
    pub fn on(&self) -> bool {
        self.port > 0
    }
    /// settings that need a new socket / interface (users and burst change live)
    fn base_differs(&self, o: &MtCfg) -> bool {
        self.port != o.port || self.obfs != o.obfs || self.address != o.address || self.mtu != o.mtu || self.devices != o.devices || self.address6 != o.address6
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
    /// 0 = a client that sends no device id
    dev: u64,
}

/// pkt is unmasked
fn parse_init(k: &PskKeys, pkt: &[u8]) -> Option<Init> {
    let hdr = &pkt[..HDR];
    let pt = k.init.decrypt(Nonce::from_slice(hdr), Payload { msg: &pkt[HDR..], aad: hdr }).ok()?;
    if pt.len() < INIT_BODY {
        return None;
    }
    let ext = &pt[INIT_BODY..];
    let dev = if ext.len() >= 12 && &ext[..4] == EXT_DEV { u64::from_be_bytes(ext[4..12].try_into().ok()?) } else { 0 };
    Some(Init {
        eph: pt[..32].try_into().ok()?,
        ts: u64::from_be_bytes(pt[32..40].try_into().ok()?),
        idx: u32::from_be_bytes(pt[40..44].try_into().ok()?),
        dev,
    })
}

/// The addresses a response tells the device: IPv4, and IPv6 when this server has it
#[derive(Clone, Copy, Debug, PartialEq)]
struct Addrs {
    v4: Ipv4Addr,
    v6: Option<Ipv6Addr>,
}

/// a masked response, never larger than the init it answers (no amplification); the addresses go
/// in only when they fit
fn build_resp(obfs: &Aes256, k: &PskKeys, eph_s: &[u8; 32], idx_s: u32, idx_c: u32, eph_c: &[u8], init_len: usize, addrs: Option<Addrs>) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut pt = Vec::with_capacity(RESP_BODY + EXT_ADDR_LEN + MAX_PAD);
    pt.extend_from_slice(eph_s);
    pt.extend_from_slice(&idx_s.to_be_bytes());
    pt.extend_from_slice(&idx_c.to_be_bytes());
    if let Some(a) = addrs.filter(|_| init_len >= HDR + RESP_BODY + EXT_ADDR_LEN + TAG) {
        pt.extend_from_slice(EXT_ADDR);
        pt.extend_from_slice(&a.v4.octets());
        pt.push(a.v6.is_some() as u8);
        pt.extend_from_slice(&a.v6.unwrap_or(Ipv6Addr::UNSPECIFIED).octets());
    }
    let room = init_len.saturating_sub(HDR + pt.len() + TAG).min(MAX_PAD);
    let pad = rng.gen_range(0..=room);
    let at = pt.len();
    pt.resize(at + pad, 0);
    rng.fill_bytes(&mut pt[at..]);
    let mut hdr = [0u8; HDR];
    rng.fill_bytes(&mut hdr[4..]);
    let aad = [&hdr[..], eph_c].concat();
    let ct = k.resp.encrypt(Nonce::from_slice(&hdr), Payload { msg: &pt, aad: &aad }).expect("seal");
    let mut pkt = [&hdr[..], &ct].concat();
    mask(obfs, &mut pkt);
    pkt
}

/// nanoseconds since 1970 by this server's clock
fn now_nanos() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos() as u64).unwrap_or(0)
}

/// whether an init timestamp may be taken: newer than the device's last one, or (the client's
/// clock went back) close to our own clock
fn ts_ok(ts: u64, last: u64, now: u64) -> bool {
    ts > last || ts.abs_diff(now) <= FRESH
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
    dev: Weak<Device>,
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
struct DevState {
    last_ts: u64,
    prev: Option<Arc<Session>>,
    pending: Option<Arc<Session>>,
}

/// One device of a user: its own sessions, endpoint and tunnel addresses
struct Device {
    id: u64,
    ip: Ipv4Addr,
    ip6: Option<Ipv6Addr>,
    user: Weak<Peer>,
    endpoint: Mutex<Option<SocketAddr>>,
    current: RwLock<Option<Arc<Session>>>,
    st: Mutex<DevState>,
    /// it has sent data with a session (a device made by an init alone does not count yet)
    confirmed: AtomicBool,
    /// unix seconds of the last authenticated packet
    last_rx: AtomicI64,
    made: Instant,
}

impl Device {
    fn owns(&self, src: IpAddr) -> bool {
        match src {
            IpAddr::V4(a) => a == self.ip,
            IpAddr::V6(a) => Some(a) == self.ip6,
        }
    }
    /// every session of the device (to take them out of the index)
    fn sessions(&self) -> Vec<u32> {
        let st = self.st.lock().unwrap();
        let cur = self.current.read().unwrap();
        [st.prev.as_ref(), st.pending.as_ref(), cur.as_ref()].into_iter().flatten().map(|s| s.local).collect()
    }
}

/// One user
struct Peer {
    name: String,
    key_hex: String,
    /// the address of the user's first device
    ip: Ipv4Addr,
    max: AtomicUsize,
    keys: PskKeys,
    devices: Mutex<Vec<Arc<Device>>>,
    /// ephemeral keys of recent inits: an init with an older timestamp is taken only once
    seen: Mutex<VecDeque<([u8; 32], Instant)>>,
    rx: AtomicU64,
    tx: AtomicU64,
}

fn now_secs() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

// ------------------------------------------------------------------ the server

#[derive(Default)]
struct Peers {
    list: Vec<Arc<Peer>>,
    /// tunnel address (IPv4 and IPv6) -> device
    by_ip: HashMap<IpAddr, Arc<Device>>,
}

/// An IPv4 subnet: the first address and the number of addresses
#[derive(Clone, Copy)]
struct Net4 {
    base: u32,
    size: u32,
}

impl Net4 {
    /// "10.80.0.1/16" -> the subnet (prefix 8-30)
    fn parse(address: &str) -> Option<Net4> {
        let (ip, bits) = address.split_once('/')?;
        let ip: Ipv4Addr = ip.parse().ok()?;
        let bits: u32 = bits.parse().ok().filter(|b| (8..=30).contains(b))?;
        let m = u32::MAX << (32 - bits);
        Some(Net4 { base: u32::from(ip) & m, size: 1 << (32 - bits) })
    }
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
    /// the subnet of second, third … devices, and the server's own address in it
    devnet: Option<(Net4, Ipv4Addr)>,
    /// the first 64 bits of the IPv6 subnet (None = IPv4 only)
    v6: Option<[u8; 8]>,
}

impl Shared {
    fn v6_of(&self, v4: Ipv4Addr) -> Option<Ipv6Addr> {
        let p = self.v6?;
        let mut o = [0u8; 16];
        o[..8].copy_from_slice(&p);
        o[12..].copy_from_slice(&v4.octets());
        Some(Ipv6Addr::from(o))
    }

    /// A free address for another device of a user (None = the subnet is full)
    fn free_addr(&self, used: &HashMap<IpAddr, Arc<Device>>) -> Option<Ipv4Addr> {
        let (net, own) = self.devnet?;
        let mut rng = rand::thread_rng();
        // random first, so the addresses of devices that come and go spread out
        for _ in 0..64 {
            let a = Ipv4Addr::from(net.base + rng.gen_range(1..net.size - 1));
            if a != own && !used.contains_key(&IpAddr::V4(a)) {
                return Some(a);
            }
        }
        (1..net.size - 1).map(|i| Ipv4Addr::from(net.base + i)).find(|a| *a != own && !used.contains_key(&IpAddr::V4(*a)))
    }

    /// Takes a device out: its addresses and sessions (the caller holds the user's device list)
    fn drop_device(&self, peers: &mut Peers, d: &Device) {
        for ip in [Some(IpAddr::V4(d.ip)), d.ip6.map(IpAddr::V6)].into_iter().flatten() {
            if peers.by_ip.get(&ip).is_some_and(|x| std::ptr::eq(Arc::as_ptr(x), d)) {
                peers.by_ip.remove(&ip);
            }
        }
        let gone = d.sessions();
        let mut s = self.sessions.write().unwrap();
        for i in gone {
            s.remove(&i);
        }
    }
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

/// iptables (or ip6tables) rules for forwarding + NAT of a tunnel subnet: (tool, table, chain, spec)
fn nat_rules(tool: &str, subnet: &str) -> Vec<Vec<String>> {
    let s = |v: &[&str]| [&[tool], v].concat().iter().map(|x| x.to_string()).collect::<Vec<_>>();
    vec![
        s(&["-t", "nat", "POSTROUTING", "-s", subnet, "!", "-o", IFACE, "-j", "MASQUERADE"]),
        s(&["-t", "filter", "FORWARD", "-i", IFACE, "-j", "ACCEPT"]),
        s(&["-t", "filter", "FORWARD", "-o", IFACE, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"]),
        s(&["-t", "mangle", "FORWARD", "-o", IFACE, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"]),
    ]
}

fn ipt(op: &str, r: &[String]) -> Result<(), String> {
    let mut a: Vec<&str> = vec![&r[0], &r[1], &r[2], op, &r[3]];
    a.extend(r[4..].iter().map(|x| x.as_str()));
    run(&a)
}

/// "10.79.0.1/16" -> ("10.79.0.0/16")
fn subnet_of(address: &str) -> Option<String> {
    let (ip, bits) = address.split_once('/')?;
    let ip: Ipv4Addr = ip.parse().ok()?;
    let bits: u32 = bits.parse().ok().filter(|b| *b <= 30)?;
    let m = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
    Some(format!("{}/{}", Ipv4Addr::from(u32::from(ip) & m), bits))
}

/// "fd79:4d54::1/64" -> (the first 64 bits, "fd79:4d54::/64"); only a /64
fn subnet6_of(address: &str) -> Option<([u8; 8], String)> {
    let (ip, bits) = address.split_once('/')?;
    let ip: Ipv6Addr = ip.parse().ok()?;
    if bits != "64" {
        return None;
    }
    let p: [u8; 8] = ip.octets()[..8].try_into().ok()?;
    let mut net = [0u8; 16];
    net[..8].copy_from_slice(&p);
    Some((p, format!("{}/64", Ipv6Addr::from(net))))
}

/// whether this server reaches the IPv6 internet (it has a default IPv6 route)
fn host_has_v6() -> bool {
    Command::new("ip").args(["-6", "route", "show", "default"]).output().map(|o| o.status.success() && !o.stdout.trim_ascii().is_empty()).unwrap_or(false)
}

impl Server {
    pub fn start(cfg: &MtCfg) -> Result<Server, String> {
        let obfs = key32(&cfg.obfs).ok_or("bad obfs key")?;
        let subnet = subnet_of(&cfg.address).ok_or("bad tunnel address")?;
        let devnet = if cfg.devices.is_empty() {
            None
        } else {
            let n = Net4::parse(&cfg.devices).ok_or("bad devices address")?;
            let own: Ipv4Addr = cfg.devices.split('/').next().and_then(|a| a.parse().ok()).ok_or("bad devices address")?;
            Some((n, own))
        };
        let v6 = if cfg.address6.is_empty() { None } else { Some(subnet6_of(&cfg.address6).ok_or("bad IPv6 tunnel address")?) }.filter(|_| host_has_v6());
        let sock = UdpSocket::bind(("::", cfg.port)).or_else(|_| UdpSocket::bind(("0.0.0.0", cfg.port))).map_err(|e| format!("UDP {}: {}", cfg.port, e))?;
        sock.set_read_timeout(Some(Duration::from_millis(500))).ok();
        let tun = open_tun(IFACE)?;
        run(&["ip", "addr", "replace", &cfg.address, "dev", IFACE])?;
        if devnet.is_some() {
            run(&["ip", "addr", "replace", &cfg.devices, "dev", IFACE])?;
        }
        run(&["ip", "link", "set", "dev", IFACE, "mtu", &cfg.mtu.clamp(576, 9000).to_string(), "up"])?;
        let mut undo = vec![];
        std::fs::write("/proc/sys/net/ipv4/ip_forward", "1").map_err(|e| format!("ip_forward: {}", e))?;
        let mut rules = nat_rules("iptables", &subnet);
        if devnet.is_some() {
            // the second subnet only needs its NAT: forwarding goes by the interface
            rules.extend(nat_rules("iptables", &subnet_of(&cfg.devices).ok_or("bad devices address")?).into_iter().take(1));
        }
        let add = |rules: Vec<Vec<String>>, undo: &mut Vec<Vec<String>>| -> Result<(), String> {
            for r in rules {
                if ipt("-C", &r).is_ok() {
                    continue;
                }
                ipt("-I", &r)?;
                undo.push(r);
            }
            Ok(())
        };
        if let Err(e) = add(rules, &mut undo) {
            for u in undo.iter().rev() {
                let _ = ipt("-D", u);
            }
            return Err(e);
        }
        // IPv6 is a bonus: a server where it does not work still serves IPv4
        let v6 = v6.filter(|(_, net6)| {
            run(&["ip", "-6", "addr", "replace", &cfg.address6, "dev", IFACE]).is_ok()
                && std::fs::write("/proc/sys/net/ipv6/conf/all/forwarding", "1").is_ok()
                && add(nat_rules("ip6tables", net6), &mut undo).is_ok()
        });
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
            devnet,
            v6: v6.map(|(p, _)| p),
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

    /// whether IPv6 runs in the tunnel on this server
    pub fn has_v6(&self) -> bool {
        self.sh.v6.is_some()
    }

    /// users and burst settings, live: users whose key and IP stay keep their devices and sessions
    pub fn set(&mut self, cfg: &MtCfg) {
        let sh = &self.sh;
        sh.burst_max.store(cfg.burst_max as usize, Ordering::Relaxed);
        sh.burst_delay.store(cfg.burst_delay_ms as u64, Ordering::Relaxed);
        let mut peers = sh.peers.write().unwrap();
        let old: HashMap<(String, String, Ipv4Addr), Arc<Peer>> = peers.list.iter().map(|p| ((p.name.clone(), p.key_hex.clone(), p.ip), p.clone())).collect();
        let mut list = vec![];
        let mut own: HashSet<Ipv4Addr> = HashSet::new();
        for u in &cfg.users {
            let (Some(k), Ok(ip)) = (key32(&u.key), u.ip.parse::<Ipv4Addr>()) else { continue };
            if !own.insert(ip) {
                continue;
            }
            let max = if u.max == 0 { MAX_DEVICES } else { (u.max as usize).min(MAX_DEVICES) };
            let p = match old.get(&(u.name.clone(), u.key.trim().to_string(), ip)) {
                // the same user keeps their devices; a lower limit takes effect at the next new device
                Some(p) => {
                    p.max.store(max, Ordering::Relaxed);
                    p.clone()
                }
                None => Arc::new(Peer {
                    name: u.name.clone(),
                    key_hex: u.key.trim().to_string(),
                    ip,
                    max: AtomicUsize::new(max),
                    keys: PskKeys::new(k),
                    devices: Mutex::new(vec![]),
                    seen: Mutex::new(VecDeque::new()),
                    rx: AtomicU64::new(0),
                    tx: AtomicU64::new(0),
                }),
            };
            list.push(p);
        }
        // the devices of users who stay go to the new list; a device that holds another user's own
        // address gives it back
        let mut next = Peers { list: vec![], by_ip: HashMap::new() };
        let mut moved: Vec<Arc<Device>> = vec![];
        for p in &list {
            let mut devs = p.devices.lock().unwrap();
            let mut keep = vec![];
            for d in devs.drain(..) {
                if d.ip != p.ip && own.contains(&d.ip) {
                    moved.push(d);
                } else {
                    keep.push(d);
                }
            }
            for d in &keep {
                next.by_ip.insert(IpAddr::V4(d.ip), d.clone());
                if let Some(a) = d.ip6 {
                    next.by_ip.insert(IpAddr::V6(a), d.clone());
                }
            }
            *devs = keep;
        }
        next.list = list;
        // sessions of devices and users that left are dropped at once
        let live: HashSet<*const Device> = next.by_ip.values().map(Arc::as_ptr).collect();
        sh.sessions.write().unwrap().retain(|_, s| s.dev.upgrade().is_some_and(|d| live.contains(&Arc::as_ptr(&d))));
        drop(moved);
        *peers = next;
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

    /// one entry per device that sent something in the last minute (a user with two devices online
    /// is there twice)
    pub fn online(&self) -> Vec<String> {
        let t = now_secs();
        let mut out = vec![];
        for p in &self.sh.peers.read().unwrap().list {
            for d in p.devices.lock().unwrap().iter() {
                if d.confirmed.load(Ordering::Relaxed) && t - d.last_rx.load(Ordering::Relaxed) < 60 {
                    out.push(p.name.clone());
                }
            }
        }
        out
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

fn ip_dst(p: &[u8]) -> Option<IpAddr> {
    match p.first()? >> 4 {
        4 if p.len() >= 20 => Some(IpAddr::V4(Ipv4Addr::new(p[16], p[17], p[18], p[19]))),
        6 if p.len() >= 40 => Some(IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&p[24..40]).ok()?))),
        _ => None,
    }
}

fn ip_src(p: &[u8]) -> Option<IpAddr> {
    match p.first()? >> 4 {
        4 if p.len() >= 20 => Some(IpAddr::V4(Ipv4Addr::new(p[12], p[13], p[14], p[15]))),
        6 if p.len() >= 40 => Some(IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&p[8..24]).ok()?))),
        _ => None,
    }
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
        let Some(d) = sh.peers.read().unwrap().by_ip.get(&dst).cloned() else { continue };
        let (Some(sess), Some(ep)) = (d.current.read().unwrap().clone(), *d.endpoint.lock().unwrap()) else { continue };
        if let Some(pkt) = sess.seal(&sh.obfs, &mut buf, n) {
            if let Some(u) = d.user.upgrade() {
                u.tx.fetch_add(n as u64, Ordering::Relaxed);
            }
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
        let Some(d) = sess.dev.upgrade() else { continue };
        let is_current = d.current.read().unwrap().as_ref().map(|c| Arc::ptr_eq(c, &sess)).unwrap_or(false);
        if !is_current {
            confirm(sh, &d, &sess);
        }
        {
            let mut ep = d.endpoint.lock().unwrap();
            if *ep != Some(from) {
                *ep = Some(from);
            }
        }
        d.last_rx.store(now_secs(), Ordering::Relaxed);
        if len == 0 {
            keepalive(sh, &d); // answered, so the client tells a dead server from a quiet one
            continue;
        }
        let ip = &pkt[HDR..HDR + len];
        if !ip_src(ip).is_some_and(|a| d.owns(a)) {
            continue; // a device may only send from its own tunnel address
        }
        if let Some(u) = d.user.upgrade() {
            u.rx.fetch_add(len as u64, Ordering::Relaxed);
        }
        let _ = tun.write(ip);
    }
}

fn keepalive(sh: &Shared, d: &Device) {
    let (Some(sess), Some(ep)) = (d.current.read().unwrap().clone(), *d.endpoint.lock().unwrap()) else { return };
    let mut buf = [0u8; OVERHEAD];
    if let Some(pkt) = sess.seal(&sh.obfs, &mut buf, 0) {
        let _ = sh.sock.send_to(pkt, ep);
    }
}

/// The device an init is for: the one with its id, else a new one (its own address: the user's own
/// address when no other device has it, else a free one of the devices subnet). None = no room.
fn device_for(sh: &Shared, p: &Arc<Peer>, id: u64) -> Option<Arc<Device>> {
    if let Some(d) = p.devices.lock().unwrap().iter().find(|d| d.id == id) {
        return Some(d.clone());
    }
    let mut peers = sh.peers.write().unwrap();
    let mut devs = p.devices.lock().unwrap();
    if let Some(d) = devs.iter().find(|d| d.id == id) {
        return Some(d.clone());
    }
    // the user is still in the list (not removed by a sync meanwhile)
    if !peers.list.iter().any(|x| Arc::ptr_eq(x, p)) {
        return None;
    }
    // devices that only sent an init are bounded too
    let max = p.max.load(Ordering::Relaxed);
    if devs.len() >= max + 4 {
        return None;
    }
    // at the limit, a new device waits until one of the others has gone quiet
    let t = now_secs();
    let live: Vec<&Arc<Device>> = devs.iter().filter(|d| d.confirmed.load(Ordering::Relaxed)).collect();
    if live.len() >= max && !live.iter().any(|d| t - d.last_rx.load(Ordering::Relaxed) >= IDLE_GIVES_WAY) {
        return None;
    }
    let ip = if devs.iter().any(|d| d.ip == p.ip) { sh.free_addr(&peers.by_ip)? } else { p.ip };
    let d = Arc::new(Device {
        id,
        ip,
        ip6: sh.v6_of(ip),
        user: Arc::downgrade(p),
        endpoint: Mutex::new(None),
        current: RwLock::new(None),
        st: Mutex::new(DevState::default()),
        confirmed: AtomicBool::new(false),
        last_rx: AtomicI64::new(0),
        made: Instant::now(),
    });
    peers.by_ip.insert(IpAddr::V4(ip), d.clone());
    if let Some(a) = d.ip6 {
        peers.by_ip.insert(IpAddr::V6(a), d.clone());
    }
    devs.push(d.clone());
    Some(d)
}

fn handle_init(sh: &Shared, pkt: &[u8], from: SocketAddr) {
    let found = {
        let peers = sh.peers.read().unwrap();
        peers.list.iter().find_map(|p| parse_init(&p.keys, pkt).map(|m| (p.clone(), m)))
    };
    let Some((p, m)) = found else { return };
    // an init is taken once: a newer timestamp than the device's last, or one near our clock whose
    // ephemeral key is new (a client whose clock went back)
    let now = now_nanos();
    let last = p.devices.lock().unwrap().iter().find(|d| d.id == m.dev).map(|d| d.st.lock().unwrap().last_ts).unwrap_or(0);
    if !ts_ok(m.ts, last, now) {
        return;
    }
    {
        let mut seen = p.seen.lock().unwrap();
        while seen.front().is_some_and(|(_, t)| t.elapsed() > SEEN_FOR) || seen.len() > 256 {
            seen.pop_front();
        }
        if seen.iter().any(|(e, _)| *e == m.eph) {
            return; // a replayed init
        }
        seen.push_back((m.eph, Instant::now()));
    }
    let Some(d) = device_for(sh, &p, m.dev) else { return };
    let eph = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
    let eph_pub = PublicKey::from(&eph).to_bytes();
    let shared = eph.diffie_hellman(&PublicKey::from(m.eph));
    if !shared.was_contributory() {
        return;
    }
    let mut st = d.st.lock().unwrap();
    st.last_ts = st.last_ts.max(m.ts);
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
        dev: Arc::downgrade(&d),
    });
    if let Some(old) = st.pending.take() {
        sessions.remove(&old.local);
    }
    sessions.insert(idx, sess.clone());
    st.pending = Some(sess);
    drop(sessions);
    drop(st);
    // a v2 client (no device id) is not told its address: it has the one of its link
    let addrs = (m.dev != 0).then_some(Addrs { v4: d.ip, v6: d.ip6 });
    let resp = build_resp(&sh.obfs, &p.keys, &eph_pub, idx, m.idx, &m.eph, pkt.len(), addrs);
    let _ = sh.sock.send_to(&resp, from);
}

/// a pending session becomes current once the client sent data with it: a replayed init never
/// displaces a working session. A device's first data makes it count; past the user's limit the
/// device heard from least recently goes (a quiet one: `device_for` lets no new device in otherwise).
fn confirm(sh: &Shared, d: &Arc<Device>, sess: &Arc<Session>) {
    {
        let mut st = d.st.lock().unwrap();
        if !st.pending.as_ref().map(|x| Arc::ptr_eq(x, sess)).unwrap_or(false) {
            return; // data on the previous session
        }
        if let Some(prev) = st.prev.take() {
            sh.sessions.write().unwrap().remove(&prev.local);
        }
        let mut cur = d.current.write().unwrap();
        st.prev = cur.take();
        *cur = st.pending.take();
    }
    d.last_rx.store(now_secs(), Ordering::Relaxed);
    if d.confirmed.swap(true, Ordering::Relaxed) {
        return;
    }
    let Some(p) = d.user.upgrade() else { return };
    let mut peers = sh.peers.write().unwrap();
    let mut devs = p.devices.lock().unwrap();
    loop {
        let live: Vec<&Arc<Device>> = devs.iter().filter(|x| x.confirmed.load(Ordering::Relaxed)).collect();
        if live.len() <= p.max.load(Ordering::Relaxed) {
            break;
        }
        let Some(old) = live.into_iter().filter(|x| !Arc::ptr_eq(x, d)).min_by_key(|x| x.last_rx.load(Ordering::Relaxed)).cloned() else { break };
        sh.drop_device(&mut peers, &old);
        devs.retain(|x| !Arc::ptr_eq(x, &old));
    }
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
            let devs = p.devices.lock().unwrap().clone();
            let mut empty = vec![];
            for d in devs {
                let mut st = d.st.lock().unwrap();
                let mut gone = vec![];
                if st.prev.as_ref().map(|s| s.expired()).unwrap_or(false) {
                    gone.extend(st.prev.take().map(|s| s.local));
                }
                if st.pending.as_ref().map(|s| s.born.elapsed() > PENDING_FOR).unwrap_or(false) {
                    gone.extend(st.pending.take().map(|s| s.local));
                }
                let mut cur = d.current.write().unwrap();
                if cur.as_ref().map(|s| s.expired()).unwrap_or(false) {
                    gone.extend(cur.take().map(|s| s.local));
                }
                // a device with no session left (gone for 3 minutes, or one that never confirmed)
                // frees its address
                if cur.is_none() && st.pending.is_none() && st.prev.is_none() && d.made.elapsed() > PENDING_FOR {
                    empty.push(d.clone());
                }
                drop(cur);
                drop(st);
                let mut sessions = sh.sessions.write().unwrap();
                for i in gone {
                    sessions.remove(&i);
                }
            }
            if !empty.is_empty() {
                let mut peers = sh.peers.write().unwrap();
                let mut devs = p.devices.lock().unwrap();
                for d in empty {
                    sh.drop_device(&mut peers, &d);
                    devs.retain(|x| !Arc::ptr_eq(x, &d));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A client side written against the Go microtun v2 wire format
    fn build_init(obfs: &Aes256, k: &PskKeys, eph: &[u8; 32], ts: u64, idx: u32) -> Vec<u8> {
        build_init_ext(obfs, k, eph, ts, idx, &[])
    }

    /// … with what follows the body (a v2.1 device id, or v2 random padding)
    fn build_init_ext(obfs: &Aes256, k: &PskKeys, eph: &[u8; 32], ts: u64, idx: u32, ext: &[u8]) -> Vec<u8> {
        let mut body = eph.to_vec();
        body.extend_from_slice(&ts.to_be_bytes());
        body.extend_from_slice(&idx.to_be_bytes());
        body.extend_from_slice(ext);
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
        let mut resp = build_resp(&obfs, &k, &se_pub, 77, 5, &ce_pub, init.len(), None);
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
            dev: Weak::new(),
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
    fn device_id_and_addresses() {
        let obfs = Aes256::new(&[7u8; 32].into());
        let k = PskKeys::new([9u8; 32]);
        let eph = [3u8; 32];
        // v2.1: "mtD1" + the device id, then padding
        let mut ext = EXT_DEV.to_vec();
        ext.extend_from_slice(&0x1122334455667788u64.to_be_bytes());
        ext.extend_from_slice(&[0xAB; 20]);
        let mut init = build_init_ext(&obfs, &k, &eph, 9, 5, &ext);
        mask(&obfs, &mut init);
        assert_eq!(parse_init(&k, &init).unwrap().dev, 0x1122334455667788);
        // v2: random padding is no device id
        let mut init2 = build_init_ext(&obfs, &k, &eph, 9, 5, &[0x55; 30]);
        mask(&obfs, &mut init2);
        assert_eq!(parse_init(&k, &init2).unwrap().dev, 0);

        // the response carries the addresses when the init left room, and is never larger
        let a = Addrs { v4: Ipv4Addr::new(10, 80, 3, 4), v6: Some("fd79:4d54::a50:304".parse().unwrap()) };
        let open = |init_len: usize| {
            let mut r = build_resp(&obfs, &k, &[4u8; 32], 77, 5, &eph, init_len, Some(a));
            assert!(r.len() <= init_len.max(HDR + RESP_BODY + TAG));
            mask(&obfs, &mut r);
            let aad = [&r[..HDR], &eph[..]].concat();
            k.resp.decrypt(Nonce::from_slice(&r[..HDR]), Payload { msg: &r[HDR..], aad: &aad }).unwrap()
        };
        let pt = open(init.len());
        assert_eq!(&pt[RESP_BODY..RESP_BODY + 4], EXT_ADDR);
        assert_eq!(&pt[RESP_BODY + 4..RESP_BODY + 8], &[10, 80, 3, 4]);
        assert_eq!(pt[RESP_BODY + 8], 1);
        assert_eq!(Ipv6Addr::from(<[u8; 16]>::try_from(&pt[RESP_BODY + 9..RESP_BODY + 25]).unwrap()), a.v6.unwrap());
        let small = open(HDR + INIT_BODY + TAG);
        assert!(small.len() < RESP_BODY + 4 || &small[RESP_BODY..RESP_BODY + 4] != EXT_ADDR);
    }

    #[test]
    fn clock_going_back() {
        let now = 1_700_000_000_000_000_000u64;
        assert!(ts_ok(now, now - 1, now), "newer than the last one");
        assert!(ts_ok(now - 60_000_000_000, now, now), "older, but near our clock");
        assert!(!ts_ok(now - 600_000_000_000, now - 300_000_000_000, now), "older and far from our clock: a replay");
        assert!(ts_ok(now + 3_600_000_000_000, 0, now), "a first init from a client whose clock is off");
    }

    #[test]
    fn device_subnet() {
        let n = Net4::parse("10.80.0.1/16").unwrap();
        assert_eq!((Ipv4Addr::from(n.base), n.size), (Ipv4Addr::new(10, 80, 0, 0), 65536));
        assert!(Net4::parse("10.80.0.1/31").is_none());
        assert_eq!(subnet6_of("fd79:4d54::1/64").unwrap().1, "fd79:4d54::/64");
        assert!(subnet6_of("fd79:4d54::1/48").is_none());
        let p = ip_src(&{
            let mut v = vec![0x60u8; 40];
            v[8..24].copy_from_slice(&"fd79:4d54::a4f:2".parse::<Ipv6Addr>().unwrap().octets());
            v
        });
        assert_eq!(p, Some(IpAddr::V6("fd79:4d54::a4f:2".parse().unwrap())));
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
