//! The datagram fast path of the cores: game UDP as datagrams of their own, next to the stream.
//!
//! ```text
//!  datagram = 0xD7 | sid (8, BE) | counter (8, BE) | ChaCha20-Poly1305(session key, body)
//!  body app -> server = flow (4, BE) | target length (1) | target "ip:port" | UDP payload
//!  body server -> app = flow (4, BE) | UDP payload
//!  sealed               = 0x00 | body                                   (fits one datagram)
//!                       | 0x01 | message (2) | index (1) | count (1) | piece   (a big body, cut)
//! ```
//!
//! The session key comes fresh from the server inside the encrypted stream, so a datagram can only
//! be made or read by the one session. The nonce is the direction and the counter; a copy of a
//! datagram (small packets are sent two or three times) has the same counter, and the receiver's
//! window keeps only the first one. On `game` the datagram rides inside the mask next to the KCP
//! datagrams; on `hq` it is a QUIC datagram.

use super::super::salamander::Mask;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::net::UdpSocket;

pub const TAG: u8 = 0xD7;
/// tag + sid + counter
pub const HEAD: usize = 17;
/// Poly1305 tag
pub const SEAL: usize = 16;
/// largest datagram body on `game`: the mask keeps a datagram at 1232 bytes or less (with a little
/// padding room), minus our head and seal
pub const GAME_MAX_BODY: usize = 1180 - HEAD - SEAL;
/// a datagram this small or smaller is sent `copies` times (game packets); bigger ones once
pub const DUP_MAX: usize = 400;
/// how many datagrams behind the newest one may still arrive (late or reordered)
const WINDOW: u64 = 2048;
/// a big body is cut into at most this many datagrams (a bigger one is not sent)
const MAX_PIECES: usize = 8;
const WHOLE: u8 = 0;
const PIECE: u8 = 1;
/// big bodies being put back together at once (older ones are dropped)
const MAX_PENDING: usize = 16;

const DIR_UP: u8 = 1;
const DIR_DOWN: u8 = 2;

/// Where sealed datagrams go out.
pub enum Wire {
    /// `game`: a masked UDP datagram; `to` = None on a connected socket (the app), else the app's
    /// latest address (the server; it follows the app when its address changes)
    Udp { sock: Arc<UdpSocket>, mask: Arc<Mask>, to: Mutex<Option<SocketAddr>> },
    /// `hq`: a QUIC datagram
    Quic(quinn::Connection),
}

impl Wire {
    fn send(&self, d: &[u8], copies: u8) {
        match self {
            Wire::Udp { sock, mask, to } => {
                let to = *to.lock().unwrap();
                let mut out = Vec::with_capacity(1300);
                for _ in 0..copies.max(1) {
                    // every copy gets its own salt and padding, so the copies do not look alike
                    out.clear();
                    mask.seal(d, &mut out);
                    let _ = match to {
                        Some(t) => sock.try_send_to(&out, t),
                        None => sock.try_send(&out),
                    };
                }
            }
            // QUIC puts datagrams in its own packets and would pack two copies into one; it is
            // sent once and QUIC's pacing keeps it on time
            Wire::Quic(c) => {
                let _ = c.send_datagram(bytes::Bytes::copy_from_slice(d));
            }
        }
    }
}

/// Seen counters: the newest one and a bitmap of the `WINDOW` before it.
#[derive(Default)]
struct Replay {
    top: u64,
    bits: [u64; (WINDOW / 64) as usize],
}

impl Replay {
    fn bit(&mut self, c: u64) -> (&mut u64, u64) {
        let i = (c % WINDOW) as usize;
        (&mut self.bits[i / 64], 1u64 << (i % 64))
    }
    /// true = new (and now marked), false = a copy or too old
    fn check(&mut self, c: u64) -> bool {
        if c == 0 {
            return false;
        }
        if c > self.top {
            // slide: forget the slots the window moved over
            let gap = c - self.top;
            if gap >= WINDOW {
                self.bits = [0; (WINDOW / 64) as usize];
            } else {
                for x in self.top + 1..=c {
                    let (w, m) = self.bit(x);
                    *w &= !m;
                }
            }
            self.top = c;
            let (w, m) = self.bit(c);
            *w |= m;
            return true;
        }
        if self.top - c >= WINDOW {
            return false;
        }
        let (w, m) = self.bit(c);
        if *w & m != 0 {
            return false;
        }
        *w |= m;
        true
    }
}

/// One end of a session's datagram path.
pub struct DgLink {
    pub sid: u64,
    aead: ChaCha20Poly1305,
    /// direction of what this end sends
    dir_tx: u8,
    ctr: AtomicU64,
    seen: Mutex<Replay>,
    pub wire: Wire,
    /// copies of a small datagram (1 = no duplication)
    pub copies: u8,
    /// largest sealed body of one datagram (a bigger body is cut into pieces)
    pub max_body: usize,
    msg: std::sync::atomic::AtomicU16,
    /// (message, the pieces so far) of the big bodies being put back together
    pending: Mutex<std::collections::VecDeque<(u16, Vec<Option<Vec<u8>>>)>>,
}

impl DgLink {
    /// `app` = this end is the app (it sends "up", the server "down")
    pub fn new(sid: u64, key: &[u8; 32], app: bool, wire: Wire, copies: u8, max_body: usize) -> DgLink {
        DgLink {
            sid,
            aead: ChaCha20Poly1305::new(Key::from_slice(key)),
            dir_tx: if app { DIR_UP } else { DIR_DOWN },
            ctr: AtomicU64::new(1),
            seen: Mutex::new(Replay::default()),
            wire,
            copies: copies.clamp(1, 3),
            max_body,
            msg: std::sync::atomic::AtomicU16::new(0),
            pending: Mutex::new(Default::default()),
        }
    }

    fn nonce(dir: u8, c: u64) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[0] = dir;
        n[4..].copy_from_slice(&c.to_be_bytes());
        n
    }

    /// The sealed datagram of `body` (without sending it).
    pub fn seal(&self, body: &[u8]) -> Vec<u8> {
        let c = self.ctr.fetch_add(1, Ordering::Relaxed);
        let ct = self.aead.encrypt(Nonce::from_slice(&Self::nonce(self.dir_tx, c)), body).unwrap_or_default();
        let mut d = Vec::with_capacity(HEAD + ct.len());
        d.push(TAG);
        d.extend_from_slice(&self.sid.to_be_bytes());
        d.extend_from_slice(&c.to_be_bytes());
        d.extend_from_slice(&ct);
        d
    }

    /// Seals and sends `body`; small bodies go `copies` times, a big one is cut into pieces.
    /// false = too big even for that.
    pub fn send(&self, body: &[u8]) -> bool {
        if body.len() < self.max_body {
            let copies = if body.len() <= DUP_MAX { self.copies } else { 1 };
            let mut p = Vec::with_capacity(1 + body.len());
            p.push(WHOLE);
            p.extend_from_slice(body);
            self.wire.send(&self.seal(&p), copies);
            return true;
        }
        let room = self.max_body.saturating_sub(5).max(1);
        let count = body.len().div_ceil(room);
        if count > MAX_PIECES {
            return false;
        }
        let m = self.msg.fetch_add(1, Ordering::Relaxed);
        for (i, piece) in body.chunks(room).enumerate() {
            let mut p = Vec::with_capacity(5 + piece.len());
            p.push(PIECE);
            p.extend_from_slice(&m.to_be_bytes());
            p.push(i as u8);
            p.push(count as u8);
            p.extend_from_slice(piece);
            self.wire.send(&self.seal(&p), 1);
        }
        true
    }

    /// A piece of a big body: the whole body once the last piece is in.
    fn join(&self, p: &[u8]) -> Option<Vec<u8>> {
        if p.len() < 4 {
            return None;
        }
        let (m, i, n) = (u16::from_be_bytes([p[0], p[1]]), p[2] as usize, p[3] as usize);
        if n == 0 || n > MAX_PIECES || i >= n {
            return None;
        }
        let mut q = self.pending.lock().unwrap();
        let at = match q.iter().position(|(x, v)| *x == m && v.len() == n) {
            Some(at) => at,
            None => {
                if q.len() >= MAX_PENDING {
                    q.pop_front();
                }
                q.push_back((m, vec![None; n]));
                q.len() - 1
            }
        };
        q[at].1[i] = Some(p[4..].to_vec());
        if q[at].1.iter().any(|x| x.is_none()) {
            return None;
        }
        let (_, parts) = q.remove(at)?;
        Some(parts.into_iter().flatten().flatten().collect())
    }

    /// The body of a datagram from the other end, or None (not ours, damaged, or a copy).
    pub fn open(&self, d: &[u8]) -> Option<Vec<u8>> {
        if d.len() < HEAD + SEAL || d[0] != TAG || sid_of(d)? != self.sid {
            return None;
        }
        let c = u64::from_be_bytes(d[9..17].try_into().ok()?);
        let dir_rx = if self.dir_tx == DIR_UP { DIR_DOWN } else { DIR_UP };
        let body = self.aead.decrypt(Nonce::from_slice(&Self::nonce(dir_rx, c)), &d[HEAD..]).ok()?;
        // only a datagram that opened counts as seen: garbage cannot move the window
        if !self.seen.lock().unwrap().check(c) {
            return None;
        }
        match body.first()? {
            &WHOLE => Some(body[1..].to_vec()),
            &PIECE => self.join(&body[1..]),
            _ => None,
        }
    }
}

/// The session id of a datagram (before it is opened)
pub fn sid_of(d: &[u8]) -> Option<u64> {
    (d.len() >= HEAD && d[0] == TAG).then(|| u64::from_be_bytes(d[1..9].try_into().unwrap()))
}

/// app -> server body
pub fn up_body(flow: u32, target: &str, data: &[u8]) -> Vec<u8> {
    let t = target.as_bytes();
    let mut b = Vec::with_capacity(5 + t.len() + data.len());
    b.extend_from_slice(&flow.to_be_bytes());
    b.push(t.len() as u8);
    b.extend_from_slice(t);
    b.extend_from_slice(data);
    b
}

/// app -> server body -> (flow, target, data)
pub fn parse_up(b: &[u8]) -> Option<(u32, &str, &[u8])> {
    if b.len() < 5 {
        return None;
    }
    let flow = u32::from_be_bytes(b[..4].try_into().ok()?);
    let tl = b[4] as usize;
    let t = std::str::from_utf8(b.get(5..5 + tl)?).ok()?;
    Some((flow, t, &b[5 + tl..]))
}

/// server -> app body
pub fn down_body(flow: u32, data: &[u8]) -> Vec<u8> {
    let mut b = Vec::with_capacity(4 + data.len());
    b.extend_from_slice(&flow.to_be_bytes());
    b.extend_from_slice(data);
    b
}

pub fn parse_down(b: &[u8]) -> Option<(u32, &[u8])> {
    (b.len() >= 4).then(|| (u32::from_be_bytes(b[..4].try_into().unwrap()), &b[4..]))
}

/// Marks a UDP socket's packets as interactive (DSCP EF), with big buffers. Routers and the
/// phone's own Wi-Fi queue that honour it send game packets first; the rest ignore it.
pub fn tune_udp(sock: &UdpSocket) {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        let fd = sock.as_raw_fd();
        let set = |level: libc::c_int, name: libc::c_int, v: libc::c_int| unsafe {
            libc::setsockopt(fd, level, name, &v as *const libc::c_int as *const libc::c_void, std::mem::size_of::<libc::c_int>() as libc::socklen_t);
        };
        set(libc::IPPROTO_IP, libc::IP_TOS, 0xB8);
        set(libc::IPPROTO_IPV6, libc::IPV6_TCLASS, 0xB8);
        set(libc::SOL_SOCKET, libc::SO_RCVBUF, 4 << 20);
        set(libc::SOL_SOCKET, libc::SO_SNDBUF, 4 << 20);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn pair() -> (DgLink, DgLink) {
        let key = [7u8; 32];
        let mut v = vec![];
        for app in [true, false] {
            let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
            v.push(DgLink::new(42, &key, app, Wire::Udp { sock, mask: Arc::new(Mask::new("x")), to: Mutex::new(None) }, 2, 1000));
        }
        let srv = v.pop().unwrap();
        (v.pop().unwrap(), srv)
    }

    #[tokio::test]
    async fn copies_are_dropped_and_directions_differ() {
        let (app, srv) = pair().await;
        let d = app.seal(b"\0hello");
        assert_eq!(srv.open(&d).as_deref(), Some(&b"hello"[..]));
        assert_eq!(srv.open(&d), None, "the second copy is dropped");
        // a datagram never opens on the side that made it (direction is in the nonce)
        assert_eq!(app.open(&app.seal(b"x")), None);
        let back = srv.seal(b"\0pong");
        assert_eq!(app.open(&back).as_deref(), Some(&b"pong"[..]));
    }

    #[tokio::test]
    async fn late_datagrams_inside_the_window_still_count() {
        let (app, srv) = pair().await;
        let a = app.seal(b"\x001");
        let b = app.seal(b"\x002");
        assert!(srv.open(&b).is_some());
        assert!(srv.open(&a).is_some(), "reordered, not a copy");
        for _ in 0..WINDOW + 5 {
            app.seal(b"");
        }
        let old = a.clone();
        assert!(srv.open(&app.seal(b"\0new")).is_some());
        assert!(srv.open(&old).is_none());
    }

    #[tokio::test]
    async fn damaged_or_foreign_datagrams_do_not_open() {
        let (app, srv) = pair().await;
        let mut d = app.seal(b"\0hello");
        let last = d.len() - 1;
        d[last] ^= 1;
        assert!(srv.open(&d).is_none());
        let mut other = app.seal(b"\0hello");
        other[1] ^= 1; // another session id
        assert!(srv.open(&other).is_none());
    }

    #[tokio::test]
    async fn big_bodies_are_cut_and_joined() {
        let (app, srv) = pair().await;
        let big: Vec<u8> = (0..5000u32).map(|i| i as u8).collect();
        // seal the pieces the way `send` does, but keep them to feed them back out of order
        let room = app.max_body - 5;
        let n = big.len().div_ceil(room);
        let mut ds = vec![];
        for (i, piece) in big.chunks(room).enumerate() {
            let mut p = vec![PIECE, 0, 9, i as u8, n as u8];
            p.extend_from_slice(piece);
            ds.push(app.seal(&p));
        }
        ds.reverse();
        let mut got = None;
        for d in &ds {
            if let Some(b) = srv.open(d) {
                got = Some(b);
            }
        }
        assert_eq!(got.as_deref(), Some(&big[..]));
        assert!(!app.send(&vec![0u8; 20_000]), "too big even in pieces");
    }

    #[test]
    fn bodies_round_trip() {
        let b = up_body(9, "1.2.3.4:5", b"data");
        assert_eq!(parse_up(&b), Some((9, "1.2.3.4:5", &b"data"[..])));
        assert_eq!(parse_down(&down_body(3, b"x")), Some((3, &b"x"[..])));
        assert!(parse_up(&[0, 0, 0, 1, 50, b'a']).is_none());
    }
}
