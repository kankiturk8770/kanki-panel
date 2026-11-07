//! The datagram lane of the `game` transport: user UDP packets that skip the ordered KCP stream.
//!
//! A `game` link is one KCP stream: reliable and in order. That is right for TCP, but a game's UDP
//! packet that rides behind a lost packet waits until that one is sent again (head-of-line
//! blocking), and the ping jumps. On this lane every UDP packet of the mux (small enough to fit one
//! datagram) travels on its own, next to the KCP traffic, through the same relay: masked, FEC-coded
//! and duplicated like the rest, but never held for another packet. A lost one that FEC cannot
//! rebuild is simply gone, as on a plain UDP path (games and WireGuard expect that).
//!
//! Wire payload (inside the mask, inside the FEC shard): `MAGIC (4) | counter (8, BE) | AEAD`,
//! ChaCha20-Poly1305 with a key of its own per link and direction, derived from the link's key
//! exchange (`link::handshake`), nonce = the counter. Replays are refused with a 128-packet window.
//! A KCP datagram starts with its conversation id; one that happens to start with MAGIC fails the
//! AEAD check and goes to KCP as before.
//!
//! The same lane rides the other UDP transports: `kcp` (its obfuscation relay, like `game`) and
//! `quic` / `hq` (QUIC's own unreliable datagrams, RFC 9221). TCP transports have no unordered
//! path; there the UDP and TCP links are only kept apart (`engine::lane`).
//!
//! The lane is only used after both ends said so (`DGOK` mux frame, `mux.rs`): an old end ignores
//! the frame and the link keeps sending everything through KCP.

use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

pub const MAGIC: [u8; 4] = [0xD9, b'k', b'g', 0x01];
const HEAD: usize = 4 + 8;
const TAG: usize = 16;
/// Largest wire payload: the same budget as one KCP datagram of the game transport
pub const MAX_WIRE: usize = 1080;
/// Largest mux frame that goes on this lane; a bigger one takes the KCP stream
pub const MAX_FRAME: usize = MAX_WIRE - HEAD - TAG;
/// Packets waiting between the relay and the session; past it the newest are dropped (a game
/// packet that would wait longer is useless anyway)
const QUEUE: usize = 512;
const WINDOW: u64 = 128;

pub fn looks_like(p: &[u8]) -> bool {
    p.len() > HEAD + TAG && p[..4] == MAGIC
}

/// The relay's half: what the session wants sent, and where received payloads go.
pub struct RelayEnd {
    pub out: mpsc::Receiver<Vec<u8>>,
    pub inbox: mpsc::Sender<Vec<u8>>,
}

/// The session's half, handed over with the link (`link::Raw::Dg`).
pub struct Port {
    out: mpsc::Sender<Vec<u8>>,
    inbox: Mutex<Option<mpsc::Receiver<Vec<u8>>>>,
    /// biggest wire payload the carrier takes (QUIC datagrams may be smaller than MAX_WIRE)
    max: usize,
    /// how many times each payload is sent: 2 on carriers without FEC (`kcp`, `faketcp`, `quic`,
    /// `hq`), so a lost game packet is not gone (the replay window drops the second copy); 1 on
    /// `game`, whose relay has FEC (and its own duplication switch)
    copies: usize,
}

impl Port {
    /// A lane on a carrier with FEC (`game`): every payload once
    pub fn pair() -> (Arc<Port>, RelayEnd) {
        Port::pair_with(MAX_WIRE, 1)
    }
    /// A lane on a carrier without FEC: every payload twice
    pub fn pair_twice(max: usize) -> (Arc<Port>, RelayEnd) {
        Port::pair_with(max, 2)
    }
    fn pair_with(max: usize, copies: usize) -> (Arc<Port>, RelayEnd) {
        let (out_tx, out_rx) = mpsc::channel(QUEUE);
        let (in_tx, in_rx) = mpsc::channel(QUEUE);
        (Arc::new(Port { out: out_tx, inbox: Mutex::new(Some(in_rx)), max: max.min(MAX_WIRE), copies }), RelayEnd { out: out_rx, inbox: in_tx })
    }
    /// The received payloads (once: the session's reader takes them)
    pub fn take_inbox(&self) -> Option<mpsc::Receiver<Vec<u8>>> {
        self.inbox.lock().unwrap_or_else(|e| e.into_inner()).take()
    }
}

/// The two keys of a link's datagram lane (`link::handshake`)
#[derive(Clone)]
pub struct Keys {
    pub tx: [u8; 32],
    pub rx: [u8; 32],
}

/// A key of this lane from a link key: separate from the stream's, so the two never share a nonce
pub fn derive(link_key: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"kanki-tunnel-dgram-v1");
    h.update(link_key);
    h.finalize().into()
}

/// Sliding replay window (the WireGuard way): the highest counter seen and a bitmap behind it
#[derive(Default)]
struct Replay {
    top: u64,
    bits: u128,
    any: bool,
}

impl Replay {
    fn check(&mut self, n: u64) -> bool {
        if !self.any {
            self.any = true;
            self.top = n;
            self.bits = 1;
            return true;
        }
        if n > self.top {
            let d = n - self.top;
            self.bits = if d >= WINDOW { 1 } else { (self.bits << d) | 1 };
            self.top = n;
            return true;
        }
        let d = self.top - n;
        if d >= WINDOW || self.bits & (1u128 << d) != 0 {
            return false;
        }
        self.bits |= 1u128 << d;
        true
    }
}

/// One link's lane, owned by its mux session.
pub struct Lane {
    port: Arc<Port>,
    tx: ChaCha20Poly1305,
    rx: ChaCha20Poly1305,
    ctr: AtomicU64,
    replay: Mutex<Replay>,
    /// the other end said it has the lane too
    pub on: AtomicBool,
}

fn nonce(n: u64) -> [u8; 12] {
    let mut b = [0u8; 12];
    b[4..].copy_from_slice(&n.to_be_bytes());
    b
}

impl Lane {
    pub fn new(port: Arc<Port>, k: &Keys) -> Lane {
        Lane {
            port,
            tx: ChaCha20Poly1305::new(Key::from_slice(&k.tx)),
            rx: ChaCha20Poly1305::new(Key::from_slice(&k.rx)),
            ctr: AtomicU64::new(0),
            replay: Mutex::new(Replay::default()),
            on: AtomicBool::new(false),
        }
    }
    pub fn port(&self) -> &Arc<Port> {
        &self.port
    }
    /// frame -> wire payload
    pub fn seal(&self, frame: &[u8]) -> Option<Vec<u8>> {
        if frame.len() > MAX_FRAME || frame.len() + HEAD + TAG > self.port.max {
            return None;
        }
        let n = self.ctr.fetch_add(1, Ordering::Relaxed);
        let ct = self.tx.encrypt(Nonce::from_slice(&nonce(n)), frame).ok()?;
        let mut v = Vec::with_capacity(HEAD + ct.len());
        v.extend_from_slice(&MAGIC);
        v.extend_from_slice(&n.to_be_bytes());
        v.extend_from_slice(&ct);
        Some(v)
    }
    /// Sends a frame on the lane. false = not sent (lane not agreed yet, frame too big, queue
    /// full): the caller sends it on the stream instead.
    pub fn send(&self, frame: &[u8]) -> bool {
        if !self.on.load(Ordering::Relaxed) {
            return false;
        }
        let Some(w) = self.seal(frame) else { return false };
        if self.port.copies > 1 && self.port.out.try_send(w.clone()).is_err() {
            return false;
        }
        // the copy that counts: when it does not fit, the caller sends the frame on the stream
        self.port.out.try_send(w).is_ok()
    }
    /// wire payload -> frame (None: not ours, damaged or replayed)
    pub fn open(&self, w: &[u8]) -> Option<Vec<u8>> {
        if !looks_like(w) {
            return None;
        }
        let n = u64::from_be_bytes(w[4..12].try_into().ok()?);
        let f = self.rx.decrypt(Nonce::from_slice(&nonce(n)), &w[HEAD..]).ok()?;
        if !self.replay.lock().unwrap_or_else(|e| e.into_inner()).check(n) {
            return None;
        }
        Some(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lanes() -> (Lane, Lane) {
        let (a, b) = ([7u8; 32], [9u8; 32]);
        let (pa, _ea) = Port::pair();
        let (pb, _eb) = Port::pair();
        (Lane::new(pa, &Keys { tx: derive(&a), rx: derive(&b) }), Lane::new(pb, &Keys { tx: derive(&b), rx: derive(&a) }))
    }

    #[test]
    fn frames_cross_once_and_in_any_order() {
        let (x, y) = lanes();
        let w: Vec<Vec<u8>> = (0..5u8).map(|i| x.seal(&[i; 40]).unwrap()).collect();
        assert!(looks_like(&w[0]));
        // out of order is fine, twice is not (the duplicate copy of a packet)
        for i in [3usize, 0, 4, 1, 2] {
            assert_eq!(y.open(&w[i]).unwrap(), vec![i as u8; 40]);
        }
        assert!(y.open(&w[2]).is_none());
        // the wrong direction's key, damage, and a KCP-looking packet are refused
        assert!(x.open(&w[0]).is_none());
        let mut bad = x.seal(&[1; 10]).unwrap();
        let l = bad.len();
        bad[l - 1] ^= 1;
        assert!(y.open(&bad).is_none());
        assert!(y.open(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29]).is_none());
        // too big for one datagram: the caller uses the stream
        assert!(x.seal(&vec![0; MAX_FRAME + 1]).is_none());
        assert!(x.seal(&vec![0; MAX_FRAME]).unwrap().len() <= MAX_WIRE);
    }

    #[test]
    fn sends_only_after_both_ends_agreed() {
        let (p, mut end) = Port::pair();
        let k = [3u8; 32];
        let x = Lane::new(p, &Keys { tx: k, rx: k });
        assert!(!x.send(b"frame"));
        x.on.store(true, Ordering::Relaxed);
        assert!(x.send(b"frame"));
        let w = end.out.try_recv().unwrap();
        assert_eq!(x.open(&w).unwrap(), b"frame");
    }

    #[test]
    fn a_small_carrier_sends_big_frames_on_the_stream() {
        let (p, _end) = Port::pair_twice(200);
        let k = [3u8; 32];
        let x = Lane::new(p, &Keys { tx: k, rx: k });
        assert!(x.seal(&[0; 200 - HEAD - TAG]).is_some());
        assert!(x.seal(&[0; 200 - HEAD - TAG + 1]).is_none());
    }

    #[test]
    fn without_fec_every_payload_goes_twice_and_arrives_once() {
        let (p, mut end) = Port::pair_twice(MAX_WIRE);
        let k = [5u8; 32];
        let x = Lane::new(p, &Keys { tx: k, rx: k });
        x.on.store(true, Ordering::Relaxed);
        assert!(x.send(b"shot"));
        let (a, b) = (end.out.try_recv().unwrap(), end.out.try_recv().unwrap());
        assert!(end.out.try_recv().is_err());
        assert_eq!(x.open(&a).unwrap(), b"shot");
        assert!(x.open(&b).is_none(), "the second copy is a replay");
        // with FEC (game): once
        let (p1, mut e1) = Port::pair();
        let y = Lane::new(p1, &Keys { tx: k, rx: k });
        y.on.store(true, Ordering::Relaxed);
        assert!(y.send(b"shot"));
        assert!(e1.out.try_recv().is_ok() && e1.out.try_recv().is_err());
    }

    #[test]
    fn replay_window() {
        let mut r = Replay::default();
        assert!(r.check(10));
        assert!(r.check(12));
        assert!(r.check(11));
        assert!(!r.check(11));
        assert!(r.check(300));
        assert!(!r.check(300 - WINDOW));
        assert!(r.check(300 - WINDOW + 1));
    }
}
