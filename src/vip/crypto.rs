//! VIP tunnel: keys and packets.
//!
//! **Handshake.** Both servers hold the tunnel's secret (the panel gives it to both). The dialer sends an
//! X25519 public key and, with `pq`, an ML-KEM-768 encapsulation key; the listener answers with its own
//! X25519 key and the ML-KEM ciphertext. The session keys come from HKDF-SHA256 over the secret, the X25519
//! result and the ML-KEM result, salted with a hash of both messages: a side without the secret gets
//! nothing, and a secret that leaks later opens no recorded session unless X25519 **and** ML-KEM are both
//! broken. Every handshake packet is sealed with a key made from the secret and a random salt, so it has no
//! fixed byte either, and a big message travels in pieces of ordinary size.
//!
//! **Packets.** `header (8, masked) | ChaCha20-Poly1305 ciphertext | tag (16)`. The header is the path
//! number and that path's packet counter; it is the nonce, and it is hidden under a mask made from the
//! tag (header protection, as in QUIC), so nothing on the wire repeats or counts up. A packet that does not
//! open is dropped without an answer.

use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use chacha20poly1305::aead::AeadInPlace;
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce, Tag};
use hkdf::Hkdf;
use ml_kem::kem::{Decapsulate, KeyExport, TryKeyInit};
use ml_kem::{DecapsulationKey768, EncapsulationKey768};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// masked header: path (1) + packet number (7)
pub const HDR: usize = 8;
pub const TAG: usize = 16;
/// what a packet costs on top of its frames
pub const OVERHEAD: usize = HDR + TAG;
/// the two clocks may differ by this much (seconds); an older or newer first message gets no answer
pub const MAX_SKEW: u64 = 900;
const VER: u8 = 1;
const FLAG_PQ: u8 = 1;
const EK_LEN: usize = 1184;
const CT_LEN: usize = 1088;
/// handshake piece: kind, message id, index, total, length
const HS_HEAD: usize = 1 + 8 + 1 + 1 + 2;
const HS_SALT: usize = 16;
pub const HS_INIT: u8 = 1;
pub const HS_RESP: u8 = 2;

/// The tunnel secret as a key (any text; the panel makes 64 hex characters)
pub fn psk_of(secret: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"kanki-vip-psk|");
    h.update(secret.as_bytes());
    h.finalize().into()
}

/// A second secret for a carrier that has its own mask or token (fake TCP, the stream links)
pub fn sub_token(psk: &[u8; 32], label: &str) -> String {
    let hk = Hkdf::<Sha256>::new(Some(b"kanki-vip-carrier"), psk);
    let mut out = [0u8; 24];
    let _ = hk.expand(label.as_bytes(), &mut out);
    hex::encode(out)
}

// ------------------------------------------------------------------ packets

/// One direction of a session
pub struct Dir {
    aead: ChaCha20Poly1305,
    hp: [u8; 32],
}

impl Dir {
    fn new(key: &[u8], hp: &[u8]) -> Dir {
        let mut h = [0u8; 32];
        h.copy_from_slice(hp);
        Dir { aead: ChaCha20Poly1305::new(Key::from_slice(key)), hp: h }
    }

    fn mask(&self, tag: &[u8]) -> [u8; HDR] {
        let mut n = [0u8; 12];
        n.copy_from_slice(&tag[..12]);
        let mut m = [0u8; HDR];
        let mut c = ChaCha20::new((&self.hp).into(), (&n).into());
        c.apply_keystream(&mut m);
        m
    }

    /// Appends the packet of `payload` (frames) to `out`
    pub fn seal(&self, path: u8, pn: u64, payload: &[u8], out: &mut Vec<u8>) {
        let start = out.len();
        let mut hdr = (pn & 0x00ff_ffff_ffff_ffff).to_be_bytes();
        hdr[0] = path;
        out.extend_from_slice(&hdr);
        out.extend_from_slice(payload);
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&hdr);
        let tag = match self.aead.encrypt_in_place_detached(Nonce::from_slice(&nonce), b"", &mut out[start + HDR..]) {
            Ok(t) => t,
            Err(_) => {
                // only a payload of gigabytes fails: nothing of it leaves
                out.truncate(start);
                return;
            }
        };
        out.extend_from_slice(&tag);
        let m = self.mask(&tag);
        for (i, b) in m.iter().enumerate() {
            out[start + i] ^= b;
        }
    }

    /// Opens a packet in place: (path, packet number, payload length); the payload is `pkt[HDR..HDR + len]`.
    /// A packet that is not ours leaves `pkt` as it was (another key may still open it).
    pub fn open(&self, pkt: &mut [u8]) -> Option<(u8, u64, usize)> {
        if pkt.len() < OVERHEAD {
            return None;
        }
        let n = pkt.len();
        let (body, tag) = pkt.split_at_mut(n - TAG);
        let m = self.mask(tag);
        let mut hdr = [0u8; HDR];
        for i in 0..HDR {
            hdr[i] = body[i] ^ m[i];
        }
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&hdr);
        let tag = Tag::clone_from_slice(tag);
        self.aead.decrypt_in_place_detached(Nonce::from_slice(&nonce), b"", &mut body[HDR..], &tag).ok()?;
        let path = hdr[0];
        hdr[0] = 0;
        Some((path, u64::from_be_bytes(hdr), n - OVERHEAD))
    }
}

/// The keys of one handshake
pub struct Keys {
    pub tx: Dir,
    pub rx: Dir,
    /// made with ML-KEM next to X25519
    pub pq: bool,
}

fn derive(psk: &[u8; 32], dh: &[u8], kem: Option<&[u8]>, init: &[u8], resp: &[u8], dialer: bool) -> Keys {
    let mut t = Sha256::new();
    t.update(init);
    t.update(resp);
    let salt = t.finalize();
    let mut ikm = Vec::with_capacity(96);
    ikm.extend_from_slice(psk);
    ikm.extend_from_slice(dh);
    if let Some(k) = kem {
        ikm.extend_from_slice(k);
    }
    let hk = Hkdf::<Sha256>::new(Some(&salt[..]), &ikm);
    let mut okm = [0u8; 128];
    let _ = hk.expand(b"kanki-vip keys v1", &mut okm);
    let d2l = Dir::new(&okm[..32], &okm[32..64]);
    let l2d = Dir::new(&okm[64..96], &okm[96..128]);
    let (tx, rx) = if dialer { (d2l, l2d) } else { (l2d, d2l) };
    Keys { tx, rx, pq: kem.is_some() }
}

/// Sliding window over the packet numbers of one path: a packet is taken once
pub struct Replay {
    top: u64,
    any: bool,
    bits: [u64; 32],
}

impl Default for Replay {
    fn default() -> Self {
        Replay { top: 0, any: false, bits: [0; 32] }
    }
}

impl Replay {
    const SPAN: u64 = 32 * 64;

    /// true = new (and now marked); false = seen before, or too old to tell
    pub fn take(&mut self, pn: u64) -> bool {
        if !self.any {
            self.any = true;
            self.top = pn;
            self.bits = [0; 32];
            self.bits[0] = 1;
            return true;
        }
        if pn > self.top {
            let shift = pn - self.top;
            if shift >= Self::SPAN {
                self.bits = [0; 32];
            } else {
                let (words, bits) = ((shift / 64) as usize, (shift % 64) as u32);
                for i in (0..32).rev() {
                    let mut v = if i >= words { self.bits[i - words] << bits } else { 0 };
                    if bits > 0 && i > words {
                        v |= self.bits[i - words - 1] >> (64 - bits);
                    }
                    self.bits[i] = v;
                }
            }
            self.bits[0] |= 1;
            self.top = pn;
            return true;
        }
        let back = self.top - pn;
        if back >= Self::SPAN {
            return false;
        }
        let (w, b) = ((back / 64) as usize, back % 64);
        if self.bits[w] & (1 << b) != 0 {
            return false;
        }
        self.bits[w] |= 1 << b;
        true
    }
}

// ------------------------------------------------------------------ handshake packets

fn hs_cipher(psk: &[u8; 32], salt: &[u8]) -> ChaCha20Poly1305 {
    let hk = Hkdf::<Sha256>::new(Some(salt), psk);
    let mut k = [0u8; 32];
    let _ = hk.expand(b"kanki-vip hs v1", &mut k);
    ChaCha20Poly1305::new(Key::from_slice(&k))
}

/// One piece of a handshake message as it arrived
pub struct HsPart {
    pub kind: u8,
    pub id: [u8; 8],
    pub idx: u8,
    pub total: u8,
    pub chunk: Vec<u8>,
}

/// The packets of one handshake message: pieces of at most `chunk` bytes, each with up to `pad` random
/// bytes of filler
pub fn hs_seal(psk: &[u8; 32], kind: u8, id: &[u8; 8], body: &[u8], chunk: usize, pad: usize) -> Vec<Vec<u8>> {
    let mut rng = rand::thread_rng();
    let chunk = chunk.clamp(64, 1200);
    let parts: Vec<&[u8]> = if body.is_empty() { vec![&[][..]] } else { body.chunks(chunk).collect() };
    let total = parts.len().min(255) as u8;
    let mut out = Vec::with_capacity(parts.len());
    for (i, p) in parts.iter().enumerate().take(255) {
        let fill = if pad == 0 { 0 } else { (rng.next_u32() as usize) % (pad + 1) };
        let mut pkt = vec![0u8; HS_SALT];
        rng.fill_bytes(&mut pkt);
        let cipher = hs_cipher(psk, &pkt[..HS_SALT]);
        let at = pkt.len();
        pkt.push(kind);
        pkt.extend_from_slice(id);
        pkt.push(i as u8);
        pkt.push(total);
        pkt.extend_from_slice(&(p.len() as u16).to_be_bytes());
        pkt.extend_from_slice(p);
        let f = pkt.len();
        pkt.resize(f + fill, 0);
        rng.fill_bytes(&mut pkt[f..]);
        let Ok(tag) = cipher.encrypt_in_place_detached(Nonce::from_slice(&[0u8; 12]), b"", &mut pkt[at..]) else { continue };
        pkt.extend_from_slice(&tag);
        out.push(pkt);
    }
    out
}

/// A handshake piece, when `pkt` is one made with this secret
pub fn hs_open(psk: &[u8; 32], pkt: &[u8]) -> Option<HsPart> {
    if pkt.len() < HS_SALT + HS_HEAD + TAG {
        return None;
    }
    let cipher = hs_cipher(psk, &pkt[..HS_SALT]);
    let mut body = pkt[HS_SALT..pkt.len() - TAG].to_vec();
    let tag = Tag::clone_from_slice(&pkt[pkt.len() - TAG..]);
    cipher.decrypt_in_place_detached(Nonce::from_slice(&[0u8; 12]), b"", &mut body, &tag).ok()?;
    let kind = body[0];
    let mut id = [0u8; 8];
    id.copy_from_slice(&body[1..9]);
    let (idx, total) = (body[9], body[10]);
    let len = u16::from_be_bytes([body[11], body[12]]) as usize;
    if total == 0 || idx >= total || HS_HEAD + len > body.len() {
        return None;
    }
    Some(HsPart { kind, id, idx, total, chunk: body[HS_HEAD..HS_HEAD + len].to_vec() })
}

/// Puts the pieces of handshake messages back together
#[derive(Default)]
pub struct HsAsm {
    msgs: HashMap<([u8; 8], u8), (Instant, Vec<Option<Vec<u8>>>)>,
}

impl HsAsm {
    /// The whole message once its last piece is here
    pub fn add(&mut self, p: HsPart) -> Option<(u8, [u8; 8], Vec<u8>)> {
        if p.total == 1 {
            return Some((p.kind, p.id, p.chunk));
        }
        if p.total > 8 {
            return None;
        }
        let now = Instant::now();
        self.msgs.retain(|_, v| now.duration_since(v.0) < Duration::from_secs(8));
        if self.msgs.len() >= 32 && !self.msgs.contains_key(&(p.id, p.kind)) {
            return None;
        }
        let e = self.msgs.entry((p.id, p.kind)).or_insert_with(|| (now, vec![None; p.total as usize]));
        if e.1.len() != p.total as usize {
            return None;
        }
        e.1[p.idx as usize] = Some(p.chunk);
        if e.1.iter().any(|x| x.is_none()) {
            return None;
        }
        let (_, parts) = self.msgs.remove(&(p.id, p.kind))?;
        Some((p.kind, p.id, parts.into_iter().flatten().flatten().collect()))
    }
}

// ------------------------------------------------------------------ the handshake itself

/// Why a first message was not answered
#[derive(Debug, PartialEq)]
pub enum HsErr {
    /// not a message of this version
    Bad,
    /// the two servers' clocks differ by this many seconds
    Skew(u64),
}

/// The dialer's half of a handshake that waits for its answer
pub struct Initiator {
    secret: Option<x25519_dalek::EphemeralSecret>,
    kem: Option<DecapsulationKey768>,
    body: Vec<u8>,
    nonce: [u8; 8],
}

impl Initiator {
    /// `instance`: 8 random bytes that stay the same while this side keeps its state (a rekey), and change
    /// when it starts again
    pub fn new(instance: &[u8; 8], pq: bool, now: u64) -> Initiator {
        let mut rng = rand::rngs::OsRng;
        let secret = x25519_dalek::EphemeralSecret::random_from_rng(rng);
        let public = x25519_dalek::PublicKey::from(&secret);
        let mut nonce = [0u8; 8];
        rng.fill_bytes(&mut nonce);
        let mut body = Vec::with_capacity(64 + if pq { EK_LEN } else { 0 });
        body.push(VER);
        body.push(if pq { FLAG_PQ } else { 0 });
        body.extend_from_slice(&now.to_be_bytes());
        body.extend_from_slice(instance);
        body.extend_from_slice(&nonce);
        body.extend_from_slice(public.as_bytes());
        let kem = pq.then(|| {
            let mut seed = [0u8; 64];
            rng.fill_bytes(&mut seed);
            DecapsulationKey768::from_seed(seed.into())
        });
        if let Some(dk) = &kem {
            body.extend_from_slice(&dk.encapsulation_key().to_bytes()[..]);
        }
        Initiator { secret: Some(secret), kem, body, nonce }
    }

    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// The id its packets travel under (the answer comes back under the same)
    pub fn id(&self) -> [u8; 8] {
        self.nonce
    }

    /// The session keys and the listener's instance, from its answer. None = not an answer to this message.
    pub fn finish(&mut self, psk: &[u8; 32], resp: &[u8]) -> Option<(Keys, [u8; 8])> {
        let pq = self.kem.is_some();
        let want = 2 + 8 + 8 + 32 + if pq { CT_LEN } else { 0 };
        if resp.len() != want || resp[0] != VER || (resp[1] & FLAG_PQ != 0) != pq || resp[10..18] != self.nonce {
            return None;
        }
        let mut inst = [0u8; 8];
        inst.copy_from_slice(&resp[2..10]);
        let mut theirs = [0u8; 32];
        theirs.copy_from_slice(&resp[18..50]);
        let ss = match &self.kem {
            Some(dk) => Some(dk.decapsulate_slice(&resp[50..]).ok()?),
            None => None,
        };
        let dh = self.secret.take()?.diffie_hellman(&x25519_dalek::PublicKey::from(theirs));
        if !dh.was_contributory() {
            return None;
        }
        Some((derive(psk, dh.as_bytes(), ss.as_ref().map(|k| &k[..]), &self.body, resp, true), inst))
    }
}

/// What the listener learns from a first message
pub struct Accepted {
    pub resp: Vec<u8>,
    pub keys: Keys,
    /// the dialer's instance
    pub peer: [u8; 8],
}

/// The listener's half: the answer to send and the session keys
pub fn respond(psk: &[u8; 32], init: &[u8], instance: &[u8; 8], now: u64) -> Result<Accepted, HsErr> {
    if init.len() < 58 || init[0] != VER {
        return Err(HsErr::Bad);
    }
    let pq = init[1] & FLAG_PQ != 0;
    if init.len() != 58 + if pq { EK_LEN } else { 0 } {
        return Err(HsErr::Bad);
    }
    let t = u64::from_be_bytes(init[2..10].try_into().map_err(|_| HsErr::Bad)?);
    let diff = t.abs_diff(now);
    if diff > MAX_SKEW {
        return Err(HsErr::Skew(diff));
    }
    let mut peer = [0u8; 8];
    peer.copy_from_slice(&init[10..18]);
    let mut nonce = [0u8; 8];
    nonce.copy_from_slice(&init[18..26]);
    let mut theirs = [0u8; 32];
    theirs.copy_from_slice(&init[26..58]);
    let mut rng = rand::rngs::OsRng;
    let secret = x25519_dalek::EphemeralSecret::random_from_rng(rng);
    let public = x25519_dalek::PublicKey::from(&secret);
    let mut resp = Vec::with_capacity(50 + if pq { CT_LEN } else { 0 });
    resp.push(VER);
    resp.push(if pq { FLAG_PQ } else { 0 });
    resp.extend_from_slice(instance);
    resp.extend_from_slice(&nonce);
    resp.extend_from_slice(public.as_bytes());
    let ss = if pq {
        let ek = EncapsulationKey768::new_from_slice(&init[58..]).map_err(|_| HsErr::Bad)?;
        let mut m = [0u8; 32];
        rng.fill_bytes(&mut m);
        let (ct, k) = ek.encapsulate_deterministic(&m.into());
        resp.extend_from_slice(&ct[..]);
        Some(k)
    } else {
        None
    };
    let dh = secret.diffie_hellman(&x25519_dalek::PublicKey::from(theirs));
    if !dh.was_contributory() {
        return Err(HsErr::Bad);
    }
    let keys = derive(psk, dh.as_bytes(), ss.as_ref().map(|k| &k[..]), init, &resp, false);
    Ok(Accepted { resp, keys, peer })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair(pq: bool) -> (Keys, Keys) {
        let psk = psk_of("s3cret");
        let mut i = Initiator::new(&[1; 8], pq, 1000);
        let a = respond(&psk, i.body(), &[2; 8], 1010).expect("answer");
        assert_eq!(a.peer, [1; 8]);
        let (k, inst) = i.finish(&psk, &a.resp).expect("keys");
        assert_eq!(inst, [2; 8]);
        assert_eq!(k.pq, pq);
        (k, a.keys)
    }

    #[test]
    fn both_ends_get_the_same_keys() {
        for pq in [false, true] {
            let (d, l) = pair(pq);
            let mut w = vec![];
            d.tx.seal(3, 77, b"hello over the line", &mut w);
            let (path, pn, n) = l.rx.open(&mut w).expect("opens");
            assert_eq!((path, pn), (3, 77));
            assert_eq!(&w[HDR..HDR + n], b"hello over the line");
            // the other direction has its own key: a packet does not open with the sender's own
            let mut w2 = vec![];
            l.tx.seal(0, 1, b"back", &mut w2);
            assert!(l.rx.open(&mut w2.clone()).is_none());
            assert!(d.rx.open(&mut w2).is_some());
        }
    }

    #[test]
    fn a_wrong_secret_gets_nothing() {
        let mut i = Initiator::new(&[1; 8], true, 1000);
        let a = respond(&psk_of("right"), i.body(), &[2; 8], 1000).unwrap();
        let (k, _) = i.finish(&psk_of("wrong"), &a.resp).unwrap();
        let mut w = vec![];
        a.keys.tx.seal(0, 0, b"x", &mut w);
        assert!(k.rx.open(&mut w).is_none());
        // and its handshake packets do not even open
        let pk = hs_seal(&psk_of("right"), HS_INIT, &[9; 8], b"abc", 600, 40);
        assert!(hs_open(&psk_of("wrong"), &pk[0]).is_none());
        assert!(hs_open(&psk_of("right"), &pk[0]).is_some());
    }

    #[test]
    fn a_changed_packet_does_not_open_and_stays_as_it_was() {
        let (d, l) = pair(false);
        let mut w = vec![];
        d.tx.seal(1, 5, &[7u8; 200], &mut w);
        for at in [0usize, 4, 9, 100, w.len() - 1] {
            let mut bad = w.clone();
            bad[at] ^= 1;
            let before = bad.clone();
            assert!(l.rx.open(&mut bad).is_none(), "byte {}", at);
            assert_eq!(bad, before);
        }
        assert!(l.rx.open(&mut w).is_some());
    }

    #[test]
    fn nothing_on_the_wire_repeats() {
        let (d, _) = pair(false);
        let (mut a, mut b) = (vec![], vec![]);
        d.tx.seal(0, 1, &[0u8; 64], &mut a);
        d.tx.seal(0, 2, &[0u8; 64], &mut b);
        // two packets in a row of the same path with the same content share no header byte pattern
        assert_ne!(a[..HDR], b[..HDR]);
        let same = a.iter().zip(&b).filter(|(x, y)| x == y).count();
        assert!(same < 12, "{} equal bytes of {}", same, a.len());
    }

    #[test]
    fn a_big_message_travels_in_pieces() {
        let psk = psk_of("k");
        let i = Initiator::new(&[1; 8], true, 5);
        let pk = hs_seal(&psk, HS_INIT, &i.id(), i.body(), 700, 120);
        assert_eq!(pk.len(), 2);
        assert!(pk.iter().all(|p| p.len() < 900));
        let mut asm = HsAsm::default();
        // out of order, and one piece twice
        assert!(asm.add(hs_open(&psk, &pk[1]).unwrap()).is_none());
        assert!(asm.add(hs_open(&psk, &pk[1]).unwrap()).is_none());
        let (kind, id, body) = asm.add(hs_open(&psk, &pk[0]).unwrap()).expect("whole");
        assert_eq!((kind, id), (HS_INIT, i.id()));
        assert_eq!(body, i.body());
    }

    #[test]
    fn an_old_first_message_gets_no_answer() {
        let psk = psk_of("k");
        let i = Initiator::new(&[1; 8], false, 1000);
        assert_eq!(respond(&psk, i.body(), &[2; 8], 1000 + MAX_SKEW + 1).err(), Some(HsErr::Skew(MAX_SKEW + 1)));
        assert!(respond(&psk, i.body(), &[2; 8], 1000 + MAX_SKEW).is_ok());
        assert_eq!(respond(&psk, &i.body()[..40], &[2; 8], 1000).err(), Some(HsErr::Bad));
    }

    #[test]
    fn an_answer_to_another_message_is_refused() {
        let psk = psk_of("k");
        let mut a = Initiator::new(&[1; 8], false, 1);
        let b = Initiator::new(&[1; 8], false, 1);
        let rb = respond(&psk, b.body(), &[2; 8], 1).unwrap();
        assert!(a.finish(&psk, &rb.resp).is_none());
    }

    #[test]
    fn replay_window() {
        let mut r = Replay::default();
        assert!(r.take(10));
        assert!(!r.take(10));
        assert!(r.take(9));
        assert!(r.take(11));
        assert!(!r.take(9));
        assert!(r.take(11 + 2000));
        assert!(r.take(12));
        assert!(!r.take(12));
        // older than the window: cannot be told from a copy
        assert!(r.take(5000));
        assert!(!r.take(5000 - Replay::SPAN));
        assert!(r.take(5000 - Replay::SPAN + 1));
        // a jump past the whole window forgets it
        assert!(r.take(1_000_000));
        assert!(r.take(999_999));
        assert!(!r.take(1_000_000));
    }
}
