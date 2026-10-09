//! Salamander-style masking of UDP datagrams, used under the QUIC of the `hq` transport.
//!
//! QUIC has a recognisable first packet (flags byte, version, connection ids, a 1200-byte padded
//! Initial). A filter that sees UDP can classify and cut it by those bytes alone. So every datagram
//! quinn sends is wrapped before it leaves the machine, and unwrapped when it arrives:
//!
//! ```text
//!   wire = salt(8) | mask( tag(4) | pad_len(1) | pad(pad_len) | quic_datagram )
//! ```
//!
//! * `salt` is fresh random bytes for every datagram. It is the nonce of a ChaCha20 keystream whose
//!   key comes from the shared secret (the tunnel token), so the masked part is a plain XOR with a
//!   keystream: no byte on the wire is fixed, and two packets never share a pattern. This is the
//!   idea of Hysteria 2's "Salamander", with a stream cipher instead of a repeating 32-byte XOR.
//! * `tag` is a 4-byte value known to both ends (derived from the secret). A datagram that does not
//!   unmask to the right tag is not ours: it is dropped *silently*, before QUIC sees it. A scanner
//!   or a probe therefore gets no answer at all, not even a QUIC "version negotiation".
//! * `pad` is random filler of random length, so the size of a datagram does not tell what it is
//!   (an ACK, a window update and a full data packet no longer have three typical sizes). Big
//!   packets get little padding (it would only cost speed), small ones get a lot. A datagram never
//!   grows past `MAX_WIRE` bytes, which fits a path MTU of 1280 (the IPv6 minimum).
//!
//! This is obfuscation, not encryption: QUIC (TLS 1.3) and the token handshake on top of it do the
//! real security. The mask only has to leave nothing to recognise.

use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use rand::RngCore;
use sha2::{Digest, Sha256};

/// random bytes in front of every datagram (the keystream nonce)
pub const SALT: usize = 8;
/// bytes of the check value
pub const TAG: usize = 4;
/// what is added in front of the payload, without the padding: salt + tag + pad length
pub const HEAD: usize = SALT + TAG + 1;
/// no datagram leaves bigger than this (unless QUIC itself produced a bigger one)
pub const MAX_WIRE: usize = 1232;

#[derive(Clone)]
pub struct Mask {
    key: [u8; 32],
    tag: [u8; TAG],
}

impl Mask {
    pub fn new(secret: &str) -> Mask {
        let mut h = Sha256::new();
        h.update(b"kanki-hq-mask-key|");
        h.update(secret.as_bytes());
        let key: [u8; 32] = h.finalize().into();
        let mut h = Sha256::new();
        h.update(b"kanki-hq-mask-tag|");
        h.update(secret.as_bytes());
        let t: [u8; 32] = h.finalize().into();
        let mut tag = [0u8; TAG];
        tag.copy_from_slice(&t[..TAG]);
        Mask { key, tag }
    }

    /// XORs `data` with the keystream of this salt (the same call masks and unmasks).
    fn xor(&self, salt: &[u8; SALT], data: &mut [u8]) {
        // ChaCha20 wants a 12-byte nonce: the 8 salt bytes and 4 zero bytes
        let mut n12 = [0u8; 12];
        n12[..SALT].copy_from_slice(salt);
        let key = &self.key;
        let mut c = ChaCha20::new(key.into(), (&n12).into());
        c.apply_keystream(data);
    }

    /// How many bytes of padding a payload of this size may get at most.
    pub fn pad_cap(len: usize) -> usize {
        let room = MAX_WIRE.saturating_sub(HEAD + len);
        let want = if len > 900 {
            32
        } else if len > 400 {
            96
        } else {
            255
        };
        room.min(want)
    }

    /// Appends the masked datagram for `payload` to `out`.
    pub fn seal(&self, payload: &[u8], out: &mut Vec<u8>) {
        let mut rng = rand::thread_rng();
        let cap = Mask::pad_cap(payload.len());
        let pad = if cap == 0 { 0 } else { (rng.next_u32() as usize) % (cap + 1) };
        let start = out.len();
        out.reserve(HEAD + pad + payload.len());
        let mut salt = [0u8; SALT];
        rng.fill_bytes(&mut salt);
        out.extend_from_slice(&salt);
        out.extend_from_slice(&self.tag);
        out.push(pad as u8);
        let pad_at = out.len();
        out.resize(pad_at + pad, 0);
        rng.fill_bytes(&mut out[pad_at..]);
        out.extend_from_slice(payload);
        self.xor(&salt, &mut out[start + SALT..]);
    }

    /// Unmasks `pkt` in place. Returns where the payload is inside `pkt` (start..end), or `None`
    /// when the datagram is not ours (wrong tag, too short, impossible padding length).
    /// Garbage costs one keystream block, not a full decryption.
    pub fn open(&self, pkt: &mut [u8]) -> Option<(usize, usize)> {
        if pkt.len() < HEAD + 1 {
            return None;
        }
        let mut salt = [0u8; SALT];
        salt.copy_from_slice(&pkt[..SALT]);
        let mut head = [0u8; TAG + 1];
        head.copy_from_slice(&pkt[SALT..SALT + TAG + 1]);
        self.xor(&salt, &mut head);
        if head[..TAG] != self.tag[..] {
            return None;
        }
        let start = HEAD + head[TAG] as usize;
        if start >= pkt.len() {
            return None;
        }
        self.xor(&salt, &mut pkt[SALT..]);
        Some((start, pkt.len()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i * 7 + 3) as u8).collect()
    }

    #[test]
    fn roundtrip_many_sizes() {
        let m = Mask::new("token-123");
        for n in [1usize, 2, 17, 40, 399, 400, 401, 899, 900, 901, 1200, 1219, 1232, 1500] {
            let p = sample(n);
            let mut wire = vec![];
            m.seal(&p, &mut wire);
            assert!(wire.len() >= HEAD + n, "wire is shorter than payload+head for n={}", n);
            if n + HEAD <= MAX_WIRE {
                assert!(wire.len() <= MAX_WIRE, "n={} grew to {}", n, wire.len());
            }
            let (s, e) = m.open(&mut wire).expect("own packet must open");
            assert_eq!(&wire[s..e], &p[..], "payload differs for n={}", n);
        }
    }

    #[test]
    fn wrong_secret_is_dropped() {
        let a = Mask::new("one");
        let b = Mask::new("two");
        let mut ok = 0;
        for _ in 0..500 {
            let mut wire = vec![];
            a.seal(&sample(100), &mut wire);
            if b.open(&mut wire).is_some() {
                ok += 1;
            }
        }
        assert_eq!(ok, 0, "a packet masked with another secret was accepted");
    }

    #[test]
    fn garbage_is_dropped() {
        let m = Mask::new("secret");
        let mut rng = rand::thread_rng();
        let mut accepted = 0;
        for i in 0..20000usize {
            let mut junk = vec![0u8; 14 + (i % 1300)];
            rng.fill_bytes(&mut junk);
            if m.open(&mut junk).is_some() {
                accepted += 1;
            }
        }
        // the chance per packet is 2^-32
        assert_eq!(accepted, 0, "random bytes passed the tag check");
    }

    #[test]
    fn too_short_and_bad_padding() {
        let m = Mask::new("secret");
        assert!(m.open(&mut [0u8; 0]).is_none());
        assert!(m.open(&mut [0u8; HEAD]).is_none());
        // a correct header whose pad length points past the end must be refused
        let mut wire = vec![];
        m.seal(&sample(3), &mut wire);
        wire.truncate(HEAD + 1);
        // after truncation the pad (if any) may exceed the length; either way it must not panic
        let _ = m.open(&mut wire);
    }

    #[test]
    fn nothing_fixed_on_the_wire() {
        // the same payload sealed twice never looks the same, and no byte position is constant
        let m = Mask::new("secret");
        let p = sample(120);
        let mut first_bytes = std::collections::HashSet::new();
        let mut lens = std::collections::HashSet::new();
        for _ in 0..400 {
            let mut w = vec![];
            m.seal(&p, &mut w);
            first_bytes.insert(w[0]);
            lens.insert(w.len());
        }
        assert!(first_bytes.len() > 100, "first byte has only {} values", first_bytes.len());
        assert!(lens.len() > 100, "datagram length has only {} values", lens.len());
    }

    #[test]
    fn big_packets_get_little_padding() {
        let m = Mask::new("secret");
        let p = sample(1200);
        for _ in 0..200 {
            let mut w = vec![];
            m.seal(&p, &mut w);
            assert!(w.len() <= HEAD + 1200 + 32);
        }
    }

    #[test]
    fn appends_after_existing_bytes() {
        let m = Mask::new("secret");
        let mut out = vec![9u8, 9, 9];
        m.seal(&sample(50), &mut out);
        assert_eq!(&out[..3], &[9, 9, 9]);
        let mut wire = out[3..].to_vec();
        let (s, e) = m.open(&mut wire).unwrap();
        assert_eq!(&wire[s..e], &sample(50)[..]);
    }
}
