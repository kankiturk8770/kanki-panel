//! VIP tunnel: what a packet carries.
//!
//! The payload of a packet is a row of frames, `type (1) | length (2) | body`, and then filler (type 0: the
//! rest of the packet means nothing). Data frames carry a sequence number of their class and an *inner*
//! block: one user datagram or one datagram of the stream layer. Repairs are made of inner blocks, so a
//! rebuilt packet is delivered exactly like one that arrived.

use rand::RngCore;
use std::collections::HashMap;
use std::time::{Duration, Instant};

const T_PAD: u8 = 0;
const T_PING: u8 = 1;
const T_PONG: u8 = 2;
const T_REPORT: u8 = 3;
const T_RT: u8 = 0x10;
const T_BULK: u8 = 0x11;
const T_RT_FIX: u8 = 0x12;
const T_BULK_FIX: u8 = 0x13;
const T_FRAG: u8 = 0x20;

/// type + length
pub const FRAME_HEAD: usize = 3;
/// a data frame on top of its inner block: the frame head, the lane and the sequence number
pub const DATA_HEAD: usize = FRAME_HEAD + 5;
/// a fragment frame on top of its chunk
pub const FRAG_HEAD: usize = FRAME_HEAD + 6;

/// inner block kinds
pub const IN_UDP: u8 = 1;
pub const IN_QUIC: u8 = 2;
pub const IN_ECHO: u8 = 3;
pub const IN_ECHO_BACK: u8 = 4;
/// an inner UDP block on top of the user's datagram: kind, port index, flow
pub const UDP_HEAD: usize = 6;

#[derive(Debug, PartialEq)]
pub enum Frame<'a> {
    /// `t`: the sender's clock (ms), sent back as it is
    Ping { id: u32, t: u32 },
    /// `gen`: the key generation the counters belong to; `hi`: the highest packet number seen on this path;
    /// `cnt`: how many packets arrived on it
    Pong { id: u32, t: u32, gen: u8, hi: u64, cnt: u64 },
    /// what the receiver delivered of each class: the newest sequence number and the count (rebuilt ones in)
    Report { rt_top: u32, rt_got: u64, bulk_top: u32, bulk_got: u64 },
    /// `lane`: which interleaved lane of the bulk class (0 for realtime); `seq` counts within it
    Data { bulk: bool, lane: u8, seq: u32, inner: &'a [u8] },
    /// a repair of one class (`lane`: which interleaved lane of the bulk class)
    Fix { bulk: bool, lane: u8, rlc: &'a [u8] },
    /// a piece of a payload too big for one packet of its path
    Frag { id: u32, idx: u8, total: u8, chunk: &'a [u8] },
}

fn head(out: &mut Vec<u8>, t: u8, len: usize) {
    out.push(t);
    out.extend_from_slice(&(len as u16).to_be_bytes());
}

/// Appends one frame
pub fn put(out: &mut Vec<u8>, f: &Frame) {
    match f {
        Frame::Ping { id, t } => {
            head(out, T_PING, 8);
            out.extend_from_slice(&id.to_be_bytes());
            out.extend_from_slice(&t.to_be_bytes());
        }
        Frame::Pong { id, t, gen, hi, cnt } => {
            head(out, T_PONG, 25);
            out.extend_from_slice(&id.to_be_bytes());
            out.extend_from_slice(&t.to_be_bytes());
            out.push(*gen);
            out.extend_from_slice(&hi.to_be_bytes());
            out.extend_from_slice(&cnt.to_be_bytes());
        }
        Frame::Report { rt_top, rt_got, bulk_top, bulk_got } => {
            head(out, T_REPORT, 24);
            out.extend_from_slice(&rt_top.to_be_bytes());
            out.extend_from_slice(&rt_got.to_be_bytes());
            out.extend_from_slice(&bulk_top.to_be_bytes());
            out.extend_from_slice(&bulk_got.to_be_bytes());
        }
        Frame::Data { bulk, lane, seq, inner } => {
            if *bulk {
                head(out, T_BULK, 5 + inner.len());
                out.push(*lane);
            } else {
                head(out, T_RT, 4 + inner.len());
            }
            out.extend_from_slice(&seq.to_be_bytes());
            out.extend_from_slice(inner);
        }
        Frame::Fix { bulk, lane, rlc } => {
            if *bulk {
                head(out, T_BULK_FIX, 1 + rlc.len());
                out.push(*lane);
            } else {
                head(out, T_RT_FIX, rlc.len());
            }
            out.extend_from_slice(rlc);
        }
        Frame::Frag { id, idx, total, chunk } => {
            head(out, T_FRAG, 6 + chunk.len());
            out.extend_from_slice(&id.to_be_bytes());
            out.push(*idx);
            out.push(*total);
            out.extend_from_slice(chunk);
        }
    }
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn u64_at(b: &[u8], at: usize) -> u64 {
    let mut v = [0u8; 8];
    v.copy_from_slice(&b[at..at + 8]);
    u64::from_be_bytes(v)
}

/// The frames of a payload, in order. A frame that is cut short or of a type this version does not know
/// ends the walk (an unknown type with a sound length is skipped: a newer peer may send it).
pub struct Frames<'a> {
    b: &'a [u8],
}

pub fn frames(payload: &[u8]) -> Frames<'_> {
    Frames { b: payload }
}

impl<'a> Iterator for Frames<'a> {
    type Item = Frame<'a>;

    fn next(&mut self) -> Option<Frame<'a>> {
        loop {
            if self.b.len() < FRAME_HEAD || self.b[0] == T_PAD {
                return None;
            }
            let t = self.b[0];
            let len = u16::from_be_bytes([self.b[1], self.b[2]]) as usize;
            if FRAME_HEAD + len > self.b.len() {
                return None;
            }
            let body = &self.b[FRAME_HEAD..FRAME_HEAD + len];
            self.b = &self.b[FRAME_HEAD + len..];
            let f = match t {
                T_PING if len == 8 => Frame::Ping { id: u32_at(body, 0), t: u32_at(body, 4) },
                T_PONG if len == 25 => Frame::Pong { id: u32_at(body, 0), t: u32_at(body, 4), gen: body[8], hi: u64_at(body, 9), cnt: u64_at(body, 17) },
                T_REPORT if len == 24 => Frame::Report { rt_top: u32_at(body, 0), rt_got: u64_at(body, 4), bulk_top: u32_at(body, 12), bulk_got: u64_at(body, 16) },
                T_RT if len > 4 => Frame::Data { bulk: false, lane: 0, seq: u32_at(body, 0), inner: &body[4..] },
                T_BULK if len > 5 => Frame::Data { bulk: true, lane: body[0], seq: u32_at(body, 1), inner: &body[5..] },
                T_RT_FIX if len > 0 => Frame::Fix { bulk: false, lane: 0, rlc: body },
                T_BULK_FIX if len > 1 => Frame::Fix { bulk: true, lane: body[0], rlc: &body[1..] },
                T_FRAG if len > 6 => Frame::Frag { id: u32_at(body, 0), idx: body[4], total: body[5], chunk: &body[6..] },
                _ => continue,
            };
            return Some(f);
        }
    }
}

/// An inner block of one user datagram
pub fn inner_udp(pidx: u8, flow: u32, data: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(UDP_HEAD + data.len());
    v.push(IN_UDP);
    v.push(pidx);
    v.extend_from_slice(&flow.to_be_bytes());
    v.extend_from_slice(data);
    v
}

/// An inner block of one datagram of the stream layer
pub fn inner_quic(data: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(1 + data.len());
    v.push(IN_QUIC);
    v.extend_from_slice(data);
    v
}

/// An echo of the quality check (and its answer): the number and the sender's clock
pub fn inner_echo(back: bool, id: u32, t: u32) -> Vec<u8> {
    let mut v = Vec::with_capacity(9);
    v.push(if back { IN_ECHO_BACK } else { IN_ECHO });
    v.extend_from_slice(&id.to_be_bytes());
    v.extend_from_slice(&t.to_be_bytes());
    v
}

pub enum Inner<'a> {
    Udp { pidx: u8, flow: u32, data: &'a [u8] },
    Quic(&'a [u8]),
    Echo { back: bool, id: u32, t: u32 },
}

pub fn inner(b: &[u8]) -> Option<Inner<'_>> {
    match *b.first()? {
        IN_UDP if b.len() >= UDP_HEAD => Some(Inner::Udp { pidx: b[1], flow: u32_at(b, 2), data: &b[UDP_HEAD..] }),
        IN_QUIC if b.len() > 1 => Some(Inner::Quic(&b[1..])),
        k @ (IN_ECHO | IN_ECHO_BACK) if b.len() == 9 => Some(Inner::Echo { back: k == IN_ECHO_BACK, id: u32_at(b, 1), t: u32_at(b, 5) }),
        _ => None,
    }
}

/// How many filler bytes a payload of `len` gets (`stealth`: 0 none, 1 a little, 2 more). Small packets
/// (pings, game packets, acknowledgements) get the most: their size says the most about what they are.
pub fn filler(stealth: u8, len: usize, room: usize) -> usize {
    let max = match (stealth, len) {
        (0, _) => 0,
        (1, 0..=199) => 48,
        (1, 200..=799) => 24,
        (1, _) => 0,
        (_, 0..=199) => 160,
        (_, 200..=799) => 64,
        _ => 16,
    };
    let max = max.min(room);
    if max == 0 { 0 } else { (rand::thread_rng().next_u32() as usize) % (max + 1) }
}

/// Appends `n` filler bytes: the first is the padding mark, the rest random
pub fn pad(out: &mut Vec<u8>, n: usize) {
    if n == 0 {
        return;
    }
    let at = out.len();
    out.resize(at + n, 0);
    rand::thread_rng().fill_bytes(&mut out[at + 1..]);
}

/// Cuts a payload that does not fit one packet into fragment payloads of at most `max` bytes each
pub fn fragments(id: u32, payload: &[u8], max: usize) -> Vec<Vec<u8>> {
    let room = max.saturating_sub(FRAG_HEAD).max(64);
    let total = payload.len().div_ceil(room);
    if total > 255 {
        return vec![];
    }
    payload
        .chunks(room)
        .enumerate()
        .map(|(i, c)| {
            let mut v = Vec::with_capacity(FRAG_HEAD + c.len());
            put(&mut v, &Frame::Frag { id, idx: i as u8, total: total as u8, chunk: c });
            v
        })
        .collect()
}

/// Puts fragments of one path back together
#[derive(Default)]
pub struct Reasm {
    parts: HashMap<u32, (Instant, Vec<Option<Vec<u8>>>)>,
}

impl Reasm {
    /// The whole payload once its last piece is here
    pub fn add(&mut self, id: u32, idx: u8, total: u8, chunk: &[u8], now: Instant) -> Option<Vec<u8>> {
        if total == 0 || idx >= total {
            return None;
        }
        if self.parts.len() >= 64 {
            self.parts.retain(|_, v| now.duration_since(v.0) < Duration::from_millis(1500));
            if self.parts.len() >= 64 {
                return None;
            }
        }
        let e = self.parts.entry(id).or_insert_with(|| (now, vec![None; total as usize]));
        if e.1.len() != total as usize {
            return None;
        }
        e.1[idx as usize] = Some(chunk.to_vec());
        if e.1.iter().any(|x| x.is_none()) {
            return None;
        }
        let (_, parts) = self.parts.remove(&id)?;
        Some(parts.into_iter().flatten().flatten().collect())
    }
}

/// Sliding window over the sequence numbers of one class (they wrap): a packet is delivered once
pub struct Dedup {
    top: u32,
    any: bool,
    bits: Vec<u64>,
}

impl Default for Dedup {
    fn default() -> Self {
        Dedup { top: 0, any: false, bits: vec![0; Self::WORDS] }
    }
}

impl Dedup {
    const WORDS: usize = 128;
    const SPAN: u32 = (Self::WORDS * 64) as u32;

    pub fn top(&self) -> u32 {
        self.top
    }

    /// true = first time (and now marked)
    pub fn take(&mut self, seq: u32) -> bool {
        if !self.any {
            self.any = true;
            self.top = seq;
            self.bits.iter_mut().for_each(|w| *w = 0);
            self.bits[0] = 1;
            return true;
        }
        let ahead = seq.wrapping_sub(self.top);
        if ahead != 0 && ahead < 1 << 31 {
            if ahead >= Self::SPAN {
                self.bits.iter_mut().for_each(|w| *w = 0);
            } else {
                let (words, bits) = ((ahead / 64) as usize, ahead % 64);
                for i in (0..Self::WORDS).rev() {
                    let mut v = if i >= words { self.bits[i - words] << bits } else { 0 };
                    if bits > 0 && i > words {
                        v |= self.bits[i - words - 1] >> (64 - bits);
                    }
                    self.bits[i] = v;
                }
            }
            self.bits[0] |= 1;
            self.top = seq;
            return true;
        }
        let back = self.top.wrapping_sub(seq);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_round_trip_and_filler_ends_them() {
        let mut p = vec![];
        put(&mut p, &Frame::Ping { id: 7, t: 99 });
        put(&mut p, &Frame::Pong { id: 7, t: 99, gen: 3, hi: 1 << 40, cnt: 12 });
        put(&mut p, &Frame::Report { rt_top: 5, rt_got: 6, bulk_top: 7, bulk_got: 8 });
        put(&mut p, &Frame::Data { bulk: false, lane: 0, seq: 0xfffffff0, inner: b"game" });
        put(&mut p, &Frame::Data { bulk: true, lane: 5, seq: 2, inner: b"download" });
        put(&mut p, &Frame::Fix { bulk: false, lane: 0, rlc: b"r1" });
        put(&mut p, &Frame::Fix { bulk: true, lane: 3, rlc: b"r2" });
        put(&mut p, &Frame::Frag { id: 9, idx: 1, total: 2, chunk: b"piece" });
        let n = p.len();
        pad(&mut p, 40);
        assert_eq!(p.len(), n + 40);
        let got: Vec<Frame> = frames(&p).collect();
        assert_eq!(
            got,
            vec![
                Frame::Ping { id: 7, t: 99 },
                Frame::Pong { id: 7, t: 99, gen: 3, hi: 1 << 40, cnt: 12 },
                Frame::Report { rt_top: 5, rt_got: 6, bulk_top: 7, bulk_got: 8 },
                Frame::Data { bulk: false, lane: 0, seq: 0xfffffff0, inner: b"game" },
                Frame::Data { bulk: true, lane: 5, seq: 2, inner: b"download" },
                Frame::Fix { bulk: false, lane: 0, rlc: b"r1" },
                Frame::Fix { bulk: true, lane: 3, rlc: b"r2" },
                Frame::Frag { id: 9, idx: 1, total: 2, chunk: b"piece" },
            ]
        );
    }

    #[test]
    fn a_cut_or_unknown_frame_is_no_trouble() {
        let mut p = vec![];
        put(&mut p, &Frame::Ping { id: 1, t: 2 });
        // a type of a later version, with a sound length: skipped
        p.extend_from_slice(&[0x77, 0, 2, 9, 9]);
        put(&mut p, &Frame::Data { bulk: false, lane: 0, seq: 1, inner: b"x" });
        assert_eq!(frames(&p).count(), 2);
        // cut in the middle of the last frame
        assert_eq!(frames(&p[..p.len() - 1]).count(), 1);
        assert_eq!(frames(&[]).count(), 0);
        assert_eq!(frames(&[T_PING, 0]).count(), 0);
    }

    #[test]
    fn inner_blocks() {
        let u = inner_udp(2, 77, b"payload");
        match inner(&u) {
            Some(Inner::Udp { pidx: 2, flow: 77, data }) => assert_eq!(data, b"payload"),
            _ => panic!("udp"),
        }
        assert!(matches!(inner(&inner_quic(b"q")), Some(Inner::Quic(b"q"))));
        assert!(matches!(inner(&inner_echo(true, 4, 5)), Some(Inner::Echo { back: true, id: 4, t: 5 })));
        assert!(inner(&[]).is_none());
        assert!(inner(&[IN_UDP, 1]).is_none());
    }

    #[test]
    fn a_big_payload_comes_back_whole() {
        let payload: Vec<u8> = (0..5000u32).map(|i| (i * 7) as u8).collect();
        let parts = fragments(42, &payload, 1276);
        assert!(parts.len() >= 4 && parts.iter().all(|p| p.len() <= 1276));
        let mut r = Reasm::default();
        let now = Instant::now();
        let mut whole = None;
        // the pieces arrive backwards
        for p in parts.iter().rev() {
            for f in frames(p) {
                if let Frame::Frag { id, idx, total, chunk } = f {
                    if let Some(w) = r.add(id, idx, total, chunk, now) {
                        whole = Some(w);
                    }
                }
            }
        }
        assert_eq!(whole.as_deref(), Some(&payload[..]));
    }

    #[test]
    fn a_packet_is_delivered_once() {
        let mut d = Dedup::default();
        assert!(d.take(0xffff_fffe));
        assert!(!d.take(0xffff_fffe));
        // across the wrap
        assert!(d.take(1));
        assert!(d.take(0xffff_ffff));
        assert!(d.take(0));
        assert!(!d.take(0));
        assert!(!d.take(1));
        assert_eq!(d.top(), 1);
        assert!(d.take(1 + 5000));
        assert!(d.take(2));
        assert!(!d.take(2));
        // older than the window
        assert!(d.take(100_000));
        assert!(!d.take(100_000 - Dedup::SPAN));
        assert!(d.take(100_000 - Dedup::SPAN + 1));
    }

    #[test]
    fn filler_respects_the_room() {
        for _ in 0..200 {
            assert_eq!(filler(0, 50, 500), 0);
            assert!(filler(2, 50, 10) <= 10);
            assert!(filler(2, 50, 500) <= 160);
            assert_eq!(filler(1, 1200, 500), 0);
        }
    }
}
