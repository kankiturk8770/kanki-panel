//! Forward error correction for the `game` transport: Reed-Solomon over groups of consecutive
//! KCP packets, so the receiver rebuilds a lost packet from the parity shards instead of waiting
//! a round trip for KCP to resend it. (Ported from the Kariz project, `transport/kcp/fec.rs`.)
//!
//! A group has up to `data` packets. Each goes out at once as a *data shard*
//! (`len (2, LE) | packet`); when the group is full, `parity` parity shards follow, computed over
//! the data shards padded to the longest (even) length. A group that is not full after
//! `max_delay` is closed early with the packets it has and a proportional number of parity shards
//! (at least one), so FEC never holds recovery back by more than that. A receiver that has any
//! `k` of a group's `k + m` shards rebuilds the missing data.

use std::collections::{HashMap, VecDeque};
use std::time::Duration;
use tokio::time::Instant;

/// Groups a receiver keeps while waiting for their missing shards.
const KEEP_GROUPS: usize = 32;

/// A shard to send, as the encoder hands it out.
#[derive(Debug, PartialEq, Eq)]
pub enum Shard<'a> {
    Data {
        group: u32,
        index: u8,
        /// `len (2) | packet`.
        shard: &'a [u8],
    },
    Parity {
        group: u32,
        index: u8,
        /// Data shards in the group.
        data_count: u8,
        /// Parity shards in the group.
        parity_count: u8,
        shard: &'a [u8],
    },
}

/// Sending side.
pub struct FecEncoder {
    data: usize,
    parity: usize,
    max_delay: Duration,
    group: u32,
    /// The open group's data shards (`len (2) | packet`, unpadded).
    shards: Vec<Vec<u8>>,
    opened: Option<Instant>,
}

impl FecEncoder {
    /// `data` 1-64 and `parity` 1-32 (checked by the caller).
    pub fn new(data: usize, parity: usize, max_delay: Duration) -> Self {
        Self { data, parity, max_delay, group: 0, shards: Vec::with_capacity(data), opened: None }
    }

    /// Adds a packet to the open group: `send` gets its data shard at once, and the group's
    /// parity shards if this filled it.
    pub fn push(&mut self, packet: &[u8], now: Instant, send: &mut impl FnMut(Shard<'_>)) {
        let len = u16::try_from(packet.len()).unwrap_or(u16::MAX) as usize;
        let packet = &packet[..packet.len().min(len)];
        let mut shard = Vec::with_capacity(packet.len() + 2);
        shard.extend_from_slice(&(packet.len() as u16).to_le_bytes());
        shard.extend_from_slice(packet);
        send(Shard::Data { group: self.group, index: self.shards.len() as u8, shard: &shard });
        self.shards.push(shard);
        self.opened.get_or_insert(now);
        if self.shards.len() == self.data {
            self.close(send);
        }
    }

    /// When the open group has to be closed, if one is open.
    pub fn deadline(&self) -> Option<Instant> {
        self.opened.map(|at| at + self.max_delay)
    }

    /// Closes the open group early if it is due.
    pub fn close_if_due(&mut self, now: Instant, send: &mut impl FnMut(Shard<'_>)) {
        if self.deadline().is_some_and(|at| at <= now) {
            self.close(send);
        }
    }

    fn close(&mut self, send: &mut impl FnMut(Shard<'_>)) {
        let k = self.shards.len();
        if k == 0 {
            return;
        }
        // Full groups get `parity`; a group closed early gets as many in proportion.
        let m = (self.parity * k).div_ceil(self.data).max(1);
        let size = self.shards.iter().map(Vec::len).max().unwrap_or(0).next_multiple_of(2);
        for shard in &mut self.shards {
            shard.resize(size, 0);
        }
        if let Ok(parity) = reed_solomon_simd::encode(k, m, &self.shards) {
            for (index, shard) in parity.iter().enumerate() {
                send(Shard::Parity { group: self.group, index: index as u8, data_count: k as u8, parity_count: m as u8, shard });
            }
        }
        self.shards.clear();
        self.opened = None;
        self.group = self.group.wrapping_add(1);
    }
}

#[derive(Default)]
struct Group {
    data: HashMap<u8, Vec<u8>>,
    parity: HashMap<u8, Vec<u8>>,
    /// `(data, parity)` shard counts, known once a parity shard came.
    counts: Option<(usize, usize)>,
    /// Every data shard is there, or was rebuilt.
    done: bool,
}

/// Receiving side.
#[derive(Default)]
pub struct FecDecoder {
    groups: HashMap<u32, Group>,
    /// the kept groups, oldest first (group numbers wrap around after 2^32: order is by arrival, and
    /// "older" is decided with wrapping arithmetic, so recovery keeps working after the wrap)
    order: VecDeque<u32>,
}

impl FecDecoder {
    /// Records a data shard (its packet is handed on by the caller) and returns the packets it
    /// let us rebuild.
    pub fn data(&mut self, group: u32, index: u8, shard: &[u8]) -> Vec<Vec<u8>> {
        let Some(g) = self.group(group) else { return Vec::new() };
        if g.done {
            return Vec::new();
        }
        g.data.insert(index, shard.to_vec());
        self.try_rebuild(group)
    }

    /// Records a parity shard and returns the packets it let us rebuild.
    pub fn parity(&mut self, group: u32, index: u8, data_count: u8, parity_count: u8, shard: &[u8]) -> Vec<Vec<u8>> {
        let (k, m) = (data_count as usize, parity_count as usize);
        if k == 0 || m == 0 || index as usize >= m || shard.is_empty() || !shard.len().is_multiple_of(2) {
            return Vec::new();
        }
        let Some(g) = self.group(group) else { return Vec::new() };
        if g.done || g.counts.is_some_and(|c| c != (k, m)) {
            return Vec::new();
        }
        g.counts = Some((k, m));
        g.parity.insert(index, shard.to_vec());
        self.try_rebuild(group)
    }

    /// The group's state, unless it is too old to keep.
    fn group(&mut self, id: u32) -> Option<&mut Group> {
        if !self.groups.contains_key(&id) {
            if self.groups.len() >= KEEP_GROUPS {
                let oldest = *self.order.front().expect("not empty");
                // a late shard of a group older than every kept one (wrapping: id is "behind" oldest)
                if (oldest.wrapping_sub(id) as i32) > 0 {
                    return None;
                }
                self.order.pop_front();
                self.groups.remove(&oldest);
            }
            self.groups.insert(id, Group::default());
            self.order.push_back(id);
        }
        self.groups.get_mut(&id)
    }

    fn try_rebuild(&mut self, id: u32) -> Vec<Vec<u8>> {
        let Some(g) = self.groups.get_mut(&id) else { return Vec::new() };
        let Some((k, m)) = g.counts else { return Vec::new() };
        let have = g.data.keys().filter(|&&i| (i as usize) < k).count();
        if have == k {
            g.done = true;
            g.parity.clear();
            g.data.clear();
            return Vec::new();
        }
        if have + g.parity.len() < k {
            return Vec::new();
        }
        let size = g.parity.values().next().map_or(0, Vec::len);
        let originals: Vec<(usize, Vec<u8>)> = g
            .data
            .iter()
            .filter(|(&i, s)| (i as usize) < k && s.len() <= size)
            .map(|(&i, s)| {
                let mut s = s.clone();
                s.resize(size, 0);
                (i as usize, s)
            })
            .collect();
        let recovery = g.parity.iter().map(|(&i, s)| (i as usize, s));
        let rebuilt = reed_solomon_simd::decode(k, m, originals, recovery);
        g.done = true;
        g.data.clear();
        g.parity.clear();
        let Ok(rebuilt) = rebuilt else { return Vec::new() };
        rebuilt
            .into_values()
            .filter_map(|shard| {
                let len = u16::from_le_bytes(shard.get(..2)?.try_into().ok()?) as usize;
                shard.get(2..2 + len).map(<[u8]>::to_vec)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn recovery_keeps_working_after_the_group_number_wraps() {
        let mut enc = FecEncoder::new(2, 1, std::time::Duration::from_secs(1));
        enc.group = u32::MAX - 40;
        let mut dec = FecDecoder::default();
        let now = tokio::time::Instant::now();
        let mut lost_and_back = 0;
        for i in 0..100u32 {
            let mut shards: Vec<(bool, u32, u8, u8, u8, Vec<u8>)> = vec![];
            for p in [format!("a{}", i), format!("b{}", i)] {
                enc.push(p.as_bytes(), now, &mut |s| match s {
                    Shard::Data { group, index, shard } => shards.push((true, group, index, 0, 0, shard.to_vec())),
                    Shard::Parity { group, index, data_count, parity_count, shard } => shards.push((false, group, index, data_count, parity_count, shard.to_vec())),
                });
            }
            // the first data shard of every group is lost: parity must bring it back
            for (data, g, idx, k, m, sh) in shards.into_iter().skip(1) {
                let out = if data { dec.data(g, idx, &sh) } else { dec.parity(g, idx, k, m, &sh) };
                if out.iter().any(|x| x == format!("a{}", i).as_bytes()) {
                    lost_and_back += 1;
                }
            }
        }
        assert_eq!(lost_and_back, 100);
    }

    use super::*;

    /// What an encoder sends, owned.
    #[derive(Debug, Clone)]
    enum Sent {
        Data(u32, u8, Vec<u8>),
        Parity(u32, u8, u8, u8, Vec<u8>),
    }

    fn collect(sent: &mut Vec<Sent>) -> impl FnMut(Shard<'_>) + '_ {
        move |s| {
            sent.push(match s {
                Shard::Data { group, index, shard } => Sent::Data(group, index, shard.to_vec()),
                Shard::Parity { group, index, data_count, parity_count, shard } => Sent::Parity(group, index, data_count, parity_count, shard.to_vec()),
            })
        }
    }

    fn packet(i: usize) -> Vec<u8> {
        (0..(24 + i * 37 % 1300)).map(|b| (b * 7 + i) as u8).collect()
    }

    /// Feeds `sent` to a decoder, skipping the shards at `lost`, and returns every packet the
    /// receiver ends up with (received or rebuilt).
    fn receive(sent: &[Sent], lost: &[usize]) -> Vec<Vec<u8>> {
        let mut d = FecDecoder::default();
        let mut got = Vec::new();
        for (i, s) in sent.iter().enumerate() {
            if lost.contains(&i) {
                continue;
            }
            match s {
                Sent::Data(g, idx, shard) => {
                    got.push(shard[2..].to_vec());
                    got.extend(d.data(*g, *idx, shard));
                }
                Sent::Parity(g, idx, k, m, shard) => got.extend(d.parity(*g, *idx, *k, *m, shard)),
            }
        }
        got.sort();
        got
    }

    fn sorted(mut v: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
        v.sort();
        v
    }

    #[test]
    fn a_full_group_sends_data_then_parity() {
        let now = Instant::now();
        let mut e = FecEncoder::new(4, 2, Duration::from_millis(20));
        let mut sent = Vec::new();
        for i in 0..4 {
            e.push(&packet(i), now, &mut collect(&mut sent));
        }
        assert_eq!(sent.len(), 6);
        assert!(matches!(sent[3], Sent::Data(0, 3, _)));
        assert!(matches!(sent[4], Sent::Parity(0, 0, 4, 2, _)));
        assert!(matches!(sent[5], Sent::Parity(0, 1, 4, 2, _)));
        assert_eq!(e.deadline(), None, "the next group opens with its first packet");
        e.push(&packet(9), now, &mut collect(&mut sent));
        assert!(matches!(sent[6], Sent::Data(1, 0, _)));
    }

    /// Any `k` of the `k + m` shards rebuild the group, whichever are lost.
    #[test]
    fn any_data_count_of_the_shards_rebuild_the_group() {
        let (k, m) = (5, 3);
        let now = Instant::now();
        let mut e = FecEncoder::new(k, m, Duration::from_millis(20));
        let mut sent = Vec::new();
        let packets: Vec<_> = (0..k).map(packet).collect();
        for p in &packets {
            e.push(p, now, &mut collect(&mut sent));
        }
        assert_eq!(sent.len(), k + m);
        let n = k + m;
        for mask in 0u32..(1 << n) {
            let lost: Vec<usize> = (0..n).filter(|i| mask & (1 << i) != 0).collect();
            let got = receive(&sent, &lost);
            if lost.len() <= m {
                assert_eq!(got, sorted(packets.clone()), "lost {lost:?}");
            } else {
                assert!(got.len() < k, "lost {lost:?}: cannot have everything");
            }
        }
    }

    /// A group not full after the delay is closed with what it has, and its parity still
    /// rebuilds it.
    #[test]
    fn a_slow_group_is_closed_after_the_delay() {
        let delay = Duration::from_millis(20);
        let start = Instant::now();
        let mut e = FecEncoder::new(10, 3, delay);
        let mut sent = Vec::new();
        e.push(&packet(1), start, &mut collect(&mut sent));
        e.push(&packet(2), start + Duration::from_millis(5), &mut collect(&mut sent));
        assert_eq!(e.deadline(), Some(start + delay), "counted from the first packet");
        e.close_if_due(start + Duration::from_millis(19), &mut collect(&mut sent));
        assert_eq!(sent.len(), 2, "not due yet");
        e.close_if_due(start + delay, &mut collect(&mut sent));
        // 2 of 10 data shards: ceil(3 * 2 / 10) = 1 parity shard.
        assert_eq!(sent.len(), 3);
        assert!(matches!(sent[2], Sent::Parity(0, 0, 2, 1, _)));
        assert_eq!(e.deadline(), None);
        for lost in [0, 1] {
            assert_eq!(receive(&sent, &[lost]), sorted(vec![packet(1), packet(2)]));
        }
    }

    #[test]
    fn parity_before_data_and_duplicates() {
        let (k, m) = (4, 2);
        let now = Instant::now();
        let mut e = FecEncoder::new(k, m, Duration::from_millis(20));
        let mut sent = Vec::new();
        let packets: Vec<_> = (0..k).map(packet).collect();
        for p in &packets {
            e.push(p, now, &mut collect(&mut sent));
        }
        // data shard 1 is lost; parity arrives first; duplicates are harmless
        let mut d = FecDecoder::default();
        let mut got = Vec::new();
        for s in sent.iter().skip(2).chain(sent.iter().skip(2)) {
            match s {
                Sent::Data(g, idx, shard) => got.extend(d.data(*g, *idx, shard)),
                Sent::Parity(g, idx, kk, mm, shard) => got.extend(d.parity(*g, *idx, *kk, *mm, shard)),
            }
        }
        assert!(got.iter().any(|p| *p == packets[1]), "shard 1 rebuilt from parity");
    }

    #[test]
    fn old_groups_are_forgotten() {
        let mut d = FecDecoder::default();
        for g in 0..40u32 {
            d.data(g, 0, &[1, 0, 42]);
        }
        // group 0 is gone: answering for it does nothing and does not panic
        assert!(d.data(0, 1, &[1, 0, 43]).is_empty());
    }
}
