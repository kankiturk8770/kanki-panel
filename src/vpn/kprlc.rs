//! KPING v3: sliding-window random linear repairs over GF(256) (kind 5), the same as the app's
//! `kanki-app/kping-core/kping/rlc.go` (shared test vector in `kpingd::tests`).
//!
//! A repair covers the newest packets of a window `[base, base+n)` (n ≤ 16) still before their deadline,
//! as a random linear combination of their blocks (`len (2, BE) | IP packet`). Any lost packets of the
//! window come back once enough repairs arrive, and overlapping windows solve together: two or three
//! packets lost in a row are rebuilt, which v2's XOR parity (one per group) cannot do. The receiver keeps
//! only equations that still have unknowns, in reduced row-echelon form (Gauss-Jordan on the fly), so a
//! repair whose packets all came costs nothing.
//!
//! Payload: `base seq (4, BE) | n (1) | index (1) | coded block (padded to the window's longest)`
use std::sync::OnceLock;
use std::time::{Duration, Instant};

pub const MAX_WIN: usize = 16;
pub const REP_HDR: usize = 6;
const KEEP: usize = 256;
const ROWS: usize = 32;
const COLS: usize = 32;
const META: usize = 2;
const MAX_BLOCK: usize = 2048;
/// a packet rebuilt later than this is old news: it is not delivered
pub const RECV_AGE: Duration = Duration::from_millis(300);

struct Gf {
    exp: [u8; 512],
    log: [u8; 256],
    mul: Box<[[u8; 256]; 256]>,
}

fn gf() -> &'static Gf {
    static G: OnceLock<Gf> = OnceLock::new();
    G.get_or_init(|| {
        let mut g = Gf { exp: [0; 512], log: [0; 256], mul: Box::new([[0; 256]; 256]) };
        let mut x: u32 = 1;
        for i in 0..255 {
            g.exp[i] = x as u8;
            g.log[x as usize] = i as u8;
            x <<= 1;
            if x & 0x100 != 0 {
                x ^= 0x11d;
            }
        }
        for i in 255..512 {
            g.exp[i] = g.exp[i - 255];
        }
        for a in 1..256 {
            for b in 1..256 {
                g.mul[a][b] = g.exp[g.log[a] as usize + g.log[b] as usize];
            }
        }
        g
    })
}

fn inv(a: u8) -> u8 {
    if a == 0 { 0 } else { gf().exp[255 - gf().log[a as usize] as usize] }
}

/// dst ^= c·src
fn mul_add(dst: &mut [u8], src: &[u8], c: u8) {
    match c {
        0 => {}
        1 => dst.iter_mut().zip(src).for_each(|(a, b)| *a ^= b),
        _ => {
            let row = &gf().mul[c as usize];
            dst.iter_mut().zip(src).for_each(|(a, b)| *a ^= row[*b as usize]);
        }
    }
}

fn scale(dst: &mut [u8], c: u8) {
    if c != 1 {
        let row = &gf().mul[c as usize];
        dst.iter_mut().for_each(|a| *a = row[*a as usize]);
    }
}

/// The coefficient of row `row` in repair `index` of window (base, n). Never 0. The app uses the same.
pub fn coef(base: u32, n: u8, index: u8, row: usize) -> u8 {
    let mut x = (base as u64).wrapping_add(0x9e3779b97f4a7c15);
    x ^= (n as u64) << 17;
    x ^= (index as u64 + 1).wrapping_mul(0xbf58476d1ce4e5b9);
    x ^= (row as u64 + 1).wrapping_mul(0x94d049bb133111eb);
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58476d1ce4e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d049bb133111eb);
    x ^= x >> 31;
    (x % 255) as u8 + 1
}

fn newer(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) > 0
}

// ------------------------------------------------------------------ sending

struct TxBlock {
    seq: u32,
    ok: bool,
    deadline: Instant,
    b: Vec<u8>,
}

/// The recent protected packets of one direction, and the repairs made of them
pub struct RlcTx {
    hist: Vec<TxBlock>,
    last: u32,
    any: bool,
    last_base: Option<(u32, u8)>,
}

impl Default for RlcTx {
    fn default() -> Self {
        let now = Instant::now();
        RlcTx { hist: (0..MAX_WIN * 2).map(|_| TxBlock { seq: 0, ok: false, deadline: now, b: Vec::new() }).collect(), last: 0, any: false, last_base: None }
    }
}

impl RlcTx {
    pub fn add(&mut self, seq: u32, p: &[u8], deadline: Instant) {
        if p.len() + META > MAX_BLOCK {
            return;
        }
        let n = self.hist.len();
        let h = &mut self.hist[seq as usize % n];
        h.seq = seq;
        h.ok = true;
        h.deadline = deadline;
        h.b.clear();
        h.b.extend_from_slice(&(p.len() as u16).to_be_bytes());
        h.b.extend_from_slice(p);
        self.last = seq;
        self.any = true;
    }

    fn get(&self, seq: u32) -> Option<&TxBlock> {
        let h = &self.hist[seq as usize % self.hist.len()];
        (h.ok && h.seq == seq).then_some(h)
    }

    /// One repair over the newest packets still worth saving (at most `win`); None when nothing is.
    pub fn repair(&mut self, now: Instant, win: usize) -> Option<Vec<u8>> {
        if !self.any || self.get(self.last).is_none_or(|h| now > h.deadline) {
            return None;
        }
        let win = win.clamp(1, MAX_WIN);
        let mut base = self.last;
        for i in 1..win as u32 {
            let s = self.last.wrapping_sub(i);
            match self.get(s) {
                Some(h) if now <= h.deadline => base = s,
                _ => break,
            }
        }
        let n = self.last.wrapping_sub(base) as u8 + 1;
        let index = match self.last_base {
            Some((b, i)) if b == base => i.wrapping_add(1),
            _ => 0,
        };
        self.last_base = Some((base, index));
        let longest = (0..n as u32).filter_map(|i| self.get(base.wrapping_add(i))).map(|h| h.b.len()).max().unwrap_or(0);
        let mut out = vec![0u8; REP_HDR + longest];
        out[..4].copy_from_slice(&base.to_be_bytes());
        out[4] = n;
        out[5] = index;
        for i in 0..n as usize {
            if let Some(h) = self.get(base.wrapping_add(i as u32)) {
                mul_add(&mut out[REP_HDR..], &h.b, coef(base, n, index, i));
            }
        }
        Some(out)
    }
}

// ------------------------------------------------------------------ receiving

#[derive(Clone)]
struct RxBlock {
    seq: u32,
    ok: bool,
    at: Instant,
    b: Vec<u8>,
}

#[derive(Clone)]
struct Row {
    used: bool,
    pivot: usize,
    coef: [u8; COLS],
    v: Vec<u8>,
}

/// Known blocks and the equations of the repairs that still have unknowns
pub struct RlcRx {
    blocks: Vec<RxBlock>,
    top: u32,
    any: bool,
    rows: Vec<Row>,
    col_seq: [u32; COLS],
    col_used: [bool; COLS],
    col_row: [Option<usize>; COLS],
    building: Option<[u8; COLS]>,
    pub fixed: u64,
    pub stale: u64,
}

impl Default for RlcRx {
    fn default() -> Self {
        let now = Instant::now();
        RlcRx {
            blocks: vec![RxBlock { seq: 0, ok: false, at: now, b: Vec::new() }; KEEP],
            top: 0,
            any: false,
            rows: vec![Row { used: false, pivot: 0, coef: [0; COLS], v: Vec::new() }; ROWS],
            col_seq: [0; COLS],
            col_used: [false; COLS],
            col_row: [None; COLS],
            building: None,
            fixed: 0,
            stale: 0,
        }
    }
}

impl RlcRx {
    fn known(&self, seq: u32) -> Option<&RxBlock> {
        let b = &self.blocks[seq as usize % KEEP];
        (b.ok && b.seq == seq).then_some(b)
    }

    fn old(&self, seq: u32) -> bool {
        self.any && (self.top.wrapping_sub(seq) as i32) >= (KEEP - MAX_WIN - 1) as i32
    }

    fn store(&mut self, seq: u32, at: Instant, block: &[u8]) {
        let b = &mut self.blocks[seq as usize % KEEP];
        b.seq = seq;
        b.ok = true;
        b.at = at;
        b.b.clear();
        b.b.extend_from_slice(block);
    }

    fn advance(&mut self, seq: u32) {
        if !self.any || newer(seq, self.top) {
            self.top = seq;
            self.any = true;
            for c in 0..COLS {
                if self.col_used[c] && self.old(self.col_seq[c]) {
                    self.expire(c);
                }
            }
        }
    }

    /// A packet that arrived (its first copy); packets rebuilt thanks to it, with their numbers
    pub fn data(&mut self, seq: u32, p: &[u8], now: Instant) -> Vec<(u32, Vec<u8>)> {
        if p.len() + META > MAX_BLOCK || self.known(seq).is_some() || self.old(seq) {
            return vec![];
        }
        let mut block = Vec::with_capacity(META + p.len());
        block.extend_from_slice(&(p.len() as u16).to_be_bytes());
        block.extend_from_slice(p);
        self.store(seq, now, &block);
        self.advance(seq);
        self.substitute(seq, &block);
        self.collect(now)
    }

    /// A repair arrived; packets rebuilt thanks to it
    pub fn repair(&mut self, pl: &[u8], now: Instant) -> Vec<(u32, Vec<u8>)> {
        if pl.len() <= REP_HDR || pl.len() - REP_HDR > MAX_BLOCK {
            return vec![];
        }
        let base = u32::from_be_bytes([pl[0], pl[1], pl[2], pl[3]]);
        let (n, index) = (pl[4], pl[5]);
        if n == 0 || n as usize > MAX_WIN || self.old(base) {
            return vec![];
        }
        if self.any && (base.wrapping_add(n as u32 - 1).wrapping_sub(self.top) as i32) > MAX_WIN as i32 {
            return vec![];
        }
        let coded = &pl[REP_HDR..];
        let (mut unknown, mut need) = (0, 0);
        for i in 0..n as u32 {
            let s = base.wrapping_add(i);
            match self.known(s) {
                Some(b) if b.b.len() > coded.len() => return vec![],
                Some(_) => {}
                None => {
                    unknown += 1;
                    if self.col(s).is_none() {
                        need += 1;
                    }
                }
            }
        }
        if unknown == 0 || (need > self.free() && !self.evict(need)) {
            return vec![];
        }
        let mut coefs = [0u8; COLS];
        let mut v = coded.to_vec();
        for i in 0..n as usize {
            let s = base.wrapping_add(i as u32);
            let c = coef(base, n, index, i);
            if let Some(b) = self.known(s) {
                let b = b.b.clone();
                mul_add(&mut v, &b, c);
                continue;
            }
            let col = match self.col(s) {
                Some(c) => c,
                None => self.alloc(s),
            };
            coefs[col] ^= c;
        }
        self.building = Some(coefs);
        self.insert(coefs, v);
        self.building = None;
        self.gc();
        self.collect(now)
    }

    fn col(&self, seq: u32) -> Option<usize> {
        (0..COLS).find(|&c| self.col_used[c] && self.col_seq[c] == seq)
    }

    fn free(&self) -> usize {
        self.col_used.iter().filter(|u| !**u).count()
    }

    fn alloc(&mut self, seq: u32) -> usize {
        let c = (0..COLS).find(|&c| !self.col_used[c]).expect("a free column was checked");
        self.col_used[c] = true;
        self.col_seq[c] = seq;
        self.col_row[c] = None;
        c
    }

    fn evict(&mut self, n: usize) -> bool {
        while self.free() < n {
            let Some(oldest) = (0..COLS).filter(|&c| self.col_used[c]).min_by(|&a, &b| {
                if newer(self.col_seq[b], self.col_seq[a]) { std::cmp::Ordering::Less } else { std::cmp::Ordering::Greater }
            }) else {
                return false;
            };
            self.expire(oldest);
        }
        true
    }

    fn expire(&mut self, c: usize) {
        for i in 0..ROWS {
            if self.rows[i].used && self.rows[i].coef[c] != 0 {
                self.drop_row(i);
            }
        }
        self.col_used[c] = false;
        self.col_row[c] = None;
    }

    fn drop_row(&mut self, i: usize) {
        if !self.rows[i].used {
            return;
        }
        let p = self.rows[i].pivot;
        if self.col_row[p] == Some(i) {
            self.col_row[p] = None;
        }
        self.rows[i] = Row { used: false, pivot: 0, coef: [0; COLS], v: Vec::new() };
        self.gc();
    }

    fn gc(&mut self) {
        for c in 0..COLS {
            if !self.col_used[c] {
                continue;
            }
            let mut referenced = self.building.is_some_and(|b| b[c] != 0);
            referenced |= self.rows.iter().any(|r| r.used && r.coef[c] != 0);
            if !referenced {
                self.col_used[c] = false;
                self.col_row[c] = None;
            }
        }
    }

    fn insert(&mut self, mut coefs: [u8; COLS], mut v: Vec<u8>) {
        for i in 0..ROWS {
            if self.rows[i].used {
                let f = coefs[self.rows[i].pivot];
                axpy(&mut coefs, &mut v, &self.rows[i].coef, &self.rows[i].v, f);
            }
        }
        let Some(p) = (0..COLS).find(|&c| coefs[c] != 0) else { return };
        normalize(&mut coefs, &mut v, p);
        for i in 0..ROWS {
            if self.rows[i].used {
                let f = self.rows[i].coef[p];
                let row = &mut self.rows[i];
                axpy(&mut row.coef, &mut row.v, &coefs, &v, f);
            }
        }
        let slot = match (0..ROWS).find(|&i| !self.rows[i].used) {
            Some(s) => s,
            None => {
                let s = (0..ROWS)
                    .min_by(|&a, &b| if newer(self.col_seq[self.rows[b].pivot], self.col_seq[self.rows[a].pivot]) { std::cmp::Ordering::Less } else { std::cmp::Ordering::Greater })
                    .unwrap_or(0);
                self.drop_row(s);
                s
            }
        };
        self.rows[slot] = Row { used: true, pivot: p, coef: coefs, v };
        self.col_row[p] = Some(slot);
    }

    fn substitute(&mut self, seq: u32, block: &[u8]) {
        let Some(c) = self.col(seq) else { return };
        let pr = self.col_row[c];
        for row in self.rows.iter_mut().filter(|r| r.used) {
            let f = row.coef[c];
            if f != 0 {
                if row.v.len() < block.len() {
                    row.v.resize(block.len(), 0);
                }
                mul_add(&mut row.v, block, f);
                row.coef[c] = 0;
            }
        }
        self.col_used[c] = false;
        self.col_row[c] = None;
        let Some(pr) = pr else { return };
        let Some(p) = (0..COLS).find(|&x| self.rows[pr].coef[x] != 0) else {
            self.drop_row(pr);
            return;
        };
        {
            let row = &mut self.rows[pr];
            normalize(&mut row.coef, &mut row.v, p);
            row.pivot = p;
        }
        self.col_row[p] = Some(pr);
        let (pc, pv) = (self.rows[pr].coef, self.rows[pr].v.clone());
        for i in 0..ROWS {
            if i != pr && self.rows[i].used {
                let f = self.rows[i].coef[p];
                let row = &mut self.rows[i];
                axpy(&mut row.coef, &mut row.v, &pc, &pv, f);
            }
        }
    }

    fn collect(&mut self, now: Instant) -> Vec<(u32, Vec<u8>)> {
        let mut out = vec![];
        loop {
            let Some(i) = (0..ROWS).find(|&i| self.rows[i].used && (0..COLS).all(|c| c == self.rows[i].pivot || self.rows[i].coef[c] == 0)) else { break };
            let seq = self.col_seq[self.rows[i].pivot];
            let v = std::mem::take(&mut self.rows[i].v);
            self.drop_row(i);
            if v.len() < META {
                continue;
            }
            let l = u16::from_be_bytes([v[0], v[1]]) as usize;
            if l == 0 || META + l > v.len() || self.known(seq).is_some() {
                continue;
            }
            // when it was due: about when the next packet that did arrive came
            let mut at = now;
            for k in 1..MAX_WIN as u32 {
                let s = seq.wrapping_add(k);
                if newer(s, self.top) {
                    break;
                }
                if let Some(b) = self.known(s) {
                    at = b.at;
                    break;
                }
            }
            let block = v[..META + l].to_vec();
            self.store(seq, at, &block);
            self.advance(seq);
            self.substitute(seq, &block);
            if now.duration_since(at) <= RECV_AGE {
                self.fixed += 1;
                out.push((seq, block[META..].to_vec()));
            } else {
                self.stale += 1;
            }
        }
        out
    }
}

/// (dc, dv) += f·(sc, sv)
fn axpy(dc: &mut [u8; COLS], dv: &mut Vec<u8>, sc: &[u8; COLS], sv: &[u8], f: u8) {
    if f == 0 {
        return;
    }
    let row = &gf().mul[f as usize];
    for c in 0..COLS {
        if sc[c] != 0 {
            dc[c] ^= row[sc[c] as usize];
        }
    }
    if dv.len() < sv.len() {
        dv.resize(sv.len(), 0);
    }
    mul_add(dv, sv, f);
}

fn normalize(coefs: &mut [u8; COLS], v: &mut [u8], p: usize) {
    let i = inv(coefs[p]);
    if i == 1 {
        return;
    }
    let row = &gf().mul[i as usize];
    for c in coefs.iter_mut() {
        *c = row[*c as usize];
    }
    scale(v, i);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkt(seq: u32) -> Vec<u8> {
        let mut v = format!("packet-{:04}-", seq).into_bytes();
        v.extend(std::iter::repeat_n(seq as u8, (seq % 37) as usize));
        v
    }

    #[test]
    fn bursts_of_three_come_back() {
        let (mut tx, mut rx) = (RlcTx::default(), RlcRx::default());
        let now = Instant::now();
        let lost = [9u32, 10, 20, 21, 22];
        let mut got = std::collections::HashMap::new();
        for s in 1..=40u32 {
            tx.add(s, &pkt(s), now + Duration::from_secs(1));
            if !lost.contains(&s) {
                got.insert(s, pkt(s));
                for (q, p) in rx.data(s, &pkt(s), now) {
                    got.insert(q, p);
                }
            }
            let rep = tx.repair(now, 8).unwrap();
            for (q, p) in rx.repair(&rep, now) {
                got.insert(q, p);
            }
        }
        for s in 1..=40u32 {
            assert_eq!(got.get(&s), Some(&pkt(s)), "packet {}", s);
        }
    }

    #[test]
    fn random_loss_never_corrupts() {
        let mut seed: u64 = 7;
        let mut rnd = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            (seed % 1000) as f64 / 1000.0
        };
        for _ in 0..20 {
            let (mut tx, mut rx) = (RlcTx::default(), RlcRx::default());
            let now = Instant::now();
            let mut got = std::collections::HashMap::new();
            for s in 1..=400u32 {
                tx.add(s, &pkt(s), now + Duration::from_secs(1));
                if rnd() > 0.12 {
                    got.insert(s, pkt(s));
                    for (q, p) in rx.data(s, &pkt(s), now) {
                        assert!(got.insert(q, p).is_none());
                    }
                }
                if rnd() < 0.6 {
                    let rep = tx.repair(now, 12).unwrap();
                    if rnd() > 0.12 {
                        for (q, p) in rx.repair(&rep, now) {
                            assert!(got.insert(q, p).is_none(), "rebuilt twice");
                        }
                    }
                }
            }
            for (s, v) in &got {
                assert_eq!(v, &pkt(*s));
            }
            assert!(got.len() >= 400 * 97 / 100, "only {}", got.len());
        }
    }

    /// The same window and coefficients as the app (`rlc_test.go` makes this repair too)
    #[test]
    fn same_repair_as_the_app() {
        let mut tx = RlcTx::default();
        let far = Instant::now() + Duration::from_secs(10);
        for s in 1..=3u32 {
            tx.add(s, &pkt(s), far);
        }
        let rep = tx.repair(Instant::now(), 8).unwrap();
        assert_eq!((hex::encode(&rep), rep.len()), ("00000001030000444e926cb373af1af8f8f8821a7a8b83".to_string(), 23));
    }
}
