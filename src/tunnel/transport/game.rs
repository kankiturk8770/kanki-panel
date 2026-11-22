//! `game`: the gaming transport — KCP at its fastest setting over the masked UDP relay of
//! `obfs.rs`, with Reed-Solomon FEC (`fec.rs`) and optional packet duplication, so a lost packet
//! is rebuilt on the spot (or arrives twice) instead of waiting for a resend round trip.
//!
//! ```text
//!  user UDP/game traffic -> mux over a Kanki link -> KCP (fastest, stream mode)
//!  KCP datagram -> [ FEC data shard + parity shards ] -> [ duplicate? ] -> mask -> wire
//! ```
//!
//! Wire payloads (inside the mask, so none of this is visible):
//! * FEC off: the raw KCP datagram, like the `kcp` transport.
//! * FEC on:  `0xF3 | group (4, BE) | index (1) | shard` for a data shard and
//!   `0xF4 | group (4, BE) | index (1) | data count (1) | parity count (1) | shard`
//!   for a parity shard, where `shard` is `len (2, LE) | KCP datagram`.
//!
//! Both ends get the same settings from the panel, so there is no negotiation. Duplication
//! sends every masked datagram twice (two different masks, so the copies do not look alike).
//!
//! **Game-FEC Pro** (FEC `auto`, both agents 3.57.0 or newer): the repairs follow the line. Every
//! half second each end tells the other how many payloads it sent and how many of the other's it
//! lost (`0xF5 | sent (4, BE) | loss per mille (2, BE)`), and each end shapes its own FEC groups from
//! what the other lost: none on a clean line (under 1 %), 10:1 to 5:1 up to 15 %, more past it, never
//! more repair bytes than data bytes (a 30 %+ outage cannot make it flood). Only the game is coded:
//! the KCP stream (TCP of the users, control) and flows that are not the game (`dgram` bulk: the KCP of
//! KANKI MIX, downloads) go as plain payloads, `0xF6 | payload`. Duplication is off.

use super::fec::{FecDecoder, FecEncoder, Shard};
use super::link::{Bag, BoxIo, Inbox, Res};
use super::salamander::Mask;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant as StdInstant};
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;
use tokio::time::Instant;

/// How the `game` transport protects packets. `fec_data`/`fec_parity` 0 = FEC off.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, PartialEq)]
#[serde(default)]
pub struct GameOpts {
    /// FEC group: data shards (1-64) and parity shards (1-32)
    pub fec_data: u8,
    pub fec_parity: u8,
    /// send every datagram twice (costs bandwidth, survives burst loss)
    pub dup: bool,
    /// Game-FEC Pro: FEC that follows the line, only the game coded (FEC "auto")
    pub pro: bool,
}

impl GameOpts {
    pub fn fec_on(&self) -> bool {
        self.pro || (self.fec_data >= 1 && self.fec_parity >= 1)
    }
    /// "8:3" style spec string -> options ("" keeps the defaults of the transport)
    pub fn parse(fec: &str, dup: bool) -> GameOpts {
        let mut g = GameOpts { fec_data: 8, fec_parity: 3, dup, pro: false };
        let f = fec.trim();
        if f.is_empty() {
            return g;
        }
        if f == "auto" {
            let (d, p) = SHAPES[START];
            return GameOpts { fec_data: d as u8, fec_parity: p as u8, dup: false, pro: true };
        }
        if f == "off" || f == "0" {
            g.fec_data = 0;
            g.fec_parity = 0;
            return g;
        }
        if let Some((a, b)) = f.split_once(':') {
            g.fec_data = a.trim().parse().unwrap_or(8);
            g.fec_parity = b.trim().parse().unwrap_or(3);
        } else if let Ok(a) = f.parse() {
            g.fec_data = a;
        }
        g.fec_data = g.fec_data.min(64);
        g.fec_parity = g.fec_parity.min(32);
        g
    }
}

const FEC_DATA: u8 = 0xF3;
const FEC_PARITY: u8 = 0xF4;
/// Game-FEC Pro: what this end sent and what it lost of the other's
const STAT: u8 = 0xF5;
/// Game-FEC Pro: a payload without FEC
const PLAIN: u8 = 0xF6;
const STAT_EVERY: Duration = Duration::from_millis(500);
/// Game-FEC Pro, by the loss the other end saw: (data, parity) of a group. Under 1 % nothing, 1-5 %
/// 10:1, 5-10 % 8:1, 10-15 % 5:1, 15-30 % 4:2, past 30 % the circuit breaker's 4:4 (repairs never more
/// than the data: twice the bytes at most)
const SHAPES: [(usize, usize); 6] = [(10, 0), (10, 1), (8, 1), (5, 1), (4, 2), (4, 4)];
const LEVEL_AT: [u32; 5] = [10, 50, 100, 150, 300];
/// the shape before the first report: light, so a new link is protected but cheap
const START: usize = 1;
/// reports in a row that want less before the repairs go down a step (up at once)
const CALM: u8 = 6;

fn level_for(loss_permille: u32) -> usize {
    LEVEL_AT.iter().take_while(|x| loss_permille >= **x).count()
}

/// One link's loss accounting for Game-FEC Pro (shared by its sending and its receiving half)
#[derive(Default)]
pub struct Adapt {
    sent: AtomicU32,
    recv: AtomicU32,
    /// the other end's sent count at its last report we used, and our received count then
    mark: Mutex<Option<(u32, u32)>>,
    /// what we lose of the other end's payloads (per mille), what the other end loses of ours
    in_loss: AtomicU32,
    out_loss: AtomicU32,
    /// the repairs now (index into SHAPES), for the panel
    pub level: AtomicU32,
}

impl Adapt {
    fn on_stat(&self, sent: u32, loss: u32) {
        self.out_loss.store(loss.min(1000), Ordering::Relaxed);
        let r = self.recv.load(Ordering::Relaxed);
        let mut m = self.mark.lock().unwrap_or_else(|e| e.into_inner());
        match *m {
            Some((ps, pr)) => {
                let ds = sent.wrapping_sub(ps);
                // the other end started again (a new relay): count from here
                if ds > 1 << 24 {
                    *m = Some((sent, r));
                    return;
                }
                // too few to say anything yet: keep counting from the same mark
                if ds < 20 {
                    return;
                }
                let dr = r.wrapping_sub(pr).min(ds);
                let now = (ds - dr) * 1000 / ds;
                let old = self.in_loss.load(Ordering::Relaxed);
                self.in_loss.store((old + now).div_ceil(2), Ordering::Relaxed);
                *m = Some((sent, r));
            }
            None => *m = Some((sent, r)),
        }
    }
    /// (what we lose, what the other end loses), per mille
    pub fn losses(&self) -> (u32, u32) {
        (self.in_loss.load(Ordering::Relaxed), self.out_loss.load(Ordering::Relaxed))
    }
}

/// What a payload is to Game-FEC Pro
#[derive(Clone, Copy, PartialEq, Debug)]
enum Kind {
    /// the KCP stream
    Stream,
    /// a game datagram (lane)
    Game,
    /// a datagram of a flow that is not the game (lane, bulk)
    Bulk,
}
/// a group closes at the latest this long after its first packet (game traffic is latency-bound)
const FEC_DELAY: Duration = Duration::from_millis(4);
/// A group closed early (sparse traffic: a game sends one packet every 15-30 ms) has its repair shards spread
/// out this far apart, and a duplicated datagram's second copy goes this long after the first: sent right
/// behind the packet, one short outage of the link (tens of ms) took the packet and all its repairs at once.
/// The packet itself still goes at once; only a rebuilt one comes a little later.
const PARITY_GAP: Duration = Duration::from_millis(10);
const DUP_GAP: Duration = Duration::from_millis(20);
/// most clients one server relay serves at the same time
const MAX_PEERS: usize = 1024;
/// a client that sent nothing for this long is forgotten
const PEER_IDLE: Duration = Duration::from_secs(90);

// ------------------------------------------------------------------ codec helpers

/// payload -> what goes on the wire (one or two masked datagrams are made by the caller).
fn seal_send(mask: &Mask, payload: &[u8], out: &mut Vec<u8>, dup: bool) -> usize {
    let mut n = 0;
    mask.seal(payload, out);
    n += 1;
    if dup {
        mask.seal(payload, out);
        n += 1;
    }
    n
}

/// Sends the datagrams in `out` (back to back, each one masked) over `sock`.
/// Splits them back apart first: every masked datagram must travel in its own UDP packet.
async fn send_masked(sock: &UdpSocket, to: Option<SocketAddr>, mask: &Mask, payload: &[u8], dup: bool) {
    let mut buf = Vec::with_capacity(1400);
    let count = seal_send(mask, payload, &mut buf, dup);
    if count == 1 {
        let _ = match to {
            Some(t) => sock.send_to(&buf, t).await,
            None => sock.send(&buf).await,
        };
        return;
    }
    // two copies: reseal one by one so each is a separate datagram
    let mut one = Vec::with_capacity(1400);
    for _ in 0..count {
        one.clear();
        mask.seal(payload, &mut one);
        let _ = match to {
            Some(t) => sock.send_to(&one, t).await,
            None => sock.send(&one).await,
        };
    }
}

/// Game-FEC Pro: a report or a plain payload is handled here; everything else goes on to `decode_in`
/// (None: handled)
fn pro_in<'a>(ad: Option<&Adapt>, payload: &'a [u8]) -> Option<Result<&'a [u8], ()>> {
    let Some(ad) = ad else { return Some(Err(())) };
    match payload.first().copied() {
        Some(STAT) if payload.len() >= 7 => {
            ad.on_stat(u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]), u16::from_be_bytes([payload[5], payload[6]]) as u32);
            None
        }
        Some(PLAIN) if payload.len() > 1 => {
            ad.recv.fetch_add(1, Ordering::Relaxed);
            Some(Ok(&payload[1..]))
        }
        _ => {
            ad.recv.fetch_add(1, Ordering::Relaxed);
            Some(Err(()))
        }
    }
}

/// The datagrams one incoming payload yields: the Game-FEC Pro kinds first, then `decode_in`
fn decode_any(dec: Option<&mut FecDecoder>, ad: Option<&Adapt>, payload: &[u8]) -> Vec<Vec<u8>> {
    match pro_in(ad, payload) {
        None => vec![],
        Some(Ok(p)) => vec![p.to_vec()],
        Some(Err(())) => decode_in(dec, payload),
    }
}

/// The KCP datagrams a masked, maybe FEC-coded, incoming payload yields.
fn decode_in(dec: Option<&mut FecDecoder>, payload: &[u8]) -> Vec<Vec<u8>> {
    match dec {
        None => vec![payload.to_vec()],
        Some(d) => match payload.first().copied() {
            Some(FEC_DATA) if payload.len() > 8 => {
                let group = u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]);
                // the shard is `len (2, LE) | datagram`: KCP gets the datagram only, the
                // decoder the whole shard
                let len = u16::from_le_bytes([payload[6], payload[7]]) as usize;
                let Some(pkt) = payload.get(8..8 + len).filter(|p| !p.is_empty()) else { return vec![] };
                let mut out = vec![pkt.to_vec()];
                out.extend(d.data(group, payload[5], &payload[6..]));
                out
            }
            Some(FEC_PARITY) if payload.len() > 8 => {
                let group = u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]);
                d.parity(group, payload[5], payload[6], payload[7], &payload[8..])
            }
            // not ours (or FEC was toggled on one side only): drop
            _ => vec![],
        },
    }
}

/// An encoder plus the shard sender of one direction, with the payloads that wait for their time
/// (spread repair shards, second copies).
struct Out {
    enc: Option<FecEncoder>,
    data: usize,
    later: Vec<(Instant, Vec<u8>)>,
    /// Game-FEC Pro: the link's accounting, the shape now, reports that wanted less, the next report
    pro: Option<Arc<Adapt>>,
    level: usize,
    calm: u8,
    next_stat: Instant,
}

impl Out {
    #[cfg(test)]
    fn new(g: GameOpts) -> Out {
        Out::with(g, None)
    }
    fn with(g: GameOpts, ad: Option<Arc<Adapt>>) -> Out {
        let pro = if g.pro { Some(ad.unwrap_or_default()) } else { None };
        let enc = if pro.is_some() {
            let (d, p) = SHAPES[START];
            Some(FecEncoder::adaptive(d, p, FEC_DELAY))
        } else if g.fec_on() {
            Some(FecEncoder::new(g.fec_data as usize, g.fec_parity as usize, FEC_DELAY))
        } else {
            None
        };
        if let Some(a) = &pro {
            a.level.store(START as u32, Ordering::Relaxed);
        }
        let data = enc.as_ref().map(|e| e.shape().0).unwrap_or(g.fec_data as usize);
        Out { enc, data, later: vec![], pro, level: START, calm: 0, next_stat: Instant::now() + STAT_EVERY }
    }
    fn deadline(&self) -> Option<Instant> {
        let a = self.enc.as_ref().and_then(|e| e.deadline());
        let b = self.later.iter().map(|x| x.0).min();
        let c = self.pro.as_ref().map(|_| self.next_stat);
        [a, b, c].into_iter().flatten().min()
    }
    /// One masked payload out (counted for Game-FEC Pro)
    async fn wire(&self, sock: &UdpSocket, to: Option<SocketAddr>, mask: &Mask, p: &[u8]) {
        if let Some(a) = &self.pro {
            a.sent.fetch_add(1, Ordering::Relaxed);
        }
        send_masked(sock, to, mask, p, false).await;
    }
    /// Game-FEC Pro: the report to the other end, and the shape from what it lost of ours
    async fn report(&mut self, sock: &UdpSocket, to: Option<SocketAddr>, mask: &Mask, dup: bool) {
        let Some(a) = self.pro.clone() else { return };
        let now = Instant::now();
        if now < self.next_stat {
            return;
        }
        self.next_stat = now + STAT_EVERY;
        let (inl, outl) = a.losses();
        let mut p = Vec::with_capacity(7);
        p.push(STAT);
        p.extend_from_slice(&a.sent.load(Ordering::Relaxed).to_be_bytes());
        p.extend_from_slice(&(inl.min(1000) as u16).to_be_bytes());
        send_masked(sock, to, mask, &p, false).await;
        let want = level_for(outl);
        if want > self.level {
            self.level = want;
            self.calm = 0;
        } else if want < self.level {
            self.calm += 1;
            if self.calm >= CALM {
                self.level -= 1;
                self.calm = 0;
            }
        } else {
            self.calm = 0;
        }
        a.level.store(self.level as u32, Ordering::Relaxed);
        let (d, pp) = SHAPES[self.level];
        if self.enc.as_ref().map(|e| e.shape()) != Some((d, pp)) {
            self.data = d;
            let mut jobs: Vec<(Option<u8>, Vec<u8>)> = vec![];
            if let Some(enc) = &mut self.enc {
                enc.set_shape(d, pp, &mut |s: Shard<'_>| jobs.push((parity_of(&s), shard_payload(&s))));
            }
            self.shards(sock, to, mask, jobs, dup).await;
        }
    }
    fn wait(&mut self, at: Instant, p: Vec<u8>) {
        self.later.push((at, p));
    }
    /// One payload now (its second copy later when `dup`)
    async fn send(&mut self, sock: &UdpSocket, to: Option<SocketAddr>, mask: &Mask, p: Vec<u8>, dup: bool, now: Instant) {
        self.wire(sock, to, mask, &p).await;
        if dup {
            self.wait(now + DUP_GAP, p);
        }
    }
    /// The shards of a group: data now; the repairs of a group closed early spread out in time
    async fn shards(&mut self, sock: &UdpSocket, to: Option<SocketAddr>, mask: &Mask, jobs: Vec<(Option<u8>, Vec<u8>)>, dup: bool) {
        // after the encoding (it takes a moment): the gaps count from when the shards really leave
        let now = Instant::now();
        let mut k = 0u32;
        for (sparse, p) in jobs {
            match sparse {
                Some(n) if (n as usize) < self.data => {
                    k += 1;
                    let at = now + PARITY_GAP * k;
                    self.wait(at, p.clone());
                    if dup {
                        self.wait(at + DUP_GAP, p);
                    }
                }
                _ => self.send(sock, to, mask, p, dup, now).await,
            }
        }
    }
    /// Turns one KCP datagram into wire payloads and sends them.
    #[cfg(test)]
    async fn push(&mut self, sock: &UdpSocket, to: Option<SocketAddr>, mask: &Mask, pkt: &[u8], dup: bool) {
        self.push_as(sock, to, mask, pkt, dup, Kind::Game).await
    }
    /// The same, knowing what it is: with Game-FEC Pro only the game is coded
    async fn push_as(&mut self, sock: &UdpSocket, to: Option<SocketAddr>, mask: &Mask, pkt: &[u8], dup: bool, kind: Kind) {
        let now = Instant::now();
        if self.pro.is_some() && kind != Kind::Game {
            let mut p = Vec::with_capacity(1 + pkt.len());
            p.push(PLAIN);
            p.extend_from_slice(pkt);
            self.wire(sock, to, mask, &p).await;
            return;
        }
        match &mut self.enc {
            None => self.send(sock, to, mask, pkt.to_vec(), dup, now).await,
            Some(enc) => {
                let mut jobs: Vec<(Option<u8>, Vec<u8>)> = vec![];
                enc.push(pkt, now, &mut |s: Shard<'_>| jobs.push((parity_of(&s), shard_payload(&s))));
                self.shards(sock, to, mask, jobs, dup).await;
            }
        }
    }
    /// Closes a due FEC group and sends what waited for its time (called when the timer fires).
    async fn flush_due(&mut self, sock: &UdpSocket, to: Option<SocketAddr>, mask: &Mask, dup: bool) {
        let now = Instant::now();
        if let Some(enc) = &mut self.enc {
            let mut jobs: Vec<(Option<u8>, Vec<u8>)> = vec![];
            enc.close_if_due(now, &mut |s: Shard<'_>| jobs.push((parity_of(&s), shard_payload(&s))));
            self.shards(sock, to, mask, jobs, dup).await;
        }
        let now = Instant::now();
        let due: Vec<Vec<u8>> = {
            let (d, keep): (Vec<_>, Vec<_>) = std::mem::take(&mut self.later).into_iter().partition(|x| x.0 <= now);
            self.later = keep;
            d.into_iter().map(|x| x.1).collect()
        };
        for p in due {
            self.wire(sock, to, mask, &p).await;
        }
        self.report(sock, to, mask, dup).await;
    }
}

/// Some(data count of its group) for a repair shard
fn parity_of(s: &Shard<'_>) -> Option<u8> {
    match s {
        Shard::Parity { data_count, .. } => Some(*data_count),
        _ => None,
    }
}

fn shard_payload(s: &Shard<'_>) -> Vec<u8> {
    match s {
        Shard::Data { group, index, shard } => {
            let mut v = Vec::with_capacity(6 + shard.len());
            v.push(FEC_DATA);
            v.extend_from_slice(&group.to_be_bytes());
            v.push(*index);
            v.extend_from_slice(shard);
            v
        }
        Shard::Parity { group, index, data_count, parity_count, shard } => {
            let mut v = Vec::with_capacity(8 + shard.len());
            v.push(FEC_PARITY);
            v.extend_from_slice(&group.to_be_bytes());
            v.push(*index);
            v.push(*data_count);
            v.push(*parity_count);
            v.extend_from_slice(shard);
            v
        }
    }
}

// ------------------------------------------------------------------ client relay

/// Client side: binds a private loopback socket for KCP to dial and relays to `remote` with the
/// mask, FEC and duplication. The relay lives until this guard is dropped.
pub struct ClientGame {
    pub local: SocketAddr,
    /// the datagram lane of this link (`dgram.rs`)
    pub port: Arc<super::dgram::Port>,
    tasks: Vec<JoinHandle<()>>,
}

impl Drop for ClientGame {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

/// Waits until `dl`, or forever without one (the FEC group timer in a `select!`)
async fn sleep_until_opt(dl: Option<Instant>) {
    match dl {
        Some(d) => tokio::time::sleep_until(d).await,
        None => std::future::pending().await,
    }
}

/// Marks the game link's packets "Expedited Forwarding" (DSCP 46), the class for real-time traffic.
/// Routers that honour it (our own `fq`/cake queues, some carriers) send them first; the ones that
/// do not just ignore it. It costs nothing and hides nothing (the payload stays masked).
fn mark_ef(sock: &UdpSocket) {
    #[cfg(target_os = "linux")]
    let _ = sock.set_tos_v4(0xb8);
    #[cfg(not(target_os = "linux"))]
    let _ = sock;
}

pub async fn client(remote: SocketAddr, token: &str, g: GameOpts) -> Res<ClientGame> {
    let mask = Arc::new(Mask::new(token));
    let bind: SocketAddr = if remote.is_ipv6() { "[::]:0".parse()? } else { "0.0.0.0:0".parse()? };
    let outer = Arc::new(UdpSocket::bind(bind).await?);
    mark_ef(&outer);
    outer.connect(remote).await?;
    let inner = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
    let local = inner.local_addr()?;
    let kcp_addr: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
    let (port, lane) = super::dgram::Port::pair();
    let super::dgram::RelayEnd { out: mut lane_out, bulk: mut lane_bulk, inbox: lane_in } = lane;
    let ad: Option<Arc<Adapt>> = g.pro.then(|| Arc::new(Adapt::default()));

    // KCP and the datagram lane -> FEC/dup -> mask -> peer (the game lane first: a burst of the stream
    // never holds a game packet back)
    let (inner1, outer1, ka1, mask1, ad1) = (inner.clone(), outer.clone(), kcp_addr.clone(), mask.clone(), ad.clone());
    let out_task = tokio::spawn(async move {
        let mut out = Out::with(g, ad1);
        let mut a = vec![0u8; 65535];
        loop {
            let dl = out.deadline();
            tokio::select! {
                biased;
                Some(w) = lane_out.recv() => out.push_as(&outer1, None, &mask1, &w, g.dup, Kind::Game).await,
                Some(w) = lane_bulk.recv() => out.push_as(&outer1, None, &mask1, &w, g.dup, Kind::Bulk).await,
                r = inner1.recv_from(&mut a) => match r {
                    Ok((n, from)) => {
                        *ka1.lock().unwrap_or_else(|e| e.into_inner()) = Some(from);
                        out.push_as(&outer1, None, &mask1, &a[..n], g.dup, Kind::Stream).await;
                    }
                    Err(_) => break,
                },
                _ = sleep_until_opt(dl) => out.flush_due(&outer1, None, &mask1, g.dup).await,
            }
        }
    });
    // peer -> unmask -> FEC decode -> KCP
    let in_task = tokio::spawn(async move {
        let mut dec = if g.fec_on() { Some(FecDecoder::default()) } else { None };
        let mut b = vec![0u8; 65535];
        loop {
            let n = match outer.recv(&mut b).await {
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => continue,
                Err(_) => break,
            };
            let dst = *kcp_addr.lock().unwrap_or_else(|e| e.into_inner());
            let Some(dst) = dst else { continue };
            let Some((s, e)) = mask.open(&mut b[..n]) else { continue };
            let payload = b[s..e].to_vec();
            for pkt in decode_any(dec.as_mut(), ad.as_deref(), &payload) {
                if super::dgram::looks_like(&pkt) {
                    // the session checks it (a full queue drops it: too late for a game anyway)
                    let _ = lane_in.try_send(pkt);
                } else {
                    let _ = inner.send_to(&pkt, dst).await;
                }
            }
        }
    });
    Ok(ClientGame { local, port, tasks: vec![out_task, in_task] })
}

// ------------------------------------------------------------------ server relay

/// One real client as the KCP listener sees it: its own loopback socket and the pump task that
/// carries KCP's answers (FEC-coded, masked, maybe duplicated) back to the client.
struct Peer {
    sock: Arc<UdpSocket>,
    last: StdInstant,
    pump: JoinHandle<()>,
    dec: Arc<Mutex<FecDecoder>>,
    /// where this client's datagram-lane payloads go (its link's session)
    lane_in: tokio::sync::mpsc::Sender<Vec<u8>>,
    /// Game-FEC Pro: this client's loss accounting
    ad: Option<Arc<Adapt>>,
}

/// The datagram lane of each client, by the address the KCP listener sees it from (its loopback
/// socket): `serve_game` hands it over with the accepted stream
type Ports = Arc<Mutex<HashMap<SocketAddr, Arc<super::dgram::Port>>>>;

/// Server side: owns the public UDP socket, unwraps incoming datagrams and forwards them (in the
/// clear) to the local KCP listener, and wraps KCP's replies back out. One relay serves every
/// client on the port, keyed by address.
pub struct ServerGame {
    tasks: Vec<JoinHandle<()>>,
    peers: Arc<Mutex<HashMap<SocketAddr, Peer>>>,
    pub ports: Ports,
}

impl Drop for ServerGame {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
        for (_, p) in self.peers.lock().unwrap_or_else(|e| e.into_inner()).drain() {
            p.pump.abort();
        }
    }
}

/// KCP and the datagram lane -> FEC/dup -> mask -> client, for one client.
struct Lanes {
    out: tokio::sync::mpsc::Receiver<Vec<u8>>,
    bulk: tokio::sync::mpsc::Receiver<Vec<u8>>,
}

async fn pump(sock: Arc<UdpSocket>, public: Arc<UdpSocket>, mask: Arc<Mask>, to: SocketAddr, g: GameOpts, mut lanes: Lanes, ad: Option<Arc<Adapt>>) {
    let mut out = Out::with(g, ad);
    let mut b = vec![0u8; 65535];
    loop {
        let dl = out.deadline();
        tokio::select! {
            biased;
            Some(w) = lanes.out.recv() => out.push_as(&public, Some(to), &mask, &w, g.dup, Kind::Game).await,
            Some(w) = lanes.bulk.recv() => out.push_as(&public, Some(to), &mask, &w, g.dup, Kind::Bulk).await,
            r = sock.recv(&mut b) => match r {
                Ok(n) => out.push_as(&public, Some(to), &mask, &b[..n], g.dup, Kind::Stream).await,
                Err(_) => break,
            },
            _ = sleep_until_opt(dl) => out.flush_due(&public, Some(to), &mask, g.dup).await,
        }
    }
}

pub async fn server(port: u16, token: &str, kcp_local: SocketAddr, g: GameOpts) -> Res<ServerGame> {
    let mask = Arc::new(Mask::new(token));
    let public = Arc::new(UdpSocket::bind(format!("0.0.0.0:{}", port)).await?);
    mark_ef(&public);
    let peers: Arc<Mutex<HashMap<SocketAddr, Peer>>> = Arc::new(Mutex::new(HashMap::new()));
    let ports: Ports = Arc::new(Mutex::new(HashMap::new()));

    let (public1, mask1, peers1, ports1) = (public.clone(), mask.clone(), peers.clone(), ports.clone());
    let main_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            let (n, from) = match public1.recv_from(&mut buf).await {
                Ok(x) => x,
                Err(_) => {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    continue;
                }
            };
            // not ours (a scanner, a probe, noise): no peer, no socket, no answer
            let Some((s, e)) = mask1.open(&mut buf[..n]) else { continue };
            let payload = buf[s..e].to_vec();
            // first look under the lock; a new peer's socket is bound outside it (await points
            // must not hold the MutexGuard)
            let mut entry = {
                let mut gmap = peers1.lock().unwrap_or_else(|e| e.into_inner());
                gmap.get_mut(&from).map(|p| {
                    p.last = StdInstant::now();
                    (p.sock.clone(), p.dec.clone(), p.lane_in.clone(), p.ad.clone())
                })
            };
            if entry.is_none() && peers1.lock().unwrap_or_else(|e| e.into_inner()).len() < MAX_PEERS {
                if let Ok(sock) = UdpSocket::bind("127.0.0.1:0").await {
                    if sock.connect(kcp_local).await.is_ok() {
                        let sock = Arc::new(sock);
                        let dec = Arc::new(Mutex::new(FecDecoder::default()));
                        let (port, lane) = super::dgram::Port::pair();
                        if let Ok(a) = sock.local_addr() {
                            ports1.lock().unwrap_or_else(|e| e.into_inner()).insert(a, port);
                        }
                        let ad: Option<Arc<Adapt>> = g.pro.then(|| Arc::new(Adapt::default()));
                        let pump = tokio::spawn(pump(sock.clone(), public1.clone(), mask1.clone(), from, g, Lanes { out: lane.out, bulk: lane.bulk }, ad.clone()));
                        peers1.lock().unwrap_or_else(|e| e.into_inner()).insert(from, Peer { sock: sock.clone(), last: StdInstant::now(), pump, dec: dec.clone(), lane_in: lane.inbox.clone(), ad: ad.clone() });
                        entry = Some((sock, dec, lane.inbox, ad));
                    }
                }
            }
            let Some((sock, dec, lane_in, ad)) = entry else { continue };
            let packets = {
                let mut d = dec.lock().unwrap_or_else(|e| e.into_inner());
                // FEC state lives per peer; without FEC payloads pass through
                decode_any(if g.fec_on() { Some(&mut *d) } else { None }, ad.as_deref(), &payload)
            };
            for pkt in packets {
                if super::dgram::looks_like(&pkt) {
                    let _ = lane_in.try_send(pkt);
                } else {
                    let _ = sock.send(&pkt).await;
                }
            }
        }
    });

    // forget clients that went quiet (and clients whose pump died)
    let (peers2, ports2) = (peers.clone(), ports.clone());
    let reaper = tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(15)).await;
            let mut gone = vec![];
            {
                let mut g = peers2.lock().unwrap_or_else(|e| e.into_inner());
                g.retain(|_, p| {
                    let keep = !p.pump.is_finished() && p.last.elapsed() < PEER_IDLE;
                    if !keep {
                        p.pump.abort();
                        if let Ok(a) = p.sock.local_addr() {
                            gone.push(a);
                        }
                    }
                    keep
                });
            }
            let mut pm = ports2.lock().unwrap_or_else(|e| e.into_inner());
            for a in gone {
                pm.remove(&a);
            }
        }
    });

    Ok(ServerGame { tasks: vec![main_task, reaper], peers, ports })
}

// ------------------------------------------------------------------ engine glue

fn game_kcp_config() -> tokio_kcp::KcpConfig {
    tokio_kcp::KcpConfig {
        stream: true,
        // the lowest-latency profile: nodelay, 10 ms interval, fast resend after 2 losses, no
        // congestion control backoff
        nodelay: tokio_kcp::KcpNoDelayConfig::fastest(),
        // 1080 leaves room for the FEC shard header (8) and the mask head and padding within the
        // 1232-byte wire budget of salamander.rs
        mtu: 1080,
        wnd_size: (1024, 1024),
        session_expire: Duration::from_secs(45),
        ..Default::default()
    }
}

/// Starts a `game` listener: KCP on a private loopback socket, the FEC/mask relay on the public
/// UDP port.
pub async fn serve_game(port: u16, token: &str, g: GameOpts, out: Inbox, sem: Arc<tokio::sync::Semaphore>) -> Res<Bag> {
    let mut inner = tokio_kcp::KcpListener::bind(game_kcp_config(), "127.0.0.1:0").await?;
    let local = inner.local_addr()?;
    let relay = server(port, token, local, g).await?;
    let task = tokio::spawn(async move {
        let ports = relay.ports.clone();
        let _relay = relay;
        loop {
            let (stream, from) = match inner.accept().await {
                Ok(x) => x,
                Err(_) => {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    continue;
                }
            };
            let Ok(permit) = sem.clone().try_acquire_owned() else {
                drop(stream);
                continue;
            };
            let io: BoxIo = Box::new(super::quic::KcpHeld { stream, _permit: permit });
            // the client's datagram lane comes with its stream (taken: one link per lane)
            let raw = match ports.lock().unwrap_or_else(|e| e.into_inner()).remove(&from) {
                Some(p) => super::link::Raw::Dg(io, p),
                None => super::link::Raw::Stream(io),
            };
            if out.send((raw, "game".to_string())).await.is_err() {
                break;
            }
        }
    });
    Ok(Bag { tasks: vec![task], endpoints: vec![] })
}

/// Dials a `game` server through the FEC/mask relay; the stream and its datagram lane.
pub async fn dial_game(remote: &str, token: &str, g: GameOpts) -> Res<(BoxIo, Arc<super::dgram::Port>)> {
    let addr: SocketAddr = tokio::net::lookup_host(remote).await?.next().ok_or("cannot resolve the tunnel address")?;
    let relay = client(addr, token, g).await?;
    let port = relay.port.clone();
    let stream = tokio::time::timeout(Duration::from_secs(12), tokio_kcp::KcpStream::connect(&game_kcp_config(), relay.local))
        .await
        .map_err(|_| "game connect timeout")??;
    Ok((Box::new(GameIo { stream, _relay: relay }), port))
}

/// A KCP stream that also owns its game relay.
pub struct GameIo {
    stream: tokio_kcp::KcpStream,
    _relay: ClientGame,
}

impl tokio::io::AsyncRead for GameIo {
    fn poll_read(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &mut tokio::io::ReadBuf<'_>) -> std::task::Poll<std::io::Result<()>> {
        tokio::io::AsyncRead::poll_read(std::pin::Pin::new(&mut self.stream), cx, buf)
    }
}
impl tokio::io::AsyncWrite for GameIo {
    fn poll_write(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &[u8]) -> std::task::Poll<std::io::Result<usize>> {
        tokio::io::AsyncWrite::poll_write(std::pin::Pin::new(&mut self.stream), cx, buf)
    }
    fn poll_flush(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        tokio::io::AsyncWrite::poll_flush(std::pin::Pin::new(&mut self.stream), cx)
    }
    fn poll_shutdown(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        tokio::io::AsyncWrite::poll_shutdown(std::pin::Pin::new(&mut self.stream), cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(i: usize) -> Vec<u8> {
        (0..(30 + i * 53 % 1000)).map(|b| (b * 3 + i) as u8).collect()
    }

    /// Encodes `packets` the way `Out::push` does and feeds the wire payloads (minus `lost`)
    /// through `decode_in`: KCP must get exactly the original datagrams.
    fn roundtrip(packets: &[Vec<u8>], lost: &[usize]) -> Vec<Vec<u8>> {
        let mut enc = FecEncoder::new(8, 3, FEC_DELAY);
        let mut wire: Vec<Vec<u8>> = vec![];
        for p in packets {
            enc.push(p, Instant::now(), &mut |s: Shard<'_>| wire.push(shard_payload(&s)));
        }
        let mut dec = FecDecoder::default();
        let mut got = vec![];
        for (i, w) in wire.iter().enumerate() {
            if !lost.contains(&i) {
                got.extend(decode_in(Some(&mut dec), w));
            }
        }
        got.sort();
        got
    }

    /// A lone game packet: the packet goes at once, its repair shards later and apart (an outage of a few
    /// tens of ms no longer takes them all), each of them still rebuilds it
    #[tokio::test]
    async fn the_repairs_of_a_lone_packet_are_spread_out() {
        let rx = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let tx = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let to = rx.local_addr().unwrap();
        let mask = Mask::new("token-for-tests-0123456789");
        let mut out = Out::new(GameOpts { fec_data: 8, fec_parity: 3, dup: false, pro: false });
        let t0 = StdInstant::now();
        out.push(&tx, Some(to), &mask, &packet(1), false).await;
        // the group closes after FEC_DELAY with one packet: the timer as the relay runs it
        let mut times = vec![];
        let mut b = vec![0u8; 2048];
        let end = tokio::time::sleep(Duration::from_secs(2));
        tokio::pin!(end);
        while times.len() < 4 {
            tokio::select! {
                r = rx.recv(&mut b) => { r.unwrap(); times.push(t0.elapsed()); }
                _ = sleep_until_opt(out.deadline()) => out.flush_due(&tx, Some(to), &mask, false).await,
                _ = &mut end => break,
            }
        }
        assert_eq!(times.len(), 4, "the packet and its three repairs");
        assert!(times[0] < Duration::from_millis(3), "the packet goes at once: {:?}", times);
        assert!(times[3] - times[1] >= PARITY_GAP * 2 - Duration::from_millis(2), "repairs spread out: {:?}", times);
    }

    #[test]
    fn fec_data_shards_reach_kcp_without_the_length() {
        let packets: Vec<_> = (0..8).map(packet).collect();
        let mut want = packets.clone();
        want.sort();
        assert_eq!(roundtrip(&packets, &[]), want, "all data shards received");
        assert_eq!(roundtrip(&packets, &[3]), want, "data shard 3 rebuilt from parity");
    }

    #[test]
    fn bad_data_shard_length_is_dropped() {
        let mut dec = FecDecoder::default();
        // claims 200 bytes, carries 3
        let bad = [FEC_DATA, 0, 0, 0, 0, 0, 200, 0, 1, 2, 3];
        assert!(decode_in(Some(&mut dec), &bad).is_empty());
    }
    #[test]
    fn the_repairs_follow_the_loss() {
        assert_eq!(SHAPES[level_for(0)], (10, 0));
        assert_eq!(SHAPES[level_for(9)], (10, 0));
        assert_eq!(SHAPES[level_for(10)], (10, 1));
        assert_eq!(SHAPES[level_for(70)], (8, 1));
        assert_eq!(SHAPES[level_for(149)], (5, 1));
        assert_eq!(SHAPES[level_for(200)], (4, 2));
        assert_eq!(SHAPES[level_for(1000)], (4, 4));
        // never more repairs than data
        assert!(SHAPES.iter().all(|(d, p)| p <= d));
        assert!(GameOpts::parse("auto", true).pro && !GameOpts::parse("auto", true).dup);
        assert!(!GameOpts::parse("8:3", false).pro);
    }

    #[test]
    fn loss_is_counted_from_the_reports() {
        let a = Adapt::default();
        a.on_stat(1000, 0);
        // the other end sent 100 more, 90 came
        a.recv.fetch_add(90, Ordering::Relaxed);
        a.on_stat(1100, 25);
        assert_eq!(a.losses(), (50, 25), "half of 10 % after one report (smoothed)");
        a.recv.fetch_add(100, Ordering::Relaxed);
        a.on_stat(1200, 0);
        assert_eq!(a.losses().0, 25);
        // too few to say: the mark stays
        a.recv.fetch_add(5, Ordering::Relaxed);
        a.on_stat(1205, 0);
        assert_eq!(a.losses().0, 25);
        // the other end started again
        a.on_stat(3, 0);
        a.recv.fetch_add(40, Ordering::Relaxed);
        a.on_stat(43, 0);
        assert_eq!(a.losses().0, 13);
    }

    /// Game-FEC Pro on the wire: the stream and bulk go plain, the game is coded; a clean line sends no
    /// repairs, a bad one sends some but never more than the data (a lone game packet: one repair)
    #[tokio::test]
    async fn pro_codes_only_the_game_and_follows_the_line() {
        let rx = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let tx = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let to = rx.local_addr().unwrap();
        let mask = Mask::new("token-for-tests-0123456789");
        let ad = Arc::new(Adapt::default());
        let mut out = Out::with(GameOpts::parse("auto", false), Some(ad.clone()));
        let mut b = vec![0u8; 2048];
        let got = |b: &mut Vec<u8>, n: usize| -> Vec<u8> {
            let (s, e) = mask.open(&mut b[..n]).unwrap();
            b[s..e].to_vec()
        };
        out.push_as(&tx, Some(to), &mask, b"stream-bytes", false, Kind::Stream).await;
        let n = rx.recv(&mut b).await.unwrap();
        assert_eq!(got(&mut b, n), [&[PLAIN][..], b"stream-bytes"].concat());
        out.push_as(&tx, Some(to), &mask, b"kcp-of-kmix", false, Kind::Bulk).await;
        let n = rx.recv(&mut b).await.unwrap();
        assert_eq!(got(&mut b, n)[0], PLAIN);
        // the other end says it loses 40 %: the next report takes the breaker's shape at once
        ad.on_stat(0, 400);
        out.next_stat = Instant::now();
        out.flush_due(&tx, Some(to), &mask, false).await;
        let n = rx.recv(&mut b).await.unwrap();
        assert_eq!(got(&mut b, n)[0], STAT);
        assert_eq!(out.enc.as_ref().unwrap().shape(), (4, 4));
        // a lone game packet: the data shard, and after the group closes one repair only (capped)
        out.push_as(&tx, Some(to), &mask, &packet(3), false, Kind::Game).await;
        let n = rx.recv(&mut b).await.unwrap();
        assert_eq!(got(&mut b, n)[0], FEC_DATA);
        let mut kinds = vec![];
        let end = tokio::time::sleep(Duration::from_millis(400));
        tokio::pin!(end);
        loop {
            tokio::select! {
                r = rx.recv(&mut b) => { let n = r.unwrap(); kinds.push(got(&mut b, n)[0]); }
                _ = sleep_until_opt(out.deadline()) => out.flush_due(&tx, Some(to), &mask, false).await,
                _ = &mut end => break,
            }
        }
        assert_eq!(kinds.iter().filter(|k| **k == FEC_PARITY).count(), 1, "{:?}", kinds);
        // a clean line for a while: the repairs go down step by step, to none
        for _ in 0..(CALM as usize * SHAPES.len()) {
            ad.on_stat(0, 0);
            out.next_stat = Instant::now();
            out.flush_due(&tx, Some(to), &mask, false).await;
        }
        assert_eq!(out.enc.as_ref().unwrap().shape(), (10, 0));
        while tokio::time::timeout(Duration::from_millis(20), rx.recv(&mut b)).await.is_ok() {}
        out.push_as(&tx, Some(to), &mask, &packet(4), false, Kind::Game).await;
        let mut kinds = vec![];
        let end = tokio::time::sleep(Duration::from_millis(300));
        tokio::pin!(end);
        loop {
            tokio::select! {
                r = rx.recv(&mut b) => { let n = r.unwrap(); kinds.push(got(&mut b, n)[0]); }
                _ = sleep_until_opt(out.deadline()) => out.flush_due(&tx, Some(to), &mask, false).await,
                _ = &mut end => break,
            }
        }
        assert!(kinds.contains(&FEC_DATA) && !kinds.contains(&FEC_PARITY), "{:?}", kinds);
        // and the receiving side reads all three kinds
        let mut dec = FecDecoder::default();
        let r = Adapt::default();
        assert_eq!(decode_any(Some(&mut dec), Some(&r), &[&[PLAIN][..], b"x"].concat()), vec![b"x".to_vec()]);
        assert!(decode_any(Some(&mut dec), Some(&r), &[STAT, 0, 0, 0, 9, 0, 7]).is_empty());
        assert_eq!(r.losses().1, 7);
    }
}
