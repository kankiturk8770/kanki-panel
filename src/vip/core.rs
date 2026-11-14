//! VIP tunnel: the session. One task owns everything of a running tunnel: the keys, the measurements of
//! every path, the two traffic classes with their repairs, and the handshakes. The carriers (`path`) and
//! the users' ports (`flows`) talk to it through channels, so nothing here waits on a lock or a socket.

use super::crypto::{self, HsAsm, Initiator, Keys, Replay};
use super::flows::{self, Down, Up};
use super::path::{self, Got, In, Out, Ring, Screen, Slot, Slots};
use super::wire::{self, Dedup, Frame, Inner, Reasm};
use super::{PathKind, PathStatus, VipSpec, VipStatus};
use crate::kprlc::{RlcRx, RlcTx};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// realtime packets are worth rebuilding this long, bulk ones this long
const RT_LIFE: Duration = Duration::from_millis(300);
const BULK_LIFE: Duration = Duration::from_millis(400);
/// a lone realtime packet gets its repair this soon when nothing follows it
const TAIL: Duration = Duration::from_millis(15);
/// one path: the second copy of a realtime packet this much later (a short outage loses only one)
const LATE_COPY: Duration = Duration::from_millis(10);
/// old keys still open packets this long after new ones came
const PREV_KEEP: Duration = Duration::from_secs(30);
/// the dialer makes new keys when nothing came back for this long
const SILENCE: Duration = Duration::from_secs(5);
/// a path is up while it answered a ping this recently
const UP_FOR: Duration = Duration::from_secs(3);
/// realtime traffic went this recently: pings are faster and game priority may hold the bulk class back
const RT_ACTIVE: Duration = Duration::from_secs(3);
/// small packets a second above which a flow is not a game (games send 20-130)
const HEAVY: u32 = 300;

pub struct Running {
    spec: VipSpec,
    status: Arc<Mutex<VipStatus>>,
    tasks: Vec<JoinHandle<()>>,
}

impl Running {
    pub fn start(spec: VipSpec) -> Running {
        let status = Arc::new(Mutex::new(VipStatus { id: spec.id.clone(), role: spec.role.clone(), ..Default::default() }));
        let psk = crypto::psk_of(&spec.secret);
        let n = spec.paths().len();
        let slots: Slots = Arc::new(Mutex::new((0..n).map(|_| Slot::default()).collect()));
        let (in_tx, in_rx) = mpsc::channel::<In>(8192);
        let (up_tx, up_rx) = mpsc::channel::<Up>(8192);
        let (down_tx, down_rx) = mpsc::channel::<Down>(8192);
        let counters = Arc::new(flows::Counters::default());
        let screen = Arc::new(Screen::new(psk));
        let mut tasks = path::start(&spec, &psk, in_tx, slots.clone(), screen.clone());
        tasks.extend(flows::start(&spec, up_tx, down_rx, counters.clone()));
        let s = Session::new(spec.clone(), psk, slots, down_tx, status.clone(), counters, screen);
        tasks.push(tokio::spawn(s.run(in_rx, up_rx)));
        Running { spec, status, tasks }
    }
    pub fn spec(&self) -> &VipSpec {
        &self.spec
    }
    /// The session task ended (it never should): the manager starts the tunnel again
    pub fn dead(&self) -> bool {
        self.tasks.last().is_none_or(|t| t.is_finished())
    }
    pub fn status(&self) -> VipStatus {
        self.status.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
    pub fn stop(self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

// ------------------------------------------------------------------ measurements of one path

#[derive(Default)]
struct PathM {
    kind: Option<PathKind>,
    /// packet number of the next packet sent on it
    pn: u64,
    /// smoothed round trip and its jitter (ms; srtt 0 = not measured yet)
    srtt: f64,
    jit: f64,
    /// the smallest round trip lately: the path with empty queues
    min_rtt: f64,
    min_at: Option<Instant>,
    /// share of our packets the other side did not get (0..1, smoothed)
    loss: f64,
    pings: VecDeque<(u32, Instant)>,
    next_ping: Option<Instant>,
    last_pong: Option<Instant>,
    last_rx: Option<Instant>,
    /// the other side's counters at the last loss sample
    base: Option<(u8, u64, u64)>,
    tx_pk: u64,
    rx_pk: u64,
    /// what we received on it, for the other side's loss: the highest packet number and how many
    rx_hi: u64,
    rx_cnt: u64,
    rank: u8,
}

impl PathM {
    /// No answer for much longer than the round trip: treated as cut until it answers. Two pings overdue, or
    /// one overdue a long time: a single lost ping on a lossy line does not take the path out.
    fn stalled(&self, now: Instant) -> bool {
        let limit = if self.srtt > 0.0 { (self.srtt * 3.0).max(self.srtt + 120.0).max(200.0) } else { 1500.0 };
        let age = |i: usize| self.pings.get(i).map(|(_, at)| now.duration_since(*at).as_secs_f64() * 1000.0).unwrap_or(0.0);
        age(1) > limit || age(0) > limit.max(1000.0)
    }
    fn up(&self, now: Instant) -> bool {
        self.last_pong.is_some_and(|t| now.duration_since(t) < UP_FOR)
    }
    /// ping + 3·jitter + 20·loss% (the lower the better); a cut or unmeasured path is last
    fn score(&self, now: Instant, idx: usize) -> f64 {
        if self.srtt == 0.0 {
            return 10_000.0 + idx as f64;
        }
        if self.stalled(now) || !self.up(now) {
            return 100_000.0 + self.srtt;
        }
        // a stream link waits for its own lost segments: a little behind an equal packet path
        let s = if self.kind == Some(PathKind::Stream) { 5.0 } else { 0.0 };
        self.srtt + 3.0 * self.jit + 2000.0 * self.loss + s
    }
    fn rtt_sample(&mut self, ms: f64, now: Instant) {
        if self.srtt == 0.0 {
            self.srtt = ms;
            self.jit = ms / 4.0;
        } else {
            self.jit = 0.75 * self.jit + 0.25 * (ms - self.srtt).abs();
            self.srtt = 0.875 * self.srtt + 0.125 * ms;
        }
        // the empty-queue round trip, forgotten after 10 s so a slower route is learned
        if self.min_rtt == 0.0 || ms < self.min_rtt || self.min_at.is_none_or(|t| now.duration_since(t) > Duration::from_secs(10)) {
            self.min_rtt = ms;
            self.min_at = Some(now);
        }
    }
}

// ------------------------------------------------------------------ the session

struct Hs {
    ini: Initiator,
    pkts: Vec<Vec<u8>>,
    started: Instant,
    sent: Option<Instant>,
}

struct Pending {
    keys: Arc<Keys>,
    peer: [u8; 8],
    at: Instant,
}

/// A first message seen by the listener: its answer, sent again for a copy of the same message
struct SeenInit {
    at: Instant,
    resp: Vec<Vec<u8>>,
    resent: VecDeque<Instant>,
}

/// Game priority: when realtime traffic goes and the best path's round trip grows past its empty-queue
/// value, the bulk class is held to a little less than it was getting, until the queue is gone
struct Guard {
    on: bool,
    rate: f64,
    tokens: f64,
    /// last refill of the tokens, last look at the queue
    refill_at: Instant,
    tick_at: Instant,
    bytes: u64,
    measured: f64,
    clear_since: Option<Instant>,
}

struct Session {
    spec: VipSpec,
    psk: [u8; 32],
    instance: [u8; 8],
    kinds: Vec<PathKind>,
    slots: Slots,
    down: mpsc::Sender<Down>,
    status: Arc<Mutex<VipStatus>>,
    counters: Arc<flows::Counters>,
    screen: Arc<Screen>,
    t0: Instant,
    paths: Vec<PathM>,
    order: Vec<usize>,
    order_at: Option<Instant>,
    // keys
    cur: Option<Arc<Keys>>,
    prev: Option<(Arc<Keys>, Instant)>,
    pending: Vec<Pending>,
    keys_at: Option<Instant>,
    peer_inst: Option<[u8; 8]>,
    hs: Option<Hs>,
    seen_inits: HashMap<[u8; 8], SeenInit>,
    asm: HsAsm,
    last_rx: Option<Instant>,
    rekeys: u64,
    since: i64,
    error: String,
    error_at: Option<Instant>,
    // what came in
    replay: Vec<Replay>,
    reasm: Vec<Reasm>,
    rx_gen: u8,
    junk: u64,
    // realtime class
    rt_seq: u32,
    rt_tx: RlcTx,
    rt_rx: RlcRx,
    rt_dedup: Dedup,
    rt_since_fix: u32,
    rt_last: Option<Instant>,
    rt_tail: Option<Instant>,
    late: VecDeque<(Instant, usize, Vec<u8>)>,
    rt_got: u64,
    peer_rep: Option<(u32, u64)>,
    resid: f64,
    // bulk class
    lanes: usize,
    bulk_seq: Vec<u32>,
    bulk_tx: Vec<RlcTx>,
    bulk_rx: Vec<RlcRx>,
    bulk_dedup: Vec<Dedup>,
    bulk_rr: usize,
    bulk_credit: f64,
    bulk_got: u64,
    guard: Guard,
    frag_id: u32,
    /// small packets of each user flow in its current second: (start, count, heavy last second)
    rates: HashMap<(u8, u32), (Instant, u32, bool)>,
    /// the last round of the slower timers
    tick_at: Option<Instant>,
    // counts
    st: VipStatus,
    // the quality check (entry): sent echoes and their answers
    echo_id: u32,
    echoes: VecDeque<(u32, Instant, Option<f64>)>,
    next_echo: Option<Instant>,
    next_report: Option<Instant>,
    next_status: Option<Instant>,
}

impl Session {
    fn new(spec: VipSpec, psk: [u8; 32], slots: Slots, down: mpsc::Sender<Down>, status: Arc<Mutex<VipStatus>>, counters: Arc<flows::Counters>, screen: Arc<Screen>) -> Session {
        let kinds = spec.paths();
        let n = kinds.len();
        let lanes = 1usize << spec.stride_bits();
        let now = Instant::now();
        Session {
            psk,
            instance: rand::random(),
            paths: kinds.iter().map(|k| PathM { kind: Some(*k), ..Default::default() }).collect(),
            kinds,
            slots,
            down,
            status,
            counters,
            screen,
            t0: now,
            order: (0..n).collect(),
            order_at: None,
            cur: None,
            prev: None,
            pending: vec![],
            keys_at: None,
            peer_inst: None,
            hs: None,
            seen_inits: HashMap::new(),
            asm: HsAsm::default(),
            last_rx: None,
            rekeys: 0,
            since: 0,
            error: String::new(),
            error_at: None,
            replay: (0..n).map(|_| Replay::default()).collect(),
            reasm: (0..n).map(|_| Reasm::default()).collect(),
            rx_gen: rand::random(),
            junk: 0,
            rt_seq: rand::random(),
            rt_tx: RlcTx::default(),
            rt_rx: RlcRx::default(),
            rt_dedup: Dedup::default(),
            rt_since_fix: 0,
            rt_last: None,
            rt_tail: None,
            late: VecDeque::new(),
            rt_got: 0,
            peer_rep: None,
            resid: 0.0,
            lanes,
            bulk_seq: (0..lanes).map(|_| rand::random()).collect(),
            bulk_tx: (0..lanes).map(|_| RlcTx::default()).collect(),
            bulk_rx: (0..lanes).map(|_| RlcRx::default()).collect(),
            bulk_dedup: (0..lanes).map(|_| Dedup::default()).collect(),
            bulk_rr: 0,
            bulk_credit: 0.0,
            bulk_got: 0,
            guard: Guard { on: false, rate: 0.0, tokens: 0.0, refill_at: now, tick_at: now, bytes: 0, measured: 0.0, clear_since: None },
            frag_id: rand::random(),
            rates: HashMap::new(),
            tick_at: None,
            st: VipStatus { id: spec.id.clone(), role: spec.role.clone(), ..Default::default() },
            echo_id: 0,
            echoes: VecDeque::new(),
            next_echo: None,
            next_report: None,
            next_status: None,
            spec,
        }
    }

    async fn run(mut self, mut inbound: mpsc::Receiver<In>, mut up: mpsc::Receiver<Up>) {
        loop {
            let due = self.next_due();
            tokio::select! {
                biased;
                m = inbound.recv() => {
                    let Some(m) = m else { return };
                    self.on_packet(m);
                    // a burst is handled before the timers
                    for _ in 0..64 {
                        match inbound.try_recv() {
                            Ok(m) => self.on_packet(m),
                            Err(_) => break,
                        }
                    }
                }
                u = up.recv() => {
                    let Some(u) = u else { return };
                    self.on_up(u);
                    for _ in 0..64 {
                        match up.try_recv() {
                            Ok(u) => self.on_up(u),
                            Err(_) => break,
                        }
                    }
                }
                _ = tokio::time::sleep_until(due.into()) => {}
            }
            self.on_timer();
        }
    }

    fn ms(&self, now: Instant) -> u32 {
        now.duration_since(self.t0).as_millis() as u32
    }

    fn mode(&self) -> &str {
        match self.spec.mode.as_str() {
            "speed" => "speed",
            "balanced" => "balanced",
            _ => "gaming",
        }
    }

    fn next_due(&self) -> Instant {
        let now = Instant::now();
        let mut due = now + Duration::from_millis(50);
        if let Some(t) = self.rt_tail {
            due = due.min(t);
        }
        if let Some((t, _, _)) = self.late.front() {
            due = due.min(*t);
        }
        due.max(now)
    }

    // ------------------------------------------------------------ sending

    fn out(&self, p: usize) -> Option<Out> {
        self.slots.lock().unwrap_or_else(|e| e.into_inner()).get(p).and_then(|s| s.out.clone())
    }

    fn mtu(&self, p: usize) -> usize {
        match self.kinds[p] {
            PathKind::Udp => self.spec.udp_mtu(),
            PathKind::Ftcp => super::FTCP_MTU,
            PathKind::Stream => 16_000,
        }
    }

    /// Seals one payload (frames) for path `p` and sends it; a payload bigger than the path takes goes in
    /// fragments. False = not sent (no keys, no carrier, a full queue).
    fn send(&mut self, p: usize, payload: &[u8]) -> bool {
        let Some(out) = self.out(p) else { return false };
        let room = self.mtu(p) - crypto::OVERHEAD;
        if payload.len() > room {
            self.frag_id = self.frag_id.wrapping_add(1);
            let parts = wire::fragments(self.frag_id, payload, room);
            let mut ok = !parts.is_empty();
            for f in parts {
                ok &= self.seal_send(p, &out, &f, room);
            }
            return ok;
        }
        self.seal_send(p, &out, payload, room)
    }

    fn seal_send(&mut self, p: usize, out: &Out, payload: &[u8], room: usize) -> bool {
        let Some(k) = &self.cur else { return false };
        let fill = wire::filler(self.spec.stealth, payload.len(), room.saturating_sub(payload.len()));
        let mut body = Vec::with_capacity(payload.len() + fill);
        body.extend_from_slice(payload);
        wire::pad(&mut body, fill);
        let pm = &mut self.paths[p];
        let pn = pm.pn;
        pm.pn += 1;
        let mut pkt = Vec::with_capacity(body.len() + crypto::OVERHEAD);
        k.tx.seal(p as u8, pn, &body, &mut pkt);
        pm.tx_pk += 1;
        self.st.tx_bytes += pkt.len() as u64;
        out.send(pkt)
    }

    fn frame(&mut self, p: usize, f: &Frame) -> bool {
        let mut v = Vec::with_capacity(64);
        wire::put(&mut v, f);
        self.send(p, &v)
    }

    /// Paths in the order they are worth using now (refreshed every 50 ms, or at once when asked)
    fn rank(&mut self, now: Instant, force: bool) {
        if !force && self.order_at.is_some_and(|t| now.duration_since(t) < Duration::from_millis(50)) {
            return;
        }
        let have: Vec<bool> = {
            let s = self.slots.lock().unwrap_or_else(|e| e.into_inner());
            (0..self.paths.len()).map(|i| s.get(i).is_some_and(|x| x.out.is_some())).collect()
        };
        let mut v: Vec<(usize, f64)> = (0..self.paths.len()).filter(|i| have[*i]).map(|i| (i, self.paths[i].score(now, i))).collect();
        v.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
        // the best path stays unless another is clearly better: no flapping between two equal ones
        if let (Some(&old), Some(&(new, ns))) = (self.order.first(), v.first()) {
            if old != new {
                if let Some(&(_, os)) = v.iter().find(|x| x.0 == old) {
                    if os < 10_000.0 && ns > os * 0.85 - 3.0 {
                        let i = v.iter().position(|x| x.0 == old).unwrap_or(0);
                        let x = v.remove(i);
                        v.insert(0, x);
                    }
                }
            }
        }
        self.order = v.into_iter().map(|x| x.0).collect();
        self.order_at = Some(now);
    }

    /// The paths of one realtime packet: the best, and the next one when the mode or the line asks for a copy
    fn rt_paths(&mut self, now: Instant) -> Vec<usize> {
        self.rank(now, false);
        let Some(&a) = self.order.first() else { return vec![] };
        let pa = &self.paths[a];
        let shaky = pa.loss > 0.005 || pa.jit > 8.0 || pa.stalled(now) || !pa.up(now) || self.resid > 0.002;
        let want = match self.mode() {
            "gaming" => true,
            "balanced" => shaky,
            _ => false,
        };
        let mut v = vec![a];
        if want {
            if let Some(&b) = self.order.get(1) {
                // a copy that arrives far behind helps nobody
                let (sa, sb) = (self.paths[a].score(now, a), self.paths[b].score(now, b));
                if sb < 10_000.0 || sa >= 10_000.0 {
                    if sb < sa * 3.0 + 60.0 || sa >= 10_000.0 {
                        v.push(b);
                    }
                }
            }
        }
        v
    }

    /// `user`: the users' own traffic (an echo of the quality check does not make the class active)
    fn send_rt(&mut self, inner: Vec<u8>, now: Instant, user: bool) {
        if self.cur.is_none() {
            return;
        }
        let ps = self.rt_paths(now);
        let Some(&first) = ps.first() else { return };
        let seq = self.rt_seq;
        self.rt_seq = seq.wrapping_add(1);
        let mut f = Vec::with_capacity(inner.len() + wire::DATA_HEAD);
        wire::put(&mut f, &Frame::Data { bulk: false, lane: 0, seq, inner: &inner });
        self.send(first, &f);
        self.st.rt_tx += 1;
        if let Some(&second) = ps.get(1) {
            if self.send(second, &f) {
                self.st.rt_copies += 1;
            }
        } else if self.mode() == "gaming" || (self.mode() == "balanced" && self.paths[first].loss > 0.02) {
            // one path: the copy a little later, so a short outage takes only one of them
            if self.late.len() < 512 {
                self.late.push_back((now + LATE_COPY, first, f));
            }
        }
        self.rt_tx.add(seq, &inner, now + RT_LIFE);
        if user {
            self.rt_last = Some(now);
        }
        self.rt_since_fix += 1;
        let loss = self.paths[first].loss.max(self.resid);
        let every = match self.mode() {
            "gaming" => 2,
            "balanced" => if loss < 0.01 { 4 } else { 2 },
            _ => if loss < 0.01 { 8 } else { 4 },
        };
        if self.rt_since_fix >= every {
            self.rt_repair(now);
        } else if self.mode() != "speed" || loss > 0.005 {
            self.rt_tail = Some(now + TAIL);
        }
    }

    /// One repair over the newest realtime packets, on another path than their first copy when there is one
    fn rt_repair(&mut self, now: Instant) {
        self.rt_since_fix = 0;
        self.rt_tail = None;
        let Some(r) = self.rt_tx.repair(now, crate::kprlc::MAX_WIN) else { return };
        let ps = self.rt_paths(now);
        let p = *ps.get(1).or(ps.first()).unwrap_or(&0);
        if self.frame(p, &Frame::Fix { bulk: false, lane: 0, rlc: &r }) {
            self.st.rt_fix_tx += 1;
        }
    }

    fn bulk_path(&mut self, now: Instant) -> Option<usize> {
        self.rank(now, false);
        self.order.first().copied()
    }

    fn send_bulk(&mut self, inner: Vec<u8>, now: Instant) {
        if self.cur.is_none() {
            return;
        }
        let Some(p) = self.bulk_path(now) else { return };
        if !self.guard_allow(inner.len(), now) {
            return;
        }
        let lane = self.bulk_rr % self.lanes;
        self.bulk_rr = self.bulk_rr.wrapping_add(1);
        let seq = self.bulk_seq[lane];
        self.bulk_seq[lane] = seq.wrapping_add(1);
        let mut f = Vec::with_capacity(inner.len() + wire::DATA_HEAD);
        wire::put(&mut f, &Frame::Data { bulk: true, lane: lane as u8, seq, inner: &inner });
        self.send(p, &f);
        self.st.bulk_tx += 1;
        self.bulk_tx[lane].add(seq, &inner, now + BULK_LIFE);
        let pm = &self.paths[p];
        let l = pm.loss;
        let mut ratio = if l < 0.002 {
            0.0
        } else if self.mode() == "speed" {
            (1.5 * l).min(0.2)
        } else {
            (2.0 * l + 0.01).min(0.25)
        };
        // a growing queue means the loss is the line being full: more repairs would only fill it more
        if pm.min_rtt > 0.0 && pm.srtt > pm.min_rtt + (0.5 * pm.min_rtt).max(20.0) {
            ratio /= 2.0;
        }
        self.bulk_credit += ratio;
        if self.bulk_credit >= 1.0 {
            self.bulk_credit -= 1.0;
            if let Some(r) = self.bulk_tx[lane].repair(now, crate::kprlc::MAX_WIN) {
                if self.frame(p, &Frame::Fix { bulk: true, lane: lane as u8, rlc: &r }) {
                    self.st.bulk_fix_tx += 1;
                }
            }
        }
    }

    fn guard_allow(&mut self, len: usize, now: Instant) -> bool {
        self.guard.bytes += len as u64;
        if !self.guard.on {
            return true;
        }
        let dt = now.duration_since(self.guard.refill_at).as_secs_f64();
        self.guard.refill_at = now;
        self.guard.tokens = (self.guard.tokens + dt * self.guard.rate).min(self.guard.rate * 0.05 + 3000.0);
        if self.guard.tokens < len as f64 {
            return false;
        }
        self.guard.tokens -= len as f64;
        true
    }

    /// every 200 ms
    fn guard_tick(&mut self, now: Instant, dt: f64) {
        let measured = self.guard.bytes as f64 / dt.max(0.05);
        self.guard.bytes = 0;
        self.guard.measured = 0.7 * self.guard.measured + 0.3 * measured;
        let rt_on = self.rt_last.is_some_and(|t| now.duration_since(t) < RT_ACTIVE);
        let best = self.order.first().copied();
        let queue = best.map(|b| {
            let p = &self.paths[b];
            if p.srtt > 0.0 && p.min_rtt > 0.0 { (p.srtt - p.min_rtt, p.min_rtt) } else { (0.0, 0.0) }
        });
        let crowded = matches!(queue, Some((q, m)) if m > 0.0 && q > (0.3 * m).max(12.0));
        if self.mode() == "speed" || !rt_on {
            self.guard.on = false;
            return;
        }
        if crowded {
            let target = (self.guard.measured * 0.85).max(64_000.0);
            self.guard.rate = if self.guard.on { (self.guard.rate * 0.85).max(64_000.0).min(target.max(64_000.0)) } else { target };
            if !self.guard.on {
                self.guard.tokens = 0.0;
                self.guard.refill_at = now;
            }
            self.guard.on = true;
            self.guard.clear_since = None;
        } else if self.guard.on {
            self.guard.rate *= 1.15;
            let since = *self.guard.clear_since.get_or_insert(now);
            if now.duration_since(since) > Duration::from_secs(3) && self.guard.rate > self.guard.measured * 2.0 {
                self.guard.on = false;
            }
        }
    }

    // ------------------------------------------------------------ what the users send

    fn on_up(&mut self, u: Up) {
        let now = Instant::now();
        match u {
            Up::Udp { pidx, flow, data } => {
                // small, and from a flow that sends at a game's pace: a flow of hundreds of small packets a
                // second is the acknowledgements of a download (inside WireGuard, say), not a game
                let rt = data.len() <= self.spec.rt_limit() && !self.heavy(pidx, flow, now);
                let inner = wire::inner_udp(pidx, flow, &data);
                if rt { self.send_rt(inner, now, true) } else { self.send_bulk(inner, now) }
            }
            // the TCP connections: QUIC sends its lost packets again by itself, so they never take the
            // realtime class's copies (and never make it look busy)
            Up::Quic(d) => self.send_bulk(wire::inner_quic(&d), now),
        }
    }

    /// Counts a small packet of a flow: true when the flow sent more than `HEAVY` of them in its last second
    fn heavy(&mut self, pidx: u8, flow: u32, now: Instant) -> bool {
        if self.rates.len() > 4096 {
            self.rates.retain(|_, r| now.duration_since(r.0) < Duration::from_secs(10));
        }
        let r = self.rates.entry((pidx, flow)).or_insert((now, 0, false));
        if now.duration_since(r.0) >= Duration::from_secs(1) {
            r.2 = r.1 > HEAVY;
            *r = (now, 0, r.2);
        }
        r.1 += 1;
        r.2 || r.1 > HEAVY
    }

    fn deliver(&mut self, inner: &[u8], now: Instant) {
        match wire::inner(inner) {
            Some(Inner::Udp { pidx, flow, data }) => {
                let _ = self.down.try_send(Down::Udp { pidx, flow, data: data.to_vec() });
            }
            Some(Inner::Quic(d)) => {
                let _ = self.down.try_send(Down::Quic(d.to_vec()));
            }
            Some(Inner::Echo { back: false, id, t }) => self.send_rt(wire::inner_echo(true, id, t), now, false),
            Some(Inner::Echo { back: true, id, t }) => {
                let rtt = self.ms(now).wrapping_sub(t) as f64;
                if let Some(e) = self.echoes.iter_mut().find(|e| e.0 == id && e.2.is_none()) {
                    e.2 = Some(rtt);
                }
            }
            None => {}
        }
    }

    // ------------------------------------------------------------ what came in

    fn on_packet(&mut self, m: In) {
        let now = Instant::now();
        let In { got, reply } = m;
        let (keys, p, pn, payload) = match got {
            Got::Hs(part) => {
                if let Some((kind, id, body)) = self.asm.add(part) {
                    self.on_hs(kind, id, body, reply, now);
                }
                return;
            }
            Got::Data { keys, path, pn, payload } => (keys, path, pn, payload),
        };
        // which of our keys opened it (the reader saw them a moment ago: they may have moved on since)
        let same = |k: &Option<Arc<Keys>>| k.as_ref().is_some_and(|k| Arc::ptr_eq(k, &keys));
        let promote = if same(&self.cur) || self.prev.as_ref().is_some_and(|(k, _)| Arc::ptr_eq(k, &keys)) {
            None
        } else {
            match self.pending.iter().position(|pd| Arc::ptr_eq(&pd.keys, &keys)) {
                Some(i) => Some(i),
                None => return,
            }
        };
        let p = p as usize;
        if p >= self.paths.len() {
            return;
        }
        if let Some(i) = promote {
            let pd = self.pending.remove(i);
            let fresh = self.peer_inst != Some(pd.peer);
            if let Some(old) = self.cur.take() {
                self.prev = Some((old, now));
            }
            self.cur = Some(pd.keys);
            self.keys_at = Some(now);
            self.peer_inst = Some(pd.peer);
            self.rekeys += 1;
            if fresh {
                self.reset_rx(now);
            }
            // the confirmed keys replace every other offer
            self.pending.clear();
            self.publish_ring();
        }
        if !self.replay[p].take(pn) {
            return;
        }
        // the listener answers each path where its newest packets come from (a UDP path moves when it hops;
        // a late packet of the old socket does not move it back)
        if !self.spec.dials && (pn >= self.paths[p].rx_hi || self.paths[p].rx_cnt == 0) {
            let mut s = self.slots.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(slot) = s.get_mut(p) {
                if !slot.out.as_ref().is_some_and(|o| o.same(&reply)) {
                    // a UDP path moves over the port range; the fake-TCP relay answers from loopback
                    if let (Out::Udp(sock, _), PathKind::Udp) = (&reply, self.kinds[p]) {
                        slot.port = sock.local_addr().map(|a| a.port()).unwrap_or(0);
                    }
                    slot.out = Some(reply);
                }
            }
        }
        self.last_rx = Some(now);
        self.st.rx_bytes += (payload.len() + crypto::OVERHEAD) as u64;
        {
            let pm = &mut self.paths[p];
            pm.last_rx = Some(now);
            pm.rx_pk += 1;
            pm.rx_cnt += 1;
            pm.rx_hi = pm.rx_hi.max(pn);
        }
        self.on_payload(p, &payload, now, true);
    }

    fn on_payload(&mut self, p: usize, payload: &[u8], now: Instant, top: bool) {
        for f in wire::frames(payload) {
            match f {
                Frame::Ping { id, t } => {
                    let (hi, cnt) = (self.paths[p].rx_hi, self.paths[p].rx_cnt);
                    let g = self.rx_gen;
                    self.frame(p, &Frame::Pong { id, t, gen: g, hi, cnt });
                }
                Frame::Pong { id, t: _, gen, hi, cnt } => self.on_pong(p, id, gen, hi, cnt, now),
                Frame::Report { rt_top, rt_got, .. } => {
                    if let Some((t0, g0)) = self.peer_rep {
                        let dt = rt_top.wrapping_sub(t0);
                        if dt >= 10 && dt < 1 << 30 && rt_got >= g0 {
                            let got = (rt_got - g0) as f64;
                            let sample = (1.0 - got / dt as f64).clamp(0.0, 1.0);
                            self.resid = 0.7 * self.resid + 0.3 * sample;
                            self.peer_rep = Some((rt_top, rt_got));
                        } else if dt >= 1 << 30 || rt_got < g0 {
                            self.peer_rep = Some((rt_top, rt_got));
                        }
                    } else {
                        self.peer_rep = Some((rt_top, rt_got));
                    }
                }
                Frame::Data { bulk: false, seq, inner, .. } => {
                    if !self.rt_dedup.take(seq) {
                        self.st.rt_dups += 1;
                        continue;
                    }
                    self.st.rt_rx += 1;
                    self.rt_got += 1;
                    self.deliver(inner, now);
                    for (s, b) in self.rt_rx.data(seq, inner, now) {
                        self.rt_rebuilt(s, &b, now);
                    }
                }
                Frame::Fix { bulk: false, rlc, .. } => {
                    for (s, b) in self.rt_rx.repair(rlc, now) {
                        self.rt_rebuilt(s, &b, now);
                    }
                }
                Frame::Data { bulk: true, lane, seq, inner } => {
                    let l = lane as usize;
                    if l >= self.lanes || !self.bulk_dedup[l].take(seq) {
                        continue;
                    }
                    self.st.bulk_rx += 1;
                    self.bulk_got += 1;
                    self.deliver(inner, now);
                    for (s, b) in self.bulk_rx[l].data(seq, inner, now) {
                        self.bulk_rebuilt(l, s, &b, now);
                    }
                }
                Frame::Fix { bulk: true, lane, rlc } => {
                    let l = lane as usize;
                    if l >= self.lanes {
                        continue;
                    }
                    for (s, b) in self.bulk_rx[l].repair(rlc, now) {
                        self.bulk_rebuilt(l, s, &b, now);
                    }
                }
                Frame::Frag { id, idx, total, chunk } => {
                    if !top {
                        continue;
                    }
                    if let Some(whole) = self.reasm[p].add(id, idx, total, chunk, now) {
                        self.on_payload(p, &whole, now, false);
                    }
                }
            }
        }
    }

    fn rt_rebuilt(&mut self, s: u32, b: &[u8], now: Instant) {
        if self.rt_dedup.take(s) {
            self.st.rt_fixed += 1;
            self.rt_got += 1;
            self.deliver(b, now);
        }
    }

    fn bulk_rebuilt(&mut self, l: usize, s: u32, b: &[u8], now: Instant) {
        if self.bulk_dedup[l].take(s) {
            self.st.bulk_fixed += 1;
            self.bulk_got += 1;
            self.deliver(b, now);
        }
    }

    fn on_pong(&mut self, p: usize, id: u32, gen: u8, hi: u64, cnt: u64, now: Instant) {
        let pm = &mut self.paths[p];
        let Some(i) = pm.pings.iter().position(|x| x.0 == id) else { return };
        let (_, at) = pm.pings[i];
        // older pings than this one were lost or came late: they are not waited for any more
        pm.pings.drain(..=i);
        pm.rtt_sample(now.duration_since(at).as_secs_f64() * 1000.0, now);
        pm.last_pong = Some(now);
        match pm.base {
            Some((g, h0, c0)) if g == gen && hi >= h0 && cnt >= c0 => {
                let sent = hi - h0;
                // a sample needs enough packets to mean something
                if sent >= 20 {
                    let sample = (1.0 - (cnt - c0) as f64 / sent as f64).clamp(0.0, 1.0);
                    pm.loss = 0.7 * pm.loss + 0.3 * sample;
                    pm.base = Some((gen, hi, cnt));
                }
            }
            _ => pm.base = Some((gen, hi, cnt)),
        }
    }

    /// A new peer (it started again): what we knew of its packets is forgotten
    fn reset_rx(&mut self, now: Instant) {
        let n = self.paths.len();
        self.replay = (0..n).map(|_| Replay::default()).collect();
        self.reasm = (0..n).map(|_| Reasm::default()).collect();
        self.rt_rx = RlcRx::default();
        self.rt_dedup = Dedup::default();
        self.bulk_rx = (0..self.lanes).map(|_| RlcRx::default()).collect();
        self.bulk_dedup = (0..self.lanes).map(|_| Dedup::default()).collect();
        self.peer_rep = None;
        self.rx_gen = self.rx_gen.wrapping_add(1);
        for pm in self.paths.iter_mut() {
            pm.rx_hi = 0;
            pm.rx_cnt = 0;
            pm.base = None;
            pm.pings.clear();
            pm.next_ping = Some(now);
        }
        self.since = crate::util::now();
    }

    // ------------------------------------------------------------ handshakes

    /// The readers open packets with exactly these keys from now on
    fn publish_ring(&self) {
        self.screen.set(Ring { cur: self.cur.clone(), prev: self.prev.as_ref().map(|x| x.0.clone()), pending: self.pending.iter().map(|p| p.keys.clone()).collect() });
    }

    fn note_error(&mut self, e: String, now: Instant) {
        self.error = e;
        self.error_at = Some(now);
    }

    fn on_hs(&mut self, kind: u8, id: [u8; 8], body: Vec<u8>, reply: Out, now: Instant) {
        if kind == crypto::HS_INIT && !self.spec.dials {
            if let Some(s) = self.seen_inits.get_mut(&id) {
                // a copy of a message already answered (lost answer, or it came on another path too)
                while s.resent.front().is_some_and(|t| now.duration_since(*t) > Duration::from_secs(1)) {
                    s.resent.pop_front();
                }
                if s.resent.len() < 8 {
                    s.resent.push_back(now);
                    for p in &s.resp {
                        reply.send(p.clone());
                    }
                }
                return;
            }
            let unix = crate::util::now().max(0) as u64;
            match crypto::respond(&self.psk, &body, &self.instance, unix) {
                Ok(acc) => {
                    let resp = crypto::hs_seal(&self.psk, crypto::HS_RESP, &id, &acc.resp, 560 + rand::random::<usize>() % 140, if self.spec.stealth > 0 { 120 } else { 24 });
                    for p in &resp {
                        reply.send(p.clone());
                    }
                    self.seen_inits.retain(|_, v| now.duration_since(v.at) < Duration::from_secs(2 * crypto::MAX_SKEW));
                    if self.seen_inits.len() >= 256 {
                        if let Some(k) = self.seen_inits.iter().min_by_key(|x| x.1.at).map(|x| *x.0) {
                            self.seen_inits.remove(&k);
                        }
                    }
                    self.seen_inits.insert(id, SeenInit { at: now, resp, resent: VecDeque::new() });
                    if self.pending.len() >= 4 {
                        self.pending.remove(0);
                    }
                    self.pending.push(Pending { keys: Arc::new(acc.keys), peer: acc.peer, at: now });
                    self.publish_ring();
                }
                Err(crypto::HsErr::Skew(d)) => self.note_error(format!("the clocks of the two servers differ by {} s (more than {} s): set the time on both", d, crypto::MAX_SKEW), now),
                Err(crypto::HsErr::Bad) => self.note_error("the other side runs another version of the VIP tunnel: update both".into(), now),
            }
            return;
        }
        if kind == crypto::HS_RESP && self.spec.dials {
            let Some(hs) = &mut self.hs else { return };
            if hs.ini.id() != id {
                return;
            }
            let Some((keys, inst)) = hs.ini.finish(&self.psk, &body) else { return };
            self.hs = None;
            let fresh = self.peer_inst != Some(inst);
            if let Some(old) = self.cur.take() {
                self.prev = Some((old, now));
            }
            self.st.pq = keys.pq;
            self.cur = Some(Arc::new(keys));
            self.publish_ring();
            self.keys_at = Some(now);
            self.peer_inst = Some(inst);
            self.rekeys += 1;
            self.last_rx = Some(now);
            if fresh {
                self.reset_rx(now);
            }
            if self.error.contains("clocks") || self.error.contains("version") || self.error.contains("no answer") {
                self.error.clear();
            }
            // pings on every path at once: the listener confirms the keys and learns where each path is
            for pm in self.paths.iter_mut() {
                pm.next_ping = Some(now);
            }
        }
    }

    fn hs_tick(&mut self, now: Instant) {
        if !self.spec.dials {
            let n = self.pending.len();
            self.pending.retain(|p| now.duration_since(p.at) < Duration::from_secs(20));
            if self.pending.len() != n {
                self.publish_ring();
            }
            return;
        }
        let rekey = Duration::from_secs(self.spec.rekey().max(5));
        let need = self.cur.is_none()
            || self.keys_at.is_some_and(|t| now.duration_since(t) >= rekey)
            || self.last_rx.is_none_or(|t| now.duration_since(t) >= SILENCE);
        if self.hs.is_none() && need {
            let ini = Initiator::new(&self.instance, self.spec.pq, crate::util::now().max(0) as u64);
            let pkts = crypto::hs_seal(&self.psk, crypto::HS_INIT, &ini.id(), ini.body(), 560 + rand::random::<usize>() % 140, if self.spec.stealth > 0 { 120 } else { 24 });
            self.hs = Some(Hs { ini, pkts, started: now, sent: None });
        }
        let Some(hs) = &mut self.hs else { return };
        if hs.sent.is_some_and(|t| now.duration_since(t) < Duration::from_millis(1000)) {
            return;
        }
        if now.duration_since(hs.started) > Duration::from_secs(10) {
            // no answer: a new first message (the old one may be the problem)
            self.hs = None;
            if self.cur.is_none() || self.last_rx.is_none_or(|t| now.duration_since(t) >= SILENCE) {
                self.note_error("no answer from the other server yet".into(), now);
            }
            return;
        }
        hs.sent = Some(now);
        let pkts = hs.pkts.clone();
        let outs: Vec<Out> = self.slots.lock().unwrap_or_else(|e| e.into_inner()).iter().filter_map(|s| s.out.clone()).collect();
        for o in outs {
            for p in &pkts {
                o.send(p.clone());
            }
        }
    }

    // ------------------------------------------------------------ the clock

    fn on_timer(&mut self) {
        let now = Instant::now();
        while self.late.front().is_some_and(|x| x.0 <= now) {
            if let Some((_, p, f)) = self.late.pop_front() {
                if self.send(p, &f) {
                    self.st.rt_copies += 1;
                }
            }
        }
        if self.rt_tail.is_some_and(|t| t <= now) {
            self.rt_repair(now);
        }
        // the rest runs at most every 50 ms
        if self.tick_at.is_some_and(|t| now.duration_since(t) < Duration::from_millis(50)) {
            return;
        }
        self.tick_at = Some(now);
        self.rank(now, true);
        self.hs_tick(now);
        if self.prev.as_ref().is_some_and(|(_, at)| now.duration_since(*at) > PREV_KEEP) {
            self.prev = None;
            self.publish_ring();
        }
        if self.cur.is_some() {
            self.ping_tick(now);
            if self.next_report.is_none_or(|t| t <= now) {
                self.next_report = Some(now + Duration::from_secs(1));
                let rep = Frame::Report { rt_top: self.rt_dedup.top(), rt_got: self.rt_got, bulk_top: 0, bulk_got: self.bulk_got };
                if let Some(&b) = self.order.first() {
                    self.frame(b, &rep);
                }
            }
            if self.spec.entry() && self.next_echo.is_none_or(|t| t <= now) {
                self.next_echo = Some(now + Duration::from_secs(1));
                self.echo_id = self.echo_id.wrapping_add(1);
                let id = self.echo_id;
                self.echoes.push_back((id, now, None));
                while self.echoes.front().is_some_and(|e| now.duration_since(e.1) > Duration::from_secs(62)) {
                    self.echoes.pop_front();
                }
                let t = self.ms(now);
                // the echo itself is realtime, not counted as the users' traffic
                self.send_rt(wire::inner_echo(false, id, t), now, false);
            }
        }
        // game priority, every 200 ms
        let gdt = now.duration_since(self.guard.tick_at).as_secs_f64();
        if gdt >= 0.2 {
            self.guard.tick_at = now;
            self.guard_tick(now, gdt);
        }
        if self.next_status.is_none_or(|t| t <= now) {
            self.next_status = Some(now + Duration::from_secs(1));
            self.publish(now);
        }
    }

    fn ping_tick(&mut self, now: Instant) {
        let rt_on = self.rt_last.is_some_and(|t| now.duration_since(t) < RT_ACTIVE);
        let every = if self.mode() == "gaming" || rt_on { Duration::from_millis(300) } else { Duration::from_millis(1000) };
        let have: Vec<bool> = {
            let s = self.slots.lock().unwrap_or_else(|e| e.into_inner());
            (0..self.paths.len()).map(|i| s.get(i).is_some_and(|x| x.out.is_some())).collect()
        };
        for p in 0..self.paths.len() {
            if !have[p] || self.paths[p].next_ping.is_some_and(|t| t > now) {
                continue;
            }
            let id = rand::random::<u32>();
            let t = self.ms(now);
            {
                let pm = &mut self.paths[p];
                pm.next_ping = Some(now + every);
                if pm.pings.len() >= 32 {
                    pm.pings.pop_front();
                }
                pm.pings.push_back((id, now));
            }
            self.frame(p, &Frame::Ping { id, t });
        }
    }

    fn publish(&mut self, now: Instant) {
        if self.error_at.is_some_and(|t| now.duration_since(t) > Duration::from_secs(60)) {
            self.error.clear();
            self.error_at = None;
        }
        let ranks: Vec<usize> = self.rt_paths(now);
        let slots = self.slots.lock().unwrap_or_else(|e| e.into_inner());
        let mut paths = vec![];
        for (i, pm) in self.paths.iter_mut().enumerate() {
            pm.rank = ranks.iter().position(|x| *x == i).map(|x| x as u8 + 1).unwrap_or(0);
            let slot = slots.get(i);
            let state = if pm.up(now) && !pm.stalled(now) {
                2
            } else if pm.last_rx.is_some_and(|t| now.duration_since(t) < Duration::from_secs(10)) {
                1
            } else {
                0
            };
            paths.push(PathStatus {
                id: i as u8,
                kind: match self.kinds[i] {
                    PathKind::Udp => "udp",
                    PathKind::Ftcp => "ftcp",
                    PathKind::Stream => "stream",
                }
                .into(),
                state,
                rank: pm.rank,
                rtt_ms: (pm.srtt * 10.0).round() / 10.0,
                jit_ms: (pm.jit * 10.0).round() / 10.0,
                loss: (pm.loss * 1000.0).round() / 10.0,
                tx_pk: pm.tx_pk,
                rx_pk: pm.rx_pk,
                port: slot.map(|s| s.port).unwrap_or(0),
                error: slot.map(|s| s.error.clone()).unwrap_or_default(),
            });
        }
        drop(slots);
        let up = self.cur.is_some() && paths.iter().any(|p| p.state == 2);
        if up && self.since == 0 {
            self.since = crate::util::now();
        }
        if !up {
            self.since = 0;
        }
        let quality = self.quality(now);
        let mut st = self.st.clone();
        st.up = up;
        st.since = self.since;
        st.error = self.error.clone();
        st.paths = paths;
        st.rekeys = self.rekeys;
        st.junk = self.junk + self.screen.junk.load(std::sync::atomic::Ordering::Relaxed);
        st.rt_resid = (self.resid * 1000.0).round() / 10.0;
        st.streams = self.counters.streams.load(std::sync::atomic::Ordering::Relaxed);
        st.udp_flows = self.counters.udp_flows.load(std::sync::atomic::Ordering::Relaxed);
        st.quality = quality;
        st.guard_bps = if self.guard.on { self.guard.rate as u64 } else { 0 };
        if self.cur.is_none() {
            st.pq = false;
        } else if let Some(k) = &self.cur {
            st.pq = k.pq;
        }
        *self.status.lock().unwrap_or_else(|e| e.into_inner()) = st;
    }

    /// The tunnel as a game sees it over the last minute: echoes through the realtime class, after copies
    /// and repairs. An echo younger than 1.5 s may still be on its way: it is not counted yet.
    fn quality(&self, now: Instant) -> Option<serde_json::Value> {
        if !self.spec.entry() {
            return None;
        }
        let done: Vec<&(u32, Instant, Option<f64>)> = self.echoes.iter().filter(|e| now.duration_since(e.1) > Duration::from_millis(1500)).collect();
        if done.len() < 5 {
            return None;
        }
        let mut rtts: Vec<f64> = done.iter().filter_map(|e| e.2).collect();
        let n = done.len();
        let loss = (n - rtts.len()) as f64 * 100.0 / n as f64;
        let jit = if rtts.len() > 1 { rtts.windows(2).map(|w| (w[1] - w[0]).abs()).sum::<f64>() / (rtts.len() - 1) as f64 } else { 0.0 };
        rtts.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let ping = if rtts.is_empty() { 0.0 } else { rtts[rtts.len() / 2] };
        let max = rtts.last().copied().unwrap_or(0.0);
        Some(serde_json::json!({ "n": n, "ping": (ping * 10.0).round() / 10.0, "jit": (jit * 10.0).round() / 10.0, "loss": (loss * 10.0).round() / 10.0, "max": (max * 10.0).round() / 10.0, "at": crate::util::now() }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A flow of hundreds of small packets a second (a download's acknowledgements) is bulk; a game's pace is not
    #[test]
    fn a_busy_small_flow_is_not_a_game() {
        let (tx, _rx) = mpsc::channel(1);
        let spec = VipSpec { id: "x".into(), role: "entry".into(), port: 1, udp_paths: 1, ..Default::default() };
        let mut s = Session::new(spec, [0; 32], Arc::new(Mutex::new(vec![])), tx, Arc::new(Mutex::new(VipStatus::default())), Arc::new(flows::Counters::default()), Arc::new(Screen::new([0; 32])));
        let t0 = Instant::now();
        // a game: 60 a second for 3 seconds
        for i in 0..180u64 {
            assert!(!s.heavy(0, 1, t0 + Duration::from_millis(i * 16)));
        }
        // acknowledgements: 1000 a second
        let mut heavy_seen = false;
        for i in 0..2000u64 {
            heavy_seen |= s.heavy(0, 2, t0 + Duration::from_micros(i * 1000));
        }
        assert!(heavy_seen && s.heavy(0, 2, t0 + Duration::from_millis(2001)));
        // the game's own flow stays a game
        assert!(!s.heavy(0, 1, t0 + Duration::from_millis(3000)));
    }
}
