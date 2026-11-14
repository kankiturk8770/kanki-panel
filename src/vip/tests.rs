//! The VIP tunnel end to end on this machine: an entry and an exit, a line between them that loses,
//! delays or cuts packets on purpose (`Line`), and game-like traffic through it.
//!
//! The lab (`cargo test vip_lab -- --ignored --nocapture`) prints the numbers of each case.

use super::core::Running;
use super::VipSpec;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

// ------------------------------------------------------------------ a bad line on purpose

#[derive(Clone, Default)]
struct Model {
    /// random loss (0..1)
    loss: f64,
    /// Gilbert-Elliott: chance to fall into a bad spell, to leave it, and the loss inside it
    p_bad: f64,
    p_good: f64,
    bad_loss: f64,
    /// one way, ms; and up to this much more at random
    delay: u64,
    jitter: u64,
    /// cut every `cut_every` ms for `cut_ms`
    cut_every: u64,
    cut_ms: u64,
    /// where in the cut cycle this line starts (ms): two lines are not cut at the same moment
    phase: u64,
}

struct Line {
    model: Mutex<Model>,
    dead: AtomicBool,
    bad: Mutex<bool>,
    t0: Instant,
    seed: Mutex<u64>,
    passed: AtomicU64,
    dropped: AtomicU64,
}

impl Line {
    fn new(m: Model, seed: u64) -> Arc<Line> {
        Arc::new(Line { model: Mutex::new(m), dead: AtomicBool::new(false), bad: Mutex::new(false), t0: Instant::now(), seed: Mutex::new(seed | 1), passed: AtomicU64::new(0), dropped: AtomicU64::new(0) })
    }
    fn rnd(&self) -> f64 {
        let mut s = self.seed.lock().unwrap();
        *s ^= *s << 13;
        *s ^= *s >> 7;
        *s ^= *s << 17;
        (*s >> 11) as f64 / (1u64 << 53) as f64
    }
    /// None = lost; Some(delay ms)
    fn fate(&self) -> Option<u64> {
        if self.dead.load(Ordering::Relaxed) {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        let m = self.model.lock().unwrap().clone();
        let ms = self.t0.elapsed().as_millis() as u64 + m.phase;
        let mut lost = m.cut_every > 0 && ms % m.cut_every < m.cut_ms;
        {
            let mut bad = self.bad.lock().unwrap();
            if *bad {
                if self.rnd() < m.p_good {
                    *bad = false;
                }
            } else if self.rnd() < m.p_bad {
                *bad = true;
            }
            let l = if *bad { m.bad_loss } else { m.loss };
            lost |= self.rnd() < l;
        }
        if lost {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        self.passed.fetch_add(1, Ordering::Relaxed);
        Some(m.delay + if m.jitter > 0 { (self.rnd() * m.jitter as f64) as u64 } else { 0 })
    }
}

/// A UDP relay over `ports` ports: `from + i` on this machine leads to `to + i`, both ways through `line`
async fn udp_line(from: u16, to: u16, ports: u16, line: Arc<Line>) -> Vec<tokio::task::JoinHandle<()>> {
    let mut tasks = vec![];
    for i in 0..ports {
        let front = Arc::new(UdpSocket::bind(("127.0.0.1", from + i)).await.unwrap());
        let dst: SocketAddr = format!("127.0.0.1:{}", to + i).parse().unwrap();
        let line = line.clone();
        tasks.push(tokio::spawn(async move {
            let mut peers: HashMap<SocketAddr, Arc<UdpSocket>> = HashMap::new();
            let mut buf = vec![0u8; 65535];
            loop {
                let Ok((n, src)) = front.recv_from(&mut buf).await else { continue };
                let back = match peers.get(&src) {
                    Some(s) => s.clone(),
                    None => {
                        let s = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
                        s.connect(dst).await.unwrap();
                        let (s2, f2, l2) = (s.clone(), front.clone(), line.clone());
                        tokio::spawn(async move {
                            let mut b = vec![0u8; 65535];
                            while let Ok(n) = s2.recv(&mut b).await {
                                if let Some(d) = l2.fate() {
                                    let (f3, pkt) = (f2.clone(), b[..n].to_vec());
                                    tokio::spawn(async move {
                                        tokio::time::sleep(Duration::from_millis(d)).await;
                                        let _ = f3.send_to(&pkt, src).await;
                                    });
                                }
                            }
                        });
                        peers.insert(src, s.clone());
                        s
                    }
                };
                if let Some(d) = line.fate() {
                    let pkt = buf[..n].to_vec();
                    tokio::spawn(async move {
                        tokio::time::sleep(Duration::from_millis(d)).await;
                        let _ = back.send(&pkt).await;
                    });
                }
            }
        }));
    }
    tasks
}

async fn udp_echo(port: u16) -> tokio::task::JoinHandle<()> {
    let s = UdpSocket::bind(("127.0.0.1", port)).await.unwrap();
    tokio::spawn(async move {
        let mut b = vec![0u8; 65535];
        while let Ok((n, a)) = s.recv_from(&mut b).await {
            let _ = s.send_to(&b[..n], a).await;
        }
    })
}

async fn tcp_echo(port: u16) -> tokio::task::JoinHandle<()> {
    let l = TcpListener::bind(("127.0.0.1", port)).await.unwrap();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    })
}

/// The two sides: the entry listens (UDP `port`, a stream path on `s_port` when given), the exit dials
/// `dial_port` (a relay in front of `port`, or `port` itself)
#[allow(clippy::too_many_arguments)]
fn pair(secret: &str, mode: &str, port: u16, dial_port: u16, hop: u8, udp_paths: u8, s_port: u16, user_udp: u16, user_tcp: u16, target: u16) -> (VipSpec, VipSpec) {
    let base = VipSpec {
        id: "t1".into(),
        name: "test".into(),
        secret: secret.into(),
        mode: mode.into(),
        stealth: 1,
        pq: true,
        hop,
        hop_secs: 0,
        udp_paths,
        s_kind: if s_port > 0 { "tcp".into() } else { String::new() },
        s_port,
        udp: vec![format!("{}:{}", user_udp, target)],
        tcp: vec![format!("{}:{}", user_tcp, target)],
        target: "127.0.0.1".into(),
        bind: "127.0.0.1".into(),
        ..Default::default()
    };
    let entry = VipSpec { role: "entry".into(), dials: false, port, ..base.clone() };
    let exit = VipSpec { role: "exit".into(), dials: true, remote: "127.0.0.1".into(), port: dial_port, ..base };
    (entry, exit)
}

async fn wait_up(a: &Running, b: &Running, secs: u64) -> bool {
    let t = Instant::now();
    while t.elapsed() < Duration::from_secs(secs) {
        if a.status().up && b.status().up {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

/// Game-like traffic: `n` packets of `size` bytes every `gap` ms to the entry's UDP port, echoed back by
/// the target. (received, received on time, round trips in ms)
async fn game(port: u16, n: u32, size: usize, gap: u64, on_time: f64) -> (u32, u32, Vec<f64>) {
    let s = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    s.connect(("127.0.0.1", port)).await.unwrap();
    let sent: Arc<Mutex<HashMap<u32, Instant>>> = Arc::new(Mutex::new(HashMap::new()));
    let rtts: Arc<Mutex<Vec<f64>>> = Arc::new(Mutex::new(vec![]));
    let (s2, sent2, rtts2) = (s.clone(), sent.clone(), rtts.clone());
    let rx = tokio::spawn(async move {
        let mut b = vec![0u8; 2048];
        while let Ok(k) = s2.recv(&mut b).await {
            if k < 4 {
                continue;
            }
            let id = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
            if let Some(t) = sent2.lock().unwrap().remove(&id) {
                rtts2.lock().unwrap().push(t.elapsed().as_secs_f64() * 1000.0);
            }
        }
    });
    let mut iv = tokio::time::interval(Duration::from_millis(gap));
    for i in 0..n {
        iv.tick().await;
        let mut p = vec![0u8; size];
        p[..4].copy_from_slice(&i.to_be_bytes());
        sent.lock().unwrap().insert(i, Instant::now());
        let _ = s.send(&p).await;
    }
    tokio::time::sleep(Duration::from_millis(800)).await;
    rx.abort();
    let r = rtts.lock().unwrap().clone();
    let ok = r.iter().filter(|x| **x <= on_time).count() as u32;
    (r.len() as u32, ok, r)
}

fn pct(v: &[f64], p: f64) -> f64 {
    if v.is_empty() {
        return 0.0;
    }
    let mut s = v.to_vec();
    s.sort_by(|a, b| a.partial_cmp(b).unwrap());
    s[((s.len() - 1) as f64 * p).round() as usize]
}

// ------------------------------------------------------------------ tests

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn udp_and_tcp_cross_the_tunnel() {
    let _e1 = udp_echo(35010).await;
    let _e2 = tcp_echo(35010).await;
    let (en, ex) = pair("secret-one", "balanced", 35000, 35000, 2, 2, 0, 35011, 35012, 35010);
    let (a, b) = (Running::start(en), Running::start(ex));
    assert!(wait_up(&a, &b, 10).await, "up: {:?} / {:?}", a.status(), b.status());
    assert!(a.status().pq && b.status().pq, "ML-KEM was used");
    // small and big datagrams (a big one goes in fragments and as bulk)
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    s.connect("127.0.0.1:35011").await.unwrap();
    for size in [20usize, 400, 1300, 4000] {
        let msg: Vec<u8> = (0..size).map(|i| (i * 31 % 251) as u8).collect();
        s.send(&msg).await.unwrap();
        let mut buf = vec![0u8; 8000];
        let n = tokio::time::timeout(Duration::from_secs(3), s.recv(&mut buf)).await.unwrap_or_else(|_| panic!("no echo of {} bytes: {:?}\n EXIT {:?}", size, a.status(), b.status())).unwrap();
        assert_eq!(&buf[..n], &msg[..], "size {}", size);
    }
    // TCP: 4 MB both ways through QUIC inside the tunnel
    let mut c = TcpStream::connect("127.0.0.1:35012").await.unwrap();
    let data: Vec<u8> = (0..4_000_000u32).map(|i| (i % 253) as u8).collect();
    let (mut r, mut w) = c.split();
    let d2 = data.clone();
    let t = Instant::now();
    let (_, back) = tokio::join!(async move { w.write_all(&d2).await.unwrap() }, async move {
        let mut got = vec![0u8; 4_000_000];
        r.read_exact(&mut got).await.unwrap();
        got
    });
    assert!(back == data, "the TCP bytes came back the same");
    eprintln!("4 MB echoed through the VIP tunnel in {:?}", t.elapsed());
    let st = a.status();
    assert!(st.streams <= 1 && st.junk == 0, "{:?}", st);
    a.stop();
    b.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wrong_secret_never_connects() {
    let (en, _) = pair("right", "balanced", 35100, 35100, 1, 1, 0, 35111, 35112, 35110);
    let (_, ex) = pair("wrong", "balanced", 35100, 35100, 1, 1, 0, 35111, 35112, 35110);
    let (a, b) = (Running::start(en), Running::start(ex));
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(!a.status().up && !b.status().up);
    // the listener dropped every packet without an answer
    assert!(a.status().junk > 0);
    assert!(b.status().paths.iter().all(|p| p.rx_pk == 0));
    a.stop();
    b.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn realtime_survives_a_lossy_line() {
    let _e = udp_echo(35210).await;
    // 5% each way, 15 ms each way
    let line = Line::new(Model { loss: 0.05, delay: 15, jitter: 3, ..Default::default() }, 7);
    let _l = udp_line(35220, 35200, 2, line.clone()).await;
    let (en, ex) = pair("lossy", "gaming", 35200, 35220, 2, 1, 0, 35211, 35212, 35210);
    let (a, b) = (Running::start(en), Running::start(ex));
    assert!(wait_up(&a, &b, 15).await);
    let (got, ok, rtts) = game(35211, 400, 80, 10, 150.0).await;
    let st = b.status();
    eprintln!("5% loss each way: {}/400 back, {} on time, p50 {:.1} ms p99 {:.1} ms, rebuilt {} copies {}", got, ok, pct(&rtts, 0.5), pct(&rtts, 0.99), a.status().rt_fixed + st.rt_fixed, st.rt_copies);
    // a round trip crosses the line twice: without the tunnel ~9.8% would be lost
    assert!(got >= 394, "{} of 400", got);
    a.stop();
    b.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dead_path_costs_nothing() {
    let _e = udp_echo(35310).await;
    let line = Line::new(Model { delay: 5, ..Default::default() }, 3);
    let _l = udp_line(35320, 35300, 1, line.clone()).await;
    // one UDP path through the line, one stream path straight
    let (en, ex) = pair("two-paths", "gaming", 35300, 35320, 1, 1, 35330, 35311, 35312, 35310);
    let (a, b) = (Running::start(en), Running::start(ex));
    assert!(wait_up(&a, &b, 15).await);
    tokio::time::sleep(Duration::from_secs(2)).await;
    let l2 = line.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(1500)).await;
        // the UDP path is cut in the middle of the game, with no warning
        l2.dead.store(true, Ordering::Relaxed);
    });
    let (got, ok, rtts) = game(35311, 300, 60, 10, 150.0).await;
    eprintln!("UDP path cut mid-game: {}/300 back, {} on time, p99 {:.1} ms", got, ok, pct(&rtts, 0.99));
    assert!(got >= 298, "{} of 300", got);
    // the cut path is seen as down
    tokio::time::sleep(Duration::from_secs(2)).await;
    let st = b.status();
    assert!(st.paths.iter().any(|p| p.kind == "udp" && p.state < 2), "{:?}", st.paths);
    assert!(st.paths.iter().any(|p| p.kind == "stream" && p.state == 2), "{:?}", st.paths);
    a.stop();
    b.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn new_keys_and_new_ports_lose_nothing() {
    let _e = udp_echo(35410).await;
    let (mut en, mut ex) = pair("rekey", "balanced", 35400, 35400, 4, 2, 0, 35411, 35412, 35410);
    en.rekey_secs = 5;
    ex.rekey_secs = 5;
    ex.hop_secs = 5;
    let (a, b) = (Running::start(en), Running::start(ex));
    assert!(wait_up(&a, &b, 10).await);
    let ports0: Vec<u16> = b.status().paths.iter().map(|p| p.port).collect();
    let (got, _, _) = game(35411, 1200, 60, 10, 150.0).await;
    let st = b.status();
    eprintln!("12 s with new keys every 5 s and new ports: {}/1200 back, {} handshakes, ports {:?} -> {:?}", got, st.rekeys, ports0, st.paths.iter().map(|p| p.port).collect::<Vec<_>>());
    assert!(st.rekeys >= 3, "{}", st.rekeys);
    assert!(got >= 1195, "{} of 1200", got);
    a.stop();
    b.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_exit_that_starts_again_comes_back() {
    let _e = udp_echo(35510).await;
    let (en, ex) = pair("restart", "balanced", 35500, 35500, 1, 1, 0, 35511, 35512, 35510);
    let a = Running::start(en);
    let b = Running::start(ex.clone());
    assert!(wait_up(&a, &b, 10).await);
    b.stop();
    tokio::time::sleep(Duration::from_millis(500)).await;
    let b = Running::start(ex);
    assert!(wait_up(&a, &b, 10).await, "a new dialer is taken at once");
    let (got, _, _) = game(35511, 50, 40, 10, 500.0).await;
    assert!(got >= 49);
    // the listener starts again too (an edit, an update): its ports were freed, the dialer finds it again
    let spec_a = a.spec().clone();
    a.stop();
    tokio::time::sleep(Duration::from_millis(300)).await;
    let a = Running::start(spec_a);
    assert!(wait_up(&a, &b, 15).await, "the same ports are taken again: {:?}", a.status());
    let (got, _, _) = game(35511, 50, 40, 10, 500.0).await;
    assert!(got >= 49, "{}", got);
    a.stop();
    b.stop();
}

/// faketcp needs raw sockets (root); skipped without them
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fake_tcp_path_carries_it() {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("VIP fake-TCP test skipped: needs root");
        return;
    }
    let _e = udp_echo(35610).await;
    let (mut en, mut ex) = pair("ftcp", "balanced", 0, 0, 1, 1, 0, 35611, 35612, 35610);
    en.ftcp_port = 35620;
    ex.ftcp_port = 35620;
    let (a, b) = (Running::start(en), Running::start(ex));
    assert!(wait_up(&a, &b, 20).await, "{:?}", b.status());
    let (got, _, _) = game(35611, 100, 200, 10, 500.0).await;
    assert!(got >= 99, "{}", got);
    a.stop();
    b.stop();
}

// ------------------------------------------------------------------ the lab

/// One case of the lab: (on time %, p50, p99) of game traffic. `paths`: 0 = no tunnel (the same line), 1 or
/// 2 UDP paths, each through its own line with its own independent losses (another route, another queue).
async fn lab_case(base: u16, m: Model, paths: u8, mode: &str) -> (f64, f64, f64) {
    let target = base + 10;
    let _e = udp_echo(target).await;
    let n = 1500u32;
    // one round trip of the line itself, plus 50 ms: what a game still takes as on time
    let on_time = 2.0 * (m.delay as f64 + m.jitter as f64) + 50.0;
    let mut keep = vec![];
    if paths == 0 {
        keep.extend(udp_line(base + 20, target, 1, Line::new(m.clone(), base as u64 * 7919)).await);
        let (_, ok, r) = game(base + 20, n, 100, 16, on_time).await;
        keep.iter().for_each(|t| t.abort());
        return (ok as f64 * 100.0 / n as f64, pct(&r, 0.5), pct(&r, 0.99));
    }
    for i in 0..paths as u16 {
        let mut mi = m.clone();
        mi.phase = i as u64 * m.cut_every / 2;
        keep.extend(udp_line(base + 20 + i, base + i, 1, Line::new(mi, (base as u64 + i as u64) * 104729)).await);
    }
    let (mut en, mut ex) = pair("lab", mode, base, base + 20, paths, paths, 0, base + 11, base + 12, target);
    en.stealth = 1;
    ex.stealth = 1;
    let (a, b) = (Running::start(en), Running::start(ex));
    let res = if wait_up(&a, &b, 15).await {
        tokio::time::sleep(Duration::from_secs(2)).await;
        let (got, ok, r) = game(base + 11, n, 100, 16, on_time).await;
        let (x, y) = (a.status(), b.status());
        eprintln!("    [{} path(s)] back {} on time {}; entry: rt sent {} copies {} repairs {} got {} dup {} rebuilt {}; exit: sent {} copies {} repairs {} got {} dup {} rebuilt {}",
            paths, got, ok, x.rt_tx, x.rt_copies, x.rt_fix_tx, x.rt_rx, x.rt_dups, x.rt_fixed, y.rt_tx, y.rt_copies, y.rt_fix_tx, y.rt_rx, y.rt_dups, y.rt_fixed);
        (ok as f64 * 100.0 / n as f64, pct(&r, 0.5), pct(&r, 0.99))
    } else {
        (0.0, 0.0, 0.0)
    };
    a.stop();
    b.stop();
    keep.iter().for_each(|t| t.abort());
    res
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn vip_lab_bursts() {
    let m = Model { loss: 0.005, p_bad: 0.01, p_good: 0.25, bad_loss: 0.9, delay: 30, jitter: 4, ..Default::default() };
    println!("one {:?}", lab_case(38000, m.clone(), 1, "gaming").await);
    println!("two {:?}", lab_case(38100, m, 2, "gaming").await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn vip_lab() {
    let lines = [
        ("2% random, 30 ms", Model { loss: 0.02, delay: 30, jitter: 4, ..Default::default() }),
        ("5% random, 30 ms", Model { loss: 0.05, delay: 30, jitter: 4, ..Default::default() }),
        ("bursts (Gilbert-Elliott, ~4%)", Model { loss: 0.005, p_bad: 0.01, p_good: 0.25, bad_loss: 0.9, delay: 30, jitter: 4, ..Default::default() }),
        ("cut 150 ms every 2 s", Model { loss: 0.003, delay: 30, jitter: 4, cut_every: 2000, cut_ms: 150, ..Default::default() }),
    ];
    let mut base = 36000u16;
    println!("\nGame traffic: 1500 packets of 100 B every 16 ms, echoed. On time = within one round trip of the line + 50 ms.");
    println!("{:<32} {:>22} {:>22} {:>22}", "line", "no tunnel", "VIP, one path", "VIP, two paths");
    for (name, m) in lines {
        let d = lab_case(base, m.clone(), 0, "gaming").await;
        let one = lab_case(base + 100, m.clone(), 1, "gaming").await;
        let two = lab_case(base + 200, m.clone(), 2, "gaming").await;
        base += 300;
        let f = |x: (f64, f64, f64)| format!("{:6.2}% {:5.0}/{:4.0}ms", x.0, x.1, x.2);
        println!("{:<32} {:>22} {:>22} {:>22}", name, f(d), f(one), f(two));
    }
}

/// TCP through the tunnel: one download of `mb` MB, the time it took (Mbit/s)
async fn tcp_speed(base: u16, m: Option<Model>, mb: usize, mode: &str) -> f64 {
    // a sink on the exit that sends `mb` MB to whoever connects
    let l = TcpListener::bind(("127.0.0.1", base + 10)).await.unwrap();
    let src = tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            tokio::spawn(async move {
                let chunk = vec![7u8; 64 * 1024];
                for _ in 0..(mb * 16) {
                    if s.write_all(&chunk).await.is_err() {
                        return;
                    }
                }
                let _ = s.shutdown().await;
            });
        }
    });
    let mut keep = vec![];
    let dial = match &m {
        Some(m) => {
            keep.extend(udp_line(base + 20, base, 1, Line::new(m.clone(), 99)).await);
            base + 20
        }
        None => base,
    };
    let (en, ex) = pair("speed", mode, base, dial, 1, 1, 0, base + 11, base + 12, base + 10);
    let (a, b) = (Running::start(en), Running::start(ex));
    assert!(wait_up(&a, &b, 15).await);
    let t = Instant::now();
    let mut c = TcpStream::connect(("127.0.0.1", base + 12)).await.unwrap();
    let mut got = 0usize;
    let mut buf = vec![0u8; 256 * 1024];
    while let Ok(Ok(n)) = tokio::time::timeout(Duration::from_secs(20), c.read(&mut buf)).await {
        if n == 0 {
            break;
        }
        got += n;
    }
    let secs = t.elapsed().as_secs_f64();
    let st = b.status();
    eprintln!("  {} MB in {:.1} s; exit sent {} bulk, {} repairs; entry rebuilt {}; guard {}", got >> 20, secs, st.bulk_tx, st.bulk_fix_tx, a.status().bulk_fixed, st.guard_bps);
    a.stop();
    b.stop();
    src.abort();
    keep.iter().for_each(|t| t.abort());
    got as f64 * 8.0 / secs / 1e6
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn vip_speed() {
    println!("TCP download through the VIP tunnel (one UDP path, release build, this machine):");
    println!("  clean line, balanced: {:.0} Mbit/s", tcp_speed(37000, None, 200, "balanced").await);
    let m = Model { loss: 0.01, delay: 20, jitter: 2, ..Default::default() };
    println!("  1% loss, 20 ms each way, balanced: {:.0} Mbit/s", tcp_speed(37100, Some(m.clone()), 50, "balanced").await);
    let m = Model { loss: 0.03, delay: 20, jitter: 2, ..Default::default() };
    println!("  3% loss, 20 ms each way, speed: {:.0} Mbit/s", tcp_speed(37200, Some(m), 50, "speed").await);
}

/// Every kind of web path alone (no UDP at all), with UDP and TCP through it
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_web_path_carries_it_alone() {
    let _e1 = udp_echo(35710).await;
    let _e2 = tcp_echo(35710).await;
    for (i, kind) in ["tcp", "ws", "wss", "h2"].into_iter().enumerate() {
        let sp = 35720 + i as u16;
        let (mut en, mut ex) = pair("web", "balanced", 0, 0, 1, 1, sp, 35711 + 2 * i as u16, 35712 + 2 * i as u16, 35710);
        for s in [&mut en, &mut ex] {
            s.s_kind = kind.into();
            s.s_sni = "www.example.com".into();
            s.s_path = "/ws".into();
        }
        let (a, b) = (Running::start(en), Running::start(ex));
        assert!(wait_up(&a, &b, 15).await, "{}: {:?}", kind, b.status());
        let (got, _, _) = game(35711 + 2 * i as u16, 100, 300, 5, 500.0).await;
        assert!(got >= 99, "{}: {} of 100", kind, got);
        let mut c = TcpStream::connect(("127.0.0.1", 35712 + 2 * i as u16)).await.unwrap();
        let data: Vec<u8> = (0..300_000u32).map(|x| (x % 251) as u8).collect();
        c.write_all(&data).await.unwrap();
        let mut back = vec![0u8; data.len()];
        tokio::time::timeout(Duration::from_secs(10), c.read_exact(&mut back)).await.expect(kind).unwrap();
        assert!(back == data, "{}", kind);
        a.stop();
        b.stop();
    }
}

/// The Iran server dials (the exit listens), in each mode, with each amount of filler, with and without ML-KEM
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_mode_and_direction() {
    let _e = udp_echo(35810).await;
    for (i, (mode, stealth, pq)) in [("speed", 0u8, false), ("balanced", 2, true), ("gaming", 1, false)].into_iter().enumerate() {
        let base = 35820 + 10 * i as u16;
        let (mut en, mut ex) = pair("dir", mode, base, base, 2, 2, 0, base + 5, base + 6, 35810);
        // the other way round: the entry dials, the exit listens
        en.dials = true;
        en.remote = "127.0.0.1".into();
        ex.dials = false;
        ex.remote.clear();
        for s in [&mut en, &mut ex] {
            s.stealth = stealth;
            s.pq = pq;
        }
        let (a, b) = (Running::start(en), Running::start(ex));
        assert!(wait_up(&a, &b, 15).await, "{}: {:?}", mode, a.status());
        assert_eq!(a.status().pq, pq);
        let (got, _, _) = game(base + 5, 200, 120, 5, 500.0).await;
        assert!(got >= 199, "{}: {} of 200", mode, got);
        a.stop();
        b.stop();
    }
}

/// A flood of junk at the listener's ports while a game runs: dropped without an answer, the game goes on
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn junk_does_not_hurt() {
    let _e = udp_echo(35910).await;
    let (en, ex) = pair("junk", "gaming", 35900, 35900, 2, 1, 0, 35911, 35912, 35910);
    let (a, b) = (Running::start(en), Running::start(ex));
    assert!(wait_up(&a, &b, 10).await);
    let flood = tokio::spawn(async {
        let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut n = 0u64;
        let mut x: u64 = 12345;
        loop {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let len = 20 + (x % 1300) as usize;
            let pkt: Vec<u8> = (0..len).map(|i| (x >> (i % 56)) as u8).collect();
            let _ = s.send_to(&pkt, ("127.0.0.1", 35900 + (n % 2) as u16)).await;
            n += 1;
            // ~10 000 junk packets a second (the debug build of the tests checks each slowly; a release build
            // dropped ~280 000 a second here with the game untouched)
            if n % 100 == 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
    });
    let (got, ok, _) = game(35911, 300, 80, 10, 150.0).await;
    flood.abort();
    let st = a.status();
    eprintln!("junk flood: {} dropped without answer; game {}/300 back, {} on time", st.junk, got, ok);
    assert!(st.junk > 10_000, "{}", st.junk);
    assert!(got >= 298 && st.up, "{} of 300", got);
    a.stop();
    b.stop();
}
