//! End-to-end tests: a real entry and a real exit on this machine, TCP and UDP through the tunnel.
//! They run on GitHub Actions before every release, so a broken tunnel never gets published.

use super::engine::{Running, Spec};
use rand::RngCore;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

async fn tcp_echo(port: u16) {
    let l = TcpListener::bind(("127.0.0.1", port)).await.unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else { break };
            tokio::spawn(async move {
                let mut b = vec![0u8; 8192];
                loop {
                    let n = match s.read(&mut b).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    if s.write_all(&b[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
}

async fn udp_echo(port: u16) {
    let s = UdpSocket::bind(("127.0.0.1", port)).await.unwrap();
    tokio::spawn(async move {
        let mut b = vec![0u8; 65536];
        loop {
            let (n, from) = s.recv_from(&mut b).await.unwrap();
            let _ = s.send_to(&b[..n], from).await;
        }
    });
}

fn pair(transport: &str, mode: &str, base: u16, token_exit: &str) -> (Spec, Spec) {
    let common = Spec {
        id: format!("t{}", base),
        name: "test".into(),
        mode: mode.into(),
        transport: transport.into(),
        port: base,
        token: "token-for-tests-0123456789".into(),
        conns: 3,
        path: "/kt".into(),
        tcp: vec![format!("{}:{}", base + 1, base + 2)],
        udp: vec![format!("{}:{}", base + 3, base + 4)],
        target: "127.0.0.1".into(),
        ..Default::default()
    };
    let mut entry = common.clone();
    entry.role = "entry".into();
    let mut exit = common;
    exit.role = "exit".into();
    exit.token = token_exit.into();
    // the dialing side needs the listening side's address
    entry.remote = format!("127.0.0.1:{}", base);
    exit.remote = format!("127.0.0.1:{}", base);
    (entry, exit)
}

async fn wait_links(r: &Running, want: usize) -> bool {
    for _ in 0..100 {
        if r.status().links >= want {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

async fn check_tcp(port: u16, size: usize) {
    let mut data = vec![0u8; size];
    rand::thread_rng().fill_bytes(&mut data);
    let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let (mut r, mut w) = s.split();
    let send = data.clone();
    let writer = async move {
        w.write_all(&send).await.unwrap();
    };
    let reader = async move {
        let mut got = vec![0u8; size];
        r.read_exact(&mut got).await.unwrap();
        got
    };
    let (_, got) = tokio::time::timeout(Duration::from_secs(30), async { tokio::join!(writer, reader) }).await.expect("tcp echo timed out");
    assert!(got == data, "TCP data came back different");
}

async fn check_udp(port: u16) {
    let c = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    c.connect(("127.0.0.1", port)).await.unwrap();
    let mut ok = 0;
    for i in 0..20u32 {
        let msg = format!("kanki-udp-{}", i);
        c.send(msg.as_bytes()).await.unwrap();
        let mut b = vec![0u8; 2048];
        if let Ok(Ok(n)) = tokio::time::timeout(Duration::from_millis(1500), c.recv(&mut b)).await {
            if &b[..n] == msg.as_bytes() {
                ok += 1;
            }
        }
    }
    assert!(ok >= 18, "only {} of 20 UDP packets came back", ok);
}

async fn run_case(transport: &str, mode: &str, base: u16) {
    run_case_with(transport, mode, base, |_| {}).await;
}

/// Same as `run_case`, with a change to both sides (for example an SNI spoof).
async fn run_case_with(transport: &str, mode: &str, base: u16, tweak: impl Fn(&mut Spec)) {
    tcp_echo(base + 2).await;
    udp_echo(base + 4).await;
    let (mut es, mut xs) = pair(transport, mode, base, "token-for-tests-0123456789");
    tweak(&mut es);
    tweak(&mut xs);
    let entry = Running::start(es);
    let exit = Running::start(xs);
    let want = if transport == "tcp" { 1 } else { 3 };
    assert!(wait_links(&entry, want).await, "{} {}: entry got no links: {:?}", transport, mode, entry.status().error);
    assert!(wait_links(&exit, want).await, "{} {}: exit got no links: {:?}", transport, mode, exit.status().error);
    // several connections at once, small and large
    let mut jobs = vec![];
    for size in [10usize, 70_000, 1_500_000, 3_000] {
        jobs.push(tokio::spawn(check_tcp(base + 1, size)));
    }
    for j in jobs {
        j.await.unwrap();
    }
    check_udp(base + 3).await;
    let st = entry.status();
    assert!(st.tx_bytes > 1_000_000 && st.rx_bytes > 1_000_000, "counters: {:?}", st);
    entry.stop();
    exit.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tunnel_tcpmux_reverse() {
    run_case("tcpmux", "reverse", 41000).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tunnel_tcp_reverse() {
    run_case("tcp", "reverse", 41100).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tunnel_ws_reverse() {
    run_case("ws", "reverse", 41200).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tunnel_wss_reverse() {
    run_case("wss", "reverse", 41300).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tunnel_tcpmux_direct() {
    run_case("tcpmux", "direct", 41400).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tunnel_wss_direct() {
    run_case("wss", "direct", 41500).await;
}

// SNI spoof: several names (each link takes another), Host header and a split TLS hello
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tunnel_wss_spoof_reverse() {
    run_case_with("wss", "reverse", 43000, |s| {
        s.sni = "www.google.com, www.bing.com".into();
        s.host = "cdn.example.org".into();
        s.frag = true;
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tunnel_wss_spoof_direct() {
    run_case_with("wss", "direct", 43100, |s| {
        s.sni = "www.microsoft.com".into();
        s.frag = true;
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tunnel_quic_spoof_reverse() {
    run_case_with("quic", "reverse", 43200, |s| s.sni = "www.cloudflare.com, www.apple.com".into()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tunnel_ws_host_reverse() {
    run_case_with("ws", "reverse", 43300, |s| s.host = "www.example.com".into()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tunnel_quic_reverse() {
    run_case("quic", "reverse", 41800).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tunnel_kcp_reverse() {
    run_case("kcp", "reverse", 41900).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tunnel_wrong_token_is_refused() {
    let base = 41600;
    let (es, xs) = pair("tcpmux", "reverse", base, "a-different-token-xxxxxxxxx");
    let entry = Running::start(es);
    let exit = Running::start(xs);
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(entry.status().links, 0, "a wrong token must not connect");
    assert_eq!(exit.status().links, 0, "a wrong token must not connect");
    entry.stop();
    exit.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tunnel_reconnects_after_exit_restart() {
    let base = 41700;
    tcp_echo(base + 2).await;
    udp_echo(base + 4).await;
    let (es, xs) = pair("tcpmux", "reverse", base, "token-for-tests-0123456789");
    let entry = Running::start(es);
    let exit = Running::start(xs.clone());
    assert!(wait_links(&entry, 3).await);
    exit.stop();
    tokio::time::sleep(Duration::from_millis(500)).await;
    let exit = Running::start(xs);
    assert!(wait_links(&exit, 3).await, "exit did not come back");
    tokio::time::sleep(Duration::from_millis(500)).await;
    check_tcp(base + 1, 200_000).await;
    entry.stop();
    exit.stop();
}

/// A stand-in for the CDN edge: it ends TLS (any name works) and passes the bytes on to the origin.
async fn fake_cdn(front: u16, origin: u16) {
    let acc = super::link::tls_acceptor("", "").unwrap();
    let l = TcpListener::bind(("127.0.0.1", front)).await.unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = l.accept().await else { break };
            let acc = acc.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acc.accept(tcp).await else { return };
                let Ok(mut up) = TcpStream::connect(("127.0.0.1", origin)).await else { return };
                let _ = tokio::io::copy_bidirectional(&mut tls, &mut up).await;
            });
        }
    });
}

/// Whitelist mode: the entry reaches the exit only through a CDN edge (TLS with a front name,
/// WebSocket with the CDN host, ClientHello in tiny pieces); the exit listens on plain WebSocket.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tunnel_cdn_direct() {
    let base = 42500;
    tcp_echo(base + 2).await;
    udp_echo(base + 4).await;
    fake_cdn(base + 5, base).await;
    let (mut es, xs) = pair("cdn", "direct", base, "token-for-tests-0123456789");
    // two edge addresses: the first is dead, the dialer must move on to the second
    es.remote = format!("127.0.0.1:{},127.0.0.1:{}", base + 6, base + 5);
    es.sni = "front.example.test".into();
    es.host = "cdn.example.test".into();
    es.frag = true;
    let entry = Running::start(es);
    let exit = Running::start(xs);
    assert!(wait_links(&entry, 3).await, "cdn: entry got no links: {:?}", entry.status().error);
    assert!(wait_links(&exit, 3).await, "cdn: exit got no links: {:?}", exit.status().error);
    check_tcp(base + 1, 300_000).await;
    check_udp(base + 3).await;
    entry.stop();
    exit.stop();
}

#[test]
fn ports_parse() {
    let p = super::engine::parse_ports(&["443".into(), "8443:443".into(), "1000-1002".into(), "x".into()]);
    assert_eq!(p, vec![(443, 443), (1000, 1000), (1001, 1001), (1002, 1002), (8443, 443)]);
}

/// Smart tunnel: the entry measures ping, TCP speed and UDP loss through a test tunnel.
async fn probe_case(transport: &str, base: u16) {
    probe_case_strict(transport, base, transport != "kcp").await
}

async fn probe_case_strict(transport: &str, base: u16, want_throughput: bool) {
    let (mut entry, mut exit) = pair(transport, "reverse", base, "token-for-tests-0123456789");
    for s in [&mut entry, &mut exit] {
        s.probe = true;
        s.tcp.clear();
        s.udp.clear();
    }
    let e = Running::start(entry);
    let x = Running::start(exit);
    let mut res = None;
    for _ in 0..600 {
        if let Some(p) = e.status().probe {
            if p["done"].as_bool() == Some(true) {
                res = Some(p);
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let r = res.expect("probe finished");
    println!("probe {}: {}", transport, r);
    // the link connected and carried traffic: ping measured, UDP echo came back
    assert!(r["udp_loss"].as_f64().unwrap_or(100.0) < 50.0, "udp loss too high: {}", r);
    // and at least one of download / upload moved real bytes (best-effort for the UDP relays)
    if want_throughput {
        let moved = r["down_mbps"].as_f64().unwrap_or(0.0) > 0.0 || r["up_mbps"].as_f64().unwrap_or(0.0) > 0.0;
        assert!(moved, "no throughput measured: {}", r);
    }
    e.stop();
    x.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn probe_tcpmux() {
    probe_case("tcpmux", 42100).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn probe_quic() {
    probe_case("quic", 42200).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn probe_kcp_obfs() {
    probe_case("kcp", 42300).await;
}

#[test]
fn obfs_roundtrip() {
    // the obfuscation must survive any payload and hide the original bytes
    let key = {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"kanki-obfs|");
        h.update(b"the-token");
        let out: [u8; 32] = h.finalize().into();
        out
    };
    for len in [1usize, 24, 200, 1400] {
        let data: Vec<u8> = (0..len).map(|i| (i * 7) as u8).collect();
        let wrapped = super::obfs::test_wrap(&key, &data);
        assert!(wrapped != data, "wrapped must differ from plaintext");
        assert!(wrapped.len() > data.len(), "wrapped carries nonce + pad");
        let back = super::obfs::test_unwrap(&key, &wrapped).expect("unwrap");
        assert_eq!(back, data, "obfs must round-trip");
        // a wrong key must not produce the original
        let bad = [9u8; 32];
        assert!(super::obfs::test_unwrap(&bad, &wrapped).map(|x| x == data).unwrap_or(false) == false);
    }
}


// ---------------------------------------------------------------- AmneziaWG tunnel

#[test]
fn awg_params_are_valid() {
    for profile in ["classic", "heavy", "mimic"] {
        for _ in 0..200 {
            let m = super::awg::gen_params(profile);
            let g = |k: &str| m.get(k).unwrap().parse::<u32>().unwrap();
            assert!(g("Jc") >= 4 && g("Jc") <= 12);
            assert!(g("Jmin") < g("Jmax") && g("Jmax") <= 1280);
            assert!(g("S1") != g("S2") && g("S1") + 56 != g("S2"));
            let h = [g("H1"), g("H2"), g("H3"), g("H4")];
            for (i, a) in h.iter().enumerate() {
                assert!(*a >= 5);
                for b in &h[i + 1..] {
                    assert_ne!(a, b);
                }
            }
            assert_eq!(m.contains_key("I1"), profile == "mimic");
        }
    }
}

#[test]
fn awg_keys_are_base64_32_bytes() {
    let (p, q) = super::awg::gen_keypair();
    assert_eq!(p.len(), 44);
    assert_eq!(q.len(), 44);
    assert!(p.ends_with('=') && q.ends_with('='));
    assert_ne!(p, q);
    assert_eq!(super::awg::gen_psk().len(), 44);
    assert_eq!(super::awg::b64(b"Man"), "TWFu");
    assert_eq!(super::awg::b64(b"Ma"), "TWE=");
}

#[test]
fn awg_cidrs_and_config() {
    let c = super::awg::clean_cidrs(&["1.1.1.1, 8.8.0.0/16 bad 300.1.1.1".to_string()]);
    assert_eq!(c, vec!["1.1.1.1/32".to_string(), "8.8.0.0/16".to_string()]);
    let mut s = super::awg::AwgSpec {
        tid: "t".into(),
        iface: "kawgtest".into(),
        role: "entry".into(),
        private: "PRIV".into(),
        peer_pub: "PUB".into(),
        psk: "PSK".into(),
        address: "10.88.1.1/30".into(),
        peer_ip: "10.88.1.2".into(),
        listen: 51900,
        endpoint: "203.0.113.5:51900".into(),
        keepalive: 25,
        mtu: 1380,
        routes: vec!["1.1.1.1/32".into()],
        fwd_tcp: vec!["8443:443".into()],
        ..Default::default()
    };
    s.params = super::awg::gen_params("classic");
    let t = super::awg::render(&s);
    assert!(t.contains("Table = off"));
    assert!(t.contains("Endpoint = 203.0.113.5:51900"));
    assert!(t.contains("AllowedIPs = 10.88.1.2/32, 1.1.1.1/32"));
    assert!(t.contains("--dport 8443 -j DNAT --to-destination 10.88.1.2:443"));
    assert!(t.contains("Jc = "));
    s.role = "exit".into();
    s.address = "10.88.1.2/30".into();
    s.peer_ip = "10.88.1.1".into();
    s.endpoint.clear();
    s.nat_exit = true;
    s.lockdown = true;
    let t = super::awg::render(&s);
    assert!(t.contains("-s 10.88.1.0/30 ! -o %i -j MASQUERADE"));
    assert!(t.contains("--dport 51900 ! -i lo -j DROP"));
    assert!(!t.contains("Endpoint"));
}
