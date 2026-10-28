//! A real core server and a real app client on this machine: TCP and UDP through SOCKS5, for
//! every core that runs without root.
use super::client::{Client, ClientCfg};
use super::server::{CoreCfg, CoreServer, CoreUser};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

/// the tests' targets live on 127.0.0.1, which a real server never dials
pub static LOOPBACK_OK: AtomicBool = AtomicBool::new(false);

#[test]
fn only_public_targets() {
    assert!(super::public_target("1.1.1.1:53"));
    assert!(super::public_target("[2606:4700::1111]:443"));
    // (loopback is let through while the end-to-end tests run, so it is checked on the IP)
    for ip in ["127.0.0.1", "::1", "::ffff:127.0.0.1"] {
        assert!(!super::public_ip(ip.parse().unwrap()), "{}", ip);
    }
    for t in ["10.0.0.1:22", "192.168.1.1:80", "172.16.0.1:1", "169.254.169.254:80", "100.64.0.1:1", "0.0.0.0:1", "[fd00::1]:1", "localhost:80", "1.1.1.1:0", "198.18.0.1:53"] {
        assert!(!super::public_target(t), "{}", t);
    }
}

#[test]
fn links_round_trip() {
    let c = ClientCfg { kind: "game".into(), server: "vpn.example.com:4100".into(), door: "d00r+/=".into(), user: "ali reza".into(), key: "k:@ey".into(), fec: "8:3".into(), copies: 3, datagrams: true, sni: String::new() };
    let u = c.to_url("آلمان 🎮");
    let (back, name) = ClientCfg::parse(&u).unwrap();
    assert_eq!(back, c);
    assert_eq!(name, "آلمان 🎮");
    assert!(ClientCfg::parse("kcore://u:k@h:1?type=nope&door=x").is_err());
    assert!(ClientCfg::parse("kcore://u:k@h:1?type=hq").is_err(), "no door");
}

async fn free_udp_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap().port()
}

async fn socks_connect(socks: SocketAddr, target: SocketAddr) -> TcpStream {
    let mut s = TcpStream::connect(socks).await.unwrap();
    s.write_all(&[5, 1, 0]).await.unwrap();
    let mut b = [0u8; 2];
    s.read_exact(&mut b).await.unwrap();
    let mut req = vec![5, 1, 0, 1];
    if let std::net::IpAddr::V4(ip) = target.ip() {
        req.extend_from_slice(&ip.octets());
    }
    req.extend_from_slice(&target.port().to_be_bytes());
    s.write_all(&req).await.unwrap();
    let mut r = [0u8; 10];
    s.read_exact(&mut r).await.unwrap();
    assert_eq!(r[1], 0);
    s
}

/// (control connection, relay address)
async fn socks_udp(socks: SocketAddr) -> (TcpStream, SocketAddr) {
    let mut s = TcpStream::connect(socks).await.unwrap();
    s.write_all(&[5, 1, 0]).await.unwrap();
    let mut b = [0u8; 2];
    s.read_exact(&mut b).await.unwrap();
    s.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
    let mut r = [0u8; 10];
    s.read_exact(&mut r).await.unwrap();
    let a = SocketAddr::new(std::net::Ipv4Addr::new(r[4], r[5], r[6], r[7]).into(), u16::from_be_bytes([r[8], r[9]]));
    (s, a)
}

fn udp_packet(target: SocketAddr, data: &[u8]) -> Vec<u8> {
    let mut p = vec![0, 0, 0, 1];
    if let std::net::IpAddr::V4(ip) = target.ip() {
        p.extend_from_slice(&ip.octets());
    }
    p.extend_from_slice(&target.port().to_be_bytes());
    p.extend_from_slice(data);
    p
}

async fn run_core(kind: &str, datagrams: bool) {
    LOOPBACK_OK.store(true, Ordering::Relaxed);
    // targets: a TCP echo and a UDP echo
    let tl = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_target = tl.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut c, _)) = tl.accept().await {
            tokio::spawn(async move {
                let mut b = vec![0u8; 65536];
                while let Ok(n) = c.read(&mut b).await {
                    if n == 0 || c.write_all(&b[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    let us = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_target = us.local_addr().unwrap();
    tokio::spawn(async move {
        let mut b = vec![0u8; 65536];
        while let Ok((n, from)) = us.recv_from(&mut b).await {
            let _ = us.send_to(&b[..n], from).await;
        }
    });

    let port = free_udp_port().await;
    let mut cfg = CoreCfg { door: "test-door-123".into(), fec: "4:2".into(), copies: 2, users: vec![CoreUser { name: "ali".into(), key: "k1".into(), max: 0 }], ..Default::default() };
    match kind {
        "game" => cfg.game = port,
        _ => cfg.hq = port,
    }
    let srv = CoreServer::start(&cfg).await;
    assert!(srv.errors.is_empty(), "{:?}", srv.errors);

    // a wrong key is refused
    let bad = ClientCfg { kind: kind.into(), server: format!("127.0.0.1:{}", port), door: cfg.door.clone(), user: "ali".into(), key: "nope".into(), copies: 2, datagrams, ..Default::default() };
    let bad_cfg = bad.clone();
    let e = Client::new(bad).await.unwrap().link().await.err().expect("refused").to_string();
    assert!(e.contains("bad key"), "{}", e);

    let cc = ClientCfg { key: "k1".into(), ..ClientCfg { kind: kind.into(), server: format!("127.0.0.1:{}", port), door: cfg.door.clone(), user: "ali".into(), copies: 2, datagrams, ..Default::default() } };
    let client = Client::new(cc.clone()).await.unwrap();
    let sl = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socks = sl.local_addr().unwrap();
    drop(sl);
    tokio::spawn(super::socks::serve(socks, client.clone()));
    tokio::time::sleep(Duration::from_millis(100)).await;

    // TCP: 300 KB both ways
    let mut s = socks_connect(socks, tcp_target).await;
    let data: Vec<u8> = (0..300_000u32).map(|i| (i * 7 % 251) as u8).collect();
    let (mut r, mut w) = s.split();
    let send = async {
        w.write_all(&data).await.unwrap();
    };
    let mut got = vec![0u8; data.len()];
    let recv = async {
        r.read_exact(&mut got).await.unwrap();
    };
    tokio::time::timeout(Duration::from_secs(20), async { tokio::join!(send, recv) }).await.expect("tcp echo");
    assert!(got == data, "tcp data intact");

    // UDP: small game packets and one big one, all answered
    let (_ctl, relay) = socks_udp(socks).await;
    let app = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut b = vec![0u8; 65536];
    for (i, size) in [60usize, 120, 200, 1400].iter().enumerate() {
        let payload: Vec<u8> = (0..*size).map(|x| (x + i) as u8).collect();
        app.send_to(&udp_packet(udp_target, &payload), relay).await.unwrap();
        let n = tokio::time::timeout(Duration::from_secs(5), app.recv(&mut b)).await.expect("udp answer").unwrap();
        assert_eq!(&b[10..n], &payload[..], "udp packet {} ({} bytes)", i, size);
    }
    // the copies of a small packet reach the target once each (no doubled answers come back)
    assert!(tokio::time::timeout(Duration::from_millis(300), app.recv(&mut b)).await.is_err(), "no extra answers");
    if datagrams {
        assert!(client.current().unwrap().dg.is_some(), "fast path is on");
    }

    // ping through the link
    assert!(client.echo_rtt().await.is_some());
    assert!(super::client::ping(cc).await.unwrap() < 1000);
    // the server counts the user's traffic and devices
    let t = srv.traffic();
    assert!(t["ali"].0 > 300_000 && t["ali"].1 > 300_000, "{:?}", t);
    assert!(srv.online().get("ali").copied().unwrap_or(0) >= 1);

    // the user is removed: their sessions end at once and a new link is refused
    srv.set_users(&[]);
    assert!(srv.online().is_empty(), "removed user is cut off");
    let e = Client::new(ClientCfg { key: "k1".into(), ..bad_cfg }).await.unwrap().link().await.err().expect("refused").to_string();
    assert!(e.contains("unknown user"), "{}", e);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn game_core_end_to_end() {
    run_core("game", true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn game_core_without_fast_path() {
    run_core("game", false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hq_core_end_to_end() {
    run_core("hq", true).await;
}
