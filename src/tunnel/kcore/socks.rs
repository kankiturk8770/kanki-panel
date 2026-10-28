//! A small SOCKS5 server on 127.0.0.1 for the app's tun2socks (hev-socks5-tunnel): CONNECT for
//! TCP, UDP ASSOCIATE for UDP. No authentication (it only listens on loopback).

use super::super::link::Res;
use super::super::mux::now_ms;
use super::client::Client;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

/// Serves SOCKS5 on `listen` until the process ends.
pub async fn serve(listen: SocketAddr, client: Arc<Client>) -> Res<()> {
    let l = TcpListener::bind(listen).await?;
    loop {
        let (s, _) = match l.accept().await {
            Ok(x) => x,
            Err(_) => {
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let c = client.clone();
        tokio::spawn(async move {
            let _ = handle(s, c).await;
        });
    }
}

/// A SOCKS address: an IP or a name
enum Addr {
    Ip(SocketAddr),
    Name(String, u16),
}

async fn read_addr(s: &mut TcpStream, atyp: u8) -> Res<Addr> {
    Ok(match atyp {
        1 => {
            let mut b = [0u8; 6];
            s.read_exact(&mut b).await?;
            Addr::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3])), u16::from_be_bytes([b[4], b[5]])))
        }
        4 => {
            let mut b = [0u8; 18];
            s.read_exact(&mut b).await?;
            let ip: [u8; 16] = b[..16].try_into()?;
            Addr::Ip(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), u16::from_be_bytes([b[16], b[17]])))
        }
        3 => {
            let n = s.read_u8().await? as usize;
            let mut b = vec![0u8; n + 2];
            s.read_exact(&mut b).await?;
            Addr::Name(String::from_utf8_lossy(&b[..n]).to_string(), u16::from_be_bytes([b[n], b[n + 1]]))
        }
        _ => return Err("bad address type".into()),
    })
}

/// A name is looked up here (the server only dials IP addresses).
async fn resolve(a: Addr) -> Res<SocketAddr> {
    match a {
        Addr::Ip(x) => Ok(x),
        Addr::Name(h, p) => Ok(tokio::net::lookup_host((h.as_str(), p)).await?.next().ok_or("cannot resolve")?),
    }
}

/// SOCKS header for an address: ATYP | ADDR | PORT
fn addr_bytes(a: SocketAddr) -> Vec<u8> {
    let mut v = vec![];
    match a.ip() {
        IpAddr::V4(ip) => {
            v.push(1);
            v.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            v.push(4);
            v.extend_from_slice(&ip.octets());
        }
    }
    v.extend_from_slice(&a.port().to_be_bytes());
    v
}

/// IPv4-mapped IPv6 as plain IPv4 (what the server's sockets expect)
fn plain(a: SocketAddr) -> SocketAddr {
    match a.ip() {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => SocketAddr::new(IpAddr::V4(v4), a.port()),
            None => a,
        },
        _ => a,
    }
}

async fn handle(mut s: TcpStream, c: Arc<Client>) -> Res<()> {
    let _ = s.set_nodelay(true);
    let mut h = [0u8; 2];
    s.read_exact(&mut h).await?;
    if h[0] != 5 {
        return Err("not socks5".into());
    }
    let mut m = vec![0u8; h[1] as usize];
    s.read_exact(&mut m).await?;
    s.write_all(&[5, 0]).await?;
    let mut r = [0u8; 4];
    s.read_exact(&mut r).await?;
    let target = read_addr(&mut s, r[3]).await?;
    match r[1] {
        // CONNECT: answered at once, the stream opens on the server while the app already sends
        1 => {
            let t = match resolve(target).await {
                Ok(t) => plain(t),
                Err(_) => {
                    s.write_all(&[5, 4, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
                    return Ok(());
                }
            };
            s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
            c.open_tcp(s, &super::target_of(t)).await;
            Ok(())
        }
        3 => udp_associate(s, c).await,
        _ => {
            s.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
            Ok(())
        }
    }
}

/// a flow quiet for this long is closed (its socket freed)
const FLOW_IDLE_MS: u64 = 120_000;

async fn udp_associate(mut s: TcpStream, c: Arc<Client>) -> Res<()> {
    let ip = s.local_addr()?.ip();
    let relay = Arc::new(UdpSocket::bind(SocketAddr::new(ip, 0)).await?);
    let mut rep = vec![5, 0, 0];
    rep.extend_from_slice(&addr_bytes(relay.local_addr()?));
    s.write_all(&rep).await?;

    // target -> flow id, and names already looked up
    let mut flows: HashMap<SocketAddr, u32> = HashMap::new();
    let mut names: HashMap<(String, u16), SocketAddr> = HashMap::new();
    let mut buf = vec![0u8; 65536];
    let mut ctl = [0u8; 64];
    let mut sweep = tokio::time::interval(Duration::from_secs(30));
    sweep.tick().await;
    loop {
        tokio::select! {
            r = s.read(&mut ctl) => {
                // the association lives as long as its TCP connection
                if matches!(r, Ok(0) | Err(_)) { break; }
            }
            r = relay.recv_from(&mut buf) => {
                let Ok((n, from)) = r else { break };
                let p = &buf[..n];
                // RSV RSV FRAG ATYP ADDR PORT DATA; fragments are not supported (nobody sends them)
                if n < 4 || p[2] != 0 { continue; }
                let (dst, off) = match p[3] {
                    1 if n >= 10 => (SocketAddr::new(IpAddr::V4(Ipv4Addr::new(p[4], p[5], p[6], p[7])), u16::from_be_bytes([p[8], p[9]])), 10),
                    4 if n >= 22 => {
                        let ip: [u8; 16] = p[4..20].try_into().unwrap();
                        (SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), u16::from_be_bytes([p[20], p[21]])), 22)
                    }
                    3 if n >= 5 => {
                        let l = p[4] as usize;
                        if n < 7 + l { continue; }
                        let key = (String::from_utf8_lossy(&p[5..5 + l]).to_string(), u16::from_be_bytes([p[5 + l], p[6 + l]]));
                        let a = match names.get(&key) {
                            Some(a) => *a,
                            None => match resolve(Addr::Name(key.0.clone(), key.1)).await {
                                Ok(a) => { names.insert(key, a); a }
                                Err(_) => continue,
                            },
                        };
                        (a, 7 + l)
                    }
                    _ => continue,
                };
                let dst = plain(dst);
                let data = &p[off..];
                let id = match flows.get(&dst) {
                    Some(id) => *id,
                    None => {
                        // answers carry the header the app sent (a name stays a name)
                        let mut head = vec![0, 0, 0];
                        head.extend_from_slice(&p[3..off]);
                        let Ok(id) = c.new_flow(relay.clone(), from, head, data.len()).await else { continue };
                        flows.insert(dst, id);
                        id
                    }
                };
                c.send_udp(id, &super::target_of(dst), from, data).await;
            }
            _ = sweep.tick() => {
                let now = now_ms();
                flows.retain(|_, id| {
                    let keep = c.flow_last(*id).is_some_and(|t| now.saturating_sub(t) < FLOW_IDLE_MS);
                    if !keep { c.close_flow(*id); }
                    keep
                });
            }
        }
    }
    for (_, id) in flows {
        c.close_flow(id);
    }
    Ok(())
}
