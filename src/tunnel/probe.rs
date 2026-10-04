//! Smart tunnel test: measures how well one transport works between two servers.
//!
//! The panel starts a short-lived test tunnel per transport. On the exit side two special targets
//! answer inside the tunnel itself (they never touch the network): `kanki:speed` (a tiny TCP
//! service for ping, download and upload) and `kanki:echo` (UDP echo). On the entry side
//! `measure` uses them to find the real ping, TCP download / upload speed and UDP loss / ping of
//! that transport. The panel then ranks the transports.

use super::mux::{now_ms, Session, Shared};
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

pub const SPEED: &str = "kanki:speed";
pub const ECHO: &str = "kanki:echo";

/// Bytes moved per direction in a test (stops earlier when the time is up).
const MAX_BYTES: u32 = 16 * 1024 * 1024;
const PHASE: Duration = Duration::from_secs(6);

static SERVER: tokio::sync::OnceCell<SocketAddr> = tokio::sync::OnceCell::const_new();

/// exit: address of the local speed service (started on first use, loopback only).
pub async fn speed_addr() -> Option<SocketAddr> {
    SERVER
        .get_or_try_init(|| async {
            let l = TcpListener::bind("127.0.0.1:0").await?;
            let a = l.local_addr()?;
            tokio::spawn(async move {
                loop {
                    if let Ok((c, _)) = l.accept().await {
                        tokio::spawn(serve(c));
                    }
                }
            });
            Ok::<SocketAddr, std::io::Error>(a)
        })
        .await
        .ok()
        .copied()
}

/// 'P' -> one byte back (repeatable) · 'D'+n -> n bytes down · 'U'+n -> read n bytes, one byte back
async fn serve(mut c: TcpStream) {
    let _ = c.set_nodelay(true);
    let mut cmd = [0u8; 1];
    let buf = vec![0x5Au8; 64 * 1024];
    loop {
        if c.read_exact(&mut cmd).await.is_err() {
            return;
        }
        match cmd[0] {
            b'P' => {
                if c.write_all(b"p").await.is_err() {
                    return;
                }
            }
            b'D' => {
                let Ok(n) = c.read_u32().await else { return };
                let mut left = n.min(MAX_BYTES) as usize;
                while left > 0 {
                    let k = left.min(buf.len());
                    if c.write_all(&buf[..k]).await.is_err() {
                        return;
                    }
                    left -= k;
                }
                let _ = c.flush().await;
            }
            b'U' => {
                let Ok(n) = c.read_u32().await else { return };
                let mut left = n.min(MAX_BYTES) as usize;
                let mut r = vec![0u8; 64 * 1024];
                while left > 0 {
                    match c.read(&mut r[..left.min(64 * 1024)]).await {
                        Ok(0) | Err(_) => return,
                        Ok(k) => left -= k,
                    }
                }
                if c.write_all(b"u").await.is_err() {
                    return;
                }
            }
            _ => return,
        }
    }
}

/// entry: a TCP stream that goes through the tunnel to the exit's speed service.
async fn speed_stream(s: &Arc<Session>) -> Option<TcpStream> {
    let l = TcpListener::bind("127.0.0.1:0").await.ok()?;
    let a = l.local_addr().ok()?;
    let (client, accepted) = tokio::join!(TcpStream::connect(a), l.accept());
    let client = client.ok()?;
    let (server_side, _) = accepted.ok()?;
    let s2 = s.clone();
    tokio::spawn(async move { s2.open_tcp(server_side, SPEED).await });
    let _ = client.set_nodelay(true);
    Some(client)
}

fn mbps(bytes: u64, d: Duration) -> f64 {
    let s = d.as_secs_f64().max(0.001);
    ((bytes as f64 * 8.0 / s / 1_000_000.0) * 10.0).round() / 10.0
}

/// TCP ping (median of 5), download and upload speed.
async fn tcp_test(s: &Arc<Session>) -> Result<(u64, f64, f64), String> {
    let mut c = speed_stream(s).await.ok_or("could not open a test stream")?;
    // ping
    let mut times = vec![];
    for _ in 0..5 {
        let t = Instant::now();
        c.write_all(b"P").await.map_err(|e| e.to_string())?;
        let mut one = [0u8; 1];
        tokio::time::timeout(Duration::from_secs(5), c.read_exact(&mut one)).await.map_err(|_| "ping timeout")?.map_err(|e| e.to_string())?;
        times.push(t.elapsed().as_millis() as u64);
    }
    times.sort();
    let ping = times[times.len() / 2];
    drop(c);
    // download: as much as fits in the phase
    let mut c = speed_stream(s).await.ok_or("could not open a test stream")?;
    c.write_all(b"D").await.map_err(|e| e.to_string())?;
    c.write_u32(MAX_BYTES).await.map_err(|e| e.to_string())?;
    let t = Instant::now();
    let mut got: u64 = 0;
    let mut buf = vec![0u8; 64 * 1024];
    while got < MAX_BYTES as u64 && t.elapsed() < PHASE {
        match tokio::time::timeout(PHASE.saturating_sub(t.elapsed()).max(Duration::from_millis(10)), c.read(&mut buf)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
            Ok(Ok(k)) => got += k as u64,
        }
    }
    let down = mbps(got, t.elapsed());
    drop(c);
    // upload: send until the phase ends, then report what the exit confirmed
    let mut c = speed_stream(s).await.ok_or("could not open a test stream")?;
    let chunk = vec![0xA5u8; 64 * 1024];
    let t = Instant::now();
    let mut sent: u64 = 0;
    let target: u64 = MAX_BYTES as u64;
    c.write_all(b"U").await.map_err(|e| e.to_string())?;
    c.write_u32(MAX_BYTES).await.map_err(|e| e.to_string())?;
    while sent < target && t.elapsed() < PHASE {
        let k = (target - sent).min(chunk.len() as u64) as usize;
        match tokio::time::timeout(PHASE.saturating_sub(t.elapsed()).max(Duration::from_millis(10)), c.write_all(&chunk[..k])).await {
            Ok(Ok(_)) => sent += k as u64,
            _ => break,
        }
    }
    let up = if sent >= target {
        // wait for the exit to confirm it received everything
        let mut one = [0u8; 1];
        let _ = tokio::time::timeout(Duration::from_secs(10), c.read_exact(&mut one)).await;
        mbps(sent, t.elapsed())
    } else {
        // the phase ended first; what was accepted by the tunnel in that time is the speed
        mbps(sent, t.elapsed())
    };
    Ok((ping, down, up))
}

/// UDP: 40 small packets through the tunnel and back; loss % and median ping.
async fn udp_test(s: &Arc<Session>, shared: &Arc<Shared>, flow: u32) -> Result<(f64, u64), String> {
    // the tunnel delivers replies to (a, b): a sends them, b receives them
    let a = Arc::new(UdpSocket::bind("127.0.0.1:0").await.map_err(|e| e.to_string())?);
    let b = UdpSocket::bind("127.0.0.1:0").await.map_err(|e| e.to_string())?;
    let b_addr = b.local_addr().map_err(|e| e.to_string())?;
    shared.udp_back.lock().unwrap().insert(flow, (a.clone(), b_addr, now_ms()));
    const N: u64 = 40;
    let start = now_ms();
    let sender = {
        let s = s.clone();
        tokio::spawn(async move {
            for i in 0..N {
                let mut p = Vec::with_capacity(64);
                p.extend_from_slice(&i.to_be_bytes());
                p.extend_from_slice(&now_ms().to_be_bytes());
                p.resize(64, 0);
                s.send_udp(flow, ECHO, &p).await;
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
    };
    let mut seen = std::collections::HashSet::new();
    let mut rtts = vec![];
    let mut buf = [0u8; 256];
    let deadline = Instant::now() + Duration::from_millis(N * 25 + 2500);
    while Instant::now() < deadline && (seen.len() as u64) < N {
        let left = deadline.saturating_duration_since(Instant::now());
        match tokio::time::timeout(left, b.recv_from(&mut buf)).await {
            Ok(Ok((n, _))) if n >= 16 => {
                let i = u64::from_be_bytes(buf[0..8].try_into().unwrap());
                let t0 = u64::from_be_bytes(buf[8..16].try_into().unwrap());
                if t0 >= start && seen.insert(i) {
                    rtts.push(now_ms().saturating_sub(t0));
                }
            }
            Ok(_) => {}
            Err(_) => break,
        }
    }
    let _ = sender.await;
    shared.udp_back.lock().unwrap().remove(&flow);
    rtts.sort();
    let loss = ((N - seen.len() as u64) as f64 * 100.0 / N as f64 * 10.0).round() / 10.0;
    let ping = if rtts.is_empty() { 0 } else { rtts[rtts.len() / 2] };
    Ok((loss, ping))
}

/// Full measurement of one transport. Never fails: errors are reported in the result.
pub async fn measure(s: Arc<Session>, shared: Arc<Shared>) -> Value {
    let t = Instant::now();
    let tcp = tokio::time::timeout(Duration::from_secs(30), tcp_test(&s)).await.unwrap_or(Err("TCP test timed out".into()));
    let udp = tokio::time::timeout(Duration::from_secs(10), udp_test(&s, &shared, 0x7FFF_FF00)).await.unwrap_or(Err("UDP test timed out".into()));
    let mut v = json!({"done": true, "secs": t.elapsed().as_secs()});
    match tcp {
        Ok((ping, down, up)) => {
            v["ping_ms"] = json!(ping);
            v["down_mbps"] = json!(down);
            v["up_mbps"] = json!(up);
        }
        Err(e) => v["tcp_error"] = json!(e),
    }
    match udp {
        Ok((loss, ping)) => {
            v["udp_loss"] = json!(loss);
            v["udp_ping_ms"] = json!(ping);
        }
        Err(e) => v["udp_error"] = json!(e),
    }
    v
}
