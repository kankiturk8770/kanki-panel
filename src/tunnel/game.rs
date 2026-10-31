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

use super::fec::{FecDecoder, FecEncoder, Shard};
use super::link::{Bag, BoxIo, Inbox, Res};
use super::salamander::Mask;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
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
}

impl GameOpts {
    pub fn fec_on(&self) -> bool {
        self.fec_data >= 1 && self.fec_parity >= 1
    }
    /// "8:3" style spec string -> options ("" keeps the defaults of the transport)
    pub fn parse(fec: &str, dup: bool) -> GameOpts {
        let mut g = GameOpts { fec_data: 8, fec_parity: 3, dup };
        let f = fec.trim();
        if f.is_empty() {
            return g;
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
/// a group closes at the latest this long after its first packet (game traffic is latency-bound)
const FEC_DELAY: Duration = Duration::from_millis(4);
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

/// An encoder plus the shard sender of one direction.
struct Out {
    enc: Option<FecEncoder>,
}

impl Out {
    fn new(g: GameOpts) -> Out {
        Out { enc: if g.fec_on() { Some(FecEncoder::new(g.fec_data as usize, g.fec_parity as usize, FEC_DELAY)) } else { None } }
    }
    fn deadline(&self) -> Option<Instant> {
        self.enc.as_ref().and_then(|e| e.deadline())
    }
    /// Turns one KCP datagram into wire payloads and sends them.
    async fn push(&mut self, sock: &UdpSocket, to: Option<SocketAddr>, mask: &Mask, pkt: &[u8], dup: bool) {
        match &mut self.enc {
            None => send_masked(sock, to, mask, pkt, dup).await,
            Some(enc) => {
                let mut jobs: Vec<Vec<u8>> = vec![];
                enc.push(pkt, Instant::now(), &mut |s: Shard<'_>| jobs.push(shard_payload(&s)));
                for j in &jobs {
                    send_masked(sock, to, mask, j, dup).await;
                }
            }
        }
    }
    /// Closes a due FEC group (called when the timer fires).
    async fn flush_due(&mut self, sock: &UdpSocket, to: Option<SocketAddr>, mask: &Mask, dup: bool) {
        if let Some(enc) = &mut self.enc {
            let mut jobs: Vec<Vec<u8>> = vec![];
            enc.close_if_due(Instant::now(), &mut |s: Shard<'_>| jobs.push(shard_payload(&s)));
            for j in &jobs {
                send_masked(sock, to, mask, j, dup).await;
            }
        }
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
    tasks: Vec<JoinHandle<()>>,
}

impl Drop for ClientGame {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

pub async fn client(remote: SocketAddr, token: &str, g: GameOpts) -> Res<ClientGame> {
    let mask = Arc::new(Mask::new(token));
    let bind: SocketAddr = if remote.is_ipv6() { "[::]:0".parse()? } else { "0.0.0.0:0".parse()? };
    let outer = Arc::new(UdpSocket::bind(bind).await?);
    outer.connect(remote).await?;
    let inner = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
    let local = inner.local_addr()?;
    let kcp_addr: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));

    // KCP -> FEC/dup -> mask -> peer
    let (inner1, outer1, ka1, mask1) = (inner.clone(), outer.clone(), kcp_addr.clone(), mask.clone());
    let out_task = tokio::spawn(async move {
        let mut out = Out::new(g);
        let mut a = vec![0u8; 65535];
        loop {
            let got = match out.deadline() {
                Some(dl) => tokio::time::timeout_at(dl, inner1.recv_from(&mut a)).await.ok(),
                None => Some(inner1.recv_from(&mut a).await),
            };
            match got {
                Some(Ok((n, from))) => {
                    *ka1.lock().unwrap_or_else(|e| e.into_inner()) = Some(from);
                    out.push(&outer1, None, &mask1, &a[..n], g.dup).await;
                }
                Some(Err(_)) => break,
                None => out.flush_due(&outer1, None, &mask1, g.dup).await,
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
            for pkt in decode_in(dec.as_mut(), &payload) {
                let _ = inner.send_to(&pkt, dst).await;
            }
        }
    });
    Ok(ClientGame { local, tasks: vec![out_task, in_task] })
}

// ------------------------------------------------------------------ server relay

/// One real client as the KCP listener sees it: its own loopback socket and the pump task that
/// carries KCP's answers (FEC-coded, masked, maybe duplicated) back to the client.
struct Peer {
    sock: Arc<UdpSocket>,
    last: StdInstant,
    pump: JoinHandle<()>,
    dec: Arc<Mutex<FecDecoder>>,
}

/// Server side: owns the public UDP socket, unwraps incoming datagrams and forwards them (in the
/// clear) to the local KCP listener, and wraps KCP's replies back out. One relay serves every
/// client on the port, keyed by address.
pub struct ServerGame {
    tasks: Vec<JoinHandle<()>>,
    peers: Arc<Mutex<HashMap<SocketAddr, Peer>>>,
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

/// KCP -> FEC/dup -> mask -> client, for one client.
async fn pump(sock: Arc<UdpSocket>, public: Arc<UdpSocket>, mask: Arc<Mask>, to: SocketAddr, g: GameOpts) {
    let mut out = Out::new(g);
    let mut b = vec![0u8; 65535];
    loop {
        let got = match out.deadline() {
            Some(dl) => tokio::time::timeout_at(dl, sock.recv(&mut b)).await.ok(),
            None => Some(sock.recv(&mut b).await),
        };
        match got {
            Some(Ok(n)) => out.push(&public, Some(to), &mask, &b[..n], g.dup).await,
            Some(Err(_)) => break,
            None => out.flush_due(&public, Some(to), &mask, g.dup).await,
        }
    }
}

pub async fn server(port: u16, token: &str, kcp_local: SocketAddr, g: GameOpts) -> Res<ServerGame> {
    let mask = Arc::new(Mask::new(token));
    let public = Arc::new(UdpSocket::bind(format!("0.0.0.0:{}", port)).await?);
    let peers: Arc<Mutex<HashMap<SocketAddr, Peer>>> = Arc::new(Mutex::new(HashMap::new()));

    let (public1, mask1, peers1) = (public.clone(), mask.clone(), peers.clone());
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
                    (p.sock.clone(), p.dec.clone())
                })
            };
            if entry.is_none() && peers1.lock().unwrap_or_else(|e| e.into_inner()).len() < MAX_PEERS {
                if let Ok(sock) = UdpSocket::bind("127.0.0.1:0").await {
                    if sock.connect(kcp_local).await.is_ok() {
                        let sock = Arc::new(sock);
                        let dec = Arc::new(Mutex::new(FecDecoder::default()));
                        let pump = tokio::spawn(pump(sock.clone(), public1.clone(), mask1.clone(), from, g));
                        peers1.lock().unwrap_or_else(|e| e.into_inner()).insert(from, Peer { sock: sock.clone(), last: StdInstant::now(), pump, dec: dec.clone() });
                        entry = Some((sock, dec));
                    }
                }
            }
            let Some((sock, dec)) = entry else { continue };
            let packets = {
                let mut d = dec.lock().unwrap_or_else(|e| e.into_inner());
                // FEC state lives per peer; without FEC payloads pass through
                decode_in(if g.fec_on() { Some(&mut *d) } else { None }, &payload)
            };
            for pkt in packets {
                let _ = sock.send(&pkt).await;
            }
        }
    });

    // forget clients that went quiet (and clients whose pump died)
    let peers2 = peers.clone();
    let reaper = tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(15)).await;
            let mut g = peers2.lock().unwrap_or_else(|e| e.into_inner());
            g.retain(|_, p| {
                let keep = !p.pump.is_finished() && p.last.elapsed() < PEER_IDLE;
                if !keep {
                    p.pump.abort();
                }
                keep
            });
        }
    });

    Ok(ServerGame { tasks: vec![main_task, reaper], peers })
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
        let _relay = relay;
        loop {
            let stream = match inner.accept().await {
                Ok((s, _)) => s,
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
            if out.send((super::link::Raw::Stream(io), "game".to_string())).await.is_err() {
                break;
            }
        }
    });
    Ok(Bag { tasks: vec![task], endpoints: vec![] })
}

/// Dials a `game` server through the FEC/mask relay.
pub async fn dial_game(remote: &str, token: &str, g: GameOpts) -> Res<BoxIo> {
    let addr: SocketAddr = tokio::net::lookup_host(remote).await?.next().ok_or("cannot resolve the tunnel address")?;
    let relay = client(addr, token, g).await?;
    let stream = tokio::time::timeout(Duration::from_secs(12), tokio_kcp::KcpStream::connect(&game_kcp_config(), relay.local))
        .await
        .map_err(|_| "game connect timeout")??;
    Ok(Box::new(GameIo { stream, _relay: relay }))
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
}
