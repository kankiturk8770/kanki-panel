//! The `game` core's UDP relay: the Game-FEC transport (KCP at its fastest setting, Reed-Solomon
//! FEC, the mask) with the datagram fast path next to it on the same port.
//!
//! It is the relay of `game.rs`, built from the same pieces (`Mask`, `FecEncoder`, `FecDecoder`,
//! the same shard format and KCP settings), with one change: every payload inside the mask starts
//! with a kind byte, so game datagrams can travel beside the KCP datagrams.
//!
//! ```text
//!  inside the mask:  0xF0 | KCP datagram                (FEC off)
//!                    0xF3 | group | index | shard       (FEC data shard, as in game.rs)
//!                    0xF4 | group | index | d | p | shard (FEC parity shard, as in game.rs)
//!                    0xD7 | sid | counter | sealed body (game datagram, dgram.rs)
//! ```
//!
//! The TCP side (websites, the game's login and lobby) rides KCP + FEC; the game's own UDP goes
//! as datagrams and never waits behind a lost KCP packet.

use super::super::fec::{FecDecoder, FecEncoder, Shard};
use super::super::game::GameOpts;
use super::super::link::{BoxIo, Res};
use super::super::salamander::Mask;
use super::dgram::{self, DgLink};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll};
use std::time::{Duration, Instant as StdInstant};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::Instant;

const RAW: u8 = 0xF0;
const FEC_DATA: u8 = 0xF3;
const FEC_PARITY: u8 = 0xF4;
/// a FEC group closes at the latest this long after its first packet
const FEC_DELAY: Duration = Duration::from_millis(4);
const MAX_PEERS: usize = 4096;
const PEER_IDLE: Duration = Duration::from_secs(90);

/// the KCP settings of the `game` transport (game.rs), with room for our kind byte
pub fn kcp_config() -> tokio_kcp::KcpConfig {
    tokio_kcp::KcpConfig {
        stream: true,
        nodelay: tokio_kcp::KcpNoDelayConfig::fastest(),
        mtu: 1080,
        wnd_size: (1024, 1024),
        session_expire: Duration::from_secs(45),
        ..Default::default()
    }
}

// ------------------------------------------------------------------ codec

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

/// The KCP datagrams an incoming (unmasked) KCP payload yields.
fn decode_kcp(dec: &mut FecDecoder, payload: &[u8]) -> Vec<Vec<u8>> {
    match payload.first().copied() {
        Some(RAW) if payload.len() > 1 => vec![payload[1..].to_vec()],
        Some(FEC_DATA) if payload.len() > 8 => {
            let group = u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]);
            let len = u16::from_le_bytes([payload[6], payload[7]]) as usize;
            let Some(pkt) = payload.get(8..8 + len).filter(|p| !p.is_empty()) else { return vec![] };
            let mut out = vec![pkt.to_vec()];
            out.extend(dec.data(group, payload[5], &payload[6..]));
            out
        }
        Some(FEC_PARITY) if payload.len() > 8 => {
            let group = u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]);
            dec.parity(group, payload[5], payload[6], payload[7], &payload[8..])
        }
        _ => vec![],
    }
}

/// KCP datagrams of one direction -> wire payloads (FEC-coded or raw), masked and sent.
struct Out {
    enc: Option<FecEncoder>,
    dup: bool,
}

impl Out {
    fn new(g: GameOpts) -> Out {
        Out { enc: if g.fec_on() { Some(FecEncoder::new(g.fec_data as usize, g.fec_parity as usize, FEC_DELAY)) } else { None }, dup: g.dup }
    }
    fn deadline(&self) -> Option<Instant> {
        self.enc.as_ref().and_then(|e| e.deadline())
    }
    async fn send(&self, sock: &UdpSocket, to: Option<SocketAddr>, mask: &Mask, payload: &[u8]) {
        let mut buf = Vec::with_capacity(1300);
        for _ in 0..if self.dup { 2 } else { 1 } {
            buf.clear();
            mask.seal(payload, &mut buf);
            let _ = match to {
                Some(t) => sock.send_to(&buf, t).await,
                None => sock.send(&buf).await,
            };
        }
    }
    async fn push(&mut self, sock: &UdpSocket, to: Option<SocketAddr>, mask: &Mask, pkt: &[u8]) {
        let mut jobs: Vec<Vec<u8>> = vec![];
        match &mut self.enc {
            None => {
                let mut v = Vec::with_capacity(1 + pkt.len());
                v.push(RAW);
                v.extend_from_slice(pkt);
                jobs.push(v);
            }
            Some(enc) => enc.push(pkt, Instant::now(), &mut |s: Shard<'_>| jobs.push(shard_payload(&s))),
        }
        for j in &jobs {
            self.send(sock, to, mask, j).await;
        }
    }
    async fn flush_due(&mut self, sock: &UdpSocket, to: Option<SocketAddr>, mask: &Mask) {
        let mut jobs: Vec<Vec<u8>> = vec![];
        if let Some(enc) = &mut self.enc {
            enc.close_if_due(Instant::now(), &mut |s: Shard<'_>| jobs.push(shard_payload(&s)));
        }
        for j in &jobs {
            self.send(sock, to, mask, j).await;
        }
    }
}

// ------------------------------------------------------------------ server

/// The datagram sessions of one `game` listener, by session id.
#[derive(Default)]
pub struct Hub {
    sessions: Mutex<HashMap<u64, (Arc<DgLink>, mpsc::Sender<Vec<u8>>)>>,
    /// the public socket and mask (set when the listener binds)
    wire: OnceLock<(Arc<UdpSocket>, Arc<Mask>)>,
}

impl Hub {
    /// A datagram path for a new session; its bodies arrive on the returned receiver.
    pub fn open(&self, sid: u64, key: &[u8; 32], copies: u8) -> Option<(Arc<DgLink>, mpsc::Receiver<Vec<u8>>)> {
        let (sock, mask) = self.wire.get()?.clone();
        let link = Arc::new(DgLink::new(sid, key, false, dgram::Wire::Udp { sock, mask, to: Mutex::new(None) }, copies, dgram::GAME_MAX_BODY));
        let (tx, rx) = mpsc::channel(1024);
        self.sessions.lock().unwrap().insert(sid, (link.clone(), tx));
        Some((link, rx))
    }
    pub fn close(&self, sid: u64) {
        self.sessions.lock().unwrap().remove(&sid);
    }
    fn deliver(&self, payload: &[u8], from: SocketAddr) {
        let Some(sid) = dgram::sid_of(payload) else { return };
        let Some((link, tx)) = self.sessions.lock().unwrap().get(&sid).cloned() else { return };
        if let Some(body) = link.open(payload) {
            // answers go where the app is now (a phone that moves from Wi-Fi to data keeps playing)
            if let dgram::Wire::Udp { to, .. } = &link.wire {
                *to.lock().unwrap() = Some(from);
            }
            let _ = tx.try_send(body);
        }
    }
}

struct Peer {
    sock: Arc<UdpSocket>,
    last: StdInstant,
    pump: JoinHandle<()>,
    dec: Arc<Mutex<FecDecoder>>,
}

/// KCP's answers to one app: FEC, mask, out.
async fn pump(sock: Arc<UdpSocket>, public: Arc<UdpSocket>, mask: Arc<Mask>, to: SocketAddr, g: GameOpts) {
    let mut out = Out::new(g);
    let mut b = vec![0u8; 65535];
    loop {
        let got = match out.deadline() {
            Some(dl) => tokio::time::timeout_at(dl, sock.recv(&mut b)).await.ok(),
            None => Some(sock.recv(&mut b).await),
        };
        match got {
            Some(Ok(n)) => out.push(&public, Some(to), &mask, &b[..n]).await,
            Some(Err(_)) => break,
            None => out.flush_due(&public, Some(to), &mask).await,
        }
    }
}

/// Owns the public UDP port: datagrams to the hub, KCP payloads to the local KCP listener.
pub struct Relay {
    tasks: Vec<JoinHandle<()>>,
    peers: Arc<Mutex<HashMap<SocketAddr, Peer>>>,
}

impl Drop for Relay {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
        for (_, p) in self.peers.lock().unwrap().drain() {
            p.pump.abort();
        }
    }
}

pub async fn relay(port: u16, door: &str, kcp_local: SocketAddr, g: GameOpts, hub: Arc<Hub>) -> Res<Relay> {
    let mask = Arc::new(Mask::new(door));
    let public = Arc::new(UdpSocket::bind(format!("0.0.0.0:{}", port)).await?);
    dgram::tune_udp(&public);
    let _ = hub.wire.set((public.clone(), mask.clone()));
    let peers: Arc<Mutex<HashMap<SocketAddr, Peer>>> = Arc::new(Mutex::new(HashMap::new()));

    let (public1, mask1, peers1) = (public.clone(), mask.clone(), peers.clone());
    let main = tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            let (n, from) = match public1.recv_from(&mut buf).await {
                Ok(x) => x,
                Err(_) => {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    continue;
                }
            };
            // not ours: no answer at all
            let Some((s, e)) = mask1.open(&mut buf[..n]) else { continue };
            let payload = &buf[s..e];
            if payload.first() == Some(&dgram::TAG) {
                hub.deliver(payload, from);
                continue;
            }
            let payload = payload.to_vec();
            let mut entry = peers1.lock().unwrap().get_mut(&from).map(|p| {
                p.last = StdInstant::now();
                (p.sock.clone(), p.dec.clone())
            });
            if entry.is_none() && peers1.lock().unwrap().len() < MAX_PEERS {
                if let Ok(sock) = UdpSocket::bind("127.0.0.1:0").await {
                    if sock.connect(kcp_local).await.is_ok() {
                        let sock = Arc::new(sock);
                        let dec = Arc::new(Mutex::new(FecDecoder::default()));
                        let pump = tokio::spawn(pump(sock.clone(), public1.clone(), mask1.clone(), from, g));
                        peers1.lock().unwrap().insert(from, Peer { sock: sock.clone(), last: StdInstant::now(), pump, dec: dec.clone() });
                        entry = Some((sock, dec));
                    }
                }
            }
            let Some((sock, dec)) = entry else { continue };
            let packets = decode_kcp(&mut dec.lock().unwrap(), &payload);
            for pkt in packets {
                let _ = sock.send(&pkt).await;
            }
        }
    });
    let peers2 = peers.clone();
    let reaper = tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(15)).await;
            peers2.lock().unwrap().retain(|_, p| {
                let keep = !p.pump.is_finished() && p.last.elapsed() < PEER_IDLE;
                if !keep {
                    p.pump.abort();
                }
                keep
            });
        }
    });
    Ok(Relay { tasks: vec![main, reaper], peers })
}

// ------------------------------------------------------------------ app side

/// The app's relay: KCP dials `local`; game datagrams arrive on `dgrams`.
pub struct Client {
    pub local: SocketAddr,
    pub outer: Arc<UdpSocket>,
    pub mask: Arc<Mask>,
    tasks: Vec<JoinHandle<()>>,
}

impl Drop for Client {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

pub async fn client(remote: SocketAddr, door: &str, g: GameOpts, dgrams: mpsc::Sender<Vec<u8>>) -> Res<Client> {
    let mask = Arc::new(Mask::new(door));
    let bind: SocketAddr = if remote.is_ipv6() { "[::]:0".parse()? } else { "0.0.0.0:0".parse()? };
    let outer = Arc::new(UdpSocket::bind(bind).await?);
    dgram::tune_udp(&outer);
    outer.connect(remote).await?;
    let inner = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
    let local = inner.local_addr()?;
    let kcp_addr: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));

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
                    *ka1.lock().unwrap() = Some(from);
                    out.push(&outer1, None, &mask1, &a[..n]).await;
                }
                Some(Err(_)) => break,
                None => out.flush_due(&outer1, None, &mask1).await,
            }
        }
    });
    let (outer2, mask2) = (outer.clone(), mask.clone());
    let in_task = tokio::spawn(async move {
        let mut dec = FecDecoder::default();
        let mut b = vec![0u8; 65535];
        loop {
            let n = match outer2.recv(&mut b).await {
                Ok(n) => n,
                // ICMP "port unreachable" from an earlier datagram: not fatal for UDP
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => continue,
                Err(_) => break,
            };
            let Some((s, e)) = mask2.open(&mut b[..n]) else { continue };
            let payload = &b[s..e];
            if payload.first() == Some(&dgram::TAG) {
                let _ = dgrams.try_send(payload.to_vec());
                continue;
            }
            let dst = *kcp_addr.lock().unwrap();
            let Some(dst) = dst else { continue };
            for pkt in decode_kcp(&mut dec, payload) {
                let _ = inner.send_to(&pkt, dst).await;
            }
        }
    });
    Ok(Client { local, outer, mask, tasks: vec![out_task, in_task] })
}

/// A stream that also owns something that must live as long as it (a relay, a permit).
pub struct Held<S, G> {
    pub stream: S,
    pub _guard: G,
}

impl<S: AsyncRead + Unpin, G: Unpin> AsyncRead for Held<S, G> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin, G: Unpin> AsyncWrite for Held<S, G> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

/// Dials the KCP stream of a `game` core through a new relay. The relay is returned too: the
/// datagram path sends on its socket.
pub async fn dial(remote: SocketAddr, door: &str, g: GameOpts, dgrams: mpsc::Sender<Vec<u8>>) -> Res<(BoxIo, Arc<UdpSocket>, Arc<Mask>)> {
    let relay = client(remote, door, g, dgrams).await?;
    let (outer, mask) = (relay.outer.clone(), relay.mask.clone());
    let stream = tokio::time::timeout(Duration::from_secs(12), tokio_kcp::KcpStream::connect(&kcp_config(), relay.local))
        .await
        .map_err(|_| "game connect timeout")??;
    Ok((Box::new(Held { stream, _guard: relay }), outer, mask))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kcp_payloads_round_trip_with_and_without_fec() {
        let mut dec = FecDecoder::default();
        assert_eq!(decode_kcp(&mut dec, &[RAW, 1, 2, 3]), vec![vec![1, 2, 3]]);
        assert!(decode_kcp(&mut dec, &[dgram::TAG, 1, 2]).is_empty(), "a datagram is never fed to KCP");
        let mut enc = FecEncoder::new(4, 2, FEC_DELAY);
        let mut wire = vec![];
        let pk: Vec<Vec<u8>> = (0..4u8).map(|i| vec![i; 20 + i as usize]).collect();
        for p in &pk {
            enc.push(p, Instant::now(), &mut |s: Shard<'_>| wire.push(shard_payload(&s)));
        }
        let mut got = vec![];
        for (i, w) in wire.iter().enumerate() {
            if i != 1 {
                got.extend(decode_kcp(&mut dec, w));
            }
        }
        got.sort();
        assert_eq!(got, pk, "the lost shard is rebuilt");
    }
}
