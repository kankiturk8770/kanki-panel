//! `hq`: QUIC under a UDP mask, for networks that cut by protocol signature or lose many packets.
//!
//! It is the same QUIC (quinn, TLS 1.3, one stream per link) the `quic` transport uses, with three
//! differences:
//!
//! 1. **The datagrams are masked.** quinn is given a custom UDP socket (`MaskedSocket`) that wraps
//!    every outgoing datagram with the mask of `salamander.rs` and unwraps every incoming one, so
//!    the first packet no longer looks like a QUIC Initial and no byte on the wire is fixed. A
//!    datagram that does not unwrap is dropped silently: a scanner gets no answer at all.
//! 2. **The size is fixed and small.** The mask adds up to a few hundred bytes of padding to a
//!    datagram, so QUIC is kept at the minimum packet size (1200 bytes, no MTU probing) and nothing
//!    grows past 1232 bytes on the wire. Segmentation offload (GSO/GRO) is off: it needs equal-sized
//!    datagrams, and every datagram here has its own size.
//! 3. **Loss-tolerant congestion control.** BBR instead of Cubic: a few percent of random loss does
//!    not shrink the window to nothing.
//!
//! The key of the mask is the tunnel token, which both ends already share.

use super::link::{Bag, BoxIo, Inbox, Res};
use super::quic::{accept_loop, client_config, server_config, QuicIo, QUIC_PRIME};
use super::salamander::Mask;
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, Endpoint, EndpointConfig, TokioRuntime, TransportConfig, UdpPoller};
use std::fmt;
use std::future::Future;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Context, Poll};
use std::time::Duration;
use tokio::sync::Semaphore;

// ------------------------------------------------------------------ the masked UDP socket

/// A UDP socket for quinn that masks every datagram it sends and unmasks every one it receives.
pub struct MaskedSocket {
    io: tokio::net::UdpSocket,
    mask: Mask,
}

impl fmt::Debug for MaskedSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MaskedSocket").finish_non_exhaustive()
    }
}

impl MaskedSocket {
    /// Binds a UDP socket on `addr`. Must be called inside the tokio runtime.
    pub fn bind(addr: SocketAddr, mask: Mask) -> io::Result<Arc<MaskedSocket>> {
        let std_sock = std::net::UdpSocket::bind(addr)?;
        std_sock.set_nonblocking(true)?;
        let io = tokio::net::UdpSocket::from_std(std_sock)?;
        Ok(Arc::new(MaskedSocket { io, mask }))
    }
}

/// Tells quinn when the socket can take another datagram (one per waiting task, like quinn's own).
struct Poller {
    sock: Arc<MaskedSocket>,
    fut: Option<Pin<Box<dyn Future<Output = io::Result<()>> + Send + Sync>>>,
}

impl fmt::Debug for Poller {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Poller").finish_non_exhaustive()
    }
}

impl UdpPoller for Poller {
    fn poll_writable(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        if self.fut.is_none() {
            let s = self.sock.clone();
            self.fut = Some(Box::pin(async move { s.io.writable().await }));
        }
        let r = match self.fut.as_mut() {
            Some(f) => f.as_mut().poll(cx),
            None => Poll::Ready(Ok(())),
        };
        if r.is_ready() {
            // a future that finished must not be polled again: make a new one next time
            self.fut = None;
        }
        r
    }
}

/// errors of a receive that say nothing about the socket itself (an ICMP error, an interrupted call)
fn transient(e: &io::Error) -> bool {
    use io::ErrorKind as K;
    matches!(e.kind(), K::ConnectionReset | K::ConnectionRefused | K::ConnectionAborted | K::Interrupted | K::TimedOut | K::NotConnected)
}

impl AsyncUdpSocket for MaskedSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(Poller { sock: self, fut: None })
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        // we never offer segmentation (max_transmit_segments is 1), but stay correct if asked
        let seg = match transmit.segment_size {
            Some(s) if s > 0 => s,
            _ => transmit.contents.len().max(1),
        };
        let mut out: Vec<u8> = Vec::with_capacity(seg + 300);
        let mut first = true;
        for chunk in transmit.contents.chunks(seg) {
            out.clear();
            self.mask.seal(chunk, &mut out);
            match self.io.try_send_to(&out, transmit.destination) {
                Ok(_) => {}
                // the first one failing lets quinn wait for the socket and try again
                Err(e) if first => return Err(e),
                // a later one is dropped; QUIC recovers like from any lost datagram
                Err(_) => {}
            }
            first = false;
        }
        Ok(())
    }

    fn poll_recv(&self, cx: &mut Context, bufs: &mut [IoSliceMut<'_>], meta: &mut [RecvMeta]) -> Poll<io::Result<usize>> {
        let max = bufs.len().min(meta.len());
        loop {
            ready!(self.io.poll_recv_ready(cx))?;
            let mut n = 0;
            let mut junk = 0u32;
            while n < max && junk < 256 {
                let buf: &mut [u8] = &mut bufs[n];
                match self.io.try_recv_from(buf) {
                    Ok((len, addr)) => match self.mask.open(&mut buf[..len]) {
                        Some((s, e)) => {
                            buf.copy_within(s..e, 0);
                            let mut m = RecvMeta::default();
                            m.addr = addr;
                            m.len = e - s;
                            // quinn splits a buffer by `stride`: it must be the datagram size, never 0
                            m.stride = e - s;
                            meta[n] = m;
                            n += 1;
                        }
                        // not ours: dropped without a trace
                        None => junk += 1,
                    },
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    // an ICMP error and the like: count it as noise so a stuck socket cannot spin us
                    Err(e) if transient(&e) => junk += 1,
                    Err(e) => return Poll::Ready(Err(e)),
                }
            }
            if n > 0 {
                return Poll::Ready(Ok(n));
            }
            if junk >= 256 {
                // a flood of garbage: let other tasks run, then come back
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            // the socket had nothing (readiness was cleared): ask to be woken again
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.local_addr()
    }
}

// ------------------------------------------------------------------ QUIC over the masked socket

fn transport() -> Arc<TransportConfig> {
    let mut t = TransportConfig::default();
    // keep NAT mappings alive and notice a dead path quickly
    t.keep_alive_interval(Some(Duration::from_secs(5)));
    t.max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()));
    // big flow-control windows so a fast burst on one stream is not stalled
    t.stream_receive_window((8u32 * 1024 * 1024).into());
    t.receive_window((32u32 * 1024 * 1024).into());
    t.send_window(32 * 1024 * 1024);
    t.max_concurrent_bidi_streams(16u32.into());
    t.max_concurrent_uni_streams(0u32.into());
    // the mask adds bytes to every datagram: stay at the minimum QUIC packet size, never probe
    t.initial_mtu(1200);
    t.min_mtu(1200);
    t.mtu_discovery_config(None);
    t.enable_segmentation_offload(false);
    // random loss must not collapse the window
    t.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
    Arc::new(t)
}

/// Starts the `hq` server on UDP `0.0.0.0:port`.
pub async fn serve(port: u16, token: &str, out: Inbox, sem: Arc<Semaphore>) -> Res<Bag> {
    let addr: SocketAddr = format!("0.0.0.0:{}", port).parse()?;
    let sock = MaskedSocket::bind(addr, Mask::new(token))?;
    let endpoint = Endpoint::new_with_abstract_socket(EndpointConfig::default(), Some(server_config(transport())?), sock, Arc::new(TokioRuntime))?;
    Ok(accept_loop(endpoint, out, sem))
}

/// Dials an `hq` server and opens one bidirectional stream.
pub async fn dial(remote: &str, sni: &str, token: &str) -> Res<BoxIo> {
    use tokio::io::AsyncWriteExt;
    let addr: SocketAddr = tokio::net::lookup_host(remote).await?.next().ok_or("cannot resolve the tunnel address")?;
    let bind: SocketAddr = if addr.is_ipv6() { "[::]:0".parse()? } else { "0.0.0.0:0".parse()? };
    let sock = MaskedSocket::bind(bind, Mask::new(token))?;
    let mut endpoint = Endpoint::new_with_abstract_socket(EndpointConfig::default(), None, sock, Arc::new(TokioRuntime))?;
    endpoint.set_default_client_config(client_config(transport())?);
    let name = if sni.is_empty() { "www.cloudflare.com" } else { sni };
    let conn = tokio::time::timeout(Duration::from_secs(12), endpoint.connect(addr, name)?).await.map_err(|_| "hq connect timeout")??;
    let (mut send, recv) = conn.open_bi().await?;
    // the stream only truly exists on the peer once some bytes are sent
    AsyncWriteExt::write_all(&mut send, QUIC_PRIME).await?;
    AsyncWriteExt::flush(&mut send).await?;
    Ok(Box::new(QuicIo::new(send, recv, conn)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tx<'a>(to: SocketAddr, data: &'a [u8]) -> Transmit<'a> {
        Transmit { destination: to, ecn: None, contents: data, segment_size: None, src_ip: None }
    }

    /// Sends one datagram the way quinn does: when the socket is not writable yet, wait for it
    /// (a fresh tokio socket reports `WouldBlock` until its first readiness event arrives).
    async fn send(s: &Arc<MaskedSocket>, to: SocketAddr, data: &[u8]) {
        loop {
            s.io.writable().await.unwrap();
            match s.try_send(&tx(to, data)) {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                r => break r.unwrap(),
            }
        }
    }

    /// Reads whatever the socket delivers next (up to 3 s).
    async fn recv_one(s: &Arc<MaskedSocket>) -> Option<(Vec<u8>, SocketAddr)> {
        let mut storage = vec![0u8; 4096];
        let mut bufs = [IoSliceMut::new(&mut storage)];
        let mut metas = [RecvMeta::default()];
        let r = tokio::time::timeout(Duration::from_secs(3), std::future::poll_fn(|cx| s.poll_recv(cx, &mut bufs, &mut metas))).await;
        match r {
            Ok(Ok(n)) if n > 0 => {
                let m = metas[0];
                assert_eq!(m.stride, m.len, "stride must equal the datagram length");
                Some((bufs[0][..m.len].to_vec(), m.addr))
            }
            _ => None,
        }
    }

    #[tokio::test]
    async fn masked_socket_roundtrip_and_junk() {
        let a = MaskedSocket::bind("127.0.0.1:0".parse().unwrap(), Mask::new("secret")).unwrap();
        let b = MaskedSocket::bind("127.0.0.1:0".parse().unwrap(), Mask::new("secret")).unwrap();
        let wrong = MaskedSocket::bind("127.0.0.1:0".parse().unwrap(), Mask::new("other")).unwrap();
        let (aa, ba) = (a.local_addr().unwrap(), b.local_addr().unwrap());

        // plain junk from a raw socket, then a masked datagram from the right key: only the second arrives
        let raw = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        raw.send_to(&[7u8; 300], ba).unwrap();
        raw.send_to(b"GET / HTTP/1.1\r\n\r\n", ba).unwrap();
        // a datagram masked with another key is junk too
        send(&wrong, ba, b"from the wrong key").await;
        send(&a, ba, b"hello through the mask").await;
        let (data, from) = recv_one(&b).await.expect("the masked datagram must arrive");
        assert_eq!(data, b"hello through the mask");
        assert_eq!(from, aa);

        // and back
        send(&b, aa, &[1u8; 1200]).await;
        let (data, from) = recv_one(&a).await.expect("reply must arrive");
        assert_eq!(data, vec![1u8; 1200]);
        assert_eq!(from, ba);

        // nothing else is waiting on b: the junk never became a datagram
        let mut storage = vec![0u8; 4096];
        let mut bufs = [IoSliceMut::new(&mut storage)];
        let mut metas = [RecvMeta::default()];
        let extra = tokio::time::timeout(Duration::from_millis(300), std::future::poll_fn(|cx| b.poll_recv(cx, &mut bufs, &mut metas))).await;
        assert!(extra.is_err(), "junk must be dropped, not delivered");
    }
}
