//! UDP-based transports for Kanki Tunnel: QUIC (quinn) and KCP (tokio_kcp).
//!
//! Both give a reliable, ordered byte stream over UDP, which is what the link's record layer and
//! the mux expect. QUIC brings its own TLS 1.3 (we skip certificate checks, because the token
//! handshake inside proves each side); KCP is a light reliable layer over raw UDP, fast on lossy
//! links. Neither opens a target itself — they only carry the encrypted tunnel, exactly like the
//! TCP and WebSocket transports.

use super::link::{Bag, BoxIo, Inbox, Raw, Res};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{ClientConfig, Endpoint, ServerConfig, TransportConfig};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

// ------------------------------------------------------------------ QUIC

/// One QUIC bidirectional stream, seen as a single AsyncRead + AsyncWrite.
pub struct QuicIo {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    // the connection is kept alive as long as the stream is
    _conn: quinn::Connection,
}

impl QuicIo {
    pub(super) fn new(send: quinn::SendStream, recv: quinn::RecvStream, conn: quinn::Connection) -> QuicIo {
        QuicIo { send, recv, _conn: conn }
    }
}

impl AsyncRead for QuicIo {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        AsyncRead::poll_read(Pin::new(&mut self.recv), cx, buf)
    }
}

impl AsyncWrite for QuicIo {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.send), cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.send), cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.send), cx)
    }
}

fn transport_config() -> Arc<TransportConfig> {
    let mut t = TransportConfig::default();
    // keep the link alive through NAT / idle; the record keepalive also runs on top
    t.keep_alive_interval(Some(Duration::from_secs(8)));
    t.max_idle_timeout(Some(Duration::from_secs(45).try_into().unwrap()));
    // big flow-control windows so a fast burst on one stream is not stalled or reset
    t.stream_receive_window((8u32 * 1024 * 1024).into());
    t.receive_window((32u32 * 1024 * 1024).into());
    t.send_window(32 * 1024 * 1024);
    t.max_concurrent_bidi_streams(64u32.into());
    t.max_concurrent_uni_streams(0u32.into());
    Arc::new(t)
}

pub(super) fn server_config(transport: Arc<TransportConfig>) -> Res<ServerConfig> {
    // a throwaway self-signed certificate; identity is proven by the token handshake inside
    let ck = rcgen::generate_simple_self_signed(vec!["www.cloudflare.com".to_string()])?;
    let cert = rustls::pki_types::CertificateDer::from(ck.cert.der().to_vec());
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der()));
    let mut tls = rustls::ServerConfig::builder_with_provider(super::link::provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)?;
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let qsc = QuicServerConfig::try_from(tls)?;
    let mut cfg = ServerConfig::with_crypto(Arc::new(qsc));
    cfg.transport_config(transport);
    Ok(cfg)
}

pub(super) fn client_config(transport: Arc<TransportConfig>) -> Res<ClientConfig> {
    let p = super::link::provider();
    let mut tls = rustls::ClientConfig::builder_with_provider(p.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(super::link::NoVerify(p)))
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let qcc = QuicClientConfig::try_from(tls)?;
    let mut cfg = ClientConfig::new(Arc::new(qcc));
    cfg.transport_config(transport);
    Ok(cfg)
}

/// Starts a QUIC listener on `0.0.0.0:port`. Every accepted connection is handled in a task of its
/// own, so a client that stalls its handshake cannot hold up the others.
pub async fn serve_quic(port: u16, out: Inbox, sem: Arc<Semaphore>) -> Res<Bag> {
    let addr: SocketAddr = format!("0.0.0.0:{}", port).parse()?;
    let endpoint = Endpoint::server(server_config(transport_config())?, addr)?;
    Ok(accept_loop(endpoint, out, sem))
}

/// Accepts the connections of a QUIC endpoint (used by `quic` and by `hq`).
pub(super) fn accept_loop(endpoint: Endpoint, out: Inbox, sem: Arc<Semaphore>) -> Bag {
    let ep = endpoint.clone();
    let task = tokio::spawn(async move {
        while let Some(incoming) = ep.accept().await {
            let Ok(permit) = sem.clone().try_acquire_owned() else {
                incoming.refuse();
                continue;
            };
            tokio::spawn(serve_conn(incoming, out.clone(), permit));
        }
    });
    Bag { tasks: vec![task], endpoints: vec![endpoint] }
}

/// One QUIC connection: finishes its handshake, then hands every stream the dialer opens to the
/// engine (after swallowing the priming byte). The semaphore permit is held only until the first
/// stream is ready, or until the 12 s limits run out.
async fn serve_conn(incoming: quinn::Incoming, out: Inbox, permit: OwnedSemaphorePermit) {
    let peer = incoming.remote_address().ip().to_string();
    let conn = match tokio::time::timeout(Duration::from_secs(12), incoming).await {
        Ok(Ok(c)) => c,
        _ => return,
    };
    let mut permit = Some(permit);
    let mut first = true;
    loop {
        let st = if first {
            match tokio::time::timeout(Duration::from_secs(12), conn.accept_bi()).await {
                Ok(r) => r,
                Err(_) => break,
            }
        } else {
            conn.accept_bi().await
        };
        first = false;
        let (send, mut recv) = match st {
            Ok(x) => x,
            Err(_) => break,
        };
        let (out, conn2, p, peer2) = (out.clone(), conn.clone(), permit.take(), peer.clone());
        tokio::spawn(async move {
            let _p = p;
            // swallow the one priming byte the dialer sent to open the stream
            let mut one = [0u8; QUIC_PRIME.len()];
            match tokio::time::timeout(Duration::from_secs(12), AsyncReadExt::read_exact(&mut recv, &mut one)).await {
                Ok(Ok(_)) => {}
                _ => return,
            }
            let io: BoxIo = Box::new(QuicIo::new(send, recv, conn2));
            let _ = out.send((Raw::Stream(io), peer2)).await;
        });
    }
}

/// Dials a QUIC server and opens one bidirectional stream.
pub async fn dial(remote: &str, sni: &str) -> Res<BoxIo> {
    let addr: SocketAddr = tokio::net::lookup_host(remote).await?.next().ok_or("cannot resolve the tunnel address")?;
    let bind: SocketAddr = if addr.is_ipv6() { "[::]:0".parse()? } else { "0.0.0.0:0".parse()? };
    let mut endpoint = Endpoint::client(bind)?;
    endpoint.set_default_client_config(client_config(transport_config())?);
    let name = if sni.is_empty() { "www.cloudflare.com" } else { sni };
    let conn = tokio::time::timeout(Duration::from_secs(12), endpoint.connect(addr, name)?).await.map_err(|_| "quic connect timeout")??;
    use tokio::io::AsyncWriteExt;
    let (mut send, recv) = conn.open_bi().await?;
    // the stream only truly exists on the peer once some bytes are sent
    AsyncWriteExt::write_all(&mut send, QUIC_PRIME).await?;
    AsyncWriteExt::flush(&mut send).await?;
    Ok(Box::new(QuicIo { send, recv, _conn: conn }))
}

// ------------------------------------------------------------------ KCP

fn kcp_config() -> tokio_kcp::KcpConfig {
    let mut c = tokio_kcp::KcpConfig::default();
    c.stream = true;
    c.nodelay = tokio_kcp::KcpNoDelayConfig::fastest();
    c.mtu = 1350;
    c.wnd_size = (1024, 1024);
    c.session_expire = Duration::from_secs(45);
    c
}

/// Starts a KCP listener. KCP runs on a private loopback socket; the obfuscation relay owns the
/// public UDP port, so nothing with a KCP header is ever sent on the wire.
pub async fn serve_kcp(port: u16, token: &str, out: Inbox, _sem: Arc<Semaphore>) -> Res<Bag> {
    let mut inner = tokio_kcp::KcpListener::bind(kcp_config(), "127.0.0.1:0").await?;
    let local = inner.local_addr()?;
    let obfs = super::obfs::server(port, token, local).await?;
    let task = tokio::spawn(async move {
        // the relay lives as long as this loop; when the loop is stopped the relay stops with it
        let _obfs = obfs;
        loop {
            let stream = match inner.accept().await {
                Ok((s, _)) => s,
                Err(_) => {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    continue;
                }
            };
            let io: BoxIo = Box::new(stream);
            if out.send((Raw::Stream(io), "kcp".to_string())).await.is_err() {
                break;
            }
        }
    });
    Ok(Bag { tasks: vec![task], endpoints: vec![] })
}

/// Dials a KCP server through the obfuscation relay.
pub async fn kcp_dial(remote: &str, token: &str) -> Res<BoxIo> {
    let addr: SocketAddr = tokio::net::lookup_host(remote).await?.next().ok_or("cannot resolve the tunnel address")?;
    let obfs = super::obfs::client(addr, token).await?;
    let cfg = kcp_config();
    let stream = tokio::time::timeout(Duration::from_secs(12), tokio_kcp::KcpStream::connect(&cfg, obfs.local))
        .await
        .map_err(|_| "kcp connect timeout")??;
    // keep the relay alive for the life of the stream
    Ok(Box::new(KcpIo { stream, _obfs: obfs }))
}

/// A KCP stream that also owns its obfuscation relay.
pub struct KcpIo {
    stream: tokio_kcp::KcpStream,
    _obfs: super::obfs::ClientObfs,
}

impl AsyncRead for KcpIo {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        AsyncRead::poll_read(Pin::new(&mut self.stream), cx, buf)
    }
}
impl AsyncWrite for KcpIo {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.stream), cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.stream), cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.stream), cx)
    }
}

// the first byte sent by the QUIC dialer is swallowed by the server side before the handshake
pub const QUIC_PRIME: &[u8] = b"k";
