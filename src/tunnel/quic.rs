//! UDP-based transports for Kanki Tunnel: QUIC (quinn) and KCP (tokio_kcp).
//!
//! Both give a reliable, ordered byte stream over UDP, which is what the link's record layer and
//! the mux expect. QUIC brings its own TLS 1.3 (we skip certificate checks, because the token
//! handshake inside proves each side); KCP is a light reliable layer over raw UDP, fast on lossy
//! links. Neither opens a target itself — they only carry the encrypted tunnel, exactly like the
//! TCP and WebSocket transports.

use super::link::{BoxIo, Res};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{ClientConfig, Endpoint, ServerConfig, TransportConfig};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

// ------------------------------------------------------------------ QUIC

/// One QUIC bidirectional stream, seen as a single AsyncRead + AsyncWrite.
pub struct QuicIo {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    // the connection is kept alive as long as the stream is
    _conn: quinn::Connection,
}

impl AsyncRead for QuicIo {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for QuicIo {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.send).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.send).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.send).poll_shutdown(cx)
    }
}

fn transport_config() -> Arc<TransportConfig> {
    let mut t = TransportConfig::default();
    // keep the link alive through NAT / idle; the record keepalive also runs on top
    t.keep_alive_interval(Some(Duration::from_secs(8)));
    t.max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()));
    Arc::new(t)
}

fn server_config() -> Res<ServerConfig> {
    // a throwaway self-signed certificate; identity is proven by the token handshake inside
    let ck = rcgen::generate_simple_self_signed(vec!["kanki.tunnel".to_string()])?;
    let cert = rustls::pki_types::CertificateDer::from(ck.cert.der().to_vec());
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der()));
    let mut tls = rustls::ServerConfig::builder_with_provider(super::link::provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)?;
    tls.alpn_protocols = vec![b"kanki".to_vec()];
    let qsc = QuicServerConfig::try_from(tls)?;
    let mut cfg = ServerConfig::with_crypto(Arc::new(qsc));
    cfg.transport_config(transport_config());
    Ok(cfg)
}

fn client_config() -> Res<ClientConfig> {
    let p = super::link::provider();
    let mut tls = rustls::ClientConfig::builder_with_provider(p.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(super::link::NoVerify(p)))
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"kanki".to_vec()];
    let qcc = QuicClientConfig::try_from(tls)?;
    let mut cfg = ClientConfig::new(Arc::new(qcc));
    cfg.transport_config(transport_config());
    Ok(cfg)
}

/// A QUIC listener: one endpoint, from which we accept connections and their first stream.
pub struct QuicListener {
    endpoint: Endpoint,
}

impl QuicListener {
    pub async fn bind(port: u16) -> Res<QuicListener> {
        let addr: SocketAddr = format!("0.0.0.0:{}", port).parse()?;
        let endpoint = Endpoint::server(server_config()?, addr)?;
        Ok(QuicListener { endpoint })
    }

    /// Accepts the next QUIC connection and its first bidirectional stream.
    pub async fn accept(&self) -> Res<BoxIo> {
        loop {
            let incoming = self.endpoint.accept().await.ok_or("quic endpoint closed")?;
            // handle each connection's first stream; a failed one must not stop the listener
            match accept_one(incoming).await {
                Ok(io) => return Ok(io),
                Err(_) => continue,
            }
        }
    }
}

async fn accept_one(incoming: quinn::Incoming) -> Res<BoxIo> {
    use tokio::io::AsyncReadExt;
    let conn = tokio::time::timeout(Duration::from_secs(12), incoming).await.map_err(|_| "quic accept timeout")??;
    let (send, mut recv) = tokio::time::timeout(Duration::from_secs(12), conn.accept_bi()).await.map_err(|_| "quic stream timeout")??;
    // swallow the one priming byte the dialer sent to open the stream
    let mut one = [0u8; QUIC_PRIME.len()];
    tokio::time::timeout(Duration::from_secs(12), AsyncReadExt::read_exact(&mut recv, &mut one)).await.map_err(|_| "quic prime timeout")??;
    Ok(Box::new(QuicIo { send, recv, _conn: conn }))
}

/// Dials a QUIC server and opens one bidirectional stream.
pub async fn dial(remote: &str, sni: &str) -> Res<BoxIo> {
    let addr: SocketAddr = tokio::net::lookup_host(remote).await?.next().ok_or("cannot resolve the tunnel address")?;
    let bind: SocketAddr = if addr.is_ipv6() { "[::]:0".parse()? } else { "0.0.0.0:0".parse()? };
    let mut endpoint = Endpoint::client(bind)?;
    endpoint.set_default_client_config(client_config()?);
    let name = if sni.is_empty() { "kanki.tunnel" } else { sni };
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

/// A KCP listener over a UDP socket.
pub struct KcpListener {
    inner: tokio_kcp::KcpListener,
}

impl KcpListener {
    pub async fn bind(port: u16) -> Res<KcpListener> {
        let addr: SocketAddr = format!("0.0.0.0:{}", port).parse()?;
        let inner = tokio_kcp::KcpListener::bind(kcp_config(), addr).await?;
        Ok(KcpListener { inner })
    }
    pub async fn accept(&mut self) -> Res<BoxIo> {
        let (stream, _) = self.inner.accept().await?;
        Ok(Box::new(stream))
    }
}

/// Dials a KCP server.
pub async fn kcp_dial(remote: &str) -> Res<BoxIo> {
    let addr: SocketAddr = tokio::net::lookup_host(remote).await?.next().ok_or("cannot resolve the tunnel address")?;
    let cfg = kcp_config();
    let stream = tokio::time::timeout(Duration::from_secs(12), tokio_kcp::KcpStream::connect(&cfg, addr)).await.map_err(|_| "kcp connect timeout")??;
    Ok(Box::new(stream))
}

// the first byte sent by the QUIC dialer is swallowed by the server side before the handshake
pub const QUIC_PRIME: &[u8] = b"k";
