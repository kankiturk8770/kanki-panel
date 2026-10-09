//! Kanki Tunnel: the link between two servers.
//!
//! A link is one connection (tcp, websocket or websocket over TLS) that carries encrypted records.
//! Handshake: both sides send an X25519 public key and 16 random bytes; the keys are derived with
//! HKDF-SHA256 from the shared secret, salted with the tunnel token, so a side without the right
//! token cannot read or write a single record (mutual authentication + forward secrecy).
//! Records are ChaCha20-Poly1305 with a counter nonce; on a byte stream the length is sealed too,
//! so nothing on the wire has fixed bytes.

use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

pub type Res<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// largest plaintext record (a mux frame)
pub const MAX_RECORD: usize = 65535 - 16;

pub trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}
pub type BoxIo = Box<dyn Io>;

// ------------------------------------------------------------------ crypto

pub struct Cipher {
    aead: ChaCha20Poly1305,
    n: u64,
    /// padded records (`hq`, `h2`, `dual`): every record carries its real length and a random
    /// amount of filler, so the size on the wire does not tell what the record is
    pad: bool,
}

/// How much filler a record of `len` bytes gets at most: small control records (window updates,
/// pings, acks) get the most, big data records almost none (it would only cost speed).
fn record_pad(len: usize) -> usize {
    let max = if len < 128 {
        192
    } else if len < 512 {
        128
    } else if len < 1400 {
        64
    } else {
        16
    };
    (rand::thread_rng().next_u32() as usize) % (max + 1)
}

impl Cipher {
    fn new(k: &[u8], pad: bool) -> Self {
        Cipher { aead: ChaCha20Poly1305::new(Key::from_slice(k)), n: 0, pad }
    }
    /// plain record -> what gets sealed (with real length and filler when padding is on)
    fn pack(&self, pt: &[u8]) -> Vec<u8> {
        if !self.pad {
            return pt.to_vec();
        }
        let room = 65535usize.saturating_sub(2 + pt.len());
        let pad = record_pad(pt.len()).min(room);
        let mut v = Vec::with_capacity(2 + pt.len() + pad);
        v.extend_from_slice(&(pt.len() as u16).to_be_bytes());
        v.extend_from_slice(pt);
        v.resize(2 + pt.len() + pad, 0);
        v
    }
    /// what was opened -> the plain record
    fn unpack(&self, v: Vec<u8>) -> Res<Vec<u8>> {
        if !self.pad {
            return Ok(v);
        }
        if v.len() < 2 {
            return Err("short record".into());
        }
        let n = u16::from_be_bytes([v[0], v[1]]) as usize;
        if 2 + n > v.len() {
            return Err("bad padded record".into());
        }
        Ok(v[2..2 + n].to_vec())
    }
    fn nonce(&mut self) -> [u8; 12] {
        let mut b = [0u8; 12];
        b[..8].copy_from_slice(&self.n.to_le_bytes());
        self.n = self.n.wrapping_add(1);
        b
    }
    fn seal(&mut self, pt: &[u8]) -> Vec<u8> {
        let n = self.nonce();
        self.aead.encrypt(Nonce::from_slice(&n), pt).unwrap_or_default()
    }
    fn open(&mut self, ct: &[u8]) -> Res<Vec<u8>> {
        let n = self.nonce();
        self.aead.decrypt(Nonce::from_slice(&n), ct).map_err(|_| "bad record (wrong token or damaged data)".into())
    }
}

fn derive(token: &str, shared: &[u8], hello_c: &[u8], hello_s: &[u8]) -> Res<([u8; 32], [u8; 32])> {
    let salt = Sha256::digest(format!("kanki-tunnel|{}", token).as_bytes());
    let hk = Hkdf::<Sha256>::new(Some(&salt[..]), shared);
    let mut info = b"kanki-tunnel-v1".to_vec();
    info.extend_from_slice(hello_c);
    info.extend_from_slice(hello_s);
    let mut okm = [0u8; 64];
    hk.expand(&info, &mut okm).map_err(|_| "hkdf")?;
    let mut c2s = [0u8; 32];
    let mut s2c = [0u8; 32];
    c2s.copy_from_slice(&okm[..32]);
    s2c.copy_from_slice(&okm[32..]);
    Ok((c2s, s2c))
}

// ------------------------------------------------------------------ raw connection (before the handshake)

pub enum Raw {
    Stream(BoxIo),
    Ws(WebSocketStream<BoxIo>),
}

impl Raw {
    async fn send_raw(&mut self, b: &[u8]) -> Res<()> {
        match self {
            Raw::Stream(s) => {
                s.write_all(b).await?;
                s.flush().await?;
            }
            Raw::Ws(w) => w.send(Message::Binary(b.to_vec())).await?,
        }
        Ok(())
    }
    async fn recv_raw(&mut self, n: usize) -> Res<Vec<u8>> {
        match self {
            Raw::Stream(s) => {
                let mut b = vec![0u8; n];
                s.read_exact(&mut b).await?;
                Ok(b)
            }
            Raw::Ws(w) => loop {
                match w.next().await {
                    Some(Ok(Message::Binary(b))) => {
                        if b.len() != n {
                            return Err("bad hello".into());
                        }
                        return Ok(b);
                    }
                    Some(Ok(Message::Close(_))) | None => return Err("closed".into()),
                    Some(Ok(_)) => continue,
                    Some(Err(e)) => return Err(e.into()),
                }
            },
        }
    }
    pub(super) fn split(self, tx: Cipher, rx: Cipher) -> (Tx, Rx) {
        match self {
            Raw::Stream(s) => {
                let (r, w) = tokio::io::split(s);
                (Tx::Stream(w, tx), Rx::Stream(r, rx))
            }
            Raw::Ws(ws) => {
                let (w, r) = ws.split();
                (Tx::Ws(w, tx), Rx::Ws(r, rx))
            }
        }
    }
}

// ------------------------------------------------------------------ encrypted halves

pub enum Tx {
    Stream(WriteHalf<BoxIo>, Cipher),
    Ws(SplitSink<WebSocketStream<BoxIo>, Message>, Cipher),
}

pub enum Rx {
    Stream(ReadHalf<BoxIo>, Cipher),
    Ws(SplitStream<WebSocketStream<BoxIo>>, Cipher),
}

impl Tx {
    pub async fn send(&mut self, pt: &[u8]) -> Res<()> {
        if pt.len() > MAX_RECORD {
            return Err("record too large".into());
        }
        match self {
            Tx::Stream(w, c) => {
                let body = c.pack(pt);
                let len = (body.len() as u16).to_be_bytes();
                let mut buf = c.seal(&len);
                buf.extend_from_slice(&c.seal(&body));
                w.write_all(&buf).await?;
                w.flush().await?;
            }
            Tx::Ws(w, c) => {
                let body = c.pack(pt);
                let ct = c.seal(&body);
                w.send(Message::Binary(ct)).await?;
            }
        }
        Ok(())
    }
    pub async fn close(&mut self) {
        match self {
            Tx::Stream(w, _) => {
                let _ = w.shutdown().await;
            }
            Tx::Ws(w, _) => {
                let _ = w.close().await;
            }
        }
    }
}

impl Rx {
    pub async fn recv(&mut self) -> Res<Vec<u8>> {
        match self {
            Rx::Stream(r, c) => {
                let mut lb = [0u8; 18];
                r.read_exact(&mut lb).await?;
                let l = c.open(&lb)?;
                if l.len() != 2 {
                    return Err("bad length".into());
                }
                let n = u16::from_be_bytes([l[0], l[1]]) as usize;
                let mut b = vec![0u8; n + 16];
                r.read_exact(&mut b).await?;
                let v = c.open(&b)?;
                c.unpack(v)
            }
            Rx::Ws(r, c) => loop {
                match r.next().await {
                    Some(Ok(Message::Binary(b))) => {
                        let v = c.open(&b)?;
                        return c.unpack(v);
                    }
                    Some(Ok(Message::Close(_))) | None => return Err("closed".into()),
                    Some(Ok(_)) => continue,
                    Some(Err(e)) => return Err(e.into()),
                }
            },
        }
    }
}

/// Runs the key exchange on a raw connection. `client` = the side that dialed. `pad` = padded
/// records (both sides must agree: the engine turns it on for `hq`, `h2` and `dual`).
pub async fn handshake(raw: Raw, token: &str, client: bool, pad: bool) -> Res<(Tx, Rx)> {
    match tokio::time::timeout(Duration::from_secs(12), handshake_inner(raw, token, client, pad)).await {
        Ok(r) => r,
        Err(_) => Err("handshake timeout".into()),
    }
}

async fn handshake_inner(mut raw: Raw, token: &str, client: bool, pad: bool) -> Res<(Tx, Rx)> {
    let secret = x25519_dalek::EphemeralSecret::random_from_rng(rand::rngs::OsRng);
    let public = x25519_dalek::PublicKey::from(&secret);
    let mut mine = [0u8; 48];
    mine[..32].copy_from_slice(public.as_bytes());
    rand::rngs::OsRng.fill_bytes(&mut mine[32..]);
    let theirs = if client {
        raw.send_raw(&mine).await?;
        raw.recv_raw(48).await?
    } else {
        let t = raw.recv_raw(48).await?;
        raw.send_raw(&mine).await?;
        t
    };
    let mut tp = [0u8; 32];
    tp.copy_from_slice(&theirs[..32]);
    let shared = secret.diffie_hellman(&x25519_dalek::PublicKey::from(tp));
    let (hc, hs) = if client { (&mine[..], &theirs[..]) } else { (&theirs[..], &mine[..]) };
    let (c2s, s2c) = derive(token, shared.as_bytes(), hc, hs)?;
    let (txk, rxk) = if client { (c2s, s2c) } else { (s2c, c2s) };
    let (mut tx, mut rx) = raw.split(Cipher::new(&txk, pad), Cipher::new(&rxk, pad));
    if client {
        tx.send(b"KT1").await?;
        let ok = rx.recv().await?;
        if ok != b"OK" {
            return Err("the other side did not accept the token".into());
        }
    } else {
        let hi = rx.recv().await?;
        if hi != b"KT1" {
            return Err("bad hello".into());
        }
        tx.send(b"OK").await?;
    }
    Ok((tx, rx))
}

// ------------------------------------------------------------------ transports

fn tune(s: &TcpStream) {
    let _ = s.set_nodelay(true);
}

/// Size limits for WebSocket messages. Nothing in the tunnel is bigger than one record (about
/// 64 KB), and the default limit (64 MiB) would let a stranger who has not proven anything yet
/// make the server buffer that much per connection.
pub(super) fn ws_config() -> WebSocketConfig {
    let mut c = WebSocketConfig::default();
    c.max_message_size = Some(1 << 20);
    c.max_frame_size = Some(1 << 20);
    c
}

/// A TCP stream whose first bytes leave in many tiny segments (2 to 7 bytes each).
///
/// Used for the TLS ClientHello of the `cdn` transport: a DPI box that looks for the SNI inside
/// the first packet without putting the pieces back together sees nothing readable. A real
/// server (the CDN) reassembles the stream and does not notice.
pub struct FragIo {
    inner: TcpStream,
    left: usize,
}

impl FragIo {
    pub fn new(inner: TcpStream, first_bytes: usize) -> FragIo {
        FragIo { inner, left: first_bytes }
    }
}

impl AsyncRead for FragIo {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut tokio::io::ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for FragIo {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        if self.left > 0 && !buf.is_empty() {
            let chunk = 2 + (self.left % 6);
            let n = buf.len().min(chunk).min(self.left);
            let r = Pin::new(&mut self.inner).poll_write(cx, &buf[..n]);
            if let Poll::Ready(Ok(w)) = r {
                self.left = self.left.saturating_sub(w);
            }
            return r;
        }
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// How many bytes at the start of a `cdn` connection are sent in tiny pieces (covers the SNI).
pub(super) const FRAG_BYTES: usize = 220;

/// Connects to `remote` and returns the TCP stream (10 s limit), with TCP_NODELAY on.
pub(super) async fn tcp_connect(remote: &str) -> Res<TcpStream> {
    let tcp = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(remote)).await.map_err(|_| "connect timeout")??;
    tune(&tcp);
    Ok(tcp)
}

/// TLS client handshake over a fresh TCP stream (12 s limit); with `frag` the ClientHello leaves
/// in tiny pieces.
pub(super) async fn tls_connect(connector: &tokio_rustls::TlsConnector, sni: &str, tcp: TcpStream, frag: bool) -> Res<BoxIo> {
    let name = server_name(sni)?;
    let limit = Duration::from_secs(12);
    let io: BoxIo = if frag {
        Box::new(tokio::time::timeout(limit, connector.connect(name, FragIo::new(tcp, FRAG_BYTES))).await.map_err(|_| "tls timeout")??)
    } else {
        Box::new(tokio::time::timeout(limit, connector.connect(name, tcp)).await.map_err(|_| "tls timeout")??)
    };
    Ok(io)
}

/// Dials the other side over the chosen transport and returns the raw connection.
/// `remote` = "host:port"; `sni` (TLS name: wss / h2 / quic / hq / cdn), `host` (HTTP Host: ws / wss /
/// h2 / cdn) and `path` (ws / wss / h2 / cdn). `frag` splits the TLS hello (wss / h2 / cdn).
///
/// `cdn` is for networks that only let traffic to whitelisted addresses through (a CDN edge such
/// as ArvanCloud): TCP goes to `remote` (the edge address), the TLS handshake says `sni`, and the
/// WebSocket request says `Host: host` so the CDN routes it to your origin. `sni` and `host` may
/// differ (a whitelisted front name in the handshake, your own domain in the request). With
/// `frag` the ClientHello is split into tiny segments.
///
/// `hq` is QUIC under a masking layer (see `salamander.rs`); `h2` is WebSocket over HTTP/2 over
/// TLS 1.3 (see `h2ws.rs`); `dual` tries `hq` first and falls back to `h2` (see `dual.rs`).
pub async fn dial(transport: &str, remote: &str, sni: &str, host_header: &str, path: &str, token: &str, frag: bool) -> Res<Raw> {
    let (path, req_host, sni_name) = request_parts(remote, sni, host_header, path);
    match transport {
        // UDP-based transports do not start from a TCP connection
        "quic" => return Ok(Raw::Stream(super::quic::dial(remote, sni).await?)),
        "kcp" => return Ok(Raw::Stream(super::quic::kcp_dial(remote, token).await?)),
        "hq" => return Ok(Raw::Stream(super::hq::dial(remote, sni, token).await?)),
        "h2" => return super::h2ws::dial(remote, &sni_name, &req_host, &path, frag).await,
        "dual" => return super::dual::dial(remote, sni, &sni_name, &req_host, &path, token, frag).await,
        _ => {}
    }
    let tcp = tcp_connect(remote).await?;
    match transport {
        "ws" => {
            let io: BoxIo = Box::new(tcp);
            let url = format!("ws://{}{}", req_host, path);
            let (ws, _) = tokio_tungstenite::client_async_with_config(url.as_str(), io, Some(ws_config())).await?;
            Ok(Raw::Ws(ws))
        }
        "wss" => {
            // SNI spoof: the TLS hello carries `sni`; with `frag` it leaves in tiny pieces
            let io = tls_connect(&tls_connector(), &sni_name, tcp, frag).await?;
            let url = format!("ws://{}{}", req_host, path);
            let (ws, _) = tokio_tungstenite::client_async_with_config(url.as_str(), io, Some(ws_config())).await?;
            Ok(Raw::Ws(ws))
        }
        "cdn" => {
            // the Host header is the CDN domain; when it is not set, it follows the SNI
            let io = tls_connect(&tls_connector(), &sni_name, tcp, frag).await?;
            let url = format!("ws://{}{}", req_host, path);
            let (ws, _) = tokio::time::timeout(Duration::from_secs(12), tokio_tungstenite::client_async_with_config(url.as_str(), io, Some(ws_config())))
                .await
                .map_err(|_| "the CDN did not answer the WebSocket request")??;
            Ok(Raw::Ws(ws))
        }
        _ => Ok(Raw::Stream(Box::new(tcp))),
    }
}

/// (path, HTTP Host, TLS name) of a dial. The path always starts with "/". The TLS name is the
/// SNI that was written, else the address. The HTTP Host is the one written, else the TLS name;
/// when a list was typed into the field only its first name is used.
pub(super) fn request_parts(remote: &str, sni: &str, host_header: &str, path: &str) -> (String, String, String) {
    let host = remote.rsplit_once(':').map(|x| x.0).unwrap_or(remote).trim_matches(|c| c == '[' || c == ']').to_string();
    let sni_name = if sni.is_empty() { host.clone() } else { sni.to_string() };
    let path = if path.is_empty() { "/".to_string() } else if path.starts_with('/') { path.to_string() } else { format!("/{}", path) };
    let req_host = if host_header.trim().is_empty() { sni_name.clone() } else { host_header.trim().to_string() };
    let req_host = req_host.split(|c: char| c == ',' || c == ';' || c.is_whitespace()).find(|x| !x.is_empty()).unwrap_or(&host).to_string();
    (path, req_host, sni_name)
}

/// How many half-open connections (TLS / WebSocket / QUIC handshakes that have not yet become a
/// link) a listener keeps at the same time. More than this are dropped at once.
const MAX_PENDING: usize = 256;

/// What a running listener owns: background tasks and QUIC endpoints. Dropping it stops them all
/// and frees the ports.
#[derive(Default)]
pub struct Bag {
    pub tasks: Vec<tokio::task::JoinHandle<()>>,
    pub endpoints: Vec<quinn::Endpoint>,
}

impl Bag {
    pub fn merge(&mut self, mut other: Bag) {
        self.tasks.append(&mut other.tasks);
        self.endpoints.append(&mut other.endpoints);
    }
}

impl Drop for Bag {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
        for e in &self.endpoints {
            e.close(0u32.into(), b"bye");
        }
    }
}

/// Where the listener's tasks put the connections that are ready for the token handshake.
pub type Inbox = tokio::sync::mpsc::Sender<(Raw, String)>;

/// A listener for any transport.
///
/// Every transport accepts in its own background task. What takes time (the TLS handshake, the
/// WebSocket upgrade, the HTTP/2 setup, the QUIC handshake) is done in a task of its own per
/// connection, with a limit on how many run at once, so one slow or hostile client cannot hold the
/// door for everybody else. Finished connections arrive through a channel: `accept()` just waits
/// on it.
pub struct Listener {
    rx: tokio::sync::mpsc::Receiver<(Raw, String)>,
    _bag: Bag,
}

impl Listener {
    /// Binds the right kind of listener for the transport on `0.0.0.0:port`.
    /// (`dual` binds both UDP and TCP on that port number.)
    pub async fn bind(transport: &str, port: u16, cert: &str, key: &str, token: &str) -> Res<Listener> {
        let (tx, rx) = tokio::sync::mpsc::channel::<(Raw, String)>(64);
        let sem = Arc::new(tokio::sync::Semaphore::new(MAX_PENDING));
        let mut bag = Bag::default();
        match transport {
            "quic" => bag.merge(super::quic::serve_quic(port, tx, sem).await?),
            "kcp" => bag.merge(super::quic::serve_kcp(port, token, tx, sem).await?),
            "hq" => bag.merge(super::hq::serve(port, token, tx, sem).await?),
            "h2" => {
                let tls = Arc::new(super::h2ws::acceptor(cert, key)?);
                bag.merge(serve_tcp("h2", port, Some(tls), tx, sem).await?);
            }
            "dual" => {
                bag.merge(super::hq::serve(port, token, tx.clone(), sem.clone()).await?);
                let tls = Arc::new(super::h2ws::acceptor(cert, key)?);
                bag.merge(serve_tcp("h2", port, Some(tls), tx, sem).await?);
            }
            _ => {
                let tls = if transport == "wss" { Some(Arc::new(tls_acceptor(cert, key)?)) } else { None };
                bag.merge(serve_tcp(transport, port, tls, tx, sem).await?);
            }
        }
        Ok(Listener { rx, _bag: bag })
    }

    /// Waits for the next connection that is ready for the token handshake, and returns it with
    /// the peer's address.
    pub async fn accept(&mut self) -> Res<(Raw, String)> {
        self.rx.recv().await.ok_or_else(|| "the listener stopped".into())
    }
}

/// TCP accept loop of a transport (`tcp`, `tcpmux`, `ws`, `cdn`, `wss`, `h2`).
async fn serve_tcp(transport: &str, port: u16, tls: Option<Arc<tokio_rustls::TlsAcceptor>>, out: Inbox, sem: Arc<tokio::sync::Semaphore>) -> Res<Bag> {
    let l = TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
    let transport = transport.to_string();
    let task = tokio::spawn(async move {
        loop {
            let (tcp, peer) = match l.accept().await {
                Ok(x) => x,
                Err(_) => {
                    // for example "too many open files": do not spin
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };
            let Ok(permit) = sem.clone().try_acquire_owned() else {
                // too many half-open connections: refuse this one
                drop(tcp);
                continue;
            };
            let (out, tls, transport) = (out.clone(), tls.clone(), transport.clone());
            tokio::spawn(async move {
                let peer = peer.ip().to_string();
                if transport == "h2" {
                    if let Some(acc) = tls {
                        super::h2ws::serve_conn(tcp, acc, peer, out, permit).await;
                    }
                    return;
                }
                let _permit = permit;
                if let Ok(raw) = accept_tcp(&transport, tcp, tls.as_deref()).await {
                    let _ = out.send((raw, peer)).await;
                }
            });
        }
    });
    Ok(Bag { tasks: vec![task], endpoints: vec![] })
}

/// Turns an accepted TCP connection into a raw connection for the transport.
pub async fn accept_tcp(transport: &str, tcp: TcpStream, tls: Option<&tokio_rustls::TlsAcceptor>) -> Res<Raw> {
    tune(&tcp);
    match transport {
        // `cdn`: the CDN terminates TLS and talks plain WebSocket to this origin
        "ws" | "cdn" => {
            let io: BoxIo = Box::new(tcp);
            let ws = tokio::time::timeout(Duration::from_secs(10), tokio_tungstenite::accept_async_with_config(io, Some(ws_config()))).await.map_err(|_| "ws timeout")??;
            Ok(Raw::Ws(ws))
        }
        "wss" => {
            let acc = tls.ok_or("no TLS certificate")?;
            let t = tokio::time::timeout(Duration::from_secs(10), acc.accept(tcp)).await.map_err(|_| "tls timeout")??;
            let io: BoxIo = Box::new(t);
            let ws = tokio::time::timeout(Duration::from_secs(10), tokio_tungstenite::accept_async_with_config(io, Some(ws_config()))).await.map_err(|_| "ws timeout")??;
            Ok(Raw::Ws(ws))
        }
        _ => Ok(Raw::Stream(Box::new(tcp))),
    }
}

// ------------------------------------------------------------------ TLS (wss)

pub(super) fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

pub(super) fn server_name(s: &str) -> Res<rustls::pki_types::ServerName<'static>> {
    rustls::pki_types::ServerName::try_from(s.to_string()).map_err(|_| format!("bad server name: {}", s).into())
}

/// A TLS acceptor with a self-signed certificate (the token handshake inside proves each side),
/// or with the given certificate files.
pub fn tls_acceptor(cert_file: &str, key_file: &str) -> Res<tokio_rustls::TlsAcceptor> {
    tls_acceptor_with(cert_file, key_file, &[], false)
}

/// Same, with the ALPN protocols the server offers (in order of preference) and, with
/// `tls13_only`, nothing older than TLS 1.3.
pub(super) fn tls_acceptor_with(cert_file: &str, key_file: &str, alpn: &[&[u8]], tls13_only: bool) -> Res<tokio_rustls::TlsAcceptor> {
    let (certs, key) = if !cert_file.is_empty() && !key_file.is_empty() {
        let c = std::fs::read(cert_file)?;
        let k = std::fs::read(key_file)?;
        let certs: Vec<rustls::pki_types::CertificateDer<'static>> = pem_blocks(&c, "CERTIFICATE").into_iter().map(rustls::pki_types::CertificateDer::from).collect();
        let key = pem_blocks(&k, "PRIVATE KEY")
            .into_iter()
            .next()
            .map(|d| rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(d)))
            .ok_or("no PKCS#8 private key in the key file")?;
        if certs.is_empty() {
            return Err("no certificate in the certificate file".into());
        }
        (certs, key)
    } else {
        let ck = rcgen::generate_simple_self_signed(vec!["www.bing.com".to_string()])?;
        let cert = rustls::pki_types::CertificateDer::from(ck.cert.der().to_vec());
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der()));
        (vec![cert], key)
    };
    let builder = rustls::ServerConfig::builder_with_provider(provider());
    let builder = if tls13_only { builder.with_protocol_versions(&[&rustls::version::TLS13])? } else { builder.with_safe_default_protocol_versions()? };
    let mut cfg = builder.with_no_client_auth().with_single_cert(certs, key)?;
    cfg.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
    Ok(tokio_rustls::TlsAcceptor::from(Arc::new(cfg)))
}

/// Very small PEM reader: the base64 bodies of "-----BEGIN <label>" blocks (label may have a prefix, like "EC PRIVATE KEY").
fn pem_blocks(data: &[u8], label: &str) -> Vec<Vec<u8>> {
    let text = String::from_utf8_lossy(data);
    let mut out = vec![];
    let mut cur: Option<String> = None;
    for line in text.lines() {
        let l = line.trim();
        if l.starts_with("-----BEGIN") && l.contains(label) {
            cur = Some(String::new());
        } else if l.starts_with("-----END") {
            if let Some(b) = cur.take() {
                if let Some(d) = b64decode(&b) {
                    out.push(d);
                }
            }
        } else if let Some(b) = cur.as_mut() {
            b.push_str(l);
        }
    }
    out
}

fn b64decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut buf = 0u32;
    let mut bits = 0;
    for ch in s.bytes() {
        let v = match ch {
            b'A'..=b'Z' => ch - b'A',
            b'a'..=b'z' => ch - b'a' + 26,
            b'0'..=b'9' => ch - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => break,
            b' ' | b'\r' | b'\n' | b'\t' => continue,
            _ => return None,
        } as u32;
        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    Some(out)
}

pub(super) fn tls_connector() -> tokio_rustls::TlsConnector {
    tls_connector_with(&[], false)
}

/// Where a cipher suite stands in a Chrome ClientHello (lower = earlier).
fn browser_rank(c: rustls::CipherSuite) -> usize {
    use rustls::CipherSuite as C;
    match c {
        C::TLS13_AES_128_GCM_SHA256 => 0,
        C::TLS13_AES_256_GCM_SHA384 => 1,
        C::TLS13_CHACHA20_POLY1305_SHA256 => 2,
        C::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 => 3,
        C::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 => 4,
        C::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 => 5,
        C::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 => 6,
        C::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 => 7,
        C::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => 8,
        _ => 9,
    }
}

/// A TLS client that does not check the certificate, offering the given ALPN protocols. With
/// `browser` the cipher suites are listed in the order Chrome lists them (AES-128 first), which
/// makes the ClientHello a little less different from a browser's. (rustls cannot copy a
/// browser's whole fingerprint: extension order and some extensions differ.)
pub(super) fn tls_connector_with(alpn: &[&[u8]], browser: bool) -> tokio_rustls::TlsConnector {
    let mut prov = rustls::crypto::ring::default_provider();
    if browser {
        prov.cipher_suites.sort_by_key(|s| browser_rank(s.suite()));
    }
    let p = Arc::new(prov);
    let mut cfg = rustls::ClientConfig::builder_with_provider(p.clone())
        .with_safe_default_protocol_versions()
        .expect("tls versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify(p)))
        .with_no_client_auth();
    cfg.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
    tokio_rustls::TlsConnector::from(Arc::new(cfg))
}

/// The certificate is not checked: the token handshake inside the TLS proves the other side.
#[derive(Debug)]
pub(super) struct NoVerify(pub(super) Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}
