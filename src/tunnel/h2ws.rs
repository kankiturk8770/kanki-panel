//! `h2`: WebSocket over HTTP/2 over TLS 1.3, for port 443.
//!
//! This is the fallback for networks where UDP is cut. On the wire it is what a browser does when
//! it opens a WebSocket on an HTTP/2 site (RFC 8441, "extended CONNECT"):
//!
//! * TCP, then TLS 1.3 with the ALPN list a browser sends (`h2`, `http/1.1`), a browser-like
//!   cipher-suite order, and session resumption;
//! * then HTTP/2 with the SETTINGS Chrome sends (window sizes, no push, header table size);
//! * then `CONNECT :protocol=websocket` requests, one per tunnel link. **Several links share one
//!   TCP connection** (HTTP/2 multiplexing): the first link makes the connection, the next ones
//!   just open another stream. At most `STREAMS_PER_CONN` links per connection, then a new one.
//!
//! Inside each HTTP/2 stream runs a normal WebSocket (binary messages), and inside the WebSocket
//! the usual token handshake and encrypted, padded records. A client or a scanner that asks the
//! server for something else gets a plain web page (a decoy) and a 404, like a real site.
//!
//! If the other side only speaks HTTP/1.1 (or an HTTP/2 server without extended CONNECT, like many
//! CDNs), the dial falls back by itself to the classic WebSocket upgrade on a new connection, so a
//! `h2` client talks to a `wss` server and the other way round.
//!
//! What this cannot do: rustls cannot copy a browser's ClientHello exactly (extension order, the
//! post-quantum key share, GREASE). A filter that fingerprints TLS hellos precisely can still tell
//! it from Chrome; ALPN, cipher order, HTTP/2 SETTINGS and the request headers do match.

use super::link::{self, BoxIo, Inbox, Raw, Res};
use bytes::Bytes;
use h2::{RecvStream, SendStream};
use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::OwnedSemaphorePermit;
use tokio_tungstenite::tungstenite::protocol::Role;
use tokio_tungstenite::WebSocketStream;

const ALPN_H2: &[u8] = b"h2";
const ALPN_H1: &[u8] = b"http/1.1";

/// tunnel links that share one TCP connection
const STREAMS_PER_CONN: usize = 4;
/// HTTP/2 windows, the values Chrome announces
const STREAM_WINDOW: u32 = 6_291_456;
const CONN_WINDOW: u32 = 15_728_640;
const USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36";

// ------------------------------------------------------------------ one HTTP/2 stream as a byte stream

/// Counts the open links of a connection; the count goes down when the link is dropped.
pub struct StreamGuard(Arc<AtomicUsize>);

impl StreamGuard {
    fn new(counter: Arc<AtomicUsize>) -> StreamGuard {
        counter.fetch_add(1, Ordering::Relaxed);
        StreamGuard(counter)
    }
}

impl Drop for StreamGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// The two halves of one HTTP/2 stream, as one AsyncRead + AsyncWrite.
pub struct H2Io {
    recv: RecvStream,
    send: SendStream<Bytes>,
    /// the rest of the last DATA frame
    chunk: Bytes,
    _guard: Option<StreamGuard>,
}

fn io_err(e: h2::Error) -> io::Error {
    io::Error::new(io::ErrorKind::Other, e)
}

impl H2Io {
    fn new(recv: RecvStream, send: SendStream<Bytes>, guard: Option<StreamGuard>) -> H2Io {
        H2Io { recv, send, chunk: Bytes::new(), _guard: guard }
    }
}

impl AsyncRead for H2Io {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if !self.chunk.is_empty() {
                let n = self.chunk.len().min(buf.remaining());
                let part = self.chunk.split_to(n);
                buf.put_slice(&part);
                return Poll::Ready(Ok(()));
            }
            match self.recv.poll_data(cx) {
                Poll::Pending => return Poll::Pending,
                // the other side ended the stream: end of file
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Err(io_err(e))),
                Poll::Ready(Some(Ok(b))) => {
                    if !b.is_empty() {
                        // give the window back right away: we only ever hold one frame
                        let _ = self.recv.flow_control().release_capacity(b.len());
                    }
                    self.chunk = b;
                }
            }
        }
    }
}

impl AsyncWrite for H2Io {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        // room that is already assigned to this stream: use it without waiting
        let mut room = self.send.capacity();
        if room == 0 {
            self.send.reserve_capacity(buf.len());
            match self.send.poll_capacity(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Err(io_err(e))),
                Poll::Ready(Some(Ok(cap))) => room = cap,
            }
        }
        let n = room.min(buf.len());
        if n == 0 {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        match self.send.send_data(Bytes::copy_from_slice(&buf[..n]), false) {
            Ok(()) => Poll::Ready(Ok(n)),
            Err(e) => Poll::Ready(Err(io_err(e))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // the HTTP/2 connection writes what was queued by itself
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // an empty DATA frame with END_STREAM; an error here only means it was already closed
        let _ = self.send.send_data(Bytes::new(), true);
        Poll::Ready(Ok(()))
    }
}

// ------------------------------------------------------------------ server

/// The TLS acceptor of the `h2` listener: TLS 1.3 only, ALPN `h2` then `http/1.1`.
pub fn acceptor(cert: &str, key: &str) -> Res<tokio_rustls::TlsAcceptor> {
    link::tls_acceptor_with(cert, key, &[ALPN_H2, ALPN_H1], true)
}

/// One accepted TCP connection of the `h2` listener: TLS, then HTTP/2 (or, for a client that
/// does not speak it, the HTTP/1.1 WebSocket upgrade). Links go to `out`.
pub(super) async fn serve_conn(tcp: TcpStream, acc: Arc<tokio_rustls::TlsAcceptor>, peer: String, out: Inbox, permit: OwnedSemaphorePermit) {
    let tls = match tokio::time::timeout(Duration::from_secs(10), acc.accept(tcp)).await {
        Ok(Ok(t)) => t,
        _ => return,
    };
    let is_h2 = tls.get_ref().1.alpn_protocol() == Some(ALPN_H2);
    let io: BoxIo = Box::new(tls);
    if !is_h2 {
        let _permit = permit;
        let r = tokio::time::timeout(Duration::from_secs(10), tokio_tungstenite::accept_async_with_config(io, Some(link::ws_config()))).await;
        if let Ok(Ok(ws)) = r {
            let _ = out.send((Raw::Ws(ws), peer)).await;
        }
        return;
    }
    serve_h2(io, peer, out, Some(permit)).await;
}

/// The HTTP/2 side of a connection (already past TLS). Runs until the connection ends.
pub(super) async fn serve_h2(io: BoxIo, peer: String, out: Inbox, permit: Option<OwnedSemaphorePermit>) {
    let mut b = h2::server::Builder::new();
    b.enable_connect_protocol();
    b.initial_window_size(STREAM_WINDOW);
    b.initial_connection_window_size(CONN_WINDOW);
    b.max_concurrent_streams(32);
    b.max_header_list_size(64 * 1024);
    let mut conn = match tokio::time::timeout(Duration::from_secs(10), b.handshake::<_, Bytes>(io)).await {
        Ok(Ok(c)) => c,
        _ => return,
    };
    let live = Arc::new(AtomicUsize::new(0));
    let mut permit = permit;
    loop {
        // while there is no link, an idle connection is closed soon (scanners); with a link, it stays
        if live.load(Ordering::Relaxed) > 0 {
            permit = None;
        }
        let wait = if live.load(Ordering::Relaxed) > 0 { Duration::from_secs(3600) } else { Duration::from_secs(20) };
        let next = match tokio::time::timeout(wait, conn.accept()).await {
            Ok(x) => x,
            Err(_) => {
                if live.load(Ordering::Relaxed) > 0 {
                    continue;
                }
                break;
            }
        };
        let (req, respond) = match next {
            Some(Ok(x)) => x,
            _ => break,
        };
        let (out2, peer2, live2) = (out.clone(), peer.clone(), live.clone());
        tokio::spawn(async move {
            handle(req, respond, out2, peer2, live2).await;
        });
    }
    drop(permit);
}

/// One request on the server: a WebSocket CONNECT becomes a link, anything else gets the decoy.
async fn handle(req: http::Request<RecvStream>, mut respond: h2::server::SendResponse<Bytes>, out: Inbox, peer: String, live: Arc<AtomicUsize>) {
    let (parts, body) = req.into_parts();
    let is_ws = parts.method == http::Method::CONNECT && parts.extensions.get::<h2::ext::Protocol>().map(|p| p.as_str() == "websocket").unwrap_or(false);
    if !is_ws {
        decoy(&parts.method, parts.uri.path(), respond);
        return;
    }
    let resp = match http::Response::builder().status(200).header("server", "nginx").body(()) {
        Ok(r) => r,
        Err(_) => return,
    };
    let send = match respond.send_response(resp, false) {
        Ok(s) => s,
        Err(_) => return,
    };
    let io: BoxIo = Box::new(H2Io::new(body, send, Some(StreamGuard::new(live))));
    let ws = WebSocketStream::from_raw_socket(io, Role::Server, Some(link::ws_config())).await;
    let _ = out.send((Raw::Ws(ws), peer)).await;
}

const DECOY_PAGE: &str = "<!DOCTYPE html>\n<html>\n<head>\n<title>Welcome to nginx!</title>\n<style>\nhtml { color-scheme: light dark; }\nbody { width: 35em; margin: 0 auto;\nfont-family: Tahoma, Verdana, Arial, sans-serif; }\n</style>\n</head>\n<body>\n<h1>Welcome to nginx!</h1>\n<p>If you see this page, the nginx web server is successfully installed and\nworking. Further configuration is required.</p>\n<p>For online documentation and support please refer to\n<a href=\"http://nginx.org/\">nginx.org</a>.<br/>\nCommercial support is available at\n<a href=\"http://nginx.com/\">nginx.com</a>.</p>\n<p><em>Thank you for using nginx.</em></p>\n</body>\n</html>\n";
const DECOY_404: &str = "<html>\r\n<head><title>404 Not Found</title></head>\r\n<body>\r\n<center><h1>404 Not Found</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n";

/// Answers an ordinary web request the way a small nginx would.
fn decoy(method: &http::Method, path: &str, mut respond: h2::server::SendResponse<Bytes>) {
    let (code, body) = if path == "/" || path == "/index.html" { (200u16, DECOY_PAGE) } else { (404u16, DECOY_404) };
    let head = *method == http::Method::HEAD;
    let resp = match http::Response::builder()
        .status(code)
        .header("server", "nginx")
        .header("content-type", "text/html")
        .header("content-length", body.len().to_string())
        .body(())
    {
        Ok(r) => r,
        Err(_) => return,
    };
    match respond.send_response(resp, head) {
        Ok(mut send) => {
            if !head {
                let _ = send.send_data(Bytes::from_static(body.as_bytes()), true);
            }
        }
        Err(_) => {}
    }
}

// ------------------------------------------------------------------ client

/// An HTTP/2 connection other links can open streams on.
#[derive(Clone)]
struct PooledConn {
    send: h2::client::SendRequest<Bytes>,
    open: Arc<AtomicUsize>,
    dead: Arc<AtomicBool>,
}

struct Pool {
    /// held while a connection is being made, so links that start together share it
    gate: Arc<tokio::sync::Mutex<()>>,
    conns: Vec<PooledConn>,
}

fn pools() -> &'static Mutex<HashMap<String, Pool>> {
    static P: OnceLock<Mutex<HashMap<String, Pool>>> = OnceLock::new();
    P.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Remotes that did not accept WebSocket over HTTP/2: skip the attempt for a while.
fn no_h2() -> &'static Mutex<HashMap<String, Instant>> {
    static P: OnceLock<Mutex<HashMap<String, Instant>>> = OnceLock::new();
    P.get_or_init(|| Mutex::new(HashMap::new()))
}

/// The browser-like TLS client (kept, so TLS sessions can be resumed like a browser does).
fn connector_h2() -> tokio_rustls::TlsConnector {
    static C: OnceLock<tokio_rustls::TlsConnector> = OnceLock::new();
    C.get_or_init(|| link::tls_connector_with(&[ALPN_H2, ALPN_H1], true)).clone()
}

/// The same, offering only HTTP/1.1 (for a server that cannot do WebSocket over HTTP/2).
fn connector_h1() -> tokio_rustls::TlsConnector {
    static C: OnceLock<tokio_rustls::TlsConnector> = OnceLock::new();
    C.get_or_init(|| link::tls_connector_with(&[ALPN_H1], true)).clone()
}

enum Connected {
    H2(PooledConn),
    /// HTTP/2 works but the server does not offer extended CONNECT
    NoConnectProtocol,
}

/// TCP + TLS (10 s each). Returns the TLS stream and whether the server chose `h2`.
async fn tls_alpn(connector: &tokio_rustls::TlsConnector, remote: &str, sni: &str, frag: bool) -> Res<(BoxIo, bool)> {
    let tcp = link::tcp_connect(remote).await?;
    let name = link::server_name(sni)?;
    let limit = Duration::from_secs(10);
    if frag {
        let t = tokio::time::timeout(limit, connector.connect(name, link::FragIo::new(tcp, link::FRAG_BYTES))).await.map_err(|_| "tls timeout")??;
        let h2 = t.get_ref().1.alpn_protocol() == Some(ALPN_H2);
        let io: BoxIo = Box::new(t);
        Ok((io, h2))
    } else {
        let t = tokio::time::timeout(limit, connector.connect(name, tcp)).await.map_err(|_| "tls timeout")??;
        let h2 = t.get_ref().1.alpn_protocol() == Some(ALPN_H2);
        let io: BoxIo = Box::new(t);
        Ok((io, h2))
    }
}

/// HTTP/2 handshake on a TLS stream; waits for the server's SETTINGS to know whether it allows
/// WebSocket over HTTP/2.
async fn h2_connect(io: BoxIo) -> Res<Connected> {
    let mut b = h2::client::Builder::new();
    b.initial_window_size(STREAM_WINDOW);
    b.initial_connection_window_size(CONN_WINDOW);
    b.max_header_list_size(262_144);
    b.header_table_size(65_536);
    b.enable_push(false);
    let (send, conn) = tokio::time::timeout(Duration::from_secs(10), b.handshake::<_, Bytes>(io)).await.map_err(|_| "h2 handshake timeout")??;
    let dead = Arc::new(AtomicBool::new(false));
    let dead2 = dead.clone();
    tokio::spawn(async move {
        let _ = conn.await;
        dead2.store(true, Ordering::Relaxed);
    });
    // the server's SETTINGS arrive once the connection task has run: wait for them (up to 5 s)
    for _ in 0..50 {
        if send.is_extended_connect_protocol_enabled() {
            return Ok(Connected::H2(PooledConn { send, open: Arc::new(AtomicUsize::new(0)), dead }));
        }
        if dead.load(Ordering::Relaxed) {
            return Err("the HTTP/2 connection closed".into());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Ok(Connected::NoConnectProtocol)
}

/// Dials `remote` and returns a WebSocket link: over a shared HTTP/2 connection when the server
/// supports it, else over HTTP/1.1.
///
/// `sni` = TLS name, `host` = the authority / Host of the request, `path` = request path.
pub async fn dial(remote: &str, sni: &str, host: &str, path: &str, frag: bool) -> Res<Raw> {
    let key = format!("{}|{}|{}", remote, sni, host);
    // a remote that has no WebSocket over HTTP/2 goes straight to HTTP/1.1 (re-checked every 10 minutes)
    let skip_h2 = {
        let mut g = no_h2().lock().unwrap();
        match g.get(&key) {
            Some(t) if t.elapsed() < Duration::from_secs(600) => true,
            Some(_) => {
                g.remove(&key);
                false
            }
            None => false,
        }
    };
    if skip_h2 {
        return dial_http1(remote, sni, host, path, frag).await;
    }

    let gate = {
        let mut g = pools().lock().unwrap();
        g.entry(key.clone()).or_insert_with(|| Pool { gate: Arc::new(tokio::sync::Mutex::new(())), conns: vec![] }).gate.clone()
    };
    let (conn, guard) = {
        let _turn = gate.lock().await;
        let reuse = {
            let mut g = pools().lock().unwrap();
            match g.get_mut(&key) {
                Some(p) => {
                    p.conns.retain(|c| !c.dead.load(Ordering::Relaxed));
                    p.conns.iter().find(|c| c.open.load(Ordering::Relaxed) < STREAMS_PER_CONN).cloned()
                }
                None => None,
            }
        };
        let conn = match reuse {
            Some(c) => c,
            None => {
                let (io, is_h2) = tls_alpn(&connector_h2(), remote, sni, frag).await?;
                if !is_h2 {
                    // the server chose HTTP/1.1: use this very TLS stream for the upgrade
                    return upgrade_http1(io, host, path).await;
                }
                match h2_connect(io).await? {
                    Connected::H2(c) => {
                        if let Some(p) = pools().lock().unwrap().get_mut(&key) {
                            p.conns.push(c.clone());
                        }
                        c
                    }
                    Connected::NoConnectProtocol => {
                        no_h2().lock().unwrap().insert(key.clone(), Instant::now());
                        return dial_http1(remote, sni, host, path, frag).await;
                    }
                }
            }
        };
        // take the stream slot while still holding the turn, so the count is right for the next link
        let guard = StreamGuard::new(conn.open.clone());
        (conn, guard)
    };
    let io = open_stream(&conn, host, path, guard).await?;
    ws_client(io).await
}

async fn ws_client(io: H2Io) -> Res<Raw> {
    let boxed: BoxIo = Box::new(io);
    let ws = WebSocketStream::from_raw_socket(boxed, Role::Client, Some(link::ws_config())).await;
    Ok(Raw::Ws(ws))
}

/// Opens one WebSocket stream (extended CONNECT) on an HTTP/2 connection.
async fn open_stream(conn: &PooledConn, host: &str, path: &str, guard: StreamGuard) -> Res<H2Io> {
    let ready = conn.send.clone().ready();
    let mut sr = match tokio::time::timeout(Duration::from_secs(10), ready).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            conn.dead.store(true, Ordering::Relaxed);
            return Err(e.into());
        }
        Err(_) => return Err("HTTP/2 stream timeout".into()),
    };
    let req = http::Request::builder()
        .method(http::Method::CONNECT)
        .uri(format!("https://{}{}", host, path))
        .header("user-agent", USER_AGENT)
        .header("accept-encoding", "gzip, deflate, br")
        .header("accept-language", "en-US,en;q=0.9")
        .header("origin", format!("https://{}", host))
        .header("sec-websocket-version", "13")
        .extension(h2::ext::Protocol::from_static("websocket"))
        .body(())
        .map_err(|e| e.to_string())?;
    let (resp, send) = match sr.send_request(req, false) {
        Ok(x) => x,
        Err(e) => {
            conn.dead.store(true, Ordering::Relaxed);
            return Err(e.into());
        }
    };
    let resp = tokio::time::timeout(Duration::from_secs(10), resp).await.map_err(|_| "HTTP/2 response timeout")??;
    if resp.status() != http::StatusCode::OK {
        return Err(format!("the server answered {} to the WebSocket request", resp.status()).into());
    }
    Ok(H2Io::new(resp.into_body(), send, Some(guard)))
}

/// WebSocket upgrade over HTTP/1.1 on a new TLS connection that offers only `http/1.1`.
async fn dial_http1(remote: &str, sni: &str, host: &str, path: &str, frag: bool) -> Res<Raw> {
    let (io, _) = tls_alpn(&connector_h1(), remote, sni, frag).await?;
    upgrade_http1(io, host, path).await
}

async fn upgrade_http1(io: BoxIo, host: &str, path: &str) -> Res<Raw> {
    let url = format!("ws://{}{}", host, path);
    let (ws, _) = tokio::time::timeout(Duration::from_secs(12), tokio_tungstenite::client_async_with_config(url.as_str(), io, Some(link::ws_config())))
        .await
        .map_err(|_| "the server did not answer the WebSocket request")??;
    Ok(Raw::Ws(ws))
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    /// WebSocket over HTTP/2, in memory (no TLS): the stream adapter, the extended CONNECT, the
    /// decoy answer and a few kinds of record sizes.
    #[tokio::test]
    async fn websocket_over_h2_in_memory() {
        let (c_io, s_io) = tokio::io::duplex(1 << 20);
        let (tx, mut rx) = tokio::sync::mpsc::channel::<(Raw, String)>(4);
        let server_io: BoxIo = Box::new(s_io);
        tokio::spawn(serve_h2(server_io, "client".to_string(), tx, None));

        let client_io: BoxIo = Box::new(c_io);
        let conn = match h2_connect(client_io).await.expect("h2 connect") {
            Connected::H2(c) => c,
            _ => panic!("the server must offer extended CONNECT"),
        };
        let guard = StreamGuard::new(conn.open.clone());
        let io = open_stream(&conn, "example.com", "/ws", guard).await.expect("open stream");
        assert_eq!(conn.open.load(Ordering::Relaxed), 1);
        let Raw::Ws(mut cws) = ws_client(io).await.unwrap() else { panic!("expected a WebSocket") };

        let (sraw, peer) = tokio::time::timeout(Duration::from_secs(5), rx.recv()).await.expect("link in time").expect("link");
        assert_eq!(peer, "client");
        let Raw::Ws(mut sws) = sraw else { panic!("expected a WebSocket") };

        // client -> server and server -> client, small and big messages
        for size in [1usize, 48, 1500, 65_000, 200_000] {
            let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
            cws.send(Message::Binary(data.clone())).await.unwrap();
            match tokio::time::timeout(Duration::from_secs(5), sws.next()).await.unwrap() {
                Some(Ok(Message::Binary(b))) => assert_eq!(b, data, "client->server size {}", size),
                other => panic!("unexpected {:?}", other),
            }
            sws.send(Message::Binary(data.clone())).await.unwrap();
            match tokio::time::timeout(Duration::from_secs(5), cws.next()).await.unwrap() {
                Some(Ok(Message::Binary(b))) => assert_eq!(b, data, "server->client size {}", size),
                other => panic!("unexpected {:?}", other),
            }
        }

        // a second stream on the same connection (multiplexing)
        let guard2 = StreamGuard::new(conn.open.clone());
        let io2 = open_stream(&conn, "example.com", "/ws", guard2).await.expect("second stream");
        assert_eq!(conn.open.load(Ordering::Relaxed), 2);
        let Raw::Ws(mut cws2) = ws_client(io2).await.unwrap() else { panic!("expected a WebSocket") };
        let (sraw2, _) = tokio::time::timeout(Duration::from_secs(5), rx.recv()).await.unwrap().unwrap();
        let Raw::Ws(mut sws2) = sraw2 else { panic!("expected a WebSocket") };
        cws2.send(Message::Binary(vec![9, 9, 9])).await.unwrap();
        match tokio::time::timeout(Duration::from_secs(5), sws2.next()).await.unwrap() {
            Some(Ok(Message::Binary(b))) => assert_eq!(b, vec![9, 9, 9]),
            other => panic!("unexpected {:?}", other),
        }
        // the first one still works
        sws.send(Message::Binary(vec![1, 2])).await.unwrap();
        match tokio::time::timeout(Duration::from_secs(5), cws.next()).await.unwrap() {
            Some(Ok(Message::Binary(b))) => assert_eq!(b, vec![1, 2]),
            other => panic!("unexpected {:?}", other),
        }
    }

    /// A plain GET gets the decoy page, not a link.
    #[tokio::test]
    async fn plain_request_gets_the_decoy() {
        let (c_io, s_io) = tokio::io::duplex(1 << 16);
        let (tx, mut rx) = tokio::sync::mpsc::channel::<(Raw, String)>(1);
        let server_io: BoxIo = Box::new(s_io);
        tokio::spawn(serve_h2(server_io, "x".to_string(), tx, None));

        let (sr, conn) = h2::client::handshake(c_io).await.expect("handshake");
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let req = http::Request::builder().method("GET").uri("https://example.com/").body(()).unwrap();
        let mut sr = sr.ready().await.expect("ready");
        let (resp, _) = sr.send_request(req, true).unwrap();
        let resp = tokio::time::timeout(Duration::from_secs(5), resp).await.unwrap().unwrap();
        assert_eq!(resp.status(), 200);
        let mut body = resp.into_body();
        let mut got = Vec::new();
        while let Some(chunk) = body.data().await {
            let chunk = chunk.unwrap();
            let _ = body.flow_control().release_capacity(chunk.len());
            got.extend_from_slice(&chunk);
        }
        assert!(String::from_utf8_lossy(&got).contains("Welcome to nginx"));

        let req = http::Request::builder().method("GET").uri("https://example.com/admin").body(()).unwrap();
        let mut sr = sr.ready().await.expect("ready");
        let (resp, _) = sr.send_request(req, true).unwrap();
        let resp = tokio::time::timeout(Duration::from_secs(5), resp).await.unwrap().unwrap();
        assert_eq!(resp.status(), 404);
        assert!(rx.try_recv().is_err(), "a plain request must never become a link");
    }
}
