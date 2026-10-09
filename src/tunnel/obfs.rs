//! UDP obfuscation for KCP, so nothing on the wire looks like KCP.
//!
//! KCP's own 24-byte header is sent in the clear, which lets deep packet inspection recognise
//! "this is KCP" even though the payload is encrypted. To hide it, every UDP datagram is wrapped
//! with the same mask the `hq` transport uses (see `salamander.rs`):
//!
//!   [ 8-byte random salt ][ mask( 4-byte check | pad length | random pad | kcp datagram ) ]
//!
//! The key comes from the tunnel token, so only the two ends can unwrap it; everyone else sees a
//! short random-looking UDP datagram with a varying length, and a datagram that does not unwrap
//! is dropped without any answer. We do this with a relay: KCP talks to a private loopback socket,
//! and this relay carries the bytes to the real peer, wrapping on the way out and unwrapping on
//! the way in. KCP and quinn stay unchanged.
//!
//! Both relays stop their tasks when they are dropped (a link that ends must not leave sockets and
//! tasks behind), and the server relay keeps a bounded table of peers that is cleaned up when a
//! peer goes quiet.

use super::link::Res;
use super::salamander::Mask;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;

/// most clients one server relay serves at the same time
const MAX_PEERS: usize = 1024;
/// a client that sent nothing for this long is forgotten
const PEER_IDLE: Duration = Duration::from_secs(90);

/// Client side: binds a private loopback socket for KCP to dial, and relays to `remote` with
/// obfuscation. `local` is the loopback address KCP should connect to. The relay lives until this
/// guard is dropped.
pub struct ClientObfs {
    pub local: SocketAddr,
    tasks: Vec<JoinHandle<()>>,
}

impl Drop for ClientObfs {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

pub async fn client(remote: SocketAddr, token: &str) -> Res<ClientObfs> {
    let mask = Arc::new(Mask::new(token));
    // socket that talks (obfuscated) to the real peer
    let bind: SocketAddr = if remote.is_ipv6() { "[::]:0".parse()? } else { "0.0.0.0:0".parse()? };
    let outer = Arc::new(UdpSocket::bind(bind).await?);
    outer.connect(remote).await?;
    // socket that KCP will talk to, in the clear, on loopback
    let inner = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
    let local = inner.local_addr()?;
    // KCP's loopback source address, learned from its first packet; shared with the inbound task
    let kcp_addr: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
    // KCP -> mask -> peer
    let (inner1, outer1, ka1, mask1) = (inner.clone(), outer.clone(), kcp_addr.clone(), mask.clone());
    let out_task = tokio::spawn(async move {
        let mut a = vec![0u8; 65535];
        let mut w: Vec<u8> = Vec::with_capacity(2048);
        loop {
            let Ok((n, from)) = inner1.recv_from(&mut a).await else { break };
            *ka1.lock().unwrap() = Some(from);
            w.clear();
            mask1.seal(&a[..n], &mut w);
            let _ = outer1.send(&w).await;
        }
    });
    // peer -> unmask -> KCP
    let in_task = tokio::spawn(async move {
        let mut b = vec![0u8; 65535];
        loop {
            let n = match outer.recv(&mut b).await {
                Ok(n) => n,
                // an ICMP "port unreachable" from a server that is not up yet: keep waiting
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => continue,
                Err(_) => break,
            };
            let dst = *kcp_addr.lock().unwrap();
            if let Some(dst) = dst {
                if let Some((s, e)) = mask.open(&mut b[..n]) {
                    let _ = inner.send_to(&b[s..e], dst).await;
                }
            }
        }
    });
    Ok(ClientObfs { local, tasks: vec![out_task, in_task] })
}

/// One real client as the KCP listener sees it: its own loopback socket, and the task that carries
/// KCP's answers back to the client.
struct Peer {
    sock: Arc<UdpSocket>,
    last: Instant,
    pump: JoinHandle<()>,
}

/// Server side: owns the public UDP socket, unwraps incoming datagrams and forwards them (in the
/// clear) to the local KCP listener, and wraps KCP's replies back out to the right peer. One relay
/// serves every client on the port, keyed by their address.
pub struct ServerObfs {
    pub kcp_addr: SocketAddr,
    tasks: Vec<JoinHandle<()>>,
    peers: Arc<Mutex<HashMap<SocketAddr, Peer>>>,
}

impl Drop for ServerObfs {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
        for (_, p) in self.peers.lock().unwrap().drain() {
            p.pump.abort();
        }
    }
}

/// KCP -> mask -> client, for one client.
async fn pump(sock: Arc<UdpSocket>, public: Arc<UdpSocket>, mask: Arc<Mask>, to: SocketAddr) {
    let mut b = vec![0u8; 65535];
    let mut w: Vec<u8> = Vec::with_capacity(2048);
    loop {
        let n = match sock.recv(&mut b).await {
            Ok(n) => n,
            Err(_) => break,
        };
        w.clear();
        mask.seal(&b[..n], &mut w);
        let _ = public.send_to(&w, to).await;
    }
}

pub async fn server(port: u16, token: &str, kcp_local: SocketAddr) -> Res<ServerObfs> {
    let mask = Arc::new(Mask::new(token));
    let public = Arc::new(UdpSocket::bind(format!("0.0.0.0:{}", port)).await?);
    // For each real client we open a private loopback socket toward the KCP listener, so KCP sees
    // distinct peers.
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
            let known = {
                let mut g = peers1.lock().unwrap();
                let r = g.get_mut(&from).map(|p| {
                    p.last = Instant::now();
                    p.sock.clone()
                });
                r
            };
            let sock = match known {
                Some(sock) => sock,
                None => {
                    let full = peers1.lock().unwrap().len() >= MAX_PEERS;
                    if full {
                        continue;
                    }
                    let Ok(sock) = UdpSocket::bind("127.0.0.1:0").await else { continue };
                    if sock.connect(kcp_local).await.is_err() {
                        continue;
                    }
                    let sock = Arc::new(sock);
                    let pump = tokio::spawn(pump(sock.clone(), public1.clone(), mask1.clone(), from));
                    peers1.lock().unwrap().insert(from, Peer { sock: sock.clone(), last: Instant::now(), pump });
                    sock
                }
            };
            let _ = sock.send(&buf[s..e]).await;
        }
    });

    // forget clients that went quiet (and clients whose pump died)
    let peers2 = peers.clone();
    let reaper = tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(15)).await;
            let mut g = peers2.lock().unwrap();
            g.retain(|_, p| {
                let keep = !p.pump.is_finished() && p.last.elapsed() < PEER_IDLE;
                if !keep {
                    p.pump.abort();
                }
                keep
            });
        }
    });

    Ok(ServerObfs { kcp_addr: kcp_local, tasks: vec![main_task, reaper], peers })
}
