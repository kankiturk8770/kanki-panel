//! UDP obfuscation for KCP, so nothing on the wire looks like KCP.
//!
//! KCP's own 24-byte header is sent in the clear, which lets deep packet inspection recognise
//! "this is KCP" even though the payload is encrypted. To hide it, every UDP datagram is wrapped:
//!
//!   [ 8-byte random nonce ][ ChaCha20( 1-byte pad-len | pad | kcp-datagram ) ]
//!
//! The key comes from the tunnel token, so only the two ends can unwrap it; everyone else sees a
//! short random-looking UDP datagram with a varying length. We do this with a relay: KCP talks to
//! a private loopback socket, and this relay carries the bytes to the real peer, wrapping on the
//! way out and unwrapping on the way in. KCP and quinn stay unchanged.

use super::link::Res;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

const NONCE: usize = 8;
const MAX_PAD: usize = 32;

fn key_of(token: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"kanki-obfs|");
    h.update(token.as_bytes());
    h.finalize().into()
}

/// Wraps one KCP datagram into an obfuscated datagram.
fn wrap(key: &[u8; 32], data: &[u8]) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut nonce = [0u8; NONCE];
    rng.fill_bytes(&mut nonce);
    let pad = (rng.next_u32() as usize) % (MAX_PAD + 1);
    let mut body = Vec::with_capacity(1 + pad + data.len());
    body.push(pad as u8);
    body.resize(1 + pad, 0);
    rng.fill_bytes(&mut body[1..1 + pad]);
    body.extend_from_slice(data);
    // ChaCha20 nonce is 12 bytes: our 8 random bytes + 4 zero bytes
    let mut n12 = [0u8; 12];
    n12[..NONCE].copy_from_slice(&nonce);
    let mut c = ChaCha20::new(key.into(), (&n12).into());
    c.apply_keystream(&mut body);
    let mut out = Vec::with_capacity(NONCE + body.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&body);
    out
}

/// Unwraps an obfuscated datagram back to the KCP datagram. Returns None if it is too short or the
/// padding length is impossible (a stray/scan packet).
fn unwrap(key: &[u8; 32], pkt: &[u8]) -> Option<Vec<u8>> {
    if pkt.len() < NONCE + 1 {
        return None;
    }
    let mut n12 = [0u8; 12];
    n12[..NONCE].copy_from_slice(&pkt[..NONCE]);
    let mut body = pkt[NONCE..].to_vec();
    let mut c = ChaCha20::new(key.into(), (&n12).into());
    c.apply_keystream(&mut body);
    let pad = body[0] as usize;
    if 1 + pad > body.len() {
        return None;
    }
    Some(body[1 + pad..].to_vec())
}

/// Client side: binds a private loopback socket for KCP to dial, and relays to `remote` with
/// obfuscation. Returns the loopback address KCP should connect to. The relay lives until the
/// returned guard is dropped (we leak it for the life of the link by keeping it in the guard).
pub struct ClientObfs {
    pub local: SocketAddr,
    _task: tokio::task::JoinHandle<()>,
}

pub async fn client(remote: SocketAddr, token: &str) -> Res<ClientObfs> {
    let key = key_of(token);
    // socket that talks (obfuscated) to the real peer
    let bind: SocketAddr = if remote.is_ipv6() { "[::]:0".parse()? } else { "0.0.0.0:0".parse()? };
    let outer = Arc::new(UdpSocket::bind(bind).await?);
    outer.connect(remote).await?;
    // socket that KCP will talk to, in the clear, on loopback
    let inner = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
    let local = inner.local_addr()?;
    let task = tokio::spawn(async move {
        // learn KCP's source address on its first packet to us
        let mut kcp_addr: Option<SocketAddr> = None;
        let mut a = [0u8; 65535];
        let mut b = [0u8; 65535];
        loop {
            tokio::select! {
                r = inner.recv_from(&mut a) => {
                    let Ok((n, from)) = r else { break };
                    kcp_addr = Some(from);
                    let _ = outer.send(&wrap(&key, &a[..n])).await;
                }
                r = outer.recv(&mut b) => {
                    let Ok(n) = r else { break };
                    if let (Some(dst), Some(data)) = (kcp_addr, unwrap(&key, &b[..n])) {
                        let _ = inner.send_to(&data, dst).await;
                    }
                }
            }
        }
    });
    Ok(ClientObfs { local, _task: task })
}

/// Server side: owns the public UDP socket, unwraps incoming datagrams and forwards them (in the
/// clear) to the local KCP listener, and wraps KCP's replies back out to the right peer. One relay
/// serves every client on the port, keyed by their address.
pub struct ServerObfs {
    pub kcp_addr: SocketAddr,
    _task: tokio::task::JoinHandle<()>,
}

pub async fn server(port: u16, token: &str, kcp_local: SocketAddr) -> Res<ServerObfs> {
    let key = key_of(token);
    let public = Arc::new(UdpSocket::bind(format!("0.0.0.0:{}", port)).await?);
    // For each real client we open a private loopback socket toward the KCP listener, so KCP sees
    // distinct peers. back[kcp_side_local_addr] = real client address.
    let peers: Arc<Mutex<HashMap<SocketAddr, Arc<UdpSocket>>>> = Arc::new(Mutex::new(HashMap::new()));
    let task = tokio::spawn(async move {
        let mut buf = [0u8; 65535];
        loop {
            let Ok((n, from)) = public.recv_from(&mut buf).await else { break };
            let Some(data) = unwrap(&key, &buf[..n]) else { continue };
            // find or create the loopback socket that represents this client to the KCP listener
            let sock = {
                let mut g = peers.lock().await;
                if let Some(s) = g.get(&from) {
                    s.clone()
                } else {
                    let Ok(s) = UdpSocket::bind("127.0.0.1:0").await else { continue };
                    let s = Arc::new(s);
                    if s.connect(kcp_local).await.is_err() {
                        continue;
                    }
                    g.insert(from, s.clone());
                    // pump KCP -> client for this peer
                    let (public2, key2, from2, s2) = (public.clone(), key, from, s.clone());
                    tokio::spawn(async move {
                        let mut b = [0u8; 65535];
                        loop {
                            match s2.recv(&mut b).await {
                                Ok(n) => {
                                    let _ = public2.send_to(&wrap(&key2, &b[..n]), from2).await;
                                }
                                Err(_) => break,
                            }
                        }
                    });
                    s
                }
            };
            let _ = sock.send(&data).await;
        }
    });
    Ok(ServerObfs { kcp_addr: kcp_local, _task: task })
}

#[cfg(test)]
pub fn test_wrap(key: &[u8; 32], data: &[u8]) -> Vec<u8> {
    wrap(key, data)
}
#[cfg(test)]
pub fn test_unwrap(key: &[u8; 32], pkt: &[u8]) -> Option<Vec<u8>> {
    unwrap(key, pkt)
}
