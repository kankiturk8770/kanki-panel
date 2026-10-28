//! The `hq` core: the HQ-QUIC transport (QUIC under the mask, `hq.rs`) with the QUIC connection in
//! hand, so game UDP can go as QUIC datagrams beside the stream.
//!
//! The masked socket (`MaskedSocket`) and the TLS setup (`quic.rs`) are the tunnel's own; the QUIC
//! settings are those of `hq.rs` with datagrams switched on.

use super::super::hq::MaskedSocket;
use super::super::link::{BoxIo, Res};
use super::super::quic::{client_config, server_config, QuicIo, QUIC_PRIME};
use super::super::salamander::Mask;
use quinn::{Endpoint, EndpointConfig, TokioRuntime, TransportConfig};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::sync::{mpsc, Semaphore};

/// largest datagram body on `hq`: QUIC packets stay at 1200 bytes (the mask needs the room)
pub const MAX_BODY: usize = 1100 - super::dgram::HEAD - super::dgram::SEAL;

fn transport() -> Arc<TransportConfig> {
    let mut t = TransportConfig::default();
    t.keep_alive_interval(Some(Duration::from_secs(5)));
    t.max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()));
    t.stream_receive_window((8u32 * 1024 * 1024).into());
    t.receive_window((32u32 * 1024 * 1024).into());
    t.send_window(32 * 1024 * 1024);
    t.max_concurrent_bidi_streams(4u32.into());
    t.max_concurrent_uni_streams(0u32.into());
    t.initial_mtu(1200);
    t.min_mtu(1200);
    t.mtu_discovery_config(None);
    t.enable_segmentation_offload(false);
    t.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
    // the game datagrams: a short queue, so an old game packet is dropped instead of sent late
    t.datagram_receive_buffer_size(Some(1 << 20));
    t.datagram_send_buffer_size(64 * 1024);
    Arc::new(t)
}

/// A connection whose first stream is ready for the link handshake.
pub type Accepted = (BoxIo, quinn::Connection);

/// Serves `hq` on UDP `0.0.0.0:port`. Finished connections arrive on `out`.
pub async fn serve(port: u16, door: &str, out: mpsc::Sender<Accepted>) -> Res<Endpoint> {
    let addr: SocketAddr = format!("0.0.0.0:{}", port).parse()?;
    let sock = MaskedSocket::bind(addr, Mask::new(door))?;
    let endpoint = Endpoint::new_with_abstract_socket(EndpointConfig::default(), Some(server_config(transport())?), sock, Arc::new(TokioRuntime))?;
    let ep = endpoint.clone();
    let pending = Arc::new(Semaphore::new(256));
    tokio::spawn(async move {
        while let Some(incoming) = ep.accept().await {
            let Ok(permit) = pending.clone().try_acquire_owned() else {
                incoming.refuse();
                continue;
            };
            let out = out.clone();
            tokio::spawn(async move {
                let _permit = permit;
                let Ok(Ok(conn)) = tokio::time::timeout(Duration::from_secs(12), incoming).await else { return };
                let Ok(Ok((send, mut recv))) = tokio::time::timeout(Duration::from_secs(12), conn.accept_bi()).await else { return };
                let mut one = [0u8; QUIC_PRIME.len()];
                if !matches!(tokio::time::timeout(Duration::from_secs(12), recv.read_exact(&mut one)).await, Ok(Ok(_))) {
                    return;
                }
                let io: BoxIo = Box::new(QuicIo::new(send, recv, conn.clone()));
                let _ = out.send((io, conn)).await;
            });
        }
    });
    Ok(endpoint)
}

/// Dials an `hq` core and opens its stream.
pub async fn dial(remote: SocketAddr, sni: &str, door: &str) -> Res<(BoxIo, quinn::Connection, Endpoint)> {
    let bind: SocketAddr = if remote.is_ipv6() { "[::]:0".parse()? } else { "0.0.0.0:0".parse()? };
    let sock = MaskedSocket::bind(bind, Mask::new(door))?;
    let mut endpoint = Endpoint::new_with_abstract_socket(EndpointConfig::default(), None, sock, Arc::new(TokioRuntime))?;
    endpoint.set_default_client_config(client_config(transport())?);
    let name = if sni.is_empty() { "www.cloudflare.com" } else { sni };
    let conn = tokio::time::timeout(Duration::from_secs(12), endpoint.connect(remote, name)?).await.map_err(|_| "hq connect timeout")??;
    let (mut send, recv) = conn.open_bi().await?;
    send.write_all(QUIC_PRIME).await?;
    send.flush().await?;
    Ok((Box::new(QuicIo::new(send, recv, conn.clone())), conn, endpoint))
}
