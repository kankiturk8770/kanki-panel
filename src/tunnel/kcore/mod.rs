//! Kanki Cores: three of the tunnel transports — `game` (Game-FEC), `hq` (HQ-QUIC) and `faketcp`
//! (FakeTCP) — served to users as VPN cores, like KANKI MIX, so the Kanki app can connect to them.
//!
//! The transports themselves are not changed: the masked UDP (`salamander.rs`), the Reed-Solomon
//! FEC (`fec.rs`), the masked QUIC socket (`hq.rs`), the fake TCP channel (`faketcp.rs`), the
//! record layer (`link.rs`) and the mux (`mux.rs`) are used as they are. What is added on top:
//!
//! * **users**: after the link handshake (keyed by the core's `door` secret, which also keys the
//!   mask) the app proves which user it is with an HMAC of that user's key. The key itself never
//!   travels. Each user has their own traffic counters and device limit.
//! * **a full proxy**: the app asks for any `ip:port` (TCP streams and UDP flows over the mux).
//!   Only public addresses are dialed, so a user can never reach the server's own services.
//! * **a datagram fast path for games** (`game` and `hq`): game UDP does not ride the reliable
//!   stream (where one lost packet would hold up every packet behind it). Each game packet is a
//!   datagram of its own, sealed with a per-session key, and small packets (PUBG's are 40–300
//!   bytes) are sent two or three times; the receiver keeps the first copy and drops the rest.
//!   Big UDP packets (video, QUIC downloads) are sent once, so the extra copies cost little.
//!
//! ```text
//!  app ── SOCKS5 (hev-socks5-tunnel) ── kanki-core client ══ game / hq / faketcp ══ server ── internet
//!                                         TCP  -> mux stream (KCP + FEC / QUIC / fake TCP)
//!                                         UDP  -> datagram fast path (game, hq) or mux (faketcp)
//! ```
//!
//! `server.rs` is what each VPN server runs (inside the panel agent or as `kanki-core server`),
//! `client.rs` + `socks.rs` is the app side (`kanki-core client`, built for Android).

pub mod client;
pub mod dgram;
pub mod gamec;
pub mod hqc;
pub mod server;
pub mod socks;

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::net::{IpAddr, SocketAddr};

/// the cores, in the order the panel and the app show them
pub const KINDS: &[&str] = &["game", "hq", "faketcp"];

/// first record of the app after the link handshake: `KC1` + JSON `Auth`
pub const HELLO: &[u8] = b"KC1";
/// answer of the server: `OK` + JSON `Welcome`, or `NO` + a reason
pub const OK: &[u8] = b"OK";
pub const NO: &[u8] = b"NO";
/// an auth older (or newer) than this is refused, so a recorded one cannot be replayed later
pub const AUTH_SKEW_SECS: u64 = 120;

/// Display name of a core
pub fn title(kind: &str) -> &'static str {
    match kind {
        "game" => "Game-FEC",
        "hq" => "HQ-QUIC",
        "faketcp" => "FakeTCP",
        _ => "?",
    }
}

/// Records are padded on `hq`, like the tunnel does (the others carry game traffic, where every
/// byte counts, and their datagrams are padded by the mask anyway).
pub fn padded(kind: &str) -> bool {
    kind == "hq"
}

/// What the app sends to prove who it is.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(default)]
pub struct Auth {
    /// user name
    pub u: String,
    /// unix seconds
    pub t: u64,
    /// 16 random bytes, hex
    pub n: String,
    /// HMAC-SHA256(user key, "kc1|u|t|n"), hex
    pub m: String,
    /// the app wants the datagram fast path
    pub d: bool,
}

/// What the server answers.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(default)]
pub struct Welcome {
    /// session id of the datagram fast path (0 = no fast path on this core)
    pub sid: u64,
    /// datagram key of this session, hex (32 bytes)
    pub dk: String,
    /// largest datagram body the fast path carries
    pub dm: u32,
}

pub fn auth_mac(key: &str, user: &str, t: u64, nonce: &str) -> String {
    let mut m = Hmac::<Sha256>::new_from_slice(key.as_bytes()).expect("hmac key");
    m.update(format!("kc1|{}|{}|{}", user, t, nonce).as_bytes());
    hex::encode(m.finalize().into_bytes())
}

pub fn now_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

pub fn make_auth(user: &str, key: &str, datagrams: bool) -> Auth {
    let mut n = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut n);
    let n = hex::encode(n);
    let t = now_secs();
    Auth { u: user.to_string(), t, m: auth_mac(key, user, t, &n), n, d: datagrams }
}

/// An `ip:port` a user may reach: a public unicast address and a real port. Names are refused
/// (a name could point at the server itself); the app resolves names before asking.
pub fn public_target(target: &str) -> bool {
    match target.parse::<SocketAddr>() {
        #[cfg(test)]
        Ok(a) if a.ip().is_loopback() && tests::LOOPBACK_OK.load(std::sync::atomic::Ordering::Relaxed) => true,
        Ok(a) => a.port() != 0 && public_ip(a.ip()),
        Err(_) => false,
    }
}

pub fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            let o = v.octets();
            !(v.is_private()
                || v.is_loopback()
                || v.is_link_local()
                || v.is_broadcast()
                || v.is_unspecified()
                || v.is_multicast()
                || o[0] == 0
                // carrier-grade NAT 100.64.0.0/10
                || (o[0] == 100 && (o[1] & 0xC0) == 64)
                // 192.0.0.0/24 and the benchmark net 198.18.0.0/15 (the app's own fake range)
                || (o[0] == 192 && o[1] == 0 && o[2] == 0)
                || (o[0] == 198 && (o[1] & 0xFE) == 18)
                || o[0] >= 240)
        }
        IpAddr::V6(v) => {
            if let Some(v4) = v.to_ipv4_mapped() {
                return public_ip(IpAddr::V4(v4));
            }
            let s = v.segments();
            !(v.is_loopback()
                || v.is_unspecified()
                || v.is_multicast()
                // unique local fc00::/7, link local fe80::/10
                || (s[0] & 0xFE00) == 0xFC00
                || (s[0] & 0xFFC0) == 0xFE80
                // the old IPv4-compatible ::/96
                || (s[0..6] == [0, 0, 0, 0, 0, 0]))
        }
    }
}

/// "host:port" of a socket address the way the mux expects it ("[v6]:port" for IPv6)
pub fn target_of(a: SocketAddr) -> String {
    a.to_string()
}

#[cfg(test)]
mod tests;
