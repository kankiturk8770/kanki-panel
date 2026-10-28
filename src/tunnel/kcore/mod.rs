//! MIX+: the tunnel transport `game` (Game-FEC: KCP at its fastest with Reed-Solomon FEC under the
//! UDP mask) served to users as a VPN protocol, like KANKI MIX, so the Kanki app can connect to it.
//!
//! The transport itself is not changed: the mask (`salamander.rs`), the FEC (`fec.rs`), the record
//! layer (`link.rs`) and the mux (`mux.rs`) are used as they are. What is added on top:
//!
//! * **users**: after the link handshake (keyed by the `door` secret, which also keys the mask) the
//!   app proves which user it is with an HMAC of that user's key. The key itself never travels.
//!   Each user has their own traffic counters and device limit.
//! * **a full proxy**: the app asks for any `ip:port` (TCP streams and UDP flows over the mux).
//!   Only public addresses are dialed, so a user can never reach the server's own services.
//! * **an optional datagram fast path for games** (off by default): game UDP as datagrams of its
//!   own beside the stream, small packets sent two or three times, copies dropped on arrival. Off,
//!   game UDP rides the stream exactly like the tunnels.
//!
//! `server.rs` is what each VPN server runs (inside the panel agent or as `kanki-core server`),
//! `client.rs` + `socks.rs` is the app side (`kanki-core client`, built for Android).

// the app side is built into `kanki-core` (kcore/); the panel only runs it in its tests
#[allow(dead_code)]
pub mod client;
pub mod dgram;
pub mod gamec;
pub mod server;
#[allow(dead_code)]
pub mod socks;

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::net::{IpAddr, SocketAddr};

/// the cores, in the order the panel and the app show them
pub const KINDS: &[&str] = &["game"];

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
        "game" => "MIX+",
        _ => "?",
    }
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

#[allow(dead_code)]
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
#[allow(dead_code)]
pub fn target_of(a: SocketAddr) -> String {
    a.to_string()
}

#[cfg(test)]
mod tests;
