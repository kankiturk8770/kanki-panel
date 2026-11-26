//! Signed requests between the panel and its servers (3.65).
//!
//! The shared secret (a node's token, a server agent's token) never travels again: each request carries
//!
//!   x-kanki-ts:    unix seconds when it was made
//!   x-kanki-nonce: 16 random bytes, hex
//!   x-kanki-sig:   hex(HMAC-SHA256(secret, "kanki-sig-v1\n{ts}\n{nonce}\n{METHOD}\n{path}\n{hex(sha256(body))}"))
//!
//! The receiver refuses a request without them, one older or newer than `MAX_SKEW` seconds, one whose
//! signature does not match (another body, path or method), and one it has already seen (the nonce is kept
//! until it would be too old anyway). The seen nonces are bounded: under a flood the oldest go first, and
//! whatever goes is already outside the window or will be refused by its time.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

pub const TS: &str = "x-kanki-ts";
pub const NONCE: &str = "x-kanki-nonce";
pub const SIG: &str = "x-kanki-sig";
/// How far the sender's clock may be from ours (servers keep their clock with NTP; minutes of drift are
/// still accepted, hours are not)
pub const MAX_SKEW: i64 = 300;
/// Nonces kept at most (a server that is polled every 5 seconds sends 120 in that window)
const MAX_SEEN: usize = 50_000;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    /// no signature headers at all
    Unsigned,
    /// a header is there but not in its form
    Malformed,
    /// the time is outside the window
    Expired,
    /// the signature does not match the request
    BadSignature,
    /// the same nonce again
    Replayed,
}

impl Refusal {
    pub fn text(&self) -> &'static str {
        match self {
            Refusal::Unsigned => "unsigned request",
            Refusal::Malformed => "malformed signature",
            Refusal::Expired => "expired request",
            Refusal::BadSignature => "bad signature",
            Refusal::Replayed => "replayed request",
        }
    }
}

fn mac(secret: &str, ts: i64, nonce: &str, method: &str, path: &str, body: &[u8]) -> Option<HmacSha256> {
    let mut m = HmacSha256::new_from_slice(secret.as_bytes()).ok()?;
    let bh = hex::encode(Sha256::digest(body));
    m.update(format!("kanki-sig-v1\n{}\n{}\n{}\n{}\n{}", ts, nonce, method.to_ascii_uppercase(), path, bh).as_bytes());
    Some(m)
}

/// The three headers of a request (name, value). `path` is the path and query as sent ("/agent/sync").
pub fn headers(secret: &str, method: &str, path: &str, body: &[u8]) -> Vec<(&'static str, String)> {
    let ts = crate::util::now();
    let nonce = hex::encode(rand::random::<[u8; 16]>());
    let sig = mac(secret, ts, &nonce, method, path, body).map(|m| hex::encode(m.finalize().into_bytes())).unwrap_or_default();
    vec![(TS, ts.to_string()), (NONCE, nonce), (SIG, sig)]
}

/// Adds the headers to a reqwest request
pub fn sign(rb: reqwest::RequestBuilder, secret: &str, method: &str, path: &str, body: &[u8]) -> reqwest::RequestBuilder {
    headers(secret, method, path, body).into_iter().fold(rb, |rb, (k, v)| rb.header(k, v))
}

/// Whether the request carries a signature at all (a sender from before 3.65 does not)
pub fn is_signed(h: &axum::http::HeaderMap) -> bool {
    h.contains_key(SIG) || h.contains_key(TS) || h.contains_key(NONCE)
}

/// Checks a request against `secret` at time `now`; a good one is remembered so it cannot come again
pub fn verify(secret: &str, h: &axum::http::HeaderMap, method: &str, path: &str, body: &[u8], now: i64) -> Result<(), Refusal> {
    if !is_signed(h) {
        return Err(Refusal::Unsigned);
    }
    if secret.is_empty() {
        return Err(Refusal::BadSignature);
    }
    let get = |k: &str| h.get(k).and_then(|v| v.to_str().ok()).map(|s| s.trim().to_string());
    let (Some(ts), Some(nonce), Some(sig)) = (get(TS), get(NONCE), get(SIG)) else { return Err(Refusal::Malformed) };
    let ts: i64 = ts.parse().map_err(|_| Refusal::Malformed)?;
    if nonce.len() != 32 || !nonce.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err(Refusal::Malformed);
    }
    let Ok(sig) = hex::decode(&sig) else { return Err(Refusal::Malformed) };
    if sig.len() != 32 {
        return Err(Refusal::Malformed);
    }
    if (now - ts).abs() > MAX_SKEW {
        return Err(Refusal::Expired);
    }
    let m = mac(secret, ts, &nonce, method, path, body).ok_or(Refusal::BadSignature)?;
    // constant time
    m.verify_slice(&sig).map_err(|_| Refusal::BadSignature)?;
    if !remember(&nonce.to_ascii_lowercase(), ts, now) {
        return Err(Refusal::Replayed);
    }
    Ok(())
}

struct Seen {
    at: HashMap<String, i64>,
    order: VecDeque<(String, i64)>,
}

fn seen() -> &'static Mutex<Seen> {
    static S: std::sync::OnceLock<Mutex<Seen>> = std::sync::OnceLock::new();
    S.get_or_init(|| Mutex::new(Seen { at: HashMap::new(), order: VecDeque::new() }))
}

/// false when `nonce` was already used inside the window
fn remember(nonce: &str, ts: i64, now: i64) -> bool {
    let mut g = seen().lock().unwrap_or_else(|e| e.into_inner());
    // what is older than the window can never be accepted again: forget it
    while let Some((n, t)) = g.order.front().cloned() {
        if now - t > MAX_SKEW || g.order.len() >= MAX_SEEN {
            g.order.pop_front();
            if g.at.get(&n) == Some(&t) {
                g.at.remove(&n);
            }
        } else {
            break;
        }
    }
    if g.at.contains_key(nonce) {
        return false;
    }
    g.at.insert(nonce.to_string(), ts);
    g.order.push_back((nonce.to_string(), ts));
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;

    fn hm(v: &[(&'static str, String)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, x) in v {
            h.insert(*k, x.parse().unwrap());
        }
        h
    }

    #[test]
    fn a_signed_request_passes_once() {
        let h = hm(&headers("secret-1", "POST", "/agent/sync", b"{\"users\":[]}"));
        let now = crate::util::now();
        assert_eq!(verify("secret-1", &h, "POST", "/agent/sync", b"{\"users\":[]}", now), Ok(()));
        // the same request again (captured and sent back): refused
        assert_eq!(verify("secret-1", &h, "POST", "/agent/sync", b"{\"users\":[]}", now), Err(Refusal::Replayed));
    }

    #[test]
    fn anything_changed_or_missing_is_refused() {
        let now = crate::util::now();
        let body = b"{\"a\":1}";
        let mk = || hm(&headers("k", "POST", "/agent/ports", body));
        assert_eq!(verify("k", &HeaderMap::new(), "POST", "/agent/ports", body, now), Err(Refusal::Unsigned));
        assert_eq!(verify("other", &mk(), "POST", "/agent/ports", body, now), Err(Refusal::BadSignature));
        assert_eq!(verify("k", &mk(), "POST", "/agent/remove", body, now), Err(Refusal::BadSignature));
        assert_eq!(verify("k", &mk(), "GET", "/agent/ports", body, now), Err(Refusal::BadSignature));
        assert_eq!(verify("k", &mk(), "POST", "/agent/ports", b"{\"a\":2}", now), Err(Refusal::BadSignature));
        assert_eq!(verify("", &mk(), "POST", "/agent/ports", body, now), Err(Refusal::BadSignature));
        // too old, too far ahead
        assert_eq!(verify("k", &mk(), "POST", "/agent/ports", body, now + MAX_SKEW + 5), Err(Refusal::Expired));
        assert_eq!(verify("k", &mk(), "POST", "/agent/ports", body, now - MAX_SKEW - 5), Err(Refusal::Expired));
        // broken headers
        let mut h = mk();
        h.insert(SIG, "zz".parse().unwrap());
        assert_eq!(verify("k", &h, "POST", "/agent/ports", body, now), Err(Refusal::Malformed));
        let mut h = mk();
        h.remove(NONCE);
        assert_eq!(verify("k", &h, "POST", "/agent/ports", body, now), Err(Refusal::Malformed));
        let mut h = mk();
        h.insert(TS, "soon".parse().unwrap());
        assert_eq!(verify("k", &h, "POST", "/agent/ports", body, now), Err(Refusal::Malformed));
    }

    #[test]
    fn concurrent_replays_get_through_only_once() {
        let h = std::sync::Arc::new(hm(&headers("k2", "POST", "/agent/sync", b"x")));
        let now = crate::util::now();
        let ok = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let ts: Vec<_> = (0..16)
            .map(|_| {
                let (h, ok) = (h.clone(), ok.clone());
                std::thread::spawn(move || {
                    if verify("k2", &h, "POST", "/agent/sync", b"x", now).is_ok() {
                        ok.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    }
                })
            })
            .collect();
        for t in ts {
            t.join().unwrap();
        }
        assert_eq!(ok.load(std::sync::atomic::Ordering::SeqCst), 1);
    }
}
