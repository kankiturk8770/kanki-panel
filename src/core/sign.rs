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
//!
//! 3.69: the seen nonces live in memory, so a restart would forget them while their requests are still inside
//! the window. A request made before this program started (`floor`: the start time, or the newest time taken
//! before the restart, kept on disk, whichever is later — a clock set back cannot reopen the window) is
//! refused. And the answer is signed too, bound to the request's nonce, so a captured answer cannot be played
//! back to a later request:
//!
//!   x-kanki-rts:  unix seconds of the answer
//!   x-kanki-rsig: hex(HMAC-SHA256(secret, "kanki-reply-v1\n{rts}\n{request nonce}\n{status}\n{hex(sha256(body))}"))

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

pub const TS: &str = "x-kanki-ts";
pub const NONCE: &str = "x-kanki-nonce";
pub const SIG: &str = "x-kanki-sig";
pub const RTS: &str = "x-kanki-rts";
pub const RSIG: &str = "x-kanki-rsig";
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
    /// made before this program started (its nonce may have been seen by the program before)
    BeforeStart,
}

impl Refusal {
    pub fn text(&self) -> &'static str {
        match self {
            Refusal::Unsigned => "unsigned request",
            Refusal::Malformed => "malformed signature",
            Refusal::Expired => "expired request",
            Refusal::BadSignature => "bad signature",
            Refusal::Replayed => "replayed request",
            Refusal::BeforeStart => "request made before a restart",
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

/// Adds the headers to a reqwest request, and gives the request's nonce (to check the signed answer with,
/// `verify_reply`)
pub fn sign_nonce(rb: reqwest::RequestBuilder, secret: &str, method: &str, path: &str, body: &[u8]) -> (reqwest::RequestBuilder, String) {
    let hs = headers(secret, method, path, body);
    let nonce = hs.iter().find(|(k, _)| *k == NONCE).map(|(_, v)| v.clone()).unwrap_or_default();
    (hs.into_iter().fold(rb, |rb, (k, v)| rb.header(k, v)), nonce)
}

/// The nonce of a request (lower case), when it has a well-formed one
pub fn nonce_of(h: &axum::http::HeaderMap) -> Option<String> {
    let n = h.get(NONCE)?.to_str().ok()?.trim().to_ascii_lowercase();
    (n.len() == 32 && n.bytes().all(|c| c.is_ascii_hexdigit())).then_some(n)
}

fn reply_mac(secret: &str, ts: i64, nonce: &str, status: u16, body: &[u8]) -> Option<HmacSha256> {
    let mut m = HmacSha256::new_from_slice(secret.as_bytes()).ok()?;
    let bh = hex::encode(Sha256::digest(body));
    m.update(format!("kanki-reply-v1\n{}\n{}\n{}\n{}", ts, nonce, status, bh).as_bytes());
    Some(m)
}

/// The two headers of an answer to the request with `nonce`
pub fn reply_headers(secret: &str, nonce: &str, status: u16, body: &[u8]) -> Vec<(&'static str, String)> {
    let ts = crate::util::now();
    let sig = reply_mac(secret, ts, nonce, status, body).map(|m| hex::encode(m.finalize().into_bytes())).unwrap_or_default();
    vec![(RTS, ts.to_string()), (RSIG, sig)]
}

/// Whether an answer carries a reply signature at all (a sender from before 3.69 does not)
pub fn reply_signed(h: &reqwest::header::HeaderMap) -> bool {
    h.contains_key(RSIG)
}

/// Checks an answer to the request with `nonce` (its status and body as received)
pub fn verify_reply(secret: &str, nonce: &str, h: &reqwest::header::HeaderMap, status: u16, body: &[u8], now: i64) -> Result<(), Refusal> {
    if !reply_signed(h) {
        return Err(Refusal::Unsigned);
    }
    if secret.is_empty() || nonce.is_empty() {
        return Err(Refusal::BadSignature);
    }
    let get = |k: &str| h.get(k).and_then(|v| v.to_str().ok()).map(|s| s.trim().to_string());
    let (Some(ts), Some(sig)) = (get(RTS), get(RSIG)) else { return Err(Refusal::Malformed) };
    let ts: i64 = ts.parse().map_err(|_| Refusal::Malformed)?;
    let sig = hex::decode(&sig).map_err(|_| Refusal::Malformed)?;
    if sig.len() != 32 {
        return Err(Refusal::Malformed);
    }
    if (now - ts).abs() > MAX_SKEW {
        return Err(Refusal::Expired);
    }
    let m = reply_mac(secret, ts, nonce, status, body).ok_or(Refusal::BadSignature)?;
    m.verify_slice(&sig).map_err(|_| Refusal::BadSignature)
}

// ------------------------------------------------------------------ the floor after a restart

fn floor_cell() -> &'static std::sync::OnceLock<std::sync::atomic::AtomicI64> {
    static F: std::sync::OnceLock<std::sync::atomic::AtomicI64> = std::sync::OnceLock::new();
    &F
}

fn floor_file() -> &'static Mutex<Option<(String, i64)>> {
    static P: Mutex<Option<(String, i64)>> = Mutex::new(None);
    &P
}

/// At start (before any request is taken): the floor is now, or the newest time taken by the program before
/// (kept in `path`), whichever is later; it is written back at once
pub fn init_floor(path: &str) {
    let f = floor_from(crate::util::now(), &std::fs::read_to_string(path).unwrap_or_default());
    floor_cell().get_or_init(|| std::sync::atomic::AtomicI64::new(f));
    if let Err(e) = crate::util::write_private(path, &f.to_string()) {
        eprintln!("sign: {} could not be written: {}", path, e);
    }
    *floor_file().lock().unwrap_or_else(|e| e.into_inner()) = Some((path.to_string(), f));
}

/// The floor at a start at `now`, with what the file kept (a time; anything else counts as nothing)
fn floor_from(now: i64, kept: &str) -> i64 {
    now.max(kept.trim().parse::<i64>().ok().filter(|t| *t > 0 && *t < now + 10 * 365 * 86400).unwrap_or(0))
}

/// Requests made before this time are refused (the start time when `init_floor` was not called)
pub fn floor() -> i64 {
    floor_cell().get_or_init(|| std::sync::atomic::AtomicI64::new(crate::util::now())).load(std::sync::atomic::Ordering::Relaxed)
}

/// A request of time `ts` was taken: the file keeps the newest one (written at most every 30 s)
fn note_taken(ts: i64) {
    let mut g = floor_file().lock().unwrap_or_else(|e| e.into_inner());
    if let Some((path, kept)) = g.as_mut() {
        if ts > *kept + 30 {
            *kept = ts;
            if let Err(e) = crate::util::write_private(path, &ts.to_string()) {
                eprintln!("sign: {} could not be written: {}", path, e);
            }
        }
    }
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
    // 3.69: made before this program started: its nonce may have been taken by the program before the restart
    if ts < floor() {
        return Err(Refusal::BeforeStart);
    }
    if !remember(&nonce.to_ascii_lowercase(), ts, now) {
        return Err(Refusal::Replayed);
    }
    note_taken(ts);
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

/// false when `nonce` was already used inside the window (also the Iran relay's signed requests, `relay`)
pub(crate) fn remember(nonce: &str, ts: i64, now: i64) -> bool {
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
    fn a_request_from_before_the_start_and_a_changed_answer_are_refused() {
        // the floor is the start of this program: a well-signed request made before it is refused
        let f = floor();
        let ts = f - 10;
        let nonce = hex::encode(rand::random::<[u8; 16]>());
        let sig = hex::encode(mac("k3", ts, &nonce, "POST", "/agent/sync", b"").unwrap().finalize().into_bytes());
        let h = hm(&[(TS, ts.to_string()), (NONCE, nonce), (SIG, sig)]);
        assert_eq!(verify("k3", &h, "POST", "/agent/sync", b"", f), Err(Refusal::BeforeStart));
        // the answer: bound to the request's nonce, its status and its body
        let n = hex::encode(rand::random::<[u8; 16]>());
        let mut rh = reqwest::header::HeaderMap::new();
        for (k, v) in reply_headers("k3", &n, 200, b"{\"ok\":true}") {
            rh.insert(k, v.parse().unwrap());
        }
        let now = crate::util::now();
        assert_eq!(verify_reply("k3", &n, &rh, 200, b"{\"ok\":true}", now), Ok(()));
        assert_eq!(verify_reply("k3", &n, &rh, 200, b"{\"ok\":false}", now), Err(Refusal::BadSignature));
        assert_eq!(verify_reply("k3", &n, &rh, 500, b"{\"ok\":true}", now), Err(Refusal::BadSignature));
        // the same answer played back to another request
        let other = hex::encode(rand::random::<[u8; 16]>());
        assert_eq!(verify_reply("k3", &other, &rh, 200, b"{\"ok\":true}", now), Err(Refusal::BadSignature));
        assert_eq!(verify_reply("other-key", &n, &rh, 200, b"{\"ok\":true}", now), Err(Refusal::BadSignature));
        assert_eq!(verify_reply("k3", &n, &rh, 200, b"{\"ok\":true}", now + MAX_SKEW + 5), Err(Refusal::Expired));
        assert_eq!(verify_reply("k3", &n, &reqwest::header::HeaderMap::new(), 200, b"", now), Err(Refusal::Unsigned));
    }

    #[test]
    fn the_floor_survives_a_restart_and_a_clock_set_back() {
        let now = 1_800_000_000;
        // a normal restart: the start time
        assert_eq!(floor_from(now, &(now - 100).to_string()), now);
        // the clock was set back after the restart: the newest time taken before stays the floor
        assert_eq!(floor_from(now, &(now + 3600).to_string()), now + 3600);
        // a missing, broken or absurd file is no floor
        assert_eq!(floor_from(now, ""), now);
        assert_eq!(floor_from(now, "junk"), now);
        assert_eq!(floor_from(now, &i64::MAX.to_string()), now);
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
