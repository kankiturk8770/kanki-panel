//! `dual`: the two-layer transport. QUIC under the mask (`hq`) first, WebSocket over HTTP/2 over
//! TLS 1.3 (`h2`) when UDP does not get through.
//!
//! The server side needs nothing special: it listens on UDP *and* TCP of the same port number
//! (`Listener::bind("dual", ..)`), so a client can reach it either way on one number, usually 443.
//!
//! The client decides with a short race ("happy eyeballs"):
//!
//! 1. `hq` starts alone and gets `HQ_HEAD_START` to finish its handshake. On a clean path that is
//!    all it takes, and the TCP path is never touched (no extra connection, no extra latency).
//! 2. If `hq` has neither succeeded nor failed by then, `h2` starts too; the first one that
//!    delivers a connection wins and the other one is cancelled. If `hq` fails at once (ICMP
//!    refusal, local error) `h2` simply goes next.
//! 3. When `h2` won, the remote is remembered as "UDP is bad" for `UDP_BAD_FOR`; during that time
//!    new links go straight to `h2` without wasting the head start. After it ends, `hq` gets a
//!    chance again, so a network that opens UDP later is used. If it still does not work the
//!    price is `HQ_HEAD_START` once per period, not once per link.
//!
//! In a network that cuts UDP the tunnel therefore comes up through TCP within about a second and
//! a half, and stays on TCP without further delay.

use super::h2ws;
use super::hq;
use super::link::{Raw, Res};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
use tokio::task::JoinHandle;

/// how long `hq` runs alone before `h2` is started next to it
const HQ_HEAD_START: Duration = Duration::from_millis(1500);
/// how long a remote is sent straight to `h2` after `h2` won against `hq`
const UDP_BAD_FOR: Duration = Duration::from_secs(90);

/// remote -> when UDP was last found not working
fn bad() -> &'static Mutex<HashMap<String, Instant>> {
    static BAD: OnceLock<Mutex<HashMap<String, Instant>>> = OnceLock::new();
    BAD.get_or_init(|| Mutex::new(HashMap::new()))
}

pub(super) fn udp_is_bad(remote: &str) -> bool {
    let mut g = bad().lock().unwrap();
    match g.get(remote) {
        Some(t) if t.elapsed() < UDP_BAD_FOR => true,
        Some(_) => {
            g.remove(remote);
            false
        }
        None => false,
    }
}

fn mark_bad(remote: &str) {
    let mut g = bad().lock().unwrap();
    // never let the table grow without bound (a remote is a configured address, so this is tiny)
    if g.len() > 256 {
        g.retain(|_, t| t.elapsed() < UDP_BAD_FOR);
    }
    g.insert(remote.to_string(), Instant::now());
}

fn mark_good(remote: &str) {
    bad().lock().unwrap().remove(remote);
}

/// A spawned task that is stopped when this guard goes away, so the loser of the race (or a dial
/// nobody waits for any more) does not keep a socket and a handshake alive.
struct Guard<T>(JoinHandle<T>);

impl<T> Drop for Guard<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// A finished task -> its result (a task that panicked or was cancelled counts as a failure).
fn flat<T>(r: Result<Res<T>, tokio::task::JoinError>) -> Res<T> {
    match r {
        Ok(x) => x,
        Err(e) => Err(format!("dial task failed: {}", e).into()),
    }
}

/// Dials with `hq` and `h2` as described above. The arguments are those of `link::dial`:
/// `sni_raw` is the SNI field as typed (used by `hq`), `sni_name`, `req_host` and `path` are the
/// already-normalised TLS name, HTTP authority and request path (used by `h2`).
pub async fn dial(remote: &str, sni_raw: &str, sni_name: &str, req_host: &str, path: &str, token: &str, frag: bool) -> Res<Raw> {
    let (remote_o, sni_name_o, req_host_o, path_o) = (remote.to_string(), sni_name.to_string(), req_host.to_string(), path.to_string());

    // starts the h2 dial in a task of its own (called at most once per `dial`)
    let start_h2 = || {
        let (r, s, h, p) = (remote_o.clone(), sni_name_o.clone(), req_host_o.clone(), path_o.clone());
        Guard(tokio::spawn(async move { h2ws::dial(&r, &s, &h, &p, frag).await }))
    };

    // UDP is known not to work here: do not spend the head start again
    if udp_is_bad(remote) {
        let mut h2 = start_h2();
        let r = flat((&mut h2.0).await);
        if r.is_err() {
            // whatever went wrong, the next link gets the full race again
            mark_good(remote);
        }
        return r;
    }

    let (hq_remote, hq_sni, hq_token) = (remote.to_string(), sni_raw.to_string(), token.to_string());
    let mut hq = Guard(tokio::spawn(async move { hq::dial(&hq_remote, &hq_sni, &hq_token).await.map(Raw::Stream) }));

    // phase 1: hq alone
    match tokio::time::timeout(HQ_HEAD_START, &mut hq.0).await {
        Ok(joined) => match flat(joined) {
            Ok(raw) => {
                mark_good(remote);
                return Ok(raw);
            }
            Err(first_err) => {
                // hq failed quickly: UDP is not usable, go to h2 and remember it
                mark_bad(remote);
                let mut h2 = start_h2();
                return match flat((&mut h2.0).await) {
                    Ok(raw) => Ok(raw),
                    Err(e) => {
                        mark_good(remote);
                        Err(format!("hq: {}; h2: {}", first_err, e).into())
                    }
                };
            }
        },
        Err(_) => {} // hq is still working on it
    }

    // phase 2: both run, the first success wins
    let mut h2 = start_h2();
    let (mut hq_done, mut h2_done) = (false, false);
    let mut hq_err: Option<Box<dyn std::error::Error + Send + Sync>> = None;
    let mut h2_err: Option<Box<dyn std::error::Error + Send + Sync>> = None;
    loop {
        tokio::select! {
            r = &mut hq.0, if !hq_done => {
                hq_done = true;
                match flat(r) {
                    Ok(raw) => {
                        mark_good(remote);
                        return Ok(raw);
                    }
                    Err(e) => hq_err = Some(e),
                }
            }
            r = &mut h2.0, if !h2_done => {
                h2_done = true;
                match flat(r) {
                    Ok(raw) => {
                        // h2 got there first (or hq never did): stay on TCP for a while
                        mark_bad(remote);
                        return Ok(raw);
                    }
                    Err(e) => h2_err = Some(e),
                }
            }
        }
        if hq_done && h2_done {
            mark_good(remote);
            let a = hq_err.map(|e| e.to_string()).unwrap_or_default();
            let b = h2_err.map(|e| e.to_string()).unwrap_or_default();
            return Err(format!("hq: {}; h2: {}", a, b).into());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bad_flag_comes_and_goes() {
        let r = "203.0.113.9:443";
        assert!(!udp_is_bad(r));
        mark_bad(r);
        assert!(udp_is_bad(r));
        assert!(!udp_is_bad("203.0.113.10:443"), "another remote is not affected");
        mark_good(r);
        assert!(!udp_is_bad(r));
    }

    #[test]
    fn bad_flag_expires() {
        let r = "203.0.113.11:443";
        bad().lock().unwrap().insert(r.to_string(), Instant::now() - UDP_BAD_FOR - Duration::from_secs(1));
        assert!(!udp_is_bad(r), "an old mark must not count");
        assert!(bad().lock().unwrap().get(r).is_none(), "an old mark is removed");
    }
}
