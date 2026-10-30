//! Request limits per IP, against spam and guessing: the login, and the public subscription paths.
//! Counted in memory in fixed windows; a restart starts them again.
use crate::util::now;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

type Table = Mutex<HashMap<String, (u32, i64)>>;

fn table(name: &'static str) -> &'static Table {
    static T: OnceLock<Mutex<HashMap<&'static str, &'static Table>>> = OnceLock::new();
    let mut m = T.get_or_init(Default::default).lock().unwrap();
    m.entry(name).or_insert_with(|| Box::leak(Box::default()))
}

/// Counts one request of `key`; false when it is past `max` in the last `window` seconds
pub fn hit(name: &'static str, key: &str, max: u32, window: i64) -> bool {
    let mut m = table(name).lock().unwrap();
    let t = now();
    // old entries go, so many addresses cannot grow the table without limit
    if m.len() > 20000 {
        m.retain(|_, e| t - e.1 < window);
    }
    let e = m.entry(key.to_string()).or_insert((0, t));
    if t - e.1 >= window {
        *e = (0, t);
    }
    e.0 += 1;
    e.0 <= max
}

/// Whether `key` is already past `max` (without counting this request)
pub fn over(name: &'static str, key: &str, max: u32, window: i64) -> bool {
    let m = table(name).lock().unwrap();
    matches!(m.get(key), Some((n, t)) if *n >= max && now() - *t < window)
}

/// Login: at most 20 tries a minute from one address (wrong passwords also lock it for 15 minutes, auth.rs)
pub const LOGIN: (u32, i64) = (20, 60);
/// Subscription and config paths: 240 requests a minute per address (many phones can share one address)
pub const SUB: (u32, i64) = (240, 60);
/// Unknown subscription codes: after 40 in 10 minutes the address waits
pub const SUB_MISS: (u32, i64) = (40, 600);

/// The paths anyone can open without signing in that give a user's data
pub fn is_sub_path(path: &str) -> bool {
    path.starts_with("/sub/") || path.starts_with("/api/config/")
}

/// Our own machine (the Iran relay and local tools reach the panel from here): never limited
pub fn exempt(ip: &str) -> bool {
    ip == "127.0.0.1" || ip == "::1" || ip.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stops_after_the_limit() {
        for _ in 0..3 {
            assert!(hit("test", "1.2.3.4", 3, 60));
        }
        assert!(!hit("test", "1.2.3.4", 3, 60));
        assert!(over("test", "1.2.3.4", 3, 60));
        // another address is not affected
        assert!(hit("test", "5.6.7.8", 3, 60) && !over("test", "5.6.7.8", 3, 60));
    }
}
