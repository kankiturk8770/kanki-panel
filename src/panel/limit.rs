//! Request limits per IP, against spam and guessing: the login, and the public subscription paths.
//! Counted in memory in fixed windows; a restart starts them again.
use crate::util::now;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

type Table = Mutex<HashMap<String, (u32, i64)>>;

fn table(name: &'static str) -> &'static Table {
    static T: OnceLock<Mutex<HashMap<&'static str, &'static Table>>> = OnceLock::new();
    let mut m = T.get_or_init(Default::default).lock().unwrap_or_else(|e| e.into_inner());
    m.entry(name).or_insert_with(|| Box::leak(Box::default()))
}

/// Counts one request of `key`; false when it is past `max` in the last `window` seconds
pub fn hit(name: &'static str, key: &str, max: u32, window: i64) -> bool {
    let mut m = table(name).lock().unwrap_or_else(|e| e.into_inner());
    let t = now();
    // old entries go, so many addresses cannot grow the table without limit
    trim(&mut m, 20000, window, t);
    let e = m.entry(key.to_string()).or_insert((0, t));
    if t - e.1 >= window {
        *e = (0, t);
    }
    e.0 += 1;
    e.0 <= max
}

/// Keeps a table of (count, window start) per address below `cap`: entries older than `window` go, and
/// when that is not enough the older half goes too, so the next full scan is `cap / 2` new addresses
/// away (not one on every request).
pub fn trim(m: &mut HashMap<String, (u32, i64)>, cap: usize, window: i64, t: i64) {
    if m.len() <= cap {
        return;
    }
    m.retain(|_, e| t - e.1 < window);
    if m.len() > cap / 2 {
        let mut starts: Vec<i64> = m.values().map(|e| e.1).collect();
        let mid = starts.len() - cap / 2;
        let (_, cut, _) = starts.select_nth_unstable(mid);
        let cut = *cut;
        m.retain(|_, e| e.1 > cut);
    }
}

/// Whether `key` is already past `max` (without counting this request)
pub fn over(name: &'static str, key: &str, max: u32, window: i64) -> bool {
    let m = table(name).lock().unwrap_or_else(|e| e.into_inner());
    matches!(m.get(key), Some((n, t)) if *n >= max && now() - *t < window)
}

/// Login: at most 20 tries a minute from one address (5 wrong passwords also lock it for an hour, auth.rs)
pub const LOGIN: (u32, i64) = (20, 60);
/// Subscription and config paths: 1200 requests a minute per address. Iranian mobile networks put many
/// phones behind one address, and a Kanki app asks every subscription host at once for the page and each
/// config (a refresh of one user with 20 configs is ~60 requests), so 240 locked whole neighbourhoods out.
pub const SUB: (u32, i64) = (1200, 60);
/// Unknown subscription codes: after 200 in an hour the address waits (bots guessing codes; a code has a
/// long random part, so guessing needs millions). An old link after "new link" is also unknown, and its
/// apps keep asking every few hours on every host: 40 blocked everyone behind the same address.
pub const SUB_MISS: (u32, i64) = (200, 3600);

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

    #[test]
    fn a_full_table_drops_its_older_half() {
        let mut m: HashMap<String, (u32, i64)> = (0..101).map(|i| (format!("ip{}", i), (1, 1000 + i))).collect();
        // all still inside the window: the older entries go, the newest stay
        trim(&mut m, 100, 3600, 1200);
        assert!(m.len() <= 50 && m.len() >= 40, "{}", m.len());
        assert!(m.contains_key("ip100") && !m.contains_key("ip0"));
        // below the cap nothing is touched
        let n = m.len();
        trim(&mut m, 100, 1, 99999);
        assert_eq!(m.len(), n);
    }
}
