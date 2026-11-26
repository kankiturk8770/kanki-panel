//! Subscription links that keep the code out of access logs (3.65).
//!
//! A subscription code opens the whole account (every config, the Kanki app, the Hysteria2 password is
//! made from it), and a URL ends up in the logs of every proxy and CDN on the way. So the panel hands out
//! links without it, and old `/sub/<code>/…` links keep working:
//!
//! * `/sub/h/<hash>[/<kind>]`: `hash` = the first 40 hex digits of HMAC-SHA256(this panel's own link key,
//!   the code). It only fetches the subscription, cannot be turned back into the code, and is only good on
//!   this panel. A new code (reset in the panel) makes a new hash and the old link stops.
//! * `/sub/me[/<kind>]` with the code in a header (`X-Kanki-Sub: <code>`, or `Authorization: Bearer <code>`):
//!   for apps that can send headers; the URL carries nothing.
//!
//! `kind` is what `/sub/<code>/<kind>` has: raw, json, xray, xjson, v2, v2qr (none = the account page).

use crate::db::User;
use crate::App;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::Mutex;

/// The setting that holds this panel's link key (made once, never shown)
const KEY_SETTING: &str = "sub_link_key";
/// Hex digits of a hashed link
pub const HASH_LEN: usize = 40;
/// The header an app sends its code in
pub const CODE_HEADER: &str = "x-kanki-sub";
/// The longest code taken from a header (a real one is `kanki-<id>-<code>`)
const MAX_CODE: usize = 128;
/// The kinds a hashed or header link may ask for
pub const KINDS: &[&str] = &["raw", "json", "xray", "xjson", "v2", "v2qr"];

fn key_lock() -> &'static Mutex<()> {
    static L: std::sync::OnceLock<Mutex<()>> = std::sync::OnceLock::new();
    L.get_or_init(|| Mutex::new(()))
}

/// This panel's link key, made the first time it is needed (one at a time, so two first requests cannot
/// make two keys)
fn link_key(app: &App) -> String {
    let k = app.db.get(KEY_SETTING);
    if k.len() >= 32 {
        return k;
    }
    let _g = key_lock().lock().unwrap_or_else(|e| e.into_inner());
    let k = app.db.get(KEY_SETTING);
    if k.len() >= 32 {
        return k;
    }
    let k = crate::util::rand_token(48);
    app.db.set(KEY_SETTING, &k);
    k
}

fn hash_with(key: &str, code: &str) -> String {
    let Ok(mut m) = Hmac::<Sha256>::new_from_slice(key.as_bytes()) else { return String::new() };
    m.update(b"kanki-sub-link-v1:");
    m.update(code.as_bytes());
    hex::encode(m.finalize().into_bytes())[..HASH_LEN].to_string()
}

/// The hashed form of an account's code
pub fn hash_of(app: &App, u: &User) -> String {
    hash_with(&link_key(app), &u.sub_code())
}

/// Whether `h` has the form of a hashed link (anything else is refused before any lookup)
pub fn valid_hash(h: &str) -> bool {
    h.len() == HASH_LEN && h.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

struct Index {
    key: String,
    /// hash -> user id
    ids: HashMap<String, i64>,
    built: std::time::Instant,
}

fn index() -> &'static Mutex<Option<Index>> {
    static I: std::sync::OnceLock<Mutex<Option<Index>>> = std::sync::OnceLock::new();
    I.get_or_init(|| Mutex::new(None))
}

/// The account a hashed link names. The hashes of every account are kept in memory; a hash not found
/// there rebuilds them (a new account, a new code), at most once every few seconds, so guessed hashes
/// cannot keep the panel busy. A found account is checked again against its code of now.
pub fn user_by_hash(app: &App, h: &str) -> Option<User> {
    if !valid_hash(h) {
        return None;
    }
    let key = link_key(app);
    let mut g = index().lock().unwrap_or_else(|e| e.into_inner());
    let fresh = g.as_ref().is_some_and(|i| i.key == key);
    let hit = g.as_ref().filter(|_| fresh).and_then(|i| i.ids.get(h).copied());
    let id = match hit {
        Some(id) => Some(id),
        None => {
            let may_rebuild = !fresh || g.as_ref().is_none_or(|i| i.built.elapsed() >= std::time::Duration::from_secs(5));
            if !may_rebuild {
                return None;
            }
            let ids: HashMap<String, i64> = app.db.users().into_iter().map(|u| (hash_with(&key, &u.sub_code()), u.id)).collect();
            let id = ids.get(h).copied();
            *g = Some(Index { key: key.clone(), ids, built: std::time::Instant::now() });
            id
        }
    };
    drop(g);
    let u = app.db.user(id?)?;
    // the code may have changed since the index was made: the link must name the code of now
    crate::util::ct_eq(&hash_with(&key, &u.sub_code()), h).then_some(u)
}

/// The code an app sent in a header (`X-Kanki-Sub`, or `Authorization: Bearer`), when it has the form of one
pub fn header_code(h: &axum::http::HeaderMap) -> Option<String> {
    let v = h
        .get(CODE_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .or_else(|| h.get(axum::http::header::AUTHORIZATION).and_then(|v| v.to_str().ok()).and_then(|s| s.trim().strip_prefix("Bearer ")).map(|s| s.trim().to_string()))?;
    (!v.is_empty() && v.len() <= MAX_CODE && v.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')).then_some(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_hash_names_one_account_and_follows_its_code() {
        let app = crate::test_app();
        let ua = app.db.create_user("hash-a", 0.0, 0, 1, "xray,hy2", "", "", 0).unwrap();
        let ub = app.db.create_user("hash-b", 0.0, 0, 1, "xray,hy2", "", "", 0).unwrap();
        let (a, b) = (ua.id, ub.id);
        let (ha, hb) = (hash_of(&app, &ua), hash_of(&app, &ub));
        assert!(valid_hash(&ha) && ha != hb && !ha.contains(&ua.code));
        assert_eq!(user_by_hash(&app, &ha).map(|u| u.id), Some(a));
        assert_eq!(user_by_hash(&app, &hb).map(|u| u.id), Some(b));
        // a new code: the old link stops, the new one works
        app.db.exec("UPDATE users SET code='renewedcode0123456789' WHERE id=?1", &[&a]).unwrap();
        assert!(user_by_hash(&app, &ha).is_none());
        let fresh = hash_of(&app, &app.db.user(a).unwrap());
        std::thread::sleep(std::time::Duration::from_millis(10));
        // (a rebuild waits a few seconds after the last one: the hash of an account made just now is
        // found once the index is rebuilt)
        *index().lock().unwrap() = None;
        assert_eq!(user_by_hash(&app, &fresh).map(|u| u.id), Some(a));
        // not a hash at all, or of another panel's key: nothing
        for bad in ["", "zz", &ha.to_uppercase(), &format!("{}0", ha), "../../api/users0000000000000000000000000"] {
            assert!(user_by_hash(&app, bad).is_none(), "{}", bad);
        }
        assert_ne!(hash_with("another panel's key 0123456789abcdef", &ua.sub_code()), ha);
    }

    #[test]
    fn the_code_comes_only_from_its_headers_and_in_its_form() {
        let mut h = axum::http::HeaderMap::new();
        assert!(header_code(&h).is_none());
        h.insert(CODE_HEADER, "kanki-3-abcDEF123".parse().unwrap());
        assert_eq!(header_code(&h).as_deref(), Some("kanki-3-abcDEF123"));
        let mut h = axum::http::HeaderMap::new();
        h.insert(axum::http::header::AUTHORIZATION, "Bearer kanki-4-xyz".parse().unwrap());
        assert_eq!(header_code(&h).as_deref(), Some("kanki-4-xyz"));
        for bad in ["kanki-1-a b", "kanki/../x", "", &"a".repeat(MAX_CODE + 1)] {
            let mut h = axum::http::HeaderMap::new();
            h.insert(CODE_HEADER, bad.parse().unwrap());
            assert!(header_code(&h).is_none(), "{}", bad);
        }
    }
}
