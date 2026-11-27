//! 3.69: the Xray and Hysteria2 credentials of an account.
//!
//! Before 3.69 they were plain hashes of the subscription code (`kanki-xray|<code>` …): whoever saw one code could
//! work out every credential of it, and the other way round a leaked credential could be tested against codes
//! offline. An account made or renewed (`regen`) from 3.69 on has `users.cred = 1`: its credentials are
//! HMAC-SHA256 under the panel's own key (`cred_key`, sealed at rest, carried by backups so a restore elsewhere
//! gives the same ones). Every account from before keeps `cred = 0` and the old derivation exactly, so no client
//! disconnects.

use crate::db::User;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::sync::RwLock;

/// `users.cred` of an account whose credentials are keyed
pub const KEYED: i64 = 1;

fn key() -> &'static RwLock<Option<String>> {
    static K: RwLock<Option<String>> = RwLock::new(None);
    &K
}

/// Reads (or makes, once) the panel's credential key. Called at start, after the database is open; the first
/// call of the process wins (one panel, one database: a restore restarts the program).
pub fn init(db: &crate::db::Db) {
    let mut k = db.get("cred_key");
    if k.len() < 32 {
        k = crate::util::rand_token(48);
        db.set("cred_key", &k);
    }
    let mut g = key().write().unwrap_or_else(|e| e.into_inner());
    if g.is_none() {
        *g = Some(k);
    }
}

fn keyed(kind: &str, u: &User) -> Option<[u8; 32]> {
    let g = key().read().unwrap_or_else(|e| e.into_inner());
    let k = g.as_ref()?;
    let mut m = Hmac::<Sha256>::new_from_slice(k.as_bytes()).ok()?;
    m.update(format!("kanki-cred-v1|{}|{}|{}", kind, u.id, u.code).as_bytes());
    Some(m.finalize().into_bytes().into())
}

/// The keyed bytes for `kind`, or None for an account of before (or before `init`: the old derivation then, with
/// a line in the log; the panel always calls `init` at start)
fn derived(kind: &str, u: &User) -> Option<[u8; 32]> {
    if u.cred < KEYED {
        return None;
    }
    let d = keyed(kind, u);
    if d.is_none() {
        eprintln!("creds: the credential key is not loaded; account {} gets its old credentials", u.id);
    }
    d
}

/// A UUID (version 4 layout) from 16 bytes of hex
fn uuid_of(hex32: &str) -> String {
    let mut b: Vec<char> = hex32.chars().take(32).collect();
    b[12] = '4';
    b[16] = ['8', '9', 'a', 'b'][(b[16].to_digit(16).unwrap_or(0) % 4) as usize];
    let s: String = b.into_iter().collect();
    format!("{}-{}-{}-{}-{}", &s[..8], &s[8..12], &s[12..16], &s[16..20], &s[20..32])
}

/// The Xray VLESS / VMess id of the account
pub fn xray_uuid(u: &User) -> String {
    match derived("xray-uuid", u) {
        Some(d) => uuid_of(&hex::encode(d)),
        None => crate::xray::panel::user_uuid(&u.code),
    }
}

/// The Xray Trojan / Shadowsocks password of the account
pub fn xray_pass(u: &User) -> String {
    match derived("xray-pass", u) {
        Some(d) => hex::encode(d)[..24].to_string(),
        None => crate::xray::panel::user_pass(&u.code),
    }
}

/// The 32 bytes a Shadowsocks 2022 user key is cut from
pub fn ss_bytes(u: &User) -> Vec<u8> {
    match derived("xray-ss", u) {
        Some(d) => d.to_vec(),
        None => crate::xray::panel::ss_legacy_bytes(&u.code),
    }
}

/// The Hysteria2 password of the account
pub fn hy2_pass(u: &User) -> String {
    match derived("hy2", u) {
        Some(d) => hex::encode(d)[..32].to_string(),
        None => crate::hy2::user_pass(&u.code),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn old_accounts_keep_their_credentials_and_new_ones_are_keyed() {
        let app = crate::test_app();
        let mut u = app.db.create_user("cred-a", 1.0, 30, 1, "xray,hy2", "", "", 0).unwrap();
        // a new account: 39 digits (128 bits and more) and keyed credentials
        assert_eq!(u.code.len(), 39);
        assert!(u.code.bytes().all(|c| c.is_ascii_digit()));
        assert_eq!(u.cred, KEYED);
        assert_ne!(xray_uuid(&u), crate::xray::panel::user_uuid(&u.code));
        assert_ne!(hy2_pass(&u), crate::hy2::user_pass(&u.code));
        assert_ne!(xray_pass(&u), crate::xray::panel::user_pass(&u.code));
        assert_eq!(xray_uuid(&u).len(), 36);
        assert_eq!(hy2_pass(&u).len(), 32);
        // stable
        assert_eq!(xray_uuid(&u), xray_uuid(&app.db.user(u.id).unwrap()));
        // an account from before (cred 0, a 19-digit code): exactly the old values
        app.db.exec("UPDATE users SET cred=0, code='1234567890123456789' WHERE id=?1", &[&u.id]).unwrap();
        u = app.db.user(u.id).unwrap();
        assert_eq!(xray_uuid(&u), crate::xray::panel::user_uuid("1234567890123456789"));
        assert_eq!(hy2_pass(&u), crate::hy2::user_pass("1234567890123456789"));
        assert_eq!(xray_pass(&u), crate::xray::panel::user_pass("1234567890123456789"));
        assert_eq!(ss_bytes(&u), crate::xray::panel::ss_legacy_bytes("1234567890123456789"));
        // a renewed link: a new 39-digit code and keyed credentials from then on
        crate::api::user_action(&app, u.id, "regen", &serde_json::Value::Null).unwrap();
        let r = app.db.user(u.id).unwrap();
        assert_eq!((r.code.len(), r.cred), (39, KEYED));
        assert_ne!(hy2_pass(&r), crate::hy2::user_pass(&r.code));
        // the bare code of 39 digits still finds its account
        assert_eq!(app.db.user_by_bare_code(&r.code).map(|x| x.id), Some(r.id));
    }
}
