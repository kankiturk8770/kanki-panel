//! Secrets at rest (3.68). The settings that hold secrets (bot tokens, payment keys, the TOTP secret, the link
//! key, the private keys inside `tun_servers` / `xray_cfg` / `dns_cfg`, …) and the WireGuard / AmneziaWG keys of
//! every peer are stored sealed:
//!
//!   enc1:<base64(nonce(12) | AES-256-GCM ciphertext+tag)>, aad = "kanki-secret-v1:" + the setting's name
//!
//! The key is `KANKI_MASTER_KEY` (64 hex digits) in /etc/kanki/kanki.env (0600), made once when missing. `Db::get`
//! / `Db::set` and the peer queries seal and open on their own, so the rest of the panel sees plain values. A value
//! written before 3.68 (no `enc1:`) is read as it is and sealed by `Db::migrate_secrets` at the next start, so
//! nothing a user has changes: the same subscription codes, the same keys, the same configs.
//!
//! Backups and moves carry the database opened (`plain_copy`): a backup restored on a server with another key
//! keeps working, and it is sealed again there at its first start.
use aes_gcm::aead::{Aead, KeyInit, Payload};
use std::sync::OnceLock;

pub const PREFIX: &str = "enc1:";
const AAD: &str = "kanki-secret-v1:";
const ENV_KEY: &str = "KANKI_MASTER_KEY";

static KEY: OnceLock<[u8; 32]> = OnceLock::new();

/// The settings whose values are sealed
pub const SEALED_SETTINGS: &[&str] = &[
    "totp_secret", "totp_pending", "sub_link_key", "kmix_secret", "bot_token", "mon_token", "tgb_token", "tgb_pass", "ai_key", "np_key",
    "zp_merchant", "toncenter_key", "card_number", "giveaway_secret", "join_token", "tun_servers", "xray_cfg", "dns_cfg",
];

pub fn sealed_setting(k: &str) -> bool {
    SEALED_SETTINGS.contains(&k)
}

fn parse_key(hex_key: &str) -> Option<[u8; 32]> {
    let b = hex::decode(hex_key.trim()).ok()?;
    b.try_into().ok()
}

/// The master key of the env file at `env_path`, made and saved (0600, the file's other lines kept) when there is
/// none. None = the file cannot be read or written, or its key is not 64 hex digits.
pub fn key_in(env_path: &str) -> Option<[u8; 32]> {
    let env = crate::util::load_env(env_path);
    if let Some(k) = env.get(ENV_KEY) {
        let k = parse_key(k);
        if k.is_none() {
            eprintln!("secrets: {} in {} is not 64 hex digits: secrets stay unsealed until it is fixed", ENV_KEY, env_path);
        }
        return k;
    }
    let old = std::fs::read_to_string(env_path).ok()?;
    let mut k = [0u8; 32];
    rand::Rng::fill(&mut rand::thread_rng(), &mut k);
    let text = format!("{}{}{}={}\n", old, if old.is_empty() || old.ends_with('\n') { "" } else { "\n" }, ENV_KEY, hex::encode(k));
    if let Err(e) = crate::util::write_private(env_path, &text) {
        eprintln!("secrets: the master key could not be saved in {}: {}", env_path, e);
        return None;
    }
    eprintln!("secrets: a master key was made ({}); secrets are sealed at rest from now on", env_path);
    Some(k)
}

/// Takes the master key of the env file for this process. false = none: values stay as they are, as before 3.68.
pub fn init(env_path: &str) -> bool {
    if KEY.get().is_some() {
        return true;
    }
    match key_in(env_path) {
        Some(k) => KEY.set(k).is_ok() || KEY.get().is_some(),
        None => false,
    }
}

/// For the tests: a fixed key
#[cfg(test)]
pub fn init_for_tests() {
    let _ = KEY.set([42u8; 32]);
}

fn cipher(k: &[u8; 32]) -> Option<aes_gcm::Aes256Gcm> {
    aes_gcm::Aes256Gcm::new_from_slice(k).ok()
}

/// `plain` sealed for `name` (an empty value, or no key: as it is)
pub fn seal(name: &str, plain: &str) -> String {
    let Some(k) = KEY.get() else { return plain.to_string() };
    if plain.is_empty() || plain.starts_with(PREFIX) {
        return plain.to_string();
    }
    let Some(c) = cipher(k) else { return plain.to_string() };
    let mut nonce = [0u8; 12];
    rand::Rng::fill(&mut rand::thread_rng(), &mut nonce);
    let aad = format!("{}{}", AAD, name);
    match c.encrypt(aes_gcm::Nonce::from_slice(&nonce), Payload { msg: plain.as_bytes(), aad: aad.as_bytes() }) {
        Ok(ct) => {
            let mut out = nonce.to_vec();
            out.extend(ct);
            format!("{}{}", PREFIX, crate::util::b64(&out))
        }
        Err(_) => {
            eprintln!("secrets: {} could not be sealed; kept as it was", name);
            plain.to_string()
        }
    }
}

/// The plain value of a stored one (a value without `enc1:` is plain already). A sealed value that cannot be
/// opened (another key) gives "" and is logged: it is never handed on as if it were the secret.
pub fn open(name: &str, stored: &str) -> String {
    let Some(body) = stored.strip_prefix(PREFIX) else { return stored.to_string() };
    let Some(k) = KEY.get() else {
        eprintln!("secrets: {} is sealed but this panel has no {}", name, ENV_KEY);
        return String::new();
    };
    let opened = crate::tunnel::link::b64decode(body).filter(|raw| raw.len() > 12 + 16).and_then(|raw| {
        let c = cipher(k)?;
        let aad = format!("{}{}", AAD, name);
        c.decrypt(aes_gcm::Nonce::from_slice(&raw[..12]), Payload { msg: &raw[12..], aad: aad.as_bytes() }).ok()
    });
    match opened.and_then(|p| String::from_utf8(p).ok()) {
        Some(p) => p,
        None => {
            eprintln!("secrets: {} could not be opened (another master key?)", name);
            String::new()
        }
    }
}

/// The settings name of a peer column (each column of each row is sealed with its own label)
pub fn peer_label(col: &str) -> String {
    format!("peers.{}", col)
}

/// Opens every sealed value of the database copy at `path` (a backup or a move): it then works on any server
pub fn plain_copy(path: &str) -> Result<(), String> {
    let c = rusqlite::Connection::open(path).map_err(|e| e.to_string())?;
    let rows: Vec<(String, String)> = {
        let mut st = c.prepare("SELECT k, v FROM settings WHERE v LIKE 'enc1:%'").map_err(|e| e.to_string())?;
        let it = st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))).map_err(|e| e.to_string())?;
        it.filter_map(|x| x.ok()).collect()
    };
    let tx = c.unchecked_transaction().map_err(|e| e.to_string())?;
    for (k, v) in rows {
        tx.execute("UPDATE settings SET v=?1 WHERE k=?2", rusqlite::params![open(&k, &v), k]).map_err(|e| e.to_string())?;
    }
    let peers: Vec<(i64, String, String)> = {
        let mut st = tx.prepare("SELECT rowid, privkey, psk FROM peers WHERE privkey LIKE 'enc1:%' OR psk LIKE 'enc1:%'").map_err(|e| e.to_string())?;
        let it = st.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?))).map_err(|e| e.to_string())?;
        it.filter_map(|x| x.ok()).collect()
    };
    for (id, pk, psk) in peers {
        tx.execute(
            "UPDATE peers SET privkey=?1, psk=?2 WHERE rowid=?3",
            rusqlite::params![open(&peer_label("privkey"), &pk), open(&peer_label("psk"), &psk), id],
        )
        .map_err(|e| e.to_string())?;
    }
    tx.commit().map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sealed_values_open_only_under_their_own_name() {
        init_for_tests();
        let s = seal("bot_token", "123456:secret-token-value");
        assert!(s.starts_with(PREFIX) && !s.contains("secret-token"));
        assert_eq!(open("bot_token", &s), "123456:secret-token-value");
        // moved to another setting: refused (the name is in the aad)
        assert_eq!(open("ai_key", &s), "");
        // a value from before 3.68 is read as it is; empty stays empty; sealing twice does nothing
        assert_eq!(open("bot_token", "plain-old"), "plain-old");
        assert_eq!(seal("bot_token", ""), "");
        assert_eq!(seal("bot_token", &s), s);
        // a damaged one never comes back as text
        assert_eq!(open("bot_token", "enc1:AAAA"), "");
    }

    /// Rows written before 3.68 are sealed in place at start; the panel still reads them as they were (the same
    /// tokens, the same peer keys: no user notices); a backup copy carries them opened
    #[test]
    fn old_rows_are_sealed_and_read_the_same() {
        init_for_tests();
        let app = crate::test_app();
        let db = &app.db;
        db.exec("INSERT INTO settings(k,v) VALUES('bot_token','111111:plain-bot-token-from-before') ON CONFLICT(k) DO UPDATE SET v=excluded.v", &[]).unwrap();
        db.exec("INSERT INTO settings(k,v) VALUES('panel_name','Kanki') ON CONFLICT(k) DO UPDATE SET v=excluded.v", &[]).unwrap();
        db.exec("INSERT INTO peers(user_id,node_id,proto,privkey,pubkey,psk,ip) VALUES(7,'local','wg','PRIVKEYold=','PUBKEY=','PSKold=','10.66.0.7')", &[]).unwrap();
        db.migrate_secrets();
        let raw = |sql: &str| db.with(|c| c.query_row(sql, [], |r| r.get::<_, String>(0)).unwrap());
        assert!(raw("SELECT v FROM settings WHERE k='bot_token'").starts_with(PREFIX));
        assert_eq!(raw("SELECT v FROM settings WHERE k='panel_name'"), "Kanki", "plain settings stay plain");
        assert!(raw("SELECT privkey FROM peers WHERE user_id=7").starts_with(PREFIX));
        assert_eq!(db.get("bot_token"), "111111:plain-bot-token-from-before");
        let p = db.peer(7, "local", "wg").unwrap();
        assert_eq!((p.privkey.as_str(), p.psk.as_str(), p.pubkey.as_str()), ("PRIVKEYold=", "PSKold=", "PUBKEY="));
        // a second start changes nothing
        let before = raw("SELECT v FROM settings WHERE k='bot_token'");
        db.migrate_secrets();
        assert_eq!(raw("SELECT v FROM settings WHERE k='bot_token'"), before);
        // a new value is sealed when written
        db.set("ai_key", "sk-new-value");
        assert!(raw("SELECT v FROM settings WHERE k='ai_key'").starts_with(PREFIX));
        assert_eq!(db.get("ai_key"), "sk-new-value");
        // the backup copy: everything opened
        let dir = std::env::temp_dir().join(format!("kanki-sec-copy-{}", crate::util::rand_token(8)));
        std::fs::create_dir_all(&dir).unwrap();
        let copy = dir.join("snap.db");
        db.with(|c| c.execute(&format!("VACUUM INTO '{}'", copy.display()), [])).unwrap();
        plain_copy(copy.to_str().unwrap()).unwrap();
        let c = rusqlite::Connection::open(&copy).unwrap();
        let v: String = c.query_row("SELECT v FROM settings WHERE k='bot_token'", [], |r| r.get(0)).unwrap();
        let pk: String = c.query_row("SELECT privkey FROM peers WHERE user_id=7", [], |r| r.get(0)).unwrap();
        assert_eq!((v.as_str(), pk.as_str()), ("111111:plain-bot-token-from-before", "PRIVKEYold="));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_master_key_is_made_once_in_the_env_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("kanki-sec-{}", crate::util::rand_token(8)));
        std::fs::create_dir_all(&dir).unwrap();
        let env = dir.join("kanki.env");
        let p = env.to_str().unwrap();
        std::fs::write(&env, "MODE=panel\nPANEL_PORT=8080").unwrap();
        let k1 = key_in(p).unwrap();
        let k2 = key_in(p).unwrap();
        assert_eq!(k1, k2, "the key is made once and then read");
        let e = crate::util::load_env(p);
        assert_eq!(e.get("PANEL_PORT").map(|s| s.as_str()), Some("8080"));
        assert_eq!(std::fs::metadata(&env).unwrap().permissions().mode() & 0o777, 0o600);
        std::fs::write(&env, "KANKI_MASTER_KEY=abc\n").unwrap();
        assert!(key_in(p).is_none(), "a broken key is not replaced (the sealed values would be lost)");
        assert!(key_in(dir.join("missing.env").to_str().unwrap()).is_none());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
