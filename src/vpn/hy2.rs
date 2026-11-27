//! Hysteria2: traffic stats API (auth is handled over HTTP in api.rs)
use std::collections::HashMap;

/// The local Hysteria2 stats API: one shared client with a short timeout, so a Hysteria that hangs
/// cannot hold the sync round (traffic, limits and the online list of every server)
fn client() -> &'static reqwest::Client {
    static C: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    C.get_or_init(|| reqwest::Client::builder().timeout(std::time::Duration::from_secs(5)).build().unwrap_or_default())
}

/// Per-user traffic since last call (clear=1)
pub async fn traffic(port: &str, secret: &str) -> HashMap<String, (i64, i64)> {
    let mut m = HashMap::new();
    if port.is_empty() {
        return m;
    }
    let url = format!("http://127.0.0.1:{}/traffic?clear=1", port);
    if let Ok(r) = client().get(&url).header("Authorization", secret).send().await {
        if let Ok(v) = r.json::<serde_json::Value>().await {
            if let Some(o) = v.as_object() {
                for (k, x) in o {
                    let tx = x.get("tx").and_then(|a| a.as_i64()).unwrap_or(0);
                    let rx = x.get("rx").and_then(|a| a.as_i64()).unwrap_or(0);
                    m.insert(k.clone(), (rx, tx));
                }
            }
        }
    }
    m
}

/// Online connections per user
pub async fn online(port: &str, secret: &str) -> HashMap<String, i64> {
    let mut m = HashMap::new();
    if port.is_empty() {
        return m;
    }
    let url = format!("http://127.0.0.1:{}/online", port);
    if let Ok(r) = client().get(&url).header("Authorization", secret).send().await {
        if let Ok(v) = r.json::<HashMap<String, i64>>().await {
            m = v;
        }
    }
    m
}

/// Connections of each user that moved real data (1 KB) lately, from Hysteria's stream list (None =
/// this Hysteria has no stream list). A ping logs in and leaves without moving data, so a ping next to
/// a real session is not a second device.
pub async fn moving(port: &str, secret: &str, now: i64) -> Option<HashMap<String, i64>> {
    if port.is_empty() {
        return None;
    }
    let url = format!("http://127.0.0.1:{}/dump/streams", port);
    let r = client().get(&url).header("Authorization", secret).send().await.ok()?;
    if !r.status().is_success() {
        return None;
    }
    let v: serde_json::Value = r.json().await.ok()?;
    let mut bytes: HashMap<(String, u64), i64> = HashMap::new();
    for s in v.get("streams")?.as_array()? {
        let (Some(user), Some(conn)) = (s["auth"].as_str(), s["connection"].as_u64()) else { continue };
        let b = s["tx"].as_i64().unwrap_or(0) + s["rx"].as_i64().unwrap_or(0);
        *bytes.entry((user.to_string(), conn)).or_default() += b;
    }
    Some(note_moving(&bytes, now))
}

/// How long a connection that moved data counts as a real one without moving more (an idle device
/// with no stream open)
const MOVED_FOR: i64 = 600;

/// (user, connection) -> when it was last seen moving data; None until a stream list was read
fn moved() -> &'static std::sync::Mutex<Option<HashMap<(String, u64), i64>>> {
    static M: std::sync::Mutex<Option<HashMap<(String, u64), i64>>> = std::sync::Mutex::new(None);
    &M
}

fn note_moving(bytes: &HashMap<(String, u64), i64>, now: i64) -> HashMap<String, i64> {
    let mut g = moved().lock().unwrap_or_else(|e| e.into_inner());
    let m = g.get_or_insert_with(HashMap::new);
    for (k, b) in bytes {
        if *b >= 1024 || m.contains_key(k) {
            m.insert(k.clone(), now);
        }
    }
    m.retain(|_, t| now - *t < MOVED_FOR);
    count_moving(m, None, now)
}

fn count_moving(m: &HashMap<(String, u64), i64>, user: Option<&str>, now: i64) -> HashMap<String, i64> {
    let mut out: HashMap<String, i64> = HashMap::new();
    for ((u, _), t) in m {
        if now - *t < MOVED_FOR && user.is_none_or(|x| x == u) {
            *out.entry(u.clone()).or_default() += 1;
        }
    }
    out
}

/// What the last stream list said about one user (None = no stream list on this Hysteria)
pub fn moving_known(user: &str, now: i64) -> Option<i64> {
    let g = moved().lock().unwrap_or_else(|e| e.into_inner());
    let m = g.as_ref()?;
    Some(count_moving(m, Some(user), now).get(user).copied().unwrap_or(0))
}

/// Disconnect users right away
pub async fn kick(port: &str, secret: &str, ids: &[String]) {
    if port.is_empty() || ids.is_empty() {
        return;
    }
    let url = format!("http://127.0.0.1:{}/kick", port);
    let _ = client().post(&url).header("Authorization", secret).json(&ids).send().await;
}

/// What Hysteria2's users may not reach (3.68): this server's loopback (the panel, the stats API, `/hy2/auth`
/// and the other local services), private and link-local networks (the provider's other machines, cloud
/// metadata at 169.254.169.254).
pub const ACL: &str = "acl:\n  inline:\n    - reject(127.0.0.0/8)\n    - reject(::1)\n    - reject(localhost)\n    - reject(0.0.0.0/8)\n    - reject(10.0.0.0/8)\n    - reject(100.64.0.0/10)\n    - reject(169.254.0.0/16)\n    - reject(172.16.0.0/12)\n    - reject(192.168.0.0/16)\n    - reject(fc00::/7)\n    - reject(fe80::/10)\n";

/// The ACL that 3.22.2 to 3.67 wrote (loopback only): replaced by `ACL`
const OLD_ACL: &str = "acl:\n  inline:\n    - reject(127.0.0.0/8)\n    - reject(::1)\n    - reject(localhost)\n";

/// The config with Kanki's ACL: added when there is none, the old loopback-only one is widened; an ACL the
/// admin wrote by hand is left alone (None = nothing to change)
pub fn with_acl(t: &str) -> Option<String> {
    if t.contains(ACL) {
        return None;
    }
    if t.contains(OLD_ACL) {
        return Some(t.replacen(OLD_ACL, ACL, 1));
    }
    if t.lines().any(|l| l.trim_start().starts_with("acl:")) {
        return None;
    }
    Some(if t.ends_with('\n') { format!("{}{}", t, ACL) } else { format!("{}\n{}", t, ACL) })
}

/// Hysteria2 must not let its users reach this server's own loopback or private networks. Configs written
/// before have no ACL or the loopback-only one: Kanki's is put in once and Hysteria restarted (back to the
/// old config if it does not start with it). Blocking.
pub fn ensure_acl() {
    const CONF: &str = "/etc/hysteria/config.yaml";
    let Ok(t) = std::fs::read_to_string(CONF) else { return };
    let Some(new) = with_acl(&t) else { return };
    let was_active = std::process::Command::new("systemctl").args(["is-active", "--quiet", "hysteria-server.service"]).status().map(|s| s.success()).unwrap_or(false);
    if let Err(e) = crate::util::write_private(CONF, &new) {
        eprintln!("hysteria2: the ACL could not be written: {}", e);
        return;
    }
    let _ = std::process::Command::new("systemctl").args(["try-restart", "hysteria-server.service"]).status();
    std::thread::sleep(std::time::Duration::from_secs(3));
    let active = std::process::Command::new("systemctl").args(["is-active", "--quiet", "hysteria-server.service"]).status().map(|s| s.success()).unwrap_or(false);
    if was_active && !active {
        // an older Hysteria that does not take this ACL: the users come first, the old config goes back
        if let Err(e) = crate::util::write_private(CONF, &t) {
            eprintln!("hysteria2: the previous config could not be put back: {}", e);
        }
        let _ = std::process::Command::new("systemctl").args(["restart", "hysteria-server.service"]).status();
        eprintln!("hysteria2: it did not start with the ACL, the previous config is back");
        return;
    }
    eprintln!("hysteria2: its users can no longer reach this server's loopback or private networks (acl)");
}

/// The key Hysteria's login check sends to `/hy2/auth` (3.65). Hysteria cannot sign a request, so its
/// auth URL carries a key only this machine knows (`?k=`, file mode 0600); with the key in place a call
/// without it, or with another, is refused even from the loopback.
pub const AUTH_KEY_FILE: &str = "/etc/kanki/hy2-auth.key";

/// The key `/hy2/auth` asks for (None = not set up here yet: loopback only, as before)
pub fn auth_key() -> Option<String> {
    std::fs::read_to_string(AUTH_KEY_FILE).ok().map(|k| k.trim().to_string()).filter(|k| k.len() >= 32)
}

/// `conf` with the key on its `/hy2/auth` URL: (new config, key in it). A URL that already has a key keeps
/// it; None when the config has no such URL (no Hysteria here, or an auth this panel did not write).
pub fn with_auth_key(conf: &str, key: &str) -> Option<(String, String)> {
    let mut out = String::with_capacity(conf.len() + 80);
    let mut used: Option<String> = None;
    for line in conf.split_inclusive('\n') {
        let body = line.trim_end_matches(['\n', '\r']);
        let t = body.trim_start();
        if used.is_none() {
            if let Some(url) = t.strip_prefix("url:").map(|u| u.trim()) {
                if url.starts_with("http://127.0.0.1:") && url.contains("/hy2/auth") {
                    if let Some((_, k)) = url.split_once("?k=") {
                        used = Some(k.to_string());
                        out.push_str(line);
                        continue;
                    }
                    let indent = &body[..body.len() - t.len()];
                    out.push_str(&format!("{}url: {}?k={}{}", indent, url, key, &line[body.len()..]));
                    used = Some(key.to_string());
                    continue;
                }
            }
        }
        out.push_str(line);
    }
    used.filter(|k| k.len() >= 32 && k.bytes().all(|c| c.is_ascii_alphanumeric())).map(|k| (out, k))
}

/// Puts the key on this machine's Hysteria auth URL once (restarting Hysteria) and keeps it in
/// `AUTH_KEY_FILE`, where `/hy2/auth` reads it. If Hysteria does not start with it, the old config comes
/// back and no key is asked for. Blocking.
pub fn ensure_auth_key() {
    const CONF: &str = "/etc/hysteria/config.yaml";
    let Ok(t) = std::fs::read_to_string(CONF) else { return };
    let Some((new, key)) = with_auth_key(&t, &crate::util::rand_token(48)) else { return };
    let save_key = |k: &str| {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let r = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(AUTH_KEY_FILE).and_then(|mut f| f.write_all(k.as_bytes()));
        if let Err(e) = r {
            eprintln!("hysteria2: cannot keep the auth key: {}", e);
        }
    };
    if new == t {
        // the config already carries a key: the file must know it
        if auth_key().as_deref() != Some(key.as_str()) {
            save_key(&key);
        }
        return;
    }
    let active = || std::process::Command::new("systemctl").args(["is-active", "--quiet", "hysteria-server.service"]).status().map(|s| s.success()).unwrap_or(false);
    let was_active = active();
    if let Err(e) = std::fs::write(CONF, &new) {
        eprintln!("hysteria2: cannot write its config: {}", e);
        return;
    }
    if let Err(e) = std::process::Command::new("systemctl").args(["try-restart", "hysteria-server.service"]).status() {
        eprintln!("hysteria2: cannot restart it: {}", e);
    }
    std::thread::sleep(std::time::Duration::from_secs(3));
    if was_active && !active() {
        if let Err(e) = std::fs::write(CONF, &t) {
            eprintln!("hysteria2: cannot put its previous config back: {}", e);
        }
        if let Err(e) = std::process::Command::new("systemctl").args(["restart", "hysteria-server.service"]).status() {
            eprintln!("hysteria2: cannot restart it: {}", e);
        }
        eprintln!("hysteria2: it did not start with the auth key, the previous config is back");
        return;
    }
    save_key(&key);
    eprintln!("hysteria2: its login check now carries a key only this server knows");
}

/// The Hysteria2 password of an account: made from its subscription code but not the code itself, so a shared
/// hysteria2:// link does not open the subscription (and every other config) of its owner
pub fn user_pass(code: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(format!("kanki-hy2|{}", code).as_bytes()))[..32].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_acl_is_added_or_widened_never_doubled() {
        let base = "listen: :8443\nauth:\n  type: http\n";
        let a = with_acl(base).unwrap();
        assert!(a.contains("reject(169.254.0.0/16)") && a.contains("reject(10.0.0.0/8)"));
        assert_eq!(with_acl(&a), None);
        let old = format!("{}{}", base, OLD_ACL);
        let w = with_acl(&old).unwrap();
        assert_eq!(w.matches("acl:").count(), 1);
        assert!(w.contains("reject(192.168.0.0/16)"));
        // the admin's own ACL stays
        assert_eq!(with_acl("acl:\n  inline:\n    - direct(all)\n"), None);
    }

    #[test]
    fn the_auth_url_gets_a_key_once() {
        let conf = "listen: :8443\nauth:\n  type: http\n  http:\n    url: http://127.0.0.1:2096/hy2/auth\ntrafficStats:\n  listen: 127.0.0.1:9999\n";
        let key = "a".repeat(48);
        let (new, k) = with_auth_key(conf, &key).unwrap();
        assert_eq!(k, key);
        assert!(new.contains(&format!("    url: http://127.0.0.1:2096/hy2/auth?k={}\n", key)));
        assert_eq!(new.replace(&format!("?k={}", key), ""), conf);
        // a second time: the key already there is kept, nothing changes
        let (again, k2) = with_auth_key(&new, &"b".repeat(48)).unwrap();
        assert_eq!((again.as_str(), k2.as_str()), (new.as_str(), key.as_str()));
        // no such URL (no Hysteria, or an auth somebody else wrote): left alone
        assert!(with_auth_key("auth:\n  type: password\n  password: x\n", &key).is_none());
        assert!(with_auth_key("auth:\n  http:\n    url: https://example.net/auth\n", &key).is_none());
        // a key too short to be ours is not trusted
        assert!(with_auth_key("    url: http://127.0.0.1:1/hy2/auth?k=short\n", &key).is_none());
    }

    #[test]
    fn only_connections_that_moved_data_are_devices() {
        let mut b: HashMap<(String, u64), i64> = HashMap::new();
        // a real session and a ping of the same user
        b.insert(("hy2test-u".into(), 1), 50_000);
        b.insert(("hy2test-u".into(), 2), 200);
        assert_eq!(note_moving(&b, 1000).get("hy2test-u"), Some(&1));
        // the real one stays counted while it is idle (no stream open)
        assert_eq!(moving_known("hy2test-u", 1100), Some(1));
        assert_eq!(moving_known("hy2test-nobody", 1100), Some(0));
    }
}
