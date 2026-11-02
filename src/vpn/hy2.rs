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

/// Hysteria2 must not let its users reach this server's own loopback (the panel, the stats API and
/// the other local services listen there). Configs written before 3.22.2 have no ACL: it is added
/// once and Hysteria restarted. Blocking.
pub fn ensure_acl() {
    const CONF: &str = "/etc/hysteria/config.yaml";
    let Ok(t) = std::fs::read_to_string(CONF) else { return };
    if t.lines().any(|l| l.trim_start().starts_with("acl:")) {
        return;
    }
    let add = "acl:\n  inline:\n    - reject(127.0.0.0/8)\n    - reject(::1)\n    - reject(localhost)\n";
    let new = if t.ends_with('\n') { format!("{}{}", t, add) } else { format!("{}\n{}", t, add) };
    let was_active = std::process::Command::new("systemctl").args(["is-active", "--quiet", "hysteria-server.service"]).status().map(|s| s.success()).unwrap_or(false);
    if std::fs::write(CONF, new).is_err() {
        return;
    }
    let _ = std::process::Command::new("systemctl").args(["try-restart", "hysteria-server.service"]).status();
    std::thread::sleep(std::time::Duration::from_secs(3));
    let active = std::process::Command::new("systemctl").args(["is-active", "--quiet", "hysteria-server.service"]).status().map(|s| s.success()).unwrap_or(false);
    if was_active && !active {
        // an older Hysteria that does not take this ACL: the users come first, the old config goes back
        let _ = std::fs::write(CONF, &t);
        let _ = std::process::Command::new("systemctl").args(["restart", "hysteria-server.service"]).status();
        eprintln!("hysteria2: it did not start with the loopback ACL, the previous config is back");
        return;
    }
    eprintln!("hysteria2: its users can no longer reach this server's loopback (acl added)");
}

#[cfg(test)]
mod tests {
    use super::*;

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
