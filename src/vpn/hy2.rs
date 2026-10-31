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
