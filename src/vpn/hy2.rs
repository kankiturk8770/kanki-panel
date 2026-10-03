//! Hysteria2: traffic stats API (auth is handled over HTTP in api.rs)
use std::collections::HashMap;

/// Per-user traffic since last call (clear=1)
pub async fn traffic(port: &str, secret: &str) -> HashMap<String, (i64, i64)> {
    let mut m = HashMap::new();
    if port.is_empty() {
        return m;
    }
    let url = format!("http://127.0.0.1:{}/traffic?clear=1", port);
    if let Ok(r) = reqwest::Client::new().get(&url).header("Authorization", secret).send().await {
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
    if let Ok(r) = reqwest::Client::new().get(&url).header("Authorization", secret).send().await {
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
    let _ = reqwest::Client::new().post(&url).header("Authorization", secret).json(&ids).send().await;
}
