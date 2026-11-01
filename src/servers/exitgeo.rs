//! Where each VPN server's traffic really leaves to the internet (its exit IP, country and city),
//! for the Kanki app's map and server list.
//!
//! A config reached through a tunnel has an endpoint on a server inside Iran, so the app cannot
//! tell the country from the endpoint. The traffic of a WireGuard / AmneziaWG / Hysteria2 config
//! leaves from the VPN server (node) itself, so the exit is the node's own public address: the
//! panel server for "local", the host of the agent address for the others. The country and city
//! are looked up from this side (outside Iran) and kept in the settings table, so building a
//! subscription page never waits on the network.
//!
//! Xray servers are looked up the same way (keyed "xray:<server id>"), from the server itself or
//! from the server everything goes on to.

use crate::db::Node;
use crate::App;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;

const KEY: &str = "exit_geo";
/// a looked-up address is checked again after this long (an IP rarely moves country)
const TTL: i64 = 7 * 24 * 3600;

/// node id -> {ip, cc, city, lat, lon, ts}
fn cache(app: &App) -> serde_json::Map<String, Value> {
    serde_json::from_str::<Value>(&app.db.get(KEY)).ok().and_then(|v| v.as_object().cloned()).unwrap_or_default()
}

/// Forgets what is known about a removed server (its keys: the node id, "srv:<id>", "xray:<id>").
pub fn forget(app: &App, keys: &[String]) {
    let mut c = cache(app);
    let n = c.len();
    for k in keys {
        c.remove(k);
    }
    if c.len() != n {
        app.db.set(KEY, &Value::Object(c).to_string());
    }
}

/// The cache key of an Xray server
pub fn xray_key(sid: &str) -> String {
    format!("xray:{}", sid)
}

/// The cache key of a tunnel server
pub fn srv_key(sid: &str) -> String {
    format!("srv:{}", sid)
}

/// The country code (like "DE", "IR") of a node ("<id>"), an Xray server ("xray:<id>") or a tunnel
/// server ("srv:<id>"); empty while unknown.
pub fn cc(app: &App, key: &str) -> String {
    cache(app).get(key).and_then(|e| e["cc"].as_str().map(|s| s.to_string())).unwrap_or_default()
}

/// Every country code known, by cache key (one read for a whole list)
pub fn all_cc(app: &App) -> std::collections::HashMap<String, String> {
    cache(app).into_iter().filter_map(|(k, e)| e["cc"].as_str().map(|c| (k, c.to_string()))).collect()
}

/// The exit fields one node adds to the app's subscription data (empty strings while unknown).
pub fn fields(app: &App, node_id: &str) -> Value {
    let c = cache(app);
    let e = c.get(node_id).cloned().unwrap_or(Value::Null);
    let s = |k: &str| e[k].as_str().unwrap_or("").to_string();
    let mut v = json!({ "exit_ip": s("ip"), "exit_cc": s("cc"), "exit_city": s("city") });
    if let (Some(lat), Some(lon)) = (e["lat"].as_f64(), e["lon"].as_f64()) {
        v["exit_lat"] = json!(lat);
        v["exit_lon"] = json!(lon);
    }
    v
}

/// The host name or IP that is this node's public address.
fn exit_host(app: &App, n: &Node) -> String {
    if n.id == "local" {
        return app.env.get("DOMAIN").cloned().unwrap_or_default().trim().to_string();
    }
    host_of_url(&n.address)
}

/// "https://1.2.3.4:2096/x" -> "1.2.3.4", "http://[::1]:80" -> "::1"
pub fn host_of_url(url: &str) -> String {
    let rest = url.trim().split("://").last().unwrap_or("");
    let hostport = rest.split('/').next().unwrap_or("");
    let hostport = hostport.rsplit('@').next().unwrap_or("");
    if let Some(v6) = hostport.strip_prefix('[') {
        return v6.split(']').next().unwrap_or("").to_string();
    }
    hostport.split(':').next().unwrap_or("").to_string()
}

/// IPv4 of a host (an IP is returned as it is)
async fn resolve_v4(host: &str) -> Option<String> {
    if host.is_empty() {
        return None;
    }
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Some(ip.to_string());
    }
    // a name server that does not answer must not hold the loop (and every server after this one)
    let it = tokio::time::timeout(Duration::from_secs(8), tokio::net::lookup_host((host, 443))).await.ok()?.ok()?;
    let all: Vec<std::net::SocketAddr> = it.collect();
    all.iter().find(|a| a.is_ipv4()).or(all.first()).map(|a| a.ip().to_string())
}

/// (country code, city, lat, lon) of an IP, from ipinfo.io over HTTPS (no plain-HTTP fallback: an answer
/// changed on the way would give a server a wrong country and flag; an IP not found now is tried again later)
async fn lookup(app: &App, ip: &str) -> Option<(String, String, Option<f64>, Option<f64>)> {
    let r = app.http.get(format!("https://ipinfo.io/{}/json", ip)).timeout(Duration::from_secs(8)).send().await.ok()?;
    if !r.status().is_success() {
        return None;
    }
    let j = r.json::<Value>().await.ok()?;
    let cc = j["country"].as_str().unwrap_or("").to_uppercase();
    if cc.len() != 2 {
        return None;
    }
    let loc: Vec<f64> = j["loc"].as_str().unwrap_or("").split(',').filter_map(|x| x.trim().parse().ok()).collect();
    let (lat, lon) = if loc.len() == 2 { (Some(loc[0]), Some(loc[1])) } else { (None, None) };
    Some((cc, j["city"].as_str().unwrap_or("").to_string(), lat, lon))
}

/// Every server the panel has now, by cache key, with its address
fn current_hosts(app: &App) -> Vec<(String, String)> {
    let mut hosts: Vec<(String, String)> = app.db.nodes().iter().map(|n| (n.id.clone(), exit_host(app, n))).collect();
    hosts.extend(crate::xray::panel::exit_hosts(app).into_iter().map(|(sid, h)| (xray_key(&sid), h)));
    // tunnel servers (Iran and abroad), for their flags in the panel
    hosts.extend(crate::tunnel::panel::server_hosts(app).into_iter().map(|(sid, h)| (srv_key(&sid), h)));
    hosts
}

/// The cache as it is now with the new answers put in; only keys of servers that still exist stay
fn merge(mut cur: serde_json::Map<String, Value>, found: serde_json::Map<String, Value>, keys: &[String]) -> serde_json::Map<String, Value> {
    for (k, v) in found {
        cur.insert(k, v);
    }
    cur.retain(|k, _| keys.iter().any(|x| x == k));
    cur
}

/// Looks up the exit of every node and Xray server whose address is new or whose answer is old.
pub async fn refresh(app: &App) {
    let c = cache(app);
    let hosts = current_hosts(app);
    let mut found = serde_json::Map::new();
    for (key, host) in &hosts {
        let Some(ip) = resolve_v4(host).await else { continue };
        let prev = c.get(key).cloned().unwrap_or(Value::Null);
        let fresh = prev["ip"].as_str() == Some(ip.as_str()) && crate::util::now() - prev["ts"].as_i64().unwrap_or(0) < TTL;
        if fresh {
            continue;
        }
        if let Some((cc, city, lat, lon)) = lookup(app, &ip).await {
            found.insert(key.clone(), json!({ "ip": ip, "cc": cc, "city": city, "lat": lat, "lon": lon, "ts": crate::util::now() }));
        }
    }
    // the lookups take a while: read the cache and the servers again, so a server removed meanwhile (and
    // what `forget` dropped) does not come back, and servers that were removed are forgotten
    let keys: Vec<String> = current_hosts(app).into_iter().map(|(k, _)| k).collect();
    let cur = cache(app);
    let next = merge(cur.clone(), found, &keys);
    if next != cur {
        app.db.set(KEY, &Value::Object(next).to_string());
    }
}

/// Keeps the exit locations up to date: soon after start, then every 10 minutes, so a new server
/// shows on the app's map soon (only new or old entries are looked up, so this costs nothing most
/// of the time).
pub async fn run(app: Arc<App>) {
    tokio::time::sleep(Duration::from_secs(20)).await;
    loop {
        refresh(&app).await;
        tokio::time::sleep(Duration::from_secs(600)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::host_of_url;
    use serde_json::json;

    #[test]
    fn a_server_removed_during_the_lookups_is_not_written_back() {
        let m = |v: serde_json::Value| v.as_object().cloned().unwrap();
        // "gone" was forgotten while looking up; "n1" got a new answer; "n2" stays as it is
        let cur = m(json!({ "n1": {"cc": "DE"}, "n2": {"cc": "FI"} }));
        let found = m(json!({ "n1": {"cc": "NL"}, "gone": {"cc": "TR"} }));
        let out = super::merge(cur, found, &["n1".to_string(), "n2".to_string()]);
        assert_eq!(serde_json::Value::Object(out), json!({ "n1": {"cc": "NL"}, "n2": {"cc": "FI"} }));
    }

    #[test]
    fn host_from_agent_address() {
        assert_eq!(host_of_url("https://de.example.com:2096"), "de.example.com");
        assert_eq!(host_of_url("http://1.2.3.4:2096/"), "1.2.3.4");
        assert_eq!(host_of_url("https://[2001:db8::1]:443/x"), "2001:db8::1");
        assert_eq!(host_of_url("tr.example.com"), "tr.example.com");
        assert_eq!(host_of_url(""), "");
        // an Xray outbound link of another server
        assert_eq!(host_of_url("vless://0f1e-uuid@se.example.com:443"), "se.example.com");
    }
}
