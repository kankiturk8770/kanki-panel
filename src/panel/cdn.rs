//! The panel's CDN domain: a second way for the servers' agents to reach the panel.
//!
//! When the panel server's IP is filtered in Iran, the tunnel agents of the Iran servers cannot report
//! to it any more (the tunnels themselves keep working: the panel dials them). The admin puts a second
//! domain behind a CDN (Cloudflare, orange cloud, SSL mode «Full») that points at this server. The panel
//! adds a Caddy site for it that passes ONLY the agents' paths (`/tunnel/*`) to the panel; the admin
//! panel, the API and the subscription are not reachable through it. Caddy shows the panel's own
//! certificate there (the CDN in «Full» mode does not check the name), so nothing has to be issued.
//!
//! Every agent is told this address in each answer (`panel_alt`) and keeps it on disk; when the panel's
//! own address stops answering it talks through the CDN and tries the direct address again every few
//! minutes (`tunnel::agent`).
use crate::api::err;
use crate::guard;
use crate::App;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde_json::{json, Value};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

type St = State<Arc<App>>;

const CADDYFILE: &str = "/etc/caddy/Caddyfile";
const BEGIN: &str = "# kanki-cdn begin";
const END: &str = "# kanki-cdn end";
/// setting: the CDN domain ("" = none)
pub const KEY: &str = "panel_cdn";
/// setting: the port its Caddy site listens on
const PORT_KEY: &str = "panel_cdn_port";
/// the HTTPS ports Cloudflare passes on to the origin
pub const CDN_PORTS: [u16; 6] = [443, 2053, 2083, 2087, 2096, 8443];

pub fn router() -> Router<Arc<App>> {
    Router::new().route("/api/panel-cdn", get(status).post(apply))
}

/// The address the agents use through the CDN, or None
pub fn url(app: &App) -> Option<String> {
    let d = app.db.get(KEY).trim().to_string();
    if d.is_empty() {
        return None;
    }
    let p: u16 = app.db.get(PORT_KEY).parse().unwrap_or(443);
    Some(if p == 443 { format!("https://{}", d) } else { format!("https://{}:{}", d, p) })
}

/// The request came in through the CDN domain (its Host): the address it came from is a CDN edge, not
/// the server's own
pub fn came_through(app: &App, h: &HeaderMap) -> bool {
    let d = app.db.get(KEY).trim().to_lowercase();
    if d.is_empty() {
        return false;
    }
    let host = h.get("host").and_then(|v| v.to_str().ok()).unwrap_or("").trim().to_lowercase();
    let name = host.rsplit_once(':').filter(|(_, p)| p.chars().all(|c| c.is_ascii_digit())).map(|(n, _)| n.to_string()).unwrap_or(host);
    name == d
}

/// The port of the main site of the Caddyfile and its certificate files: (port, "cert key")
fn main_site(cf: &str) -> Option<(u16, String)> {
    let mut port = None;
    let mut tls = None;
    let mut skip = false;
    for l in cf.lines() {
        let t = l.trim();
        if t.starts_with("# kanki-") && t.ends_with(" begin") {
            skip = true;
            continue;
        }
        if t.starts_with("# kanki-") && t.ends_with(" end") {
            skip = false;
            continue;
        }
        if skip {
            continue;
        }
        // "panel.example.com:2053 {" at the top level
        if port.is_none() && !l.starts_with(' ') && !l.starts_with('\t') && t.ends_with('{') && t != "{" {
            let addr = t.trim_end_matches('{').trim();
            port = Some(addr.rsplit_once(':').and_then(|(_, p)| p.parse::<u16>().ok()).unwrap_or(443));
        }
        if tls.is_none() && port.is_some() {
            if let Some(rest) = t.strip_prefix("tls ") {
                let parts: Vec<&str> = rest.split_whitespace().collect();
                if parts.len() == 2 && parts.iter().all(|p| p.starts_with('/')) {
                    tls = Some(format!("{} {}", parts[0], parts[1]));
                }
            }
        }
    }
    Some((port?, tls?))
}

fn block(domain: &str, port: u16, tls: &str, upstream: &str) -> String {
    format!(
        "{b}\n{d}:{port} {{\n  tls {tls}\n  @agent path /tunnel/*\n  handle @agent {{\n    reverse_proxy 127.0.0.1:{u}\n  }}\n  handle {{\n    respond 404\n  }}\n  header {{\n    -Server\n  }}\n}}\n{e}\n",
        b = BEGIN, d = domain, port = port, tls = tls, u = upstream, e = END
    )
}

/// The Caddyfile with our block (re)written, or taken out with `None`; everything else stays as it was
fn build(old: &str, add: Option<&str>) -> String {
    let mut skip = false;
    let mut s = String::new();
    for l in old.lines() {
        let t = l.trim();
        if t == BEGIN {
            skip = true;
            continue;
        }
        if t == END {
            skip = false;
            continue;
        }
        if !skip {
            s.push_str(l);
            s.push('\n');
        }
    }
    while s.ends_with("\n\n") {
        s.pop();
    }
    if let Some(b) = add {
        s.push('\n');
        s.push_str(b);
    }
    s
}

/// The port the CDN site listens on: the panel's own HTTPS port when the CDN passes it on, else the first
/// of the CDN's ports that is free here
fn pick_port(main: u16) -> Option<u16> {
    if CDN_PORTS.contains(&main) {
        return Some(main);
    }
    CDN_PORTS.iter().copied().find(|p| std::net::TcpListener::bind(("0.0.0.0", *p)).is_ok())
}

fn run(cmd: &str, args: &[&str]) -> (bool, String) {
    match Command::new(cmd).args(args).output() {
        Ok(o) => (o.status.success(), format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr)).trim().to_string()),
        Err(e) => (false, e.to_string()),
    }
}

fn tail(s: &str) -> String {
    let v: Vec<&str> = s.lines().rev().take(4).collect();
    v.into_iter().rev().collect::<Vec<_>>().join(" | ")
}

fn write_and_reload(content: &str) -> Result<(), String> {
    std::fs::write(CADDYFILE, content).map_err(|e| format!("cannot write {}: {}", CADDYFILE, e))?;
    let (ok, out) = run("caddy", &["validate", "--config", CADDYFILE, "--adapter", "caddyfile"]);
    if !ok {
        return Err(format!("Caddy rejected the new config: {}", tail(&out)));
    }
    if run("systemctl", &["reload", "caddy"]).0 {
        return Ok(());
    }
    let (ok, out) = run("systemctl", &["restart", "caddy"]);
    if ok { Ok(()) } else { Err(format!("Caddy did not start: {}", tail(&out))) }
}

fn restore(old: &str) {
    let _ = std::fs::write(CADDYFILE, old);
    let _ = run("systemctl", &["reload", "caddy"]);
}

fn open_firewall(port: u16) {
    let _ = Command::new("sh")
        .args(["-c", &format!("command -v ufw >/dev/null 2>&1 && ufw status | grep -q '^Status: active' && ufw allow {}/tcp >/dev/null 2>&1; true", port)])
        .status();
}

/// Caddy answers the agents' path for this name on this machine (the panel says 405 to a GET there)
async fn answers(domain: &str, port: u16) -> bool {
    let Ok(addr) = format!("127.0.0.1:{}", port).parse::<std::net::SocketAddr>() else { return false };
    let Ok(c) = reqwest::Client::builder().resolve(domain, addr).danger_accept_invalid_certs(true).no_proxy().timeout(Duration::from_secs(5)).build() else { return false };
    for _ in 0..5 {
        if let Ok(r) = c.get(format!("https://{}:{}/tunnel/agent", domain, port)).send().await {
            return r.status() == StatusCode::METHOD_NOT_ALLOWED;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    false
}

/// Through the CDN from here (the panel server reaches the CDN like anybody else): None = could not tell
async fn through_cdn(u: &str) -> Option<bool> {
    let c = reqwest::Client::builder().timeout(Duration::from_secs(8)).build().ok()?;
    match c.get(format!("{}/tunnel/agent", u)).send().await {
        Ok(r) => Some(r.status() == StatusCode::METHOD_NOT_ALLOWED),
        Err(_) => Some(false),
    }
}

/// At start: the CDN domain is set but the Caddyfile has no block for it (a restore or a move wrote a fresh
/// Caddyfile), so it is written again
pub fn ensure_on_start(app: &App) {
    let d = app.db.get(KEY).trim().to_string();
    let Some(up) = app.env.get("PANEL_PORT").map(|s| s.trim().to_string()).filter(|s| !s.is_empty()) else { return };
    let Ok(old) = std::fs::read_to_string(CADDYFILE) else { return };
    if d.is_empty() || !crate::subdomain::valid_domain(&d) {
        return;
    }
    let Some((main, tls)) = main_site(&old) else { return };
    let saved: u16 = app.db.get(PORT_KEY).parse().unwrap_or(0);
    let port = if CDN_PORTS.contains(&main) { main } else if saved > 0 { saved } else { return };
    let new = build(&old, Some(&block(&d, port, &tls, &up)));
    if new == old {
        return;
    }
    match write_and_reload(&new) {
        Ok(()) => {
            open_firewall(port);
            app.db.set(PORT_KEY, &port.to_string());
            eprintln!("panel CDN domain {}: Caddy site written again", d)
        }
        Err(e) => {
            eprintln!("panel CDN domain {}: {}", d, e);
            restore(&old);
        }
    }
}

async fn status(State(app): St, h: HeaderMap) -> Response {
    let _ = guard!(app, h, "settings");
    let cf = std::fs::read_to_string(CADDYFILE).unwrap_or_default();
    Json(json!({ "domain": app.db.get(KEY), "url": url(&app), "caddy": !cf.is_empty(), "in_caddyfile": cf.contains(BEGIN) })).into_response()
}

async fn apply(State(app): St, h: HeaderMap, Json(b): Json<Value>) -> Response {
    let _ = guard!(app, h, "settings");
    let raw = b.get("domain").and_then(|v| v.as_str()).unwrap_or("").trim().to_lowercase();
    let d = raw.trim_start_matches("https://").trim_start_matches("http://").trim_end_matches('/').to_string();
    let Some(up) = app.env.get("PANEL_PORT").map(|s| s.trim().to_string()).filter(|s| !s.is_empty()) else {
        return err(StatusCode::BAD_REQUEST, "PANEL_PORT is not set: this works only on the main panel server");
    };
    let old = match std::fs::read_to_string(CADDYFILE) {
        Ok(s) => s,
        Err(_) => return err(StatusCode::BAD_REQUEST, "Caddy is not installed here (no /etc/caddy/Caddyfile). This needs the standard install of the panel"),
    };
    if d.is_empty() {
        let new = build(&old, None);
        let r = tokio::task::spawn_blocking(move || write_and_reload(&new)).await.unwrap_or_else(|e| Err(e.to_string()));
        if let Err(e) = r {
            let o = old.clone();
            let _ = tokio::task::spawn_blocking(move || restore(&o)).await;
            return err(StatusCode::INTERNAL_SERVER_ERROR, &e);
        }
        app.db.set(KEY, "");
        return Json(json!({ "ok": true, "domain": "", "url": Value::Null })).into_response();
    }
    if !crate::subdomain::valid_domain(&d) {
        return err(StatusCode::BAD_REQUEST, "Write a domain like cdn.example.com (English letters; use the punycode form for a Persian domain)");
    }
    let own = app.env.get("DOMAIN").map(|s| s.trim().to_lowercase()).unwrap_or_default();
    if d == own || d == app.db.get("sub_domain").trim().to_lowercase() {
        return err(StatusCode::BAD_REQUEST, "Use a domain of its own for the CDN, not the panel's domain or the subscription domain");
    }
    let Some((main, tls)) = main_site(&old) else {
        return err(StatusCode::BAD_REQUEST, "The panel's site in the Caddyfile has no certificate files. This needs the standard install of the panel");
    };
    let Some(port) = pick_port(main) else {
        return err(StatusCode::BAD_REQUEST, "None of the CDN's HTTPS ports (443, 2053, 2083, 2087, 2096, 8443) is free on this server");
    };
    let new = build(&old, Some(&block(&d, port, &tls, &up)));
    let r = tokio::task::spawn_blocking(move || write_and_reload(&new)).await.unwrap_or_else(|e| Err(e.to_string()));
    if let Err(e) = r {
        let o = old.clone();
        let _ = tokio::task::spawn_blocking(move || restore(&o)).await;
        return err(StatusCode::INTERNAL_SERVER_ERROR, &e);
    }
    if !answers(&d, port).await {
        let o = old.clone();
        let _ = tokio::task::spawn_blocking(move || restore(&o)).await;
        return err(StatusCode::BAD_GATEWAY, "Caddy did not answer for this domain; nothing was changed");
    }
    let _ = tokio::task::spawn_blocking(move || open_firewall(port)).await;
    app.db.set(KEY, &d);
    app.db.set(PORT_KEY, &port.to_string());
    let u = url(&app).unwrap_or_default();
    let via = through_cdn(&u).await;
    Json(json!({ "ok": true, "domain": d, "url": u, "port": port, "through_cdn": via })).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    const CF: &str = "{\n  auto_https off\n}\npanel.example.com:2053 {\n  tls /etc/kanki/tls/fullchain.pem /etc/kanki/tls/privkey.pem\n  reverse_proxy 127.0.0.1:18080\n}\n# kanki-sub begin\nsub.example.ir {\n  respond 404\n}\n# kanki-sub end\n";

    #[test]
    fn the_cdn_site_passes_only_the_agents_and_leaves_the_rest() {
        let (port, tls) = main_site(CF).unwrap();
        assert_eq!(port, 2053);
        assert_eq!(tls, "/etc/kanki/tls/fullchain.pem /etc/kanki/tls/privkey.pem");
        let b = block("cdn.example.net", port, &tls, "18080");
        let new = build(CF, Some(&b));
        assert!(new.starts_with(CF.trim_end()));
        assert!(new.contains("cdn.example.net:2053 {") && new.contains("@agent path /tunnel/*") && new.contains("respond 404"));
        // written again: one block, not two
        assert_eq!(build(&new, Some(&b)), new);
        // taken out: the file as it was
        assert_eq!(build(&new, None), CF);
        // the CDN's ports: the panel's own when it passes, else another
        assert_eq!(pick_port(2053), Some(2053));
        assert!(CDN_PORTS.contains(&pick_port(18443).unwrap()));
    }

    #[test]
    fn only_the_cdn_host_counts_as_through_the_cdn() {
        let app = crate::kping::tests::test_app();
        let h = |v: &str| {
            let mut m = HeaderMap::new();
            m.insert("host", v.parse().unwrap());
            m
        };
        assert!(!came_through(&app, &h("cdn.example.net")));
        app.db.set(KEY, "cdn.example.net");
        assert!(came_through(&app, &h("cdn.example.net")));
        assert!(came_through(&app, &h("CDN.example.net:2053")));
        assert!(!came_through(&app, &h("panel.example.com:2053")));
        assert_eq!(url(&app).as_deref(), Some("https://cdn.example.net"));
        app.db.set(PORT_KEY, "2053");
        assert_eq!(url(&app).as_deref(), Some("https://cdn.example.net:2053"));
    }
}
