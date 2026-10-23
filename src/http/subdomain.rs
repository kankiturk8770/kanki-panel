//! Separate subscription domain.
//!
//! The panel adds a second site to the Caddyfile for the domain the admin typed. Caddy gets its SSL
//! certificate by itself (Let's Encrypt, HTTP-01 on port 80 / TLS-ALPN on 443) and serves ONLY the
//! subscription page, the config downloads and the font on it; the admin panel is not reachable
//! through that domain. When the certificate cannot be obtained, the old Caddyfile is put back, so a
//! wrong domain never breaks the panel.
//!
//! Servers added while this domain was the panel's link address (before 3.9) were given it as the
//! panel's address: the agent and join paths (all checked by their own tokens) are passed on too, so
//! those servers reach the panel.
use crate::api::err;
use crate::guard;
use crate::App;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

type St = State<Arc<App>>;

const CADDYFILE: &str = "/etc/caddy/Caddyfile";
const BEGIN: &str = "# kanki-sub begin";
const END: &str = "# kanki-sub end";

pub fn router() -> Router<Arc<App>> {
    Router::new().route("/api/sub-domain", get(status).post(apply))
}

fn valid_domain(d: &str) -> bool {
    if d.len() < 4 || d.len() > 253 || !d.contains('.') || d.parse::<std::net::IpAddr>().is_ok() {
        return false;
    }
    d.split('.').all(|l| {
        !l.is_empty() && l.len() <= 63 && !l.starts_with('-') && !l.ends_with('-') && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    })
}

fn block(domain: &str, port: &str) -> String {
    format!(
        "{b}\n{d} {{\n  @pub path /sub/* /api/config/* /assets/* /tunnel/* /join/* /dl/*\n  handle @pub {{\n    reverse_proxy 127.0.0.1:{p}\n  }}\n  handle {{\n    respond 404\n  }}\n  header {{\n    Strict-Transport-Security \"max-age=31536000\"\n    X-Content-Type-Options nosniff\n    Referrer-Policy no-referrer\n    -Server\n  }}\n}}\n{e}\n",
        b = BEGIN, d = domain, p = port, e = END
    )
}

/// New Caddyfile text. `Some(domain)`: our block is (re)written and automatic HTTPS is switched on
/// (the main site keeps using its own certificate files, so it is not affected). `None`: our block is
/// removed and the installer's `auto_https off` comes back.
fn build(old: &str, domain: Option<&str>, port: &str) -> String {
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
        if skip {
            continue;
        }
        if domain.is_some() && t == "auto_https off" {
            s.push_str("  auto_https disable_redirects\n");
        } else if domain.is_none() && t == "auto_https disable_redirects" {
            s.push_str("  auto_https off\n");
        } else {
            s.push_str(l);
            s.push('\n');
        }
    }
    if let Some(d) = domain {
        while s.ends_with("\n\n") {
            s.pop();
        }
        s.push('\n');
        s.push_str(&block(d, port));
    }
    s
}

fn run(cmd: &str, args: &[&str]) -> (bool, String) {
    match Command::new(cmd).args(args).output() {
        Ok(o) => (
            o.status.success(),
            format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr)).trim().to_string(),
        ),
        Err(e) => (false, e.to_string()),
    }
}

fn tail(s: &str) -> String {
    let v: Vec<&str> = s.lines().rev().take(5).collect();
    v.into_iter().rev().collect::<Vec<_>>().join(" | ")
}

fn reload() -> Result<(), String> {
    let (ok, _) = run("systemctl", &["reload", "caddy"]);
    if ok {
        return Ok(());
    }
    let (ok, out) = run("systemctl", &["restart", "caddy"]);
    if ok { Ok(()) } else { Err(format!("Caddy did not start: {}", tail(&out))) }
}

fn write_and_reload(content: &str) -> Result<(), String> {
    std::fs::write(CADDYFILE, content).map_err(|e| format!("cannot write {}: {}", CADDYFILE, e))?;
    let (ok, out) = run("caddy", &["validate", "--config", CADDYFILE, "--adapter", "caddyfile"]);
    if !ok {
        return Err(format!("Caddy rejected the new config: {}", tail(&out)));
    }
    reload()
}

fn restore(old: &str) {
    let _ = std::fs::write(CADDYFILE, old);
    let _ = reload();
}

fn open_firewall() {
    let _ = Command::new("sh")
        .args(["-c", "command -v ufw >/dev/null 2>&1 && ufw status | grep -q '^Status: active' && { ufw allow 80/tcp; ufw allow 443/tcp; } >/dev/null 2>&1; true"])
        .status();
}

/// Waits until Caddy answers on 443 for this name with a certificate that browsers trust.
async fn wait_tls(domain: &str) -> bool {
    let addr: SocketAddr = match "127.0.0.1:443".parse() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let client = match reqwest::Client::builder()
        .resolve(domain, addr)
        .connect_timeout(Duration::from_secs(4))
        .timeout(Duration::from_secs(6))
        .build()
    {
        Ok(c) => c,
        Err(_) => return false,
    };
    let url = format!("https://{}/sub/x", domain);
    for _ in 0..15 {
        tokio::time::sleep(Duration::from_secs(4)).await;
        if client.get(&url).send().await.is_ok() {
            return true;
        }
    }
    false
}

fn caddy_error() -> String {
    let (_, out) = run("journalctl", &["-u", "caddy", "-n", "80", "--no-pager"]);
    let l = out.lines().rev().find(|l| l.contains("error")).unwrap_or("").to_string();
    l.chars().rev().take(320).collect::<Vec<_>>().into_iter().rev().collect()
}

/// At start: the subscription domain is set but the Caddyfile has no (or an older) block for it — after
/// a restore or a move the installer wrote a fresh Caddyfile — so it is written again.
pub fn ensure_on_start(app: &App) {
    let d = app.db.get("sub_domain").trim().to_string();
    let Some(port) = app.env.get("PANEL_PORT").map(|s| s.trim().to_string()).filter(|s| !s.is_empty()) else { return };
    let Ok(old) = std::fs::read_to_string(CADDYFILE) else { return };
    if d.is_empty() || !valid_domain(&d) {
        return;
    }
    let new = build(&old, Some(&d), &port);
    if new == old {
        return;
    }
    match write_and_reload(&new) {
        Ok(()) => eprintln!("subscription domain {}: Caddy site written again", d),
        Err(e) => {
            eprintln!("subscription domain {}: {}", d, e);
            restore(&old);
        }
    }
}

async fn status(State(app): St, h: HeaderMap) -> Response {
    let _ = guard!(app, h, "settings");
    let cf = std::fs::read_to_string(CADDYFILE).unwrap_or_default();
    Json(json!({ "domain": app.db.get("sub_domain"), "caddy": !cf.is_empty(), "in_caddyfile": cf.contains(BEGIN) })).into_response()
}

async fn apply(State(app): St, h: HeaderMap, Json(b): Json<Value>) -> Response {
    let _ = guard!(app, h, "settings");
    let raw = b.get("domain").and_then(|v| v.as_str()).unwrap_or("").trim().to_lowercase();
    let d = raw.trim_start_matches("https://").trim_start_matches("http://").trim_end_matches('/').to_string();
    let port = app.env.get("PANEL_PORT").map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    let Some(port) = port else {
        return err(StatusCode::BAD_REQUEST, "PANEL_PORT is not set: this works only on the main panel server");
    };
    let old = match std::fs::read_to_string(CADDYFILE) {
        Ok(s) => s,
        Err(_) => return err(StatusCode::BAD_REQUEST, "Caddy is not installed here (no /etc/caddy/Caddyfile). This needs the standard install of the panel"),
    };

    // empty = remove
    if d.is_empty() {
        let new = build(&old, None, &port);
        let r = tokio::task::spawn_blocking(move || write_and_reload(&new)).await.unwrap_or_else(|e| Err(e.to_string()));
        if let Err(e) = r {
            let o = old.clone();
            let _ = tokio::task::spawn_blocking(move || restore(&o)).await;
            return err(StatusCode::INTERNAL_SERVER_ERROR, &e);
        }
        app.db.set("sub_domain", "");
        return Json(json!({ "ok": true, "domain": "" })).into_response();
    }

    if !valid_domain(&d) {
        return err(StatusCode::BAD_REQUEST, "Write a domain like sub.example.ir (English letters; use the punycode form for a Persian domain)");
    }
    if d == app.env.get("DOMAIN").map(|s| s.trim().to_lowercase()).unwrap_or_default() {
        return err(StatusCode::BAD_REQUEST, "This is the panel's own domain. Use another domain for the subscription links");
    }
    if tokio::net::lookup_host((d.as_str(), 443)).await.map(|mut it| it.next().is_none()).unwrap_or(true) {
        return err(StatusCode::BAD_REQUEST, "The domain does not resolve yet. Add an A record that points to this server's IP, wait a few minutes and try again");
    }

    let new = build(&old, Some(&d), &port);
    let r = tokio::task::spawn_blocking(move || write_and_reload(&new)).await.unwrap_or_else(|e| Err(e.to_string()));
    if let Err(e) = r {
        let o = old.clone();
        let _ = tokio::task::spawn_blocking(move || restore(&o)).await;
        return err(StatusCode::INTERNAL_SERVER_ERROR, &e);
    }
    let _ = tokio::task::spawn_blocking(open_firewall).await;

    if !wait_tls(&d).await {
        let detail = tokio::task::spawn_blocking(caddy_error).await.unwrap_or_default();
        let o = old.clone();
        let _ = tokio::task::spawn_blocking(move || restore(&o)).await;
        return err(
            StatusCode::BAD_GATEWAY,
            &format!(
                "No SSL certificate was issued, nothing was changed. The domain must point DIRECTLY (no CDN / proxy) to this server and ports 80 and 443 must be open and free. {}",
                detail
            ),
        );
    }
    app.db.set("sub_domain", &d);
    Json(json!({ "ok": true, "domain": d })).into_response()
}
