//! Subscription link on an Iran server.
//!
//! Some Iranian ISPs block the panel's domain, so the subscription is also served from a tunnel server
//! inside Iran: https://<domain>:<port>/sub/<code>. The panel builds a hidden Kanki tunnel from that
//! server (entry) to the panel server (exit) that carries a local port there to the panel's web
//! listener. The agent there gets SSL for the domain with certbot and runs an HTTPS listener that
//! sends each request through the tunnel. Like the separate subscription domain, only the
//! subscription pages, the config downloads and the assets pass; the admin panel does not.
use crate::api::err;
use crate::guard;
use crate::tunnel::engine::{parse_ports, Spec};
use crate::tunnel::panel::Tunnel;
use crate::util::{rand_token, sha256_hex};
use crate::App;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

type St = State<Arc<App>>;

/// id of the hidden tunnel
const TUNNEL_ID: &str = "subiran";
/// local port on the Iran server that reaches the panel (when no tunnel of the admin does already)
const LOCAL_PORT: u16 = 10855;
const DEFAULT_PORT: u16 = 2053;
/// the hidden tunnel's port on the Iran server (the next free one is taken)
const TUNNEL_PORT: u16 = 8447;
/// paths that are served (the same as on the separate subscription domain)
const PUBLIC: &[&str] = &["/sub/", "/api/config/", "/assets/"];

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(default)]
pub struct SubIran {
    /// the tunnel server inside Iran (empty = off)
    pub server: String,
    pub domain: String,
    pub port: u16,
    /// the hidden tunnel's listening port on that server
    pub tunnel_port: u16,
    pub token: String,
    /// the server served HTTPS once: subscription links use it from then on
    pub ready: bool,
}

/// What the agent of the Iran server runs.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(default)]
pub struct SubCfg {
    pub domain: String,
    pub port: u16,
    /// where the panel is reached on that server ("127.0.0.1:<port>", through the tunnel)
    pub upstream: String,
}

pub fn settings(app: &App) -> SubIran {
    serde_json::from_str(&app.db.get("sub_iran")).unwrap_or_default()
}

fn save(app: &App, s: &SubIran) {
    app.db.set("sub_iran", &serde_json::to_string(s).unwrap_or_default());
}

/// The server was removed from the panel: the subscription is no longer served from it.
pub(crate) fn forget_server(app: &App, id: &str) {
    let s = settings(app);
    if s.server == id {
        save(app, &SubIran { token: s.token, tunnel_port: s.tunnel_port, ..Default::default() });
    }
}

fn on(s: &SubIran) -> bool {
    !s.server.is_empty() && !s.domain.is_empty() && s.port > 0
}

/// https://domain, with the port unless it is 443
pub fn link_base(domain: &str, port: u16) -> String {
    if port == 443 || port == 0 { format!("https://{}", domain) } else { format!("https://{}:{}", domain, port) }
}

/// Base of the subscription links when the Iran server serves them (None = not set up or not ready yet).
pub fn origin(app: &App) -> Option<String> {
    let s = settings(app);
    (on(&s) && s.ready).then(|| link_base(&s.domain, s.port))
}

/// Where the panel's web listener is, from the panel server itself.
fn panel_target(app: &App) -> (String, u16) {
    let bind = app.env.get("PANEL_BIND").map(|s| s.trim().to_string()).unwrap_or_default();
    let host = if bind.is_empty() || bind == "0.0.0.0" || bind == "::" || bind == "[::]" { "127.0.0.1".to_string() } else { bind };
    let port = app.env.get("PANEL_PORT").and_then(|p| p.trim().parse().ok()).unwrap_or(8080);
    (host, port)
}

/// The local port on server `sid` of an enabled Kanki tunnel of the admin from there to the panel
/// server that already carries the panel's web port.
pub fn reuse_port(list: &[Tunnel], sid: &str, host: &str, port: u16) -> Option<u16> {
    list.iter()
        .filter(|t| t.enabled && t.kind.is_empty() && t.entry == sid && t.exit == "local")
        .filter(|t| {
            let tg = t.target.trim();
            tg.is_empty() || tg == host || tg == "127.0.0.1" || tg == "localhost"
        })
        .find_map(|t| parse_ports(&t.tcp).into_iter().find(|(_, b)| *b == port).map(|(a, _)| a))
}

fn upstream_port(app: &App, s: &SubIran) -> u16 {
    let (host, port) = panel_target(app);
    reuse_port(&crate::tunnel::panel::kanki_tunnels(app), &s.server, &host, port).unwrap_or(LOCAL_PORT)
}

/// The hidden tunnel from the Iran server to the panel, for server `sid` ("local" = the panel).
pub fn specs(app: &App, sid: &str) -> Vec<Spec> {
    let s = settings(app);
    if !on(&s) || (sid != s.server && sid != "local") {
        return vec![];
    }
    let (host, port) = panel_target(app);
    if reuse_port(&crate::tunnel::panel::kanki_tunnels(app), &s.server, &host, port).is_some() {
        return vec![];
    }
    let role = if sid == "local" { "exit" } else { "entry" };
    // reverse: the Iran server (entry) listens, the panel dials it
    let remote = if role == "exit" { crate::tunnel::panel::dial_addr(app, &s.server, s.tunnel_port) } else { String::new() };
    vec![Spec {
        id: TUNNEL_ID.into(),
        name: "Subscription on the Iran server".into(),
        role: role.into(),
        mode: "reverse".into(),
        transport: "tcpmux".into(),
        port: s.tunnel_port,
        remote,
        token: s.token.clone(),
        conns: 4,
        path: "/".into(),
        tcp: vec![format!("{}:{}", LOCAL_PORT, port)],
        target: host,
        bind: "127.0.0.1".into(),
        ..Default::default()
    }]
}

/// The listener config for the agent of server `sid` (Null = none there).
pub fn cfg_for(app: &App, sid: &str) -> Value {
    let s = settings(app);
    if !on(&s) || s.server != sid {
        return Value::Null;
    }
    json!(SubCfg { domain: s.domain.clone(), port: s.port, upstream: format!("127.0.0.1:{}", upstream_port(app, &s)) })
}

fn last_status() -> &'static Mutex<HashMap<String, Value>> {
    static S: OnceLock<Mutex<HashMap<String, Value>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(HashMap::new()))
}

/// What the agent of server `sid` reported about the listener.
pub fn ingest(app: &App, sid: &str, st: &Value) {
    last_status().lock().unwrap().insert(sid.to_string(), st.clone());
    let s = settings(app);
    if on(&s) && !s.ready && s.server == sid && st["active"].as_bool() == Some(true) && st["domain"].as_str() == Some(s.domain.as_str()) && st["port"].as_u64() == Some(s.port as u64) {
        save(app, &SubIran { ready: true, ..s });
    }
}

/// TCP ports the other tunnels, Kanki DNS and the emergency chat use on server `sid`.
fn taken_ports(app: &App, sid: &str) -> Vec<u16> {
    let mut v = vec![80];
    for s in crate::tunnel::panel::specs_of(app, sid).iter().filter(|s| s.id != TUNNEL_ID) {
        if s.listens() && s.port > 0 {
            v.push(s.port);
        }
        if s.role == "entry" {
            v.extend(parse_ports(&s.tcp).into_iter().map(|(a, _)| a));
        }
    }
    if let Some((c, _)) = crate::dns::panel::cfg_for(app, sid) {
        v.extend([c.dns_port, c.dot_port, c.https_port, c.http_port]);
    }
    if app.db.get("emer_server") == sid {
        if let Some((c, _)) = crate::tunnel::panel::emer_cfg(app) {
            v.push(c.port);
        }
    }
    v
}

// ------------------------------------------------------------------ admin API

pub fn router() -> Router<Arc<App>> {
    Router::new().route("/api/sub-iran", get(get_cfg).put(put_cfg))
}

async fn get_cfg(State(app): St, h: HeaderMap) -> Response {
    let _ = guard!(app, h, "settings");
    let s = settings(&app);
    let names = crate::tunnel::panel::server_names(&app);
    let locs = crate::tunnel::panel::server_locs(&app);
    let mut agents: Vec<Value> = names
        .iter()
        .map(|(k, v)| json!({ "id": k, "name": v, "ip": crate::tunnel::panel::seen_ip(k).unwrap_or_default(), "loc": locs.get(k).map(|x| x.0.clone()).unwrap_or_default() }))
        .collect();
    agents.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    let status = last_status().lock().unwrap().get(&s.server).cloned().unwrap_or(Value::Null);
    let reused = on(&s) && upstream_port(&app, &s) != LOCAL_PORT;
    let links = |sid: &str| crate::tunnel::panel::links_of(sid, TUNNEL_ID);
    let tunnel = if !on(&s) { "" } else if reused { "reused" } else if links(&s.server) > 0 && links("local") > 0 { "up" } else { "down" };
    Json(json!({
        "server": s.server, "domain": s.domain, "port": if s.port == 0 { DEFAULT_PORT } else { s.port }, "ready": s.ready,
        "link": if on(&s) { link_base(&s.domain, s.port) } else { String::new() },
        "agents": agents, "status": status, "tunnel": tunnel,
    }))
    .into_response()
}

async fn put_cfg(State(app): St, h: HeaderMap, Json(b): Json<Value>) -> Response {
    let _ = guard!(app, h, "settings");
    let mut s = settings(&app);
    let server = b["server"].as_str().unwrap_or("").trim().to_string();
    let raw = b["domain"].as_str().unwrap_or("").trim().to_ascii_lowercase();
    let domain = raw.trim_start_matches("https://").trim_start_matches("http://").trim_end_matches('/').to_string();
    // empty = off
    if server.is_empty() || domain.is_empty() {
        save(&app, &SubIran { token: s.token, tunnel_port: s.tunnel_port, ..Default::default() });
        return Json(json!({ "ok": true })).into_response();
    }
    if !crate::tunnel::panel::server_names(&app).contains_key(&server) {
        return err(StatusCode::BAD_REQUEST, "pick a tunnel server (add it first in Servers with its one-line install command)");
    }
    if domain.len() > 253 || !crate::certbot::valid_domain(&domain) {
        return err(StatusCode::BAD_REQUEST, "Write a domain like sub.example.com (English letters; use the punycode form for a Persian domain)");
    }
    let port = b["port"].as_u64().or_else(|| b["port"].as_str().and_then(|p| p.trim().parse().ok())).unwrap_or(DEFAULT_PORT as u64);
    if !(1..=65535).contains(&port) {
        return err(StatusCode::BAD_REQUEST, "the port is a number from 1 to 65535");
    }
    let port = port as u16;
    let taken = taken_ports(&app, &server);
    if taken.contains(&port) || port == LOCAL_PORT {
        return err(StatusCode::BAD_REQUEST, &format!("port {} is already used on that server (another tunnel, Kanki DNS or the SSL check on port 80); pick another one", port));
    }
    let changed = s.server != server || s.domain != domain || s.port != port;
    // live: a program on that server already listens there (the subscription listener itself does not count)
    if s.server != server || s.port != port {
        if let Some(e) = crate::tunnel::panel::port_busy(&app, &server, port, false, &[]) {
            return err(StatusCode::CONFLICT, &e);
        }
    }
    if s.server != server || s.tunnel_port == 0 || taken.contains(&s.tunnel_port) {
        s.tunnel_port = (TUNNEL_PORT..TUNNEL_PORT + 100).find(|p| !taken.contains(p) && *p != port).unwrap_or(TUNNEL_PORT);
    }
    if s.token.is_empty() {
        s.token = sha256_hex(&rand_token(40))[..40].to_string();
    }
    s.server = server;
    s.domain = domain;
    s.port = port;
    if changed {
        s.ready = false;
    }
    save(&app, &s);
    Json(json!({ "ok": true })).into_response()
}

// ------------------------------------------------------------------ the listener (run by the agent)

const CACHE: &str = "/var/lib/kanki/subsrv.json";
/// marks the listener as a user of its domain's certificate (it reloads a renewed one by itself)
const SSL_USER: &str = "kanki-subsrv";

/// The HTTPS listener of the agent: started, changed and stopped from the panel's answer.
#[derive(Default)]
pub struct Runner {
    cfg: Option<SubCfg>,
    task: Option<tokio::task::JoinHandle<()>>,
    status: Arc<Mutex<Value>>,
}

impl Runner {
    /// The last config the panel sent (kept on disk, so the link works after a reboot without the panel).
    pub fn from_disk() -> Runner {
        let mut r = Runner::default();
        if let Some(c) = std::fs::read_to_string(CACHE).ok().and_then(|t| serde_json::from_str::<SubCfg>(&t).ok()) {
            r.apply(Some(c));
        }
        r
    }

    pub fn apply(&mut self, want: Option<SubCfg>) {
        if want == self.cfg {
            return;
        }
        if let Some(t) = self.task.take() {
            t.abort();
        }
        *self.status.lock().unwrap() = Value::Null;
        match &want {
            Some(c) => {
                eprintln!("subscription: https://{}:{}", c.domain, c.port);
                let _ = std::fs::write(CACHE, serde_json::to_string(c).unwrap_or_default());
                self.task = Some(tokio::spawn(serve(c.clone(), self.status.clone())));
            }
            None => {
                let _ = std::fs::remove_file(CACHE);
            }
        }
        // the old listener's port is closed and its certificate is no longer renewed here
        if let Some(old) = &self.cfg {
            let same_domain = want.as_ref().map(|w| w.domain == old.domain).unwrap_or(false);
            let (d, keep) = (old.domain.clone(), want.as_ref().map(|w| w.port));
            tokio::task::spawn_blocking(move || {
                match keep {
                    Some(p) => crate::fw::sync("subsrv", vec![crate::fw::rule(p, false)]),
                    None => crate::fw::close("subsrv"),
                }
                if !same_domain {
                    crate::certbot::forget(&d, SSL_USER);
                }
            });
        }
        self.cfg = want;
    }

    /// Null when there is no listener here
    pub fn status(&self) -> Value {
        self.status.lock().unwrap().clone()
    }
}

fn acceptor(domain: &str) -> Result<tokio_rustls::TlsAcceptor, String> {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    let (cf, kf) = crate::certbot::files(domain);
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(&cf).map_err(|e| format!("{}: {:?}", cf, e))?.filter_map(|c| c.ok()).collect();
    if certs.is_empty() {
        return Err(format!("no certificate in {}", cf));
    }
    let key = PrivateKeyDer::from_pem_file(&kf).map_err(|e| format!("{}: {:?}", kf, e))?;
    let mut c = rustls::ServerConfig::builder_with_provider(crate::tunnel::link::provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| e.to_string())?;
    c.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(tokio_rustls::TlsAcceptor::from(Arc::new(c)))
}

fn cert_stamp(domain: &str) -> Option<std::time::SystemTime> {
    std::fs::metadata(crate::certbot::files(domain).0).and_then(|m| m.modified()).ok()
}

async fn serve(c: SubCfg, status: Arc<Mutex<Value>>) {
    let set = |active: bool, ssl: bool, error: &str| {
        *status.lock().unwrap() = json!({ "active": active, "ssl": ssl, "domain": c.domain, "port": c.port, "error": error });
    };
    loop {
        // SSL first: certbot frees port 80 by itself, and waits after a failure before it tries again
        let d = c.domain.clone();
        let r = tokio::task::spawn_blocking(move || crate::certbot::ensure(&d, &[SSL_USER])).await.unwrap_or_else(|e| Err(e.to_string()));
        let acc = match r.and_then(|_| acceptor(&c.domain)) {
            Ok(a) => a,
            Err(e) => {
                set(false, false, &e);
                tokio::time::sleep(Duration::from_secs(60)).await;
                continue;
            }
        };
        let l = match tokio::net::TcpListener::bind(("0.0.0.0", c.port)).await {
            Ok(l) => l,
            Err(e) => {
                set(false, true, &format!("port {}: {}", c.port, e));
                tokio::time::sleep(Duration::from_secs(30)).await;
                continue;
            }
        };
        let port = c.port;
        let _ = tokio::task::spawn_blocking(move || crate::fw::sync("subsrv", vec![crate::fw::rule(port, false)])).await;
        set(true, true, "");
        let mut acc = acc;
        let mut stamp = cert_stamp(&c.domain);
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        let busy = Arc::new(tokio::sync::Semaphore::new(1024));
        loop {
            tokio::select! {
                a = l.accept() => {
                    let Ok((tcp, peer)) = a else { continue };
                    let Ok(permit) = busy.clone().try_acquire_owned() else { continue };
                    let (acc, up) = (acc.clone(), c.upstream.clone());
                    tokio::spawn(async move {
                        let _ = handle(tcp, peer.ip().to_string(), acc, &up).await;
                        drop(permit);
                    });
                }
                _ = tick.tick() => {
                    // a renewed certificate: new connections get it
                    let now = cert_stamp(&c.domain);
                    if now != stamp {
                        match acceptor(&c.domain) {
                            Ok(a) => {
                                acc = a;
                                stamp = now;
                                eprintln!("subscription: certificate of {} reloaded", c.domain);
                            }
                            Err(e) => eprintln!("subscription: {}", e),
                        }
                    }
                }
            }
        }
    }
}

/// true for the paths served on the Iran server
pub fn allowed_path(target: &str) -> bool {
    let path = target.split('?').next().unwrap_or("");
    PUBLIC.iter().any(|p| path.starts_with(p)) && !path.contains("..") && !path.contains("//") && !path.contains('%') && !path.contains('\\')
}

/// The request head sent on to the panel, or None when it is not a subscription request. One request
/// per connection: the panel closes it after the answer, so a second request cannot slip through.
pub fn proxy_head(head: &str, client: &str) -> Option<String> {
    let mut lines = head.split("\r\n");
    let mut first = lines.next()?.split(' ');
    let (method, target, ver) = (first.next()?, first.next()?, first.next()?);
    if first.next().is_some() || !(method == "GET" || method == "HEAD") || !ver.starts_with("HTTP/1.") || !allowed_path(target) {
        return None;
    }
    let mut out = format!("{} {} {}\r\n", method, target, ver);
    for l in lines.filter(|l| !l.is_empty()) {
        // a bare CR or LF inside a line is a line break to the panel's HTTP parser: it would carry a header
        // past the filter below (an X-Forwarded-For of the sender's choosing skips the request limits)
        if l.starts_with(' ') || l.starts_with('\t') || l.contains('\n') || l.contains('\r') {
            return None;
        }
        let name = l.split(':').next().unwrap_or("").trim().to_ascii_lowercase();
        if ["connection", "keep-alive", "proxy-connection", "upgrade", "x-forwarded-for", "x-forwarded-proto", "x-real-ip", "forwarded", "te", "transfer-encoding", "content-length"].contains(&name.as_str()) {
            continue;
        }
        out.push_str(l);
        out.push_str("\r\n");
    }
    out.push_str(&format!("X-Forwarded-For: {}\r\nX-Forwarded-Proto: https\r\nConnection: close\r\n\r\n", client));
    Some(out)
}

async fn handle(tcp: tokio::net::TcpStream, client: String, acc: tokio_rustls::TlsAcceptor, upstream: &str) -> Result<(), String> {
    let mut tls = tokio::time::timeout(Duration::from_secs(10), acc.accept(tcp)).await.map_err(|_| "tls timeout")?.map_err(|e| e.to_string())?;
    // the request head
    let mut buf = Vec::with_capacity(2048);
    let mut tmp = [0u8; 4096];
    let end = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                return Ok(i + 4);
            }
            if buf.len() > 16384 {
                return Err("head too big".to_string());
            }
            let n = tls.read(&mut tmp).await.map_err(|e| e.to_string())?;
            if n == 0 {
                return Err("closed".to_string());
            }
            buf.extend_from_slice(&tmp[..n]);
        }
    })
    .await
    .map_err(|_| "read timeout")??;
    let reply = |code: &str| format!("HTTP/1.1 {}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", code, code.len(), code);
    let Some(head) = std::str::from_utf8(&buf[..end]).ok().and_then(|h| proxy_head(h, &client)) else {
        let _ = tls.write_all(reply("404 Not Found").as_bytes()).await;
        let _ = tls.shutdown().await;
        return Ok(());
    };
    let mut up = match tokio::time::timeout(Duration::from_secs(10), tokio::net::TcpStream::connect(upstream)).await {
        Ok(Ok(s)) => s,
        _ => {
            let _ = tls.write_all(reply("502 Bad Gateway").as_bytes()).await;
            let _ = tls.shutdown().await;
            return Err("the tunnel to the panel is down".into());
        }
    };
    up.write_all(head.as_bytes()).await.map_err(|e| e.to_string())?;
    // the answer goes back as it comes; GET has no body, so nothing more is sent to the panel
    let (mut ur, _uw) = up.into_split();
    let _ = tokio::time::timeout(Duration::from_secs(600), tokio::io::copy(&mut ur, &mut tls)).await;
    let _ = tls.shutdown().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_subscription_paths_pass() {
        for p in ["/sub/abc", "/sub/abc/raw", "/sub/abc/json", "/api/config/3/wg?sub=x&node=local", "/assets/font.woff2"] {
            assert!(allowed_path(p), "{}", p);
        }
        for p in ["/", "/admin", "/api/users", "/sub", "/assets/../api/users", "/sub/%2e%2e/api/users", "//sub/x", "http://x/sub/a", "/sub/a\\..\\b"] {
            assert!(!allowed_path(p), "{}", p);
        }
    }

    #[test]
    fn head_is_rewritten_for_the_panel() {
        // a header hidden behind a bare line feed is refused (it would get past the filter)
        assert!(proxy_head("GET /sub/abc HTTP/1.1\r\nUser-Agent: x\nX-Forwarded-For: 127.0.0.1\r\n\r\n", "5.6.7.8").is_none());
        assert!(proxy_head("GET /sub/abc HTTP/1.1\r\nUser-Agent: x\rX-Forwarded-For: 127.0.0.1\r\n\r\n", "5.6.7.8").is_none());
        let h = "GET /sub/abc HTTP/1.1\r\nHost: sub.example.com:2053\r\nConnection: keep-alive\r\nX-Forwarded-For: 6.6.6.6\r\nUser-Agent: v2rayNG\r\n\r\n";
        let out = proxy_head(h, "5.6.7.8").unwrap();
        assert_eq!(out, "GET /sub/abc HTTP/1.1\r\nHost: sub.example.com:2053\r\nUser-Agent: v2rayNG\r\nX-Forwarded-For: 5.6.7.8\r\nX-Forwarded-Proto: https\r\nConnection: close\r\n\r\n");
        assert!(proxy_head("GET /admin HTTP/1.1\r\nHost: x\r\n\r\n", "1.1.1.1").is_none());
        assert!(proxy_head("POST /sub/abc HTTP/1.1\r\nHost: x\r\n\r\n", "1.1.1.1").is_none());
        assert!(proxy_head("GET /sub/abc HTTP/2\r\n\r\n", "1.1.1.1").is_none());
        assert!(proxy_head("GET /sub/abc HTTP/1.1\r\nHost: x\r\n folded\r\n\r\n", "1.1.1.1").is_none());
    }

    #[test]
    fn link_base_hides_443() {
        assert_eq!(link_base("sub.kanki.pro", 2053), "https://sub.kanki.pro:2053");
        assert_eq!(link_base("sub.kanki.pro", 443), "https://sub.kanki.pro");
    }

    #[test]
    fn an_existing_tunnel_to_the_panel_is_reused() {
        let t = |entry: &str, exit: &str, tcp: &str, target: &str, enabled: bool| Tunnel {
            entry: entry.into(), exit: exit.into(), tcp: vec![tcp.into()], target: target.into(), enabled, ..Default::default()
        };
        let list = vec![t("ir", "local", "443:443", "", true), t("ir", "local", "9080:8080", "1.2.3.4", true), t("ir", "de", "9081:8080", "", true)];
        assert_eq!(reuse_port(&list, "ir", "127.0.0.1", 8080), None);
        let list = vec![t("ir", "local", "9080:8080", "", false), t("ir", "local", "2000,9090:8080", "127.0.0.1", true)];
        assert_eq!(reuse_port(&list, "ir", "127.0.0.1", 8080), Some(9090));
        assert_eq!(reuse_port(&list, "other", "127.0.0.1", 8080), None);
    }
}
