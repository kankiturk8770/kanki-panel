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
const PUBLIC: &[&str] = &["/sub/", "/api/config/", "/assets/", "/tg/"];

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
    /// 3.69: the key the relay signs each request's client address with (`relay_header`); "" = a panel from
    /// before (nothing is signed, the panel sees the relay's own address as before)
    pub relay_key: String,
    /// 3.72: relay Let's Encrypt's port 80 (only `/.well-known/acme-challenge/`) to the panel; false from a panel before
    pub acme: bool,
    /// 3.72: "" = terminate TLS here (as before); else where the encrypted connections go untouched (the hidden
    /// tunnel's port to the panel's TLS listener): passthrough, this server holds no certificate and sees no request
    pub passthrough: String,
}

/// The header a trusted Iran relay adds: `v1;<ts>;<nonce>;<hex HMAC>` over the client address and the request line
pub const RELAY_HEADER: &str = "x-kanki-relay";
/// How old a relayed request may be (the relay and the panel both keep their clocks with NTP)
const RELAY_SKEW: i64 = 120;

/// The relay key of the subscription relay: HMAC of its own secret (the hidden tunnel's token), never stored apart
pub fn relay_key(s: &SubIran) -> String {
    use hmac::{Hmac, Mac};
    if s.token.is_empty() {
        return String::new();
    }
    let Ok(mut m) = Hmac::<sha2::Sha256>::new_from_slice(s.token.as_bytes()) else { return String::new() };
    m.update(b"kanki-relay-key-v1");
    hex::encode(m.finalize().into_bytes())
}

fn relay_mac(key: &str, ts: i64, nonce: &str, client: &str, method: &str, target: &str) -> Option<hmac::Hmac<sha2::Sha256>> {
    use hmac::Mac;
    let mut m = hmac::Hmac::<sha2::Sha256>::new_from_slice(key.as_bytes()).ok()?;
    m.update(format!("kanki-relay-v1\n{}\n{}\n{}\n{}\n{}", ts, nonce, client, method, target).as_bytes());
    Some(m)
}

/// The value of `RELAY_HEADER` for one request
pub fn relay_header(key: &str, client: &str, method: &str, target: &str, ts: i64) -> String {
    use hmac::Mac;
    let nonce = hex::encode(rand::random::<[u8; 16]>());
    let sig = relay_mac(key, ts, &nonce, client, method, target).map(|m| hex::encode(m.finalize().into_bytes())).unwrap_or_default();
    format!("v1;{};{};{}", ts, nonce, sig)
}

/// The panel's side: the client address a relayed request carries, when its header was made with this panel's relay
/// key for exactly this request (method, path) and this address, recently and only once
pub fn verified_client(app: &App, h: &axum::http::HeaderMap, method: &str, target: &str, now: i64) -> Option<String> {
    use hmac::Mac;
    let v = h.get(RELAY_HEADER)?.to_str().ok()?;
    let key = relay_key(&settings(app));
    if key.is_empty() {
        return None;
    }
    let mut it = v.split(';');
    let (ver, ts, nonce, sig) = (it.next()?, it.next()?, it.next()?, it.next()?);
    if ver != "v1" || it.next().is_some() || nonce.len() != 32 || !nonce.bytes().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let ts: i64 = ts.parse().ok()?;
    if (now - ts).abs() > RELAY_SKEW || ts < crate::sign::floor() {
        return None;
    }
    // the address the relay named (the rightmost one: the relay adds exactly one)
    let client = h.get("x-forwarded-for")?.to_str().ok()?.split(',').next_back()?.trim().to_string();
    client.parse::<std::net::IpAddr>().ok()?;
    let sig = hex::decode(sig).ok()?;
    relay_mac(&key, ts, nonce, &client, method, target)?.verify_slice(&sig).ok()?;
    crate::sign::remember(&format!("relay-{}", nonce.to_ascii_lowercase()), ts, now).then_some(client)
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

/// Where the panel dials the hidden tunnel: the subscription domain itself. Its A record must point to the Iran
/// server for the SSL certificate, while the address set on the server for other tunnels may be another name
/// (a CDN, an old domain) the panel cannot reach the tunnel port on.
fn dial(s: &SubIran) -> String {
    format!("{}:{}", s.domain.trim(), s.tunnel_port)
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
    let remote = if role == "exit" { dial(&s) } else { String::new() };
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
        // 3.72: a second port to the panel's TLS listener once the Iran agent can pass TLS through
        tcp: if agent_passes(&s.server) { vec![format!("{}:{}", LOCAL_PORT, port), format!("{}:{}", LOCAL_TLS_PORT, PANEL_TLS_PORT)] } else { vec![format!("{}:{}", LOCAL_PORT, port)] },
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
    let m = mode(app, &s);
    json!(SubCfg {
        domain: s.domain.clone(),
        port: s.port,
        upstream: format!("127.0.0.1:{}", upstream_port(app, &s)),
        relay_key: relay_key(&s),
        acme: m != "terminate",
        passthrough: if m == "passthrough" { format!("127.0.0.1:{}", LOCAL_TLS_PORT) } else { String::new() },
    })
}

fn last_status() -> &'static Mutex<HashMap<String, Value>> {
    static S: OnceLock<Mutex<HashMap<String, Value>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(HashMap::new()))
}

/// What the agent of server `sid` reported about the listener.
pub fn ingest(app: &Arc<App>, sid: &str, st: &Value) {
    let s = settings(app);
    // 3.72: in passthrough the certificate is the panel's own: its end date is what the warning watches
    let mut st = st.clone();
    if st["mode"].as_str() == Some("passthrough") {
        if let (Some(o), serde_json::Value::Object(h)) = (st.as_object_mut(), crate::certbot::health(&s.domain)) {
            o.extend(h);
        }
    }
    let st = &st;
    last_status().lock().unwrap_or_else(|e| e.into_inner()).insert(sid.to_string(), st.clone());
    if on(&s) && s.server == sid {
        if let Some(text) = cert_warning(st, crate::util::now(), &app.db.get("subiran_cert_warned")) {
            app.db.set("subiran_cert_warned", &crate::util::now().to_string());
            let a = app.clone();
            tokio::spawn(async move { crate::backup::tell_admin(&a, &text).await });
        }
    }
    if on(&s) && !s.ready && s.server == sid && st["active"].as_bool() == Some(true) && st["domain"].as_str() == Some(s.domain.as_str()) && st["port"].as_u64() == Some(s.port as u64) {
        save(app, &SubIran { ready: true, ..s });
    }
}

/// A Telegram note for the admin when the certificate of the Iran subscription link is about to end or
/// has ended (the apps cannot read the subscription with an expired one); at most every 12 hours.
fn cert_warning(st: &Value, now: i64, last: &str) -> Option<String> {
    let end = st["cert_end"].as_i64().filter(|e| *e > 0)?;
    let days = (end - now).div_euclid(86400);
    if days >= 7 || now - last.parse::<i64>().unwrap_or(0) < 12 * 3600 {
        return None;
    }
    let domain = st["domain"].as_str().unwrap_or("");
    let why = st["renew_error"].as_str().unwrap_or("");
    let head = if end <= now {
        format!("⚠️ گواهی SSL لینک اشتراک ایران ({}) منقضی شده: اپ‌ها نمی‌توانند اشتراک را از آن بخوانند.", domain)
    } else {
        format!("⚠️ گواهی SSL لینک اشتراک ایران ({}) {} روز دیگر تمام می‌شود و هنوز تمدید نشده.", domain, days)
    };
    Some(format!(
        "{}\n{}Let's Encrypt باید از بیرون ایران به پورت 80 آن سرور برسد. بعد از رفع مشکل: پنل › تنظیمات › لینک اشتراک ایران › «دوباره گرفتن SSL».",
        head,
        if why.is_empty() { String::new() } else { format!("علت: {}\n", why) }
    ))
}

#[cfg(test)]
mod cert_tests {
    use serde_json::json;

    #[test]
    fn the_admin_hears_about_an_ending_certificate_twice_a_day_at_most() {
        let now = 1_800_000_000;
        let st = |days: i64| json!({ "domain": "s.example.com", "cert_end": now + days * 86400 + 60, "renew_error": "port 80 closed" });
        assert!(super::cert_warning(&st(30), now, "").is_none());
        let t = super::cert_warning(&st(3), now, "").unwrap();
        assert!(t.contains("3 روز") && t.contains("port 80 closed"));
        assert!(super::cert_warning(&st(-1), now, "").unwrap().contains("منقضی"));
        // told an hour ago: not again yet
        assert!(super::cert_warning(&st(-1), now, &(now - 3600).to_string()).is_none());
        assert!(super::cert_warning(&json!({ "cert_end": 0 }), now, "").is_none());
    }
}

/// TCP ports the other tunnels and Kanki DNS use on server `sid`.
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
    v
}

// ------------------------------------------------------------------ admin API

pub fn router() -> Router<Arc<App>> {
    Router::new().route("/api/sub-iran", get(get_cfg).put(put_cfg)).route("/.well-known/acme-challenge/:token", get(acme_challenge))
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
    let status = last_status().lock().unwrap_or_else(|e| e.into_inner()).get(&s.server).cloned().unwrap_or(Value::Null);
    let reused = on(&s) && upstream_port(&app, &s) != LOCAL_PORT;
    let links = |sid: &str| crate::tunnel::panel::links_of(sid, TUNNEL_ID);
    let tunnel = if !on(&s) { "" } else if reused { "reused" } else if links(&s.server) > 0 && links("local") > 0 { "up" } else { "down" };
    // why the hidden tunnel is down: each side as its own engine reports it
    let side = |sid: &str| match crate::tunnel::panel::status_of(sid, TUNNEL_ID) {
        Some(st) => json!({ "runs": true, "links": st.links, "listening": st.listening, "error": st.error }),
        None => json!({ "runs": false }),
    };
    let seen_ago = crate::tunnel::panel::agent_state(&s.server).map(|x| crate::util::now() - x.0);
    let detail = if tunnel == "down" {
        json!({
            "port": s.tunnel_port,
            "dial": dial(&s),
            "iran": side(&s.server), "panel": side("local"),
            "iran_seen": seen_ago,
        })
    } else {
        Value::Null
    };
    Json(json!({
        "server": s.server, "domain": s.domain, "port": if s.port == 0 { DEFAULT_PORT } else { s.port }, "ready": s.ready,
        "link": if on(&s) { link_base(&s.domain, s.port) } else { String::new() },
        "agents": agents, "status": status, "tunnel": tunnel, "tunnel_detail": detail,
        // 3.72: "passthrough" (zero-knowledge), "acme" (the panel is taking its certificate) or "terminate" (HMAC)
        "mode": mode(&app, &s),
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
    // the hidden tunnel to the panel already listens on that server's port (it stays while the server stays)
    if s.server == server && s.tunnel_port != 0 && port == s.tunnel_port {
        return err(StatusCode::BAD_REQUEST, &format!("port {} is used by this link's own hidden tunnel on that server; pick another one", port));
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
    acme: Option<tokio::task::JoinHandle<()>>,
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
        if let Some(t) = self.acme.take() {
            t.abort();
        }
        *self.status.lock().unwrap_or_else(|e| e.into_inner()) = Value::Null;
        match &want {
            Some(c) => {
                eprintln!("subscription: https://{}:{}", c.domain, c.port);
                let _ = std::fs::write(CACHE, serde_json::to_string(c).unwrap_or_default());
                self.task = Some(if c.passthrough.is_empty() { tokio::spawn(serve(c.clone(), self.status.clone())) } else { tokio::spawn(serve_pass(c.clone(), self.status.clone())) });
                if c.acme {
                    self.acme = Some(tokio::spawn(acme_serve(c.domain.clone(), c.upstream.clone(), self.status.clone())));
                }
            }
            None => {
                let _ = std::fs::remove_file(CACHE);
            }
        }
        // the old listener's port is closed and its certificate is no longer renewed here
        if let Some(old) = &self.cfg {
            let same_domain = want.as_ref().map(|w| w.domain == old.domain).unwrap_or(false);
            let (d, keep) = (old.domain.clone(), want.as_ref().map(|w| w.port));
            let acme_off = !want.as_ref().map(|w| w.acme).unwrap_or(false);
            tokio::task::spawn_blocking(move || {
                if acme_off {
                    crate::fw::close("subsrv-acme");
                }
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
        self.status.lock().unwrap_or_else(|e| e.into_inner()).clone()
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
        let mut v = json!({ "active": active, "ssl": ssl, "domain": c.domain, "port": c.port, "error": error });
        // when the certificate ends and why it was not renewed: an expired one looked healthy before
        if let (Some(o), Value::Object(h)) = (v.as_object_mut(), crate::certbot::health(&c.domain)) {
            o.extend(h);
        }
        *status.lock().unwrap_or_else(|e| e.into_inner()) = v;
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
        let mut ticks: u64 = 0;
        let busy = Arc::new(tokio::sync::Semaphore::new(1024));
        loop {
            tokio::select! {
                a = l.accept() => {
                    let Ok((tcp, peer)) = a else { continue };
                    let Ok(permit) = busy.clone().try_acquire_owned() else { continue };
                    let (acc, up, key) = (acc.clone(), c.upstream.clone(), c.relay_key.clone());
                    tokio::spawn(async move {
                        let _ = handle(tcp, peer.ip().to_string(), acc, &up, &key).await;
                        drop(permit);
                    });
                }
                _ = tick.tick() => {
                    ticks += 1;
                    if ticks.is_multiple_of(30) {
                        // close to its end: renew now (certbot's own timer cannot answer Let's Encrypt
                        // while nothing listens on port 80), then show the new date or the reason
                        let d = c.domain.clone();
                        let _ = tokio::task::spawn_blocking(move || crate::certbot::renew_if_due(&d)).await;
                        let d = c.domain.clone();
                        let h = tokio::task::spawn_blocking(move || crate::certbot::health(&d)).await.unwrap_or(Value::Null);
                        if let (Value::Object(o), Value::Object(h)) = (&mut *status.lock().unwrap_or_else(|e| e.into_inner()), h) {
                            o.extend(h);
                        }
                    }
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
pub fn proxy_head(head: &str, client: &str, key: &str) -> Option<String> {
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
        if ["connection", "keep-alive", "proxy-connection", "upgrade", "x-forwarded-for", "x-forwarded-proto", "x-real-ip", "forwarded", "te", "transfer-encoding", "content-length", RELAY_HEADER].contains(&name.as_str()) {
            continue;
        }
        out.push_str(l);
        out.push_str("\r\n");
    }
    out.push_str(&format!("X-Forwarded-For: {}\r\nX-Forwarded-Proto: https\r\n", client));
    // 3.69: the client's address signed for the panel, so its limits count each client, not the relay
    if !key.is_empty() {
        out.push_str(&format!("X-Kanki-Relay: {}\r\n", relay_header(key, client, method, target, crate::util::now())));
    }
    out.push_str("Connection: close\r\n\r\n");
    Some(out)
}

async fn handle(tcp: tokio::net::TcpStream, client: String, acc: tokio_rustls::TlsAcceptor, upstream: &str, key: &str) -> Result<(), String> {
    let tls = tokio::time::timeout(Duration::from_secs(10), acc.accept(tcp)).await.map_err(|_| "tls timeout")?.map_err(|e| e.to_string())?;
    relay(tls, client, upstream, key).await
}

/// Longest a relayed answer may take, and longest it may stay silent (a client that stops reading cannot
/// hold a slot of the relay)
const ANSWER_MAX: Duration = Duration::from_secs(600);
const IDLE_MAX: Duration = Duration::from_secs(60);

/// One request of an app or browser, already past TLS: its head (paths and headers checked by `proxy_head`,
/// every app header kept: X-Kanki-Sub, X-Kanki-Device, X-Kanki-Seal, Authorization) goes to the panel, the
/// answer comes back byte for byte (no redirect, no rewrite)
pub(crate) async fn relay<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(mut tls: S, client: String, upstream: &str, key: &str) -> Result<(), String> {
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
    let Some(head) = std::str::from_utf8(&buf[..end]).ok().and_then(|h| proxy_head(h, &client, key)) else {
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
    let copied = tokio::time::timeout(ANSWER_MAX, async {
        let mut buf = vec![0u8; 16 << 10];
        loop {
            let n = match tokio::time::timeout(IDLE_MAX, ur.read(&mut buf)).await {
                Ok(Ok(0)) => return Ok(()),
                Ok(Ok(n)) => n,
                Ok(Err(e)) => return Err(e.to_string()),
                Err(_) => return Err("the panel went silent".to_string()),
            };
            match tokio::time::timeout(IDLE_MAX, tls.write_all(&buf[..n])).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => return Err(e.to_string()),
                Err(_) => return Err("the client stopped reading".to_string()),
            }
        }
    })
    .await
    .map_err(|_| "answer took too long".to_string())
    .and_then(|r| r);
    if let Err(e) = tls.shutdown().await {
        if copied.is_ok() {
            return Err(e.to_string());
        }
    }
    copied
}

// ------------------------------------------------------------------ 3.72: TLS passthrough (zero-knowledge Iran relay)
//
// The Iran server no longer terminates TLS. It reads only the TLS ClientHello's server name (to drop strangers), puts a
// PROXY protocol v2 header with the client's address in front, and sends the encrypted bytes through the hidden tunnel
// to a TLS listener of the panel (loopback only, reached only through that tunnel, whose token authenticates the Iran
// server). The panel holds the certificate of the subscription domain (Let's Encrypt over the Iran server's port 80,
// which forwards only `/.well-known/acme-challenge/`), opens TLS, and sends the request on as before with the client's
// address signed (`relay`), so its limits count each client. The Iran server never sees a code, a header or a cookie.
//
// Rollout: the panel offers the new mode only to an agent of `PASS_FROM` or later; until the panel's own certificate
// for the domain exists, the agent keeps the HMAC termination (and also relays port 80 for Let's Encrypt), then the
// panel's answer switches it to passthrough. An older agent keeps the HMAC termination, which the panel still accepts.

/// the first agent version that relays TLS untouched and Let's Encrypt's port 80
pub const PASS_FROM: &str = "3.72.0";
/// on the Iran server: the hidden tunnel's local port that leads to the panel's TLS listener
const LOCAL_TLS_PORT: u16 = 10856;
/// on the panel: its TLS listener for the relay (loopback, reached only through the hidden tunnel)
pub const PANEL_TLS_PORT: u16 = 10857;

/// a.b.c >= b.b.c (a missing or odd part is 0)
fn ver_ge(a: &str, b: &str) -> bool {
    let p = |v: &str| v.trim_start_matches('v').split(['.', '-']).take(3).map(|x| x.parse::<u64>().unwrap_or(0)).collect::<Vec<_>>();
    p(a) >= p(b)
}

/// Does the Iran server's agent relay TLS untouched (reported version `PASS_FROM` or later)?
fn agent_passes(sid: &str) -> bool {
    crate::tunnel::panel::agent_state(sid).map(|x| ver_ge(&x.1, PASS_FROM)).unwrap_or(false)
}

/// The panel's own certificate of the subscription domain exists and has more than 3 days left
fn panel_cert_ok(domain: &str) -> bool {
    crate::certbot::have(domain) && crate::certbot::not_after(domain).map(|e| e > crate::util::now() + 3 * 86400).unwrap_or(false)
}

/// The mode of the relay: "passthrough", "acme" (the agent relays port 80 while the panel takes its certificate) or
/// "terminate" (the HMAC termination of 3.69, for an older agent or when the admin's own tunnel carries the panel)
pub fn mode(app: &App, s: &SubIran) -> &'static str {
    if !on(s) || !agent_passes(&s.server) || upstream_port(app, s) != LOCAL_PORT {
        "terminate"
    } else if panel_cert_ok(&s.domain) {
        "passthrough"
    } else {
        "acme"
    }
}

/// PROXY protocol v2 header: PROXY command, TCP over IPv4 or IPv6, `src` -> `dst`
pub fn proxy_v2(src: std::net::SocketAddr, dst: std::net::SocketAddr) -> Vec<u8> {
    let mut v = b"\r\n\r\n\0\r\nQUIT\n".to_vec();
    v.push(0x21);
    match (src, dst) {
        (std::net::SocketAddr::V4(a), std::net::SocketAddr::V4(b)) => {
            v.push(0x11);
            v.extend_from_slice(&12u16.to_be_bytes());
            v.extend_from_slice(&a.ip().octets());
            v.extend_from_slice(&b.ip().octets());
            v.extend_from_slice(&a.port().to_be_bytes());
            v.extend_from_slice(&b.port().to_be_bytes());
        }
        _ => {
            let six = |x: std::net::SocketAddr| match x {
                std::net::SocketAddr::V4(a) => a.ip().to_ipv6_mapped(),
                std::net::SocketAddr::V6(a) => *a.ip(),
            };
            v.push(0x21);
            v.extend_from_slice(&36u16.to_be_bytes());
            v.extend_from_slice(&six(src).octets());
            v.extend_from_slice(&six(dst).octets());
            v.extend_from_slice(&src.port().to_be_bytes());
            v.extend_from_slice(&dst.port().to_be_bytes());
        }
    }
    v
}

/// Reads a PROXY protocol v2 header and gives the client's address (an IPv4-mapped IPv6 address as IPv4). Only the
/// PROXY command over TCP is taken: LOCAL, UDP, UNIX, v1 text or anything malformed is an error (the connection drops).
pub async fn read_proxy_v2<R: tokio::io::AsyncRead + Unpin>(r: &mut R) -> Result<std::net::IpAddr, String> {
    let mut h = [0u8; 16];
    r.read_exact(&mut h).await.map_err(|e| e.to_string())?;
    if &h[..12] != b"\r\n\r\n\0\r\nQUIT\n" || h[12] != 0x21 {
        return Err("not a PROXY v2 header".into());
    }
    let len = u16::from_be_bytes([h[14], h[15]]) as usize;
    if len > 216 {
        return Err("PROXY header too long".into());
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).await.map_err(|e| e.to_string())?;
    match h[13] {
        0x11 if len >= 12 => Ok(std::net::IpAddr::from([body[0], body[1], body[2], body[3]])),
        0x21 if len >= 36 => {
            let mut a = [0u8; 16];
            a.copy_from_slice(&body[..16]);
            let ip = std::net::Ipv6Addr::from(a);
            Ok(ip.to_ipv4_mapped().map(std::net::IpAddr::V4).unwrap_or(std::net::IpAddr::V6(ip)))
        }
        _ => Err("PROXY header: only TCP over IPv4 / IPv6".into()),
    }
}

/// The server name of a TLS ClientHello in `b` (the first record), None when `b` is not one or has none
pub fn sni_of(b: &[u8]) -> Option<String> {
    // record: type 22 (handshake), version, length
    if b.len() < 5 || b[0] != 22 {
        return None;
    }
    let rl = u16::from_be_bytes([b[3], b[4]]) as usize;
    let rec = b.get(5..5 + rl)?;
    // handshake: type 1 (ClientHello), 3-byte length
    if rec.len() < 4 || rec[0] != 1 {
        return None;
    }
    let mut i = 4 + 2 + 32;
    let sid = *rec.get(i)? as usize;
    i += 1 + sid;
    let cs = u16::from_be_bytes([*rec.get(i)?, *rec.get(i + 1)?]) as usize;
    i += 2 + cs;
    let cm = *rec.get(i)? as usize;
    i += 1 + cm;
    let el = u16::from_be_bytes([*rec.get(i)?, *rec.get(i + 1)?]) as usize;
    i += 2;
    let ext = rec.get(i..i + el)?;
    let mut j = 0;
    while j + 4 <= ext.len() {
        let t = u16::from_be_bytes([ext[j], ext[j + 1]]);
        let l = u16::from_be_bytes([ext[j + 2], ext[j + 3]]) as usize;
        let d = ext.get(j + 4..j + 4 + l)?;
        if t == 0 {
            // server_name_list: length, then (type 0 = host_name, length, name)
            if d.len() < 5 || d[2] != 0 {
                return None;
            }
            let nl = u16::from_be_bytes([d[3], d[4]]) as usize;
            let name = std::str::from_utf8(d.get(5..5 + nl)?).ok()?;
            return Some(name.to_ascii_lowercase());
        }
        j += 4 + l;
    }
    None
}

/// Reads the first TLS record (the ClientHello) from a client: (bytes read, its server name)
async fn read_hello<R: tokio::io::AsyncRead + Unpin>(r: &mut R) -> Result<(Vec<u8>, Option<String>), String> {
    let mut b = vec![0u8; 5];
    r.read_exact(&mut b).await.map_err(|e| e.to_string())?;
    if b[0] != 22 {
        return Err("not TLS".into());
    }
    let rl = u16::from_be_bytes([b[3], b[4]]) as usize;
    if rl > 16 * 1024 + 256 {
        return Err("record too long".into());
    }
    b.resize(5 + rl, 0);
    r.read_exact(&mut b[5..]).await.map_err(|e| e.to_string())?;
    let name = sni_of(&b);
    Ok((b, name))
}

/// One client on the Iran server in passthrough mode: its ClientHello must name the subscription domain; then the
/// PROXY header and every byte go to the panel's TLS listener, and back, untouched (never decrypted here).
pub(crate) async fn pass_one(mut tcp: tokio::net::TcpStream, domain: &str, upstream: &str) -> Result<(), String> {
    let peer = tcp.peer_addr().map_err(|e| e.to_string())?;
    let local = tcp.local_addr().map_err(|e| e.to_string())?;
    let (hello, name) = tokio::time::timeout(Duration::from_secs(10), read_hello(&mut tcp)).await.map_err(|_| "hello timeout")??;
    if name.as_deref() != Some(domain.trim().to_ascii_lowercase().as_str()) {
        return Err("another server name".into());
    }
    let mut up = tokio::time::timeout(Duration::from_secs(10), tokio::net::TcpStream::connect(upstream)).await.map_err(|_| "panel timeout")?.map_err(|e| e.to_string())?;
    let mut first = proxy_v2(peer, local);
    first.extend_from_slice(&hello);
    up.write_all(&first).await.map_err(|e| e.to_string())?;
    match tokio::time::timeout(ANSWER_MAX, tokio::io::copy_bidirectional(&mut tcp, &mut up)).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => Err("connection took too long".into()),
    }
}

/// Let's Encrypt on the Iran server's port 80: only `GET /.well-known/acme-challenge/<token>` goes on to the panel
/// (plain HTTP through the hidden tunnel; the panel answers from its webroot); anything else gets 404
pub(crate) async fn acme_one<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(mut c: S, domain: &str, upstream: &str) -> Result<(), String> {
    let mut buf = Vec::with_capacity(1024);
    let mut tmp = [0u8; 1024];
    let read = tokio::time::timeout(Duration::from_secs(5), async {
        while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
            if buf.len() > 4096 {
                return Err("head too big".to_string());
            }
            let n = c.read(&mut tmp).await.map_err(|e| e.to_string())?;
            if n == 0 {
                return Err("closed".to_string());
            }
            buf.extend_from_slice(&tmp[..n]);
        }
        Ok(())
    })
    .await;
    let token = match read {
        Ok(Ok(())) => std::str::from_utf8(&buf).ok().and_then(|h| {
            let mut f = h.lines().next()?.split(' ');
            let (m, t) = (f.next()?, f.next()?);
            let tok = t.strip_prefix("/.well-known/acme-challenge/")?;
            (m == "GET" && !tok.is_empty() && tok.len() <= 128 && tok.bytes().all(|x| x.is_ascii_alphanumeric() || x == b'-' || x == b'_')).then(|| tok.to_string())
        }),
        _ => None,
    };
    let Some(tok) = token else {
        let _ = c.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await;
        return Ok(());
    };
    let mut up = tokio::time::timeout(Duration::from_secs(10), tokio::net::TcpStream::connect(upstream)).await.map_err(|_| "panel timeout")?.map_err(|e| e.to_string())?;
    up.write_all(format!("GET /.well-known/acme-challenge/{} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", tok, domain).as_bytes()).await.map_err(|e| e.to_string())?;
    let mut ans = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), (&mut up).take(65536).read_to_end(&mut ans)).await.map_err(|_| "panel silent")?.map_err(|e| e.to_string())?;
    c.write_all(&ans).await.map_err(|e| e.to_string())?;
    c.shutdown().await.map_err(|e| e.to_string())
}

/// The relay's port 80 for Let's Encrypt (agent): runs while the panel wants it; an error (port 80 taken) is reported
async fn acme_serve(domain: String, upstream: String, status: Arc<Mutex<Value>>) {
    let l = match tokio::net::TcpListener::bind(("0.0.0.0", 80)).await {
        Ok(l) => l,
        Err(e) => {
            if let Value::Object(o) = &mut *status.lock().unwrap_or_else(|e| e.into_inner()) {
                o.insert("acme".into(), json!(format!("port 80: {}", e)));
            }
            return;
        }
    };
    if let Err(e) = tokio::task::spawn_blocking(|| crate::fw::sync("subsrv-acme", vec![crate::fw::rule(80, false)])).await {
        eprintln!("subscription: firewall: {}", e);
    }
    if let Value::Object(o) = &mut *status.lock().unwrap_or_else(|e| e.into_inner()) {
        o.insert("acme".into(), json!("on"));
    }
    let busy = Arc::new(tokio::sync::Semaphore::new(64));
    loop {
        let Ok((c, _)) = l.accept().await else { continue };
        let Ok(permit) = busy.clone().try_acquire_owned() else { continue };
        let (d, u) = (domain.clone(), upstream.clone());
        tokio::spawn(async move {
            if let Err(e) = acme_one(c, &d, &u).await {
                eprintln!("subscription: port 80: {}", e);
            }
            drop(permit);
        });
    }
}

/// The agent in passthrough mode: no certificate here, the encrypted connections go to the panel
async fn serve_pass(c: SubCfg, status: Arc<Mutex<Value>>) {
    // the certificate this server took before is not needed (or renewed) any more
    let d = c.domain.clone();
    if let Err(e) = tokio::task::spawn_blocking(move || crate::certbot::forget(&d, SSL_USER)).await {
        eprintln!("subscription: {}", e);
    }
    loop {
        let l = match tokio::net::TcpListener::bind(("0.0.0.0", c.port)).await {
            Ok(l) => l,
            Err(e) => {
                *status.lock().unwrap_or_else(|e| e.into_inner()) = json!({ "active": false, "ssl": true, "mode": "passthrough", "domain": c.domain, "port": c.port, "error": format!("port {}: {}", c.port, e) });
                tokio::time::sleep(Duration::from_secs(30)).await;
                continue;
            }
        };
        let port = c.port;
        if let Err(e) = tokio::task::spawn_blocking(move || crate::fw::sync("subsrv", vec![crate::fw::rule(port, false)])).await {
            eprintln!("subscription: firewall: {}", e);
        }
        *status.lock().unwrap_or_else(|e| e.into_inner()) = json!({ "active": true, "ssl": true, "mode": "passthrough", "domain": c.domain, "port": c.port, "error": "" });
        let busy = Arc::new(tokio::sync::Semaphore::new(1024));
        loop {
            let Ok((tcp, _)) = l.accept().await else { continue };
            let Ok(permit) = busy.clone().try_acquire_owned() else { continue };
            let (d, up) = (c.domain.clone(), c.passthrough.clone());
            tokio::spawn(async move {
                if let Err(e) = pass_one(tcp, &d, &up).await {
                    if e != "another server name" {
                        eprintln!("subscription: {}", e);
                    }
                }
                drop(permit);
            });
        }
    }
}

// ------------------------------------------------------------------ the panel's side of the passthrough

/// The panel's TLS listener for the relay: only from this machine (the hidden tunnel delivers here), a PROXY v2 header
/// first (5 s), then TLS with the panel's certificate of the subscription domain, then the request like any relayed one
async fn panel_tls_one(app: Arc<App>, tcp: tokio::net::TcpStream, acc: tokio_rustls::TlsAcceptor) -> Result<(), String> {
    let peer = tcp.peer_addr().map_err(|e| e.to_string())?;
    let (host, port) = panel_target(&app);
    // the pinned allowlist: only the local end of the authenticated hidden tunnel reaches this port
    let allowed = peer.ip().is_loopback() || host.parse::<std::net::IpAddr>().map(|h| h == peer.ip()).unwrap_or(false);
    if !allowed {
        return Err(format!("{} is not the relay's tunnel", peer.ip()));
    }
    let mut tcp = tcp;
    let client = tokio::time::timeout(Duration::from_secs(5), read_proxy_v2(&mut tcp)).await.map_err(|_| "PROXY header timeout")??;
    let tls = tokio::time::timeout(Duration::from_secs(10), acc.accept(tcp)).await.map_err(|_| "tls timeout")?.map_err(|e| e.to_string())?;
    let key = relay_key(&settings(&app));
    relay(tls, client.to_string(), &format!("{}:{}", host, port), &key).await
}

/// Runs on the panel: takes the certificate of the subscription domain through the relay's port 80, and listens for
/// the relay's encrypted connections while the relay is in passthrough (or about to be). Checked every minute.
pub async fn panel_loop(app: Arc<App>) {
    let acc: Arc<std::sync::RwLock<Option<tokio_rustls::TlsAcceptor>>> = Arc::new(std::sync::RwLock::new(None));
    let mut listening: Option<tokio::task::JoinHandle<()>> = None;
    let mut stamp: Option<(String, Option<std::time::SystemTime>)> = None;
    let mut tick = tokio::time::interval(Duration::from_secs(60));
    loop {
        tick.tick().await;
        let s = settings(&app);
        let m = mode(&app, &s);
        if m == "terminate" {
            if let Some(t) = listening.take() {
                t.abort();
            }
            continue;
        }
        if !panel_cert_ok(&s.domain) {
            let d = s.domain.clone();
            match tokio::task::spawn_blocking(move || crate::certbot::ensure_webroot(&d)).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => eprintln!("subscription relay: {}", e),
                Err(e) => eprintln!("subscription relay: {}", e),
            }
        }
        if !crate::certbot::have(&s.domain) {
            continue;
        }
        // a new or renewed certificate: new connections get it
        let now = cert_stamp(&s.domain);
        if stamp.as_ref() != Some(&(s.domain.clone(), now)) {
            match acceptor(&s.domain) {
                Ok(a) => {
                    *acc.write().unwrap_or_else(|e| e.into_inner()) = Some(a);
                    stamp = Some((s.domain.clone(), now));
                }
                Err(e) => {
                    eprintln!("subscription relay: {}", e);
                    continue;
                }
            }
        }
        if listening.as_ref().map(|t| t.is_finished()).unwrap_or(true) {
            let (host, _) = panel_target(&app);
            let l = match tokio::net::TcpListener::bind((host.as_str(), PANEL_TLS_PORT)).await {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("subscription relay: {}:{}: {}", host, PANEL_TLS_PORT, e);
                    continue;
                }
            };
            let (a2, acc2) = (app.clone(), acc.clone());
            listening = Some(tokio::spawn(async move {
                let busy = Arc::new(tokio::sync::Semaphore::new(1024));
                loop {
                    let Ok((tcp, _)) = l.accept().await else { continue };
                    let Some(a) = acc2.read().unwrap_or_else(|e| e.into_inner()).clone() else { continue };
                    let Ok(permit) = busy.clone().try_acquire_owned() else { continue };
                    let app = a2.clone();
                    tokio::spawn(async move {
                        if let Err(e) = panel_tls_one(app, tcp, a).await {
                            eprintln!("subscription relay: {}", e);
                        }
                        drop(permit);
                    });
                }
            }));
        }
    }
}

/// `GET /.well-known/acme-challenge/<token>`: the panel's answer to Let's Encrypt for the relay's domain (the Iran
/// server's port 80 forwards only these requests here)
async fn acme_challenge(axum::extract::Path(token): axum::extract::Path<String>) -> Response {
    match crate::certbot::challenge(&format!("/.well-known/acme-challenge/{}", token)) {
        Some(t) => ([(axum::http::header::CONTENT_TYPE, "text/plain")], t).into_response(),
        None => (StatusCode::NOT_FOUND, "").into_response(),
    }
}

#[cfg(test)]
mod pass_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const NAME: &str = "sub.example.test";

    #[tokio::test]
    async fn proxy_v2_carries_the_client_and_nothing_else_is_taken() {
        let a: std::net::SocketAddr = "203.0.113.9:51000".parse().unwrap();
        let b: std::net::SocketAddr = "198.51.100.2:2053".parse().unwrap();
        let mut h = proxy_v2(a, b);
        h.extend_from_slice(b"rest");
        let mut r = &h[..];
        assert_eq!(read_proxy_v2(&mut r).await.unwrap().to_string(), "203.0.113.9");
        assert_eq!(r, b"rest", "only the header is read");
        let a6: std::net::SocketAddr = "[2001:db8::7]:1".parse().unwrap();
        let h6 = proxy_v2(a6, b);
        assert_eq!(read_proxy_v2(&mut &h6[..]).await.unwrap().to_string(), "2001:db8::7");
        // v1 text, LOCAL, UDP, a too long body, a cut one: refused
        assert!(read_proxy_v2(&mut &b"PROXY TCP4 1.2.3.4 5.6.7.8 1 2\r\n"[..]).await.is_err());
        let mut local = proxy_v2(a, b);
        local[12] = 0x20;
        assert!(read_proxy_v2(&mut &local[..]).await.is_err());
        let mut udp = proxy_v2(a, b);
        udp[13] = 0x12;
        assert!(read_proxy_v2(&mut &udp[..]).await.is_err());
        let mut long = proxy_v2(a, b);
        long[14] = 0xff;
        assert!(read_proxy_v2(&mut &long[..]).await.is_err());
        assert!(read_proxy_v2(&mut &proxy_v2(a, b)[..20]).await.is_err());
        assert!(ver_ge("3.72.0", PASS_FROM) && ver_ge("v3.80.1", PASS_FROM) && !ver_ge("3.71.9", PASS_FROM) && !ver_ge("", PASS_FROM));
    }

    fn server_tls() -> (tokio_rustls::TlsAcceptor, rustls::pki_types::CertificateDer<'static>) {
        let ck = rcgen::generate_simple_self_signed(vec![NAME.to_string()]).unwrap();
        let cert = rustls::pki_types::CertificateDer::from(ck.cert.der().to_vec());
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der()));
        let mut c = rustls::ServerConfig::builder_with_provider(crate::tunnel::link::provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.clone()], key)
            .unwrap();
        c.alpn_protocols = vec![b"http/1.1".to_vec()];
        (tokio_rustls::TlsAcceptor::from(Arc::new(c)), cert)
    }

    fn client(cert: rustls::pki_types::CertificateDer<'static>) -> tokio_rustls::TlsConnector {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert).unwrap();
        let c = rustls::ClientConfig::builder_with_provider(crate::tunnel::link::provider()).with_safe_default_protocol_versions().unwrap().with_root_certificates(roots).with_no_client_auth();
        tokio_rustls::TlsConnector::from(Arc::new(c))
    }

    /// The Iran relay in passthrough: the panel opens TLS, the relay passes only encrypted bytes after the PROXY
    /// header (no code, no header, no path readable there), a wrong server name or a missing PROXY header gets nothing
    #[tokio::test]
    async fn the_iran_relay_passes_tls_untouched_and_the_panel_answers() {
        // the panel's web listener
        let web = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let web_port = web.local_addr().unwrap().port();
        let app = crate::test_app_env(&[("PANEL_PORT", &web_port.to_string())]);
        let router = crate::api::master_router(app.clone());
        tokio::spawn(async move {
            let _ = axum::serve(web, router.into_make_service_with_connect_info::<std::net::SocketAddr>()).await;
        });
        save(&app, &SubIran { server: "ir1".into(), domain: NAME.into(), port: 2053, token: "relay-tunnel-token-0123456789".into(), ..Default::default() });
        let u = app.db.create_user("passuser", 0.0, 0, 1, "wg", "", "", 0).unwrap();
        // the panel's TLS listener for the relay
        let (acc, cert) = server_tls();
        let ptls = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ptls_addr = ptls.local_addr().unwrap().to_string();
        let a2 = app.clone();
        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = ptls.accept().await else { break };
                let (app, acc) = (a2.clone(), acc.clone());
                tokio::spawn(async move {
                    let _ = panel_tls_one(app, tcp, acc).await;
                });
            }
        });
        // what goes through the hidden tunnel, recorded on its way (the Iran side of the tunnel)
        let seen = Arc::new(Mutex::new(Vec::<u8>::new()));
        let tap = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tap_addr = tap.local_addr().unwrap().to_string();
        let (seen2, up) = (seen.clone(), ptls_addr.clone());
        tokio::spawn(async move {
            loop {
                let Ok((mut c, _)) = tap.accept().await else { break };
                let (seen, up) = (seen2.clone(), up.clone());
                tokio::spawn(async move {
                    let mut p = tokio::net::TcpStream::connect(&up).await.unwrap();
                    let (mut cr, mut cw) = c.split();
                    let (mut pr, mut pw) = p.split();
                    let to = async {
                        let mut b = [0u8; 4096];
                        loop {
                            let n = cr.read(&mut b).await.unwrap_or(0);
                            if n == 0 { let _ = pw.shutdown().await; break }
                            seen.lock().unwrap().extend_from_slice(&b[..n]);
                            if pw.write_all(&b[..n]).await.is_err() { break }
                        }
                    };
                    let back = tokio::io::copy(&mut pr, &mut cw);
                    let _ = tokio::join!(to, back);
                });
            }
        });
        // the Iran server's listener
        let iran = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let iran_addr = iran.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = iran.accept().await else { break };
                let up = tap_addr.clone();
                tokio::spawn(async move {
                    let _ = pass_one(tcp, NAME, &up).await;
                });
            }
        });
        let conn = client(cert);
        let ask = |name: &'static str, req: String| {
            let conn = conn.clone();
            async move {
                let tcp = tokio::net::TcpStream::connect(iran_addr).await.unwrap();
                let sn = rustls::pki_types::ServerName::try_from(name).unwrap();
                let mut t = match conn.connect(sn, tcp).await { Ok(t) => t, Err(_) => return String::new() };
                t.write_all(req.as_bytes()).await.unwrap();
                let mut out = Vec::new();
                let _ = t.read_to_end(&mut out).await;
                String::from_utf8_lossy(&out).to_string()
            }
        };
        let code = u.sub_code();
        let ans = ask(NAME, format!("GET /sub/me HTTP/1.1\r\nHost: {NAME}:2053\r\nUser-Agent: KankiVPN-Android\r\nX-Kanki-Sub: {code}\r\nCookie: secret-cookie\r\n\r\n")).await;
        assert!(ans.starts_with("HTTP/1.1 200"), "{}", &ans[..ans.len().min(200)]);
        // the tunnel carried a PROXY header and TLS only: no code, no path, no cookie
        let raw = seen.lock().unwrap().clone();
        assert!(raw.starts_with(b"\r\n\r\n\0\r\nQUIT\n"), "the PROXY header first");
        let text = String::from_utf8_lossy(&raw);
        assert!(!text.contains(&u.code) && !text.contains("/sub/me") && !text.contains("secret-cookie") && !text.contains("X-Kanki-Sub"));
        // admin paths still never pass (the panel filters after it opened TLS)
        let admin = ask(NAME, "GET /api/users HTTP/1.1\r\nHost: r\r\n\r\n".into()).await;
        assert!(admin.starts_with("HTTP/1.1 404"), "{}", &admin[..admin.len().min(80)]);
        // another server name: the relay drops it before anything reaches the panel
        seen.lock().unwrap().clear();
        assert_eq!(ask("other.example.test", "GET /sub/me HTTP/1.1\r\n\r\n".into()).await, "");
        assert!(seen.lock().unwrap().is_empty());
        // straight to the panel's TLS listener without a PROXY header: nothing
        let mut raw = tokio::net::TcpStream::connect(&ptls_addr).await.unwrap();
        raw.write_all(b"\x16\x03\x01\x00\x05hello-not-a-proxy-header").await.unwrap();
        let mut b = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(8), raw.read_to_end(&mut b)).await;
        assert!(b.is_empty());
    }

    /// The relay's port 80 passes only Let's Encrypt's challenge path on, exactly, to the panel
    #[tokio::test]
    async fn only_acme_challenges_pass_port_80() {
        let up = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let up_addr = up.local_addr().unwrap().to_string();
        let got = Arc::new(Mutex::new(String::new()));
        let g2 = got.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut c, _)) = up.accept().await else { break };
                let mut b = [0u8; 2048];
                let n = c.read(&mut b).await.unwrap_or(0);
                *g2.lock().unwrap() = String::from_utf8_lossy(&b[..n]).to_string();
                let _ = c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nkey").await;
            }
        });
        let ask = |req: &'static str| {
            let up = up_addr.clone();
            async move {
                let (mut cli, srv) = tokio::io::duplex(1 << 16);
                let t = tokio::spawn(async move { acme_one(srv, NAME, &up).await });
                cli.write_all(req.as_bytes()).await.unwrap();
                let mut out = Vec::new();
                cli.read_to_end(&mut out).await.unwrap();
                let _ = t.await;
                String::from_utf8_lossy(&out).to_string()
            }
        };
        let ok = ask("GET /.well-known/acme-challenge/AbC_d-9 HTTP/1.1\r\nHost: x\r\nCookie: c\r\n\r\n").await;
        assert!(ok.ends_with("key"), "{}", ok);
        let sent = got.lock().unwrap().clone();
        assert!(sent.starts_with("GET /.well-known/acme-challenge/AbC_d-9 HTTP/1.1\r\nHost: sub.example.test\r\n") && !sent.contains("Cookie"), "{}", sent);
        got.lock().unwrap().clear();
        for bad in ["GET /sub/kanki-1-123 HTTP/1.1\r\n\r\n", "GET /.well-known/acme-challenge/../x HTTP/1.1\r\n\r\n", "POST /.well-known/acme-challenge/a HTTP/1.1\r\n\r\n", "GET /.well-known/acme-challenge/ HTTP/1.1\r\n\r\n"] {
            assert!(ask(bad).await.starts_with("HTTP/1.1 404"), "{}", bad);
        }
        assert!(got.lock().unwrap().is_empty(), "nothing else reached the panel");
    }

    #[test]
    fn the_server_name_is_read_from_a_real_client_hello() {
        let (_, cert) = server_tls();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert).unwrap();
        let cfg = rustls::ClientConfig::builder_with_provider(crate::tunnel::link::provider()).with_safe_default_protocol_versions().unwrap().with_root_certificates(roots).with_no_client_auth();
        let mut c = rustls::ClientConnection::new(Arc::new(cfg), rustls::pki_types::ServerName::try_from(NAME).unwrap()).unwrap();
        let mut hello = Vec::new();
        c.write_tls(&mut hello).unwrap();
        assert_eq!(sni_of(&hello).as_deref(), Some(NAME));
        assert!(sni_of(&hello[..20]).is_none() && sni_of(b"GET / HTTP/1.1\r\n").is_none() && sni_of(&[]).is_none());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn the_panel_dials_the_subscription_domain_not_the_server_address() {
        use std::sync::{atomic::AtomicI64, Mutex};
        let dir = std::env::temp_dir().join(format!("kanki-subiran-test-{}", crate::util::rand_token(8)));
        std::fs::create_dir_all(&dir).unwrap();
        let app = App {
            db: crate::db::Db::open(dir.join("kanki.db").to_str().unwrap()),
            env: HashMap::new(),
            hy2_allowed: Mutex::new(HashMap::new()), limits: Mutex::new(HashMap::new()), reported: Mutex::new(HashMap::new()),
            login_fails: Mutex::new(HashMap::new()), sync_lock: tokio::sync::Mutex::new(()), bot_alive: AtomicI64::new(0),
            http: reqwest::Client::new(), http_insecure: reqwest::Client::new(), pin_clients: Mutex::new(HashMap::new()),
        };
        save(&app, &SubIran { server: "ir2".into(), domain: "s1s.example.shop".into(), port: 2053, tunnel_port: 8447, token: "t".into(), ready: true });
        let local = specs(&app, "local");
        assert_eq!(local.len(), 1);
        assert_eq!(local[0].role, "exit");
        assert_eq!(local[0].remote, "s1s.example.shop:8447");
        // the Iran side listens and dials nothing
        let iran = specs(&app, "ir2");
        assert_eq!(iran[0].role, "entry");
        assert!(iran[0].remote.is_empty());
    }

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
        assert!(proxy_head("GET /sub/abc HTTP/1.1\r\nUser-Agent: x\nX-Forwarded-For: 127.0.0.1\r\n\r\n", "5.6.7.8", "").is_none());
        assert!(proxy_head("GET /sub/abc HTTP/1.1\r\nUser-Agent: x\rX-Forwarded-For: 127.0.0.1\r\n\r\n", "5.6.7.8", "").is_none());
        let h = "GET /sub/abc HTTP/1.1\r\nHost: sub.example.com:2053\r\nConnection: keep-alive\r\nX-Forwarded-For: 6.6.6.6\r\nUser-Agent: v2rayNG\r\n\r\n";
        let out = proxy_head(h, "5.6.7.8", "").unwrap();
        assert_eq!(out, "GET /sub/abc HTTP/1.1\r\nHost: sub.example.com:2053\r\nUser-Agent: v2rayNG\r\nX-Forwarded-For: 5.6.7.8\r\nX-Forwarded-Proto: https\r\nConnection: close\r\n\r\n");
        assert!(proxy_head("GET /admin HTTP/1.1\r\nHost: x\r\n\r\n", "1.1.1.1", "").is_none());
        assert!(proxy_head("POST /sub/abc HTTP/1.1\r\nHost: x\r\n\r\n", "1.1.1.1", "").is_none());
        assert!(proxy_head("GET /sub/abc HTTP/2\r\n\r\n", "1.1.1.1", "").is_none());
        assert!(proxy_head("GET /sub/abc HTTP/1.1\r\nHost: x\r\n folded\r\n\r\n", "1.1.1.1", "").is_none());
    }

    /// The Kanki app through the relay: GET /sub/me with the code in X-Kanki-Sub and a sealed answer asked for
    /// (X-Kanki-Device + X-Kanki-Seal), and a config download with Authorization: Bearer, reach the real panel
    /// router unchanged and come back 200 (sealed with the code and device the app sent)
    #[tokio::test]
    async fn the_app_headers_pass_the_relay() {
        let app = crate::test_app();
        let u = app.db.create_user("relayuser", 0.0, 0, 1, "wg", "", "", 0).unwrap();
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let up = l.local_addr().unwrap().to_string();
        let router = crate::api::master_router(app.clone());
        tokio::spawn(async move {
            let _ = axum::serve(l, router.into_make_service_with_connect_info::<std::net::SocketAddr>()).await;
        });
        save(&app, &SubIran { token: "relay-tunnel-token-0123456789".into(), ..Default::default() });
        let key = relay_key(&settings(&app));
        let ask = |head: String| {
            let (up, key) = (up.clone(), key.clone());
            async move {
                let (mut cli, srv) = tokio::io::duplex(4 << 20);
                let t = tokio::spawn(async move { relay(srv, "203.0.113.7".into(), &up, &key).await });
                cli.write_all(head.as_bytes()).await.unwrap();
                let mut out = Vec::new();
                cli.read_to_end(&mut out).await.unwrap();
                t.await.unwrap().unwrap();
                String::from_utf8_lossy(&out).to_string()
            }
        };
        let code = u.sub_code();
        let dev = "phone-relay-0001";
        let me = ask(format!(
            "GET /sub/me HTTP/1.1\r\nHost: relay.example:2053\r\nUser-Agent: KankiVPN-Android\r\nX-Kanki-Sub: {code}\r\nX-Kanki-Device: {dev}\r\nX-Kanki-Seal: kseal1\r\n\r\n"
        ))
        .await;
        assert!(me.starts_with("HTTP/1.1 200"), "{}", &me[..me.len().min(200)]);
        let body = me.split("\r\n\r\n").nth(1).unwrap_or("");
        assert!(body.starts_with("kseal1."), "the answer is sealed for the app");
        // the bare /sub/<code> path of an older app, and a wrong code (404, not a redirect)
        let old = ask(format!("GET /sub/{code} HTTP/1.1\r\nHost: r\r\nUser-Agent: KankiVPN-Android\r\n\r\n")).await;
        assert!(old.starts_with("HTTP/1.1 200"));
        let miss = ask("GET /sub/me HTTP/1.1\r\nHost: r\r\nX-Kanki-Sub: kanki-1-wrongwrong\r\n\r\n".into()).await;
        assert!(miss.starts_with("HTTP/1.1 404"), "{}", &miss[..miss.len().min(80)]);
        // admin paths never pass
        let admin = ask("GET /api/users HTTP/1.1\r\nHost: r\r\nAuthorization: Bearer x\r\n\r\n".into()).await;
        assert!(admin.starts_with("HTTP/1.1 404"));
    }

    /// 3.69: the relay's signed client address: taken only for exactly the request it was made for, once, recently,
    /// with this panel's key; the limits then count that client, not the relay
    #[tokio::test]
    async fn the_relay_signs_its_clients_address() {
        use axum::http::{HeaderMap, HeaderValue};
        let app = crate::test_app();
        save(&app, &SubIran { token: "relay-tunnel-token-abcdef012345".into(), ..Default::default() });
        let key = relay_key(&settings(&app));
        let now = crate::util::now();
        let hm = |client: &str, v: &str| {
            let mut h = HeaderMap::new();
            h.insert("x-forwarded-for", HeaderValue::from_str(client).unwrap());
            h.insert(RELAY_HEADER, HeaderValue::from_str(v).unwrap());
            h
        };
        let v = relay_header(&key, "203.0.113.20", "GET", "/sub/x", now);
        assert_eq!(verified_client(&app, &hm("203.0.113.20", &v), "GET", "/sub/x", now).as_deref(), Some("203.0.113.20"));
        // the same header again (captured): refused
        assert_eq!(verified_client(&app, &hm("203.0.113.20", &v), "GET", "/sub/x", now), None);
        // another address, path or method under a good header: refused
        let v = relay_header(&key, "203.0.113.20", "GET", "/sub/x", now);
        assert_eq!(verified_client(&app, &hm("203.0.113.21", &v), "GET", "/sub/x", now), None);
        assert_eq!(verified_client(&app, &hm("203.0.113.20", &v), "GET", "/sub/y", now), None);
        assert_eq!(verified_client(&app, &hm("203.0.113.20", &v), "HEAD", "/sub/x", now), None);
        // old, another key, junk
        let old = relay_header(&key, "203.0.113.20", "GET", "/sub/x", now - RELAY_SKEW - 5);
        assert_eq!(verified_client(&app, &hm("203.0.113.20", &old), "GET", "/sub/x", now), None);
        let other = relay_header("another-key", "203.0.113.20", "GET", "/sub/x", now);
        assert_eq!(verified_client(&app, &hm("203.0.113.20", &other), "GET", "/sub/x", now), None);
        assert_eq!(verified_client(&app, &hm("203.0.113.20", "v1;x;y;z"), "GET", "/sub/x", now), None);
        // through the whole panel from an address that is not this machine (PANEL_BIND public): a signed relay
        // request counts its client; an unsigned one with a made-up address counts the sender
        use tower::ServiceExt;
        let send = |xff: &str, relay: Option<String>| {
            let mut r = axum::http::Request::get("/sub/me").header("x-kanki-sub", "kanki-1-nosuchcode000").header("x-forwarded-for", xff);
            if let Some(v) = relay {
                r = r.header(RELAY_HEADER, v);
            }
            let mut r = r.body(axum::body::Body::empty()).unwrap();
            r.extensions_mut().insert(axum::extract::ConnectInfo(std::net::SocketAddr::from(([198, 51, 100, 40], 5555))));
            crate::api::master_router(app.clone()).oneshot(r)
        };
        let signed = relay_header(&key, "203.0.113.30", "GET", "/sub/me", crate::util::now());
        assert_eq!(send("203.0.113.30", Some(signed)).await.unwrap().status(), axum::http::StatusCode::NOT_FOUND);
        assert!(crate::limit::over("sub_miss", "203.0.113.30", 1, 3600), "the relayed client is counted");
        assert_eq!(send("203.0.113.31", None).await.unwrap().status(), axum::http::StatusCode::NOT_FOUND);
        assert!(!crate::limit::over("sub_miss", "203.0.113.31", 1, 3600), "a made-up address is not believed");
        assert!(crate::limit::over("sub_miss", "198.51.100.40", 1, 3600), "the sender is counted");
    }

    #[test]
    fn link_base_hides_443() {
        assert_eq!(link_base("sub.example.net", 2053), "https://sub.example.net:2053");
        assert_eq!(link_base("sub.example.net", 443), "https://sub.example.net");
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
