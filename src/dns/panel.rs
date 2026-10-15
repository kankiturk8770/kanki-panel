//! The panel side of Kanki DNS: settings, which agent servers run it (exit abroad / relay in Iran),
//! the config each one gets, the hidden tunnel from a relay to its exit, usage accounting and the
//! block a subscriber's app reads from the subscription.
use super::{user_token, DnsCfg, DnsUser};
use crate::api::err;
use crate::db::User;
use crate::guard;
use crate::tunnel::engine::Spec;
use crate::util::{now, rand_token, sha256_hex};
use crate::App;
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

type St = State<Arc<App>>;

/// Local port on an exit where its relays' tunnels deliver, and the port a relay reaches it on.
const INTAKE_PORT: u16 = 10853;
const RELAY_LOCAL_PORT: u16 = 10854;

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct DnsSrv {
    /// the agent server (Tunnel servers) that runs DNS
    pub server: String,
    /// "exit" | "relay"
    pub role: String,
    /// first label of the server's DNS name: <label>.<base>
    pub label: String,
    /// IPv4 answered for routed names (empty = the address the agent reports from)
    pub ip: String,
    /// relay: the exit server it carries connections to
    pub exit: String,
    /// relay: Kanki tunnel transport and the port the relay listens on for it
    pub transport: String,
    pub tunnel_port: u16,
    /// shown to subscribers next to the server ("for Irancell")
    pub note: String,
    /// hidden from subscribers (under repair)
    pub hidden: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct DnsSettings {
    pub on: bool,
    /// the zone the servers live under, like dns.example.com (each server is <label>.<base>)
    pub base: String,
    pub upstreams: Vec<String>,
    /// "<service>/<group>" turned off (groups are on unless opt-in)
    pub off: Vec<String>,
    /// opt-in groups turned on
    pub opt: Vec<String>,
    /// extra routed names
    pub custom: Vec<String>,
    pub ip_hours: u64,
    pub cert: String,
    pub key: String,
    pub servers: Vec<DnsSrv>,
    /// secret the relay keys and tunnel tokens are derived from
    pub secret: String,
    /// automatic certificate + records: "" (manual) | "cloudflare" | "arvan", its API token, ACME e-mail
    pub provider: String,
    pub api_token: String,
    pub email: String,
    /// when the certificate was issued and for which names; the last error of the automatic run
    pub cert_at: i64,
    pub cert_names: String,
    pub acme_err: String,
}

pub fn settings(app: &App) -> DnsSettings {
    let mut s: DnsSettings = serde_json::from_str(&app.db.get("dns_cfg")).unwrap_or_default();
    if s.upstreams.is_empty() {
        s.upstreams = vec!["1.1.1.1".into(), "8.8.8.8".into(), "9.9.9.9".into()];
    }
    if s.ip_hours == 0 {
        s.ip_hours = 12;
    }
    s
}

/// Change the settings in place (load, change, save).
pub fn update(app: &App, f: impl FnOnce(&mut DnsSettings)) {
    let mut s = settings(app);
    f(&mut s);
    save(app, &mut s);
}

fn save(app: &App, s: &mut DnsSettings) {
    if s.secret.is_empty() {
        s.secret = rand_token(40);
    }
    app.db.set("dns_cfg", &serde_json::to_string(s).unwrap_or_default());
}

fn catalog() -> &'static Value {
    static C: OnceLock<Value> = OnceLock::new();
    C.get_or_init(|| serde_json::from_str(include_str!("../../assets/dns/services.json")).unwrap_or(json!({"services": [], "sections": []})))
}

/// Every routed name under the current settings.
pub fn domains(s: &DnsSettings) -> Vec<String> {
    let mut out = vec![];
    for svc in catalog()["services"].as_array().into_iter().flatten() {
        let sk = svc["key"].as_str().unwrap_or("");
        for g in svc["groups"].as_array().into_iter().flatten() {
            let id = format!("{}/{}", sk, g["key"].as_str().unwrap_or(""));
            let on = if g["locked"].as_bool() == Some(true) {
                false
            } else if g["opt_in"].as_bool() == Some(true) {
                s.opt.contains(&id)
            } else {
                !s.off.contains(&id)
            };
            if on {
                out.extend(g["domains"].as_array().into_iter().flatten().filter_map(|d| d.as_str()).map(|d| d.to_string()));
            }
        }
    }
    out.extend(s.custom.iter().map(|d| d.trim().trim_matches('.').to_ascii_lowercase()).filter(|d| valid_name(d)));
    out.sort();
    out.dedup();
    out
}

fn valid_name(d: &str) -> bool {
    !d.is_empty() && d.len() <= 253 && d.contains('.') && d.split('.').all(|l| !l.is_empty() && l.len() <= 63 && l.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_'))
}

pub fn host_of(s: &DnsSettings, srv: &DnsSrv) -> String {
    if s.base.trim().is_empty() || srv.label.trim().is_empty() {
        String::new()
    } else {
        format!("{}.{}", srv.label.trim().to_ascii_lowercase(), s.base.trim().trim_matches('.').to_ascii_lowercase())
    }
}

pub fn answer_ip(srv: &DnsSrv) -> String {
    if !srv.ip.trim().is_empty() {
        return srv.ip.trim().to_string();
    }
    crate::tunnel::panel::seen_ip(&srv.server).filter(|ip| ip.parse::<std::net::Ipv4Addr>().is_ok()).unwrap_or_default()
}

fn relay_key(s: &DnsSettings, exit: &str) -> String {
    sha256_hex(&format!("kanki-dns-relay|{}|{}", s.secret, exit))[..32].to_string()
}

fn dns_users(app: &App) -> Vec<DnsUser> {
    let limit_on = app.db.get("conn_limit_on") != "0";
    app.db
        .users()
        .into_iter()
        .filter(|u| u.active() && u.has_proto("dns"))
        .map(|u| DnsUser { id: u.id, name: u.username.clone(), token: user_token(&u.code), max_ips: if limit_on { u.max_conn.max(0) as u32 } else { 0 } })
        .collect()
}

/// The config of server `sid` and its version, or None when it runs no DNS.
pub fn cfg_for(app: &App, sid: &str) -> Option<(DnsCfg, String)> {
    let s = settings(app);
    if !s.on {
        return None;
    }
    let srv = s.servers.iter().find(|x| x.server == sid)?;
    let relay = srv.role == "relay";
    if relay && !s.servers.iter().any(|x| x.server == srv.exit && x.role == "exit") {
        return None;
    }
    let has_relays = s.servers.iter().any(|x| x.role == "relay" && x.exit == sid);
    let c = DnsCfg {
        role: if relay { "relay".into() } else { "exit".into() },
        host: host_of(&s, srv),
        answer_ip: answer_ip(srv),
        upstreams: s.upstreams.clone(),
        domains: domains(&s),
        users: dns_users(app),
        cert: s.cert.clone(),
        key: s.key.clone(),
        dns_port: 53,
        dot_port: 853,
        https_port: 443,
        http_port: 80,
        intake_port: if !relay && has_relays { INTAKE_PORT } else { 0 },
        exit_addr: if relay { format!("127.0.0.1:{}", RELAY_LOCAL_PORT) } else { String::new() },
        relay_key: if relay { relay_key(&s, &srv.exit) } else if has_relays { relay_key(&s, sid) } else { String::new() },
        ip_hours: s.ip_hours,
    };
    let ver = sha256_hex(&serde_json::to_string(&c).unwrap_or_default())[..16].to_string();
    Some((c, ver))
}

/// The hidden Kanki tunnel from each relay to its exit, for the agent of server `sid`.
pub fn relay_specs(app: &App, sid: &str) -> Vec<Spec> {
    let s = settings(app);
    if !s.on {
        return vec![];
    }
    let mut out = vec![];
    for r in s.servers.iter().filter(|x| x.role == "relay" && !x.exit.is_empty() && x.exit != x.server) {
        if r.server != sid && r.exit != sid {
            continue;
        }
        let role = if r.server == sid { "entry" } else { "exit" };
        let port = if r.tunnel_port == 0 { 8446 } else { r.tunnel_port };
        // reverse: the relay (entry, inside Iran) listens, the exit dials it
        let remote = if role == "exit" { crate::tunnel::panel::dial_addr(app, &r.server, port) } else { String::new() };
        out.push(Spec {
            id: format!("dns~{}", r.server),
            name: "Kanki DNS relay".into(),
            role: role.into(),
            mode: "reverse".into(),
            transport: if r.transport.is_empty() { "tcpmux".into() } else { r.transport.clone() },
            port,
            remote,
            token: sha256_hex(&format!("kanki-dns-tunnel|{}|{}", s.secret, r.server))[..40].to_string(),
            conns: 4,
            path: "/".into(),
            tcp: vec![format!("{}:{}", RELAY_LOCAL_PORT, INTAKE_PORT)],
            target: "127.0.0.1".into(),
            bind: "127.0.0.1".into(),
            ..Default::default()
        });
    }
    out
}

// ------------------------------------------------------------------ usage from the agents

fn last_status() -> &'static Mutex<HashMap<String, (i64, Value)>> {
    static S: OnceLock<Mutex<HashMap<String, (i64, Value)>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(HashMap::new()))
}

/// The DNS status an agent reported: counts the bytes used since its last report.
pub fn ingest(app: &App, sid: &str, st: &Value) {
    if st.is_null() {
        last_status().lock().unwrap().remove(sid);
        return;
    }
    last_status().lock().unwrap().insert(sid.to_string(), (now(), st.clone()));
    let Some(run) = st["run"].as_str() else { return };
    let Some(users) = st["users"].as_object() else { return };
    let key = format!("dns_prev_{}", sid);
    let prev: Value = serde_json::from_str(&app.db.get(&key)).unwrap_or(json!({}));
    let same = prev["run"].as_str() == Some(run);
    let mut cur = serde_json::Map::new();
    let mut changed = !same;
    for (uid, v) in users {
        let bytes = v[0].as_i64().unwrap_or(0).max(0);
        let before = if same { prev["users"][uid].as_i64().unwrap_or(0) } else { 0 };
        let delta = if bytes >= before { bytes - before } else { bytes };
        cur.insert(uid.clone(), json!(bytes));
        if delta > 0 {
            changed = true;
            if let Ok(id) = uid.parse::<i64>() {
                let _ = app.db.exec("UPDATE users SET used_bytes=used_bytes+?1, last_seen=?2 WHERE id=?3", &[&delta, &now(), &id]);
            }
        }
    }
    if changed {
        app.db.set(&key, &json!({ "run": run, "users": cur }).to_string());
    }
}

// ------------------------------------------------------------------ subscription

/// What a subscriber's app needs to use DNS (Null when the user has no DNS).
pub fn sub_info(app: &App, u: &User) -> Value {
    let s = settings(app);
    if !s.on || !u.has_proto("dns") || !u.active() {
        return Value::Null;
    }
    let token = user_token(&u.code);
    let mut list: Vec<&DnsSrv> = s.servers.iter().filter(|x| !x.hidden).collect();
    // relays first: inside Iran is the faster and safer way in
    list.sort_by_key(|x| if x.role == "relay" { 0 } else { 1 });
    let names = crate::tunnel::panel::server_names(app);
    let servers: Vec<Value> = list
        .iter()
        .filter(|x| x.role != "relay" || s.servers.iter().any(|e| e.server == x.exit && e.role == "exit"))
        .map(|x| {
            let host = host_of(&s, x);
            let ip = answer_ip(x);
            let tls = !host.is_empty() && !s.cert.is_empty();
            json!({
                "id": x.server, "name": names.get(&x.server).cloned().unwrap_or_default(), "note": x.note, "role": x.role,
                "ip": ip, "host": host,
                "dot": if tls { format!("{}.{}", token, host) } else { String::new() },
                "doh": if tls { format!("https://{}/dns-query/{}", host, token) } else { String::new() },
                "register": if tls { format!("https://{}/r/{}", host, token) } else { String::new() },
                "register_http": if ip.is_empty() { String::new() } else { format!("http://{}/kdns/r/{}", ip, token) },
            })
        })
        .collect();
    json!({ "token": token, "servers": servers })
}

// ------------------------------------------------------------------ admin API

pub fn router() -> Router<Arc<App>> {
    Router::new()
        .route("/api/dns", get(get_all).put(put_settings))
        .route("/api/dns/servers", post(put_server))
        .route("/api/dns/cert", post(cert_now))
        .route("/api/dns/servers/:id", delete(del_server))
        .route("/assets/dns-icons.json", get(|| async {
            ([(header::CONTENT_TYPE, "application/json"), (header::CACHE_CONTROL, "public, max-age=86400")], include_str!("../../assets/dns/icons.json"))
        }))
}

fn cert_info(pem: &str) -> Value {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::CertificateDer;
    let n = CertificateDer::pem_slice_iter(pem.as_bytes()).filter(|c| c.is_ok()).count();
    json!({ "present": n > 0, "certs": n })
}

async fn get_all(State(app): St, h: HeaderMap) -> Response {
    let _ = guard!(app, h, "nodes");
    let s = settings(&app);
    let names = crate::tunnel::panel::server_names(&app);
    let st = last_status().lock().unwrap().clone();
    let servers: Vec<Value> = s
        .servers
        .iter()
        .map(|x| {
            let (at, status) = st.get(&x.server).cloned().unwrap_or((0, Value::Null));
            json!({
                "server": x.server, "name": names.get(&x.server).cloned().unwrap_or_default(), "role": x.role, "label": x.label,
                "ip": x.ip, "answer_ip": answer_ip(x), "exit": x.exit, "transport": x.transport, "tunnel_port": x.tunnel_port,
                "note": x.note, "hidden": x.hidden, "host": host_of(&s, x), "status": status, "status_at": at,
            })
        })
        .collect();
    let users = app.db.users().iter().filter(|u| u.has_proto("dns")).count();
    Json(json!({
        "on": s.on, "base": s.base, "upstreams": s.upstreams, "off": s.off, "opt": s.opt, "custom": s.custom, "ip_hours": s.ip_hours,
        "cert": cert_info(&s.cert), "cert_at": s.cert_at, "cert_names": s.cert_names, "acme_err": s.acme_err,
        "acme_busy": ACME_BUSY.load(std::sync::atomic::Ordering::Relaxed),
        "provider": s.provider, "email": s.email, "has_token": !s.api_token.is_empty(), "servers": servers, "catalog": catalog(), "domains": domains(&s).len(), "users": users,
        "agents": names.iter().map(|(k, v)| json!({"id": k, "name": v})).collect::<Vec<_>>(),
    }))
    .into_response()
}

fn str_list(v: &Value) -> Option<Vec<String>> {
    match v {
        Value::Array(a) => Some(a.iter().filter_map(|x| x.as_str()).map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect()),
        Value::String(t) => Some(t.split(|c: char| c == ',' || c.is_whitespace()).map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect()),
        _ => None,
    }
}

async fn put_settings(State(app): St, h: HeaderMap, Json(b): Json<Value>) -> Response {
    let _ = guard!(app, h, "nodes");
    let mut s = settings(&app);
    if let Some(v) = b["on"].as_bool() {
        s.on = v;
    }
    if let Some(v) = b["base"].as_str() {
        let v = v.trim().trim_matches('.').to_ascii_lowercase();
        if !v.is_empty() && !valid_name(&v) {
            return err(StatusCode::BAD_REQUEST, "the DNS domain is not a valid name (like dns.example.com)");
        }
        s.base = v;
    }
    if let Some(v) = str_list(&b["upstreams"]) {
        if v.iter().any(|x| x.parse::<std::net::IpAddr>().is_err() && x.parse::<std::net::SocketAddr>().is_err()) {
            return err(StatusCode::BAD_REQUEST, "upstream resolvers are IP addresses (optionally ip:port)");
        }
        s.upstreams = v;
    }
    if let Some(v) = str_list(&b["off"]) {
        s.off = v;
    }
    if let Some(v) = str_list(&b["opt"]) {
        s.opt = v;
    }
    if let Some(v) = str_list(&b["custom"]) {
        let bad: Vec<&String> = v.iter().filter(|d| !valid_name(&d.trim_matches('.').to_ascii_lowercase())).collect();
        if let Some(d) = bad.first() {
            return err(StatusCode::BAD_REQUEST, &format!("not a domain name: {}", d));
        }
        s.custom = v;
    }
    if let Some(v) = b["provider"].as_str() {
        if !["", "cloudflare", "arvan"].contains(&v) {
            return err(StatusCode::BAD_REQUEST, "provider: cloudflare, arvan or empty (manual certificate)");
        }
        s.provider = v.to_string();
    }
    if let Some(v) = b["api_token"].as_str().map(|x| x.trim()).filter(|x| !x.is_empty()) {
        s.api_token = v.to_string();
    }
    if let Some(v) = b["email"].as_str() {
        s.email = v.trim().to_string();
    }
    if let Some(v) = b["ip_hours"].as_u64() {
        s.ip_hours = v.clamp(1, 24 * 30);
    }
    if b["cert"].is_string() || b["key"].is_string() {
        let cert = b["cert"].as_str().unwrap_or("").trim().to_string();
        let key = b["key"].as_str().unwrap_or("").trim().to_string();
        if !cert.is_empty() || !key.is_empty() {
            let test = DnsCfg { cert: cert.clone(), key: key.clone(), ..Default::default() };
            if let Err(e) = super::engine::check_tls(&test) {
                return err(StatusCode::BAD_REQUEST, &format!("certificate: {}", e));
            }
        }
        s.cert = cert;
        s.key = key;
    }
    save(&app, &mut s);
    Json(json!({ "ok": true })).into_response()
}

async fn put_server(State(app): St, h: HeaderMap, Json(b): Json<Value>) -> Response {
    let _ = guard!(app, h, "nodes");
    let sid = b["server"].as_str().unwrap_or("").trim().to_string();
    let names = crate::tunnel::panel::server_names(&app);
    if !names.contains_key(&sid) {
        return err(StatusCode::BAD_REQUEST, "pick a server (add it first with its one-line install command)");
    }
    let mut s = settings(&app);
    let mut x = s.servers.iter().find(|x| x.server == sid).cloned().unwrap_or(DnsSrv { server: sid.clone(), ..Default::default() });
    if let Some(r) = b["role"].as_str() {
        x.role = if r == "relay" { "relay".into() } else { "exit".into() };
    }
    if x.role.is_empty() {
        x.role = "exit".into();
    }
    if let Some(v) = b["label"].as_str() {
        let v = v.trim().to_ascii_lowercase();
        if !v.is_empty() && !(v.len() <= 20 && v.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')) {
            return err(StatusCode::BAD_REQUEST, "the server label is letters, digits and '-' (like de or ir1)");
        }
        x.label = v;
    }
    if let Some(v) = b["ip"].as_str() {
        let v = v.trim().to_string();
        if !v.is_empty() && v.parse::<std::net::Ipv4Addr>().is_err() {
            return err(StatusCode::BAD_REQUEST, "the answer address is an IPv4 address");
        }
        x.ip = v;
    }
    if let Some(v) = b["exit"].as_str() {
        x.exit = v.trim().to_string();
    }
    if let Some(v) = b["transport"].as_str() {
        x.transport = v.trim().to_string();
    }
    if let Some(v) = b["tunnel_port"].as_u64() {
        x.tunnel_port = v.min(65535) as u16;
    }
    if let Some(v) = b["note"].as_str() {
        x.note = v.trim().chars().take(80).collect();
    }
    if let Some(v) = b["hidden"].as_bool() {
        x.hidden = v;
    }
    if x.role == "relay" && (x.exit.is_empty() || x.exit == x.server || !s.servers.iter().any(|e| e.server == x.exit && e.role == "exit")) {
        return err(StatusCode::BAD_REQUEST, "a relay needs an exit DNS server (abroad) to carry its connections");
    }
    if x.label.is_empty() {
        x.label = format!("s{}", s.servers.len() + 1);
    }
    if s.servers.iter().any(|o| o.server != x.server && o.label == x.label) {
        return err(StatusCode::BAD_REQUEST, "another DNS server already has this label");
    }
    // an exit with relays cannot become a relay itself
    if x.role == "relay" && s.servers.iter().any(|o| o.role == "relay" && o.exit == x.server) {
        return err(StatusCode::BAD_REQUEST, "other relays use this server as their exit");
    }
    match s.servers.iter_mut().find(|o| o.server == x.server) {
        Some(o) => *o = x,
        None => s.servers.push(x),
    }
    save(&app, &mut s);
    Json(json!({ "ok": true })).into_response()
}

async fn del_server(State(app): St, h: HeaderMap, Path(id): Path<String>) -> Response {
    let _ = guard!(app, h, "nodes");
    let mut s = settings(&app);
    if s.servers.iter().any(|o| o.role == "relay" && o.exit == id) {
        return err(StatusCode::BAD_REQUEST, "remove the relays that use this exit first");
    }
    s.servers.retain(|o| o.server != id);
    save(&app, &mut s);
    app.db.set(&format!("dns_prev_{}", id), "");
    Json(json!({ "ok": true })).into_response()
}

static ACME_BUSY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Set the records and get the certificate now (in the background: it takes about a minute).
async fn cert_now(State(app): St, h: HeaderMap) -> Response {
    let _ = guard!(app, h, "nodes");
    if ACME_BUSY.swap(true, std::sync::atomic::Ordering::SeqCst) {
        return err(StatusCode::CONFLICT, "already working on it");
    }
    let a = app.clone();
    tokio::spawn(async move {
        let r = super::acme::run_once(&a).await;
        if let Err(e) = &r {
            update(&a, |x| x.acme_err = e.clone());
        }
        ACME_BUSY.store(false, std::sync::atomic::Ordering::SeqCst);
    });
    Json(json!({ "ok": true })).into_response()
}
