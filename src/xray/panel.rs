//! The panel side of Xray: inbounds (VLESS / VMess / Trojan / Shadowsocks over TCP, WebSocket, gRPC,
//! HTTPUpgrade, XHTTP or mKCP, with TLS or REALITY), which servers run them, the Xray config each
//! server gets, and the share links in the subscription. The clients of every inbound are the panel's
//! own users who have Xray ticked: Xray has no users of its own.
use super::XrayCfg;
use crate::api::err;
use crate::db::User;
use crate::guard;
use crate::util::{now, pct, rand_token, sha256_hex};
use crate::App;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

type St = State<Arc<App>>;

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct Inbound {
    pub id: String,
    pub remark: String,
    pub enabled: bool,
    /// agent server id, or "local" (the panel server)
    pub server: String,
    /// vless | vmess | trojan | shadowsocks
    pub protocol: String,
    pub port: u16,
    /// tcp | ws | grpc | httpupgrade | xhttp | kcp
    pub network: String,
    /// none | tls | reality
    pub security: String,
    /// ws / httpupgrade / xhttp path, tcp http-header path
    pub path: String,
    /// ws / httpupgrade / xhttp host, tcp http-header host
    pub host: String,
    /// grpc service name
    pub service: String,
    /// xhttp mode: auto | packet-up | stream-up | stream-one
    pub mode: String,
    /// tcp: "http" for the HTTP header camouflage, else none
    pub header: String,
    /// VLESS flow (xtls-rprx-vision on TCP + TLS / REALITY)
    pub flow: String,
    /// shadowsocks method and (2022) server key
    pub ss_method: String,
    pub ss_key: String,
    /// TLS: SNI, ALPN, certificate + key (PEM), client fingerprint
    pub sni: String,
    pub alpn: String,
    pub cert: String,
    pub key: String,
    pub fp: String,
    /// REALITY: target site, names, keys, short ids, spiderX
    pub dest: String,
    pub names: String,
    pub private: String,
    pub public: String,
    pub short_ids: String,
    pub spx: String,
    pub sniffing: bool,
    /// what the share link says (for a CDN in front): address, port, TLS at the CDN, SNI there
    pub link_host: String,
    pub link_port: u16,
    pub link_tls: bool,
    pub link_sni: String,
    /// only these user ids (empty = every user with Xray)
    pub only: Vec<i64>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct XServer {
    /// agent server id, or "local"
    pub server: String,
    /// the address users connect to (domain or IP); empty = the address the server reports from
    pub address: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct XraySettings {
    pub on: bool,
    /// Xray-core release tag ("" = latest)
    pub version: String,
    pub servers: Vec<XServer>,
    pub inbounds: Vec<Inbound>,
    pub block_private: bool,
    pub block_bt: bool,
    /// advanced: extra routing rules and outbounds (JSON arrays)
    pub rules: String,
    pub outbounds: String,
    pub secret: String,
}

pub fn settings(app: &App) -> XraySettings {
    let mut s: XraySettings = serde_json::from_str(&app.db.get("xray_cfg")).unwrap_or_else(|_| XraySettings { block_private: true, block_bt: false, ..Default::default() });
    if s.secret.is_empty() {
        s.secret = rand_token(40);
        app.db.set("xray_cfg", &serde_json::to_string(&s).unwrap_or_default());
    }
    s
}

fn save(app: &App, s: &XraySettings) {
    app.db.set("xray_cfg", &serde_json::to_string(s).unwrap_or_default());
}

// ------------------------------------------------------------------ per-user credentials

/// A stable UUID for a subscription code (changes when the user's link is renewed).
pub fn user_uuid(code: &str) -> String {
    let h = sha256_hex(&format!("kanki-xray|{}", code));
    let mut b: Vec<char> = h[..32].chars().collect();
    b[12] = '4';
    b[16] = ['8', '9', 'a', 'b'][(b[16].to_digit(16).unwrap_or(0) % 4) as usize];
    let s: String = b.into_iter().collect();
    format!("{}-{}-{}-{}-{}", &s[..8], &s[8..12], &s[12..16], &s[16..20], &s[20..32])
}

fn user_pass(code: &str) -> String {
    sha256_hex(&format!("kanki-pass|{}", code))[..24].to_string()
}

fn ss_key_len(method: &str) -> usize {
    if method == "2022-blake3-aes-128-gcm" { 16 } else { 32 }
}

fn is_2022(method: &str) -> bool {
    method.starts_with("2022-")
}

fn b64_std(b: &[u8]) -> String {
    crate::util::b64(b)
}

fn b64_url(b: &[u8]) -> String {
    crate::util::b64(b).replace('+', "-").replace('/', "_").trim_end_matches('=').to_string()
}

fn ss_user_key(code: &str, method: &str) -> String {
    let h = hex::decode(sha256_hex(&format!("kanki-ss|{}", code))).unwrap_or_default();
    b64_std(&h[..ss_key_len(method)])
}

/// A REALITY key pair: (private, public), base64url without padding like `xray x25519`.
pub fn reality_keys() -> (String, String) {
    let mut k: [u8; 32] = rand::random();
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
    let p = x25519_dalek::x25519(k, x25519_dalek::X25519_BASEPOINT_BYTES);
    (b64_url(&k), b64_url(&p))
}

fn list(s: &str) -> Vec<String> {
    s.split(|c: char| c == ',' || c.is_whitespace()).map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect()
}

// ------------------------------------------------------------------ the Xray config of a server

fn xray_users(app: &App) -> Vec<User> {
    app.db.users().into_iter().filter(|u| u.active() && u.has_proto("xray")).collect()
}

fn clients(ib: &Inbound, users: &[User]) -> Vec<Value> {
    users
        .iter()
        .filter(|u| ib.only.is_empty() || ib.only.contains(&u.id))
        .map(|u| {
            let email = format!("u{}", u.id);
            match ib.protocol.as_str() {
                "vless" => {
                    let mut c = json!({ "id": user_uuid(&u.code), "email": email });
                    if !ib.flow.is_empty() && ib.network == "tcp" && ib.security != "none" {
                        c["flow"] = json!(ib.flow);
                    }
                    c
                }
                "vmess" => json!({ "id": user_uuid(&u.code), "email": email }),
                "trojan" => json!({ "password": user_pass(&u.code), "email": email }),
                _ => {
                    if is_2022(&ib.ss_method) {
                        json!({ "password": ss_user_key(&u.code, &ib.ss_method), "email": email })
                    } else {
                        json!({ "method": ib.ss_method, "password": user_pass(&u.code), "email": email })
                    }
                }
            }
        })
        .collect()
}

fn pem_lines(p: &str) -> Vec<String> {
    p.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect()
}

fn stream(ib: &Inbound) -> Value {
    let mut st = json!({ "network": if ib.network.is_empty() { "tcp" } else { ib.network.as_str() } });
    let path = if ib.path.is_empty() { "/".to_string() } else { ib.path.clone() };
    match ib.network.as_str() {
        "ws" => st["wsSettings"] = json!({ "path": path, "host": ib.host }),
        "httpupgrade" => st["httpupgradeSettings"] = json!({ "path": path, "host": ib.host }),
        "xhttp" => st["xhttpSettings"] = json!({ "path": path, "host": ib.host, "mode": if ib.mode.is_empty() { "auto" } else { ib.mode.as_str() } }),
        "grpc" => st["grpcSettings"] = json!({ "serviceName": ib.service }),
        // Xray 26 removed the mKCP seed and header (now "finalmask"): plain mKCP
        "kcp" => st["kcpSettings"] = json!({}),
        _ => {
            if ib.header == "http" {
                st["tcpSettings"] = json!({ "header": { "type": "http", "request": { "path": [path], "headers": { "Host": list(&ib.host) } } } });
            }
        }
    }
    match ib.security.as_str() {
        "tls" => {
            st["security"] = json!("tls");
            st["tlsSettings"] = json!({
                "serverName": ib.sni,
                "alpn": if ib.alpn.is_empty() { vec!["h2".to_string(), "http/1.1".to_string()] } else { list(&ib.alpn) },
                "certificates": [{ "certificate": pem_lines(&ib.cert), "key": pem_lines(&ib.key) }],
            });
        }
        "reality" => {
            st["security"] = json!("reality");
            st["realitySettings"] = json!({
                "show": false, "dest": ib.dest, "xver": 0, "serverNames": list(&ib.names),
                "privateKey": ib.private, "shortIds": list(&ib.short_ids),
            });
        }
        _ => {}
    }
    st
}

fn inbound_json(ib: &Inbound, users: &[User]) -> Value {
    let cl = clients(ib, users);
    let settings = match ib.protocol.as_str() {
        "vless" => json!({ "clients": cl, "decryption": "none" }),
        "shadowsocks" if is_2022(&ib.ss_method) => json!({ "method": ib.ss_method, "password": ib.ss_key, "clients": cl, "network": "tcp,udp" }),
        "shadowsocks" => json!({ "clients": cl, "network": "tcp,udp" }),
        _ => json!({ "clients": cl }),
    };
    let mut v = json!({ "tag": format!("in-{}", ib.id), "listen": "0.0.0.0", "port": ib.port, "protocol": ib.protocol, "settings": settings, "streamSettings": stream(ib) });
    if ib.sniffing {
        v["sniffing"] = json!({ "enabled": true, "destOverride": ["http", "tls", "quic"], "routeOnly": true });
    }
    v
}

const PRIVATE_NETS: &[&str] = &["0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7", "fe80::/10", "::1/128"];

pub fn build_config(s: &XraySettings, sid: &str, users: &[User]) -> Value {
    let inbounds: Vec<Value> = s.inbounds.iter().filter(|ib| ib.enabled && ib.server == sid).map(|ib| inbound_json(ib, users)).collect();
    let mut rules = vec![json!({ "type": "field", "inboundTag": ["api"], "outboundTag": "api" })];
    if s.block_private {
        rules.push(json!({ "type": "field", "ip": PRIVATE_NETS, "outboundTag": "block" }));
    }
    if s.block_bt {
        rules.push(json!({ "type": "field", "protocol": ["bittorrent"], "outboundTag": "block" }));
    }
    if let Ok(Value::Array(extra)) = serde_json::from_str::<Value>(&s.rules) {
        rules.extend(extra);
    }
    let mut outbounds = vec![json!({ "protocol": "freedom", "tag": "direct" }), json!({ "protocol": "blackhole", "tag": "block" })];
    if let Ok(Value::Array(extra)) = serde_json::from_str::<Value>(&s.outbounds) {
        // a custom outbound first becomes the default route
        let mut e = extra;
        e.extend(outbounds);
        outbounds = e;
    }
    json!({
        "log": { "loglevel": "warning", "access": "none" },
        "api": { "tag": "api", "listen": format!("127.0.0.1:{}", super::API_PORT), "services": ["HandlerService", "StatsService"] },
        "stats": {},
        "policy": {
            "levels": { "0": { "statsUserUplink": true, "statsUserDownlink": true } },
            "system": { "statsInboundUplink": true, "statsInboundDownlink": true },
        },
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": { "domainStrategy": "AsIs", "rules": rules },
    })
}

/// The Xray config of server `sid` and its version, or None when it runs no Xray.
pub fn cfg_for(app: &App, sid: &str) -> Option<(XrayCfg, String)> {
    let s = settings(app);
    if !s.on || !s.servers.iter().any(|x| x.server == sid) || !s.inbounds.iter().any(|ib| ib.enabled && ib.server == sid) {
        return None;
    }
    let c = XrayCfg { config: build_config(&s, sid, &xray_users(app)), version: s.version.clone() };
    let ver = sha256_hex(&serde_json::to_string(&c).unwrap_or_default())[..16].to_string();
    Some((c, ver))
}

// ------------------------------------------------------------------ share links

fn server_address(app: &App, s: &XraySettings, sid: &str) -> String {
    if let Some(x) = s.servers.iter().find(|x| x.server == sid) {
        if !x.address.trim().is_empty() {
            return x.address.trim().to_string();
        }
    }
    if sid == "local" {
        return crate::api::panel_endpoint(app);
    }
    crate::tunnel::panel::seen_ip(sid).unwrap_or_default()
}

fn host_port(h: &str, p: u16) -> String {
    if h.contains(':') && !h.starts_with('[') { format!("[{}]:{}", h, p) } else { format!("{}:{}", h, p) }
}

/// The share link of one inbound for one user.
pub fn link(app: &App, s: &XraySettings, ib: &Inbound, u: &User) -> Option<String> {
    link_with(s, ib, u, &server_address(app, s, &ib.server))
}

fn link_with(_s: &XraySettings, ib: &Inbound, u: &User, server_addr: &str) -> Option<String> {
    let host = if ib.link_host.trim().is_empty() { server_addr.to_string() } else { ib.link_host.trim().to_string() };
    if host.is_empty() {
        return None;
    }
    let port = if ib.link_port > 0 { ib.link_port } else { ib.port };
    let name = if ib.remark.is_empty() { format!("{}-{}", ib.protocol, u.username) } else { format!("{}-{}", ib.remark, u.username) };
    let sec = if ib.link_tls { "tls" } else if ib.security.is_empty() { "none" } else { ib.security.as_str() };
    let sni = if !ib.link_sni.is_empty() {
        ib.link_sni.clone()
    } else if ib.security == "reality" {
        list(&ib.names).into_iter().next().unwrap_or_default()
    } else {
        ib.sni.clone()
    };
    let fp = if ib.fp.is_empty() { "chrome".to_string() } else { ib.fp.clone() };
    let path = if ib.path.is_empty() { "/".to_string() } else { ib.path.clone() };
    let net = if ib.network.is_empty() { "tcp" } else { ib.network.as_str() };
    if ib.protocol == "vmess" {
        let mut v = json!({
            "v": "2", "ps": name, "add": host, "port": port.to_string(), "id": user_uuid(&u.code), "aid": "0", "scy": "auto",
            "net": net, "type": if ib.header == "http" { "http" } else { "none" }, "host": ib.host, "path": if net == "grpc" { ib.service.clone() } else { path.clone() },
            "tls": if sec == "tls" { "tls" } else { "" }, "sni": sni, "fp": if sec == "tls" { fp.as_str() } else { "" },
        });
        if net == "xhttp" {
            v["mode"] = json!(if ib.mode.is_empty() { "auto" } else { ib.mode.as_str() });
        }
        return Some(format!("vmess://{}", b64_std(v.to_string().as_bytes())));
    }
    if ib.protocol == "shadowsocks" {
        let pass = if is_2022(&ib.ss_method) { format!("{}:{}", ib.ss_key, ss_user_key(&u.code, &ib.ss_method)) } else { user_pass(&u.code) };
        let ui = b64_url(format!("{}:{}", ib.ss_method, pass).as_bytes());
        return Some(format!("ss://{}@{}#{}", ui, host_port(&host, port), pct(&name)));
    }
    let mut q: Vec<String> = vec![format!("type={}", net), format!("security={}", sec)];
    match net {
        "ws" | "httpupgrade" => {
            q.push(format!("path={}", pct(&path)));
            if !ib.host.is_empty() {
                q.push(format!("host={}", pct(&ib.host)));
            }
        }
        "xhttp" => {
            q.push(format!("path={}", pct(&path)));
            if !ib.host.is_empty() {
                q.push(format!("host={}", pct(&ib.host)));
            }
            q.push(format!("mode={}", if ib.mode.is_empty() { "auto" } else { ib.mode.as_str() }));
        }
        "grpc" => {
            q.push(format!("serviceName={}", pct(&ib.service)));
            q.push("mode=gun".into());
        }
        _ => {
            if ib.header == "http" {
                q.push("headerType=http".into());
                q.push(format!("path={}", pct(&path)));
                if !ib.host.is_empty() {
                    q.push(format!("host={}", pct(&ib.host)));
                }
            }
        }
    }
    if sec == "tls" || sec == "reality" {
        if !sni.is_empty() {
            q.push(format!("sni={}", pct(&sni)));
        }
        q.push(format!("fp={}", fp));
    }
    if sec == "tls" && !ib.alpn.is_empty() && !ib.link_tls {
        q.push(format!("alpn={}", pct(&list(&ib.alpn).join(","))));
    }
    if sec == "reality" {
        q.push(format!("pbk={}", ib.public));
        if let Some(sid) = list(&ib.short_ids).into_iter().next() {
            q.push(format!("sid={}", sid));
        }
        q.push(format!("spx={}", pct(if ib.spx.is_empty() { "/" } else { ib.spx.as_str() })));
    }
    let cred = if ib.protocol == "trojan" {
        user_pass(&u.code)
    } else {
        if !ib.flow.is_empty() && net == "tcp" && ib.security != "none" {
            q.push(format!("flow={}", ib.flow));
        }
        q.push("encryption=none".into());
        user_uuid(&u.code)
    };
    Some(format!("{}://{}@{}?{}#{}", ib.protocol, cred, host_port(&host, port), q.join("&"), pct(&name)))
}

/// Every Xray link of a user (empty when the user has no Xray).
pub fn user_links(app: &App, u: &User) -> Vec<(String, String)> {
    let s = settings(app);
    if !s.on || !u.has_proto("xray") || !u.active() {
        return vec![];
    }
    s.inbounds
        .iter()
        .filter(|ib| ib.enabled && (ib.only.is_empty() || ib.only.contains(&u.id)) && s.servers.iter().any(|x| x.server == ib.server))
        .filter_map(|ib| link(app, &s, ib, u).map(|l| (ib.remark.clone(), l)))
        .collect()
}

pub fn sub_info(app: &App, u: &User) -> Value {
    let v: Vec<Value> = user_links(app, u).into_iter().map(|(n, l)| json!({ "name": n, "link": l })).collect();
    if v.is_empty() { Value::Null } else { json!(v) }
}

// ------------------------------------------------------------------ status / usage

fn last_status() -> &'static Mutex<HashMap<String, (i64, Value)>> {
    static S: OnceLock<Mutex<HashMap<String, (i64, Value)>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(HashMap::new()))
}

pub fn ingest(app: &App, sid: &str, st: &Value) {
    if st.is_null() {
        last_status().lock().unwrap().remove(sid);
        return;
    }
    last_status().lock().unwrap().insert(sid.to_string(), (now(), st.clone()));
    crate::dns::panel::count_usage(app, &format!("xray_prev_{}", sid), st);
    // online now: the users whose traffic moved since the previous read
    if let Some(on) = st["online"].as_array() {
        for id in on.iter().filter_map(|x| x.as_i64()) {
            let _ = app.db.exec("UPDATE users SET last_seen=?1 WHERE id=?2", &[&now(), &id]);
        }
    }
}

/// The panel server itself can run Xray too: deploy and count here every 15 seconds.
pub async fn local_loop(app: Arc<App>) {
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(15)).await;
        let cfg = cfg_for(&app, "local");
        if cfg.is_none() && !std::path::Path::new(super::UNIT).exists() {
            continue;
        }
        let r = tokio::task::spawn_blocking(move || {
            let applied = super::applied_ver();
            let res = match &cfg {
                Some((c, v)) if *v != applied || !super::running() => super::deploy(Some((c, v)), None),
                Some(_) => Ok(()),
                None => super::deploy(None, None),
            };
            (res, super::status())
        })
        .await;
        if let Ok((res, mut st)) = r {
            if let Err(e) = res {
                eprintln!("xray: {}", e);
                if st.is_object() {
                    st["deploy_error"] = json!(e);
                }
            }
            ingest(&app, "local", &st);
        }
    }
}

// ------------------------------------------------------------------ admin API

pub fn router() -> Router<Arc<App>> {
    Router::new()
        .route("/api/xray", get(get_all).put(put_settings))
        .route("/api/xray/servers", post(put_server))
        .route("/api/xray/servers/:id", delete(del_server))
        .route("/api/xray/inbounds", post(put_inbound))
        .route("/api/xray/inbounds/:id", delete(del_inbound))
        .route("/api/xray/keys", post(new_keys))
        .route("/api/xray/config/:id", get(preview))
        .route("/tunnel/xraybin", post(agent_xraybin))
}

async fn get_all(State(app): St, h: HeaderMap) -> Response {
    let _ = guard!(app, h, "nodes");
    let s = settings(&app);
    let mut names = crate::tunnel::panel::server_names(&app);
    names.insert("local".into(), app.env.get("LOCAL_NAME").cloned().filter(|x| !x.is_empty()).unwrap_or_else(|| "Main".into()));
    let st = last_status().lock().unwrap().clone();
    let servers: Vec<Value> = s
        .servers
        .iter()
        .map(|x| {
            let (at, status) = st.get(&x.server).cloned().unwrap_or((0, Value::Null));
            json!({ "server": x.server, "name": names.get(&x.server).cloned().unwrap_or_default(), "address": x.address,
                "effective": server_address(&app, &s, &x.server), "status": status, "status_at": at })
        })
        .collect();
    let users = xray_users(&app);
    let inbounds: Vec<Value> = s
        .inbounds
        .iter()
        .map(|ib| {
            let mut v = serde_json::to_value(ib).unwrap_or(json!({}));
            v["clients"] = json!(users.iter().filter(|u| ib.only.is_empty() || ib.only.contains(&u.id)).count());
            v["traffic"] = st.get(&ib.server).map(|x| x.1["inbounds"][format!("in-{}", ib.id)].clone()).unwrap_or(Value::Null);
            v["server_name"] = json!(names.get(&ib.server).cloned().unwrap_or_default());
            // the private keys never leave the panel in a listing
            v["key"] = json!(if ib.key.is_empty() { "" } else { "set" });
            v["private"] = json!(if ib.private.is_empty() { "" } else { "set" });
            v
        })
        .collect();
    let all_users = app.db.users();
    Json(json!({
        "on": s.on, "version": s.version, "block_private": s.block_private, "block_bt": s.block_bt, "rules": s.rules, "outbounds": s.outbounds,
        "servers": servers, "inbounds": inbounds, "users": users.len(),
        "agents": names.iter().map(|(k, v)| json!({ "id": k, "name": v })).collect::<Vec<_>>(),
        "user_list": all_users.iter().filter(|u| u.has_proto("xray")).map(|u| json!({ "id": u.id, "name": u.username })).collect::<Vec<_>>(),
    }))
    .into_response()
}

fn json_array_ok(t: &str) -> bool {
    t.trim().is_empty() || matches!(serde_json::from_str::<Value>(t), Ok(Value::Array(_)))
}

async fn put_settings(State(app): St, h: HeaderMap, Json(b): Json<Value>) -> Response {
    let _ = guard!(app, h, "nodes");
    let mut s = settings(&app);
    if let Some(v) = b["on"].as_bool() {
        s.on = v;
    }
    if let Some(v) = b["version"].as_str() {
        let v = v.trim();
        if !v.is_empty() && !(v.starts_with('v') && v[1..].chars().all(|c| c.is_ascii_digit() || c == '.')) {
            return err(StatusCode::BAD_REQUEST, "the Xray version is a release tag like v25.10.15 (empty = latest)");
        }
        s.version = v.to_string();
    }
    if let Some(v) = b["block_private"].as_bool() {
        s.block_private = v;
    }
    if let Some(v) = b["block_bt"].as_bool() {
        s.block_bt = v;
    }
    for (k, field) in [("rules", &mut s.rules), ("outbounds", &mut s.outbounds)] {
        if let Some(v) = b[k].as_str() {
            if !json_array_ok(v) {
                return err(StatusCode::BAD_REQUEST, &format!("{}: a JSON array is expected", k));
            }
            *field = v.trim().to_string();
        }
    }
    save(&app, &s);
    Json(json!({ "ok": true })).into_response()
}

async fn put_server(State(app): St, h: HeaderMap, Json(b): Json<Value>) -> Response {
    let _ = guard!(app, h, "nodes");
    let sid = b["server"].as_str().unwrap_or("").trim().to_string();
    if sid != "local" && !crate::tunnel::panel::server_names(&app).contains_key(&sid) {
        return err(StatusCode::BAD_REQUEST, "pick a server (add it first with its one-line install command)");
    }
    let mut s = settings(&app);
    let address = b["address"].as_str().unwrap_or("").trim().to_string();
    match s.servers.iter_mut().find(|x| x.server == sid) {
        Some(x) => x.address = address,
        None => s.servers.push(XServer { server: sid, address }),
    }
    save(&app, &s);
    Json(json!({ "ok": true })).into_response()
}

async fn del_server(State(app): St, h: HeaderMap, Path(id): Path<String>) -> Response {
    let _ = guard!(app, h, "nodes");
    let mut s = settings(&app);
    if s.inbounds.iter().any(|ib| ib.server == id) {
        return err(StatusCode::BAD_REQUEST, "delete the inbounds of this server first");
    }
    s.servers.retain(|x| x.server != id);
    save(&app, &s);
    Json(json!({ "ok": true })).into_response()
}

/// Ports another service of the panel already uses on that server.
fn taken_ports(app: &App, sid: &str) -> Vec<u16> {
    let d = crate::dns::panel::settings(app);
    if d.on && d.servers.iter().any(|x| x.server == sid) {
        return vec![53, 80, 443, 853, super::API_PORT];
    }
    vec![super::API_PORT]
}

async fn put_inbound(State(app): St, h: HeaderMap, Json(b): Json<Value>) -> Response {
    let _ = guard!(app, h, "nodes");
    let mut s = settings(&app);
    let id = b["id"].as_str().unwrap_or("").trim().to_string();
    let old = s.inbounds.iter().find(|x| x.id == id && !id.is_empty()).cloned();
    let mut ib: Inbound = match serde_json::from_value(b.clone()) {
        Ok(x) => x,
        Err(e) => return err(StatusCode::BAD_REQUEST, &e.to_string()),
    };
    // secrets the listing hid ("set") or the form left empty keep their saved value
    if let Some(o) = &old {
        if ib.key.is_empty() || ib.key == "set" {
            ib.key = o.key.clone();
        }
        if ib.private.is_empty() || ib.private == "set" {
            ib.private = o.private.clone();
        }
        if ib.ss_key.is_empty() {
            ib.ss_key = o.ss_key.clone();
        }
    }
    if ib.id.is_empty() || old.is_none() {
        ib.id = rand_token(6).to_lowercase();
    }
    if !["vless", "vmess", "trojan", "shadowsocks"].contains(&ib.protocol.as_str()) {
        return err(StatusCode::BAD_REQUEST, "protocol: vless, vmess, trojan or shadowsocks");
    }
    if ib.network.is_empty() {
        ib.network = "tcp".into();
    }
    if !["tcp", "ws", "grpc", "httpupgrade", "xhttp", "kcp"].contains(&ib.network.as_str()) {
        return err(StatusCode::BAD_REQUEST, "transport: tcp, ws, grpc, httpupgrade, xhttp or kcp");
    }
    if ib.security.is_empty() {
        ib.security = "none".into();
    }
    if !["none", "tls", "reality"].contains(&ib.security.as_str()) {
        return err(StatusCode::BAD_REQUEST, "security: none, tls or reality");
    }
    if ib.protocol == "shadowsocks" {
        ib.security = "none".into();
        if ib.ss_method.is_empty() {
            ib.ss_method = "2022-blake3-aes-128-gcm".into();
        }
        if !["2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305", "aes-256-gcm", "aes-128-gcm", "chacha20-ietf-poly1305"].contains(&ib.ss_method.as_str()) {
            return err(StatusCode::BAD_REQUEST, "unknown shadowsocks method");
        }
        let need = ss_key_len(&ib.ss_method);
        let bad = crate::tunnel::link::b64decode(&ib.ss_key).map(|k| k.len() != need).unwrap_or(true);
        if is_2022(&ib.ss_method) && bad {
            let k: Vec<u8> = (0..need).map(|_| rand::random::<u8>()).collect();
            ib.ss_key = b64_std(&k);
        }
    }
    if ib.security == "reality" {
        if ib.protocol != "vless" && ib.protocol != "trojan" {
            return err(StatusCode::BAD_REQUEST, "REALITY works with VLESS (and Trojan)");
        }
        if !["tcp", "grpc", "xhttp"].contains(&ib.network.as_str()) {
            return err(StatusCode::BAD_REQUEST, "REALITY works over TCP, gRPC or XHTTP");
        }
        if ib.dest.trim().is_empty() || list(&ib.names).is_empty() {
            return err(StatusCode::BAD_REQUEST, "REALITY needs a target (like www.microsoft.com:443) and its server names");
        }
        if ib.private.is_empty() || ib.public.is_empty() {
            let (p, q) = reality_keys();
            ib.private = p;
            ib.public = q;
        }
        if list(&ib.short_ids).is_empty() {
            ib.short_ids = hex::encode(rand::random::<[u8; 8]>());
        }
    }
    if ib.security == "tls" {
        let test = crate::dns::DnsCfg { cert: ib.cert.clone(), key: ib.key.clone(), ..Default::default() };
        if let Err(e) = crate::dns::engine::check_tls(&test) {
            return err(StatusCode::BAD_REQUEST, &format!("TLS certificate: {}", e));
        }
    }
    if ib.port == 0 {
        return err(StatusCode::BAD_REQUEST, "the port is required");
    }
    if !s.servers.iter().any(|x| x.server == ib.server) {
        return err(StatusCode::BAD_REQUEST, "pick one of the Xray servers");
    }
    if taken_ports(&app, &ib.server).contains(&ib.port) || s.inbounds.iter().any(|o| o.id != ib.id && o.server == ib.server && o.port == ib.port) {
        return err(StatusCode::BAD_REQUEST, "this port is already used on that server");
    }
    if ib.path.is_empty() && ["ws", "httpupgrade", "xhttp"].contains(&ib.network.as_str()) {
        ib.path = format!("/{}", rand_token(8).to_lowercase());
    }
    if ib.network == "grpc" && ib.service.is_empty() {
        ib.service = rand_token(8).to_lowercase();
    }
    match s.inbounds.iter_mut().find(|o| o.id == ib.id) {
        Some(o) => *o = ib.clone(),
        None => s.inbounds.push(ib.clone()),
    }
    save(&app, &s);
    Json(json!({ "ok": true, "id": ib.id })).into_response()
}

async fn del_inbound(State(app): St, h: HeaderMap, Path(id): Path<String>) -> Response {
    let _ = guard!(app, h, "nodes");
    let mut s = settings(&app);
    s.inbounds.retain(|x| x.id != id);
    save(&app, &s);
    Json(json!({ "ok": true })).into_response()
}

async fn new_keys(State(app): St, h: HeaderMap) -> Response {
    let _ = guard!(app, h, "nodes");
    let (p, q) = reality_keys();
    Json(json!({ "private": p, "public": q, "short_id": hex::encode(rand::random::<[u8; 8]>()) })).into_response()
}

async fn preview(State(app): St, h: HeaderMap, Path(id): Path<String>) -> Response {
    let _ = guard!(app, h, "nodes");
    let s = settings(&app);
    Json(build_config(&s, &id, &xray_users(&app))).into_response()
}

/// An agent that cannot reach GitHub gets the Xray-core release zip through the panel.
async fn agent_xraybin(State(app): St, Json(b): Json<Value>) -> Response {
    if !crate::tunnel::panel::agent_token_ok(&app, b["id"].as_str().unwrap_or(""), b["token"].as_str().unwrap_or("")) {
        return err(StatusCode::FORBIDDEN, "wrong token");
    }
    let zip = b["zip"].as_str().unwrap_or("");
    if !["Xray-linux-64.zip", "Xray-linux-arm64-v8a.zip", "Xray-linux-arm32-v7a.zip"].contains(&zip) {
        return err(StatusCode::BAD_REQUEST, "unknown file");
    }
    let version = b["version"].as_str().unwrap_or("");
    if !version.is_empty() && !(version.starts_with('v') && version[1..].chars().all(|c| c.is_ascii_digit() || c == '.')) {
        return err(StatusCode::BAD_REQUEST, "bad version");
    }
    let cache = format!("/var/lib/kanki/xraybin/{}-{}", if version.is_empty() { "latest" } else { version }, zip);
    let fresh = std::fs::metadata(&cache).and_then(|m| m.modified()).map(|t| t.elapsed().map(|e| e.as_secs() < 86400).unwrap_or(false)).unwrap_or(false);
    if !fresh {
        static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
        let _g = LOCK.lock().await;
        let http = match reqwest::Client::builder().timeout(std::time::Duration::from_secs(300)).build() {
            Ok(h) => h,
            Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
        };
        match http.get(super::release_url(version, zip)).send().await {
            Ok(r) if r.status().is_success() => match r.bytes().await {
                Ok(bytes) if bytes.starts_with(b"PK") => {
                    let _ = tokio::fs::create_dir_all("/var/lib/kanki/xraybin").await;
                    let _ = tokio::fs::write(&cache, &bytes).await;
                }
                _ => return err(StatusCode::BAD_GATEWAY, "the panel could not download Xray-core"),
            },
            _ => return err(StatusCode::BAD_GATEWAY, "the panel could not download Xray-core"),
        }
    }
    match tokio::fs::read(&cache).await {
        Ok(bytes) => (StatusCode::OK, bytes).into_response(),
        Err(_) => err(StatusCode::NOT_FOUND, "no Xray-core"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuids_are_stable_and_valid() {
        let a = user_uuid("1234567890");
        assert_eq!(a, user_uuid("1234567890"));
        assert_ne!(a, user_uuid("1234567891"));
        let p: Vec<&str> = a.split('-').collect();
        assert_eq!(p.iter().map(|x| x.len()).collect::<Vec<_>>(), vec![8, 4, 4, 4, 12]);
        assert!(p[2].starts_with('4'));
        assert!("89ab".contains(&p[3][..1]));
    }

    #[test]
    fn reality_keys_match() {
        let (p, q) = reality_keys();
        assert_eq!((p.len(), q.len()), (43, 43));
        let k: [u8; 32] = crate::tunnel::link::b64decode(&format!("{}=", p.replace('-', "+").replace('_', "/"))).unwrap().try_into().unwrap();
        let pubk = x25519_dalek::x25519(k, x25519_dalek::X25519_BASEPOINT_BYTES);
        assert_eq!(b64_url(&pubk), q);
    }

    #[test]
    fn ss2022_keys_have_the_right_size() {
        assert_eq!(crate::tunnel::link::b64decode(&ss_user_key("x", "2022-blake3-aes-128-gcm")).unwrap().len(), 16);
        assert_eq!(crate::tunnel::link::b64decode(&ss_user_key("x", "2022-blake3-aes-256-gcm")).unwrap().len(), 32);
    }
}

/// `KX_OUT=dir cargo test xray_configs -- --ignored`: writes one config per kind of inbound (checked
/// with `xray run -test` by hand) and their share links.
#[cfg(test)]
mod emit {
    use super::*;

    #[test]
    #[ignore]
    fn xray_configs() {
        let out = std::env::var("KX_OUT").expect("KX_OUT");
        let ck = rcgen::generate_simple_self_signed(vec!["x.example.com".to_string()]).unwrap();
        let (cert, key) = (ck.cert.pem(), ck.key_pair.serialize_pem());
        let u = User { id: 7, username: "mahtab87".into(), code: "1234567890123456789".into(), enabled: true, protocols: "xray".into(), ..test_user() };
        let mut n = 0;
        for proto in ["vless", "vmess", "trojan", "shadowsocks"] {
            for net in ["tcp", "ws", "grpc", "httpupgrade", "xhttp", "kcp"] {
                for sec in ["none", "tls", "reality"] {
                    if proto == "shadowsocks" && (sec != "none" || net != "tcp") {
                        continue;
                    }
                    if sec == "reality" && (!["vless", "trojan"].contains(&proto) || !["tcp", "grpc", "xhttp"].contains(&net)) {
                        continue;
                    }
                    n += 1;
                    let (p, q) = reality_keys();
                    let ib = Inbound {
                        id: format!("t{}", n), remark: format!("{}-{}-{}", proto, net, sec), enabled: true, server: "local".into(), protocol: proto.into(),
                        port: 20000 + n, network: net.into(), security: sec.into(), path: "/p".into(), host: "x.example.com".into(), service: "svc".into(),
                        flow: if proto == "vless" && net == "tcp" && sec != "none" { "xtls-rprx-vision".into() } else { String::new() },
                        ss_method: "2022-blake3-aes-128-gcm".into(), ss_key: b64_std(&[9u8; 16]), sni: "x.example.com".into(), cert: cert.clone(), key: key.clone(),
                        dest: "www.microsoft.com:443".into(), names: "www.microsoft.com".into(), private: p, public: q, short_ids: "a1b2c3d4".into(),
                        sniffing: true, ..Default::default()
                    };
                    let s = XraySettings { on: true, servers: vec![XServer { server: "local".into(), address: "203.0.113.9".into() }], inbounds: vec![ib.clone()], block_private: true, block_bt: true, ..Default::default() };
                    std::fs::write(format!("{}/{}.json", out, ib.remark), build_config(&s, "local", std::slice::from_ref(&u)).to_string()).unwrap();
                    let l = link_with(&s, &ib, &u, "203.0.113.9").unwrap();
                    std::fs::write(format!("{}/{}.link", out, ib.remark), l).unwrap();
                }
            }
        }
    }

    fn test_user() -> User {
        User {
            id: 0, username: String::new(), code: String::new(), limit_gb: 0.0, used_bytes: 0, expires_at: 0, max_conn: 0, enabled: true,
            protocols: String::new(), nodes: String::new(), notes: String::new(), tg_id: 0, created_at: 0, last_seen: 0, online: 0, warned: 0,
        }
    }
}
