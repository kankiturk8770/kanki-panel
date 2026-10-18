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
    /// listen address ("" = every address)
    pub listen: String,
    /// the inbound stops when its traffic passes this (GB, 0 = no limit) or at this time (0 = never)
    pub total_gb: f64,
    pub expire: i64,
    /// sniffing: what to look at (empty = http, tls, quic), use it for the destination too (not only
    /// for routing), and only the connection metadata
    pub sniff_dest: Vec<String>,
    pub sniff_override: bool,
    pub sniff_meta: bool,
    /// accept the PROXY protocol (behind nginx / HAProxy)
    pub proxy_protocol: bool,
    /// TLS: lowest version, refuse unknown SNI, or a certificate from files on the server
    pub tls_min: String,
    pub reject_sni: bool,
    pub cert_file: String,
    pub key_file: String,
    /// REALITY: PROXY protocol version to the target, largest clock difference (ms)
    pub xver: u8,
    pub max_time_diff: u64,
    /// WebSocket heartbeat (seconds)
    pub heartbeat: u32,
    /// gRPC: multi mode and authority (in the link)
    pub multi_mode: bool,
    pub authority: String,
    /// XHTTP padding, like 100-1000
    pub x_padding: String,
    /// mKCP tuning
    pub kcp_mtu: u32,
    pub kcp_tti: u32,
    pub kcp_up: u32,
    pub kcp_down: u32,
    pub kcp_cong: bool,
    /// VLESS / Trojan over TCP: where other traffic goes
    pub fallbacks: Vec<Fallback>,
    /// TLS: the certificate of the SNI domain from certbot on the server (Let's Encrypt, renewed by itself)
    pub acme: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct Fallback {
    pub name: String,
    pub alpn: String,
    pub path: String,
    /// port, addr:port or a unix socket path
    pub dest: String,
    pub xver: u8,
}

/// A routing rule built in the panel: what matches, and the outbound it goes to.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct XRule {
    pub name: String,
    pub off: bool,
    /// lists separated by commas or new lines (geosite:, domain:, regexp:, geoip:, CIDR ...)
    pub domain: String,
    pub ip: String,
    pub port: String,
    /// tcp | udp | tcp,udp | ""
    pub network: String,
    /// http, tls, bittorrent, quic
    pub protocol: String,
    /// inbound ids
    pub inbound: Vec<String>,
    /// panel user ids
    pub users: Vec<i64>,
    /// outbound tag (direct, block or one of ours)
    pub outbound: String,
}

/// An outbound built in the panel.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct XOut {
    pub tag: String,
    /// freedom | blackhole | socks | http | link | json
    pub kind: String,
    pub address: String,
    pub port: u16,
    pub user: String,
    pub pass: String,
    /// kind "link": a vless:// vmess:// trojan:// ss:// link of another server
    pub link: String,
    /// kind "json": the whole outbound
    pub json: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct XServer {
    /// agent server id, or "local"
    pub server: String,
    /// the address users connect to (domain or IP); empty = the address the server reports from
    pub address: String,
    /// `address` is a domain: the server gets its certificate with certbot, and the server's TLS
    /// inbounds with the automatic certificate use it
    pub ssl: bool,
}

/// A domain (not an IP, not empty)?
fn is_domain(d: &str) -> bool {
    let d = d.trim().trim_matches('.');
    d.parse::<std::net::IpAddr>().is_err()
        && d.contains('.')
        && d.split('.').all(|l| !l.is_empty() && l.len() <= 63 && l.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-'))
}

/// The domain of a server whose certificate the panel keeps ("" = none).
pub fn server_domain(s: &XraySettings, sid: &str) -> String {
    s.servers.iter().find(|x| x.server == sid && x.ssl && is_domain(&x.address)).map(|x| x.address.trim().trim_matches('.').to_ascii_lowercase()).unwrap_or_default()
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
    /// none | error | warning | info | debug ("" = warning)
    pub log_level: String,
    /// AsIs | IPIfNonMatch | IPOnDemand
    pub domain_strategy: String,
    /// Xray's own DNS servers (comma separated, empty = the system's)
    pub dns: String,
    /// resolve and connect over IPv4 only
    pub ipv4: bool,
    pub block_ads: bool,
    /// block Iranian sites and addresses (they must not see the server)
    pub block_ir: bool,
    pub rule_list: Vec<XRule>,
    pub outs: Vec<XOut>,
    /// the outbound everything else goes to ("" = direct)
    pub default_out: String,
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
        "ws" => {
            st["wsSettings"] = json!({ "path": path, "host": ib.host });
            if ib.heartbeat > 0 {
                st["wsSettings"]["heartbeatPeriod"] = json!(ib.heartbeat);
            }
        }
        "httpupgrade" => st["httpupgradeSettings"] = json!({ "path": path, "host": ib.host }),
        "xhttp" => {
            st["xhttpSettings"] = json!({ "path": path, "host": ib.host, "mode": if ib.mode.is_empty() { "auto" } else { ib.mode.as_str() } });
            if !ib.x_padding.trim().is_empty() {
                st["xhttpSettings"]["xPaddingBytes"] = json!(ib.x_padding.trim());
            }
        }
        "grpc" => st["grpcSettings"] = json!({ "serviceName": ib.service }),
        // Xray 26 removed the mKCP seed and header (now "finalmask"): plain mKCP
        "kcp" => {
            let mut k = json!({});
            for (name, v) in [("mtu", ib.kcp_mtu), ("tti", ib.kcp_tti), ("uplinkCapacity", ib.kcp_up), ("downlinkCapacity", ib.kcp_down)] {
                if v > 0 {
                    k[name] = json!(v);
                }
            }
            if ib.kcp_cong {
                k["congestion"] = json!(true);
            }
            st["kcpSettings"] = k;
        }
        _ => {
            if ib.header == "http" {
                st["tcpSettings"] = json!({ "header": { "type": "http", "request": { "path": [path], "headers": { "Host": list(&ib.host) } } } });
            }
        }
    }
    match ib.security.as_str() {
        "tls" => {
            st["security"] = json!("tls");
            let cert = if ib.acme {
                let (c, k) = crate::certbot::files(ib.sni.trim());
                json!({ "certificateFile": c, "keyFile": k })
            } else if !ib.cert_file.trim().is_empty() {
                json!({ "certificateFile": ib.cert_file.trim(), "keyFile": ib.key_file.trim() })
            } else {
                json!({ "certificate": pem_lines(&ib.cert), "key": pem_lines(&ib.key) })
            };
            st["tlsSettings"] = json!({
                "serverName": ib.sni,
                "alpn": if ib.alpn.is_empty() { vec!["h2".to_string(), "http/1.1".to_string()] } else { list(&ib.alpn) },
                "certificates": [cert],
            });
            if !ib.tls_min.is_empty() {
                st["tlsSettings"]["minVersion"] = json!(ib.tls_min);
            }
            if ib.reject_sni {
                st["tlsSettings"]["rejectUnknownSni"] = json!(true);
            }
        }
        "reality" => {
            st["security"] = json!("reality");
            st["realitySettings"] = json!({
                "show": false, "dest": ib.dest, "xver": ib.xver, "serverNames": list(&ib.names),
                "privateKey": ib.private, "shortIds": list(&ib.short_ids),
            });
            if ib.max_time_diff > 0 {
                st["realitySettings"]["maxTimeDiff"] = json!(ib.max_time_diff);
            }
        }
        _ => {}
    }
    if ib.proxy_protocol && ib.network != "kcp" {
        st["sockopt"] = json!({ "acceptProxyProtocol": true });
    }
    st
}

fn fallbacks_json(ib: &Inbound) -> Vec<Value> {
    ib.fallbacks
        .iter()
        .filter(|f| !f.dest.trim().is_empty())
        .map(|f| {
            let d = f.dest.trim();
            let mut v = json!({ "dest": d.parse::<u16>().map(|p| json!(p)).unwrap_or(json!(d)) });
            if !f.name.trim().is_empty() {
                v["name"] = json!(f.name.trim());
            }
            if !f.alpn.trim().is_empty() {
                v["alpn"] = json!(f.alpn.trim());
            }
            if !f.path.trim().is_empty() {
                v["path"] = json!(f.path.trim());
            }
            if f.xver > 0 {
                v["xver"] = json!(f.xver);
            }
            v
        })
        .collect()
}

fn inbound_json(ib: &Inbound, users: &[User]) -> Value {
    let cl = clients(ib, users);
    let mut settings = match ib.protocol.as_str() {
        "vless" => json!({ "clients": cl, "decryption": "none" }),
        "shadowsocks" if is_2022(&ib.ss_method) => json!({ "method": ib.ss_method, "password": ib.ss_key, "clients": cl, "network": "tcp,udp" }),
        "shadowsocks" => json!({ "clients": cl, "network": "tcp,udp" }),
        _ => json!({ "clients": cl }),
    };
    let fb = fallbacks_json(ib);
    if !fb.is_empty() && (ib.protocol == "vless" || ib.protocol == "trojan") && ib.network == "tcp" && ib.security != "reality" {
        settings["fallbacks"] = json!(fb);
    }
    let listen = if ib.listen.trim().is_empty() { "0.0.0.0" } else { ib.listen.trim() };
    let mut v = json!({ "tag": format!("in-{}", ib.id), "listen": listen, "port": ib.port, "protocol": ib.protocol, "settings": settings, "streamSettings": stream(ib) });
    if ib.sniffing {
        let dest: Vec<String> = if ib.sniff_dest.is_empty() { vec!["http".into(), "tls".into(), "quic".into()] } else { ib.sniff_dest.clone() };
        v["sniffing"] = json!({ "enabled": true, "destOverride": dest, "routeOnly": !ib.sniff_override });
        if ib.sniff_meta {
            v["sniffing"]["metadataOnly"] = json!(true);
        }
    }
    v
}

const PRIVATE_NETS: &[&str] = &["0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7", "fe80::/10", "::1/128"];

/// The outbound of a panel-built outbound (None when it cannot be built).
pub fn out_json(o: &XOut, ipv4: bool) -> Result<Value, String> {
    let tag = o.tag.trim();
    let mut v = match o.kind.as_str() {
        "blackhole" => json!({ "protocol": "blackhole" }),
        "socks" | "http" => {
            if o.address.trim().is_empty() || o.port == 0 {
                return Err(format!("{}: address and port are required", tag));
            }
            let mut srv = json!({ "address": o.address.trim(), "port": o.port });
            if !o.user.is_empty() {
                srv["users"] = json!([{ "user": o.user, "pass": o.pass }]);
            }
            json!({ "protocol": o.kind, "settings": { "servers": [srv] } })
        }
        "link" => link_outbound(o.link.trim())?,
        "json" => match serde_json::from_str::<Value>(&o.json) {
            Ok(Value::Object(m)) => Value::Object(m),
            _ => return Err(format!("{}: the outbound is not a JSON object", tag)),
        },
        _ => json!({ "protocol": "freedom", "settings": if ipv4 { json!({ "domainStrategy": "UseIPv4" }) } else { json!({}) } }),
    };
    v["tag"] = json!(tag);
    Ok(v)
}

fn csv(s: &str) -> Vec<String> {
    s.split([',', '\n']).map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect()
}

fn rule_json(r: &XRule, tags: &[String]) -> Option<Value> {
    let mut v = json!({ "type": "field" });
    let mut any = false;
    for (k, val) in [("domain", csv(&r.domain)), ("ip", csv(&r.ip)), ("protocol", csv(&r.protocol))] {
        if !val.is_empty() {
            v[k] = json!(val);
            any = true;
        }
    }
    if !r.port.trim().is_empty() {
        v["port"] = json!(r.port.trim().replace(' ', ""));
        any = true;
    }
    if !r.network.trim().is_empty() {
        v["network"] = json!(r.network.trim());
        any = true;
    }
    if !r.inbound.is_empty() {
        v["inboundTag"] = json!(r.inbound.iter().map(|i| format!("in-{}", i)).collect::<Vec<_>>());
        any = true;
    }
    if !r.users.is_empty() {
        v["user"] = json!(r.users.iter().map(|i| format!("u{}", i)).collect::<Vec<_>>());
        any = true;
    }
    let out = if r.outbound.is_empty() { "direct".to_string() } else { r.outbound.clone() };
    if !any || r.off || !tags.contains(&out) {
        return None;
    }
    v["outboundTag"] = json!(out);
    Some(v)
}

pub fn build_config(s: &XraySettings, sid: &str, users: &[User]) -> Value {
    let inbounds: Vec<Value> = s.inbounds.iter().filter(|ib| ib.enabled && ib.server == sid).map(|ib| inbound_json(ib, users)).collect();
    let mut outbounds = vec![json!({ "protocol": "freedom", "tag": "direct", "settings": if s.ipv4 { json!({ "domainStrategy": "UseIPv4" }) } else { json!({}) } }), json!({ "protocol": "blackhole", "tag": "block" })];
    for o in &s.outs {
        if let Ok(v) = out_json(o, s.ipv4) {
            outbounds.push(v);
        }
    }
    if let Ok(Value::Array(extra)) = serde_json::from_str::<Value>(&s.outbounds) {
        // a custom outbound first becomes the default route
        let mut e = extra;
        e.extend(outbounds);
        outbounds = e;
    }
    // the chosen default goes first (Xray sends what no rule catches to the first outbound)
    if !s.default_out.is_empty() {
        if let Some(i) = outbounds.iter().position(|o| o["tag"].as_str() == Some(s.default_out.as_str())) {
            let d = outbounds.remove(i);
            outbounds.insert(0, d);
        }
    }
    let tags: Vec<String> = outbounds.iter().filter_map(|o| o["tag"].as_str().map(|t| t.to_string())).collect();
    let mut rules = vec![json!({ "type": "field", "inboundTag": ["api"], "outboundTag": "api" })];
    if s.block_private {
        rules.push(json!({ "type": "field", "ip": PRIVATE_NETS, "outboundTag": "block" }));
    }
    if s.block_bt {
        rules.push(json!({ "type": "field", "protocol": ["bittorrent"], "outboundTag": "block" }));
    }
    if s.block_ads {
        rules.push(json!({ "type": "field", "domain": ["geosite:category-ads-all"], "outboundTag": "block" }));
    }
    if s.block_ir {
        rules.push(json!({ "type": "field", "domain": ["domain:ir", "geosite:category-ir"], "outboundTag": "block" }));
        rules.push(json!({ "type": "field", "ip": ["geoip:ir"], "outboundTag": "block" }));
    }
    rules.extend(s.rule_list.iter().filter_map(|r| rule_json(r, &tags)));
    if let Ok(Value::Array(extra)) = serde_json::from_str::<Value>(&s.rules) {
        rules.extend(extra);
    }
    let level = if s.log_level.is_empty() { "warning" } else { s.log_level.as_str() };
    let strategy = if s.domain_strategy.is_empty() { "AsIs" } else { s.domain_strategy.as_str() };
    let mut cfg = json!({
        "log": { "loglevel": level, "access": "none" },
        "api": { "tag": "api", "listen": format!("127.0.0.1:{}", super::API_PORT), "services": ["HandlerService", "StatsService"] },
        "stats": {},
        "policy": {
            "levels": { "0": { "statsUserUplink": true, "statsUserDownlink": true } },
            "system": { "statsInboundUplink": true, "statsInboundDownlink": true },
        },
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": { "domainStrategy": strategy, "rules": rules },
    });
    let dns = csv(&s.dns);
    if !dns.is_empty() {
        cfg["dns"] = json!({ "servers": dns, "queryStrategy": if s.ipv4 { "UseIPv4" } else { "UseIP" } });
    }
    cfg
}

// ------------------------------------------------------------------ an outbound from a share link

fn query_map(q: &str) -> HashMap<String, String> {
    q.split('&')
        .filter_map(|kv| {
            let mut it = kv.splitn(2, '=');
            let k = it.next()?.to_string();
            Some((k, crate::util::pct_decode(it.next().unwrap_or(""))))
        })
        .collect()
}

fn b64_any(s: &str) -> Option<Vec<u8>> {
    let t = s.trim().replace('-', "+").replace('_', "/");
    let pad = (4 - t.len() % 4) % 4;
    crate::tunnel::link::b64decode(&format!("{}{}", t, "=".repeat(pad)))
}

fn split_host_port(hp: &str) -> Option<(String, u16)> {
    let (h, p) = if let Some(rest) = hp.strip_prefix('[') {
        let i = rest.find(']')?;
        (rest[..i].to_string(), rest[i + 1..].strip_prefix(':')?)
    } else {
        let i = hp.rfind(':')?;
        (hp[..i].to_string(), &hp[i + 1..])
    };
    Some((h, p.parse().ok()?))
}

/// The stream settings a client uses for a link's transport and security.
fn client_stream(q: &HashMap<String, String>) -> Value {
    let g = |k: &str| q.get(k).cloned().unwrap_or_default();
    let net = { let n = g("type"); if n.is_empty() { "tcp".to_string() } else { n } };
    let mut st = json!({ "network": net });
    let path = { let p = g("path"); if p.is_empty() { "/".to_string() } else { p } };
    match net.as_str() {
        "ws" => st["wsSettings"] = json!({ "path": path, "host": g("host") }),
        "httpupgrade" => st["httpupgradeSettings"] = json!({ "path": path, "host": g("host") }),
        "xhttp" | "splithttp" => {
            st["network"] = json!("xhttp");
            st["xhttpSettings"] = json!({ "path": path, "host": g("host"), "mode": if g("mode").is_empty() { "auto".to_string() } else { g("mode") } });
        }
        "grpc" => st["grpcSettings"] = json!({ "serviceName": g("serviceName"), "multiMode": g("mode") == "multi", "authority": g("authority") }),
        "kcp" => st["kcpSettings"] = json!({}),
        _ => {
            if g("headerType") == "http" {
                st["tcpSettings"] = json!({ "header": { "type": "http", "request": { "path": [path], "headers": { "Host": csv(&g("host")) } } } });
            }
        }
    }
    let fp = { let f = g("fp"); if f.is_empty() { "chrome".to_string() } else { f } };
    match g("security").as_str() {
        "tls" => {
            let mut t = json!({ "serverName": g("sni"), "fingerprint": fp });
            if !g("alpn").is_empty() {
                t["alpn"] = json!(csv(&g("alpn")));
            }
            if g("allowInsecure") == "1" || g("insecure") == "1" {
                t["allowInsecure"] = json!(true);
            }
            st["security"] = json!("tls");
            st["tlsSettings"] = t;
        }
        "reality" => {
            st["security"] = json!("reality");
            st["realitySettings"] = json!({ "serverName": g("sni"), "fingerprint": fp, "publicKey": g("pbk"), "shortId": g("sid"), "spiderX": g("spx") });
        }
        _ => {}
    }
    st
}

/// Turn a vless:// vmess:// trojan:// ss:// link into an Xray outbound (for chaining to another server).
pub fn link_outbound(link: &str) -> Result<Value, String> {
    let link = link.trim();
    let bad = || "the link is not a vless, vmess, trojan or ss link".to_string();
    let (scheme, rest) = link.split_once("://").ok_or_else(bad)?;
    let rest = rest.split('#').next().unwrap_or("");
    if scheme == "vmess" {
        let raw = b64_any(rest).ok_or_else(bad)?;
        let j: Value = serde_json::from_slice(&raw).map_err(|_| bad())?;
        let s = |k: &str| match &j[k] { Value::String(x) => x.clone(), Value::Number(n) => n.to_string(), _ => String::new() };
        let mut q: HashMap<String, String> = HashMap::new();
        q.insert("type".into(), s("net"));
        q.insert("security".into(), if s("tls") == "tls" { "tls".into() } else { String::new() });
        q.insert("sni".into(), s("sni"));
        q.insert("fp".into(), s("fp"));
        q.insert("alpn".into(), s("alpn"));
        q.insert("host".into(), s("host"));
        q.insert("mode".into(), s("mode"));
        q.insert("headerType".into(), s("type"));
        if s("net") == "grpc" {
            q.insert("serviceName".into(), s("path"));
        } else {
            q.insert("path".into(), s("path"));
        }
        let port: u16 = s("port").parse().map_err(|_| bad())?;
        return Ok(json!({
            "protocol": "vmess",
            "settings": { "vnext": [{ "address": s("add"), "port": port, "users": [{ "id": s("id"), "security": if s("scy").is_empty() { "auto".to_string() } else { s("scy") } }] }] },
            "streamSettings": client_stream(&q),
        }));
    }
    let (userinfo, hostq) = rest.rsplit_once('@').ok_or_else(bad)?;
    let (hp, query) = hostq.split_once('?').unwrap_or((hostq, ""));
    let hp = hp.trim_end_matches('/');
    let (host, port) = split_host_port(hp).ok_or_else(bad)?;
    let q = query_map(query);
    if q.get("security").map(|x| x.as_str()) == Some("reality") {
        let ok = q.get("pbk").and_then(|k| b64_any(k)).map(|k| k.len() == 32).unwrap_or(false);
        if !ok {
            return Err("the REALITY public key (pbk) in the link is not valid".into());
        }
    }
    match scheme {
        "vless" => {
            let mut u = json!({ "id": crate::util::pct_decode(userinfo), "encryption": q.get("encryption").cloned().filter(|x| !x.is_empty()).unwrap_or_else(|| "none".into()) });
            if let Some(f) = q.get("flow").filter(|f| !f.is_empty()) {
                u["flow"] = json!(f);
            }
            Ok(json!({ "protocol": "vless", "settings": { "vnext": [{ "address": host, "port": port, "users": [u] }] }, "streamSettings": client_stream(&q) }))
        }
        "trojan" => Ok(json!({ "protocol": "trojan", "settings": { "servers": [{ "address": host, "port": port, "password": crate::util::pct_decode(userinfo) }] }, "streamSettings": client_stream(&q) })),
        "ss" => {
            let ui = crate::util::pct_decode(userinfo);
            let dec = if ui.contains(':') { ui.into_bytes() } else { b64_any(&ui).ok_or_else(bad)? };
            let dec = String::from_utf8(dec).map_err(|_| bad())?;
            let (method, pass) = dec.split_once(':').ok_or_else(bad)?;
            Ok(json!({ "protocol": "shadowsocks", "settings": { "servers": [{ "address": host, "port": port, "method": method, "password": pass }] } }))
        }
        _ => Err(bad()),
    }
}

// ------------------------------------------------------------------ inbound traffic and limits

/// Traffic of each inbound (id -> bytes), kept across restarts until the admin resets it.
pub fn ib_traffic(app: &App) -> HashMap<String, i64> {
    serde_json::from_str(&app.db.get("xray_ibt")).unwrap_or_default()
}

/// Add what each inbound moved since the server's last report (its running totals by tag).
fn count_inbounds(app: &App, sid: &str, st: &Value) {
    let Some(run) = st["run"].as_str() else { return };
    let Some(ins) = st["inbounds"].as_object() else { return };
    let key = format!("xray_ibprev_{}", sid);
    let prev: Value = serde_json::from_str(&app.db.get(&key)).unwrap_or(json!({}));
    let same = prev["run"].as_str() == Some(run);
    let mut totals = ib_traffic(app);
    let mut moved = false;
    for (tag, v) in ins {
        let bytes = v.as_i64().unwrap_or(0).max(0);
        let before = if same { prev["inbounds"][tag].as_i64().unwrap_or(0) } else { 0 };
        let delta = if bytes >= before { bytes - before } else { bytes };
        if delta > 0 {
            if let Some(id) = tag.strip_prefix("in-") {
                *totals.entry(id.to_string()).or_default() += delta;
                moved = true;
            }
        }
    }
    if moved {
        app.db.set("xray_ibt", &serde_json::to_string(&totals).unwrap_or_default());
    }
    if moved || !same {
        app.db.set(&key, &json!({ "run": run, "inbounds": ins }).to_string());
    }
}

/// "" (working), "depleted" (its traffic limit is used up) or "expired".
pub fn ib_state(ib: &Inbound, used: i64) -> &'static str {
    if ib.total_gb > 0.0 && crate::util::gb(used) >= ib.total_gb {
        "depleted"
    } else if ib.expire > 0 && now() >= ib.expire {
        "expired"
    } else {
        ""
    }
}

/// The settings with only the inbounds that may run now.
fn runnable(app: &App) -> XraySettings {
    let mut s = settings(app);
    let t = ib_traffic(app);
    s.inbounds.retain(|ib| ib.enabled && ib_state(ib, t.get(&ib.id).copied().unwrap_or(0)).is_empty());
    s
}

/// The Xray config of server `sid` and its version, or None when it runs no Xray.
pub fn cfg_for(app: &App, sid: &str) -> Option<(XrayCfg, String)> {
    let s = runnable(app);
    let domain = server_domain(&s, sid);
    // a server with its own domain gets its SSL right away, even before it has an inbound
    if !s.on || !s.servers.iter().any(|x| x.server == sid) || (!s.inbounds.iter().any(|ib| ib.enabled && ib.server == sid) && domain.is_empty()) {
        return None;
    }
    let c = XrayCfg { config: build_config(&s, sid, &xray_users(app)), version: s.version.clone(), certs: if domain.is_empty() { vec![] } else { vec![domain] } };
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
    let host = if !ib.link_host.trim().is_empty() {
        ib.link_host.trim().to_string()
    } else if ib.acme && ib.security == "tls" && !ib.sni.trim().is_empty() {
        ib.sni.trim().to_string()
    } else {
        server_addr.to_string()
    };
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
    let s = runnable(app);
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

/// (user id, server) of the users whose Xray traffic moved in the last report of each server,
/// for reports younger than `fresh` seconds
pub fn online_now(fresh: i64) -> Vec<(i64, String)> {
    let t = now();
    last_status()
        .lock()
        .unwrap()
        .iter()
        .filter(|(_, (at, _))| t - *at <= fresh)
        .flat_map(|(sid, (_, v))| v["online"].as_array().cloned().unwrap_or_default().into_iter().filter_map(|x| x.as_i64()).map(move |u| (u, sid.clone())).collect::<Vec<_>>())
        .collect()
}

pub fn ingest(app: &App, sid: &str, st: &Value) {
    if st.is_null() {
        last_status().lock().unwrap().remove(sid);
        return;
    }
    last_status().lock().unwrap().insert(sid.to_string(), (now(), st.clone()));
    crate::dns::panel::count_usage(app, &format!("xray_prev_{}", sid), st);
    count_inbounds(app, sid, st);
    // online now: the users whose traffic moved since the previous read
    if let Some(on) = st["online"].as_array() {
        for id in on.iter().filter_map(|x| x.as_i64()) {
            let _ = app.db.exec("UPDATE users SET last_seen=?1 WHERE id=?2", &[&now(), &id]);
        }
    }
}

/// The panel server itself can run Xray too: deploy and count here every 15 seconds.
pub async fn local_loop(app: Arc<App>) {
    let mut last_err = String::new();
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(15)).await;
        let cfg = cfg_for(&app, "local");
        if cfg.is_none() && !std::path::Path::new(super::UNIT).exists() {
            continue;
        }
        let force = take_repair("local") && cfg.is_some();
        let r = tokio::task::spawn_blocking(move || {
            let applied = super::applied_ver();
            if force {
                super::repair_prep();
            }
            let res = match &cfg {
                Some((c, v)) if force || *v != applied || !super::running() => super::deploy(Some((c, v)), None),
                Some(_) => Ok(()),
                None => super::deploy(None, None),
            };
            (res, super::status())
        })
        .await;
        if let Ok((res, mut st)) = r {
            match res {
                Err(e) => {
                    // the same error is logged once, not on every round
                    if e != last_err {
                        eprintln!("xray: {}", e);
                        last_err = e.clone();
                    }
                    if st.is_object() {
                        st["deploy_error"] = json!(e);
                    }
                }
                Ok(()) => last_err.clear(),
            }
            ingest(&app, "local", &st);
        }
    }
}

// ------------------------------------------------------------------ repair (asked in the panel)

fn repairs() -> &'static Mutex<std::collections::HashSet<String>> {
    static S: OnceLock<Mutex<std::collections::HashSet<String>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(std::collections::HashSet::new()))
}

/// Was a repair asked for this server? (asked once: reading it clears it)
pub fn take_repair(sid: &str) -> bool {
    repairs().lock().unwrap().remove(sid)
}

/// Seconds since the server last reported (None = never since the panel started)
fn report_age(sid: &str) -> Option<i64> {
    last_status().lock().unwrap().get(sid).map(|(at, _)| now() - *at)
}

async fn repair_server(State(app): St, h: HeaderMap, Path(id): Path<String>) -> Response {
    let _ = guard!(app, h, "nodes");
    let s = settings(&app);
    if !s.servers.iter().any(|x| x.server == id) {
        return err(StatusCode::NOT_FOUND, "this server is not an Xray server");
    }
    if cfg_for(&app, &id).is_none() {
        return err(StatusCode::BAD_REQUEST, "nothing runs on this server: Xray is off, or the server has no inbound that is on");
    }
    repairs().lock().unwrap().insert(id.clone());
    let age = report_age(&id);
    Json(json!({ "ok": true, "waiting": age.map(|a| a > 60).unwrap_or(true), "age": age })).into_response()
}

// ------------------------------------------------------------------ admin API

pub fn router() -> Router<Arc<App>> {
    Router::new()
        .route("/api/xray", get(get_all).put(put_settings))
        .route("/api/xray/servers", post(put_server))
        .route("/api/xray/servers/:id", delete(del_server))
        .route("/api/xray/servers/:id/repair", post(repair_server))
        .route("/api/xray/inbounds", post(put_inbound))
        .route("/api/xray/inbounds/:id", delete(del_inbound))
        .route("/api/xray/inbounds/:id/reset", post(reset_inbound))
        .route("/api/xray/inbounds/:id/clone", post(clone_inbound))
        .route("/api/xray/inbounds/:id/clients", get(inbound_clients))
        .route("/api/xray/inbounds/:id/json", get(inbound_preview))
        .route("/api/xray/outs/check", post(check_out))
        .route("/api/xray/keys", post(new_keys))
        .route("/api/xray/config/:id", get(preview))
        .route("/tunnel/xraybin", post(agent_xraybin))
}

async fn get_all(State(app): St, h: HeaderMap) -> Response {
    let _ = guard!(app, h, "nodes");
    let s = settings(&app);
    let mut names = crate::tunnel::panel::server_names(&app);
    names.insert("local".into(), app.env.get("LOCAL_NAME").cloned().filter(|x| !x.is_empty()).unwrap_or_else(|| "Main".into()));
    let locs = crate::tunnel::panel::server_locs(&app);
    let st = last_status().lock().unwrap().clone();
    let servers: Vec<Value> = s
        .servers
        .iter()
        .map(|x| {
            let (at, status) = st.get(&x.server).cloned().unwrap_or((0, Value::Null));
            json!({ "server": x.server, "name": names.get(&x.server).cloned().unwrap_or_default(), "address": x.address,
                "effective": server_address(&app, &s, &x.server), "status": status, "status_at": at, "ssl": x.ssl,
                "domain": server_domain(&s, &x.server) })
        })
        .collect();
    let users = xray_users(&app);
    let totals = ib_traffic(&app);
    let inbounds: Vec<Value> = s
        .inbounds
        .iter()
        .map(|ib| {
            let mut v = serde_json::to_value(ib).unwrap_or(json!({}));
            v["clients"] = json!(users.iter().filter(|u| ib.only.is_empty() || ib.only.contains(&u.id)).count());
            let used = totals.get(&ib.id).copied().unwrap_or(0);
            v["traffic"] = json!(used);
            v["state"] = json!(ib_state(ib, used));
            // automatic SSL: the server says which certificates it has (and why one failed)
            if ib.acme {
                if let Some((_, sv)) = st.get(&ib.server) {
                    let have = sv["certs"].as_array().map(|a| a.iter().any(|d| d.as_str() == Some(ib.sni.as_str()))).unwrap_or(false);
                    v["cert_err"] = sv["cert_errors"][&ib.sni].clone();
                    if !have && ib.enabled && v["state"] == "" {
                        v["state"] = json!("nocert");
                    }
                }
            }
            v["server_name"] = json!(names.get(&ib.server).cloned().unwrap_or_default());
            // the private keys never leave the panel in a listing
            v["key"] = json!(if ib.key.is_empty() { "" } else { "set" });
            v["private"] = json!(if ib.private.is_empty() { "" } else { "set" });
            v
        })
        .collect();
    let all_users = app.db.users();
    let uname: HashMap<i64, String> = all_users.iter().map(|u| (u.id, u.username.clone())).collect();
    let mut online = vec![];
    for (sid, (_, v)) in st.iter() {
        for id in v["online"].as_array().into_iter().flatten().filter_map(|x| x.as_i64()) {
            online.push(json!({ "id": id, "name": uname.get(&id).cloned().unwrap_or_else(|| format!("#{}", id)), "server": names.get(sid).cloned().unwrap_or_default() }));
        }
    }
    Json(json!({
        "on": s.on, "version": s.version, "block_private": s.block_private, "block_bt": s.block_bt, "rules": s.rules, "outbounds": s.outbounds,
        "log_level": s.log_level, "domain_strategy": s.domain_strategy, "dns": s.dns, "ipv4": s.ipv4, "block_ads": s.block_ads, "block_ir": s.block_ir,
        "rule_list": s.rule_list, "outs": s.outs.iter().map(|o| { let mut v = serde_json::to_value(o).unwrap_or(json!({})); v["error"] = json!(out_json(o, s.ipv4).err()); v }).collect::<Vec<_>>(),
        "default_out": s.default_out, "online": online,
        "servers": servers, "inbounds": inbounds, "users": users.len(),
        "agents": names.iter().map(|(k, v)| json!({ "id": k, "name": v, "loc": locs.get(k).map(|x| x.0.clone()).unwrap_or_default() })).collect::<Vec<_>>(),
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
    if let Some(v) = b["log_level"].as_str() {
        if !["", "none", "error", "warning", "info", "debug"].contains(&v) {
            return err(StatusCode::BAD_REQUEST, "log level: none, error, warning, info or debug");
        }
        s.log_level = v.to_string();
    }
    if let Some(v) = b["domain_strategy"].as_str() {
        if !["", "AsIs", "IPIfNonMatch", "IPOnDemand"].contains(&v) {
            return err(StatusCode::BAD_REQUEST, "domain strategy: AsIs, IPIfNonMatch or IPOnDemand");
        }
        s.domain_strategy = v.to_string();
    }
    if let Some(v) = b["dns"].as_str() {
        s.dns = csv(v).join(", ");
    }
    for (k, field) in [("ipv4", &mut s.ipv4), ("block_ads", &mut s.block_ads), ("block_ir", &mut s.block_ir)] {
        if let Some(v) = b[k].as_bool() {
            *field = v;
        }
    }
    if b["outs"].is_array() {
        let outs: Vec<XOut> = match serde_json::from_value(b["outs"].clone()) {
            Ok(x) => x,
            Err(e) => return err(StatusCode::BAD_REQUEST, &e.to_string()),
        };
        let mut seen: Vec<String> = vec!["direct".into(), "block".into(), "api".into()];
        for o in &outs {
            let t = o.tag.trim();
            if t.is_empty() || !t.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
                return err(StatusCode::BAD_REQUEST, "an outbound tag is English letters, digits, - and _");
            }
            if seen.iter().any(|x| x == t) {
                return err(StatusCode::BAD_REQUEST, &format!("the outbound tag {} is used twice (direct, block and api are taken)", t));
            }
            seen.push(t.to_string());
            if let Err(e) = out_json(o, s.ipv4) {
                return err(StatusCode::BAD_REQUEST, &e);
            }
        }
        s.outs = outs;
    }
    if b["rule_list"].is_array() {
        match serde_json::from_value::<Vec<XRule>>(b["rule_list"].clone()) {
            Ok(x) => s.rule_list = x,
            Err(e) => return err(StatusCode::BAD_REQUEST, &e.to_string()),
        }
    }
    if let Some(v) = b["default_out"].as_str() {
        s.default_out = v.trim().to_string();
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
    let address = b["address"].as_str().unwrap_or("").trim().trim_matches('.').to_string();
    let ssl = b["ssl"].as_bool().unwrap_or(false) && is_domain(&address);
    if b["ssl"].as_bool() == Some(true) && !address.is_empty() && !is_domain(&address) {
        return err(StatusCode::BAD_REQUEST, "SSL needs a domain (like de.example.com), not an IP");
    }
    let address = if ssl { address.to_ascii_lowercase() } else { address };
    match s.servers.iter_mut().find(|x| x.server == sid) {
        Some(x) => {
            x.address = address.clone();
            x.ssl = ssl;
        }
        None => s.servers.push(XServer { server: sid.clone(), address: address.clone(), ssl }),
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
    if ib.security != "tls" {
        ib.acme = false;
    }
    if ib.acme {
        // empty SNI = the domain of the server (its certificate is shared)
        let d = if ib.sni.trim().is_empty() { server_domain(&s, &ib.server) } else { ib.sni.trim().trim_matches('.').to_ascii_lowercase() };
        let ok = d.contains('.') && d.split('.').all(|l| !l.is_empty() && l.len() <= 63 && l.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-'));
        if !ok {
            return err(StatusCode::BAD_REQUEST, "automatic SSL: give the server its domain (Xray › Servers › Edit) or write the domain in SNI (like de.example.com)");
        }
        ib.sni = d;
        ib.cert.clear();
        ib.key.clear();
        ib.cert_file.clear();
        ib.key_file.clear();
    } else if ib.security == "tls" && !ib.cert_file.trim().is_empty() {
        if !ib.cert_file.trim().starts_with('/') || !ib.key_file.trim().starts_with('/') {
            return err(StatusCode::BAD_REQUEST, "certificate and key files are full paths on the server, like /etc/letsencrypt/live/x/fullchain.pem");
        }
    } else if ib.security == "tls" {
        let test = crate::dns::DnsCfg { cert: ib.cert.clone(), key: ib.key.clone(), ..Default::default() };
        if let Err(e) = crate::dns::engine::check_tls(&test) {
            return err(StatusCode::BAD_REQUEST, &format!("TLS certificate: {}", e));
        }
    }
    if ib.port == 0 {
        return err(StatusCode::BAD_REQUEST, "the port is required");
    }
    ib.listen = ib.listen.trim().to_string();
    if !ib.listen.is_empty() && ib.listen.parse::<std::net::IpAddr>().is_err() {
        return err(StatusCode::BAD_REQUEST, "the listen address is an IP (empty = every address)");
    }
    if !["", "1.0", "1.1", "1.2", "1.3"].contains(&ib.tls_min.as_str()) {
        return err(StatusCode::BAD_REQUEST, "lowest TLS version: 1.0, 1.1, 1.2 or 1.3");
    }
    ib.sniff_dest.retain(|d| ["http", "tls", "quic", "fakedns"].contains(&d.as_str()));
    if ib.total_gb < 0.0 || !ib.total_gb.is_finite() {
        ib.total_gb = 0.0;
    }
    ib.fallbacks.retain(|f| !f.dest.trim().is_empty());
    if ib.xver > 2 || ib.fallbacks.iter().any(|f| f.xver > 2) {
        return err(StatusCode::BAD_REQUEST, "xver is 0, 1 or 2");
    }
    if !ib.x_padding.trim().is_empty() {
        let ok = ib.x_padding.trim().split('-').all(|x| x.parse::<u32>().is_ok()) && ib.x_padding.trim().split('-').count() <= 2;
        if !ok {
            return err(StatusCode::BAD_REQUEST, "XHTTP padding is a number or a range like 100-1000");
        }
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

async fn reset_inbound(State(app): St, h: HeaderMap, Path(id): Path<String>) -> Response {
    let _ = guard!(app, h, "nodes");
    let mut t = ib_traffic(&app);
    t.remove(&id);
    app.db.set("xray_ibt", &serde_json::to_string(&t).unwrap_or_default());
    Json(json!({ "ok": true })).into_response()
}

/// A copy of an inbound on the next free port, switched off until the admin checks it.
async fn clone_inbound(State(app): St, h: HeaderMap, Path(id): Path<String>) -> Response {
    let _ = guard!(app, h, "nodes");
    let mut s = settings(&app);
    let Some(mut ib) = s.inbounds.iter().find(|x| x.id == id).cloned() else { return err(StatusCode::NOT_FOUND, "no such inbound") };
    let taken = taken_ports(&app, &ib.server);
    let mut port = ib.port;
    loop {
        port = if port >= 65000 { 10000 } else { port + 1 };
        if !taken.contains(&port) && !s.inbounds.iter().any(|o| o.server == ib.server && o.port == port) {
            break;
        }
    }
    ib.id = rand_token(6).to_lowercase();
    ib.port = port;
    ib.enabled = false;
    ib.remark = format!("{} copy", ib.remark).trim().to_string();
    s.inbounds.push(ib.clone());
    save(&app, &s);
    Json(json!({ "ok": true, "id": ib.id })).into_response()
}

/// The users of an inbound with their links, traffic and whether they are online.
async fn inbound_clients(State(app): St, h: HeaderMap, Path(id): Path<String>) -> Response {
    let _ = guard!(app, h, "nodes");
    let s = settings(&app);
    let Some(ib) = s.inbounds.iter().find(|x| x.id == id) else { return err(StatusCode::NOT_FOUND, "no such inbound") };
    let online: Vec<i64> = last_status().lock().unwrap().values().flat_map(|(_, v)| v["online"].as_array().cloned().unwrap_or_default()).filter_map(|x| x.as_i64()).collect();
    let list: Vec<Value> = app
        .db
        .users()
        .iter()
        .filter(|u| u.has_proto("xray") && (ib.only.is_empty() || ib.only.contains(&u.id)))
        .map(|u| {
            json!({
                "id": u.id, "name": u.username, "active": u.active(), "online": online.contains(&u.id), "used": u.used_bytes, "limit_gb": u.limit_gb,
                "expires": u.expires_at, "link": link(&app, &s, ib, u).unwrap_or_default(),
            })
        })
        .collect();
    Json(json!({ "clients": list })).into_response()
}

async fn inbound_preview(State(app): St, h: HeaderMap, Path(id): Path<String>) -> Response {
    let _ = guard!(app, h, "nodes");
    let s = settings(&app);
    let Some(ib) = s.inbounds.iter().find(|x| x.id == id) else { return err(StatusCode::NOT_FOUND, "no such inbound") };
    Json(inbound_json(ib, &xray_users(&app))).into_response()
}

/// Build one outbound without saving it (the form shows what Xray will get).
async fn check_out(State(app): St, h: HeaderMap, Json(b): Json<Value>) -> Response {
    let _ = guard!(app, h, "nodes");
    let o: XOut = match serde_json::from_value(b) {
        Ok(x) => x,
        Err(e) => return err(StatusCode::BAD_REQUEST, &e.to_string()),
    };
    match out_json(&o, settings(&app).ipv4) {
        Ok(v) => Json(v).into_response(),
        Err(e) => err(StatusCode::BAD_REQUEST, &e),
    }
}

async fn new_keys(State(app): St, h: HeaderMap) -> Response {
    let _ = guard!(app, h, "nodes");
    let (p, q) = reality_keys();
    Json(json!({ "private": p, "public": q, "short_id": hex::encode(rand::random::<[u8; 8]>()) })).into_response()
}

async fn preview(State(app): St, h: HeaderMap, Path(id): Path<String>) -> Response {
    let _ = guard!(app, h, "nodes");
    // what the server really gets (no stopped inbounds, certificates filled in)
    let s = runnable(&app);
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
    fn links_turn_back_into_outbounds() {
        let u = User { id: 3, username: "ali".into(), code: "99887766".into(), enabled: true, protocols: "xray".into(), ..emit::test_user() };
        let (p, q) = reality_keys();
        let ib = Inbound {
            id: "a".into(), protocol: "vless".into(), port: 443, network: "tcp".into(), security: "reality".into(), flow: "xtls-rprx-vision".into(),
            dest: "www.microsoft.com:443".into(), names: "www.microsoft.com".into(), private: p, public: q.clone(), short_ids: "abcd".into(), ..Default::default()
        };
        let s = XraySettings::default();
        let l = link_with(&s, &ib, &u, "1.2.3.4").unwrap();
        let o = link_outbound(&l).unwrap();
        assert_eq!(o["protocol"], "vless");
        assert_eq!(o["settings"]["vnext"][0]["address"], "1.2.3.4");
        assert_eq!(o["settings"]["vnext"][0]["port"], 443);
        assert_eq!(o["settings"]["vnext"][0]["users"][0]["id"], user_uuid(&u.code));
        assert_eq!(o["settings"]["vnext"][0]["users"][0]["flow"], "xtls-rprx-vision");
        assert_eq!(o["streamSettings"]["realitySettings"]["publicKey"], q);
        assert_eq!(o["streamSettings"]["realitySettings"]["shortId"], "abcd");
        let vm = Inbound { id: "b".into(), protocol: "vmess".into(), port: 8080, network: "ws".into(), security: "none".into(), path: "/x y".into(), host: "h.example".into(), ..Default::default() };
        let o = link_outbound(&link_with(&s, &vm, &u, "5.6.7.8").unwrap()).unwrap();
        assert_eq!(o["settings"]["vnext"][0]["port"], 8080);
        assert_eq!(o["streamSettings"]["wsSettings"]["path"], "/x y");
        let ss = Inbound { id: "c".into(), protocol: "shadowsocks".into(), port: 9000, ss_method: "2022-blake3-aes-128-gcm".into(), ss_key: b64_std(&[1u8; 16]), ..Default::default() };
        let o = link_outbound(&link_with(&s, &ss, &u, "[2001:db8::1]").unwrap()).unwrap();
        assert_eq!(o["settings"]["servers"][0]["method"], "2022-blake3-aes-128-gcm");
        assert_eq!(o["settings"]["servers"][0]["address"], "2001:db8::1");
        assert!(link_outbound("http://example.com").is_err());
        assert!(link_outbound("vless://11111111-2222-4333-8444-555555555555@1.2.3.4:443?type=tcp&security=reality&pbk=abc#x").is_err());
    }

    #[test]
    fn limits_stop_an_inbound() {
        let mut ib = Inbound { total_gb: 1.0, ..Default::default() };
        assert_eq!(ib_state(&ib, 0), "");
        assert_eq!(ib_state(&ib, 2 * 1024 * 1024 * 1024), "depleted");
        ib.total_gb = 0.0;
        ib.expire = 1;
        assert_eq!(ib_state(&ib, 0), "expired");
    }

    #[test]
    fn automatic_certificates_use_the_domain() {
        let u = User { id: 3, username: "ali".into(), code: "99887766".into(), enabled: true, protocols: "xray".into(), ..emit::test_user() };
        let ib = Inbound { id: "a".into(), protocol: "trojan".into(), port: 443, network: "tcp".into(), security: "tls".into(), sni: "de.example.com".into(), acme: true, ..Default::default() };
        let l = link_with(&XraySettings::default(), &ib, &u, "1.2.3.4").unwrap();
        assert!(l.contains("@de.example.com:443?"), "{}", l);
        assert!(l.contains("sni=de.example.com"));
    }

    #[test]
    fn rules_only_point_at_known_outbounds() {
        let tags = vec!["direct".to_string(), "block".to_string(), "de".to_string()];
        let r = XRule { domain: "geosite:openai, domain:example.com".into(), users: vec![4], outbound: "de".into(), ..Default::default() };
        let v = rule_json(&r, &tags).unwrap();
        assert_eq!(v["domain"], json!(["geosite:openai", "domain:example.com"]));
        assert_eq!(v["user"], json!(["u4"]));
        assert!(rule_json(&XRule { outbound: "nope".into(), ..r.clone() }, &tags).is_none());
        assert!(rule_json(&XRule { outbound: "de".into(), ..Default::default() }, &tags).is_none());
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
                    let s = XraySettings { on: true, servers: vec![XServer { server: "local".into(), address: "203.0.113.9".into(), ..Default::default() }], inbounds: vec![ib.clone()], block_private: true, block_bt: true, ..Default::default() };
                    std::fs::write(format!("{}/{}.json", out, ib.remark), build_config(&s, "local", std::slice::from_ref(&u)).to_string()).unwrap();
                    let l = link_with(&s, &ib, &u, "203.0.113.9").unwrap();
                    std::fs::write(format!("{}/{}.link", out, ib.remark), l).unwrap();
                }
            }
        }
    }

    /// `KX_OUT=dir cargo test xray_advanced -- --ignored`: one config with every extra option.
    #[test]
    #[ignore]
    fn xray_advanced() {
        let out = std::env::var("KX_OUT").expect("KX_OUT");
        let ck = rcgen::generate_simple_self_signed(vec!["x.example.com".to_string()]).unwrap();
        let (cert, key) = (ck.cert.pem(), ck.key_pair.serialize_pem());
        let u = User { id: 7, username: "mahtab87".into(), code: "1234567890123456789".into(), enabled: true, protocols: "xray".into(), ..test_user() };
        let (p, q) = reality_keys();
        let base = Inbound { enabled: true, server: "local".into(), sniffing: true, sniff_dest: vec!["http".into(), "tls".into(), "quic".into(), "fakedns".into()], sniff_override: true, sniff_meta: false, ..Default::default() };
        let ibs = vec![
            Inbound { id: "ws".into(), protocol: "vless".into(), port: 21001, network: "ws".into(), security: "tls".into(), path: "/w".into(), heartbeat: 30, sni: "x.example.com".into(), cert: cert.clone(), key: key.clone(), tls_min: "1.2".into(), reject_sni: true, proxy_protocol: true, listen: "0.0.0.0".into(), ..base.clone() },
            Inbound { id: "xh".into(), protocol: "vless".into(), port: 21002, network: "xhttp".into(), security: "reality".into(), path: "/x".into(), x_padding: "100-1000".into(), dest: "www.microsoft.com:443".into(), names: "www.microsoft.com".into(), private: p.clone(), public: q.clone(), short_ids: "ab12".into(), xver: 0, max_time_diff: 60000, ..base.clone() },
            Inbound { id: "kcp".into(), protocol: "vmess".into(), port: 21003, network: "kcp".into(), security: "none".into(), kcp_mtu: 1350, kcp_tti: 20, kcp_up: 50, kcp_down: 100, kcp_cong: true, ..base.clone() },
            Inbound { id: "fb".into(), protocol: "trojan".into(), port: 21004, network: "tcp".into(), security: "tls".into(), sni: "x.example.com".into(), cert: cert.clone(), key: key.clone(),
                fallbacks: vec![Fallback { dest: "8080".into(), ..Default::default() }, Fallback { path: "/ws".into(), dest: "127.0.0.1:2002".into(), xver: 1, ..Default::default() }, Fallback { alpn: "h2".into(), dest: "8081".into(), ..Default::default() }], ..base.clone() },
            Inbound { id: "vf".into(), protocol: "vless".into(), port: 21005, network: "tcp".into(), security: "tls".into(), flow: "xtls-rprx-vision".into(), cert_file: "CERTFILE".into(), key_file: "KEYFILE".into(), sni: "x.example.com".into(), fallbacks: vec![Fallback { dest: "80".into(), ..Default::default() }], ..base.clone() },
            Inbound { id: "gr".into(), protocol: "vless".into(), port: 21006, network: "grpc".into(), security: "reality".into(), service: "g".into(), multi_mode: true, dest: "www.apple.com:443".into(), names: "www.apple.com".into(), private: p.clone(), public: q.clone(), short_ids: "cd34".into(), sniff_meta: true, ..base.clone() },
        ];
        let vless_link = link_with(&XraySettings::default(), &ibs[1], &u, "203.0.113.9").unwrap();
        let vmess_link = link_with(&XraySettings::default(), &ibs[2], &u, "203.0.113.9").unwrap();
        let tro_link = link_with(&XraySettings::default(), &ibs[3], &u, "203.0.113.9").unwrap();
        let ss = Inbound { id: "ss".into(), protocol: "shadowsocks".into(), port: 21007, ss_method: "2022-blake3-aes-256-gcm".into(), ss_key: b64_std(&[3u8; 32]), ..base.clone() };
        let ss_link = link_with(&XraySettings::default(), &ss, &u, "203.0.113.9").unwrap();
        let mut ibs = ibs;
        ibs.push(ss);
        let s = XraySettings {
            on: true, servers: vec![XServer { server: "local".into(), address: "203.0.113.9".into(), ..Default::default() }], inbounds: ibs, block_private: true, block_bt: true, block_ads: true, block_ir: true,
            log_level: "info".into(), domain_strategy: "IPIfNonMatch".into(), dns: "1.1.1.1, https://dns.google/dns-query".into(), ipv4: true,
            outs: vec![
                XOut { tag: "s5".into(), kind: "socks".into(), address: "127.0.0.1".into(), port: 1080, user: "a".into(), pass: "b".into(), ..Default::default() },
                XOut { tag: "hp".into(), kind: "http".into(), address: "127.0.0.1".into(), port: 3128, ..Default::default() },
                XOut { tag: "de".into(), kind: "link".into(), link: vless_link, ..Default::default() },
                XOut { tag: "vm".into(), kind: "link".into(), link: vmess_link, ..Default::default() },
                XOut { tag: "tr".into(), kind: "link".into(), link: tro_link, ..Default::default() },
                XOut { tag: "sso".into(), kind: "link".into(), link: ss_link, ..Default::default() },
                XOut { tag: "js".into(), kind: "json".into(), json: r#"{"protocol":"freedom","settings":{"domainStrategy":"UseIPv6"}}"#.into(), ..Default::default() },
                XOut { tag: "bh".into(), kind: "blackhole".into(), ..Default::default() },
            ],
            rule_list: vec![
                XRule { domain: "geosite:openai\ndomain:example.com".into(), outbound: "de".into(), ..Default::default() },
                XRule { ip: "8.8.8.8/32, geoip:us".into(), port: "53,443,1000-2000".into(), network: "tcp,udp".into(), outbound: "s5".into(), ..Default::default() },
                XRule { users: vec![7], inbound: vec!["ws".into()], protocol: "tls".into(), outbound: "block".into(), ..Default::default() },
            ],
            default_out: "de".into(),
            ..Default::default()
        };
        std::fs::write(format!("{}/advanced.json", out), serde_json::to_string_pretty(&build_config(&s, "local", std::slice::from_ref(&u))).unwrap()).unwrap();
        std::fs::write(format!("{}/adv.crt", out), &cert).unwrap();
        std::fs::write(format!("{}/adv.key", out), &key).unwrap();
    }

    /// `KX_OUT=dir cargo test xray_chain -- --ignored`: a server (VLESS over WS, REALITY over TCP, SS-2022)
    /// and a client whose outbounds are made from the server's share links.
    #[test]
    #[ignore]
    fn xray_chain() {
        let out = std::env::var("KX_OUT").expect("KX_OUT");
        let u = User { id: 9, username: "chain1".into(), code: "55554444333322221111".into(), enabled: true, protocols: "xray".into(), ..test_user() };
        let (p, q) = reality_keys();
        let ibs = vec![
            Inbound { id: "w".into(), enabled: true, server: "local".into(), protocol: "vless".into(), port: 22001, network: "ws".into(), security: "none".into(), path: "/c".into(), ..Default::default() },
            Inbound { id: "r".into(), enabled: true, server: "local".into(), protocol: "vless".into(), port: 22002, network: "tcp".into(), security: "reality".into(), flow: "xtls-rprx-vision".into(), dest: "www.microsoft.com:443".into(), names: "www.microsoft.com".into(), private: p, public: q, short_ids: "1a2b".into(), ..Default::default() },
            Inbound { id: "s".into(), enabled: true, server: "local".into(), protocol: "shadowsocks".into(), port: 22003, ss_method: "2022-blake3-aes-128-gcm".into(), ss_key: b64_std(&[5u8; 16]), ..Default::default() },
            Inbound { id: "t".into(), enabled: true, server: "local".into(), protocol: "trojan".into(), port: 22004, network: "grpc".into(), security: "none".into(), service: "gg".into(), ..Default::default() },
        ];
        let srv = XraySettings { on: true, inbounds: ibs.clone(), ..Default::default() };
        std::fs::write(format!("{}/server.json", out), build_config(&srv, "local", std::slice::from_ref(&u)).to_string()).unwrap();
        for (i, ib) in ibs.iter().enumerate() {
            let link = link_with(&srv, ib, &u, "127.0.0.1").unwrap();
            let o = link_outbound(&link).unwrap();
            let mut ob = o.clone();
            ob["tag"] = json!("up");
            let cli = json!({
                "log": { "loglevel": "warning" },
                "inbounds": [{ "port": 23001 + i, "listen": "127.0.0.1", "protocol": "socks", "settings": { "udp": false } }],
                "outbounds": [ob],
            });
            std::fs::write(format!("{}/client{}.json", out, i), cli.to_string()).unwrap();
        }
    }

    pub(super) fn test_user() -> User {
        User {
            id: 0, username: String::new(), code: String::new(), limit_gb: 0.0, used_bytes: 0, expires_at: 0, max_conn: 0, enabled: true,
            protocols: String::new(), nodes: String::new(), notes: String::new(), tg_id: 0, created_at: 0, last_seen: 0, online: 0, warned: 0,
        }
    }
}
