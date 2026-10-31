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
    /// the server's own full DNS name (instead of <label>.<base>)
    pub domain: String,
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
    /// a certificate pasted by hand (empty = every DNS server gets its own with certbot)
    pub cert: String,
    pub key: String,
    pub servers: Vec<DnsSrv>,
    /// secret the relay keys and tunnel tokens are derived from
    pub secret: String,
    /// user id -> epoch: bumping it makes the servers forget the user's allowed addresses
    pub kicks: HashMap<String, u64>,
    /// catalog changes already carried over (1: PUBG Mobile split into login, store, anti-cheat, updates)
    pub cat_ver: u32,
}

pub fn settings(app: &App) -> DnsSettings {
    let mut s: DnsSettings = serde_json::from_str(&app.db.get("dns_cfg")).unwrap_or_default();
    if s.upstreams.is_empty() {
        s.upstreams = vec!["1.1.1.1".into(), "8.8.8.8".into(), "9.9.9.9".into()];
    }
    if s.ip_hours == 0 {
        s.ip_hours = 12;
    }
    // 3.6.8: the one PUBG Mobile group became four; who had it on keeps every name it routed
    if s.cat_ver < 1 {
        if s.opt.iter().any(|x| x == "pubgmobile/main") {
            for g in ["pubgmobile/store", "pubgmobile/update"] {
                if !s.opt.iter().any(|x| x == g) {
                    s.opt.push(g.into());
                }
            }
        }
        s.cat_ver = 1;
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
    if !srv.domain.trim().is_empty() {
        return srv.domain.trim().trim_matches('.').to_ascii_lowercase();
    }
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
        .map(|u| DnsUser {
            id: u.id,
            name: u.username.clone(),
            token: user_token(&u.code),
            max_ips: if limit_on { u.max_conn.max(0) as u32 } else { 0 },
            epoch: kick_epoch(app, u.id),
        })
        .collect()
}

fn kick_epoch(app: &App, id: i64) -> u64 {
    settings(app).kicks.get(&id.to_string()).copied().unwrap_or(0)
}

/// Where a name is routed from: (service label, group label, group key, on) of the first group listing
/// it or one of its parents; a custom name is ("", "", "custom", true).
pub fn explain(s: &DnsSettings, name: &str) -> Option<(String, String, String, bool)> {
    let name = name.trim().trim_matches('.').to_ascii_lowercase();
    let parents: Vec<String> = {
        let mut v = vec![];
        let mut n = name.as_str();
        loop {
            v.push(n.to_string());
            match n.find('.') {
                Some(i) => n = &n[i + 1..],
                None => break,
            }
        }
        v
    };
    for p in &parents {
        for svc in catalog()["services"].as_array().into_iter().flatten() {
            let sk = svc["key"].as_str().unwrap_or("");
            for g in svc["groups"].as_array().into_iter().flatten() {
                if g["domains"].as_array().into_iter().flatten().any(|d| d.as_str() == Some(p.as_str())) {
                    let id = format!("{}/{}", sk, g["key"].as_str().unwrap_or(""));
                    let on = if g["locked"].as_bool() == Some(true) {
                        false
                    } else if g["opt_in"].as_bool() == Some(true) {
                        s.opt.contains(&id)
                    } else {
                        !s.off.contains(&id)
                    };
                    return Some((svc["label"].as_str().unwrap_or(sk).to_string(), g["label"].as_str().unwrap_or("").to_string(), id, on));
                }
            }
        }
        if s.custom.iter().any(|c| c.trim().trim_matches('.').eq_ignore_ascii_case(p)) {
            return Some((String::new(), String::new(), "custom".into(), true));
        }
    }
    None
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
        // no pasted certificate: the server gets its own with certbot for its name
        acme: s.cert.trim().is_empty() && !host_of(&s, srv).is_empty(),
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
        last_status().lock().unwrap_or_else(|e| e.into_inner()).remove(sid);
        return;
    }
    let mut kept = st.clone();
    if let Some(o) = kept.as_object_mut() {
        if let Some(q) = o.remove("qlog") {
            qlog_ingest(sid, &q);
        }
    }
    last_status().lock().unwrap_or_else(|e| e.into_inner()).insert(sid.to_string(), (now(), kept));
    count_usage(app, &format!("dns_prev_{}", sid), st);
}

// ------------------------------------------------------------------ query log

/// queries the panel keeps in memory (all servers together; the oldest go first)
const QLOG_MAX: usize = 50_000;

struct QEntry {
    ts: i64,
    sid: String,
    uid: i64,
    name: String,
    qtype: u16,
    routed: String,
}

#[derive(Default)]
struct QStore {
    /// server -> (run id, last seq received)
    seen: HashMap<String, (String, u64)>,
    items: std::collections::VecDeque<QEntry>,
}

/// (user id, server) of the users who asked a Kanki DNS server something in the last `secs` seconds
pub fn active_users(secs: i64) -> Vec<(i64, String)> {
    let from = now() - secs;
    let mut v: Vec<(i64, String)> = vec![];
    // newest first; reports of different servers interleave, so look at a window instead of
    // stopping at the first old entry
    for e in qstore().lock().unwrap_or_else(|e| e.into_inner()).items.iter().rev().take(20_000) {
        if e.ts < from {
            continue;
        }
        if e.uid > 0 && !v.iter().any(|(u, s)| *u == e.uid && *s == e.sid) {
            v.push((e.uid, e.sid.clone()));
        }
    }
    v
}

fn qstore() -> &'static Mutex<QStore> {
    static S: OnceLock<Mutex<QStore>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(QStore::default()))
}

/// Queries a server reported: { "run": ..., "items": [[seq, ts, uid, name, qtype, routed], ...] }
fn qlog_ingest(sid: &str, q: &Value) {
    let run = q["run"].as_str().unwrap_or("").to_string();
    let mut st = qstore().lock().unwrap_or_else(|e| e.into_inner());
    let after = st.seen.get(sid).filter(|x| x.0 == run).map(|x| x.1).unwrap_or(0);
    let mut last = after;
    for x in q["items"].as_array().into_iter().flatten() {
        let seq = x[0].as_u64().unwrap_or(0);
        if seq <= after {
            continue;
        }
        last = last.max(seq);
        st.items.push_back(QEntry {
            ts: x[1].as_i64().unwrap_or(0),
            sid: sid.to_string(),
            uid: x[2].as_i64().unwrap_or(0),
            name: x[3].as_str().unwrap_or("").chars().take(255).collect(),
            qtype: x[4].as_u64().unwrap_or(0) as u16,
            routed: x[5].as_str().unwrap_or("").to_string(),
        });
    }
    while st.items.len() > QLOG_MAX {
        st.items.pop_front();
    }
    st.seen.insert(sid.to_string(), (run, last));
}

fn qtype_name(t: u16) -> String {
    match t {
        1 => "A".into(),
        2 => "NS".into(),
        5 => "CNAME".into(),
        6 => "SOA".into(),
        12 => "PTR".into(),
        15 => "MX".into(),
        16 => "TXT".into(),
        28 => "AAAA".into(),
        33 => "SRV".into(),
        64 => "SVCB".into(),
        65 => "HTTPS".into(),
        _ => t.to_string(),
    }
}

/// listed name -> "Service · Group" from the catalog
fn service_labels() -> &'static HashMap<String, String> {
    static M: OnceLock<HashMap<String, String>> = OnceLock::new();
    M.get_or_init(|| {
        let mut m = HashMap::new();
        for svc in catalog()["services"].as_array().into_iter().flatten() {
            let sl = svc["label"].as_str().unwrap_or("");
            let multi = svc["groups"].as_array().map(|g| g.len() > 1).unwrap_or(false);
            for g in svc["groups"].as_array().into_iter().flatten() {
                let label = if multi { format!("{} · {}", sl, g["label"].as_str().unwrap_or("")) } else { sl.to_string() };
                for d in g["domains"].as_array().into_iter().flatten().filter_map(|d| d.as_str()) {
                    m.entry(d.to_string()).or_insert_with(|| label.clone());
                }
            }
        }
        m
    })
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct LogQuery {
    /// user id (0 = everybody)
    user: i64,
    /// text in the name
    q: String,
    /// "routed" | "direct" | "" (all)
    kind: String,
    limit: usize,
}

/// The query log, newest first, and the same queries grouped by name (most asked first).
async fn get_log(State(app): St, h: HeaderMap, axum::extract::Query(f): axum::extract::Query<LogQuery>) -> Response {
    let _ = guard!(app, h, "nodes");
    let names = crate::tunnel::panel::server_names(&app);
    let users: HashMap<i64, String> = app.db.users().into_iter().map(|u| (u.id, u.username)).collect();
    let labels = service_labels();
    let q = f.q.trim().to_ascii_lowercase();
    let limit = if f.limit == 0 { 500 } else { f.limit.min(5000) };
    let st = qstore().lock().unwrap_or_else(|e| e.into_inner());
    let total = st.items.len();
    let keep = |e: &&QEntry| {
        (f.user == 0 || e.uid == f.user)
            && (q.is_empty() || e.name.contains(&q))
            && match f.kind.as_str() {
                "routed" => !e.routed.is_empty(),
                "direct" => e.routed.is_empty(),
                _ => true,
            }
    };
    let label = |r: &str| if r.is_empty() { String::new() } else { labels.get(r).cloned().unwrap_or_else(|| "custom".into()) };
    let mut groups: HashMap<&str, (u64, &str, i64, std::collections::BTreeSet<i64>)> = HashMap::new();
    let mut matched = 0usize;
    for e in st.items.iter().filter(keep) {
        matched += 1;
        let g = groups.entry(e.name.as_str()).or_insert((0, e.routed.as_str(), 0, Default::default()));
        g.0 += 1;
        g.2 = g.2.max(e.ts);
        g.3.insert(e.uid);
    }
    let items: Vec<Value> = st
        .items
        .iter()
        .rev()
        .filter(keep)
        .take(limit)
        .map(|e| {
            json!({
                "ts": e.ts, "server": names.get(&e.sid).cloned().unwrap_or_else(|| e.sid.clone()),
                "user": users.get(&e.uid).cloned().unwrap_or_else(|| format!("#{}", e.uid)), "uid": e.uid,
                "name": e.name, "type": qtype_name(e.qtype), "routed": e.routed, "service": label(&e.routed),
            })
        })
        .collect();
    // name -> (count, routed, last, users)
    type Group<'a> = (u64, &'a str, i64, std::collections::BTreeSet<i64>);
    let mut by_name: Vec<(&str, Group)> = groups.into_iter().collect();
    by_name.sort_by(|a, b| b.1 .0.cmp(&a.1 .0).then(a.0.cmp(b.0)));
    let by_name: Vec<Value> = by_name
        .into_iter()
        .take(limit)
        .map(|(n, (c, r, last, us))| {
            json!({
                "name": n, "count": c, "routed": r, "service": label(r), "last": last,
                "users": us.iter().map(|u| users.get(u).cloned().unwrap_or_else(|| format!("#{}", u))).collect::<Vec<_>>(),
            })
        })
        .collect();
    Json(json!({ "total": total, "matched": matched, "max": QLOG_MAX, "items": items, "names": by_name })).into_response()
}

async fn clear_log(State(app): St, h: HeaderMap) -> Response {
    let _ = guard!(app, h, "nodes");
    qstore().lock().unwrap_or_else(|e| e.into_inner()).items.clear();
    Json(json!({ "ok": true })).into_response()
}

/// Add the bytes a server counted since its last report to each user's traffic. `st` has the run id of
/// the counting process and its running totals: { "run": "...", "users": { "<id>": [bytes, ...] } }.
pub fn count_usage(app: &App, key: &str, st: &Value) {
    let Some(run) = st["run"].as_str() else { return };
    let Some(users) = st["users"].as_object() else { return };
    let prev: Value = serde_json::from_str(&app.db.get(key)).unwrap_or(json!({}));
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
        app.db.set(key, &json!({ "run": run, "users": cur }).to_string());
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
            // a pasted certificate covers *.name (the DoT name carries the user's token); a certbot one
            // is for the name itself: DoT on it knows the user by the address the app registered
            let manual = !s.cert.trim().is_empty();
            let ssl_ok = manual || last_status().lock().unwrap_or_else(|e| e.into_inner()).get(&x.server).map(|v| v.1["ssl"].as_bool() == Some(true)).unwrap_or(false);
            let tls = !host.is_empty() && ssl_ok;
            json!({
                "id": x.server, "name": names.get(&x.server).cloned().unwrap_or_default(), "note": x.note, "role": x.role,
                // a relay (inside Iran) tunnels to this foreign server: the app shows it as "Iran → <exit>"
                "exit": if x.role == "relay" { x.exit.clone() } else { String::new() },
                "exit_name": if x.role == "relay" { names.get(&x.exit).cloned().unwrap_or_default() } else { String::new() },
                "ip": ip, "host": host,
                "dot": if tls { if manual { format!("{}.{}", token, host) } else { host.clone() } } else { String::new() },
                "doh": if tls { format!("https://{}/dns-query/{}", host, token) } else { String::new() },
                "register": if tls { format!("https://{}/r/{}", host, token) } else { String::new() },
                "register_http": if ip.is_empty() { String::new() } else { format!("http://{}/kdns/r/{}", ip, token) },
            })
        })
        .collect();
    json!({ "token": token, "servers": servers })
}

// ------------------------------------------------------------------ admin API

// ------------------------------------------------------------------ repair (asked in the panel)

fn repairs() -> &'static Mutex<std::collections::HashSet<String>> {
    static S: OnceLock<Mutex<std::collections::HashSet<String>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(std::collections::HashSet::new()))
}

/// Was a repair asked for this server? (asked once: reading it clears it)
pub fn take_repair(sid: &str) -> bool {
    repairs().lock().unwrap_or_else(|e| e.into_inner()).remove(sid)
}

/// Seconds since the server last reported (None = never since the panel started)
fn report_age(sid: &str) -> Option<i64> {
    last_status().lock().unwrap_or_else(|e| e.into_inner()).get(sid).map(|(at, _)| now() - *at)
}

async fn repair_server(State(app): St, h: HeaderMap, Path(id): Path<String>) -> Response {
    let _ = guard!(app, h, "nodes");
    let s = settings(&app);
    if !s.servers.iter().any(|x| x.server == id) {
        return err(StatusCode::NOT_FOUND, "this server is not an DNS server");
    }
    if cfg_for(&app, &id).is_none() {
        return err(StatusCode::BAD_REQUEST, "nothing runs on this server: Kanki DNS is off, or this relay has no exit server");
    }
    repairs().lock().unwrap_or_else(|e| e.into_inner()).insert(id.clone());
    let age = report_age(&id);
    Json(json!({ "ok": true, "waiting": age.map(|a| a > 60).unwrap_or(true), "age": age })).into_response()
}

pub fn router() -> Router<Arc<App>> {
    Router::new()
        .route("/api/dns", get(get_all).put(put_settings))
        .route("/api/dns/servers", post(put_server))
        .route("/api/dns/servers/:id", delete(del_server))
        .route("/api/dns/servers/:id/repair", post(repair_server))
        .route("/api/dns/users", get(get_users))
        .route("/api/dns/users/:id/kick", post(kick_user))
        .route("/api/dns/log", get(get_log).delete(clear_log))
        .route("/api/dns/check", post(check_name))
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
    let st = last_status().lock().unwrap_or_else(|e| e.into_inner()).clone();
    let servers: Vec<Value> = s
        .servers
        .iter()
        .map(|x| {
            let (at, status) = st.get(&x.server).cloned().unwrap_or((0, Value::Null));
            json!({
                "server": x.server, "name": names.get(&x.server).cloned().unwrap_or_default(), "role": x.role, "label": x.label, "domain": x.domain,
                "ip": x.ip, "answer_ip": answer_ip(x), "exit": x.exit, "transport": x.transport, "tunnel_port": x.tunnel_port,
                "note": x.note, "hidden": x.hidden, "host": host_of(&s, x), "status": status, "status_at": at,
            })
        })
        .collect();
    let users = app.db.users().iter().filter(|u| u.has_proto("dns")).count();
    let locs = crate::tunnel::panel::server_locs(&app);
    Json(json!({
        "on": s.on, "base": s.base, "upstreams": s.upstreams, "off": s.off, "opt": s.opt, "custom": s.custom, "ip_hours": s.ip_hours,
        "cert": cert_info(&s.cert), "servers": servers, "catalog": catalog(), "domains": domains(&s).len(), "users": users,
        "agents": names.iter().map(|(k, v)| json!({"id": k, "name": v, "loc": locs.get(k).map(|x| x.0.clone()).unwrap_or_default()})).collect::<Vec<_>>(),
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
    if let Some(v) = b["domain"].as_str() {
        let v = v.trim().trim_matches('.').to_ascii_lowercase();
        if !v.is_empty() && !valid_name(&v) {
            return err(StatusCode::BAD_REQUEST, "the server's domain is not a valid name (like de.dns.example.com)");
        }
        x.domain = v;
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
    if let Some(p) = crate::tunnel::panel::emer_port_on(&app, &x.server).filter(|p| crate::tunnel::panel::DNS_PORTS.contains(p)) {
        return err(StatusCode::BAD_REQUEST, &format!("the emergency chat uses port {} on this server, and Kanki DNS needs 53, 80, 443 and 853: move the chat to another port first (Emergency chat › Port, e.g. 8080 or 2053)", p));
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
    let host = host_of(&s, &x);
    if !host.is_empty() && s.servers.iter().any(|o| o.server != x.server && host_of(&s, o) == host) {
        return err(StatusCode::BAD_REQUEST, "another DNS server already has this name");
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
    let st = crate::tunnel::panel::step(&app, &id, "dns", "");
    let rid = crate::tunnel::panel::track("dns", &st.name.clone(), vec![st]);
    Json(json!({ "ok": true, "removal": rid })).into_response()
}

/// The server was removed from the panel: it and the relays that sent their connections to it leave
/// Kanki DNS (their agents remove the DNS service and close its ports).
pub(crate) fn forget_server(app: &App, id: &str) {
    let mut s = settings(app);
    let n = s.servers.len();
    let gone: Vec<String> = s.servers.iter().filter(|o| o.server == id || (o.role == "relay" && o.exit == id)).map(|o| o.server.clone()).collect();
    s.servers.retain(|o| !gone.contains(&o.server));
    if s.servers.len() != n {
        save(app, &mut s);
    }
    for g in gone {
        app.db.set(&format!("dns_prev_{}", g), "");
    }
}

/// The users with DNS: their queries and bytes on each server (since its service started) and the
/// addresses allowed for them right now.
async fn get_users(State(app): St, h: HeaderMap) -> Response {
    let _ = guard!(app, h, "nodes");
    let names = crate::tunnel::panel::server_names(&app);
    let st = last_status().lock().unwrap_or_else(|e| e.into_inner()).clone();
    let users: Vec<Value> = app
        .db
        .users()
        .iter()
        .filter(|u| u.has_proto("dns"))
        .map(|u| {
            let key = u.id.to_string();
            let (mut bytes, mut queries) = (0u64, 0u64);
            let mut ips = vec![];
            for (sid, (_, v)) in st.iter() {
                bytes += v["users"][&key][0].as_u64().unwrap_or(0);
                queries += v["users"][&key][1].as_u64().unwrap_or(0);
                for ip in v["ips"][&key].as_array().into_iter().flatten().filter_map(|x| x.as_str()) {
                    ips.push(json!({ "server": names.get(sid).cloned().unwrap_or_else(|| sid.clone()), "ip": ip }));
                }
            }
            json!({
                "id": u.id, "name": u.username, "active": u.active(), "max": u.max_conn, "bytes": bytes, "queries": queries, "ips": ips,
                "token": user_token(&u.code), "last_seen": u.last_seen,
            })
        })
        .collect();
    Json(json!({ "users": users })).into_response()
}

async fn kick_user(State(app): St, h: HeaderMap, Path(id): Path<i64>) -> Response {
    let _ = guard!(app, h, "nodes");
    update(&app, |s| {
        *s.kicks.entry(id.to_string()).or_insert(0) += 1;
    });
    Json(json!({ "ok": true })).into_response()
}

/// Would this name be routed, and by which service?
async fn check_name(State(app): St, h: HeaderMap, Json(b): Json<Value>) -> Response {
    let _ = guard!(app, h, "nodes");
    let s = settings(&app);
    let raw = b["name"].as_str().unwrap_or("").trim().to_ascii_lowercase();
    // a pasted address: keep only the host
    let name = raw.trim_start_matches("https://").trim_start_matches("http://").split(['/', ':', '?']).next().unwrap_or("").trim_matches('.').to_string();
    if !valid_name(&name) {
        return err(StatusCode::BAD_REQUEST, "not a domain name");
    }
    let routed = domains(&s).iter().any(|d| name == *d || name.ends_with(&format!(".{}", d)));
    let why = explain(&s, &name);
    Json(json!({
        "name": name, "routed": routed,
        "service": why.as_ref().map(|w| w.0.clone()), "group": why.as_ref().map(|w| w.1.clone()), "id": why.as_ref().map(|w| w.2.clone()), "group_on": why.as_ref().map(|w| w.3),
    }))
    .into_response()
}


#[cfg(test)]
mod qlog_tests {
    use super::*;

    #[test]
    fn a_report_sent_twice_is_kept_once() {
        let q = json!({ "run": "r1", "items": [[1, 100, 7, "a.example", 1, ""], [2, 101, 7, "igamecj.com", 1, "igamecj.com"]] });
        qlog_ingest("test-srv", &q);
        qlog_ingest("test-srv", &q);
        let st = qstore().lock().unwrap_or_else(|e| e.into_inner());
        let mine: Vec<&QEntry> = st.items.iter().filter(|e| e.sid == "test-srv").collect();
        assert_eq!(mine.len(), 2);
        assert_eq!(mine[1].routed, "igamecj.com");
    }
}
