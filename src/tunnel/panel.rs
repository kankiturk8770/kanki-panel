//! Tunnels in the panel: tunnel servers (lightweight agents, no VPN on them), tunnels between two
//! servers, the endpoint agents talk to, and the copy of the engine that runs on the panel itself.

use super::engine::{parse_ports, Manager, Spec, Status};
use crate::api::err;
use crate::guard;
use crate::util::{self, now, rand_token};
use crate::App;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

type St = State<Arc<App>>;

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct TServer {
    pub id: String,
    pub name: String,
    pub token: String,
    /// address other servers dial (domain or IP); empty = the IP the agent was seen from
    pub addr: String,
    pub created: i64,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct Tunnel {
    pub id: String,
    pub name: String,
    pub entry: String,
    pub exit: String,
    pub mode: String,
    pub transport: String,
    pub port: u16,
    pub conns: u32,
    pub token: String,
    pub tcp: Vec<String>,
    pub udp: Vec<String>,
    pub target: String,
    pub sni: String,
    pub path: String,
    pub dial: String,
    pub enabled: bool,
    pub created: i64,
}

#[derive(Clone, Default)]
struct Seen {
    at: i64,
    version: String,
    ip: String,
    status: Vec<Status>,
}

fn seen() -> &'static Mutex<HashMap<String, Seen>> {
    static S: OnceLock<Mutex<HashMap<String, Seen>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(HashMap::new()))
}

fn load<T: for<'de> Deserialize<'de>>(app: &App, key: &str) -> Vec<T> {
    serde_json::from_str(&app.db.get(key)).unwrap_or_default()
}

fn servers(app: &App) -> Vec<TServer> {
    load(app, "tun_servers")
}

fn tunnels(app: &App) -> Vec<Tunnel> {
    load(app, "tun_list")
}

fn save_servers(app: &App, v: &[TServer]) {
    app.db.set("tun_servers", &serde_json::to_string(v).unwrap_or_else(|_| "[]".into()));
}

fn save_tunnels(app: &App, v: &[Tunnel]) {
    app.db.set("tun_list", &serde_json::to_string(v).unwrap_or_else(|_| "[]".into()));
}

fn local_name(app: &App) -> String {
    app.env.get("LOCAL_NAME").cloned().filter(|s| !s.is_empty()).unwrap_or_else(|| "Main".into())
}

/// The address other servers use to reach server `sid`.
fn host_of(app: &App, sid: &str) -> String {
    if sid == "local" {
        let a = app.db.get("tun_local_addr");
        if !a.trim().is_empty() {
            return a.trim().to_string();
        }
        return app.env.get("DOMAIN").cloned().unwrap_or_default();
    }
    let s = servers(app).into_iter().find(|s| s.id == sid);
    if let Some(s) = s {
        if !s.addr.trim().is_empty() {
            return s.addr.trim().to_string();
        }
    }
    seen().lock().unwrap().get(sid).map(|x| x.ip.clone()).unwrap_or_default()
}

fn hostport(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{}]:{}", host, port)
    } else {
        format!("{}:{}", host, port)
    }
}

/// The tunnels server `sid` has to run.
fn specs_for(app: &App, sid: &str) -> Vec<Spec> {
    let mut out = vec![];
    for t in tunnels(app) {
        if !t.enabled || (t.entry != sid && t.exit != sid) || t.entry == t.exit {
            continue;
        }
        let role = if t.entry == sid { "entry" } else { "exit" };
        let mode = if t.mode == "direct" { "direct" } else { "reverse" };
        // the side that listens is the entry in reverse mode and the exit in direct mode
        let listener = if mode == "reverse" { &t.entry } else { &t.exit };
        let host = if !t.dial.trim().is_empty() { t.dial.trim().to_string() } else { host_of(app, listener) };
        out.push(Spec {
            id: t.id.clone(),
            name: t.name.clone(),
            role: role.into(),
            mode: mode.into(),
            transport: t.transport.clone(),
            port: t.port,
            remote: hostport(&host, t.port),
            token: t.token.clone(),
            conns: t.conns,
            sni: t.sni.clone(),
            path: t.path.clone(),
            tcp: t.tcp.clone(),
            udp: t.udp.clone(),
            target: t.target.clone(),
            cert: String::new(),
            key: String::new(),
            probe: false,
        });
    }
    // a running smart-tunnel test adds one short-lived test tunnel per transport
    if let Some(p) = probe_job().lock().unwrap().clone() {
        if !p.finished && now() - p.started < PROBE_MAX && (p.entry == sid || p.exit == sid) {
            let role = if p.entry == sid { "entry" } else { "exit" };
            let listener = if p.mode == "direct" { &p.exit } else { &p.entry };
            let host = host_of(app, listener);
            for (i, tr) in PROBE_TRANSPORTS.iter().enumerate() {
                let port = p.port + i as u16;
                out.push(Spec {
                    id: format!("probe-{}-{}", p.id, tr),
                    name: format!("test {}", tr),
                    role: role.into(),
                    mode: p.mode.clone(),
                    transport: tr.to_string(),
                    port,
                    remote: hostport(&host, port),
                    token: p.token.clone(),
                    conns: 2,
                    sni: String::new(),
                    path: "/".into(),
                    tcp: vec![],
                    udp: vec![],
                    target: String::new(),
                    cert: String::new(),
                    key: String::new(),
                    probe: true,
                });
            }
        }
    }
    out
}

// ------------------------------------------------------------------ smart tunnel (test every transport)

const PROBE_TRANSPORTS: &[&str] = &["tcpmux", "tcp", "ws", "wss", "quic", "kcp"];
/// a test never runs longer than this (seconds)
const PROBE_MAX: i64 = 200;

#[derive(Clone, Default)]
struct ProbeJob {
    id: String,
    entry: String,
    exit: String,
    mode: String,
    port: u16,
    token: String,
    started: i64,
    finished: bool,
    results: Vec<Value>,
}

fn probe_job() -> &'static Mutex<Option<ProbeJob>> {
    static P: OnceLock<Mutex<Option<ProbeJob>>> = OnceLock::new();
    P.get_or_init(|| Mutex::new(None))
}

/// Higher is better. Download counts most, then upload; UDP loss and ping pull it down.
/// A transport whose UDP does not work keeps a third of its score (fine for TCP-only use).
fn probe_score(r: &Value) -> f64 {
    let down = r["down_mbps"].as_f64().unwrap_or(0.0);
    let up = r["up_mbps"].as_f64().unwrap_or(0.0);
    if down <= 0.0 && up <= 0.0 {
        return 0.0;
    }
    let ping = r["ping_ms"].as_f64().unwrap_or(500.0);
    let tcp = (down * 0.6 + up * 0.4) / (1.0 + ping / 300.0);
    let udp = match r["udp_loss"].as_f64() {
        Some(l) => (1.0 - l / 100.0).max(0.0).powi(2),
        None => 0.33,
    };
    (tcp * udp * 10.0).round() / 10.0
}

async fn probe_start(State(app): St, h: HeaderMap, Json(b): Json<Value>) -> Response {
    let _ = guard!(app, h, "nodes");
    let entry = b["entry"].as_str().unwrap_or("").to_string();
    let exit = b["exit"].as_str().unwrap_or("").to_string();
    let known = |id: &str| id == "local" || servers(&app).iter().any(|s| s.id == id);
    if entry.is_empty() || exit.is_empty() || entry == exit || !known(&entry) || !known(&exit) {
        return err(StatusCode::BAD_REQUEST, "pick two different servers");
    }
    let mode = if b["mode"].as_str() == Some("direct") { "direct" } else { "reverse" };
    let port = b["port"].as_u64().unwrap_or(3990).clamp(1024, 65000) as u16;
    // the test ports must not collide with a tunnel that already listens there
    let listener = if mode == "direct" { &exit } else { &entry };
    for t in tunnels(&app) {
        let l = if t.mode == "direct" { &t.exit } else { &t.entry };
        if l == listener && t.port >= port && t.port < port + PROBE_TRANSPORTS.len() as u16 {
            return err(StatusCode::BAD_REQUEST, &format!("port {} is used by tunnel {}; pick another test port", t.port, t.name));
        }
    }
    let job = ProbeJob {
        id: rand_token(6).to_lowercase(),
        entry,
        exit,
        mode: mode.into(),
        port,
        token: rand_token(32),
        started: now(),
        finished: false,
        results: vec![],
    };
    let id = job.id.clone();
    *probe_job().lock().unwrap() = Some(job);
    Json(json!({"ok": true, "id": id, "transports": PROBE_TRANSPORTS})).into_response()
}

async fn probe_get(State(app): St, h: HeaderMap) -> Response {
    let _ = guard!(app, h, "nodes");
    let mut g = probe_job().lock().unwrap();
    let Some(p) = g.as_mut() else { return Json(json!({"job": null})).into_response() };
    let t = now();
    if !p.finished {
        let seen = seen().lock().unwrap().clone();
        let entry_st = seen.get(&p.entry).map(|x| x.status.clone()).unwrap_or_default();
        let exit_st = seen.get(&p.exit).map(|x| x.status.clone()).unwrap_or_default();
        let mut all_done = true;
        let mut res = vec![];
        for tr in PROBE_TRANSPORTS {
            let sid = format!("probe-{}-{}", p.id, tr);
            let es = entry_st.iter().find(|s| s.id == sid);
            let xs = exit_st.iter().find(|s| s.id == sid);
            let mut r = es.and_then(|s| s.probe.clone()).unwrap_or_else(|| json!({"done": false, "stage": "starting"}));
            if r["done"].as_bool() != Some(true) {
                all_done = false;
            }
            r["transport"] = json!(tr);
            r["port"] = json!(p.port + PROBE_TRANSPORTS.iter().position(|x| x == tr).unwrap_or(0) as u16);
            r["links"] = json!(es.map(|s| s.links).unwrap_or(0).max(xs.map(|s| s.links).unwrap_or(0)));
            if r["error"].is_null() {
                let e = es.map(|s| s.error.clone()).filter(|e| !e.is_empty()).or_else(|| xs.map(|s| s.error.clone()).filter(|e| !e.is_empty()));
                if let Some(e) = e {
                    r["last_error"] = json!(e);
                }
            }
            r["score"] = json!(probe_score(&r));
            res.push(r);
        }
        p.results = res;
        if all_done || t - p.started >= PROBE_MAX {
            // stop the test tunnels; keep the results on screen
            p.finished = true;
        }
    }
    let mut ranked = p.results.clone();
    ranked.sort_by(|a, b| b["score"].as_f64().unwrap_or(0.0).partial_cmp(&a["score"].as_f64().unwrap_or(0.0)).unwrap_or(std::cmp::Ordering::Equal));
    let best = ranked.first().filter(|r| r["score"].as_f64().unwrap_or(0.0) > 0.0).map(|r| r["transport"].clone());
    // best for UDP (WireGuard / Hysteria2): lowest loss, then lowest ping, among working ones
    let best_udp = p
        .results
        .iter()
        .filter(|r| r["udp_loss"].is_number() && r["udp_loss"].as_f64().unwrap_or(100.0) < 50.0)
        .min_by(|a, b| {
            let ka = a["udp_loss"].as_f64().unwrap_or(100.0) * 1000.0 + a["udp_ping_ms"].as_f64().unwrap_or(9999.0);
            let kb = b["udp_loss"].as_f64().unwrap_or(100.0) * 1000.0 + b["udp_ping_ms"].as_f64().unwrap_or(9999.0);
            ka.partial_cmp(&kb).unwrap_or(std::cmp::Ordering::Equal)
        })
        .map(|r| r["transport"].clone());
    let best_tcp = p
        .results
        .iter()
        .filter(|r| r["down_mbps"].as_f64().unwrap_or(0.0) > 0.0)
        .max_by(|a, b| a["down_mbps"].as_f64().unwrap_or(0.0).partial_cmp(&b["down_mbps"].as_f64().unwrap_or(0.0)).unwrap_or(std::cmp::Ordering::Equal))
        .map(|r| r["transport"].clone());
    Json(json!({"job": {
        "id": p.id, "entry": p.entry, "exit": p.exit, "mode": p.mode, "port": p.port,
        "started": p.started, "elapsed": t - p.started, "max": PROBE_MAX, "finished": p.finished,
        "results": ranked, "best": best, "best_udp": best_udp, "best_tcp": best_tcp,
    }}))
    .into_response()
}

async fn probe_stop(State(app): St, h: HeaderMap) -> Response {
    let _ = guard!(app, h, "nodes");
    if let Some(p) = probe_job().lock().unwrap().as_mut() {
        p.finished = true;
    }
    Json(json!({"ok": true})).into_response()
}

// ------------------------------------------------------------------ the engine on the panel server

pub async fn local_loop(app: Arc<App>) {
    let mgr = Manager::default();
    let opened = Mutex::new(HashSet::new());
    loop {
        let specs = specs_for(&app, "local");
        let ps = specs.clone();
        let set = std::mem::take(&mut *opened.lock().unwrap());
        let set = tokio::task::spawn_blocking(move || {
            let m = Mutex::new(set);
            super::agent::open_ports(&ps, &m);
            m.into_inner().unwrap_or_default()
        })
        .await
        .unwrap_or_default();
        *opened.lock().unwrap() = set;
        mgr.apply(specs).await;
        let st = mgr.statuses().await;
        seen().lock().unwrap().insert(
            "local".into(),
            Seen { at: now(), version: crate::VERSION.into(), ip: host_of(&app, "local"), status: st },
        );
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

// ------------------------------------------------------------------ routes

pub fn router() -> Router<Arc<App>> {
    Router::new()
        .route("/api/tunnels", get(list).post(save))
        .route("/api/tunnels/probe", get(probe_get).post(probe_start).delete(probe_stop))
        .route("/api/tunnels/servers", post(server_add))
        .route("/api/tunnels/servers/:id", delete(server_del).put(server_edit))
        .route("/api/tunnels/:id", delete(tunnel_del))
        .route("/api/tunnels/:id/:action", post(tunnel_action))
        .route("/tunnel/agent", post(agent_report))
}

fn status_json(st: Option<&Status>) -> Value {
    match st {
        Some(s) => serde_json::to_value(s).unwrap_or(Value::Null),
        None => Value::Null,
    }
}

async fn list(State(app): St, h: HeaderMap) -> Response {
    let _ = guard!(app, h, "nodes");
    let seen = seen().lock().unwrap().clone();
    let t = now();
    let mut srv = vec![json!({
        "id": "local", "name": local_name(&app), "local": true, "addr": app.db.get("tun_local_addr"),
        "host": host_of(&app, "local"), "online": true, "last_seen": t, "version": crate::VERSION,
    })];
    for s in servers(&app) {
        let x = seen.get(&s.id).cloned().unwrap_or_default();
        srv.push(json!({
            "id": s.id, "name": s.name, "local": false, "addr": s.addr, "host": host_of(&app, &s.id),
            "ip": x.ip, "online": x.at > 0 && t - x.at < 20, "last_seen": x.at, "version": x.version,
        }));
    }
    let mut tl = vec![];
    for tu in tunnels(&app) {
        let es = seen.get(&tu.entry).and_then(|x| x.status.iter().find(|s| s.id == tu.id).cloned());
        let xs = seen.get(&tu.exit).and_then(|x| x.status.iter().find(|s| s.id == tu.id).cloned());
        let fresh = |sid: &str| seen.get(sid).map(|x| t - x.at < 20).unwrap_or(false);
        let up = es.as_ref().map(|s| s.links > 0).unwrap_or(false) && xs.as_ref().map(|s| s.links > 0).unwrap_or(false) && fresh(tu.entry.as_str()) && fresh(tu.exit.as_str());
        let state = if !tu.enabled {
            "off"
        } else if up {
            "up"
        } else if es.as_ref().map(|s| s.links > 0).unwrap_or(false) || xs.as_ref().map(|s| s.links > 0).unwrap_or(false) {
            "partial"
        } else {
            "down"
        };
        let mut v = serde_json::to_value(&tu).unwrap_or(Value::Null);
        v["state"] = json!(state);
        v["entry_status"] = status_json(es.as_ref());
        v["exit_status"] = status_json(xs.as_ref());
        v["dial_host"] = json!(if !tu.dial.trim().is_empty() { tu.dial.clone() } else { host_of(&app, if tu.mode == "direct" { &tu.exit } else { &tu.entry }) });
        tl.push(v);
    }
    Json(json!({ "servers": srv, "tunnels": tl, "panel": crate::api::origin(&app), "repo": crate::admin::repo() })).into_response()
}

fn clean_list(v: &Value) -> Vec<String> {
    let raw: Vec<String> = match v {
        Value::Array(a) => a.iter().filter_map(|x| x.as_str().map(|s| s.to_string()).or_else(|| x.as_u64().map(|n| n.to_string()))).collect(),
        Value::String(s) => s.split(|c| c == ',' || c == ' ' || c == '\n').map(|x| x.to_string()).collect(),
        _ => vec![],
    };
    raw.into_iter().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()
}

/// Create (no id) or edit (with id) a tunnel.
async fn save(State(app): St, h: HeaderMap, Json(b): Json<Value>) -> Response {
    let _ = guard!(app, h, "nodes");
    let mut list = tunnels(&app);
    let id = b["id"].as_str().unwrap_or("").to_string();
    let mut t = if id.is_empty() {
        Tunnel { id: rand_token(10).to_lowercase(), token: rand_token(40), enabled: true, created: now(), ..Default::default() }
    } else {
        match list.iter().find(|x| x.id == id) {
            Some(x) => x.clone(),
            None => return err(StatusCode::NOT_FOUND, "tunnel not found"),
        }
    };
    let s = |k: &str| b[k].as_str().unwrap_or("").trim().to_string();
    if b.get("name").is_some() {
        t.name = s("name");
    }
    if b.get("entry").is_some() {
        t.entry = s("entry");
    }
    if b.get("exit").is_some() {
        t.exit = s("exit");
    }
    if b.get("mode").is_some() {
        t.mode = if s("mode") == "direct" { "direct".into() } else { "reverse".into() };
    }
    if b.get("transport").is_some() {
        let tr = s("transport");
        t.transport = if ["tcp", "tcpmux", "ws", "wss", "quic", "kcp"].contains(&tr.as_str()) { tr } else { "tcpmux".into() };
    }
    if let Some(p) = b["port"].as_u64() {
        t.port = p.min(65535) as u16;
    }
    if let Some(c) = b["conns"].as_u64() {
        t.conns = c.clamp(1, 16) as u32;
    }
    if b.get("tcp").is_some() {
        t.tcp = clean_list(&b["tcp"]);
    }
    if b.get("udp").is_some() {
        t.udp = clean_list(&b["udp"]);
    }
    for k in ["target", "sni", "path", "dial"] {
        if b.get(k).is_some() {
            let v = s(k);
            match k {
                "target" => t.target = v,
                "sni" => t.sni = v,
                "path" => t.path = v,
                _ => t.dial = v,
            }
        }
    }
    if let Some(e) = b["enabled"].as_bool() {
        t.enabled = e;
    }
    if t.name.is_empty() {
        t.name = format!("tunnel-{}", &t.id[..4.min(t.id.len())]);
    }
    if t.transport.is_empty() {
        t.transport = "tcpmux".into();
    }
    if t.mode.is_empty() {
        t.mode = "reverse".into();
    }
    if t.conns == 0 {
        t.conns = 4;
    }
    // checks
    let known: Vec<String> = std::iter::once("local".to_string()).chain(servers(&app).into_iter().map(|s| s.id)).collect();
    if !known.contains(&t.entry) || !known.contains(&t.exit) {
        return err(StatusCode::BAD_REQUEST, "choose the entry and the exit server");
    }
    if t.entry == t.exit {
        return err(StatusCode::BAD_REQUEST, "the entry and the exit must be two different servers");
    }
    if t.port == 0 {
        return err(StatusCode::BAD_REQUEST, "the tunnel port is required");
    }
    if parse_ports(&t.tcp).is_empty() && parse_ports(&t.udp).is_empty() {
        return err(StatusCode::BAD_REQUEST, "add at least one TCP or UDP port to forward");
    }
    // the ports the entry opens must not collide with the tunnel port or with other tunnels on the same server
    let listener = if t.mode == "direct" { t.exit.clone() } else { t.entry.clone() };
    let mine_tcp: HashSet<u16> = parse_ports(&t.tcp).into_iter().map(|p| p.0).collect();
    if listener == t.entry && mine_tcp.contains(&t.port) {
        return err(StatusCode::BAD_REQUEST, "the tunnel port is also in the forwarded TCP ports");
    }
    for o in list.iter().filter(|o| o.id != t.id && o.enabled) {
        let o_listener = if o.mode == "direct" { &o.exit } else { &o.entry };
        let mut taken_tcp: HashSet<u16> = HashSet::new();
        let mut taken_udp: HashSet<u16> = HashSet::new();
        if *o_listener == listener {
            taken_tcp.insert(o.port);
        }
        if o.entry == t.entry {
            taken_tcp.extend(parse_ports(&o.tcp).into_iter().map(|p| p.0));
            taken_udp.extend(parse_ports(&o.udp).into_iter().map(|p| p.0));
        }
        if o.entry == listener || o_listener.as_str() == listener {
            if taken_tcp.contains(&t.port) {
                return err(StatusCode::CONFLICT, &format!("port {} is already used by the tunnel \"{}\"", t.port, o.name));
            }
        }
        if o.entry == t.entry {
            if let Some(p) = mine_tcp.iter().find(|p| taken_tcp.contains(p)) {
                return err(StatusCode::CONFLICT, &format!("TCP port {} is already used by the tunnel \"{}\"", p, o.name));
            }
            if let Some(p) = parse_ports(&t.udp).into_iter().map(|p| p.0).find(|p| taken_udp.contains(p)) {
                return err(StatusCode::CONFLICT, &format!("UDP port {} is already used by the tunnel \"{}\"", p, o.name));
            }
        }
    }
    if let Some(x) = list.iter_mut().find(|x| x.id == t.id) {
        *x = t.clone();
    } else {
        list.push(t.clone());
    }
    save_tunnels(&app, &list);
    Json(json!({ "ok": true, "id": t.id })).into_response()
}

async fn tunnel_del(State(app): St, h: HeaderMap, Path(id): Path<String>) -> Response {
    let _ = guard!(app, h, "nodes");
    let mut list = tunnels(&app);
    let n = list.len();
    list.retain(|t| t.id != id);
    if list.len() == n {
        return err(StatusCode::NOT_FOUND, "tunnel not found");
    }
    save_tunnels(&app, &list);
    Json(json!({ "ok": true })).into_response()
}

async fn tunnel_action(State(app): St, h: HeaderMap, Path((id, action)): Path<(String, String)>) -> Response {
    let _ = guard!(app, h, "nodes");
    let mut list = tunnels(&app);
    let Some(t) = list.iter_mut().find(|t| t.id == id) else { return err(StatusCode::NOT_FOUND, "tunnel not found") };
    match action.as_str() {
        "enable" => t.enabled = true,
        "disable" => t.enabled = false,
        // a new token makes both sides drop their links and make new ones
        "restart" | "rekey" => t.token = rand_token(40),
        _ => return err(StatusCode::BAD_REQUEST, "unknown action"),
    }
    save_tunnels(&app, &list);
    Json(json!({ "ok": true })).into_response()
}

async fn server_add(State(app): St, h: HeaderMap, Json(b): Json<Value>) -> Response {
    let _ = guard!(app, h, "nodes");
    let mut list = servers(&app);
    let name = b["name"].as_str().unwrap_or("").trim().to_string();
    let s = TServer {
        id: format!("t{}", rand_token(7).to_lowercase()),
        name: if name.is_empty() { format!("server-{}", list.len() + 1) } else { name },
        token: rand_token(40),
        addr: b["addr"].as_str().unwrap_or("").trim().to_string(),
        created: now(),
    };
    list.push(s.clone());
    save_servers(&app, &list);
    Json(json!({ "ok": true, "id": s.id, "token": s.token, "name": s.name, "panel": crate::api::origin(&app), "repo": crate::admin::repo() })).into_response()
}

async fn server_edit(State(app): St, h: HeaderMap, Path(id): Path<String>, Json(b): Json<Value>) -> Response {
    let _ = guard!(app, h, "nodes");
    if id == "local" {
        if let Some(a) = b["addr"].as_str() {
            app.db.set("tun_local_addr", a.trim());
        }
        return Json(json!({ "ok": true })).into_response();
    }
    let mut list = servers(&app);
    let Some(s) = list.iter_mut().find(|s| s.id == id) else { return err(StatusCode::NOT_FOUND, "server not found") };
    if let Some(n) = b["name"].as_str() {
        if !n.trim().is_empty() {
            s.name = n.trim().to_string();
        }
    }
    if let Some(a) = b["addr"].as_str() {
        s.addr = a.trim().to_string();
    }
    let token = if b["new_token"].as_bool().unwrap_or(false) {
        s.token = rand_token(40);
        Some(s.token.clone())
    } else {
        None
    };
    save_servers(&app, &list);
    Json(json!({ "ok": true, "token": token, "panel": crate::api::origin(&app), "repo": crate::admin::repo() })).into_response()
}

async fn server_del(State(app): St, h: HeaderMap, Path(id): Path<String>) -> Response {
    let _ = guard!(app, h, "nodes");
    if id == "local" {
        return err(StatusCode::BAD_REQUEST, "the panel server cannot be removed");
    }
    let used: Vec<String> = tunnels(&app).into_iter().filter(|t| t.entry == id || t.exit == id).map(|t| t.name).collect();
    if !used.is_empty() {
        return err(StatusCode::CONFLICT, &format!("delete its tunnels first: {}", used.join(", ")));
    }
    let mut list = servers(&app);
    list.retain(|s| s.id != id);
    save_servers(&app, &list);
    seen().lock().unwrap().remove(&id);
    Json(json!({ "ok": true })).into_response()
}

/// Public: a tunnel agent reports its tunnels and gets the list it should run.
async fn agent_report(State(app): St, h: HeaderMap, Json(b): Json<Value>) -> Response {
    let id = b["id"].as_str().unwrap_or("").to_string();
    let token = b["token"].as_str().unwrap_or("").to_string();
    let Some(s) = servers(&app).into_iter().find(|s| s.id == id) else {
        // unknown or removed: the agent stops its tunnels
        return (StatusCode::GONE, "this server is not in the panel any more").into_response();
    };
    if token.is_empty() || !util::ct_eq(&token, &s.token) {
        return err(StatusCode::FORBIDDEN, "wrong token");
    }
    let status: Vec<Status> = serde_json::from_value(b["status"].clone()).unwrap_or_default();
    let ip = util::client_ip(&h);
    seen().lock().unwrap().insert(
        id.clone(),
        Seen { at: now(), version: b["version"].as_str().unwrap_or("").to_string(), ip, status },
    );
    Json(json!({ "tunnels": specs_for(&app, &id) })).into_response()
}
