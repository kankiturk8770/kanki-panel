//! Servers: one list, one kind of server.
//!
//! The panel runs on one server ("local"). Every other server is a node of the panel and is added
//! with ONE command, which installs everything a server can do: the VPN (WireGuard, AmneziaWG,
//! Hysteria2, KANKI MIX: the node agent) and the server agent (tunnels, Xray, Kanki DNS, emergency
//! chat). What a server actually runs is then switched on in the panel, nothing more is typed on it.
//!
//! Inside, a server is still two records that run as two services on the machine: a VPN node (the
//! panel calls it) and an agent server (it calls the panel). They are linked here (`TServer.node`)
//! and shown as one. A server made before this version (only one of the two) gets the missing part
//! with one button (`complete`): a node starts the agent next to itself, an agent runs the installer
//! for the VPN part by itself.
//!
//! The VPN ports of every server are different from those of every other server (WireGuard,
//! AmneziaWG, Hysteria2 and KANKI MIX), so one tunnel entry (the Iran server) can carry the ports of
//! all servers at once. A new server gets free ports before it is installed; servers that clash are
//! moved with `fix-ports`, and the tunnels that forward the old port follow.
use crate::api::err;
use crate::db::Node;
use crate::guard;
use crate::tunnel::panel::{self as tp, TServer};
use crate::util::{now, rand_token};
use crate::App;
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

type St = State<Arc<App>>;

/// The installer of this very version (the panel serves it, so a server that cannot reach GitHub
/// still gets it, and an agent can install the VPN part without downloading anything)
pub const INSTALL_SH: &str = include_str!("../../install.sh");

/// how long a server's join token works
const JOIN_VALID: i64 = 6 * 3600;
/// the agent version that can install the VPN part when the panel asks
const SETUP_FROM: &str = "3.9.0";

pub fn router() -> Router<Arc<App>> {
    Router::new()
        .route("/api/servers", get(list).post(add))
        .route("/api/servers/fix-ports", post(fix_ports))
        .route("/api/servers/direct", get(direct_get).put(direct_put))
        .route("/api/servers/:id", delete(remove).put(edit))
        .route("/api/servers/:id/complete", post(complete))
        .route("/api/servers/:id/vpn", post(vpn_switch))
        .route("/api/servers/:id/ports", post(set_ports))
        .route("/api/servers/:id/kmix", post(kmix_switch))
        .route("/api/servers/:id/command", get(command_again))
        // outside /api/: a new server fetches them with its one-time token (no admin session there)
        .route("/dl/install.sh", get(dl_script))
        .route("/dl/kanki-panel", get(dl_bin))
        .route("/dl/kanki-panel.sha256", get(dl_sum))
}

// ------------------------------------------------------------------ addresses

/// The panel's own address for servers (agents and joining nodes): its domain and HTTPS port. Never
/// the separate subscription domain: that one only serves the subscription pages, so an agent given
/// it could never reach the panel.
pub fn panel_url(app: &App) -> String {
    let domain = app.env.get("DOMAIN").map(|d| d.trim().to_string()).unwrap_or_default();
    if domain.is_empty() {
        return crate::api::origin(app);
    }
    match app.env.get("HTTPS_PORT").map(|s| s.trim()).filter(|p| !p.is_empty() && *p != "443") {
        Some(p) => format!("https://{}:{}", domain, p),
        None => format!("https://{}", domain),
    }
}

fn repo() -> String {
    let r = crate::admin::repo();
    if r.is_empty() { "kankiturk8770/kanki-panel".into() } else { r }
}

/// The one command that makes a machine this server: everything installed, joined to the panel.
fn command(app: &App, s: &TServer) -> String {
    let panel = panel_url(app);
    let repo = repo();
    let ports = s.ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(",");
    let mut env = format!("KANKI_REPO='{}' KANKI_PANEL='{}' KANKI_TUNNEL='{}:{}'", repo, panel, s.id, s.token);
    if !s.join.is_empty() {
        env.push_str(&format!(" KANKI_JOIN='{}' KANKI_PORTS='{}'", s.join, ports));
    }
    if !s.domain.is_empty() {
        env.push_str(&format!(" KANKI_DOMAIN='{}'", s.domain));
    }
    // the installer from the panel first (works where GitHub is filtered), GitHub second
    format!(
        "curl -fsSL '{p}/dl/install.sh' -o /tmp/kanki-install.sh || curl -fsSL 'https://raw.githubusercontent.com/{r}/main/install.sh' -o /tmp/kanki-install.sh; {e} bash /tmp/kanki-install.sh",
        p = panel,
        r = repo,
        e = env
    )
}

// ------------------------------------------------------------------ ports

/// One VPN port a server uses: (node id, protocol, UDP port)
#[derive(Clone, Debug, PartialEq)]
pub struct Use {
    pub node: String,
    pub proto: &'static str,
    pub port: u16,
}

pub const PROTOS: [&str; 4] = ["wg", "awg", "hy2", "kmix"];
/// every protocol with a port of its own per server: the four above and microtun (its port is given
/// when the server joins, not in the installer's list of four)
pub const ALL_PROTOS: [&str; 5] = ["wg", "awg", "hy2", "kmix", "mtun"];

fn num(v: &Value) -> Option<u16> {
    v.as_u64().or_else(|| v.as_str().and_then(|s| s.trim().parse().ok())).and_then(|p| u16::try_from(p).ok()).filter(|p| *p > 0)
}

/// The VPN ports of one node: from what it reported, KANKI MIX from the panel's setting (where the
/// node moves on its next sync).
fn node_uses(n: &Node, km: &crate::kmix::Settings, mt: Option<&crate::microtun::Settings>) -> Vec<Use> {
    let i = crate::api::node_info(n);
    let has = |k: &str| i[k].as_str().map(|s| !s.is_empty()).unwrap_or(false);
    let mut v = vec![];
    let mut push = |proto: &'static str, p: Option<u16>| {
        if let Some(port) = p {
            v.push(Use { node: n.id.clone(), proto, port });
        }
    };
    push("wg", if has("wg_pub") { num(&i["wg_port"]) } else { None });
    push("awg", if has("awg_pub") { num(&i["awg_port"]) } else { None });
    push("hy2", num(&i["hy2_port"]));
    let kmix_installed = !i["kmix_port"].is_null() || n.id == "local";
    // a server given its own KANKI MIX port when it joined holds it from then on, also before its first
    // sync installs KANKI MIX there (else the next server added got the same port)
    let kmix_given = km.nodes.get(&n.id).map(|o| o.port > 0).unwrap_or(false);
    push("kmix", if km.node_on(&n.id) && (kmix_installed || kmix_given) { Some(km.node_port(&n.id)) } else { None });
    // microtun: the port the panel wants there (the server moves to it on its next sync)
    push("mtun", mt.and_then(|s| s.node_on(&n.id).then(|| s.node_port(&n.id))));
    v
}

/// Every VPN port of every server; the panel server first, then the others in the order they joined
fn all_uses(app: &App) -> Vec<Use> {
    let km = crate::kmix::settings(app);
    let mt = crate::microtun::settings(app);
    let mut nodes = app.db.nodes();
    nodes.sort_by_key(|n| n.id != "local");
    nodes.iter().flat_map(|n| node_uses(n, &km, Some(&mt))).collect()
}

/// The clashes: the same UDP port used by two different servers. [(port, [(node, proto)])]
pub fn clashes(uses: &[Use]) -> Vec<(u16, Vec<(String, &'static str)>)> {
    let mut by: Vec<(u16, Vec<(String, &'static str)>)> = vec![];
    for u in uses {
        match by.iter_mut().find(|(p, _)| *p == u.port) {
            Some((_, v)) => v.push((u.node.clone(), u.proto)),
            None => by.push((u.port, vec![(u.node.clone(), u.proto)])),
        }
    }
    by.retain(|(_, v)| {
        let first = &v[0].0;
        v.iter().any(|(n, _)| n != first)
    });
    by
}

/// Every port a new VPN port must not be: the VPN ports of all servers, the ports of tunnels (both
/// ends), Xray inbounds, servers being installed, KANKI MIX port-hop ranges, and the well-known ones.
fn taken(app: &App, uses: &[Use]) -> HashSet<u16> {
    let mut t: HashSet<u16> = [22, 53, 80, 443, 853, 2053, 2083, 2087, 2096, 8080, 8880].into_iter().collect();
    if let Some(p) = app.env.get("HTTPS_PORT").and_then(|p| p.trim().parse().ok()) {
        t.insert(p);
    }
    t.extend(uses.iter().map(|u| u.port));
    let km = crate::kmix::settings(app);
    if let Some((a, b)) = crate::kmix::hop_range(&km.hop) {
        t.extend(a..=b);
    }
    for tu in tp::tunnels(app) {
        if tu.port > 0 {
            t.insert(tu.port);
        }
        for (a, b) in crate::tunnel::engine::parse_ports(&tu.tcp).into_iter().chain(crate::tunnel::engine::parse_ports(&tu.udp)) {
            t.insert(a);
            t.insert(b);
        }
    }
    for ib in crate::xray::panel::settings(app).inbounds {
        t.insert(ib.port);
    }
    for s in tp::servers(app).iter().filter(|s| !s.join.is_empty()) {
        t.extend(s.ports.iter().copied().filter(|p| *p > 0));
    }
    t
}

/// The first free port of a protocol's range
fn pick(taken: &mut HashSet<u16>, proto: &str) -> u16 {
    let ranges: &[(u16, u16)] = match proto {
        "wg" | "awg" => &[(51820, 51999), (52000, 52999)],
        "hy2" => &[(8443, 8499), (30000, 30999)],
        "mtun" => &[(4200, 4299), (42000, 42999)],
        _ => &[(4000, 4199), (40000, 40999)],
    };
    for (a, b) in ranges {
        if let Some(p) = (*a..=*b).find(|p| !taken.contains(p)) {
            taken.insert(p);
            return p;
        }
    }
    0
}

/// Four free ports for a new server: [WireGuard, AmneziaWG, Hysteria2, KANKI MIX]
pub fn allocate(app: &App) -> Vec<u16> {
    let uses = all_uses(app);
    let mut t = taken(app, &uses);
    PROTOS.iter().map(|p| pick(&mut t, p)).collect()
}

/// A tunnel's port list with the target port `old` sent to `new` (a symmetric "old" or "old:old"
/// moves on both sides). Ranges are left as they are. Returns None when nothing changed.
pub fn remap(list: &[String], old: u16, new: u16) -> Option<Vec<String>> {
    let mut changed = false;
    let out: Vec<String> = list
        .iter()
        .map(|item| {
            item.split(',')
                .map(|part| {
                    let p = part.trim();
                    if let Some((a, b)) = p.split_once(':') {
                        if b.trim().parse::<u16>().ok() == Some(old) {
                            changed = true;
                            let a2 = if a.trim().parse::<u16>().ok() == Some(old) { new.to_string() } else { a.trim().to_string() };
                            return format!("{}:{}", a2, new);
                        }
                    } else if p.parse::<u16>().ok() == Some(old) {
                        changed = true;
                        return new.to_string();
                    }
                    p.to_string()
                })
                .collect::<Vec<_>>()
                .join(",")
        })
        .collect();
    changed.then_some(out)
}

/// The agent server id of node `nid` ("local" for the panel server)
fn agent_of(app: &App, nid: &str) -> Option<String> {
    if nid == "local" {
        return Some("local".into());
    }
    tp::servers(app).into_iter().find(|s| s.node == nid).map(|s| s.id)
}

/// Moves the VPN ports that clash with another server. `only`: move only that node's ports (a server
/// that just joined); None: every clash, the server that had the port first keeps it.
pub async fn fix_ports_of(app: &Arc<App>, only: Option<&str>) -> Value {
    let uses = all_uses(app);
    let mut t = taken(app, &uses);
    let mut owner: HashMap<u16, String> = HashMap::new();
    if let Some(o) = only {
        // the others keep theirs
        for u in uses.iter().filter(|u| u.node != o) {
            owner.entry(u.port).or_insert(u.node.clone());
        }
    }
    let mut moves: Vec<(String, &'static str, u16, u16)> = vec![];
    for u in &uses {
        let first = owner.entry(u.port).or_insert(u.node.clone()).clone();
        if first == u.node || only.map(|o| o != u.node).unwrap_or(false) {
            continue;
        }
        let new = pick(&mut t, u.proto);
        if new > 0 {
            moves.push((u.node.clone(), u.proto, u.port, new));
        }
    }
    let mut report = vec![];
    let mut by_node: HashMap<String, Vec<(&'static str, u16, u16)>> = HashMap::new();
    for (n, p, o, nw) in &moves {
        by_node.entry(n.clone()).or_default().push((p, *o, *nw));
    }
    for (nid, list) in by_node {
        let Some(n) = app.db.node(&nid) else { continue };
        let mut body = json!({});
        for (p, _, nw) in list.iter().filter(|(p, _, _)| *p != "kmix" && *p != "mtun") {
            body[*p] = json!(nw);
        }
        let mut errs: Vec<String> = vec![];
        if body.as_object().map(|o| !o.is_empty()).unwrap_or(false) {
            let r = if nid == "local" {
                let b = body.clone();
                tokio::task::spawn_blocking(move || crate::admin::set_ports(&b)).await.ok()
            } else {
                crate::sync::remote_post_json(app, &n, "/agent/ports", &body).await
            };
            match r {
                Some(v) => errs.extend(v["errors"].as_array().into_iter().flatten().filter_map(|e| e.as_str().map(|s| s.to_string()))),
                None => errs.push("the server did not answer (update its agent, then try again)".into()),
            }
        }
        let agent = agent_of(app, &nid);
        for (p, old, new) in list {
            let failed = p != "kmix" && p != "mtun" && errs.iter().any(|e| e.starts_with(p) || e.contains("did not answer"));
            if !failed {
                if p == "kmix" {
                    crate::kmix::set_node_port(app, &nid, new);
                    crate::kmix::move_tunnel_port(app, &nid, old, new);
                }
                if p == "mtun" {
                    crate::microtun::set_node_port(app, &nid, new);
                }
                // the tunnels that carry this port to this server follow it
                if let Some(a) = &agent {
                    let mut tl = tp::tunnels(app);
                    let mut any = false;
                    for tu in tl.iter_mut().filter(|tu| &tu.exit == a) {
                        if let Some(u) = remap(&tu.udp, old, new) {
                            tu.udp = u;
                            any = true;
                        }
                    }
                    if any {
                        tp::save_tunnels(app, &tl);
                    }
                }
            }
            report.push(json!({ "server": n.name, "proto": p, "old": old, "new": new, "ok": !failed, "error": if failed { errs.join("; ") } else { String::new() } }));
        }
    }
    if !report.is_empty() {
        crate::api::spawn_sync(app);
    }
    json!({ "ok": true, "moved": report })
}

async fn fix_ports(State(app): St, h: HeaderMap) -> Response {
    let _ = guard!(app, h, "nodes");
    Json(fix_ports_of(&app, None).await).into_response()
}

/// The direct names of the servers (fr.example.com …), the IP each must point at and whether it does
async fn direct_get(State(app): St, h: HeaderMap) -> Response {
    let _ = guard!(app, h, "nodes");
    Json(crate::direct::table(&app)).into_response()
}

/// { base: "example.com" } ("" = the panel domain without its first label)
async fn direct_put(State(app): St, h: HeaderMap, Json(b): Json<Value>) -> Response {
    let _ = guard!(app, h, "nodes");
    let v = b["base"].as_str().unwrap_or("").trim().trim_matches('.').to_ascii_lowercase();
    let ok = v.is_empty() || (v.contains('.') && v.len() <= 200 && v.split('.').all(|l| !l.is_empty() && l.len() <= 63 && l.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')));
    if !ok {
        return err(StatusCode::BAD_REQUEST, "not a domain (like example.com)");
    }
    app.db.set(crate::direct::BASE_KEY, &v);
    Json(crate::direct::table(&app)).into_response()
}

// ------------------------------------------------------------------ links between the two parts

/// The server whose one-time join token this is (its VPN part is joining)
pub fn join_server(app: &App, token: &str) -> Option<TServer> {
    if token.len() < 20 {
        return None;
    }
    tp::servers(app).into_iter().find(|s| !s.join.is_empty() && s.join_exp > now() && crate::util::ct_eq(&s.join, token))
}

/// The VPN part of server `sid` joined as node `nid`: linked, the token used up, its KANKI MIX port set.
pub fn joined(app: &App, sid: &str, nid: &str) {
    let mut list = tp::servers(app);
    let Some(s) = list.iter_mut().find(|s| s.id == sid) else { return };
    s.node = nid.to_string();
    s.join.clear();
    s.setup_at = 0;
    let km = s.ports.get(3).copied().unwrap_or(0);
    tp::save_servers(app, &list);
    if km > 0 {
        crate::kmix::set_node_port(app, nid, km);
    }
    // microtun too: the next free port (4200, 4201 …), so a tunnel entry can carry every server
    let uses: Vec<Use> = all_uses(app).into_iter().filter(|u| !(u.node == nid && u.proto == "mtun")).collect();
    let mut t = taken(app, &uses);
    let p = pick(&mut t, "mtun");
    if p > 0 {
        crate::microtun::set_node_port(app, nid, p);
    }
}

/// A node was deleted: no server points to it any more
pub fn node_gone(app: &App, nid: &str) {
    let mut list = tp::servers(app);
    let mut any = false;
    for s in list.iter_mut().filter(|s| s.node == nid) {
        s.node.clear();
        any = true;
    }
    if any {
        tp::save_servers(app, &list);
    }
}

/// The address host of a node (its agent URL)
fn node_host(n: &Node) -> String {
    let rest = n.address.trim().split("://").last().unwrap_or("");
    let hp = rest.split('/').next().unwrap_or("");
    if let Some(v6) = hp.strip_prefix('[') {
        return v6.split(']').next().unwrap_or("").to_lowercase();
    }
    hp.split(':').next().unwrap_or("").to_lowercase()
}

/// Servers installed before 3.9 (a node and an agent on the same machine, added apart) are found and
/// linked: same address, or the agent reports from an IP the node's name resolves to.
pub async fn auto_link(app: &App) {
    let mut list = tp::servers(app);
    let nodes: Vec<Node> = app.db.nodes().into_iter().filter(|n| n.id != "local").collect();
    let ids: HashSet<String> = nodes.iter().map(|n| n.id.clone()).collect();
    let mut changed = false;
    for s in list.iter_mut().filter(|s| !s.node.is_empty() && !ids.contains(&s.node)) {
        s.node.clear();
        changed = true;
    }
    let linked: HashSet<String> = list.iter().map(|s| s.node.clone()).filter(|x| !x.is_empty()).collect();
    for n in nodes.iter().filter(|n| !linked.contains(&n.id)) {
        let host = node_host(n);
        if host.is_empty() {
            continue;
        }
        let ips: Vec<String> = match tokio::net::lookup_host((host.as_str(), 443u16)).await {
            Ok(it) => it.map(|a| a.ip().to_string()).collect(),
            Err(_) => vec![],
        };
        let hit = list.iter_mut().find(|s| {
            if !s.node.is_empty() || !s.join.is_empty() {
                return false;
            }
            let ip = tp::agent_state(&s.id).map(|x| x.2).unwrap_or_default();
            s.addr.trim().to_lowercase() == host || (!ip.is_empty() && (ips.contains(&ip) || ip == host))
        });
        if let Some(s) = hit {
            s.node = n.id.clone();
            changed = true;
        }
    }
    if changed {
        tp::save_servers(app, &list);
    }
}

pub async fn link_loop(app: Arc<App>) {
    tokio::time::sleep(std::time::Duration::from_secs(20)).await;
    loop {
        auto_link(&app).await;
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
    }
}

/// What the agent of server `s` is told about installing its VPN part: the request (until the agent
/// says it took it), or Null.
pub fn setup_for(app: &App, s: &TServer, reported: &Value) -> Value {
    if s.setup_at == 0 || s.join.is_empty() || s.join_exp <= now() || !s.node.is_empty() {
        return Value::Null;
    }
    if reported["req"].as_i64() == Some(s.setup_at) {
        return Value::Null;
    }
    json!({
        "req": s.setup_at,
        "panel": panel_url(app),
        "join": s.join,
        "ports": s.ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(","),
        "domain": s.domain,
        "repo": repo(),
    })
}

// ------------------------------------------------------------------ the list

fn ver_lt(a: &str, b: &str) -> bool {
    crate::admin::newer(b, a)
}

fn ports_json(uses: &[Use], nid: &str) -> Value {
    let mut m = json!({});
    for u in uses.iter().filter(|u| u.node == nid) {
        m[u.proto] = json!(u.port);
    }
    m
}

async fn list(State(app): St, h: HeaderMap) -> Response {
    let _ = guard!(app, h, "nodes");
    Json(list_json(&app)).into_response()
}

pub fn list_json(app: &App) -> Value {
    let users = app.db.users();
    let nodes = app.db.nodes();
    let uses = all_uses(app);
    let cl = clashes(&uses);
    let srv = tp::servers(app);
    let locs = tp::server_locs(app);
    let ccs = crate::exitgeo::all_cc(app);
    let tl = tp::tunnels(app);
    let xr = crate::xray::panel::settings(app);
    let dn = crate::dns::panel::settings(app);
    let emer = app.db.get("emer_server");
    let subs = crate::subiran::settings(app).server;
    let t = now();
    let names: HashMap<String, String> = nodes.iter().map(|n| (n.id.clone(), n.name.clone())).collect();
    let jobs = |sid: &str| {
        json!({
            "tunnels": tl.iter().filter(|x| x.entry == sid || x.exit == sid).count(),
            "tunnels_up": tl.iter().filter(|x| (x.entry == sid || x.exit == sid) && x.enabled).count(),
            "xray": xr.inbounds.iter().filter(|i| i.server == sid).count(),
            "xray_on": xr.on && xr.servers.iter().any(|x| x.server == sid),
            "dns": dn.servers.iter().find(|x| x.server == sid).map(|x| x.role.clone()).unwrap_or_default(),
            "emergency": emer == sid,
            "subsrv": subs == sid,
        })
    };
    let node_v = |nid: &str| nodes.iter().find(|n| n.id == nid).map(|n| crate::api::node_json(app, n, &users)).unwrap_or(Value::Null);
    let mut out = vec![];
    // the panel server
    out.push(json!({
        "key": "local", "name": nodes.iter().find(|n| n.id == "local").map(|n| n.name.clone()).unwrap_or_else(|| "Main".into()),
        "local": true, "loc": locs.get("local").map(|x| x.0.clone()).unwrap_or_default(), "cc": crate::exitgeo::cc(app, "local"),
        "agent": { "id": "local", "online": true, "last_seen": t, "version": crate::VERSION, "addr": app.db.get("tun_local_addr") },
        "node": node_v("local"), "ports": ports_json(&uses, "local"), "jobs": jobs("local"), "command": Value::Null,
        "tunnel": crate::twin::info(app, "local", Some("local")),
    }));
    let mut linked: HashSet<String> = HashSet::new();
    for s in &srv {
        let st = tp::agent_state(&s.id);
        let (at, ver, ip, setup) = st.clone().unwrap_or_default();
        let node = if s.node.is_empty() { Value::Null } else { node_v(&s.node) };
        if !node.is_null() {
            linked.insert(s.node.clone());
        }
        let cc = Some(crate::exitgeo::cc(app, &s.node)).filter(|c| !c.is_empty() && !s.node.is_empty()).unwrap_or_else(|| ccs.get(&crate::exitgeo::srv_key(&s.id)).cloned().unwrap_or_default());
        let pending = !s.join.is_empty() && s.join_exp > t;
        out.push(json!({
            "key": s.id, "name": s.name, "local": false,
            "loc": locs.get(&s.id).map(|x| x.0.clone()).unwrap_or_default(), "cc": cc,
            "agent": { "id": s.id, "online": at > 0 && t - at < 20, "last_seen": at, "version": ver, "ip": ip, "addr": s.addr,
                       "can_setup": !ver.is_empty() && !ver_lt(&ver, SETUP_FROM) },
            "node": node, "ports": if s.node.is_empty() { json!({}) } else { ports_json(&uses, &s.node) },
            "planned": s.ports, "pending": pending, "vpn_wanted": s.vpn, "domain": s.domain,
            "setup": setup, "setup_asked": s.setup_at,
            "jobs": jobs(&s.id), "created": s.created,
            "tunnel": crate::twin::info(app, &s.id, Some(s.node.as_str()).filter(|n| !n.is_empty())),
        }));
    }
    // VPN nodes with no agent yet (added before 3.9)
    for n in nodes.iter().filter(|n| n.id != "local" && !linked.contains(&n.id)) {
        out.push(json!({
            "key": format!("node:{}", n.id), "name": n.name, "local": false,
            "loc": if crate::exitgeo::cc(app, &n.id) == "IR" { "iran" } else { "abroad" }, "cc": crate::exitgeo::cc(app, &n.id),
            "agent": Value::Null, "node": node_v(&n.id), "ports": ports_json(&uses, &n.id), "jobs": Value::Null,
            "tunnel": crate::twin::info(app, &format!("node:{}", n.id), Some(n.id.as_str())),
        }));
    }
    let clash: Vec<Value> = cl
        .iter()
        .map(|(p, v)| json!({ "port": p, "users": v.iter().map(|(n, pr)| json!({ "node": n, "name": names.get(n).cloned().unwrap_or(n.clone()), "proto": pr })).collect::<Vec<_>>() }))
        .collect();
    json!({ "servers": out, "clashes": clash, "panel": panel_url(app), "repo": repo(), "version": crate::VERSION })
}

// ------------------------------------------------------------------ add / complete / switch / remove

fn clean_loc(v: &str) -> String {
    if v == "iran" || v == "abroad" { v.into() } else { String::new() }
}

fn clean_domain(d: &str) -> String {
    let d = d.trim().trim_matches('.').to_ascii_lowercase();
    let ok = d.len() >= 4 && d.contains('.') && d.parse::<std::net::IpAddr>().is_err() && d.split('.').all(|l| !l.is_empty() && l.len() <= 63 && l.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-'));
    if ok { d } else { String::new() }
}

/// { name, loc: iran|abroad, domain?, vpn? } -> a new server and the one command for it
async fn add(State(app): St, h: HeaderMap, Json(b): Json<Value>) -> Response {
    let _ = guard!(app, h, "nodes");
    let mut list = tp::servers(&app);
    let name = b["name"].as_str().unwrap_or("").trim().chars().take(40).collect::<String>();
    let loc = clean_loc(b["loc"].as_str().unwrap_or(""));
    let domain = clean_domain(b["domain"].as_str().unwrap_or(""));
    if !b["domain"].as_str().unwrap_or("").trim().is_empty() && domain.is_empty() {
        return err(StatusCode::BAD_REQUEST, "the domain is not valid (like node1.example.com, not an IP)");
    }
    // a relay in Iran carries tunnels; its VPN is installed but serves nobody until switched on
    let vpn = b["vpn"].as_bool().unwrap_or(loc != "iran");
    // its tunnel domain (the Iran server's): every config gets its copy through it once the server joins
    let tun = b["tunnel_host"].as_str().unwrap_or("").trim().to_string();
    let s = TServer {
        id: format!("t{}", rand_token(7).to_lowercase()),
        name: if name.is_empty() { format!("server-{}", list.len() + 1) } else { name },
        token: rand_token(40),
        loc,
        created: now(),
        join: rand_token(40),
        join_exp: now() + JOIN_VALID,
        vpn,
        ports: allocate(&app),
        domain,
        ..Default::default()
    };
    if !tun.is_empty() {
        if let Err(e) = crate::twin::save(&app, &s.id, &json!({ "on": true, "host": tun })) {
            return err(StatusCode::BAD_REQUEST, &e);
        }
    }
    list.push(s.clone());
    tp::save_servers(&app, &list);
    Json(json!({ "ok": true, "id": s.id, "command": command(&app, &s), "expires": s.join_exp, "ports": s.ports })).into_response()
}

/// The command of a server again (a new join token when the old one ran out)
async fn command_again(State(app): St, h: HeaderMap, Path(id): Path<String>) -> Response {
    let _ = guard!(app, h, "nodes");
    let mut list = tp::servers(&app);
    let Some(s) = list.iter_mut().find(|s| s.id == id) else { return err(StatusCode::NOT_FOUND, "unknown server") };
    if s.node.is_empty() && (s.join.is_empty() || s.join_exp <= now()) {
        s.join = rand_token(40);
        s.join_exp = now() + JOIN_VALID;
        if s.ports.len() != 4 {
            s.ports = vec![];
        }
    }
    let need_ports = s.node.is_empty() && s.ports.is_empty();
    let s2 = s.clone();
    tp::save_servers(&app, &list);
    let s = if need_ports {
        let ports = allocate(&app);
        let mut list = tp::servers(&app);
        if let Some(x) = list.iter_mut().find(|x| x.id == id) {
            x.ports = ports;
        }
        tp::save_servers(&app, &list);
        list.into_iter().find(|x| x.id == id).unwrap_or(s2)
    } else {
        s2
    };
    // a server whose VPN part already joined only needs the agent part again
    let mut c = s.clone();
    if !s.node.is_empty() {
        c.join.clear();
    }
    Json(json!({ "ok": true, "command": command(&app, &c), "expires": s.join_exp })).into_response()
}

/// { name?, loc?, addr? }
async fn edit(State(app): St, h: HeaderMap, Path(id): Path<String>, Json(b): Json<Value>) -> Response {
    let _ = guard!(app, h, "nodes");
    // { tunnel: { on, host, name } }: the copy of every config through this server's tunnel
    if let Some(t) = b.get("tunnel").filter(|t| t.is_object()) {
        let known = id == "local" || id.starts_with("node:") || tp::servers(&app).iter().any(|s| s.id == id);
        if !known {
            return err(StatusCode::NOT_FOUND, "unknown server");
        }
        if let Err(e) = crate::twin::save(&app, &id, t) {
            return err(StatusCode::BAD_REQUEST, &e);
        }
    }
    if id == "local" {
        if let Some(n) = b["name"].as_str().map(|s| s.trim()).filter(|s| !s.is_empty()) {
            let _ = app.db.exec("UPDATE nodes SET name=?1 WHERE id='local'", &[&n]);
        }
        if let Some(l) = b["loc"].as_str() {
            app.db.set("tun_local_loc", &clean_loc(l));
        }
        if let Some(a) = b["addr"].as_str() {
            app.db.set("tun_local_addr", a.trim());
        }
        return Json(json!({ "ok": true })).into_response();
    }
    if let Some(nid) = id.strip_prefix("node:") {
        if let Some(n) = b["name"].as_str().map(|s| s.trim()).filter(|s| !s.is_empty()) {
            let _ = app.db.exec("UPDATE nodes SET name=?1 WHERE id=?2", &[&n, &nid]);
        }
        return Json(json!({ "ok": true })).into_response();
    }
    let mut list = tp::servers(&app);
    let Some(s) = list.iter_mut().find(|s| s.id == id) else { return err(StatusCode::NOT_FOUND, "unknown server") };
    if let Some(n) = b["name"].as_str().map(|s| s.trim()).filter(|s| !s.is_empty()) {
        s.name = n.chars().take(40).collect();
        if !s.node.is_empty() {
            let _ = app.db.exec("UPDATE nodes SET name=?1 WHERE id=?2", &[&s.name, &s.node]);
        }
    }
    if let Some(l) = b["loc"].as_str() {
        s.loc = clean_loc(l);
    }
    if let Some(a) = b["addr"].as_str() {
        s.addr = a.trim().to_string();
    }
    tp::save_servers(&app, &list);
    Json(json!({ "ok": true })).into_response()
}

/// Installs the part a server is missing, from the panel: a VPN node gets the agent next to it; an
/// agent server installs the VPN part itself. { vpn?: serve users once installed, domain? }
async fn complete(State(app): St, h: HeaderMap, Path(id): Path<String>, body: Option<Json<Value>>) -> Response {
    let _ = guard!(app, h, "nodes");
    let b = body.map(|j| j.0).unwrap_or(Value::Null);
    if let Some(nid) = id.strip_prefix("node:") {
        let Some(n) = app.db.node(nid) else { return err(StatusCode::NOT_FOUND, "unknown server") };
        let cc = crate::exitgeo::cc(&app, &n.id);
        let s = TServer {
            id: format!("t{}", rand_token(7).to_lowercase()),
            name: n.name.clone(),
            token: rand_token(40),
            node: n.id.clone(),
            loc: if cc == "IR" { "iran".into() } else if cc.is_empty() { String::new() } else { "abroad".into() },
            created: now(),
            vpn: n.enabled,
            ..Default::default()
        };
        let r = crate::sync::remote_post_json(&app, &n, "/agent/setup-tunnel", &json!({ "panel": panel_url(&app), "id": s.id, "token": s.token })).await;
        return match r {
            Some(v) if v["ok"].as_bool() == Some(true) => {
                let mut list = tp::servers(&app);
                list.push(s.clone());
                tp::save_servers(&app, &list);
                Json(json!({ "ok": true, "id": s.id })).into_response()
            }
            Some(v) if v["error"].is_string() => err(StatusCode::BAD_GATEWAY, v["error"].as_str().unwrap_or("")),
            _ => err(StatusCode::BAD_GATEWAY, "this server's agent is older: press Update on it first, then try again"),
        };
    }
    let mut list = tp::servers(&app);
    let Some(s) = list.iter_mut().find(|s| s.id == id) else { return err(StatusCode::NOT_FOUND, "unknown server") };
    if !s.node.is_empty() {
        return err(StatusCode::BAD_REQUEST, "this server already has everything installed");
    }
    let (at, ver, _, _) = tp::agent_state(&s.id).unwrap_or_default();
    if at == 0 || now() - at > 60 {
        return err(StatusCode::CONFLICT, "this server is not connected to the panel right now");
    }
    if ver.is_empty() || ver_lt(&ver, SETUP_FROM) {
        return err(StatusCode::CONFLICT, "this server's agent is older: press Update all first (it takes a minute), then try again");
    }
    if let Some(d) = b["domain"].as_str() {
        s.domain = clean_domain(d);
    }
    s.vpn = b["vpn"].as_bool().unwrap_or(s.loc != "iran");
    s.join = rand_token(40);
    s.join_exp = now() + JOIN_VALID;
    s.setup_at = now();
    let need = s.ports.len() != 4;
    tp::save_servers(&app, &list);
    if need {
        let ports = allocate(&app);
        let mut list = tp::servers(&app);
        if let Some(x) = list.iter_mut().find(|x| x.id == id) {
            x.ports = ports;
        }
        tp::save_servers(&app, &list);
    }
    Json(json!({ "ok": true })).into_response()
}

/// The VPN node of a server key ("local", "node:<id>" or an agent server linked to a node)
#[allow(clippy::result_large_err)] // the error is the ready axum answer (404/400)
fn node_of_key(app: &App, id: &str) -> Result<String, Response> {
    if id == "local" {
        return Ok("local".into());
    }
    if let Some(n) = id.strip_prefix("node:") {
        return Ok(n.to_string());
    }
    let list = tp::servers(app);
    let Some(s) = list.iter().find(|s| s.id == id) else { return Err(err(StatusCode::NOT_FOUND, "unknown server")) };
    if s.node.is_empty() {
        return Err(err(StatusCode::BAD_REQUEST, "the VPN is not installed on this server yet"));
    }
    Ok(s.node.clone())
}

/// Who else uses UDP `port` for a VPN protocol (another server, or another protocol of this one)
fn port_user(app: &App, nid: &str, proto: &str, port: u16) -> Option<String> {
    let names: HashMap<String, String> = app.db.nodes().into_iter().map(|n| (n.id, n.name)).collect();
    all_uses(app).into_iter().find(|u| u.port == port && !(u.node == nid && u.proto == proto)).map(|u| {
        format!("UDP {} is already used by {} ({})", port, names.get(&u.node).cloned().unwrap_or(u.node.clone()), match u.proto { "wg" => "WireGuard", "awg" => "AmneziaWG", "hy2" => "Hysteria2", "mtun" => "microtun", _ => "KANKI MIX" })
    })
}

/// { wg?, awg?, hy2?, kmix? }: new ports for this server's VPN. A port another server (or another
/// protocol here) uses is refused, so a tunnel entry can always carry every server.
async fn set_ports(State(app): St, h: HeaderMap, Path(id): Path<String>, Json(b): Json<Value>) -> Response {
    let _ = guard!(app, h, "nodes");
    let nid = match node_of_key(&app, &id) {
        Ok(n) => n,
        Err(r) => return r,
    };
    let Some(n) = app.db.node(&nid) else { return err(StatusCode::NOT_FOUND, "unknown server") };
    let mut want: Vec<(&'static str, u16)> = vec![];
    for p in ALL_PROTOS {
        if b[p].is_null() {
            continue;
        }
        match num(&b[p]) {
            Some(port) => want.push((p, port)),
            None => return err(StatusCode::BAD_REQUEST, "a port must be 1-65535"),
        }
    }
    for (i, (p, port)) in want.iter().enumerate() {
        if want.iter().skip(i + 1).any(|(_, q)| q == port) {
            return err(StatusCode::BAD_REQUEST, "two protocols cannot share one port");
        }
        if let Some(e) = port_user(&app, &nid, p, *port) {
            return err(StatusCode::CONFLICT, &e);
        }
    }
    let mut body = json!({});
    for (p, port) in want.iter().filter(|(p, _)| *p != "kmix" && *p != "mtun") {
        body[*p] = json!(port);
    }
    let mut errors: Vec<String> = vec![];
    if body.as_object().map(|o| !o.is_empty()).unwrap_or(false) {
        let r = if nid == "local" {
            let b2 = body.clone();
            tokio::task::spawn_blocking(move || crate::admin::set_ports(&b2)).await.ok()
        } else {
            crate::sync::remote_post_json(&app, &n, "/agent/ports", &body).await
        };
        match r {
            Some(v) => errors.extend(v["errors"].as_array().into_iter().flatten().filter_map(|e| e.as_str().map(|s| s.to_string()))),
            None => errors.push("the server did not answer: press Update agent on it, then try again".into()),
        }
    }
    if let Some((_, port)) = want.iter().find(|(p, _)| *p == "mtun") {
        crate::microtun::set_node_port(&app, &nid, *port);
    }
    if let Some((_, port)) = want.iter().find(|(p, _)| *p == "kmix") {
        let old = crate::kmix::settings(&app).node_port(&nid);
        crate::kmix::set_node_port(&app, &nid, *port);
        crate::kmix::move_tunnel_port(&app, &nid, old, *port);
    }
    crate::api::spawn_sync(&app);
    if errors.is_empty() {
        Json(json!({ "ok": true })).into_response()
    } else {
        err(StatusCode::BAD_GATEWAY, &errors.join("; "))
    }
}

/// { on }: KANKI MIX on this server (the rest of its settings stay)
async fn kmix_switch(State(app): St, h: HeaderMap, Path(id): Path<String>, Json(b): Json<Value>) -> Response {
    let _ = guard!(app, h, "nodes");
    let nid = match node_of_key(&app, &id) {
        Ok(n) => n,
        Err(r) => return r,
    };
    crate::kmix::set_node_off(&app, &nid, !b["on"].as_bool().unwrap_or(true));
    crate::api::spawn_sync(&app);
    Json(json!({ "ok": true })).into_response()
}

/// { on: bool } — the VPN of this server serves users, or nobody (it stays installed)
async fn vpn_switch(State(app): St, h: HeaderMap, Path(id): Path<String>, Json(b): Json<Value>) -> Response {
    let _ = guard!(app, h, "nodes");
    let nid = match node_of_key(&app, &id) {
        Ok(n) => n,
        Err(r) => return r,
    };
    let on = b["on"].as_bool().unwrap_or(true);
    if app.db.node(&nid).is_none() {
        return err(StatusCode::NOT_FOUND, "unknown server");
    }
    let _ = app.db.exec("UPDATE nodes SET enabled=?1 WHERE id=?2", &[&(on as i64), &nid]);
    let mut list = tp::servers(&app);
    if let Some(s) = list.iter_mut().find(|s| s.node == nid) {
        s.vpn = on;
        tp::save_servers(&app, &list);
    }
    crate::api::spawn_sync(&app);
    Json(json!({ "ok": true })).into_response()
}

/// Removes the whole server: its agent (tunnels must be deleted first) and its VPN node.
/// Removes the whole server, from the panel and from the server itself. ?tunnels=1: the tunnels that
/// use it go too (without it, a server with tunnels answers 409 with their names, to ask first).
async fn remove(State(app): St, h: HeaderMap, Path(id): Path<String>, Query(q): Query<HashMap<String, String>>) -> Response {
    let _ = guard!(app, h, "nodes");
    if id == "local" {
        return err(StatusCode::BAD_REQUEST, "the panel server cannot be removed");
    }
    if let Some(nid) = id.strip_prefix("node:") {
        let n = crate::api::delete_node(&app, nid);
        crate::twin::forget(&app, &id);
        let name = n.as_ref().map(|n| n.name.clone()).unwrap_or_default();
        let rid = tp::track("node", &name, n.iter().map(|n| tp::node_step(&n.id, &n.name)).collect());
        if let Some(n) = n {
            crate::api::spawn_node_removal(&app, n);
        }
        return Json(json!({ "ok": true, "removal": rid })).into_response();
    }
    let with_tunnels = q.get("tunnels").map(|v| v == "1").unwrap_or(false);
    let used: Vec<Value> = tp::tunnels(&app)
        .into_iter()
        .filter(|t| t.entry == id || t.exit == id)
        .map(|t| json!({ "id": t.id, "name": t.name, "other": if t.entry == id { t.exit } else { t.entry } }))
        .collect();
    if !used.is_empty() && !with_tunnels {
        return (StatusCode::CONFLICT, Json(json!({ "error": "tunnels use this server", "tunnels": used }))).into_response();
    }
    let node = tp::servers(&app).into_iter().find(|s| s.id == id).map(|s| s.node).unwrap_or_default();
    // what each server has to do: this one removes everything and itself, the other ends stop the tunnels
    let mut steps = vec![tp::step(&app, &id, "server", "")];
    let tl: Vec<tp::Tunnel> = tp::tunnels(&app).into_iter().filter(|t| t.entry == id || t.exit == id).collect();
    steps.extend(tp::tunnel_steps(&app, &tl, &id));
    let name = steps[0].name.clone();
    if let Err((code, e)) = tp::delete_server(&app, &id, with_tunnels) {
        return err(code, &e);
    }
    let n = if node.is_empty() { None } else { crate::api::delete_node(&app, &node) };
    if let Some(n) = &n {
        steps.push(tp::node_step(&n.id, &n.name));
    }
    let rid = tp::track("server", &name, steps);
    if let Some(n) = n {
        crate::api::spawn_node_removal(&app, n);
    }
    crate::twin::forget(&app, &id);
    Json(json!({ "ok": true, "removal": rid })).into_response()
}

// ------------------------------------------------------------------ downloads for a new server

fn dl_ok(app: &App, q: &HashMap<String, String>) -> bool {
    let t = q.get("t").map(|s| s.as_str()).unwrap_or("");
    let id = q.get("id").map(|s| s.as_str()).unwrap_or("");
    if t.len() < 20 {
        return false;
    }
    if !id.is_empty() && tp::agent_token_ok(app, id, t) {
        return true;
    }
    if join_server(app, t).is_some() {
        return true;
    }
    let want = app.db.get("join_token");
    let exp: i64 = app.db.get("join_expires").parse().unwrap_or(0);
    !want.is_empty() && exp > now() && crate::util::ct_eq(t, &want)
}

async fn dl_script() -> Response {
    ([(header::CONTENT_TYPE, "text/x-shellscript; charset=utf-8"), (header::CACHE_CONTROL, "no-store")], INSTALL_SH).into_response()
}

fn own_binary() -> Option<Vec<u8>> {
    crate::util::exe_path().ok().and_then(|p| std::fs::read(p).ok())
}

fn sha_hex(b: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b);
    hex::encode(h.finalize())
}

/// The panel's own program for a server being installed (GitHub may be filtered there).
/// ?id=&t=&arch= (the agent token, or a join token)
async fn dl_bin(State(app): St, Query(q): Query<HashMap<String, String>>) -> Response {
    if !dl_ok(&app, &q) {
        return (StatusCode::FORBIDDEN, "not allowed").into_response();
    }
    if q.get("arch").map(|a| a.as_str()) != Some(std::env::consts::ARCH) {
        return (StatusCode::CONFLICT, "another CPU type: download from GitHub").into_response();
    }
    match tokio::task::spawn_blocking(own_binary).await.ok().flatten() {
        Some(b) => ([(header::CONTENT_TYPE, "application/octet-stream")], b).into_response(),
        None => (StatusCode::INTERNAL_SERVER_ERROR, "no binary").into_response(),
    }
}

async fn dl_sum(State(app): St, Query(q): Query<HashMap<String, String>>) -> Response {
    if !dl_ok(&app, &q) {
        return (StatusCode::FORBIDDEN, "not allowed").into_response();
    }
    match tokio::task::spawn_blocking(|| own_binary().map(|b| sha_hex(&b))).await.ok().flatten() {
        Some(s) => format!("{}  kanki-panel\n", s).into_response(),
        None => (StatusCode::INTERNAL_SERVER_ERROR, "no binary").into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u(n: &str, p: &'static str, port: u16) -> Use {
        Use { node: n.into(), proto: p, port }
    }

    #[test]
    fn same_port_on_two_servers_is_a_clash() {
        let uses = vec![u("local", "wg", 51820), u("local", "kmix", 4000), u("a", "wg", 51819), u("a", "kmix", 4000), u("b", "kmix", 4000)];
        let c = clashes(&uses);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].0, 4000);
        assert_eq!(c[0].1.len(), 3);
        // one server using one port twice is not a clash between servers
        assert!(clashes(&[u("a", "wg", 1), u("a", "awg", 1)]).is_empty());
    }

    #[test]
    fn picks_free_ports_per_protocol() {
        let mut t: HashSet<u16> = [51820, 51821, 4000, 8443].into_iter().collect();
        assert_eq!(pick(&mut t, "wg"), 51822);
        assert_eq!(pick(&mut t, "awg"), 51823);
        assert_eq!(pick(&mut t, "hy2"), 8444);
        assert_eq!(pick(&mut t, "kmix"), 4001);
        assert_eq!(pick(&mut t, "kmix"), 4002);
    }

    #[test]
    fn tunnel_ports_follow_a_moved_port() {
        let v = |x: &[&str]| x.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(remap(&v(&["4000"]), 4000, 4001), Some(v(&["4001"])));
        assert_eq!(remap(&v(&["4000:4000", "51820"]), 4000, 4001), Some(v(&["4001:4001", "51820"])));
        // only the target side when the entry listens on another number
        assert_eq!(remap(&v(&["5000:4000"]), 4000, 4001), Some(v(&["5000:4001"])));
        assert_eq!(remap(&v(&["4000,51820"]), 51820, 51830), Some(v(&["4000,51830"])));
        assert_eq!(remap(&v(&["3990-4010"]), 4000, 4001), None);
        assert_eq!(remap(&v(&["4000:5000"]), 4000, 4001), None);
    }

    #[test]
    fn a_new_server_holds_its_kanki_mix_port_before_it_is_installed() {
        let n = crate::db::Node {
            id: "n1".into(), name: "Germany".into(), address: String::new(), endpoint: String::new(), token: String::new(),
            enabled: true, online: true, last_sync: 0, info: r#"{"wg_pub":"k","wg_port":"51824"}"#.into(), note: String::new(),
            insecure: false, drain: false, maint: false, accept_all: true, endpoint_mode: "custom".into(), sync_state: String::new(),
        };
        let mut km = crate::kmix::Settings { on: true, port: 4000, parity: 3, hop: String::new(), gaming: true, nodes: Default::default() };
        // not installed and no port of its own: nothing to hold yet
        assert!(!node_uses(&n, &km, None).iter().any(|u| u.proto == "kmix"));
        // given 4001 when it joined: held from then on, so the next server gets another one
        km.nodes.insert("n1".into(), crate::kmix::NodeOpt { port: 4001, ..Default::default() });
        assert!(node_uses(&n, &km, None).contains(&Use { node: "n1".into(), proto: "kmix", port: 4001 }));
    }

    #[test]
    fn the_installer_is_built_in() {
        assert!(INSTALL_SH.starts_with("#!/usr/bin/env bash"));
        assert!(INSTALL_SH.contains("KANKI_PORTS"));
    }
}
