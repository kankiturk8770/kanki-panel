//! A server's tunnel configs.
//!
//! On the Servers page a server can be marked "has a tunnel", with the Iran address (domain or IP) whose
//! tunnel brings this server's ports there. Users then get, next to the direct configs (the server's own
//! address), a second copy of every config through that address: WireGuard, AmneziaWG, Hysteria2,
//! KANKI MIX and Xray. The copies are the server's second entry in the subscription (`<id>@tunnel`), so
//! every app, old or new, lists them as a server of their own. Plain WireGuard is given only this way:
//! straight to a server abroad it does not pass in Iran.
//!
//! Each port is the one the Iran address really carries to this server: a Kanki tunnel (or a
//! multi-location route) may move it on the way (4002 on Iran → 4001 here). With no Kanki tunnel in the
//! panel for it (a tunnel set up elsewhere) the port is the server's own.
//!
//! Each core (VPN services) can have its own Iran address for its second config, so one server can send
//! WireGuard through Iran-1 and Xray through Iran-2: `cores` (core -> address) wins over the server's
//! address for that core only. KANKI MIX keeps its own setting (KANKI MIX page).
use crate::db::Node;
use crate::App;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};

/// setting: Servers page key ("local", the tunnel server id, or "node:<id>") -> Opt
const KEY: &str = "srv_tunnel";

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(default)]
pub struct Opt {
    pub on: bool,
    /// the Iran address users connect to ("" = the first server of the tunnel that ends here)
    pub host: String,
    /// the name of these configs in the app ("" = "<server name> (تانل)")
    pub name: String,
    /// core (wg, awg, hy2, mtun, xray) -> the Iran address of that core's second config, even when
    /// the server's own tunnel is off
    pub cores: BTreeMap<String, String>,
}

/// The cores that can have their own Iran address
pub const CORES: [&str; 5] = ["wg", "awg", "hy2", "mtun", "xray"];

pub fn all(app: &App) -> HashMap<String, Opt> {
    serde_json::from_str(&app.db.get(KEY)).unwrap_or_default()
}

fn store(app: &App, m: &HashMap<String, Opt>) {
    app.db.set(KEY, &serde_json::to_string(m).unwrap_or_else(|_| "{}".into()));
}

/// { on, host, name } from the Servers page; an address or name that is not plain text is refused
pub fn save(app: &App, key: &str, b: &Value) -> Result<(), String> {
    let host = b["host"].as_str().unwrap_or("").trim().trim_end_matches('.').to_ascii_lowercase();
    if !host.is_empty() && !valid_host(&host) {
        return Err("tunnel address: a domain or IP only (like ir.example.com)".into());
    }
    let name = b["name"].as_str().unwrap_or("").trim().to_string();
    if name.chars().count() > 40 || name.chars().any(|c| c.is_control() || "<>\"".contains(c)) {
        return Err("tunnel name: up to 40 letters, no < > \"".into());
    }
    let m = all(app);
    let cores = m.get(key).map(|o| o.cores.clone()).unwrap_or_default();
    let o = Opt { on: b["on"].as_bool().unwrap_or(false), host, name, cores };
    put(app, m, key, o);
    Ok(())
}

/// { core, host } from a core's page: that core's own Iran address ("" = the server's)
pub fn save_core(app: &App, key: &str, b: &Value) -> Result<(), String> {
    let core = b["core"].as_str().unwrap_or("");
    if !CORES.contains(&core) {
        return Err("unknown core".into());
    }
    let host = b["host"].as_str().unwrap_or("").trim().trim_end_matches('.').to_ascii_lowercase();
    if !host.is_empty() && !valid_host(&host) {
        return Err("tunnel address: a domain or IP only (like ir.example.com)".into());
    }
    let m = all(app);
    let mut o = m.get(key).cloned().unwrap_or_default();
    if host.is_empty() {
        o.cores.remove(core);
    } else {
        o.cores.insert(core.to_string(), host);
    }
    put(app, m, key, o);
    Ok(())
}

fn put(app: &App, mut m: HashMap<String, Opt>, key: &str, o: Opt) {
    if o == Opt::default() {
        m.remove(key);
    } else {
        m.insert(key.to_string(), o);
    }
    store(app, &m);
}

/// A removed server takes its tunnel setting with it
pub fn forget(app: &App, key: &str) {
    let mut m = all(app);
    if m.remove(key).is_some() {
        store(app, &m);
    }
}

fn valid_host(h: &str) -> bool {
    h.len() <= 253 && h.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']'))
}

/// The tunnel server id of a VPN node ("local" for the panel server; "" = it has no agent)
pub fn sid_of_node(app: &App, nid: &str) -> String {
    if nid == "local" {
        return "local".into();
    }
    crate::tunnel::panel::servers(app).into_iter().find(|s| s.node == nid).map(|s| s.id).unwrap_or_default()
}

/// The Servers page key of a VPN node
pub fn key_of_node(app: &App, nid: &str) -> String {
    let sid = sid_of_node(app, nid);
    if sid.is_empty() { format!("node:{}", nid) } else { sid }
}

/// A server's tunnel: where its second configs connect and what they are called
pub struct Twin {
    pub host: String,
    pub name: String,
    /// the tunnel server id ("" = no agent: ports stay the server's own)
    sid: String,
}

impl Twin {
    /// The port on the Iran address that reaches `port` (TCP or UDP) of this server
    pub fn port(&self, app: &App, port: u16, tcp: bool) -> u16 {
        if self.sid.is_empty() {
            return port;
        }
        crate::tunnel::panel::port_entry_at(app, &self.sid, port, tcp, &self.host).map(|x| x.1).unwrap_or(port)
    }

    /// host:port, an IPv6 address in brackets
    pub fn addr(&self, port: u16) -> String {
        if self.host.contains(':') && !self.host.starts_with('[') { format!("[{}]:{}", self.host, port) } else { format!("{}:{}", self.host, port) }
    }
}

/// `core`: a core with its own Iran address uses it (None = the server's tunnel)
fn make(app: &App, key: &str, sid: &str, server_name: &str, core: Option<&str>) -> Option<Twin> {
    let o = all(app).remove(key)?;
    let own = core.and_then(|c| o.cores.get(c)).map(|h| h.trim().to_string()).filter(|h| !h.is_empty());
    let host = match own {
        Some(h) => h,
        None if !o.on => return None,
        None if o.host.trim().is_empty() && !sid.is_empty() => crate::tunnel::panel::entry_host(app, sid),
        None => o.host.trim().to_string(),
    };
    if host.is_empty() {
        return None;
    }
    let name = named(server_name, &o.name);
    Some(Twin { host, name, sid: sid.to_string() })
}

pub fn default_name(server_name: &str) -> String {
    format!("{} (تانل)", server_name)
}

/// The name a second entry shows in the app: the one set, with the server's name in front when it
/// does not say which server it is (four servers all named «تانل» looked the same in the app)
pub fn named(server_name: &str, set: &str) -> String {
    let set = set.trim();
    if set.is_empty() {
        return default_name(server_name);
    }
    let server = server_name.trim();
    if server.is_empty() || set.to_lowercase().contains(&server.to_lowercase()) {
        set.to_string()
    } else {
        format!("{} · {}", server, set)
    }
}

/// The tunnel of a VPN server (None = none)
pub fn of_node(app: &App, n: &Node) -> Option<Twin> {
    make(app, &key_of_node(app, &n.id), &sid_of_node(app, &n.id), &n.name, None)
}

/// The tunnel of one core of a VPN server: its own Iran address, else the server's (None = none)
pub fn of_node_core(app: &App, n: &Node, core: &str) -> Option<Twin> {
    make(app, &key_of_node(app, &n.id), &sid_of_node(app, &n.id), &n.name, Some(core))
}

/// The Xray tunnel of a server by its tunnel server id: Xray's own Iran address, else the server's
pub fn of_server(app: &App, sid: &str) -> Option<Twin> {
    let name = crate::tunnel::panel::server_names(app).get(sid).cloned().unwrap_or_else(|| sid.to_string());
    let name = if sid == "local" { app.db.node("local").map(|n| n.name).unwrap_or(name) } else { name };
    make(app, sid, sid, &name, Some("xray"))
}

/// The name of a server's second entry in the app (its tunnel name, set even when only a core has one)
pub fn name_of_node(app: &App, n: &Node) -> Option<String> {
    let o = all(app).remove(&key_of_node(app, &n.id))?;
    (o.on || !o.cores.is_empty()).then(|| named(&n.name, &o.name))
}

/// For the Servers page: the setting of server `key`, the address its configs would really use and
/// each VPN port with the port it gets on that address
pub fn info(app: &App, key: &str, nid: Option<&str>) -> Value {
    let o = all(app).get(key).cloned().unwrap_or_default();
    let sid = if key.starts_with("node:") { String::new() } else { key.to_string() };
    let auto = if sid.is_empty() { String::new() } else { crate::tunnel::panel::entry_host(app, &sid) };
    let host = if o.host.is_empty() { auto.clone() } else { o.host.clone() };
    // a core's own address, else the server's (None = no second config for that core)
    let core_host = |c: &str| -> Option<String> {
        o.cores.get(c).filter(|h| !h.is_empty()).cloned().or_else(|| (o.on && !host.is_empty()).then(|| host.clone()))
    };
    let mut ports: Vec<Value> = vec![];
    // where the server's own (main) configs point: its own address, or an Iran entry ("tunnel")
    let mut main_via = "direct";
    if let Some(n) = nid.and_then(|id| app.db.node(id)) {
        if crate::direct::through_tunnel(app, &n) {
            main_via = "tunnel";
        }
        let i = crate::api::node_info(&n);
        let num = |k: &str| i[k].as_str().and_then(|s| s.parse::<u16>().ok()).or_else(|| i[k].as_u64().map(|p| p as u16)).filter(|p| *p > 0);
        for (k, p, c) in [("wg_port", "WireGuard", "wg"), ("awg_port", "AmneziaWG", "awg"), ("hy2_port", "Hysteria2", "hy2"), ("kmix_port", "KANKI MIX", ""), ("mt_port", "microtun", "mtun")] {
            let Some(port) = num(k) else { continue };
            let Some(h) = core_host(c) else { continue };
            let tw = Twin { host: h.clone(), name: String::new(), sid: sid.clone() };
            ports.push(json!({ "proto": p, "core": c, "host": h, "port": port, "via": tw.port(app, port, false), "tcp": false }));
        }
    }
    if !sid.is_empty() {
        let x = crate::xray::panel::settings(app);
        let xh = core_host("xray");
        for ib in x.inbounds.iter().filter(|ib| ib.enabled && ib.server == sid && ib.link_host.trim().is_empty() && ib.link_port == 0) {
            let Some(h) = xh.clone() else { break };
            let tcp = ib.network != "kcp";
            let tw = Twin { host: h.clone(), name: String::new(), sid: sid.clone() };
            let name = if ib.remark.is_empty() { format!("Xray {}", ib.protocol) } else { format!("Xray {}", ib.remark) };
            ports.push(json!({ "proto": name, "core": "xray", "host": h, "port": ib.port, "via": tw.port(app, ib.port, tcp), "tcp": tcp }));
        }
    }
    json!({ "on": o.on, "host": o.host, "name": o.name, "auto": auto, "uses": host, "ports": ports, "main_via": main_via, "cores": o.cores })
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_tunnel_name_says_which_server() {
        assert_eq!(super::named("ENGLAND", "تانل"), "ENGLAND · تانل");
        assert_eq!(super::named("Sweden", "Sweden (تانل)"), "Sweden (تانل)");
        assert_eq!(super::named("Sweden", ""), "Sweden (تانل)");
        assert_eq!(super::named("TURKEY", "turkey fast"), "turkey fast");
    }

    use super::*;

    #[test]
    fn addresses_are_checked() {
        assert!(valid_host("ir.example.com"));
        assert!(valid_host("5.5.5.5"));
        assert!(valid_host("[2001:db8::1]"));
        assert!(!valid_host("ir.example.com/x"));
        assert!(!valid_host("a b"));
    }

    #[test]
    fn ipv6_gets_brackets() {
        let t = Twin { host: "2001:db8::1".into(), name: String::new(), sid: String::new() };
        assert_eq!(t.addr(443), "[2001:db8::1]:443");
        let t = Twin { host: "ir.example.com".into(), name: String::new(), sid: String::new() };
        assert_eq!(t.addr(443), "ir.example.com:443");
    }
}
