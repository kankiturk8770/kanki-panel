//! A server's tunnel configs.
//!
//! Users get, next to the direct configs (the server's own address), a second copy of every config through
//! Iran: WireGuard, AmneziaWG, Hysteria2, KANKI MIX and Xray. The copies are the server's second entry in the
//! subscription (`<id>@tunnel`), so every app, old or new, lists them as a server of their own. Plain
//! WireGuard is given only this way: straight to a server abroad it does not pass in Iran.
//!
//! 3.61: nothing is typed any more. The address of each copy is the Iran server of the tunnel that really
//! carries that core's port here (a tunnel, a multi-location route or the forwarded ports of an AmneziaWG
//! link): WireGuard through Iran 2 and KANKI MIX through Iran 3 give Iran 2's and Iran 3's address, and a
//! tunnel moved to another Iran server moves the copy with it at the users' next subscription update. Each
//! port is the one that Iran server really carries to this server (4002 on Iran → 4001 here). A port no
//! tunnel carries gets no copy (it would never connect).
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
    /// (before 3.61: the tunnel switch; not used any more)
    pub on: bool,
    /// (before 3.61: a typed Iran address; not used any more)
    pub host: String,
    /// the name of these configs in the app ("" = "<server name> (تانل)")
    pub name: String,
    /// (before 3.61: a typed Iran address per core; not used any more)
    pub cores: BTreeMap<String, String>,
}

/// The cores that can have their own Iran address
pub const CORES: [&str; 4] = ["wg", "awg", "hy2", "xray"];

pub fn all(app: &App) -> HashMap<String, Opt> {
    serde_json::from_str(&app.db.get(KEY)).unwrap_or_default()
}

/// 3.61: the typed Iran addresses (server, every core, KANKI MIX's own) go once: the tunnels give them now
pub fn drop_retired(app: &App) {
    if app.db.get("twin_auto_v1") == "1" {
        return;
    }
    let mut m = all(app);
    for o in m.values_mut() {
        o.on = false;
        o.host.clear();
        o.cores.clear();
    }
    m.retain(|_, o| *o != Opt::default());
    store(app, &m);
    crate::kmix::forget_tunnel_hosts(app);
    app.db.set("twin_auto_v1", "1");
}

fn store(app: &App, m: &HashMap<String, Opt>) {
    app.db.set(KEY, &serde_json::to_string(m).unwrap_or_else(|_| "{}".into()));
}

/// { name } from the Servers page: the name of the tunnel configs in the app (the address comes from the tunnels)
pub fn save(app: &App, key: &str, b: &Value) -> Result<(), String> {
    let name = b["name"].as_str().unwrap_or("").trim().to_string();
    if name.chars().count() > 40 || name.chars().any(|c| c.is_control() || "<>\"".contains(c)) {
        return Err("tunnel name: up to 40 letters, no < > \"".into());
    }
    let m = all(app);
    let o = Opt { name, ..Default::default() };
    put(app, m, key, o);
    Ok(())
}

/// { core, host } from an older page: a core no longer has an address of its own (3.61), so nothing is kept
pub fn save_core(_app: &App, _key: &str, b: &Value) -> Result<(), String> {
    let core = b["core"].as_str().unwrap_or("");
    if !CORES.contains(&core) {
        return Err("unknown core".into());
    }
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

/// A domain or IP: ':' only inside a real IPv6 address (bare or in [ ]), so "host:port" is refused
pub fn valid_host(h: &str) -> bool {
    if h.contains(':') || h.contains('[') || h.contains(']') {
        let ip = h.strip_prefix('[').and_then(|x| x.strip_suffix(']')).unwrap_or(h);
        return ip.parse::<std::net::Ipv6Addr>().is_ok();
    }
    !h.is_empty() && h.len() <= 253 && h.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'))
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

/// A server's tunnel: where its second configs connect
pub struct Twin {
    pub host: String,
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

    /// The port on the Iran address for `port`, only when the tunnel really brings it here. None = this
    /// server has Kanki tunnels but none carries `port`: a second config on it would never connect (the
    /// app showed ✕), so it is not given at all. A server with no Kanki port tunnel (one set up
    /// elsewhere, or a layer-3 AmneziaWG one) keeps the port as it is.
    pub fn carried(&self, app: &App, port: u16, tcp: bool) -> Option<u16> {
        if self.sid.is_empty() {
            return Some(port);
        }
        match crate::tunnel::panel::port_entry_at(app, &self.sid, port, tcp, &self.host) {
            Some(x) => Some(x.1),
            None if crate::tunnel::panel::has_port_tunnels(app, &self.sid) => None,
            None => Some(port),
        }
    }

    /// host:port, an IPv6 address in brackets
    pub fn addr(&self, port: u16) -> String {
        if self.host.contains(':') && !self.host.starts_with('[') { format!("[{}]:{}", self.host, port) } else { format!("{}:{}", self.host, port) }
    }
}

/// The tunnel of server `sid` for `port` (TCP or UDP; None = any port): the Iran server whose tunnel really
/// carries it here. None = the server has no panel agent, or no tunnel ends here.
fn make(app: &App, sid: &str, port: Option<u16>, tcp: Option<bool>) -> Option<Twin> {
    if sid.is_empty() {
        return None;
    }
    let host = auto_host(app, sid, port, tcp);
    if host.is_empty() {
        return None;
    }
    Some(Twin { host, sid: sid.to_string() })
}

/// The Iran address of a server's second configs: the first server of the tunnel that brings `port` here (the
/// asked protocol, else UDP then TCP), else the first server of any tunnel that ends here
pub fn auto_host(app: &App, sid: &str, port: Option<u16>, tcp: Option<bool>) -> String {
    if let Some(p) = port {
        let order: Vec<bool> = match tcp {
            Some(t) => vec![t, !t],
            None => vec![false, true],
        };
        for tcp in order {
            if let Some((entry, _)) = crate::tunnel::panel::port_entry(app, sid, p, tcp) {
                let h = crate::tunnel::panel::host_of(app, &entry);
                if !h.is_empty() {
                    return h;
                }
            }
        }
    }
    crate::tunnel::panel::entry_host(app, sid)
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


/// The tunnel of one core of a VPN server: the Iran server that carries its port. None = none, or no tunnel
/// carries this core's port (no second config that would lead nowhere).
pub fn of_node_core(app: &App, n: &Node, core: &str) -> Option<Twin> {
    let port = core_port(n, core);
    let t = make(app, &sid_of_node(app, &n.id), port, Some(false))?;
    match port {
        Some(p) => t.carried(app, p, false).map(|_| t),
        None => Some(t),
    }
}

/// The tunnel of a VPN server for a port of its own (KANKI MIX): the Iran server that carries it, found by itself
pub fn of_node_port(app: &App, n: &Node, port: u16) -> Option<Twin> {
    make(app, &sid_of_node(app, &n.id), Some(port), Some(false))
}

/// The UDP port of a core on a VPN server (None = not known yet)
pub fn core_port(n: &Node, core: &str) -> Option<u16> {
    let k = match core {
        "wg" => "wg_port",
        "awg" => "awg_port",
        "hy2" => "hy2_port",
        "kmix" => "kmix_port",
        _ => return None,
    };
    let i = crate::api::node_info(n);
    i[k].as_str().and_then(|s| s.trim().parse::<u16>().ok()).or_else(|| i[k].as_u64().map(|p| p as u16)).filter(|p| *p > 0)
}

/// The tunnel of an Xray inbound by its server's tunnel server id: the Iran server that carries its port
pub fn of_server(app: &App, sid: &str, port: u16, tcp: bool) -> Option<Twin> {
    make(app, sid, Some(port), Some(tcp))
}

/// The name of a server's second entry in the app: the one set on the Servers page, else «<server> (تانل)».
/// None = no tunnel ends at this server.
pub fn name_of_node(app: &App, n: &Node) -> Option<String> {
    let sid = sid_of_node(app, &n.id);
    if sid.is_empty() || crate::tunnel::panel::entry_host(app, &sid).is_empty() {
        return None;
    }
    let set = all(app).remove(&key_of_node(app, &n.id)).map(|o| o.name).unwrap_or_default();
    Some(named(&n.name, &set))
}

/// For the Servers page: the name set for server `key`, and each VPN port with the Iran server that carries it
/// (found from the tunnels) and the port it gets there
pub fn info(app: &App, key: &str, nid: Option<&str>) -> Value {
    let o = all(app).get(key).cloned().unwrap_or_default();
    let sid = if key.starts_with("node:") { String::new() } else { key.to_string() };
    let auto = if sid.is_empty() { String::new() } else { crate::tunnel::panel::entry_host(app, &sid) };
    let mut ports: Vec<Value> = vec![];
    // where the server's own (main) configs point: its own address, or an Iran entry ("tunnel")
    let mut main_via = "direct";
    let row = |proto: String, core: &str, port: u16, tcp: bool| -> Option<Value> {
        let tw = make(app, &sid, Some(port), Some(tcp))?;
        let via = tw.carried(app, port, tcp);
        Some(json!({ "proto": proto, "core": core, "host": tw.host, "port": port, "via": via.unwrap_or(port), "tcp": tcp, "carried": via.is_some(), "auto": true }))
    };
    if let Some(n) = nid.and_then(|id| app.db.node(id)) {
        if crate::direct::through_tunnel(app, &n) {
            main_via = "tunnel";
        }
        let i = crate::api::node_info(&n);
        let num = |k: &str| i[k].as_str().and_then(|s| s.parse::<u16>().ok()).or_else(|| i[k].as_u64().map(|p| p as u16)).filter(|p| *p > 0);
        for (k, p, c) in [("wg_port", "WireGuard", "wg"), ("awg_port", "AmneziaWG", "awg"), ("hy2_port", "Hysteria2", "hy2")] {
            if let Some(port) = num(k) {
                ports.extend(row(p.to_string(), c, port, false));
            }
        }
        // KANKI MIX: the address its config really uses
        if let Some(port) = num("kmix_port") {
            let km = crate::kmix::settings(app);
            if let Some((h, via)) = crate::kmix::tunnel_target(app, &km, &n, port) {
                ports.push(json!({ "proto": "KANKI MIX", "core": "kmix", "host": h, "port": port, "via": via, "tcp": false, "carried": true, "auto": true }));
            }
        }
    }
    if !sid.is_empty() {
        let x = crate::xray::panel::settings(app);
        for ib in x.inbounds.iter().filter(|ib| ib.enabled && ib.server == sid && ib.link_host.trim().is_empty() && ib.link_port == 0) {
            let name = if ib.remark.is_empty() { format!("Xray {}", ib.protocol) } else { format!("Xray {}", ib.remark) };
            ports.extend(row(name, "xray", ib.port, ib.network != "kcp"));
        }
    }
    json!({ "on": !auto.is_empty(), "host": "", "name": o.name, "auto": auto, "uses": auto, "ports": ports, "main_via": main_via, "cores": {} })
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
        assert!(valid_host("2001:db8::1"));
        assert!(!valid_host("ir.example.com:8443"));
        assert!(!valid_host("5.5.5.5:443"));
        assert!(!valid_host("[ir.example.com]"));
    }

    /// 3.61: every core's second config takes the Iran server of the tunnel that carries its own port (Kanki,
    /// KANKI-UP or the forwarded ports of an AmneziaWG link), never a typed address, and follows a moved tunnel
    #[test]
    fn each_core_follows_the_tunnel_of_its_port() {
        let app = crate::test_app();
        let info = json!({ "wg_port": "51820", "awg_port": "51821", "hy2_port": "8443", "kmix_port": "4000" });
        app.db.exec("INSERT INTO nodes(id,name,address,endpoint,token,info) VALUES('tr','Turkey','tr.example.com','tr.example.com','t',?1)", &[&info.to_string()]).unwrap();
        let n = app.db.node("tr").unwrap();
        let srv = json!([{ "id": "ir2", "name": "Iran 2", "token": "x", "addr": "ir2.example.com" }, { "id": "ir3", "name": "Iran 3", "token": "y", "addr": "ir3.example.com" },
            { "id": "ir4", "name": "Iran 4", "token": "z", "addr": "ir4.example.com" }, { "id": "s-tr", "name": "Turkey", "token": "w", "node": "tr" }]);
        app.db.set("tun_servers", &srv.to_string());
        // WireGuard and AmneziaWG through Iran 2; Hysteria2 and KANKI MIX through Iran 3 (KANKI-UP, 4001 on Iran)
        let list = json!([
            { "id": "a", "name": "a", "entry": "ir2", "exit": "s-tr", "transport": "game", "enabled": true, "udp": ["51820", "51821"] },
            { "id": "b", "name": "b", "entry": "ir3", "exit": "s-tr", "kind": "kup", "transport": "kup", "mode": "direct", "port": 29000, "enabled": true, "udp": ["8443", "4001:4000"] },
        ]);
        app.db.set("tun_list", &list.to_string());
        // an address typed before 3.61 changes nothing
        app.db.set("srv_tunnel", &json!({ "s-tr": { "on": true, "host": "old.example.com", "cores": { "wg": "old.example.com" } } }).to_string());
        let host = |c: &str| of_node_core(&app, &n, c).map(|t| t.host);
        assert_eq!(host("wg").as_deref(), Some("ir2.example.com"));
        assert_eq!(host("awg").as_deref(), Some("ir2.example.com"));
        assert_eq!(host("hy2").as_deref(), Some("ir3.example.com"));
        let km = crate::kmix::settings(&app);
        assert_eq!(crate::kmix::tunnel_target(&app, &km, &n, 4000), Some(("ir3.example.com".to_string(), 4001)));
        // the KANKI MIX tunnel moved to Iran 4, as an AmneziaWG link forwarding the port: the address follows
        let list = json!([
            { "id": "a", "name": "a", "entry": "ir2", "exit": "s-tr", "transport": "game", "enabled": true, "udp": ["51820", "51821"] },
            { "id": "c", "name": "c", "entry": "ir4", "exit": "s-tr", "kind": "awg", "enabled": true, "awg": { "n": 2, "port": 51900, "fwd_udp": ["4000"] } },
        ]);
        app.db.set("tun_list", &list.to_string());
        assert_eq!(crate::kmix::tunnel_target(&app, &km, &n, 4000), Some(("ir4.example.com".to_string(), 4000)));
        // Hysteria2's port is carried by no tunnel now: no second config that would never connect
        assert!(host("hy2").is_none());
        assert_eq!(host("wg").as_deref(), Some("ir2.example.com"));
        // the Servers page shows the same, and names the copies
        let v = super::info(&app, "s-tr", Some("tr"));
        let ports = v["ports"].as_array().unwrap();
        assert!(ports.iter().any(|p| p["core"] == "wg" && p["host"] == "ir2.example.com"));
        assert!(ports.iter().any(|p| p["core"] == "kmix" && p["host"] == "ir4.example.com"));
        assert_eq!(name_of_node(&app, &n).as_deref(), Some("Turkey (تانل)"));
    }

    #[test]
    fn ipv6_gets_brackets() {
        let t = Twin { host: "2001:db8::1".into(), sid: String::new() };
        assert_eq!(t.addr(443), "[2001:db8::1]:443");
        let t = Twin { host: "ir.example.com".into(), sid: String::new() };
        assert_eq!(t.addr(443), "ir.example.com:443");
    }
}
