//! Who is connected right now, and with what: (protocol, server) per user.
//! VPN servers report it on every sync round (WireGuard / AmneziaWG handshakes, Hysteria2 and
//! KANKI MIX sessions), Xray servers say whose traffic moved, Kanki DNS servers send the queries.
//! Kept in memory only; a panel restart starts empty and fills again within a sync round.
use crate::util::now;
use crate::App;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

/// A VPN server's last report: (time, server name, [(user id, protocol)])
type VpnSeen = (i64, String, Vec<(i64, String)>);

fn vpn() -> &'static Mutex<HashMap<String, VpnSeen>> {
    static S: OnceLock<Mutex<HashMap<String, VpnSeen>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(HashMap::new()))
}

/// How long a report counts. Sync rounds run every few seconds to a minute, so a server that stops
/// answering drops out of "connected now" after this.
const VPN_FRESH: i64 = 300;
const XRAY_FRESH: i64 = 90;
const DNS_FRESH: i64 = 180;

/// A VPN server's connections from this sync round (replaces its previous list).
pub fn set_vpn(node_id: &str, node_name: &str, conns: Vec<(i64, String)>) {
    vpn().lock().unwrap().insert(node_id.to_string(), (now(), node_name.to_string(), conns));
}

/// A removed server must not keep showing users as connected.
pub fn forget(node_id: &str) {
    vpn().lock().unwrap().remove(node_id);
}

/// user id -> [(protocol, server)]
/// (protocol, server name, exit country code, through a tunnel)
type Conn = (String, String, String, bool);
type UserServers = HashMap<i64, Vec<Conn>>;

/// user id -> [(protocol, server)], built at most every few seconds
fn cache() -> &'static Mutex<(i64, UserServers)> {
    static S: OnceLock<Mutex<(i64, UserServers)>> = OnceLock::new();
    S.get_or_init(|| Mutex::new((0, HashMap::new())))
}

fn build(app: &App) -> UserServers {
    let t = now();
    let mut m: UserServers = HashMap::new();
    let mut add = |uid: i64, p: &str, s: &str, cc: &str, tun: bool| {
        let v = m.entry(uid).or_default();
        if !v.iter().any(|(a, b, _, _)| a == p && b == s) {
            v.push((p.to_string(), s.to_string(), cc.to_string(), tun));
        }
    };
    let kmix = crate::kmix::settings(app);
    for (nid, (at, name, conns)) in vpn().lock().unwrap().iter() {
        if t - at <= VPN_FRESH {
            // the real exit of the server, and whether its configs of a protocol go through an Iran
            // tunnel (from how the server is set up: the panel does not see which address a phone used)
            let cc = crate::exitgeo::fields(app, nid)["exit_cc"].as_str().unwrap_or("").to_string();
            let node = app.db.node(nid);
            for (uid, p) in conns {
                let tun = node.as_ref().map(|n| match p.as_str() {
                    "kmix" => kmix.node_tunnel(&n.id),
                    "kgame" | "mtun" => false,
                    _ => crate::direct::through_tunnel(app, n),
                }).unwrap_or(false);
                add(*uid, p, name, &cc, tun);
            }
        }
    }
    let names = crate::tunnel::panel::server_names(app);
    let name_of = |sid: &str| -> String {
        if sid == "local" {
            // the same name the Xray page shows for the panel server
            app.env.get("LOCAL_NAME").cloned().filter(|x| !x.is_empty()).unwrap_or_else(|| "Main".into())
        } else {
            names.get(sid).cloned().unwrap_or_else(|| sid.to_string())
        }
    };
    for (uid, sid) in crate::xray::panel::online_now(XRAY_FRESH) {
        add(uid, "xray", &name_of(&sid), "", false);
    }
    for (uid, sid) in crate::dns::panel::active_users(DNS_FRESH) {
        add(uid, "dns", &name_of(&sid), "", false);
    }
    for v in m.values_mut() {
        v.sort();
    }
    m
}

/// The connections of one user right now: [{ "p": protocol, "s": server }]
pub fn of(app: &App, uid: i64) -> Value {
    let t = now();
    let mut c = cache().lock().unwrap();
    if t - c.0 >= 3 {
        *c = (t, build(app));
    }
    json!(c.1.get(&uid).map(|v| v.iter().map(|(p, s, cc, tun)| json!({ "p": p, "s": s, "cc": cc, "t": tun })).collect::<Vec<_>>()).unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_server_report_replaces_the_previous_one() {
        set_vpn("live-test-node", "Germany", vec![(1, "kmix".into()), (2, "wg".into())]);
        set_vpn("live-test-node", "Germany", vec![(2, "awg".into())]);
        let g = vpn().lock().unwrap();
        let (_, name, conns) = g.get("live-test-node").unwrap();
        assert_eq!(name, "Germany");
        assert_eq!(conns, &vec![(2, "awg".to_string())]);
    }

    #[test]
    fn a_removed_server_is_forgotten() {
        set_vpn("live-test-gone", "Finland", vec![(5, "hy2".into())]);
        forget("live-test-gone");
        assert!(vpn().lock().unwrap().get("live-test-gone").is_none());
    }
}
