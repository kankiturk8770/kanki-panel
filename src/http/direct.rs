//! Direct addresses of the VPN servers, for the app's "Amnezia Direct" configs.
//!
//! A server behind the Iran tunnel gives configs whose endpoint is the Iran server. The app also offers
//! the same AmneziaWG config straight to the server ("direct"), for when the tunnel is down. Its address
//! is `<code>.<base>`, like `fr.kankipro.cafe`: the admin points that name at the server, so the server
//! can change its IP without a new app. Germany keeps `g` (the app used it first); a second server in the
//! same country gets a number (`fr2`). A name, once given to a server, stays with it.
//!
//! The panel resolves every name and only hands it to the app when it really points at that server.
//! Until then (or when the country is not known yet) the server's own address goes out, so a direct
//! config never reaches the wrong server. The Servers page shows each name, the IP it must point at and
//! whether it does.
use crate::db::Node;
use crate::App;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

/// setting: the domain the names live under ("" = the panel domain without its first label)
pub const BASE_KEY: &str = "direct_base";
/// setting: node id -> label ("fr", "fr2", "g"), kept so a server's name never moves
const NAMES_KEY: &str = "direct_names";

/// A removed server's direct name is freed (another server may take it)
pub fn forget(app: &App, node_id: &str) {
    let mut m: HashMap<String, String> = serde_json::from_str(&app.db.get(NAMES_KEY)).unwrap_or_default();
    if m.remove(node_id).is_some() {
        app.db.set(NAMES_KEY, &serde_json::to_string(&m).unwrap_or_else(|_| "{}".into()));
    }
}

/// The domain under which the direct names live
pub fn base(app: &App) -> String {
    let b = app.db.get(BASE_KEY).trim().trim_matches('.').to_ascii_lowercase();
    if !b.is_empty() {
        return b;
    }
    let d = app.env.get("DOMAIN").cloned().unwrap_or_default().trim().trim_matches('.').to_ascii_lowercase();
    let labels: Vec<&str> = d.split('.').filter(|l| !l.is_empty()).collect();
    if labels.len() >= 3 && d.parse::<IpAddr>().is_err() {
        labels[1..].join(".")
    } else {
        d
    }
}

/// The label of a country code: lower case, Germany "g" as in the first apps
pub fn code(cc: &str) -> String {
    match cc.trim().to_ascii_uppercase().as_str() {
        "" => String::new(),
        "DE" => "g".into(),
        c => c.to_ascii_lowercase(),
    }
}

/// The servers that serve users (the panel server first), with their exit IP and country
fn servers(app: &App) -> Vec<(Node, String, String)> {
    app.db
        .nodes()
        .into_iter()
        .map(|n| {
            let f = crate::exitgeo::fields(app, &n.id);
            let ip = f["exit_ip"].as_str().unwrap_or("").to_string();
            let cc = f["exit_cc"].as_str().unwrap_or("").to_uppercase();
            (n, ip, cc)
        })
        .collect()
}

/// node id -> label, giving a label to every server whose country is known (and a new one when a
/// server moved to another country). Saved only when something changed.
fn labels(app: &App) -> HashMap<String, String> {
    let mut m: HashMap<String, String> = serde_json::from_str(&app.db.get(NAMES_KEY)).unwrap_or_default();
    let list = servers(app);
    let mut changed = false;
    let ids: std::collections::HashSet<&str> = list.iter().map(|(n, _, _)| n.id.as_str()).collect();
    let before = m.len();
    m.retain(|id, _| ids.contains(id.as_str()));
    changed |= m.len() != before;
    for (n, _, cc) in &list {
        let c = code(cc);
        if c.is_empty() {
            continue;
        }
        let fits = m.get(&n.id).map(|l| l.trim_end_matches(|ch: char| ch.is_ascii_digit()) == c).unwrap_or(false);
        if fits {
            continue;
        }
        let mut k = 1;
        let label = loop {
            let l = if k == 1 { c.clone() } else { format!("{}{}", c, k) };
            if !m.values().any(|v| *v == l) {
                break l;
            }
            k += 1;
        };
        m.insert(n.id.clone(), label);
        changed = true;
    }
    if changed {
        app.db.set(NAMES_KEY, &serde_json::to_string(&m).unwrap_or_else(|_| "{}".into()));
    }
    m
}

/// name -> (its addresses, when looked up)
type Lookups = HashMap<String, (Vec<String>, i64)>;

/// filled by `run`, read without waiting
fn resolved() -> &'static Mutex<Lookups> {
    static R: OnceLock<Mutex<Lookups>> = OnceLock::new();
    R.get_or_init(|| Mutex::new(HashMap::new()))
}

fn addrs_of(host: &str) -> Option<Vec<String>> {
    if host.parse::<IpAddr>().is_ok() {
        return Some(vec![host.to_string()]);
    }
    resolved().lock().unwrap().get(host).map(|x| x.0.clone())
}

/// The server's own public address: the panel domain for the panel server, the agent address for others
fn own_host(app: &App, n: &Node) -> String {
    if n.id == "local" {
        return app.env.get("DOMAIN").cloned().unwrap_or_default().trim().to_ascii_lowercase();
    }
    crate::exitgeo::host_of_url(&n.address).to_ascii_lowercase()
}

/// One server's direct name: (planned name, the IP it must point at, whether it does now)
pub fn plan_of(app: &App, labels: &HashMap<String, String>, n: &Node, ip: &str) -> (String, String, bool) {
    let b = base(app);
    let Some(l) = labels.get(&n.id) else { return (String::new(), ip.to_string(), false) };
    if b.is_empty() {
        return (String::new(), ip.to_string(), false);
    }
    let host = format!("{}.{}", l, b);
    let ok = !ip.is_empty() && addrs_of(&host).map(|a| a.iter().any(|x| x == ip)).unwrap_or(false);
    (host, ip.to_string(), ok)
}

/// What the app gets for a server's AmneziaWG: (how its endpoint reaches the server: "tunnel" | "direct",
/// the direct address for a second config: the planned name when it points at the server, else the
/// server's own address; "" = none)
pub fn awg(app: &App, n: &Node) -> (&'static str, String) {
    let ip = crate::exitgeo::fields(app, &n.id)["exit_ip"].as_str().unwrap_or("").to_string();
    let (planned, _, ok) = plan_of(app, &labels_ro(app), n, &ip);
    let own = own_host(app, n);
    let direct = if ok { planned } else if !own.is_empty() { own.clone() } else { ip.clone() };
    let ep = crate::api::endpoint(app, n).trim().to_ascii_lowercase();
    // the endpoint is the server itself (its name, its own address, or a name that points at it)
    let same = !ep.is_empty()
        && (ep == direct || ep == own || ep == ip || (!ip.is_empty() && addrs_of(&ep).map(|a| a.contains(&ip)).unwrap_or(false)));
    if same {
        ("direct", String::new())
    } else {
        ("tunnel", direct)
    }
}

/// The saved labels, without assigning new ones (a subscription page must not write settings)
fn labels_ro(app: &App) -> HashMap<String, String> {
    serde_json::from_str(&app.db.get(NAMES_KEY)).unwrap_or_default()
}

/// For the Servers page: every server's direct name, the IP it must point at, and whether it does
pub fn table(app: &App) -> Value {
    let l = labels(app);
    let rows: Vec<Value> = servers(app)
        .iter()
        .map(|(n, ip, cc)| {
            let (host, ip, ok) = plan_of(app, &l, n, ip);
            let now = if host.is_empty() { vec![] } else { addrs_of(&host).unwrap_or_default() };
            let (via, _) = awg(app, n);
            json!({ "node": n.id, "name": n.name, "cc": cc, "host": host, "ip": ip, "ok": ok, "points_to": now, "via": via })
        })
        .collect();
    json!({ "base": base(app), "servers": rows })
}

/// Gives labels to new servers and looks every name (and every endpoint) up again every 5 minutes
pub async fn run(app: Arc<App>) {
    tokio::time::sleep(Duration::from_secs(15)).await;
    loop {
        let l = labels(&app);
        let b = base(&app);
        let mut hosts: Vec<String> = vec![];
        if !b.is_empty() {
            hosts.extend(l.values().map(|v| format!("{}.{}", v, b)));
        }
        for n in app.db.nodes() {
            hosts.push(crate::api::endpoint(&app, &n).trim().to_ascii_lowercase());
        }
        hosts.retain(|h| !h.is_empty() && h.parse::<IpAddr>().is_err());
        hosts.sort();
        hosts.dedup();
        for h in hosts {
            let ips: Vec<String> = match tokio::time::timeout(Duration::from_secs(5), tokio::net::lookup_host((h.as_str(), 443))).await {
                Ok(Ok(it)) => it.map(|a| a.ip().to_string()).collect(),
                _ => vec![],
            };
            resolved().lock().unwrap().insert(h, (ips, crate::util::now()));
        }
        tokio::time::sleep(Duration::from_secs(300)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicI64;

    fn app() -> Arc<App> {
        let dir = std::env::temp_dir().join(format!("kanki-direct-test-{}", crate::util::rand_token(8)));
        std::fs::create_dir_all(&dir).unwrap();
        let db = crate::db::Db::open(dir.join("kanki.db").to_str().unwrap());
        Arc::new(App {
            db,
            env: HashMap::from([("DOMAIN".to_string(), "fi.example.com".to_string())]),
            hy2_allowed: Mutex::new(HashMap::new()), limits: Mutex::new(HashMap::new()), reported: Mutex::new(HashMap::new()),
            login_fails: Mutex::new(HashMap::new()), sync_lock: tokio::sync::Mutex::new(()), bot_alive: AtomicI64::new(0),
            http: reqwest::Client::new(), http_insecure: reqwest::Client::new(), pin_clients: Mutex::new(HashMap::new()),
        })
    }

    /// a node behind the Iran tunnel (endpoint = the Iran name) or straight (endpoint = its own address)
    fn node(app: &App, id: &str, addr: &str, endpoint: &str, ip: &str, cc: &str) {
        let mode = if endpoint.is_empty() { "panel" } else { "custom" };
        app.db.exec("INSERT INTO nodes(id,name,address,endpoint,token,online,endpoint_mode) VALUES(?1,?1,?2,?3,'t',1,?4)", &[&id, &addr, &endpoint, &mode]).unwrap();
        let mut c: serde_json::Map<String, Value> = serde_json::from_str(&app.db.get("exit_geo")).unwrap_or_default();
        c.insert(id.to_string(), json!({ "ip": ip, "cc": cc, "city": "", "ts": crate::util::now() }));
        app.db.set("exit_geo", &Value::Object(c).to_string());
    }

    #[test]
    fn names_and_routes() {
        let a = app();
        a.db.exec("INSERT INTO nodes(id,name,address,endpoint,token,online) VALUES('local','Main','','','',1)", &[]).unwrap();
        a.db.set("exit_geo", &json!({ "local": { "ip": "9.9.9.1", "cc": "FI" } }).to_string());
        node(&a, "n-fr1", "https://5.5.5.1:2096", "ir.example.com", "5.5.5.1", "FR");
        node(&a, "n-fr2", "https://5.5.5.2:2096", "ir.example.com", "5.5.5.2", "FR");
        node(&a, "n-de", "https://de-own.example.com:2096", "de-own.example.com", "6.6.6.6", "DE");
        assert_eq!(base(&a), "example.com");
        let t = table(&a);
        let host = |id: &str| t["servers"].as_array().unwrap().iter().find(|r| r["node"] == id).unwrap()["host"].as_str().unwrap().to_string();
        assert_eq!(host("local"), "fi.example.com");
        assert_eq!(host("n-de"), "g.example.com");
        let mut fr = vec![host("n-fr1"), host("n-fr2")];
        fr.sort();
        assert_eq!(fr, vec!["fr.example.com", "fr2.example.com"]);
        // a name never moves: asked again, the same
        assert_eq!(host("n-fr1"), host("n-fr1"));

        // nothing resolved yet: the direct config of a tunnelled server goes to the server's own address
        let n1 = a.db.node("n-fr1").unwrap();
        assert_eq!(awg(&a, &n1), ("tunnel", "5.5.5.1".to_string()));
        // its name points at the right server: that name
        let fr1 = host("n-fr1");
        resolved().lock().unwrap().insert(fr1.clone(), (vec!["5.5.5.1".into()], 0));
        assert_eq!(awg(&a, &n1), ("tunnel", fr1.clone()));
        // a name that points at another server is never given
        let n2 = a.db.node("n-fr2").unwrap();
        resolved().lock().unwrap().insert(host("n-fr2"), (vec!["5.5.5.1".into()], 0));
        assert_eq!(awg(&a, &n2), ("tunnel", "5.5.5.2".to_string()));
        // a server whose endpoint is the server itself has no second, direct config
        let de = a.db.node("n-de").unwrap();
        assert_eq!(awg(&a, &de).0, "direct");
        // the panel server, endpoint = its own domain
        let local = a.db.node("local").unwrap();
        assert_eq!(awg(&a, &local).0, "direct");
    }

    #[test]
    fn country_labels() {
        assert_eq!(code("FR"), "fr");
        assert_eq!(code("de"), "g");
        assert_eq!(code("GB"), "gb");
        assert_eq!(code(""), "");
    }
}
