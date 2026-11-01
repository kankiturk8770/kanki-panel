//! A restore file (.backup) for the AmneziaVPN app (iPhone, Android, Windows) with every WireGuard /
//! AmneziaWG config of a user, so the whole account goes in with one «Restore from backup».
//!
//! The file is the app's own backup format (amnezia-client: secureQSettings.cpp backupAppConfig,
//! core/controllers/settingsController.cpp): a plain JSON object of the app's "Conf/..." and "Servers/..."
//! settings. "Servers/serversList" is a JSON array kept as a string. Each server is what the app makes
//! itself when it imports a .conf file (core/controllers/selfhosted/importController.cpp,
//! extractWireGuardConfig): a config with any AmneziaWG key goes in the "amnezia-awg" container, a plain
//! one in "amnezia-wireguard", and "last_config" is a JSON object kept as a string.

use serde_json::{json, Map, Value};

/// The platforms a backup is made for: (code in buttons and URLs, AppPlatform value, name to show)
pub const PLATFORMS: [(&str, &str, &str); 3] = [("i", "iOS", "iPhone"), ("a", "Android", "Android"), ("w", "Windows", "Windows")];

/// AppPlatform of a platform code ("i", "a", "w") or name (any case); None for anything else
pub fn platform(code: &str) -> Option<&'static str> {
    let c = code.trim().to_lowercase();
    PLATFORMS.iter().find(|p| p.0 == c || p.1.to_lowercase() == c || p.2.to_lowercase() == c).map(|p| p.1)
}

/// The flag of a country code ("TR" -> 🇹🇷); empty for anything that is not two letters
pub fn flag(cc: &str) -> String {
    let c = cc.trim().to_ascii_uppercase();
    if c.len() != 2 || !c.chars().all(|x| x.is_ascii_uppercase()) {
        return String::new();
    }
    c.chars().filter_map(|x| char::from_u32(0x1F1E6 + (x as u32 - 'A' as u32))).collect()
}

/// The AmneziaWG keys the panel writes (the app copies every one it finds into last_config)
const AWG_KEYS: [&str; 16] = ["Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4", "I1", "I2", "I3", "I4", "I5"];

/// key = value lines of a .conf (sections are skipped, as the app does)
fn conf_map(text: &str) -> Map<String, Value> {
    let mut m = Map::new();
    for line in text.lines() {
        let l = line.trim();
        if l.starts_with('[') && l.ends_with(']') {
            continue;
        }
        if let Some(i) = l.find('=').filter(|i| *i > 0) {
            m.insert(l[..i].trim().to_string(), json!(l[i + 1..].trim()));
        }
    }
    m
}

fn s<'a>(m: &'a Map<String, Value>, k: &str) -> &'a str {
    m.get(k).and_then(|v| v.as_str()).unwrap_or("")
}

/// A random UUID (v4), the id the app keeps each server under
fn uuid4() -> String {
    let mut b: [u8; 16] = rand::random();
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h: String = b.iter().map(|x| format!("{:02x}", x)).collect();
    format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32])
}

/// One server of the app from one WireGuard / AmneziaWG .conf; None when the config lacks a key part.
pub fn server(conf: &str, description: &str) -> Option<Value> {
    let m = conf_map(conf);
    let (priv_key, addr, pub_key) = (s(&m, "PrivateKey"), s(&m, "Address"), s(&m, "PublicKey"));
    if priv_key.is_empty() || addr.is_empty() || pub_key.is_empty() {
        return None;
    }
    // Endpoint = host:port, or [v6]:port
    let ep = s(&m, "Endpoint");
    let (host, port) = match ep.rsplit_once(':') {
        Some((h, p)) if p.parse::<u16>().is_ok() => (h.trim_start_matches('[').trim_end_matches(']').to_string(), p.to_string()),
        _ => (ep.to_string(), "51820".to_string()),
    };
    if host.is_empty() {
        return None;
    }
    let awg = AWG_KEYS.iter().any(|k| !s(&m, k).is_empty());
    let (proto, container) = if awg { ("awg", "amnezia-awg") } else { ("wireguard", "amnezia-wireguard") };

    let mut last = Map::new();
    last.insert("config".into(), json!(conf));
    last.insert("hostName".into(), json!(host));
    last.insert("port".into(), json!(port.parse::<u16>().unwrap_or(51820)));
    last.insert("client_priv_key".into(), json!(priv_key));
    last.insert("client_ip".into(), json!(addr));
    if !s(&m, "PresharedKey").is_empty() {
        last.insert("psk_key".into(), json!(s(&m, "PresharedKey")));
    }
    last.insert("server_pub_key".into(), json!(pub_key));
    if !s(&m, "PersistentKeepalive").is_empty() {
        last.insert("persistent_keep_alive".into(), json!(s(&m, "PersistentKeepalive")));
    }
    let allowed: Vec<&str> = s(&m, "AllowedIPs").split(',').map(|x| x.trim()).filter(|x| !x.is_empty()).collect();
    last.insert("allowed_ips".into(), json!(allowed));
    for k in AWG_KEYS {
        if !s(&m, k).is_empty() {
            last.insert(k.into(), json!(s(&m, k)));
        }
    }
    let mtu = match s(&m, "MTU") { "" if awg => "1280", "" => "1376", x => x };
    last.insert("mtu".into(), json!(mtu));

    let mut entry = json!({
        "containers": [{
            "container": container,
            proto: {
                "last_config": serde_json::to_string_pretty(&Value::Object(last)).ok()?,
                "isThirdPartyConfig": true,
                "port": port,
                "transport_proto": "udp",
            },
        }],
        "defaultContainer": container,
        "description": description,
        "hostName": host,
        "storageServerId": uuid4(),
    });
    // DNS = a, b: the app keeps the first two
    let dns: Vec<&str> = s(&m, "DNS").split(',').map(|x| x.trim()).filter(|x| !x.is_empty()).collect();
    if dns.len() >= 2 {
        entry["dns1"] = json!(dns[0]);
        entry["dns2"] = json!(dns[1]);
    }
    Some(entry)
}

/// The whole backup file for one platform ("iOS", "Android", "Windows"); the first server is the default.
/// None when no config could be read.
pub fn backup(configs: &[(String, String)], platform: &str) -> Option<String> {
    let servers: Vec<Value> = configs.iter().filter_map(|(name, conf)| server(conf, name)).collect();
    let first = servers.first()?["storageServerId"].clone();
    let mut cfg = json!({
        "AppPlatform": platform,
        "Conf/autoStart": false,
        "Conf/killSwitchEnabled": false,
        "Conf/strictKillSwitchEnabled": false,
        "Conf/useAmneziaDns": false,
        "Conf/routeMode": 0,
        "Servers/defaultServerId": first,
        // older apps read the index instead of the id
        "Servers/defaultServerIndex": 0,
        "Servers/serversList": serde_json::to_string_pretty(&servers).ok()?,
    });
    // split tunneling by app exists only on Android and Windows
    if platform == "Android" || platform == "Windows" {
        cfg["Conf/appsRouteMode"] = json!(0);
    }
    serde_json::to_string_pretty(&cfg).ok()
}

/// The file name: the config name of the user, then .backup (the app lists only that extension)
pub fn file_name(who: &str) -> String {
    let w: String = who.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_').take(32).collect();
    format!("{}.backup", if w.is_empty() { "kanki" } else { &w })
}

#[cfg(test)]
mod tests {
    use super::*;

    const AWG: &str = "[Interface]\nPrivateKey = cHJpdmF0ZQ==\nAddress = 10.8.0.5/32\nDNS = 1.1.1.1, 8.8.8.8\nMTU = 1380\nJc = 4\nJmin = 40\nJmax = 70\nS1 = 15\nS2 = 30\nH1 = 1234\nH2 = 5678\nH3 = 91011\nH4 = 121314\nI1 = <r 2><b 0x8580>\n\n[Peer]\nPublicKey = cHVibGlj\nPresharedKey = cHNr\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = de1.example.net:51821\nPersistentKeepalive = 25\n";
    const WG: &str = "[Interface]\nPrivateKey = d2dwcml2\nAddress = 10.9.0.5/32\nDNS = 1.1.1.1\n\n[Peer]\nPublicKey = d2dwdWI=\nAllowedIPs = 0.0.0.0/0\nEndpoint = [2001:db8::1]:51820\n";

    fn servers_of(b: &str) -> (Value, Vec<Value>) {
        let v: Value = serde_json::from_str(b).unwrap();
        let list: Vec<Value> = serde_json::from_str(v["Servers/serversList"].as_str().expect("the list is a string")).unwrap();
        (v, list)
    }

    #[test]
    fn every_amneziawg_config_goes_in_the_awg_container_as_the_app_imports_it() {
        let s = server(AWG, "GERMANY").unwrap();
        assert_eq!(s["defaultContainer"], "amnezia-awg");
        let c = &s["containers"][0];
        assert_eq!(c["container"], "amnezia-awg");
        assert_eq!(c["awg"]["isThirdPartyConfig"], true);
        assert_eq!(c["awg"]["port"], "51821");
        let last: Value = serde_json::from_str(c["awg"]["last_config"].as_str().expect("last_config is a string")).unwrap();
        assert_eq!(last["config"], AWG);
        assert_eq!(last["hostName"], "de1.example.net");
        assert_eq!(last["port"], 51821);
        assert_eq!(last["client_ip"], "10.8.0.5/32");
        assert_eq!(last["psk_key"], "cHNr");
        assert_eq!(last["H1"], "1234");
        assert_eq!(last["I1"], "<r 2><b 0x8580>");
        assert_eq!(last["mtu"], "1380");
        assert_eq!(last["allowed_ips"], json!(["0.0.0.0/0", "::/0"]));
        assert_eq!((s["dns1"].as_str(), s["dns2"].as_str()), (Some("1.1.1.1"), Some("8.8.8.8")));
    }

    #[test]
    fn a_plain_wireguard_config_stays_wireguard() {
        let s = server(WG, "FINLAND").unwrap();
        assert_eq!(s["containers"][0]["container"], "amnezia-wireguard");
        let last: Value = serde_json::from_str(s["containers"][0]["wireguard"]["last_config"].as_str().unwrap()).unwrap();
        assert_eq!(last["hostName"], "2001:db8::1");
        assert_eq!(last["mtu"], "1376");
        assert!(last.get("psk_key").is_none());
        assert!(s.get("dns1").is_none());
    }

    #[test]
    fn a_backup_holds_every_server_once_with_its_own_id() {
        let cfgs = vec![("GERMANY".to_string(), AWG.to_string()), ("bad".to_string(), "nothing".to_string()), ("FINLAND".to_string(), WG.to_string())];
        let (v, list) = servers_of(&backup(&cfgs, "iOS").unwrap());
        assert_eq!(v["AppPlatform"], "iOS");
        assert!(v.get("Conf/appsRouteMode").is_none());
        assert_eq!(list.len(), 2);
        assert_eq!(list[0]["description"], "GERMANY");
        assert_ne!(list[0]["storageServerId"], list[1]["storageServerId"]);
        assert_eq!(v["Servers/defaultServerId"], list[0]["storageServerId"]);
        assert_eq!(list[0]["storageServerId"].as_str().unwrap().len(), 36);
        let (a, _) = servers_of(&backup(&cfgs, "Android").unwrap());
        assert_eq!(a["Conf/appsRouteMode"], 0);
        assert!(backup(&[("x".into(), "nothing".into())], "iOS").is_none());
    }

    #[test]
    fn platforms_and_file_names() {
        assert_eq!(platform("i"), Some("iOS"));
        assert_eq!(platform("android"), Some("Android"));
        assert_eq!(platform("Windows"), Some("Windows"));
        assert_eq!(platform("mac"), None);
        assert_eq!(file_name("mahtab87"), "mahtab87.backup");
        assert_eq!(file_name("../x y"), "xy.backup");
        assert_eq!(file_name("علی"), "kanki.backup");
        assert_eq!(flag("tr"), "🇹🇷");
        assert_eq!(flag("IR"), "🇮🇷");
        assert_eq!(flag(""), "");
        assert_eq!(flag("1x"), "");
    }

    fn test_app() -> std::sync::Arc<crate::App> {
        use std::sync::{atomic::AtomicI64, Mutex};
        let dir = std::env::temp_dir().join(format!("kanki-amnezia-test-{}", crate::util::rand_token(8)));
        std::fs::create_dir_all(&dir).unwrap();
        std::sync::Arc::new(crate::App {
            db: crate::db::Db::open(dir.join("kanki.db").to_str().unwrap()),
            env: std::collections::HashMap::from([("DOMAIN".to_string(), "fi.example.com".to_string())]),
            hy2_allowed: Mutex::new(Default::default()), limits: Mutex::new(Default::default()), reported: Mutex::new(Default::default()),
            login_fails: Mutex::new(Default::default()), sync_lock: tokio::sync::Mutex::new(()), bot_alive: AtomicI64::new(0),
            http: reqwest::Client::new(), http_insecure: reqwest::Client::new(), pin_clients: Mutex::new(Default::default()),
        })
    }

    #[tokio::test]
    async fn the_backup_of_a_user_holds_the_same_config_the_panel_hands_out() {
        let app = test_app();
        let info = json!({"awg_pub": "c2VydmVycHVi", "awg_port": "51821", "awg": [["Jc", "4"], ["Jmin", "40"], ["H1", "1234"]]});
        app.db.exec("INSERT INTO nodes(id,name,address,endpoint,token,info,online) VALUES('local','GERMANY','de1.example.net','','',?1,1)", &[&info.to_string()]).unwrap();
        app.db.set("exit_geo", &json!({ "local": { "ip": "9.9.9.1", "cc": "TR" } }).to_string());
        let u = app.db.create_user("mahtab87", 10.0, 30, 1, "awg", "", "", 0).unwrap();
        // the key the panel made for this user on this server (made here: the test machine has no `wg`)
        app.db.exec("INSERT INTO peers(user_id,node_id,proto,privkey,pubkey,psk,ip) VALUES(?1,'local','awg','dXNlcnByaXY=','dXNlcnB1Yg==','cHNr','10.67.0.3')", &[&u.id]).unwrap();
        let cfgs = crate::api::amnezia_configs(&app, &u).await;
        assert_eq!(cfgs.len(), 1, "{:?}", cfgs);
        let local = app.db.node("local").unwrap();
        let (_, conf) = crate::api::bot_config(&app, &u, &local, "amneziawg", false).await.unwrap();
        assert_eq!(cfgs[0].1, conf);
        assert_eq!(cfgs[0].0, "🇹🇷 AmneziaWG · GERMANY");
        let (v, list) = servers_of(&backup(&cfgs, "Windows").unwrap());
        assert_eq!(v["AppPlatform"], "Windows");
        assert_eq!(list[0]["defaultContainer"], "amnezia-awg");
        let last: Value = serde_json::from_str(list[0]["containers"][0]["awg"]["last_config"].as_str().unwrap()).unwrap();
        assert_eq!(last["config"], conf);
        assert_eq!(last["server_pub_key"], "c2VydmVycHVi");
        assert_eq!(last["Jc"], "4");
        // a user without WireGuard / AmneziaWG gets no file
        let h = app.db.create_user("sara12", 10.0, 30, 1, "hy2", "", "", 0).unwrap();
        assert!(backup(&crate::api::amnezia_configs(&app, &h).await, "iOS").is_none());
    }
}
