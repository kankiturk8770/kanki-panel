//! WireGuard, AmneziaWG and Hysteria2 each on or off per server. The panel keeps which ones are off
//! (`core_off`: node id -> cores) and sends the list with every sync; the server stops and disables an
//! off core and closes its port, and starts it again when it is switched back on. A server that joins
//! gets all three off (installed, waiting to be switched on); servers from before stay as they were.
use crate::App;
use std::collections::HashMap;
use std::process::Command;

/// (core, systemd unit, its config file on the server)
pub const CORES: [(&str, &str, &str); 3] = [
    ("wg", "wg-quick@wg0", "/etc/wireguard/wg0.conf"),
    ("awg", "awg-quick@awg0", "/etc/amnezia/amneziawg/awg0.conf"),
    ("hy2", "hysteria-server", "/etc/hysteria/config.yaml"),
];

/// node id -> the cores switched off there
pub fn load(app: &App) -> HashMap<String, Vec<String>> {
    serde_json::from_str(&app.db.get("core_off")).unwrap_or_default()
}

fn save(app: &App, m: &HashMap<String, Vec<String>>) {
    app.db.set("core_off", &serde_json::to_string(m).unwrap_or_else(|_| "{}".into()));
}

/// The cores switched off on node `nid`
pub fn off_list(app: &App, nid: &str) -> Vec<String> {
    load(app).remove(nid).unwrap_or_default()
}

pub fn is_off(app: &App, nid: &str, core: &str) -> bool {
    off_list(app, nid).iter().any(|c| c == core)
}

/// Switches `core` on node `nid` off (or back on)
pub fn set(app: &App, nid: &str, core: &str, off: bool) -> Result<(), String> {
    if !CORES.iter().any(|c| c.0 == core) {
        return Err("core: wg, awg or hy2".into());
    }
    let mut m = load(app);
    let l = m.entry(nid.to_string()).or_default();
    l.retain(|c| c != core);
    if off {
        l.push(core.to_string());
    }
    l.sort();
    if l.is_empty() {
        m.remove(nid);
    }
    save(app, &m);
    Ok(())
}

/// A server that just joined: every core installed but off until it is switched on
pub fn all_off(app: &App, nid: &str) {
    let mut m = load(app);
    m.insert(nid.to_string(), CORES.iter().map(|c| c.0.to_string()).collect());
    save(app, &m);
}

/// The node left the panel
pub fn forget(app: &App, nid: &str) {
    let mut m = load(app);
    if m.remove(nid).is_some() {
        save(app, &m);
    }
}

// ------------------------------------------------------------------ on the server

const LAST: &str = "/var/lib/kanki/cores_off.json";

fn port_of(core: &str, conf: &str) -> Option<u16> {
    if core == "hy2" {
        let env = crate::util::load_env("/etc/kanki/kanki.env");
        return env.get("HY2_PORT").and_then(|p| p.trim().parse().ok());
    }
    let t = std::fs::read_to_string(conf).ok()?;
    t.lines().find_map(|l| l.trim().strip_prefix("ListenPort").map(|r| r.trim_start_matches([' ', '=']).trim().parse().ok())).flatten()
}

fn ufw(args: &str) {
    let _ = Command::new("sh").arg("-c").arg(format!("command -v ufw >/dev/null 2>&1 && ufw {} >/dev/null 2>&1", args)).status();
}

/// Applies the panel's list on this server. Only what changed since the last list is touched, so a
/// service stopped by hand (Dashboard > Services) is not started again by every sync. Blocking.
pub fn apply(off: &[String]) {
    let last: Vec<String> = std::fs::read_to_string(LAST).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default();
    let mut want: Vec<String> = off.iter().filter(|c| CORES.iter().any(|x| x.0 == c.as_str())).cloned().collect();
    want.sort();
    want.dedup();
    if want == last {
        return;
    }
    for (core, unit, conf) in CORES {
        if !std::path::Path::new(conf).exists() {
            continue;
        }
        let (now_off, was_off) = (want.iter().any(|c| c == core), last.iter().any(|c| c == core));
        if now_off == was_off {
            continue;
        }
        let port = port_of(core, conf);
        if now_off {
            let _ = Command::new("systemctl").args(["disable", "--now", "-q", unit]).status();
            if let Some(p) = port {
                ufw(&format!("--force delete allow {}/udp", p));
            }
            eprintln!("{}: switched off in the panel (stopped, port closed)", core);
        } else {
            if let Some(p) = port {
                ufw(&format!("allow {}/udp", p));
            }
            let _ = Command::new("systemctl").args(["enable", "--now", "-q", unit]).status();
            eprintln!("{}: switched on in the panel (started, port open)", core);
        }
    }
    let _ = std::fs::create_dir_all("/var/lib/kanki");
    let _ = std::fs::write(LAST, serde_json::to_string(&want).unwrap_or_default());
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::{atomic::AtomicI64, Arc, Mutex};

    fn app() -> Arc<crate::App> {
        let dir = std::env::temp_dir().join(format!("kanki-cores-test-{}", crate::util::rand_token(8)));
        std::fs::create_dir_all(&dir).unwrap();
        let db = crate::db::Db::open(dir.join("kanki.db").to_str().unwrap());
        Arc::new(crate::App {
            db,
            env: HashMap::new(),
            hy2_allowed: Mutex::new(HashMap::new()), limits: Mutex::new(HashMap::new()), reported: Mutex::new(HashMap::new()),
            login_fails: Mutex::new(HashMap::new()), sync_lock: tokio::sync::Mutex::new(()), bot_alive: AtomicI64::new(0),
            http: reqwest::Client::new(), http_insecure: reqwest::Client::new(), pin_clients: Mutex::new(HashMap::new()),
        })
    }

    #[test]
    fn a_new_server_starts_with_its_cores_off_and_old_ones_stay_on() {
        let a = app();
        // a node from before: nothing stored, every core on
        assert!(!super::is_off(&a, "old", "wg") && !super::is_off(&a, "old", "hy2"));
        super::all_off(&a, "new");
        assert!(super::is_off(&a, "new", "wg") && super::is_off(&a, "new", "awg") && super::is_off(&a, "new", "hy2"));
        super::set(&a, "new", "awg", false).unwrap();
        assert_eq!(super::off_list(&a, "new"), vec!["hy2".to_string(), "wg".to_string()]);
        assert!(super::set(&a, "new", "kmix", true).is_err());
        super::forget(&a, "new");
        assert!(super::off_list(&a, "new").is_empty());
    }
}
