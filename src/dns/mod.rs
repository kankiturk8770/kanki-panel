//! Kanki DNS: a private smart DNS for subscribers. Names of sanctioned services resolve to this server,
//! which carries those connections abroad (directly on an exit server, or through a Kanki tunnel from a
//! relay server inside Iran). Runs as its own service (`kanki-panel dns`), deployed by the agent.
pub mod acme;
pub mod doh;
pub mod engine;
pub mod panel;
pub mod sni;
pub mod wire;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub const CONF_FILE: &str = "/etc/kanki/dns.json";
const DATA_DIR: &str = "/var/lib/kanki/dns";
const STATS_FILE: &str = "/var/lib/kanki/dns/stats.json";
const UNIT: &str = "/etc/systemd/system/kanki-dns.service";
const VER_FILE: &str = "/var/lib/kanki/dns/applied.ver";
const RESTART_FILE: &str = "/var/lib/kanki/dns/applied.restart";
const RUNNING_VER: &str = "/var/lib/kanki/dns/running.ver";

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(default)]
pub struct DnsUser {
    pub id: i64,
    pub name: String,
    /// the user's DNS token: `<token>.<host>` for DoT, `/dns-query/<token>` for DoH
    pub token: String,
    /// how many addresses may be allowed at once (0 = no limit)
    pub max_ips: u32,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct DnsCfg {
    /// "exit" (carries connections itself) | "relay" (sends them to an exit through a tunnel)
    pub role: String,
    /// this server's DNS name (DoT / DoH, and `<token>.` it); empty = no encrypted DNS
    pub host: String,
    /// the IPv4 answered for routed names (this server's public address)
    pub answer_ip: String,
    pub upstreams: Vec<String>,
    /// routed names (a name routes when it or one of its parents is listed)
    pub domains: Vec<String>,
    pub users: Vec<DnsUser>,
    /// PEM certificate (with its chain) and key for `host` and `*.host`
    pub cert: String,
    pub key: String,
    pub dns_port: u16,
    pub dot_port: u16,
    pub https_port: u16,
    pub http_port: u16,
    /// exit: local port the relay's tunnel delivers to (0 = no relay)
    pub intake_port: u16,
    /// relay: where routed connections go ("127.0.0.1:<tunnel port>")
    pub exit_addr: String,
    /// shared secret between a relay and its exit
    pub relay_key: String,
    /// how long an address stays allowed after its last use with the token
    pub ip_hours: u64,
}

/// The DNS token of a subscription code: changes when the user's link is renewed.
pub fn user_token(code: &str) -> String {
    crate::util::sha256_hex(&format!("kanki-dns|{}", code))[..20].to_string()
}

fn load_cfg() -> Result<DnsCfg, String> {
    let t = std::fs::read_to_string(CONF_FILE).map_err(|e| format!("cannot read {}: {}", CONF_FILE, e))?;
    serde_json::from_str(&t).map_err(|e| format!("{}: {}", CONF_FILE, e))
}

/// `kanki-panel dns`: run the server from /etc/kanki/dns.json (users and names are re-read live)
pub async fn run() {
    let cfg = match load_cfg() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(1);
        }
    };
    let _ = std::fs::create_dir_all(DATA_DIR);
    let eng = engine::Engine::new(cfg);
    engine::serve(eng.clone()).await;
    let _ = std::fs::write(RUNNING_VER, crate::VERSION);
    eprintln!("kanki dns {} running", crate::VERSION);
    let run_id = crate::util::rand_token(8);
    let mut last = std::fs::metadata(CONF_FILE).and_then(|m| m.modified()).ok();
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        let m = std::fs::metadata(CONF_FILE).and_then(|m| m.modified()).ok();
        if m != last {
            last = m;
            match load_cfg() {
                Ok(c) => eng.reload(c),
                Err(e) => eprintln!("{}", e),
            }
        }
        let users: serde_json::Map<String, Value> = eng.stats_snapshot().into_iter().map(|(k, (b, q))| (k.to_string(), json!([b, q]))).collect();
        let st = json!({
            "run": run_id, "ts": crate::util::now(), "users": users, "allowed": eng.allowed_count(),
            "conns": eng.conns.load(std::sync::atomic::Ordering::Relaxed), "errors": eng.errors.lock().unwrap().clone(),
        });
        let tmp = format!("{}.new", STATS_FILE);
        if std::fs::write(&tmp, st.to_string()).is_ok() {
            let _ = std::fs::rename(&tmp, STATS_FILE);
        }
    }
}

// ------------------------------------------------------------------ deploy (run by the agent)

fn sh(cmd: &str) -> (bool, String) {
    match std::process::Command::new("sh").arg("-c").arg(cmd).stdin(std::process::Stdio::null()).output() {
        Ok(o) => {
            let mut t = String::from_utf8_lossy(&o.stdout).to_string();
            t.push_str(&String::from_utf8_lossy(&o.stderr));
            (o.status.success(), t.trim().to_string())
        }
        Err(e) => (false, e.to_string()),
    }
}

pub fn applied_ver() -> String {
    std::fs::read_to_string(VER_FILE).map(|s| s.trim().to_string()).unwrap_or_default()
}

/// Write the config and keep the service in step with it (None = remove the service). Blocking.
pub fn deploy(cfg: Option<(&DnsCfg, &str)>) -> Result<(), String> {
    let Some((c, ver)) = cfg else {
        if std::path::Path::new(UNIT).exists() {
            eprintln!("dns: stopping");
            let _ = sh("systemctl disable --now -q kanki-dns.service 2>&1");
            let _ = std::fs::remove_file(UNIT);
            let _ = sh("systemctl daemon-reload");
        }
        for f in [CONF_FILE, VER_FILE, RESTART_FILE, STATS_FILE] {
            let _ = std::fs::remove_file(f);
        }
        return Ok(());
    };
    let _ = std::fs::create_dir_all("/etc/kanki");
    let _ = std::fs::create_dir_all(DATA_DIR);
    let text = serde_json::to_string(c).map_err(|e| e.to_string())?;
    if std::fs::read_to_string(CONF_FILE).map(|t| t != text).unwrap_or(true) {
        let tmp = format!("{}.new", CONF_FILE);
        std::fs::write(&tmp, &text).map_err(|e| format!("cannot write {}: {}", CONF_FILE, e))?;
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
        }
        std::fs::rename(&tmp, CONF_FILE).map_err(|e| e.to_string())?;
    }
    let exe = std::env::current_exe().map_err(|e| e.to_string())?.to_string_lossy().replace(" (deleted)", "");
    let unit = format!(
        "# written by kanki-panel\n[Unit]\nDescription=Kanki DNS\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nExecStart={} dns\nRestart=always\nRestartSec=3\nLimitNOFILE=1048576\n\n[Install]\nWantedBy=multi-user.target\n",
        exe
    );
    let unit_changed = std::fs::read_to_string(UNIT).map(|t| t != unit).unwrap_or(true);
    if unit_changed {
        std::fs::write(UNIT, &unit).map_err(|e| format!("cannot write {}: {}", UNIT, e))?;
        let _ = sh("systemctl daemon-reload");
        let _ = sh("systemctl enable -q kanki-dns.service");
    }
    // ports, certificate, role and relay path need a restart; users and names are re-read live
    let restart_key = crate::util::sha256_hex(&format!(
        "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
        c.role, c.host, c.cert, c.key, c.dns_port, c.dot_port, c.https_port, c.http_port, c.intake_port, c.exit_addr, c.answer_ip
    ));
    let old_key = std::fs::read_to_string(RESTART_FILE).unwrap_or_default();
    let active = sh("systemctl is-active --quiet kanki-dns.service").0;
    if unit_changed || old_key.trim() != restart_key || !active {
        let (ok, out) = sh("systemctl restart kanki-dns.service 2>&1");
        if !ok {
            return Err(format!("systemctl restart kanki-dns: {}", out.lines().last().unwrap_or("")));
        }
        let _ = std::fs::write(RESTART_FILE, &restart_key);
        eprintln!("dns: started ({})", c.role);
    }
    if sh("ufw status 2>/dev/null | grep -q 'Status: active'").0 {
        for (p, proto) in [(c.dns_port, "udp"), (c.dns_port, "tcp"), (c.dot_port, "tcp"), (c.https_port, "tcp"), (c.http_port, "tcp")] {
            if p > 0 {
                let _ = sh(&format!("ufw allow {}/{} >/dev/null 2>&1", p, proto));
            }
        }
    }
    let _ = std::fs::write(VER_FILE, ver);
    Ok(())
}

/// After an update the service still runs the old binary: restart it once onto the new one.
pub fn restart_if_outdated() {
    let Ok(v) = std::fs::read_to_string(RUNNING_VER) else { return };
    if v.trim() != crate::VERSION && std::path::Path::new(UNIT).exists() && sh("systemctl is-active --quiet kanki-dns.service").0 {
        eprintln!("dns: restarting onto v{}", crate::VERSION);
        let _ = sh("systemctl restart kanki-dns.service");
    }
}

/// What the agent reports about DNS on this server (Null = not installed here).
pub fn status() -> Value {
    if !std::path::Path::new(UNIT).exists() {
        return Value::Null;
    }
    let active = sh("systemctl is-active --quiet kanki-dns.service").0;
    let mut st: Value = std::fs::read_to_string(STATS_FILE).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or(json!({}));
    // stale numbers from a stopped service would be counted again
    if !active || st["ts"].as_i64().map(|t| crate::util::now() - t > 60).unwrap_or(true) {
        st = json!({});
    }
    st["active"] = json!(active);
    st["ver"] = json!(applied_ver());
    if !active {
        st["error"] = json!(sh("journalctl -u kanki-dns.service -n 5 --no-pager -o cat 2>/dev/null").1.lines().last().unwrap_or("not running").to_string());
    }
    st
}
