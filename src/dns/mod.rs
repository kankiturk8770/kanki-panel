//! Kanki DNS: a private smart DNS for subscribers. Names of sanctioned services resolve to this server,
//! which carries those connections abroad (directly on an exit server, or through a Kanki tunnel from a
//! relay server inside Iran). Runs as its own service (`kanki-panel dns`), deployed by the agent.
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
const SSL_ERR_FILE: &str = "/var/lib/kanki/dns/ssl.err";
/// the latest queries of subscribers, written by the service for the agent to report
const QLOG_FILE: &str = "/var/lib/kanki/dns/qlog.json";
/// "Repair" from the panel: restart the DNS service on the next deploy even when nothing changed
const FORCE_FILE: &str = "/var/lib/kanki/dns/force";
/// queries sent to the panel in one report (the newest when more are waiting)
const QLOG_PER_REPORT: usize = 2000;

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(default)]
pub struct DnsUser {
    pub id: i64,
    pub name: String,
    /// the user's DNS token: `<token>.<host>` for DoT, `/dns-query/<token>` for DoH
    pub token: String,
    /// how many addresses may be allowed at once (0 = no limit)
    pub max_ips: u32,
    /// bumped by the admin to forget the user's allowed addresses
    pub epoch: u64,
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
    /// no certificate in the config: this server gets its own for `host` with certbot
    pub acme: bool,
}

/// The DNS token of a subscription code: changes when the user's link is renewed.
pub fn user_token(code: &str) -> String {
    crate::util::sha256_hex(&format!("kanki-dns|{}", code))[..20].to_string()
}

fn load_cfg() -> Result<DnsCfg, String> {
    let t = std::fs::read_to_string(CONF_FILE).map_err(|e| format!("cannot read {}: {}", CONF_FILE, e))?;
    let mut c: DnsCfg = serde_json::from_str(&t).map_err(|e| format!("{}: {}", CONF_FILE, e))?;
    // the certificate certbot got for this server's name
    if c.acme && c.cert.trim().is_empty() && !c.host.is_empty() {
        let (cf, kf) = crate::certbot::files(&c.host);
        c.cert = std::fs::read_to_string(cf).unwrap_or_default();
        c.key = std::fs::read_to_string(kf).unwrap_or_default();
    }
    Ok(c)
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
    let mut qlog_written = 0u64;
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
        let ld = |a: &std::sync::atomic::AtomicU64| a.load(std::sync::atomic::Ordering::Relaxed);
        let st = json!({
            "run": run_id, "ts": crate::util::now(), "users": users, "allowed": eng.allowed_count(),
            "conns": eng.conns.load(std::sync::atomic::Ordering::Relaxed), "errors": eng.errors.lock().unwrap().clone(),
            "q": { "total": ld(&eng.q_total), "routed": ld(&eng.q_routed), "cache": ld(&eng.q_cache), "refused": ld(&eng.q_refused) },
            "top": eng.top(15), "ips": eng.ips_snapshot(), "version": crate::VERSION,
        });
        let tmp = format!("{}.new", STATS_FILE);
        if std::fs::write(&tmp, st.to_string()).is_ok() {
            let _ = std::fs::rename(&tmp, STATS_FILE);
        }
        // the query log: every query still kept (the agent sends the ones the panel has not had yet)
        if eng.qlog_last() != qlog_written {
            qlog_written = eng.qlog_last();
            let items: Vec<Value> = eng.qlog_after(0).into_iter().map(|q| json!([q.seq, q.ts, q.uid, q.name, q.qtype, q.routed])).collect();
            let tmp = format!("{}.new", QLOG_FILE);
            if std::fs::write(&tmp, json!({ "run": run_id, "items": items }).to_string()).is_ok() {
                let _ = std::fs::rename(&tmp, QLOG_FILE);
            }
        }
    }
}

/// (run id, last query seq) the panel has received from this server
fn qlog_acked() -> &'static std::sync::Mutex<(String, u64)> {
    static A: std::sync::OnceLock<std::sync::Mutex<(String, u64)>> = std::sync::OnceLock::new();
    A.get_or_init(|| std::sync::Mutex::new((String::new(), 0)))
}

/// The queries the panel has not received yet: { "run": ..., "items": [[seq, ts, uid, name, qtype, routed], ...] }
fn qlog_pending() -> Value {
    let Some(v) = std::fs::read_to_string(QLOG_FILE).ok().and_then(|t| serde_json::from_str::<Value>(&t).ok()) else { return Value::Null };
    let run = v["run"].as_str().unwrap_or("").to_string();
    let after = {
        let a = qlog_acked().lock().unwrap();
        if a.0 == run { a.1 } else { 0 }
    };
    let mut items: Vec<Value> = v["items"].as_array().into_iter().flatten().filter(|x| x[0].as_u64().unwrap_or(0) > after).cloned().collect();
    if items.len() > QLOG_PER_REPORT {
        items.drain(..items.len() - QLOG_PER_REPORT);
    }
    if items.is_empty() {
        return Value::Null;
    }
    json!({ "run": run, "items": items })
}

/// After a report reached the panel: the queries it carried are not sent again.
pub fn qlog_ack(st: &Value) {
    let run = st["qlog"]["run"].as_str().unwrap_or("");
    let Some(last) = st["qlog"]["items"].as_array().and_then(|l| l.last()).and_then(|x| x[0].as_u64()) else { return };
    *qlog_acked().lock().unwrap() = (run.to_string(), last);
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
/// The panel asked for a repair: the next deploy writes the service again and restarts it.
pub fn repair_prep() {
    let _ = std::fs::create_dir_all(DATA_DIR);
    let _ = std::fs::write(FORCE_FILE, "1");
}

pub fn deploy(cfg: Option<(&DnsCfg, &str)>) -> Result<(), String> {
    let Some((c, ver)) = cfg else {
        if std::path::Path::new(UNIT).exists() {
            eprintln!("dns: stopping");
            let _ = sh("systemctl disable --now -q kanki-dns.service 2>&1");
            let _ = std::fs::remove_file(UNIT);
            let _ = sh("systemctl daemon-reload");
        }
        for f in [CONF_FILE, VER_FILE, RESTART_FILE, STATS_FILE, QLOG_FILE] {
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
    let forced = std::path::Path::new(FORCE_FILE).exists();
    let unit_changed = std::fs::read_to_string(UNIT).map(|t| t != unit).unwrap_or(true);
    if unit_changed || forced {
        std::fs::write(UNIT, &unit).map_err(|e| format!("cannot write {}: {}", UNIT, e))?;
        let _ = sh("systemctl daemon-reload");
        let _ = sh("systemctl enable -q kanki-dns.service");
    }
    // ports, certificate, role and relay path need a restart; users and names are re-read live
    let key_of = |c: &DnsCfg| {
        crate::util::sha256_hex(&format!(
            "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
            c.role, c.host, c.cert, c.key, c.dns_port, c.dot_port, c.https_port, c.http_port, c.intake_port, c.exit_addr,
            format!("{}|{}", c.answer_ip, c.acme && crate::certbot::have(&c.host))
        ))
    };
    let restart_key = key_of(c);
    let old_key = std::fs::read_to_string(RESTART_FILE).unwrap_or_default();
    let active = sh("systemctl is-active --quiet kanki-dns.service").0;
    if unit_changed || forced || old_key.trim() != restart_key || !active {
        let (ok, out) = sh("systemctl restart kanki-dns.service 2>&1");
        if !ok {
            return Err(format!("systemctl restart kanki-dns: {}", out.lines().last().unwrap_or("")));
        }
        let _ = std::fs::write(RESTART_FILE, &restart_key);
        let _ = std::fs::remove_file(FORCE_FILE);
        eprintln!("dns: started ({})", c.role);
    }
    if sh("ufw status 2>/dev/null | grep -q 'Status: active'").0 {
        for (p, proto) in [(c.dns_port, "udp"), (c.dns_port, "tcp"), (c.dot_port, "tcp"), (c.https_port, "tcp"), (c.http_port, "tcp")] {
            if p > 0 {
                let _ = sh(&format!("ufw allow {}/{} >/dev/null 2>&1", p, proto));
            }
        }
    }
    // SSL with certbot for this server's name, now that the service runs: Kanki DNS answers Let's Encrypt
    // itself on port 80, so DNS does not stop; DNS works without it, only DoT / DoH wait for the certificate
    let mut ssl_err = String::new();
    if c.acme && !c.host.is_empty() {
        let had = crate::certbot::have(&c.host);
        if !had && c.http_port == 80 {
            // just started: let it take port 80 first, so certbot sees it and does not stop it
            for _ in 0..20 {
                if crate::certbot::port80_used() {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(250));
            }
        }
        match crate::certbot::ensure(&c.host, &["kanki-dns.service"]) {
            Ok(()) if !had => {
                // the service was restarted onto the new certificate
                if !sh("systemctl is-active --quiet kanki-dns.service").0 {
                    let _ = sh("systemctl restart kanki-dns.service");
                }
                let _ = std::fs::write(RESTART_FILE, key_of(c));
            }
            Ok(()) => {}
            Err(e) => {
                eprintln!("dns: {}", e);
                ssl_err = e;
            }
        }
    }
    let _ = std::fs::write(SSL_ERR_FILE, &ssl_err);
    // no certificate yet: the config is sent again next round and certbot tries again (after 10 minutes)
    let _ = std::fs::write(VER_FILE, if c.acme && !c.host.is_empty() && !crate::certbot::have(&c.host) { format!("{}-nossl", ver) } else { ver.to_string() });
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
    if active {
        st["qlog"] = qlog_pending();
    }
    // the certificate of this server's name (certbot or pasted) and why certbot failed
    let host = load_cfg().map(|c| (c.host.clone(), !c.cert.trim().is_empty())).unwrap_or_default();
    st["ssl"] = json!(host.1);
    st["ssl_host"] = json!(host.0);
    st["ssl_error"] = json!(std::fs::read_to_string(SSL_ERR_FILE).unwrap_or_default().trim());
    if !active {
        st["error"] = json!(sh("journalctl -u kanki-dns.service -n 5 --no-pager -o cat 2>/dev/null").1.lines().last().unwrap_or("not running").to_string());
    }
    st
}
