//! Xray on a server: the panel builds the whole Xray config (inbounds with our own users as clients),
//! the agent installs Xray-core, keeps the service in step with the config and reads each user's
//! traffic from Xray's stats API. No speed limits anywhere.
pub mod panel;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Mutex;

const BIN: &str = "/usr/local/bin/kanki-xray";
const ASSET_DIR: &str = "/usr/local/share/kanki-xray";
const CONF_DIR: &str = "/etc/kanki/xray";
const CONF_FILE: &str = "/etc/kanki/xray/config.json";
pub(crate) const UNIT: &str = "/etc/systemd/system/kanki-xray.service";
const VER_FILE: &str = "/var/lib/kanki/xray.applied";
const BIN_VER_FILE: &str = "/var/lib/kanki/xray.binver";
const EXTRA_CERTS: &str = "/var/lib/kanki/xray.certs";
/// "Repair" from the panel: restart Xray on the next deploy even when nothing changed
const FORCE_FILE: &str = "/var/lib/kanki/xray.force";
pub const API_PORT: u16 = 10085;

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct XrayCfg {
    /// the full Xray JSON config
    pub config: Value,
    /// Xray-core release tag to install ("" = the latest release)
    pub version: String,
    /// domains of this server whose certificate certbot gets now (even before an inbound uses it)
    pub certs: Vec<String>,
}

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

fn q(s: &str) -> String {
    format!("'{}'", s.replace('\'', ""))
}

pub fn zip_name() -> Option<&'static str> {
    match std::env::consts::ARCH {
        "x86_64" => Some("Xray-linux-64.zip"),
        "aarch64" => Some("Xray-linux-arm64-v8a.zip"),
        "arm" => Some("Xray-linux-arm32-v7a.zip"),
        _ => None,
    }
}

pub fn release_url(version: &str, zip: &str) -> String {
    if version.trim().is_empty() {
        format!("https://github.com/XTLS/Xray-core/releases/latest/download/{}", zip)
    } else {
        format!("https://github.com/XTLS/Xray-core/releases/download/{}/{}", version.trim(), zip)
    }
}

/// Install Xray-core (from GitHub, or through the panel when GitHub is not reachable). Blocking.
fn install(version: &str, panel: Option<(&str, &str, &str)>) -> Result<(), String> {
    let want = if version.trim().is_empty() { "latest" } else { version.trim() };
    let have = std::fs::read_to_string(BIN_VER_FILE).unwrap_or_default();
    if std::path::Path::new(BIN).exists() && have.trim() == want {
        return Ok(());
    }
    // a failed install is tried again after a pause, not on every round (every 15 s it filled the log)
    if let Some((at, ver, e)) = last_fail().lock().unwrap_or_else(|e| e.into_inner()).clone() {
        if ver == want && at.elapsed() < std::time::Duration::from_secs(300) {
            return Err(e);
        }
    }
    let r = install_now(version, want, panel);
    *last_fail().lock().unwrap_or_else(|e| e.into_inner()) = match &r {
        Err(e) => Some((std::time::Instant::now(), want.to_string(), e.clone())),
        Ok(()) => None,
    };
    r
}

fn last_fail() -> &'static Mutex<Option<(std::time::Instant, String, String)>> {
    static L: std::sync::OnceLock<Mutex<Option<(std::time::Instant, String, String)>>> = std::sync::OnceLock::new();
    L.get_or_init(|| Mutex::new(None))
}

fn install_now(version: &str, want: &str, panel: Option<(&str, &str, &str)>) -> Result<(), String> {
    let zip = zip_name().ok_or("this CPU type has no Xray build")?;
    let direct = release_url(version, zip);
    let via_panel = match panel {
        Some((url, id, token)) => format!(
            " || curl -fsS --max-time 300 -H 'content-type: application/json' --data {} -o \"$T/x.zip\" {}",
            q(&json!({ "id": id, "token": token, "zip": zip, "version": version }).to_string()),
            q(&format!("{}/tunnel/xraybin", url))
        ),
        None => String::new(),
    };
    let script = format!(
        "set -e; mkdir -p /var/lib/kanki/tmp; T=$(mktemp -d -p /var/lib/kanki/tmp); trap 'rm -rf \"$T\"' EXIT; \
         (curl -fsSL --max-time 300 -o \"$T/x.zip\" {direct}{via_panel}); \
         if command -v unzip >/dev/null 2>&1; then unzip -o -q \"$T/x.zip\" -d \"$T/x\"; \
         else python3 -c 'import zipfile,sys; zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])' \"$T/x.zip\" \"$T/x\"; fi; \
         test -s \"$T/x/xray\"; chmod 755 \"$T/x/xray\"; \"$T/x/xray\" version >/dev/null; \
         mkdir -p {assets}; for f in geoip.dat geosite.dat; do [ -f \"$T/x/$f\" ] && cp -f \"$T/x/$f\" {assets}/; done; \
         install -m 755 \"$T/x/xray\" {bin}.new && mv -f {bin}.new {bin}",
        direct = q(&direct),
        via_panel = via_panel,
        assets = ASSET_DIR,
        bin = BIN
    );
    let (ok, out) = sh(&script);
    if !ok {
        return Err(format!("installing Xray-core failed: {}", out.lines().last().unwrap_or("")));
    }
    let _ = std::fs::create_dir_all("/var/lib/kanki");
    let _ = std::fs::write(BIN_VER_FILE, want);
    Ok(())
}

pub fn running() -> bool {
    sh("systemctl is-active --quiet kanki-xray.service").0
}

pub fn applied_ver() -> String {
    std::fs::read_to_string(VER_FILE).map(|s| s.trim().to_string()).unwrap_or_default()
}

/// Keep Xray in step with the config (None = remove it). `panel` = (url, id, token) of the agent, for
/// downloading Xray-core through the panel. Blocking.
/// The panel asked for a repair: the next deploy checks the Xray binary again (and reinstalls a
/// missing or broken one right away), writes the service again and restarts Xray.
pub fn repair_prep() {
    let _ = std::fs::create_dir_all("/var/lib/kanki");
    let _ = std::fs::write(FORCE_FILE, "1");
    *last_fail().lock().unwrap_or_else(|e| e.into_inner()) = None;
    if !sh(&format!("{} version >/dev/null 2>&1", BIN)).0 {
        let _ = std::fs::remove_file(BIN_VER_FILE);
    }
}

pub fn deploy(cfg: Option<(&XrayCfg, &str)>, panel: Option<(&str, &str, &str)>) -> Result<(), String> {
    let old_domains = cert_domains_on_disk();
    let Some((c, ver)) = cfg else {
        if std::path::Path::new(UNIT).exists() {
            eprintln!("xray: stopping");
            let _ = sh("systemctl disable --now -q kanki-xray.service 2>&1");
            let _ = std::fs::remove_file(UNIT);
            let _ = sh("systemctl daemon-reload");
        }
        let _ = std::fs::remove_file(CONF_FILE);
        let _ = std::fs::remove_file(VER_FILE);
        let _ = std::fs::remove_file(EXTRA_CERTS);
        // removed from this server: its ports are closed and its certificates are no longer renewed
        crate::fw::close("xray");
        loopback_guard(None);
        for d in old_domains {
            crate::certbot::forget(&d, "kanki-xray.service");
        }
        return Ok(());
    };
    // domains no inbound uses any more: their certificates are no longer renewed
    {
        let mut now = acme_domains(&c.config);
        now.extend(c.certs.iter().cloned());
        for d in old_domains.iter().filter(|d| !now.contains(d)) {
            crate::certbot::forget(d, "kanki-xray.service");
        }
    }
    install(&c.version, panel)?;
    let _ = std::fs::create_dir_all(CONF_DIR);
    // automatic SSL: certbot gets the certificates the config uses; an inbound whose certificate is
    // not there (yet) is left out, so the rest still runs
    let mut config = c.config.clone();
    let _ = std::fs::write(EXTRA_CERTS, c.certs.join("\n"));
    let partial = certs_for(&mut config, &c.certs);
    let text = serde_json::to_string_pretty(&config).map_err(|e| e.to_string())?;
    let changed = std::fs::read_to_string(CONF_FILE).map(|t| t != text).unwrap_or(true);
    if changed {
        // Xray tells the format by the extension: the file being checked must end in .json
        let tmp = format!("{}/config.new.json", CONF_DIR);
        std::fs::write(&tmp, &text).map_err(|e| format!("cannot write {}: {}", CONF_FILE, e))?;
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
        }
        // never replace a working config with one Xray refuses
        let (ok, out) = sh(&format!("XRAY_LOCATION_ASSET={} {} run -test -c {} 2>&1", ASSET_DIR, BIN, q(&tmp)));
        if !ok {
            let _ = std::fs::remove_file(&tmp);
            let last: Vec<&str> = out.lines().filter(|l| !l.trim().is_empty()).collect();
            return Err(format!("Xray refused the config: {}", last.last().unwrap_or(&"")));
        }
        std::fs::rename(&tmp, CONF_FILE).map_err(|e| e.to_string())?;
    }
    let unit = format!(
        "# written by kanki-panel\n[Unit]\nDescription=Kanki Xray\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nEnvironment=XRAY_LOCATION_ASSET={}\nExecStart={} run -c {}\nRestart=always\nRestartSec=3\nLimitNOFILE=1048576\nAmbientCapabilities=CAP_NET_BIND_SERVICE\n\n[Install]\nWantedBy=multi-user.target\n",
        ASSET_DIR, BIN, CONF_FILE
    );
    let forced = std::path::Path::new(FORCE_FILE).exists();
    let unit_changed = std::fs::read_to_string(UNIT).map(|t| t != unit).unwrap_or(true);
    if unit_changed || forced {
        std::fs::write(UNIT, &unit).map_err(|e| format!("cannot write {}: {}", UNIT, e))?;
        let _ = sh("systemctl daemon-reload");
        let _ = sh("systemctl enable -q kanki-xray.service");
    }
    let active = sh("systemctl is-active --quiet kanki-xray.service").0;
    if changed || unit_changed || forced || !active {
        // the traffic not read yet would be lost with the restart
        collect();
        let (ok, out) = sh("systemctl restart kanki-xray.service 2>&1");
        if !ok {
            return Err(format!("systemctl restart kanki-xray: {}", out.lines().last().unwrap_or("")));
        }
        eprintln!("xray: (re)started");
        let _ = std::fs::remove_file(FORCE_FILE);
    }
    // the inbound ports (a deleted inbound's port is closed again)
    let mut rules = vec![];
    for ib in c.config["inbounds"].as_array().into_iter().flatten() {
        if let Some(p) = ib["port"].as_u64().filter(|p| *p > 0 && *p < 65536) {
            if !matches!(ib["listen"].as_str(), Some("127.0.0.1") | Some("::1") | Some("localhost")) {
                rules.push(crate::fw::rule(p as u16, false));
                rules.push(crate::fw::rule(p as u16, true));
            }
        }
    }
    crate::fw::sync("xray", rules);
    loopback_guard(Some(&c.config));
    // missing certificates: deploy again on the next round (certbot waits 10 minutes after a failure)
    let _ = std::fs::write(VER_FILE, if partial { format!("{}-nocert", ver) } else { ver.to_string() });
    Ok(())
}

/// The certbot domains of the config this server runs now (before a new one is written)
const LO_CHAIN: &str = "KANKI-XRAY-LO";

/// The loopback ports the config itself needs: fallback targets ("80", "127.0.0.1:2002"), outbounds to a
/// local proxy, and DNS (53)
fn loopback_ports(config: &Value) -> Vec<u16> {
    let local = |h: &str| matches!(h.trim_matches(|c| c == '[' || c == ']'), "127.0.0.1" | "localhost" | "::1" | "");
    let mut v = vec![53u16];
    for ib in config["inbounds"].as_array().into_iter().flatten() {
        for f in ib["settings"]["fallbacks"].as_array().into_iter().flatten() {
            match &f["dest"] {
                Value::Number(n) => v.extend(n.as_u64().and_then(|p| u16::try_from(p).ok())),
                Value::String(d) => {
                    if let Some((h, p)) = d.rsplit_once(':') {
                        if local(h) {
                            v.extend(p.parse::<u16>().ok());
                        }
                    } else {
                        v.extend(d.parse::<u16>().ok());
                    }
                }
                _ => {}
            }
        }
    }
    for o in config["outbounds"].as_array().into_iter().flatten() {
        for srv in o["settings"]["servers"].as_array().into_iter().chain(o["settings"]["vnext"].as_array()).flatten() {
            if srv["address"].as_str().map(local).unwrap_or(false) {
                v.extend(srv["port"].as_u64().and_then(|p| u16::try_from(p).ok()));
            }
        }
    }
    // a local DNS server ("127.0.0.1:5353", "https://localhost:8053/dns-query", {address, port}) and a
    // freedom outbound that redirects to a local port
    let host_port = |a: &str| -> Option<u16> {
        let rest = a.split_once("://").map(|x| x.1).unwrap_or(a);
        let hp = rest.split('/').next().unwrap_or("");
        let (h, p) = hp.rsplit_once(':')?;
        if !local(h) {
            return None;
        }
        p.parse::<u16>().ok()
    };
    for d in config["dns"]["servers"].as_array().into_iter().flatten() {
        match d {
            Value::String(a) => v.extend(host_port(a)),
            Value::Object(_) => {
                let a = d["address"].as_str().unwrap_or("");
                if let Some(p) = d["port"].as_u64().and_then(|p| u16::try_from(p).ok()) {
                    if local(a.split_once("://").map(|x| x.1).unwrap_or(a).split('/').next().unwrap_or("")) {
                        v.push(p);
                    }
                }
                v.extend(host_port(a));
            }
            _ => {}
        }
    }
    for o in config["outbounds"].as_array().into_iter().flatten() {
        v.extend(o["settings"]["redirect"].as_str().and_then(host_port));
    }
    v.retain(|p| *p > 0 && *p != API_PORT);
    v.sort();
    v.dedup();
    v
}

/// Xray must not open connections to this server's own loopback (its control API has no password; the
/// panel and the other local services listen there) except to the ports its own config needs. A domain
/// that resolves to 127.0.0.1 gets past routing rules, so this is done by the kernel for the Xray service
/// only (its cgroup). Without iptables' cgroup match it stays with the routing rules. Blocking.
fn loopback_guard(config: Option<&Value>) {
    static WARNED: std::sync::Once = std::sync::Once::new();
    // only the loopback addresses: the server's public address also goes out on `lo` and stays as it was
    for (t, lo) in [("iptables", "127.0.0.0/8"), ("ip6tables", "::1/128")] {
        let unit_match = format!("-o lo -d {} -m cgroup --path system.slice/kanki-xray.service -m conntrack --ctstate NEW", lo);
        if !sh(&format!("command -v {} >/dev/null 2>&1", t)).0 {
            continue;
        }
        let jump = format!("{} -w -C OUTPUT {} -j {} 2>/dev/null", t, unit_match, LO_CHAIN);
        let Some(cfg) = config else {
            while sh(&jump).0 {
                let _ = sh(&format!("{} -w -D OUTPUT {} -j {}", t, unit_match, LO_CHAIN));
            }
            let _ = sh(&format!("{t} -w -F {c} 2>/dev/null; {t} -w -X {c} 2>/dev/null", t = t, c = LO_CHAIN));
            continue;
        };
        let _ = sh(&format!("{} -w -N {} 2>/dev/null", t, LO_CHAIN));
        let _ = sh(&format!("{} -w -F {}", t, LO_CHAIN));
        for p in loopback_ports(cfg) {
            let _ = sh(&format!("{t} -w -A {c} -p tcp --dport {p} -j RETURN; {t} -w -A {c} -p udp --dport {p} -j RETURN", t = t, c = LO_CHAIN, p = p));
        }
        let _ = sh(&format!("{} -w -A {} -j REJECT", t, LO_CHAIN));
        // the kernel ties the rule to the service's cgroup of that moment, and a restart makes a new one:
        // the jump is always put in again
        while sh(&jump).0 {
            let _ = sh(&format!("{} -w -D OUTPUT {} -j {}", t, unit_match, LO_CHAIN));
        }
        let (ok, out) = sh(&format!("{} -w -I OUTPUT {} -j {} 2>&1", t, unit_match, LO_CHAIN));
        if !ok {
            // no cgroup match here (or Xray is not running): nothing is blocked by the kernel, the
            // routing rules stay
            let _ = sh(&format!("{t} -w -F {c} 2>/dev/null; {t} -w -X {c} 2>/dev/null", t = t, c = LO_CHAIN));
            WARNED.call_once(|| eprintln!("xray: the kernel loopback guard is not available ({}); the routing rules still block 127.0.0.1", out.lines().last().unwrap_or("")));
        }
    }
    *guard_pid().lock().unwrap_or_else(|e| e.into_inner()) = if config.is_some() { xray_pid() } else { String::new() };
}

/// the Xray process the loopback guard was last set for
fn guard_pid() -> &'static Mutex<String> {
    static P: std::sync::OnceLock<Mutex<String>> = std::sync::OnceLock::new();
    P.get_or_init(|| Mutex::new(String::new()))
}

fn xray_pid() -> String {
    sh("systemctl show -p MainPID --value kanki-xray.service 2>/dev/null").1.trim().to_string()
}

/// Xray was restarted by systemd (a crash) since the guard was set: set it again for the new process
fn heal_loopback_guard(conf: &Value) {
    let pid = xray_pid();
    if pid.is_empty() || pid == "0" || conf.is_null() {
        return;
    }
    let last = guard_pid().lock().unwrap_or_else(|e| e.into_inner()).clone();
    if pid != last {
        loopback_guard(Some(conf));
    }
}

fn cert_domains_on_disk() -> Vec<String> {
    let conf: Value = std::fs::read_to_string(CONF_FILE).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or(Value::Null);
    let mut v = acme_domains(&conf);
    for d in std::fs::read_to_string(EXTRA_CERTS).unwrap_or_default().lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()) {
        if !v.contains(&d) {
            v.push(d);
        }
    }
    v
}

/// Domains whose certbot certificate the config needs: (domain, file)
fn acme_domains(config: &Value) -> Vec<String> {
    let mut v = vec![];
    for ib in config["inbounds"].as_array().into_iter().flatten() {
        for c in ib["streamSettings"]["tlsSettings"]["certificates"].as_array().into_iter().flatten() {
            if let Some(d) = c["certificateFile"].as_str().and_then(|f| f.strip_prefix("/etc/letsencrypt/live/")).and_then(|r| r.strip_suffix("/fullchain.pem")) {
                if !v.contains(&d.to_string()) {
                    v.push(d.to_string());
                }
            }
        }
    }
    v
}

fn cert_errors() -> &'static Mutex<HashMap<String, String>> {
    static E: std::sync::OnceLock<Mutex<HashMap<String, String>>> = std::sync::OnceLock::new();
    E.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Get the missing certificates; drop the inbounds whose certificate is still missing. true = some were dropped.
fn certs_for(config: &mut Value, extra: &[String]) -> bool {
    let mut domains = acme_domains(config);
    for d in extra {
        if !domains.contains(d) {
            domains.push(d.clone());
        }
    }
    if domains.is_empty() {
        cert_errors().lock().unwrap_or_else(|e| e.into_inner()).clear();
        return false;
    }
    // whatever holds port 80 (an Xray inbound too) is set aside for certbot and given back right after
    let mut errs = HashMap::new();
    for d in &domains {
        if let Err(e) = crate::certbot::ensure(d, &["kanki-xray.service"]) {
            errs.insert(d.clone(), e);
        }
    }
    let missing: Vec<String> = domains.into_iter().filter(|d| !crate::certbot::have(d)).collect();
    *cert_errors().lock().unwrap_or_else(|e| e.into_inner()) = errs;
    if missing.is_empty() {
        return false;
    }
    if let Some(a) = config["inbounds"].as_array_mut() {
        a.retain(|ib| {
            !ib["streamSettings"]["tlsSettings"]["certificates"].as_array().into_iter().flatten().any(|c| {
                c["certificateFile"].as_str().map(|f| missing.iter().any(|d| f == crate::certbot::files(d).0)).unwrap_or(false)
            })
        });
    }
    true
}

/// Traffic counted since this process started: user id -> bytes, inbound tag -> bytes
#[derive(Default)]
struct Counters {
    run: String,
    users: HashMap<i64, u64>,
    inbounds: HashMap<String, u64>,
    online: Vec<i64>,
}

fn counters() -> &'static Mutex<Counters> {
    static C: std::sync::OnceLock<Mutex<Counters>> = std::sync::OnceLock::new();
    C.get_or_init(|| Mutex::new(Counters { run: crate::util::rand_token(8), ..Default::default() }))
}

/// Read (and reset) Xray's counters into ours. Blocking.
fn collect() {
    if !std::path::Path::new(BIN).exists() {
        return;
    }
    let (ok, out) = sh(&format!("{} api statsquery --server=127.0.0.1:{} -reset 2>/dev/null", BIN, API_PORT));
    if !ok {
        return;
    }
    let v: Value = serde_json::from_str(&out).unwrap_or(Value::Null);
    let mut c = counters().lock().unwrap_or_else(|e| e.into_inner());
    let mut online = vec![];
    for s in v["stat"].as_array().into_iter().flatten() {
        let name = s["name"].as_str().unwrap_or("");
        let val = s["value"].as_u64().or_else(|| s["value"].as_str().and_then(|x| x.parse().ok())).unwrap_or(0);
        if val == 0 {
            continue;
        }
        let parts: Vec<&str> = name.split(">>>").collect();
        match parts.as_slice() {
            ["user", email, "traffic", _] => {
                if let Some(id) = email.strip_prefix('u').and_then(|x| x.parse::<i64>().ok()) {
                    *c.users.entry(id).or_default() += val;
                    if !online.contains(&id) {
                        online.push(id);
                    }
                }
            }
            ["inbound", tag, "traffic", _] if *tag != "api" => {
                *c.inbounds.entry(tag.to_string()).or_default() += val;
            }
            _ => {}
        }
    }
    c.online = online;
}

/// Restart Xray (if this server runs it), e.g. after the ports it needs were freed.
pub fn restart_if_installed() {
    if std::path::Path::new(UNIT).exists() {
        let _ = sh("systemctl restart kanki-xray.service");
    }
}

/// The ports the Xray inbounds listen on from outside ((port, udp)), from the running config.
pub fn needed_ports() -> Vec<(u16, bool)> {
    let conf: Value = std::fs::read_to_string(CONF_FILE).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or(Value::Null);
    let mut v: Vec<(u16, bool)> = conf["inbounds"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|ib| !matches!(ib["listen"].as_str(), Some("127.0.0.1") | Some("::1") | Some("localhost")))
        .filter_map(|ib| ib["port"].as_u64().filter(|p| *p > 0 && *p < 65536).map(|p| (p as u16, false)))
        .collect();
    v.sort();
    v.dedup();
    v
}

/// What the agent reports about Xray on this server (Null = not installed here). Blocking.
pub fn status() -> Value {
    if !std::path::Path::new(UNIT).exists() {
        return Value::Null;
    }
    let active = sh("systemctl is-active --quiet kanki-xray.service").0;
    if active {
        collect();
    }
    let c = counters().lock().unwrap_or_else(|e| e.into_inner());
    let users: serde_json::Map<String, Value> = c.users.iter().map(|(k, v)| (k.to_string(), json!([v]))).collect();
    let conf: Value = std::fs::read_to_string(CONF_FILE).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or(Value::Null);
    if active {
        heal_loopback_guard(&conf);
    }
    let mut certs: Vec<String> = acme_domains(&conf).into_iter().filter(|d| crate::certbot::have(d)).collect();
    certs.extend(std::fs::read_to_string(EXTRA_CERTS).unwrap_or_default().lines().map(|l| l.trim().to_string()).filter(|d| !d.is_empty() && crate::certbot::have(d)));
    certs.extend(cert_errors().lock().unwrap_or_else(|e| e.into_inner()).keys().filter(|d| crate::certbot::have(d)).cloned());
    certs.sort();
    certs.dedup();
    let mut st = json!({
        "active": active, "run": c.run, "users": users, "inbounds": c.inbounds, "online": c.online,
        "ver": applied_ver(), "core": std::fs::read_to_string(BIN_VER_FILE).unwrap_or_default().trim(),
        "certs": certs, "cert_errors": cert_errors().lock().unwrap_or_else(|e| e.into_inner()).clone(),
        // inbound ports that another program holds
        "taken": crate::certbot::taken_json(&crate::certbot::taken_cached(&needed_ports(), "kanki-xray.service")),
    });
    if !active {
        st["error"] = json!(sh("journalctl -u kanki-xray.service -n 5 --no-pager -o cat 2>/dev/null").1.lines().last().unwrap_or("not running").to_string());
    }
    st
}

#[cfg(test)]
mod loopback_tests {
    #[test]
    fn the_ports_the_config_needs_stay_open() {
        let c = serde_json::json!({
            "inbounds": [{ "settings": { "fallbacks": [{ "dest": 8080 }, { "dest": "127.0.0.1:2002" }, { "dest": "80" }, { "dest": "1.2.3.4:443" }, { "dest": 10085 }] } }],
            "outbounds": [{ "settings": { "servers": [{ "address": "127.0.0.1", "port": 1080 }, { "address": "8.8.8.8", "port": 9 }] } }, { "settings": { "redirect": "127.0.0.1:7000" } }],
            "dns": { "servers": ["1.1.1.1", "127.0.0.1:5353", "https://localhost:8053/dns-query", { "address": "127.0.0.1", "port": 5300 }, "https://dns.google/dns-query"] }
        });
        // the API port never, an outside address never
        assert_eq!(super::loopback_ports(&c), vec![53, 80, 1080, 2002, 5300, 5353, 7000, 8053, 8080]);
    }
}
