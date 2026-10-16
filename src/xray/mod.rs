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
        "set -e; T=$(mktemp -d); trap 'rm -rf \"$T\"' EXIT; \
         (curl -fsSL --max-time 300 -o \"$T/x.zip\" {direct}{via_panel}); \
         if command -v unzip >/dev/null 2>&1; then unzip -o -q \"$T/x.zip\" -d \"$T/x\"; \
         else python3 -c 'import zipfile,sys; zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])' \"$T/x.zip\" \"$T/x\"; fi; \
         test -s \"$T/x/xray\"; \"$T/x/xray\" version >/dev/null; \
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
pub fn deploy(cfg: Option<(&XrayCfg, &str)>, panel: Option<(&str, &str, &str)>) -> Result<(), String> {
    let Some((c, ver)) = cfg else {
        if std::path::Path::new(UNIT).exists() {
            eprintln!("xray: stopping");
            let _ = sh("systemctl disable --now -q kanki-xray.service 2>&1");
            let _ = std::fs::remove_file(UNIT);
            let _ = sh("systemctl daemon-reload");
        }
        let _ = std::fs::remove_file(CONF_FILE);
        let _ = std::fs::remove_file(VER_FILE);
        return Ok(());
    };
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
    let unit_changed = std::fs::read_to_string(UNIT).map(|t| t != unit).unwrap_or(true);
    if unit_changed {
        std::fs::write(UNIT, &unit).map_err(|e| format!("cannot write {}: {}", UNIT, e))?;
        let _ = sh("systemctl daemon-reload");
        let _ = sh("systemctl enable -q kanki-xray.service");
    }
    let active = sh("systemctl is-active --quiet kanki-xray.service").0;
    if changed || unit_changed || !active {
        // the traffic not read yet would be lost with the restart
        collect();
        let (ok, out) = sh("systemctl restart kanki-xray.service 2>&1");
        if !ok {
            return Err(format!("systemctl restart kanki-xray: {}", out.lines().last().unwrap_or("")));
        }
        eprintln!("xray: (re)started");
    }
    if sh("ufw status 2>/dev/null | grep -q 'Status: active'").0 {
        for ib in c.config["inbounds"].as_array().into_iter().flatten() {
            if let Some(p) = ib["port"].as_u64() {
                if ib["listen"].as_str() != Some("127.0.0.1") {
                    let _ = sh(&format!("ufw allow {}/tcp >/dev/null 2>&1; ufw allow {}/udp >/dev/null 2>&1", p, p));
                }
            }
        }
    }
    // missing certificates: deploy again on the next round (certbot waits 10 minutes after a failure)
    let _ = std::fs::write(VER_FILE, if partial { format!("{}-nocert", ver) } else { ver.to_string() });
    Ok(())
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
        cert_errors().lock().unwrap().clear();
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
    *cert_errors().lock().unwrap() = errs;
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
    let mut c = counters().lock().unwrap();
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

/// What the agent reports about Xray on this server (Null = not installed here). Blocking.
pub fn status() -> Value {
    if !std::path::Path::new(UNIT).exists() {
        return Value::Null;
    }
    let active = sh("systemctl is-active --quiet kanki-xray.service").0;
    if active {
        collect();
    }
    let c = counters().lock().unwrap();
    let users: serde_json::Map<String, Value> = c.users.iter().map(|(k, v)| (k.to_string(), json!([v]))).collect();
    let conf: Value = std::fs::read_to_string(CONF_FILE).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or(Value::Null);
    let mut certs: Vec<String> = acme_domains(&conf).into_iter().filter(|d| crate::certbot::have(d)).collect();
    certs.extend(std::fs::read_to_string(EXTRA_CERTS).unwrap_or_default().lines().map(|l| l.trim().to_string()).filter(|d| !d.is_empty() && crate::certbot::have(d)));
    certs.extend(cert_errors().lock().unwrap().keys().filter(|d| crate::certbot::have(d)).cloned());
    certs.sort();
    certs.dedup();
    let mut st = json!({
        "active": active, "run": c.run, "users": users, "inbounds": c.inbounds, "online": c.online,
        "ver": applied_ver(), "core": std::fs::read_to_string(BIN_VER_FILE).unwrap_or_default().trim(),
        "certs": certs, "cert_errors": cert_errors().lock().unwrap().clone(),
    });
    if !active {
        st["error"] = json!(sh("journalctl -u kanki-xray.service -n 5 --no-pager -o cat 2>/dev/null").1.lines().last().unwrap_or("not running").to_string());
    }
    st
}
