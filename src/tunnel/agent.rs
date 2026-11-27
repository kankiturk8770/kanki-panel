//! The tunnel agent: runs on a server that only carries tunnels (for example the Iran server).
//! No VPN is installed there. Every 5 seconds it tells the panel how its tunnels are doing and
//! gets the list of tunnels it should run. The last list is kept on disk, so the tunnels keep
//! working after a reboot even if the panel cannot be reached.

use super::engine::{parse_ports, Manager, Spec};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub const ENV_FILE: &str = "/etc/kanki/tunnel.env";
const CACHE: &str = "/var/lib/kanki/tunnels.json";
/// TOFU pin of the panel's certificate for INSECURE installs (see `panel_client`)
pub const PIN_FILE: &str = "/etc/kanki/panel.pin";

/// The panel's addresses the panel itself named: its own and the CDN one(s) (`cdn.rs`), kept for when it
/// cannot be reached
const ALT_FILE: &str = "/etc/kanki/panel.alt";

/// 3.69: what this agent learned about signing, kept across restarts (a restart must not reopen the fallback):
/// `signed_ok` = the panel took a signed report (the bare token is never sent with a report again);
/// `panel_signs` = the panel signs its answers (from then on an unsigned or wrongly signed answer is refused,
/// and the token never goes in a body again)
const SIG_STATE: &str = "/var/lib/kanki/agent-sig.json";

#[derive(serde::Serialize, serde::Deserialize, Default, Clone, Copy, Debug, PartialEq)]
#[serde(default)]
pub struct SigState {
    pub signed_ok: bool,
    pub panel_signs: bool,
}

fn sig_cell() -> &'static Mutex<Option<SigState>> {
    static S: Mutex<Option<SigState>> = Mutex::new(None);
    &S
}

pub fn sig_state() -> SigState {
    let mut g = sig_cell().lock().unwrap_or_else(|e| e.into_inner());
    *g.get_or_insert_with(|| std::fs::read_to_string(SIG_STATE).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default())
}

/// Moves the ratchet forward (never back) and keeps it on disk
fn raise_sig_state(f: impl Fn(&mut SigState)) {
    let mut g = sig_cell().lock().unwrap_or_else(|e| e.into_inner());
    let mut st = g.unwrap_or_else(|| std::fs::read_to_string(SIG_STATE).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default());
    let before = st;
    f(&mut st);
    st.signed_ok |= before.signed_ok;
    st.panel_signs |= before.panel_signs;
    *g = Some(st);
    if st != before {
        if let Err(e) = crate::util::write_private(SIG_STATE, &serde_json::to_string(&st).unwrap_or_default()) {
            eprintln!("agent: {} could not be written: {}", SIG_STATE, e);
        }
    }
}

/// 3.69: the body and signature headers of a download request to the panel (`path`): `fields` plus the server id;
/// the token goes in the body only to a panel not yet known to sign its answers (an older one reads only that)
pub fn signed_body(id: &str, token: &str, path: &str, fields: Value) -> (Vec<u8>, Vec<(&'static str, String)>) {
    let mut b = if fields.is_object() { fields } else { json!({}) };
    b["id"] = json!(id);
    if !sig_state().panel_signs {
        b["token"] = json!(token);
    }
    let raw = serde_json::to_vec(&b).unwrap_or_default();
    let headers = crate::sign::headers(token, "POST", path, &raw);
    (raw, headers)
}

/// 3.69: an answer of the panel to a signed request: a signed one must check out (and teaches the agent that the
/// panel signs); an unsigned one is taken only from a panel never seen signing
pub fn check_reply(token: &str, nonce: &str, h: &reqwest::header::HeaderMap, status: u16, body: &[u8]) -> Result<(), String> {
    if crate::sign::reply_signed(h) {
        crate::sign::verify_reply(token, nonce, h, status, body, crate::util::now()).map_err(|r| format!("the panel's answer: {}", r.text()))?;
        if !sig_state().panel_signs {
            eprintln!("the panel signs its answers: unsigned ones are refused from now on");
            raise_sig_state(|s| s.panel_signs = true);
        }
        return Ok(());
    }
    if sig_state().panel_signs {
        return Err("the panel's answer is not signed (the panel signed before): refused".into());
    }
    Ok(())
}

/// The address the agent talks to the panel through right now, and whether it is a CDN one
static NOW: Mutex<Option<(String, bool)>> = Mutex::new(None);

/// (address, through a CDN) the agent uses now; None outside the tunnel agent
pub fn panel_now() -> Option<(String, bool)> {
    NOW.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

fn good_url(u: &str) -> bool {
    u.starts_with("https://") && u.len() <= 200 && u[8..].bytes().all(|c| c.is_ascii_alphanumeric() || b".-:[]".contains(&c))
}

/// What the panel named: (its own address, its CDN addresses)
fn named(v: &Value) -> (String, Vec<String>) {
    let main = v["panel"].as_str().map(|s| s.trim().trim_end_matches('/').to_string()).filter(|s| good_url(s)).unwrap_or_default();
    let alt = v["panel_alt"].as_array().into_iter().flatten().filter_map(|x| x.as_str()).map(|s| s.trim().trim_end_matches('/').to_string()).filter(|s| good_url(s)).take(3).collect();
    (main, alt)
}

fn load_named() -> (String, Vec<String>) {
    std::fs::read_to_string(ALT_FILE).ok().and_then(|t| serde_json::from_str::<Value>(&t).ok()).map(|v| named(&v)).unwrap_or_default()
}

fn save_named(main: &str, alt: &[String]) {
    let _ = std::fs::write(ALT_FILE, json!({ "panel": main, "panel_alt": alt }).to_string());
}

/// The addresses to try, in order: the panel's own (as it named it, then as installed here), then the CDN
/// ones. A CDN address is checked against the public CAs only (never pinned: the CDN's certificate is not the
/// panel's).
fn candidates(env_url: &str, main: &str, alt: &[String]) -> Vec<(String, bool)> {
    let mut v: Vec<(String, bool)> = vec![];
    for u in [main, env_url].into_iter().chain(alt.iter().map(|s| s.as_str())) {
        let u = u.trim().trim_end_matches('/');
        if !u.is_empty() && !v.iter().any(|x| x.0 == u) {
            v.push((u.to_string(), alt.iter().any(|a| a == u)));
        }
    }
    v
}

/// The HTTP client for talking to the panel. With INSECURE=1 (the agent's curl could not verify
/// the panel: old CA bundle, IP address, filtering) the certificate is still CA-checked first
/// with built-in roots; when that fails it is pinned instead: the first certificate seen is
/// stored in /etc/kanki/panel.pin and any later change is refused (a MITM cannot keep
/// impersonating the panel after first contact). For zero first-contact trust, copy the pin
/// file to the server by hand.
pub fn panel_client(insecure: bool, timeout: Duration) -> reqwest::Client {
    if insecure {
        crate::pin::pinned_client(std::path::Path::new(PIN_FILE), timeout)
    } else {
        // one kept-alive connection carries every report (no new TCP and TLS handshake each 5 seconds)
        reqwest::Client::builder()
            .timeout(timeout)
            .connect_timeout(crate::pin::CONNECT_TIMEOUT)
            .pool_idle_timeout(crate::pin::POOL_IDLE)
            .tcp_keepalive(crate::pin::TCP_KEEPALIVE)
            .build()
            .expect("http")
    }
}

/// Opens the ports the tunnels listen on in ufw (when ufw is on) and closes the ones of tunnels that
/// were deleted or changed (see `fw`). Blocking.
pub fn open_ports(specs: &[Spec]) {
    let mut want = vec![];
    for s in specs {
        if let Some(a) = &s.awg {
            if a.open_udp > 0 {
                want.push(format!("{}/udp", a.open_udp));
            }
            if a.role == "entry" {
                for (p, _) in parse_ports(&a.fwd_tcp) {
                    want.push(format!("{}/tcp", p));
                }
                for (p, _) in parse_ports(&a.fwd_udp) {
                    want.push(format!("{}/udp", p));
                }
            }
            continue;
        }
        if let Some(y) = &s.hy2 {
            if y.role == "exit" && y.listen > 0 {
                want.push(format!("{}/udp", y.listen));
            } else {
                for (p, _) in parse_ports(&y.fwd_tcp) {
                    want.push(format!("{}/tcp", p));
                }
                for (p, _) in parse_ports(&y.fwd_udp) {
                    want.push(format!("{}/udp", p));
                }
            }
            continue;
        }
        // KANKI-UP: the users' UDP ports of the entry. The exit's raw ports stay closed on purpose: udp2raw
        // reads them before the firewall, and an open one would let the kernel answer (RST / unreachable)
        if let Some(k) = &s.kup {
            for w in k {
                if w.role == "entry" {
                    // the measuring pair listens on 127.0.0.1 only: nothing to open
                    if !w.probe {
                        want.push(format!("{}/udp", w.listen));
                    }
                } else if w.cfg.easy() {
                    // easy-faketcp: the kernel's own TCP connection, so its port is opened like any listener
                    want.push(format!("{}/tcp", w.listen));
                }
            }
            continue;
        }
        // a smart-test tunnel: its port, TCP and UDP, on both servers while the test runs (the panel's firewall
        // may be on everywhere); the test's tunnels go when it ends and `fw::sync` closes the port again
        if s.probe && s.port > 0 {
            want.push(format!("{}/tcp", s.port));
            want.push(format!("{}/udp", s.port));
            continue;
        }
        if s.listens() && s.port > 0 {
            // quic, kcp, hq and game run over UDP; dual listens on UDP and TCP of the same number;
            // faketcp's packets are TCP on the wire
            let protos: &[&str] = match s.transport.as_str() {
                "quic" | "kcp" | "hq" | "game" => &["udp"],
                "dual" => &["tcp", "udp"],
                _ => &["tcp"],
            };
            for proto in protos {
                want.push(format!("{}/{}", s.port, proto));
            }
        }
        // a tunnel that takes its users' ports on 127.0.0.1 only (a core of this machine behind it)
        if s.role == "entry" && !s.bind.trim().starts_with("127.") {
            for (a, _) in parse_ports(&s.tcp) {
                want.push(format!("{}/tcp", a));
            }
            for (a, _) in parse_ports(&s.udp) {
                want.push(format!("{}/udp", a));
            }
        }
    }
    crate::fw::sync("tunnels", want);
}

// ------------------------------------------------------------------ installing the VPN part (asked in the panel)

const SETUP_DIR: &str = "/var/lib/kanki";

fn setup_file(name: &str) -> String {
    format!("{}/setup.{}", SETUP_DIR, name)
}

/// The VPN install the panel asked for: {req, state: running|done|failed, code, tail} (Null = none)
pub fn setup_status() -> Value {
    let Ok(t) = std::fs::read_to_string(setup_file("json")) else { return Value::Null };
    let mut v: Value = serde_json::from_str(&t).unwrap_or(Value::Null);
    if !v.is_object() {
        return Value::Null;
    }
    let log = std::fs::read_to_string(setup_file("log")).unwrap_or_default();
    // colours of the installer out, the last lines in
    let clean: String = log.replace("\u{1b}[1;33m", "").replace("\u{1b}[1;31m", "").replace("\u{1b}[1;32m", "").replace("\u{1b}[1;36m", "").replace("\u{1b}[0m", "");
    let lines: Vec<&str> = clean.lines().filter(|l| !l.trim().is_empty()).collect();
    v["tail"] = json!(lines[lines.len().saturating_sub(12)..].join("\n"));
    match std::fs::read_to_string(setup_file("exit")).ok().and_then(|c| c.trim().parse::<i32>().ok()) {
        Some(0) => v["state"] = json!("done"),
        Some(c) => {
            v["state"] = json!("failed");
            v["code"] = json!(c);
        }
        None => {
            // still running, unless it was cut off (a reboot) long ago
            let started = v["started"].as_i64().unwrap_or(0);
            v["state"] = json!(if crate::util::now() - started > 3600 { "failed" } else { "running" });
        }
    }
    v
}

/// Runs the installer of this very program for the VPN part of this server (WireGuard, AmneziaWG,
/// Hysteria2, KANKI MIX and the node agent), the way the panel asked. It runs as its own systemd
/// unit, so a restart of this agent does not cut it off. Blocking, returns at once.
fn start_setup(cfg: &Value) -> Result<(), String> {
    let req = cfg["req"].as_i64().unwrap_or(0);
    let s = |k: &str| cfg[k].as_str().unwrap_or("").trim().to_string();
    let (panel, join, ports, domain, repo) = (s("panel"), s("join"), s("ports"), s("domain"), s("repo"));
    let safe = |v: &str, extra: &[u8]| v.bytes().all(|c| c.is_ascii_alphanumeric() || extra.contains(&c));
    if req == 0 || join.len() < 20 || !safe(&join, b"") {
        return Err("bad request".into());
    }
    if !panel.starts_with("https://") || !safe(&panel, b":/.-_[]") {
        return Err("bad panel address".into());
    }
    if !safe(&ports, b",") || !safe(&domain, b".-") || !safe(&repo, b"/.-_") {
        return Err("bad request".into());
    }
    // the same request is started once
    if let Ok(t) = std::fs::read_to_string(setup_file("json")) {
        if serde_json::from_str::<Value>(&t).ok().and_then(|v| v["req"].as_i64()) == Some(req) {
            return Ok(());
        }
    }
    let _ = std::fs::create_dir_all(SETUP_DIR);
    let script = setup_file("sh");
    std::fs::write(&script, crate::servers::INSTALL_SH).map_err(|e| e.to_string())?;
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700));
    }
    let _ = std::fs::remove_file(setup_file("exit"));
    let _ = std::fs::write(setup_file("log"), "");
    let _ = std::fs::write(setup_file("json"), json!({ "req": req, "started": crate::util::now() }).to_string());
    let mut env = format!("KANKI_PANEL='{}' KANKI_JOIN='{}' KANKI_PORTS='{}' KANKI_LOCAL_BIN=1", panel, join, ports);
    if !domain.is_empty() {
        env.push_str(&format!(" KANKI_DOMAIN='{}'", domain));
    }
    if !repo.is_empty() {
        env.push_str(&format!(" KANKI_REPO='{}'", repo));
    }
    let inner = format!("{} bash {} > {} 2>&1 < /dev/null; echo $? > {}", env, script, setup_file("log"), setup_file("exit"));
    let unit = format!("kanki-setup-{}", req);
    let ok = std::process::Command::new("systemd-run")
        .args(["--unit", &unit, "--collect", "--quiet", "/bin/sh", "-c", &inner])
        .stdin(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !ok {
        // no systemd-run: a detached shell
        std::process::Command::new("setsid")
            .args(["-f", "/bin/sh", "-c", &inner])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(|e| e.to_string())?;
    }
    eprintln!("installing the VPN part of this server, as the panel asked ({})", setup_file("log"));
    Ok(())
}

/// This server was removed from the panel: close the ports Kanki opened, then remove the tunnel agent
/// itself (its service, settings and saved tunnels). The program file stays when the panel or a VPN
/// node of the same machine still uses it. Blocking; does not return when systemd stops the agent.
fn uninstall_self() {
    crate::fw::close_all();
    let sh = |c: &str| {
        let _ = std::process::Command::new("sh").arg("-c").arg(c).stdin(std::process::Stdio::null()).status();
    };
    let _ = std::fs::remove_file(ENV_FILE);
    let _ = std::fs::remove_file(PIN_FILE);
    let _ = std::fs::remove_file("/var/lib/kanki/subsrv.json");
    let _ = std::fs::remove_file("/etc/sysctl.d/90-kanki-tunnel.conf");
    let _ = std::fs::remove_file(CACHE);
    eprintln!("removed from the panel: the tunnel agent uninstalls itself");
    sh("systemctl disable -q kanki-tunnel.service 2>/dev/null; rm -f /etc/systemd/system/kanki-tunnel.service; systemctl daemon-reload");
    // the VPN part of this machine (when it is still here) takes the rest when it goes
    crate::admin::wipe_all_if_last();
    sh("systemctl stop kanki-tunnel.service");
    std::process::exit(0);
}

/// Downloads the panel's own binary (same file, same machine type), checks its sha256, swaps it in
/// and exits; systemd starts the new one. Used when the panel asks for an update (Update all).
async fn update_from_panel(http: &reqwest::Client, panel: &str, id: &str, token: &str) -> Result<(), String> {
    let path = crate::tunnel::panel::BINARY_PATH;
    let (raw, hs) = signed_body(id, token, path, json!({ "arch": std::env::consts::ARCH }));
    let nonce = hs.iter().find(|(k, _)| *k == crate::sign::NONCE).map(|(_, v)| v.clone()).unwrap_or_default();
    let rb = hs.into_iter().fold(http.post(format!("{}{}", panel, path)).header(reqwest::header::CONTENT_TYPE, "application/json").body(raw), |rb, (k, v)| rb.header(k, v));
    let r = rb.timeout(Duration::from_secs(300)).send().await.map_err(|e| crate::pin::error_text(&e))?;
    if !r.status().is_success() {
        return Err(format!("the panel answered {}", r.status()));
    }
    let (status, rh) = (r.status().as_u16(), r.headers().clone());
    let want = r.headers().get("x-sha256").and_then(|v| v.to_str().ok()).unwrap_or("").to_lowercase();
    // 3.69: the release signature of the program (base64 of its .minisig), checked with the key built into this
    // agent before the file is ever started; a panel without one (installed by hand, an older one) is refused
    let sig = r.headers().get("x-minisig").and_then(|v| v.to_str().ok()).and_then(crate::tunnel::link::b64decode).map(|b| String::from_utf8_lossy(&b).to_string());
    let bytes = r.bytes().await.map_err(|e| e.to_string())?;
    check_reply(token, &nonce, &rh, status, &bytes)?;
    if want.is_empty() || !crate::release::matches(&bytes, &want) {
        return Err("checksum mismatch, update aborted".into());
    }
    let sig = sig.ok_or("the panel sent no release signature: update aborted (update the panel first, or this server by hand)")?;
    let v = crate::release::verify_update(&bytes, &sig).map_err(|e| format!("signature check failed, update aborted: {}", e))?;
    if v.version().is_some_and(|sv| crate::admin::newer(crate::VERSION, &sv)) {
        return Err("the panel's program is older than this one: not installed".into());
    }
    let path = crate::util::exe_path().map_err(|e| e.to_string())?;
    // off the async workers: they carry the tunnels while the new file is written and test-run
    tokio::task::spawn_blocking(move || crate::util::swap_program(&path, &bytes)).await.map_err(|e| e.to_string())??;
    if let Err(e) = crate::release::save_own_signature(&sig) {
        eprintln!("update: {}", e);
    }
    crate::util::restart_siblings();
    eprintln!("updated from the panel: restarting");
    std::process::exit(0);
}

/// 3.58.1: a relay of the first versions ran as a service of its own (`kanki-relay`); a leftover one only holds a
/// port open: stopped, removed, and its port taken off the firewall
fn drop_old_relay() {
    let unit = "/etc/systemd/system/kanki-relay.service";
    if !std::path::Path::new(unit).exists() {
        return;
    }
    // the ports it listened on (":44330" in its command line), to close once it is gone
    let text = std::fs::read_to_string(unit).unwrap_or_default();
    let ports: Vec<String> = text.split(':').skip(1).filter_map(|x| x.split(|c: char| !c.is_ascii_digit()).next()?.parse::<u16>().ok())
        .filter(|p| *p >= 1024).map(|p| format!("{}/udp", p)).collect();
    let run = |c: &str| { let _ = std::process::Command::new("sh").arg("-c").arg(c).stdin(std::process::Stdio::null()).output(); };
    run("systemctl disable --now kanki-relay.service >/dev/null 2>&1");
    let _ = std::fs::remove_file(unit);
    run("systemctl daemon-reload >/dev/null 2>&1");
    crate::fw::close("kanki-relay");
    crate::fw::close_unused(&ports);
    eprintln!("removed the old kanki-relay service");
}

pub async fn run(version: &str) {
    let env = crate::util::load_env(ENV_FILE);
    let panel = env.get("PANEL_URL").cloned().unwrap_or_default().trim_end_matches('/').to_string();
    let id = env.get("AGENT_ID").cloned().unwrap_or_default();
    let token = env.get("AGENT_TOKEN").cloned().unwrap_or_default();
    let insecure = env.get("INSECURE").map(|v| v == "1").unwrap_or(false);
    if panel.is_empty() || id.is_empty() || token.is_empty() {
        eprintln!("{} is missing PANEL_URL / AGENT_ID / AGENT_TOKEN. Copy the command from the panel (Tunnels > Add server).", ENV_FILE);
        std::process::exit(1);
    }
    eprintln!("kanki tunnel agent {} for {} (server {})", version, panel, id);
    tokio::task::spawn_blocking(drop_old_relay);
    let mgr = Arc::new(Manager::default());
    let mut last = String::new();
    if let Ok(t) = std::fs::read_to_string(CACHE) {
        if let Ok(specs) = serde_json::from_str::<Vec<Spec>>(&t) {
            eprintln!("starting {} saved tunnel(s)", specs.len());
            let ps = specs.clone();
            mgr.apply(specs).await;
            let _ = tokio::task::spawn_blocking(move || open_ports(&ps)).await;
            last = t;
        }
    }
    // 3.69: the panel's certificate key from the join command (PANEL_PIN=ca:sha256//… | self:sha256//…) is the
    // pin from the very first contact (no trust on first use); a pin file already there (renewals) is kept
    let given = env.get("PANEL_PIN").map(|s| s.trim().to_string()).unwrap_or_default();
    if let Some((mode, pin)) = given.split_once(':') {
        if !std::path::Path::new(PIN_FILE).exists() {
            match crate::pin::preset(std::path::Path::new(PIN_FILE), pin, mode == "ca") {
                Ok(()) => eprintln!("the panel's certificate key from the join command is pinned ({})", PIN_FILE),
                Err(e) => eprintln!("PANEL_PIN in {}: {}", ENV_FILE, e),
            }
        }
    }
    // INSECURE=1: a CA-valid certificate is still accepted (and re-pinned), anything else is
    // pinned on first contact (see `panel_client`)
    if insecure {
        eprintln!("warning: INSECURE=1 — a panel certificate that is not CA-valid will be pinned on first contact ({})", PIN_FILE);
    }
    let http = panel_client(insecure, Duration::from_secs(20));
    // the CDN addresses: CA-checked only
    let http_ca = panel_client(false, Duration::from_secs(20));
    let (mut main_named, mut alt_named) = load_named();
    let mut cands = candidates(&panel, &main_named, &alt_named);
    let mut idx = 0usize;
    // reports in a row that did not reach the panel through the address in use
    let mut miss = 0u32;
    let mut probe_at = std::time::Instant::now();
    let _ = tokio::task::spawn_blocking(crate::dns::restart_if_outdated).await;
    // 3.57.0: the VIP tunnel is gone; what an older agent left behind goes too
    let _ = tokio::task::spawn_blocking(retire_vip).await;
    // certificates close to their end are renewed with what holds port 80 at that moment
    crate::certbot::renew_loop();
    let mut fails = 0u32;
    // a failed update is tried again after a minute, not on every report (it downloads the whole program)
    let mut update_tried: Option<std::time::Instant> = None;
    // answers in a row that say this server was removed from the panel
    let mut gone = 0u32;
    let (mut stats, mut stats_at) = (serde_json::Value::Null, std::time::Instant::now());
    // the first report already carries the logs
    let mut logs_at = std::time::Instant::now().checked_sub(std::time::Duration::from_secs(120)).unwrap_or_else(std::time::Instant::now);
    // the last error of setting up Kanki DNS
    let dns_err: Mutex<Option<String>> = Mutex::new(None);
    // the last error of setting up Xray
    let xray_err: Mutex<Option<String>> = Mutex::new(None);
    // the subscription's HTTPS listener (when this Iran server serves it)
    let mut subsrv = crate::subiran::Runner::from_disk();
    // the panel took a signed report (it never gets the bare token again) / it is older (since when). 3.69: kept
    // on disk, so a restart does not send the token again
    let mut signed_ok = sig_state().signed_ok;
    let (mut listen, mut listen_at) = (serde_json::Value::Null, std::time::Instant::now());
    let mut panel_old: Option<std::time::Instant> = None;
    loop {
        let st = mgr.statuses().await;
        let (dns_ver, mut dns_st) = tokio::task::spawn_blocking(|| (crate::dns::applied_ver(), crate::dns::status())).await.unwrap_or_default();
        if let Some(e) = dns_err.lock().unwrap_or_else(|e| e.into_inner()).clone() {
            if dns_st.is_object() {
                dns_st["deploy_error"] = json!(e);
            } else {
                dns_st = json!({ "active": false, "deploy_error": e });
            }
        }
        let (xray_ver, mut xray_st) = tokio::task::spawn_blocking(|| (crate::xray::applied_ver(), crate::xray::status())).await.unwrap_or_default();
        if let Some(e) = xray_err.lock().unwrap_or_else(|e| e.into_inner()).clone() {
            if xray_st.is_object() {
                xray_st["deploy_error"] = json!(e);
            } else {
                xray_st = json!({ "active": false, "deploy_error": e });
            }
        }
        let fw_st = tokio::task::spawn_blocking(crate::fw::report).await.unwrap_or_default();
        // what listens here changes rarely: read every 15 seconds, not on every report
        if listen_at.elapsed() >= Duration::from_secs(15) || listen.is_null() {
            listen = tokio::task::spawn_blocking(crate::certbot::listeners_json).await.unwrap_or_default();
            listen_at = std::time::Instant::now();
        }
        let setup_st = tokio::task::spawn_blocking(setup_status).await.unwrap_or_default();
        // the machine (CPU, memory, disk, uptime, sockets) every 30 seconds: Iran servers have no VPN part
        // that reports it
        if stats_at.elapsed() >= std::time::Duration::from_secs(30) || stats.is_null() {
            stats = tokio::task::spawn_blocking(crate::admin::node_stats).await.unwrap_or_default();
            stats_at = std::time::Instant::now();
        }
        // signed with the token (3.65); the bare token goes along only to a panel from before (`panel_old`)
        if panel_old.is_some_and(|t| t.elapsed() >= Duration::from_secs(600)) {
            panel_old = None;
        }
        let mut body = json!({ "id": id, "version": version, "status": st, "dns_ver": dns_ver, "dns": dns_st, "xray_ver": xray_ver, "xray": xray_st, "subsrv": subsrv.status(), "fw": fw_st, "listen": listen, "setup": setup_st, "stats": stats });
        // the last warnings and errors of Kanki's services here, once a minute, for the panel's Logs page (3.58.1)
        if logs_at.elapsed() >= std::time::Duration::from_secs(60) {
            logs_at = std::time::Instant::now();
            let units: Vec<String> = ["kanki-tunnel", "kanki-node", "kanki-mix", "hysteria-server", "wg-quick@wg0", "awg-quick@awg0"].iter().map(|u| u.to_string()).collect();
            body["logs"] = json!(tokio::task::spawn_blocking(move || crate::admin::journal(&units, 40, true)).await.unwrap_or_default());
        }
        if panel_old.is_some() {
            body["token"] = json!(token);
        }
        let raw = serde_json::to_vec(&body).unwrap_or_default();
        let post = |c: &reqwest::Client, base: &str| {
            let rb = c.post(format!("{}{}", base, crate::tunnel::panel::REPORT_PATH)).header(reqwest::header::CONTENT_TYPE, "application/json").body(raw.clone());
            crate::sign::sign_nonce(rb, &token, "POST", crate::tunnel::panel::REPORT_PATH, &raw)
        };
        // on another address: the first one is tried again every five minutes, with a short wait
        let mut early = None;
        if idx != 0 && probe_at.elapsed() >= Duration::from_secs(300) {
            probe_at = std::time::Instant::now();
            let (b0, a0) = &cands[0];
            let (rb, n0) = post(if *a0 { &http_ca } else { &http }, b0);
            if let Ok(r) = rb.timeout(Duration::from_secs(8)).send().await {
                if r.status().is_success() {
                    eprintln!("the panel answers at {} again", b0);
                    idx = 0;
                    miss = 0;
                    early = Some((Ok(r), n0));
                }
            }
        }
        let (base, alt) = cands[idx].clone();
        *NOW.lock().unwrap_or_else(|e| e.into_inner()) = Some((base.clone(), alt));
        let http = if alt { &http_ca } else { &http };
        let (res, nonce) = match early {
            Some(r) => r,
            None => {
                let (rb, n) = post(http, &base);
                (rb.send().await, n)
            }
        };
        // a panel from before 3.65 does not read the signature and wants the token: it goes along for ten
        // minutes, then a signed report alone is tried again. Once a signed report alone was taken, the
        // token never goes again.
        match &res {
            Ok(r) if r.status() == reqwest::StatusCode::FORBIDDEN && panel_old.is_none() && !signed_ok => {
                eprintln!("the panel did not take the signed report: it is older, the token goes along for now");
                panel_old = Some(std::time::Instant::now());
            }
            Ok(r) if r.status().is_success() && panel_old.is_none() && !signed_ok => {
                signed_ok = true;
                raise_sig_state(|s| s.signed_ok = true);
            }
            _ => {}
        }
        let reached = matches!(&res, Ok(r) if r.status().is_success() || r.status().as_u16() == 410);
        if reached {
            miss = 0;
        } else {
            miss += 1;
            // three reports (15 seconds and more) without the panel: the next address
            if miss >= 3 && cands.len() > 1 {
                idx = (idx + 1) % cands.len();
                miss = 0;
                probe_at = std::time::Instant::now();
                eprintln!("cannot reach the panel at {}: trying {}", base, cands[idx].0);
            }
        }
        match res {
            Ok(r) if r.status().as_u16() == 410 => {
                // this server was removed in the panel: everything Kanki put here is removed (a few
                // answers in a row, so one odd answer does not wipe a working server). 3.69: from a panel that
                // signs, only a signed «gone» counts
                let rh = r.headers().clone();
                let b = r.bytes().await.unwrap_or_default();
                let trusted = match check_reply(&token, &nonce, &rh, 410, &b) {
                    Ok(()) => true,
                    Err(e) => {
                        eprintln!("{}", e);
                        false
                    }
                };
                if trusted {
                    gone += 1;
                }
                if trusted && gone >= 3 {
                    eprintln!("the panel removed this server: removing every tunnel and service Kanki installed here");
                    mgr.apply(vec![]).await;
                    let _ = tokio::task::spawn_blocking(|| crate::dns::deploy(None)).await;
                    let _ = tokio::task::spawn_blocking(|| crate::xray::deploy(None, None)).await;
                    subsrv.apply(None);
                    let _ = std::fs::remove_file(CACHE);
                    last.clear();
                    // the Hysteria2 / AmneziaWG tunnel workers stop their units and routes by themselves
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    let _ = tokio::task::spawn_blocking(uninstall_self).await;
                }
            }
            Ok(r) if r.status().is_success() => {
                fails = 0;
                gone = 0;
                crate::dns::qlog_ack(&body["dns"]);
                let (rst, rh) = (r.status().as_u16(), r.headers().clone());
                // 3.69: the answer is signed by a panel from 3.69 on (bound to this report's nonce): a changed or
                // replayed one is not applied
                let answer = match r.bytes().await {
                    Ok(b) => match check_reply(&token, &nonce, &rh, rst, &b) {
                        Ok(()) => serde_json::from_slice::<Value>(&b).ok(),
                        Err(e) => {
                            eprintln!("{}", e);
                            None
                        }
                    },
                    Err(_) => None,
                };
                if let Some(v) = answer {
                    // the panel's addresses as it names them now (an older panel names none: kept as they were)
                    if v.get("panel_alt").is_some() {
                        let (m, a) = named(&v);
                        if m != main_named || a != alt_named {
                            save_named(&m, &a);
                            (main_named, alt_named) = (m, a);
                            cands = candidates(&panel, &main_named, &alt_named);
                            idx = cands.iter().position(|c| c.0 == base).unwrap_or(0);
                        }
                    }
                    // "Restart services" in the panel: the tunnels stop now and start again below
                    if v["restart"].as_bool() == Some(true) {
                        eprintln!("the panel asked: restarting the tunnels");
                        mgr.apply(vec![]).await;
                        last.clear();
                    }
                    // "Sync" in the panel: everything below is applied again now (nothing kept from before)
                    if v["resync"].as_bool() == Some(true) {
                        last.clear();
                    }
                    // "Try SSL again" in the panel: no waiting after earlier failures
                    if v["ssl_retry"].as_bool() == Some(true) {
                        let _ = tokio::task::spawn_blocking(crate::certbot::retry_now).await;
                    }
                    // the firewall guard (a panel without it sends nothing: ufw is left as it is)
                    let fw_want = v["fw_guard"].as_bool();
                    let (fw_confirm, fw_fresh) = (v["fw_confirm"].as_bool() == Some(true), v["fw_fresh"].as_bool() == Some(true));
                    let _ = tokio::task::spawn_blocking(move || {
                        if fw_fresh {
                            crate::fw::guard_reset_note();
                        }
                        crate::fw::guard_tick(fw_want, fw_confirm)
                    })
                    .await;
                    // firewall ports the admin asked to close (open in ufw, nothing listens there)
                    if let Some(rules) = v["fw_close"].as_array().filter(|a| !a.is_empty()) {
                        let rules: Vec<String> = rules.iter().filter_map(|u| u.as_str().map(|s| s.to_string())).collect();
                        let _ = tokio::task::spawn_blocking(move || crate::fw::close_unused(&rules)).await;
                    }
                    // ports the admin asked to free (Health › Free the ports): the services holding them
                    // are stopped and kept off, then Kanki DNS and Xray restart onto those ports
                    if let Some(units) = v["free"].as_array().filter(|a| !a.is_empty()) {
                        let units: Vec<String> = units.iter().filter_map(|u| u.as_str().map(|s| s.to_string())).collect();
                        let _ = tokio::task::spawn_blocking(move || {
                            let mut need = crate::dns::needed_ports();
                            need.extend(crate::xray::needed_ports());
                            if !crate::certbot::free_ports(&units, &need).is_empty() {
                                crate::dns::restart_if_installed();
                                crate::xray::restart_if_installed();
                            }
                        })
                        .await;
                    }
                    // Kanki DNS: "set" (new config), "keep" (unchanged) or "off"
                    match v["dns"]["mode"].as_str() {
                        Some("set") => {
                            if let (Ok(c), Some(ver)) = (serde_json::from_value::<crate::dns::DnsCfg>(v["dns"]["cfg"].clone()), v["dns"]["ver"].as_str().map(|s| s.to_string())) {
                                let force = v["dns"]["force"].as_bool() == Some(true);
                                let r = tokio::task::spawn_blocking(move || {
                                    if force {
                                        crate::dns::repair_prep();
                                    }
                                    crate::dns::deploy(Some((&c, &ver)))
                                })
                                .await
                                .unwrap_or(Err("deploy crashed".into()));
                                *dns_err.lock().unwrap_or_else(|e| e.into_inner()) = r.err();
                            }
                        }
                        Some("off") => {
                            let r = tokio::task::spawn_blocking(|| crate::dns::deploy(None)).await.unwrap_or(Ok(()));
                            *dns_err.lock().unwrap_or_else(|e| e.into_inner()) = r.err();
                        }
                        _ => {}
                    }
                    // Xray: "set" (new config), "keep" (unchanged) or "off"
                    match v["xray"]["mode"].as_str() {
                        Some("set") => {
                            if let (Ok(c), Some(ver)) = (serde_json::from_value::<crate::xray::XrayCfg>(v["xray"]["cfg"].clone()), v["xray"]["ver"].as_str().map(|s| s.to_string())) {
                                let (p, i, t) = (base.clone(), id.clone(), token.clone());
                                let force = v["xray"]["force"].as_bool() == Some(true);
                                let r = tokio::task::spawn_blocking(move || {
                                    if force {
                                        crate::xray::repair_prep();
                                    }
                                    crate::xray::deploy(Some((&c, &ver)), Some((&p, &i, &t)))
                                })
                                .await
                                .unwrap_or(Err("deploy crashed".into()));
                                *xray_err.lock().unwrap_or_else(|e| e.into_inner()) = r.err();
                            }
                        }
                        Some("off") => {
                            let r = tokio::task::spawn_blocking(|| crate::xray::deploy(None, None)).await.unwrap_or(Ok(()));
                            *xray_err.lock().unwrap_or_else(|e| e.into_inner()) = r.err();
                        }
                        _ => {}
                    }
                    // the connection limit: users whose Xray is shut here for now (an older panel sends none)
                    if let Some(b) = v["xray_block"].as_array() {
                        let ids: Vec<i64> = b.iter().filter_map(|x| x.as_i64()).collect();
                        // extra devices on one config: (user, address)
                        let drop: Vec<(i64, String)> = v["xray_drop"].as_array().into_iter().flatten().filter_map(|x| Some((x[0].as_i64()?, x[1].as_str()?.to_string()))).collect();
                        let _ = tokio::task::spawn_blocking(move || {
                            crate::xray::set_blocked(&ids);
                            crate::xray::set_ip_blocks(&drop);
                        })
                        .await;
                    }
                    // the VPN part of this server, when the admin pressed "Install VPN" in the panel
                    if v["setup"].is_object() {
                        let c = v["setup"].clone();
                        if let Ok(Err(e)) = tokio::task::spawn_blocking(move || start_setup(&c)).await {
                            eprintln!("VPN install: {}", e);
                        }
                    }
                    // the subscription listener: its config, or Null (none here)
                    subsrv.apply(serde_json::from_value(v["subsrv"].clone()).ok());
                    if v["update"].as_bool() == Some(true) && update_tried.map(|t| t.elapsed() >= Duration::from_secs(60)).unwrap_or(true) {
                        update_tried = Some(std::time::Instant::now());
                        if let Err(e) = update_from_panel(http, &base, &id, &token).await {
                            eprintln!("update from the panel failed (tried again in a minute): {}", e);
                        }
                    }
                    if let Ok(specs) = serde_json::from_value::<Vec<Spec>>(v["tunnels"].clone()) {
                        let text = serde_json::to_string(&specs).unwrap_or_default();
                        if text != last {
                            let _ = std::fs::create_dir_all("/var/lib/kanki");
                            let _ = std::fs::write(CACHE, &text);
                            last = text;
                        }
                        let ps = specs.clone();
                        // stopped first, so the ports of a deleted tunnel are free when they are closed
                        mgr.apply(specs).await;
                        let _ = tokio::task::spawn_blocking(move || open_ports(&ps)).await;
                    }
                }
            }
            Ok(r) => {
                fails += 1;
                if fails % 12 == 1 {
                    eprintln!("panel answered {}", r.status());
                }
            }
            Err(e) => {
                fails += 1;
                if fails % 12 == 1 {
                    eprintln!("cannot reach the panel ({}); the tunnels keep running", crate::pin::error_text(&e));
                }
            }
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

// ------------------------------------------------------------------ standalone mode (no panel)

/// Reads the tunnel descriptions of a standalone run: one `Spec` object or a list of them. Gives
/// every tunnel without an id one (`t1`, `t2`, …) and refuses descriptions that cannot work.
pub fn parse_spec_file(text: &str) -> Result<Vec<Spec>, String> {
    let mut specs: Vec<Spec> = match serde_json::from_str::<Vec<Spec>>(text) {
        Ok(v) => v,
        Err(_) => vec![serde_json::from_str::<Spec>(text).map_err(|e| format!("the file is not a tunnel description: {}", e))?],
    };
    if specs.is_empty() {
        return Err("the file has no tunnel".into());
    }
    for (i, s) in specs.iter_mut().enumerate() {
        if s.id.trim().is_empty() {
            s.id = format!("t{}", i + 1);
        }
        if s.name.trim().is_empty() {
            s.name = s.id.clone();
        }
        if s.mode.is_empty() {
            s.mode = "reverse".into();
        }
        if s.role != "entry" && s.role != "exit" {
            return Err(format!("tunnel {}: \"role\" must be \"entry\" (the side users connect to) or \"exit\" (the side that reaches the targets)", s.id));
        }
        if s.mode != "reverse" && s.mode != "direct" {
            return Err(format!("tunnel {}: \"mode\" must be \"reverse\" or \"direct\"", s.id));
        }
        if !super::panel::TRANSPORTS.contains(&s.transport.as_str()) {
            return Err(format!("tunnel {}: unknown transport \"{}\" (use one of: {})", s.id, s.transport, super::panel::TRANSPORTS.join(", ")));
        }
        // the UDP mask key comes from this token and the wire shows a 4-byte tag of it, so a
        // short token can be brute-forced offline by a watcher: require real entropy
        if s.token.len() < 24 {
            return Err(format!(
                "tunnel {}: \"token\" is the shared secret of both ends and a watcher can brute-force a short one offline; use at least 24 random characters (for example: openssl rand -hex 24)",
                s.id
            ));
        }
        // the example files carry public placeholders: running one unchanged would give the tunnel a
        // secret everybody knows, or point it at an address that does not exist
        if s.token.contains("CHANGE-ME") {
            return Err(format!("tunnel {}: \"token\" is still the placeholder from the example; make your own, the same on both servers (for example: openssl rand -hex 24)", s.id));
        }
        if s.remote.contains("_PUBLIC_IP") {
            return Err(format!("tunnel {}: \"remote\" still has the placeholder {}; write the real address of the other server", s.id, s.remote));
        }
        if s.listens() && s.port == 0 {
            return Err(format!("tunnel {}: this side listens, so \"port\" is required", s.id));
        }
        if !s.listens() && s.remote.trim().is_empty() {
            return Err(format!("tunnel {}: this side dials, so \"remote\" (host:port of the other side) is required", s.id));
        }
        if s.role == "entry" && parse_ports(&s.tcp).is_empty() && parse_ports(&s.udp).is_empty() && !s.probe {
            return Err(format!("tunnel {}: the entry needs at least one port in \"tcp\" or \"udp\" to carry", s.id));
        }
        if s.path.is_empty() {
            s.path = "/".into();
        }
    }
    let mut ids = HashSet::new();
    for s in &specs {
        if !ids.insert(s.id.clone()) {
            return Err(format!("two tunnels have the id \"{}\"", s.id));
        }
    }
    Ok(specs)
}

/// What a person has to open in the firewall for these tunnels, one "port/proto" per item.
pub fn firewall_list(specs: &[Spec]) -> Vec<String> {
    let mut v = vec![];
    for s in specs {
        if s.listens() && s.port > 0 {
            let protos: &[&str] = match s.transport.as_str() {
                "quic" | "kcp" | "hq" => &["udp"],
                "dual" => &["tcp", "udp"],
                _ => &["tcp"],
            };
            for p in protos {
                v.push(format!("{}/{}", s.port, p));
            }
        }
        if s.role == "entry" {
            for (a, _) in parse_ports(&s.tcp) {
                v.push(format!("{}/tcp", a));
            }
            for (a, _) in parse_ports(&s.udp) {
                v.push(format!("{}/udp", a));
            }
        }
    }
    v.sort();
    v.dedup();
    v
}

/// `kanki-panel tunnel-run <file.json> --check`: only reads and validates the file. Prints the ports
/// to open in the firewall, one `port/proto` per line on stdout, and exits 0; or prints the reason on
/// stderr and exits 1. Nothing is started. (The installer script uses this before it touches the system.)
pub fn check_file(path: &str) {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("cannot read {}: {}", path, e);
            std::process::exit(1);
        }
    };
    match parse_spec_file(&text) {
        Ok(specs) => {
            for p in firewall_list(&specs) {
                println!("{}", p);
            }
        }
        Err(e) => {
            eprintln!("{}: {}", path, e);
            std::process::exit(1);
        }
    }
}

/// `kanki-panel tunnel-run <file.json>`: runs the tunnels of the file on this machine, with no panel
/// and no database. Put the entry description on the first server (Node A) and the exit description
/// on the second (Node B). Ctrl-C stops it.
pub async fn run_file(path: &str) {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("cannot read {}: {}", path, e);
            std::process::exit(1);
        }
    };
    let specs = match parse_spec_file(&text) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{}: {}", path, e);
            std::process::exit(1);
        }
    };
    eprintln!("kanki tunnel: {} tunnel(s) from {}", specs.len(), path);
    eprintln!("open in the firewall of this server: {}", firewall_list(&specs).join(" "));
    let mgr = Manager::default();
    mgr.apply(specs).await;
    let mut last = String::new();
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                eprintln!("stopping");
                return;
            }
            _ = tokio::time::sleep(Duration::from_secs(10)) => {}
        }
        for s in mgr.statuses().await {
            let line = format!(
                "{} [{}] links {}/{} rtt {} ms, in {} B, out {} B, streams {}{}",
                s.id,
                s.transport,
                s.links,
                s.want,
                s.rtt_ms,
                s.rx_bytes,
                s.tx_bytes,
                s.streams,
                if s.error.is_empty() { String::new() } else { format!(" · last error: {}", s.error) }
            );
            // print when something changed (with traffic the byte counters change every time)
            if line != last {
                eprintln!("{}", line);
                last = line;
            }
        }
    }
}

/// An older agent kept its VIP tunnels in `/var/lib/kanki/vip.json` and their firewall rules under "vip"
fn retire_vip() {
    let _ = std::fs::remove_file("/var/lib/kanki/vip.json");
    crate::fw::sync("vip", Vec::<String>::new());
}

#[cfg(test)]
mod standalone_tests {
    use super::*;

    #[test]
    fn the_panel_is_tried_first_then_its_cdn_address() {
        let v = json!({ "panel": "https://panel.example.com:2053/", "panel_alt": ["https://cdn.example.net:2053", "javascript:x", "https://a b.c", "http://plain.example"] });
        let (m, a) = named(&v);
        assert_eq!(m, "https://panel.example.com:2053");
        assert_eq!(a, vec!["https://cdn.example.net:2053".to_string()]);
        // installed with the panel's address: that one first, the CDN one only through the CA check
        let c = candidates("https://panel.example.com:2053", &m, &a);
        assert_eq!(c, vec![("https://panel.example.com:2053".to_string(), false), ("https://cdn.example.net:2053".to_string(), true)]);
        // a server pointed at the CDN by hand (it could not reach the panel to update): the panel's own address
        // comes first again once the panel names it, and the CDN one stays a CDN one
        let c = candidates("https://cdn.example.net:2053", &m, &a);
        assert_eq!(c, vec![("https://panel.example.com:2053".to_string(), false), ("https://cdn.example.net:2053".to_string(), true)]);
        // an older panel names nothing: only the installed address
        assert_eq!(candidates("https://p.example", "", &[]), vec![("https://p.example".to_string(), false)]);
    }

    const GOOD: &str = r#"{"role":"entry","mode":"direct","transport":"dual","remote":"203.0.113.5:443","token":"0123456789abcdef01234567","tcp":["2222:22"]}"#;

    #[test]
    fn one_object_or_a_list() {
        let one = parse_spec_file(GOOD).unwrap();
        assert_eq!(one.len(), 1);
        assert_eq!(one[0].id, "t1");
        assert_eq!(one[0].path, "/");
        let two = parse_spec_file(&format!("[{},{}]", GOOD.replace("2222:22", "2223:22"), GOOD.replace("\"dual\"", "\"hq\"").replace("2222:22", "2224:22"))).unwrap();
        assert_eq!(two.len(), 2);
        assert_eq!(two[1].id, "t2");
    }

    #[test]
    fn bad_descriptions_are_refused_with_a_reason() {
        let bad_role = GOOD.replace("entry", "client");
        assert!(parse_spec_file(&bad_role).unwrap_err().contains("role"));
        let bad_tr = GOOD.replace("dual", "carrier-pigeon");
        assert!(parse_spec_file(&bad_tr).unwrap_err().contains("unknown transport"));
        let short = GOOD.replace("0123456789abcdef01234567", "short");
        assert!(parse_spec_file(&short).unwrap_err().contains("token"));
        let no_remote = GOOD.replace("203.0.113.5:443", "");
        assert!(parse_spec_file(&no_remote).unwrap_err().contains("remote"));
        let no_ports = GOOD.replace(r#","tcp":["2222:22"]"#, "");
        assert!(parse_spec_file(&no_ports).unwrap_err().contains("at least one port"));
        assert!(parse_spec_file("[]").is_err());
        assert!(parse_spec_file("not json").is_err());
        let dup = format!("[{},{}]", GOOD.replace("{", "{\"id\":\"a\","), GOOD.replace("{", "{\"id\":\"a\","));
        assert!(parse_spec_file(&dup).unwrap_err().contains("two tunnels"));
    }

    #[test]
    fn shipped_examples_are_valid() {
        for text in [
            include_str!("../../docs/examples/node-a-entry.json"),
            include_str!("../../docs/examples/node-b-exit.json"),
            include_str!("../../docs/examples/node-a-entry-reverse.json"),
            include_str!("../../docs/examples/node-b-exit-reverse.json"),
        ] {
            // an unchanged example is refused on purpose (public secret, address that does not exist) ...
            let why = parse_spec_file(text).unwrap_err();
            assert!(why.contains("placeholder"), "{}", why);
            // ... and valid once the two placeholders are filled in
            let filled = text.replace("CHANGE-ME-same-secret-on-both-nodes-32+chars", "0123456789abcdef01234567456789abcdef").replace("NODE_A_PUBLIC_IP", "203.0.113.5").replace("NODE_B_PUBLIC_IP", "203.0.113.6");
            let s = parse_spec_file(&filled).expect("an example file must be valid");
            assert_eq!(s[0].transport, "dual");
        }
    }

    #[test]
    fn firewall_list_has_both_protocols_for_dual() {
        let exit = r#"{"role":"exit","mode":"direct","transport":"dual","port":443,"token":"0123456789abcdef01234567"}"#;
        let s = parse_spec_file(exit).unwrap();
        assert_eq!(firewall_list(&s), vec!["443/tcp".to_string(), "443/udp".to_string()]);
        let entry = parse_spec_file(GOOD).unwrap();
        assert_eq!(firewall_list(&entry), vec!["2222/tcp".to_string()]);
    }
}
