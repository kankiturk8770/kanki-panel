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
        reqwest::Client::builder().timeout(timeout).build().expect("http")
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
        if s.role == "entry" {
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
    let shared = ["/etc/systemd/system/kanki-panel.service", "/etc/systemd/system/kanki-node.service"].iter().any(|f| std::path::Path::new(f).exists());
    if !shared {
        if let Ok(exe) = std::env::current_exe() {
            let _ = std::fs::remove_file(exe.to_string_lossy().replace(" (deleted)", ""));
        }
        let _ = std::fs::remove_file("/usr/local/bin/kanki");
    }
    eprintln!("removed from the panel: the tunnel agent uninstalls itself");
    sh("systemctl disable -q kanki-tunnel.service 2>/dev/null; rm -f /etc/systemd/system/kanki-tunnel.service; systemctl daemon-reload");
    sh("systemctl stop kanki-tunnel.service");
    std::process::exit(0);
}

/// Downloads the panel's own binary (same file, same machine type), checks its sha256, swaps it in
/// and exits; systemd starts the new one. Used when the panel asks for an update (Update all).
async fn update_from_panel(http: &reqwest::Client, panel: &str, id: &str, token: &str) -> Result<(), String> {
    let r = http
        .post(format!("{}/tunnel/binary", panel))
        .json(&json!({ "id": id, "token": token, "arch": std::env::consts::ARCH }))
        .timeout(Duration::from_secs(300))
        .send()
        .await
        .map_err(|e| crate::pin::error_text(&e))?;
    if !r.status().is_success() {
        return Err(format!("the panel answered {}", r.status()));
    }
    let want = r.headers().get("x-sha256").and_then(|v| v.to_str().ok()).unwrap_or("").to_lowercase();
    let bytes = r.bytes().await.map_err(|e| e.to_string())?;
    let got = {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(&bytes);
        hex::encode(h.finalize())
    };
    if want.is_empty() || want != got {
        return Err("checksum mismatch, update aborted".into());
    }
    let path = std::env::current_exe().map_err(|e| e.to_string())?;
    let tmp = path.with_extension("new");
    std::fs::write(&tmp, &bytes).map_err(|e| e.to_string())?;
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755));
    }
    std::fs::rename(&tmp, &path).map_err(|e| e.to_string())?;
    eprintln!("updated from the panel: restarting");
    std::process::exit(0);
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
    // INSECURE=1: a CA-valid certificate is still accepted (and re-pinned), anything else is
    // pinned on first contact (see `panel_client`)
    if insecure {
        eprintln!("warning: INSECURE=1 — a panel certificate that is not CA-valid will be pinned on first contact ({})", PIN_FILE);
    }
    let http = panel_client(insecure, Duration::from_secs(20));
    // an updated agent also moves the emergency chat onto the new binary
    let _ = tokio::task::spawn_blocking(crate::emergency::restart_if_outdated).await;
    let _ = tokio::task::spawn_blocking(crate::dns::restart_if_outdated).await;
    // certificates close to their end are renewed with what holds port 80 at that moment
    crate::certbot::renew_loop();
    let mut fails = 0u32;
    // answers in a row that say this server was removed from the panel
    let mut gone = 0u32;
    // the last error of setting up the emergency chat (reported to the panel)
    let emer_err: Mutex<Option<String>> = Mutex::new(None);
    // the last error of setting up Kanki DNS
    let dns_err: Mutex<Option<String>> = Mutex::new(None);
    // the last error of setting up Xray
    let xray_err: Mutex<Option<String>> = Mutex::new(None);
    // the subscription's HTTPS listener (when this Iran server serves it)
    let mut subsrv = crate::subiran::Runner::from_disk();
    loop {
        let st = mgr.statuses().await;
        let (emer_ver, mut emer_st) = tokio::task::spawn_blocking(|| (crate::emergency::applied_ver(), crate::emergency::status()))
            .await
            .unwrap_or_default();
        if let Some(e) = emer_err.lock().unwrap().clone() {
            if emer_st.is_object() {
                emer_st["error"] = json!(e);
            } else {
                emer_st = json!({ "active": false, "error": e });
            }
        }
        let (dns_ver, mut dns_st) = tokio::task::spawn_blocking(|| (crate::dns::applied_ver(), crate::dns::status())).await.unwrap_or_default();
        if let Some(e) = dns_err.lock().unwrap().clone() {
            if dns_st.is_object() {
                dns_st["deploy_error"] = json!(e);
            } else {
                dns_st = json!({ "active": false, "deploy_error": e });
            }
        }
        let (xray_ver, mut xray_st) = tokio::task::spawn_blocking(|| (crate::xray::applied_ver(), crate::xray::status())).await.unwrap_or_default();
        if let Some(e) = xray_err.lock().unwrap().clone() {
            if xray_st.is_object() {
                xray_st["deploy_error"] = json!(e);
            } else {
                xray_st = json!({ "active": false, "deploy_error": e });
            }
        }
        let fw_st = tokio::task::spawn_blocking(crate::fw::report).await.unwrap_or_default();
        let listen = tokio::task::spawn_blocking(crate::certbot::listeners_json).await.unwrap_or_default();
        let setup_st = tokio::task::spawn_blocking(setup_status).await.unwrap_or_default();
        let body = json!({ "id": id, "token": token, "version": version, "status": st, "emer_ver": emer_ver, "emergency": emer_st, "dns_ver": dns_ver, "dns": dns_st, "xray_ver": xray_ver, "xray": xray_st, "subsrv": subsrv.status(), "fw": fw_st, "listen": listen, "setup": setup_st });
        match http.post(format!("{}/tunnel/agent", panel)).json(&body).send().await {
            Ok(r) if r.status().as_u16() == 410 => {
                // this server was removed in the panel: everything Kanki put here is removed (a few
                // answers in a row, so one odd answer does not wipe a working server)
                gone += 1;
                if gone >= 3 {
                    eprintln!("the panel removed this server: removing every tunnel and service Kanki installed here");
                    mgr.apply(vec![]).await;
                    let _ = tokio::task::spawn_blocking(|| crate::emergency::deploy(None)).await;
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
                if let Ok(v) = r.json::<Value>().await {
                    // the emergency chat: "set" (new config), "keep" (unchanged) or "off"
                    match v["emergency"]["mode"].as_str() {
                        Some("set") => {
                            if let (Ok(c), Some(ver)) = (serde_json::from_value::<crate::emergency::EmerCfg>(v["emergency"]["cfg"].clone()), v["emergency"]["ver"].as_str().map(|s| s.to_string())) {
                                let r = tokio::task::spawn_blocking(move || crate::emergency::deploy(Some((&c, &ver)))).await.unwrap_or(Err("deploy crashed".into()));
                                *emer_err.lock().unwrap() = r.err();
                            }
                        }
                        Some("off") => {
                            let r = tokio::task::spawn_blocking(|| crate::emergency::deploy(None)).await.unwrap_or(Ok(()));
                            *emer_err.lock().unwrap() = r.err();
                        }
                        _ => {}
                    }
                    // "Try SSL again" in the panel: no waiting after earlier failures
                    if v["ssl_retry"].as_bool() == Some(true) {
                        let _ = tokio::task::spawn_blocking(crate::certbot::retry_now).await;
                    }
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
                                *dns_err.lock().unwrap() = r.err();
                            }
                        }
                        Some("off") => {
                            let r = tokio::task::spawn_blocking(|| crate::dns::deploy(None)).await.unwrap_or(Ok(()));
                            *dns_err.lock().unwrap() = r.err();
                        }
                        _ => {}
                    }
                    // Xray: "set" (new config), "keep" (unchanged) or "off"
                    match v["xray"]["mode"].as_str() {
                        Some("set") => {
                            if let (Ok(c), Some(ver)) = (serde_json::from_value::<crate::xray::XrayCfg>(v["xray"]["cfg"].clone()), v["xray"]["ver"].as_str().map(|s| s.to_string())) {
                                let (p, i, t) = (panel.clone(), id.clone(), token.clone());
                                let force = v["xray"]["force"].as_bool() == Some(true);
                                let r = tokio::task::spawn_blocking(move || {
                                    if force {
                                        crate::xray::repair_prep();
                                    }
                                    crate::xray::deploy(Some((&c, &ver)), Some((&p, &i, &t)))
                                })
                                .await
                                .unwrap_or(Err("deploy crashed".into()));
                                *xray_err.lock().unwrap() = r.err();
                            }
                        }
                        Some("off") => {
                            let r = tokio::task::spawn_blocking(|| crate::xray::deploy(None, None)).await.unwrap_or(Ok(()));
                            *xray_err.lock().unwrap() = r.err();
                        }
                        _ => {}
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
                    if v["update"].as_bool() == Some(true) {
                        if let Err(e) = update_from_panel(&http, &panel, &id, &token).await {
                            eprintln!("update from the panel failed: {}", e);
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

#[cfg(test)]
mod standalone_tests {
    use super::*;

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
