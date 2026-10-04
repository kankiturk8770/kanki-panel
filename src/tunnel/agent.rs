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

/// Opens the ports a tunnel listens on in ufw (only when ufw is active). Remembers what it opened.
pub fn open_ports(specs: &[Spec], done: &Mutex<HashSet<String>>) {
    let mut want = vec![];
    for s in specs {
        if s.listens() && s.port > 0 {
            // quic and kcp run over UDP
            let proto = if s.transport == "quic" || s.transport == "kcp" { "udp" } else { "tcp" };
            want.push(format!("{}/{}", s.port, proto));
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
    let todo: Vec<String> = {
        let d = done.lock().unwrap();
        want.into_iter().filter(|p| !d.contains(p)).collect()
    };
    if todo.is_empty() {
        return;
    }
    let active = std::process::Command::new("ufw")
        .arg("status")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("Status: active"))
        .unwrap_or(false);
    let mut d = done.lock().unwrap();
    for p in todo {
        if active {
            let _ = std::process::Command::new("ufw").args(["allow", &p]).output();
        }
        d.insert(p);
    }
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
    let opened = Mutex::new(HashSet::new());
    let mut last = String::new();
    if let Ok(t) = std::fs::read_to_string(CACHE) {
        if let Ok(specs) = serde_json::from_str::<Vec<Spec>>(&t) {
            eprintln!("starting {} saved tunnel(s)", specs.len());
            let ps = specs.clone();
            let _ = tokio::task::spawn_blocking(move || open_ports(&ps, &Mutex::new(HashSet::new()))).await;
            mgr.apply(specs).await;
            last = t;
        }
    }
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .danger_accept_invalid_certs(insecure)
        .build()
        .expect("http");
    let mut fails = 0u32;
    loop {
        let st = mgr.statuses().await;
        let body = json!({ "id": id, "token": token, "version": version, "status": st });
        match http.post(format!("{}/tunnel/agent", panel)).json(&body).send().await {
            Ok(r) if r.status().as_u16() == 410 => {
                // this server was removed in the panel
                if !last.is_empty() {
                    eprintln!("the panel removed this server: stopping every tunnel");
                    mgr.apply(vec![]).await;
                    let _ = std::fs::remove_file(CACHE);
                    last.clear();
                }
            }
            Ok(r) if r.status().is_success() => {
                fails = 0;
                if let Ok(v) = r.json::<Value>().await {
                    if let Ok(specs) = serde_json::from_value::<Vec<Spec>>(v["tunnels"].clone()) {
                        let text = serde_json::to_string(&specs).unwrap_or_default();
                        if text != last {
                            let _ = std::fs::create_dir_all("/var/lib/kanki");
                            let _ = std::fs::write(CACHE, &text);
                            last = text;
                        }
                        let ps = specs.clone();
                        let set = std::mem::take(&mut *opened.lock().unwrap());
                        let set = tokio::task::spawn_blocking(move || {
                            let m = Mutex::new(set);
                            open_ports(&ps, &m);
                            m.into_inner().unwrap_or_default()
                        })
                        .await
                        .unwrap_or_default();
                        *opened.lock().unwrap() = set;
                        mgr.apply(specs).await;
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
                    eprintln!("cannot reach the panel ({}); the tunnels keep running", e);
                }
            }
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}
