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
        if s.listens() && s.port > 0 {
            // quic, kcp and hq run over UDP; dual listens on UDP and TCP of the same number
            let protos: &[&str] = match s.transport.as_str() {
                "quic" | "kcp" | "hq" => &["udp"],
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

/// Logs a clear warning when another tunnel-running kanki job (`other`) runs on this machine too.
/// They no longer fight (each keeps to its own AmneziaWG interfaces), but a panel server that is
/// also registered as a separate tunnel server is almost always a mistake: the panel already runs
/// the tunnels of its own machine as the server "local", and a tunnel cannot have both ends here.
pub fn warn_if_sharing_machine(other: &str, other_name: &str) {
    if crate::instance::alive(other) == Some(true) {
        eprintln!(
            "warning: the {} runs on this server too. Each one now keeps to its own AmneziaWG interfaces, \
             so they no longer remove each other's tunnels. But the panel already runs this server's tunnels \
             as its own server (\"local\"): if this machine is also added under Tunnels > servers, remove that \
             entry and uninstall kanki-tunnel here (systemctl disable --now kanki-tunnel).",
            other_name
        );
    }
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
        .map_err(|e| e.to_string())?;
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
    // only one tunnel agent per machine; a second copy waits here and touches nothing
    let _instance = crate::instance::hold_or_wait(super::awg::OWNER_AGENT, "tunnel agent").await;
    super::awg::set_owner(super::awg::OWNER_AGENT);
    eprintln!("kanki tunnel agent {} for {} (server {})", version, panel, id);
    warn_if_sharing_machine(super::awg::OWNER_PANEL, "Kanki panel (kanki-panel)");
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
                    // without a verified panel certificate anyone on the path could answer here,
                    // so never replace our own (root) binary in INSECURE mode
                    if v["update"].as_bool() == Some(true) && insecure {
                        eprintln!("update skipped: INSECURE=1 (panel certificate not verified); update this server by hand");
                    } else if v["update"].as_bool() == Some(true) {
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
        if s.token.len() < 16 {
            return Err(format!("tunnel {}: \"token\" is the shared secret of both ends; use at least 16 random characters", s.id));
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

/// Name of a standalone run: "tunnel-run-" + the first 8 hex digits of the sha256 of the file's
/// full path, so two different files on one machine are two jobs and the same file is one.
pub fn run_owner(path: &str) -> String {
    use sha2::{Digest, Sha256};
    let full = std::fs::canonicalize(path).map(|p| p.to_string_lossy().to_string()).unwrap_or_else(|_| path.to_string());
    let mut h = Sha256::new();
    h.update(full.as_bytes());
    format!("tunnel-run-{}", &hex::encode(h.finalize())[..8])
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
    // one copy per file; the name also marks the AmneziaWG interfaces this run owns
    let owner = run_owner(path);
    let _instance = crate::instance::hold_or_wait(&owner, &format!("tunnel-run of {}", path)).await;
    super::awg::set_owner(&owner);
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

    const GOOD: &str = r#"{"role":"entry","mode":"direct","transport":"dual","remote":"203.0.113.5:443","token":"0123456789abcdef0123","tcp":["2222:22"]}"#;

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
        let short = GOOD.replace("0123456789abcdef0123", "short");
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
            let filled = text.replace("CHANGE-ME-same-secret-on-both-nodes-32+chars", "0123456789abcdef0123456789abcdef").replace("NODE_A_PUBLIC_IP", "203.0.113.5").replace("NODE_B_PUBLIC_IP", "203.0.113.6");
            let s = parse_spec_file(&filled).expect("an example file must be valid");
            assert_eq!(s[0].transport, "dual");
        }
    }

    #[test]
    fn firewall_list_has_both_protocols_for_dual() {
        let exit = r#"{"role":"exit","mode":"direct","transport":"dual","port":443,"token":"0123456789abcdef0123"}"#;
        let s = parse_spec_file(exit).unwrap();
        assert_eq!(firewall_list(&s), vec!["443/tcp".to_string(), "443/udp".to_string()]);
        let entry = parse_spec_file(GOOD).unwrap();
        assert_eq!(firewall_list(&entry), vec!["2222/tcp".to_string()]);
    }
}
