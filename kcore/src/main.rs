//! kanki-core: MIX+ (the Game-FEC transport as a VPN protocol), server and app client in one binary.
//!
//! ```text
//! kanki-core client --url 'kcore://…' [--socks 127.0.0.1:10808] [--status]
//!     the app side: a SOCKS5 proxy on loopback for hev-socks5-tunnel; with --status a JSON line
//!     every 2 s on stdout: {"up":true,"kind":"game","rtt":38,"fast":true,"rx":…,"tx":…,"error":""}
//! kanki-core ping --url 'kcore://…'
//!     connects once and prints the round trip in ms (exit code 1 and the reason when it fails)
//! kanki-core server -c /etc/kanki/kcore.json [--stats /run/kanki-core.json]
//!     the server side (the panel's agent runs the same code itself); the config is read again
//!     when the file changes: users in place, ports and secrets with a restart of the listeners
//! kanki-core url --kind game --server host:port --door … --user … --key … [--name …]
//!     prints the kcore:// link of a user
//! ```

mod tunnel;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;
use tunnel::kcore::client::{self, Client, ClientCfg};
use tunnel::kcore::server::{CoreCfg, CoreServer};

fn args() -> (String, HashMap<String, String>) {
    let mut it = std::env::args().skip(1);
    let cmd = it.next().unwrap_or_default();
    let mut m = HashMap::new();
    let mut key: Option<String> = None;
    for a in it {
        if let Some(k) = a.strip_prefix("--").or_else(|| a.strip_prefix('-').filter(|k| k.len() == 1)) {
            if let Some(k0) = key.take() {
                m.insert(k0, "1".into());
            }
            key = Some(k.to_string());
        } else if let Some(k) = key.take() {
            m.insert(k, a);
        }
    }
    if let Some(k) = key {
        m.insert(k, "1".into());
    }
    (cmd, m)
}

fn usage() -> ! {
    eprintln!(
        "kanki-core {}\n  client --url kcore://… [--socks 127.0.0.1:10808] [--status]\n  ping --url kcore://…\n  server -c config.json [--stats file]\n  url --kind game --server host:port --door … --user … --key … [--name …]",
        env!("CARGO_PKG_VERSION")
    );
    std::process::exit(2)
}

fn main() {
    let (cmd, a) = args();
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().expect("runtime");
    let code = rt.block_on(async move {
        match cmd.as_str() {
            "client" => run_client(&a).await,
            "ping" => run_ping(&a).await,
            "server" => run_server(&a).await,
            "url" => {
                let c = ClientCfg {
                    kind: a.get("kind").cloned().unwrap_or_else(|| "game".into()),
                    server: a.get("server").cloned().unwrap_or_default(),
                    door: a.get("door").cloned().unwrap_or_default(),
                    user: a.get("user").cloned().unwrap_or_default(),
                    key: a.get("key").cloned().unwrap_or_default(),
                    fec: a.get("fec").cloned().unwrap_or_default(),
                    copies: a.get("copies").and_then(|c| c.parse().ok()).unwrap_or(2),
                    datagrams: true,
                };
                let u = c.to_url(a.get("name").map(|s| s.as_str()).unwrap_or(""));
                match ClientCfg::parse(&u) {
                    Ok(_) => {
                        println!("{}", u);
                        0
                    }
                    Err(e) => {
                        eprintln!("{}", e);
                        1
                    }
                }
            }
            "version" | "--version" | "-v" => {
                println!("{}", env!("CARGO_PKG_VERSION"));
                0
            }
            _ => usage(),
        }
    });
    std::process::exit(code);
}

fn client_cfg(a: &HashMap<String, String>) -> ClientCfg {
    let url = a.get("url").cloned().unwrap_or_else(|| usage());
    match ClientCfg::parse(&url) {
        Ok((c, _)) => c,
        Err(e) => {
            eprintln!("bad link: {}", e);
            std::process::exit(2);
        }
    }
}

async fn run_client(a: &HashMap<String, String>) -> i32 {
    let cfg = client_cfg(a);
    let socks: SocketAddr = a.get("socks").map(|s| s.as_str()).unwrap_or("127.0.0.1:10808").parse().unwrap_or_else(|_| usage());
    let c = match Client::new(cfg).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{}", e);
            return 1;
        }
    };
    tokio::spawn(c.clone().keep_up());
    if a.contains_key("status") {
        let c2 = c.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(2)).await;
                let mut st = c2.status();
                // a live ping through the link (the server's echo), not just the server's address
                if c2.current().is_some() {
                    if let Some(r) = c2.echo_rtt().await {
                        st["rtt"] = r.into();
                    }
                }
                println!("{}", st);
            }
        });
    }
    tokio::select! {
        r = tunnel::kcore::socks::serve(socks, c) => {
            if let Err(e) = r {
                eprintln!("socks: {}", e);
            }
            1
        }
        _ = tokio::signal::ctrl_c() => 0,
    }
}

async fn run_ping(a: &HashMap<String, String>) -> i32 {
    match tokio::time::timeout(Duration::from_secs(15), client::ping(client_cfg(a))).await {
        Ok(Ok(ms)) => {
            println!("{}", ms);
            0
        }
        Ok(Err(e)) => {
            println!("error: {}", e);
            1
        }
        Err(_) => {
            println!("error: timeout");
            1
        }
    }
}

fn read_cfg(path: &str) -> Option<CoreCfg> {
    let t = std::fs::read_to_string(path).ok()?;
    match serde_json::from_str(&t) {
        Ok(c) => Some(c),
        Err(e) => {
            eprintln!("{}: {}", path, e);
            None
        }
    }
}

async fn run_server(a: &HashMap<String, String>) -> i32 {
    let path = a.get("c").or_else(|| a.get("config")).cloned().unwrap_or_else(|| "/etc/kanki/kcore.json".into());
    let Some(mut cfg) = read_cfg(&path) else {
        eprintln!("cannot read {}", path);
        return 1;
    };
    let mut srv = CoreServer::start(&cfg).await;
    for (k, e) in &srv.errors {
        eprintln!("{} did not start: {}", k, e);
    }
    let mtime = |p: &str| std::fs::metadata(p).and_then(|m| m.modified()).ok();
    let mut seen = mtime(&path);
    let mut tick = 0u64;
    loop {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(5)) => {}
            _ = tokio::signal::ctrl_c() => return 0,
        }
        tick += 1;
        let now = mtime(&path);
        if now != seen {
            seen = now;
            if let Some(n) = read_cfg(&path) {
                if srv.needs_restart(&n) {
                    drop(srv);
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    srv = CoreServer::start(&n).await;
                    for (k, e) in &srv.errors {
                        eprintln!("{} did not start: {}", k, e);
                    }
                } else if n.users != cfg.users {
                    srv.set_users(&n.users);
                }
                cfg = n;
            }
        }
        if let Some(st) = a.get("stats") {
            if tick % 2 == 0 {
                let v = serde_json::json!({
                    "traffic": srv.traffic(),
                    "online": srv.online(),
                    "errors": srv.errors.iter().map(|(k, e)| format!("{}: {}", k, e)).collect::<Vec<_>>(),
                });
                let _ = std::fs::write(st, v.to_string());
            }
        }
    }
}
