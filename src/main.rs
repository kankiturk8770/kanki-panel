//! Kanki Panel: WireGuard / AmneziaWG / Hysteria2 panel with a built-in Telegram sales bot
// core: storage + shared helpers
#[path = "core/db.rs"]
mod db;
#[path = "core/util.rs"]
mod util;
#[path = "core/certbot.rs"]
mod certbot;
#[path = "core/pin.rs"]
mod pin;

// http: web panel, REST API, security, backups
#[path = "http/admin.rs"]
mod admin;
#[path = "http/api.rs"]
mod api;
#[path = "http/auth.rs"]
mod auth;
#[path = "http/backup.rs"]
mod backup;
#[path = "http/subdomain.rs"]
mod subdomain;

// vpn: protocol engines + node sync
mod dns;
mod emergency;
#[path = "vpn/hy2.rs"]
mod hy2;
#[path = "vpn/sync.rs"]
mod sync;
#[path = "vpn/wg.rs"]
mod wg;

// telegram: built-in sales bot
#[path = "telegram/bot.rs"]
mod bot;
#[path = "telegram/channel.rs"]
mod channel;

// tunnel: encrypted tunnels between servers (Kanki Tunnel)
mod tunnel;

// xray: Xray-core inbounds for the panel's users
mod xray;

use std::collections::HashMap;
use std::sync::atomic::AtomicI64;
use std::sync::{Arc, Mutex};

pub const ENV_PATH: &str = "/etc/kanki/kanki.env";
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub struct App {
    pub db: db::Db,
    pub env: HashMap<String, String>,
    /// sub code -> username (Hysteria2 users allowed on this server)
    pub hy2_allowed: Mutex<HashMap<String, String>>,
    /// username -> (max connections, online across all nodes at last sync)
    pub limits: Mutex<HashMap<String, (i64, i64)>>,
    /// username -> hy2 sessions this server reported at last sync
    pub reported: Mutex<HashMap<String, i64>>,
    /// failed logins per IP: (count, first failure ts)
    pub login_fails: Mutex<HashMap<String, (u32, i64)>>,
    /// only one sync round at a time (prevents double-counted traffic)
    pub sync_lock: tokio::sync::Mutex<()>,
    /// last time the Telegram bot polled successfully
    pub bot_alive: AtomicI64,
    /// strict TLS client
    pub http: reqwest::Client,
    /// for nodes explicitly marked "self-signed certificate"
    pub http_insecure: reqwest::Client,
    /// pinned (TOFU) clients for nodes with self-signed certificates, one per node
    pub pin_clients: Mutex<HashMap<String, Arc<reqwest::Client>>>,
}

impl App {
    pub fn client(&self, insecure: bool) -> &reqwest::Client {
        if insecure { &self.http_insecure } else { &self.http }
    }
    /// HTTP client for one node: CA-checked, or certificate-pinned (TOFU) when the node has a
    /// self-signed certificate. The pin lives in {data_dir}/nodepins/<key>.pin: the first
    /// certificate seen is kept and any later change is refused (a MITM cannot keep
    /// impersonating the node after first contact).
    pub fn node_client(&self, key: &str, insecure: bool) -> Arc<reqwest::Client> {
        if !insecure {
            return Arc::new(self.http.clone());
        }
        let key = pin_key(key);
        let mut g = self.pin_clients.lock().unwrap();
        g.entry(key.clone())
            .or_insert_with(|| Arc::new(crate::pin::pinned_client(&self.node_pin_file(&key), std::time::Duration::from_secs(125))))
            .clone()
    }
    /// {data_dir}/nodepins/<key>.pin
    pub fn node_pin_file(&self, key: &str) -> std::path::PathBuf {
        std::path::PathBuf::from(self.data_dir()).join("nodepins").join(format!("{}.pin", pin_key(key)))
    }
    /// Forgets the certificate pins of a node (by id and by address, files and cached clients):
    /// on delete, on a new address / certificate setting, and when a reinstalled node joins again
    /// (its self-signed certificate is new). The next contact pins again.
    pub fn forget_node_pins(&self, id: &str, addr: &str) {
        let mut g = self.pin_clients.lock().unwrap();
        for key in [id, addr] {
            let _ = std::fs::remove_file(self.node_pin_file(key));
            g.remove(&pin_key(key));
        }
    }
    /// The pin a node's first contact made (keyed by address) also becomes the pin of its id,
    /// so the certificate the admin added is the one later syncs expect.
    pub fn adopt_node_pin(&self, addr: &str, id: &str) {
        let _ = std::fs::copy(self.node_pin_file(addr), self.node_pin_file(id));
        self.pin_clients.lock().unwrap().remove(&pin_key(id));
    }
    pub fn data_dir(&self) -> String {
        self.env.get("DATA_DIR").cloned().unwrap_or_else(|| "/var/lib/kanki".into())
    }
}

/// a node id or address as a file name
fn pin_key(key: &str) -> String {
    key.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' }).collect()
}

fn usage() {
    println!("kanki-panel {}\n\nCommands:\n  serve                      run the main panel (default)\n  node                       run the node agent\n  tunnel-agent               run the tunnel agent (servers that only carry tunnels)\n  dns                        run Kanki DNS from /etc/kanki/dns.json (started by the agent)\n  tunnel-run <file.json>     run a standalone tunnel from a JSON file (no panel); add --check to only validate it\n  hash-password <pass>       print a password hash\n  reset-admin <user> <pass>  reset admin login, sessions and 2FA\n  reset-security             clear IP allow/deny lists and disable 2FA\n  set-bot <token> <admins>   set / change the Telegram sales bot (empty token = remove)\n  version", VERSION);
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(|s| s.as_str()).unwrap_or("serve");
    // SIGTERM (systemd stop, update) skips Drop: take the faketcp iptables rules away first
    tokio::spawn(async {
        if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            s.recv().await;
            tunnel::faketcp::remove_own_rules();
            std::process::exit(0);
        }
    });

    match cmd {
        "hash-password" => {
            println!("{}", util::hash_password(args.get(2).map(|s| s.as_str()).unwrap_or("")));
            return;
        }
        "version" | "--version" | "-v" => {
            println!("kanki-panel {}", VERSION);
            return;
        }
        "help" | "--help" | "-h" => {
            usage();
            return;
        }
        // the emergency chat server on an Iran server (started by the tunnel agent)
        "emergency" => {
            emergency::run().await;
            return;
        }
        // Kanki DNS on a DNS server (started by the agent)
        "dns" => {
            dns::run().await;
            return;
        }
        "tunnel-agent" => {
            tunnel::agent::run(VERSION).await;
            return;
        }
        // standalone tunnel, no panel and no database: runs the tunnels written in a JSON file
        "tunnel-run" => {
            let Some(path) = args.get(2) else {
                eprintln!("usage: kanki-panel tunnel-run <tunnel.json>   (see docs/examples/)");
                std::process::exit(1);
            };
            // `--check`: only validate the file and print the ports to open (starts nothing)
            if args.get(3).map(|s| s.as_str()) == Some("--check") {
                tunnel::agent::check_file(path);
                return;
            }
            tunnel::agent::run_file(path).await;
            return;
        }
        _ => {}
    }

    let env = util::load_env(ENV_PATH);
    let data = env.get("DATA_DIR").cloned().unwrap_or_else(|| "/var/lib/kanki".into());
    let _ = std::fs::create_dir_all(&data);
    let db = db::Db::open(&format!("{}/kanki.db", data));

    if cmd == "reset-admin" {
        let (Some(u), Some(p)) = (args.get(2), args.get(3)) else {
            eprintln!("usage: kanki-panel reset-admin <user> <pass>");
            std::process::exit(1);
        };
        db.set("admin_user", u);
        db.set("admin_pass", &util::hash_password(p));
        db.set("totp_on", "0");
        db.set("force_2fa", "0");
        let _ = db.exec("DELETE FROM sessions", &[]);
        println!("Admin reset. Restart the panel: systemctl restart kanki-panel");
        return;
    }
    if cmd == "set-bot" {
        let token = args.get(2).cloned().unwrap_or_default();
        let admins = args.get(3).cloned().unwrap_or_default();
        db.set("bot_token", token.trim());
        db.set("bot_admins", admins.trim());
        db.set("bot_paused", "0");
        println!("{}", if token.trim().is_empty() { "Telegram bot removed." } else { "Telegram bot saved." });
        return;
    }
    if cmd == "reset-security" {
        db.set("ip_allow", "");
        db.set("ip_deny", "");
        db.set("totp_on", "0");
        db.set("force_2fa", "0");
        println!("IP policy cleared and 2FA disabled.");
        return;
    }

    let mk = |insecure: bool| {
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(20))
            .danger_accept_invalid_certs(insecure)
            .build()
            .expect("http")
    };
    let app = Arc::new(App {
        db,
        env,
        hy2_allowed: Mutex::new(HashMap::new()),
        limits: Mutex::new(HashMap::new()),
        reported: Mutex::new(HashMap::new()),
        login_fails: Mutex::new(HashMap::new()),
        sync_lock: tokio::sync::Mutex::new(()),
        bot_alive: AtomicI64::new(0),
        http: mk(false),
        http_insecure: mk(true),
        pin_clients: Mutex::new(HashMap::new()),
    });

    if cmd == "node" {
        let port = app.env.get("NODE_PORT").cloned().unwrap_or_else(|| "2096".into());
        // new installs put Caddy (TLS) in front and bind locally; old installs listened publicly
        let bind = app.env.get("NODE_BIND").cloned().unwrap_or_else(|| "0.0.0.0".into());
        let addr = format!("{}:{}", bind, port);
        eprintln!("kanki node agent {} on {}", VERSION, addr);
        let l = tokio::net::TcpListener::bind(&addr).await.expect("bind");
        axum::serve(l, api::node_router(app)).await.expect("serve");
        return;
    }

    // main server: local node + legacy API key
    if app.db.node("local").is_none() {
        let name = app.env.get("LOCAL_NAME").cloned().unwrap_or_else(|| "Main".into());
        let _ = app.db.exec("INSERT INTO nodes(id,name,address,endpoint,token,online) VALUES('local',?1,'','','',1)", &[&name]);
    }
    if app.db.get("api_key").is_empty() {
        app.db.set("api_key", &util::rand_token(40));
    }
    // upgrade legacy sha256 admin hash stored in the db is done at next successful login

    tokio::spawn(sync::run(app.clone()));
    tokio::spawn(tunnel::panel::local_loop(app.clone()));
    tokio::spawn(tunnel::panel::auto_update_loop(app.clone()));
    // an updated panel also moves an emergency chat on this server onto the new binary
    tokio::task::spawn_blocking(emergency::restart_if_outdated);
    tokio::spawn(xray::panel::local_loop(app.clone()));
    // certificates of this server (Xray, emergency chat) that are close to their end
    certbot::renew_loop();
    tokio::spawn(backup::telegram_loop(app.clone()));
    tokio::spawn(channel::channel_loop(app.clone()));
    if let Some(b) = bot::Bot::new(app.clone()) {
        tokio::spawn(b.run());
        eprintln!("telegram bot started");
    }

    let port = app.env.get("PANEL_PORT").cloned().unwrap_or_else(|| "8080".into());
    let bind = app.env.get("PANEL_BIND").cloned().unwrap_or_else(|| "127.0.0.1".into());
    let addr = format!("{}:{}", bind, port);
    eprintln!("kanki panel {} on {}", VERSION, addr);
    let l = tokio::net::TcpListener::bind(&addr).await.expect("bind");
    axum::serve(l, api::master_router(app)).await.expect("serve");
}
