//! Kanki Panel: WireGuard / AmneziaWG / Hysteria2 panel with a built-in Telegram sales bot
// Handlers return `Result<_, axum::response::Response>` so `?` can short-circuit straight to an HTTP reply
// (boxing it would only add an allocation per error), and the shared-state tuples are private to one module each.
#![allow(clippy::result_large_err, clippy::type_complexity)]
// core: database, shared helpers, SSL, pinned certificates, firewall, live numbers (src/core)
#[path = "core/db.rs"]
mod db;
#[path = "core/util.rs"]
mod util;
#[path = "core/secrets.rs"]
mod secrets;
#[path = "core/certbot.rs"]
mod certbot;
#[path = "core/pin.rs"]
mod pin;
#[path = "core/fw.rs"]
mod fw;
#[path = "core/live.rs"]
mod live;
#[path = "core/netq.rs"]
mod netq;
#[path = "core/access.rs"]
mod access;
#[path = "core/sign.rs"]
mod sign;
#[path = "core/creds.rs"]
mod creds;
#[path = "core/release.rs"]
mod release;
#[cfg(test)]
#[path = "core/sign_tests.rs"]
mod sign_tests;
#[cfg(test)]
#[path = "core/access_tests.rs"]
mod access_tests;

// panel: the admin panel's web server and API, login and tokens, request limits, system and updates, backups (src/panel)
#[path = "panel/api.rs"]
mod api;
#[path = "panel/auth.rs"]
mod auth;
#[path = "panel/limit.rs"]
mod limit;
#[path = "panel/admin.rs"]
mod admin;
#[path = "panel/backup.rs"]
mod backup;
#[path = "panel/bkcrypt.rs"]
mod bkcrypt;
#[path = "panel/migrate.rs"]
mod migrate;
#[path = "panel/cleanup.rs"]
mod cleanup;
#[path = "panel/cdn.rs"]
mod cdn;

// servers: VPN servers (add, edit, remove), cores on/off per server, the second config through a tunnel, exit country (src/servers)
#[path = "servers/servers.rs"]
mod servers;
#[path = "servers/cores.rs"]
mod cores;
#[path = "servers/twin.rs"]
mod twin;
#[path = "servers/direct.rs"]
mod direct;
#[path = "servers/exitgeo.rs"]
mod exitgeo;
#[path = "servers/traffic.rs"]
mod srvtraffic;

// subscription: the subscription on an Iran server or its own domain, users' devices, app files (src/subscription)
#[path = "subscription/subiran.rs"]
mod subiran;
#[path = "subscription/subdomain.rs"]
mod subdomain;
#[path = "subscription/devices.rs"]
mod devices;
#[path = "subscription/apps.rs"]
mod apps;
#[path = "subscription/sublink.rs"]
mod sublink;

// vpn: the VPN cores and syncing users to the servers (src/vpn)
#[path = "vpn/wg.rs"]
mod wg;
#[path = "vpn/isolate.rs"]
mod isolate;
#[path = "vpn/hy2.rs"]
mod hy2;
#[path = "vpn/kmix.rs"]
mod kmix;
#[path = "vpn/sync.rs"]
mod sync;
#[path = "vpn/amnezia.rs"]
mod amnezia;
#[path = "vpn/mtu.rs"]
mod mtu;

// bot: the Telegram sales bot, its shop and mini app, the smart channel, the AI writer (src/bot)
#[path = "bot/bot.rs"]
mod bot;
#[path = "bot/shop.rs"]
mod shop;
#[path = "bot/miniapp.rs"]
mod miniapp;
#[path = "bot/channel.rs"]
mod channel;
#[path = "bot/ai.rs"]
mod ai;
#[path = "bot/pay.rs"]
mod pay;
#[path = "bot/buttons.rs"]
mod buttons;
#[path = "bot/monitor.rs"]
mod monitor;

// tunnel: tunnels between servers and tunnel servers; the wire protocols in src/tunnel/transport
mod tunnel;

// xray: Xray-core on the servers and its part of the panel
mod xray;

// dns: Kanki DNS
mod dns;


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

/// A panel with an empty database of its own, for the tests
#[cfg(test)]
pub(crate) fn test_app() -> std::sync::Arc<App> {
    test_app_env(&[])
}

/// `test_app` with more settings of kanki.env (a node's NODE_TOKEN …)
#[cfg(test)]
pub(crate) fn test_app_env(extra: &[(&str, &str)]) -> std::sync::Arc<App> {
    let dir = std::env::temp_dir().join(format!("kanki-test-{}", util::rand_token(8)));
    std::fs::create_dir_all(&dir).unwrap();
    let mut env = HashMap::from([("DOMAIN".to_string(), "fi.example.com".to_string()), ("BACKUP_PASS_FILE".to_string(), dir.join("backup.pass").to_string_lossy().to_string())]);
    env.extend(extra.iter().map(|(k, v)| (k.to_string(), v.to_string())));
    let db = db::Db::open(dir.join("kanki.db").to_str().unwrap());
    creds::init(&db);
    std::sync::Arc::new(App {
        db,
        env,
        hy2_allowed: Mutex::new(Default::default()), limits: Mutex::new(Default::default()), reported: Mutex::new(Default::default()),
        login_fails: Mutex::new(Default::default()), sync_lock: tokio::sync::Mutex::new(()), bot_alive: AtomicI64::new(0),
        http: reqwest::Client::new(), http_insecure: reqwest::Client::new(), pin_clients: Mutex::new(Default::default()),
    })
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
        let mut g = self.pin_clients.lock().unwrap_or_else(|e| e.into_inner());
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
        let mut g = self.pin_clients.lock().unwrap_or_else(|e| e.into_inner());
        for key in [id, addr] {
            let _ = std::fs::remove_file(self.node_pin_file(key));
            g.remove(&pin_key(key));
        }
        drop(g);
        // 3.69: a reinstalled node starts its signing ratchet again (with its new token)
        crate::sync::forget_node_sig(self, &[id, addr]);
    }
    /// The pin a node's first contact made (keyed by address) also becomes the pin of its id,
    /// so the certificate the admin added is the one later syncs expect.
    pub fn adopt_node_pin(&self, addr: &str, id: &str) {
        let _ = std::fs::copy(self.node_pin_file(addr), self.node_pin_file(id));
        self.pin_clients.lock().unwrap_or_else(|e| e.into_inner()).remove(&pin_key(id));
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

/// A secret given to the command line: "-" or nothing = the first line of stdin (3.68: so it is not in the
/// process list for other users to read); anything else is taken as it is, for scripts of older versions
fn secret_arg(a: Option<&String>) -> String {
    match a.map(|s| s.as_str()) {
        Some(v) if v != "-" => v.to_string(),
        _ => {
            let mut line = String::new();
            if let Err(e) = std::io::stdin().read_line(&mut line) {
                eprintln!("could not read stdin: {}", e);
            }
            line.trim_end_matches(['\n', '\r']).to_string()
        }
    }
}

/// The data folder 0700; the database, its WAL and shared memory, the env file and the WireGuard configs 0600;
/// Hysteria's config root:hysteria 0640 (its service reads it). Logged, never fatal: the panel must start.
fn secure_files(data: &str) {
    if let Err(e) = util::private_dir(data) {
        eprintln!("permissions: {}: {}", data, e);
    }
    if let Err(e) = util::private_dir(&format!("{}/tmp", data)) {
        eprintln!("permissions: {}/tmp: {}", data, e);
    }
    for f in ["kanki.db", "kanki.db-wal", "kanki.db-shm"] {
        if let Err(e) = util::chmod_if_present(&format!("{}/{}", data, f), 0o600) {
            eprintln!("permissions: {}/{}: {}", data, f, e);
        }
    }
    for f in [ENV_PATH, "/etc/wireguard/wg0.conf", "/etc/amnezia/amneziawg/awg0.conf"] {
        if let Err(e) = util::chmod_if_present(f, 0o600) {
            eprintln!("permissions: {}: {}", f, e);
        }
    }
    if let Err(e) = util::service_readable("/etc/hysteria/config.yaml", "hysteria") {
        eprintln!("permissions: /etc/hysteria/config.yaml: {}", e);
    }
    harden_units();
}

/// Units installed before 3.68 get the hardening of new installs as a drop-in (PrivateTmp, NoNewPrivileges);
/// it takes effect at their next restart
fn harden_units() {
    const DROP: &str = "# written by kanki-panel 3.68\n[Service]\nPrivateTmp=true\nNoNewPrivileges=true\n";
    let mut wrote = false;
    for unit in ["kanki-panel", "kanki-node", "kanki-tunnel"] {
        if !std::path::Path::new(&format!("/etc/systemd/system/{}.service", unit)).exists() {
            continue;
        }
        let dir = format!("/etc/systemd/system/{}.service.d", unit);
        let f = format!("{}/10-kanki-hardening.conf", dir);
        if std::fs::read_to_string(&f).map(|t| t == DROP).unwrap_or(false) {
            continue;
        }
        if let Err(e) = std::fs::create_dir_all(&dir).and_then(|_| std::fs::write(&f, DROP)) {
            eprintln!("hardening: {}: {}", f, e);
            continue;
        }
        wrote = true;
    }
    if wrote {
        match std::process::Command::new("systemctl").arg("daemon-reload").status() {
            Ok(s) if s.success() => {}
            other => eprintln!("hardening: systemctl daemon-reload: {:?}", other),
        }
    }
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
            // 3.68: the password comes on stdin ("-" or no argument), never as an argument other users could read
            let p = secret_arg(args.get(2));
            println!("{}", util::hash_password(&p));
            return;
        }
        // what this binary understands, for install.sh (it may be newer or older than the binary it runs)
        "features" => {
            println!("stdin-secrets");
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
        // Kanki DNS on a DNS server (started by the agent)
        "dns" => {
            dns::run().await;
            return;
        }
        "tunnel-agent" => {
            netq::spawn();
            // what microtun and KPING (gone in 3.60) left on this server
            let _ = tokio::task::spawn_blocking(sync::forget_retired).await;
            tunnel::agent::run(VERSION).await;
            return;
        }
        // standalone tunnel, no panel and no database: runs the tunnels written in a JSON file
        // the installer, after it put a moved or restored panel's database in place: the certificates of
        // the backup (only what this machine lacks)
        "restore-files" => {
            let Some(dir) = args.get(2) else {
                eprintln!("usage: kanki-panel restore-files <unpacked backup folder>");
                std::process::exit(1);
            };
            for d in backup::restore_extra(dir) {
                println!("restored: {}", d);
            }
            return;
        }
        // 3.69: the installer opens a backup with these (any format the panel ever made), never with
        // `openssl` + `tar` straight: the archive is authenticated and unpacked entry by entry
        // usage: KANKI_BK_PASS=… kanki-panel backup-unpack <backup file> <empty folder>
        "backup-unpack" => {
            let (Some(file), Some(dir)) = (args.get(2), args.get(3)) else {
                eprintln!("usage: KANKI_BK_PASS=<passphrase> kanki-panel backup-unpack <backup file> <empty folder>");
                std::process::exit(1);
            };
            let pass = std::env::var("KANKI_BK_PASS").unwrap_or_default();
            match backup::unpack_file(file, dir, &pass) {
                Ok(n) => println!("unpacked {} entries", n),
                Err(e) => {
                    eprintln!("{}", e);
                    std::process::exit(1);
                }
            }
            return;
        }
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
    // a restore made in the panel last run is put in place before the database is opened
    backup::take_pending(&data);
    // 3.68: secrets at rest are sealed with the master key of the env file (made once when missing)
    let sealed = secrets::init(ENV_PATH);
    let db = db::Db::open(&format!("{}/kanki.db", data));
    if sealed {
        db.migrate_secrets();
    }
    // 3.69: the key of the keyed account credentials (made once)
    creds::init(&db);
    // 3.68: the data folder (database, its WAL, keys, backups' work files) is root's alone
    secure_files(&data);
    // 3.69: no signed request made before this start is taken (the nonces seen before a restart are gone)
    sign::init_floor(&format!("{}/sig-floor-{}", data, if cmd == "node" { "node" } else { "panel" }));

    if cmd == "reset-admin" {
        auth::audit_db(&db, "cli", "CLI", "reset-admin", 0, "local", "");
        let Some(u) = args.get(2) else {
            eprintln!("usage: kanki-panel reset-admin <user> -   (the password on stdin)");
            std::process::exit(1);
        };
        let p = secret_arg(args.get(3));
        if p.chars().count() < auth::MIN_PASSWORD {
            eprintln!("the password must be at least {} characters", auth::MIN_PASSWORD);
            std::process::exit(1);
        }
        let p = &p;
        if auth::reserved_admin_name(u.trim()) {
            eprintln!("this username is reserved (api-key, token:…), pick another");
            std::process::exit(1);
        }
        db.set("admin_user", u);
        db.set("admin_pass", &util::hash_password(p));
        db.set("totp_on", "0");
        db.set("force_2fa", "0");
        let _ = db.exec("DELETE FROM sessions", &[]);
        println!("Admin reset. Restart the panel: systemctl restart kanki-panel");
        return;
    }
    if cmd == "set-bot" {
        auth::audit_db(&db, "cli", "CLI", "set-bot", 0, "local", "");
        let token = secret_arg(args.get(2));
        let admins = args.get(3).cloned().unwrap_or_default();
        db.set("bot_token", token.trim());
        db.set("bot_admins", admins.trim());
        db.set("bot_paused", "0");
        println!("{}", if token.trim().is_empty() { "Telegram bot removed." } else { "Telegram bot saved." });
        return;
    }
    if cmd == "reset-security" {
        auth::audit_db(&db, "cli", "CLI", "reset-security", 0, "local", "");
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
            .connect_timeout(crate::pin::CONNECT_TIMEOUT)
            .pool_idle_timeout(crate::pin::POOL_IDLE)
            .tcp_keepalive(crate::pin::TCP_KEEPALIVE)
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

    // OpenVPN left by a very old version (servers installed before it was dropped)
    let _ = tokio::task::spawn_blocking(admin::drop_legacy_openvpn).await;
    // and what microtun and KPING (gone in 3.60) left
    let _ = tokio::task::spawn_blocking(sync::forget_retired).await;
    // short, fair network queues (games): panel and VPN node alike
    netq::spawn();

    if cmd == "node" {
        let port = app.env.get("NODE_PORT").cloned().unwrap_or_else(|| "2096".into());
        // new installs put Caddy (TLS) in front and bind locally; old installs listened publicly
        // 3.68: without NODE_BIND a node with Caddy in front (NODE_PUBLIC_PORT set by the installer) binds only to
        // 127.0.0.1; an old plain-HTTP node (no Caddy) keeps 0.0.0.0 so the panel still reaches it
        let bind = app.env.get("NODE_BIND").cloned().unwrap_or_else(|| {
            if app.env.get("NODE_PUBLIC_PORT").is_some_and(|p| !p.trim().is_empty()) {
                "127.0.0.1".into()
            } else {
                eprintln!("kanki node: NODE_BIND is not set and there is no TLS front: listening on 0.0.0.0 (reinstall the node to get TLS)");
                "0.0.0.0".into()
            }
        });
        let addr = format!("{}:{}", bind, port);
        eprintln!("kanki node agent {} on {}", VERSION, addr);
        let l = tokio::net::TcpListener::bind(&addr).await.expect("bind");
        axum::serve(l, api::node_router(app).into_make_service_with_connect_info::<std::net::SocketAddr>()).await.expect("serve");
        return;
    }

    // main server: local node + legacy API key
    if app.db.node("local").is_none() {
        let name = app.env.get("LOCAL_NAME").cloned().unwrap_or_else(|| "Main".into());
        let _ = app.db.exec("INSERT INTO nodes(id,name,address,endpoint,token,online) VALUES('local',?1,'','','',1)", &[&name]);
    }
    // the first start on a new server after a move or a restore
    migrate::after_move(&app);
    migrate::load_frozen(&app);
    tokio::spawn(migrate::freeze_loop(app.clone()));
    {
        let a = app.clone();
        std::thread::spawn(move || {
            subdomain::ensure_on_start(&a);
            cdn::ensure_on_start(&a);
        });
    }
    auth::legacy_key_start(&app.db);
    // upgrade legacy sha256 admin hash stored in the db is done at next successful login

    tunnel::panel::drop_vip(&app);
    tokio::spawn(sync::run(app.clone()));
    // deleted nodes that were off at the time are asked again to remove themselves
    tokio::spawn(api::leftover_loop(app.clone()));
    // where each VPN server's traffic leaves (country and city for the app's map)
    tokio::spawn(exitgeo::run(app.clone()));
    // what every server's network card moved (the traffic table of the servers)
    tokio::spawn(srvtraffic::run(app.clone()));
    tokio::spawn(tunnel::panel::local_loop(app.clone()));
    // a node and an agent of the same machine (added apart before 3.9) are shown as one server
    tokio::spawn(servers::link_loop(app.clone()));
    // the direct names of the servers (fr.example.com …) for the app's direct configs, checked every 5 minutes
    tokio::spawn(direct::run(app.clone()));
    // this server's public IP, written into every backup
    tokio::spawn(migrate::ip_loop(app.clone()));
    tokio::spawn(tunnel::panel::auto_update_loop(app.clone()));
    tokio::spawn(xray::panel::local_loop(app.clone()));
    // certificates of this server (Xray, Kanki DNS) that are close to their end
    certbot::renew_loop();
    tokio::spawn(backup::telegram_loop(app.clone()));
    servers::install_cores(&app);
    tokio::spawn(cleanup::sweep_loop(app.clone()));
    tokio::spawn(cleanup::offline_loop(app.clone()));
    tokio::spawn(channel::channel_loop(app.clone()));
    if let Some(b) = bot::Bot::new(app.clone()) {
        tokio::spawn(b.run());
        eprintln!("telegram bot started");
    }
    // the alerts (servers, tunnels, paths) and the report bot when it has its own token
    monitor::start(app.clone());

    let port = app.env.get("PANEL_PORT").cloned().unwrap_or_else(|| "8080".into());
    let bind = app.env.get("PANEL_BIND").cloned().unwrap_or_else(|| "127.0.0.1".into());
    let addr = format!("{}:{}", bind, port);
    eprintln!("kanki panel {} on {}", VERSION, addr);
    let l = tokio::net::TcpListener::bind(&addr).await.expect("bind");
    axum::serve(l, api::master_router(app).into_make_service_with_connect_info::<std::net::SocketAddr>()).await.expect("serve");
}
