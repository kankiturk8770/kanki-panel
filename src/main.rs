//! Kanki Panel — پنل سبک WireGuard / AmneziaWG / Hysteria2 با ربات تلگرام داخلی
mod admin;
mod api;
mod bot;
mod db;
mod hy2;
mod sync;
mod util;
mod wg;

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

pub const ENV_PATH: &str = "/etc/kanki/kanki.env";

pub struct App {
    pub db: db::Db,
    pub env: HashMap<String, String>,
    pub sessions: Mutex<HashSet<String>>,
    /// کد اشتراک ← نام کاربری (کاربران مجاز Hysteria2 روی همین سرور)
    pub hy2_allowed: Mutex<HashMap<String, String>>,
    pub http: reqwest::Client,
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(|s| s.as_str()).unwrap_or("serve");

    if cmd == "hash-password" {
        println!("{}", util::hash_password(args.get(2).map(|s| s.as_str()).unwrap_or("")));
        return;
    }
    if cmd == "version" {
        println!("kanki-panel {}", env!("CARGO_PKG_VERSION"));
        return;
    }

    let env = util::load_env(ENV_PATH);
    let data = env.get("DATA_DIR").cloned().unwrap_or_else(|| "/var/lib/kanki".into());
    let _ = std::fs::create_dir_all(&data);
    let db = db::Db::open(&format!("{}/kanki.db", data));
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .danger_accept_invalid_certs(true)
        .build()
        .expect("http");
    let app = Arc::new(App { db, env, sessions: Mutex::new(HashSet::new()), hy2_allowed: Mutex::new(HashMap::new()), http });

    if cmd == "node" {
        let port = app.env.get("NODE_PORT").cloned().unwrap_or_else(|| "2096".into());
        let addr = format!("0.0.0.0:{}", port);
        eprintln!("kanki node agent on {}", addr);
        let l = tokio::net::TcpListener::bind(&addr).await.expect("bind");
        axum::serve(l, api::node_router(app)).await.expect("serve");
        return;
    }

    // سرور اصلی: نود محلی + کلید API
    if app.db.node("local").is_none() {
        let name = app.env.get("LOCAL_NAME").cloned().unwrap_or_else(|| "Main".into());
        let _ = app.db.exec("INSERT INTO nodes(id,name,address,endpoint,token,online) VALUES('local',?1,'','','',1)", &[&name]);
    }
    if app.db.get("api_key").is_empty() {
        app.db.set("api_key", &util::rand_token(40));
    }

    tokio::spawn(sync::run(app.clone()));
    if let Some(b) = bot::Bot::new(app.clone()) {
        tokio::spawn(b.run());
        eprintln!("telegram bot started");
    }

    let port = app.env.get("PANEL_PORT").cloned().unwrap_or_else(|| "8080".into());
    let addr = format!("127.0.0.1:{}", port);
    eprintln!("kanki panel on {}", addr);
    let l = tokio::net::TcpListener::bind(&addr).await.expect("bind");
    axum::serve(l, api::master_router(app)).await.expect("serve");
}
