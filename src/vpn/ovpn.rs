//! OpenVPN (UDP + TCP): username/password auth against the panel, traffic + online
//! through the management interface, instant kick of users who lost access.
use crate::db::{Node, User};
use crate::App;
use std::collections::{HashMap, HashSet};

const DIR: &str = "/etc/openvpn/server";

pub fn read_ca() -> String {
    std::fs::read_to_string(format!("{}/ca.crt", DIR)).unwrap_or_default()
}

pub fn read_tc() -> String {
    std::fs::read_to_string(format!("{}/tc.key", DIR)).unwrap_or_default()
}

fn mgmt_ports(app: &App) -> Vec<String> {
    ["OVPN_UDP_MGMT", "OVPN_TCP_MGMT"]
        .iter()
        .filter_map(|k| app.env.get(*k).cloned())
        .filter(|p| !p.is_empty())
        .collect()
}

async fn mgmt_inner(addr: String, cmds: Vec<String>) -> Option<Vec<String>> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let s = tokio::net::TcpStream::connect(addr).await.ok()?;
    let (r, mut w) = s.into_split();
    let mut lines = BufReader::new(r).lines();
    let mut out: Vec<String> = vec![];
    for c in cmds {
        w.write_all(format!("{}\n", c).as_bytes()).await.ok()?;
        let multi = c.starts_with("status");
        loop {
            let l = match lines.next_line().await {
                Ok(Some(l)) => l,
                _ => return Some(out),
            };
            if l.starts_with('>') {
                continue;
            }
            if multi {
                if l.trim() == "END" {
                    break;
                }
                out.push(l);
            } else {
                out.push(l);
                break;
            }
        }
    }
    let _ = w.write_all(b"quit\n").await;
    Some(out)
}

async fn mgmt(port: &str, cmds: Vec<String>) -> Vec<String> {
    if port.is_empty() || cmds.is_empty() {
        return vec![];
    }
    let fut = mgmt_inner(format!("127.0.0.1:{}", port), cmds);
    match tokio::time::timeout(std::time::Duration::from_secs(5), fut).await {
        Ok(Some(v)) => v,
        _ => vec![],
    }
}

struct Client {
    cn: String,
    bytes: i64,
    cid: String,
}

async fn clients(port: &str) -> Vec<Client> {
    let lines = mgmt(port, vec!["status 2".into()]).await;
    // column positions from the HEADER line (format differs between OpenVPN versions)
    let mut idx: HashMap<String, usize> = HashMap::new();
    for l in &lines {
        if let Some(h) = l.strip_prefix("HEADER,CLIENT_LIST,") {
            for (i, name) in h.split(',').enumerate() {
                idx.insert(name.trim().to_string(), i + 1);
            }
        }
    }
    let col = |name: &str, def: usize| idx.get(name).copied().unwrap_or(def);
    let (c_cn, c_rx, c_tx, c_id) = (col("Common Name", 1), col("Bytes Received", 5), col("Bytes Sent", 6), col("Client ID", 10));
    let mut out = vec![];
    for l in &lines {
        if !l.starts_with("CLIENT_LIST,") {
            continue;
        }
        let f: Vec<&str> = l.split(',').collect();
        let get = |i: usize| f.get(i).copied().unwrap_or("");
        let cn = get(c_cn).to_string();
        if cn.is_empty() || cn == "UNDEF" {
            continue;
        }
        let rx: i64 = get(c_rx).parse().unwrap_or(0);
        let tx: i64 = get(c_tx).parse().unwrap_or(0);
        out.push(Client { cn, bytes: rx + tx, cid: get(c_id).to_string() });
    }
    out
}

/// Traffic deltas + online per user; kicks users not in `allowed` (username -> code)
pub async fn poll(app: &App, allowed: &HashMap<String, String>) -> (HashMap<String, (i64, i64)>, HashMap<String, i64>) {
    let mut traffic: HashMap<String, (i64, i64)> = HashMap::new();
    let mut online: HashMap<String, i64> = HashMap::new();
    let ports = mgmt_ports(app);
    if ports.is_empty() {
        return (traffic, online);
    }
    // first round after a restart only primes counters (avoids recounting old bytes)
    let priming = !app.ovpn_last.lock().unwrap().contains_key("__primed");
    let mut keep: HashSet<String> = HashSet::new();
    keep.insert("__primed".into());
    for port in ports {
        let list = clients(&port).await;
        let mut kill: HashSet<String> = HashSet::new();
        for c in list {
            if !allowed.contains_key(&c.cn) {
                kill.insert(c.cn.clone());
                continue;
            }
            let key = format!("{}:{}", port, c.cid);
            let prev = app.ovpn_last.lock().unwrap().insert(key.clone(), c.bytes);
            let delta = match prev {
                _ if priming => 0,
                Some(p) if c.bytes >= p => c.bytes - p,
                Some(_) => c.bytes,
                None => c.bytes,
            };
            traffic.entry(c.cn.clone()).or_insert((0, 0)).0 += delta;
            *online.entry(c.cn.clone()).or_insert(0) += 1;
            keep.insert(key);
        }
        if !kill.is_empty() {
            let cmds: Vec<String> = kill.iter().filter(|k| !k.contains(' ')).map(|k| format!("kill {}", k)).collect();
            mgmt(&port, cmds).await;
        }
    }
    let mut last = app.ovpn_last.lock().unwrap();
    last.retain(|k, _| keep.contains(k));
    last.insert("__primed".into(), 0);
    (traffic, online)
}

pub async fn online_of(app: &App, username: &str) -> i64 {
    let mut n = 0;
    for port in mgmt_ports(app) {
        n += clients(&port).await.iter().filter(|c| c.cn == username).count() as i64;
    }
    n
}

/// .ovpn client profile with inline CA / tls-crypt (and credentials if enabled)
pub fn client_config(app: &App, u: &User, n: &Node, endpoint: &str, t: &str) -> Option<String> {
    let info = crate::api::node_info(n);
    let port = info[if t == "tcp" { "ovpn_tcp" } else { "ovpn_udp" }].as_str().unwrap_or("").to_string();
    let ca = info["ovpn_ca"].as_str().unwrap_or("").trim().to_string();
    let tc = info["ovpn_tc"].as_str().unwrap_or("").trim().to_string();
    if port.is_empty() || ca.is_empty() || tc.is_empty() {
        return None;
    }
    let auth = if app.db.get("ovpn_inline_auth") != "0" {
        format!("<auth-user-pass>\n{}\n{}\n</auth-user-pass>\n", u.username, u.code)
    } else {
        "auth-user-pass\n".to_string()
    };
    Some(format!(
        "# {name} - {node} ({t})\nclient\ndev tun\nproto {proto}\nremote {ep} {port}\nresolv-retry infinite\nnobind\npersist-key\npersist-tun\nremote-cert-tls server\nauth-nocache\ncipher AES-128-GCM\ndata-ciphers AES-128-GCM:AES-256-GCM:CHACHA20-POLY1305\nverb 3\n{auth}<ca>\n{ca}\n</ca>\n<tls-crypt>\n{tc}\n</tls-crypt>\n",
        name = u.username, node = n.name, t = t.to_uppercase(), proto = if t == "tcp" { "tcp" } else { "udp" },
        ep = endpoint, port = port, auth = auth, ca = ca, tc = tc
    ))
}
