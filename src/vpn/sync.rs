//! Sync users to nodes, count traffic, enforce limits.
//! One round at a time (sync_lock) so traffic is never counted twice.
use crate::db::{Node, User};
use crate::util::now;
use crate::wg::{self, PeerSpec, PeerStat};
use crate::App;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

#[derive(Serialize, Deserialize, Default)]
pub struct SyncReq {
    #[serde(default)]
    pub wg: Vec<PeerSpec>,
    #[serde(default)]
    pub awg: Vec<PeerSpec>,
    /// sub code -> username (Hysteria2)
    #[serde(default)]
    pub hy2: HashMap<String, String>,
    /// username -> (max connections, online across all nodes)
    #[serde(default)]
    pub limits: HashMap<String, (i64, i64)>,
    /// KANKI MIX on this server (None = a panel that does not manage it: leave it as it is)
    #[serde(default)]
    pub kmix: Option<crate::kmix::KmixCfg>,
    /// MIX+ was removed: the panel always sends `{}` here, which an agent that still has MIX+ reads
    /// as "everything off" (it stops it and closes its port). Newer agents ignore it.
    #[serde(default)]
    pub kcore: Option<serde_json::Value>,
    /// WireGuard / AmneziaWG / Hysteria2 switched off on this server ("wg", "awg", "hy2"): stopped and
    /// their ports closed (see `cores::apply`); an older agent ignores it but gets no users for them
    #[serde(default)]
    pub off: Vec<String>,
    /// connection limit: addresses of extra devices on one WireGuard / AmneziaWG config, dropped by the
    /// firewall here ("wg 1.2.3.4:5678")
    #[serde(default)]
    pub block: Vec<String>,
    /// connection limit: Hysteria2 sessions each user at their limit may have on this server
    /// (username -> sessions); more are dropped here and refused at login
    #[serde(default)]
    pub hy2_cap: HashMap<String, i64>,
    /// automatic MTU: interface -> MTU ("wg0" -> 1320) worked out by the panel (`mtu.rs`); empty =
    /// leave them; an older agent ignores it
    #[serde(default)]
    pub mtu: HashMap<String, u16>,
}

#[derive(Serialize, Deserialize, Default)]
pub struct SyncResp {
    #[serde(default)]
    pub wg: HashMap<String, PeerStat>,
    #[serde(default)]
    pub awg: HashMap<String, PeerStat>,
    #[serde(default)]
    pub hy2: HashMap<String, (i64, i64)>,
    #[serde(default)]
    pub hy2_online: HashMap<String, i64>,
    /// KANKI MIX: username -> (rx, tx) since the last sync, and devices online
    #[serde(default)]
    pub kmix: HashMap<String, (i64, i64)>,
    #[serde(default)]
    pub kmix_online: HashMap<String, i64>,
    #[serde(default)]
    pub kmix_error: String,
    /// KANKI MIX's live health on this server (3.67, `kmix::health`): sessions, gaming, hinted, the loss the
    /// apps measured, the extra ports; Null = an older node, or KANKI MIX off
    #[serde(default)]
    pub kmix_health: Value,
    /// this server's clock (unix seconds) when it answered: handshake times are compared with it,
    /// not with the panel's clock (an older node sends 0)
    #[serde(default)]
    pub now: i64,
}

fn loadavg() -> String {
    std::fs::read_to_string("/proc/loadavg").unwrap_or_default().split_whitespace().take(3).collect::<Vec<_>>().join(" ")
}

/// This server's keys, ports and params (used to build client configs)
pub fn local_info(app: &App) -> Value {
    let e = &app.env;
    let g = |k: &str| e.get(k).cloned().unwrap_or_default();
    let mut v = json!({
        "wg_pub": wg::iface_pub("wg"), "wg_port": wg::listen_port("wg"),
        "awg_pub": wg::iface_pub("awg"), "awg_port": wg::listen_port("awg"),
        "awg": wg::awg_params(),
        "hy2_port": g("HY2_PORT"), "hy2_obfs": g("HY2_OBFS"), "hy2_sni": g("DOMAIN"),
        "hy2_insecure": g("HY2_INSECURE"),
        "services": crate::admin::service_states(), "version": crate::VERSION, "load": loadavg(),
        "stats": crate::admin::node_stats(),
    });
    if let (Some(o), Some(k)) = (v.as_object_mut(), crate::kmix::info().as_object()) {
        o.extend(k.clone());
    }
    v
}

/// `local_info` off the async workers: it runs `systemctl` for every service and reads /proc, which
/// would hold a worker thread (and every request waiting on it) for a moment on each round
pub async fn local_info_async(app: &Arc<App>) -> Value {
    let a = app.clone();
    tokio::task::spawn_blocking(move || local_info(&a)).await.unwrap_or_else(|_| json!({}))
}

/// Apply on this server
pub async fn apply_local(app: &App, req: SyncReq) -> SyncResp {
    static ACL: std::sync::Once = std::sync::Once::new();
    if !ACL.is_completed() {
        let _ = tokio::task::spawn_blocking(|| {
            ACL.call_once(|| {
                crate::hy2::ensure_acl();
                crate::hy2::ensure_auth_key();
            })
        })
        .await;
    }
    // 3.68: users no longer allowed (deleted, disabled, frozen, expired, over their data) are cut off at once
    let gone = {
        let mut cur = app.hy2_allowed.lock().unwrap_or_else(|e| e.into_inner());
        let gone = crate::hy2::revoked(&cur, &req.hy2);
        *cur = req.hy2.clone();
        gone
    };
    *app.limits.lock().unwrap_or_else(|e| e.into_inner()) = req.limits.clone();
    let hy2_names: HashSet<String> = req.hy2.values().cloned().collect();
    let block = req.block.clone();
    let _ = tokio::task::spawn_blocking(move || crate::wg::set_blocked(&block)).await;
    // WireGuard / AmneziaWG users never reach the management ports or private networks (3.68)
    let env = app.env.clone();
    let _ = tokio::task::spawn_blocking(move || crate::isolate::apply(&env)).await;
    let off = req.off.clone();
    let _ = tokio::task::spawn_blocking(move || crate::cores::apply(&off)).await;
    let (wgv, awgv, mtu) = (req.wg, req.awg, req.mtu);
    let (w, a) = tokio::task::spawn_blocking(move || {
        let r = (wg::apply("wg", &wgv), wg::apply("awg", &awgv));
        crate::mtu::apply_ifaces(&mtu);
        r
    })
        .await
        .unwrap_or_default();
    let port = app.env.get("HY2_STATS_PORT").cloned().unwrap_or_default();
    let secret = app.env.get("HY2_SECRET").cloned().unwrap_or_default();
    crate::hy2::kick(&port, &secret, &gone).await;
    let hy2 = crate::hy2::traffic(&port, &secret).await;
    let mut hy2_online = crate::hy2::online(&port, &secret).await;
    // a ping session next to a real one is no device: where Hysteria tells which of its connections
    // moved data, a user counts as many devices as moved data (at least one, at most what is open)
    if let Some(real) = crate::hy2::moving(&port, &secret, now()).await {
        for (k, c) in hy2_online.iter_mut() {
            *c = hy2_devices(*c, real.get(k).copied().unwrap_or(0));
        }
    }
    *hy2_caps().lock().unwrap_or_else(|e| e.into_inner()) = req.hy2_cap.clone();
    // disconnect Hysteria2 users who are no longer allowed (expired / over quota / disabled)
    let mut kick: Vec<String> = hy2_online.keys().filter(|k| !hy2_names.contains(*k)).cloned().collect();
    // more sessions here than the limit leaves for this server: Hysteria can only drop all sessions of
    // a user, and the login check then lets back in no more than allowed
    for (k, c) in hy2_online.iter() {
        if req.hy2_cap.get(k).is_some_and(|cap| c > cap) && !kick.contains(k) {
            kick.push(k.clone());
        }
    }
    crate::hy2::kick(&port, &secret, &kick).await;
    let mut rep: HashMap<String, i64> = HashMap::new();
    for (k, v) in hy2_online.iter() {
        *rep.entry(k.clone()).or_default() += v;
    }
    *app.reported.lock().unwrap_or_else(|e| e.into_inner()) = rep;
    let (mut kmix, mut kmix_online, mut kmix_error, mut kmix_health) = (HashMap::new(), HashMap::new(), String::new(), Value::Null);
    if let Some(cfg) = req.kmix {
        // traffic first: a restart below would lose what was not read yet
        kmix = crate::kmix::traffic().await;
        let r = tokio::task::spawn_blocking(move || crate::kmix::apply(&cfg)).await.unwrap_or_else(|_| Err("kanki-mix apply crashed".into()));
        if let Err(e) = r {
            if last_kmix_err().lock().unwrap_or_else(|e| e.into_inner()).as_deref() != Some(e.as_str()) {
                eprintln!("kanki-mix: {}", e);
            }
            kmix_error = e;
        }
        *last_kmix_err().lock().unwrap_or_else(|e| e.into_inner()) = Some(kmix_error.clone()).filter(|e| !e.is_empty());
        kmix_online = crate::kmix::online().await;
        kmix_health = crate::kmix::health().await;
    }
    // the firewall rule an older version opened for MIX+ is closed once
    static MIXPLUS_GONE: std::sync::Once = std::sync::Once::new();
    MIXPLUS_GONE.call_once(|| {
        tokio::task::spawn_blocking(|| crate::fw::close("kcore"));
    });
    SyncResp { wg: w, awg: a, hy2, hy2_online, kmix, kmix_online, kmix_error, kmix_health, now: now() }
}

/// 3.60: microtun and KPING are gone (KANKI MIX does their work, with two paths). What they left on a server
/// that ran them: the firewall rules of their ports, the NAT of their address ranges, their cache files. Once a
/// start, by the node and by the tunnel agent; every step is harmless where there is nothing to take away.
pub fn forget_retired() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        retire_emergency();
        for k in ["mtun", "kping", "kpcore"] {
            crate::fw::close(k);
        }
        crate::mtu::forget_iface("mtun0");
        for f in ["/var/lib/kanki/kping.json", "/var/lib/kanki/kping-node.json"] {
            let _ = std::fs::remove_file(f);
        }
        for (subnet, iface) in [("10.79.0.0/16", "mtun0"), ("10.80.0.0/16", "mtun0"), ("10.81.0.0/16", "kping0")] {
            let rules: [&[&str]; 4] = [
                &["-t", "nat", "POSTROUTING", "-s", subnet, "!", "-o", iface, "-j", "MASQUERADE"],
                &["-t", "filter", "FORWARD", "-i", iface, "-j", "ACCEPT"],
                &["-t", "filter", "FORWARD", "-o", iface, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
                &["-t", "mangle", "FORWARD", "-o", iface, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"],
            ];
            for r in rules {
                // the same rule may have been put in twice; take every copy (at most a few)
                for _ in 0..4 {
                    let mut a: Vec<&str> = vec![r[0], r[1], "-D", r[2]];
                    a.extend(&r[3..]);
                    let ok = std::process::Command::new("iptables").args(&a).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null())
                        .status().map(|x| x.success()).unwrap_or(false);
                    if !ok {
                        break;
                    }
                }
            }
        }
    });
}

/// 3.65: the emergency chat is gone. What it left on a server that ran it goes with it: the service, its
/// firewall port, its config (the message signing key and the admin password hash) and its messages.
fn retire_emergency() {
    const UNIT_FILE: &str = "/etc/systemd/system/kanki-emergency.service";
    if std::path::Path::new(UNIT_FILE).exists() {
        match std::process::Command::new("systemctl").args(["disable", "--now", "-q", "kanki-emergency.service"]).output() {
            Ok(o) if !o.status.success() => eprintln!("retire emergency chat: systemctl disable failed ({})", o.status),
            Ok(_) => {}
            Err(e) => eprintln!("retire emergency chat: cannot run systemctl: {}", e),
        }
        remove_logged(UNIT_FILE, false);
        if let Err(e) = std::process::Command::new("systemctl").arg("daemon-reload").output() {
            eprintln!("retire emergency chat: cannot reload systemd: {}", e);
        }
    }
    crate::fw::close("emergency");
    remove_logged("/etc/kanki/emergency.json", false);
    remove_logged("/var/lib/kanki/emergency", true);
}

/// Removes a file or a folder; a missing one is fine, any other failure is logged
fn remove_logged(path: &str, dir: bool) {
    let r = if dir { std::fs::remove_dir_all(path) } else { std::fs::remove_file(path) };
    if let Err(e) = r {
        if e.kind() != std::io::ErrorKind::NotFound {
            eprintln!("cannot remove {}: {}", path, e);
        }
    }
}

/// Hysteria2 devices of a user on this server: `open` sessions, `real` of them seen moving data (a
/// session that only logged in is a ping; one that moves only UDP shows no streams, so at least one)
fn hy2_devices(open: i64, real: i64) -> i64 {
    open.min(real.max(1))
}

/// Hysteria2 sessions per user this server may have now (set on every sync; empty = no cap)
fn hy2_caps() -> &'static Mutex<HashMap<String, i64>> {
    static C: std::sync::OnceLock<Mutex<HashMap<String, i64>>> = std::sync::OnceLock::new();
    C.get_or_init(Default::default)
}

/// when each switched-off node was last given its empty user list
fn off_checked() -> &'static std::sync::Mutex<HashMap<String, i64>> {
    static M: std::sync::OnceLock<std::sync::Mutex<HashMap<String, i64>>> = std::sync::OnceLock::new();
    M.get_or_init(|| std::sync::Mutex::new(HashMap::new()))
}

/// the last KANKI MIX error (the same error is logged once, not every 30 s)
fn last_kmix_err() -> &'static std::sync::Mutex<Option<String>> {
    static E: std::sync::OnceLock<std::sync::Mutex<Option<String>>> = std::sync::OnceLock::new();
    E.get_or_init(|| std::sync::Mutex::new(None))
}

/// Is a WireGuard / AmneziaWG key with a recent handshake really in use? The Kanki apps "ping" every
/// server with a real handshake of the user's key (about 240 bytes, then nothing); that is not a
/// connection. A key counts once it moved real data (1 KB) and stays counted while anything moves
/// (keepalives every 25 s) within `LIVE_FOR` seconds; extra sync rounds a second apart change nothing.
fn live_peer(uid: i64, node: &str, proto: &str, moved: i64, now: i64) -> bool {
    static LIVE: std::sync::OnceLock<Mutex<HashMap<(i64, String, String), i64>>> = std::sync::OnceLock::new();
    let mut live = LIVE.get_or_init(Default::default).lock().unwrap_or_else(|e| e.into_inner());
    let key = (uid, node.to_string(), proto.to_string());
    let was = live.get(&key).copied();
    // a key that was last counted long ago (closed, then opened again) is new: one ping must not make
    // it a device. Rounds of keepalives only come 30 s or more apart, so the gap is wider than LIVE_FOR.
    let recent = was.is_some_and(|t| now - t < NEW_AFTER);
    if moved >= 1024 || (moved > 0 && recent) {
        live.insert(key, now);
        return true;
    }
    // a little data in two rounds in a row (an idle phone's keepalives every 25 s: it never moves 1 KB in
    // one round, so after a panel restart it stayed «0 connections»); a ping moves data in one round only
    static SMALL: std::sync::OnceLock<Mutex<HashMap<(i64, String, String), i64>>> = std::sync::OnceLock::new();
    let mut small = SMALL.get_or_init(Default::default).lock().unwrap_or_else(|e| e.into_inner());
    if moved > 0 {
        match small.get(&key).copied() {
            Some(t) if now - t >= 20 && now - t < NEW_AFTER => {
                small.remove(&key);
                live.insert(key, now);
                return true;
            }
            Some(t) if now - t < 20 => {}
            _ => {
                small.insert(key.clone(), now);
            }
        }
    }
    small.retain(|_, t| now - *t < NEW_AFTER);
    match was {
        Some(t) if now - t < LIVE_FOR => true,
        _ => {
            live.remove(&key);
            false
        }
    }
}

/// A Hysteria2 / KANKI MIX session the server reports: it counts once it moved real data
/// (1 KB) and then for as long as the server keeps it. A ping logs in and leaves without moving data.
fn sessions() -> &'static Mutex<HashMap<(i64, String, String), i64>> {
    static S: std::sync::OnceLock<Mutex<HashMap<(i64, String, String), i64>>> = std::sync::OnceLock::new();
    S.get_or_init(Default::default)
}

/// 3.58.1: a session counts while it moves data, and `LIVE_FOR` after its last data, like WireGuard. Before, it
/// counted for as long as the server kept it (KANKI MIX ~30 s, Hysteria2 up to minutes), so a one-device user
/// who switched to another protocol stayed shut out that long: the old session held the one place.
fn live_session(uid: i64, node: &str, proto: &str, moved: i64) -> bool {
    let mut s = sessions().lock().unwrap_or_else(|e| e.into_inner());
    let key = (uid, node.to_string(), proto.to_string());
    let t = now();
    if moved >= 1024 || (moved > 0 && s.contains_key(&key)) {
        s.insert(key, t);
        return true;
    }
    s.get(&key).is_some_and(|last| t - last < LIVE_FOR)
}

/// Forget the sessions of `node` that are no longer open there
fn forget_sessions(node: &str, open: impl Fn(i64, &str) -> bool) {
    sessions().lock().unwrap_or_else(|e| e.into_inner()).retain(|(u, n, p), _| n != node || open(*u, p));
}

/// How long a WireGuard / AmneziaWG key counts as connected after the last data it moved
const LIVE_FOR: i64 = 30;
/// … and after how long without data it is a new key that has to move 1 KB again
const NEW_AFTER: i64 = 120;

/// The connection limit of an account counts devices, over every server, protocol and app: a config
/// copied to several devices is several connections. Once a user has as many live devices as allowed,
/// every other server and protocol is shut for that user (the WireGuard / AmneziaWG key, the Hysteria2,
/// KANKI MIX user is taken off there) and an extra device on a config already in use is
/// dropped by its address (WireGuard / AmneziaWG) or by that server's own device limit (KANKI MIX:
/// the places left; Hysteria2: refused at login). The devices that came first keep working;
/// once one of them ends, another may connect. Pings and subscription views never count.
#[derive(Default)]
pub struct Limits {
    /// when each live connection (user, node, protocol) was first seen
    since: HashMap<(i64, String, String), i64>,
    /// the live connections of the last round (kept for a node that does not answer)
    last: Vec<(i64, String, String, i64)>,
    /// users at their limit: the devices allowed on each (node, protocol); anything else is shut
    open: HashMap<i64, HashMap<(String, String), i64>>,
    /// addresses of extra devices dropped on a WireGuard / AmneziaWG config, until a device of that
    /// user ends (they stay out of sight while dropped, so they are kept here)
    blocked: HashMap<(i64, String, String), Vec<String>>,
    /// when each node last answered (what a silent node had is kept only for `CARRY_FOR`)
    heard: HashMap<String, i64>,
}

/// How long the connections of a node that stopped answering are still counted
const CARRY_FOR: i64 = 120;

impl Limits {
    /// One sync round: `units` are the live connections (user, node, protocol, devices) of the nodes in
    /// `answered`; `eps` the addresses of the devices on one WireGuard / AmneziaWG key, oldest first.
    /// True when something was shut, dropped or let in.
    pub fn round(&mut self, units: &[(i64, String, String, i64)], eps: &HashMap<(i64, String, String), Vec<String>>, answered: &HashSet<String>, max: &HashMap<i64, i64>, now: i64) -> bool {
        for n in answered {
            self.heard.insert(n.clone(), now);
        }
        self.heard.retain(|_, t| now - *t < 86_400);
        // a node that did not answer keeps what it had, for a while: a node that is gone for good must
        // not keep its users out of every other server
        let heard = &self.heard;
        let mut all: Vec<(i64, String, String, i64)> = vec![];
        let mut at: HashMap<(i64, String, String), usize> = HashMap::new();
        let kept = self.last.iter().filter(|x| !answered.contains(&x.1) && heard.get(&x.1).is_some_and(|t| now - t < CARRY_FOR));
        for x in units.iter().chain(kept) {
            // the same user, node and protocol twice (two KANKI MIX devices) is that many devices
            match at.get(&(x.0, x.1.clone(), x.2.clone())) {
                Some(i) => all[*i].3 += x.3,
                None => {
                    at.insert((x.0, x.1.clone(), x.2.clone()), all.len());
                    all.push(x.clone());
                }
            }
        }
        self.last = all.clone();
        let live: HashSet<(i64, String, String)> = all.iter().map(|(u, n, p, _)| (*u, n.clone(), p.clone())).collect();
        self.since.retain(|k, _| live.contains(k));
        for k in &live {
            self.since.entry(k.clone()).or_insert(now);
        }
        let (open_before, blocked_before) = (self.open.clone(), self.blocked.clone());
        // a config that ended frees its dropped devices
        self.blocked.retain(|k, _| live.contains(k));
        let mut per: HashMap<i64, Vec<(i64, String, String, i64)>> = HashMap::new();
        for (u, n, p, c) in all {
            let t = self.since.get(&(u, n.clone(), p.clone())).copied().unwrap_or(now);
            per.entry(u).or_default().push((t, n, p, c));
        }
        self.open.clear();
        for (u, mut list) in per {
            let m = max.get(&u).copied().unwrap_or(0);
            let total: i64 = list.iter().map(|x| x.3).sum();
            if m <= 0 || total < m {
                // a place is free: dropped devices may come back
                self.blocked.retain(|k, _| k.0 != u);
                continue;
            }
            // oldest first (ties by node and protocol, so every round decides the same way)
            list.sort_by(|a, b| (a.0, &a.1, &a.2).cmp(&(b.0, &b.1, &b.2)));
            let mut left = m;
            let open = self.open.entry(u).or_default();
            for (_, n, p, c) in list {
                let take = c.min(left);
                left -= take;
                if take > 0 {
                    *open.entry((n.clone(), p.clone())).or_default() += take;
                }
                let key = (u, n, p);
                if take < c {
                    if let Some(addrs) = eps.get(&key) {
                        let b = self.blocked.entry(key).or_default();
                        for a in addrs.iter().skip(take as usize) {
                            if !b.contains(a) {
                                b.push(a.clone());
                            }
                        }
                    }
                }
            }
        }
        self.blocked.retain(|_, v| !v.is_empty());
        self.open != open_before || self.blocked != blocked_before
    }

    /// Servers that are switched off or removed serve nobody: what they had is not kept
    pub fn keep_nodes(&mut self, keep: impl Fn(&str) -> bool) {
        self.last.retain(|x| keep(&x.1));
    }

    /// The users this server and protocol is shut for now
    pub fn shut_on(&self, node: &str, proto: &str) -> Vec<i64> {
        let k = (node.to_string(), proto.to_string());
        let mut v: Vec<i64> = self.open.iter().filter(|(_, s)| !s.contains_key(&k)).map(|(u, _)| *u).collect();
        v.sort();
        v
    }

    /// Someone is at the limit: rounds come quicker, so a place that frees up opens soon
    pub fn busy(&self) -> bool {
        !self.open.is_empty()
    }

    /// Is this server and protocol shut for the user now?
    pub fn is_shut(&self, user: i64, node: &str, proto: &str) -> bool {
        self.open.get(&user).is_some_and(|s| !s.contains_key(&(node.to_string(), proto.to_string())))
    }

    /// How many devices the user may have on this server and protocol now (None = no limit reached)
    pub fn allowed(&self, user: i64, node: &str, proto: &str) -> Option<i64> {
        self.open.get(&user).map(|s| s.get(&(node.to_string(), proto.to_string())).copied().unwrap_or(0))
    }

    /// The addresses to drop on a node: "wg 1.2.3.4:5678"
    pub fn blocks_on(&self, node: &str) -> Vec<String> {
        let mut v: Vec<String> = self.blocked.iter().filter(|(k, _)| k.1 == node && k.2 != "xray").flat_map(|(k, a)| a.iter().map(move |x| format!("{} {}", k.2, x))).collect();
        v.sort();
        v
    }

    /// The devices dropped on a node for a protocol: (user, address)
    pub fn dropped_on(&self, node: &str, proto: &str) -> Vec<(i64, String)> {
        let mut v: Vec<(i64, String)> = self.blocked.iter().filter(|(k, _)| k.1 == node && k.2 == proto).flat_map(|(k, a)| a.iter().map(move |x| (k.0, x.clone()))).collect();
        v.sort();
        v
    }

    /// Is this device of the user dropped there now?
    pub fn is_dropped(&self, user: i64, node: &str, proto: &str, addr: &str) -> bool {
        self.blocked.get(&(user, node.to_string(), proto.to_string())).is_some_and(|v| v.iter().any(|x| x == addr))
    }
}

pub fn limits() -> &'static Mutex<Limits> {
    static L: std::sync::OnceLock<Mutex<Limits>> = std::sync::OnceLock::new();
    L.get_or_init(Default::default)
}

/// Live Hysteria2 sessions of a user on this server (a ping session next to one that moved data is
/// not counted, as in the sync rounds)
pub async fn live_sessions(app: &App, username: &str) -> i64 {
    let port = app.env.get("HY2_STATS_PORT").cloned().unwrap_or_default();
    let secret = app.env.get("HY2_SECRET").cloned().unwrap_or_default();
    let h = crate::hy2::online(&port, &secret).await.get(username).copied().unwrap_or(0);
    match crate::hy2::moving_known(username, now()) {
        Some(real) if h > 0 => hy2_devices(h, real),
        _ => h,
    }
}

/// Logins let in during the last seconds: Hysteria lists a session only after its login, so two
/// logins at the same moment must not both see the place free
#[derive(Default)]
struct Grants(HashMap<String, Vec<std::time::Instant>>);

const GRANT_FOR: std::time::Duration = std::time::Duration::from_secs(3);

impl Grants {
    fn recent(&mut self, user: &str, at: std::time::Instant) -> i64 {
        let v = self.0.entry(user.to_string()).or_default();
        v.retain(|t| at.saturating_duration_since(*t) < GRANT_FOR);
        v.len() as i64
    }
    fn note(&mut self, user: &str, at: std::time::Instant) {
        self.0.entry(user.to_string()).or_default().push(at);
        self.0.retain(|_, v| !v.is_empty());
    }
}

fn grants() -> &'static Mutex<Grants> {
    static G: std::sync::OnceLock<Mutex<Grants>> = std::sync::OnceLock::new();
    G.get_or_init(Default::default)
}

/// One Hysteria2 login at a time per user (the count and the grant go together)
fn login_lock(user: &str) -> Arc<tokio::sync::Mutex<()>> {
    static L: std::sync::OnceLock<Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>> = std::sync::OnceLock::new();
    L.get_or_init(Default::default).lock().unwrap_or_else(|e| e.into_inner()).entry(user.to_string()).or_default().clone()
}

/// Connection-limit check used by Hysteria2 auth
pub async fn conn_allowed(app: &App, username: &str) -> bool {
    let (max, total) = app.limits.lock().unwrap_or_else(|e| e.into_inner()).get(username).copied().unwrap_or((0, 0));
    if max <= 0 {
        return true;
    }
    let lock = login_lock(username);
    let _one = lock.lock().await;
    let reported = app.reported.lock().unwrap_or_else(|e| e.into_inner()).get(username).copied().unwrap_or(0);
    let elsewhere = (total - reported).max(0);
    let cap = hy2_caps().lock().unwrap_or_else(|e| e.into_inner()).get(username).copied();
    let live = live_sessions(app, username).await;
    let t = std::time::Instant::now();
    let mut g = grants().lock().unwrap_or_else(|e| e.into_inner());
    let here = live + g.recent(username, t);
    let ok = elsewhere + here < max && cap.is_none_or(|c| here < c);
    if ok {
        g.note(username, t);
    }
    ok
}

fn desired_for(app: &App, users: &[User], n: &Node) -> (SyncReq, Vec<(i64, String, String)>) {
    // (user_id, proto, pubkey)
    let info = crate::api::node_info(n);
    let has = |k: &str| info[k].as_str().map(|s| !s.is_empty()).unwrap_or(false);
    let off = crate::cores::off_list(app, &n.id);
    let is_off = |c: &str| off.iter().any(|x| x == c);
    let (wg_on, awg_on) = (has("wg_pub") && !is_off("wg"), has("awg_pub") && !is_off("awg"));
    let limit_on = app.db.get("conn_limit_on") != "0";
    let mut req = SyncReq::default();
    let mut map = vec![];
    let lim = limits().lock().unwrap_or_else(|e| e.into_inner());
    let shut = |u: &User, p: &str| lim.is_shut(u.id, &n.id, p);
    // drain: no new users here, on any core; the users assigned by name or there when it was drained stay
    let keep = app.db.drain_keep(n);
    let here: Vec<&User> = users.iter().filter(|u| u.active() && app.db.serves(u, n, keep.as_ref())).collect();
    // at the limit, KANKI MIX on this server take only the devices still allowed here
    let room = |proto: &str| -> Vec<User> {
        here.iter()
            .filter(|u| !shut(u, proto))
            .map(|u| {
                let mut u = (*u).clone();
                if let Some(a) = lim.allowed(u.id, &n.id, proto) {
                    u.max_conn = a.max(1);
                }
                u
            })
            .collect()
    };
    let kmix_users = room("kmix");
    let kmix_here: Vec<&User> = kmix_users.iter().collect();
    req.kmix = Some(crate::kmix::cfg_for(app, &crate::kmix::settings(app), n, &kmix_here));
    req.kcore = Some(serde_json::json!({}));
    req.block = lim.blocks_on(&n.id);
    req.off = off.clone();
    req.mtu = crate::mtu::ifaces(app, n);
    for u in here.iter().copied() {
        for (proto, on) in [("wg", wg_on), ("awg", awg_on)] {
            if !on || !u.has_proto(proto) || shut(u, proto) {
                continue;
            }
            if let Some(p) = app.db.ensure_peer(u.id, &n.id, proto) {
                let spec = PeerSpec { pubkey: p.pubkey.clone(), psk: p.psk.clone(), ip: p.ip.clone() };
                if proto == "wg" { req.wg.push(spec) } else { req.awg.push(spec) }
                map.push((u.id, proto.to_string(), p.pubkey));
            }
        }
        if u.has_proto("hy2") && !is_off("hy2") && !shut(u, "hy2") {
            // the links carry the derived password; the code itself still works for links made before 3.51
            req.hy2.insert(crate::hy2::user_pass(&u.code), u.username.clone());
            req.hy2.insert(u.code.clone(), u.username.clone());
            if let Some(a) = lim.allowed(u.id, &n.id, "hy2") {
                req.hy2_cap.insert(u.username.clone(), a);
            }
        }
        req.limits.insert(u.username.clone(), (if limit_on { u.max_conn } else { 0 }, u.online));
    }
    (req, map)
}

/// One sync round over every enabled node
pub async fn sync_all(app: &Arc<App>) {
    let _round = app.sync_lock.lock().await;
    let users = app.db.users();
    let mut online: HashMap<i64, i64> = HashMap::new();
    let mut seen: HashMap<i64, i64> = HashMap::new();
    let mut add_bytes: HashMap<i64, i64> = HashMap::new();
    // the same bytes by where they came from ("server · protocol"), to say where a user who was already
    // out of data or time still moved data
    let mut by_src: HashMap<i64, Vec<(String, i64)>> = HashMap::new();
    let by_name: HashMap<String, i64> = users.iter().map(|u| (u.username.clone(), u.id)).collect();
    // every live connection of this round: (user, node, protocol, devices)
    let mut units: Vec<(i64, String, String, i64)> = vec![];
    let mut answered: HashSet<String> = HashSet::new();
    let mut eps: HashMap<(i64, String, String), Vec<String>> = HashMap::new();

    let all_nodes = app.db.nodes();
    let enabled: HashSet<String> = all_nodes.iter().filter(|n| n.enabled).map(|n| n.id.clone()).collect();
    // a node whose VPN is switched off serves nobody: its users are taken off (an empty sync), so a
    // relay server keeps its ports free and an old peer cannot keep using it. These run beside the
    // enabled ones, with a short timeout: an unreachable one must not hold the round.
    let mut off_jobs = vec![];
    for n in all_nodes.iter().filter(|n| !n.enabled).cloned() {
        // the panel server's own info (version, services, load) stays fresh while its VPN is off too
        if n.id == "local" {
            let _ = app.db.exec("UPDATE nodes SET info=?1 WHERE id='local'", &[&local_info_async(app).await.to_string()]);
        }
        // once it is empty (or did not answer), checked again every 5 minutes
        {
            let mut g = off_checked().lock().unwrap_or_else(|e| e.into_inner());
            let last = g.get(&n.id).copied().unwrap_or(0);
            if (n.sync_state == "off" || !n.online) && last > 0 && now() - last < 300 {
                continue;
            }
            g.insert(n.id.clone(), now());
        }
        off_jobs.push(async move {
            let empty = SyncReq { kmix: Some(crate::kmix::KmixCfg::default()), kcore: Some(serde_json::json!({})), ..Default::default() };
            let local = n.id == "local";
            let ok = if local {
                apply_local(app, empty).await;
                true
            } else {
                tokio::time::timeout(OFF_TIMEOUT, remote_sync(app, &n, &empty)).await.is_ok_and(|r| r.is_ok())
            };
            let info = if ok && !local { tokio::time::timeout(OFF_TIMEOUT, remote_info(app, &n.address, &n.token, n.insecure)).await.ok().flatten() } else { None };
            (n, ok, info)
        });
    }
    // every server is asked at the same time: one that does not answer must not hold the round (traffic,
    // limits and who is online) for everyone else
    let mut jobs = vec![];
    for mut n in all_nodes.into_iter().filter(|n| n.enabled) {
        let local = n.id == "local";
        if local {
            let info = local_info_async(app).await.to_string();
            let _ = app.db.exec("UPDATE nodes SET info=?1 WHERE id='local'", &[&info]);
            n.info = info;
        }
        let (req, map) = desired_for(app, &users, &n);
        jobs.push(async move {
            let want = req.wg.len() + req.awg.len();
            let resp: Result<SyncResp, String> = if local { Ok(apply_local(app, req).await) } else { remote_sync(app, &n, &req).await };
            (n, map, want, resp)
        });
    }
    let (offs, results) = futures_util::future::join(futures_util::future::join_all(off_jobs), futures_util::future::join_all(jobs)).await;
    for (n, ok, info) in offs {
        // "off" only once it really took the empty list
        let state = if ok { "off" } else { "offline" };
        let _ = app.db.exec("UPDATE nodes SET online=?1, sync_state=?2 WHERE id=?3", &[&(ok as i64), &state, &n.id]);
        if let Some(info) = info {
            crate::srvtraffic::note(app, &format!("n:{}", n.id), &info["stats"]["net"]);
            let _ = app.db.exec("UPDATE nodes SET info=?1, last_sync=?2 WHERE id=?3", &[&info.to_string(), &now(), &n.id]);
        }
        crate::live::set_vpn(&n.id, &n.name, vec![]);
    }
    for (n, map, want, resp) in results {
        let local = n.id == "local";
        let ok = resp.is_ok();
        let state = match &resp {
            // a pin mismatch is not just "offline": it is logged and kept apart
            Err(e) if e.contains(crate::pin::MISMATCH) => "pin mismatch",
            Err(_) => "offline",
            Ok(r) => {
                let have = map.iter().filter(|(_, proto, pk)| if proto == "wg" { r.wg.contains_key(pk) } else { r.awg.contains_key(pk) }).count();
                if have == want { "synced" } else { "mismatch" }
            }
        };
        if ok {
            let _ = app.db.exec("UPDATE nodes SET online=1, last_sync=?1, sync_state=?2 WHERE id=?3", &[&now(), &state, &n.id]);
        } else {
            let _ = app.db.exec("UPDATE nodes SET online=0, sync_state=?1 WHERE id=?2", &[&state, &n.id]);
        }
        if !local && ok {
            // the server's info (CPU, memory, its network counters) is read beside the round, not in it: a
            // slow server must not hold the round, or a user who just ran out of data keeps going until it ends
            // (one read per server at a time)
            static READING: Mutex<Option<HashSet<String>>> = Mutex::new(None);
            let fresh = READING.lock().unwrap_or_else(|e| e.into_inner()).get_or_insert_with(HashSet::new).insert(n.id.clone());
            if fresh {
                let (a, n2) = (app.clone(), n.clone());
                tokio::spawn(async move {
                    if let Some(info) = remote_info(&a, &n2.address, &n2.token, n2.insecure).await {
                        crate::srvtraffic::note(&a, &format!("n:{}", n2.id), &info["stats"]["net"]);
                        let _ = a.db.exec("UPDATE nodes SET info=?1 WHERE id=?2", &[&info.to_string(), &n2.id]);
                    }
                    if let Some(s) = READING.lock().unwrap_or_else(|e| e.into_inner()).as_mut() {
                        s.remove(&n2.id);
                    }
                });
            }
        }
        let Ok(resp) = resp else {
            crate::live::set_vpn(&n.id, &n.name, vec![]);
            continue;
        };
        let before = add_bytes.clone();
        // who is connected here right now, and with which protocol (for the panel)
        let mut here: Vec<(i64, String)> = vec![];
        // the node's own clock: its handshake and address times are by it (an older node sends none)
        let node_now = if resp.now > 0 { resp.now } else { now() };
        let skew = now() - node_now;
        // keys taken off this round: their last traffic still counts
        let mine: HashSet<&str> = map.iter().map(|x| x.2.as_str()).collect();
        for (proto, stats) in [("wg", &resp.wg), ("awg", &resp.awg)] {
            for (pk, st) in stats.iter().filter(|(k, _)| !mine.contains(k.as_str())) {
                let row: Option<(i64, i64, i64)> = app.db.with(|c| {
                    c.query_row("SELECT user_id,rx,tx FROM peers WHERE node_id=?1 AND proto=?2 AND pubkey=?3", rusqlite::params![n.id, proto, pk], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).ok()
                });
                let Some((uid, prx, ptx)) = row else { continue };
                let (total, prev) = (st.rx + st.tx, prx + ptx);
                let delta = if total >= prev { total - prev } else { total };
                if delta > 0 {
                    *add_bytes.entry(uid).or_default() += delta;
                    let _ = app.db.exec("UPDATE peers SET rx=?1, tx=?2 WHERE user_id=?3 AND node_id=?4 AND proto=?5", &[&st.rx, &st.tx, &uid, &n.id, &proto]);
                }
            }
        }

        for (uid, proto, pubk) in map {
            let stats = if proto == "wg" { &resp.wg } else { &resp.awg };
            let Some(st) = stats.get(&pubk) else { continue };
            let mut moved = 0;
            if let Some(p) = app.db.peer(uid, &n.id, &proto) {
                let total = st.rx + st.tx;
                let prev = p.rx + p.tx;
                let delta = if total >= prev { total - prev } else { total };
                moved = delta;
                *add_bytes.entry(uid).or_default() += delta;
                let _ = app.db.exec(
                    "UPDATE peers SET rx=?1, tx=?2 WHERE user_id=?3 AND node_id=?4 AND proto=?5",
                    &[&st.rx, &st.tx, &uid, &n.id, &proto],
                );
            }
            if st.handshake > 0 && node_now - st.handshake < 180 && live_peer(uid, &n.id, &proto, moved, now()) {
                here.push((uid, proto.clone()));
                // one config on several devices: its address keeps changing between them (a phone that
                // changes network changes it once)
                let t = node_now;
                let active: Vec<String> = st.eps.iter().filter(|e| t - e.last < 30).map(|e| e.at.clone()).collect();
                let devices = if st.flips >= 3 && active.len() >= 2 { active.len() as i64 } else { 1 };
                if devices > 1 {
                    eps.insert((uid, n.id.clone(), proto.clone()), active);
                }
                units.push((uid, n.id.clone(), proto.clone(), devices));
                *online.entry(uid).or_default() += devices;
                let e = seen.entry(uid).or_default();
                *e = (*e).max(st.handshake + skew);
            }
        }
        for (name, (rx, tx)) in resp.hy2.iter() {
            if let Some(uid) = by_name.get(name) {
                *add_bytes.entry(*uid).or_default() += rx + tx;
            }
        }
        // data each user moved here this round, per protocol (a session that never moved data is a ping)
        let moved = |name: &String, proto: &str| -> i64 {
            let m = if proto == "hy2" { &resp.hy2 } else { &resp.kmix };
            m.get(name).map(|(rx, tx)| rx + tx).unwrap_or(0)
        };
        for (name, c, proto) in resp.hy2_online.iter().map(|(n, c)| (n, c, "hy2")).chain(resp.kmix_online.iter().map(|(n, c)| (n, c, "kmix"))) {
            if let Some(uid) = by_name.get(name) {
                if *c > 0 && live_session(*uid, &n.id, proto, moved(name, proto)) {
                    here.push((*uid, proto.to_string()));
                    units.push((*uid, n.id.clone(), proto.to_string(), *c));
                    *online.entry(*uid).or_default() += c;
                    seen.insert(*uid, now());
                }
            }
        }
        for (name, (rx, tx)) in resp.kmix.iter() {
            if let Some(uid) = by_name.get(name) {
                *add_bytes.entry(*uid).or_default() += rx + tx;
            }
        }
        // sessions that ended here are forgotten (a new one has to move data again to count)
        let open_now: HashSet<(String, &str)> = resp.hy2_online.iter().filter(|x| *x.1 > 0).map(|x| (x.0.clone(), "hy2"))
            .chain(resp.kmix_online.iter().filter(|x| *x.1 > 0).map(|x| (x.0.clone(), "kmix"))).collect();
        forget_sessions(&n.id, |uid, proto| users.iter().find(|u| u.id == uid).is_some_and(|u| open_now.contains(&(u.username.clone(), proto))));
        crate::kmix::note_error(&n.id, &resp.kmix_error);
        crate::kmix::note_health(&n.id, &resp.kmix_health);
        for (uid, b) in add_bytes.iter() {
            let d = b - before.get(uid).copied().unwrap_or(0);
            if d > 0 {
                let protos: Vec<&str> = here.iter().filter(|x| x.0 == *uid).map(|x| x.1.as_str()).collect();
                by_src.entry(*uid).or_default().push((format!("{} · {}", n.name, if protos.is_empty() { "?".to_string() } else { protos.join("+") }), d));
            }
        }
        crate::live::set_vpn(&n.id, &n.name, here);
        answered.insert(n.id.clone());
    }
    let limit_on = app.db.get("conn_limit_on") != "0";
    let max: HashMap<i64, i64> = users.iter().map(|u| (u.id, if limit_on && u.active() { u.max_conn } else { 0 })).collect();
    // Xray counts like the others (its servers report every 5 seconds)
    let (xu, xe, xa) = crate::xray::panel::live_units(now());
    // … and in the account's «connections» too (they were only used for the limit: an Xray user showed 0)
    for (uid, _, _, devices) in &xu {
        *online.entry(*uid).or_default() += devices;
        seen.insert(*uid, now());
    }
    units.extend(xu);
    eps.extend(xe);
    answered.extend(xa);
    // what the panel shows as «connected now» is what was counted here
    crate::live::set_others(&units);
    let changed = {
        let mut l = limits().lock().unwrap_or_else(|e| e.into_inner());
        // a server switched off or removed: what it had goes at once (Xray servers by their reports)
        l.keep_nodes(|n| n.starts_with("x:") || enabled.contains(n));
        l.round(&units, &eps, &answered, &max, now())
    };
    if changed {
        // a connection was shut or let in again: the servers get it now, not in 30 seconds
        crate::api::spawn_sync(app);
    }

    // a user whose data ran out in this round is taken off every server now, not in the next round
    // (30 seconds of a fast download is hundreds of megabytes)
    let ran_out = users.iter().any(|u| {
        let add = add_bytes.get(&u.id).copied().unwrap_or(0);
        u.active() && add > 0 && !User { used_bytes: u.used_bytes + add, ..u.clone() }.active()
    });
    if ran_out {
        crate::api::spawn_sync(app);
    }
    // a user who has data and time again (renewed, reset) starts with a clean «after the limit»
    let al = app.db.get("after_limit");
    if al.len() > 2 {
        if let Ok(serde_json::Value::Object(mut m)) = serde_json::from_str::<serde_json::Value>(&al) {
            let n = m.len();
            m.retain(|k, _| users.iter().any(|u| u.id.to_string() == *k && !u.active()));
            if m.len() != n {
                app.db.set("after_limit", &serde_json::Value::Object(m).to_string());
            }
        }
    }
    for u in &users {
        let add = add_bytes.get(&u.id).copied().unwrap_or(0);
        if add > 0 && !u.active() {
            for (src, b) in by_src.get(&u.id).cloned().unwrap_or_default() {
                note_after_limit(app, u, &src, b);
            }
        }
        let on = online.get(&u.id).copied().unwrap_or(0);
        let last = seen.get(&u.id).copied().unwrap_or(u.last_seen).max(u.last_seen);
        if add > 0 || on != u.online || last != u.last_seen {
            let _ = app.db.exec(
                "UPDATE users SET used_bytes=used_bytes+?1, online=?2, last_seen=?3 WHERE id=?4",
                &[&add, &on, &last, &u.id],
            );
        }
    }
}

/// Data a user moved while already out of data, out of time or switched off (it should be close to
/// nothing: the last seconds before the servers took them off). Kept per user and source in
/// `after_limit` (the user's window in the panel shows it) and logged, so a server or protocol that
/// does not take such a user off is seen at once.
pub fn note_after_limit(app: &App, u: &User, src: &str, bytes: i64) {
    if bytes <= 0 {
        return;
    }
    let mut all: serde_json::Value = serde_json::from_str(&app.db.get("after_limit")).unwrap_or(serde_json::json!({}));
    if !all.is_object() {
        all = serde_json::json!({});
    }
    let k = u.id.to_string();
    let e = &mut all[&k];
    if !e.is_object() {
        *e = serde_json::json!({ "src": {} });
    }
    let was = e["src"][src].as_i64().unwrap_or(0);
    e["src"][src] = serde_json::json!(was + bytes);
    e["last"] = serde_json::json!(now());
    // only the users that still exist, at most 500
    if let Some(m) = all.as_object_mut() {
        if m.len() > 500 {
            let mut v: Vec<(String, i64)> = m.iter().map(|(k, v)| (k.clone(), v["last"].as_i64().unwrap_or(0))).collect();
            v.sort_by_key(|x| x.1);
            for (k, _) in v.iter().take(m.len() - 500) {
                m.remove(k);
            }
        }
    }
    app.db.set("after_limit", &all.to_string());
    eprintln!("traffic after the limit: user {} ({}) moved {} bytes on {}", u.id, u.username, bytes, src);
}

/// What a user moved after the limit, by source: { "src": { "<server · protocol>": bytes }, "last": time }
pub fn after_limit_of(app: &App, uid: i64) -> serde_json::Value {
    let all: serde_json::Value = serde_json::from_str(&app.db.get("after_limit")).unwrap_or(serde_json::json!({}));
    all[uid.to_string()].clone()
}

/// Why a request to a node failed. A certificate pin mismatch is logged and says how to reset it
/// (otherwise the node would only show as offline).
pub fn node_err(addr: &str, e: &reqwest::Error) -> String {
    match crate::pin::mismatch_of(e) {
        Some(m) => {
            eprintln!("node {}: {}", addr, m);
            format!("{} (if the node was reinstalled: run its join command again, or remove the node and add it again)", m)
        }
        None => crate::pin::error_text(e),
    }
}

/// How long a sync or info request to a server may take
const SYNC_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(45);
/// … and to a switched-off server (it only gets its empty user list)
const OFF_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// The first version whose node agent takes only signed requests (`sign`)
pub const SIGN_FROM: &str = "3.65.0";

/// Whether node `n` may still be from before signed requests: it never reported a version of 3.65 or
/// newer. Only such a node may get the bare token, and only after it refused the signed request.
fn node_legacy(n: &Node) -> bool {
    let v = serde_json::from_str::<Value>(&n.info).ok().and_then(|i| i["version"].as_str().map(|s| s.to_string())).unwrap_or_default();
    v.is_empty() || crate::admin::newer(SIGN_FROM, &v)
}

/// A request to a node's agent, signed with its token (3.65): the token itself is not sent. A node that
/// may be from before (`legacy`) and refuses it (401) gets the same request once more with the bare
/// token, as before; a node known to be newer never sees the token. One client per node (kept-alive
/// connections are reused round after round).
#[allow(clippy::too_many_arguments)]
async fn node_call(app: &App, key: &str, addr: &str, token: &str, insecure: bool, method: reqwest::Method, path: &str, body: Option<Vec<u8>>, timeout: std::time::Duration, legacy: bool) -> Result<reqwest::Response, String> {
    let c = app.node_client(key, insecure);
    let url = format!("{}{}", addr.trim_end_matches('/'), path);
    let build = |bare: bool| {
        let raw = body.clone().unwrap_or_default();
        let mut rb = c.request(method.clone(), &url).timeout(timeout);
        if body.is_some() {
            rb = rb.header(reqwest::header::CONTENT_TYPE, "application/json").body(raw.clone());
        }
        rb = crate::sign::sign(rb, token, method.as_str(), path, &raw);
        if bare {
            rb = rb.header("X-Node-Token", token);
        }
        rb
    };
    let r = build(false).send().await.map_err(|e| node_err(addr, &e))?;
    if r.status() == reqwest::StatusCode::UNAUTHORIZED && legacy {
        return build(true).send().await.map_err(|e| node_err(addr, &e));
    }
    Ok(r)
}

async fn remote_sync(app: &App, n: &Node, req: &SyncReq) -> Result<SyncResp, String> {
    // a sync answers within seconds; the self-signed client's long timeout is for updates
    let body = serde_json::to_vec(req).map_err(|e| e.to_string())?;
    let r = node_call(app, &n.id, &n.address, &n.token, n.insecure, reqwest::Method::POST, "/agent/sync", Some(body), SYNC_TIMEOUT, node_legacy(n)).await?;
    if !r.status().is_success() {
        return Err(format!("the node answered {}", r.status()));
    }
    r.json::<SyncResp>().await.map_err(|e| e.to_string())
}

/// Nodes that were just told to update restart onto the new program: their info (and so the version the
/// panel shows) is read again every few seconds until they report `want`, not only at the next sync round.
pub fn refresh_after_update(app: &Arc<App>, mut nodes: Vec<Node>, want: &str) {
    if nodes.is_empty() {
        return;
    }
    let (a, want) = (app.clone(), want.to_string());
    tokio::spawn(async move {
        for _ in 0..15 {
            tokio::time::sleep(std::time::Duration::from_secs(6)).await;
            let mut left = vec![];
            for n in nodes {
                match remote_info(&a, &n.address, &n.token, n.insecure).await {
                    Some(info) => {
                        let _ = a.db.exec("UPDATE nodes SET info=?1, online=1 WHERE id=?2", &[&info.to_string(), &n.id]);
                        if !want.is_empty() && info["version"].as_str() != Some(want.as_str()) {
                            left.push(n);
                        }
                    }
                    None => left.push(n),
                }
            }
            if left.is_empty() {
                break;
            }
            nodes = left;
        }
    });
}

pub async fn remote_info(app: &App, addr: &str, token: &str, insecure: bool) -> Option<Value> {
    remote_info_res(app, addr, token, insecure).await.ok()
}

/// `remote_info` with the reason it failed
pub async fn remote_info_res(app: &App, addr: &str, token: &str, insecure: bool) -> Result<Value, String> {
    // keyed by address: for a node being added this is also the TOFU first contact. A node the panel
    // already knows as newer never gets the bare token; one being added may still be from before.
    let legacy = app.db.nodes().into_iter().find(|n| n.address.trim_end_matches('/') == addr.trim_end_matches('/')).map(|n| node_legacy(&n)).unwrap_or(true);
    let r = node_call(app, addr, addr, token, insecure, reqwest::Method::GET, "/agent/info", None, SYNC_TIMEOUT, legacy).await?;
    if !r.status().is_success() {
        return Err(format!("the node answered {}", r.status()));
    }
    r.json::<Value>().await.map_err(|e| e.to_string())
}

pub async fn remote_post(app: &App, n: &Node, path: &str) -> Option<Value> {
    let r = node_call(app, &n.id, &n.address, &n.token, n.insecure, reqwest::Method::POST, path, None, std::time::Duration::from_secs(120), node_legacy(n)).await;
    match r {
        Ok(r) => r.json::<Value>().await.map_err(|e| eprintln!("node {}: {} answered: {}", n.name, path, e)).ok(),
        Err(e) => {
            eprintln!("node {}: {}: {}", n.name, path, e);
            None
        }
    }
}

pub async fn remote_post_json(app: &App, n: &Node, path: &str, body: &Value) -> Option<Value> {
    let raw = serde_json::to_vec(body).ok()?;
    let r = node_call(app, &n.id, &n.address, &n.token, n.insecure, reqwest::Method::POST, path, Some(raw), std::time::Duration::from_secs(60), node_legacy(n)).await;
    match r {
        Ok(r) => r.json::<Value>().await.map_err(|e| eprintln!("node {}: {} answered: {}", n.name, path, e)).ok(),
        Err(e) => {
            eprintln!("node {}: {}: {}", n.name, path, e);
            None
        }
    }
}

/// Forever loop
pub async fn run(app: Arc<App>) {
    loop {
        // a panel being moved leaves the servers alone: the new panel takes over from the backup
        if crate::migrate::frozen() {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            continue;
        }
        sync_all(&app).await;
        let busy = limits().lock().unwrap_or_else(|e| e.into_inner()).busy();
        tokio::time::sleep(std::time::Duration::from_secs(if busy { 10 } else { 30 })).await;
    }
}

#[cfg(test)]
mod live_tests {
    use super::{live_peer, Limits};
    use std::collections::{HashMap, HashSet};

    fn u(user: i64, node: &str, proto: &str) -> (i64, String, String, i64) {
        (user, node.to_string(), proto.to_string(), 1)
    }

    impl Limits {
        fn round_t(&mut self, units: &[(i64, String, String, i64)], answered: &HashSet<String>, max: &HashMap<i64, i64>, now: i64) -> bool {
            self.round(units, &HashMap::new(), answered, max, now)
        }
    }

    #[test]
    fn one_config_on_two_phones_is_two_connections() {
        let mut l = Limits::default();
        let max: HashMap<i64, i64> = [(1, 1), (2, 2)].into_iter().collect();
        let eps: HashMap<(i64, String, String), Vec<String>> = [
            ((1, "de".to_string(), "wg".to_string()), vec!["1.1.1.1:1000".to_string(), "2.2.2.2:2000".to_string()]),
            ((2, "de".to_string(), "wg".to_string()), vec!["3.3.3.3:1".to_string(), "4.4.4.4:2".to_string()]),
        ].into_iter().collect();
        let two = |u: i64| (u, "de".to_string(), "wg".to_string(), 2);
        assert!(l.round(&[two(1), two(2)], &eps, &nodes(), &max, 1000));
        // one-connection account: the newer phone is dropped by its address, the first keeps working
        assert_eq!(l.blocks_on("de"), vec!["wg 2.2.2.2:2000".to_string()]);
        // two-connection account: both phones work
        assert!(!l.blocks_on("de").iter().any(|x| x.contains("3.3.3.3") || x.contains("4.4.4.4")));
        // the dropped phone is out of sight now: it stays dropped while the first is connected
        l.round(&[u(1, "de", "wg"), two(2)], &eps, &nodes(), &max, 1030);
        assert_eq!(l.blocks_on("de"), vec!["wg 2.2.2.2:2000".to_string()]);
        // the first phone disconnects: the other may connect
        l.round(&[two(2)], &eps, &nodes(), &max, 1060);
        assert!(l.blocks_on("de").is_empty());
    }

    #[test]
    fn one_xray_config_on_two_phones_is_two_connections() {
        let mut l = Limits::default();
        let max: HashMap<i64, i64> = [(1, 1)].into_iter().collect();
        let key = (1, "x:ir".to_string(), "xray".to_string());
        let eps: HashMap<(i64, String, String), Vec<String>> = [(key.clone(), vec!["5.5.5.5".to_string(), "6.6.6.6".to_string()])].into_iter().collect();
        let nodes: HashSet<String> = ["x:ir".to_string()].into_iter().collect();
        l.round(&[(1, "x:ir".to_string(), "xray".to_string(), 2)], &eps, &nodes, &max, 1000);
        assert_eq!(l.dropped_on("x:ir", "xray"), vec![(1, "6.6.6.6".to_string())]);
        assert!(l.is_dropped(1, "x:ir", "xray", "6.6.6.6") && !l.is_dropped(1, "x:ir", "xray", "5.5.5.5"));
        // Xray drops are not firewall rules
        assert!(l.blocks_on("x:ir").is_empty());
    }

    fn nodes() -> HashSet<String> {
        ["de", "tr"].iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn a_ping_handshake_is_not_a_connection() {
        // the apps' ping: one handshake (~240 bytes), then nothing
        assert!(!live_peer(-7, "n", "wg", 240, 1000));
        assert!(!live_peer(-7, "n", "wg", 0, 1030));
        // a real connection: data, then only keepalives
        assert!(live_peer(-8, "n", "wg", 50_000, 1000));
        // an extra round a second later sees nothing moved: still connected
        assert!(live_peer(-8, "n", "wg", 0, 1001));
        assert!(live_peer(-8, "n", "wg", 64, 1030));
        // disconnected: nothing moves for longer than LIVE_FOR
        assert!(live_peer(-8, "n", "wg", 0, 1055));
        assert!(!live_peer(-8, "n", "wg", 0, 1061));
    }

    #[test]
    fn a_session_that_moved_no_data_is_a_ping() {
        use super::{forget_sessions, live_session};
        assert!(!live_session(-9, "n", "kmix", 300));
        assert!(live_session(-9, "n", "hy2", 5000));
        // idle but still open on the server: still a connection
        assert!(live_session(-9, "n", "hy2", 0));
        forget_sessions("n", |_, _| false);
        assert!(!live_session(-9, "n", "hy2", 0));
    }

    #[test]
    fn a_one_connection_account_works_on_one_device_at_a_time() {
        let mut l = Limits::default();
        let max: HashMap<i64, i64> = [(1, 1)].into_iter().collect();
        // not connected: everything open
        l.round_t(&[], &nodes(), &max, 1000);
        assert!(!l.is_shut(1, "de", "wg") && !l.is_shut(1, "tr", "hy2"));
        // connected on Germany WireGuard: every other server and protocol is shut for this account
        assert!(l.round_t(&[u(1, "de", "wg")], &nodes(), &max, 1010));
        assert!(!l.is_shut(1, "de", "wg"));
        assert!(l.is_shut(1, "tr", "hy2") && l.is_shut(1, "tr", "wg") && l.is_shut(1, "de", "kmix"));
        // the first device disconnects: everything opens, another device may connect
        assert!(l.round_t(&[], &nodes(), &max, 1060));
        assert!(!l.is_shut(1, "tr", "hy2"));
        // the other device connects: now the first one cannot come back elsewhere
        l.round_t(&[u(1, "tr", "hy2")], &nodes(), &max, 1090);
        assert!(l.is_shut(1, "de", "wg") && !l.is_shut(1, "tr", "hy2"));
    }

    #[test]
    fn if_two_got_in_at_once_the_newest_is_shut() {
        let mut l = Limits::default();
        let max: HashMap<i64, i64> = [(1, 1)].into_iter().collect();
        l.round_t(&[u(1, "de", "wg")], &nodes(), &max, 1000);
        l.round_t(&[u(1, "de", "wg"), u(1, "tr", "kmix")], &nodes(), &max, 1030);
        assert!(!l.is_shut(1, "de", "wg") && l.is_shut(1, "tr", "kmix"));
    }

    #[test]
    fn two_connections_allow_two_devices_and_no_third() {
        let mut l = Limits::default();
        let max: HashMap<i64, i64> = [(1, 2), (2, 0)].into_iter().collect();
        l.round_t(&[u(1, "de", "wg")], &nodes(), &max, 1000);
        assert!(!l.is_shut(1, "tr", "hy2"));
        l.round_t(&[u(1, "de", "wg"), u(1, "tr", "hy2"), u(2, "de", "wg"), u(2, "tr", "wg")], &nodes(), &max, 1030);
        assert!(!l.is_shut(1, "de", "wg") && !l.is_shut(1, "tr", "hy2"));
        assert!(l.is_shut(1, "tr", "wg") && l.is_shut(1, "de", "kmix"));
        // no limit (0): never shut
        assert!(!l.is_shut(2, "de", "kmix"));
    }

    #[test]
    fn a_node_that_does_not_answer_keeps_its_connection() {
        let mut l = Limits::default();
        let max: HashMap<i64, i64> = [(1, 1)].into_iter().collect();
        l.round_t(&[u(1, "de", "wg")], &nodes(), &max, 1000);
        let only_tr: HashSet<String> = ["tr".to_string()].into_iter().collect();
        l.round_t(&[], &only_tr, &max, 1030);
        assert!(l.is_shut(1, "tr", "wg") && !l.is_shut(1, "de", "wg"));
    }

    #[test]
    fn a_node_gone_for_good_lets_its_users_go_elsewhere() {
        let mut l = Limits::default();
        let max: HashMap<i64, i64> = [(1, 1)].into_iter().collect();
        let only_tr: HashSet<String> = ["tr".to_string()].into_iter().collect();
        l.round_t(&[u(1, "de", "wg")], &nodes(), &max, 1000);
        // silent for a while: still kept
        l.round_t(&[], &only_tr, &max, 1100);
        assert!(l.is_shut(1, "tr", "wg"));
        // silent past CARRY_FOR: dropped, the user may connect elsewhere
        l.round_t(&[], &only_tr, &max, 1130);
        assert!(!l.is_shut(1, "tr", "wg"));
        // a node switched off or removed goes at once
        let mut l = Limits::default();
        l.round_t(&[u(1, "de", "wg")], &nodes(), &max, 1000);
        l.keep_nodes(|n| n == "tr");
        l.round_t(&[], &only_tr, &max, 1010);
        assert!(!l.is_shut(1, "tr", "wg"));
    }

    #[test]
    fn two_kanki_mix_devices_on_one_server_add_up() {
        let mut l = Limits::default();
        let max: HashMap<i64, i64> = [(1, 2), (2, 1)].into_iter().collect();
        l.round_t(&[u(1, "de", "kmix"), u(1, "de", "kmix"), u(2, "de", "kmix"), u(2, "de", "kmix")], &nodes(), &max, 1000);
        // a two-device account keeps both, and nothing else is open
        assert_eq!(l.allowed(1, "de", "kmix"), Some(2));
        assert!(l.is_shut(1, "tr", "wg"));
        // a one-device account gets one place
        assert_eq!(l.allowed(2, "de", "kmix"), Some(1));
    }

    #[test]
    fn an_idle_device_with_keepalives_counts() {
        // connected before the panel started, idle: only keepalives (about 100 bytes a round)
        assert!(!live_peer(-12, "n", "wg", 96, 1000));
        // an extra round a second later changes nothing
        assert!(!live_peer(-12, "n", "wg", 32, 1001));
        // the next round has keepalives again: a device
        assert!(live_peer(-12, "n", "wg", 96, 1031));
        assert!(live_peer(-12, "n", "wg", 96, 1062));
        // a ping that comes back minutes later is still one round of data
        assert!(!live_peer(-13, "n", "wg", 240, 1000));
        assert!(!live_peer(-13, "n", "wg", 240, 1300));
    }

    #[test]
    fn a_key_quiet_for_long_is_new_again() {
        assert!(live_peer(-11, "n", "wg", 50_000, 1000));
        // closed for minutes, then one ping handshake: not a device
        assert!(!live_peer(-11, "n", "wg", 240, 1300));
        assert!(!live_peer(-11, "n", "wg", 0, 1301));
    }

    #[test]
    fn hysteria_pings_and_logins_at_once() {
        use super::{hy2_devices, Grants, GRANT_FOR};
        // two sessions open, one moved data: one device; nothing seen moving (UDP only): one
        assert_eq!(hy2_devices(2, 1), 1);
        assert_eq!(hy2_devices(2, 0), 1);
        assert_eq!(hy2_devices(1, 3), 1);
        // a login just let in counts until Hysteria lists it
        let mut g = Grants::default();
        let t = std::time::Instant::now();
        assert_eq!(g.recent("a", t), 0);
        g.note("a", t);
        assert_eq!(g.recent("a", t), 1);
        assert_eq!(g.recent("b", t), 0);
        assert_eq!(g.recent("a", t + GRANT_FOR), 0);
    }
}

#[cfg(test)]
mod drain_tests {
    use std::collections::HashMap;
    use std::sync::{atomic::AtomicI64, Arc, Mutex};

    /// A drained server keeps the users it had, on every core, and takes no new one: not even one who
    /// opened the subscription (that made a key there, and a key was what «already there» meant)
    #[test]
    fn a_drained_server_takes_no_new_user() {
        let dir = std::env::temp_dir().join(format!("kanki-drain-{}", crate::util::rand_token(8)));
        std::fs::create_dir_all(&dir).unwrap();
        let db = crate::db::Db::open(dir.join("kanki.db").to_str().unwrap());
        let app = Arc::new(crate::App {
            db,
            env: HashMap::new(),
            hy2_allowed: Mutex::new(HashMap::new()), limits: Mutex::new(HashMap::new()), reported: Mutex::new(HashMap::new()),
            login_fails: Mutex::new(HashMap::new()), sync_lock: tokio::sync::Mutex::new(()), bot_alive: AtomicI64::new(0),
            http: reqwest::Client::new(), http_insecure: reqwest::Client::new(), pin_clients: Mutex::new(HashMap::new()),
        });
        app.db.exec("INSERT INTO nodes(id,name,address,endpoint,token,online,endpoint_mode,accept_all) VALUES('n1','DE','https://a','','t',1,'panel',1)", &[]).unwrap();
        let old = app.db.create_user("old", 0.0, 30, 1, "hy2,kmix", "", "", 0).unwrap();
        app.db.exec("UPDATE nodes SET drain=1 WHERE id='n1'", &[]).unwrap();
        let n = app.db.node("n1").unwrap();
        app.db.drain_changed(&n);
        let new = app.db.create_user("new", 0.0, 30, 1, "hy2,kmix", "", "", 0).unwrap();
        let named = app.db.create_user("named", 0.0, 30, 1, "hy2", "n1", "", 0).unwrap();
        // the new one opens its subscription: the drained server is not in it
        assert!(crate::api::user_nodes(&app, &new).iter().all(|x| x.id != "n1"));
        assert!(crate::api::user_nodes(&app, &old).iter().any(|x| x.id == "n1"));
        let (req, _) = super::desired_for(&app, &app.db.users(), &n);
        let names: Vec<&String> = req.hy2.values().collect();
        assert!(names.contains(&&old.username) && names.contains(&&named.username) && !names.contains(&&new.username));
        assert!(!serde_json::to_string(&req.kmix).unwrap().contains("\"new\""));
        // its number goes to the next new user: no place on the drained server comes with it
        app.db.delete_user(old.id);
        let again = app.db.create_user("again", 0.0, 30, 1, "hy2", "", "", 0).unwrap();
        assert_eq!(again.id, old.id);
        assert!(crate::api::user_nodes(&app, &again).iter().all(|x| x.id != "n1"));
        // drain off: everyone again
        app.db.exec("UPDATE nodes SET drain=0 WHERE id='n1'", &[]).unwrap();
        let n = app.db.node("n1").unwrap();
        app.db.drain_changed(&n);
        let (req, _) = super::desired_for(&app, &app.db.users(), &n);
        assert!(req.hy2.values().any(|x| x == &new.username));
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod after_limit_tests {
    #[test]
    fn data_after_the_end_is_kept_by_source_and_goes_when_renewed() {
        let app = crate::test_app();
        let u = app.db.create_user("trial1", 0.5, 1, 1, "wg,xray", "", "", 0).unwrap();
        super::note_after_limit(&app, &u, "Germany · wg", 1000);
        super::note_after_limit(&app, &u, "Germany · wg", 500);
        super::note_after_limit(&app, &u, "Turkey · xray", 0);
        let v = super::after_limit_of(&app, u.id);
        assert_eq!(v["src"]["Germany · wg"], 1500);
        assert!(v["src"]["Turkey · xray"].is_null());
        // xray / DNS counters name the server and protocol of their key
        app.db.exec("UPDATE users SET used_bytes=?1 WHERE id=?2", &[&(1i64 << 30), &u.id]).unwrap();
        crate::dns::panel::count_usage(&app, "xray_prev_de1", &serde_json::json!({ "run": "r", "users": { u.id.to_string(): [700] } }));
        assert_eq!(super::after_limit_of(&app, u.id)["src"]["de1 · xray"], 700);
        // an active user's counters are not noted
        let ok = app.db.create_user("paid1", 50.0, 30, 1, "xray", "", "", 0).unwrap();
        crate::dns::panel::count_usage(&app, "xray_prev_de1", &serde_json::json!({ "run": "r", "users": { ok.id.to_string(): [700] } }));
        assert!(super::after_limit_of(&app, ok.id).is_null());
    }
}
