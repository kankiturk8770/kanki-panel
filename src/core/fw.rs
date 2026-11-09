//! The firewall (ufw) ports Kanki opens, kept per service ("owner": the tunnels, Kanki DNS, Xray, the
//! emergency chat, KANKI MIX …), so a port is closed again as soon as what needed it is removed: a
//! deleted tunnel, a DNS server taken out of the panel, an Xray inbound, a server removed from the panel.
//!
//! A port is closed only when no other owner still needs it, never for SSH, and never while a program
//! that is not Kanki listens on it (an older rule of the admin for nginx on 443 stays open).
//!
//! The guard (3.38.0, a switch per server in the panel): ufw is turned on with every incoming port
//! closed except SSH and what Kanki uses here (every owner above, WireGuard, AmneziaWG, Hysteria2, the
//! panel's and the node's web ports, what Kanki's programs listen on, NAT redirects). Forwarding stays
//! allowed (VPN users and tunnels pass as before). The panel must confirm the server still works within
//! `GUARD_CONFIRM_SECS`; without that confirmation the server turns ufw off again by itself.
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

const STATE: &str = "/var/lib/kanki/fw.json";
/// how often the rules an owner still wants are allowed again (ufw may have been reset or turned on since)
const RECHECK_SECS: u64 = 600;

#[derive(Serialize, Deserialize, Default, Debug, PartialEq)]
#[serde(default)]
struct State {
    /// owner -> the rules it needs ("443/tcp", "4000:4010/udp")
    owners: BTreeMap<String, BTreeSet<String>>,
    guard: Guard,
}

/// The firewall guard of this server
#[derive(Serialize, Deserialize, Default, Debug, PartialEq, Clone)]
#[serde(default)]
pub struct Guard {
    /// ufw is on with only Kanki's ports and SSH open
    pub on: bool,
    /// Kanki turned ufw on (it was off): turning the guard off turns ufw off again
    pub by_kanki: bool,
    /// when it was turned on (unix seconds)
    pub since: i64,
    /// the panel saw the server still working afterwards
    pub confirmed: bool,
    /// why it is off although the panel asked for it ("" = nothing to say)
    pub note: String,
}

/// without the panel's confirmation this long after turning ufw on, the server turns it off again
pub const GUARD_CONFIRM_SECS: i64 = 180;

fn sh(cmd: &str) -> (bool, String) {
    match std::process::Command::new("sh").arg("-c").arg(cmd).stdin(std::process::Stdio::null()).output() {
        Ok(o) => {
            let mut t = String::from_utf8_lossy(&o.stdout).to_string();
            t.push_str(&String::from_utf8_lossy(&o.stderr));
            (o.status.success(), t.trim().to_string())
        }
        Err(e) => (false, e.to_string()),
    }
}

fn lock() -> &'static Mutex<HashMap<String, Instant>> {
    static L: OnceLock<Mutex<HashMap<String, Instant>>> = OnceLock::new();
    L.get_or_init(|| Mutex::new(HashMap::new()))
}

/// "443/tcp" or "4000:4010/udp" (the only forms written into ufw commands)
pub fn valid_rule(r: &str) -> bool {
    let Some((ports, proto)) = r.split_once('/') else { return false };
    if proto != "tcp" && proto != "udp" {
        return false;
    }
    let num = |s: &str| s.parse::<u16>().map(|p| p > 0).unwrap_or(false) && s.bytes().all(|c| c.is_ascii_digit());
    match ports.split_once(':') {
        Some((a, b)) => num(a) && num(b) && a.parse::<u16>().unwrap_or(0) < b.parse::<u16>().unwrap_or(0),
        None => num(ports),
    }
}

/// a rule for one port and protocol
pub fn rule(port: u16, udp: bool) -> String {
    format!("{}/{}", port, if udp { "udp" } else { "tcp" })
}

/// SSH ports: never closed by Kanki, whatever asked for them
fn ssh_ports() -> BTreeSet<u16> {
    let mut v: BTreeSet<u16> = [22].into_iter().collect();
    for f in ["/etc/ssh/sshd_config"].into_iter().map(String::from).chain(
        std::fs::read_dir("/etc/ssh/sshd_config.d").into_iter().flatten().flatten().map(|e| e.path().to_string_lossy().to_string()),
    ) {
        for l in std::fs::read_to_string(&f).unwrap_or_default().lines() {
            let l = l.trim();
            if let Some(p) = l.strip_prefix("Port ").or_else(|| l.strip_prefix("Port\t")) {
                if let Ok(p) = p.trim().parse() {
                    v.insert(p);
                }
            }
        }
    }
    v
}

fn protected(r: &str, ssh: &BTreeSet<u16>) -> bool {
    r.split('/').next().and_then(|p| p.parse::<u16>().ok()).map(|p| ssh.contains(&p) && r.ends_with("/tcp")).unwrap_or(false)
}

/// the last state that was read back fine (kept so a broken fw.json does not forget every owner)
fn backup() -> String {
    format!("{}.bak", STATE)
}

/// Read a state file: Ok(None) when it does not exist, Err when it is there but cannot be read.
fn read_state(path: &str) -> Result<Option<State>, ()> {
    match std::fs::read_to_string(path) {
        Ok(t) if t.trim().is_empty() => Err(()),
        Ok(t) => serde_json::from_str(&t).map(Some).map_err(|_| ()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(()),
    }
}

/// The saved state. None when fw.json is broken and there is no good backup either: then nobody knows
/// which owners still need which ports, so nothing may be closed on its account.
fn load_checked() -> Option<State> {
    match read_state(STATE) {
        Ok(s) => Some(s.unwrap_or_default()),
        Err(()) => match read_state(&backup()) {
            Ok(Some(s)) => {
                eprintln!("firewall: {} is broken, using the last good copy", STATE);
                Some(s)
            }
            _ => {
                eprintln!("firewall: {} is broken and has no good copy; no port is closed until the owners are known again", STATE);
                None
            }
        },
    }
}

fn load() -> State {
    load_checked().unwrap_or_default()
}

/// write `text` to `path` through a temp file of this process (the panel, node and agent share the file)
fn write_atomic(path: &str, text: &str) -> bool {
    let tmp = format!("{}.{}.new", path, std::process::id());
    if std::fs::write(&tmp, text).is_ok() && std::fs::rename(&tmp, path).is_ok() {
        return true;
    }
    let _ = std::fs::remove_file(&tmp);
    false
}

fn save(s: &State) {
    let _ = std::fs::create_dir_all("/var/lib/kanki");
    let text = serde_json::to_string(s).unwrap_or_default();
    if write_atomic(STATE, &text) {
        let _ = write_atomic(&backup(), &text);
    }
}

/// An exclusive lock on the state for every Kanki process on this server, held while the guard lives
/// (load, change, save must not interleave between the panel, node and the tunnel agent).
struct FileLock(Option<std::fs::File>);

fn file_lock() -> FileLock {
    use std::os::unix::io::AsRawFd;
    let _ = std::fs::create_dir_all("/var/lib/kanki");
    let f = std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(format!("{}.lock", STATE));
    match f {
        Ok(f) => {
            // blocking: the other holder only runs a few ufw commands
            unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX) };
            FileLock(Some(f))
        }
        Err(_) => FileLock(None),
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        use std::os::unix::io::AsRawFd;
        if let Some(f) = &self.0 {
            unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_UN) };
        }
    }
}

fn ufw_here() -> bool {
    sh("command -v ufw").0
}

fn ufw_active() -> bool {
    sh("ufw status 2>/dev/null | grep -q 'Status: active'").0
}

/// The rules to close when `owner` goes from `old` to `want`: the ones nobody else needs any more.
fn to_close(st: &State, owner: &str, old: &BTreeSet<String>, want: &BTreeSet<String>) -> Vec<String> {
    old.iter()
        .filter(|r| !want.contains(*r))
        .filter(|r| !st.owners.iter().any(|(o, rs)| o != owner && rs.contains(*r)))
        .cloned()
        .collect()
}

/// Open exactly the rules `want` for `owner`: new ones are allowed in ufw (when ufw is on), the ones it
/// no longer needs are deleted (unless another owner needs them, it is SSH, or a program that is not
/// Kanki listens there). Cheap when nothing changed: safe to call every few seconds. Blocking.
pub fn sync<I: IntoIterator<Item = String>>(owner: &str, want: I) {
    let ssh = ssh_ports();
    let want: BTreeSet<String> = want.into_iter().filter(|r| valid_rule(r) && !protected(r, &ssh)).collect();
    let mut seen = lock().lock().unwrap_or_else(|e| e.into_inner());
    let _file = file_lock();
    let loaded = load_checked();
    let known = loaded.is_some();
    let mut st = loaded.unwrap_or_default();
    let old = st.owners.get(owner).cloned().unwrap_or_default();
    let recheck = seen.get(owner).map(|t| t.elapsed().as_secs() >= RECHECK_SECS).unwrap_or(true);
    if old == want && !recheck {
        return;
    }
    if !ufw_here() {
        if want.is_empty() {
            st.owners.remove(owner);
        } else {
            st.owners.insert(owner.to_string(), want);
        }
        save(&st);
        seen.insert(owner.to_string(), Instant::now());
        return;
    }
    // a broken state forgot the other owners: open what is wanted, close nothing this time
    let close = if known { to_close(&st, owner, &old, &want) } else { vec![] };
    if ufw_active() {
        // only the rules ufw does not have yet (one status read, not one command per port)
        let (_, status) = sh("ufw status 2>/dev/null");
        let present = status_rules(&status);
        for r in want.iter().filter(|r| !present.contains(*r)) {
            let _ = sh(&format!("ufw allow {} >/dev/null 2>&1", r));
        }
    }
    for r in &close {
        let single = r.split('/').next().and_then(|p| p.parse::<u16>().ok());
        if let Some(p) = single {
            if crate::certbot::foreign_listener(p, r.ends_with("/udp")) {
                eprintln!("firewall: {} stays open (another program listens there)", r);
                continue;
            }
        }
        if sh(&format!("ufw --force delete allow {} >/dev/null 2>&1", r)).0 {
            eprintln!("firewall: closed {} (no longer used by {})", r, owner);
        }
    }
    if want.is_empty() {
        st.owners.remove(owner);
    } else {
        st.owners.insert(owner.to_string(), want);
    }
    save(&st);
    seen.insert(owner.to_string(), Instant::now());
}

/// Close every port of `owner` (it was removed from this server). Blocking.
pub fn close(owner: &str) {
    sync(owner, Vec::<String>::new());
}

/// Close the ports of every owner (this server was removed from the panel). Blocking.
pub fn close_all() {
    let owners: Vec<String> = load().owners.keys().cloned().collect();
    for o in owners {
        close(&o);
    }
}

/// "443/tcp" rules allowed for anywhere in `ufw status` text (single ports with a protocol only)
fn allowed_rules(status: &str) -> BTreeSet<String> {
    status
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            // "443/tcp ALLOW Anywhere" or "443/tcp (v6) ALLOW Anywhere (v6)"
            let (r, rest) = (f.first()?, &f[1..]);
            let rest: Vec<&&str> = rest.iter().filter(|x| **x != "(v6)").collect();
            (rest.first().map(|a| **a == "ALLOW") == Some(true) && rest.get(1).map(|a| **a == "Anywhere") == Some(true) && valid_rule(r) && !r.contains(':'))
                .then(|| r.to_string())
        })
        .collect()
}

/// every "port/proto" or "a:b/proto" rule of `ufw status` that allows anywhere (ranges too)
fn status_rules(status: &str) -> BTreeSet<String> {
    status
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().filter(|x| *x != "(v6)").collect();
            (f.len() >= 3 && f[1] == "ALLOW" && f[2] == "Anywhere" && valid_rule(f[0])).then(|| f[0].to_string())
        })
        .collect()
}

/// ports that a kernel module or iptables uses without a listening socket (WireGuard / AmneziaWG
/// interfaces, NAT redirects, Docker): never offered for closing
fn hidden_users() -> BTreeSet<String> {
    let mut v = BTreeSet::new();
    for tool in ["wg", "awg"] {
        let (_, out) = sh(&format!("command -v {t} >/dev/null 2>&1 && {t} show all listen-port 2>/dev/null", t = tool));
        for p in out.lines().filter_map(|l| l.split_whitespace().last()?.parse::<u16>().ok()) {
            v.insert(rule(p, true));
        }
    }
    let (_, nat) = sh("iptables -t nat -S 2>/dev/null; ip6tables -t nat -S 2>/dev/null");
    for l in nat.lines() {
        let f: Vec<&str> = l.split_whitespace().collect();
        let proto = f.windows(2).find(|w| w[0] == "-p").map(|w| w[1]).unwrap_or("");
        for w in f.windows(2).filter(|w| w[0] == "--dport" || w[0] == "--to-ports") {
            if let Ok(p) = w[1].parse::<u16>() {
                for pr in ["tcp", "udp"] {
                    if proto.is_empty() || proto == pr {
                        v.insert(format!("{}/{}", p, pr));
                    }
                }
            }
        }
    }
    v
}

// ------------------------------------------------------------------ the guard

/// programs of Kanki (and the services it installs) whose listening ports the guard keeps open
const OURS: &[&str] = &["kanki-panel", "caddy", "hysteria", "xray", "kanki-mix-serve", "kanki-mix-server", "sshd"];

/// whether a public listener belongs to Kanki (or SSH)
fn ours(prog: &str, unit: &str) -> bool {
    OURS.contains(&prog) || unit.starts_with("kanki") || matches!(unit, "caddy.service" | "hysteria-server.service" | "ssh.service" | "sshd.service") || unit.starts_with("xray")
}

/// the `ListenPort` of a WireGuard / AmneziaWG config
fn conf_port(path: &str) -> Option<u16> {
    std::fs::read_to_string(path).ok()?.lines().find_map(|l| {
        let (k, v) = l.split_once('=')?;
        (k.trim() == "ListenPort").then(|| v.trim().parse().ok()).flatten()
    })
}

/// Every port Kanki needs open here, whatever ufw says now: SSH, the cores' configs, the web ports in
/// kanki.env, what Kanki's programs listen on from outside, NAT redirects and every owner's rules.
fn needed(st: &State) -> BTreeSet<String> {
    let mut v: BTreeSet<String> = ssh_ports().into_iter().map(|p| rule(p, false)).collect();
    for f in ["/etc/wireguard/wg0.conf", "/etc/amnezia/amneziawg/awg0.conf"] {
        if let Some(p) = conf_port(f) {
            v.insert(rule(p, true));
        }
    }
    let env = crate::util::load_env("/etc/kanki/kanki.env");
    for (k, udp) in [("HY2_PORT", true), ("HTTPS_PORT", false), ("NODE_PUBLIC_PORT", false)] {
        if let Some(p) = env.get(k).and_then(|p| p.trim().parse::<u16>().ok()).filter(|p| *p > 0) {
            v.insert(rule(p, udp));
        }
    }
    for (port, udp, prog, unit) in crate::certbot::public_listeners() {
        // UDP: the kernel's (WireGuard / AmneziaWG) and Kanki's services outside the range the system
        // gives to outgoing sockets (an unconnected client socket looks like a listener there); ports
        // in that range come from the owners' lists
        let take = if udp { prog == "kernel" || (ours(&prog, &unit) && !(32768..=60999).contains(&port)) } else { ours(&prog, &unit) };
        if take {
            v.insert(rule(port, udp));
        }
    }
    v.extend(hidden_users());
    for rs in st.owners.values() {
        v.extend(rs.iter().cloned());
    }
    v.retain(|r| valid_rule(r));
    v
}

/// the rules ufw has, on or off ("ufw show added" lists them either way)
fn added_rules() -> BTreeSet<String> {
    let (_, out) = sh("ufw show added 2>/dev/null");
    out.lines().filter_map(|l| l.trim().strip_prefix("ufw allow ")).map(|r| r.trim().to_string()).filter(|r| valid_rule(r)).collect()
}

fn install_ufw() -> bool {
    if ufw_here() {
        return true;
    }
    let _ = sh("DEBIAN_FRONTEND=noninteractive timeout 240 apt-get install -y ufw >/dev/null 2>&1 || (timeout 240 apt-get update >/dev/null 2>&1 && DEBIAN_FRONTEND=noninteractive timeout 240 apt-get install -y ufw >/dev/null 2>&1)");
    ufw_here()
}

/// Turn ufw on with only `want` (and SSH) open. SSH must be in ufw before it is turned on. Blocking.
fn enable(want: &BTreeSet<String>) -> Result<bool, String> {
    if !install_ufw() {
        return Err("ufw is not installed and could not be installed".into());
    }
    let was = ufw_active();
    let have = added_rules();
    for r in want.iter().filter(|r| !have.contains(*r)) {
        let _ = sh(&format!("ufw allow {} >/dev/null 2>&1", r));
    }
    let have = added_rules();
    let ssh: Vec<String> = ssh_ports().into_iter().map(|p| rule(p, false)).collect();
    if let Some(r) = ssh.iter().find(|r| !have.contains(*r)) {
        return Err(format!("SSH ({}) could not be allowed in ufw: not turned on", r));
    }
    // forwarding stays open: VPN users and tunnels pass through this server as before
    for c in ["ufw default allow outgoing", "ufw default allow routed", "ufw default deny incoming"] {
        if !sh(&format!("{} >/dev/null 2>&1", c)).0 {
            return Err(format!("\"{}\" failed", c));
        }
    }
    if !was && !sh("ufw --force enable >/dev/null 2>&1").0 {
        return Err("ufw could not be turned on".into());
    }
    if !was {
        // ufw keeps its rules in its own chains; ours (VPN NAT and forwarding) stay as they were
        let _ = sh("ufw reload >/dev/null 2>&1");
    }
    if !ufw_active() {
        return Err("ufw did not turn on".into());
    }
    Ok(!was)
}

/// One round of the guard (every report of the agent, and the panel's own loop): `want` is what the
/// panel asks (None = a panel that knows nothing of it), `confirm` that the panel saw this server still
/// working. Returns the guard's state. Blocking.
pub fn guard_tick(want: Option<bool>, confirm: bool) -> Guard {
    // installing ufw can take minutes: not while holding what the other Kanki programs here wait on
    if want == Some(true) && !ufw_here() {
        install_ufw();
    }
    let mut seen = lock().lock().unwrap_or_else(|e| e.into_inner());
    let _file = file_lock();
    let Some(mut st) = load_checked() else { return Guard { note: "the firewall state is broken".into(), ..Default::default() } };
    let now = crate::util::now();
    let before = st.guard.clone();
    match want {
        None => {}
        Some(true) if !st.guard.on => {
            // asked again after it was rolled back or turned off by hand: only when the panel asks anew
            if st.guard.note.is_empty() {
                let need = needed(&st);
                match enable(&need) {
                    Ok(by) => {
                        st.guard = Guard { on: true, by_kanki: by, since: now, confirmed: false, note: String::new() };
                        // every owner's rules are in ufw now: no early return in `sync` keeps one out
                        seen.clear();
                        eprintln!("firewall: on, {} rule(s) open, the rest closed; waiting for the panel to confirm", need.len());
                    }
                    Err(e) => {
                        eprintln!("firewall: {}", e);
                        st.guard.note = e;
                    }
                }
            }
        }
        Some(true) => {
            if !ufw_active() {
                // turned off by hand on the server: not turned on again behind the admin's back
                st.guard = Guard { note: "ufw was turned off on the server".into(), ..Default::default() };
            } else if !st.guard.confirmed && confirm {
                st.guard.confirmed = true;
                eprintln!("firewall: confirmed by the panel");
            } else if !st.guard.confirmed && now - st.guard.since > GUARD_CONFIRM_SECS {
                if st.guard.by_kanki {
                    let _ = sh("ufw --force disable >/dev/null 2>&1");
                }
                eprintln!("firewall: the panel did not confirm within {} s: turned off again", GUARD_CONFIRM_SECS);
                st.guard = Guard { note: "rolled back: the panel did not see this server working with the firewall on".into(), ..Default::default() };
            } else {
                // something new listens or was added since: open it too
                let have = added_rules();
                for r in needed(&st).iter().filter(|r| !have.contains(*r)) {
                    let _ = sh(&format!("ufw allow {} >/dev/null 2>&1", r));
                }
            }
        }
        Some(false) => {
            if st.guard.on && st.guard.by_kanki {
                let _ = sh("ufw --force disable >/dev/null 2>&1");
                eprintln!("firewall: off (as before Kanki turned it on)");
            }
            st.guard = Guard::default();
        }
    }
    if st.guard != before {
        save(&st);
        *report_cache().lock().unwrap_or_else(|e| e.into_inner()) = None;
    }
    st.guard
}

/// The panel asked for the guard anew (a press of the switch): a note of an earlier failure is forgotten
pub fn guard_reset_note() {
    let _file = file_lock();
    if let Some(mut st) = load_checked() {
        if !st.guard.note.is_empty() {
            st.guard.note.clear();
            save(&st);
        }
    }
}

fn report_cache() -> &'static Mutex<Option<(Instant, serde_json::Value)>> {
    static C: OnceLock<Mutex<Option<(Instant, serde_json::Value)>>> = OnceLock::new();
    C.get_or_init(|| Mutex::new(None))
}

/// What the agent reports: the ports of each owner, and the ports open in ufw that nothing uses (an
/// earlier version opened them for something deleted since, or they were opened by hand). Worked out at
/// most once a minute. Blocking.
pub fn report() -> serde_json::Value {
    let c = report_cache();
    if let Some((at, v)) = c.lock().unwrap_or_else(|e| e.into_inner()).as_ref() {
        if at.elapsed().as_secs() < 60 {
            return v.clone();
        }
    }
    let st = load();
    let mut unused: Vec<String> = vec![];
    if ufw_here() && ufw_active() {
        let (_, status) = sh("ufw status 2>/dev/null");
        let owned: BTreeSet<&String> = st.owners.values().flatten().collect();
        let ssh = ssh_ports();
        let hidden = hidden_users();
        for r in allowed_rules(&status) {
            if owned.contains(&r) || protected(&r, &ssh) || hidden.contains(&r) {
                continue;
            }
            let (p, udp) = (r.split('/').next().and_then(|p| p.parse::<u16>().ok()).unwrap_or(0), r.ends_with("/udp"));
            if p == 0 || crate::certbot::listening(p, udp) {
                continue;
            }
            unused.push(r);
        }
    }
    let active = ufw_here() && ufw_active();
    let v = serde_json::json!({ "owners": st.owners, "unused": unused, "guard": st.guard, "active": active, "ufw": ufw_here() });
    *c.lock().unwrap_or_else(|e| e.into_inner()) = Some((Instant::now(), v.clone()));
    v
}

/// The admin asked to close these ufw rules: each is closed only if it is still unused (no owner wants
/// it, not SSH, nothing listens there). Blocking.
pub fn close_unused(rules: &[String]) {
    let _file = file_lock();
    let Some(st) = load_checked() else { return };
    let ssh = ssh_ports();
    let hidden = hidden_users();
    for r in rules.iter().filter(|r| valid_rule(r) && !r.contains(':')) {
        if st.owners.values().any(|v| v.contains(r)) || protected(r, &ssh) || hidden.contains(r) {
            continue;
        }
        let p = r.split('/').next().and_then(|p| p.parse::<u16>().ok()).unwrap_or(0);
        if p == 0 || crate::certbot::listening(p, r.ends_with("/udp")) {
            continue;
        }
        if sh(&format!("ufw --force delete allow {} >/dev/null 2>&1", r)).0 {
            eprintln!("firewall: closed unused {}", r);
        }
    }
    // the next report shows the new state
    *report_cache().lock().unwrap_or_else(|e| e.into_inner()) = None;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_plain_rules_reach_ufw() {
        for r in ["443/tcp", "53/udp", "4000:4010/udp"] {
            assert!(valid_rule(r), "{}", r);
        }
        for r in ["0/tcp", "443", "443/icmp", "4010:4000/udp", "1;rm -rf /", "443/tcp ", "80:80/tcp", "65536/tcp", "+80/tcp"] {
            assert!(!valid_rule(r), "{}", r);
        }
        assert_eq!(rule(53, true), "53/udp");
    }

    #[test]
    fn a_port_another_owner_needs_stays_open() {
        let mut st = State::default();
        let set = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<BTreeSet<String>>();
        st.owners.insert("dns".into(), set(&["53/udp", "443/tcp", "80/tcp"]));
        st.owners.insert("xray".into(), set(&["443/tcp"]));
        let old = st.owners["dns"].clone();
        let mut close = to_close(&st, "dns", &old, &BTreeSet::new());
        close.sort();
        assert_eq!(close, vec!["53/udp".to_string(), "80/tcp".to_string()]);
        // a smaller list closes only what was dropped
        assert_eq!(to_close(&st, "dns", &old, &set(&["53/udp", "443/tcp"])), vec!["80/tcp".to_string()]);
    }

    #[test]
    fn a_broken_state_is_not_read_as_empty() {
        let dir = std::env::temp_dir().join(format!("kanki-fw-test-{}", crate::util::rand_token(8)));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("fw.json");
        let f = f.to_str().unwrap();
        assert_eq!(read_state(f), Ok(None));
        assert!(write_atomic(f, r#"{"owners":{"dns":["53/udp"]}}"#));
        assert_eq!(read_state(f).unwrap().unwrap().owners["dns"].len(), 1);
        std::fs::write(f, "{\"owners\":{\"dns\":[").unwrap();
        assert_eq!(read_state(f), Err(()));
        std::fs::write(f, "").unwrap();
        assert_eq!(read_state(f), Err(()));
        // no temp file is left behind
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ssh_is_never_closed() {
        let ssh: BTreeSet<u16> = [22, 2222].into_iter().collect();
        assert!(protected("22/tcp", &ssh) && protected("2222/tcp", &ssh));
        assert!(!protected("22/udp", &ssh) && !protected("443/tcp", &ssh) && !protected("2000:3000/tcp", &ssh));
    }

    #[test]
    fn rules_read_from_ufw_status() {
        let st = "Status: active\n\nTo                         Action      From\n--                         ------      ----\n22/tcp                     ALLOW       Anywhere\n443/tcp                    ALLOW       Anywhere\n8443/tcp                   ALLOW       1.2.3.4\n4000:4010/udp              ALLOW       Anywhere\n53                         ALLOW       Anywhere\n2053/tcp                   DENY        Anywhere\n443/tcp (v6)               ALLOW       Anywhere (v6)\n9000/udp (v6)              ALLOW       Anywhere (v6)\n";
        let got: Vec<String> = allowed_rules(st).into_iter().collect();
        assert_eq!(got, vec!["22/tcp", "443/tcp", "9000/udp"]);
        let all: Vec<String> = status_rules(st).into_iter().collect();
        assert_eq!(all, vec!["22/tcp", "4000:4010/udp", "443/tcp", "9000/udp"]);
    }
}

/// The guard for real, with ufw and iptables, in a network namespace made for it (root; run by
/// `scripts/fw_guard_live.sh`, which also checks from outside which ports answer).
#[cfg(test)]
#[test]
#[ignore]
fn guard_live() {
    let run = |c: &str| sh(c);
    let wait = |secs: u64| std::thread::sleep(std::time::Duration::from_secs(secs));
    let _ = run("ufw --force disable; ufw --force reset");
    let _ = std::fs::remove_file(STATE);
    let _ = std::fs::remove_file(backup());
    // a VPN server forwards; the VPN's own forwarding and NAT (like wg-quick or microtun) must survive ufw
    let _ = std::fs::write("/proc/sys/net/ipv4/ip_forward", "1");
    let _ = run("iptables -I FORWARD -i kt0 -j ACCEPT; iptables -t nat -A POSTROUTING -s 10.79.0.0/16 ! -o kt0 -j MASQUERADE");
    // a tunnel's ports while ufw is still off: only remembered
    sync("tunnels", vec!["8443/tcp".to_string(), "24300/udp".to_string()]);
    let g = guard_tick(Some(true), false);
    assert!(g.on && g.by_kanki && !g.confirmed, "{:?}", g);
    assert!(ufw_active());
    let added = added_rules();
    for r in ["22/tcp", "8443/tcp", "24300/udp"] {
        assert!(added.contains(r), "{} not open: {:?}", r, added);
    }
    assert!(!added.contains("9999/tcp"), "{:?}", added);
    let (_, verbose) = run("ufw status verbose");
    assert!(verbose.contains("deny (incoming)") && verbose.contains("allow (outgoing)") && verbose.contains("allow (routed)"), "{}", verbose);
    let (_, fwd) = run("iptables -S FORWARD; iptables -t nat -S POSTROUTING");
    assert!(fwd.contains("-i kt0 -j ACCEPT") && fwd.contains("10.79.0.0/16"), "our rules are gone: {}", fwd);
    assert_eq!(std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward").unwrap_or_default().trim(), "1", "forwarding was turned off");
    println!("GUARD ON");
    wait(std::env::var("FW_HOLD").ok().and_then(|s| s.parse().ok()).unwrap_or(8));
    // a tunnel is deleted and another made: its port closes, the new one opens at once (the tunnel
    // stops listening first, as Kanki does: the script stops the stand-in listener)
    for _ in 0..40 {
        if !crate::certbot::listening(8443, false) {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    sync("tunnels", vec!["24300/udp".to_string(), "9443/tcp".to_string()]);
    let added = added_rules();
    assert!(!added.contains("8443/tcp") && added.contains("9443/tcp"), "{:?}", added);
    println!("TUNNEL PORTS MOVED");
    wait(std::env::var("FW_HOLD").ok().and_then(|s| s.parse().ok()).unwrap_or(8));
    // the panel never confirms: rolled back by itself
    {
        let _l = file_lock();
        let mut st = load();
        st.guard.since -= GUARD_CONFIRM_SECS + 5;
        save(&st);
    }
    let g = guard_tick(Some(true), false);
    assert!(!g.on && g.note.starts_with("rolled back"), "{:?}", g);
    assert!(!ufw_active(), "still on after the roll back");
    // asked again without a new press: stays off; a new press turns it on, the panel confirms
    assert!(!guard_tick(Some(true), false).on);
    guard_reset_note();
    assert!(guard_tick(Some(true), false).on);
    let g = guard_tick(Some(true), true);
    assert!(g.on && g.confirmed, "{:?}", g);
    // confirmed: no roll back, however long
    {
        let _l = file_lock();
        let mut st = load();
        st.guard.since -= 10_000;
        save(&st);
    }
    assert!(guard_tick(Some(true), false).on && ufw_active());
    // turned off in the panel: ufw off again, as it was before Kanki
    let g = guard_tick(Some(false), false);
    assert!(!g.on && !ufw_active());
    let (_, fwd) = run("iptables -S FORWARD");
    assert!(fwd.contains("-i kt0 -j ACCEPT"), "{}", fwd);
    println!("GUARD LIVE OK");
}
