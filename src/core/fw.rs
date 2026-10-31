//! The firewall (ufw) ports Kanki opens, kept per service ("owner": the tunnels, Kanki DNS, Xray, the
//! emergency chat, KANKI MIX …), so a port is closed again as soon as what needed it is removed: a
//! deleted tunnel, a DNS server taken out of the panel, an Xray inbound, a server removed from the panel.
//!
//! A port is closed only when no other owner still needs it, never for SSH, and never while a program
//! that is not Kanki listens on it (an older rule of the admin for nginx on 443 stays open).
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
}

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

fn load() -> State {
    std::fs::read_to_string(STATE).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default()
}

fn save(s: &State) {
    let _ = std::fs::create_dir_all("/var/lib/kanki");
    let tmp = format!("{}.new", STATE);
    if std::fs::write(&tmp, serde_json::to_string(s).unwrap_or_default()).is_ok() {
        let _ = std::fs::rename(&tmp, STATE);
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
    let mut st = load();
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
    let close = to_close(&st, owner, &old, &want);
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
    let v = serde_json::json!({ "owners": st.owners, "unused": unused });
    *c.lock().unwrap_or_else(|e| e.into_inner()) = Some((Instant::now(), v.clone()));
    v
}

/// The admin asked to close these ufw rules: each is closed only if it is still unused (no owner wants
/// it, not SSH, nothing listens there). Blocking.
pub fn close_unused(rules: &[String]) {
    let st = load();
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
