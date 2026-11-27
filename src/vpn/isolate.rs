//! VPN users never reach this server's management ports or private networks through the kernel cores
//! (3.68). Hysteria2 (ACL), Xray (routing) and KANKI MIX (its own dialer) refuse those destinations
//! themselves; WireGuard and AmneziaWG users' packets are plain kernel traffic, so `iptables`/`ip6tables` do it:
//!
//! * `KANKI-ISO-IN` (INPUT, from `wg0`/`awg0`): TCP and UDP to the panel, node agent, Hysteria2 stats, Xray API,
//!   Kanki DNS intake/relay and Iran sub-relay ports are dropped. DNS (53) and the public HTTPS port stay open.
//! * `KANKI-ISO-FWD` (FORWARD, from `wg0`/`awg0`): private, CGNAT and link-local destinations (other machines of
//!   the provider, cloud metadata at 169.254.169.254) are dropped.
//!
//! Every call compares the chains with what they should be and rebuilds them only when they differ, so a ufw
//! reload that dropped a jump is repaired on the next sync. Arguments are passed as arrays, never through a shell.
use std::collections::HashMap;
use std::process::Command;

const IN_CHAIN: &str = "KANKI-ISO-IN";
const FWD_CHAIN: &str = "KANKI-ISO-FWD";
const IFACES: [&str; 2] = ["wg0", "awg0"];

const PRIVATE_V4: &[&str] = &["0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16"];
const PRIVATE_V6: &[&str] = &["::1/128", "fc00::/7", "fe80::/10"];

/// The management ports of this server (env values first, the defaults of the install script otherwise)
pub fn management_ports(env: &HashMap<String, String>) -> Vec<u16> {
    let mut v: Vec<u16> = vec![8080, 2096, crate::xray::API_PORT, 10853, 10854, 10855];
    for k in ["PANEL_PORT", "NODE_PORT", "HY2_STATS_PORT"] {
        if let Some(p) = env.get(k).and_then(|p| p.trim().parse::<u16>().ok()).filter(|p| *p > 0) {
            v.push(p);
        }
    }
    // the public HTTPS port (Caddy) and DNS are what users are meant to reach
    let https = env.get("HTTPS_PORT").and_then(|p| p.trim().parse::<u16>().ok()).unwrap_or(443);
    v.retain(|p| *p != https && *p != 53);
    v.sort_unstable();
    v.dedup();
    v
}

/// The rules of both chains for one tool, in the form `iptables -S <chain>` prints them
pub fn rules(v6: bool, ports: &[u16]) -> (Vec<String>, Vec<String>) {
    let list = ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(",");
    let mut inp = vec![format!("-N {}", IN_CHAIN)];
    if !ports.is_empty() {
        for proto in ["tcp", "udp"] {
            inp.push(format!("-A {} -p {} -m multiport --dports {} -j DROP", IN_CHAIN, proto, list));
        }
    }
    let mut fwd = vec![format!("-N {}", FWD_CHAIN)];
    for net in if v6 { PRIVATE_V6 } else { PRIVATE_V4 } {
        fwd.push(format!("-A {} -d {} -j DROP", FWD_CHAIN, net));
    }
    (inp, fwd)
}

fn tool_here(t: &str) -> bool {
    Command::new(t).arg("-V").output().map(|o| o.status.success()).unwrap_or(false)
}

fn run(t: &str, args: &[&str]) -> bool {
    Command::new(t).arg("-w").args(args).output().map(|o| o.status.success()).unwrap_or(false)
}

fn listed(t: &str, chain: &str) -> Vec<String> {
    Command::new(t)
        .args(["-w", "-S", chain])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).lines().map(|l| l.trim().to_string()).collect())
        .unwrap_or_default()
}

fn fill(t: &str, chain: &str, want: &[String]) {
    if listed(t, chain) == want {
        return;
    }
    if !run(t, &["-N", chain]) {
        run(t, &["-F", chain]);
    }
    for r in want.iter().skip(1) {
        let a: Vec<&str> = r.split_whitespace().collect();
        if !run(t, &a) {
            eprintln!("isolate: {} could not add `{}`", t, r);
        }
    }
}

fn jump(t: &str, parent: &str, iface: &str, chain: &str) {
    if !run(t, &["-C", parent, "-i", iface, "-j", chain]) && !run(t, &["-I", parent, "1", "-i", iface, "-j", chain]) {
        eprintln!("isolate: {} could not send {} {} to {}", t, parent, iface, chain);
    }
}

/// Puts both chains and their jumps in place (only what is missing or different). Blocking.
pub fn apply(env: &HashMap<String, String>) {
    let ports = management_ports(env);
    for (t, v6) in [("iptables", false), ("ip6tables", true)] {
        if !tool_here(t) {
            continue;
        }
        let (inp, fwd) = rules(v6, &ports);
        fill(t, IN_CHAIN, &inp);
        fill(t, FWD_CHAIN, &fwd);
        for i in IFACES {
            jump(t, "INPUT", i, IN_CHAIN);
            jump(t, "FORWARD", i, FWD_CHAIN);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn management_ports_are_closed_dns_and_https_stay() {
        let env: HashMap<String, String> = [("PANEL_PORT", "29332"), ("NODE_PORT", "2096"), ("HY2_STATS_PORT", "9999"), ("HTTPS_PORT", "443")]
            .into_iter()
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .collect();
        let p = management_ports(&env);
        for want in [29332, 2096, 9999, 8080, crate::xray::API_PORT] {
            assert!(p.contains(&want), "{} in {:?}", want, p);
        }
        assert!(!p.contains(&443) && !p.contains(&53));
        let (inp, fwd) = rules(false, &p);
        assert!(inp.iter().any(|r| r.contains("-p tcp -m multiport --dports") && r.contains("29332")));
        assert!(fwd.iter().any(|r| r == "-A KANKI-ISO-FWD -d 169.254.0.0/16 -j DROP"));
        assert!(fwd.iter().any(|r| r.contains("10.0.0.0/8")));
        let (_, f6) = rules(true, &p);
        assert!(f6.iter().any(|r| r.contains("fe80::/10")) && !f6.iter().any(|r| r.contains("10.0.0.0/8")));
    }
}
