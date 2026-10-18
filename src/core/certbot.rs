//! SSL with certbot, the simple way: the agent runs certbot on the server the domain points to, with no
//! e-mail. Port 80 is handled by itself, when the certificate is first taken and on every renewal:
//! - nothing on port 80: `certbot --standalone`;
//! - Kanki DNS on port 80: `certbot --webroot` (Kanki DNS answers Let's Encrypt itself), so DNS never stops;
//! - anything else on port 80 (Caddy, nginx, an Xray inbound, a Docker container …): it is stopped for the
//!   few seconds certbot needs and started again right after, even when certbot fails or hangs.
//! certbot renews by itself; the agent also checks every 12 hours and renews a certificate that is close to
//! its end with what holds port 80 at that moment, so a renewal does not fail because the server changed.
//! After a failure it waits before trying again (10 minutes, then longer, up to a day), so a server that
//! Let's Encrypt cannot reach is not disturbed again and again.
use std::path::Path;

/// Kanki DNS serves `/.well-known/acme-challenge/` on port 80 from here.
pub const WEBROOT: &str = "/var/lib/kanki/acme-webroot";
/// per domain: `<domain>.units` (services using the certificate), `<domain>.fail` (failures in a row + why)
const STATE_DIR: &str = "/var/lib/kanki/certbot";
const DEPLOY_HOOK: &str = "/etc/letsencrypt/renewal-hooks/deploy/kanki-restart.sh";
/// renew when fewer days are left (certbot itself renews at 30)
const RENEW_DAYS: u64 = 25;

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

/// (certificate chain, private key) files of a domain
pub fn files(domain: &str) -> (String, String) {
    (format!("/etc/letsencrypt/live/{}/fullchain.pem", domain), format!("/etc/letsencrypt/live/{}/privkey.pem", domain))
}

pub fn have(domain: &str) -> bool {
    Path::new(&files(domain).0).exists() && Path::new(&files(domain).1).exists()
}

pub fn valid_domain(d: &str) -> bool {
    d.parse::<std::net::IpAddr>().is_err()
        && d.contains('.')
        && d.split('.').all(|l| !l.is_empty() && l.len() <= 63 && l.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-'))
}

/// A file Kanki DNS may serve for Let's Encrypt: `/.well-known/acme-challenge/<token>`.
pub fn challenge(path: &str) -> Option<String> {
    let token = path.strip_prefix("/.well-known/acme-challenge/")?;
    if token.is_empty() || token.len() > 200 || !token.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_') {
        return None;
    }
    std::fs::read_to_string(format!("{}/.well-known/acme-challenge/{}", WEBROOT, token)).ok()
}

/// a name that is safe inside the hook commands
fn safe(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|c| c.is_ascii_alphanumeric() || b"@._-:".contains(&c))
}

/// Who listens on TCP port 80 now.
#[derive(Default, Debug, PartialEq)]
struct Port80 {
    /// systemd services (stopped and started again)
    units: Vec<String>,
    /// Docker containers (stopped and started again)
    containers: Vec<String>,
    /// Kanki DNS (answers Let's Encrypt itself)
    kdns: bool,
    /// programs that are not a service: cannot be set aside safely
    other: Vec<String>,
}

/// socket inodes listening on TCP `port` in /proc/net/tcp or tcp6 text
fn listen_inodes(text: &str, port: u16) -> Vec<String> {
    let hex = format!(":{:04X}", port);
    text.lines()
        .skip(1)
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            (f.len() > 9 && f[1].ends_with(&hex) && f[3] == "0A").then(|| f[9].to_string())
        })
        .filter(|i| i != "0")
        .collect()
}

/// is anything listening on TCP port 80?
pub fn port80_used() -> bool {
    ["/proc/net/tcp", "/proc/net/tcp6"].iter().any(|f| !listen_inodes(&std::fs::read_to_string(f).unwrap_or_default(), 80).is_empty())
}

/// (program, pid) of everything listening on TCP port 80 (read from /proc, no tools needed)
fn holders() -> Vec<(String, u32)> {
    let mut inodes = vec![];
    for f in ["/proc/net/tcp", "/proc/net/tcp6"] {
        inodes.extend(listen_inodes(&std::fs::read_to_string(f).unwrap_or_default(), 80).into_iter().map(|i| format!("socket:[{}]", i)));
    }
    let mut v = vec![];
    if inodes.is_empty() {
        return v;
    }
    for e in std::fs::read_dir("/proc").into_iter().flatten().flatten() {
        let Ok(pid) = e.file_name().to_string_lossy().parse::<u32>() else { continue };
        let Ok(fds) = std::fs::read_dir(format!("/proc/{}/fd", pid)) else { continue };
        if fds.flatten().any(|fd| std::fs::read_link(fd.path()).map(|l| inodes.iter().any(|i| Path::new(i) == l)).unwrap_or(false)) {
            v.push((std::fs::read_to_string(format!("/proc/{}/comm", pid)).unwrap_or_default().trim().to_string(), pid));
        }
    }
    v
}

/// the systemd service or scope of a process, from /proc/<pid>/cgroup
fn unit_of(cgroup: &str) -> String {
    cgroup
        .lines()
        .flat_map(|l| l.split('/'))
        .filter(|s| s.ends_with(".service") || s.ends_with(".scope"))
        .last()
        .unwrap_or("")
        .to_string()
}

fn port80() -> Port80 {
    let mut p = Port80::default();
    for (name, pid) in holders() {
        let unit = unit_of(&std::fs::read_to_string(format!("/proc/{}/cgroup", pid)).unwrap_or_default());
        if unit == "kanki-dns.service" {
            p.kdns = true;
        } else if let Some(id) = unit.strip_prefix("docker-").and_then(|s| s.strip_suffix(".scope")) {
            // a container on the host network
            p.containers.push(id.chars().take(12).collect());
        } else if unit == "docker.service" || unit == "containerd.service" {
            // docker-proxy of a published port: that container is stopped below, not Docker
        } else if unit.ends_with(".service") && safe(&unit) {
            p.units.push(unit);
        } else {
            p.other.push(format!("{} (pid {})", if name.is_empty() { "?" } else { &name }, pid));
        }
    }
    // containers publishing port 80 (also without docker-proxy, when Docker forwards the port itself)
    if sh("command -v docker").0 {
        let (_, ids) = sh("docker ps --filter publish=80 --format '{{.ID}}' 2>/dev/null");
        p.containers.extend(ids.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()));
    }
    p.containers.retain(|c| safe(c));
    for v in [&mut p.units, &mut p.containers, &mut p.other] {
        v.sort();
        v.dedup();
    }
    p
}

/// does the domain have an IPv6 address? (Kanki DNS answers on port 80 over IPv4 only)
fn has_v6(domain: &str) -> bool {
    use std::net::ToSocketAddrs;
    (domain, 80).to_socket_addrs().map(|a| a.into_iter().any(|x| x.is_ipv6())).unwrap_or(false)
}

/// the certbot options for port 80 and the commands that give it back afterwards
fn port80_plan(p: &Port80, v6: bool) -> (String, Vec<String>) {
    if p.kdns && p.units.is_empty() && p.containers.is_empty() && !v6 {
        // Kanki DNS holds port 80 and answers Let's Encrypt from the webroot: nothing stops
        return (format!(" --webroot -w {}", WEBROOT), vec![]);
    }
    let mut stop: Vec<String> = p.units.iter().map(|u| format!("systemctl stop {} || true", u)).collect();
    let mut start: Vec<String> = p.units.iter().map(|u| format!("systemctl start {} || true", u)).collect();
    if p.kdns {
        stop.push("systemctl stop kanki-dns.service || true".into());
        start.push("systemctl start kanki-dns.service || true".into());
    }
    stop.extend(p.containers.iter().map(|c| format!("docker stop {} || true", c)));
    start.extend(p.containers.iter().map(|c| format!("docker start {} || true", c)));
    let mut how = " --standalone".to_string();
    if !stop.is_empty() {
        // kept by certbot for its own renewals too
        how.push_str(&format!(" --pre-hook \"{}\" --post-hook \"{}\"", stop.join("; "), start.join("; ")));
    }
    (how, start)
}

fn units_file(domain: &str) -> String {
    format!("{}/{}.units", STATE_DIR, domain)
}

fn units(domain: &str) -> Vec<String> {
    std::fs::read_to_string(units_file(domain)).unwrap_or_default().lines().map(|l| l.trim().to_string()).filter(|l| safe(l)).collect()
}

/// certbot's own renewals restart what uses the certificate (read from the state dir at that time)
fn write_deploy_hook() {
    let script = format!(
        "#!/bin/sh\n# written by kanki-panel: restart the services that use a renewed certificate\nf={}/$(basename \"$RENEWED_LINEAGE\").units\n[ -f \"$f\" ] || exit 0\nwhile read -r u || [ -n \"$u\" ]; do [ -n \"$u\" ] && systemctl restart \"$u\"; done < \"$f\"\nexit 0\n",
        STATE_DIR
    );
    if std::fs::read_to_string(DEPLOY_HOOK).map(|t| t != script).unwrap_or(true) {
        let _ = std::fs::create_dir_all(Path::new(DEPLOY_HOOK).parent().unwrap());
        if std::fs::write(DEPLOY_HOOK, &script).is_ok() {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(DEPLOY_HOOK, std::fs::Permissions::from_mode(0o755));
        }
    }
}

/// is the certificate of `domain` close to its end?
fn expiring(domain: &str) -> bool {
    let (_, out) = sh(&format!("openssl x509 -checkend {} -noout -in {} 2>&1", RENEW_DAYS * 86400, files(domain).0));
    out.contains("will expire") && !out.contains("not expire")
}

/// Get the certificate of `domain` if it is not there yet; `restart` = services that use it (restarted when
/// it is taken or renewed). Blocking.
pub fn ensure(domain: &str, restart: &[&str]) -> Result<(), String> {
    if !valid_domain(domain) {
        return Err(format!("SSL: {} is not a domain", domain));
    }
    let _ = std::fs::create_dir_all(STATE_DIR);
    // remember every service that uses the certificate (a domain may serve DNS and Xray together)
    let mut u = units(domain);
    let n = u.len();
    for s in restart {
        if safe(s) && !u.iter().any(|x| x == s) {
            u.push(s.to_string());
        }
    }
    if u.len() != n || !Path::new(&units_file(domain)).exists() {
        let _ = std::fs::write(units_file(domain), u.join("\n") + "\n");
    }
    if have(domain) {
        return Ok(());
    }
    obtain(domain)
}

/// Run certbot for `domain` (a new certificate, or a renewal when it is due). Blocking.
fn obtain(domain: &str) -> Result<(), String> {
    let fail_file = format!("{}/{}.fail", STATE_DIR, domain);
    // after a failure: 10 minutes, then 20, 40 … up to a day
    if let Ok(t) = std::fs::read_to_string(&fail_file) {
        let n: u32 = t.lines().next().and_then(|l| l.trim().parse().ok()).unwrap_or(1);
        let wait = (600u64 << (n.saturating_sub(1)).min(8)).min(86400);
        let age = std::fs::metadata(&fail_file).ok().and_then(|m| m.modified().ok()).and_then(|t| t.elapsed().ok()).map(|e| e.as_secs()).unwrap_or(u64::MAX);
        if age < wait {
            return Err(t.lines().skip(1).collect::<Vec<_>>().join(" "));
        }
    }
    let fail = |why: String| {
        let n: u32 = std::fs::read_to_string(&fail_file).ok().and_then(|t| t.lines().next().and_then(|l| l.trim().parse().ok())).unwrap_or(0) + 1;
        let _ = std::fs::write(&fail_file, format!("{}\n{}", n, why));
        Err(why)
    };
    if !sh("command -v certbot").0 {
        eprintln!("certbot: installing ...");
        let _ = sh("export DEBIAN_FRONTEND=noninteractive; apt-get install -y -qq certbot >/dev/null 2>&1 || (apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq certbot >/dev/null 2>&1)");
        if !sh("command -v certbot").0 {
            return fail("SSL: certbot could not be installed (apt install certbot)".into());
        }
    }
    write_deploy_hook();
    if sh("ufw status 2>/dev/null | grep -q 'Status: active'").0 {
        let _ = sh("ufw allow 80/tcp >/dev/null 2>&1");
    }
    let p = port80();
    if !p.other.is_empty() {
        return fail(format!(
            "SSL for {}: port 80 is used by {}, which is not a service that can be stopped and started again. Stop it, or run it as a systemd service.",
            domain,
            p.other.join(", ")
        ));
    }
    let (how, give_back) = port80_plan(&p, has_v6(domain));
    if how.contains("--webroot") {
        let _ = std::fs::create_dir_all(format!("{}/.well-known/acme-challenge", WEBROOT));
    } else if !give_back.is_empty() {
        let names: Vec<String> = p.units.iter().chain(p.containers.iter()).cloned().chain(p.kdns.then(|| "kanki-dns".to_string())).collect();
        eprintln!("certbot: port 80 is used by {}: set aside for certbot and given back right after", names.join(", "));
    }
    eprintln!("certbot: certificate for {} ...", domain);
    // one certbot at a time (the panel and the agent may run on the same server)
    let lock = if sh("command -v flock").0 { format!("flock -w 300 {}/.lock ", STATE_DIR) } else { String::new() };
    let (ok, out) = sh(&format!(
        "{}timeout 240 certbot certonly{} -d {} --cert-name {} --keep-until-expiring --non-interactive --agree-tos --register-unsafely-without-email --key-type ecdsa 2>&1",
        lock, how, domain, domain
    ));
    // certbot's post-hook does not run when it hangs and is killed: give port 80 back in any case
    if !give_back.is_empty() {
        let _ = sh(&give_back.join("; "));
    }
    if ok && have(domain) && !expiring(domain) {
        let _ = std::fs::remove_file(&fail_file);
        for u in units(domain) {
            let _ = sh(&format!("systemctl restart {} 2>&1", u));
        }
        eprintln!("certbot: {} done", domain);
        return Ok(());
    }
    let why = out
        .lines()
        .rev()
        .find(|l| l.contains("Detail") || l.contains("Problem") || l.contains("Error") || l.contains("Could not") || l.contains("Another instance"))
        .unwrap_or("certbot failed")
        .trim()
        .to_string();
    fail(format!("SSL for {} failed: {}. {} must point to this server and port 80 must be reachable from outside.", domain, why, domain))
}

/// Renew the certificates that are close to their end with what holds port 80 now (in case certbot's own
/// renewal failed because the server changed since). Blocking.
pub fn renew_due() {
    let Ok(rd) = std::fs::read_dir(STATE_DIR) else { return };
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        let Some(d) = name.strip_suffix(".units") else { continue };
        if valid_domain(d) && have(d) && expiring(d) {
            if let Err(e) = obtain(d) {
                eprintln!("certbot: renewing {}: {}", d, e);
            }
        }
    }
}

/// every 12 hours (a thread: certbot blocks)
pub fn renew_loop() {
    std::thread::spawn(|| loop {
        std::thread::sleep(std::time::Duration::from_secs(1800));
        renew_due();
        std::thread::sleep(std::time::Duration::from_secs(12 * 3600 - 1800));
    });
}

// ------------------------------------------------------------------ ports other programs hold

/// A program that holds a port a Kanki service of this server needs (Kanki DNS: 53 / 853 / 443 / 80,
/// Xray: its inbound ports), so that service cannot listen there. Shown in the panel (Health).
#[derive(Debug, Clone, PartialEq)]
pub struct Taken {
    pub port: u16,
    pub udp: bool,
    pub prog: String,
    /// its systemd service ("" = not a service)
    pub unit: String,
    /// may be stopped for us: a plain service that listens from outside on nothing but ports we need
    pub free: bool,
    /// why it may not be stopped from the panel
    pub why: String,
    /// the sites it serves (Caddy / nginx), so the admin sees what would go down
    pub serves: Vec<String>,
}

/// services never stopped from the panel, whatever port they hold
const KEEP: &[&str] = &["ssh.service", "sshd.service", "docker.service", "containerd.service", "systemd-resolved.service"];

/// A listening socket: (inode, port, udp, loopback only)
type Sock = (String, u16, bool, bool);

/// The listening sockets of /proc/net/tcp, tcp6, udp or udp6 text.
fn parse_sockets(text: &str, udp: bool) -> Vec<Sock> {
    text.lines()
        .skip(1)
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            if f.len() <= 9 || f[3] != if udp { "07" } else { "0A" } || f[9] == "0" {
                return None;
            }
            let (addr, port) = f[1].rsplit_once(':')?;
            let port = u16::from_str_radix(port, 16).ok()?;
            // 127.x.x.x is stored with its first byte last; ::1 and ::ffff:127.x as below
            let lo = match addr.len() {
                8 => addr.ends_with("7F"),
                32 => addr == "00000000000000000000000001000000" || (addr.starts_with("0000000000000000FFFF0000") && addr.ends_with("7F")),
                _ => false,
            };
            Some((f[9].to_string(), port, udp, lo))
        })
        .collect()
}

fn sockets() -> Vec<Sock> {
    [("/proc/net/tcp", false), ("/proc/net/tcp6", false), ("/proc/net/udp", true), ("/proc/net/udp6", true)]
        .iter()
        .flat_map(|(f, udp)| parse_sockets(&std::fs::read_to_string(f).unwrap_or_default(), *udp))
        .collect()
}

/// pid of each of these socket inodes (read from /proc/<pid>/fd)
fn owners(inodes: &std::collections::HashSet<String>) -> std::collections::HashMap<String, u32> {
    let mut m = std::collections::HashMap::new();
    if inodes.is_empty() {
        return m;
    }
    for e in std::fs::read_dir("/proc").into_iter().flatten().flatten() {
        let Ok(pid) = e.file_name().to_string_lossy().parse::<u32>() else { continue };
        let Ok(fds) = std::fs::read_dir(format!("/proc/{}/fd", pid)) else { continue };
        for fd in fds.flatten() {
            let Ok(l) = std::fs::read_link(fd.path()) else { continue };
            let l = l.to_string_lossy();
            if let Some(i) = l.strip_prefix("socket:[").and_then(|x| x.strip_suffix(']')) {
                if inodes.contains(i) {
                    m.insert(i.to_string(), pid);
                }
            }
        }
    }
    m
}

/// Who holds the ports in `need` ((port, udp)), other than the service `own` itself. A listener on
/// 127.0.0.1 only (like systemd-resolved on 53) is left out: it does not stop us from listening.
pub fn taken(need: &[(u16, bool)], own: &str) -> Vec<Taken> {
    let socks: Vec<Sock> = sockets().into_iter().filter(|s| !s.3).collect();
    if !socks.iter().any(|s| need.contains(&(s.1, s.2))) {
        return vec![];
    }
    let inodes = socks.iter().map(|s| s.0.clone()).collect();
    let pid_of = owners(&inodes);
    // (unit, program) of each pid, and every outside port of each unit
    let mut who: std::collections::HashMap<u32, (String, String)> = std::collections::HashMap::new();
    let mut unit_ports: std::collections::HashMap<String, Vec<(u16, bool)>> = std::collections::HashMap::new();
    for (inode, port, udp, _) in &socks {
        let Some(pid) = pid_of.get(inode) else { continue };
        let (unit, _) = who
            .entry(*pid)
            .or_insert_with(|| {
                (
                    unit_of(&std::fs::read_to_string(format!("/proc/{}/cgroup", pid)).unwrap_or_default()),
                    std::fs::read_to_string(format!("/proc/{}/comm", pid)).unwrap_or_default().trim().to_string(),
                )
            })
            .clone();
        unit_ports.entry(unit).or_default().push((*port, *udp));
    }
    let mut out: Vec<Taken> = vec![];
    for (inode, port, udp, _) in &socks {
        if !need.contains(&(*port, *udp)) {
            continue;
        }
        let Some(pid) = pid_of.get(inode) else { continue };
        let (unit, prog) = who.get(pid).cloned().unwrap_or_default();
        if !own.is_empty() && unit == own {
            continue;
        }
        let (free, why) = judge(&unit, unit_ports.get(&unit).map(|v| v.as_slice()).unwrap_or(&[]), need);
        let serves = sites_of(&unit);
        let t = Taken { port: *port, udp: *udp, prog: if prog.is_empty() { "?".into() } else { prog }, unit, free, why, serves };
        if !out.contains(&t) {
            out.push(t);
        }
    }
    out.sort_by_key(|a| (a.port, a.udp));
    out
}

/// The sites a web server serves, from its config (Caddy: the site addresses of the Caddyfile,
/// nginx: server_name of the enabled sites)
fn sites_of(unit: &str) -> Vec<String> {
    match unit {
        "caddy.service" => caddy_sites(&std::fs::read_to_string("/etc/caddy/Caddyfile").unwrap_or_default()),
        "nginx.service" => {
            let mut v: Vec<String> = std::fs::read_dir("/etc/nginx/sites-enabled")
                .into_iter()
                .flatten()
                .flatten()
                .flat_map(|e| nginx_names(&std::fs::read_to_string(e.path()).unwrap_or_default()))
                .collect();
            v.sort();
            v.dedup();
            v
        }
        _ => vec![],
    }
}

/// "dl.example.com {" at the top level of a Caddyfile (not the global options block or a snippet)
fn caddy_sites(text: &str) -> Vec<String> {
    let mut depth = 0i32;
    let mut v = vec![];
    for l in text.lines() {
        let t = l.trim();
        if t.starts_with('#') {
            continue;
        }
        if depth == 0 && t.ends_with('{') {
            let head = t.trim_end_matches('{').trim();
            if !head.is_empty() && !head.starts_with('(') {
                v.extend(head.split(|c: char| c == ',' || c.is_whitespace()).filter(|s| !s.is_empty()).map(|s| s.to_string()));
            }
        }
        depth += t.matches('{').count() as i32 - t.matches('}').count() as i32;
    }
    v
}

fn nginx_names(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|l| l.trim().strip_prefix("server_name"))
        .flat_map(|r| r.trim_end_matches(';').split_whitespace().map(|s| s.trim_end_matches(';').to_string()).collect::<Vec<_>>())
        .filter(|s| !s.is_empty() && s != "_")
        .collect()
}

/// May this service be stopped to free our ports? (no = why not)
fn judge(unit: &str, ports: &[(u16, bool)], need: &[(u16, bool)]) -> (bool, String) {
    if unit.starts_with("kanki") {
        return (false, "another Kanki service".into());
    }
    if unit.starts_with("docker-") || unit == "docker.service" || unit == "containerd.service" {
        return (false, "a Docker container: stop it by hand".into());
    }
    if !unit.ends_with(".service") || !safe(unit) {
        return (false, "not a service: stop it by hand".into());
    }
    if KEEP.contains(&unit) {
        return (false, "a system service".into());
    }
    // UDP on a port we need on TCP is the same site (HTTP/3 on 443), not something else it serves
    let mut other: Vec<String> = ports.iter().filter(|p| !need.contains(p) && !(p.1 && need.contains(&(p.0, false)))).map(|(p, u)| format!("{}/{}", p, if *u { "udp" } else { "tcp" })).collect();
    other.sort();
    other.dedup();
    if !other.is_empty() {
        return (false, format!("it also serves {}: change it by hand", other.join(", ")));
    }
    (true, String::new())
}

/// The panel asked to free our ports from these services: each one that still holds only ports in
/// `need` is stopped and disabled (so it does not take them again after a reboot). Returns the ones
/// stopped. Blocking.
pub fn free_ports(units: &[String], need: &[(u16, bool)]) -> Vec<String> {
    let ok: Vec<String> = taken(need, "").into_iter().filter(|t| t.free && units.contains(&t.unit)).map(|t| t.unit).collect();
    let mut done = vec![];
    for u in ok {
        if done.contains(&u) {
            continue;
        }
        if sh(&format!("systemctl disable --now {}", u)).0 {
            eprintln!("ports: stopped {} (it held ports Kanki needs here)", u);
            done.push(u);
        }
    }
    done
}

/// `taken`, worked out at most every 30 seconds per service (the agent reports every few seconds).
pub fn taken_cached(need: &[(u16, bool)], own: &str) -> Vec<Taken> {
    use std::sync::{Mutex, OnceLock};
    /// service -> (when, the ports asked, the answer)
    type Cache = std::collections::HashMap<String, (std::time::Instant, Vec<(u16, bool)>, Vec<Taken>)>;
    static C: OnceLock<Mutex<Cache>> = OnceLock::new();
    let c = C.get_or_init(|| Mutex::new(std::collections::HashMap::new()));
    if let Some((at, n, v)) = c.lock().unwrap().get(own) {
        if at.elapsed().as_secs() < 30 && n.as_slice() == need {
            return v.clone();
        }
    }
    let v = taken(need, own);
    c.lock().unwrap().insert(own.to_string(), (std::time::Instant::now(), need.to_vec(), v.clone()));
    v
}

/// The JSON the agent reports for a list of taken ports.
pub fn taken_json(v: &[Taken]) -> serde_json::Value {
    serde_json::Value::Array(
        v.iter()
            .map(|t| serde_json::json!({ "port": t.port, "proto": if t.udp { "udp" } else { "tcp" }, "prog": t.prog, "unit": t.unit, "free": t.free, "why": t.why, "serves": t.serves }))
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listening_sockets_and_loopback() {
        let tcp = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 3500007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000   991        0 111 1\n   1: 00000000:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 222 1\n   2: 0100A8C0:01BB 0200A8C0:D431 01 00000000:00000000 00:00000000 00000000     0        0 333 1\n";
        assert_eq!(parse_sockets(tcp, false), vec![("111".to_string(), 53, false, true), ("222".to_string(), 443, false, false)]);
        let tcp6 = "  sl  local_address remote_address st\n   0: 00000000000000000000000000000000:0050 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 444 1\n   1: 00000000000000000000000001000000:07E3 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 555 1\n";
        assert_eq!(parse_sockets(tcp6, false), vec![("444".to_string(), 80, false, false), ("555".to_string(), 2019, false, true)]);
        let udp = "  sl  local_address rem_address   st\n   0: 00000000:01BB 00000000:0000 07 00000000:00000000 00:00000000 00000000 0 0 666 2\n";
        assert_eq!(parse_sockets(udp, true), vec![("666".to_string(), 443, true, false)]);
    }

    #[test]
    fn finds_who_holds_a_port() {
        // this test process listens on a port: found by /proc with its program name (whether it may be
        // stopped depends on where the tests run: a CI runner is itself a systemd service)
        let l = std::net::TcpListener::bind("0.0.0.0:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let v = taken(&[(port, false)], "");
        assert_eq!(v.len(), 1, "{:?}", v);
        assert_eq!((v[0].port, v[0].udp), (port, false));
        let me = std::fs::read_to_string("/proc/self/comm").unwrap().trim().to_string();
        assert_eq!(v[0].prog, me);
        // nothing on a port that no one holds; 127.0.0.1 only does not count
        let lo = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        assert!(taken(&[(lo.local_addr().unwrap().port(), false)], "").is_empty());
    }

    #[test]
    fn sites_a_web_server_serves() {
        let caddy = "{\n  auto_https off\n}\n(common) {\n  header -Server\n}\n# old\ndl.kankipro.cafe {\n    root * /var/www/dl\n    file_server\n}\nhttps://a.example.com:2053, b.example.com {\n  handle {\n    respond 404\n  }\n}\n";
        assert_eq!(caddy_sites(caddy), vec!["dl.kankipro.cafe", "https://a.example.com:2053", "b.example.com"]);
        assert_eq!(nginx_names("server {\n  listen 80;\n  server_name  x.com www.x.com;\n}\nserver { server_name _; }"), vec!["x.com", "www.x.com"]);
    }

    #[test]
    fn what_may_be_stopped_for_our_ports() {
        let need = [(53, true), (53, false), (853, false), (443, false), (80, false)];
        // Caddy on 80 + 443 (also HTTP/3 on udp 443, its admin on 127.0.0.1 is not counted)
        let caddy = [(80, false), (443, false), (443, true)];
        assert_eq!(judge("caddy.service", &caddy, &need), (true, String::new()));
        // the node API on 2096 behind the same Caddy: not touched
        let (free, why) = judge("caddy.service", &[(443, false), (2096, false)], &need);
        assert!(!free && why.contains("2096/tcp"), "{}", why);
        assert!(!judge("kanki-xray.service", &[(443, false)], &need).0);
        assert!(!judge("sshd.service", &[(443, false)], &need).0);
        assert!(!judge("docker.service", &[(80, false)], &need).0);
        assert!(!judge("session-3.scope", &[(80, false)], &need).0);
        assert!(!judge("", &[(80, false)], &need).0);
    }

    #[test]
    fn challenge_paths_stay_in_the_webroot() {
        assert!(challenge("/.well-known/acme-challenge/../../etc/passwd").is_none());
        assert!(challenge("/.well-known/acme-challenge/").is_none());
        assert!(challenge("/other").is_none());
        assert!(valid_domain("de.example.com") && !valid_domain("1.2.3.4") && !valid_domain("x"));
    }

    #[test]
    fn port80_holders() {
        let tcp = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 31337 1 0000000000000000 100 0 0 10 0
   1: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 4242 1 0000000000000000 100 0 0 10 0
   2: 0A00000F:0050 0A000001:C350 01 00000000:00000000 00:00000000 00000000     0        0 5151 1 0000000000000000 20 4 30 10 -1";
        assert_eq!(listen_inodes(tcp, 80), vec!["31337"]);
        assert_eq!(listen_inodes(tcp, 8080), vec!["4242"]);
        assert_eq!(unit_of("0::/system.slice/caddy.service\n"), "caddy.service");
        assert_eq!(unit_of("0::/system.slice/docker-0123456789abcdef.scope\n"), "docker-0123456789abcdef.scope");
        assert_eq!(unit_of("12:pids:/user.slice/user-0.slice/session-3.scope\n"), "session-3.scope");
    }

    #[test]
    fn port80_plans() {
        // only Kanki DNS: webroot, nothing stops
        let p = Port80 { kdns: true, ..Default::default() };
        assert_eq!(port80_plan(&p, false), (format!(" --webroot -w {}", WEBROOT), vec![]));
        // Kanki DNS but the name has IPv6: stopped for those seconds
        let (how, back) = port80_plan(&p, true);
        assert!(how.starts_with(" --standalone --pre-hook \"systemctl stop kanki-dns.service || true\""));
        assert_eq!(back, vec!["systemctl start kanki-dns.service || true"]);
        // Caddy and a container: stopped and started again
        let p = Port80 { units: vec!["caddy.service".into()], containers: vec!["0123456789ab".into()], ..Default::default() };
        let (how, back) = port80_plan(&p, false);
        assert!(how.contains("--pre-hook \"systemctl stop caddy.service || true; docker stop 0123456789ab || true\""));
        assert!(how.contains("--post-hook \"systemctl start caddy.service || true; docker start 0123456789ab || true\""));
        assert_eq!(back.len(), 2);
        // nothing on port 80
        assert_eq!(port80_plan(&Port80::default(), false), (" --standalone".to_string(), vec![]));
        assert!(!safe("a$(x).service") && safe("caddy.service") && safe("getty@tty1.service"));
    }
}
