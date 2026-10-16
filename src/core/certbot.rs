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

#[cfg(test)]
mod tests {
    use super::*;

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
