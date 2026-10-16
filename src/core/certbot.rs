//! SSL with certbot, the simplest way: `certbot certonly --standalone -d <domain>` with no e-mail, run by
//! the agent on the server the domain points to. Port 80 of that server must be reachable; a Kanki
//! service that holds port 80 there (Kanki DNS, an Xray inbound on 80) is stopped for those few seconds
//! and started again, now and on every renewal (certbot renews by itself and restarts the service).
use std::path::Path;

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

const FAIL_DIR: &str = "/var/lib/kanki/certbot";

/// Get the certificate of `domain` if it is not there yet. `port80` = the systemd unit holding port 80 on
/// this server (stopped while certbot answers Let's Encrypt), `restart` = units that use the certificate.
/// After a failure the same error is returned for 10 minutes (Let's Encrypt limits failed tries). Blocking.
pub fn ensure(domain: &str, port80: Option<&str>, restart: &[&str]) -> Result<(), String> {
    if have(domain) {
        return Ok(());
    }
    if !valid_domain(domain) {
        return Err(format!("SSL: {} is not a domain", domain));
    }
    let _ = std::fs::create_dir_all(FAIL_DIR);
    let fail_file = format!("{}/{}.fail", FAIL_DIR, domain);
    if let Ok(m) = std::fs::metadata(&fail_file) {
        if m.modified().ok().and_then(|t| t.elapsed().ok()).map(|e| e.as_secs() < 600).unwrap_or(false) {
            return Err(std::fs::read_to_string(&fail_file).unwrap_or_default().trim().to_string());
        }
    }
    if !sh("command -v certbot").0 {
        eprintln!("certbot: installing ...");
        let _ = sh("export DEBIAN_FRONTEND=noninteractive; apt-get install -y -qq certbot >/dev/null 2>&1 || (apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq certbot >/dev/null 2>&1)");
        if !sh("command -v certbot").0 {
            return Err("SSL: certbot could not be installed (apt install certbot)".into());
        }
    }
    if sh("ufw status 2>/dev/null | grep -q 'Status: active'").0 {
        let _ = sh("ufw allow 80/tcp >/dev/null 2>&1");
    }
    let mut hooks = String::new();
    if let Some(u) = port80 {
        hooks.push_str(&format!(" --pre-hook 'systemctl stop {u} || true' --post-hook 'systemctl start {u} || true'", u = u));
    }
    if !restart.is_empty() {
        let cmd = restart.iter().map(|u| format!("systemctl restart {} || true", u)).collect::<Vec<_>>().join("; ");
        hooks.push_str(&format!(" --deploy-hook '{}'", cmd));
    }
    eprintln!("certbot: getting a certificate for {} ...", domain);
    let (ok, out) = sh(&format!(
        "timeout 240 certbot certonly --standalone -d {} --non-interactive --agree-tos --register-unsafely-without-email --key-type ecdsa{} 2>&1",
        domain, hooks
    ));
    if ok && have(domain) {
        let _ = std::fs::remove_file(&fail_file);
        eprintln!("certbot: {} done", domain);
        Ok(())
    } else {
        let why = out
            .lines()
            .rev()
            .find(|l| l.contains("Detail") || l.contains("Problem") || l.contains("Error") || l.contains("Could not"))
            .unwrap_or("certbot failed")
            .trim()
            .to_string();
        let msg = format!("SSL for {} failed: {}. Port 80 of this server must be reachable and {} must point to this server (tried again in 10 minutes).", domain, why, domain);
        let _ = std::fs::write(&fail_file, &msg);
        Err(msg)
    }
}
