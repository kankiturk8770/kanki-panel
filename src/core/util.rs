//! Shared helpers: time, random, hashing, TOTP, CIDR, encoding, QR
use axum::http::HeaderMap;
use hmac::{Hmac, Mac};
use rand::Rng;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

pub fn rand_token(len: usize) -> String {
    const C: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut r = rand::thread_rng();
    (0..len).map(|_| C[r.gen_range(0..C.len())] as char).collect()
}

pub fn rand_digits(len: usize) -> String {
    let mut r = rand::thread_rng();
    let mut s = String::new();
    s.push(char::from(b'1' + r.gen_range(0..9u8)));
    for _ in 1..len {
        s.push(char::from(b'0' + r.gen_range(0..10u8)));
    }
    s
}

pub fn sha256_hex(s: &str) -> String {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    hex::encode(h.finalize())
}

/// Constant-time string compare
pub fn ct_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut d = 0u8;
    for i in 0..a.len() {
        d |= a[i] ^ b[i];
    }
    d == 0
}

fn pbkdf2_sha256(pass: &[u8], salt: &[u8], iters: u32) -> [u8; 32] {
    type H = Hmac<Sha256>;
    let mac = <H as Mac>::new_from_slice(pass).expect("hmac key");
    let mut m = mac.clone();
    m.update(salt);
    m.update(&1u32.to_be_bytes());
    let mut u = [0u8; 32];
    u.copy_from_slice(&m.finalize().into_bytes());
    let mut t = u;
    for _ in 1..iters {
        let mut m = mac.clone();
        m.update(&u);
        u.copy_from_slice(&m.finalize().into_bytes());
        for i in 0..32 {
            t[i] ^= u[i];
        }
    }
    t
}

const PBKDF2_ITERS: u32 = 120_000;

/// "pbkdf2$iters$salt$hash" (legacy "salt$sha256" still accepted on check)
pub fn hash_password(pass: &str) -> String {
    let salt = rand_token(16);
    let h = pbkdf2_sha256(pass.as_bytes(), salt.as_bytes(), PBKDF2_ITERS);
    format!("pbkdf2${}${}${}", PBKDF2_ITERS, salt, hex::encode(h))
}

pub fn check_password(stored: &str, pass: &str) -> bool {
    if let Some(rest) = stored.strip_prefix("pbkdf2$") {
        let parts: Vec<&str> = rest.splitn(3, '$').collect();
        if parts.len() != 3 {
            return false;
        }
        let iters: u32 = parts[0].parse().unwrap_or(0);
        if iters == 0 {
            return false;
        }
        let h = pbkdf2_sha256(pass.as_bytes(), parts[1].as_bytes(), iters);
        return ct_eq(&hex::encode(h), parts[2]);
    }
    match stored.split_once('$') {
        Some((salt, h)) => ct_eq(&sha256_hex(&format!("{}{}", salt, pass)), h),
        None => false,
    }
}

pub fn is_legacy_hash(stored: &str) -> bool {
    !stored.starts_with("pbkdf2$")
}

// ---------------------------------------------------------------- TOTP (RFC 6238)
const B32: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

pub fn base32_encode(data: &[u8]) -> String {
    let mut out = String::new();
    let mut buf: u32 = 0;
    let mut bits = 0;
    for &b in data {
        buf = (buf << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            out.push(B32[((buf >> (bits - 5)) & 31) as usize] as char);
            bits -= 5;
        }
    }
    if bits > 0 {
        out.push(B32[((buf << (5 - bits)) & 31) as usize] as char);
    }
    out
}

pub fn base32_decode(s: &str) -> Vec<u8> {
    let mut out = vec![];
    let mut buf: u32 = 0;
    let mut bits = 0;
    for c in s.chars().filter(|c| !c.is_whitespace() && *c != '=') {
        let Some(v) = B32.iter().position(|x| *x as char == c.to_ascii_uppercase()) else { continue };
        buf = (buf << 5) | v as u32;
        bits += 5;
        if bits >= 8 {
            out.push(((buf >> (bits - 8)) & 0xff) as u8);
            bits -= 8;
        }
    }
    out
}

pub fn totp_secret() -> String {
    let mut r = rand::thread_rng();
    let bytes: Vec<u8> = (0..20).map(|_| r.gen::<u8>()).collect();
    base32_encode(&bytes)
}

fn hotp(key: &[u8], counter: u64) -> u32 {
    type H = Hmac<sha1::Sha1>;
    let Ok(mut m) = <H as Mac>::new_from_slice(key) else { return 0 };
    m.update(&counter.to_be_bytes());
    let r = m.finalize().into_bytes();
    let off = (r[19] & 0x0f) as usize;
    let bin = ((r[off] as u32 & 0x7f) << 24) | ((r[off + 1] as u32) << 16) | ((r[off + 2] as u32) << 8) | r[off + 3] as u32;
    bin % 1_000_000
}

/// Accepts the current 30s step and one step either side
pub fn totp_check(secret_b32: &str, code: &str) -> bool {
    totp_step(secret_b32, code, now()).is_some()
}

/// The 30s step `code` belongs to (the step of `at`, or one either side), None when it is wrong.
/// A caller that remembers the last step it accepted can refuse the same code a second time.
pub fn totp_step(secret_b32: &str, code: &str, at: i64) -> Option<u64> {
    let code = code.trim();
    if code.len() != 6 || !code.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let key = base32_decode(secret_b32);
    if key.is_empty() {
        return None;
    }
    let step = (at.max(0) / 30) as u64;
    [step.saturating_sub(1), step, step + 1].into_iter().find(|s| ct_eq(&format!("{:06}", hotp(&key, *s)), code))
}

// ---------------------------------------------------------------- network helpers
/// Real client IP. The panel only listens on 127.0.0.1 behind Caddy, which sets X-Forwarded-For.
pub fn client_ip(h: &HeaderMap) -> String {
    h.get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next_back())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "127.0.0.1".into())
}

pub fn user_agent(h: &HeaderMap) -> String {
    h.get("user-agent").and_then(|v| v.to_str().ok()).unwrap_or("").chars().take(200).collect()
}

pub fn in_cidr(ip: &str, cidr: &str) -> bool {
    let Ok(ip) = ip.parse::<IpAddr>() else { return false };
    let c = cidr.trim();
    if c.is_empty() {
        return false;
    }
    let (a, bits) = match c.split_once('/') {
        Some((a, b)) => (a.trim(), b.trim().parse::<u32>().ok()),
        None => (c, None),
    };
    let Ok(net) = a.parse::<IpAddr>() else { return false };
    match (ip, net) {
        (IpAddr::V4(x), IpAddr::V4(n)) => {
            let b = bits.unwrap_or(32).min(32);
            if b == 0 {
                return true;
            }
            let m = u32::MAX << (32 - b);
            (u32::from(x) & m) == (u32::from(n) & m)
        }
        (IpAddr::V6(x), IpAddr::V6(n)) => {
            let b = bits.unwrap_or(128).min(128);
            if b == 0 {
                return true;
            }
            let m = u128::MAX << (128 - b);
            (u128::from(x) & m) == (u128::from(n) & m)
        }
        _ => false,
    }
}

pub fn in_any(ip: &str, list: &str) -> bool {
    list.lines().flat_map(|l| l.split(',')).any(|c| in_cidr(ip, c))
}

// ---------------------------------------------------------------- formatting
pub fn iso(ts: i64) -> String {
    if ts <= 0 {
        return String::new();
    }
    chrono::DateTime::from_timestamp(ts, 0)
        .map(|d| d.format("%Y-%m-%dT%H:%M:%SZ").to_string())
        .unwrap_or_default()
}

pub fn stamp(ts: i64) -> String {
    chrono::DateTime::from_timestamp(ts, 0).map(|d| d.format("%Y%m%d-%H%M%S").to_string()).unwrap_or_default()
}

pub fn gb(bytes: i64) -> f64 {
    bytes as f64 / 1_073_741_824.0
}

/// KEY=VALUE env file
/// An address on the public internet: not loopback, private (RFC 1918, CGNAT, ULA), link-local (cloud
/// metadata 169.254.169.254), unspecified, multicast, broadcast or reserved. The SSRF guard of every request the
/// panel makes to an address an admin or a client typed (3.68).
pub fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            let o = v.octets();
            !(v.is_private() || v.is_loopback() || v.is_link_local() || v.is_unspecified() || v.is_broadcast() || v.is_multicast()
                || o[0] == 0 || o[0] >= 240 || (o[0] == 100 && (o[1] & 0xC0) == 64) || (o[0] == 192 && o[1] == 0 && o[2] == 0)
                || (o[0] == 198 && (o[1] & 0xFE) == 18))
        }
        IpAddr::V6(v) => {
            if let Some(m) = v.to_ipv4_mapped() {
                return public_ip(IpAddr::V4(m));
            }
            let s = v.segments();
            !(v.is_loopback() || v.is_unspecified() || v.is_multicast() || (s[0] & 0xfe00) == 0xfc00 || (s[0] & 0xffc0) == 0xfe80)
        }
    }
}

/// `host` (a name or an address) resolves only to public addresses; Err names the reason. With `allow_private`
/// only loopback, link-local, unspecified and multicast are refused (servers of one private network).
pub async fn public_host(host: &str, port: u16, allow_private: bool) -> Result<Vec<std::net::SocketAddr>, String> {
    let h = host.trim().trim_start_matches('[').trim_end_matches(']');
    if h.is_empty() || h.eq_ignore_ascii_case("localhost") || h.to_ascii_lowercase().ends_with(".localhost") {
        return Err("that address is this server itself".into());
    }
    let addrs: Vec<std::net::SocketAddr> = tokio::time::timeout(std::time::Duration::from_secs(5), tokio::net::lookup_host((h, port)))
        .await
        .map_err(|_| "the name did not resolve in time".to_string())?
        .map_err(|_| "the name does not resolve".to_string())?
        .collect();
    if addrs.is_empty() {
        return Err("the name does not resolve".into());
    }
    let local = |ip: IpAddr| {
        let ip = match ip {
            IpAddr::V6(v) => v.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v)),
            x => x,
        };
        ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() || match ip {
            IpAddr::V4(v) => v.is_link_local() || v.is_broadcast() || v.octets()[0] == 0,
            IpAddr::V6(v) => (v.segments()[0] & 0xffc0) == 0xfe80,
        }
    };
    for a in &addrs {
        if local(a.ip()) || (!allow_private && !public_ip(a.ip())) {
            return Err(format!("{} is a local or private address", a.ip()));
        }
    }
    Ok(addrs)
}

/// The host and port of an http(s) URL, checked with `public_host`
pub async fn public_url(url: &str, allow_private: bool) -> Result<(), String> {
    let u = reqwest::Url::parse(url.trim()).map_err(|_| "not a valid URL".to_string())?;
    if u.scheme() != "https" && u.scheme() != "http" {
        return Err("only http(s) addresses".into());
    }
    if !u.username().is_empty() || u.password().is_some() {
        return Err("an address with a user name is not allowed".into());
    }
    let host = u.host_str().ok_or_else(|| "the address has no host".to_string())?;
    let port = u.port_or_known_default().unwrap_or(443);
    public_host(host, port, allow_private).await.map(|_| ())
}

/// A log line with its secrets masked (3.68, `GET /api/logs`): Telegram bot tokens, subscription codes
/// (`kanki-<id>-<code>` keeps `kanki-<id>-`), WireGuard keys and other base64 keys, long hex secrets, the values of
/// `sub=`/`token=`/`key=`/`secret=`/`pass=`/`password=`, a `Bearer` token, and every string of `known` (the
/// panel's own secrets, at least 8 characters).
pub fn redact(line: &str, known: &[String]) -> String {
    let mut out = line.to_string();
    for k in known.iter().filter(|k| k.len() >= 8) {
        if out.contains(k.as_str()) {
            out = out.replace(k.as_str(), "[secret]");
        }
    }
    let word = |c: char| c.is_ascii_alphanumeric() || "_+/=:-.".contains(c);
    let mut res = String::with_capacity(out.len());
    let mut bearer = false;
    let mut i = 0;
    let b: Vec<char> = out.chars().collect();
    while i < b.len() {
        if !word(b[i]) {
            res.push(b[i]);
            i += 1;
            continue;
        }
        let start = i;
        while i < b.len() && word(b[i]) {
            i += 1;
        }
        let w: String = b[start..i].iter().collect();
        let masked = if bearer { "[secret]".to_string() } else { redact_word(&w) };
        bearer = w.eq_ignore_ascii_case("bearer");
        res.push_str(&masked);
    }
    res
}

fn redact_word(w: &str) -> String {
    // key=value: the value of a secret-looking key, otherwise each side on its own
    if let Some((k, v)) = w.split_once('=').filter(|(k, v)| !k.is_empty() && !v.is_empty()) {
        let kl = k.to_ascii_lowercase();
        if ["sub", "token", "key", "secret", "pass", "password", "psk", "privatekey", "auth", "code"].iter().any(|x| kl.ends_with(x)) {
            return format!("{}=[secret]", k);
        }
        return format!("{}={}", redact_word(k), redact_word(v));
    }
    // a Telegram bot token: <digits>:<35 characters>
    if let Some((id, rest)) = w.split_once(':') {
        if (6..=12).contains(&id.len()) && id.bytes().all(|c| c.is_ascii_digit()) && rest.len() >= 30 {
            return format!("{}:[secret]", id);
        }
    }
    // a subscription code: <letters>-<digits>-<code>
    let parts: Vec<&str> = w.splitn(3, '-').collect();
    if parts.len() == 3 && (2..=12).contains(&parts[0].len()) && parts[0].bytes().all(|c| c.is_ascii_alphabetic())
        && !parts[1].is_empty() && parts[1].bytes().all(|c| c.is_ascii_digit()) && parts[2].len() >= 4
        && parts[2].bytes().all(|c| c.is_ascii_alphanumeric())
    {
        return format!("{}-{}-[secret]", parts[0], parts[1]);
    }
    // WireGuard / base64 keys (44 with '='), long base64 or hex secrets
    let b64 = w.len() >= 40 && w.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'+' || c == b'/' || c == b'=' || c == b'-' || c == b'_');
    let hex = w.len() >= 32 && w.bytes().all(|c| c.is_ascii_hexdigit());
    let mixed = w.bytes().any(|c| c.is_ascii_digit()) && w.bytes().any(|c| c.is_ascii_alphabetic());
    if hex || (b64 && mixed) {
        return "[secret]".into();
    }
    w.to_string()
}

/// Writes `text` to `path` readable by its owner only (0600): a temp file in the same directory (made 0600 before
/// a byte is written), fsync, then rename over the old file, so a reader never sees half a file and a crash never
/// leaves an empty one.
pub fn write_private(path: &str, text: &str) -> std::io::Result<()> {
    write_private_bytes(path, text.as_bytes())
}

pub fn write_private_bytes(path: &str, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let p = std::path::Path::new(path);
    // the file keeps its owner (Hysteria's config belongs to the `hysteria` user, which must still read it)
    let owner = std::fs::metadata(p).ok().map(|m| (m.uid(), m.gid()));
    let dir = p.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or(std::path::Path::new("."));
    let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("file");
    let tmp = dir.join(format!(".{}.{}.{}.tmp", name, std::process::id(), rand_token(6)));
    let res = (|| {
        let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp)?;
        if let Some((u, g)) = owner {
            std::os::unix::fs::fchown(&f, Some(u), Some(g))?;
        }
        f.write_all(data)?;
        f.sync_all()?;
        std::fs::rename(&tmp, p)?;
        if let Ok(d) = std::fs::File::open(dir) {
            d.sync_all()?;
        }
        Ok(())
    })();
    if res.is_err() {
        if let Err(e) = std::fs::remove_file(&tmp) {
            if e.kind() != std::io::ErrorKind::NotFound {
                eprintln!("could not remove {}: {}", tmp.display(), e);
            }
        }
    }
    res
}

/// Overwrites a file with zeros (synced) before removing it: a snapshot of the database or a key never stays
/// readable in free blocks of the data folder as long as the filesystem writes in place
pub fn shred_remove(path: &str) -> std::io::Result<()> {
    use std::io::Write;
    let len = match std::fs::metadata(path) {
        Ok(m) => m.len(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    {
        let mut f = std::fs::OpenOptions::new().write(true).open(path)?;
        let zero = vec![0u8; 64 << 10];
        let mut left = len;
        while left > 0 {
            let n = left.min(zero.len() as u64) as usize;
            f.write_all(&zero[..n])?;
            left -= n as u64;
        }
        f.sync_all()?;
    }
    std::fs::remove_file(path)
}

/// The id of a system group (None when there is no such group)
pub fn gid_of(group: &str) -> Option<u32> {
    let c = std::ffi::CString::new(group).ok()?;
    // SAFETY: `c` is a valid NUL-terminated string that lives across the call; getgrnam returns NULL or a pointer
    // to a static struct that is read at once (gr_gid) and not kept
    let g = unsafe { libc::getgrnam(c.as_ptr()) };
    if g.is_null() {
        return None;
    }
    // SAFETY: checked non-null above; only the plain integer field is read
    Some(unsafe { (*g).gr_gid })
}

/// A config a service of its own reads (Hysteria runs as `hysteria`): owned by root, group of the service,
/// 0640 (no one else reads it). Without that group the file is left as it is.
pub fn service_readable(path: &str, group: &str) -> std::io::Result<()> {
    let Some(gid) = gid_of(group) else { return Ok(()) };
    match std::os::unix::fs::chown(path, Some(0), Some(gid)) {
        Ok(()) => chmod_if_present(path, 0o640),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Sets `mode` on `path` when it exists (a missing file is fine: nothing to protect)
pub fn chmod_if_present(path: &str, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    match std::fs::metadata(path) {
        Ok(m) if m.permissions().mode() & 0o7777 == mode => Ok(()),
        Ok(_) => std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// A directory only its owner can enter (0700), made when missing
pub fn private_dir(path: &str) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    match std::fs::DirBuilder::new().recursive(true).mode(0o700).create(path) {
        Ok(()) => chmod_if_present(path, 0o700),
        Err(e) => Err(e),
    }
}

pub fn load_env(path: &str) -> HashMap<String, String> {
    let mut m = HashMap::new();
    // read as bytes: one line that is not valid UTF-8 (a name typed in another encoding) must not
    // make the whole file unreadable (the panel then came up on the default port behind Caddy)
    if let Ok(raw) = std::fs::read(path) {
        let t = String::from_utf8_lossy(&raw);
        for line in t.lines() {
            let l = line.trim();
            if l.starts_with('#') {
                continue;
            }
            if let Some((k, v)) = l.split_once('=') {
                m.insert(k.trim().to_string(), v.trim().trim_matches('"').to_string());
            }
        }
    }
    m
}

/// The file this program runs from. When it was replaced while running (an update, or the other Kanki
/// service of the same machine updated the shared file), Linux names it "<path> (deleted)": the path
/// itself is what is meant.
pub fn exe_path() -> std::io::Result<std::path::PathBuf> {
    let p = std::env::current_exe()?;
    let s = p.to_string_lossy();
    Ok(match s.strip_suffix(" (deleted)") {
        Some(real) => std::path::PathBuf::from(real),
        None => p,
    })
}

/// Puts `bytes` in place of the program file `path` (mode 755). Written to a temporary file of this
/// process first and renamed over it: a crash never leaves half a program, and two updates of the same
/// file at once (the node and the agent of one server) never write into one temporary file. The new
/// program must start on this server (`version`) before it replaces the old one, so a broken download
/// or a build for another machine leaves the server running as it was. Nothing else is touched: the
/// settings (`/etc/kanki/*.env`, the saved tunnels) stay as they are.
pub fn swap_program(path: &std::path::Path, bytes: &[u8]) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| "kanki-panel".into());
    clean_stale_updates(path, &name);
    let tmp = path.with_file_name(format!(".{}.{}.new", name, std::process::id()));
    std::fs::write(&tmp, bytes).map_err(|e| e.to_string())?;
    let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755));
    if let Err(e) = check_program(&tmp, std::time::Duration::from_secs(20)) {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("the new program does not start on this server, kept the old one: {}", e));
    }
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        e.to_string()
    })
}

/// Runs `<path> version` and expects "kanki-panel <version>" within `limit`
pub fn check_program(path: &std::path::Path, limit: std::time::Duration) -> Result<(), String> {
    use std::io::Read;
    let mut child = std::process::Command::new(path)
        .arg("version")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| e.to_string())?;
    let end = std::time::Instant::now() + limit;
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) if std::time::Instant::now() < end => std::thread::sleep(std::time::Duration::from_millis(50)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("it did not answer in time".into());
            }
            Err(e) => return Err(e.to_string()),
        }
    };
    let mut out = String::new();
    if let Some(mut o) = child.stdout.take() {
        let _ = o.read_to_string(&mut out);
    }
    if status.success() && out.trim_start().starts_with("kanki-panel ") {
        Ok(())
    } else {
        Err(format!("it answered {:?}", out.trim().chars().take(80).collect::<String>()))
    }
}

/// Temporary files of updates that were cut off (a crash, a full disk) are removed; one younger than
/// ten minutes may belong to an update running right now (the other service of this machine) and stays
fn clean_stale_updates(path: &std::path::Path, name: &str) {
    let Some(dir) = path.parent() else { return };
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    let prefix = format!(".{}.", name);
    for e in rd.flatten() {
        let f = e.file_name().to_string_lossy().to_string();
        if !f.starts_with(&prefix) || !f.ends_with(".new") {
            continue;
        }
        let old = e.metadata().and_then(|m| m.modified()).ok().and_then(|t| t.elapsed().ok()).map(|a| a.as_secs() > 600).unwrap_or(false);
        if old {
            let _ = std::fs::remove_file(e.path());
        }
    }
}

/// After the program file was replaced: the other Kanki services of this machine that run the same
/// file (the node and the tunnel agent) restart onto the new one, so no old copy keeps running (and
/// keeps its disk space) and both parts of the server run one version. Only running ones restart.
pub fn restart_siblings() {
    let me = match std::env::args().nth(1).as_deref() {
        Some("node") => "kanki-node",
        Some("tunnel-agent") => "kanki-tunnel",
        _ => "kanki-panel",
    };
    let others: Vec<&str> = ["kanki-node", "kanki-tunnel"].into_iter().filter(|u| *u != me).collect();
    let mut args = vec!["--no-block", "try-restart"];
    args.extend(others);
    let _ = std::process::Command::new("systemctl").args(&args).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).spawn();
}

pub fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&#39;")
}

/// RFC 3986 percent-encoding (unreserved chars kept)
pub fn pct(s: &str) -> String {
    let mut o = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
            o.push(b as char);
        } else {
            o.push_str(&format!("%{:02X}", b));
        }
    }
    o
}

/// Undo percent-encoding ('+' stays '+'); bad escapes are kept as they are.
pub fn pct_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut o = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            let h = |c: u8| (c as char).to_digit(16);
            if let (Some(x), Some(y)) = (h(b[i + 1]), h(b[i + 2])) {
                o.push((x * 16 + y) as u8);
                i += 3;
                continue;
            }
        }
        o.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&o).to_string()
}

pub fn b64(data: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut o = String::new();
    for ch in data.chunks(3) {
        let n = (ch[0] as u32) << 16 | (*ch.get(1).unwrap_or(&0) as u32) << 8 | *ch.get(2).unwrap_or(&0) as u32;
        o.push(T[(n >> 18 & 63) as usize] as char);
        o.push(T[(n >> 12 & 63) as usize] as char);
        o.push(if ch.len() > 1 { T[(n >> 6 & 63) as usize] as char } else { '=' });
        o.push(if ch.len() > 2 { T[(n & 63) as usize] as char } else { '=' });
    }
    o
}

/// SVG QR code (None if data too large)
pub fn qr_svg(data: &str) -> Option<String> {
    use qrcode::render::svg;
    let code = qrcode::QrCode::new(data.as_bytes()).ok()?;
    Some(
        code.render::<svg::Color>()
            .min_dimensions(260, 260)
            .dark_color(svg::Color("#111111"))
            .light_color(svg::Color("#ffffff"))
            .build(),
    )
}

/// A user / config name: English letters and digits only, starting with a letter, 3 to 12 characters (like mahtab87).
/// WireGuard and AmneziaWG apps refuse tunnel names with other characters, so names stay this simple.
pub fn valid_cfg_name(s: &str) -> bool {
    let n = s.chars().count();
    (3..=12).contains(&n) && s.chars().all(|c| c.is_ascii_alphanumeric()) && s.starts_with(|c: char| c.is_ascii_alphabetic())
}

/// A config name made from a Telegram name: only its English letters and digits are kept (emoji, stickers,
/// symbols, spaces and other alphabets are dropped), in lower case. None when less than 3 usable characters remain.
pub fn cfg_name_from(s: &str) -> Option<String> {
    let t: String = s.chars().filter(|c| c.is_ascii_alphanumeric()).collect::<String>().to_lowercase();
    let t: String = t.trim_start_matches(|c: char| c.is_ascii_digit()).chars().take(12).collect();
    if valid_cfg_name(&t) { Some(t) } else { None }
}

#[cfg(test)]
mod exe_tests {
    #[test]
    fn a_program_is_swapped_whole() {
        let d = std::env::temp_dir().join(format!("kanki-swap-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let f = d.join("kanki-panel");
        std::fs::write(&f, b"old").unwrap();
        // the new file must answer `version` before it is put in place
        let new = b"#!/bin/sh\necho kanki-panel 9.9.9\n";
        super::swap_program(&f, new).unwrap();
        assert_eq!(std::fs::read(&f).unwrap(), new);
        // nothing else is left next to it
        assert_eq!(std::fs::read_dir(&d).unwrap().count(), 1);
        let _ = std::fs::remove_dir_all(&d);
    }
}

#[cfg(test)]
mod name_tests {
    use super::*;

    #[test]
    fn config_names() {
        assert!(valid_cfg_name("mahtab87"));
        assert!(valid_cfg_name("Erfan456"));
        assert!(!valid_cfg_name("ab"));
        assert!(!valid_cfg_name("87mahtab"));
        assert!(!valid_cfg_name("mah_tab"));
        assert!(!valid_cfg_name("mahtab 87"));
        assert!(!valid_cfg_name("مهتاب"));
        assert!(!valid_cfg_name("abcdefghijklm"));
        assert_eq!(cfg_name_from("✨Mahtab 87🌙"), Some("mahtab87".into()));
        assert_eq!(cfg_name_from("𝓜𝓪𝓱𝓽𝓪𝓫"), None);
        assert_eq!(cfg_name_from("علی ali"), Some("ali".into()));
        assert_eq!(cfg_name_from("2024_erfan_dev_account"), Some("erfandevacco".into()));
        assert_eq!(cfg_name_from("محمد"), None);
    }
}

#[cfg(test)]
mod env_tests {
    #[test]
    fn a_bad_byte_in_one_line_keeps_the_others() {
        let p = std::env::temp_dir().join(format!("kanki-env-{}", super::rand_token(8)));
        std::fs::write(&p, b"PANEL_PORT=20973\nLOCAL_NAME=Ger\xe9many\nDOMAIN=a.b\n").unwrap();
        let m = super::load_env(p.to_str().unwrap());
        let _ = std::fs::remove_file(&p);
        assert_eq!(m.get("PANEL_PORT").map(|s| s.as_str()), Some("20973"));
        assert_eq!(m.get("DOMAIN").map(|s| s.as_str()), Some("a.b"));
    }
}

#[cfg(test)]
mod update_tests {
    use std::os::unix::fs::PermissionsExt;

    fn script(dir: &std::path::Path, name: &str, body: &str) -> std::path::PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, format!("#!/bin/sh\n{}\n", body)).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    #[test]
    fn only_a_program_that_starts_replaces_the_old_one() {
        let dir = std::env::temp_dir().join(format!("kanki-upd-{}", super::rand_token(8)));
        std::fs::create_dir_all(&dir).unwrap();
        let t = std::time::Duration::from_secs(5);
        assert!(super::check_program(&script(&dir, "good", "echo kanki-panel 9.9.9"), t).is_ok());
        assert!(super::check_program(&script(&dir, "bad", "echo Exec format error; exit 1"), t).is_err());
        assert!(super::check_program(&script(&dir, "slow", "sleep 5; echo kanki-panel 1"), std::time::Duration::from_millis(300)).is_err());
        // a download that is not a program at all: the old file stays as it was
        let prog = script(&dir, "kanki-panel", "echo kanki-panel 1.0.0");
        assert!(super::swap_program(&prog, b"not a program").is_err());
        assert_eq!(std::fs::read_to_string(&prog).unwrap(), "#!/bin/sh\necho kanki-panel 1.0.0\n");
        // a good one takes its place, and no temporary file is left
        assert!(super::swap_program(&prog, b"#!/bin/sh\necho kanki-panel 2.0.0\n").is_ok());
        assert!(std::fs::read_to_string(&prog).unwrap().contains("2.0.0"));
        assert!(!std::fs::read_dir(&dir).unwrap().flatten().any(|e| e.file_name().to_string_lossy().ends_with(".new")));
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod totp_tests {
    use super::*;

    #[test]
    fn totp_step_names_the_step_of_the_code() {
        let secret = totp_secret();
        let key = base32_decode(&secret);
        let at = 1_800_000_000;
        let step = (at / 30) as u64;
        assert_eq!(totp_step(&secret, &format!("{:06}", hotp(&key, step)), at), Some(step));
        assert_eq!(totp_step(&secret, &format!("{:06}", hotp(&key, step - 1)), at), Some(step - 1));
        assert_eq!(totp_step(&secret, &format!("{:06}", hotp(&key, step + 5)), at), None);
        assert_eq!(totp_step(&secret, "12345", at), None);
    }
}

#[cfg(test)]
mod private_tests {
    use super::*;

    #[test]
    fn log_lines_lose_their_secrets() {
        let wg = "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHdpcmVndWFyZCE=";
        let l = format!(
            "sub kanki-12-4821930012345678901 GET /api/config/3/wg?sub=kanki-3-abcdef12&node=x bot 123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw key {} Authorization: Bearer abc.def hex 0123456789abcdef0123456789abcdef pass=hunter22 mine s3cretValue99",
            wg
        );
        let r = redact(&l, &["s3cretValue99".to_string()]);
        for leak in ["4821930012345678901", "abcdef12", "AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw", wg, "abc.def", "0123456789abcdef0123456789abcdef", "hunter22", "s3cretValue99"] {
            assert!(!r.contains(leak), "{} in {}", leak, r);
        }
        assert!(r.contains("kanki-12-[secret]") && r.contains("node=x") && r.contains("123456789:[secret]"), "{}", r);
        // an ordinary line stays as it is
        let plain = "firewall: closed unused 51820/udp (no longer used by wg) at 2026-11-27 12:00";
        assert_eq!(redact(plain, &[]), plain);
    }

    #[test]
    fn only_public_addresses_pass_the_ssrf_guard() {
        for a in ["127.0.0.1", "10.0.0.1", "172.16.5.5", "192.168.0.1", "169.254.169.254", "100.64.1.1", "0.0.0.0", "::1", "fd00::1", "fe80::1", "::ffff:127.0.0.1", "224.0.0.1", "255.255.255.255"] {
            assert!(!public_ip(a.parse().unwrap()), "{}", a);
        }
        for a in ["1.1.1.1", "8.8.8.8", "172.32.0.1", "2606:4700:4700::1111"] {
            assert!(public_ip(a.parse().unwrap()), "{}", a);
        }
    }

    #[tokio::test]
    async fn local_targets_are_refused_by_name_and_url() {
        assert!(public_host("localhost", 80, true).await.is_err());
        assert!(public_host("127.0.0.1", 8080, true).await.is_err());
        assert!(public_host("169.254.169.254", 80, true).await.is_err());
        assert!(public_host("10.0.0.5", 2096, false).await.is_err());
        assert!(public_host("10.0.0.5", 2096, true).await.is_ok());
        assert!(public_url("https://127.0.0.1:29332/api/users", false).await.is_err());
        assert!(public_url("https://u:p@1.1.1.1/", false).await.is_err());
        assert!(public_url("file:///etc/passwd", false).await.is_err());
        assert!(public_url("https://1.1.1.1/", false).await.is_ok());
    }

    #[test]
    fn private_files_are_0600_and_replace_atomically() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("kanki-priv-{}", rand_token(8)));
        let d = dir.to_str().unwrap().to_string();
        private_dir(&d).unwrap();
        assert_eq!(std::fs::metadata(&d).unwrap().permissions().mode() & 0o777, 0o700);
        let f = format!("{}/users.json", d);
        write_private(&f, "one").unwrap();
        write_private(&f, "two").unwrap();
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "two");
        assert_eq!(std::fs::metadata(&f).unwrap().permissions().mode() & 0o777, 0o600);
        // no temp file is left behind
        assert_eq!(std::fs::read_dir(&d).unwrap().count(), 1);
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644)).unwrap();
        chmod_if_present(&f, 0o600).unwrap();
        assert_eq!(std::fs::metadata(&f).unwrap().permissions().mode() & 0o777, 0o600);
        chmod_if_present(&format!("{}/missing", d), 0o600).unwrap();
        std::fs::remove_dir_all(&d).unwrap();
    }
}
