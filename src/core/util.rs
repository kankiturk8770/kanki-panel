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
    let code = code.trim();
    if code.len() != 6 || !code.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    let key = base32_decode(secret_b32);
    if key.is_empty() {
        return false;
    }
    let step = (now() / 30) as u64;
    for s in [step.saturating_sub(1), step, step + 1] {
        if ct_eq(&format!("{:06}", hotp(&key, s)), code) {
            return true;
        }
    }
    false
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
