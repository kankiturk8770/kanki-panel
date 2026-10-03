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
        .and_then(|v| v.split(',').last())
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
    if let Ok(t) = std::fs::read_to_string(path) {
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
