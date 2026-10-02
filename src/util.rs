//! توابع کمکی مشترک
use rand::Rng;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
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

/// «salt$hash»
pub fn hash_password(pass: &str) -> String {
    let salt = rand_token(16);
    format!("{}${}", salt, sha256_hex(&format!("{}{}", salt, pass)))
}

pub fn check_password(stored: &str, pass: &str) -> bool {
    match stored.split_once('$') {
        Some((salt, h)) => sha256_hex(&format!("{}{}", salt, pass)) == h,
        None => false,
    }
}

pub fn iso(ts: i64) -> String {
    if ts <= 0 {
        return String::new();
    }
    chrono::DateTime::from_timestamp(ts, 0)
        .map(|d| d.format("%Y-%m-%dT%H:%M:%SZ").to_string())
        .unwrap_or_default()
}

pub fn gb(bytes: i64) -> f64 {
    bytes as f64 / 1_073_741_824.0
}

/// فایل تنظیمات KEY=VALUE
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
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}
