//! Devices of each user and the sealed configs of the Kanki apps.
//!
//! The Kanki apps (Windows, and Android once updated) send two headers with every subscription request:
//! `X-Kanki-Device` (an id that stays the same on that device) and `X-Kanki-Seal: kseal1`. The panel then
//! answers sealed: `kseal1.<base64url(nonce(12) | AES-256-GCM ciphertext+tag)>`, key =
//! HKDF-SHA256(secret = subscription code, salt = device id, info = "kanki sealed config v1"), aad = "kseal1"
//! (the same as `windows/service/internal/sub/seal.go` in kanki-app), so a config cached or logged on the
//! way (CDN, proxy) cannot be read.
//!
//! Every app that reads a subscription (the Kanki apps, v2rayNG, a browser…) is also listed, with phone or
//! PC, so the admin sees what each user connects with. Only listed: no app and no device is ever refused.
use crate::db::User;
use crate::util::{self, client_ip, now, sha256_hex, user_agent};
use crate::App;
use axum::{
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde_json::{json, Value};

pub const SEAL: &str = "kseal1";

/// The device id the app sent, when it looks like one
pub fn device_id(h: &HeaderMap) -> Option<String> {
    let d = h.get("x-kanki-device")?.to_str().ok()?.trim();
    let ok = (6..=128).contains(&d.len()) && d.bytes().all(|c| c.is_ascii_alphanumeric() || b"-_.:".contains(&c));
    ok.then(|| d.to_string())
}

/// The request comes from a Kanki app that can open sealed configs
pub fn wants_seal(h: &HeaderMap) -> bool {
    device_id(h).is_some() && h.get("x-kanki-seal").and_then(|v| v.to_str().ok()).map(|v| v.trim() == SEAL).unwrap_or(false)
}

/// Phone or PC from the system part of a user agent ("" when it does not say)
fn system_of(l: &str) -> &'static str {
    let has = |s: &str| l.contains(s);
    // Android (also "Dalvik/… Android 13" and okhttp, the HTTP library of most Android apps), iPhone / iPad
    // (CFNetwork/Darwin without "macintosh" is iOS), then the desktop systems
    if has("android") || has("dalvik") || has("okhttp") || has("iphone") || has("ipad") || has("ipod") || has("ios") || has("mobile") {
        return "mobile";
    }
    if has("cfnetwork") || has("darwin") {
        return if has("macintosh") || has("mac os") || has("macos") { "pc" } else { "mobile" };
    }
    if has("windows") || has("macintosh") || has("mac os") || has("macos") || has("linux") || has("x11") {
        return "pc";
    }
    ""
}

/// What kind of device and app a request comes from: ("pc" | "mobile" | "", app name)
pub fn kind_of(ua: &str) -> (&'static str, &'static str) {
    let l = ua.to_ascii_lowercase();
    let has = |s: &str| l.contains(s);
    if has("kankivpn-windows") {
        return ("pc", "Kanki Windows");
    }
    if has("kankivpn-android") {
        return ("mobile", "Kanki Android");
    }
    // other VPN apps first: their names say more than the system part
    for (k, kind, name) in [
        ("v2rayng", "mobile", "v2rayNG"), ("v2box", "mobile", "V2Box"), ("streisand", "mobile", "Streisand"),
        ("shadowrocket", "mobile", "Shadowrocket"), ("foxray", "mobile", "FoXray"), ("npvtunnel", "mobile", "NPV Tunnel"),
        ("clashmetaforandroid", "mobile", "Clash"), ("sfa/", "mobile", "sing-box"), ("sfi/", "mobile", "sing-box"),
        ("nekobox", "", "NekoBox"), ("hiddify", "", "Hiddify"), ("v2rayn", "pc", "v2rayN"), ("nekoray", "pc", "NekoRay"),
        ("clash-verge", "pc", "Clash"), ("clashx", "pc", "Clash"), ("flclash", "", "Clash"), ("clash", "", "Clash"),
        ("sing-box", "", "sing-box"), ("singbox", "", "sing-box"), ("wireguard", "", "WireGuard"),
        ("amnezia", "", "AmneziaVPN"), ("happ", "", "Happ"), ("karing", "", "Karing"),
    ] {
        if has(k) {
            let kind = if !kind.is_empty() { kind } else { system_of(&l) };
            return (kind, name);
        }
    }
    if has("mozilla") {
        let kind = if system_of(&l) == "mobile" { "mobile" } else { "pc" };
        return (kind, "Browser");
    }
    (system_of(&l), "Other app")
}

/// The id the panel keeps: a hash, so the device's own id is not stored
fn key_of(raw: &str) -> String {
    sha256_hex(raw)[..24].to_string()
}

/// Remembers which device and app read the subscription (never refuses anything)
pub fn note(app: &App, u: &User, h: &HeaderMap) {
    let (kind, name) = kind_of(&user_agent(h));
    // a Kanki app: one row per device; other apps send no id: one row per app
    // other apps send no id: one row per user agent (the version and often the phone model are in it, so two
    // phones with the same app are two rows; the same app updated is a new row, and the old one ages out)
    let ua = user_agent(h);
    let (id, kanki) = match device_id(h) {
        Some(raw) => (key_of(&raw), true),
        None => (format!("ua-{}", &sha256_hex(&format!("{}|{}|{}", kind, name, ua))[..16]), false),
    };
    let _ = app.db.exec(
        "INSERT INTO devices(user_id,id,bound,kind,app,ip,first_seen,last_seen) VALUES(?1,?2,?3,?4,?5,?6,?7,?7)
         ON CONFLICT(user_id,id) DO UPDATE SET kind=?4, app=?5, ip=?6, last_seen=?7",
        &[&u.id, &id, &(kanki as i64), &kind, &name, &client_ip(h), &now()],
    );
}

/// An unknown subscription code (marked, so the limiter counts these per address)
pub fn miss() -> Response {
    (StatusCode::NOT_FOUND, [(header::CACHE_CONTROL, "no-store"), (header::HeaderName::from_static("x-kanki-reason"), "unknown")], "not found").into_response()
}

/// `kseal1.<base64url(nonce | ciphertext+tag)>` (see the top of this file)
pub fn seal(plain: &[u8], code: &str, device: &str, nonce: &[u8; 12]) -> String {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(device.as_bytes()), code.as_bytes());
    let mut key = [0u8; 32];
    hk.expand(b"kanki sealed config v1", &mut key).expect("32 bytes");
    let c = aes_gcm::Aes256Gcm::new_from_slice(&key).expect("32-byte key");
    let ct = c.encrypt(aes_gcm::Nonce::from_slice(nonce), Payload { msg: plain, aad: SEAL.as_bytes() }).expect("seal");
    let mut out = nonce.to_vec();
    out.extend(ct);
    let b = util::b64(&out).replace('+', "-").replace('/', "_");
    format!("{}.{}", SEAL, b.trim_end_matches('='))
}

/// The answer to a Kanki app that asked for it, sealed with the subscription code it used (`code`, as in
/// its address). Errors, pictures and other clients' answers go out as they are.
pub async fn reply(h: &HeaderMap, code: &str, r: Response) -> Response {
    if r.status() != StatusCode::OK || !wants_seal(h) || code.is_empty() {
        return r;
    }
    let ct = r.headers().get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    if ct.starts_with("image/") {
        return r;
    }
    let Ok(body) = axum::body::to_bytes(r.into_body(), 8 << 20).await else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "").into_response();
    };
    let mut nonce = [0u8; 12];
    rand::Rng::fill(&mut rand::thread_rng(), &mut nonce);
    let device = device_id(h).unwrap_or_default();
    ([(header::CONTENT_TYPE, "text/plain; charset=utf-8"), (header::CACHE_CONTROL, "no-store")], seal(&body, code, &device, &nonce)).into_response()
}

fn row(r: &rusqlite::Row) -> rusqlite::Result<(i64, Value)> {
    let id: String = r.get(1)?;
    Ok((r.get(0)?, json!({
        "id": id, "kanki": r.get::<_, i64>(2)? == 1, "kind": r.get::<_, String>(3)?, "app": r.get::<_, String>(4)?,
        "ip": r.get::<_, String>(5)?, "first": r.get::<_, i64>(6)?, "last": r.get::<_, i64>(7)?,
    })))
}

const COLS: &str = "user_id,id,bound,kind,app,ip,first_seen,last_seen";

/// The devices of one user, newest first
pub fn of(app: &App, uid: i64) -> Vec<Value> {
    app.db.with(|c| {
        let Ok(mut s) = c.prepare(&format!("SELECT {} FROM devices WHERE user_id=?1 ORDER BY last_seen DESC", COLS)) else { return vec![] };
        s.query_map([uid], row).map(|r| r.flatten().map(|x| x.1).collect()).unwrap_or_default()
    })
}

/// Forgets every device of a user (a new subscription link)
pub fn clear(app: &App, uid: i64) {
    let _ = app.db.exec("DELETE FROM devices WHERE user_id=?1", &[&uid]);
}

/// Devices and apps not seen for 60 days leave the list
pub fn prune(app: &App) {
    let _ = app.db.exec("DELETE FROM devices WHERE last_seen<?1", &[&(now() - 60 * 86400)]);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unb64url(s: &str) -> Vec<u8> {
        let v = |c: u8| match c { b'A'..=b'Z' => c - b'A', b'a'..=b'z' => c - b'a' + 26, b'0'..=b'9' => c - b'0' + 52, b'-' => 62, _ => 63 } as u32;
        let (mut out, mut acc, mut bits) = (vec![], 0u32, 0);
        for c in s.bytes() {
            acc = (acc << 6 | v(c)) & 0xffff;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push((acc >> bits) as u8);
            }
        }
        out
    }

    #[test]
    fn tells_phone_from_pc() {
        for (ua, kind, app) in [
            ("KankiVPN-Android", "mobile", "Kanki Android"),
            ("KankiVPN-Windows", "pc", "Kanki Windows"),
            ("v2rayNG/1.9.30", "mobile", "v2rayNG"),
            ("HiddifyNext/2.5.7 (android) like ClashMeta v2ray sing-box", "mobile", "Hiddify"),
            ("HiddifyNext/2.5.7 (windows) like ClashMeta", "pc", "Hiddify"),
            ("NekoBox/Android/1.3.4 (Prefer ClashMeta Format)", "mobile", "NekoBox"),
            ("ClashMetaForAndroid/2.10.1.Meta", "mobile", "Clash"),
            ("clash-verge/v1.7.7", "pc", "Clash"),
            ("SFA/1.10.1 (sing-box 1.10.1; android)", "mobile", "sing-box"),
            ("Streisand/1.6 CFNetwork/1494 Darwin/23.4.0", "mobile", "Streisand"),
            ("Happ/1.6.2/ios", "mobile", "Happ"),
            ("okhttp/4.12.0", "mobile", "Other app"),
            ("Dalvik/2.1.0 (Linux; U; Android 13; SM-A515F Build/TP1A)", "mobile", "Other app"),
            ("SomeApp/2 CFNetwork/1494 Darwin/23.4.0", "mobile", "Other app"),
            ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) Safari", "mobile", "Browser"),
            ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126", "pc", "Browser"),
            ("Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) Safari", "pc", "Browser"),
            ("curl/8.5.0", "", "Other app"),
            ("Go-http-client/1.1", "", "Other app"),
        ] {
            assert_eq!(kind_of(ua), (kind, app), "{}", ua);
        }
    }

    #[test]
    fn seals_like_the_windows_app() {
        // the same inputs as TestSealedConfig in kanki-app (windows/service/internal/sub/sub_test.go)
        let s = seal(b"[Interface]\nPrivateKey = x\n", "kanki-12-abcd1234", "dev-1", &[0u8; 12]);
        assert!(s.starts_with("kseal1."));
        let raw = s.trim_start_matches("kseal1.");
        assert!(!raw.contains('=') && !raw.contains('+') && !raw.contains('/'));
        // open it again the way the app does
        use aes_gcm::aead::{Aead, KeyInit, Payload};
        let bytes = unb64url(raw);
        let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(b"dev-1"), b"kanki-12-abcd1234");
        let mut key = [0u8; 32];
        hk.expand(b"kanki sealed config v1", &mut key).unwrap();
        let c = aes_gcm::Aes256Gcm::new_from_slice(&key).unwrap();
        let p = c.decrypt(aes_gcm::Nonce::from_slice(&bytes[..12]), Payload { msg: &bytes[12..], aad: b"kseal1" }).unwrap();
        assert_eq!(p, b"[Interface]\nPrivateKey = x\n");
        // another device cannot open it
        let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(b"dev-2"), b"kanki-12-abcd1234");
        hk.expand(b"kanki sealed config v1", &mut key).unwrap();
        let c = aes_gcm::Aes256Gcm::new_from_slice(&key).unwrap();
        assert!(c.decrypt(aes_gcm::Nonce::from_slice(&bytes[..12]), Payload { msg: &bytes[12..], aad: b"kseal1" }).is_err());
    }

    fn test_app() -> std::sync::Arc<App> {
        use std::sync::{atomic::AtomicI64, Mutex};
        let dir = std::env::temp_dir().join(format!("kanki-devices-test-{}", util::rand_token(8)));
        std::fs::create_dir_all(&dir).unwrap();
        std::sync::Arc::new(App {
            db: crate::db::Db::open(dir.join("kanki.db").to_str().unwrap()),
            env: std::collections::HashMap::from([("DOMAIN".to_string(), "fi.example.com".to_string())]),
            hy2_allowed: Mutex::new(Default::default()), limits: Mutex::new(Default::default()), reported: Mutex::new(Default::default()),
            login_fails: Mutex::new(Default::default()), sync_lock: tokio::sync::Mutex::new(()), bot_alive: AtomicI64::new(0),
            http: reqwest::Client::new(), http_insecure: reqwest::Client::new(), pin_clients: Mutex::new(Default::default()),
        })
    }

    async fn get(app: &std::sync::Arc<App>, uri: &str, hdr: &[(&str, &str)]) -> (StatusCode, String, String) {
        use tower::ServiceExt;
        let mut r = axum::http::Request::get(uri);
        for (k, v) in hdr {
            r = r.header(*k, *v);
        }
        let res = crate::api::master_router(app.clone()).oneshot(r.body(axum::body::Body::empty()).unwrap()).await.unwrap();
        let st = res.status();
        let why = res.headers().get("x-kanki-reason").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
        let b = axum::body::to_bytes(res.into_body(), 1 << 22).await.unwrap();
        (st, String::from_utf8_lossy(&b).to_string(), why)
    }

    fn open(body: &str, code: &str, dev: &str) -> String {
        use aes_gcm::aead::{Aead, KeyInit, Payload};
        let bytes = unb64url(body.trim_start_matches("kseal1."));
        let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(dev.as_bytes()), code.as_bytes());
        let mut key = [0u8; 32];
        hk.expand(b"kanki sealed config v1", &mut key).unwrap();
        let c = aes_gcm::Aes256Gcm::new_from_slice(&key).unwrap();
        String::from_utf8(c.decrypt(aes_gcm::Nonce::from_slice(&bytes[..12]), Payload { msg: &bytes[12..], aad: b"kseal1" }).unwrap()).unwrap()
    }

    #[tokio::test]
    async fn seals_for_kanki_apps_and_lists_every_device() {
        let app = test_app();
        let u = app.db.create_user("ALI", 10.0, 30, 1, "wg,hy2", "", "", 0).unwrap();
        let code = u.sub_code();
        let page = format!("/sub/{}", code);
        let win = |d: &'static str| [("x-kanki-device", d), ("x-kanki-seal", "kseal1"), ("user-agent", "KankiVPN-Windows")];
        // a Kanki app gets the page sealed for its device
        let (st, body, _) = get(&app, &page, &win("pc-aaaaaaaa")).await;
        assert_eq!(st, StatusCode::OK);
        // (base64 can hold "ALI" by chance: check the page itself is not readable)
        assert!(body.starts_with("kseal1.") && !body.contains("<") && !body.contains(' '));
        assert!(open(&body, &code, "pc-aaaaaaaa").contains("ALI"));
        // no device limit: more devices than the connection count all get in
        let (st, body, _) = get(&app, &page, &win("pc-bbbbbbbb")).await;
        assert!(st == StatusCode::OK && open(&body, &code, "pc-bbbbbbbb").contains("ALI"));
        // a browser sees the normal page with its configs, other apps the plain subscription
        let (st, body, _) = get(&app, &page, &[("user-agent", "Mozilla/5.0 (Linux; Android 14) Mobile")]).await;
        assert!(st == StatusCode::OK && body.contains("ALI") && !body.starts_with("kseal1."));
        let (st, body, _) = get(&app, &format!("{}/raw", page), &[("user-agent", "v2rayNG/1.9")]).await;
        assert!(st == StatusCode::OK && !body.starts_with("kseal1."));
        // every one of them is listed, with phone or PC
        let d = of(&app, u.id);
        assert_eq!(d.len(), 4);
        assert_eq!(d.iter().filter(|x| x["app"] == "Kanki Windows" && x["kind"] == "pc" && x["kanki"] == true).count(), 2);
        assert!(d.iter().any(|x| x["app"] == "v2rayNG" && x["kind"] == "mobile" && x["kanki"] == false));
        assert!(d.iter().any(|x| x["app"] == "Browser" && x["kind"] == "mobile"));
        // a new link starts the list again
        crate::api::user_action(&app, u.id, "regen", &json!({})).unwrap();
        assert!(of(&app, u.id).is_empty());
        // an unknown code is marked, so the limiter can count it
        let (st, _, why) = get(&app, "/sub/kanki-999-00000000", &[]).await;
        assert_eq!((st, why.as_str()), (StatusCode::NOT_FOUND, "unknown"));
    }

    // (the panel's request limits, through the same router)
    #[tokio::test]
    async fn five_wrong_logins_lock_the_address() {
        use tower::ServiceExt;
        let app = test_app();
        let login = |pw: &str| {
            axum::http::Request::post("/api/login").header("content-type", "application/json").header("x-forwarded-for", "9.9.9.9")
                .body(axum::body::Body::from(format!(r#"{{"username":"admin","password":"{}"}}"#, pw))).unwrap()
        };
        for _ in 0..5 {
            let r = crate::api::master_router(app.clone()).oneshot(login("wrong-pass")).await.unwrap();
            assert_ne!(r.status(), StatusCode::TOO_MANY_REQUESTS);
        }
        let r = crate::api::master_router(app.clone()).oneshot(login("wrong-pass")).await.unwrap();
        assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[test]
    fn the_same_bytes_as_the_go_seal() {
        // Seal() of windows/service/internal/sub/seal.go with the same inputs gives exactly this
        assert_eq!(
            seal(b"hello kanki", "kanki-12-4821930012", "dev-xyz-123", &[7u8; 12]),
            "kseal1.BwcHBwcHBwcHBwcHvnHPO9eY_DY09_ePqTKyeYjxT3wdvUGtrDWp"
        );
    }

    #[test]
    fn tells_pc_from_phone() {
        assert_eq!(kind_of("KankiVPN-Windows"), ("pc", "Kanki Windows"));
        assert_eq!(kind_of("KankiVPN-Android"), ("mobile", "Kanki Android"));
        assert_eq!(kind_of("v2rayNG/1.9.5"), ("mobile", "v2rayNG"));
        assert_eq!(kind_of("v2rayN/7.0"), ("pc", "v2rayN"));
        assert_eq!(kind_of("HiddifyNext/2.5 (android) like ClashMeta"), ("mobile", "Hiddify"));
        assert_eq!(kind_of("Mozilla/5.0 (Linux; Android 14) Mobile Safari"), ("mobile", "Browser"));
        assert_eq!(kind_of("Mozilla/5.0 (Windows NT 10.0; Win64; x64)"), ("pc", "Browser"));
        assert_eq!(kind_of("curl/8"), ("", "Other app"));
    }

    #[test]
    fn only_a_good_device_id_counts() {
        let mut h = HeaderMap::new();
        assert!(device_id(&h).is_none());
        h.insert("x-kanki-device", "abc".parse().unwrap());
        assert!(device_id(&h).is_none());
        h.insert("x-kanki-device", "3f9a2c1e-7b44-4c1d-9a0e-1234567890ab".parse().unwrap());
        assert!(device_id(&h).is_some() && !wants_seal(&h));
        h.insert("x-kanki-seal", "kseal1".parse().unwrap());
        assert!(wants_seal(&h));
        h.insert("x-kanki-device", "bad id <x>".parse().unwrap());
        assert!(!wants_seal(&h));
    }
}

