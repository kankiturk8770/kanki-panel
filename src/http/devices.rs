//! Devices of each user and the sealed configs of the Kanki apps.
//!
//! The Kanki apps (Windows, and Android once updated) send two headers with every subscription request:
//! `X-Kanki-Device` (an id that stays the same on that device) and `X-Kanki-Seal: kseal1`. The panel then
//!
//! - binds the device to the user, up to the user's limit (`max_conn`; 0 = no limit). A new device past the
//!   limit is refused until the admin removes one, or one stays unused for `device_idle_days` (default 30);
//! - answers sealed: `kseal1.<base64url(nonce(12) | AES-256-GCM ciphertext+tag)>`, key =
//!   HKDF-SHA256(secret = subscription code, salt = device id, info = "kanki sealed config v1"), aad = "kseal1"
//!   (the same as `windows/service/internal/sub/seal.go` in kanki-app), so a config cached or logged on the
//!   way (CDN, proxy) cannot be read.
//!
//! Other apps (v2rayNG, a browser) send neither. They are listed too (not counted against the limit) so
//! the admin sees what each user connects with. With "Kanki apps only" (`app_only`) they get no configs
//! from the web (vless://, hy2://, base64); the sales bot still sends the config files.
use crate::db::User;
use crate::util::{self, client_ip, now, sha256_hex, user_agent};
use crate::App;
use axum::{
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
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
        ("nekobox", "", "NekoBox"), ("hiddify", "", "Hiddify"), ("v2rayn", "pc", "v2rayN"), ("nekoray", "pc", "NekoRay"),
        ("clash", "", "Clash"), ("sing-box", "", "sing-box"), ("singbox", "", "sing-box"), ("wireguard", "", "WireGuard"),
        ("amnezia", "", "AmneziaVPN"), ("happ", "", "Happ"), ("karing", "", "Karing"),
    ] {
        if has(k) {
            let kind = if !kind.is_empty() { kind } else if has("android") || has("iphone") || has("ios") { "mobile" } else if has("windows") || has("mac") || has("linux") { "pc" } else { "" };
            return (kind, name);
        }
    }
    if has("mozilla") {
        let kind = if has("android") || has("iphone") || has("ipad") || has("mobile") { "mobile" } else { "pc" };
        return (kind, "Browser");
    }
    ("", "Other app")
}

/// The id the panel keeps: a hash, so the device's own id is not stored
fn key_of(raw: &str) -> String {
    sha256_hex(raw)[..24].to_string()
}

pub fn app_only(app: &App) -> bool {
    app.db.on("app_only")
}

fn limit_on(app: &App) -> bool {
    app.db.get("device_limit_on") != "0"
}

fn idle_days(app: &App) -> i64 {
    app.db.get("device_idle_days").trim().parse().unwrap_or(30).max(0)
}

/// Lets the request in (and remembers the device) or answers it: the device limit is full, or only the
/// Kanki apps may read configs and this is another app.
pub fn admit(app: &App, u: &User, h: &HeaderMap) -> Result<(), Response> {
    let ua = user_agent(h);
    let (kind, name) = kind_of(&ua);
    let ip = client_ip(h);
    let t = now();
    if app_only(app) && !wants_seal(h) {
        return Err(refuse(StatusCode::FORBIDDEN, "app_only", "Configs are only in the Kanki app"));
    }
    let Some(raw) = device_id(h) else {
        if app_only(app) {
            return Err(refuse(StatusCode::FORBIDDEN, "app_only", "Configs are only in the Kanki app"));
        }
        // other apps: one row per app (not per phone, they send no id) and never counted
        let id = format!("ua-{}", &sha256_hex(&format!("{}|{}", kind, name))[..16]);
        remember(app, u.id, &id, false, kind, name, &ip, t);
        return Ok(());
    };
    let id = key_of(&raw);
    let known = app.db.with(|c| c.query_row("SELECT 1 FROM devices WHERE user_id=?1 AND id=?2", rusqlite::params![u.id, id], |_| Ok(())).is_ok());
    if !known && limit_on(app) && u.max_conn > 0 {
        let days = idle_days(app);
        if days > 0 {
            let _ = app.db.exec("DELETE FROM devices WHERE user_id=?1 AND bound=1 AND last_seen<?2", &[&u.id, &(t - days * 86400)]);
        }
        let used: i64 = app.db.with(|c| c.query_row("SELECT COUNT(*) FROM devices WHERE user_id=?1 AND bound=1", [u.id], |r| r.get(0)).unwrap_or(0));
        if used >= u.max_conn {
            return Err(refuse(StatusCode::FORBIDDEN, "device_limit", "This subscription is already in use on its maximum number of devices"));
        }
    }
    remember(app, u.id, &id, true, kind, name, &ip, t);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn remember(app: &App, uid: i64, id: &str, bound: bool, kind: &str, name: &str, ip: &str, t: i64) {
    let _ = app.db.exec(
        "INSERT INTO devices(user_id,id,bound,kind,app,ip,first_seen,last_seen) VALUES(?1,?2,?3,?4,?5,?6,?7,?7)
         ON CONFLICT(user_id,id) DO UPDATE SET kind=?4, app=?5, ip=?6, last_seen=?7",
        &[&uid, &id, &(bound as i64), &kind, &name, &ip, &t],
    );
}

/// An unknown subscription code (the limiter counts these per address)
pub fn miss() -> Response {
    refuse(StatusCode::NOT_FOUND, "unknown", "not found")
}

/// The standard links for other apps are not on the web while only the Kanki apps get configs
pub fn links_off() -> Response {
    refuse(StatusCode::NOT_FOUND, "app_only", "Configs are only in the Kanki app and the Telegram bot")
}

/// A refusal the apps can show: text for a person, and a reason code for the app
fn refuse(st: StatusCode, reason: &str, text: &str) -> Response {
    (st, [(header::CACHE_CONTROL, "no-store"), (header::HeaderName::from_static("x-kanki-reason"), reason)], text.to_string()).into_response()
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

/// The subscription page for a browser or another app when only the Kanki apps get configs: the account
/// and the app's address
pub fn app_only_page(app: &App, u: &User) -> Response {
    let link = app.db.get("app_link");
    let left = if u.limit_gb > 0.0 { format!("{:.2} / {:.0} GB", u.used_gb(), u.limit_gb) } else { format!("{:.2} GB / ∞", u.used_gb()) };
    let app_line = if link.is_empty() { String::new() } else { format!("<p dir=\"ltr\"><a href=\"{0}\">{0}</a></p>", util::esc(&link)) };
    let page = format!(
        "<!doctype html><html lang=\"fa\" dir=\"rtl\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>{name}</title>\
<style>body{{margin:0;font:15px/1.7 system-ui,sans-serif;background:#0d0b07;color:#f3ead7;display:grid;place-items:center;min-height:100vh}}\
main{{max-width:420px;margin:16px;padding:24px;border-radius:16px;background:#1a160e;border:1px solid #3a3020}}h1{{font-size:20px;margin:0 0 4px}}\
.s{{color:#bfb39a;font-size:13px}}a{{color:#f5c451}}b{{direction:ltr;unicode-bidi:isolate}}</style></head><body><main>\
<h1 dir=\"ltr\">{name}</h1><p class=\"s\">{st} · <b>{left}</b></p>\
<p>کانفیگ‌ها فقط داخل برنامه‌ی کانکی است. با همین لینک وارد برنامه شوید.</p><p dir=\"ltr\" class=\"s\">Configs are only in the Kanki app: sign in there with this link.</p>{app_line}</main></body></html>",
        name = util::esc(&u.username), st = u.status(), left = left, app_line = app_line
    );
    ([(header::CACHE_CONTROL, "no-store")], Html(page)).into_response()
}

fn row(r: &rusqlite::Row) -> rusqlite::Result<(i64, Value)> {
    let id: String = r.get(1)?;
    Ok((r.get(0)?, json!({
        "id": id, "bound": r.get::<_, i64>(2)? == 1, "kind": r.get::<_, String>(3)?, "app": r.get::<_, String>(4)?,
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

/// Frees one device's place (`id` = "" frees all of them)
pub fn remove(app: &App, uid: i64, id: &str) {
    if id.is_empty() {
        let _ = app.db.exec("DELETE FROM devices WHERE user_id=?1", &[&uid]);
    } else {
        let _ = app.db.exec("DELETE FROM devices WHERE user_id=?1 AND id=?2", &[&uid, &id]);
    }
}

/// Rows of other apps not seen for 60 days go (a bound device stays until the admin or the idle rule frees it)
pub fn prune(app: &App) {
    let _ = app.db.exec("DELETE FROM devices WHERE bound=0 AND last_seen<?1", &[&(now() - 60 * 86400)]);
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
    async fn binds_devices_seals_configs_and_hides_links() {
        let app = test_app();
        let u = app.db.create_user("ALI", 10.0, 30, 1, "wg,hy2", "", "", 0).unwrap();
        let code = u.sub_code();
        let page = format!("/sub/{}", code);
        let win = |d: &'static str| [("x-kanki-device", d), ("x-kanki-seal", "kseal1"), ("user-agent", "KankiVPN-Windows")];
        // the first Kanki device gets the page, sealed for it
        let (st, body, _) = get(&app, &page, &win("pc-aaaaaaaa")).await;
        assert_eq!(st, StatusCode::OK);
        assert!(body.starts_with("kseal1.") && !body.contains("ALI"));
        assert!(open(&body, &code, "pc-aaaaaaaa").contains("ALI"));
        // one place: a second device is refused, the first one still works
        let (st, _, why) = get(&app, &page, &win("pc-bbbbbbbb")).await;
        assert_eq!((st, why.as_str()), (StatusCode::FORBIDDEN, "device_limit"));
        assert_eq!(get(&app, &page, &win("pc-aaaaaaaa")).await.0, StatusCode::OK);
        // other apps still read the plain subscription, are listed and take no place
        let (st, body, _) = get(&app, &format!("{}/raw", page), &[("user-agent", "v2rayNG/1.9")]).await;
        assert_eq!(st, StatusCode::OK);
        assert!(!body.starts_with("kseal1."));
        let d = of(&app, u.id);
        assert_eq!(d.len(), 2);
        assert!(d.iter().any(|x| x["app"] == "Kanki Windows" && x["kind"] == "pc" && x["bound"] == true));
        assert!(d.iter().any(|x| x["app"] == "v2rayNG" && x["kind"] == "mobile" && x["bound"] == false));
        // the admin frees the place: the new device gets in
        let id = d.iter().find(|x| x["bound"] == true).unwrap()["id"].as_str().unwrap().to_string();
        crate::api::user_action(&app, u.id, "forget-device", &json!({"id": id})).unwrap();
        assert_eq!(get(&app, &page, &win("pc-bbbbbbbb")).await.0, StatusCode::OK);
        // Kanki apps only: no links on the web, a page without configs for a browser, sealed for the apps
        app.db.set("app_only", "1");
        let (st, _, why) = get(&app, &format!("{}/raw", page), &[("user-agent", "v2rayNG/1.9")]).await;
        assert_eq!((st, why.as_str()), (StatusCode::NOT_FOUND, "app_only"));
        assert_eq!(get(&app, &format!("{}/v2", page), &[]).await.0, StatusCode::NOT_FOUND);
        let (st, body, _) = get(&app, &page, &[("user-agent", "Mozilla/5.0 (Linux; Android 14) Mobile")]).await;
        assert!(st == StatusCode::OK && body.contains("Kanki app") && !body.contains("/api/config/"));
        let (st, _, why) = get(&app, &format!("/api/config/{}/wireguard?sub={}&node=local", u.id, code), &[]).await;
        assert_eq!((st, why.as_str()), (StatusCode::FORBIDDEN, "app_only"));
        let (st, body, _) = get(&app, &page, &win("pc-bbbbbbbb")).await;
        assert!(st == StatusCode::OK && open(&body, &code, "pc-bbbbbbbb").contains("ALI"));
        // an unknown code is marked, so the limiter can count it
        let (st, _, why) = get(&app, "/sub/kanki-999-00000000", &[]).await;
        assert_eq!((st, why.as_str()), (StatusCode::NOT_FOUND, "unknown"));
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

