//! The Kanki app's install files (APK), uploaded in the panel: one per phone type (arm64, armv7,
//! universal). Customers download them from their subscription page and the bot sends them as a
//! file, so nobody needs GitHub (private) or another download site.
//!
//! The files are kept in `<DATA_DIR>/apps/<abi>.apk`; a new upload of the same type replaces the old
//! one. Downloads go through `/sub/<code>/app/<abi>`, so only subscribers get them and the Iran
//! subscription server and the separate subscription domain pass them like the rest of the page.
use crate::api::err;
use crate::guard;
use crate::App;
use axum::body::{Body, Bytes};
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;

type St = State<Arc<App>>;

const KEY: &str = "app_files";
/// a bigger file is not an app (and the bot could not send it anyway)
const MAX: usize = 200 * 1024 * 1024;
/// phone types, in the order they are shown (the one most phones need first)
const ABIS: &[&str] = &["arm64-v8a", "armeabi-v7a", "universal", "x86_64"];
/// Telegram bots may upload files up to 50 MB
pub const TG_MAX: u64 = 50 * 1000 * 1000;

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(default)]
pub struct AppFile {
    pub abi: String,
    pub version: String,
    pub size: u64,
    pub sha256: String,
    /// when it was uploaded
    pub at: i64,
    /// Telegram's id of the file once the bot sent it (sent again by id, without uploading)
    pub tg: String,
}

impl AppFile {
    /// "KankiVPN-1.15.1-arm64.apk"
    pub fn file_name(&self) -> String {
        let v = if self.version.is_empty() { String::new() } else { format!("-{}", self.version) };
        format!("KankiVPN{}-{}.apk", v, short(&self.abi))
    }

    /// "Kanki VPN 1.15.1 · arm64"
    pub fn label(&self) -> String {
        let v = if self.version.is_empty() { String::new() } else { format!(" {}", self.version) };
        format!("Kanki VPN{} · {}", v, short(&self.abi))
    }
}

fn short(abi: &str) -> &str {
    match abi {
        "arm64-v8a" => "arm64",
        "armeabi-v7a" => "armv7",
        x => x,
    }
}

/// Which phones a file is for, in Persian (title, who should take it).
pub fn title(abi: &str) -> (&'static str, &'static str) {
    match abi {
        "arm64-v8a" => ("گوشی‌های جدید (۶۴ بیتی)", "بیشتر گوشی‌های امروزی؛ اگر مطمئن نیستی همین را بگیر"),
        "armeabi-v7a" => ("گوشی‌های قدیمی (۳۲ بیتی)", "اگر نسخه‌ی ۶۴ بیتی نصب نشد، این را بگیر"),
        "universal" => ("همه‌ی گوشی‌ها", "روی هر گوشی نصب می‌شود، فقط حجمش بیشتر است"),
        _ => ("گوشی‌ها و شبیه‌سازهای x86", "برای شبیه‌ساز اندروید روی کامپیوتر"),
    }
}

/// The phone type in an APK's file name ("app-arm64-v8a-release.apk" -> arm64-v8a).
pub fn abi_of(name: &str) -> Option<&'static str> {
    let n = name.to_ascii_lowercase();
    if n.contains("arm64") || n.contains("aarch64") || n.contains("v8a") {
        Some("arm64-v8a")
    } else if n.contains("armeabi") || n.contains("armv7") || n.contains("arm7") || n.contains("v7a") {
        Some("armeabi-v7a")
    } else if n.contains("x86_64") || n.contains("x64") {
        Some("x86_64")
    } else if n.contains("universal") {
        Some("universal")
    } else {
        None
    }
}

/// The version in a file name ("KankiVPN-1.15.1-arm64.apk" -> "1.15.1"), or "".
pub fn version_of(name: &str) -> String {
    let b = name.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i].is_ascii_digit() && (i == 0 || !b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'v' || b[i - 1] == b'V') {
            let mut j = i;
            let mut dots = 0;
            while j < b.len() && (b[j].is_ascii_digit() || (b[j] == b'.' && j + 1 < b.len() && b[j + 1].is_ascii_digit())) {
                if b[j] == b'.' {
                    dots += 1;
                }
                j += 1;
            }
            if dots >= 1 {
                return name[i..j].to_string();
            }
            i = j.max(i + 1);
        } else {
            i += 1;
        }
    }
    String::new()
}

fn clean_version(v: &str) -> String {
    v.trim().trim_start_matches(['v', 'V']).chars().filter(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '-').take(24).collect()
}

/// Looks like an Android app: a zip with an AndroidManifest.xml in it.
fn looks_like_apk(b: &[u8]) -> bool {
    b.len() > 64 * 1024 && b.starts_with(b"PK\x03\x04") && b.windows(19).any(|w| w == b"AndroidManifest.xml")
}

fn dir(app: &App) -> String {
    format!("{}/apps", app.data_dir())
}

fn path(app: &App, abi: &str) -> String {
    format!("{}/{}.apk", dir(app), abi)
}

/// The uploaded files whose file is there, the one most phones need first.
pub fn list(app: &App) -> Vec<AppFile> {
    let mut v: Vec<AppFile> = serde_json::from_str(&app.db.get(KEY)).unwrap_or_default();
    v.retain(|f| ABIS.contains(&f.abi.as_str()) && std::path::Path::new(&path(app, &f.abi)).exists());
    v.sort_by_key(|f| ABIS.iter().position(|a| *a == f.abi).unwrap_or(99));
    v
}

fn save(app: &App, v: &[AppFile]) {
    app.db.set(KEY, &serde_json::to_string(v).unwrap_or_else(|_| "[]".into()));
}

pub fn get_file(app: &App, abi: &str) -> Option<AppFile> {
    list(app).into_iter().find(|f| f.abi == abi)
}

/// The bot sent this file once: Telegram's id is kept to send it again without uploading.
pub fn set_tg(app: &App, abi: &str, file_id: &str) {
    let mut v = list(app);
    if let Some(f) = v.iter_mut().find(|f| f.abi == abi) {
        f.tg = file_id.to_string();
        save(app, &v);
    }
}

pub async fn read(app: &App, abi: &str) -> Option<Vec<u8>> {
    tokio::fs::read(path(app, abi)).await.ok()
}

/// For the subscription page: each file with its download address for this subscriber.
pub fn sub_info(app: &App, code: &str) -> Value {
    json!(list(app)
        .iter()
        .map(|f| {
            let (t, hint) = title(&f.abi);
            json!({ "abi": f.abi, "short": short(&f.abi), "title": t, "hint": hint, "version": f.version, "size": f.size,
                    "name": f.file_name(), "url": format!("/sub/{}/app/{}", code, f.abi) })
        })
        .collect::<Vec<_>>())
}

// ------------------------------------------------------------------ panel API

fn info(f: &AppFile) -> Value {
    let (t, hint) = title(&f.abi);
    json!({ "abi": f.abi, "short": short(&f.abi), "title": t, "hint": hint, "version": f.version, "size": f.size,
            "sha256": f.sha256, "at": f.at, "name": f.file_name(), "label": f.label(), "bot": f.size <= TG_MAX })
}

async fn get_list(State(app): St, h: HeaderMap) -> Response {
    let _ = guard!(app, h, "settings");
    Json(json!({ "files": list(&app).iter().map(info).collect::<Vec<_>>() })).into_response()
}

/// POST /api/apps?name=<file name>&abi=<type, or empty = from the name>&version=<or empty = from the name>
async fn upload(State(app): St, h: HeaderMap, Query(q): Query<HashMap<String, String>>, body: Bytes) -> Response {
    let _ = guard!(app, h, "settings");
    let name = q.get("name").cloned().unwrap_or_default();
    let abi = match q.get("abi").map(|s| s.trim()).filter(|s| !s.is_empty()) {
        Some(a) => match ABIS.iter().find(|x| **x == a) {
            Some(x) => *x,
            None => return err(StatusCode::BAD_REQUEST, "unknown phone type"),
        },
        None => match abi_of(&name) {
            Some(a) => a,
            None => return err(StatusCode::BAD_REQUEST, "choose the phone type of this file (arm64, armv7 or universal)"),
        },
    };
    if !looks_like_apk(&body) {
        return err(StatusCode::BAD_REQUEST, "this is not an Android app (.apk)");
    }
    let version = clean_version(q.get("version").map(|s| s.as_str()).filter(|s| !s.trim().is_empty()).unwrap_or(&version_of(&name)));
    // hashing up to 200 MB takes a moment: not on an async worker
    let sum = {
        let b = body.clone();
        tokio::task::spawn_blocking(move || {
            use sha2::{Digest, Sha256};
            hex::encode(Sha256::digest(&b))
        })
        .await
        .unwrap_or_default()
    };
    let _ = tokio::fs::create_dir_all(dir(&app)).await;
    let dst = path(&app, abi);
    let tmp = format!("{}.part", dst);
    if let Err(e) = tokio::fs::write(&tmp, &body).await {
        return err(StatusCode::INTERNAL_SERVER_ERROR, &format!("cannot save the file: {}", e));
    }
    if let Err(e) = tokio::fs::rename(&tmp, &dst).await {
        return err(StatusCode::INTERNAL_SERVER_ERROR, &format!("cannot save the file: {}", e));
    }
    let f = AppFile { abi: abi.into(), version, size: body.len() as u64, sha256: sum, at: crate::util::now(), tg: String::new() };
    let mut v = list(&app);
    v.retain(|x| x.abi != abi);
    v.push(f.clone());
    save(&app, &v);
    Json(json!({ "ok": true, "file": info(&f) })).into_response()
}

/// PUT /api/apps/:abi { version }
async fn edit(State(app): St, h: HeaderMap, Path(abi): Path<String>, Json(b): Json<Value>) -> Response {
    let _ = guard!(app, h, "settings");
    let mut v = list(&app);
    let Some(f) = v.iter_mut().find(|f| f.abi == abi) else { return err(StatusCode::NOT_FOUND, "no such file") };
    if let Some(ver) = b["version"].as_str() {
        f.version = clean_version(ver);
    }
    save(&app, &v);
    Json(json!({ "ok": true })).into_response()
}

async fn remove(State(app): St, h: HeaderMap, Path(abi): Path<String>) -> Response {
    let _ = guard!(app, h, "settings");
    if !ABIS.contains(&abi.as_str()) {
        return err(StatusCode::NOT_FOUND, "no such file");
    }
    let _ = tokio::fs::remove_file(path(&app, &abi)).await;
    let mut v = list(&app);
    v.retain(|f| f.abi != abi);
    save(&app, &v);
    Json(json!({ "ok": true })).into_response()
}

// ------------------------------------------------------------------ download (subscribers)

/// GET /sub/:code/app/:abi — the file, read from disk in pieces (never whole in memory)
async fn download(State(app): St, Path((code, abi)): Path<(String, String)>) -> Response {
    // an unknown code is marked like on the other subscription paths, so the limiter counts it
    let Some((id, c)) = crate::api::parse_code(&code) else { return crate::devices::miss() };
    if app.db.user_by_code(id, &c).is_none() {
        return crate::devices::miss();
    }
    let Some(f) = get_file(&app, &abi) else { return (StatusCode::NOT_FOUND, "not found").into_response() };
    let Ok(file) = tokio::fs::File::open(path(&app, &abi)).await else { return (StatusCode::NOT_FOUND, "not found").into_response() };
    let stream = futures_util::stream::unfold(file, |mut file| async move {
        use tokio::io::AsyncReadExt;
        let mut buf = vec![0u8; 64 * 1024];
        match file.read(&mut buf).await {
            Ok(0) => None,
            Ok(n) => {
                buf.truncate(n);
                Some((Ok::<Bytes, std::io::Error>(Bytes::from(buf)), file))
            }
            Err(e) => Some((Err(e), file)),
        }
    });
    (
        [
            (header::CONTENT_TYPE, "application/vnd.android.package-archive".to_string()),
            (header::CONTENT_LENGTH, f.size.to_string()),
            (header::CONTENT_DISPOSITION, format!("attachment; filename=\"{}\"", f.file_name())),
            (header::CACHE_CONTROL, "private, max-age=3600".to_string()),
        ],
        Body::from_stream(stream),
    )
        .into_response()
}

pub fn router() -> Router<Arc<App>> {
    Router::new()
        .route("/api/apps", get(get_list).post(upload).layer(DefaultBodyLimit::max(MAX)))
        .route("/api/apps/:abi", put(edit).delete(remove))
        .route("/sub/:code/app/:abi", get(download))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phone_type_and_version_from_the_file_name() {
        assert_eq!(abi_of("app-arm64-v8a-release.apk"), Some("arm64-v8a"));
        assert_eq!(abi_of("app-armeabi-v7a-release.apk"), Some("armeabi-v7a"));
        assert_eq!(abi_of("KankiVPN-1.15.1-armv7.apk"), Some("armeabi-v7a"));
        assert_eq!(abi_of("app-universal-release.apk"), Some("universal"));
        assert_eq!(abi_of("app-release.apk"), None);
        assert_eq!(version_of("KankiVPN-1.15.1-arm64.apk"), "1.15.1");
        assert_eq!(version_of("kanki_v2.0-armv7.apk"), "2.0");
        assert_eq!(version_of("app-arm64-v8a-release.apk"), "");
        assert_eq!(clean_version(" v1.15.1 "), "1.15.1");
    }

    #[test]
    fn names_people_see() {
        let f = AppFile { abi: "arm64-v8a".into(), version: "1.15.1".into(), ..Default::default() };
        assert_eq!(f.file_name(), "KankiVPN-1.15.1-arm64.apk");
        assert_eq!(f.label(), "Kanki VPN 1.15.1 · arm64");
        let g = AppFile { abi: "armeabi-v7a".into(), ..Default::default() };
        assert_eq!(g.file_name(), "KankiVPN-armv7.apk");
    }

    #[tokio::test]
    async fn subscribers_download_the_file() {
        use std::sync::atomic::AtomicI64;
        use std::sync::Mutex;
        use tower::ServiceExt;
        let dir = std::env::temp_dir().join(format!("kanki-apps-test-{}", crate::util::rand_token(8)));
        std::fs::create_dir_all(dir.join("apps")).unwrap();
        let db = crate::db::Db::open(dir.join("kanki.db").to_str().unwrap());
        let app = Arc::new(App {
            db, env: HashMap::from([("DATA_DIR".to_string(), dir.to_string_lossy().to_string())]),
            hy2_allowed: Mutex::new(HashMap::new()), limits: Mutex::new(HashMap::new()), reported: Mutex::new(HashMap::new()),
            login_fails: Mutex::new(HashMap::new()), sync_lock: tokio::sync::Mutex::new(()), bot_alive: AtomicI64::new(0),
            http: reqwest::Client::new(), http_insecure: reqwest::Client::new(), pin_clients: Mutex::new(HashMap::new()),
        });
        let data: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        std::fs::write(dir.join("apps/arm64-v8a.apk"), &data).unwrap();
        save(&app, &[AppFile { abi: "arm64-v8a".into(), version: "1.15.1".into(), size: data.len() as u64, ..Default::default() }]);
        let u = app.db.create_user("ali", 10.0, 30, 1, "wg", "", "", 0).unwrap();
        let get = |p: String| axum::http::Request::builder().uri(p).body(Body::empty()).unwrap();
        let r = router().with_state(app.clone()).oneshot(get(format!("/sub/{}/app/arm64-v8a", u.sub_code()))).await.unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(r.headers()[header::CONTENT_DISPOSITION], "attachment; filename=\"KankiVPN-1.15.1-arm64.apk\"");
        let body = axum::body::to_bytes(r.into_body(), usize::MAX).await.unwrap();
        assert_eq!(body.as_ref(), data.as_slice());
        // a wrong code or a type that was not uploaded: nothing
        let r = router().with_state(app.clone()).oneshot(get("/sub/kanki-1-wrong/app/arm64-v8a".into())).await.unwrap();
        assert_eq!(r.status(), StatusCode::NOT_FOUND);
        let r = router().with_state(app.clone()).oneshot(get(format!("/sub/{}/app/armeabi-v7a", u.sub_code()))).await.unwrap();
        assert_eq!(r.status(), StatusCode::NOT_FOUND);
        // the subscription page data
        let s = sub_info(&app, &u.sub_code());
        assert_eq!(s[0]["name"], "KankiVPN-1.15.1-arm64.apk");
        assert_eq!(s[0]["url"], format!("/sub/{}/app/arm64-v8a", u.sub_code()));
    }

    #[test]
    fn only_android_apps_are_taken() {
        let mut apk = b"PK\x03\x04".to_vec();
        apk.extend(vec![0u8; 70 * 1024]);
        apk.extend(b"AndroidManifest.xml");
        assert!(looks_like_apk(&apk));
        assert!(!looks_like_apk(b"PK\x03\x04 small"));
        let mut zip = b"PK\x03\x04".to_vec();
        zip.extend(vec![0u8; 70 * 1024]);
        assert!(!looks_like_apk(&zip));
    }
}
