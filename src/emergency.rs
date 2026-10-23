//! Emergency chat: a small server that runs on a server inside Iran, so that users and the admin
//! can still talk when the international internet is cut.
//!
//! The main panel (abroad) decides which server runs it and hands the agent there a config file
//! (`/etc/kanki/emergency.json`): the port, an optional TLS certificate, the admin password hash,
//! the signing key and the list of customers. The agent starts `kanki-panel emergency` under
//! systemd. While the internet works the panel keeps the customer list up to date; when it is cut
//! this server keeps working on its own.
//!
//! * Users (the Kanki app) are known by `sha256("kanki-emergency-v1:" + subscription code)`, never
//!   the code itself, so even over plain HTTP nobody in the middle learns a subscription.
//! * Every admin message is signed (ECDSA P-256). The app got the public key from the main panel
//!   while the internet worked and only trusts messages with a valid signature: nobody in the
//!   middle can slip in a fake config.
//! * The admin reads and answers at `/admin` on the same address, with the password set in the panel.

use crate::util::{self, now, rand_token};
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, RwLock};

pub const CONF_FILE: &str = "/etc/kanki/emergency.json";
pub const DATA_DIR: &str = "/var/lib/kanki/emergency";
/// prefix of the hash that identifies a user (the app computes the same)
pub const ID_PREFIX: &str = "kanki-emergency-v1:";
/// first line of every signed text (the app checks the same)
const SIGN_PREFIX: &str = "kanki-emergency-v1";

const MAX_TEXT: usize = 2000;
const MAX_IMAGE: usize = 1_500_000;
const KEEP_PER_USER: i64 = 500;

// ------------------------------------------------------------------ config (written by the agent)

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(default)]
pub struct EUser {
    /// username, shown to the admin
    pub u: String,
    /// sha256(ID_PREFIX + subscription code), hex
    pub h: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(default)]
pub struct EmerCfg {
    pub port: u16,
    /// PEM certificate chain and PKCS#8 key; empty = plain HTTP
    pub cert: String,
    pub key: String,
    /// pbkdf2 hash of the admin password (util::hash_password)
    pub admin_hash: String,
    /// PKCS#8 of the ECDSA P-256 signing key, base64
    pub sign_key: String,
    /// shown on the pages
    pub name: String,
    pub users: Vec<EUser>,
    /// automatic SSL: the agent gets a Let's Encrypt certificate for this domain (certbot)
    pub acme_domain: String,
}

impl EmerCfg {
    pub fn tls(&self) -> bool {
        (!self.cert.trim().is_empty() && !self.key.trim().is_empty()) || !self.acme_domain.is_empty()
    }
}

fn acme_files(d: &str) -> (String, String) {
    (format!("/etc/letsencrypt/live/{}/fullchain.pem", d), format!("/etc/letsencrypt/live/{}/privkey.pem", d))
}

pub fn user_hash(code: &str) -> String {
    util::sha256_hex(&format!("{}{}", ID_PREFIX, code))
}

// ------------------------------------------------------------------ signing

/// a new signing key: (PKCS#8 base64, public key as SubjectPublicKeyInfo DER base64)
pub fn gen_sign_key() -> Result<(String, String), String> {
    let rng = ring::rand::SystemRandom::new();
    let doc = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).map_err(|_| "cannot make a key".to_string())?;
    let pubk = public_spki(doc.as_ref())?;
    Ok((util::b64(doc.as_ref()), pubk))
}

/// SubjectPublicKeyInfo (DER, base64) of a PKCS#8 key: what Java's X509EncodedKeySpec reads
pub fn public_spki(pkcs8: &[u8]) -> Result<String, String> {
    let rng = ring::rand::SystemRandom::new();
    let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8, &rng).map_err(|_| "bad signing key".to_string())?;
    // fixed header for an id-ecPublicKey / prime256v1 key with a 65-byte uncompressed point
    let mut der = hex::decode("3059301306072a8648ce3d020106082a8648ce3d030107034200").unwrap_or_default();
    der.extend_from_slice(kp.public_key().as_ref());
    Ok(util::b64(&der))
}

/// the exact text that is signed for a message (the app rebuilds it the same way)
pub fn signed_text(id: i64, user: &str, ts: i64, kind: &str, payload: &str) -> String {
    format!("{}\n{}\n{}\n{}\n{}\n{}", SIGN_PREFIX, id, user, ts, kind, payload)
}

fn sign(key: &EcdsaKeyPair, text: &str) -> String {
    let rng = ring::rand::SystemRandom::new();
    key.sign(&rng, text.as_bytes()).map(|s| util::b64(s.as_ref())).unwrap_or_default()
}

// ------------------------------------------------------------------ server state

struct Live {
    /// user hash -> username
    users: HashMap<String, String>,
    admin_hash: String,
    signer: Option<EcdsaKeyPair>,
    name: String,
}

struct Srv {
    db: Mutex<Connection>,
    live: RwLock<Live>,
    /// admin session token -> expiry
    sessions: Mutex<HashMap<String, i64>>,
    /// rate limits: key -> recent hit times
    hits: Mutex<HashMap<String, Vec<i64>>>,
}

type St = State<Arc<Srv>>;

/// the client address: the first X-Forwarded-For (behind a CDN) or the TCP peer
#[derive(Clone, Copy)]
struct Peer(SocketAddr);

fn client_key(h: &HeaderMap, p: &Peer) -> String {
    h.get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| p.0.ip().to_string())
}

impl Srv {
    /// true when `key` has had fewer than `max` hits in the last `secs` (and counts this one)
    fn allow(&self, key: &str, max: usize, secs: i64) -> bool {
        let t = now();
        let mut m = self.hits.lock().unwrap_or_else(|e| e.into_inner());
        if m.len() > 20_000 {
            m.retain(|_, v| v.last().map(|x| t - x < 3600).unwrap_or(false));
        }
        let v = m.entry(key.to_string()).or_default();
        v.retain(|x| t - x < secs);
        if v.len() >= max {
            return false;
        }
        v.push(t);
        true
    }
    fn user_of(&self, h: &HeaderMap) -> Option<String> {
        let id = h.get("x-kanki-id")?.to_str().ok()?.trim().to_lowercase();
        if id.len() != 64 || !id.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        self.live.read().ok()?.users.get(&id).cloned()
    }
    fn admin_ok(&self, h: &HeaderMap) -> bool {
        let Some(tok) = h.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()).and_then(|v| v.strip_prefix("Bearer ")) else { return false };
        let mut s = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        let t = now();
        s.retain(|_, exp| *exp > t);
        s.keys().any(|k| util::ct_eq(k, tok))
    }
}

fn err(code: StatusCode, msg: &str) -> Response {
    (code, Json(json!({ "error": msg }))).into_response()
}

fn load_cfg() -> Result<EmerCfg, String> {
    let t = std::fs::read_to_string(CONF_FILE).map_err(|e| format!("cannot read {}: {}", CONF_FILE, e))?;
    serde_json::from_str(&t).map_err(|e| format!("{} is not valid: {}", CONF_FILE, e))
}

fn live_of(c: &EmerCfg) -> Live {
    let signer = util_b64d(&c.sign_key).and_then(|k| EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &k, &ring::rand::SystemRandom::new()).ok());
    Live {
        users: c.users.iter().filter(|u| u.h.len() == 64).map(|u| (u.h.to_lowercase(), u.u.clone())).collect(),
        admin_hash: c.admin_hash.clone(),
        signer,
        name: c.name.clone(),
    }
}

fn util_b64d(s: &str) -> Option<Vec<u8>> {
    crate::tunnel::link::b64decode(s.trim())
}

fn open_db(path: &str) -> Connection {
    let c = Connection::open(path).expect("open the chat database");
    c.execute_batch(
        "PRAGMA journal_mode=WAL;
         CREATE TABLE IF NOT EXISTS msgs(
           id INTEGER PRIMARY KEY AUTOINCREMENT, user TEXT NOT NULL, admin INTEGER NOT NULL,
           kind TEXT NOT NULL, body TEXT NOT NULL DEFAULT '', img BLOB, ts INTEGER NOT NULL,
           sig TEXT NOT NULL DEFAULT '', seen INTEGER NOT NULL DEFAULT 0);
         CREATE INDEX IF NOT EXISTS msgs_user ON msgs(user, id);",
    )
    .expect("prepare the chat database");
    // read receipts (3.6.8): an admin message the customer has read in the app
    let _ = c.execute("ALTER TABLE msgs ADD COLUMN rd INTEGER NOT NULL DEFAULT 0", []);
    // the app's own number of a customer message (3.7.7): a message sent again after a lost answer is
    // not stored twice
    let _ = c.execute("ALTER TABLE msgs ADD COLUMN cid INTEGER NOT NULL DEFAULT 0", []);
    let _ = c.execute("CREATE INDEX IF NOT EXISTS msgs_cid ON msgs(user, cid)", []);
    c
}

/// The id of the customer's message with this app number, if it is already stored
fn by_cid(s: &Srv, user: &str, cid: i64) -> Option<i64> {
    if cid <= 0 {
        return None;
    }
    let db = s.db.lock().unwrap_or_else(|e| e.into_inner());
    db.query_row("SELECT id FROM msgs WHERE user=?1 AND cid=?2 AND admin=0", params![user, cid], |r| r.get(0)).ok()
}

fn set_cid(s: &Srv, id: i64, cid: i64) {
    if cid > 0 {
        let db = s.db.lock().unwrap_or_else(|e| e.into_inner());
        let _ = db.execute("UPDATE msgs SET cid=?1 WHERE id=?2", params![cid, id]);
    }
}

/// (the newest admin message the app has, the newest admin message the customer read, the newest
/// customer message the admin read) of a conversation: every message up to each id has that tick
fn ticks_of(db: &Connection, user: &str) -> (i64, i64, i64) {
    let q = |sql: &str| db.query_row(sql, params![user], |r| r.get::<_, i64>(0)).unwrap_or(0);
    (
        q("SELECT COALESCE(MAX(id),0) FROM msgs WHERE user=?1 AND admin=1 AND seen=1"),
        q("SELECT COALESCE(MAX(id),0) FROM msgs WHERE user=?1 AND admin=1 AND rd=1"),
        q("SELECT COALESCE(MAX(id),0) FROM msgs WHERE user=?1 AND admin=0 AND seen=1"),
    )
}

/// image type from its first bytes (only these are accepted)
fn image_type(b: &[u8]) -> Option<&'static str> {
    if b.starts_with(&[0xFF, 0xD8, 0xFF]) {
        Some("image/jpeg")
    } else if b.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some("image/png")
    } else if b.len() > 12 && &b[0..4] == b"RIFF" && &b[8..12] == b"WEBP" {
        Some("image/webp")
    } else {
        None
    }
}

/// stores a message; admin messages are signed. Returns the id.
fn insert(srv: &Srv, user: &str, admin: bool, kind: &str, body: &str, img: Option<&[u8]>) -> Result<i64, String> {
    let ts = now();
    let db = srv.db.lock().unwrap_or_else(|e| e.into_inner());
    db.execute(
        "INSERT INTO msgs(user,admin,kind,body,img,ts,seen) VALUES(?1,?2,?3,?4,?5,?6,?7)",
        params![user, admin as i64, kind, body, img, ts, 0i64],
    )
    .map_err(|e| e.to_string())?;
    let id = db.last_insert_rowid();
    if admin {
        let payload = match img {
            Some(b) => {
                use sha2::{Digest, Sha256};
                let mut h = Sha256::new();
                h.update(b);
                hex::encode(h.finalize())
            }
            None => body.to_string(),
        };
        let sig = match srv.live.read().ok().and_then(|l| l.signer.as_ref().map(|k| sign(k, &signed_text(id, user, ts, kind, &payload)))) {
            Some(s) if !s.is_empty() => s,
            _ => return Err("the signing key is missing: save the emergency settings in the panel again".into()),
        };
        db.execute("UPDATE msgs SET sig=?1 WHERE id=?2", params![sig, id]).map_err(|e| e.to_string())?;
    }
    // keep the newest messages of each user
    let _ = db.execute(
        "DELETE FROM msgs WHERE user=?1 AND id NOT IN (SELECT id FROM msgs WHERE user=?1 ORDER BY id DESC LIMIT ?2)",
        params![user, KEEP_PER_USER],
    );
    Ok(id)
}

fn list(srv: &Srv, user: &str, after: i64) -> Vec<Value> {
    let db = srv.db.lock().unwrap_or_else(|e| e.into_inner());
    // first load (after = 0): the newest 200; later: what came after
    let q = if after == 0 {
        "SELECT * FROM (SELECT id,admin,kind,body,ts,sig,img IS NOT NULL,seen,rd FROM msgs WHERE user=?1 AND id>?2 ORDER BY id DESC LIMIT 200) ORDER BY id"
    } else {
        "SELECT id,admin,kind,body,ts,sig,img IS NOT NULL,seen,rd FROM msgs WHERE user=?1 AND id>?2 ORDER BY id LIMIT 200"
    };
    let Ok(mut st) = db.prepare(q) else { return vec![] };
    let rows = st.query_map(params![user, after], |r| {
        Ok(json!({
            "id": r.get::<_, i64>(0)?, "admin": r.get::<_, i64>(1)? == 1, "kind": r.get::<_, String>(2)?,
            "body": r.get::<_, String>(3)?, "ts": r.get::<_, i64>(4)?, "sig": r.get::<_, String>(5)?, "img": r.get::<_, bool>(6)?, "seen": r.get::<_, i64>(7)? == 1, "read": r.get::<_, i64>(8)? == 1,
        }))
    });
    rows.map(|it| it.flatten().collect()).unwrap_or_default()
}

// ------------------------------------------------------------------ user side (the Kanki app)

#[derive(Deserialize)]
struct After {
    #[serde(default)]
    after: i64,
}

/// unknown ids are counted per client, so codes cannot be guessed
#[allow(clippy::result_large_err)] // the error is the ready axum answer (401/403)
fn user_or_deny(srv: &Srv, h: &HeaderMap, p: &Peer) -> Result<String, Response> {
    let ck = client_key(h, p);
    match srv.user_of(h) {
        Some(u) => Ok(u),
        None => {
            if !srv.allow(&format!("bad:{}", ck), 30, 600) || !srv.allow("bad:all", 2000, 600) {
                return Err(err(StatusCode::TOO_MANY_REQUESTS, "too many tries, wait a few minutes"));
            }
            Err(err(StatusCode::FORBIDDEN, "this subscription is not known here yet"))
        }
    }
}

async fn u_hello(State(s): St, Extension(p): Extension<Peer>, h: HeaderMap) -> Response {
    match user_or_deny(&s, &h, &p) {
        Ok(u) => Json(json!({ "user": u, "name": s.live.read().map(|l| l.name.clone()).unwrap_or_default() })).into_response(),
        Err(r) => r,
    }
}

async fn u_messages(State(s): St, Extension(p): Extension<Peer>, h: HeaderMap, Query(q): Query<After>) -> Response {
    let u = match user_or_deny(&s, &h, &p) {
        Ok(u) => u,
        Err(r) => return r,
    };
    let msgs = list(&s, &u, q.after);
    // the app has them now: the admin sees ✓✓ (delivered); read = the customer opened the chat
    let db = s.db.lock().unwrap_or_else(|e| e.into_inner());
    let _ = db.execute("UPDATE msgs SET seen=1 WHERE user=?1 AND admin=1 AND seen=0", params![u]);
    // the customer's own messages the admin has read (the app shows ✓✓ on every one up to this id)
    let (_, _, admin_read) = ticks_of(&db, &u);
    Json(json!({ "user": u, "messages": msgs, "read_upto": admin_read })).into_response()
}

#[derive(Deserialize)]
struct ReadBody {
    /// the newest admin message the customer has seen on screen
    #[serde(default)]
    upto: i64,
}

/// The app: the customer has read the admin's messages up to `upto` (the admin sees blue ✓✓)
async fn u_read(State(s): St, Extension(p): Extension<Peer>, h: HeaderMap, Json(b): Json<ReadBody>) -> Response {
    let u = match user_or_deny(&s, &h, &p) {
        Ok(u) => u,
        Err(r) => return r,
    };
    let db = s.db.lock().unwrap_or_else(|e| e.into_inner());
    let n = db.execute("UPDATE msgs SET rd=1, seen=1 WHERE user=?1 AND admin=1 AND rd=0 AND id<=?2", params![u, b.upto]).unwrap_or(0);
    Json(json!({ "ok": true, "marked": n })).into_response()
}

#[derive(Deserialize)]
struct SendBody {
    #[serde(default)]
    text: String,
    /// the app's own number for this message (0 = none)
    #[serde(default)]
    cid: i64,
}

async fn u_send(State(s): St, Extension(p): Extension<Peer>, h: HeaderMap, Json(b): Json<SendBody>) -> Response {
    let u = match user_or_deny(&s, &h, &p) {
        Ok(u) => u,
        Err(r) => return r,
    };
    let text = b.text.trim();
    if text.is_empty() || text.chars().count() > MAX_TEXT {
        return err(StatusCode::BAD_REQUEST, "the message is empty or too long");
    }
    // sent again (the answer was lost on the way): the stored one counts
    if let Some(id) = by_cid(&s, &u, b.cid) {
        return Json(json!({ "ok": true, "id": id, "again": true })).into_response();
    }
    if !s.allow(&format!("send:{}", u), 20, 300) {
        return err(StatusCode::TOO_MANY_REQUESTS, "too many messages, wait a few minutes");
    }
    match insert(&s, &u, false, "text", text, None) {
        Ok(id) => {
            set_cid(&s, id, b.cid);
            Json(json!({ "ok": true, "id": id })).into_response()
        }
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, &e),
    }
}

async fn u_image(State(s): St, Extension(p): Extension<Peer>, h: HeaderMap, Query(q): Query<HashMap<String, String>>, body: Bytes) -> Response {
    let u = match user_or_deny(&s, &h, &p) {
        Ok(u) => u,
        Err(r) => return r,
    };
    if body.len() > MAX_IMAGE || image_type(&body).is_none() {
        return err(StatusCode::BAD_REQUEST, "send a JPEG / PNG / WEBP picture smaller than 1.5 MB");
    }
    let cid: i64 = q.get("cid").and_then(|v| v.parse().ok()).unwrap_or(0);
    if let Some(id) = by_cid(&s, &u, cid) {
        return Json(json!({ "ok": true, "id": id, "again": true })).into_response();
    }
    if !s.allow(&format!("img:{}", u), 6, 600) {
        return err(StatusCode::TOO_MANY_REQUESTS, "too many pictures, wait a few minutes");
    }
    match insert(&s, &u, false, "image", "", Some(&body)) {
        Ok(id) => {
            set_cid(&s, id, cid);
            Json(json!({ "ok": true, "id": id })).into_response()
        }
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, &e),
    }
}

fn image_of(s: &Srv, id: i64, user: Option<&str>) -> Response {
    let db = s.db.lock().unwrap_or_else(|e| e.into_inner());
    let r: Option<(String, Vec<u8>)> = db
        .query_row("SELECT user,img FROM msgs WHERE id=?1 AND img IS NOT NULL", params![id], |r| Ok((r.get(0)?, r.get(1)?)))
        .ok();
    match r {
        Some((owner, img)) if user.map(|u| u == owner).unwrap_or(true) => {
            let ct = image_type(&img).unwrap_or("application/octet-stream");
            ([(header::CONTENT_TYPE, ct), (header::CACHE_CONTROL, "private, max-age=86400")], img).into_response()
        }
        _ => err(StatusCode::NOT_FOUND, "not found"),
    }
}

async fn u_image_get(State(s): St, Extension(p): Extension<Peer>, h: HeaderMap, Path(id): Path<i64>) -> Response {
    let u = match user_or_deny(&s, &h, &p) {
        Ok(u) => u,
        Err(r) => return r,
    };
    image_of(&s, id, Some(&u))
}

// ------------------------------------------------------------------ admin side

#[derive(Deserialize)]
struct Login {
    #[serde(default)]
    password: String,
}

async fn a_login(State(s): St, Extension(p): Extension<Peer>, h: HeaderMap, Json(b): Json<Login>) -> Response {
    let ck = client_key(&h, &p);
    // a few tries per address, and a ceiling for everyone together (the address can be spoofed)
    if !s.allow(&format!("login:{}", ck), 8, 600) || !s.allow("login:all", 60, 600) {
        return err(StatusCode::TOO_MANY_REQUESTS, "too many tries, wait 10 minutes");
    }
    let stored = s.live.read().map(|l| l.admin_hash.clone()).unwrap_or_default();
    if stored.is_empty() || !util::check_password(&stored, &b.password) {
        return err(StatusCode::FORBIDDEN, "wrong password");
    }
    let tok = rand_token(48);
    s.sessions.lock().unwrap_or_else(|e| e.into_inner()).insert(tok.clone(), now() + 12 * 3600);
    Json(json!({ "token": tok })).into_response()
}

async fn a_threads(State(s): St, h: HeaderMap) -> Response {
    if !s.admin_ok(&h) {
        return err(StatusCode::UNAUTHORIZED, "sign in");
    }
    let db = s.db.lock().unwrap_or_else(|e| e.into_inner());
    let Ok(mut st) = db.prepare(
        "SELECT user, MAX(id), MAX(ts), SUM(CASE WHEN admin=0 AND seen=0 THEN 1 ELSE 0 END),
                (SELECT CASE WHEN kind='image' THEN '[picture]' ELSE body END FROM msgs m2 WHERE m2.user=m.user ORDER BY id DESC LIMIT 1)
         FROM msgs m GROUP BY user ORDER BY MAX(id) DESC LIMIT 500",
    ) else {
        return err(StatusCode::INTERNAL_SERVER_ERROR, "db");
    };
    let rows: Vec<Value> = st
        .query_map([], |r| Ok(json!({ "user": r.get::<_, String>(0)?, "ts": r.get::<_, i64>(2)?, "unread": r.get::<_, i64>(3)?, "last": r.get::<_, String>(4)? })))
        .map(|it| it.flatten().collect())
        .unwrap_or_default();
    let users = s.live.read().map(|l| l.users.len()).unwrap_or(0);
    Json(json!({ "threads": rows, "customers": users })).into_response()
}

async fn a_thread(State(s): St, h: HeaderMap, Path(user): Path<String>, Query(q): Query<After>) -> Response {
    if !s.admin_ok(&h) {
        return err(StatusCode::UNAUTHORIZED, "sign in");
    }
    let msgs = list(&s, &user, q.after);
    let db = s.db.lock().unwrap_or_else(|e| e.into_inner());
    let _ = db.execute("UPDATE msgs SET seen=1 WHERE user=?1 AND admin=0", params![user]);
    // admin messages up to seen_upto have reached the app (✓✓), up to read_upto the customer read them
    let (seen_upto, read_upto, _) = ticks_of(&db, &user);
    Json(json!({ "messages": msgs, "seen_upto": seen_upto, "read_upto": read_upto })).into_response()
}

#[derive(Deserialize)]
struct AdminSend {
    #[serde(default)]
    user: String,
    #[serde(default)]
    kind: String,
    #[serde(default)]
    text: String,
}

fn known_user(s: &Srv, user: &str) -> bool {
    s.live.read().map(|l| l.users.values().any(|u| u == user)).unwrap_or(false)
        || s.db.lock().unwrap_or_else(|e| e.into_inner()).query_row("SELECT 1 FROM msgs WHERE user=?1 LIMIT 1", params![user], |_| Ok(())).is_ok()
}

async fn a_send(State(s): St, h: HeaderMap, Json(b): Json<AdminSend>) -> Response {
    if !s.admin_ok(&h) {
        return err(StatusCode::UNAUTHORIZED, "sign in");
    }
    let kind = if b.kind == "config" { "config" } else { "text" };
    let text = b.text.trim();
    if text.is_empty() || text.chars().count() > 20_000 {
        return err(StatusCode::BAD_REQUEST, "the message is empty or too long");
    }
    if !known_user(&s, &b.user) {
        return err(StatusCode::NOT_FOUND, "no such user");
    }
    match insert(&s, &b.user, true, kind, text, None) {
        Ok(id) => Json(json!({ "ok": true, "id": id })).into_response(),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, &e),
    }
}

#[derive(Deserialize)]
struct ToUser {
    #[serde(default)]
    user: String,
}

async fn a_image(State(s): St, h: HeaderMap, Query(q): Query<ToUser>, body: Bytes) -> Response {
    if !s.admin_ok(&h) {
        return err(StatusCode::UNAUTHORIZED, "sign in");
    }
    if body.len() > MAX_IMAGE || image_type(&body).is_none() {
        return err(StatusCode::BAD_REQUEST, "send a JPEG / PNG / WEBP picture smaller than 1.5 MB");
    }
    if !known_user(&s, &q.user) {
        return err(StatusCode::NOT_FOUND, "no such user");
    }
    match insert(&s, &q.user, true, "image", "", Some(&body)) {
        Ok(id) => Json(json!({ "ok": true, "id": id })).into_response(),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, &e),
    }
}

async fn a_image_get(State(s): St, h: HeaderMap, Path(id): Path<i64>) -> Response {
    if !s.admin_ok(&h) {
        return err(StatusCode::UNAUTHORIZED, "sign in");
    }
    image_of(&s, id, None)
}

async fn a_users(State(s): St, h: HeaderMap) -> Response {
    if !s.admin_ok(&h) {
        return err(StatusCode::UNAUTHORIZED, "sign in");
    }
    let mut v: Vec<String> = s.live.read().map(|l| l.users.values().cloned().collect()).unwrap_or_default();
    v.sort();
    Json(json!({ "users": v })).into_response()
}

async fn admin_page(State(s): St) -> Response {
    let name = s.live.read().map(|l| l.name.clone()).unwrap_or_default();
    let page = ADMIN_HTML.replace("{{NAME}}", &util::esc(if name.is_empty() { "Kanki" } else { &name }));
    ([(header::CACHE_CONTROL, "no-store"), (header::X_FRAME_OPTIONS, "DENY")], Html(page)).into_response()
}

/// the panel's font, so the admin page looks like the panel without reaching the internet
async fn font() -> Response {
    ([(header::CONTENT_TYPE, "font/woff"), (header::CACHE_CONTROL, "public, max-age=604800")], &include_bytes!("../assets/web/vazirmatn.woff")[..]).into_response()
}

async fn home() -> Response {
    ([(header::CACHE_CONTROL, "no-store")], Html("<!doctype html><meta charset=utf-8><title>Kanki</title><p style=\"font-family:sans-serif\">Kanki</p>")).into_response()
}

fn router(srv: Arc<Srv>) -> Router {
    Router::new()
        .route("/", get(home))
        .route("/admin", get(admin_page))
        .route("/api/e/hello", get(u_hello))
        .route("/api/e/messages", get(u_messages))
        .route("/api/e/send", post(u_send))
        .route("/api/e/read", post(u_read))
        .route("/font.woff", get(font))
        .route("/api/e/image", post(u_image))
        .route("/api/e/image/:id", get(u_image_get))
        .route("/api/a/login", post(a_login))
        .route("/api/a/threads", get(a_threads))
        .route("/api/a/thread/:user", get(a_thread))
        .route("/api/a/send", post(a_send))
        .route("/api/a/image", post(a_image))
        .route("/api/a/image/:id", get(a_image_get))
        .route("/api/a/users", get(a_users))
        .layer(DefaultBodyLimit::max(2 * 1024 * 1024))
        .layer(axum::middleware::map_response(|mut r: Response| async move {
            if !r.headers().contains_key(header::CACHE_CONTROL) {
                r.headers_mut().insert(header::CACHE_CONTROL, header::HeaderValue::from_static("no-store"));
            }
            r
        }))
        .with_state(srv)
}

/// builds the server around an open database (used by `run` and by the tests)
fn make(cfg: &EmerCfg, db: Connection) -> Arc<Srv> {
    Arc::new(Srv { db: Mutex::new(db), live: RwLock::new(live_of(cfg)), sessions: Mutex::new(HashMap::new()), hits: Mutex::new(HashMap::new()) })
}

/// `kanki-panel emergency`: runs until stopped. The customer list and the password are re-read
/// when the agent rewrites the config; a new port or certificate needs a restart (the agent does it).
pub async fn run() {
    let cfg = match load_cfg() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(1);
        }
    };
    if cfg.port == 0 {
        eprintln!("no port in {}", CONF_FILE);
        std::process::exit(1);
    }
    let _ = std::fs::create_dir_all(DATA_DIR);
    let srv = make(&cfg, open_db(&format!("{}/chat.db", DATA_DIR)));
    // keep the customer list and the password in step with the file
    {
        let srv = srv.clone();
        tokio::spawn(async move {
            let mut last = std::fs::metadata(CONF_FILE).and_then(|m| m.modified()).ok();
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                let m = std::fs::metadata(CONF_FILE).and_then(|m| m.modified()).ok();
                if m != last {
                    last = m;
                    if let Ok(c) = load_cfg() {
                        if let Ok(mut l) = srv.live.write() {
                            *l = live_of(&c);
                        }
                    }
                }
            }
        });
    }
    let app = router(srv);
    let addr = format!("0.0.0.0:{}", cfg.port);
    let l = match tokio::net::TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("cannot listen on {}: {}", addr, e);
            std::process::exit(1);
        }
    };
    let tls = if cfg.tls() {
        let _ = std::fs::create_dir_all(DATA_DIR);
        let (cf, kf) = if !cfg.acme_domain.is_empty() {
            acme_files(&cfg.acme_domain)
        } else {
            let (cf, kf) = (format!("{}/tls.crt", DATA_DIR), format!("{}/tls.key", DATA_DIR));
            let _ = std::fs::write(&cf, &cfg.cert);
            let _ = std::fs::write(&kf, &cfg.key);
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&kf, std::fs::Permissions::from_mode(0o600));
            (cf, kf)
        };
        match crate::tunnel::link::tls_acceptor_with(&cf, &kf, &[b"http/1.1"], false) {
            Ok(a) => Some(a),
            Err(e) => {
                eprintln!("the TLS certificate cannot be used: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        None
    };
    eprintln!("kanki emergency chat on {} ({})", addr, if tls.is_some() { "https" } else { "http" });
    // the version this chat runs: after an update the agent / panel restarts it onto the new binary
    let _ = std::fs::write(RUNNING_VER, crate::VERSION);
    loop {
        let Ok((sock, peer)) = l.accept().await else { continue };
        let app = app.clone().layer(Extension(Peer(peer)));
        let tls = tls.clone();
        tokio::spawn(async move {
            let svc = hyper_util::service::TowerToHyperService::new(app);
            let b = hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new());
            match tls {
                Some(acc) => {
                    let Ok(Ok(s)) = tokio::time::timeout(std::time::Duration::from_secs(10), acc.accept(sock)).await else { return };
                    let _ = b.serve_connection(hyper_util::rt::TokioIo::new(s), svc).await;
                }
                None => {
                    let _ = b.serve_connection(hyper_util::rt::TokioIo::new(sock), svc).await;
                }
            }
        });
    }
}

// ------------------------------------------------------------------ deploy (run by the agent on the chosen server)

const UNIT: &str = "/etc/systemd/system/kanki-emergency.service";
const VER_FILE: &str = "/var/lib/kanki/emergency/applied.ver";
const RESTART_FILE: &str = "/var/lib/kanki/emergency/applied.restart";

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

/// the config version this server runs now (sent to the panel, which only sends a new one on change)
pub fn applied_ver() -> String {
    std::fs::read_to_string(VER_FILE).unwrap_or_default().trim().to_string()
}

/// Makes this server run (`Some`) or stop running (`None`) the emergency chat. Blocking: it calls
/// systemctl. Messages are kept when it stops, so turning it on again shows the old chats.
pub fn deploy(cfg: Option<(&EmerCfg, &str)>) -> Result<(), String> {
    let old_domain = std::fs::read_to_string(CONF_FILE).ok().and_then(|t| serde_json::from_str::<EmerCfg>(&t).ok()).map(|o| o.acme_domain).unwrap_or_default();
    let Some((c, ver)) = cfg else {
        // removed from this server: its port is closed and its certificate is no longer renewed
        crate::fw::close("emergency");
        if !old_domain.is_empty() {
            crate::certbot::forget(&old_domain, "kanki-emergency.service");
        }
        if std::path::Path::new(UNIT).exists() {
            eprintln!("emergency chat: stopping");
            let _ = sh("systemctl disable --now -q kanki-emergency.service 2>&1");
            let _ = std::fs::remove_file(UNIT);
            let _ = sh("systemctl daemon-reload");
        }
        let _ = std::fs::remove_file(CONF_FILE);
        let _ = std::fs::remove_file(VER_FILE);
        let _ = std::fs::remove_file(RESTART_FILE);
        return Ok(());
    };
    let _ = std::fs::create_dir_all("/etc/kanki");
    let _ = std::fs::create_dir_all(DATA_DIR);
    let text = serde_json::to_string(c).map_err(|e| e.to_string())?;
    if std::fs::read_to_string(CONF_FILE).map(|t| t != text).unwrap_or(true) {
        // written beside and renamed, so the server never reads half a file
        let tmp = format!("{}.new", CONF_FILE);
        std::fs::write(&tmp, &text).map_err(|e| format!("cannot write {}: {}", CONF_FILE, e))?;
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
        }
        std::fs::rename(&tmp, CONF_FILE).map_err(|e| e.to_string())?;
    }
    let exe = std::env::current_exe().map_err(|e| e.to_string())?.to_string_lossy().replace(" (deleted)", "");
    let unit = format!(
        "# written by kanki-panel\n[Unit]\nDescription=Kanki emergency chat\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nExecStart={} emergency\nRestart=always\nRestartSec=3\nLimitNOFILE=65536\n\n[Install]\nWantedBy=multi-user.target\n",
        exe
    );
    let unit_changed = std::fs::read_to_string(UNIT).map(|t| t != unit).unwrap_or(true);
    if unit_changed {
        std::fs::write(UNIT, &unit).map_err(|e| format!("cannot write {}: {}", UNIT, e))?;
        let _ = sh("systemctl daemon-reload");
        let _ = sh("systemctl enable -q kanki-emergency.service");
    }
    if !old_domain.is_empty() && old_domain != c.acme_domain {
        crate::certbot::forget(&old_domain, "kanki-emergency.service");
    }
    // automatic SSL: get the certificate once (certbot renews it and restarts the chat by itself);
    // whatever holds port 80 (Caddy, nginx …) is set aside for those seconds and given back right after
    if !c.acme_domain.is_empty() {
        crate::certbot::ensure(&c.acme_domain, &["kanki-emergency.service"])?;
    }
    // a new port or certificate needs a restart; the customer list and the password are re-read live
    let restart_key = util::sha256_hex(&format!("{}|{}|{}|{}", c.port, c.cert, c.key, c.acme_domain));
    let old_key = std::fs::read_to_string(RESTART_FILE).unwrap_or_default();
    let active = sh("systemctl is-active --quiet kanki-emergency.service").0;
    if unit_changed || old_key.trim() != restart_key || !active {
        let (ok, out) = sh("systemctl restart kanki-emergency.service 2>&1");
        if !ok {
            return Err(format!("systemctl restart kanki-emergency: {}", out.lines().last().unwrap_or("")));
        }
        let _ = std::fs::write(RESTART_FILE, &restart_key);
        eprintln!("emergency chat: started on port {}", c.port);
    }
    // the port must be reachable from inside Iran (an old port is closed again)
    crate::fw::sync("emergency", vec![crate::fw::rule(c.port, false)]);
    let _ = std::fs::write(VER_FILE, ver);
    Ok(())
}

const RUNNING_VER: &str = "/var/lib/kanki/emergency/running.ver";

/// After the agent or the panel was updated, the chat still runs the old binary in memory:
/// restart it once so it runs the new one too. Blocking (systemctl).
pub fn restart_if_outdated() {
    let Ok(v) = std::fs::read_to_string(RUNNING_VER) else { return };
    if v.trim() != crate::VERSION && std::path::Path::new(UNIT).exists() && running() {
        eprintln!("emergency chat: restarting onto v{}", crate::VERSION);
        let _ = sh("systemctl restart kanki-emergency.service");
    }
}

/// is the chat service running on this machine?
pub fn running() -> bool {
    sh("systemctl is-active --quiet kanki-emergency.service").0
}

/// what the agent reports about the chat on this server
pub fn status() -> Value {
    if !std::path::Path::new(UNIT).exists() {
        return Value::Null;
    }
    let active = sh("systemctl is-active --quiet kanki-emergency.service").0;
    let unread = Connection::open_with_flags(format!("{}/chat.db", DATA_DIR), rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
        .ok()
        .and_then(|c| c.query_row("SELECT COUNT(*) FROM msgs WHERE admin=0 AND seen=0", [], |r| r.get::<_, i64>(0)).ok())
        .unwrap_or(0);
    let err = if active {
        String::new()
    } else {
        sh("journalctl -u kanki-emergency.service -n 5 --no-pager -o cat 2>/dev/null").1.lines().last().unwrap_or("not running").to_string()
    };
    json!({ "active": active, "unread": unread, "error": err, "ver": applied_ver() })
}

// ------------------------------------------------------------------ admin page

const ADMIN_HTML: &str = include_str!("../assets/web/emergency-admin.html");

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    fn srv() -> (Arc<Srv>, String, String) {
        let (sk, pk) = gen_sign_key().unwrap();
        let cfg = EmerCfg {
            port: 1,
            admin_hash: util::hash_password("pass-1234"),
            sign_key: sk,
            name: "Test".into(),
            users: vec![EUser { u: "ali".into(), h: user_hash("kanki-4-abcd1234") }],
            ..Default::default()
        };
        (make(&cfg, open_db(":memory:")), pk, user_hash("kanki-4-abcd1234"))
    }

    async fn call(s: &Arc<Srv>, req: Request<Body>) -> (StatusCode, Value) {
        let r = router(s.clone()).layer(Extension(Peer("1.2.3.4:5".parse().unwrap()))).oneshot(req).await.unwrap();
        let st = r.status();
        let b = axum::body::to_bytes(r.into_body(), 1 << 22).await.unwrap();
        (st, serde_json::from_slice(&b).unwrap_or(Value::Null))
    }

    fn req(m: &str, uri: &str, hdr: &[(&str, &str)], body: &str) -> Request<Body> {
        let mut b = Request::builder().method(m).uri(uri).header("content-type", "application/json");
        for (k, v) in hdr {
            b = b.header(*k, *v);
        }
        b.body(Body::from(body.to_string())).unwrap()
    }

    #[tokio::test]
    async fn customer_and_admin_talk_and_admin_messages_are_signed() {
        let (s, pk, id) = srv();
        // a stranger is refused
        let (st, _) = call(&s, req("GET", "/api/e/messages", &[("x-kanki-id", &"0".repeat(64))], "")).await;
        assert_eq!(st, StatusCode::FORBIDDEN);
        // the customer writes
        let (st, _) = call(&s, req("POST", "/api/e/send", &[("x-kanki-id", &id)], r#"{"text":"salam, config mikham"}"#)).await;
        assert_eq!(st, StatusCode::OK);
        // the admin signs in (wrong password first)
        let (st, _) = call(&s, req("POST", "/api/a/login", &[], r#"{"password":"nope"}"#)).await;
        assert_eq!(st, StatusCode::FORBIDDEN);
        let (_, v) = call(&s, req("POST", "/api/a/login", &[], r#"{"password":"pass-1234"}"#)).await;
        let tok = format!("Bearer {}", v["token"].as_str().unwrap());
        let (_, v) = call(&s, req("GET", "/api/a/threads", &[("authorization", &tok)], "")).await;
        assert_eq!(v["threads"][0]["user"], "ali");
        assert_eq!(v["threads"][0]["unread"], 1);
        // the admin answers with a config
        let (st, _) = call(&s, req("POST", "/api/a/send", &[("authorization", &tok)], r#"{"user":"ali","kind":"config","text":"hysteria2://x@y:1"}"#)).await;
        assert_eq!(st, StatusCode::OK);
        // without a session the admin side is closed
        let (st, _) = call(&s, req("POST", "/api/a/send", &[], r#"{"user":"ali","text":"x"}"#)).await;
        assert_eq!(st, StatusCode::UNAUTHORIZED);
        // the customer sees both; the admin one carries a valid signature
        let (_, v) = call(&s, req("GET", "/api/e/messages", &[("x-kanki-id", &id)], "")).await;
        let m = v["messages"].as_array().unwrap();
        assert_eq!(m.len(), 2);
        let a = &m[1];
        assert_eq!(a["admin"], true);
        let text = signed_text(a["id"].as_i64().unwrap(), "ali", a["ts"].as_i64().unwrap(), "config", "hysteria2://x@y:1");
        let spki = util_b64d(&pk).unwrap();
        // the last 65 bytes of the SubjectPublicKeyInfo are the point ring verifies with
        let point = &spki[spki.len() - 65..];
        let key = ring::signature::UnparsedPublicKey::new(&ring::signature::ECDSA_P256_SHA256_ASN1, point);
        assert!(key.verify(text.as_bytes(), &util_b64d(a["sig"].as_str().unwrap()).unwrap()).is_ok());
        // a changed text does not verify
        assert!(key.verify(text.replace("y:1", "evil:1").as_bytes(), &util_b64d(a["sig"].as_str().unwrap()).unwrap()).is_err());
    }

    #[tokio::test]
    async fn a_message_sent_again_is_stored_once() {
        let (s, _, id) = srv();
        let body = r#"{"text":"salam","cid":1761030000123}"#;
        let (_, a) = call(&s, req("POST", "/api/e/send", &[("x-kanki-id", &id)], body)).await;
        // the answer was lost: the app sends the same message again
        let (st, b) = call(&s, req("POST", "/api/e/send", &[("x-kanki-id", &id)], body)).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(a["id"], b["id"]);
        assert_eq!(b["again"], true);
        let (_, v) = call(&s, req("GET", "/api/e/messages", &[("x-kanki-id", &id)], "")).await;
        assert_eq!(v["messages"].as_array().unwrap().len(), 1);
        // another message (another number, or none) is stored
        let (_, c) = call(&s, req("POST", "/api/e/send", &[("x-kanki-id", &id)], r#"{"text":"salam"}"#)).await;
        assert_ne!(a["id"], c["id"]);
    }

    #[tokio::test]
    async fn read_ticks_on_both_sides() {
        let (s, _, id) = srv();
        let (_, v) = call(&s, req("POST", "/api/a/login", &[], r#"{"password":"pass-1234"}"#)).await;
        let tok = format!("Bearer {}", v["token"].as_str().unwrap());
        let (_, v) = call(&s, req("POST", "/api/e/send", &[("x-kanki-id", &id)], r#"{"text":"salam"}"#)).await;
        let mine = v["id"].as_i64().unwrap();
        // the admin has not opened the conversation: the customer's message has one tick
        let (_, v) = call(&s, req("GET", "/api/e/messages", &[("x-kanki-id", &id)], "")).await;
        assert_eq!(v["read_upto"], 0);
        // the admin opens it and answers
        let (_, v) = call(&s, req("GET", "/api/a/thread/ali", &[("authorization", &tok)], "")).await;
        assert_eq!((v["seen_upto"].as_i64(), v["read_upto"].as_i64()), (Some(0), Some(0)));
        let (_, v) = call(&s, req("POST", "/api/a/send", &[("authorization", &tok)], r#"{"user":"ali","text":"salam, befarmaeed"}"#)).await;
        let ans = v["id"].as_i64().unwrap();
        // the app fetches: the customer's message was read, the answer is delivered
        let (_, v) = call(&s, req("GET", "/api/e/messages", &[("x-kanki-id", &id)], "")).await;
        assert_eq!(v["read_upto"].as_i64(), Some(mine));
        let (_, v) = call(&s, req("GET", "/api/a/thread/ali", &[("authorization", &tok)], "")).await;
        assert_eq!((v["seen_upto"].as_i64(), v["read_upto"].as_i64()), (Some(ans), Some(0)));
        // the customer reads it in the app
        let (st, v) = call(&s, req("POST", "/api/e/read", &[("x-kanki-id", &id)], &format!(r#"{{"upto":{}}}"#, ans))).await;
        assert_eq!((st, v["marked"].as_i64()), (StatusCode::OK, Some(1)));
        let (_, v) = call(&s, req("GET", "/api/a/thread/ali", &[("authorization", &tok)], "")).await;
        assert_eq!(v["read_upto"].as_i64(), Some(ans));
        assert_eq!(v["messages"][1]["read"], true);
        // a stranger cannot mark anything
        let (st, _) = call(&s, req("POST", "/api/e/read", &[("x-kanki-id", &"0".repeat(64))], r#"{"upto":99}"#)).await;
        assert_eq!(st, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn pictures_are_checked_and_only_the_owner_sees_them() {
        let (s, _, id) = srv();
        let png = {
            let mut v = b"\x89PNG\r\n\x1a\n".to_vec();
            v.extend_from_slice(&[0u8; 100]);
            v
        };
        let mk = |body: Vec<u8>, id: &str| Request::builder().method("POST").uri("/api/e/image").header("x-kanki-id", id).body(Body::from(body)).unwrap();
        let r = router(s.clone()).layer(Extension(Peer("1.2.3.4:5".parse().unwrap()))).oneshot(mk(b"not a picture".to_vec(), &id)).await.unwrap();
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
        let r = router(s.clone()).layer(Extension(Peer("1.2.3.4:5".parse().unwrap()))).oneshot(mk(png.clone(), &id)).await.unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        let (_, v) = call(&s, req("GET", "/api/e/messages", &[("x-kanki-id", &id)], "")).await;
        let mid = v["messages"][0]["id"].as_i64().unwrap();
        assert_eq!(v["messages"][0]["img"], true);
        // another id cannot read it
        let (st, _) = call(&s, req("GET", &format!("/api/e/image/{}", mid), &[("x-kanki-id", &"1".repeat(64))], "")).await;
        assert_eq!(st, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn guessing_ids_and_passwords_is_throttled() {
        let (s, _, _) = srv();
        let mut last = StatusCode::OK;
        for _ in 0..40 {
            last = call(&s, req("GET", "/api/e/messages", &[("x-kanki-id", &"2".repeat(64))], "")).await.0;
        }
        assert_eq!(last, StatusCode::TOO_MANY_REQUESTS);
        for _ in 0..10 {
            last = call(&s, req("POST", "/api/a/login", &[], r#"{"password":"x"}"#)).await.0;
        }
        assert_eq!(last, StatusCode::TOO_MANY_REQUESTS);
    }

    #[test]
    fn user_hash_is_stable() {
        // the Kanki app computes the same value (see Emergency.kt)
        assert_eq!(user_hash("kanki-4-abcd1234"), util::sha256_hex("kanki-emergency-v1:kanki-4-abcd1234"));
    }
}
