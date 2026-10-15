//! DNS over HTTPS (RFC 8484) on the server's own name, and the address registration the app calls.
//! `/dns-query/<token>` knows the user by its token; a bare `/dns-query` only serves allowed addresses.
use super::engine::Engine;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Router};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

#[derive(Clone, Copy)]
struct Peer(IpAddr);

type St = State<Arc<Engine>>;

pub async fn serve<S>(eng: Arc<Engine>, stream: S, ip: IpAddr)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let app = Router::new()
        .route("/dns-query", get(q_get).post(q_post))
        .route("/dns-query/:token", get(qt_get).post(qt_post))
        .route("/r/:token", get(register).post(register))
        .route("/", get(|| async { "Kanki DNS" }))
        .layer(axum::extract::DefaultBodyLimit::max(8 * 1024))
        .layer(Extension(Peer(ip)))
        .with_state(eng);
    let svc = hyper_util::service::TowerToHyperService::new(app);
    let b = hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new());
    let _ = b.serve_connection(hyper_util::rt::TokioIo::new(stream), svc).await;
}

/// base64url without padding (the `dns` parameter of a GET)
fn b64url(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in s.trim_end_matches('=').bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' | b'+' => 62,
            b'_' | b'/' => 63,
            _ => return None,
        } as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

fn user_of(eng: &Engine, ip: IpAddr, token: Option<&str>) -> Option<i64> {
    match token {
        Some(t) => {
            let uid = eng.live().cfg.users.iter().find(|u| !u.token.is_empty() && u.token.eq_ignore_ascii_case(t)).map(|u| u.id)?;
            eng.allow(ip, uid);
            Some(uid)
        }
        None => eng.who(ip),
    }
}

async fn reply(eng: &Engine, msg: &[u8], who: Option<i64>) -> Response {
    if msg.len() < 12 || msg.len() > 4096 {
        return (StatusCode::BAD_REQUEST, "bad dns message").into_response();
    }
    match eng.answer(msg, who).await {
        Some(r) => {
            let ttl = super::wire::min_ttl(&r, 60).unwrap_or(0).min(3600);
            ([(header::CONTENT_TYPE, "application/dns-message".to_string()), (header::CACHE_CONTROL, format!("max-age={}", ttl))], r).into_response()
        }
        None => (StatusCode::BAD_REQUEST, "bad dns message").into_response(),
    }
}

async fn get_common(eng: &Engine, ip: IpAddr, token: Option<&str>, q: &HashMap<String, String>) -> Response {
    let Some(msg) = q.get("dns").and_then(|d| b64url(d)) else { return (StatusCode::BAD_REQUEST, "missing dns").into_response() };
    reply(eng, &msg, user_of(eng, ip, token)).await
}

async fn post_common(eng: &Engine, ip: IpAddr, token: Option<&str>, h: &HeaderMap, body: &[u8]) -> Response {
    let ct = h.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("");
    if !ct.starts_with("application/dns-message") {
        return (StatusCode::UNSUPPORTED_MEDIA_TYPE, "application/dns-message only").into_response();
    }
    reply(eng, body, user_of(eng, ip, token)).await
}

async fn q_get(State(e): St, Extension(p): Extension<Peer>, Query(q): Query<HashMap<String, String>>) -> Response {
    get_common(&e, p.0, None, &q).await
}

async fn q_post(State(e): St, Extension(p): Extension<Peer>, h: HeaderMap, body: Bytes) -> Response {
    post_common(&e, p.0, None, &h, &body).await
}

async fn qt_get(State(e): St, Extension(p): Extension<Peer>, Path(t): Path<String>, Query(q): Query<HashMap<String, String>>) -> Response {
    get_common(&e, p.0, Some(&t), &q).await
}

async fn qt_post(State(e): St, Extension(p): Extension<Peer>, Path(t): Path<String>, h: HeaderMap, body: Bytes) -> Response {
    post_common(&e, p.0, Some(&t), &h, &body).await
}

/// The app calls this whenever its network changes: the caller's address is allowed for this user.
async fn register(State(e): St, Extension(p): Extension<Peer>, Path(t): Path<String>) -> Response {
    let ok = user_of(&e, p.0, Some(&t)).is_some();
    let code = if ok { StatusCode::OK } else { StatusCode::NOT_FOUND };
    (code, [(header::CACHE_CONTROL, "no-store")], axum::Json(serde_json::json!({ "ok": ok, "ip": p.0.to_string() }))).into_response()
}

#[cfg(test)]
mod tests {
    #[test]
    fn decodes_base64url() {
        // RFC 8484 example query for www.example.com
        let d = super::b64url("AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB").unwrap();
        let q = super::super::wire::parse_query(&d).unwrap();
        assert_eq!(q.name, "www.example.com");
        assert!(super::b64url("a b").is_none());
    }
}
