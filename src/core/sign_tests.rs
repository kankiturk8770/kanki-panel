//! Signed requests over HTTP (3.65): a node's agent routes and the server agents' reports refuse what is
//! unsigned, old, changed or sent twice; the bare token of before is refused where it is no longer valid.

use crate::App;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{json, Value};
use std::sync::Arc;
use tower::ServiceExt;

const NODE_TOKEN: &str = "node-secret-0123456789abcdef0123456789";

async fn send(router: axum::Router, r: Request<Body>) -> (StatusCode, String) {
    let res = router.oneshot(r).await.unwrap();
    let st = res.status();
    let b = axum::body::to_bytes(res.into_body(), 1 << 20).await.unwrap();
    (st, String::from_utf8_lossy(&b).to_string())
}

fn node_req(path: &str, body: &[u8], sign_with: Option<&str>, bare: Option<&str>) -> Request<Body> {
    let mut r = Request::post(path).header("content-type", "application/json");
    if let Some(k) = sign_with {
        for (h, v) in crate::sign::headers(k, "POST", path, body) {
            r = r.header(h, v);
        }
    }
    if let Some(t) = bare {
        r = r.header("X-Node-Token", t);
    }
    r.body(Body::from(body.to_vec())).unwrap()
}

#[tokio::test]
async fn a_node_takes_only_requests_the_panel_signed() {
    let app = crate::test_app_env(&[("NODE_TOKEN", NODE_TOKEN)]);
    let router = || crate::api::node_router(app.clone());
    // a body that does nothing on this machine: an unknown recorder action answers without touching it
    let body = br#"{"action":"nothing-here"}"#;
    let path = "/agent/kmix/record";
    // nothing, the bare token of before, a wrong key: 401 before any handler runs
    for (sign, bare) in [(None, None), (None, Some(NODE_TOKEN)), (Some("not-the-token"), None), (Some(""), None)] {
        let (st, b) = send(router(), node_req(path, body, sign, bare)).await;
        assert_eq!(st, StatusCode::UNAUTHORIZED, "{:?} {:?}: {}", sign, bare, b);
    }
    // the right signature passes, once
    let r = node_req(path, body, Some(NODE_TOKEN), None);
    let replay = {
        let mut x = Request::post(path).header("content-type", "application/json");
        for (k, v) in r.headers() {
            x = x.header(k, v);
        }
        x.body(Body::from(body.to_vec())).unwrap()
    };
    let (st, b) = send(router(), r).await;
    assert_ne!(st, StatusCode::UNAUTHORIZED, "{}", b);
    let (st, b) = send(router(), replay).await;
    assert_eq!((st, b.contains("replayed")), (StatusCode::UNAUTHORIZED, true), "{}", b);
    // signed for one body, sent with another: refused
    let mut r = Request::post(path).header("content-type", "application/json");
    for (k, v) in crate::sign::headers(NODE_TOKEN, "POST", path, body) {
        r = r.header(k, v);
    }
    let (st, _) = send(router(), r.body(Body::from(br#"{"action":"clear"}"#.to_vec())).unwrap()).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    // signed for another route: refused
    let mut r = Request::post("/agent/remove").header("content-type", "application/json");
    for (k, v) in crate::sign::headers(NODE_TOKEN, "POST", path, b"") {
        r = r.header(k, v);
    }
    let (st, _) = send(router(), r.body(Body::empty()).unwrap()).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    // a node without a token takes nothing at all
    let bare = crate::test_app();
    let (st, _) = send(crate::api::node_router(bare), node_req(path, body, Some(""), None)).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn an_oversized_request_is_refused_before_it_is_read_whole() {
    let app = crate::test_app_env(&[("NODE_TOKEN", NODE_TOKEN)]);
    let big = vec![b'x'; 3 * 1024 * 1024];
    let (st, _) = send(crate::api::node_router(app), node_req("/agent/sync", &big, Some(NODE_TOKEN), None)).await;
    assert_eq!(st, StatusCode::PAYLOAD_TOO_LARGE);
}

fn add_server(app: &Arc<App>, id: &str, token: &str, signed: bool) {
    let mut list = crate::tunnel::panel::servers(app);
    list.push(crate::tunnel::panel::TServer { id: id.into(), name: id.into(), token: token.into(), signed, ..Default::default() });
    crate::tunnel::panel::save_servers(app, &list);
}

fn report(body: &Value, sign_with: Option<&str>) -> Request<Body> {
    let raw = serde_json::to_vec(body).unwrap();
    let mut r = Request::post(crate::tunnel::panel::REPORT_PATH).header("content-type", "application/json");
    if let Some(k) = sign_with {
        for (h, v) in crate::sign::headers(k, "POST", crate::tunnel::panel::REPORT_PATH, &raw) {
            r = r.header(h, v);
        }
    }
    r.body(Body::from(raw)).unwrap()
}

#[tokio::test]
async fn a_server_agent_signs_its_reports_and_cannot_go_back() {
    let app = crate::test_app();
    let tok = "agent-secret-0123456789abcdef01234567";
    add_server(&app, "sg1", tok, false);
    let router = || crate::api::master_router(app.clone());
    // an agent from before: the bare token still works while it never signed
    let (st, b) = send(router(), report(&json!({"id": "sg1", "token": tok, "version": "3.64.0"}), None)).await;
    assert_eq!(st, StatusCode::OK, "{}", b);
    let (st, _) = send(router(), report(&json!({"id": "sg1", "token": "wrong", "version": "3.64.0"}), None)).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    // a signature with another key, or none matching the body: refused
    let (st, _) = send(router(), report(&json!({"id": "sg1", "version": "3.65.0"}), Some("another-key"))).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    // signed: taken, and the server is marked
    let (st, b) = send(router(), report(&json!({"id": "sg1", "version": "3.65.0"}), Some(tok))).await;
    assert_eq!(st, StatusCode::OK, "{}", b);
    assert!(crate::tunnel::panel::servers(&app).iter().any(|s| s.id == "sg1" && s.signed));
    // from now on the bare token is not enough, even the right one (a stolen token of an old log)
    let (st, b) = send(router(), report(&json!({"id": "sg1", "token": tok, "version": "3.64.0"}), None)).await;
    assert_eq!((st, b.contains("unsigned")), (StatusCode::UNAUTHORIZED, true), "{}", b);
    // not JSON: refused before anything
    let (st, _) = send(router(), Request::post(crate::tunnel::panel::REPORT_PATH).body(Body::from("not json")).unwrap()).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
}

#[test]
fn hysteria_must_send_this_machines_key_once_it_has_one() {
    let key = "k".repeat(48);
    assert!(!crate::api::hy2_key_ok(None, false, None), "3.68: no key file is no login (fail closed)");
    assert!(crate::api::hy2_key_ok(None, true, None), "an older Hysteria kept without the key on purpose");
    assert!(crate::api::hy2_key_ok(Some(&key), false, Some(&format!("k={}", key))));
    assert!(crate::api::hy2_key_ok(Some(&key), true, Some(&format!("x=1&k={}", key))));
    for q in [None, Some(""), Some("k="), Some("k=kkk"), Some("kk=x")] {
        assert!(!crate::api::hy2_key_ok(Some(&key), true, q), "{:?}", q);
    }
}
