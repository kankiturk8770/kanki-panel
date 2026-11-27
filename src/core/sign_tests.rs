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

/// A signed request (method POST to `path`) with the given body, and its nonce
fn signed_req(path: &str, body: &Value, key: &str) -> (Request<Body>, String) {
    let raw = serde_json::to_vec(body).unwrap();
    let hs = crate::sign::headers(key, "POST", path, &raw);
    let nonce = hs.iter().find(|(k, _)| *k == crate::sign::NONCE).map(|(_, v)| v.clone()).unwrap();
    let mut r = Request::post(path).header("content-type", "application/json");
    for (h, v) in hs {
        r = r.header(h, v);
    }
    (r.body(Body::from(raw)).unwrap(), nonce)
}

/// status, headers as reqwest has them (what the agent checks), body
async fn send_h(router: axum::Router, r: Request<Body>) -> (StatusCode, reqwest::header::HeaderMap, Vec<u8>) {
    let res = router.oneshot(r).await.unwrap();
    let st = res.status();
    let mut h = reqwest::header::HeaderMap::new();
    for (k, v) in res.headers() {
        h.insert(k.clone(), v.clone());
    }
    let b = axum::body::to_bytes(res.into_body(), 64 << 20).await.unwrap();
    (st, h, b.to_vec())
}

/// 3.69: the panel's answer to a signed report is signed with the server's token and bound to that report: the
/// agent checks it (a changed answer, or the answer to another report, is refused); the «gone» of a removed
/// server is signed with its old token, so a man in the middle cannot make an agent uninstall itself
#[tokio::test]
async fn the_panel_signs_its_answers_to_the_agents() {
    let app = crate::test_app();
    let tok = "agent-secret-for-replies-0123456789abcd";
    add_server(&app, "sr1", tok, true);
    let router = || crate::api::master_router(app.clone());
    let (r, nonce) = signed_req(crate::tunnel::panel::REPORT_PATH, &json!({"id": "sr1", "version": "3.69.0"}), tok);
    let (st, h, body) = send_h(router(), r).await;
    assert_eq!(st, StatusCode::OK);
    assert!(crate::sign::reply_signed(&h));
    assert_eq!(crate::sign::verify_reply(tok, &nonce, &h, 200, &body, crate::util::now()), Ok(()));
    // a byte of the answer changed (another tunnel list): refused
    let mut bad = body.clone();
    bad[1] ^= 1;
    assert!(crate::sign::verify_reply(tok, &nonce, &h, 200, &bad, crate::util::now()).is_err());
    // the same answer played back to the next report: refused
    let (_, other) = signed_req(crate::tunnel::panel::REPORT_PATH, &json!({"id": "sr1"}), tok);
    assert!(crate::sign::verify_reply(tok, &other, &h, 200, &body, crate::util::now()).is_err());
    // removed: the «gone» is signed with the token it had
    crate::tunnel::panel::delete_server(&app, "sr1", true).unwrap();
    let (r, nonce) = signed_req(crate::tunnel::panel::REPORT_PATH, &json!({"id": "sr1", "version": "3.69.0"}), tok);
    let (st, h, body) = send_h(router(), r).await;
    assert_eq!(st, StatusCode::GONE);
    assert_eq!(crate::sign::verify_reply(tok, &nonce, &h, 410, &body, crate::util::now()), Ok(()));
    // a report signed with another key gets the plain «gone» (nothing to sign it with that the agent trusts)
    let (r, _) = signed_req(crate::tunnel::panel::REPORT_PATH, &json!({"id": "sr1"}), "not-the-token");
    let (st, h, _) = send_h(router(), r).await;
    assert_eq!((st, crate::sign::reply_signed(&h)), (StatusCode::GONE, false));
}

/// 3.69: the downloads of a server agent (program, Hysteria2, Xray): signed, or the body token only until that
/// server signed one; another server's token or key opens nothing
#[tokio::test]
async fn agent_downloads_are_signed_and_cannot_go_back_to_the_body_token() {
    let app = crate::test_app();
    let (tok, other) = ("agent-secret-dl-0123456789abcdef0123", "agent-secret-other-0123456789abcdef");
    add_server(&app, "sd1", tok, true);
    add_server(&app, "sd2", other, true);
    let router = || crate::api::master_router(app.clone());
    let path = crate::tunnel::panel::HY2BIN_PATH;
    let check = json!({"id": "sd1", "arch": "x86_64", "check": true});
    // no token, a wrong one, another server's: refused
    for t in ["", "wrong", other] {
        let mut b = check.clone();
        b["token"] = json!(t);
        let (st, _) = send(router(), Request::post(path).header("content-type", "application/json").body(Body::from(b.to_string())).unwrap()).await;
        assert_eq!(st, StatusCode::FORBIDDEN, "{}", t);
    }
    // an agent from before: the body token still works
    let mut b = check.clone();
    b["token"] = json!(tok);
    let (st, body) = send(router(), Request::post(path).header("content-type", "application/json").body(Body::from(b.to_string())).unwrap()).await;
    assert_eq!(st, StatusCode::OK, "{}", body);
    // it always says «have»: an agent of before never uploads its own copy any more, and the upload route is gone
    assert!(body.contains("\"have\":true"), "{}", body);
    let (st, _) = send(router(), Request::post("/tunnel/hy2bin/put").header("x-id", "sd1").header("x-token", tok).body(Body::from(vec![0u8; 64])).unwrap()).await;
    assert_eq!(st, StatusCode::GONE);
    // signed with another server's key: refused; with its own: taken, answer signed
    let (r, _) = signed_req(path, &check, other);
    assert_eq!(send(router(), r).await.0, StatusCode::UNAUTHORIZED);
    let (r, nonce) = signed_req(path, &check, tok);
    let (st, h, body) = send_h(router(), r).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(crate::sign::verify_reply(tok, &nonce, &h, 200, &body, crate::util::now()), Ok(()));
    // from now on the body token is refused for this server, the other one keeps it
    let (st, _) = send(router(), Request::post(path).header("content-type", "application/json").body(Body::from(b.to_string())).unwrap()).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    let mut b2 = json!({"id": "sd2", "arch": "x86_64", "check": true});
    b2["token"] = json!(other);
    let (st, _) = send(router(), Request::post(path).header("content-type", "application/json").body(Body::from(b2.to_string())).unwrap()).await;
    assert_eq!(st, StatusCode::OK);
    // the program: asked without an update request is refused (signed or not), and never handed out unsigned
    let (r, _) = signed_req(crate::tunnel::panel::BINARY_PATH, &json!({"id": "sd1", "arch": std::env::consts::ARCH}), tok);
    assert_eq!(send(router(), r).await.0, StatusCode::CONFLICT);
    // concurrent signed requests: each nonce once
    let (r, _) = signed_req(path, &check, tok);
    let (parts, body) = r.into_parts();
    let raw = axum::body::to_bytes(body, 1 << 16).await.unwrap();
    let mut jobs = vec![];
    for _ in 0..8 {
        let mut x = Request::post(path);
        for (k, v) in parts.headers.iter() {
            x = x.header(k, v);
        }
        let r = x.body(Body::from(raw.clone())).unwrap();
        jobs.push(tokio::spawn(send(router(), r)));
    }
    let mut ok = 0;
    for j in jobs {
        if j.await.unwrap().0 == StatusCode::OK {
            ok += 1;
        }
    }
    assert_eq!(ok, 1);
}

/// 3.69: a node signs its answers (bound to the panel's request); the panel refuses a changed one, and once a node
/// signed, an unsigned one; a node that took a signed request never gets the bare token again
#[tokio::test]
async fn node_answers_are_signed_and_the_ratchet_holds() {
    let node = crate::test_app_env(&[("NODE_TOKEN", NODE_TOKEN)]);
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = format!("http://{}", l.local_addr().unwrap());
    let r = crate::api::node_router(node.clone());
    tokio::spawn(async move { axum::serve(l, r.into_make_service_with_connect_info::<std::net::SocketAddr>()).await });
    let panel = crate::test_app();
    // the node's info, signed both ways
    let info = crate::sync::remote_info_res(&panel, &addr, NODE_TOKEN, false).await.expect("signed info");
    assert!(info.is_object());
    assert_eq!(crate::sync::node_sig(&panel, &addr), crate::sync::NodeSig { signed: true, replies: true });
    // a wrong token: the node refuses (401), and the panel never falls back to the bare token for it
    let e = crate::sync::remote_info_res(&panel, &addr, "not-the-node-token", false).await.unwrap_err();
    assert!(e.contains("401") || e.contains("answer"), "{}", e);
    // a server that answers unsigned at that address now (a man in the middle, a rolled back node): refused
    let l2 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr2 = format!("http://{}", l2.local_addr().unwrap());
    let fake = axum::Router::new().route("/agent/info", axum::routing::get(|| async { axum::Json(json!({"version": "9.9.9"})) }));
    tokio::spawn(async move { axum::serve(l2, fake).await });
    // first contact with the fake: unsigned is taken (a node from before 3.69) …
    assert!(crate::sync::remote_info_res(&panel, &addr2, NODE_TOKEN, false).await.is_ok());
    // … but not at an address whose node already signed
    panel.db.set("node_sig", &json!({ addr2.clone(): {"signed": true, "replies": true} }).to_string());
    let e = crate::sync::remote_info_res(&panel, &addr2, NODE_TOKEN, false).await.unwrap_err();
    assert!(e.contains("not signed"), "{}", e);
}
