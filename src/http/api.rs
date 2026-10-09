//! Web: management API, subscription page, client configs, node agent, Hysteria2 auth
use crate::db::{Node, User};
use crate::guard;
use crate::sync::{self, SyncReq};
use crate::util::{self, esc, iso, now, pct, rand_token};
use crate::App;
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;

type St = State<Arc<App>>;

pub fn err(code: StatusCode, msg: &str) -> Response {
    (code, Json(json!({ "error": msg }))).into_response()
}

fn spawn_sync(app: &Arc<App>) {
    let a = app.clone();
    tokio::spawn(async move { sync::sync_all(&a).await });
}

/// Public panel origin used in subscription links
pub fn origin(app: &App) -> String {
    let base = app.db.get("sub_base");
    if !base.trim().is_empty() {
        return base.trim().trim_end_matches('/').to_string();
    }
    let domain = app.env.get("DOMAIN").cloned().unwrap_or_default();
    match app.env.get("HTTPS_PORT").map(|s| s.trim()).filter(|p| !p.is_empty() && *p != "443") {
        Some(p) => format!("https://{}:{}", domain, p),
        None => format!("https://{}", domain),
    }
}

/// Public host users connect to on the main server (settings > env ENDPOINT > env DOMAIN)
pub fn panel_endpoint(app: &App) -> String {
    let s = app.db.get("endpoint");
    if !s.trim().is_empty() {
        return s.trim().to_string();
    }
    app.env.get("ENDPOINT").cloned().filter(|s| !s.is_empty()).or_else(|| app.env.get("DOMAIN").cloned()).unwrap_or_default()
}

pub fn endpoint(app: &App, n: &Node) -> String {
    if n.endpoint_mode == "panel" || n.endpoint.trim().is_empty() {
        panel_endpoint(app)
    } else {
        n.endpoint.trim().to_string()
    }
}

pub fn valid_username(s: &str) -> bool {
    !s.is_empty() && s.len() <= 40 && s.chars().all(|c| c.is_ascii_alphanumeric() || "_-.".contains(c))
}

pub fn user_json(app: &App, u: &User) -> Value {
    json!({
        "id": u.id, "username": u.username, "subscription_id": u.code, "code": u.sub_code(),
        "link": format!("{}/sub/{}", origin(app), u.sub_code()),
        "traffic_limit_gb": u.limit_gb, "traffic_used_gb": (u.used_gb() * 100.0).round() / 100.0, "used_bytes": u.used_bytes,
        "expires_at": iso(u.expires_at), "expires_ts": u.expires_at,
        "max_connections": u.max_conn, "online_connections": u.online, "enabled": u.enabled,
        "status": u.status(), "protocols": u.protocols, "nodes": u.nodes, "notes": u.notes,
        "tg_id": u.tg_id, "created_at": iso(u.created_at), "last_seen_at": iso(u.last_seen), "last_seen_ts": u.last_seen,
    })
}

// ============================================================ routes

pub fn master_router(app: Arc<App>) -> Router {
    Router::new()
        .route("/", get(|| async { Redirect::to("/admin") }))
        .route("/admin", get(|| async {
            ([(header::CACHE_CONTROL, "no-store"), (header::X_FRAME_OPTIONS, "DENY")], Html(include_str!("../../assets/web/index.html")))
        }))
        // Vazirmatn (SIL Open Font License), shared by the panel and the subscription page
        .route("/assets/vazirmatn.woff", get(|| async {
            ([(header::CONTENT_TYPE, "font/woff"), (header::CACHE_CONTROL, "public, max-age=2592000, immutable")],
             &include_bytes!("../../assets/web/vazirmatn.woff")[..])
        }))
        .route("/api/overview", get(overview))
        .route("/api/users", get(users_list).post(users_create))
        .route("/api/users/:id", axum::routing::put(users_update).delete(users_delete))
        .route("/api/users/:id/:action", post(users_action))
        .route("/api/nodes", get(nodes_list).post(nodes_add))
        .route("/api/nodes/:id", axum::routing::put(nodes_edit).delete(nodes_delete))
        .route("/api/nodes/:id/:action", post(nodes_action))
        .route("/api/node-ports/:id", post(node_ports))
        .route("/api/node-join", post(node_join_token))
        .route("/join/register", post(node_join_register))
        .route("/api/settings", get(settings_get).put(settings_put))
        .route("/api/settings/apply-endpoint", post(apply_endpoint_all))
        .route("/api/plans", get(plans_list).post(plans_add))
        .route("/api/plans/bulk", post(plans_bulk))
        .route("/api/plans/category", axum::routing::put(plans_cat_rename))
        .route("/api/plans/:id", axum::routing::delete(plans_delete).put(plans_update))
        .route("/api/sync", post(force_sync))
        .route("/sub/:code", get(sub_page))
        .route("/sub/:code/raw", get(sub_raw))
        .route("/sub/:code/json", get(sub_json))
        .route("/api/config/:id/:proto", get(config_file))
        .route("/api/config/:id/:proto/:extra", get(config_file_extra))
        .route("/hy2/auth", post(hy2_auth))
        .merge(crate::auth::router())
        .merge(crate::admin::router())
        .merge(crate::backup::router())
        .merge(crate::channel::router())
        .merge(crate::tunnel::panel::router())
        .layer(axum::middleware::from_fn_with_state(app.clone(), crate::auth::middleware))
        // 2 MiB for every route: login, join and hy2/auth are open to strangers and must not make the
        // server buffer more. Only the backup upload gets a bigger limit (see backup::router).
        .layer(axum::extract::DefaultBodyLimit::max(2 * 1024 * 1024))
        .with_state(app)
}

pub fn node_router(app: Arc<App>) -> Router {
    Router::new()
        .route("/agent/info", get(agent_info))
        .route("/agent/sync", post(agent_sync))
        .route("/agent/repair", post(agent_repair))
        .route("/agent/update", post(agent_update))
        .route("/agent/ports", post(agent_ports))
        .route("/hy2/auth", post(hy2_auth))
        .with_state(app)
}

// ============================================================ overview

async fn overview(State(app): St, h: HeaderMap) -> Response {
    let _ = guard!(app, h, "users:read");
    let us = app.db.users();
    let nodes = app.db.nodes();
    let sales = app.db.with(|c| {
        c.query_row("SELECT COUNT(*), COALESCE(SUM(CASE WHEN method IN ('card','zp') THEN CAST(amount AS INTEGER) END),0) FROM orders WHERE status='done'", [], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?))
        }).unwrap_or((0, 0))
    });
    let mut protos: HashMap<&str, usize> = HashMap::new();
    for p in ["wg", "awg", "hy2"] {
        protos.insert(p, us.iter().filter(|u| u.has_proto(p)).count());
    }
    let online = us.iter().filter(|u| u.online > 0).count();
    Json(json!({
        "users": us.len(), "active": us.iter().filter(|u| u.active()).count(),
        "online": online, "offline": us.len() - online,
        "traffic_gb": (us.iter().map(|u| u.used_gb()).sum::<f64>() * 10.0).round() / 10.0,
        "expired": us.iter().filter(|u| u.enabled && (u.expired() || u.over_quota())).count(),
        "disabled": us.iter().filter(|u| !u.enabled).count(),
        "nodes": nodes.len(), "nodes_online": nodes.iter().filter(|n| n.online).count(),
        "sales": sales.0, "revenue": sales.1, "protocols": protos,
    })).into_response()
}

// ============================================================ users

async fn users_list(State(app): St, h: HeaderMap) -> Response {
    let _ = guard!(app, h, "users:read");
    let v: Vec<Value> = app.db.users().iter().map(|u| user_json(&app, u)).collect();
    Json(json!(v)).into_response()
}

fn list_or(v: &Value, def: &str) -> String {
    match v {
        Value::Array(a) => a.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(","),
        Value::String(s) => s.clone(),
        _ => def.to_string(),
    }
}

fn num(v: &Value) -> Option<f64> {
    v.as_f64().or_else(|| v.as_str().and_then(|s| s.trim().parse().ok()))
}

async fn users_create(State(app): St, h: HeaderMap, Json(b): Json<Value>) -> Response {
    let _ = guard!(app, h, "users:write");
    let count = num(&b["count"]).unwrap_or(1.0).clamp(1.0, 200.0) as i64;
    let base = b["username"].as_str().unwrap_or("").trim().to_string();
    if !base.is_empty() && !valid_username(&base) {
        return err(StatusCode::BAD_REQUEST, "username: only letters, digits, _ - . (max 40)");
    }
    let gb = num(&b["traffic_limit_gb"]).or_else(|| num(&b["traffic_limit"])).unwrap_or(0.0).max(0.0);
    let days = num(&b["days"]).unwrap_or(30.0) as i64;
    let conns = num(&b["max_connections"]).unwrap_or(1.0).max(0.0) as i64;
    let protos = list_or(&b["protocols"], &app.db.get("default_protocols"));
    let nodes = list_or(&b["nodes"], "");
    let notes = b["notes"].as_str().unwrap_or("");
    let tg = b["tg_id"].as_i64().unwrap_or(0);
    let mut out = vec![];
    for i in 0..count {
        let name = if base.is_empty() {
            "auto".to_string() // USER<n>, lowest free number
        } else if count > 1 {
            format!("{}_{}", base, i + 1)
        } else {
            base.clone()
        };
        match app.db.create_user(&name, gb, days, conns, &protos, &nodes, notes, tg) {
            Ok(u) => {
                if let Some(ts) = b["expires_ts"].as_i64() {
                    let _ = app.db.exec("UPDATE users SET expires_at=?1 WHERE id=?2", &[&ts, &u.id]);
                }
                out.push(user_json(&app, &app.db.user(u.id).unwrap_or(u)))
            }
            Err(e) => return err(StatusCode::BAD_REQUEST, &e),
        }
    }
    spawn_sync(&app);
    Json(json!(out)).into_response()
}

async fn users_update(State(app): St, h: HeaderMap, Path(id): Path<i64>, Json(b): Json<Value>) -> Response {
    let _ = guard!(app, h, "users:write");
    let Some(u) = app.db.user(id) else { return err(StatusCode::NOT_FOUND, "not found") };
    let gb = num(&b["traffic_limit_gb"]).unwrap_or(u.limit_gb).max(0.0);
    let exp = match b["expires_ts"].as_i64() {
        Some(t) => t.max(0),
        None => match num(&b["days"]) {
            Some(d) if d > 0.0 => now() + (d as i64) * 86400,
            Some(_) => 0,
            None => u.expires_at,
        },
    };
    let conns = num(&b["max_connections"]).map(|x| x as i64).unwrap_or(u.max_conn).max(0);
    let protos = if b["protocols"].is_null() { u.protocols.clone() } else { list_or(&b["protocols"], "") };
    let nodes = if b["nodes"].is_null() { u.nodes.clone() } else { list_or(&b["nodes"], "") };
    let notes = b["notes"].as_str().unwrap_or(&u.notes).to_string();
    let enabled = b["enabled"].as_bool().unwrap_or(u.enabled) as i64;
    let mut username = u.username.clone();
    if let Some(n) = b["username"].as_str().map(|s| s.trim()).filter(|s| !s.is_empty() && *s != u.username) {
        if !valid_username(n) {
            return err(StatusCode::BAD_REQUEST, "username: only letters, digits, _ - . (max 40)");
        }
        username = n.to_string();
    }
    let r = app.db.exec(
        "UPDATE users SET username=?1, limit_gb=?2, expires_at=?3, max_conn=?4, protocols=?5, nodes=?6, notes=?7, enabled=?8, warned=0 WHERE id=?9",
        &[&username, &gb, &exp, &conns, &protos, &nodes, &notes, &enabled, &id],
    );
    if let Err(e) = r {
        return err(StatusCode::BAD_REQUEST, &e);
    }
    // quick add (days / GB) on top of the saved values
    let add_days = num(&b["add_days"]).unwrap_or(0.0) as i64;
    let add_gb = num(&b["add_gb"]).unwrap_or(0.0);
    if add_days > 0 || add_gb > 0.0 {
        let _ = app.db.extend(id, add_days, add_gb);
        if add_days > 0 || add_gb > 0.0 {
            app.db.promote_trial(id);
        }
    }
    spawn_sync(&app);
    Json(user_json(&app, &app.db.user(id).unwrap_or(u))).into_response()
}

async fn users_delete(State(app): St, h: HeaderMap, Path(id): Path<i64>) -> Response {
    let _ = guard!(app, h, "users:write");
    app.db.delete_user(id);
    spawn_sync(&app);
    Json(json!({ "ok": true })).into_response()
}

pub fn user_action(app: &App, id: i64, action: &str, b: &Value) -> Result<(), String> {
    match action {
        "extend" => app.db.extend(id, num(&b["days"]).unwrap_or(0.0) as i64, num(&b["gb"]).unwrap_or(0.0)).map(|_| app.db.promote_trial(id)),
        "reset" | "reset-traffic" => app.db.exec("UPDATE users SET used_bytes=0, warned=0 WHERE id=?1", &[&id]).map(|_| ()),
        "toggle" | "freeze" => app.db.exec("UPDATE users SET enabled=1-enabled WHERE id=?1", &[&id]).map(|_| ()),
        "enable" => app.db.exec("UPDATE users SET enabled=1 WHERE id=?1", &[&id]).map(|_| ()),
        "disable" => app.db.exec("UPDATE users SET enabled=0 WHERE id=?1", &[&id]).map(|_| ()),
        "regen" => {
            let _ = app.db.exec("DELETE FROM peers WHERE user_id=?1", &[&id]);
            app.db.exec("UPDATE users SET code=?1 WHERE id=?2", &[&util::rand_digits(19), &id]).map(|_| ())
        }
        "delete" => {
            app.db.delete_user(id);
            Ok(())
        }
        _ => Err("unknown action".into()),
    }
}

async fn users_action(State(app): St, h: HeaderMap, Path((id, action)): Path<(i64, String)>, body: Option<Json<Value>>) -> Response {
    let _ = guard!(app, h, "users:write");
    let b = body.map(|j| j.0).unwrap_or(Value::Null);
    if let Err(e) = user_action(&app, id, &action, &b) {
        return err(StatusCode::BAD_REQUEST, &e);
    }
    spawn_sync(&app);
    match app.db.user(id) {
        Some(u) => Json(user_json(&app, &u)).into_response(),
        None => Json(json!({"ok": true})).into_response(),
    }
}

// ============================================================ nodes

pub fn node_info(n: &Node) -> Value {
    serde_json::from_str(&n.info).unwrap_or(json!({}))
}

fn node_json(app: &App, n: &Node, users: &[User]) -> Value {
    let info = node_info(n);
    let mut info_pub = info.clone();
    if let Some(o) = info_pub.as_object_mut() {
    }
    let assigned = users.iter().filter(|u| u.on(n)).count();
    json!({
        "id": n.id, "name": n.name, "address": n.address, "endpoint": n.endpoint, "endpoint_mode": n.endpoint_mode,
        "effective_endpoint": endpoint(app, n), "enabled": n.enabled, "online": n.online, "last_sync": n.last_sync,
        "note": n.note, "insecure": n.insecure, "drain": n.drain, "maint": n.maint, "accept_all": n.accept_all,
        "sync_state": n.sync_state, "users": assigned, "info": info_pub,
        "plain_http": n.id != "local" && n.address.starts_with("http://"),
    })
}

async fn nodes_list(State(app): St, h: HeaderMap) -> Response {
    let _ = guard!(app, h, "nodes");
    let users = app.db.users();
    let v: Vec<Value> = app.db.nodes().iter().map(|n| node_json(&app, n, &users)).collect();
    Json(json!(v)).into_response()
}

async fn nodes_add(State(app): St, h: HeaderMap, Json(b): Json<Value>) -> Response {
    let _ = guard!(app, h, "nodes");
    let name = b["name"].as_str().unwrap_or("").trim().to_string();
    let addr = b["address"].as_str().unwrap_or("").trim().trim_end_matches('/').to_string();
    let endpoint = b["endpoint"].as_str().unwrap_or("").trim().to_string();
    let token = b["token"].as_str().unwrap_or("").trim().to_string();
    let insecure = b["insecure"].as_bool().unwrap_or(false);
    if name.is_empty() || addr.is_empty() || token.is_empty() {
        return err(StatusCode::BAD_REQUEST, "name, API address and token are required");
    }
    if !addr.starts_with("http://") && !addr.starts_with("https://") {
        return err(StatusCode::BAD_REQUEST, "API address must start with https:// (or http:// for old nodes)");
    }
    let Some(info) = sync::remote_info(&app, &addr, &token, insecure).await else {
        return err(StatusCode::BAD_GATEWAY, "cannot reach the node (check address / token / firewall / certificate)");
    };
    let id = format!("node-{}", rand_token(10).to_lowercase());
    let mode = if endpoint.is_empty() { "panel" } else { "custom" };
    let r = app.db.exec(
        "INSERT INTO nodes(id,name,address,endpoint,token,info,online,insecure,endpoint_mode,note) VALUES(?1,?2,?3,?4,?5,?6,1,?7,?8,?9)",
        &[&id, &name, &addr, &endpoint, &token, &info.to_string(), &(insecure as i64), &mode, &b["note"].as_str().unwrap_or("")],
    );
    if let Err(e) = r {
        return err(StatusCode::BAD_REQUEST, &e);
    }
    spawn_sync(&app);
    Json(json!({ "ok": true, "id": id })).into_response()
}

async fn nodes_edit(State(app): St, h: HeaderMap, Path(id): Path<String>, Json(b): Json<Value>) -> Response {
    let _ = guard!(app, h, "nodes");
    let Some(n) = app.db.node(&id) else { return err(StatusCode::NOT_FOUND, "not found") };
    let name = b["name"].as_str().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).unwrap_or(n.name.clone());
    let note = b["note"].as_str().unwrap_or(&n.note).to_string();
    let accept = b["accept_all"].as_bool().unwrap_or(n.accept_all) as i64;
    let mode = match b["endpoint_mode"].as_str() { Some("panel") => "panel", Some("custom") => "custom", _ => n.endpoint_mode.as_str() }.to_string();
    let ep = b["endpoint"].as_str().map(|s| s.trim().to_string()).unwrap_or(n.endpoint.clone());
    let addr = b["address"].as_str().map(|s| s.trim().trim_end_matches('/').to_string()).filter(|s| !s.is_empty()).unwrap_or(n.address.clone());
    let token = b["token"].as_str().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).unwrap_or(n.token.clone());
    let insecure = b["insecure"].as_bool().unwrap_or(n.insecure) as i64;
    let r = app.db.exec(
        "UPDATE nodes SET name=?1, note=?2, accept_all=?3, endpoint_mode=?4, endpoint=?5, address=?6, token=?7, insecure=?8 WHERE id=?9",
        &[&name, &note, &accept, &mode, &ep, &addr, &token, &insecure, &id],
    );
    if let Err(e) = r {
        return err(StatusCode::BAD_REQUEST, &e);
    }
    spawn_sync(&app);
    Json(json!({"ok": true})).into_response()
}

async fn nodes_delete(State(app): St, h: HeaderMap, Path(id): Path<String>) -> Response {
    let _ = guard!(app, h, "nodes");
    if id == "local" {
        return err(StatusCode::BAD_REQUEST, "the main server cannot be deleted");
    }
    let _ = app.db.exec("DELETE FROM nodes WHERE id=?1", &[&id]);
    let _ = app.db.exec("DELETE FROM peers WHERE node_id=?1", &[&id]);
    Json(json!({ "ok": true })).into_response()
}

/// Changes the WireGuard / AmneziaWG / Hysteria2 ports of a node (or of the panel server) in one go
async fn node_ports(State(app): St, h: HeaderMap, Path(id): Path<String>, Json(b): Json<Value>) -> Response {
    let _ = guard!(app, h, "nodes");
    let Some(n) = app.db.node(&id) else { return err(StatusCode::NOT_FOUND, "not found") };
    let r = if n.id == "local" { Some(crate::admin::set_ports(&b)) } else { sync::remote_post_json(&app, &n, "/agent/ports", &b).await };
    spawn_sync(&app);
    match r {
        Some(v) => Json(v).into_response(),
        None => err(StatusCode::BAD_GATEWAY, "the node did not answer: update the node agent first (Update agent), then try again"),
    }
}

async fn nodes_action(State(app): St, h: HeaderMap, Path((id, action)): Path<(String, String)>) -> Response {
    let _ = guard!(app, h, "nodes");
    let Some(n) = app.db.node(&id) else { return err(StatusCode::NOT_FOUND, "not found") };
    match action.as_str() {
        "toggle" => { let _ = app.db.exec("UPDATE nodes SET enabled=1-enabled WHERE id=?1", &[&id]); }
        "drain" => { let _ = app.db.exec("UPDATE nodes SET drain=1-drain WHERE id=?1", &[&id]); spawn_sync(&app); }
        "maint" | "maintenance" => { let _ = app.db.exec("UPDATE nodes SET maint=1-maint WHERE id=?1", &[&id]); spawn_sync(&app); }
        "sync" => { sync::sync_all(&app).await; }
        "assign-all" | "unassign-all" => {
            let add = action == "assign-all";
            if !add && id == "local" {
                return err(StatusCode::BAD_REQUEST, "the main server cannot be removed from all users");
            }
            // users without a node list follow the node's accept_all flag, users with a list need the id in it
            let _ = app.db.exec("UPDATE nodes SET accept_all=?1 WHERE id=?2", &[&(add as i64), &id]);
            for u in app.db.users() {
                if !u.explicit_nodes() {
                    continue;
                }
                let mut list: Vec<String> = u.nodes.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect();
                let has = list.iter().any(|x| *x == id);
                if add && !has {
                    list.push(id.clone());
                } else if !add && has {
                    list.retain(|x| *x != id);
                } else {
                    continue;
                }
                let joined = list.join(",");
                let _ = app.db.exec("UPDATE users SET nodes=?1 WHERE id=?2", &[&joined, &u.id]);
            }
            spawn_sync(&app);
        }
        "health" => {
            let t0 = std::time::Instant::now();
            let info = if n.id == "local" { Some(sync::local_info(&app)) } else { sync::remote_info(&app, &n.address, &n.token, n.insecure).await };
            let ms = t0.elapsed().as_millis() as i64;
            return match info {
                Some(i) => Json(json!({"ok": true, "ms": ms, "services": i["services"], "version": i["version"], "load": i["load"]})).into_response(),
                None => Json(json!({"ok": false, "ms": ms})).into_response(),
            };
        }
        "repair" => {
            let r = if n.id == "local" { Some(crate::admin::repair_services()) } else { sync::remote_post(&app, &n, "/agent/repair").await };
            spawn_sync(&app);
            return Json(json!({"ok": r.is_some(), "result": r})).into_response();
        }
        "update" => {
            if n.id == "local" {
                return err(StatusCode::BAD_REQUEST, "use the panel update button for the main server");
            }
            let r = sync::remote_post(&app, &n, "/agent/update").await;
            return Json(json!({"ok": r.as_ref().map(|v| v["ok"].as_bool().unwrap_or(false)).unwrap_or(false), "result": r})).into_response();
        }
        _ => return err(StatusCode::BAD_REQUEST, "unknown action"),
    }
    Json(json!({"ok": true})).into_response()
}

// ============================================================ node join (one-time token)

/// Admin: make a one-time token (valid for 1 hour). The new server runs the installer with it and registers itself.
async fn node_join_token(State(app): St, h: HeaderMap) -> Response {
    let _ = guard!(app, h, "nodes");
    let token = rand_token(40);
    let exp = now() + 3600;
    app.db.set("join_token", &token);
    app.db.set("join_expires", &exp.to_string());
    Json(json!({ "token": token, "expires": exp, "panel": origin(&app), "repo": crate::admin::repo() })).into_response()
}

/// Public: called by the installer on the new server once its agent runs. The one-time token is the only credential.
async fn node_join_register(State(app): St, Json(b): Json<Value>) -> Response {
    let want = app.db.get("join_token");
    let given = b["token"].as_str().unwrap_or("").trim().to_string();
    let exp: i64 = app.db.get("join_expires").parse().unwrap_or(0);
    if want.is_empty() || given.is_empty() || !util::ct_eq(&given, &want) || exp < now() {
        return err(StatusCode::FORBIDDEN, "the join token is wrong, already used or expired");
    }
    let name = b["name"].as_str().unwrap_or("").trim().to_string();
    let addr = b["address"].as_str().unwrap_or("").trim().trim_end_matches('/').to_string();
    let endpoint = b["endpoint"].as_str().unwrap_or("").trim().to_string();
    let token = b["node_token"].as_str().unwrap_or("").trim().to_string();
    let insecure = b["insecure"].as_bool().unwrap_or(false);
    if token.is_empty() || !addr.starts_with("https://") {
        return err(StatusCode::BAD_REQUEST, "address (https://...) and node_token are required");
    }
    let name = if name.is_empty() { format!("node-{}", rand_token(4).to_lowercase()) } else { name };
    let Some(info) = sync::remote_info(&app, &addr, &token, insecure).await else {
        return err(StatusCode::BAD_GATEWAY, "the panel cannot reach the node (open the node API port in its firewall, then run the same command again)");
    };
    let mode = if endpoint.is_empty() { "panel" } else { "custom" };
    // the same server registering twice (re-run after a firewall fix) updates its row instead of adding a copy
    let existing = app.db.nodes().into_iter().find(|n| n.address == addr).map(|n| n.id);
    let id = match existing {
        Some(id) => {
            let _ = app.db.exec(
                "UPDATE nodes SET token=?1, endpoint=?2, endpoint_mode=?3, insecure=?4, info=?5, online=1 WHERE id=?6",
                &[&token, &endpoint, &mode, &(insecure as i64), &info.to_string(), &id],
            );
            id
        }
        None => {
            let id = format!("node-{}", rand_token(10).to_lowercase());
            let r = app.db.exec(
                "INSERT INTO nodes(id,name,address,endpoint,token,info,online,insecure,endpoint_mode,note) VALUES(?1,?2,?3,?4,?5,?6,1,?7,?8,?9)",
                &[&id, &name, &addr, &endpoint, &token, &info.to_string(), &(insecure as i64), &mode, &"joined with a one-time token"],
            );
            if let Err(e) = r {
                return err(StatusCode::BAD_REQUEST, &e);
            }
            id
        }
    };
    // one use only
    app.db.set("join_token", "");
    spawn_sync(&app);
    Json(json!({ "ok": true, "id": id })).into_response()
}

// ============================================================ settings / plans

pub const SETTING_KEYS: &[&str] = &[
    "dns", "mtu", "default_protocols", "sales_on", "trial_on", "trial_gb", "trial_days", "card_on", "card_number", "card_holder",
    "wallet_on", "wallet_text", "np_on", "np_key", "np_coins", "zp_on", "zp_merchant", "zp_callback", "support", "app_link",
    "welcome", "ref_gb", "ref_days", "warn_on", "backup_on", "channel",
    "panel_name", "lang", "theme", "color", "refresh", "endpoint", "sub_base", "awg_compat", "conn_limit_on", "tg_alerts", "logo", "price_rules",
    // v2.8.4: ready values of the "New user" form
    "def_gb", "def_days", "def_conns",
];

/// "owner/repo" with only the characters GitHub allows
fn valid_repo(r: &str) -> bool {
    let mut it = r.split('/');
    let ok = |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.');
    matches!((it.next(), it.next(), it.next()), (Some(a), Some(b), None) if ok(a) && ok(b))
}

async fn settings_get(State(app): St, h: HeaderMap) -> Response {
    let _ = guard!(app, h, "settings");
    let mut m = serde_json::Map::new();
    for k in SETTING_KEYS {
        m.insert(k.to_string(), json!(app.db.get(k)));
    }
    m.insert("web_bind".into(), json!(app.env.get("PANEL_BIND").cloned().unwrap_or_else(|| "127.0.0.1".into())));
    m.insert("web_port".into(), json!(app.env.get("PANEL_PORT").cloned().unwrap_or_default()));
    m.insert("domain".into(), json!(app.env.get("DOMAIN").cloned().unwrap_or_default()));
    m.insert("https_port".into(), json!(app.env.get("HTTPS_PORT").cloned().unwrap_or_else(|| "443".into())));
    // update source: /etc/kanki/repo, unless KANKI_REPO is set in the environment
    m.insert("update_repo".into(), json!(crate::admin::repo()));
    m.insert("repo_env".into(), json!(std::env::var("KANKI_REPO").map(|s| !s.is_empty()).unwrap_or(false)));
    Json(Value::Object(m)).into_response()
}

async fn settings_put(State(app): St, h: HeaderMap, Json(b): Json<Value>) -> Response {
    let _ = guard!(app, h, "settings");
    if let Some(o) = b.as_object() {
        if let Some(r) = o.get("update_repo").and_then(|v| v.as_str()) {
            let r = r.trim().trim_start_matches("https://github.com/").trim_end_matches('/').trim_end_matches(".git");
            if r.is_empty() {
                let _ = std::fs::remove_file("/etc/kanki/repo");
            } else if valid_repo(r) {
                let _ = std::fs::create_dir_all("/etc/kanki");
                if let Err(e) = std::fs::write("/etc/kanki/repo", format!("{}\n", r)) {
                    return err(StatusCode::INTERNAL_SERVER_ERROR, &format!("cannot write /etc/kanki/repo: {}", e));
                }
            } else {
                return err(StatusCode::BAD_REQUEST, "update source must look like owner/repo");
            }
        }
        for (k, v) in o {
            if SETTING_KEYS.contains(&k.as_str()) {
                let s = match v { Value::String(s) => s.clone(), Value::Bool(x) => if *x { "1".into() } else { "0".into() }, other => other.to_string() };
                app.db.set(k, s.trim());
            }
        }
    }
    spawn_sync(&app);
    Json(json!({ "ok": true })).into_response()
}

async fn apply_endpoint_all(State(app): St, h: HeaderMap) -> Response {
    let _ = guard!(app, h, "settings");
    let _ = app.db.exec("UPDATE nodes SET endpoint_mode='panel'", &[]);
    Json(json!({"ok": true})).into_response()
}

async fn plans_list(State(app): St, h: HeaderMap) -> Response {
    let _ = guard!(app, h, "settings");
    let v: Vec<Value> = app.db.with(|c| {
        let mut s = c.prepare("SELECT id,name,days,gb,toman,usd,conns,active,COALESCE(countries,0),COALESCE(category,'') FROM plans ORDER BY toman").unwrap();
        let rows: Vec<Value> = s.query_map([], |r| {
            Ok(json!({ "id": r.get::<_, i64>(0)?, "name": r.get::<_, String>(1)?, "days": r.get::<_, i64>(2)?,
                "gb": r.get::<_, f64>(3)?, "toman": r.get::<_, i64>(4)?, "usd": r.get::<_, f64>(5)?,
                "conns": r.get::<_, i64>(6)?, "active": r.get::<_, i64>(7)? == 1, "countries": r.get::<_, i64>(8)?, "category": r.get::<_, String>(9)? }))
        }).unwrap().filter_map(|x| x.ok()).collect();
        rows
    });
    Json(json!(v)).into_response()
}

fn insert_plan(app: &App, b: &Value) -> Result<usize, String> {
    let name = b["name"].as_str().map(|s| s.trim()).filter(|s| !s.is_empty()).unwrap_or("Plan").to_string();
    let cat = b["category"].as_str().map(|s| s.trim().to_string()).unwrap_or_default();
    app.db.exec(
        "INSERT INTO plans(name,days,gb,toman,usd,conns,countries,active,category) VALUES(?1,?2,?3,?4,?5,?6,?7,1,?8)",
        &[&name, &(num(&b["days"]).unwrap_or(30.0) as i64), &num(&b["gb"]).unwrap_or(0.0).max(0.0),
          &(num(&b["toman"]).unwrap_or(0.0).max(0.0) as i64), &num(&b["usd"]).unwrap_or(0.0).max(0.0),
          &(num(&b["conns"]).unwrap_or(1.0).max(1.0) as i64), &(num(&b["countries"]).unwrap_or(0.0).max(0.0) as i64), &cat],
    )
}

async fn plans_add(State(app): St, h: HeaderMap, Json(b): Json<Value>) -> Response {
    let _ = guard!(app, h, "settings");
    match insert_plan(&app, &b) {
        Ok(_) => Json(json!({ "ok": true })).into_response(),
        Err(e) => err(StatusCode::BAD_REQUEST, &e),
    }
}

/// Smart plan builder: many plans at once (the panel computes the prices).
async fn plans_bulk(State(app): St, h: HeaderMap, Json(b): Json<Value>) -> Response {
    let _ = guard!(app, h, "settings");
    if b["replace"].as_bool() == Some(true) {
        let _ = app.db.exec("DELETE FROM plans", &[]);
    }
    let mut n = 0;
    for p in b["plans"].as_array().cloned().unwrap_or_default() {
        if insert_plan(&app, &p).is_ok() {
            n += 1;
        }
    }
    if let Some(r) = b.get("rules").filter(|r| r.is_object()) {
        app.db.set("price_rules", &r.to_string());
    }
    Json(json!({ "ok": true, "added": n })).into_response()
}

async fn plans_update(State(app): St, h: HeaderMap, Path(id): Path<i64>, Json(b): Json<Value>) -> Response {
    let _ = guard!(app, h, "settings");
    if let Some(a) = b["active"].as_bool() {
        let _ = app.db.exec("UPDATE plans SET active=?1 WHERE id=?2", &[&(a as i64), &id]);
    }
    if let Some(t) = num(&b["toman"]) {
        let _ = app.db.exec("UPDATE plans SET toman=?1 WHERE id=?2", &[&(t.max(0.0) as i64), &id]);
    }
    if let Some(cat) = b["category"].as_str() {
        let _ = app.db.exec("UPDATE plans SET category=?1 WHERE id=?2", &[&cat.trim().to_string(), &id]);
    }
    if let Some(nm) = b["name"].as_str().map(|s| s.trim()).filter(|s| !s.is_empty()) {
        let _ = app.db.exec("UPDATE plans SET name=?1 WHERE id=?2", &[&nm.to_string(), &id]);
    }
    Json(json!({ "ok": true })).into_response()
}

/// Rename a plan category (from = "" renames the uncategorised plans, to = "" removes the category).
async fn plans_cat_rename(State(app): St, h: HeaderMap, Json(b): Json<Value>) -> Response {
    let _ = guard!(app, h, "settings");
    let from = b["from"].as_str().unwrap_or("").trim().to_string();
    let to = b["to"].as_str().unwrap_or("").trim().to_string();
    let _ = app.db.exec("UPDATE plans SET category=?1 WHERE COALESCE(category,'')=?2", &[&to, &from]);
    Json(json!({ "ok": true })).into_response()
}

async fn plans_delete(State(app): St, h: HeaderMap, Path(id): Path<i64>) -> Response {
    let _ = guard!(app, h, "settings");
    let _ = app.db.exec("DELETE FROM plans WHERE id=?1", &[&id]);
    Json(json!({ "ok": true })).into_response()
}

async fn force_sync(State(app): St, h: HeaderMap) -> Response {
    let _ = guard!(app, h, "nodes");
    sync::sync_all(&app).await;
    Json(json!({ "ok": true })).into_response()
}

// ============================================================ subscription page (Kanki app)

/// "<prefix>-<id>-<code>": new links use the kanki prefix, links made by older versions keep working
fn parse_code(code: &str) -> Option<(i64, String)> {
    let (prefix, rest) = code.split_once('-')?;
    if prefix.is_empty() || !prefix.chars().all(|c| c.is_ascii_alphabetic()) {
        return None;
    }
    let (id, c) = rest.split_once('-')?;
    Some((id.parse().ok()?, c.to_string()))
}

fn hy2_uri(app: &App, u: &User, n: &Node) -> Option<String> {
    let info = node_info(n);
    let port = info["hy2_port"].as_str().unwrap_or("");
    if port.is_empty() || !u.has_proto("hy2") {
        return None;
    }
    let mut q = vec![];
    let sni = info["hy2_sni"].as_str().unwrap_or("");
    if !sni.is_empty() {
        q.push(format!("sni={}", sni));
    }
    if info["hy2_insecure"].as_str() == Some("1") {
        q.push("insecure=1".into());
    }
    let obfs = info["hy2_obfs"].as_str().unwrap_or("");
    if !obfs.is_empty() {
        q.push(format!("obfs=salamander&obfs-password={}", pct(obfs)));
    }
    Some(format!("hysteria2://{}@{}:{}/?{}#{}", u.code, endpoint(app, n), port, q.join("&"), pct(&n.name)))
}

pub fn user_nodes(app: &App, u: &User) -> Vec<Node> {
    app.db.nodes().into_iter().filter(|n| n.usable() && u.on(n)).collect()
}

/// Which protocols this user can actually use on this node
pub fn node_protos(u: &User, n: &Node) -> Vec<&'static str> {
    let info = node_info(n);
    let mut v = vec![];
    let has = |k: &str| info[k].as_str().map(|s| !s.is_empty()).unwrap_or(false);
    if u.has_proto("wg") && has("wg_pub") { v.push("wireguard"); }
    if u.has_proto("awg") && has("awg_pub") { v.push("amneziawg"); }
    if u.has_proto("hy2") && has("hy2_port") { v.push("hysteria2"); }
    v
}

fn sub_data(app: &App, u: &User) -> Value {
    let nodes: Vec<Value> = user_nodes(app, u).iter().map(|n| {
        let info = node_info(n);
        json!({
            "id": n.id, "name": n.name, "main": n.id == "local", "protocols": node_protos(u, n),
            "hy2": hy2_uri(app, u, n),
        })
    }).collect();
    json!({
        "id": u.id, "username": u.username, "sub": u.sub_code(), "status": u.status(), "active": u.active(),
        "limit_gb": u.limit_gb, "used_gb": u.used_gb(), "expires_ts": u.expires_at, "created_ts": u.created_at,
        "online": u.online, "max_conn": u.max_conn, "last_seen_ts": u.last_seen,
        "panel_name": app.db.get("panel_name"), "version": crate::VERSION, "nodes": nodes,
        "support": app.db.get("support"), "app_link": app.db.get("app_link"),
        "logo": app.db.get("logo"),
    })
}

async fn sub_page(State(app): St, Path(code): Path<String>) -> Response {
    let Some((id, c)) = parse_code(&code) else { return (StatusCode::NOT_FOUND, "not found").into_response() };
    let Some(u) = app.db.user_by_code(id, &c) else { return (StatusCode::NOT_FOUND, "not found").into_response() };
    let sub = u.sub_code();
    // server-rendered config links keep the exact URL format the Kanki Android app reads
    let mut nodes_html = String::new();
    for n in user_nodes(&app, &u) {
        let mut rows = String::new();
        for p in node_protos(&u, &n) {
            let (title, letter) = match p { "wireguard" => ("WireGuard", "W"), "amneziawg" => ("AmneziaWG", "A"), _ => ("Hysteria2", "H") };
            let base = format!("/api/config/{}/{}?sub={}&amp;node={}", u.id, p, sub, esc(&n.id));
            let mut btns = String::new();
            match p {
                "hysteria2" => {
                    if let Some(hu) = hy2_uri(&app, &u, &n) {
                        btns.push_str(&format!("<code class=\"uri\">{}</code>", esc(&hu)));
                        btns.push_str(&format!("<button class=\"b2\" data-act=\"copy\" data-text=\"{}\" data-i18n=\"copy_uri\">Copy URI</button>", esc(&hu)));
                        btns.push_str(&format!("<button class=\"b2\" data-act=\"qr\" data-url=\"/api/config/{}/{}/qr?sub={}&amp;node={}\" data-i18n=\"qr\">QR Code</button>", u.id, p, sub, esc(&n.id)));
                    }
                }
                _ => {
                    btns.push_str(&format!("<a class=\"btn\" href=\"{}\" data-i18n=\"dl_conf\">Download config</a>", base));
                    btns.push_str(&format!("<button class=\"b2\" data-act=\"info\" data-url=\"{}\" data-i18n=\"show_info\">Show info</button>", base));
                    btns.push_str(&format!("<button class=\"b2\" data-act=\"qr\" data-url=\"/api/config/{}/{}/qr?sub={}&amp;node={}\" data-i18n=\"qr\">QR Code</button>", u.id, p, sub, esc(&n.id)));
                    if p == "wireguard" {
                        btns.push_str(&format!("<button class=\"b2\" data-act=\"uri\" data-url=\"/api/config/{}/{}/uri?sub={}&amp;node={}\" data-i18n=\"get_uri\">Get URI</button>", u.id, p, sub, esc(&n.id)));
                    }
                }
            }
            rows.push_str(&format!(
                "<div class=\"row proto\" data-proto=\"{p}\"><div class=\"ph\"><i class=\"pl pl-{p}\">{l}</i><div><b>{t}</b><small>{p}</small></div></div><div class=\"acts\">{b}</div></div>",
                p = p, l = letter, t = title, b = btns
            ));
        }
        if !rows.is_empty() {
            nodes_html.push_str(&format!(
                "<section class=\"node\" data-node=\"{}\"><h3>{}<small data-i18n=\"{}\"></small></h3>{}</section>",
                esc(&n.id), esc(&n.name), if n.id == "local" { "main_server" } else { "node" }, rows
            ));
        }
    }
    let data = serde_json::to_string(&sub_data(&app, &u)).unwrap_or_default().replace("</", "<\\/");
    let page = include_str!("../../assets/web/sub.html")
        .replace("{{TITLE}}", &esc(&u.username))
        .replace("{{SUB}}", &sub)
        .replace("{{STATUS}}", u.status())
        .replace("{{EXP}}", &iso(u.expires_at))
        .replace("{{LIM}}", &format!("{:.6}", u.limit_gb))
        .replace("{{USED}}", &format!("{:.6}", u.used_gb()))
        .replace("{{NODES}}", &nodes_html)
        .replace("{{DATA}}", &data);
    ([(header::CACHE_CONTROL, "no-store")], Html(page)).into_response()
}

async fn sub_json(State(app): St, Path(code): Path<String>) -> Response {
    let Some((id, c)) = parse_code(&code) else { return err(StatusCode::NOT_FOUND, "not found") };
    let Some(u) = app.db.user_by_code(id, &c) else { return err(StatusCode::NOT_FOUND, "not found") };
    Json(sub_data(&app, &u)).into_response()
}

/// Raw subscription for v2rayNG / Hiddify (Hysteria2 + WireGuard URIs, base64)
async fn sub_raw(State(app): St, Path(code): Path<String>) -> Response {
    let Some((id, c)) = parse_code(&code) else { return (StatusCode::NOT_FOUND, "").into_response() };
    let Some(u) = app.db.user_by_code(id, &c) else { return (StatusCode::NOT_FOUND, "").into_response() };
    let mut lines: Vec<String> = vec![];
    for n in user_nodes(&app, &u) {
        if let Some(h) = hy2_uri(&app, &u, &n) {
            lines.push(h);
        }
        if u.has_proto("wg") {
            if let Some(w) = wg_uri(&app, &u, &n) {
                lines.push(w);
            }
        }
    }
    let used = u.used_bytes.max(0);
    let total = (u.limit_gb * 1_073_741_824.0) as i64;
    let info = format!("upload=0; download={}; total={}; expire={}", used, total, u.expires_at);
    ([(header::HeaderName::from_static("subscription-userinfo"), info), (header::CONTENT_TYPE, "text/plain; charset=utf-8".to_string())],
     util::b64(lines.join("\n").as_bytes())).into_response()
}

fn wg_uri(app: &App, u: &User, n: &Node) -> Option<String> {
    let info = node_info(n);
    let spub = info["wg_pub"].as_str().filter(|s| !s.is_empty())?.to_string();
    let port = info["wg_port"].as_str().unwrap_or("").to_string();
    let peer = app.db.ensure_peer(u.id, &n.id, "wg")?;
    Some(format!(
        "wireguard://{}@{}:{}?publickey={}&presharedkey={}&address={}&mtu={}#{}",
        pct(&peer.privkey), endpoint(app, n), port, pct(&spub), pct(&peer.psk), pct(&format!("{}/32", peer.ip)),
        app.db.get("mtu"), pct(&format!("{}-{}", n.name, u.username))
    ))
}

async fn config_file_extra(st: St, Path((id, proto, extra)): Path<(i64, String, String)>, q: Query<HashMap<String, String>>) -> Response {
    build_config(st, id, proto, q.0, &extra).await
}

async fn config_file(st: St, Path((id, proto)): Path<(i64, String)>, q: Query<HashMap<String, String>>) -> Response {
    build_config(st, id, proto, q.0, "").await
}

fn text_conf(s: String) -> Response {
    ([(header::CONTENT_TYPE, "text/plain; charset=utf-8".to_string())], s).into_response()
}

/// For the sales bot: the config of one protocol on one server -> (file name, text).
pub async fn bot_config(app: &Arc<App>, u: &User, n: &Node, proto: &str) -> Option<(String, String)> {
    let mut q: HashMap<String, String> = HashMap::new();
    q.insert("sub".to_string(), u.sub_code().to_string());
    q.insert("node".to_string(), n.id.clone());
    let resp = build_config(State(app.clone()), u.id, proto.to_string(), q, "").await;
    if resp.status() != StatusCode::OK {
        return None;
    }
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20).await.ok()?;
    let text = String::from_utf8(bytes.to_vec()).ok()?;
    Some((format!("{}-{}-{}.conf", u.username, n.name.replace(' ', "_"), proto), text))
}

async fn build_config(State(app): St, id: i64, proto: String, q: HashMap<String, String>, extra: &str) -> Response {
    let sub = q.get("sub").cloned().unwrap_or_default();
    let code = parse_code(&sub).map(|x| x.1).unwrap_or(sub);
    let Some(u) = app.db.user_by_code(id, &code) else { return (StatusCode::NOT_FOUND, "not found").into_response() };
    let node_id = q.get("node").cloned().unwrap_or_else(|| "local".into());
    let Some(n) = app.db.node(&node_id) else { return (StatusCode::NOT_FOUND, "node").into_response() };
    if !u.on(&n) {
        return (StatusCode::FORBIDDEN, "node not allowed").into_response();
    }
    let info = node_info(&n);
    let qr = |s: &str| -> Response {
        match util::qr_svg(s) {
            Some(svg) => ([(header::CONTENT_TYPE, "image/svg+xml".to_string())], svg).into_response(),
            None => (StatusCode::PAYLOAD_TOO_LARGE, "too large for a QR code").into_response(),
        }
    };
    if proto == "hysteria2" {
        let s = hy2_uri(&app, &u, &n).unwrap_or_default();
        return if extra == "qr" { qr(&s) } else { text_conf(s) };
    }
    let p = match proto.as_str() { "amneziawg" => "awg", "wireguard" => "wg", _ => return (StatusCode::NOT_FOUND, "proto").into_response() };
    if !u.has_proto(p) {
        return (StatusCode::FORBIDDEN, "protocol not allowed").into_response();
    }
    if p == "wg" && extra == "uri" {
        return text_conf(wg_uri(&app, &u, &n).unwrap_or_default());
    }
    let spub = info[format!("{}_pub", p)].as_str().unwrap_or("").to_string();
    let port = info[format!("{}_port", p)].as_str().unwrap_or("").to_string();
    if spub.is_empty() {
        return (StatusCode::NOT_FOUND, "protocol not installed on this server").into_response();
    }
    let Some(peer) = app.db.ensure_peer(u.id, &n.id, p) else { return (StatusCode::INTERNAL_SERVER_ERROR, "keys").into_response() };
    let mut s = format!(
        "[Interface]\nPrivateKey = {}\nAddress = {}/32\nDNS = {}\nMTU = {}\n",
        peer.privkey, peer.ip, app.db.get("dns"), app.db.get("mtu")
    );
    if p == "awg" {
        let compat = app.db.on("awg_compat");
        let classic = ["Jc", "Jmin", "Jmax", "S1", "S2", "H1", "H2", "H3", "H4"];
        if let Some(arr) = info["awg"].as_array() {
            for kv in arr {
                if let (Some(k), Some(v)) = (kv[0].as_str(), kv[1].as_str()) {
                    if compat && !classic.contains(&k) {
                        continue;
                    }
                    s.push_str(&format!("{} = {}\n", k, v));
                }
            }
        }
    }
    s.push_str(&format!(
        "\n[Peer]\nPublicKey = {}\nPresharedKey = {}\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = {}:{}\nPersistentKeepalive = 25\n",
        spub, peer.psk, endpoint(&app, &n), port
    ));
    if extra == "qr" {
        return qr(&s);
    }
    if extra == "text" {
        return text_conf(s);
    }
    let fname = format!("{}-{}-{}.conf", u.username, n.name.replace(' ', "_"), proto);
    ([(header::CONTENT_TYPE, "text/plain; charset=utf-8".to_string()),
      (header::CONTENT_DISPOSITION, format!("attachment; filename=\"{}\"", fname))], s).into_response()
}

// ============================================================ Hysteria2 auth (local only, blocked at Caddy)

async fn hy2_auth(State(app): St, Json(b): Json<Value>) -> Response {
    let auth = b["auth"].as_str().unwrap_or("").to_string();
    let name = app.hy2_allowed.lock().unwrap().get(&auth).cloned();
    if let Some(n) = name {
        if sync::conn_allowed(&app, &n).await {
            return Json(json!({ "ok": true, "id": n })).into_response();
        }
    }
    Json(json!({ "ok": false })).into_response()
}

// ============================================================ node agent

fn node_authed(app: &App, h: &HeaderMap) -> bool {
    let t = h.get("X-Node-Token").and_then(|v| v.to_str().ok()).unwrap_or("");
    match app.env.get("NODE_TOKEN") {
        Some(want) if !want.is_empty() && !t.is_empty() => util::ct_eq(t, want),
        _ => false,
    }
}

async fn agent_info(State(app): St, h: HeaderMap) -> Response {
    if !node_authed(&app, &h) {
        return err(StatusCode::UNAUTHORIZED, "bad token");
    }
    Json(sync::local_info(&app)).into_response()
}

async fn agent_sync(State(app): St, h: HeaderMap, Json(req): Json<SyncReq>) -> Response {
    if !node_authed(&app, &h) {
        return err(StatusCode::UNAUTHORIZED, "bad token");
    }
    Json(sync::apply_local(&app, req).await).into_response()
}

async fn agent_repair(State(app): St, h: HeaderMap) -> Response {
    if !node_authed(&app, &h) {
        return err(StatusCode::UNAUTHORIZED, "bad token");
    }
    Json(crate::admin::repair_services()).into_response()
}

async fn agent_ports(State(app): St, h: HeaderMap, Json(b): Json<Value>) -> Response {
    if !node_authed(&app, &h) {
        return err(StatusCode::UNAUTHORIZED, "bad token");
    }
    Json(crate::admin::set_ports(&b)).into_response()
}

async fn agent_update(State(app): St, h: HeaderMap) -> Response {
    if !node_authed(&app, &h) {
        return err(StatusCode::UNAUTHORIZED, "bad token");
    }
    match crate::admin::self_update(&app).await {
        Ok(v) => {
            // the tunnel agent of this machine (when there is one) runs the same file: restart it onto the new one
            let _ = std::process::Command::new("systemctl").args(["restart", "kanki-tunnel"]).spawn();
            Json(json!({"ok": true, "version": v})).into_response()
        }
        Err(e) => Json(json!({"ok": false, "error": e})).into_response(),
    }
}
