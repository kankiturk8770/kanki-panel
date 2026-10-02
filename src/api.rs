//! وب: API مدیریت، صفحه‌ی اشتراک، کانفیگ‌ها، عامل نود و احراز هویت Hysteria2
use crate::db::{Node, User};
use crate::sync::{self, SyncReq};
use crate::util::{check_password, esc, iso, now, rand_token};
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

fn err(code: StatusCode, msg: &str) -> Response {
    (code, Json(json!({ "error": msg }))).into_response()
}

fn authed(app: &App, h: &HeaderMap) -> bool {
    let t = h.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()).unwrap_or("");
    let t = t.trim_start_matches("Bearer ").trim();
    if t.is_empty() {
        return false;
    }
    if t == app.db.get("api_key") {
        return true;
    }
    app.sessions.lock().unwrap().contains(t)
}

macro_rules! guard {
    ($app:expr, $h:expr) => {
        if !authed(&$app, &$h) {
            return err(StatusCode::UNAUTHORIZED, "unauthorized");
        }
    };
}

pub fn origin(app: &App) -> String {
    format!("https://{}", app.env.get("DOMAIN").cloned().unwrap_or_default())
}

pub fn user_json(app: &App, u: &User) -> Value {
    json!({
        "id": u.id, "username": u.username, "subscription_id": u.code, "code": u.sub_code(),
        "link": format!("{}/sub/{}", origin(app), u.sub_code()),
        "traffic_limit_gb": u.limit_gb, "traffic_used_gb": (u.used_gb() * 100.0).round() / 100.0,
        "expires_at": iso(u.expires_at), "expires_ts": u.expires_at,
        "max_connections": u.max_conn, "online_connections": u.online, "enabled": u.enabled,
        "status": u.status(), "protocols": u.protocols, "nodes": u.nodes, "notes": u.notes,
        "tg_id": u.tg_id, "created_at": iso(u.created_at), "last_seen_at": iso(u.last_seen),
    })
}

// ============================================================ مسیرها

pub fn master_router(app: Arc<App>) -> Router {
    Router::new()
        .route("/", get(|| async { Redirect::to("/admin") }))
        .route("/admin", get(|| async { Html(include_str!("../web/index.html")) }))
        .route("/api/login", post(login))
        .route("/api/overview", get(overview))
        .route("/api/users", get(users_list).post(users_create))
        .route("/api/users/:id", axum::routing::put(users_update).delete(users_delete))
        .route("/api/users/:id/:action", post(users_action))
        .route("/api/nodes", get(nodes_list).post(nodes_add))
        .route("/api/nodes/:id", axum::routing::delete(nodes_delete))
        .route("/api/nodes/:id/toggle", post(nodes_toggle))
        .route("/api/settings", get(settings_get).put(settings_put))
        .route("/api/plans", get(plans_list).post(plans_add))
        .route("/api/plans/:id", axum::routing::delete(plans_delete))
        .route("/api/sync", post(force_sync))
        .route("/api/backup", get(backup))
        .route("/sub/:code", get(sub_page))
        .route("/sub/:code/raw", get(sub_raw))
        .route("/api/config/:id/:proto", get(config_file))
        .route("/api/config/:id/:proto/:extra", get(config_file_extra))
        .route("/hy2/auth", post(hy2_auth))
        .with_state(app)
}

pub fn node_router(app: Arc<App>) -> Router {
    Router::new()
        .route("/agent/info", get(agent_info))
        .route("/agent/sync", post(agent_sync))
        .route("/hy2/auth", post(hy2_auth))
        .with_state(app)
}

// ============================================================ ورود و آمار

async fn login(State(app): St, Json(b): Json<Value>) -> Response {
    let u = b["username"].as_str().unwrap_or("");
    let p = b["password"].as_str().unwrap_or("");
    let ok = u == app.env.get("ADMIN_USER").map(|s| s.as_str()).unwrap_or("")
        && check_password(app.env.get("ADMIN_PASS").map(|s| s.as_str()).unwrap_or(""), p);
    if !ok {
        tokio::time::sleep(std::time::Duration::from_millis(800)).await;
        return err(StatusCode::UNAUTHORIZED, "نام کاربری یا رمز اشتباه است");
    }
    let t = rand_token(40);
    app.sessions.lock().unwrap().insert(t.clone());
    Json(json!({ "token": t })).into_response()
}

async fn overview(State(app): St, h: HeaderMap) -> Response {
    guard!(app, h);
    let us = app.db.users();
    let nodes = app.db.nodes();
    let sales = app.db.with(|c| {
        c.query_row("SELECT COUNT(*), COALESCE(SUM(CASE WHEN method IN ('card','zp') THEN CAST(amount AS INTEGER) END),0) FROM orders WHERE status='done'", [], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?))
        }).unwrap_or((0, 0))
    });
    Json(json!({
        "users": us.len(), "active": us.iter().filter(|u| u.active()).count(),
        "online": us.iter().filter(|u| u.online > 0).count(),
        "traffic_gb": (us.iter().map(|u| u.used_gb()).sum::<f64>() * 10.0).round() / 10.0,
        "expired": us.iter().filter(|u| u.expired()).count(),
        "nodes": nodes.len(), "nodes_online": nodes.iter().filter(|n| n.online).count(),
        "sales": sales.0, "revenue": sales.1,
        "api_key": app.db.get("api_key"),
    })).into_response()
}

// ============================================================ کاربران

async fn users_list(State(app): St, h: HeaderMap) -> Response {
    guard!(app, h);
    let v: Vec<Value> = app.db.users().iter().map(|u| user_json(&app, u)).collect();
    Json(json!(v)).into_response()
}

async fn users_create(State(app): St, h: HeaderMap, Json(b): Json<Value>) -> Response {
    guard!(app, h);
    let count = b["count"].as_i64().unwrap_or(1).clamp(1, 100);
    let base = b["username"].as_str().unwrap_or("").trim().to_string();
    let gb = b["traffic_limit_gb"].as_f64().or_else(|| b["traffic_limit"].as_f64()).unwrap_or(0.0);
    let days = b["days"].as_i64().unwrap_or(30);
    let conns = b["max_connections"].as_i64().unwrap_or(1);
    let protos = list_or(&b["protocols"], &app.db.get("default_protocols"));
    let nodes = list_or(&b["nodes"], "");
    let notes = b["notes"].as_str().unwrap_or("");
    let tg = b["tg_id"].as_i64().unwrap_or(0);
    let mut out = vec![];
    for i in 0..count {
        let name = if base.is_empty() {
            format!("u{}", rand_token(6).to_lowercase())
        } else if count > 1 {
            format!("{}_{}", base, i + 1)
        } else {
            base.clone()
        };
        match app.db.create_user(&name, gb, days, conns, &protos, &nodes, notes, tg) {
            Ok(u) => out.push(user_json(&app, &u)),
            Err(e) => return err(StatusCode::BAD_REQUEST, &e),
        }
    }
    let a = app.clone();
    tokio::spawn(async move { sync::sync_all(&a).await });
    Json(json!(out)).into_response()
}

fn list_or(v: &Value, def: &str) -> String {
    match v {
        Value::Array(a) => a.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(","),
        Value::String(s) => s.clone(),
        _ => def.to_string(),
    }
}

async fn users_update(State(app): St, h: HeaderMap, Path(id): Path<i64>, Json(b): Json<Value>) -> Response {
    guard!(app, h);
    let Some(u) = app.db.user(id) else { return err(StatusCode::NOT_FOUND, "not found") };
    let gb = b["traffic_limit_gb"].as_f64().unwrap_or(u.limit_gb);
    let exp = match b["expires_ts"].as_i64() {
        Some(t) => t,
        None => match b["days"].as_i64() {
            Some(d) if d > 0 => now() + d * 86400,
            Some(_) => 0,
            None => u.expires_at,
        },
    };
    let conns = b["max_connections"].as_i64().unwrap_or(u.max_conn);
    let protos = if b["protocols"].is_null() { u.protocols.clone() } else { list_or(&b["protocols"], "") };
    let nodes = if b["nodes"].is_null() { u.nodes.clone() } else { list_or(&b["nodes"], "") };
    let notes = b["notes"].as_str().unwrap_or(&u.notes).to_string();
    let r = app.db.exec(
        "UPDATE users SET limit_gb=?1, expires_at=?2, max_conn=?3, protocols=?4, nodes=?5, notes=?6, warned=0 WHERE id=?7",
        &[&gb, &exp, &conns, &protos, &nodes, &notes, &id],
    );
    if let Err(e) = r {
        return err(StatusCode::BAD_REQUEST, &e);
    }
    let a = app.clone();
    tokio::spawn(async move { sync::sync_all(&a).await });
    Json(user_json(&app, &app.db.user(id).unwrap_or(u))).into_response()
}

async fn users_delete(State(app): St, h: HeaderMap, Path(id): Path<i64>) -> Response {
    guard!(app, h);
    app.db.delete_user(id);
    let a = app.clone();
    tokio::spawn(async move { sync::sync_all(&a).await });
    Json(json!({ "ok": true })).into_response()
}

async fn users_action(State(app): St, h: HeaderMap, Path((id, action)): Path<(i64, String)>, body: Option<Json<Value>>) -> Response {
    guard!(app, h);
    let b = body.map(|j| j.0).unwrap_or(Value::Null);
    let r = match action.as_str() {
        "extend" => app.db.extend(id, b["days"].as_i64().unwrap_or(0), b["gb"].as_f64().unwrap_or(0.0)),
        "reset" | "reset-traffic" => app.db.exec("UPDATE users SET used_bytes=0, warned=0 WHERE id=?1", &[&id]).map(|_| ()),
        "toggle" | "freeze" => app.db.exec("UPDATE users SET enabled=1-enabled WHERE id=?1", &[&id]).map(|_| ()),
        "regen" => app.db.exec("UPDATE users SET code=?1 WHERE id=?2", &[&crate::util::rand_digits(19), &id]).map(|_| ()),
        _ => Err("unknown action".into()),
    };
    if let Err(e) = r {
        return err(StatusCode::BAD_REQUEST, &e);
    }
    let a = app.clone();
    tokio::spawn(async move { sync::sync_all(&a).await });
    match app.db.user(id) {
        Some(u) => Json(user_json(&app, &u)).into_response(),
        None => err(StatusCode::NOT_FOUND, "not found"),
    }
}

// ============================================================ نودها

async fn nodes_list(State(app): St, h: HeaderMap) -> Response {
    guard!(app, h);
    let v: Vec<Value> = app.db.nodes().iter().map(|n| {
        let info: Value = serde_json::from_str(&n.info).unwrap_or(json!({}));
        json!({ "id": n.id, "name": n.name, "address": n.address, "endpoint": n.endpoint, "enabled": n.enabled,
                "online": n.online, "last_sync": n.last_sync, "info": info })
    }).collect();
    Json(json!(v)).into_response()
}

async fn nodes_add(State(app): St, h: HeaderMap, Json(b): Json<Value>) -> Response {
    guard!(app, h);
    let name = b["name"].as_str().unwrap_or("").trim().to_string();
    let addr = b["address"].as_str().unwrap_or("").trim().trim_end_matches('/').to_string();
    let endpoint = b["endpoint"].as_str().unwrap_or("").trim().to_string();
    let token = b["token"].as_str().unwrap_or("").trim().to_string();
    if name.is_empty() || addr.is_empty() || token.is_empty() || endpoint.is_empty() {
        return err(StatusCode::BAD_REQUEST, "نام، آدرس API، آدرس اتصال و توکن لازم است");
    }
    let Some(info) = sync::remote_info(&app, &addr, &token).await else {
        return err(StatusCode::BAD_GATEWAY, "اتصال به نود برقرار نشد (آدرس/توکن/فایروال را بررسی کنید)");
    };
    let id = format!("node-{}", rand_token(10).to_lowercase());
    let r = app.db.exec(
        "INSERT INTO nodes(id,name,address,endpoint,token,info,online) VALUES(?1,?2,?3,?4,?5,?6,1)",
        &[&id, &name, &addr, &endpoint, &token, &info.to_string()],
    );
    if let Err(e) = r {
        return err(StatusCode::BAD_REQUEST, &e);
    }
    let a = app.clone();
    tokio::spawn(async move { sync::sync_all(&a).await });
    Json(json!({ "ok": true, "id": id })).into_response()
}

async fn nodes_delete(State(app): St, h: HeaderMap, Path(id): Path<String>) -> Response {
    guard!(app, h);
    if id == "local" {
        return err(StatusCode::BAD_REQUEST, "سرور اصلی حذف نمی‌شود");
    }
    let _ = app.db.exec("DELETE FROM nodes WHERE id=?1", &[&id]);
    let _ = app.db.exec("DELETE FROM peers WHERE node_id=?1", &[&id]);
    Json(json!({ "ok": true })).into_response()
}

async fn nodes_toggle(State(app): St, h: HeaderMap, Path(id): Path<String>) -> Response {
    guard!(app, h);
    let _ = app.db.exec("UPDATE nodes SET enabled=1-enabled WHERE id=?1", &[&id]);
    Json(json!({ "ok": true })).into_response()
}

// ============================================================ تنظیمات، پلن‌ها، بکاپ

const SETTING_KEYS: &[&str] = &[
    "dns", "mtu", "default_protocols", "sales_on", "trial_on", "trial_gb", "trial_days", "card_on", "card_number", "card_holder",
    "wallet_on", "wallet_text", "np_on", "np_key", "np_coins", "zp_on", "zp_merchant", "zp_callback", "support", "app_link",
    "welcome", "ref_gb", "ref_days", "warn_on", "backup_on", "channel",
];

async fn settings_get(State(app): St, h: HeaderMap) -> Response {
    guard!(app, h);
    let mut m = serde_json::Map::new();
    for k in SETTING_KEYS {
        m.insert(k.to_string(), json!(app.db.get(k)));
    }
    Json(Value::Object(m)).into_response()
}

async fn settings_put(State(app): St, h: HeaderMap, Json(b): Json<Value>) -> Response {
    guard!(app, h);
    if let Some(o) = b.as_object() {
        for (k, v) in o {
            if SETTING_KEYS.contains(&k.as_str()) {
                let s = match v { Value::String(s) => s.clone(), other => other.to_string() };
                app.db.set(k, &s);
            }
        }
    }
    Json(json!({ "ok": true })).into_response()
}

async fn plans_list(State(app): St, h: HeaderMap) -> Response {
    guard!(app, h);
    let v: Vec<Value> = app.db.with(|c| {
        let mut s = c.prepare("SELECT id,name,days,gb,toman,usd,conns,active FROM plans ORDER BY toman").unwrap();
        let rows: Vec<Value> = s.query_map([], |r| {
            Ok(json!({ "id": r.get::<_, i64>(0)?, "name": r.get::<_, String>(1)?, "days": r.get::<_, i64>(2)?,
                "gb": r.get::<_, f64>(3)?, "toman": r.get::<_, i64>(4)?, "usd": r.get::<_, f64>(5)?,
                "conns": r.get::<_, i64>(6)?, "active": r.get::<_, i64>(7)? == 1 }))
        }).unwrap().filter_map(|x| x.ok()).collect();
        rows
    });
    Json(json!(v)).into_response()
}

async fn plans_add(State(app): St, h: HeaderMap, Json(b): Json<Value>) -> Response {
    guard!(app, h);
    let r = app.db.exec(
        "INSERT INTO plans(name,days,gb,toman,usd,conns) VALUES(?1,?2,?3,?4,?5,?6)",
        &[&b["name"].as_str().unwrap_or("پلن").to_string(), &b["days"].as_i64().unwrap_or(30), &b["gb"].as_f64().unwrap_or(0.0),
          &b["toman"].as_i64().unwrap_or(0), &b["usd"].as_f64().unwrap_or(0.0), &b["conns"].as_i64().unwrap_or(1)],
    );
    match r {
        Ok(_) => Json(json!({ "ok": true })).into_response(),
        Err(e) => err(StatusCode::BAD_REQUEST, &e),
    }
}

async fn plans_delete(State(app): St, h: HeaderMap, Path(id): Path<i64>) -> Response {
    guard!(app, h);
    let _ = app.db.exec("DELETE FROM plans WHERE id=?1", &[&id]);
    Json(json!({ "ok": true })).into_response()
}

async fn force_sync(State(app): St, h: HeaderMap) -> Response {
    guard!(app, h);
    sync::sync_all(&app).await;
    Json(json!({ "ok": true })).into_response()
}

pub fn backup_bytes(app: &App) -> Option<Vec<u8>> {
    let path = format!("/tmp/kanki-backup-{}.db", rand_token(6));
    app.db.with(|c| c.execute(&format!("VACUUM INTO '{}'", path), [])).ok()?;
    let b = std::fs::read(&path).ok();
    let _ = std::fs::remove_file(&path);
    b
}

async fn backup(State(app): St, h: HeaderMap) -> Response {
    guard!(app, h);
    match backup_bytes(&app) {
        Some(b) => (
            [(header::CONTENT_TYPE, "application/octet-stream".to_string()),
             (header::CONTENT_DISPOSITION, format!("attachment; filename=\"kanki-backup-{}.db\"", now()))],
            b,
        ).into_response(),
        None => err(StatusCode::INTERNAL_SERVER_ERROR, "backup failed"),
    }
}

// ============================================================ صفحه‌ی اشتراک (سازگار با اپ کانکی)

fn parse_code(code: &str) -> Option<(i64, String)> {
    let rest = code.strip_prefix("bub-")?;
    let (id, c) = rest.split_once('-')?;
    Some((id.parse().ok()?, c.to_string()))
}

fn node_info(n: &Node) -> Value {
    serde_json::from_str(&n.info).unwrap_or(json!({}))
}

fn endpoint(app: &App, n: &Node) -> String {
    if n.id == "local" || n.endpoint.is_empty() {
        app.env.get("ENDPOINT").cloned().filter(|s| !s.is_empty()).or_else(|| app.env.get("DOMAIN").cloned()).unwrap_or_default()
    } else {
        n.endpoint.clone()
    }
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
        q.push(format!("obfs=salamander&obfs-password={}", obfs));
    }
    Some(format!("hysteria2://{}@{}:{}/?{}#{}", u.code, endpoint(app, n), port, q.join("&"), n.name.replace(' ', "-")))
}

fn user_nodes(app: &App, u: &User) -> Vec<Node> {
    app.db.nodes().into_iter().filter(|n| n.enabled && u.on_node(&n.id)).collect()
}

async fn sub_page(State(app): St, Path(code): Path<String>) -> Response {
    let Some((id, c)) = parse_code(&code) else { return (StatusCode::NOT_FOUND, "not found").into_response() };
    let Some(u) = app.db.user_by_code(id, &c) else { return (StatusCode::NOT_FOUND, "not found").into_response() };
    let sub = u.sub_code();
    let left = if u.limit_gb > 0.0 { format!("{:.2} GB", (u.limit_gb - u.used_gb()).max(0.0)) } else { "∞".into() };
    let mut nodes_html = String::new();
    for n in user_nodes(&app, &u) {
        let info = node_info(&n);
        let mut rows = String::new();
        for (p, title, key) in [("wg", "WireGuard", "wireguard"), ("awg", "AmneziaWG", "amneziawg")] {
            let has = info[format!("{}_pub", p)].as_str().map(|s| !s.is_empty()).unwrap_or(false);
            if u.has_proto(p) && has {
                rows.push_str(&format!(
                    "<div class=\"row\"><b>{t}</b><a class=\"btn\" href=\"/api/config/{id}/{k}?sub={s}&amp;node={n}\">⬇ {t}</a></div>",
                    t = title, id = u.id, k = key, s = sub, n = n.id
                ));
            }
        }
        if let Some(h) = hy2_uri(&app, &u, &n) {
            rows.push_str(&format!(
                "<div class=\"row\"><b>Hysteria2</b><code onclick=\"navigator.clipboard.writeText(this.innerText)\">{}</code></div>",
                esc(&h)
            ));
        }
        if !rows.is_empty() {
            nodes_html.push_str(&format!("<section class=\"node\"><h3>{}</h3>{}</section>", esc(&n.name), rows));
        }
    }
    let page = format!(
        r#"<!doctype html><html lang="fa" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{name}</title><style>
body{{margin:0;background:#0b0906;color:#f7f1e3;font-family:Vazirmatn,Tahoma,sans-serif}}main{{max-width:560px;margin:auto;padding:20px}}
h1{{color:#f5c451;font-size:24px;margin:6px 0}}.card,.node{{background:#15110a;border:1px solid #5b4a1f;border-radius:18px;padding:14px;margin:12px 0}}
.grid{{display:grid;grid-template-columns:1fr 1fr;gap:8px}}.grid div{{background:#1d170d;border-radius:12px;padding:10px}}small{{color:#a89c82;display:block}}
.row{{display:flex;justify-content:space-between;align-items:center;gap:8px;margin:8px 0;flex-wrap:wrap}}
.btn{{background:#f5c451;color:#1a1206;text-decoration:none;padding:8px 14px;border-radius:12px;font-weight:700}}
code{{direction:ltr;display:block;word-break:break-all;background:#0e0b07;padding:8px;border-radius:10px;font-size:11px;cursor:pointer;width:100%}}
h3{{color:#f5c451;margin:0 0 6px}}.st{{display:inline-block;padding:3px 10px;border-radius:10px;border:1px solid #3ddc97;color:#3ddc97}}
</style></head><body><main class="sub-shell" data-token="{sub}" data-expires="{exp}" data-traffic-limit="{lim:.6}" data-traffic-used="{used:.6}">
<h1>{name}</h1><span class="st">{status}</span>
<div class="card grid">
<div><small>Data remaining</small>{left}</div><div><small>Used traffic</small>{used:.2} GB</div>
<div><small>Connections</small>{on}/{max}</div><div><small>Time remaining</small><span id="t">—</span></div>
</div>{nodes}
</main><script>
var e=document.querySelector('main').dataset.expires;if(e){{var s=(new Date(e)-new Date())/1000;
document.getElementById('t').textContent=s<=0?'منقضی':Math.floor(s/86400)+' روز و '+Math.floor(s%86400/3600)+' ساعت'}}else document.getElementById('t').textContent='نامحدود';
</script></body></html>"#,
        name = esc(&u.username), sub = sub, exp = iso(u.expires_at), lim = u.limit_gb, used = u.used_gb(),
        status = u.status(), left = left, on = u.online, max = u.max_conn, nodes = nodes_html
    );
    Html(page).into_response()
}

/// اشتراک خام برای کلاینت‌هایی مثل v2rayNG/Hiddify (Hysteria2)
async fn sub_raw(State(app): St, Path(code): Path<String>) -> Response {
    let Some((id, c)) = parse_code(&code) else { return (StatusCode::NOT_FOUND, "").into_response() };
    let Some(u) = app.db.user_by_code(id, &c) else { return (StatusCode::NOT_FOUND, "").into_response() };
    let lines: Vec<String> = user_nodes(&app, &u).iter().filter_map(|n| hy2_uri(&app, &u, n)).collect();
    use base64_engine::encode;
    encode(lines.join("\n")).into_response()
}

mod base64_engine {
    pub fn encode(s: String) -> String {
        const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let b = s.as_bytes();
        let mut o = String::new();
        for ch in b.chunks(3) {
            let n = (ch[0] as u32) << 16 | (*ch.get(1).unwrap_or(&0) as u32) << 8 | *ch.get(2).unwrap_or(&0) as u32;
            o.push(T[(n >> 18 & 63) as usize] as char);
            o.push(T[(n >> 12 & 63) as usize] as char);
            o.push(if ch.len() > 1 { T[(n >> 6 & 63) as usize] as char } else { '=' });
            o.push(if ch.len() > 2 { T[(n & 63) as usize] as char } else { '=' });
        }
        o
    }
}

async fn config_file_extra(st: St, Path((id, proto, _extra)): Path<(i64, String, String)>, q: Query<HashMap<String, String>>) -> Response {
    config_file(st, Path((id, proto)), q).await
}

async fn config_file(State(app): St, Path((id, proto)): Path<(i64, String)>, Query(q): Query<HashMap<String, String>>) -> Response {
    let sub = q.get("sub").cloned().unwrap_or_default();
    let code = parse_code(&sub).map(|x| x.1).unwrap_or(sub);
    let Some(u) = app.db.user_by_code(id, &code) else { return (StatusCode::NOT_FOUND, "not found").into_response() };
    let node_id = q.get("node").cloned().unwrap_or_else(|| "local".into());
    let Some(n) = app.db.node(&node_id) else { return (StatusCode::NOT_FOUND, "node").into_response() };
    if proto == "hysteria2" {
        return hy2_uri(&app, &u, &n).unwrap_or_default().into_response();
    }
    let p = match proto.as_str() { "amneziawg" => "awg", "wireguard" => "wg", _ => return (StatusCode::NOT_FOUND, "proto").into_response() };
    if !u.has_proto(p) {
        return (StatusCode::FORBIDDEN, "protocol not allowed").into_response();
    }
    let info = node_info(&n);
    let spub = info[format!("{}_pub", p)].as_str().unwrap_or("").to_string();
    let port = info[format!("{}_port", p)].as_str().unwrap_or("").to_string();
    let Some(peer) = app.db.ensure_peer(u.id, &n.id, p) else { return (StatusCode::INTERNAL_SERVER_ERROR, "keys").into_response() };
    let mut s = format!(
        "[Interface]\nPrivateKey = {}\nAddress = {}/32\nDNS = {}\nMTU = {}\n",
        peer.privkey, peer.ip, app.db.get("dns"), app.db.get("mtu")
    );
    if p == "awg" {
        if let Some(arr) = info["awg"].as_array() {
            for kv in arr {
                if let (Some(k), Some(v)) = (kv[0].as_str(), kv[1].as_str()) {
                    s.push_str(&format!("{} = {}\n", k, v));
                }
            }
        }
    }
    s.push_str(&format!(
        "\n[Peer]\nPublicKey = {}\nPresharedKey = {}\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = {}:{}\nPersistentKeepalive = 25\n",
        spub, peer.psk, endpoint(&app, &n), port
    ));
    let fname = format!("{}-{}-{}.conf", u.username, n.name.replace(' ', "_"), proto);
    ([(header::CONTENT_TYPE, "text/plain; charset=utf-8".to_string()),
      (header::CONTENT_DISPOSITION, format!("attachment; filename=\"{}\"", fname))], s).into_response()
}

// ============================================================ Hysteria2 و عامل نود

async fn hy2_auth(State(app): St, Json(b): Json<Value>) -> Response {
    let auth = b["auth"].as_str().unwrap_or("");
    let name = app.hy2_allowed.lock().unwrap().get(auth).cloned();
    match name {
        Some(n) => Json(json!({ "ok": true, "id": n })).into_response(),
        None => Json(json!({ "ok": false })).into_response(),
    }
}

fn node_authed(app: &App, h: &HeaderMap) -> bool {
    let t = h.get("X-Node-Token").and_then(|v| v.to_str().ok()).unwrap_or("");
    !t.is_empty() && Some(t) == app.env.get("NODE_TOKEN").map(|s| s.as_str())
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
