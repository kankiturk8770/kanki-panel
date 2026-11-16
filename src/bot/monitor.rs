//! The report bot: a second Telegram bot (its own token) only for the panel's owners. Servers going offline or back,
//! tunnels cut or slow, lossy paths between servers and the daily backup go there, so the sales bot stays only for
//! customers. Without its token everything goes to the sales bot's admins, as before.
use crate::util::{esc, now};
use crate::App;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

pub struct Mon {
    app: Arc<App>,
    token: String,
    admins: Vec<i64>,
    http: reqwest::Client,
    /// Telegram Bot API address (a local fake one in the tests)
    api: String,
}

/// The report bot's token ("" = none: alerts go to the sales bot)
pub fn mon_token(app: &App) -> String {
    app.db.get("mon_token").trim().to_string()
}

/// Who gets the reports: its own list, else the sales bot's admins
pub fn mon_admins_raw(app: &App) -> String {
    let a = app.db.get("mon_admins");
    if a.trim().is_empty() { crate::bot::bot_admins_raw(app) } else { a }
}

fn ids(raw: &str) -> Vec<i64> {
    raw.split(',').filter_map(|x| x.trim().parse().ok()).collect()
}

/// Is this Telegram user one of the report bot's admins?
pub fn is_admin(app: &App, tg: i64) -> bool {
    !mon_token(app).is_empty() && ids(&mon_admins_raw(app)).contains(&tg)
}

fn slot() -> &'static Mutex<Option<Arc<Mon>>> {
    static R: std::sync::OnceLock<Mutex<Option<Arc<Mon>>>> = std::sync::OnceLock::new();
    R.get_or_init(|| Mutex::new(None))
}

fn running() -> Option<Arc<Mon>> {
    slot().lock().unwrap_or_else(|e| e.into_inner()).clone()
}

/// Is the report bot on (it then sends the alerts and the daily backup)?
pub fn on() -> bool {
    running().is_some()
}

/// An alert for the panel's owners: through the report bot when it is set, else through the sales bot
pub async fn notify(text: &str, kb: Option<Value>) {
    if let Some(m) = running() {
        m.to_admins(text, kb).await;
    } else if let Some(b) = crate::bot::running() {
        b.notify_admins_pub(text, kb).await;
    }
}

/// Starts the watcher (always) and the report bot (when it has a token)
pub fn start(app: Arc<App>) {
    if let Some(m) = Mon::new(app.clone()) {
        *slot().lock().unwrap_or_else(|e| e.into_inner()) = Some(m.clone());
        tokio::spawn(m.clone().run());
        tokio::spawn(m.backups());
        eprintln!("report bot started");
    }
    tokio::spawn(watch(app));
}

/// A web app button into the report page of the mini app (`?mon=1`: the panel's state only, never the shop), only
/// when the panel has an https address
fn page_btn(app: &App, text: &str, tab: &str) -> Option<Value> {
    let mini = crate::miniapp::url(app);
    mini.starts_with("https://").then(|| json!({"text": text, "web_app": {"url": format!("{}?mon=1&tab={}", mini, tab)}}))
}

fn paths_btn(app: &App) -> Option<Value> {
    page_btn(app, "📡 وضعیت مسیرها", "paths")
}

/// Telegram alert to the owners when a node, tunnel server or tunnel stays down for about 90 seconds, or a server
/// pair gets lossy (`tunnel::quality`), and another one when it is back. Off when the setting `tg_alerts` is "0".
async fn watch(app: Arc<App>) {
    // after a panel restart the agents need a moment to report again
    tokio::time::sleep(std::time::Duration::from_secs(120)).await;
    // key -> (consecutive bad checks, alert already sent)
    let mut st: HashMap<String, (u32, bool)> = HashMap::new();
    // one message per problem, edited while it lasts and when it is over (no new message for each change)
    let mut live: HashMap<String, Incident> = HashMap::new();
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        if app.db.get("tg_alerts") == "0" {
            continue;
        }
        let evs = check(&app, &mut st);
        let t = now();
        for ev in evs {
            let path = ev.key.starts_with("pq:");
            // path alerts can be turned off in the paths page; server alerts are always sent
            if path && !crate::tunnel::quality::alerts_on(&app) {
                continue;
            }
            // every alert opens the report page where it is: paths, tunnels or servers
            let tab = if path { "paths" } else if ev.key.starts_with("tu:") || ev.key.starts_with("tp:") { "tun" } else { "srv" };
            let label = if path { "📡 وضعیت مسیرها" } else if tab == "tun" { "🔗 جزئیات تانل‌ها" } else { "🖥 جزئیات سرورها" };
            let kb = page_btn(&app, label, tab).map(|b| json!({"inline_keyboard": [[b]]}));
            let Some(m) = running() else {
                // no report bot: the sales bot's admins get the change (it cannot edit what it did not send)
                if ev.state != Ev::STILL {
                    notify(&ev.text, kb).await;
                }
                continue;
            };
            m.incident(&mut live, &ev, kb, t).await;
        }
        // a problem that is over and quiet for a day is forgotten
        live.retain(|_, x| x.over == 0 || t - x.over < 86400);
    }
}

/// One change the watcher saw: a problem that started, one that is over, or the latest numbers of one that lasts
pub(crate) struct Ev {
    key: String,
    text: String,
    state: u8,
}

impl Ev {
    const DOWN: u8 = 0;
    const UP: u8 = 1;
    const STILL: u8 = 2;
}

/// The message of one problem in each owner's chat: where it is, since when, when it was last edited, when it ended
#[derive(Default)]
pub(crate) struct Incident {
    msgs: Vec<(i64, i64)>,
    since: i64,
    edited: i64,
    over: i64,
    shown: String,
}

/// "17:20"
fn hm(ts: i64) -> String {
    crate::channel::fa_datetime(ts).1
}

fn mins(s: i64) -> String {
    let m = (s.max(0) + 30) / 60;
    if m < 60 { format!("{} دقیقه", m.max(1)) } else { format!("{} ساعت و {} دقیقه", m / 60, m % 60) }
}

/// One round of the watcher: what started, what is over, and the latest numbers of what is still wrong
fn check(app: &App, st: &mut HashMap<String, (u32, bool)>) -> Vec<Ev> {
    let nodes: Vec<_> = app.db.nodes().into_iter().filter(|n| n.enabled).collect();
    let offline: std::collections::HashSet<String> = nodes.iter().filter(|n| !n.online).map(|n| n.id.clone()).collect();
    let mut items: Vec<(String, String, bool, String)> =
        nodes.iter().map(|n| (format!("node:{}", n.id), format!("نود {}", n.name), n.online, String::new())).collect();
    items.extend(crate::tunnel::panel::health(app, &offline));
    items.extend(crate::tunnel::quality::health(app));
    let keys: Vec<String> = items.iter().map(|i| i.0.clone()).collect();
    st.retain(|k, _| keys.contains(k));
    // a line more for each alert: where the server is and when it was last heard; which servers a tunnel joins
    let tservers = crate::tunnel::panel::servers(app);
    let sname = |id: &str| -> String {
        if id == "local" { return "سرور پنل".into(); }
        tservers.iter().find(|x| x.id == id).map(|x| x.name.clone()).unwrap_or_else(|| id.to_string())
    };
    let tunnels = crate::tunnel::panel::tunnels(app);
    let more = |key: &str| -> String {
        if let Some(id) = key.strip_prefix("node:") {
            if let Some(n) = nodes.iter().find(|n| n.id == id) {
                let ago = if n.last_sync > 0 { format!(" · آخرین ارتباط {} دقیقه پیش", ((now() - n.last_sync) / 60).max(0)) } else { String::new() };
                return format!("\n🌐 <code>{}</code>{}", esc(&crate::api::endpoint(app, n)), ago);
            }
        }
        if let Some(id) = key.strip_prefix("tu:").or_else(|| key.strip_prefix("tp:")) {
            if let Some(t) = tunnels.iter().find(|t| t.id == id) {
                return format!("\n🔗 {} ← {} · {}", esc(&sname(&t.entry)), esc(&sname(&t.exit)), esc(if t.kind.is_empty() { &t.transport } else { &t.kind }));
            }
        }
        String::new()
    };
    let mut out = vec![];
    for (key, name, ok, detail) in items {
        // the tunnel agent of a VPN server waits longer: when the whole server is down, its own alert (the node's)
        // comes first and this one is not sent at all
        let need = if key.starts_with("ts:") && !detail.is_empty() { 5 } else { 3 };
        let e = st.entry(key.clone()).or_insert((0, false));
        if ok {
            if e.1 {
                out.push(Ev { key: key.clone(), text: format!("{}{}", crate::bot::alert_text(&key, &name, true, &detail), more(&key)), state: Ev::UP });
            }
            *e = (0, false);
        } else {
            e.0 += 1;
            let text = format!("{}{}", crate::bot::alert_text(&key, &name, false, &detail), more(&key));
            if e.0 >= need && !e.1 {
                e.1 = true;
                out.push(Ev { key: key.clone(), text, state: Ev::DOWN });
            } else if e.1 {
                out.push(Ev { key: key.clone(), text, state: Ev::STILL });
            }
        }
    }
    out
}

impl Mon {
    pub fn new(app: Arc<App>) -> Option<Arc<Mon>> {
        Self::with_api(app, "https://api.telegram.org")
    }

    fn with_api(app: Arc<App>, api: &str) -> Option<Arc<Mon>> {
        let token = mon_token(&app);
        // the same token as the sales bot would make two programs read one bot
        if token.is_empty() || token == crate::bot::bot_token(&app) {
            return None;
        }
        let admins = ids(&mon_admins_raw(&app));
        Some(Arc::new(Mon {
            app, token, admins, api: api.to_string(),
            http: reqwest::Client::builder().timeout(std::time::Duration::from_secs(75)).connect_timeout(std::time::Duration::from_secs(15)).build().unwrap_or_default(),
        }))
    }

    async fn call(&self, m: &str, body: Value) -> Result<Value, String> {
        // tried again on Telegram's «too many requests» and its own errors, as the sales bot does; an error never
        // carries the request's address (it holds the token)
        let tries = if m == "getUpdates" { 1 } else { 3 };
        let mut v = Value::Null;
        for i in 0..tries {
            match self.http.post(format!("{}/bot{}/{}", self.api, self.token, m)).json(&body).send().await {
                Err(e) => {
                    if i + 1 == tries { return Err(e.without_url().to_string()); }
                    tokio::time::sleep(std::time::Duration::from_millis(700 * (i as u64 + 1))).await;
                    continue;
                }
                Ok(r) => v = r.json().await.map_err(|e| e.without_url().to_string())?,
            }
            if v["ok"].as_bool() == Some(true) {
                return Ok(v["result"].clone());
            }
            let wait = match v["error_code"].as_i64().unwrap_or(0) {
                429 => v["parameters"]["retry_after"].as_u64().unwrap_or(1).clamp(1, 30) * 1000,
                500..=599 => 700 * (i as u64 + 1),
                _ => break,
            };
            tokio::time::sleep(std::time::Duration::from_millis(wait)).await;
        }
        Err(v["description"].as_str().unwrap_or("telegram error").to_string())
    }

    async fn send(&self, chat: i64, text: &str, kb: Option<Value>) -> Option<Value> {
        let mut body = json!({"chat_id": chat, "text": text, "parse_mode": "HTML", "disable_web_page_preview": true});
        if let Some(k) = kb { body["reply_markup"] = k; }
        self.call("sendMessage", body).await.ok()
    }

    /// One problem in the owners' chats: a new message when it starts (or the same one again when it came back within
    /// 15 minutes), the latest numbers edited in while it lasts (at most once a minute), and «over, from … to …» edited
    /// in when it ends. Nothing new is sent for a change of the same problem.
    async fn incident(&self, live: &mut HashMap<String, Incident>, ev: &Ev, kb: Option<Value>, t: i64) {
        let x = live.entry(ev.key.clone()).or_default();
        let text = match ev.state {
            Ev::UP => {
                if x.msgs.is_empty() { return; }
                x.over = t;
                format!("{}\n\n✅ <b>حل شد</b> · از {} تا {} ({})", ev.text, hm(x.since), hm(t), mins(t - x.since))
            }
            Ev::DOWN => {
                // back again soon after it was over: the same message, not a new one
                if x.msgs.is_empty() || x.over == 0 || t - x.over > 900 {
                    *x = Incident { since: t, ..Default::default() };
                } else {
                    x.over = 0;
                }
                format!("{}\n\n⏳ <b>هنوز برقرار</b> · از ساعت {}", ev.text, hm(x.since))
            }
            _ => {
                if x.msgs.is_empty() || x.over > 0 || t - x.edited < 60 { return; }
                format!("{}\n\n⏳ <b>هنوز برقرار</b> · از ساعت {} ({})", ev.text, hm(x.since), mins(t - x.since))
            }
        };
        if text == x.shown {
            return;
        }
        if x.msgs.is_empty() {
            for a in &self.admins {
                if let Some(m) = self.send(*a, &text, kb.clone()).await {
                    x.msgs.push((*a, m["message_id"].as_i64().unwrap_or(0)));
                }
            }
        } else {
            for (chat, mid) in x.msgs.clone() {
                let mut body = json!({"chat_id": chat, "message_id": mid, "text": text, "parse_mode": "HTML", "disable_web_page_preview": true});
                if let Some(k) = kb.clone() { body["reply_markup"] = k; }
                let _ = self.call("editMessageText", body).await;
            }
        }
        x.edited = t;
        x.shown = text;
    }

    async fn to_admins(&self, text: &str, kb: Option<Value>) {
        for a in &self.admins {
            self.send(*a, text, kb.clone()).await;
        }
    }

    /// The report bot's home: how everything is right now, with its buttons
    fn home(&self) -> (String, Value) {
        let app = &self.app;
        let nodes: Vec<_> = app.db.nodes().into_iter().filter(|n| n.enabled).collect();
        let offline: std::collections::HashSet<String> = nodes.iter().filter(|n| !n.online).map(|n| n.id.clone()).collect();
        let tun = crate::tunnel::panel::health(app, &offline);
        let paths = crate::tunnel::quality::health(app);
        let bad = |v: &[(String, String, bool, String)], pre: &str| -> Vec<String> {
            v.iter().filter(|x| !x.2 && x.0.starts_with(pre)).map(|x| esc(&x.1)).collect()
        };
        let mut t = format!("📊 <b>گزارش پنل</b> · {}\n\n🖥 سرورهای VPN: <b>{}</b> از {} آنلاین", { let (d, t) = crate::channel::fa_datetime(now()); format!("{} · {}", d, t) }, nodes.len() - offline.len(), nodes.len());
        let down: Vec<String> = nodes.iter().filter(|n| !n.online).map(|n| esc(&n.name)).collect();
        if !down.is_empty() {
            t.push_str(&format!("\n🔴 آفلاین: {}", down.join("، ")));
        }
        let ts = bad(&tun, "ts:");
        if !ts.is_empty() {
            t.push_str(&format!("\n🔴 سرور تانل آفلاین: {}", ts.join("، ")));
        }
        let tu = bad(&tun, "tu:");
        let tp = bad(&tun, "tp:");
        let ntun = tun.iter().filter(|x| x.0.starts_with("tu:")).count();
        t.push_str(&format!("\n\n🔗 تانل‌ها: <b>{}</b> از {} وصل", ntun - tu.len(), ntun));
        if !tu.is_empty() {
            t.push_str(&format!("\n🔴 قطع: {}", tu.join("، ")));
        }
        if !tp.is_empty() {
            t.push_str(&format!("\n🟠 پینگ بالا: {}", tp.join("، ")));
        }
        let pq = bad(&paths, "pq:");
        t.push_str(&format!("\n\n📡 مسیرها: {}", if paths.is_empty() { "هنوز سنجشی نرسیده".to_string() } else if pq.is_empty() { "🟢 همه خوب".to_string() } else { format!("🟠 پر افت: {}", pq.join("، ")) }));
        let alerts = app.db.get("tg_alerts") != "0";
        t.push_str(&format!("\n\n🔔 هشدارها: <b>{}</b>", if alerts { "روشن" } else { "خاموش" }));
        let mut rows: Vec<Vec<Value>> = vec![];
        if let Some(p) = page_btn(app, "📊 گزارش کامل (سرورها، تانل‌ها، مسیرها، خطاها)", "sum") {
            rows.push(vec![p]);
        }
        rows.push(vec![json!({"text": "🔄 به‌روز کردن", "callback_data": "m:home"})]);
        if let Some(p) = paths_btn(app) {
            rows.push(vec![p]);
        }
        rows.push(vec![
            json!({"text": if alerts { "🔕 خاموش کردن هشدارها" } else { "🔔 روشن کردن هشدارها" }, "callback_data": "m:al"}),
            json!({"text": "💾 بکاپ الان", "callback_data": "m:bk"}),
        ]);
        (t, json!({"inline_keyboard": rows}))
    }

    async fn backup_to(&self, chats: &[i64], caption: &str) -> bool {
        let pass = self.app.db.get("tgb_pass");
        let app = self.app.clone();
        let Ok(Ok((bytes, name))) = tokio::task::spawn_blocking(move || crate::backup::make_archive(&app, &pass)).await else { return false };
        let mut ok = false;
        for c in chats {
            let part = reqwest::multipart::Part::bytes(bytes.clone()).file_name(name.clone());
            let form = reqwest::multipart::Form::new().text("chat_id", c.to_string()).text("caption", caption.to_string()).part("document", part);
            let r = self.http.post(format!("{}/bot{}/sendDocument", self.api, self.token)).multipart(form).timeout(std::time::Duration::from_secs(600)).send().await;
            if let Ok(r) = r {
                ok |= r.json::<Value>().await.map(|v| v["ok"].as_bool() == Some(true)).unwrap_or(false);
            }
        }
        ok
    }

    /// Every morning (09:00 Tehran): the panel's report and the backup to the owners (the sales bot leaves both to this one)
    async fn backups(self: Arc<Self>) {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            let t = now();
            let day = (t + 12600) / 86400;
            // 05:30 UTC = 09:00 Tehran, once a day
            if (t % 86400) < 5 * 3600 + 1800 || self.app.db.get("mon_daily") == day.to_string() {
                continue;
            }
            self.app.db.set("mon_daily", &day.to_string());
            let (text, kb) = self.home();
            self.to_admins(&format!("☀️ <b>گزارش روزانه</b>\n\n{}", text), Some(kb)).await;
            if self.app.db.on("backup_on") {
                self.backup_to(&self.admins.clone(), "💾 بکاپ خودکار روزانه").await;
            }
        }
    }

    /// The old report script (`kanki-watch`, a cron job on the panel server) sent through the sales bot: with the report
    /// bot it is not needed. Its cron file is set aside (a file with a dot in its name is not run by cron), not deleted.
    fn old_script_off() {
        let f = "/etc/cron.d/kanki-watch";
        if std::path::Path::new(f).exists() {
            match std::fs::rename(f, format!("{}.off", f)) {
                Ok(()) => eprintln!("report bot: the old report script (kanki-watch) is off; its cron file is {}.off", f),
                Err(e) => eprintln!("report bot: cannot set aside {}: {}", f, e),
            }
        }
    }

    /// One update: only the owners are answered; anyone else gets one line and nothing more
    async fn on_update(&self, u: &Value) {
        if let Some(q) = u.get("callback_query") {
            let uid = q["from"]["id"].as_i64().unwrap_or(0);
            let chat = q["message"]["chat"]["id"].as_i64().unwrap_or(uid);
            let mid = q["message"]["message_id"].as_i64().unwrap_or(0);
            let qid = q["id"].clone();
            if !self.admins.contains(&uid) {
                let _ = self.call("answerCallbackQuery", json!({"callback_query_id": qid})).await;
                return;
            }
            let note = match q["data"].as_str().unwrap_or("") {
                "m:al" => {
                    let on = self.app.db.get("tg_alerts") != "0";
                    self.app.db.set("tg_alerts", if on { "0" } else { "1" });
                    if on { "🔕 هشدارها خاموش شد" } else { "🔔 هشدارها روشن شد" }
                }
                "m:bk" => {
                    let _ = self.call("answerCallbackQuery", json!({"callback_query_id": qid, "text": "⏳ در حال ساخت بکاپ…"})).await;
                    if !self.backup_to(&[chat], "💾 بکاپ پنل").await {
                        self.send(chat, "⚠️ ساخت یا ارسال بکاپ نشد.", None).await;
                    }
                    return;
                }
                _ => "",
            };
            let _ = self.call("answerCallbackQuery", json!({"callback_query_id": qid, "text": note})).await;
            let (t, kb) = self.home();
            let r = self.call("editMessageText", json!({"chat_id": chat, "message_id": mid, "text": t, "parse_mode": "HTML", "reply_markup": kb})).await;
            if matches!(&r, Err(e) if !e.contains("not modified")) {
                self.send(chat, &t, Some(kb)).await;
            }
            return;
        }
        let m = &u["message"];
        let uid = m["from"]["id"].as_i64().unwrap_or(0);
        let chat = m["chat"]["id"].as_i64().unwrap_or(uid);
        if uid == 0 || m["chat"]["type"].as_str().unwrap_or("private") != "private" {
            return;
        }
        if !self.admins.contains(&uid) {
            self.send(chat, &format!("⛔️ این ربات فقط برای مدیران پنل است.\nشناسه‌ی شما: <code>{}</code>", uid), None).await;
            return;
        }
        let (t, kb) = self.home();
        self.send(chat, &t, Some(kb)).await;
    }

    async fn run(self: Arc<Self>) {
        Self::old_script_off();
        let _ = self.call("deleteWebhook", json!({"drop_pending_updates": false})).await;
        // the chat's menu button opens the report page
        let mini = crate::miniapp::url(&self.app);
        if mini.starts_with("https://") {
            let _ = self.call("setChatMenuButton", json!({"menu_button": {"type": "web_app", "text": "Report 📊", "web_app": {"url": format!("{}?mon=1", mini)}}})).await;
        }
        if let Ok(me) = self.call("getMe", json!({})).await {
            self.app.db.set("mon_username", me["username"].as_str().unwrap_or(""));
        }
        let mut offset = 0i64;
        loop {
            match self.call("getUpdates", json!({"offset": offset, "timeout": 30, "allowed_updates": ["message", "callback_query"]})).await {
                Ok(Value::Array(list)) => {
                    self.app.db.set("mon_alive", &now().to_string());
                    self.app.db.set("mon_error", "");
                    for u in list {
                        offset = u["update_id"].as_i64().unwrap_or(offset) + 1;
                        let me = self.clone();
                        tokio::spawn(async move { me.on_update(&u).await });
                    }
                }
                Ok(_) => tokio::time::sleep(std::time::Duration::from_secs(3)).await,
                Err(e) => {
                    if self.app.db.get("mon_error") != e {
                        self.app.db.set("mon_error", &e);
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type Log = Arc<Mutex<Vec<(String, Value)>>>;

    async fn fake() -> (String, Log) {
        let log: Log = Arc::new(Mutex::new(vec![]));
        let l2 = log.clone();
        let r = axum::Router::new().route("/:bot/:method", axum::routing::post(move |axum::extract::Path((_b, m)): axum::extract::Path<(String, String)>, axum::Json(v): axum::Json<Value>| {
            let l = l2.clone();
            async move {
                l.lock().unwrap().push((m, v));
                axum::Json(json!({"ok": true, "result": {"message_id": 5}}))
            }
        }));
        let lis = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = lis.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(lis, r).await.unwrap() });
        (format!("http://{}", addr), log)
    }

    #[tokio::test]
    async fn only_the_owners_get_reports_and_its_token_is_its_own() {
        let app = crate::kping::tests::test_app();
        app.db.set("bot_token", "111:sales");
        app.db.set("bot_admins", "10,11");
        // no token, or the sales bot's own token: no report bot
        assert!(Mon::new(app.clone()).is_none());
        app.db.set("mon_token", "111:sales");
        assert!(Mon::new(app.clone()).is_none());
        app.db.set("mon_token", "222:report");
        // its admins: the sales bot's, until it has its own list
        assert_eq!(Mon::new(app.clone()).unwrap().admins, vec![10, 11]);
        app.db.set("mon_admins", "20");
        assert!(is_admin(&app, 20) && !is_admin(&app, 10));
        let (api, log) = fake().await;
        let m = Mon::with_api(app.clone(), &api).unwrap();
        // a stranger gets one line, an owner the report with its buttons
        m.on_update(&json!({"message": {"from": {"id": 99}, "chat": {"id": 99, "type": "private"}, "text": "/start"}})).await;
        m.on_update(&json!({"message": {"from": {"id": 20}, "chat": {"id": 20, "type": "private"}, "text": "/start"}})).await;
        let l = log.lock().unwrap().clone();
        assert!(l[0].1["text"].as_str().unwrap().contains("فقط برای مدیران"), "{:?}", l);
        assert!(l[0].1.get("reply_markup").is_none());
        assert!(l[1].1["text"].as_str().unwrap().contains("گزارش پنل"));
        // a stranger's tap changes nothing
        app.db.set("tg_alerts", "1");
        m.on_update(&json!({"callback_query": {"id": "q", "from": {"id": 99}, "message": {"chat": {"id": 99}, "message_id": 1}, "data": "m:al"}})).await;
        assert_eq!(app.db.get("tg_alerts"), "1");
        m.on_update(&json!({"callback_query": {"id": "q2", "from": {"id": 20}, "message": {"chat": {"id": 20}, "message_id": 1}, "data": "m:al"}})).await;
        assert_eq!(app.db.get("tg_alerts"), "0");
    }

    /// A problem is one message: sent when it starts, edited while it lasts and when it is over, and the same message
    /// again when it comes back soon; never a new message for each change
    #[tokio::test]
    async fn one_message_per_problem_edited_until_it_is_over() {
        let app = crate::kping::tests::test_app();
        app.db.set("bot_token", "111:sales");
        app.db.set("mon_token", "222:report");
        app.db.set("mon_admins", "20,21");
        let (api, log) = fake().await;
        let m = Mon::with_api(app.clone(), &api).unwrap();
        let mut live = HashMap::new();
        let ev = |state: u8, text: &str| Ev { key: "pq:a|b".into(), text: text.into(), state };
        let t = 1_800_000_000;
        m.incident(&mut live, &ev(Ev::DOWN, "🟠 مسیر IRAN3 ↔ TURKEY پر افت شده · افت 20%"), None, t).await;
        // the same numbers, then new numbers within a minute: nothing; after a minute: one edit of each message
        m.incident(&mut live, &ev(Ev::STILL, "🟠 مسیر IRAN3 ↔ TURKEY پر افت شده · افت 20%"), None, t + 30).await;
        m.incident(&mut live, &ev(Ev::STILL, "🟠 مسیر IRAN3 ↔ TURKEY پر افت شده · افت 12%"), None, t + 45).await;
        m.incident(&mut live, &ev(Ev::STILL, "🟠 مسیر IRAN3 ↔ TURKEY پر افت شده · افت 12%"), None, t + 70).await;
        m.incident(&mut live, &ev(Ev::UP, "🟢 مسیر IRAN3 ↔ TURKEY دوباره خوب شد"), None, t + 400).await;
        // back within 15 minutes: the same message again
        m.incident(&mut live, &ev(Ev::DOWN, "🟠 مسیر IRAN3 ↔ TURKEY پر افت شده · افت 9%"), None, t + 600).await;
        let l = log.lock().unwrap().clone();
        let sends = l.iter().filter(|(x, _)| x == "sendMessage").count();
        let edits: Vec<&Value> = l.iter().filter(|(x, _)| x == "editMessageText").map(|(_, v)| v).collect();
        assert_eq!(sends, 2, "one message for each of the two owners: {:?}", l);
        assert_eq!(edits.len(), 6, "{:?}", l);
        assert!(edits[2]["text"].as_str().unwrap().contains("حل شد") && edits[2]["text"].as_str().unwrap().contains("7 دقیقه"), "{}", edits[2]);
        assert!(edits[4]["text"].as_str().unwrap().contains("هنوز برقرار"));
    }

    #[test]
    fn a_server_alert_comes_once_after_three_bad_rounds_and_once_when_back() {
        let app = crate::kping::tests::test_app();
        app.db.exec("INSERT INTO nodes(id,name,address,endpoint,token,enabled,online,note,insecure,drain,maint,accept_all,endpoint_mode,sync_state) VALUES('n1','DE','1.2.3.4','','s',1,0,'',0,0,0,1,'custom','')", &[]).unwrap();
        let mut st = HashMap::new();
        assert!(check(&app, &mut st).is_empty());
        assert!(check(&app, &mut st).is_empty());
        let a = check(&app, &mut st);
        assert_eq!(a.len(), 1);
        assert!(a[0].state == Ev::DOWN && a[0].text.contains("آفلاین"));
        // while it lasts: the latest numbers, not a new alert
        let a = check(&app, &mut st);
        assert!(a.len() == 1 && a[0].state == Ev::STILL);
        app.db.exec("UPDATE nodes SET online=1", &[]).unwrap();
        let b = check(&app, &mut st);
        assert!(b.len() == 1 && b[0].state == Ev::UP && b[0].text.contains("دوباره آنلاین"), "{}", b[0].text);
        assert!(check(&app, &mut st).is_empty());
    }
}
