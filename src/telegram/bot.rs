//! ربات تلگرام داخلی: فروش، پرداخت، سرویس‌ها، مدیریت کامل
use crate::api::origin;
use crate::backup::make_archive;
use crate::db::User;
use crate::util::{esc, now, rand_token};
use crate::{sync, App};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
enum Wait {
    Receipt(String),
    Set(String),
    Plan,
    Search,
    Make,
    Extend(i64),
    Broadcast,
    DiscountAdd,
    DiscountUse,
}

#[derive(Clone, Default)]
struct Pending {
    plan: i64,
    kind: String,
    target: i64,
    discount: String,
    percent: i64,
}

pub struct Bot {
    app: Arc<App>,
    token: String,
    admins: Vec<i64>,
    http: reqwest::Client,
    waits: Mutex<HashMap<i64, Wait>>,
    pend: Mutex<HashMap<i64, Pending>>,
}

type Kb = Vec<Vec<(String, String)>>;

fn b(t: &str, d: &str) -> (String, String) {
    (t.to_string(), d.to_string())
}

fn ik(rows: Kb) -> Value {
    let r: Vec<Vec<Value>> = rows
        .into_iter()
        .map(|row| row.into_iter().map(|(t, d)| {
            if let Some(u) = d.strip_prefix("url:") { json!({"text": t, "url": u}) } else { json!({"text": t, "callback_data": d}) }
        }).collect())
        .collect();
    json!({ "inline_keyboard": r })
}

fn toman(n: i64) -> String {
    let s = n.to_string();
    let mut o = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i) % 3 == 0 {
            o.push(',');
        }
        o.push(c);
    }
    format!("{} تومان", o)
}

fn left_text(u: &User) -> String {
    if u.expires_at == 0 {
        return "نامحدود".into();
    }
    let s = u.expires_at - now();
    if s <= 0 {
        return "منقضی شده".into();
    }
    let (d, h) = (s / 86400, s % 86400 / 3600);
    if d > 0 { format!("{} روز و {} ساعت", d, h) } else { format!("{} ساعت", h) }
}

#[derive(Clone)]
struct Plan {
    id: i64,
    name: String,
    days: i64,
    gb: f64,
    toman: i64,
    usd: f64,
    conns: i64,
    /// how many countries (servers) the plan gives; 0 = all
    countries: i64,
    category: String,
}

/// Bot token: panel setting first, then install-time env
pub fn bot_token(app: &App) -> String {
    let t = app.db.get("bot_token");
    if t.is_empty() { app.env.get("BOT_TOKEN").cloned().unwrap_or_default() } else { t }
}

pub fn bot_admins_raw(app: &App) -> String {
    let a = app.db.get("bot_admins");
    if a.is_empty() { app.env.get("BOT_ADMINS").cloned().unwrap_or_default() } else { a }
}

impl Bot {
    pub fn new(app: Arc<App>) -> Option<Arc<Bot>> {
        let token = bot_token(&app);
        if token.is_empty() {
            return None;
        }
        let admins = bot_admins_raw(&app)
            .split(',').filter_map(|x| x.trim().parse().ok()).collect();
        Some(Arc::new(Bot {
            app, token, admins, http: reqwest::Client::new(),
            waits: Mutex::new(HashMap::new()), pend: Mutex::new(HashMap::new()),
        }))
    }

    fn admin(&self, id: i64) -> bool {
        self.admins.contains(&id)
    }

    // ============================================================ Bot API
    async fn call(&self, m: &str, body: Value) -> Option<Value> {
        let r = self.http.post(format!("https://api.telegram.org/bot{}/{}", self.token, m))
            .json(&body).send().await.ok()?;
        let v: Value = r.json().await.ok()?;
        if v["ok"].as_bool() == Some(true) { Some(v["result"].clone()) } else { None }
    }

    async fn send(&self, chat: i64, text: &str, kb: Option<Value>) -> Option<Value> {
        let mut body = json!({"chat_id": chat, "text": text, "parse_mode": "HTML", "disable_web_page_preview": true});
        if let Some(k) = kb { body["reply_markup"] = k; }
        self.call("sendMessage", body).await
    }

    async fn edit(&self, chat: i64, mid: i64, text: &str, kb: Option<Value>) {
        let mut body = json!({"chat_id": chat, "message_id": mid, "text": text, "parse_mode": "HTML", "disable_web_page_preview": true});
        if let Some(k) = kb.clone() { body["reply_markup"] = k; }
        if self.call("editMessageText", body).await.is_none() {
            self.send(chat, text, kb).await;
        }
    }

    async fn answer(&self, id: &str, text: &str, alert: bool) {
        self.call("answerCallbackQuery", json!({"callback_query_id": id, "text": text, "show_alert": alert})).await;
    }

    async fn notify_admins(&self, text: &str, kb: Option<Value>, photo: Option<String>) {
        for a in &self.admins {
            match &photo {
                Some(p) => {
                    let mut body = json!({"chat_id": a, "photo": p, "caption": text, "parse_mode": "HTML"});
                    if let Some(k) = kb.clone() { body["reply_markup"] = k; }
                    self.call("sendPhoto", body).await;
                }
                None => { self.send(*a, text, kb.clone()).await; }
            }
        }
    }

    async fn send_doc(&self, chat: i64, bytes: Vec<u8>, name: &str, caption: &str) {
        let part = reqwest::multipart::Part::bytes(bytes).file_name(name.to_string());
        let form = reqwest::multipart::Form::new()
            .text("chat_id", chat.to_string()).text("caption", caption.to_string()).part("document", part);
        let _ = self.http.post(format!("https://api.telegram.org/bot{}/sendDocument", self.token)).multipart(form).send().await;
    }

    // ============================================================ کمکی‌های داده
    fn db(&self) -> &crate::db::Db {
        &self.app.db
    }

    fn plans(&self, only_active: bool) -> Vec<(Plan, bool)> {
        self.db().with(|c| {
            let mut s = c.prepare("SELECT id,name,days,gb,toman,usd,conns,active,COALESCE(countries,0),COALESCE(category,'') FROM plans ORDER BY toman").unwrap();
            let v: Vec<(Plan, bool)> = s.query_map([], |r| Ok((Plan {
                id: r.get(0)?, name: r.get(1)?, days: r.get(2)?, gb: r.get(3)?, toman: r.get(4)?, usd: r.get(5)?, conns: r.get(6)?,
                countries: r.get(8)?, category: r.get(9)?,
            }, r.get::<_, i64>(7)? == 1))).unwrap().filter_map(|x| x.ok()).filter(|(_, a)| *a || !only_active).collect();
            v
        })
    }

    fn plan(&self, id: i64) -> Option<Plan> {
        self.plans(false).into_iter().map(|x| x.0).find(|p| p.id == id)
    }

    fn account_text(&self, u: &User) -> String {
        let left = if u.limit_gb > 0.0 { format!("{:.2} GB", (u.limit_gb - u.used_gb()).max(0.0)) } else { "نامحدود".into() };
        let st = if u.active() { "🟢 فعال" } else { "🔴 غیرفعال" };
        format!(
            "👤 <b>{}</b>  ·  {}\n📦 حجم باقی‌مانده: <b>{}</b>  (مصرف: {:.2} GB)\n⏳ زمان باقی‌مانده: <b>{}</b>\n🔌 اتصال: {}/{}\n\n🔗 لینک اشتراک:\n<code>{}/sub/{}</code>\n\n🔑 کد ورود به اپ:\n<code>{}</code>",
            esc(&u.username), st, left, u.used_gb(), left_text(u), u.online, u.max_conn, origin(&self.app), u.sub_code(), u.sub_code()
        )
    }

    fn create_account(&self, tg: i64, gb: f64, days: i64, conns: i64, notes: &str) -> Result<User, String> {
        self.create_account_n(tg, gb, days, conns, notes, 0)
    }

    /// The `countries` least-loaded servers (0 = every server, the normal case).
    fn pick_nodes(&self, countries: i64) -> String {
        if countries <= 0 {
            return String::new();
        }
        let mut ns: Vec<(String, usize)> = self.db().nodes().into_iter().filter(|n| n.enabled && !n.drain && !n.maint).map(|n| {
            let load = self.db().users().iter().filter(|u| u.on(&n)).count();
            (n.id, load)
        }).collect();
        if (ns.len() as i64) <= countries {
            return String::new();
        }
        ns.sort_by_key(|x| x.1);
        ns.into_iter().take(countries as usize).map(|x| x.0).collect::<Vec<_>>().join(",")
    }

    fn create_account_n(&self, tg: i64, gb: f64, days: i64, conns: i64, notes: &str, countries: i64) -> Result<User, String> {
        // USER<n> for buyers, USER<n>-TEST for free trials (same number when the trial is bought)
        let name = if notes == "trial" { "auto-test" } else { "auto" };
        let nodes = self.pick_nodes(countries);
        let u = self.db().create_user(name, gb, days, conns, &self.db().get("default_protocols"), &nodes, notes, tg)?;
        let a = self.app.clone();
        tokio::spawn(async move { sync::sync_all(&a).await });
        Ok(u)
    }

    fn home_kb(&self, uid: i64) -> Value {
        let mut rows: Kb = vec![
            vec![b("🛒 خرید اشتراک", "buy"), b("🎁 تست رایگان", "trial")],
            vec![b("📊 سرویس‌های من", "my"), b("🔁 تمدید", "renew")],
            vec![b("👥 دعوت دوستان", "ref"), b("📱 دانلود اپ", "app")],
            vec![b("💬 پشتیبانی", "support")],
        ];
        if self.admin(uid) {
            rows.push(vec![b("👑 پنل مدیریت", "adm")]);
        }
        ik(rows)
    }

    fn price(&self, p: &Plan, pe: &Pending) -> (i64, f64) {
        let f = (100 - pe.percent.clamp(0, 100)) as f64 / 100.0;
        (((p.toman as f64) * f).round() as i64, ((p.usd * f) * 100.0).round() / 100.0)
    }

    /// عضویت اجباری کانال (اگر تنظیم شده)
    async fn joined(&self, uid: i64) -> bool {
        let ch = self.db().get("channel");
        if ch.is_empty() || self.admin(uid) {
            return true;
        }
        match self.call("getChatMember", json!({"chat_id": ch, "user_id": uid})).await {
            Some(v) => matches!(v["status"].as_str(), Some("member") | Some("administrator") | Some("creator")),
            None => true,
        }
    }

    // ============================================================ حلقه‌ی اصلی
    pub async fn run(self: Arc<Self>) {
        if self.db().get("api_key").is_empty() {
            self.db().set("api_key", &rand_token(40));
        }
        let me = self.clone();
        tokio::spawn(async move { me.background().await });
        let me2 = self.clone();
        tokio::spawn(async move { me2.watch().await });
        let mut offset = 0i64;
        loop {
            if self.db().on("bot_paused") {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                continue;
            }
            let up = self.call("getUpdates", json!({"offset": offset, "timeout": 30, "allowed_updates": ["message", "callback_query"]})).await;
            if up.is_some() {
                self.app.bot_alive.store(now(), std::sync::atomic::Ordering::Relaxed);
            }
            let Some(Value::Array(list)) = up else {
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                continue;
            };
            for u in list {
                offset = u["update_id"].as_i64().unwrap_or(offset) + 1;
                let me = self.clone();
                tokio::spawn(async move {
                    if u["callback_query"].is_object() {
                        me.on_callback(&u["callback_query"]).await;
                    } else if u["message"].is_object() {
                        me.on_message(&u["message"]).await;
                    }
                });
            }
        }
    }

    fn touch(&self, uid: i64, name: &str, ref_by: i64) {
        let _ = self.db().exec(
            "INSERT INTO bot_users(tg_id,name,joined,ref_by) VALUES(?1,?2,?3,?4) ON CONFLICT(tg_id) DO UPDATE SET name=excluded.name",
            &[&uid, &name, &now(), &ref_by],
        );
    }

    // ============================================================ پیام‌ها
    async fn on_message(&self, m: &Value) {
        let uid = m["from"]["id"].as_i64().unwrap_or(0);
        let chat = m["chat"]["id"].as_i64().unwrap_or(uid);
        let name = m["from"]["first_name"].as_str().unwrap_or("").to_string();
        let text = m["text"].as_str().unwrap_or("").trim().to_string();
        if text.starts_with("/start") {
            let ref_by = text.split_whitespace().nth(1).and_then(|s| s.strip_prefix("ref_")).and_then(|s| s.parse::<i64>().ok())
                .filter(|r| *r != uid).unwrap_or(0);
            self.touch(uid, &name, ref_by);
            self.waits.lock().unwrap().remove(&uid);
            if !self.joined(uid).await {
                return self.ask_join(chat).await;
            }
            self.send(chat, &self.db().get("welcome"), Some(self.home_kb(uid))).await;
            return;
        }
        self.touch(uid, &name, 0);
        let wait = self.waits.lock().unwrap().remove(&uid);
        let Some(w) = wait else {
            self.send(chat, "از منوی زیر استفاده کنید 👇", Some(self.home_kb(uid))).await;
            return;
        };
        match w {
            Wait::Receipt(method) => self.got_receipt(uid, chat, &name, &method, m).await,
            Wait::DiscountUse => {
                let code = text.to_uppercase();
                let pct: Option<i64> = self.db().with(|c| c.query_row(
                    "SELECT percent FROM discounts WHERE code=?1 AND uses_left>0 AND (COALESCE(expires,0)=0 OR expires>?2)",
                    rusqlite::params![&code, now()], |r| r.get(0)).ok());
                match pct {
                    Some(p) => {
                        let plan_id = {
                            let mut g = self.pend.lock().unwrap();
                            let pe = g.entry(uid).or_default();
                            pe.discount = code.clone();
                            pe.percent = p;
                            pe.plan
                        };
                        self.send(chat, &format!("✅ کد تخفیف {}٪ اعمال شد", p), None).await;
                        self.show_plan(chat, None, uid, plan_id).await;
                    }
                    None => { self.send(chat, "❌ کد تخفیف نامعتبر یا تمام شده است.", Some(self.home_kb(uid))).await; }
                }
            }
            other if self.admin(uid) => self.admin_input(uid, chat, other, &text, m).await,
            _ => {}
        }
    }

    async fn ask_join(&self, chat: i64) {
        let ch = self.db().get("channel");
        let link = format!("url:https://t.me/{}", ch.trim_start_matches('@'));
        self.send(chat, &format!("📢 برای استفاده از ربات، اول عضو کانال {} شوید.", esc(&ch)),
            Some(ik(vec![vec![b("📢 عضویت در کانال", &link)], vec![b("✅ عضو شدم", "home")]]))).await;
    }

    async fn got_receipt(&self, uid: i64, chat: i64, name: &str, method: &str, m: &Value) {
        let pe = self.pend.lock().unwrap().get(&uid).cloned();
        let Some(pe) = pe else { return };
        let Some(p) = self.plan(pe.plan) else { return };
        let photo = m["photo"].as_array().and_then(|a| a.last()).and_then(|x| x["file_id"].as_str()).map(|s| s.to_string());
        let reference = photo.clone().unwrap_or_else(|| m["text"].as_str().unwrap_or("").to_string());
        let (t, u) = self.price(&p, &pe);
        let amount = if method == "card" { t.to_string() } else { u.to_string() };
        let oid = self.new_order(uid, &p, &pe, method, &amount, "pending", &reference);
        self.send(chat, &format!("✅ رسید سفارش #{} ثبت شد؛ بعد از تأیید، اشتراک خودکار فعال می‌شود.", oid), Some(self.home_kb(uid))).await;
        let cap = format!(
            "🧾 <b>سفارش جدید #{}</b>\n👤 {} · <code>{}</code>\n📦 {} ({})\n💳 {} · {}{}",
            oid, esc(name), uid, esc(&p.name), if pe.kind == "renew" { "تمدید" } else { "جدید" }, method, amount,
            if pe.discount.is_empty() { String::new() } else { format!("\n🎟 {} ({}٪)", pe.discount, pe.percent) }
        );
        let kb = ik(vec![vec![b("✅ تأیید", &format!("ap:{}", oid)), b("❌ رد", &format!("rj:{}", oid))]]);
        if photo.is_some() {
            self.notify_admins(&cap, Some(kb), photo).await;
        } else {
            self.notify_admins(&format!("{}\n\nTXID: <code>{}</code>", cap, esc(&reference)), Some(kb), None).await;
        }
    }

    fn new_order(&self, uid: i64, p: &Plan, pe: &Pending, method: &str, amount: &str, status: &str, reference: &str) -> i64 {
        let kind = if pe.kind.is_empty() { "new".to_string() } else { pe.kind.clone() };
        self.db().with(|c| {
            let _ = c.execute(
                "INSERT INTO orders(tg_id,plan_id,kind,target,method,amount,status,ref,discount,created) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
                rusqlite::params![uid, p.id, kind, pe.target, method, amount, status, reference, pe.discount, now()],
            );
            c.last_insert_rowid()
        })
    }

    // ============================================================ دکمه‌ها
    async fn on_callback(&self, q: &Value) {
        let uid = q["from"]["id"].as_i64().unwrap_or(0);
        let chat = q["message"]["chat"]["id"].as_i64().unwrap_or(uid);
        let mid = q["message"]["message_id"].as_i64().unwrap_or(0);
        let qid = q["id"].as_str().unwrap_or("").to_string();
        let d = q["data"].as_str().unwrap_or("").to_string();
        let name = q["from"]["first_name"].as_str().unwrap_or("").to_string();
        self.touch(uid, &name, 0);
        self.answer(&qid, "", false).await;
        let back = |to: &str| vec![b("⬅️ بازگشت", to)];

        if !self.joined(uid).await {
            return self.ask_join(chat).await;
        }

        match d.as_str() {
            "home" => {
                self.waits.lock().unwrap().remove(&uid);
                return self.edit(chat, mid, &self.db().get("welcome"), Some(self.home_kb(uid))).await;
            }
            "buy" => {
                if !self.db().on("sales_on") && !self.admin(uid) {
                    return self.edit(chat, mid, "⛔ فروش موقتاً بسته است.", Some(ik(vec![back("home")]))).await;
                }
                self.pend.lock().unwrap().insert(uid, Pending { kind: "new".into(), ..Default::default() });
                return self.plans_menu(chat, mid, "pl").await;
            }
            "trial" => return self.trial(uid, chat, mid).await,
            "my" | "renew" => {
                let accs = self.db().users_of_tg(uid);
                if accs.is_empty() {
                    return self.edit(chat, mid, "هنوز سرویسی ندارید. از «خرید اشتراک» شروع کنید 🛒", Some(ik(vec![back("home")]))).await;
                }
                let pre = if d == "my" { "acc" } else { "rnw" };
                let mut rows: Kb = accs.iter().map(|u| vec![b(&format!("{} {}", if u.active() { "🟢" } else { "🔴" }, u.username), &format!("{}:{}", pre, u.id))]).collect();
                rows.push(back("home"));
                return self.edit(chat, mid, "سرویس موردنظر را انتخاب کنید:", Some(ik(rows))).await;
            }
            "ref" => {
                let me = self.call("getMe", json!({})).await.and_then(|v| v["username"].as_str().map(|s| s.to_string())).unwrap_or_default();
                let cnt: i64 = self.db().with(|c| c.query_row("SELECT COUNT(*) FROM bot_users WHERE ref_by=?1", [uid], |r| r.get(0)).unwrap_or(0));
                return self.edit(chat, mid, &format!(
                    "👥 <b>دعوت دوستان</b>\n\nبا اولین خرید هر دوستی که با لینک شما بیاید، <b>{} گیگ و {} روز</b> هدیه به سرویس شما اضافه می‌شود 🎁\n\n🔗 لینک شما:\n<code>https://t.me/{}?start=ref_{}</code>\n\n👤 تعداد دعوت‌ها: {}",
                    self.db().get("ref_gb"), self.db().get("ref_days"), me, uid, cnt), Some(ik(vec![back("home")]))).await;
            }
            "app" => {
                let l = self.db().get("app_link");
                return self.edit(chat, mid, &format!("📱 <b>دانلود اپ</b>\n\n{}\n\nبعد از نصب، «کد ورود» سرویس را در اپ وارد کنید.",
                    if l.is_empty() { "لینک هنوز تنظیم نشده.".to_string() } else { esc(&l) }), Some(ik(vec![back("home")]))).await;
            }
            "support" => return self.edit(chat, mid, &format!("💬 پشتیبانی: {}", esc(&self.db().get("support"))), Some(ik(vec![back("home")]))).await,
            "disc" => {
                self.waits.lock().unwrap().insert(uid, Wait::DiscountUse);
                return self.edit(chat, mid, "🎟 کد تخفیف را بفرستید:", Some(ik(vec![back("home")]))).await;
            }
            _ => {}
        }

        let (head, rest) = d.split_once(':').unwrap_or((d.as_str(), ""));
        match head {
            "pcat" => {
                let (mode, sel) = rest.split_once(':').unwrap_or(("b", "m"));
                let pattern = if mode == "b" { "pl".to_string() } else { format!("rpl:{{}}:{}", mode.get(1..).unwrap_or("0")) };
                return self.plans_menu_sel(chat, mid, &pattern, sel).await;
            }
            "pl" | "rpl" => {
                let mut parts = rest.split(':');
                let pid: i64 = parts.next().and_then(|x| x.parse().ok()).unwrap_or(0);
                {
                    let mut g = self.pend.lock().unwrap();
                    let pe = g.entry(uid).or_default();
                    pe.plan = pid;
                    if head == "rpl" {
                        pe.kind = "renew".into();
                        pe.target = parts.next().and_then(|x| x.parse().ok()).unwrap_or(0);
                    } else if pe.kind.is_empty() {
                        pe.kind = "new".into();
                    }
                }
                return self.show_plan(chat, Some(mid), uid, pid).await;
            }
            "pay" => return self.pay(uid, chat, mid, rest).await,
            "npc" => return self.np_start(uid, chat, mid, rest).await,
            "chk" => {
                let oid: i64 = rest.parse().unwrap_or(0);
                let o = self.order(oid);
                let Some(o) = o else { return };
                if o.1 != uid { return; }
                if o.6 == "done" {
                    return self.answer(&qid, "این سفارش قبلاً فعال شده ✅", true).await;
                }
                if self.check_gateway(oid).await {
                    self.edit(chat, mid, "✅ پرداخت تأیید شد؛ در حال ساخت اشتراک…", None).await;
                    return self.fulfill(oid).await;
                }
                return self.answer(&qid, "هنوز پرداختی تأیید نشده است.", true).await;
            }
            "acc" => {
                let id: i64 = rest.parse().unwrap_or(0);
                if let Some(u) = self.app.db.user(id).filter(|u| u.tg_id == uid || self.admin(uid)) {
                    return self.edit(chat, mid, &self.account_text(&u), Some(ik(vec![vec![b("🔁 تمدید همین سرویس", &format!("rnw:{}", id))], back("my")]))).await;
                }
                return;
            }
            "rnw" => {
                let id: i64 = rest.parse().unwrap_or(0);
                self.pend.lock().unwrap().insert(uid, Pending { kind: "renew".into(), target: id, ..Default::default() });
                return self.plans_menu(chat, mid, &format!("rpl:{{}}:{}", id)).await;
            }
            "ap" | "rj" if self.admin(uid) => return self.review(chat, mid, q, head == "ap", rest.parse().unwrap_or(0)).await,
            _ => {}
        }
        if self.admin(uid) {
            self.admin_cb(uid, chat, mid, &d).await;
        }
    }

    async fn plans_menu(&self, chat: i64, mid: i64, pattern: &str) {
        self.plans_menu_sel(chat, mid, pattern, "m").await
    }

    /// sel: "m" = category menu (or the flat list when there are no categories), "o" = plans without a category, "<n>" = n-th category.
    async fn plans_menu_sel(&self, chat: i64, mid: i64, pattern: &str, sel: &str) {
        let mut list: Vec<Plan> = self.plans(true).into_iter().map(|x| x.0).collect();
        // categories are ordered by their shortest duration, then by name
        let mut cats: Vec<(i64, String)> = vec![];
        for p in list.iter() {
            if p.category.is_empty() { continue; }
            if let Some(i) = cats.iter().position(|c| c.1 == p.category) {
                if p.days < cats[i].0 { cats[i].0 = p.days; }
            } else {
                cats.push((p.days, p.category.clone()));
            }
        }
        cats.sort();
        let has_other = list.iter().any(|p| p.category.is_empty());
        let mode = if pattern == "pl" { "b".to_string() } else { format!("r{}", pattern.rsplit(':').next().unwrap_or("0")) };
        let mut title = String::from("🛒 <b>یک پلن انتخاب کنید:</b>\n");
        let mut back_to = "home".to_string();
        if !cats.is_empty() {
            if sel == "m" {
                let mut rows: Kb = cats.iter().enumerate().map(|(i, c)| vec![b(&format!("📂 {}", c.1), &format!("pcat:{}:{}", mode, i))]).collect();
                if has_other { rows.push(vec![b("📦 سایر پلن‌ها", &format!("pcat:{}:o", mode))]); }
                rows.push(vec![b("⬅️ بازگشت", "home")]);
                return self.edit(chat, mid, "🛒 <b>یک دسته‌بندی انتخاب کنید:</b>", Some(ik(rows))).await;
            }
            let want: String = if sel == "o" {
                String::new()
            } else {
                sel.parse::<usize>().ok().and_then(|i| cats.get(i)).map(|c| c.1.clone()).unwrap_or_default()
            };
            if !want.is_empty() { title = format!("📂 <b>{}</b>\n", esc(&want)); }
            list.retain(|p| p.category == want);
            back_to = format!("pcat:{}:m", mode);
        }
        // ordered by duration, then number of users, then price; the text groups them by duration
        list.sort_by(|x, y| (x.days, x.conns, x.toman).cmp(&(y.days, y.conns, y.toman)));
        let mut rows: Kb = vec![];
        let mut txt = title;
        let mut last_days: i64 = -1;
        for p in list.iter() {
            let price = if p.toman > 0 { toman(p.toman) } else { format!("{}$", p.usd) };
            let dur = if p.days > 0 && p.days % 30 == 0 { format!("{} ماهه", p.days / 30) } else { format!("{} روزه", p.days) };
            let vol = if p.gb > 0.0 { format!("{}GB", p.gb) } else { "نامحدود".to_string() };
            if p.days != last_days {
                txt.push_str(&format!("\n📅 <b>{}</b>\n", dur));
                last_days = p.days;
            }
            txt.push_str(&format!("• {} — 👤 {} کاربر — {} — {}\n", esc(&p.name), p.conns, vol, price));
            let data = if pattern.contains("{}") { pattern.replace("{}", &p.id.to_string()) } else { format!("{}:{}", pattern, p.id) };
            rows.push(vec![b(&format!("📅 {} · 👤 {} · {} · {}", dur, p.conns, vol, price), &data)]);
        }
        if rows.is_empty() {
            return self.edit(chat, mid, "هنوز پلنی تعریف نشده است.", Some(ik(vec![vec![b("⬅️ بازگشت", &back_to)]]))).await;
        }
        rows.push(vec![b("⬅️ بازگشت", &back_to)]);
        self.edit(chat, mid, &txt, Some(ik(rows))).await;
    }

    async fn show_plan(&self, chat: i64, mid: Option<i64>, uid: i64, pid: i64) {
        let Some(p) = self.plan(pid) else { return };
        let pe = self.pend.lock().unwrap().get(&uid).cloned().unwrap_or_default();
        let (t, u) = self.price(&p, &pe);
        let db = self.db();
        let mut rows: Kb = vec![];
        if db.on("card_on") && !db.get("card_number").is_empty() && t > 0 { rows.push(vec![b("💳 کارت به کارت", "pay:card")]); }
        if db.on("zp_on") && !db.get("zp_merchant").is_empty() && t > 0 { rows.push(vec![b("🏦 درگاه بانکی (زرین‌پال)", "pay:zp")]); }
        if db.on("np_on") && !db.get("np_key").is_empty() && u > 0.0 { rows.push(vec![b("🪙 درگاه ارزی (خودکار)", "pay:np")]); }
        if db.on("wallet_on") && !db.get("wallet_text").is_empty() && u > 0.0 { rows.push(vec![b("💰 ارز دیجیتال (کیف پول)", "pay:wallet")]); }
        if pe.discount.is_empty() { rows.push(vec![b("🎟 کد تخفیف دارم", "disc")]); }
        rows.push(vec![b("⬅️ بازگشت", "home")]);
        let txt = format!(
            "📦 <b>{}</b>\nحجم: {} · مدت: {} روز · {} کاربر{}\nقیمت: <b>{}</b>{}{}\n\nروش پرداخت را انتخاب کنید:",
            esc(&p.name), if p.gb > 0.0 { format!("{} GB", p.gb) } else { "نامحدود".into() }, p.days, p.conns,
            if p.countries > 0 { format!(" · {} کشور", p.countries) } else { String::new() }, toman(t),
            if u > 0.0 { format!("  ·  <b>{}$</b>", u) } else { String::new() },
            if pe.percent > 0 { format!("\n🎟 تخفیف {}٪ اعمال شده", pe.percent) } else { String::new() }
        );
        match mid {
            Some(m) => self.edit(chat, m, &txt, Some(ik(rows))).await,
            None => { self.send(chat, &txt, Some(ik(rows))).await; }
        }
    }

    async fn pay(&self, uid: i64, chat: i64, mid: i64, method: &str) {
        let pe = self.pend.lock().unwrap().get(&uid).cloned();
        let Some(pe) = pe else { return };
        let Some(p) = self.plan(pe.plan) else { return };
        let (t, u) = self.price(&p, &pe);
        let db = self.db();
        let home = Some(ik(vec![vec![b("⬅️ بازگشت", "home")]]));
        match method {
            "card" => {
                self.waits.lock().unwrap().insert(uid, Wait::Receipt("card".into()));
                self.edit(chat, mid, &format!(
                    "💳 <b>کارت به کارت</b>\n\nمبلغ: <b>{}</b>\nشماره کارت:\n<code>{}</code>\nبه نام: {}\n\n📸 بعد از واریز، <b>عکس رسید</b> را همین‌جا بفرستید.",
                    toman(t), esc(&db.get("card_number")), esc(&db.get("card_holder"))), home).await;
            }
            "wallet" => {
                self.waits.lock().unwrap().insert(uid, Wait::Receipt("wallet".into()));
                self.edit(chat, mid, &format!("💰 <b>پرداخت ارزی</b>\n\nمبلغ: <b>{}$</b>\n\n{}\n\n📸 بعد از پرداخت، عکس یا TXID را بفرستید.",
                    u, esc(&db.get("wallet_text"))), home).await;
            }
            "np" => {
                let rows: Kb = db.get("np_coins").split(',').filter(|c| !c.trim().is_empty())
                    .map(|c| vec![b(&c.trim().to_uppercase(), &format!("npc:{}", c.trim()))]).collect();
                self.edit(chat, mid, "🪙 ارز پرداخت را انتخاب کنید:", Some(ik(rows))).await;
            }
            "zp" => {
                let oid = self.new_order(uid, &p, &pe, "zp", &t.to_string(), "waiting", "");
                let cb = { let c = db.get("zp_callback"); if c.is_empty() { origin(&self.app) } else { c } };
                let r = self.http.post("https://payment.zarinpal.com/pg/v4/payment/request.json").json(&json!({
                    "merchant_id": db.get("zp_merchant"), "amount": t * 10, "callback_url": cb, "description": format!("order {}", oid)
                })).send().await;
                let auth = match r { Ok(r) => r.json::<Value>().await.ok().and_then(|v| v["data"]["authority"].as_str().map(|s| s.to_string())), Err(_) => None };
                let Some(auth) = auth else {
                    return self.edit(chat, mid, "⚠️ خطای درگاه زرین‌پال؛ بعداً امتحان کنید.", home).await;
                };
                let _ = db.exec("UPDATE orders SET ref=?1 WHERE id=?2", &[&auth, &oid]);
                self.edit(chat, mid, &format!("🏦 مبلغ: <b>{}</b>\n\n۱. «پرداخت» را بزنید\n۲. بعد از پرداخت «بررسی پرداخت» را بزنید.", toman(t)),
                    Some(ik(vec![vec![b("💳 پرداخت", &format!("url:https://payment.zarinpal.com/pg/StartPay/{}", auth))],
                                 vec![b("🔍 بررسی پرداخت", &format!("chk:{}", oid))]]))).await;
            }
            _ => {}
        }
    }

    async fn np_start(&self, uid: i64, chat: i64, mid: i64, coin: &str) {
        let pe = self.pend.lock().unwrap().get(&uid).cloned();
        let Some(pe) = pe else { return };
        let Some(p) = self.plan(pe.plan) else { return };
        let (_, usd) = self.price(&p, &pe);
        let oid = self.new_order(uid, &p, &pe, "np", &usd.to_string(), "waiting", "");
        let r = self.http.post("https://api.nowpayments.io/v1/payment").header("x-api-key", self.db().get("np_key")).json(&json!({
            "price_amount": usd, "price_currency": "usd", "pay_currency": coin, "order_id": oid.to_string(), "order_description": format!("order {}", oid)
        })).send().await;
        let v = match r { Ok(r) => r.json::<Value>().await.ok(), Err(_) => None }.unwrap_or(Value::Null);
        let pid = v["payment_id"].as_i64().map(|x| x.to_string()).or_else(|| v["payment_id"].as_str().map(|s| s.to_string()));
        let Some(pid) = pid else {
            return self.edit(chat, mid, "⚠️ خطای درگاه ارزی؛ بعداً امتحان کنید.", Some(ik(vec![vec![b("⬅️ بازگشت", "home")]]))).await;
        };
        let _ = self.db().exec("UPDATE orders SET ref=?1 WHERE id=?2", &[&pid, &oid]);
        self.edit(chat, mid, &format!(
            "🪙 دقیقاً این مقدار را بفرستید:\n<b>{} {}</b>\n\nبه آدرس:\n<code>{}</code>\n\n✅ بعد از تأیید شبکه، اشتراک <b>خودکار</b> فعال می‌شود.",
            v["pay_amount"], coin.to_uppercase(), v["pay_address"].as_str().unwrap_or("")),
            Some(ik(vec![vec![b("🔍 بررسی پرداخت", &format!("chk:{}", oid))]]))).await;
    }

    /// (id, tg_id, plan_id, kind, target, method, status, amount, ref, discount)
    #[allow(clippy::type_complexity)]
    fn order(&self, oid: i64) -> Option<(i64, i64, i64, String, i64, String, String, String, String, String)> {
        self.db().with(|c| c.query_row(
            "SELECT id,tg_id,plan_id,kind,target,method,status,amount,ref,discount FROM orders WHERE id=?1", [oid],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?, r.get(8)?, r.get(9)?)),
        ).ok())
    }

    async fn check_gateway(&self, oid: i64) -> bool {
        let Some(o) = self.order(oid) else { return false };
        if o.5 == "np" {
            let r = self.http.get(format!("https://api.nowpayments.io/v1/payment/{}", o.8)).header("x-api-key", self.db().get("np_key")).send().await;
            if let Ok(r) = r {
                if let Ok(v) = r.json::<Value>().await {
                    return matches!(v["payment_status"].as_str(), Some("finished") | Some("confirmed"));
                }
            }
        } else if o.5 == "zp" {
            let amount: i64 = o.7.parse().unwrap_or(0);
            let r = self.http.post("https://payment.zarinpal.com/pg/v4/payment/verify.json").json(&json!({
                "merchant_id": self.db().get("zp_merchant"), "amount": amount * 10, "authority": o.8
            })).send().await;
            if let Ok(r) = r {
                if let Ok(v) = r.json::<Value>().await {
                    return matches!(v["data"]["code"].as_i64(), Some(100) | Some(101));
                }
            }
        }
        false
    }

    async fn fulfill(&self, oid: i64) {
        let Some(o) = self.order(oid) else { return };
        if o.6 == "done" { return; }
        let _ = self.db().exec("UPDATE orders SET status='done' WHERE id=?1", &[&oid]);
        let Some(p) = self.plan(o.2) else { return };
        // a buyer who still has a free-trial account gets that same account (USER<n>-TEST -> USER<n>)
        let trial = self.db().users_of_tg(o.1).into_iter().find(|u| u.username.to_uppercase().ends_with("-TEST"));
        let res: Result<User, String> = if o.3 == "renew" && o.4 > 0 {
            self.db().extend(o.4, p.days, p.gb).and_then(|_| {
                self.db().promote_trial(o.4);
                self.db().user(o.4).ok_or("not found".into())
            })
        } else if let Some(t) = trial {
            let exp = if p.days > 0 { crate::util::now() + p.days * 86400 } else { 0 };
            let lim = if p.gb > 0.0 { t.used_gb() + p.gb } else { 0.0 };
            let note = format!("order #{}", oid);
            self.db()
                .exec("UPDATE users SET expires_at=?1, limit_gb=?2, max_conn=?3, notes=?4, warned=0, enabled=1 WHERE id=?5", &[&exp, &lim, &p.conns, &note, &t.id])
                .and_then(|_| {
                    self.db().promote_trial(t.id);
                    self.db().user(t.id).ok_or("not found".into())
                })
        } else {
            self.create_account_n(o.1, p.gb, p.days, p.conns, &format!("order #{}", oid), p.countries)
        };
        match res {
            Ok(u) => {
                let head = if o.3 == "renew" { "✅ <b>اشتراک شما تمدید شد</b>" } else { "✅ <b>اشتراک شما فعال شد</b>" };
                self.send(o.1, &format!("{}\n\n{}", head, self.account_text(&u)), None).await;
                if !o.9.is_empty() {
                    let _ = self.db().exec("UPDATE discounts SET uses_left=uses_left-1 WHERE code=?1", &[&o.9]);
                }
                self.reward_referrer(o.1).await;
                let a = self.app.clone();
                tokio::spawn(async move { sync::sync_all(&a).await });
            }
            Err(e) => {
                let _ = self.db().exec("UPDATE orders SET status='error' WHERE id=?1", &[&oid]);
                self.notify_admins(&format!("⚠️ خطا در سفارش #{}: <code>{}</code>", oid, esc(&e)), None, None).await;
                self.send(o.1, "⚠️ پرداخت ثبت شد ولی ساخت اشتراک خطا داد؛ پشتیبانی پیگیری می‌کند.", None).await;
            }
        }
    }

    async fn reward_referrer(&self, tg: i64) {
        let r: Option<(i64, i64)> = self.db().with(|c| c.query_row(
            "SELECT ref_by, ref_rewarded FROM bot_users WHERE tg_id=?1", [tg], |r| Ok((r.get(0)?, r.get(1)?))).ok());
        let Some((by, done)) = r else { return };
        if by == 0 || done == 1 { return; }
        let _ = self.db().exec("UPDATE bot_users SET ref_rewarded=1 WHERE tg_id=?1", &[&tg]);
        let gb: f64 = self.db().get("ref_gb").parse().unwrap_or(0.0);
        let days: i64 = self.db().get("ref_days").parse().unwrap_or(0);
        if let Some(u) = self.db().users_of_tg(by).first() {
            if self.db().extend(u.id, days, gb).is_ok() {
                self.send(by, &format!("🎁 دوست شما خرید کرد! {} گیگ و {} روز به سرویس {} اضافه شد.", gb, days, esc(&u.username)), None).await;
            }
        }
    }

    async fn review(&self, chat: i64, mid: i64, q: &Value, approve: bool, oid: i64) {
        let Some(o) = self.order(oid) else { return };
        if o.6 != "pending" && o.6 != "error" {
            return self.answer(q["id"].as_str().unwrap_or(""), "این سفارش قبلاً بررسی شده.", true).await;
        }
        let note = if approve { "\n\n✅ تأیید شد" } else { "\n\n❌ رد شد" };
        let msg = &q["message"];
        if msg["photo"].is_array() {
            let cap = format!("{}{}", msg["caption"].as_str().unwrap_or(""), note);
            self.call("editMessageCaption", json!({"chat_id": chat, "message_id": mid, "caption": cap})).await;
        } else {
            let t = format!("{}{}", msg["text"].as_str().unwrap_or(""), note);
            self.call("editMessageText", json!({"chat_id": chat, "message_id": mid, "text": t})).await;
        }
        if approve {
            let _ = self.db().exec("UPDATE orders SET status='approved' WHERE id=?1", &[&oid]);
            self.fulfill(oid).await;
        } else {
            let _ = self.db().exec("UPDATE orders SET status='rejected' WHERE id=?1", &[&oid]);
            self.send(o.1, &format!("❌ رسید سفارش #{} تأیید نشد. پشتیبانی: {}", oid, esc(&self.db().get("support"))), None).await;
        }
    }

    async fn trial(&self, uid: i64, chat: i64, mid: i64) {
        let back = Some(ik(vec![vec![b("⬅️ بازگشت", "home")]]));
        if !self.db().on("trial_on") {
            return self.edit(chat, mid, "تست رایگان فعلاً غیرفعال است.", back).await;
        }
        let used: i64 = self.db().with(|c| c.query_row("SELECT trial_used FROM bot_users WHERE tg_id=?1", [uid], |r| r.get(0)).unwrap_or(0));
        if used == 1 && !self.admin(uid) {
            return self.edit(chat, mid, "شما قبلاً از تست رایگان استفاده کرده‌اید 🙂", back).await;
        }
        let gb: f64 = self.db().get("trial_gb").parse().unwrap_or(1.0);
        let days: i64 = self.db().get("trial_days").parse().unwrap_or(1);
        match self.create_account(uid, gb, days, 1, "trial") {
            Ok(u) => {
                let _ = self.db().exec("UPDATE bot_users SET trial_used=1 WHERE tg_id=?1", &[&uid]);
                self.edit(chat, mid, &format!("🎁 <b>اکانت تست شما آماده است</b>\n\n{}", self.account_text(&u)), back).await;
            }
            Err(e) => {
                self.notify_admins(&format!("⚠️ خطای ساخت تست: <code>{}</code>", esc(&e)), None, None).await;
                self.edit(chat, mid, "⚠️ ساخت اکانت تست ناموفق بود.", back).await;
            }
        }
    }

    // ============================================================ مدیریت
    fn adm_kb(&self) -> Value {
        ik(vec![
            vec![b("📈 آمار", "a:stats"), b("🧾 سفارش‌های باز", "a:pend")],
            vec![b("🔍 جستجوی کاربر", "a:search"), b("➕ ساخت کانفیگ", "a:mk")],
            vec![b("📦 پلن‌ها", "a:plans"), b("🎁 تست رایگان", "a:trial")],
            vec![b("💳 پرداخت‌ها", "a:pay"), b("🖥 نودها", "a:nodes")],
            vec![b("🎟 کدهای تخفیف", "a:disc"), b("👥 دعوت و هدیه", "a:ref")],
            vec![b("📣 پیام همگانی", "a:bc"), b("💾 بکاپ الان", "a:backup")],
            vec![b("📢 کانال هوشمند", "a:ch"), b("⚙️ تنظیمات عمومی", "a:gen")],
            vec![b("⬅️ بازگشت", "home")],
        ])
    }

    fn onoff(&self, k: &str) -> &'static str {
        if self.db().on(k) { "🟢" } else { "⚪️" }
    }

    fn user_kb(&self, id: i64) -> Value {
        ik(vec![
            vec![b("➕ تمدید/افزایش", &format!("u:ext:{}", id)), b("🔄 ریست حجم", &format!("u:rst:{}", id))],
            vec![b("⏯ فعال/غیرفعال", &format!("u:tgl:{}", id)), b("🔑 لینک جدید", &format!("u:rgn:{}", id))],
            vec![b("🗑 حذف", &format!("u:del:{}", id)), b("🔗 جزئیات", &format!("u:inf:{}", id))],
            vec![b("⬅️ پنل مدیریت", "adm")],
        ])
    }

    /// صفحه‌های پنل مدیریت؛ اگر کلید شناخته شد true
    async fn admin_view(&self, uid: i64, chat: i64, mid: i64, d: &str) -> bool {
        let db = self.db();
        let back = Some(ik(vec![vec![b("⬅️ پنل مدیریت", "adm")]]));
        let set_wait = |w: Wait| { self.waits.lock().unwrap().insert(uid, w); };
        match d {
            "adm" => { self.edit(chat, mid, "👑 <b>پنل مدیریت</b>", Some(self.adm_kb())).await; return true; }
            "a:stats" => {
                let us = db.users();
                let bu: i64 = db.with(|c| c.query_row("SELECT COUNT(*) FROM bot_users", [], |r| r.get(0)).unwrap_or(0));
                let (cnt, rev): (i64, i64) = db.with(|c| c.query_row(
                    "SELECT COUNT(*), COALESCE(SUM(CASE WHEN method IN ('card','zp') THEN CAST(amount AS INTEGER) END),0) FROM orders WHERE status='done'",
                    [], |r| Ok((r.get(0)?, r.get(1)?))).unwrap_or((0, 0)));
                let today: i64 = db.with(|c| c.query_row("SELECT COUNT(*) FROM orders WHERE status='done' AND created>?1", [now() - 86400], |r| r.get(0)).unwrap_or(0));
                let ns = db.nodes();
                let txt = format!(
                    "📈 <b>آمار</b>\n\n👥 کاربران: <b>{}</b> (فعال: {})\n🟢 آنلاین: <b>{}</b>\n⛔ منقضی/تمام‌حجم: {}\n📊 مصرف کل: {:.1} GB\n🖥 نودها: {}/{} آنلاین\n\n🤖 کاربران ربات: <b>{}</b>\n🧾 فروش: <b>{}</b> (۲۴ ساعت اخیر: {})\n💰 درآمد ریالی: <b>{}</b>",
                    us.len(), us.iter().filter(|u| u.active()).count(), us.iter().filter(|u| u.online > 0).count(),
                    us.iter().filter(|u| !u.active()).count(), us.iter().map(|u| u.used_gb()).sum::<f64>(),
                    ns.iter().filter(|n| n.online).count(), ns.len(), bu, cnt, today, toman(rev));
                { self.edit(chat, mid, &txt, back).await; return true; }
            }
            "a:pend" => {
                let rows: Vec<(i64, String, String, String, i64)> = db.with(|c| {
                    let mut s = c.prepare("SELECT id,method,amount,status,tg_id FROM orders WHERE status IN ('pending','waiting','error') ORDER BY id DESC LIMIT 15").unwrap();
                    let v: Vec<(i64, String, String, String, i64)> = s.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))).unwrap().filter_map(|x| x.ok()).collect();
                    v
                });
                if rows.is_empty() {
                    { self.edit(chat, mid, "سفارش بازی وجود ندارد ✅", back).await; return true; }
                }
                let txt: Vec<String> = rows.iter().map(|o| format!("#{} · {} · {} · {} · <code>{}</code>", o.0, o.1, o.2, o.3, o.4)).collect();
                let mut kb: Kb = rows.iter().filter(|o| o.3 != "waiting").map(|o| vec![b(&format!("✅ تأیید #{}", o.0), &format!("ap:{}", o.0))]).collect();
                kb.push(vec![b("⬅️ پنل مدیریت", "adm")]);
                { self.edit(chat, mid, &format!("🧾 <b>سفارش‌های باز</b>\n\n{}", txt.join("\n")), Some(ik(kb))).await; return true; }
            }
            "a:search" => { set_wait(Wait::Search); { self.edit(chat, mid, "🔍 نام کاربری، شناسه یا آیدی تلگرام را بفرستید:", back).await; return true; } }
            "a:mk" => { set_wait(Wait::Make); { self.edit(chat, mid, "➕ بفرستید: <code>حجم_گیگ روز تعداد_اتصال [نام]</code>\nمثلاً: <code>50 30 2 ali</code>", back).await; return true; } }
            "a:plans" => {
                let mut kb: Kb = self.plans(false).into_iter().map(|(p, a)| vec![
                    b(&format!("{} {} · {}G · {}d · {} · {}$", if a { "🟢" } else { "⚪️" }, p.name, p.gb, p.days, p.toman, p.usd), &format!("pt:{}", p.id)),
                    b("🗑", &format!("pd:{}", p.id)),
                ]).collect();
                kb.push(vec![b("➕ افزودن پلن", "pa")]);
                kb.push(vec![b("⬅️ پنل مدیریت", "adm")]);
                { self.edit(chat, mid, "📦 <b>پلن‌ها</b> (روی هر پلن بزنید تا فعال/غیرفعال شود)", Some(ik(kb))).await; return true; }
            }
            "pa" => { set_wait(Wait::Plan); { self.edit(chat, mid, "بفرستید:\n<code>نام | روز | گیگ | تومان | دلار | اتصال</code>\nمثلاً:\n<code>یک‌ماهه | 30 | 50 | 150000 | 2.5 | 1</code>", back).await; return true; } }
            "a:trial" => { self.edit(chat, mid, &format!("🎁 <b>تست رایگان</b>\nحجم: {} GB · مدت: {} روز", db.get("trial_gb"), db.get("trial_days")),
                Some(ik(vec![vec![b(&format!("{} روشن/خاموش", self.onoff("trial_on")), "tg:trial_on")],
                    vec![b("✏️ حجم", "set:trial_gb"), b("✏️ مدت", "set:trial_days")], vec![b("⬅️ پنل مدیریت", "adm")]]))).await; return true; }
            "a:pay" => { self.edit(chat, mid, &format!("💳 <b>روش‌های پرداخت</b>\nکارت: {}", esc(&db.get("card_number"))),
                Some(ik(vec![
                    vec![b(&format!("{} کارت", self.onoff("card_on")), "tg:card_on"), b("✏️ شماره", "set:card_number"), b("✏️ نام", "set:card_holder")],
                    vec![b(&format!("{} زرین‌پال", self.onoff("zp_on")), "tg:zp_on"), b("✏️ مرچنت", "set:zp_merchant"), b("✏️ بازگشت", "set:zp_callback")],
                    vec![b(&format!("{} ارزی خودکار", self.onoff("np_on")), "tg:np_on"), b("✏️ API Key", "set:np_key"), b("✏️ ارزها", "set:np_coins")],
                    vec![b(&format!("{} کیف پول", self.onoff("wallet_on")), "tg:wallet_on"), b("✏️ آدرس‌ها", "set:wallet_text")],
                    vec![b("⬅️ پنل مدیریت", "adm")]]))).await; return true; }
            "a:nodes" => {
                let txt: Vec<String> = db.nodes().iter().map(|n| format!("{} <b>{}</b> · {}", if n.online { "🟢" } else { "🔴" }, esc(&n.name),
                    if n.enabled { "فعال" } else { "خاموش" })).collect();
                { self.edit(chat, mid, &format!("🖥 <b>نودها</b>\n\n{}\n\nافزودن نود از پنل وب انجام می‌شود.", txt.join("\n")), back).await; return true; }
            }
            "a:disc" => {
                let rows: Vec<(String, i64, i64)> = db.with(|c| {
                    let mut s = c.prepare("SELECT code,percent,uses_left FROM discounts").unwrap();
                    let v: Vec<(String, i64, i64)> = s.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap().filter_map(|x| x.ok()).collect();
                    v
                });
                let mut kb: Kb = rows.iter().map(|r| vec![b(&format!("🎟 {} · {}٪ · {} بار", r.0, r.1, r.2), "noop"), b("🗑", &format!("dd:{}", r.0))]).collect();
                kb.push(vec![b("➕ کد جدید", "da")]);
                kb.push(vec![b("⬅️ پنل مدیریت", "adm")]);
                { self.edit(chat, mid, "🎟 <b>کدهای تخفیف</b>", Some(ik(kb))).await; return true; }
            }
            "da" => { set_wait(Wait::DiscountAdd); { self.edit(chat, mid, "بفرستید: <code>کد درصد تعداد</code>\nمثلاً: <code>NOWRUZ 20 100</code>", back).await; return true; } }
            "a:ref" => { self.edit(chat, mid, &format!("👥 <b>هدیه‌ی دعوت</b>\nبه ازای اولین خرید هر دعوت‌شده: {} GB و {} روز", db.get("ref_gb"), db.get("ref_days")),
                Some(ik(vec![vec![b("✏️ گیگ هدیه", "set:ref_gb"), b("✏️ روز هدیه", "set:ref_days")], vec![b("⬅️ پنل مدیریت", "adm")]]))).await; return true; }
            "a:bc" => { set_wait(Wait::Broadcast); { self.edit(chat, mid, "📣 پیام را بفرستید (متن، عکس، ویدیو…):", back).await; return true; } }
            "a:backup" => {
                let pass = crate::backup::backup_pass(&self.app);
                if let Ok((bytes, name)) = make_archive(&self.app, &pass) {
                    self.send_doc(chat, bytes, &name, "💾 بکاپ کامل پنل (رمزدار — رمز در پنل > بکاپ)").await;
                }
                return true;
            }
            "a:ch" | "a:cht" => {
                if d == "a:cht" {
                    db.set("ch_on", if db.on("ch_on") { "0" } else { "1" });
                }
                let id = db.get("ch_id");
                let txt = format!(
                    "📢 <b>کانال هوشمند</b>\n\nکانال: {}\nوضعیت: {}\nهر {} ساعت یک پست (به‌جز ۱ تا ۸ صبح)\nپست‌های ارسال‌شده: {}\n\nربات باید ادمین کانال باشد. تنظیمات کامل در پنل وب > ربات فروش.",
                    if id.is_empty() { "تنظیم نشده".to_string() } else { esc(&id) },
                    if db.on("ch_on") { "🟢 روشن" } else { "⚪️ خاموش" },
                    db.get("ch_hours").parse::<i64>().unwrap_or(8), db.get("ch_count").parse::<i64>().unwrap_or(0)
                );
                let kb = ik(vec![
                    vec![b("📝 پست پیشنهادی", "a:chp"), b("🔥 کمپین تخفیف ۲۰٪", "a:chc")],
                    vec![b(&format!("{} انتشار خودکار", self.onoff("ch_on")), "a:cht")],
                    vec![b("⬅️ پنل مدیریت", "adm")],
                ]);
                self.edit(chat, mid, &txt, Some(kb)).await;
                return true;
            }
            "a:chp" => {
                let (kind, text) = crate::channel::make_post(&self.app, "auto");
                db.set("ch_draft", &text);
                db.set("ch_draft_kind", &kind);
                let kb = ik(vec![
                    vec![b("📤 ارسال به کانال", "a:chs"), b("🔄 یکی دیگر", "a:chp")],
                    vec![b("⬅️ کانال هوشمند", "a:ch")],
                ]);
                self.edit(chat, mid, &format!("👁 <b>پیش‌نمایش</b>\n➖➖➖➖➖\n{}", text), Some(kb)).await;
                return true;
            }
            "a:chs" => {
                let text = db.get("ch_draft");
                let back = Some(ik(vec![vec![b("⬅️ کانال هوشمند", "a:ch")]]));
                let r = crate::channel::send_to_channel(&self.app, &text).await;
                let msg = match r {
                    Ok(_) => "✅ در کانال منتشر شد.".to_string(),
                    Err(e) => format!("⚠️ ارسال نشد: <code>{}</code>\nآیدی کانال را در پنل وب بررسی کنید و ربات را ادمین کانال کنید.", esc(&e)),
                };
                self.edit(chat, mid, &msg, back).await;
                return true;
            }
            "a:chc" => {
                let back = Some(ik(vec![vec![b("⬅️ کانال هوشمند", "a:ch")]]));
                let msg = match crate::channel::new_campaign(&self.app, 20, 48, 300) {
                    Ok(code) => {
                        let (_, text) = crate::channel::make_post(&self.app, "offer");
                        match crate::channel::send_to_channel(&self.app, &text).await {
                            Ok(_) => format!("🔥 کمپین ساخته و منتشر شد.\nکد: <code>{}</code> · ۲۰٪ · ۴۸ ساعت", esc(&code)),
                            Err(e) => format!("کد <code>{}</code> ساخته شد ولی ارسال به کانال نشد: <code>{}</code>", esc(&code), esc(&e)),
                        }
                    }
                    Err(e) => format!("⚠️ {}", esc(&e)),
                };
                self.edit(chat, mid, &msg, back).await;
                return true;
            }
            "a:gen" => { self.edit(chat, mid, &format!("⚙️ <b>تنظیمات عمومی</b>\nپشتیبانی: {}\nکانال اجباری: {}\nلینک اپ: {}",
                esc(&db.get("support")), esc(&db.get("channel")), esc(&db.get("app_link"))),
                Some(ik(vec![
                    vec![b(&format!("{} فروش", self.onoff("sales_on")), "tg:sales_on"), b(&format!("{} هشدار اتمام", self.onoff("warn_on")), "tg:warn_on")],
                    vec![b(&format!("{} بکاپ روزانه", self.onoff("backup_on")), "tg:backup_on")],
                    vec![b("✏️ پشتیبانی", "set:support"), b("✏️ کانال اجباری", "set:channel")],
                    vec![b("✏️ لینک اپ", "set:app_link"), b("✏️ خوش‌آمد", "set:welcome")],
                    vec![b("⬅️ پنل مدیریت", "adm")]]))).await; return true; }
            _ => return false,
        }
    }

    async fn admin_cb(&self, uid: i64, chat: i64, mid: i64, d: &str) {
        if self.admin_view(uid, chat, mid, d).await {
            return;
        }
        let db = self.db();
        let back = Some(ik(vec![vec![b("⬅️ پنل مدیریت", "adm")]]));
        let set_wait = |w: Wait| { self.waits.lock().unwrap().insert(uid, w); };
        let (head, rest) = d.split_once(':').unwrap_or((d, ""));
        match head {
            "tg" => {
                db.set(rest, if db.on(rest) { "0" } else { "1" });
                let to = match rest { "trial_on" => "a:trial", "sales_on" | "warn_on" | "backup_on" => "a:gen", _ => "a:pay" };
                self.admin_view(uid, chat, mid, to).await;
            }
            "set" => {
                set_wait(Wait::Set(rest.to_string()));
                self.edit(chat, mid, &format!("مقدار جدید «{}» را بفرستید.\nمقدار فعلی: <code>{}</code>", rest, esc(&db.get(rest))), back).await;
            }
            "pt" => {
                let id: i64 = rest.parse().unwrap_or(0);
                let _ = db.exec("UPDATE plans SET active=1-active WHERE id=?1", &[&id]);
                self.admin_view(uid, chat, mid, "a:plans").await;
            }
            "pd" => {
                let id: i64 = rest.parse().unwrap_or(0);
                let _ = db.exec("DELETE FROM plans WHERE id=?1", &[&id]);
                self.admin_view(uid, chat, mid, "a:plans").await;
            }
            "dd" => {
                let _ = db.exec("DELETE FROM discounts WHERE code=?1", &[&rest]);
                self.admin_view(uid, chat, mid, "a:disc").await;
            }
            "u" => {
                let (act, id) = rest.split_once(':').unwrap_or(("", "0"));
                let id: i64 = id.parse().unwrap_or(0);
                let r: Result<(), String> = match act {
                    "ext" => { set_wait(Wait::Extend(id)); return self.edit(chat, mid, "بفرستید: <code>روز گیگ</code> (مثلاً <code>30 50</code>)", back).await; }
                    "rst" => db.exec("UPDATE users SET used_bytes=0, warned=0 WHERE id=?1", &[&id]).map(|_| ()),
                    "tgl" => db.exec("UPDATE users SET enabled=1-enabled WHERE id=?1", &[&id]).map(|_| ()),
                    "rgn" => db.exec("UPDATE users SET code=?1 WHERE id=?2", &[&crate::util::rand_digits(19), &id]).map(|_| ()),
                    "del" => return self.edit(chat, mid, "⚠️ کاربر کامل حذف شود؟", Some(ik(vec![vec![b("🗑 بله", &format!("u:dly:{}", id))], vec![b("⬅️ پنل مدیریت", "adm")]]))).await,
                    "dly" => { db.delete_user(id); let a = self.app.clone(); tokio::spawn(async move { sync::sync_all(&a).await }); return self.edit(chat, mid, "🗑 حذف شد.", back).await; }
                    _ => Ok(()),
                };
                let a = self.app.clone();
                tokio::spawn(async move { sync::sync_all(&a).await });
                let txt = match (r, db.user(id)) {
                    (Ok(_), Some(u)) => format!("✅\n\n{}", self.account_text(&u)),
                    (Err(e), _) => format!("⚠️ {}", esc(&e)),
                    _ => "پیدا نشد".into(),
                };
                self.edit(chat, mid, &txt, Some(self.user_kb(id))).await;
            }
            _ => {}
        }
    }

    async fn admin_input(&self, uid: i64, chat: i64, w: Wait, text: &str, m: &Value) {
        let db = self.db();
        let kb = Some(self.adm_kb());
        let parts: Vec<&str> = text.split_whitespace().collect();
        match w {
            Wait::Set(k) => { db.set(&k, text); self.send(chat, "✅ ذخیره شد", kb).await; }
            Wait::Plan => {
                let f: Vec<&str> = text.split('|').map(|x| x.trim()).collect();
                if f.len() < 6 { self.send(chat, "⚠️ فرمت نادرست است.", kb).await; return; }
                let r = db.exec("INSERT INTO plans(name,days,gb,toman,usd,conns) VALUES(?1,?2,?3,?4,?5,?6)", &[
                    &f[0], &f[1].parse::<i64>().unwrap_or(30), &f[2].parse::<f64>().unwrap_or(0.0),
                    &f[3].parse::<i64>().unwrap_or(0), &f[4].parse::<f64>().unwrap_or(0.0), &f[5].parse::<i64>().unwrap_or(1)]);
                self.send(chat, if r.is_ok() { "✅ پلن اضافه شد" } else { "⚠️ خطا" }, kb).await;
            }
            Wait::Search => {
                let q = text.to_lowercase();
                let res: Vec<User> = db.users().into_iter().filter(|u| u.username.to_lowercase().contains(&q) || u.id.to_string() == q || u.tg_id.to_string() == q).take(20).collect();
                if res.is_empty() { self.send(chat, "کاربری پیدا نشد.", kb).await; return; }
                let mut rows: Kb = res.iter().map(|u| vec![b(&format!("{} {} · #{}", if u.active() { "🟢" } else { "🔴" }, u.username, u.id), &format!("u:inf:{}", u.id))]).collect();
                rows.push(vec![b("⬅️ پنل مدیریت", "adm")]);
                self.send(chat, "نتایج:", Some(ik(rows))).await;
            }
            Wait::Make => {
                if parts.len() < 2 { self.send(chat, "⚠️ فرمت نادرست است.", kb).await; return; }
                let gb: f64 = parts[0].parse().unwrap_or(0.0);
                let days: i64 = parts[1].parse().unwrap_or(30);
                let conns: i64 = parts.get(2).and_then(|x| x.parse().ok()).unwrap_or(1);
                let name = parts.get(3).map(|s| s.to_string()).unwrap_or_else(|| "auto".to_string());
                match db.create_user(&name, gb, days, conns, &db.get("default_protocols"), "", "admin", 0) {
                    Ok(u) => {
                        let a = self.app.clone();
                        tokio::spawn(async move { sync::sync_all(&a).await });
                        self.send(chat, &format!("✅ ساخته شد\n\n{}", self.account_text(&u)), Some(self.user_kb(u.id))).await;
                    }
                    Err(e) => { self.send(chat, &format!("⚠️ {}", esc(&e)), kb).await; }
                }
            }
            Wait::Extend(id) => {
                let days: i64 = parts.first().and_then(|x| x.parse().ok()).unwrap_or(0);
                let gb: f64 = parts.get(1).and_then(|x| x.parse().ok()).unwrap_or(0.0);
                match db.extend(id, days, gb).map(|_| db.promote_trial(id)) {
                    Ok(_) => {
                        let a = self.app.clone();
                        tokio::spawn(async move { sync::sync_all(&a).await });
                        let t = db.user(id).map(|u| self.account_text(&u)).unwrap_or_default();
                        self.send(chat, &format!("✅ تمدید شد\n\n{}", t), Some(self.user_kb(id))).await;
                    }
                    Err(e) => { self.send(chat, &format!("⚠️ {}", esc(&e)), kb).await; }
                }
            }
            Wait::DiscountAdd => {
                if parts.len() < 3 { self.send(chat, "⚠️ فرمت نادرست است.", kb).await; return; }
                let r = db.exec("INSERT OR REPLACE INTO discounts(code,percent,uses_left) VALUES(?1,?2,?3)",
                    &[&parts[0].to_uppercase(), &parts[1].parse::<i64>().unwrap_or(0), &parts[2].parse::<i64>().unwrap_or(0)]);
                self.send(chat, if r.is_ok() { "✅ کد تخفیف ساخته شد" } else { "⚠️ خطا" }, kb).await;
            }
            Wait::Broadcast => {
                let ids: Vec<i64> = db.with(|c| {
                    let mut s = c.prepare("SELECT tg_id FROM bot_users WHERE blocked=0").unwrap();
                    let v: Vec<i64> = s.query_map([], |r| r.get(0)).unwrap().filter_map(|x| x.ok()).collect();
                    v
                });
                let (from, msg_id) = (m["chat"]["id"].as_i64().unwrap_or(chat), m["message_id"].as_i64().unwrap_or(0));
                let mut ok = 0;
                for t in ids {
                    if self.call("copyMessage", json!({"chat_id": t, "from_chat_id": from, "message_id": msg_id})).await.is_some() {
                        ok += 1;
                    } else {
                        let _ = db.exec("UPDATE bot_users SET blocked=1 WHERE tg_id=?1", &[&t]);
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
                self.send(chat, &format!("📣 برای {} کاربر ارسال شد.", ok), kb).await;
            }
            _ => {}
        }
        let _ = uid;
    }

    // ============================================================ کارهای زمان‌بندی‌شده
    /// Telegram alert to the admins when a node, tunnel server or tunnel stays down for about
    /// 90 seconds, and another one when it is back. Off when the setting `tg_alerts` is "0".
    async fn watch(self: Arc<Self>) {
        // after a panel restart the agents need a moment to report again
        tokio::time::sleep(std::time::Duration::from_secs(120)).await;
        // key -> (consecutive bad checks, alert already sent)
        let mut st: HashMap<String, (u32, bool)> = HashMap::new();
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            if self.db().get("tg_alerts") == "0" {
                continue;
            }
            let mut items: Vec<(String, String, bool)> = self
                .db()
                .nodes()
                .into_iter()
                .filter(|n| n.enabled)
                .map(|n| (format!("node:{}", n.id), format!("نود {}", n.name), n.online))
                .collect();
            items.extend(crate::tunnel::panel::health(&self.app));
            let keys: Vec<String> = items.iter().map(|i| i.0.clone()).collect();
            st.retain(|k, _| keys.contains(k));
            for (key, name, ok) in items {
                let mut msg: Option<String> = None;
                {
                    let e = st.entry(key).or_insert((0, false));
                    if ok {
                        if e.1 {
                            msg = Some(format!("🟢 <b>{}</b> دوباره آنلاین شد", esc(&name)));
                        }
                        *e = (0, false);
                    } else {
                        e.0 += 1;
                        if e.0 >= 3 && !e.1 {
                            e.1 = true;
                            msg = Some(format!("🔴 <b>{}</b> آفلاین است", esc(&name)));
                        }
                    }
                }
                if let Some(m) = msg {
                    self.notify_admins(&m, None, None).await;
                }
            }
        }
    }

    async fn background(self: Arc<Self>) {
        let mut tick: u64 = 0;
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            tick += 1;
            // پرداخت‌های ارزی خودکار
            let waiting: Vec<i64> = self.db().with(|c| {
                let mut s = c.prepare("SELECT id FROM orders WHERE status='waiting' AND method='np' AND created>?1").unwrap();
                let v: Vec<i64> = s.query_map([now() - 2 * 86400], |r| r.get(0)).unwrap().filter_map(|x| x.ok()).collect();
                v
            });
            for oid in waiting {
                if self.check_gateway(oid).await {
                    self.fulfill(oid).await;
                }
            }
            // هشدار اتمام حجم/زمان (هر ۳۰ دقیقه)
            if tick % 30 == 0 && self.db().on("warn_on") {
                for u in self.db().users().into_iter().filter(|u| u.tg_id != 0) {
                    let mut flag = u.warned;
                    let mut msg = None;
                    if !u.active() && flag & 4 == 0 {
                        flag |= 4;
                        msg = Some(format!("⛔ سرویس <b>{}</b> تمام شد. برای ادامه، از «🔁 تمدید» استفاده کنید.", esc(&u.username)));
                    } else if u.limit_gb > 0.0 && (u.limit_gb - u.used_gb()) < (u.limit_gb * 0.1).max(1.0) && flag & 1 == 0 && u.active() {
                        flag |= 1;
                        msg = Some(format!("⚠️ حجم سرویس <b>{}</b> رو به اتمام است ({:.2} GB مانده).", esc(&u.username), (u.limit_gb - u.used_gb()).max(0.0)));
                    } else if u.expires_at > 0 && u.expires_at - now() < 86400 && flag & 2 == 0 && u.active() {
                        flag |= 2;
                        msg = Some(format!("⏳ سرویس <b>{}</b> کمتر از ۲۴ ساعت دیگر منقضی می‌شود.", esc(&u.username)));
                    }
                    if let Some(t) = msg {
                        let _ = self.db().exec("UPDATE users SET warned=?1 WHERE id=?2", &[&flag, &u.id]);
                        self.send(u.tg_id, &t, Some(ik(vec![vec![b("🔁 تمدید", &format!("rnw:{}", u.id))]]))).await;
                    }
                }
            }
            // بکاپ روزانه برای ادمین‌ها
            if tick % (24 * 60) == 0 && self.db().on("backup_on") {
                if let Ok((bytes, name)) = make_archive(&self.app, &self.db().get("tgb_pass")) {
                    for a in self.admins.clone() {
                        self.send_doc(a, bytes.clone(), &name, "💾 بکاپ خودکار روزانه").await;
                    }
                }
            }
        }
    }
}
