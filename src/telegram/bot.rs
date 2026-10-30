//! ربات تلگرام داخلی: فروش، پرداخت، سرویس‌ها، مدیریت کامل
use crate::api::{origin, sub_origin};
use crate::backup::make_archive;
use crate::db::User;
use crate::util::{cfg_name_from, ct_eq, esc, now, rand_token, valid_cfg_name};
use hmac::{Hmac, Mac};
use sha2::Sha256;
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
    BroadcastPin,
    DiscountAdd,
    DiscountUse,
    /// next message from the admin (video, file, photo or text) becomes a new tutorial
    GuideNew,
    GuideTitle(i64),
    GuideCap(i64),
    GuideFile(i64),
    /// (plan id, column)
    PlanField(i64, String),
    CatRename(String),
    /// a customer types the name of their config, then this continues ("trial" or "buy")
    CfgName(String),
    /// a customer renames one of their accounts
    Rename(i64),
    /// the admin types "days GB [reason]" of a gift: for one account, or 0 = every active account
    Gift(i64),
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
    /// Telegram Bot API address (a local fake one in the tests)
    api: String,
    waits: Mutex<HashMap<i64, Wait>>,
    pend: Mutex<HashMap<i64, Pending>>,
    /// a gift for everyone waiting for the admin's "yes": admin -> (days, GB, reason)
    gifts: Mutex<HashMap<i64, (i64, f64, String)>>,
}

type Kb = Vec<Vec<(String, String)>>;

fn b(t: &str, d: &str) -> (String, String) {
    (t.to_string(), d.to_string())
}

/// Every customer-facing button whose text the admin can change from the bot: (key, default text, where it shows).
/// The text is kept in the setting `btn_<key>`; an empty setting means the default.
const BTNS: &[(&str, &str, &str)] = &[
    ("buy", "🛒 خرید اشتراک", "منوی اصلی"),
    ("trial", "🎁 تست رایگان", "منوی اصلی"),
    ("my", "📊 سرویس‌های من", "منوی اصلی"),
    ("renew", "🔁 تمدید", "منوی اصلی"),
    ("guide", "🎬 آموزش اتصال", "منوی اصلی (فقط وقتی آموزشی اضافه شده باشد)"),
    ("ref", "👥 دعوت دوستان", "منوی اصلی"),
    ("app", "📱 دانلود اپ", "منوی اصلی"),
    ("support", "💬 پشتیبانی", "منوی اصلی"),
    ("guide_acc", "🎬 آموزش اتصال و استفاده از اپ", "زیر پیام اشتراک و دانلود اپ"),
    ("cfg_w", "📥 کانفیگ WireGuard", "زیر پیام اشتراک"),
    ("cfg_a", "📥 کانفیگ AmneziaWG", "زیر پیام اشتراک"),
    ("cfg_h", "📥 کانفیگ Hysteria2", "زیر پیام اشتراک"),
    ("renew_this", "🔁 تمدید همین سرویس", "زیر پیام اشتراک"),
    ("rename", "✏️ تغییر نام کانفیگ", "زیر پیام اشتراک"),
    ("other_plans", "📦 سایر پلن‌ها", "فهرست دسته‌بندی پلن‌ها"),
    ("disc", "🎟 کد تخفیف دارم", "صفحه‌ی پرداخت"),
    ("pay_card", "💳 کارت به کارت", "صفحه‌ی پرداخت"),
    ("pay_zp", "🏦 درگاه بانکی (زرین‌پال)", "صفحه‌ی پرداخت"),
    ("pay_np", "🪙 درگاه ارزی (خودکار)", "صفحه‌ی پرداخت"),
    ("pay_wallet", "💰 ارز دیجیتال (کیف پول)", "صفحه‌ی پرداخت"),
    ("back", "⬅️ بازگشت", "همه‌ی صفحه‌ها"),
    ("home", "🏠 منوی اصلی", "بعد از خرید و زیر آموزش‌ها"),
];

/// Buttons of the main menu, in order; each one can also be hidden (`hide_<key>` = 1).
const MAIN_BTNS: &[&str] = &["buy", "trial", "my", "renew", "guide", "ref", "app", "support"];

/// Messages the admin can rewrite from the bot: (setting key, default, title). HTML (<b>, <i>, <code>) is allowed.
const TEXTS: &[(&str, &str, &str)] = &[
    ("welcome", "به ربات فروش خوش آمدید 🌟", "پیام خوش‌آمد (منوی اصلی)"),
    ("txt_menu", "از منوی زیر استفاده کنید 👇", "جواب پیام‌های بی‌ربط"),
    ("txt_cats", "سلام 👋\nدسته‌بندی موردنظرتون رو از پایین انتخاب کنید 👇", "بالای دسته‌بندی پلن‌ها"),
    ("txt_plans", "سلام 👋\nپلن خودتون رو از پایین انتخاب کنید 👇", "بالای فهرست پلن‌ها"),
    ("txt_trial_ready", "🎁 <b>اکانت تست شما آماده است</b>", "بالای پیام اکانت تست"),
    ("txt_bought", "✅ <b>اشتراک شما فعال شد</b>", "بالای پیام بعد از خرید"),
    ("txt_renewed", "✅ <b>اشتراک شما تمدید شد</b>", "بالای پیام بعد از تمدید"),
    ("txt_cfg", "⚙️ اگه با برنامه‌ی دیگه‌ای (WireGuard، AmneziaWG، Hiddify…) وصل می‌شید، کانفیگ مخصوصش رو از دکمه‌های زیر بگیرید. همراه هر کانفیگ نوشته شده با کدوم برنامه کار می‌کنه و چطور واردش کنید 👇", "پایین پیام اشتراک"),
    ("txt_app", "بعد از نصب، «کد ورود» سرویس را در اپ وارد کنید.", "زیر لینک دانلود اپ"),
    ("txt_guides", "🎬 آموزش موردنظرتون رو از پایین انتخاب کنید 👇", "بالای فهرست آموزش‌ها"),
    ("txt_gift", "🎁 <b>کاربر گرامی، سلام</b> 🌷\n\nاز صبر و همراهی همیشگی شما صمیمانه سپاسگزاریم 💛\nبابت اختلالی که پیش آمد پوزش می‌خواهیم و به رسم جبران، هدیه‌ای کوچک از طرف ما به اشتراک شما اضافه شد:", "پیام هدیه‌ی حجم و زمان (جبران)"),
];

fn is_text_key(k: &str) -> bool {
    TEXTS.iter().any(|t| t.0 == k)
}

/// Which admin page a setting belongs to (where to go back after editing it).
fn back_view(k: &str) -> &'static str {
    match k {
        "trial_gb" | "trial_days" => "a:trial",
        "card_number" | "card_holder" | "zp_merchant" | "zp_callback" | "np_key" | "np_coins" | "wallet_text" => "a:pay",
        "ref_gb" | "ref_days" => "a:ref",
        "app_link" | "support" | "channel" => "a:links",
        _ if k.starts_with("btn_") => "a:btns",
        _ if is_text_key(k) => "a:txts",
        _ => "a:gen",
    }
}

/// Human name of a setting, for the "send the new value" prompt.
fn key_title(k: &str) -> String {
    if let Some(x) = k.strip_prefix("btn_") {
        if let Some(t) = BTNS.iter().find(|t| t.0 == x) {
            return format!("دکمه‌ی «{}»", t.1);
        }
    }
    if let Some(t) = TEXTS.iter().find(|t| t.0 == k) {
        return format!("متن «{}»", t.2);
    }
    match k {
        "app_link" => "لینک دانلود اپ".into(),
        "support" => "پشتیبانی (آیدی یا لینک)".into(),
        "channel" => "کانال اجباری (مثل @mychannel)".into(),
        "trial_gb" => "حجم تست (گیگ)".into(),
        "trial_days" => "مدت تست (روز)".into(),
        "ref_gb" => "گیگ هدیه‌ی دعوت".into(),
        "ref_days" => "روز هدیه‌ی دعوت".into(),
        _ => k.to_string(),
    }
}

/// The media of a message the admin sent for a tutorial: (kind, file id or text).
fn media_of(m: &Value) -> Option<(String, String)> {
    let id = |v: &Value| v["file_id"].as_str().map(|s| s.to_string());
    if let Some(f) = id(&m["video"]) { return Some(("video".into(), f)); }
    if let Some(f) = id(&m["animation"]) { return Some(("animation".into(), f)); }
    if let Some(f) = id(&m["document"]) { return Some(("document".into(), f)); }
    if let Some(f) = m["photo"].as_array().and_then(|a| a.last()).and_then(id) { return Some(("photo".into(), f)); }
    let t = m["text"].as_str().unwrap_or("").trim();
    if !t.is_empty() { return Some(("text".into(), String::new())); }
    None
}

fn kind_title(k: &str) -> &'static str {
    match k { "video" => "ویدیو", "animation" => "گیف", "document" => "فایل", "photo" => "عکس", _ => "متن" }
}

/// "38.2 MB"
fn mb(bytes: u64) -> String {
    format!("{:.1} MB", bytes as f64 / 1_000_000.0)
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
        if i > 0 && (s.len() - i).is_multiple_of(3) {
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

/// Shared secret with the channel bot that signs giveaway prize claims: panel setting (set with /claimkey), then env.
pub fn giveaway_secret(app: &App) -> String {
    let s = app.db.get("giveaway_secret");
    if s.is_empty() { app.env.get("GIVEAWAY_SECRET").cloned().unwrap_or_default() } else { s }
}

/// A giveaway prize from the channel bot: t.me/<this bot>?start=c_<gid>_<n>_<tg>_<gb>_<days>_<tag>_<sig>.
/// n: 0 = the exact score prediction, 1.. = the draw winners. sig = first 20 hex of
/// HMAC-SHA256(secret, "kgw1:<gid>.<n>.<tg>.<gb>.<days>.<tag>").
#[derive(Debug, PartialEq)]
pub struct Claim {
    pub gid: i64,
    pub n: i64,
    pub tg: i64,
    pub gb: i64,
    pub days: i64,
    pub tag: String,
}

pub fn claim_sig(secret: &str, payload: &str) -> String {
    let mut m = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("hmac key");
    m.update(format!("kgw1:{}", payload).as_bytes());
    hex::encode(m.finalize().into_bytes())[..20].to_string()
}

/// Checks the shape, the limits and the signature. Every number must be written plainly ("5", not "05"),
/// so one claim has exactly one spelling.
pub fn parse_claim(p: &str, secret: &str) -> Result<Claim, &'static str> {
    if secret.len() < 16 {
        return Err("off");
    }
    let f: Vec<&str> = p.split('_').collect();
    if f.len() != 7 {
        return Err("bad");
    }
    let num = |s: &str| -> Result<i64, &'static str> {
        let v: i64 = s.parse().map_err(|_| "bad")?;
        if v.to_string() != s { Err("bad") } else { Ok(v) }
    };
    let (gid, n, tg, gb, days) = (num(f[0])?, num(f[1])?, num(f[2])?, num(f[3])?, num(f[4])?);
    let tag = f[5];
    let ok_tag = (1..=10).contains(&tag.len()) && tag.chars().all(|c| c.is_ascii_alphanumeric());
    if gid < 1 || !(0..=50).contains(&n) || tg < 1 || !(1..=100).contains(&gb) || !(1..=90).contains(&days) || !ok_tag {
        return Err("bad");
    }
    let payload = format!("{}.{}.{}.{}.{}.{}", f[0], f[1], f[2], f[3], f[4], tag);
    if f[6].len() != 20 || !ct_eq(&claim_sig(secret, &payload), f[6]) {
        return Err("bad");
    }
    Ok(Claim { gid, n, tg, gb, days, tag: tag.to_string() })
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
            app, token, admins, http: reqwest::Client::new(), api: "https://api.telegram.org".into(),
            waits: Mutex::new(HashMap::new()), pend: Mutex::new(HashMap::new()), gifts: Mutex::new(HashMap::new()),
        }))
    }

    fn admin(&self, id: i64) -> bool {
        self.admins.contains(&id)
    }

    // ============================================================ editable texts, buttons and tutorials
    /// Text of a customer button (the admin's own text, or the default).
    fn bt(&self, k: &str) -> String {
        let v = self.db().get(&format!("btn_{}", k));
        if !v.trim().is_empty() {
            return v;
        }
        BTNS.iter().find(|t| t.0 == k).map(|t| t.1.to_string()).unwrap_or_else(|| k.to_string())
    }

    /// A message text (the admin's own text, or the default).
    fn tx(&self, k: &str) -> String {
        let v = self.db().get(k);
        if !v.trim().is_empty() {
            return v;
        }
        TEXTS.iter().find(|t| t.0 == k).map(|t| t.1.to_string()).unwrap_or_default()
    }

    /// Tutorials, in order; the first one is the "connection tutorial" under the account message.
    /// Kept as JSON in the setting `guides`: [{id, title, kind, file, caption}].
    fn guides(&self) -> Vec<Value> {
        serde_json::from_str::<Value>(&self.db().get("guides")).ok().and_then(|v| v.as_array().cloned()).unwrap_or_default()
    }

    fn save_guides(&self, g: &[Value]) {
        self.db().set("guides", &Value::Array(g.to_vec()).to_string());
    }

    fn guide(&self, id: i64) -> Option<Value> {
        self.guides().into_iter().find(|g| g["id"].as_i64() == Some(id))
    }

    /// Changes one field of a tutorial.
    fn guide_set(&self, id: i64, field: &str, value: Value) {
        let mut g = self.guides();
        for x in g.iter_mut() {
            if x["id"].as_i64() == Some(id) {
                x[field] = value.clone();
            }
        }
        self.save_guides(&g);
    }

    /// Sends one tutorial (video, gif, file, photo or text) with a button back to the main menu.
    async fn send_guide(&self, chat: i64, g: &Value) {
        let kind = g["kind"].as_str().unwrap_or("text");
        let file = g["file"].as_str().unwrap_or("");
        let title = g["title"].as_str().unwrap_or("");
        let cap = g["caption"].as_str().filter(|c| !c.trim().is_empty()).unwrap_or(title).to_string();
        let kb = ik(vec![vec![b(&self.bt("home"), "home")]]);
        let (method, field) = match kind {
            "video" => ("sendVideo", "video"),
            "animation" => ("sendAnimation", "animation"),
            "photo" => ("sendPhoto", "photo"),
            "document" => ("sendDocument", "document"),
            _ => ("", ""),
        };
        if method.is_empty() || file.is_empty() {
            self.send(chat, &esc(&cap), Some(kb)).await;
            return;
        }
        let short: String = cap.chars().take(1000).collect();
        let mut body = json!({"chat_id": chat, "caption": esc(&short), "parse_mode": "HTML", "reply_markup": kb});
        body[field] = json!(file);
        if kind == "video" {
            body["supports_streaming"] = json!(true);
        }
        if self.call(method, body).await.is_none() {
            self.send(chat, "⚠️ ارسال آموزش ناموفق بود؛ لطفاً به پشتیبانی پیام بدید.", None).await;
        }
    }

    /// The tutorial button for under the account / app messages (only when a tutorial exists).
    fn guide_row(&self) -> Option<Vec<(String, String)>> {
        if self.guides().is_empty() { None } else { Some(vec![b(&self.bt("guide_acc"), "guide1")]) }
    }

    // ============================================================ Bot API
    /// Copies one message to every bot user (optionally pinning it in each chat); returns how many got it.
    async fn broadcast(&self, from: i64, msg_id: i64, pin: bool) -> i64 {
        let db = &self.app.db;
        let ids: Vec<i64> = db.with(|c| {
            let mut s = c.prepare("SELECT tg_id FROM bot_users WHERE blocked=0").unwrap();
            let v: Vec<i64> = s.query_map([], |r| r.get(0)).unwrap().filter_map(|x| x.ok()).collect();
            v
        });
        let mut ok = 0;
        for t in ids {
            match self.call("copyMessage", json!({"chat_id": t, "from_chat_id": from, "message_id": msg_id})).await {
                Some(res) => {
                    ok += 1;
                    if pin {
                        if let Some(nid) = res["message_id"].as_i64() {
                            let _ = self.call("pinChatMessage", json!({"chat_id": t, "message_id": nid, "disable_notification": true})).await;
                        }
                    }
                }
                None => {
                    let _ = db.exec("UPDATE bot_users SET blocked=1 WHERE tg_id=?1", &[&t]);
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(60)).await;
        }
        ok
    }

    /// The reason getUpdates last failed ("" = it works). A refusal by Telegram (wrong token, another
    /// program polling the bot, a webhook) is kept apart from a connection cut on the way.
    fn set_poll_error(&self, e: &str) {
        if self.db().get("bot_poll_error") != e {
            self.db().set("bot_poll_error", e);
        }
    }

    async fn call(&self, m: &str, body: Value) -> Option<Value> {
        self.call_res(m, body).await.ok()
    }

    /// A Bot API call with Telegram's reason when it fails
    async fn call_res(&self, m: &str, body: Value) -> Result<Value, String> {
        let r = self.http.post(format!("{}/bot{}/{}", self.api, self.token, m))
            .json(&body).send().await.map_err(|e| e.to_string())?;
        let v: Value = r.json().await.map_err(|e| e.to_string())?;
        if v["ok"].as_bool() == Some(true) {
            return Ok(v["result"].clone());
        }
        let why = v["description"].as_str().unwrap_or("telegram error").to_string();
        // 409 on getUpdates: another program polls this bot (an old panel still running after a move):
        // both would answer customers and both would post to the channel
        if m == "getUpdates" && v["error_code"].as_i64() == Some(409) {
            self.db().set("bot_conflict", &now().to_string());
        }
        Err(why)
    }

    async fn send(&self, chat: i64, text: &str, kb: Option<Value>) -> Option<Value> {
        let mut body = json!({"chat_id": chat, "text": text, "parse_mode": "HTML", "disable_web_page_preview": true});
        if let Some(k) = kb { body["reply_markup"] = k; }
        self.call("sendMessage", body).await
    }

    async fn edit(&self, chat: i64, mid: i64, text: &str, kb: Option<Value>) {
        let mut body = json!({"chat_id": chat, "message_id": mid, "text": text, "parse_mode": "HTML", "disable_web_page_preview": true});
        if let Some(k) = kb.clone() { body["reply_markup"] = k; }
        // a message that cannot be edited any more gets a new one; the same text again (a button tapped
        // twice) is not a reason to send a second message
        if let Err(e) = self.call_res("editMessageText", body).await {
            if !e.contains("message is not modified") {
                self.send(chat, text, kb).await;
            }
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

    /// "Download the app": a button per phone type when the files are uploaded in the panel
    /// (the bot sends the file itself), else the download link of the settings.
    fn app_menu(&self, with_back: bool) -> (String, Kb) {
        let files = crate::apps::list(&self.app);
        let l = self.db().get("app_link");
        let mut rows: Kb = vec![];
        let text = if files.is_empty() {
            format!("📱 <b>دانلود اپ</b>\n\n{}\n\n{}", if l.is_empty() { "لینک هنوز تنظیم نشده.".to_string() } else { esc(&l) }, self.tx("txt_app"))
        } else {
            let ver = files.iter().map(|f| f.version.clone()).find(|v| !v.is_empty()).map(|v| format!(" · نسخه‌ی {}", v)).unwrap_or_default();
            let mut t = format!("📱 <b>دانلود اپ Kanki VPN</b>{}\n\nنسخه‌ی گوشی‌تون رو انتخاب کنید، فایل همین‌جا فرستاده می‌شه 👇\n", ver);
            for f in &files {
                let (title, hint) = crate::apps::title(&f.abi);
                t.push_str(&format!("\n• <b>{}</b>: {}", title, hint));
                rows.push(vec![b(&format!("⬇️ {} · {}", title, mb(f.size)), &format!("apk:{}", f.abi))]);
            }
            t.push_str(&format!("\n\n{}", self.tx("txt_app")));
            t
        };
        if let Some(r) = self.guide_row() { rows.push(r); }
        if with_back { rows.push(vec![b(&self.bt("back"), "home")]); }
        (text, rows)
    }

    /// Sends one install file: by Telegram's id when it was sent before, else uploaded from the panel
    /// (and its id kept, so the next customer gets it at once).
    async fn send_apk(&self, chat: i64, abi: &str) {
        let Some(f) = crate::apps::get_file(&self.app, abi) else {
            self.send(chat, "⚠️ این فایل دیگه نیست؛ دوباره «📱 دانلود اپ» رو بزنید.", None).await;
            return;
        };
        let (title, _) = crate::apps::title(abi);
        let cap = format!("📱 <b>{}</b>\n{} · {}\n\n{}", esc(&f.label()), title, mb(f.size), esc(&self.tx("txt_app")));
        if !f.tg.is_empty() && self.call("sendDocument", json!({"chat_id": chat, "document": f.tg, "caption": cap, "parse_mode": "HTML"})).await.is_some() {
            return;
        }
        if f.size > crate::apps::TG_MAX {
            let l = self.db().get("app_link");
            self.send(chat, &format!("⚠️ حجم این فایل برای تلگرام زیاده؛ از صفحه‌ی لینک اشتراک دانلودش کنید.{}", if l.is_empty() { String::new() } else { format!("\n{}", esc(&l)) }), None).await;
            return;
        }
        let Some(bytes) = crate::apps::read(&self.app, abi).await else { return };
        let _ = self.call("sendChatAction", json!({"chat_id": chat, "action": "upload_document"})).await;
        let part = reqwest::multipart::Part::bytes(bytes).file_name(f.file_name()).mime_str("application/vnd.android.package-archive").unwrap();
        let form = reqwest::multipart::Form::new().text("chat_id", chat.to_string()).text("caption", cap).text("parse_mode", "HTML").part("document", part);
        let r = self.http.post(format!("{}/bot{}/sendDocument", self.api, self.token)).multipart(form).timeout(std::time::Duration::from_secs(600)).send().await;
        let v: Value = match r {
            Ok(r) => r.json().await.unwrap_or(Value::Null),
            Err(_) => Value::Null,
        };
        match v["result"]["document"]["file_id"].as_str() {
            Some(id) => crate::apps::set_tg(&self.app, abi, id),
            None => {
                self.send(chat, "⚠️ ارسال فایل ناموفق بود؛ چند دقیقه‌ی دیگه دوباره امتحان کنید یا به پشتیبانی پیام بدید.", None).await;
            }
        }
    }

    async fn send_doc(&self, chat: i64, bytes: Vec<u8>, name: &str, caption: &str) {
        let part = reqwest::multipart::Part::bytes(bytes).file_name(name.to_string());
        let form = reqwest::multipart::Form::new()
            .text("chat_id", chat.to_string()).text("caption", caption.to_string()).part("document", part);
        let _ = self.http.post(format!("{}/bot{}/sendDocument", self.api, self.token)).multipart(form).send().await;
    }

    // ============================================================ کمکی‌های داده
    fn db(&self) -> &crate::db::Db {
        &self.app.db
    }

    fn plans(&self, only_active: bool) -> Vec<(Plan, bool)> {
        self.db().with(|c| {
            let mut s = c.prepare("SELECT id,name,COALESCE(days,0),COALESCE(gb,0),COALESCE(toman,0),COALESCE(usd,0),COALESCE(conns,1),COALESCE(active,1),COALESCE(countries,0),COALESCE(category,'') FROM plans ORDER BY toman").unwrap();
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
        let link = self.db().get("app_link");
        let files = !crate::apps::list(&self.app).is_empty();
        let step1 = if files {
            "1️⃣ برنامه رو با دکمه‌ی «📱 دانلود اپ» زیر همین پیام بگیرید و نصب کنید.\n\n".to_string()
        } else if link.is_empty() {
            String::new()
        } else {
            format!("1️⃣ برنامه رو از لینک زیر نصب کنید:\n{}\n\n", esc(&link))
        };
        let step2 = if step1.is_empty() { "با این کد وارد برنامه‌ی کانکی بشید:" } else { "2️⃣ با این کد وارد برنامه بشید:" };
        // other apps: the web link, or only the links bot when the configs are only in the Kanki apps
        let other = if !crate::devices::app_only(&self.app) {
            format!("\n\n🔗 لینک اشتراک (برای برنامه‌های دیگه):\n<code>{}/sub/{}</code>", sub_origin(&self.app), u.sub_code())
        } else {
            match self.db().get("links_bot_user") {
                b if b.is_empty() => String::new(),
                b => format!("\n\n🔗 لینک برای برنامه‌های دیگه (v2rayNG و …): @{}", esc(&b)),
            }
        };
        format!(
            "👤 <b>{}</b>  ·  {}\n📦 حجم باقی‌مانده: <b>{}</b>  (مصرف: {:.2} GB)\n⏳ زمان باقی‌مانده: <b>{}</b>\n🔌 اتصال: {}/{}\n\n📱 <b>بهترین راه (پیشنهاد ما): برنامه‌ی کانکی</b>\n{}{}\n<code>{}</code>{}",
            esc(&u.username), st, left, u.used_gb(), left_text(u), u.online, u.max_conn, step1, step2, u.sub_code(), other
        )
    }

    /// What the customer gets after a purchase / trial / "my service": the account plus a hint about the config buttons.
    fn account_msg(&self, u: &User) -> String {
        format!("{}\n\n{}", self.account_text(u), self.tx("txt_cfg"))
    }

    /// Buttons that send the config files, in a fixed order, followed by `extra` rows.
    fn acct_kb(&self, u: &User, mut extra: Kb) -> Value {
        let mut have: Vec<&str> = vec![];
        for n in crate::api::user_nodes(&self.app, u) {
            for p in crate::api::node_protos(&self.app, u, &n).into_iter().chain(crate::api::twin_protos(&self.app, u, &n)) {
                if !have.contains(&p) { have.push(p); }
            }
        }
        let mut rows: Kb = vec![];
        // the connection tutorial first, so a new customer sees it before the manual configs
        if let Some(r) = self.guide_row() {
            rows.push(r);
        }
        // the configs for other apps: one button to the links bot when it is set and the configs are only in
        // the Kanki apps (the separate bot is then the only place for them), else the file buttons
        let lb = self.db().get("links_bot_user");
        if crate::devices::app_only(&self.app) && !lb.is_empty() {
            rows.push(vec![b("🔗 لینک برای برنامه‌های دیگه", &format!("url:https://t.me/{}?start={}", lb, u.sub_code()))]);
        } else {
            for (p, code) in [("wireguard", "w"), ("amneziawg", "a"), ("hysteria2", "h")] {
                if have.contains(&p) {
                    rows.push(vec![b(&self.bt(&format!("cfg_{}", code)), &format!("cfg:{}:{}", u.id, code))]);
                }
            }
        }
        rows.push(vec![b(&self.bt("rename"), &format!("ren:{}", u.id))]);
        // the app's install files (sent as a new message, so this account message stays)
        if !crate::apps::list(&self.app).is_empty() {
            rows.push(vec![b(&self.bt("app"), "app2")]);
        }
        rows.append(&mut extra);
        ik(rows)
    }

    /// Sends the config(s) of one protocol: first a short "which app and how" guide, then a file per server
    /// (Hysteria2 as a copyable link).
    async fn send_configs(&self, chat: i64, qid: &str, u: &User, code: &str) {
        let (proto, title) = match code { "w" => ("wireguard", "WireGuard"), "a" => ("amneziawg", "AmneziaWG"), _ => ("hysteria2", "Hysteria2") };
        // each server's direct config, then its copy through the tunnel (WireGuard only that one)
        let mut list: Vec<(crate::db::Node, bool)> = vec![];
        for n in crate::api::user_nodes(&self.app, u) {
            if crate::api::node_protos(&self.app, u, &n).contains(&proto) {
                list.push((n.clone(), false));
            }
            if crate::api::twin_protos(&self.app, u, &n).contains(&proto) {
                list.push((n, true));
            }
        }
        list.truncate(8);
        if list.is_empty() {
            return self.answer(qid, "این پروتکل برای سرویس شما فعال نیست.", true).await;
        }
        self.send(chat, &cfg_help(code), None).await;
        for (n, tunnel) in list {
            let Some((name, text)) = crate::api::bot_config(&self.app, u, &n, proto, tunnel).await else { continue };
            let server = if tunnel { crate::api::twin_name(&self.app, &n) } else { n.name.clone() };
            if proto == "hysteria2" {
                self.send(chat, &format!("📥 <b>{} · {}</b>\n\n<code>{}</code>\n\n☝️ روی لینک بزنید تا کپی بشه.", title, esc(&server), esc(text.trim())), None).await;
            } else {
                let cap = format!("📥 {} · {}\nاسم داخل برنامه: {}", title, server, name.trim_end_matches(".conf"));
                self.send_doc(chat, text.into_bytes(), &name, &cap).await;
            }
        }
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

    /// The config name for a customer: the name they chose, else the English letters and digits of their
    /// Telegram name, else of their @username. None = ask them (see `Wait::CfgName`).
    fn cfg_name_for(&self, tg: i64) -> Option<String> {
        let r: Option<(String, String, String, String)> = self.db().with(|c| c.query_row(
            "SELECT COALESCE(cfg_name,''), COALESCE(name,''), COALESCE(lname,''), COALESCE(uname,'') FROM bot_users WHERE tg_id=?1",
            [tg], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))).ok());
        let (chosen, first, last, uname) = r?;
        if valid_cfg_name(&chosen) {
            return Some(chosen);
        }
        cfg_name_from(&format!("{}{}", first, last)).or_else(|| cfg_name_from(&uname))
    }

    fn create_account_n(&self, tg: i64, gb: f64, days: i64, conns: i64, notes: &str, countries: i64) -> Result<User, String> {
        // the customer's own name (mahtab87; mahtab872 … when taken); USER<n> only when there is no usable name.
        // The number (id) is always the lowest free one, so a deleted trial's number goes to the next customer.
        let name = match self.cfg_name_for(tg) {
            Some(n) => format!("pick:{}", n),
            None if notes == "trial" => "auto-test".to_string(),
            None => "auto".to_string(),
        };
        let nodes = self.pick_nodes(countries);
        let u = self.db().create_user(&name, gb, days, conns, &self.db().get("default_protocols"), &nodes, notes, tg)?;
        let a = self.app.clone();
        tokio::spawn(async move { sync::sync_all(&a).await });
        Ok(u)
    }

    fn home_kb(&self, uid: i64) -> Value {
        // visible buttons two per row; the tutorial button gets a row of its own
        let has_guides = !self.guides().is_empty();
        let mut rows: Kb = vec![];
        let mut pair: Vec<(String, String)> = vec![];
        for k in MAIN_BTNS {
            if self.db().on(&format!("hide_{}", k)) || (*k == "guide" && !has_guides) {
                continue;
            }
            let btn = b(&self.bt(k), k);
            if *k == "guide" {
                if !pair.is_empty() { rows.push(std::mem::take(&mut pair)); }
                rows.push(vec![btn]);
                continue;
            }
            pair.push(btn);
            if pair.len() == 2 { rows.push(std::mem::take(&mut pair)); }
        }
        if !pair.is_empty() { rows.push(pair); }
        if self.admin(uid) {
            rows.push(vec![b("👑 پنل مدیریت", "adm")]);
        }
        ik(rows)
    }

    fn price(&self, p: &Plan, pe: &Pending) -> (i64, f64) {
        let f = (100 - pe.percent.clamp(0, 100)) as f64 / 100.0;
        (((p.toman as f64) * f).round() as i64, ((plan_usd(self.db(), p) * f) * 100.0).round() / 100.0)
    }

    /// Is this payment method offered for these prices? (the same test for the buttons and for the payment)
    fn method_ok(&self, method: &str, t: i64, u: f64) -> bool {
        let db = self.db();
        match method {
            "card" => db.on("card_on") && !db.get("card_number").is_empty() && t > 0,
            "zp" => db.on("zp_on") && !db.get("zp_merchant").is_empty() && t > 0,
            "np" => db.on("np_on") && !db.get("np_key").is_empty() && u > 0.0,
            "wallet" => db.on("wallet_on") && wallet_has_address(db) && u > 0.0,
            _ => false,
        }
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
            let res = self.call_res("getUpdates", json!({"offset": offset, "timeout": 30, "allowed_updates": ["message", "callback_query"]})).await;
            match &res {
                Ok(_) => {
                    self.app.bot_alive.store(now(), std::sync::atomic::Ordering::Relaxed);
                    self.set_poll_error("");
                }
                Err(e) => {
                    self.set_poll_error(e);
                    // a webhook left on this token (it was used by another panel or service) blocks getUpdates
                    if e.contains("webhook is active") {
                        let _ = self.call_res("deleteWebhook", json!({"drop_pending_updates": false})).await;
                    }
                }
            }
            let up = res.ok();
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

    fn touch(&self, uid: i64, from: &Value, ref_by: i64) {
        let name = from["first_name"].as_str().unwrap_or("");
        let lname = from["last_name"].as_str().unwrap_or("");
        let uname = from["username"].as_str().unwrap_or("");
        let _ = self.db().exec(
            "INSERT INTO bot_users(tg_id,name,joined,ref_by,lname,uname) VALUES(?1,?2,?3,?4,?5,?6) \
             ON CONFLICT(tg_id) DO UPDATE SET name=excluded.name, lname=excluded.lname, uname=excluded.uname",
            &[&uid, &name, &now(), &ref_by, &lname, &uname],
        );
    }

    /// The "type a name for your config" message
    fn name_prompt(&self, why: &str) -> String {
        format!("{}✏️ <b>یک نام برای کانفیگ خودتون بفرستید</b>\n\n\
            ✅ فقط <b>حروف انگلیسی و عدد</b>، بین ۳ تا ۱۲ حرف، اولش هم حرف باشه. مثل:\n\
            <code>mahtab87</code>   <code>erfan456</code>   <code>ali2</code>\n\n\
            ❌ فاصله، ایموجی، استیکر، حروف فارسی و علامت‌ها (مثل _ - . @) ننویسید.\n\n\
            نام رو همین‌جا تایپ کنید و بفرستید 👇", why)
    }

    /// After the name was asked: go on with the free trial or the plan list.
    async fn after_name(&self, uid: i64, chat: i64, next: &str) {
        match next {
            "trial" => self.trial(uid, chat, 0).await,
            _ => {
                self.pend.lock().unwrap().insert(uid, Pending { kind: "new".into(), ..Default::default() });
                self.plans_menu(chat, 0, "pl").await
            }
        }
    }

    /// Checks a typed config name: Ok(name) or Err(message to send back)
    fn check_name(&self, text: &str, except: i64) -> Result<String, String> {
        let t = text.trim();
        if !valid_cfg_name(t) {
            return Err(self.name_prompt("⚠️ این نام قابل قبول نیست.\n\n"));
        }
        if self.db().name_taken(t, except) {
            return Err(format!("⚠️ نام <code>{}</code> قبلاً گرفته شده. یه نام دیگه بفرستید (مثلاً یه عدد آخرش اضافه کنید، مثل <code>{}7</code>).", esc(t), esc(&t.chars().take(11).collect::<String>())));
        }
        Ok(t.to_string())
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
            self.touch(uid, &m["from"], ref_by);
            self.waits.lock().unwrap().remove(&uid);
            if !self.joined(uid).await {
                return self.ask_join(chat).await;
            }
            // a giveaway prize from the channel bot (see `Claim`)
            if let Some(p) = text.split_whitespace().nth(1).and_then(|s| s.strip_prefix("c_")) {
                return self.claim_prize(uid, chat, p).await;
            }
            // t.me/<bot>?start=app (a "download the app" button in the channel): the download menu at once
            if text.split_whitespace().nth(1) == Some("app") {
                let (t, rows) = self.app_menu(true);
                self.send(chat, &t, Some(ik(rows))).await;
                return;
            }
            self.send(chat, &self.tx("welcome"), Some(self.home_kb(uid))).await;
            return;
        }
        // the giveaway secret, sent once by an admin (the message is deleted so it doesn't stay in the chat)
        if let Some(k) = text.strip_prefix("/claimkey") {
            if !self.admin(uid) {
                return;
            }
            let k = k.trim();
            let _ = self.call("deleteMessage", json!({"chat_id": chat, "message_id": m["message_id"]})).await;
            if k.len() < 32 || !k.chars().all(|c| c.is_ascii_alphanumeric()) {
                self.send(chat, "⚠️ کلید باید حداقل ۳۲ حرف و فقط حروف انگلیسی و عدد باشه.", None).await;
                return;
            }
            self.db().set("giveaway_secret", k);
            self.send(chat, "✅ کلید جایزه‌های قرعه‌کشی ذخیره شد.", None).await;
            return;
        }
        self.touch(uid, &m["from"], 0);
        let wait = self.waits.lock().unwrap().remove(&uid);
        let Some(w) = wait else {
            self.send(chat, &self.tx("txt_menu"), Some(self.home_kb(uid))).await;
            return;
        };
        match w {
            Wait::Receipt(method) => self.got_receipt(uid, chat, &name, &method, m).await,
            Wait::CfgName(next) => match self.check_name(&text, 0) {
                Ok(n) => {
                    let _ = self.db().exec("UPDATE bot_users SET cfg_name=?1 WHERE tg_id=?2", &[&n, &uid]);
                    self.send(chat, &format!("✅ نام کانفیگ شما: <b>{}</b>", esc(&n)), None).await;
                    self.after_name(uid, chat, &next).await;
                }
                Err(e) => {
                    self.waits.lock().unwrap().insert(uid, Wait::CfgName(next));
                    self.send(chat, &e, Some(ik(vec![vec![b(&self.bt("back"), "home")]]))).await;
                }
            },
            Wait::Rename(id) => {
                let Some(u) = self.db().user(id).filter(|u| u.tg_id == uid || self.admin(uid)) else { return };
                match self.check_name(&text, id) {
                    Ok(n) => {
                        let _ = self.db().exec("UPDATE users SET username=?1 WHERE id=?2", &[&n, &id]);
                        if u.tg_id == uid {
                            let _ = self.db().exec("UPDATE bot_users SET cfg_name=?1 WHERE tg_id=?2", &[&n, &uid]);
                        }
                        let a = self.app.clone();
                        tokio::spawn(async move { sync::sync_all(&a).await });
                        let u2 = self.db().user(id).unwrap_or(u);
                        self.send(chat, &format!("✅ نام کانفیگ شد <b>{}</b>\n\nکد و لینک اشتراک شما عوض نشده و برنامه‌ی کانکی همون‌طور وصل می‌مونه. اگه از WireGuard یا AmneziaWG استفاده می‌کنید و اسم جدید رو می‌خواید، کانفیگ رو دوباره بگیرید.\n\n{}", esc(&n), self.account_msg(&u2)),
                            Some(self.acct_kb(&u2, vec![vec![b(&self.bt("home"), "home")]]))).await;
                    }
                    Err(e) => {
                        self.waits.lock().unwrap().insert(uid, Wait::Rename(id));
                        self.send(chat, &e, Some(ik(vec![vec![b(&self.bt("back"), &format!("acc:{}", id))]]))).await;
                    }
                }
            }
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

    #[allow(clippy::too_many_arguments)]
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
        self.touch(uid, &q["from"], 0);
        self.answer(&qid, "", false).await;
        let back_lbl = self.bt("back");
        let back = |to: &str| vec![b(&back_lbl, to)];

        if !self.joined(uid).await {
            return self.ask_join(chat).await;
        }

        match d.as_str() {
            "home" => {
                self.waits.lock().unwrap().remove(&uid);
                return self.edit(chat, mid, &self.tx("welcome"), Some(self.home_kb(uid))).await;
            }
            "buy" => {
                if !self.db().on("sales_on") && !self.admin(uid) {
                    return self.edit(chat, mid, "⛔ فروش موقتاً بسته است.", Some(ik(vec![back("home")]))).await;
                }
                if self.cfg_name_for(uid).is_none() {
                    self.waits.lock().unwrap().insert(uid, Wait::CfgName("buy".into()));
                    return self.edit(chat, mid, &self.name_prompt(""), Some(ik(vec![back("home")]))).await;
                }
                self.pend.lock().unwrap().insert(uid, Pending { kind: "new".into(), ..Default::default() });
                return self.plans_menu(chat, mid, "pl").await;
            }
            "trial" => {
                if self.db().on("trial_on") && !self.trial_taken(uid) && self.cfg_name_for(uid).is_none() {
                    self.waits.lock().unwrap().insert(uid, Wait::CfgName("trial".into()));
                    return self.edit(chat, mid, &self.name_prompt(""), Some(ik(vec![back("home")]))).await;
                }
                return self.trial(uid, chat, mid).await;
            }
            "my" | "renew" => {
                let accs = self.db().users_of_tg(uid);
                if accs.is_empty() {
                    return self.edit(chat, mid, "هنوز سرویسی ندارید. از «خرید اشتراک» شروع کنید 🛒", Some(ik(vec![back("home")]))).await;
                }
                let pre = if d == "my" { "acc" } else { "rnw" };
                let mut rows: Kb = accs.iter().map(|u| vec![b(&format!("{} {}", if u.active() { "🟢" } else { "🔴" }, u.username), &format!("{}:{}", pre, u.id))]).collect();
                rows.push(back("home"));
                return self.edit(chat, mid, if d == "my" { "📊 سرویس خودتون رو از پایین انتخاب کنید 👇" } else { "🔁 سرویسی که می‌خواید تمدید کنید رو از پایین انتخاب کنید 👇" }, Some(ik(rows))).await;
            }
            "ref" => {
                let me = self.call("getMe", json!({})).await.and_then(|v| v["username"].as_str().map(|s| s.to_string())).unwrap_or_default();
                let cnt: i64 = self.db().with(|c| c.query_row("SELECT COUNT(*) FROM bot_users WHERE ref_by=?1", [uid], |r| r.get(0)).unwrap_or(0));
                return self.edit(chat, mid, &format!(
                    "👥 <b>دعوت دوستان</b>\n\nبا اولین خرید هر دوستی که با لینک شما بیاید، <b>{} گیگ و {} روز</b> هدیه به سرویس شما اضافه می‌شود 🎁\n\n🔗 لینک شما:\n<code>https://t.me/{}?start=ref_{}</code>\n\n👤 تعداد دعوت‌ها: {}",
                    self.db().get("ref_gb"), self.db().get("ref_days"), me, uid, cnt), Some(ik(vec![back("home")]))).await;
            }
            "app" => {
                let (text, rows) = self.app_menu(true);
                return self.edit(chat, mid, &text, Some(ik(rows))).await;
            }
            "app2" => {
                let (text, rows) = self.app_menu(false);
                self.send(chat, &text, Some(ik(rows))).await;
                return;
            }
            "guide" => {
                let g = self.guides();
                if g.len() == 1 {
                    return self.send_guide(chat, &g[0]).await;
                }
                if g.is_empty() {
                    return self.edit(chat, mid, "هنوز آموزشی اضافه نشده است.", Some(ik(vec![back("home")]))).await;
                }
                let mut rows: Kb = g.iter().map(|x| vec![b(&format!("🎬 {}", x["title"].as_str().unwrap_or("")), &format!("gd:{}", x["id"].as_i64().unwrap_or(0)))]).collect();
                rows.push(back("home"));
                return self.edit(chat, mid, &self.tx("txt_guides"), Some(ik(rows))).await;
            }
            "guide1" => {
                if let Some(g) = self.guides().first() {
                    self.send_guide(chat, g).await;
                }
                return;
            }
            "support" => {
                let sup = self.db().get("support").trim().to_string();
                // @id or a t.me link: a button that opens the chat
                let link = if let Some(id) = sup.strip_prefix('@') { Some(format!("https://t.me/{}", id)) }
                    else if sup.starts_with("https://") { Some(sup.clone()) } else { None };
                let mut rows: Kb = vec![];
                if let Some(l) = link { rows.push(vec![b("💬 پیام به پشتیبانی", &format!("url:{}", l))]); }
                rows.push(back("home"));
                return self.edit(chat, mid, &format!("💬 <b>پشتیبانی</b>\n\n{}\n\nسؤال یا مشکلی داشتید، پیام بدهید؛ کد اشتراک یا اسم سرویس را هم بنویسید تا سریع‌تر جواب بگیرید.",
                    if sup.is_empty() { "—".to_string() } else { esc(&sup) }), Some(ik(rows))).await;
            }
            "disc" => {
                self.waits.lock().unwrap().insert(uid, Wait::DiscountUse);
                return self.edit(chat, mid, "🎟 کد تخفیف را بفرستید:", Some(ik(vec![back("home")]))).await;
            }
            _ => {}
        }

        let (head, rest) = d.split_once(':').unwrap_or((d.as_str(), ""));
        match head {
            "apk" => return self.send_apk(chat, rest).await,
            "gd" => {
                if let Some(g) = self.guide(rest.parse().unwrap_or(0)) {
                    self.send_guide(chat, &g).await;
                }
                return;
            }
            "cfg" => {
                let mut parts = rest.split(':');
                let id: i64 = parts.next().and_then(|x| x.parse().ok()).unwrap_or(0);
                let code = parts.next().unwrap_or("");
                if let Some(u) = self.app.db.user(id).filter(|u| u.tg_id == uid || self.admin(uid)) {
                    self.send_configs(chat, &qid, &u, code).await;
                }
                return;
            }
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
                        let target: i64 = parts.next().and_then(|x| x.parse().ok()).unwrap_or(0);
                        // the account in the button must be the buyer's own (or the buyer is an admin)
                        let mine = self.app.db.user(target).map(|u| u.tg_id == uid || self.admin(uid)).unwrap_or(false);
                        pe.target = if mine { target } else { 0 };
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
                    return self.edit(chat, mid, &self.account_msg(&u), Some(self.acct_kb(&u, vec![vec![b(&self.bt("renew_this"), &format!("rnw:{}", id))], back("my")]))).await;
                }
                return;
            }
            "ren" => {
                let id: i64 = rest.parse().unwrap_or(0);
                if let Some(u) = self.app.db.user(id).filter(|u| u.tg_id == uid || self.admin(uid)) {
                    self.waits.lock().unwrap().insert(uid, Wait::Rename(id));
                    let head = format!("نام فعلی: <b>{}</b>\n\n", esc(&u.username));
                    return self.edit(chat, mid, &self.name_prompt(&head), Some(ik(vec![back(&format!("acc:{}", id))]))).await;
                }
                return;
            }
            "rnw" => {
                let id: i64 = rest.parse().unwrap_or(0);
                // only the owner (or an admin) renews an account
                if self.app.db.user(id).filter(|u| u.tg_id == uid || self.admin(uid)).is_none() {
                    return;
                }
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
        let mut title = self.tx("txt_plans");
        let back_lbl = self.bt("back");
        let mut back_to = "home".to_string();
        if !cats.is_empty() {
            if sel == "m" {
                let mut rows: Kb = cats.iter().enumerate().map(|(i, c)| vec![b(&format!("📂 {}", c.1), &format!("pcat:{}:{}", mode, i))]).collect();
                if has_other { rows.push(vec![b(&self.bt("other_plans"), &format!("pcat:{}:o", mode))]); }
                rows.push(vec![b(&back_lbl, "home")]);
                return self.edit(chat, mid, &self.tx("txt_cats"), Some(ik(rows))).await;
            }
            let want: String = if sel == "o" {
                String::new()
            } else {
                sel.parse::<usize>().ok().and_then(|i| cats.get(i)).map(|c| c.1.clone()).unwrap_or_default()
            };
            title = if want.is_empty() { "📦 <b>سایر پلن‌ها</b>\nپلن خودتون رو از پایین انتخاب کنید 👇".to_string() } else { format!("📂 <b>{}</b>\nپلن خودتون رو از پایین انتخاب کنید 👇", esc(&want)) };
            list.retain(|p| p.category == want);
            back_to = format!("pcat:{}:m", mode);
        }
        // ordered by duration, then number of users, then price; the text groups them by duration
        list.sort_by_key(|x| (x.days, x.conns, x.toman));
        let mut rows: Kb = vec![];
        for p in list.iter() {
            let price = if p.toman > 0 { toman(p.toman) } else { format!("{}$", p.usd) };
            let dur = if p.days > 0 && p.days % 30 == 0 { format!("{} ماهه", p.days / 30) } else { format!("{} روزه", p.days) };
            let vol = if p.gb > 0.0 { format!("{}GB", p.gb) } else { "نامحدود".to_string() };
            let data = if pattern.contains("{}") { pattern.replace("{}", &p.id.to_string()) } else { format!("{}:{}", pattern, p.id) };
            rows.push(vec![b(&format!("📅 {} · 👤 {} · {} · {}", dur, p.conns, vol, price), &data)]);
        }
        if rows.is_empty() {
            return self.edit(chat, mid, "هنوز پلنی تعریف نشده است.", Some(ik(vec![vec![b(&back_lbl, &back_to)]]))).await;
        }
        rows.push(vec![b(&back_lbl, &back_to)]);
        self.edit(chat, mid, &title, Some(ik(rows))).await;
    }

    async fn show_plan(&self, chat: i64, mid: Option<i64>, uid: i64, pid: i64) {
        let Some(p) = self.plan(pid) else { return };
        let pe = self.pend.lock().unwrap().get(&uid).cloned().unwrap_or_default();
        let (t, u) = self.price(&p, &pe);
        let mut rows: Kb = vec![];
        for (m, k) in [("card", "pay_card"), ("zp", "pay_zp"), ("np", "pay_np"), ("wallet", "pay_wallet")] {
            if self.method_ok(m, t, u) {
                rows.push(vec![b(&self.bt(k), &format!("pay:{}", m))]);
            }
        }
        if pe.discount.is_empty() { rows.push(vec![b(&self.bt("disc"), "disc")]); }
        rows.push(vec![b(&self.bt("back"), "home")]);
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
        // an old button (the method was switched off or the plan has no price for it since)
        if !self.method_ok(method, t, u) {
            return self.edit(chat, mid, "⚠️ این روش پرداخت الان فعال نیست؛ روش دیگری انتخاب کنید.", home).await;
        }
        match method {
            "card" => {
                self.waits.lock().unwrap().insert(uid, Wait::Receipt("card".into()));
                self.edit(chat, mid, &format!(
                    "💳 <b>کارت به کارت</b>\n\nمبلغ: <b>{}</b>\nشماره کارت:\n<code>{}</code>\nبه نام: {}\n\n📸 بعد از واریز، <b>عکس رسید</b> را همین‌جا بفرستید.",
                    toman(t), esc(&db.get("card_number")), esc(&db.get("card_holder"))), home).await;
            }
            "wallet" => {
                self.waits.lock().unwrap().insert(uid, Wait::Receipt("wallet".into()));
                let ton = db.get("ton_address").trim().to_string();
                let usdt = db.get("usdt_address").trim().to_string();
                let mut txt = format!("💰 <b>پرداخت ارزی</b>\n\nمبلغ: <b>{}$</b>", u);
                let mut rows: Kb = vec![];
                if !ton.is_empty() {
                    // the amount in TON at today's price (when the price can be read), for a ready Tonkeeper link
                    match ton_usd(&self.app).await {
                        Some(rate) if rate > 0.0 => {
                            let amount = ((u / rate) * 1000.0).ceil() / 1000.0;
                            txt.push_str(&format!("\n\n💎 <b>TON</b> (شبکه‌ی TON): <b>{} TON</b>\nآدرس کیف پول:\n<code>{}</code>", amount, esc(&ton)));
                            rows.push(vec![b("💎 پرداخت با Tonkeeper", &format!("url:https://app.tonkeeper.com/transfer/{}?amount={}", ton, (amount * 1e9).round() as u64))]);
                        }
                        _ => txt.push_str(&format!("\n\n💎 <b>TON</b> (شبکه‌ی TON) به اندازه‌ی {}$\nآدرس کیف پول:\n<code>{}</code>", u, esc(&ton))),
                    }
                }
                if !usdt.is_empty() {
                    txt.push_str(&format!("\n\n💵 <b>USDT</b> (شبکه‌ی TRC20): <b>{} USDT</b>\nآدرس:\n<code>{}</code>", u, esc(&usdt)));
                }
                let extra = db.get("wallet_text");
                if !extra.trim().is_empty() {
                    txt.push_str(&format!("\n\n{}", esc(&extra)));
                }
                txt.push_str("\n\n👆 روی آدرس بزنید تا کپی شود.\n📸 بعد از پرداخت، <b>عکس رسید یا TXID</b> را همین‌جا بفرستید.");
                rows.push(vec![b("⬅️ بازگشت", "home")]);
                self.edit(chat, mid, &txt, Some(ik(rows))).await;
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
        // every update runs in its own task, so a double tap on "check payment" runs this twice at the
        // same time: only the call that really flips the status may deliver the service
        match self.db().exec("UPDATE orders SET status='done' WHERE id=?1 AND status<>'done'", &[&oid]) {
            Ok(1) => {}
            _ => return,
        }
        let Some(p) = self.plan(o.2) else { return };
        // a buyer who still has a free-trial account gets that same account (USER<n>-TEST -> USER<n>)
        let trial = self.db().users_of_tg(o.1).into_iter().find(|u| u.notes == "trial" || u.username.to_uppercase().ends_with("-TEST"));
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
                let head = if o.3 == "renew" { self.tx("txt_renewed") } else { self.tx("txt_bought") };
                self.send(o.1, &format!("{}\n\n{}", head, self.account_msg(&u)), Some(self.acct_kb(&u, vec![vec![b(&self.bt("home"), "home")]]))).await;
                if !o.9.is_empty() {
                    let _ = self.db().exec("UPDATE discounts SET uses_left=uses_left-1 WHERE code=?1 AND uses_left>0", &[&o.9]);
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
        match self.db().exec("UPDATE bot_users SET ref_rewarded=1 WHERE tg_id=?1 AND ref_rewarded=0", &[&tg]) {
            Ok(1) => {}
            _ => return,
        }
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
        // approve and reject tapped together (or twice): only the first decision counts
        let to = if approve { "approved" } else { "rejected" };
        if !matches!(self.db().exec("UPDATE orders SET status=?1 WHERE id=?2 AND status IN ('pending','error')", &[&to, &oid]), Ok(1)) {
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
            self.fulfill(oid).await;
        } else {
            self.send(o.1, &format!("❌ رسید سفارش #{} تأیید نشد. پشتیبانی: {}", oid, esc(&self.db().get("support"))), None).await;
        }
    }

    /// A giveaway prize: only for the Telegram account in the claim, only once (the claims row is taken before
    /// anything is created, so a double tap or a forwarded link can't make a second account).
    async fn claim_prize(&self, uid: i64, chat: i64, p: &str) {
        let home = Some(ik(vec![vec![b(&self.bt("home"), "home")]]));
        let c = match parse_claim(p, &giveaway_secret(&self.app)) {
            Ok(c) => c,
            Err(e) => {
                let t = if e == "off" { "⏳ تحویل جایزه‌ها هنوز فعال نشده؛ کمی بعد دوباره امتحان کنید." } else { "⛔️ این لینک جایزه معتبر نیست." };
                self.send(chat, t, home).await;
                return;
            }
        };
        if c.tg != uid {
            self.send(chat, "⛔️ این جایزه برای حساب تلگرام دیگه‌ایه و فقط خود برنده می‌تونه بگیرتش.", home).await;
            return;
        }
        let key = format!("{}:{}:{}", c.tag, c.gid, c.n);
        let claimed = self.db().exec("INSERT OR IGNORE INTO claims(id, tg_id, user_id, created) VALUES(?1, ?2, 0, ?3)", &[&key, &uid, &now()]).unwrap_or(0);
        if claimed == 0 {
            self.send(chat, "✅ این جایزه قبلاً تحویل داده شده.\nاکانتت رو از «سرویس‌های من» ببین.", home).await;
            return;
        }
        // ElClasicoP (the prediction) / ElClasicoW1 … (the draw); a number is added when the name is taken
        let base: String = c.tag.chars().take(9).collect();
        let base = if c.n == 0 { format!("{}P", base) } else { format!("{}W{}", base, c.n) };
        let notes = format!("giveaway {}", key);
        match self.db().create_user(&format!("pick:{}", base), c.gb as f64, c.days, 1, &self.db().get("default_protocols"), &self.pick_nodes(0), &notes, uid) {
            Ok(u) => {
                let _ = self.db().exec("UPDATE claims SET user_id=?1 WHERE id=?2", &[&u.id, &key]);
                let a = self.app.clone();
                tokio::spawn(async move { sync::sync_all(&a).await });
                let head = format!("🎁 <b>جایزه‌ی قرعه‌کشی شما آماده است</b> ({} گیگ، {} روزه)", c.gb, c.days);
                self.send(chat, &format!("{}\n\n{}", head, self.account_msg(&u)), Some(self.acct_kb(&u, vec![vec![b(&self.bt("home"), "home")]]))).await;
                self.notify_admins(&format!("🎁 جایزه‌ی قرعه‌کشی تحویل شد: <b>{}</b> ({} گیگ، {} روز) · {} · <code>{}</code>", esc(&u.username), c.gb, c.days, esc(&key), uid), None, None).await;
            }
            Err(e) => {
                // nothing was created: the claim can be tried again
                let _ = self.db().exec("DELETE FROM claims WHERE id=?1", &[&key]);
                self.notify_admins(&format!("⚠️ خطای ساخت جایزه‌ی قرعه‌کشی {}: <code>{}</code>", esc(&key), esc(&e)), None, None).await;
                self.send(chat, "⚠️ ساخت اکانت جایزه ناموفق بود؛ کمی بعد دوباره امتحان کنید.", home).await;
            }
        }
    }

    /// One free trial per Telegram user, for everyone (admins too): a flag in bot_users, or an existing trial account.
    /// The flag stays after the finished trial is deleted, so it cannot be taken again.
    fn trial_taken(&self, uid: i64) -> bool {
        let used: i64 = self.db().with(|c| c.query_row("SELECT trial_used FROM bot_users WHERE tg_id=?1", [uid], |r| r.get(0)).unwrap_or(0));
        used == 1 || self.db().users_of_tg(uid).iter().any(|u| u.notes == "trial")
    }

    async fn trial(&self, uid: i64, chat: i64, mid: i64) {
        let back = Some(ik(vec![vec![b(&self.bt("back"), "home")]]));
        if !self.db().on("trial_on") {
            return self.edit(chat, mid, "تست رایگان فعلاً غیرفعال است.", back).await;
        }
        let again = "شما قبلاً تست رایگان خودتون رو گرفتید 🙂\nبرای ادامه، از «خرید اشتراک» استفاده کنید 🛒";
        if self.trial_taken(uid) {
            return self.edit(chat, mid, again, back).await;
        }
        // claim it first so a double tap cannot create two accounts
        let claimed = self.db().exec("UPDATE bot_users SET trial_used=1 WHERE tg_id=?1 AND COALESCE(trial_used,0)=0", &[&uid]).unwrap_or(0);
        if claimed == 0 {
            return self.edit(chat, mid, again, back).await;
        }
        let gb: f64 = self.db().get("trial_gb").parse().unwrap_or(1.0);
        let days: i64 = self.db().get("trial_days").parse().unwrap_or(1);
        match self.create_account(uid, gb, days, 1, "trial") {
            Ok(u) => {
                self.edit(chat, mid, &format!("{}\n\n{}", self.tx("txt_trial_ready"), self.account_msg(&u)), Some(self.acct_kb(&u, vec![vec![b(&self.bt("back"), "home")]]))).await;
            }
            Err(e) => {
                // nothing was created: give the trial back
                let _ = self.db().exec("UPDATE bot_users SET trial_used=0 WHERE tg_id=?1", &[&uid]);
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
            vec![b("🎁 هدیه حجم و زمان (جبران قطعی)", "a:gift")],
            vec![b("📦 پلن‌ها", "a:plans"), b("📂 دسته‌بندی‌ها", "a:cats")],
            vec![b("🎬 آموزش‌ها", "a:guides"), b("🎨 دکمه‌ها و متن‌ها", "a:ui")],
            vec![b("🎁 تست رایگان", "a:trial"), b("💳 پرداخت‌ها", "a:pay")],
            vec![b("🖥 نودها", "a:nodes"), b("🎟 کدهای تخفیف", "a:disc")],
            vec![b("👥 دعوت و هدیه", "a:ref"), b("💾 بکاپ الان", "a:backup")],
            vec![b("📣 پیام همگانی", "a:bc"), b("📌 سنجاق برای همه", "a:bcp")],
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
            vec![b("🎁 هدیه حجم و زمان", &format!("u:gft:{}", id))],
            vec![b("⬅️ پنل مدیریت", "adm")],
        ])
    }

    /// صفحه‌های پنل مدیریت؛ اگر کلید شناخته شد true
    async fn admin_view(&self, uid: i64, chat: i64, mid: i64, d: &str) -> bool {
        let db = self.db();
        let back = Some(ik(vec![vec![b("⬅️ پنل مدیریت", "adm")]]));
        let set_wait = |w: Wait| { self.waits.lock().unwrap().insert(uid, w); };
        match d {
            "adm" => { self.edit(chat, mid, "👑 <b>پنل مدیریت</b>", Some(self.adm_kb())).await; true }
            "a:stats" => {
                let us = db.users();
                let bu: i64 = db.with(|c| c.query_row("SELECT COUNT(*) FROM bot_users", [], |r| r.get(0)).unwrap_or(0));
                let (cnt, rev): (i64, i64) = db.with(|c| c.query_row(
                    "SELECT COUNT(*), COALESCE(SUM(CASE WHEN method IN ('card','zp') THEN CAST(amount AS INTEGER) END),0) FROM orders WHERE status='done'",
                    [], |r| Ok((r.get(0)?, r.get(1)?))).unwrap_or((0, 0)));
                let today: i64 = db.with(|c| c.query_row("SELECT COUNT(*) FROM orders WHERE status='done' AND created>?1", [now() - 86400], |r| r.get(0)).unwrap_or(0));
                // crypto orders keep their amount in dollars
                let usd: f64 = db.with(|c| c.query_row(
                    "SELECT COALESCE(SUM(CASE WHEN method NOT IN ('card','zp') THEN CAST(amount AS REAL) END),0) FROM orders WHERE status='done'",
                    [], |r| r.get(0)).unwrap_or(0.0));
                let ns = db.nodes();
                let txt = format!(
                    "📈 <b>آمار</b>\n\n👥 کاربران: <b>{}</b> (فعال: {})\n🟢 آنلاین: <b>{}</b>\n⛔ منقضی/تمام‌حجم: {}\n📊 مصرف کل: {:.1} GB\n🖥 نودها: {}/{} آنلاین\n\n🤖 کاربران ربات: <b>{}</b>\n🧾 فروش: <b>{}</b> (۲۴ ساعت اخیر: {})\n💰 درآمد ریالی: <b>{}</b>\n💎 درآمد ارزی: <b>{:.2}$</b>",
                    us.len(), us.iter().filter(|u| u.active()).count(), us.iter().filter(|u| u.online > 0).count(),
                    us.iter().filter(|u| !u.active()).count(), us.iter().map(|u| u.used_gb()).sum::<f64>(),
                    ns.iter().filter(|n| n.online).count(), ns.len(), bu, cnt, today, toman(rev), usd);
                { self.edit(chat, mid, &txt, back).await; true }
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
                { self.edit(chat, mid, &format!("🧾 <b>سفارش‌های باز</b>\n\n{}", txt.join("\n")), Some(ik(kb))).await; true }
            }
            "a:search" => { set_wait(Wait::Search); { self.edit(chat, mid, "🔍 نام کاربری، شناسه یا آیدی تلگرام را بفرستید:", back).await; true } }
            "a:gift" => {
                let txt = "🎁 <b>هدیه‌ی حجم و زمان</b>\n\nبرای جبران قطعی سرورها یا هدیه دادن، روز و گیگ به اشتراک اضافه کنید. به هر کاربری که در ربات است، یک پیام زیبا می‌رود.\n\n👥 <b>همه</b>: همه‌ی کاربران روشن و منقضی‌نشده (بدون اکانت‌های تست)\n👤 <b>یک نفر</b>: کاربر را پیدا کنید و در صفحه‌اش «🎁 هدیه حجم و زمان» را بزنید\n\nزمان یا حجم نامحدود، نامحدود می‌ماند.";
                let kb = ik(vec![
                    vec![b("👥 هدیه به همه", "gf:all"), b("👤 هدیه به یک نفر", "a:search")],
                    vec![b("📝 متن پیام هدیه", "tv:txt_gift")],
                    vec![b("⬅️ پنل مدیریت", "adm")],
                ]);
                self.edit(chat, mid, txt, Some(kb)).await;
                true
            }
            "a:mk" => { set_wait(Wait::Make); { self.edit(chat, mid, "➕ بفرستید: <code>حجم_گیگ روز تعداد_اتصال [نام]</code>\nمثلاً: <code>50 30 2 ali</code>", back).await; true } }
            "a:plans" => {
                let mut kb: Kb = self.plans(false).into_iter().map(|(p, a)| vec![
                    b(&format!("{} {} · {}G · {}d · {} · {}$", if a { "🟢" } else { "⚪️" }, p.name, p.gb, p.days, p.toman, p.usd), &format!("pv:{}", p.id)),
                ]).collect();
                kb.push(vec![b("➕ افزودن پلن", "pa"), b("📂 دسته‌بندی‌ها", "a:cats")]);
                kb.push(vec![b("⬅️ پنل مدیریت", "adm")]);
                { self.edit(chat, mid, "📦 <b>پلن‌ها</b>\nروی هر پلن بزنید تا همه‌چیزش (نام، مدت، حجم، قیمت، تعداد کاربر، کشورها، دسته) را عوض کنید، روشن/خاموش یا حذفش کنید.", Some(ik(kb))).await; true }
            }
            "pa" => { set_wait(Wait::Plan); { self.edit(chat, mid, "بفرستید:\n<code>نام | روز | گیگ | تومان | دلار | اتصال | دسته</code>\n(دسته اختیاری است)\nمثلاً:\n<code>یک‌ماهه | 30 | 50 | 150000 | 2.5 | 1 | اقتصادی</code>", back).await; true } }
            "a:cats" => {
                let cats = self.categories();
                let mut kb: Kb = cats.iter().enumerate().map(|(i, (c, n))| vec![b(&format!("📂 {} · {} پلن", c, n), &format!("ck:{}", i))]).collect();
                kb.push(vec![b("📦 پلن‌ها", "a:plans")]);
                kb.push(vec![b("⬅️ پنل مدیریت", "adm")]);
                let txt = if cats.is_empty() {
                    "📂 <b>دسته‌بندی‌ها</b>\n\nهنوز دسته‌ای نیست. از صفحه‌ی هر پلن («📂 دسته») یا موقع افزودن پلن، اسم دسته را بدهید تا ساخته شود."
                } else {
                    "📂 <b>دسته‌بندی‌ها</b>\n\nروی هر دسته بزنید تا اسمش را عوض یا حذفش کنید. دسته‌ی هر پلن از صفحه‌ی همان پلن تعیین می‌شود."
                };
                self.edit(chat, mid, txt, Some(ik(kb))).await;
                true
            }
            "a:ui" => {
                let kb = ik(vec![
                    vec![b("🔘 متن دکمه‌ها", "a:btns"), b("📝 متن پیام‌ها", "a:txts")],
                    vec![b("🔗 لینک‌ها", "a:links"), b("🎬 آموزش‌ها", "a:guides")],
                    vec![b("⬅️ پنل مدیریت", "adm")],
                ]);
                self.edit(chat, mid, "🎨 <b>دکمه‌ها و متن‌ها</b>\n\nاز اینجا متن همه‌ی دکمه‌ها و پیام‌های ربات، لینک‌ها و آموزش‌ها را عوض کنید. دکمه‌های منوی اصلی را می‌شود پنهان هم کرد.", Some(kb)).await;
                true
            }
            "a:btns" => {
                let mut kb: Kb = BTNS.iter().map(|(k, _, _)| {
                    let hidden = MAIN_BTNS.contains(k) && db.on(&format!("hide_{}", k));
                    vec![b(&format!("{}{}", if hidden { "🚫 " } else { "" }, self.bt(k)), &format!("bv:{}", k))]
                }).collect();
                kb.push(vec![b("⬅️ دکمه‌ها و متن‌ها", "a:ui")]);
                self.edit(chat, mid, "🔘 <b>متن دکمه‌ها</b>\n\nروی هر دکمه بزنید تا متنش را عوض کنید (🚫 = پنهان).", Some(ik(kb))).await;
                true
            }
            "a:txts" => {
                let mut kb: Kb = TEXTS.iter().map(|(k, _, title)| vec![b(&format!("📝 {}", title), &format!("tv:{}", k))]).collect();
                kb.push(vec![b("⬅️ دکمه‌ها و متن‌ها", "a:ui")]);
                self.edit(chat, mid, "📝 <b>متن پیام‌ها</b>\n\nروی هر پیام بزنید تا متنش را ببینید و عوض کنید.", Some(ik(kb))).await;
                true
            }
            "a:links" => {
                let show = |k: &str| { let v = db.get(k); if v.is_empty() { "تنظیم نشده".to_string() } else { esc(&v) } };
                let txt = format!("🔗 <b>لینک‌ها</b>\n\n📱 لینک دانلود اپ:\n{}\n\n💬 پشتیبانی:\n{}\n\n📢 کانال اجباری:\n{}", show("app_link"), show("support"), show("channel"));
                let kb = ik(vec![
                    vec![b("✏️ لینک دانلود اپ", "set:app_link")],
                    vec![b("✏️ پشتیبانی", "set:support"), b("✏️ کانال اجباری", "set:channel")],
                    vec![b("⬅️ دکمه‌ها و متن‌ها", "a:ui")],
                ]);
                self.edit(chat, mid, &txt, Some(kb)).await;
                true
            }
            "a:guides" => {
                let g = self.guides();
                let mut kb: Kb = g.iter().enumerate().map(|(i, x)| vec![b(
                    &format!("{}{} · {}", if i == 0 { "⭐️ " } else { "🎬 " }, x["title"].as_str().unwrap_or(""), kind_title(x["kind"].as_str().unwrap_or(""))),
                    &format!("gv:{}", x["id"].as_i64().unwrap_or(0)),
                )]).collect();
                kb.push(vec![b("➕ آموزش جدید", "gn")]);
                kb.push(vec![b("⬅️ پنل مدیریت", "adm")]);
                let txt = if g.is_empty() {
                    "🎬 <b>آموزش‌ها</b>\n\nهنوز آموزشی نیست، پس دکمه‌ی «آموزش اتصال» به کاربرها نشان داده نمی‌شود.\n«➕ آموزش جدید» را بزنید و ویدیو را بفرستید تا دکمه روشن شود."
                } else {
                    "🎬 <b>آموزش‌ها</b>\n\n⭐️ آموزش اول همان است که با دکمه‌ی «آموزش اتصال» زیر پیام اشتراک و دانلود اپ فرستاده می‌شود. اگر بیشتر از یکی باشد، دکمه‌ی منوی اصلی فهرست همه را نشان می‌دهد."
                };
                self.edit(chat, mid, txt, Some(ik(kb))).await;
                true
            }
            "gn" => {
                set_wait(Wait::GuideNew);
                self.edit(chat, mid, "🎬 ویدیوی آموزش را بفرستید (یا گیف، فایل، عکس یا یک متن).\nاگر زیر ویدیو متنی بنویسید، خط اولش عنوان آموزش و کلش متن زیر ویدیو می‌شود.", Some(ik(vec![vec![b("⬅️ آموزش‌ها", "a:guides")]]))).await;
                true
            }
            "a:trial" => { self.edit(chat, mid, &format!("🎁 <b>تست رایگان</b>\nحجم: {} GB · مدت: {} روز", db.get("trial_gb"), db.get("trial_days")),
                Some(ik(vec![vec![b(&format!("{} روشن/خاموش", self.onoff("trial_on")), "tg:trial_on")],
                    vec![b("✏️ حجم", "set:trial_gb"), b("✏️ مدت", "set:trial_days")], vec![b("⬅️ پنل مدیریت", "adm")]]))).await; true }
            "a:pay" => { self.edit(chat, mid, &format!("💳 <b>روش‌های پرداخت</b>\nکارت: {}", esc(&db.get("card_number"))),
                Some(ik(vec![
                    vec![b(&format!("{} کارت", self.onoff("card_on")), "tg:card_on"), b("✏️ شماره", "set:card_number"), b("✏️ نام", "set:card_holder")],
                    vec![b(&format!("{} زرین‌پال", self.onoff("zp_on")), "tg:zp_on"), b("✏️ مرچنت", "set:zp_merchant"), b("✏️ بازگشت", "set:zp_callback")],
                    vec![b(&format!("{} ارزی خودکار", self.onoff("np_on")), "tg:np_on"), b("✏️ API Key", "set:np_key"), b("✏️ ارزها", "set:np_coins")],
                    vec![b(&format!("{} کیف پول", self.onoff("wallet_on")), "tg:wallet_on"), b("✏️ آدرس‌ها", "set:wallet_text")],
                    vec![b("⬅️ پنل مدیریت", "adm")]]))).await; true }
            "a:nodes" => {
                let txt: Vec<String> = db.nodes().iter().map(|n| format!("{} <b>{}</b> · {}", if n.online { "🟢" } else { "🔴" }, esc(&n.name),
                    if n.enabled { "فعال" } else { "خاموش" })).collect();
                { self.edit(chat, mid, &format!("🖥 <b>نودها</b>\n\n{}\n\nافزودن نود از پنل وب انجام می‌شود.", txt.join("\n")), back).await; true }
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
                { self.edit(chat, mid, "🎟 <b>کدهای تخفیف</b>", Some(ik(kb))).await; true }
            }
            "da" => { set_wait(Wait::DiscountAdd); { self.edit(chat, mid, "بفرستید: <code>کد درصد تعداد</code>\nمثلاً: <code>NOWRUZ 20 100</code>", back).await; true } }
            "a:ref" => { self.edit(chat, mid, &format!("👥 <b>هدیه‌ی دعوت</b>\nبه ازای اولین خرید هر دعوت‌شده: {} GB و {} روز", db.get("ref_gb"), db.get("ref_days")),
                Some(ik(vec![vec![b("✏️ گیگ هدیه", "set:ref_gb"), b("✏️ روز هدیه", "set:ref_days")], vec![b("⬅️ پنل مدیریت", "adm")]]))).await; true }
            "a:bc" => { set_wait(Wait::Broadcast); { self.edit(chat, mid, "📣 پیام را بفرستید (متن، عکس، ویدیو…):", back).await; true } }
            "a:bcp" => {
                // use the message the admin pinned in this chat; otherwise ask for one
                let pinned = self.call("getChat", json!({"chat_id": chat})).await.and_then(|c| c["pinned_message"]["message_id"].as_i64());
                if let Some(pm) = pinned {
                    self.edit(chat, mid, "📌 در حال ارسال و سنجاق برای همه…", None).await;
                    let n = self.broadcast(chat, pm, true).await;
                    self.send(chat, &format!("📌 برای {} کاربر ارسال و سنجاق شد.", n), Some(self.adm_kb())).await;
                    return true;
                }
                set_wait(Wait::BroadcastPin);
                self.edit(chat, mid, "📌 پیامی که می‌خواید برای همه سنجاق بشه رو بفرستید.\n(یا اول همون پیام رو همین‌جا تو چت ربات سنجاق کنید و دوباره این دکمه رو بزنید.)", back).await;
                true
            }
            "a:backup" => {
                let pass = crate::backup::backup_pass(&self.app);
                if let Ok((bytes, name)) = make_archive(&self.app, &pass) {
                    self.send_doc(chat, bytes, &name, "💾 بکاپ کامل پنل (رمزدار — رمز در پنل > بکاپ)").await;
                }
                true
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
                true
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
                true
            }
            "a:chs" => {
                let back = Some(ik(vec![vec![b("⬅️ کانال هوشمند", "a:ch")]]));
                // the draft is taken once: a second tap (or Telegram sending the tap again) does not post it twice
                let text = db.get("ch_draft");
                if text.trim().is_empty() || !matches!(db.exec("UPDATE settings SET v='' WHERE k='ch_draft' AND v=?1", &[&text]), Ok(1)) {
                    self.edit(chat, mid, "این پیش‌نویس قبلاً ارسال شده است.", back).await;
                    return true;
                }
                let r = crate::channel::send_to_channel(&self.app, &text).await;
                if r.is_err() {
                    db.set("ch_draft", &text);
                }
                let msg = match r {
                    Ok(_) => "✅ در کانال منتشر شد.".to_string(),
                    Err(e) => format!("⚠️ ارسال نشد: <code>{}</code>\nآیدی کانال را در پنل وب بررسی کنید و ربات را ادمین کانال کنید.", esc(&e)),
                };
                self.edit(chat, mid, &msg, back).await;
                true
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
                true
            }
            "a:gen" => { self.edit(chat, mid, &format!("⚙️ <b>تنظیمات عمومی</b>\nپشتیبانی: {}\nکانال اجباری: {}\nلینک اپ: {}",
                esc(&db.get("support")), esc(&db.get("channel")), esc(&db.get("app_link"))),
                Some(ik(vec![
                    vec![b(&format!("{} فروش", self.onoff("sales_on")), "tg:sales_on"), b(&format!("{} هشدار اتمام", self.onoff("warn_on")), "tg:warn_on")],
                    vec![b(&format!("{} بکاپ روزانه", self.onoff("backup_on")), "tg:backup_on")],
                    vec![b("✏️ پشتیبانی", "set:support"), b("✏️ کانال اجباری", "set:channel")],
                    vec![b("✏️ لینک اپ", "set:app_link"), b("✏️ خوش‌آمد", "set:welcome")],
                    vec![b("🎨 دکمه‌ها و متن‌ها", "a:ui")],
                    vec![b("⬅️ پنل مدیریت", "adm")]]))).await; true }
            _ => false,
        }
    }

    /// Plan categories (name, number of plans), by name.
    fn categories(&self) -> Vec<(String, usize)> {
        let mut out: Vec<(String, usize)> = vec![];
        for (p, _) in self.plans(false) {
            if p.category.is_empty() { continue; }
            if let Some(i) = out.iter().position(|c| c.0 == p.category) {
                out[i].1 += 1;
            } else {
                out.push((p.category.clone(), 1));
            }
        }
        out.sort();
        out
    }

    async fn plan_view(&self, chat: i64, mid: i64, id: i64) {
        let Some((p, active)) = self.plans(false).into_iter().find(|x| x.0.id == id) else {
            return self.edit(chat, mid, "پلن پیدا نشد.", Some(ik(vec![vec![b("📦 پلن‌ها", "a:plans")]]))).await;
        };
        let txt = format!(
            "📦 <b>{}</b>  {}\n\n📅 مدت: {} روز\n📊 حجم: {}\n💰 قیمت: {} · {}$\n👤 تعداد کاربر: {}\n🌍 کشورها: {}\n📂 دسته: {}",
            esc(&p.name), if active { "🟢 فعال" } else { "⚪️ غیرفعال" }, p.days,
            if p.gb > 0.0 { format!("{} GB", p.gb) } else { "نامحدود".into() }, toman(p.toman), p.usd, p.conns,
            if p.countries > 0 { p.countries.to_string() } else { "همه".into() },
            if p.category.is_empty() { "بدون دسته".to_string() } else { esc(&p.category) }
        );
        let e = |f: &str, t: &str| b(t, &format!("pe:{}:{}", id, f));
        let kb = ik(vec![
            vec![e("name", "✏️ نام"), e("days", "✏️ مدت (روز)")],
            vec![e("gb", "✏️ حجم (گیگ)"), e("conns", "✏️ تعداد کاربر")],
            vec![e("toman", "✏️ قیمت تومان"), e("usd", "✏️ قیمت دلار")],
            vec![e("countries", "✏️ تعداد کشور"), e("category", "📂 دسته")],
            vec![b(if active { "⏸ غیرفعال کن" } else { "▶️ فعال کن" }, &format!("pt:{}", id)), b("🗑 حذف", &format!("pd:{}", id))],
            vec![b("⬅️ پلن‌ها", "a:plans")],
        ]);
        self.edit(chat, mid, &txt, Some(kb)).await;
    }

    async fn cat_view(&self, chat: i64, mid: i64, i: usize) {
        let cats = self.categories();
        let Some((name, n)) = cats.get(i).cloned() else {
            return self.edit(chat, mid, "دسته پیدا نشد.", Some(ik(vec![vec![b("📂 دسته‌بندی‌ها", "a:cats")]]))).await;
        };
        let plans: Vec<String> = self.plans(false).into_iter().filter(|x| x.0.category == name).map(|x| format!("• {}", esc(&x.0.name))).collect();
        let kb = ik(vec![
            vec![b("✏️ تغییر نام", &format!("cr:{}", i)), b("🗑 حذف دسته", &format!("cx:{}", i))],
            vec![b("⬅️ دسته‌بندی‌ها", "a:cats")],
        ]);
        self.edit(chat, mid, &format!("📂 <b>{}</b> · {} پلن\n\n{}\n\nبا حذف دسته، پلن‌هایش پاک نمی‌شوند؛ فقط بدون دسته می‌شوند.", esc(&name), n, plans.join("\n")), Some(kb)).await;
    }

    async fn btn_view(&self, chat: i64, mid: i64, k: &str) {
        let Some((_, def, place)) = BTNS.iter().find(|t| t.0 == k).cloned() else { return };
        let main = MAIN_BTNS.contains(&k);
        let hidden = main && self.db().on(&format!("hide_{}", k));
        let mut txt = format!("🔘 <b>دکمه</b>\n\nمتن فعلی: <b>{}</b>\nپیش‌فرض: {}\nجای دکمه: {}", esc(&self.bt(k)), esc(def), place);
        if main { txt.push_str(&format!("\nوضعیت: {}", if hidden { "🚫 پنهان" } else { "👁 نمایش" })); }
        if k == "guide" || k == "guide_acc" { txt.push_str("\n\nاین دکمه فقط وقتی دیده می‌شود که در «🎬 آموزش‌ها» حداقل یک آموزش باشد."); }
        let mut rows: Kb = vec![vec![b("✏️ متن جدید", &format!("set:btn_{}", k)), b("↩️ پیش‌فرض", &format!("rs:btn_{}", k))]];
        if main { rows.push(vec![b(if hidden { "👁 نمایش بده" } else { "🚫 پنهان کن" }, &format!("hd:{}", k))]); }
        rows.push(vec![b("⬅️ متن دکمه‌ها", "a:btns")]);
        self.edit(chat, mid, &txt, Some(ik(rows))).await;
    }

    async fn txt_view(&self, chat: i64, mid: i64, k: &str) {
        let Some((_, _, title)) = TEXTS.iter().find(|t| t.0 == k).cloned() else { return };
        let kb = ik(vec![
            vec![b("✏️ متن جدید", &format!("set:{}", k)), b("↩️ پیش‌فرض", &format!("rs:{}", k))],
            vec![b("⬅️ متن پیام‌ها", "a:txts")],
        ]);
        self.edit(chat, mid, &format!("📝 <b>{}</b>\n➖➖➖➖➖\n{}\n➖➖➖➖➖\nمی‌توانید از &lt;b&gt;پررنگ&lt;/b&gt; و &lt;code&gt;کد&lt;/code&gt; هم استفاده کنید.", title, self.tx(k)), Some(kb)).await;
    }

    async fn guide_view(&self, chat: i64, mid: i64, id: i64) {
        let g = self.guides();
        let Some(pos) = g.iter().position(|x| x["id"].as_i64() == Some(id)) else {
            return self.edit(chat, mid, "آموزش پیدا نشد.", Some(ik(vec![vec![b("⬅️ آموزش‌ها", "a:guides")]]))).await;
        };
        let x = &g[pos];
        let cap = x["caption"].as_str().unwrap_or("");
        let txt = format!(
            "🎬 <b>{}</b>{}\nنوع: {}\nمتن زیر آموزش: {}",
            esc(x["title"].as_str().unwrap_or("")), if pos == 0 { "  ⭐️ (آموزش اتصال اصلی)" } else { "" },
            kind_title(x["kind"].as_str().unwrap_or("")), if cap.trim().is_empty() { "— (عنوان نشان داده می‌شود)".to_string() } else { esc(cap) }
        );
        let mut rows: Kb = vec![
            vec![b("▶️ پیش‌نمایش", &format!("gp:{}", id))],
            vec![b("✏️ عنوان", &format!("gt:{}", id)), b("✏️ متن زیر آموزش", &format!("gc:{}", id))],
            vec![b("🔄 جایگزینی ویدیو/فایل", &format!("gr:{}", id))],
        ];
        if pos > 0 { rows.push(vec![b("⭐️ آموزش اصلی کن (اول فهرست)", &format!("gu:{}", id))]); }
        rows.push(vec![b("🗑 حذف", &format!("gx:{}", id))]);
        rows.push(vec![b("⬅️ آموزش‌ها", "a:guides")]);
        self.edit(chat, mid, &txt, Some(ik(rows))).await;
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
                let cur = if let Some(k) = rest.strip_prefix("btn_") { self.bt(k) } else if is_text_key(rest) { self.tx(rest) } else { db.get(rest) };
                let to = match rest.strip_prefix("btn_") { Some(k) => format!("bv:{}", k), None if is_text_key(rest) => format!("tv:{}", rest), None => back_view(rest).to_string() };
                self.edit(chat, mid, &format!("✏️ مقدار جدید برای {} را بفرستید.\n\nمقدار فعلی:\n<code>{}</code>", key_title(rest), esc(&cur)),
                    Some(ik(vec![vec![b("⬅️ انصراف", &to)]]))).await;
            }
            "rs" => {
                db.set(rest, "");
                match rest.strip_prefix("btn_") {
                    Some(k) => self.btn_view(chat, mid, k).await,
                    None => self.txt_view(chat, mid, rest).await,
                }
            }
            "hd" => {
                let k = format!("hide_{}", rest);
                db.set(&k, if db.on(&k) { "0" } else { "1" });
                self.btn_view(chat, mid, rest).await;
            }
            "bv" => self.btn_view(chat, mid, rest).await,
            "tv" => self.txt_view(chat, mid, rest).await,
            "pv" => self.plan_view(chat, mid, rest.parse().unwrap_or(0)).await,
            "pe" => {
                let (id, f) = rest.split_once(':').unwrap_or(("0", ""));
                let id: i64 = id.parse().unwrap_or(0);
                let hint = match f {
                    "name" => "نام جدید پلن",
                    "days" => "مدت به روز (مثلاً 30)",
                    "gb" => "حجم به گیگ (0 = نامحدود)",
                    "conns" => "تعداد کاربر همزمان",
                    "toman" => "قیمت به تومان (فقط عدد)",
                    "usd" => "قیمت به دلار (مثلاً 2.5؛ 0 = بدون پرداخت ارزی)",
                    "countries" => "تعداد کشور (0 = همه‌ی سرورها)",
                    "category" => "اسم دسته (برای «بدون دسته» یک خط تیره - بفرستید)",
                    _ => return,
                };
                let mut msg = format!("✏️ {} را بفرستید.", hint);
                if f == "category" {
                    let cats: Vec<String> = self.categories().into_iter().map(|c| format!("<code>{}</code>", esc(&c.0))).collect();
                    if !cats.is_empty() { msg.push_str(&format!("\n\nدسته‌های فعلی: {}", cats.join("، "))); }
                }
                set_wait(Wait::PlanField(id, f.to_string()));
                self.edit(chat, mid, &msg, Some(ik(vec![vec![b("⬅️ انصراف", &format!("pv:{}", id))]]))).await;
            }
            "pt" => {
                let id: i64 = rest.parse().unwrap_or(0);
                let _ = db.exec("UPDATE plans SET active=1-active WHERE id=?1", &[&id]);
                self.plan_view(chat, mid, id).await;
            }
            "pd" => {
                let id: i64 = rest.parse().unwrap_or(0);
                self.edit(chat, mid, "⚠️ این پلن حذف شود؟", Some(ik(vec![vec![b("🗑 بله، حذف کن", &format!("pdy:{}", id))], vec![b("⬅️ نه", &format!("pv:{}", id))]]))).await;
            }
            "pdy" => {
                let id: i64 = rest.parse().unwrap_or(0);
                let _ = db.exec("DELETE FROM plans WHERE id=?1", &[&id]);
                self.admin_view(uid, chat, mid, "a:plans").await;
            }
            "ck" => self.cat_view(chat, mid, rest.parse().unwrap_or(usize::MAX)).await,
            "cr" | "cx" => {
                let Some((name, _)) = self.categories().get(rest.parse().unwrap_or(usize::MAX)).cloned() else {
                    self.admin_view(uid, chat, mid, "a:cats").await;
                    return;
                };
                if head == "cx" {
                    let _ = db.exec("UPDATE plans SET category='' WHERE category=?1", &[&name]);
                    self.admin_view(uid, chat, mid, "a:cats").await;
                    return;
                }
                set_wait(Wait::CatRename(name.clone()));
                self.edit(chat, mid, &format!("✏️ اسم جدید دسته‌ی «{}» را بفرستید.", esc(&name)), Some(ik(vec![vec![b("⬅️ انصراف", "a:cats")]]))).await;
            }
            "gv" => self.guide_view(chat, mid, rest.parse().unwrap_or(0)).await,
            "gp" => {
                if let Some(g) = self.guide(rest.parse().unwrap_or(0)) {
                    self.send_guide(chat, &g).await;
                }
            }
            "gt" | "gc" | "gr" => {
                let id: i64 = rest.parse().unwrap_or(0);
                let (w, msg) = match head {
                    "gt" => (Wait::GuideTitle(id), "✏️ عنوان جدید آموزش را بفرستید (روی دکمه‌ی فهرست آموزش‌ها نشان داده می‌شود)."),
                    "gc" => (Wait::GuideCap(id), "✏️ متن زیر آموزش را بفرستید. برای پاک کردن، یک خط تیره - بفرستید."),
                    _ => (Wait::GuideFile(id), "🔄 ویدیو (یا گیف، فایل، عکس یا متن) جدید را بفرستید."),
                };
                set_wait(w);
                self.edit(chat, mid, msg, Some(ik(vec![vec![b("⬅️ انصراف", &format!("gv:{}", id))]]))).await;
            }
            "gu" => {
                let id: i64 = rest.parse().unwrap_or(0);
                let mut g = self.guides();
                if let Some(pos) = g.iter().position(|x| x["id"].as_i64() == Some(id)) {
                    let x = g.remove(pos);
                    g.insert(0, x);
                    self.save_guides(&g);
                }
                self.guide_view(chat, mid, id).await;
            }
            "gx" => {
                let id: i64 = rest.parse().unwrap_or(0);
                self.edit(chat, mid, "⚠️ این آموزش حذف شود؟", Some(ik(vec![vec![b("🗑 بله، حذف کن", &format!("gxy:{}", id))], vec![b("⬅️ نه", &format!("gv:{}", id))]]))).await;
            }
            "gxy" => {
                let id: i64 = rest.parse().unwrap_or(0);
                let mut g = self.guides();
                g.retain(|x| x["id"].as_i64() != Some(id));
                self.save_guides(&g);
                self.admin_view(uid, chat, mid, "a:guides").await;
            }
            "gf" if rest == "all" => {
                set_wait(Wait::Gift(0));
                self.edit(chat, mid, &gift_prompt("همه‌ی کاربران فعال"), Some(ik(vec![vec![b("⬅️ انصراف", "a:gift")]]))).await;
            }
            "gfy" => {
                // taken once: a second tap on "yes" gives nothing more
                let Some((days, gb, why)) = self.gifts.lock().unwrap().remove(&uid) else {
                    return self.edit(chat, mid, "این هدیه قبلاً داده شده یا لغو شده است.", Some(ik(vec![vec![b("⬅️ هدیه", "a:gift")]]))).await;
                };
                self.edit(chat, mid, "⏳ در حال اضافه کردن هدیه و فرستادن پیام‌ها…", None).await;
                let targets = self.gift_targets(days, gb);
                let (n, sent) = self.give_gift(&targets, days, gb, &why).await;
                self.edit(chat, mid, &format!("✅ هدیه داده شد\n\n{}\n👥 سرویس‌ها: <b>{}</b>\n✉️ پیام در تلگرام: <b>{}</b> نفر", gift_line(days, gb), n, sent),
                    Some(ik(vec![vec![b("⬅️ پنل مدیریت", "adm")]]))).await;
            }
            "dd" => {
                let _ = db.exec("DELETE FROM discounts WHERE code=?1", &[&rest]);
                self.admin_view(uid, chat, mid, "a:disc").await;
            }
            "u" => {
                let (act, id) = rest.split_once(':').unwrap_or(("", "0"));
                let id: i64 = id.parse().unwrap_or(0);
                let r: Result<(), String> = match act {
                    "gft" => {
                        let who = db.user(id).map(|u| u.username).unwrap_or_default();
                        set_wait(Wait::Gift(id));
                        return self.edit(chat, mid, &gift_prompt(&esc(&who)), Some(ik(vec![vec![b("⬅️ انصراف", &format!("u:inf:{}", id))]]))).await;
                    }
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
            Wait::Set(k) => {
                let v = text.trim();
                let retry = |to: String| Some(ik(vec![vec![b("✏️ دوباره", &format!("set:{}", k))], vec![b("⬅️ بازگشت", &to)]]));
                let to = match k.strip_prefix("btn_") { Some(x) => format!("bv:{}", x), None if is_text_key(&k) => format!("tv:{}", k), None => back_view(&k).to_string() };
                if v.is_empty() {
                    self.send(chat, "⚠️ لطفاً یک متن بفرستید.", retry(to)).await;
                    return;
                }
                if k.starts_with("btn_") && v.chars().count() > 60 {
                    self.send(chat, "⚠️ متن دکمه حداکثر ۶۰ حرف باشد.", retry(to)).await;
                    return;
                }
                // messages are sent as HTML: make sure Telegram accepts this one before saving it
                if is_text_key(&k) && self.send(chat, &format!("👁 پیش‌نمایش:\n\n{}", v), None).await.is_none() {
                    self.send(chat, "⚠️ تلگرام این متن را قبول نکرد (احتمالاً علامت &lt; یا &gt; یا تگ ناقص دارد). ذخیره نشد.", retry(to)).await;
                    return;
                }
                db.set(&k, v);
                self.send(chat, "✅ ذخیره شد", None).await;
                if let Some(x) = k.strip_prefix("btn_") {
                    self.btn_view(chat, 0, x).await;
                } else if is_text_key(&k) {
                    self.txt_view(chat, 0, &k).await;
                } else {
                    self.admin_view(uid, chat, 0, back_view(&k)).await;
                }
            }
            Wait::Plan => {
                let f: Vec<&str> = text.split('|').map(|x| x.trim()).collect();
                if f.len() < 6 { self.send(chat, "⚠️ فرمت نادرست است.", kb).await; return; }
                let cat = f.get(6).map(|c| c.to_string()).unwrap_or_default();
                let r = db.exec("INSERT INTO plans(name,days,gb,toman,usd,conns,category) VALUES(?1,?2,?3,?4,?5,?6,?7)", &[
                    &f[0], &f[1].parse::<i64>().unwrap_or(30), &f[2].parse::<f64>().unwrap_or(0.0),
                    &f[3].parse::<i64>().unwrap_or(0), &f[4].parse::<f64>().unwrap_or(0.0), &f[5].parse::<i64>().unwrap_or(1), &cat]);
                self.send(chat, if r.is_ok() { "✅ پلن اضافه شد" } else { "⚠️ خطا" }, None).await;
                self.admin_view(uid, chat, 0, "a:plans").await;
            }
            Wait::PlanField(id, f) => {
                let v = text.trim();
                let again = Some(ik(vec![vec![b("✏️ دوباره", &format!("pe:{}:{}", id, f))], vec![b("⬅️ پلن", &format!("pv:{}", id))]]));
                let r = match f.as_str() {
                    "name" if !v.is_empty() => db.exec("UPDATE plans SET name=?1 WHERE id=?2", &[&v, &id]),
                    "category" => {
                        let c = if v == "-" || v == "—" { "" } else { v };
                        db.exec("UPDATE plans SET category=?1 WHERE id=?2", &[&c, &id])
                    }
                    "days" | "conns" | "toman" | "countries" => match v.parse::<i64>() {
                        Ok(n) if n >= 0 => db.exec(&format!("UPDATE plans SET {}=?1 WHERE id=?2", f), &[&n, &id]),
                        _ => Err("bad".into()),
                    },
                    "gb" | "usd" => match v.parse::<f64>() {
                        Ok(n) if n >= 0.0 => db.exec(&format!("UPDATE plans SET {}=?1 WHERE id=?2", f), &[&n, &id]),
                        _ => Err("bad".into()),
                    },
                    _ => Err("bad".into()),
                };
                if r.is_err() {
                    self.send(chat, "⚠️ مقدار نادرست است (برای عددها فقط عدد بفرستید).", again).await;
                    return;
                }
                self.send(chat, "✅ ذخیره شد", None).await;
                self.plan_view(chat, 0, id).await;
            }
            Wait::CatRename(old) => {
                let v = text.trim();
                if v.is_empty() || v == "-" {
                    self.send(chat, "⚠️ اسم دسته خالی نباشد.", Some(ik(vec![vec![b("⬅️ دسته‌بندی‌ها", "a:cats")]]))).await;
                    return;
                }
                let _ = db.exec("UPDATE plans SET category=?1 WHERE category=?2", &[&v, &old]);
                self.send(chat, "✅ اسم دسته عوض شد", None).await;
                self.admin_view(uid, chat, 0, "a:cats").await;
            }
            Wait::GuideNew | Wait::GuideFile(_) => {
                let Some((kind, file)) = media_of(m) else {
                    self.send(chat, "⚠️ ویدیو، گیف، فایل، عکس یا متن بفرستید.", Some(ik(vec![vec![b("⬅️ آموزش‌ها", "a:guides")]]))).await;
                    return;
                };
                // the caption under the video (or the text itself, for a text tutorial)
                let cap = m["caption"].as_str().or_else(|| m["text"].as_str()).unwrap_or("").trim().to_string();
                let mut g = self.guides();
                let id = if let Wait::GuideFile(id) = w {
                    for x in g.iter_mut() {
                        if x["id"].as_i64() == Some(id) {
                            x["kind"] = json!(kind);
                            x["file"] = json!(file);
                            if !cap.is_empty() { x["caption"] = json!(cap); }
                        }
                    }
                    id
                } else {
                    let id = g.iter().filter_map(|x| x["id"].as_i64()).max().unwrap_or(0) + 1;
                    let first: String = cap.lines().next().unwrap_or("").trim().chars().take(40).collect();
                    let title = if !first.is_empty() { first } else if g.is_empty() { "آموزش اتصال".to_string() } else { format!("آموزش {}", g.len() + 1) };
                    g.push(json!({"id": id, "title": title, "kind": kind, "file": file, "caption": cap}));
                    id
                };
                self.save_guides(&g);
                self.send(chat, "✅ آموزش ذخیره شد. دکمه‌ی «آموزش اتصال» حالا برای کاربرها فعال است.", None).await;
                self.guide_view(chat, 0, id).await;
            }
            Wait::GuideTitle(id) => {
                let v: String = text.trim().chars().take(40).collect();
                if v.is_empty() { self.send(chat, "⚠️ عنوان خالی نباشد.", Some(ik(vec![vec![b("⬅️ آموزش", &format!("gv:{}", id))]]))).await; return; }
                self.guide_set(id, "title", json!(v));
                self.guide_view(chat, 0, id).await;
            }
            Wait::GuideCap(id) => {
                let v = text.trim();
                let v = if v == "-" || v == "—" { "" } else { v };
                self.guide_set(id, "caption", json!(v));
                self.guide_view(chat, 0, id).await;
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
                if name != "auto" && !valid_cfg_name(&name) {
                    self.send(chat, "⚠️ نام فقط حروف انگلیسی و عدد، ۳ تا ۱۲ حرف و اولش حرف (مثل mahtab87).", kb).await;
                    return;
                }
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
            Wait::Gift(target) => {
                let (days, gb, why) = match parse_gift(text) {
                    Ok(g) => g,
                    Err(e) => {
                        self.waits.lock().unwrap().insert(uid, Wait::Gift(target));
                        let to = if target == 0 { "a:gift".to_string() } else { format!("u:inf:{}", target) };
                        self.send(chat, &e, Some(ik(vec![vec![b("⬅️ انصراف", &to)]]))).await;
                        return;
                    }
                };
                if target == 0 {
                    let targets = self.gift_targets(days, gb);
                    if targets.is_empty() {
                        self.send(chat, "کاربری نیست که این هدیه به او برسد (یا همه نامحدودند).", Some(ik(vec![vec![b("⬅️ هدیه", "a:gift")]]))).await;
                        return;
                    }
                    let mut tgs: Vec<i64> = targets.iter().map(|u| u.tg_id).filter(|t| *t > 0).collect();
                    tgs.sort_unstable();
                    tgs.dedup();
                    self.gifts.lock().unwrap().insert(uid, (days, gb, why.clone()));
                    let note = if why.is_empty() { String::new() } else { format!("\n📝 {}", esc(&why)) };
                    self.send(chat, &format!("🎁 <b>هدیه به همه</b>\n\n{}{}\n\n👥 سرویس‌ها: <b>{}</b>\n✉️ پیام در تلگرام: <b>{}</b> نفر\n\nداده شود؟", gift_line(days, gb), note, targets.len(), tgs.len()),
                        Some(ik(vec![vec![b("✅ بله، هدیه بده", "gfy")], vec![b("⬅️ انصراف", "a:gift")]]))).await;
                    return;
                }
                let Some(u) = db.user(target) else { self.send(chat, "پیدا نشد", kb).await; return };
                let (n, sent) = self.give_gift(std::slice::from_ref(&u), days, gb, &why).await;
                let t = db.user(target).map(|u| self.account_text(&u)).unwrap_or_default();
                let head = match (n, sent) {
                    (0, _) => "ℹ️ چیزی عوض نشد (زمان و حجم این کاربر نامحدود است).".to_string(),
                    (_, 0) => format!("✅ هدیه داده شد ({})\nاین کاربر در ربات نیست، پیامی نرفت.", gift_line(days, gb).replace('\n', " ")),
                    _ => format!("✅ هدیه داده شد ({})\n✉️ پیام برای کاربر رفت.", gift_line(days, gb).replace('\n', " ")),
                };
                self.send(chat, &format!("{}\n\n{}", head, t), Some(self.user_kb(target))).await;
            }
            Wait::DiscountAdd => {
                if parts.len() < 3 { self.send(chat, "⚠️ فرمت نادرست است.", kb).await; return; }
                let r = db.exec("INSERT OR REPLACE INTO discounts(code,percent,uses_left) VALUES(?1,?2,?3)",
                    &[&parts[0].to_uppercase(), &parts[1].parse::<i64>().unwrap_or(0), &parts[2].parse::<i64>().unwrap_or(0)]);
                self.send(chat, if r.is_ok() { "✅ کد تخفیف ساخته شد" } else { "⚠️ خطا" }, kb).await;
            }
            Wait::Broadcast => {
                let (from, msg_id) = (m["chat"]["id"].as_i64().unwrap_or(chat), m["message_id"].as_i64().unwrap_or(0));
                let ok = self.broadcast(from, msg_id, false).await;
                self.send(chat, &format!("{} برای {} کاربر ارسال شد.", "📣", ok), kb).await;
            }
            Wait::BroadcastPin => {
                let (from, msg_id) = (m["chat"]["id"].as_i64().unwrap_or(chat), m["message_id"].as_i64().unwrap_or(0));
                let ok = self.broadcast(from, msg_id, true).await;
                self.send(chat, &format!("{} برای {} کاربر ارسال شد.", "📌", ok), kb).await;
            }
            _ => {}
        }
        let _ = uid;
    }

    // ============================================================ هدیه (جبران قطعی)
    /// Accounts a gift for everyone reaches: on, not a trial, not expired, and with a limited time
    /// (for days) or a limited volume (for GB), since unlimited stays unlimited.
    fn gift_targets(&self, days: i64, gb: f64) -> Vec<User> {
        self.db().users().into_iter()
            .filter(|u| u.enabled && u.notes != "trial" && !u.expired())
            .filter(|u| (days > 0 && u.expires_at > 0) || (gb > 0.0 && u.limit_gb > 0.0))
            .collect()
    }

    /// Adds the gift to these accounts and tells each Telegram user once (all their accounts in one
    /// message). Returns (accounts changed, people told).
    async fn give_gift(&self, users: &[User], days: i64, gb: f64, why: &str) -> (usize, usize) {
        let db = self.db();
        let mut by_tg: Vec<(i64, Vec<i64>)> = vec![];
        let mut n = 0;
        for u in users {
            if !matches!(db.gift(u.id, days, gb), Ok(true)) {
                continue;
            }
            n += 1;
            if u.tg_id > 0 {
                match by_tg.iter_mut().find(|x| x.0 == u.tg_id) {
                    Some(x) => x.1.push(u.id),
                    None => by_tg.push((u.tg_id, vec![u.id])),
                }
            }
        }
        if n > 0 {
            let a = self.app.clone();
            tokio::spawn(async move { sync::sync_all(&a).await });
        }
        let note = if why.is_empty() { String::new() } else { format!("\n\n📝 {}", esc(why)) };
        let kb = Some(ik(vec![vec![b(&self.bt("my"), "my")]]));
        let mut sent = 0;
        for (i, (tg, ids)) in by_tg.iter().enumerate() {
            let accs: Vec<String> = ids.iter().filter_map(|id| db.user(*id)).map(|u| {
                let left = if u.limit_gb > 0.0 { format!("{:.2} GB", (u.limit_gb - u.used_gb()).max(0.0)) } else { "نامحدود".into() };
                format!("👤 <b>{}</b>\n📦 حجم باقی‌مانده: <b>{}</b>\n⏳ زمان باقی‌مانده: <b>{}</b>", esc(&u.username), left, left_text(&u))
            }).collect();
            let msg = format!("{}\n\n{}{}\n\n{}\n\n✨ ممنون که همراه ما هستید؛ کانکی همیشه کنار شماست 💙",
                self.tx("txt_gift"), gift_line(days, gb), note, accs.join("\n\n"));
            if self.send(*tg, &msg, kb.clone()).await.is_some() {
                sent += 1;
            }
            // Telegram allows about 30 messages a second
            if i + 1 < by_tg.len() {
                tokio::time::sleep(std::time::Duration::from_millis(60)).await;
            }
        }
        (n, sent)
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

    /// Free trials that are over are deleted (their number goes to the next new customer) and the owner is told.
    async fn clean_trials(&self) {
        let done = self.db().finished_trials();
        for u in &done {
            self.db().delete_user(u.id);
            if u.tg_id != 0 {
                self.send(u.tg_id, &format!("🎁 تست رایگان شما (<b>{}</b>) تموم شد.\n\nامیدواریم راضی بوده باشید 🙏 برای ادامه، یک اشتراک بخرید 👇", esc(&u.username)),
                    Some(ik(vec![vec![b(&self.bt("buy"), "buy")]]))).await;
            }
        }
        if !done.is_empty() {
            sync::sync_all(&self.app).await;
        }
    }

    async fn background(self: Arc<Self>) {
        let mut tick: u64 = 0;
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            tick += 1;
            // the bot is alive when Telegram accepts its token and the polling is not refused: a long poll
            // that a network on the way cuts while nobody writes must not make it look offline
            if !self.db().on("bot_paused") {
                let refused = { let e = self.db().get("bot_poll_error"); e.contains("Conflict") || e.contains("Unauthorized") || e.contains("Not Found") || e.contains("webhook") };
                if !refused && self.call_res("getMe", json!({})).await.is_ok() {
                    self.app.bot_alive.store(now(), std::sync::atomic::Ordering::Relaxed);
                }
            }
            // another panel polls this bot (Telegram answered 409): the admins are told, at most every 6 hours
            let conflict: i64 = self.db().get("bot_conflict").parse().unwrap_or(0);
            let told: i64 = self.db().get("bot_conflict_told").parse().unwrap_or(0);
            if now() - conflict < 300 && now() - told > 6 * 3600 {
                self.db().set("bot_conflict_told", &now().to_string());
                self.notify_admins("⚠️ <b>یک برنامه‌ی دیگر هم از همین ربات استفاده می‌کند</b> (مثلاً پنل روی سرور قبلی هنوز روشن است).\nهر دو به مشتری‌ها جواب می‌دهند و هر دو در کانال پست می‌گذارند. پنل قدیمی را خاموش کن: <code>systemctl disable --now kanki-panel</code>", None, None).await;
            }
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
            self.clean_trials().await;
            // هشدار اتمام حجم/زمان
            // (every 5 minutes, so the 500 MB warning comes before the data is gone)
            if tick.is_multiple_of(5) && self.db().on("warn_on") {
                // the low-data warning: when this much is left (MB), 500 unless set in the database
                let warn_mb: f64 = self.db().get("warn_mb").parse().ok().filter(|v: &f64| *v > 0.0).unwrap_or(500.0);
                for u in self.db().users().into_iter().filter(|u| u.tg_id != 0) {
                    let mut flag = u.warned;
                    let mut msg = None;
                    if !u.active() && flag & 4 == 0 {
                        flag |= 4;
                        msg = Some(format!("⛔ سرویس <b>{}</b> تمام شد. برای ادامه، از «🔁 تمدید» استفاده کنید.", esc(&u.username)));
                    } else if u.limit_gb > 0.0 && (u.limit_gb - u.used_gb()) * 1024.0 <= warn_mb && flag & 1 == 0 && u.active() {
                        flag |= 1;
                        // the warning carries the whole account card (name, what is left, the code and the
                        // subscription link) and the config buttons, so the customer has everything at hand
                        let left_mb = ((u.limit_gb - u.used_gb()).max(0.0) * 1024.0).round();
                        let used = (u.used_gb() / u.limit_gb).clamp(0.0, 1.0);
                        let full = (used * 10.0).round() as usize;
                        let bar = format!("{}{} {}%", "▰".repeat(full), "▱".repeat(10 - full), (used * 100.0).round());
                        let t = format!("⚠️ <b>حجم سرویس {} داره تموم میشه</b>
فقط <b>{} MB</b> مونده.
<code>{}</code>

{}", esc(&u.username), left_mb, bar, self.account_text(&u));
                        let renew = vec![b("🔁 تمدید", &format!("rnw:{}", u.id))];
                        let _ = self.db().exec("UPDATE users SET warned=?1 WHERE id=?2", &[&flag, &u.id]);
                        self.send(u.tg_id, &t, Some(self.acct_kb(&u, vec![renew]))).await;
                        continue;
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
            if tick.is_multiple_of(24 * 60) && self.db().on("backup_on") {
                if let Ok((bytes, name)) = make_archive(&self.app, &self.db().get("tgb_pass")) {
                    for a in self.admins.clone() {
                        self.send_doc(a, bytes.clone(), &name, "💾 بکاپ خودکار روزانه").await;
                    }
                }
            }
        }
    }
}

/// "Which app and how": sent before the config files of one protocol (w = WireGuard, a = AmneziaWG, h = Hysteria2)
fn gift_prompt(who: &str) -> String {
    format!("🎁 هدیه برای <b>{}</b>\n\nبفرستید: <code>روز گیگ [دلیل]</code>\nمثلاً: <code>2 10 قطعی سرورها در شب گذشته</code>\n(فقط زمان: <code>1 0</code> · فقط حجم: <code>0 5</code>)\n\nدلیل اختیاری است و در پیام کاربر نوشته می‌شود.", who)
}

/// "days GB [reason]" (Persian digits too) -> (days, GB, reason)
fn parse_gift(text: &str) -> Result<(i64, f64, String), String> {
    let t: String = text.chars().map(|c| match c {
        '۰'..='۹' => char::from(b'0' + (c as u32 - '۰' as u32) as u8),
        '٠'..='٩' => char::from(b'0' + (c as u32 - '٠' as u32) as u8),
        '٫' => '.',
        _ => c,
    }).collect();
    let mut it = t.split_whitespace();
    let bad = || "⚠️ فرمت درست: <code>روز گیگ [دلیل]</code> مثلاً <code>2 10</code>".to_string();
    let days: i64 = it.next().and_then(|x| x.parse().ok()).ok_or_else(bad)?;
    let gb: f64 = it.next().and_then(|x| x.parse().ok()).ok_or_else(bad)?;
    if !(0..=365).contains(&days) || !(0.0..=1000.0).contains(&gb) {
        return Err("⚠️ روز بین 0 تا 365 و گیگ بین 0 تا 1000 باشد.".into());
    }
    if days == 0 && gb == 0.0 {
        return Err("⚠️ حداقل یکی از روز یا گیگ بیشتر از صفر باشد.".into());
    }
    let why: String = it.collect::<Vec<_>>().join(" ").chars().take(200).collect();
    Ok((days, gb, why))
}

/// "➕ 2 روز\n➕ 10 گیگ"
fn gift_line(days: i64, gb: f64) -> String {
    let mut v = vec![];
    if days > 0 { v.push(format!("➕ <b>{}</b> روز", days)); }
    if gb > 0.0 { v.push(format!("➕ <b>{}</b> گیگ", gb)); }
    v.join("\n")
}

fn cfg_help(code: &str) -> String {
    let easy = "\n\n💡 <b>راحت‌ترین راه:</b> برنامه‌ی کانکی؛ فقط «کد ورود» رو واردش کنید و دیگه به این فایل‌ها نیازی ندارید.";
    match code {
        "w" => format!("📘 <b>کانفیگ WireGuard</b>\n\n\
            ✅ با این برنامه‌ها کار می‌کنه: <b>WireGuard</b>، <b>AmneziaWG</b> و <b>کانکی</b>\n\n\
            <b>روش وصل شدن با WireGuard:</b>\n\
            1️⃣ برنامه‌ی WireGuard رو از گوگل‌پلی نصب کنید.\n\
            2️⃣ فایل پایین رو دانلود کنید (یک بار روش بزنید).\n\
            3️⃣ توی برنامه دکمه‌ی ➕ رو بزنید ← «Import from file or archive» ← همین فایل رو انتخاب کنید.\n\
            4️⃣ کلید کنار اسم کانفیگ رو روشن کنید ✅{}", easy),
        "a" => format!("📙 <b>کانفیگ AmneziaWG</b>\n\n\
            ⚠️ این کانفیگ با برنامه‌ی WireGuard معمولی <b>وصل نمی‌شه</b>!\n\
            ✅ فقط با این برنامه‌ها: <b>کانکی</b> یا <b>AmneziaWG</b>\n\n\
            <b>روش وصل شدن با AmneziaWG:</b>\n\
            1️⃣ برنامه‌ی AmneziaWG رو از گوگل‌پلی نصب کنید.\n\
            2️⃣ فایل پایین رو دانلود کنید (یک بار روش بزنید).\n\
            3️⃣ توی برنامه دکمه‌ی ➕ رو بزنید ← «Import from file or archive» ← همین فایل رو انتخاب کنید.\n\
            4️⃣ کلید کنار اسم کانفیگ رو روشن کنید ✅{}", easy),
        _ => format!("📗 <b>کانفیگ Hysteria2</b>\n\n\
            ✅ با این برنامه‌ها کار می‌کنه: <b>کانکی</b>، <b>Hiddify</b> و <b>v2rayNG</b>\n\n\
            <b>روش وصل شدن با Hiddify یا v2rayNG:</b>\n\
            1️⃣ روی لینک پایین بزنید تا کپی بشه.\n\
            2️⃣ توی برنامه دکمه‌ی ➕ رو بزنید ← «Import from clipboard» (وارد کردن از کلیپ‌بورد).\n\
            3️⃣ کانفیگ رو انتخاب کنید و دکمه‌ی اتصال رو بزنید ✅{}", easy),
    }
}

/// The plan's dollar price: its own, or the toman price at the admin's rate (Sales › Toman per dollar)
fn plan_usd(db: &crate::db::Db, p: &Plan) -> f64 {
    if p.usd > 0.0 {
        return p.usd;
    }
    let rate: f64 = db.get("usd_rate").replace([',', '٬'], "").trim().parse().unwrap_or(0.0);
    if rate > 0.0 && p.toman > 0 { ((p.toman as f64 / rate) * 100.0).round() / 100.0 } else { 0.0 }
}

/// A wallet address or a payment text the buyer can pay to
fn wallet_has_address(db: &crate::db::Db) -> bool {
    ["ton_address", "usdt_address", "wallet_text"].iter().any(|k| !db.get(k).trim().is_empty())
}

/// Today's TON price in dollars (kept 10 minutes; None when it cannot be read)
async fn ton_usd(app: &crate::App) -> Option<f64> {
    let db = &app.db;
    let at: i64 = db.get("ton_usd_at").parse().unwrap_or(0);
    let cached: f64 = db.get("ton_usd").parse().unwrap_or(0.0);
    if cached > 0.0 && crate::util::now() - at < 600 {
        return Some(cached);
    }
    let r = app.http.get("https://api.coingecko.com/api/v3/simple/price?ids=the-open-network&vs_currencies=usd")
        .timeout(std::time::Duration::from_secs(8)).send().await.ok()?;
    let v: serde_json::Value = r.json().await.ok()?;
    let p = v["the-open-network"]["usd"].as_f64().filter(|p| *p > 0.0)?;
    db.set("ton_usd", &p.to_string());
    db.set("ton_usd_at", &crate::util::now().to_string());
    Some(p)
}

#[cfg(test)]
mod flow_tests {
    //! The customer journey against a fake Telegram API: name prompt, trial, end of the trial, number reuse,
    //! purchase over a trial, rename.
    use super::*;
    use std::sync::atomic::AtomicI64;

    type Log = Arc<Mutex<Vec<(String, Value)>>>;

    async fn fake_telegram() -> (String, Log) {
        let log: Log = Arc::new(Mutex::new(vec![]));
        let l2 = log.clone();
        let router = axum::Router::new().route("/:bot/:method", axum::routing::post(
            move |axum::extract::Path((_bot, m)): axum::extract::Path<(String, String)>, body: String| {
                let l = l2.clone();
                async move {
                    let v: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
                    let bad_edit = m == "editMessageText" && v["message_id"].as_i64() == Some(0);
                    l.lock().unwrap().push((m, v));
                    // like Telegram: a message that does not exist cannot be edited
                    axum::Json(if bad_edit { json!({"ok": false}) } else { json!({"ok": true, "result": {"message_id": 7}}) })
                }
            }));
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(l, router).await.unwrap() });
        (format!("http://{}", addr), log)
    }

    async fn bot() -> (Arc<Bot>, Log) {
        let dir = std::env::temp_dir().join(format!("kanki-bot-test-{}", rand_token(8)));
        std::fs::create_dir_all(&dir).unwrap();
        let db = crate::db::Db::open(dir.join("kanki.db").to_str().unwrap());
        db.set("trial_on", "1");
        let app = Arc::new(App {
            db, env: HashMap::from([("DATA_DIR".to_string(), dir.to_string_lossy().to_string())]),
            hy2_allowed: Mutex::new(HashMap::new()), limits: Mutex::new(HashMap::new()), reported: Mutex::new(HashMap::new()),
            login_fails: Mutex::new(HashMap::new()), sync_lock: tokio::sync::Mutex::new(()), bot_alive: AtomicI64::new(0),
            http: reqwest::Client::new(), http_insecure: reqwest::Client::new(), pin_clients: Mutex::new(HashMap::new()),
        });
        let (api, log) = fake_telegram().await;
        let bot = Arc::new(Bot {
            app, token: "TEST".into(), admins: vec![ADMIN], http: reqwest::Client::new(), api,
            waits: Mutex::new(HashMap::new()), pend: Mutex::new(HashMap::new()), gifts: Mutex::new(HashMap::new()),
        });
        (bot, log)
    }

    const ADMIN: i64 = 9000;

    fn from(id: i64, first: &str, uname: &str) -> Value {
        json!({"id": id, "first_name": first, "username": uname})
    }

    async fn tap(bot: &Bot, f: Value, data: &str) {
        let chat = f["id"].clone();
        bot.on_callback(&json!({"id": "q", "from": f, "data": data, "message": {"message_id": 5, "chat": {"id": chat}}})).await;
    }

    async fn say(bot: &Bot, f: Value, text: &str) {
        let chat = f["id"].clone();
        bot.on_message(&json!({"from": f, "chat": {"id": chat}, "text": text})).await;
    }

    /// The last text sent to / edited for this chat
    fn last(log: &Log, chat: i64) -> String {
        log.lock().unwrap().iter().rev()
            .find(|(m, v)| (m == "sendMessage" || m == "editMessageText") && v["chat_id"].as_i64() == Some(chat))
            .map(|(_, v)| v["text"].as_str().unwrap_or("").to_string()).unwrap_or_default()
    }

    fn accounts(bot: &Bot, tg: i64) -> Vec<(i64, String, String)> {
        let mut v: Vec<_> = bot.db().users_of_tg(tg).into_iter().map(|u| (u.id, u.username, u.notes)).collect();
        v.sort();
        v
    }

    fn order(bot: &Bot, tg: i64, plan: i64, kind: &str, target: i64, status: &str) -> i64 {
        bot.db().with(|c| {
            c.execute("INSERT INTO orders(tg_id,plan_id,kind,target,method,amount,status,ref,discount,created) VALUES(?1,?2,?3,?4,'card','1',?5,'','',?6)",
                rusqlite::params![tg, plan, kind, target, status, now()]).unwrap();
            c.last_insert_rowid()
        })
    }

    fn claim_link(secret: &str, gid: i64, n: i64, tg: i64, gb: i64, days: i64, tag: &str) -> String {
        let payload = format!("{}.{}.{}.{}.{}.{}", gid, n, tg, gb, days, tag);
        format!("/start c_{}_{}_{}_{}_{}_{}_{}", gid, n, tg, gb, days, tag, claim_sig(secret, &payload))
    }

    #[tokio::test]
    async fn giveaway_prize_once_and_only_for_the_winner() {
        let (bot, log) = bot().await;
        let secret = "0123456789abcdef0123456789abcdef0123456789abcdef";
        let link = claim_link(secret, 6, 1, 501, 5, 30, "ElClasico");
        // not configured yet
        say(&bot, from(501, "Ali", "ali"), &link).await;
        assert!(last(&log, 501).contains("فعال نشده"));
        assert!(accounts(&bot, 501).is_empty());
        // only an admin sets the key; too short is refused
        say(&bot, from(501, "Ali", "ali"), &format!("/claimkey {}", secret)).await;
        assert_eq!(bot.db().get("giveaway_secret"), "");
        say(&bot, from(ADMIN, "Boss", "boss"), "/claimkey short").await;
        assert_eq!(bot.db().get("giveaway_secret"), "");
        say(&bot, from(ADMIN, "Boss", "boss"), &format!("/claimkey {}", secret)).await;
        assert_eq!(bot.db().get("giveaway_secret"), secret);
        // someone else can't use the winner's link
        say(&bot, from(502, "Reza", "reza"), &link).await;
        assert!(last(&log, 502).contains("حساب تلگرام دیگه"));
        assert!(accounts(&bot, 502).is_empty());
        // the winner gets one account with the prize's volume and days
        say(&bot, from(501, "Ali", "ali"), &link).await;
        let acc = accounts(&bot, 501);
        assert_eq!(acc.len(), 1, "{:?}", acc);
        assert_eq!(acc[0].1, "ElClasicoW1");
        assert_eq!(acc[0].2, "giveaway ElClasico:6:1");
        let u = bot.db().user(acc[0].0).unwrap();
        assert_eq!(u.limit_gb, 5.0);
        assert!(u.expires_at > now() + 29 * 86400 && u.expires_at <= now() + 30 * 86400);
        // the same link again: nothing new
        say(&bot, from(501, "Ali", "ali"), &link).await;
        assert!(last(&log, 501).contains("قبلاً تحویل"));
        assert_eq!(accounts(&bot, 501).len(), 1);
        // a changed volume / user / padded number breaks the signature
        let forged = link.replace("_5_30_", "_50_30_");
        say(&bot, from(501, "Ali", "ali"), &forged).await;
        assert!(last(&log, 501).contains("معتبر نیست"));
        let padded = link.replace("c_6_1_", "c_06_1_");
        say(&bot, from(501, "Ali", "ali"), &padded).await;
        assert!(last(&log, 501).contains("معتبر نیست"));
        assert_eq!(accounts(&bot, 501).len(), 1);
        // the prediction prize (n = 0) is a separate prize
        say(&bot, from(501, "Ali", "ali"), &claim_link(secret, 6, 0, 501, 20, 30, "ElClasico")).await;
        let acc = accounts(&bot, 501);
        assert_eq!(acc.len(), 2);
        assert!(acc.iter().any(|a| a.1 == "ElClasicoP"));
    }

    #[test]
    fn claim_signature_matches_the_channel_bot() {
        // same input as lib/claim.js in the channel bot: HMAC-SHA256("secret", "kgw1:6.1.4002.5.30.ElClasico")
        // the exact link the channel bot makes for this winner (node: claimParam('secret-secret-secret', …))
        assert_eq!(claim_sig("secret-secret-secret", "6.1.4002.5.30.ElClasico"), "469fe127b8e46f504285");
        let c = parse_claim("6_1_4002_5_30_ElClasico_469fe127b8e46f504285", "secret-secret-secret").unwrap();
        assert_eq!(c, Claim { gid: 6, n: 1, tg: 4002, gb: 5, days: 30, tag: "ElClasico".into() });
        assert_eq!(parse_claim("6_1_4002_500_30_ElClasico_00000000000000000000", "secret-secret-secret"), Err("bad"));
    }

    #[tokio::test]
    async fn sends_the_app_file() {
        let (bot, log) = bot().await;
        let u = from(500, "سارا", "");
        // no file uploaded: the app link of the settings
        bot.db().set("app_link", "https://example.com/app");
        tap(&bot, u.clone(), "app").await;
        assert!(last(&log, 500).contains("https://example.com/app"));
        // a file uploaded in the panel (sent before, so Telegram knows it by id)
        let dir = format!("{}/apps", bot.app.data_dir());
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(format!("{}/arm64-v8a.apk", dir), b"apk").unwrap();
        bot.db().set("app_files", r#"[{"abi":"arm64-v8a","version":"1.15.1","size":38200000,"tg":"FILE1"}]"#);
        tap(&bot, u.clone(), "app").await;
        let text = last(&log, 500);
        assert!(text.contains("Kanki VPN") && text.contains("1.15.1"), "{}", text);
        let kb = log.lock().unwrap().iter().rev().find(|(m, _)| m == "editMessageText").map(|(_, v)| v["reply_markup"].to_string()).unwrap();
        assert!(kb.contains("apk:arm64-v8a") && kb.contains("38.2 MB"), "{}", kb);
        tap(&bot, u.clone(), "apk:arm64-v8a").await;
        let sent = log.lock().unwrap().iter().rev().find(|(m, _)| m == "sendDocument").map(|(_, v)| v.clone()).unwrap();
        assert_eq!(sent["document"], "FILE1");
        assert!(sent["caption"].as_str().unwrap().contains("Kanki VPN 1.15.1 · arm64"));
        // the channel's "download the app" link opens the same menu right away
        say(&bot, from(501, "رضا", ""), "/start app").await;
        let m = log.lock().unwrap().iter().rev().find(|(m, v)| m == "sendMessage" && v["chat_id"] == 501).map(|(_, v)| v.clone()).unwrap();
        assert!(m["text"].as_str().unwrap().contains("دانلود اپ Kanki VPN"));
        assert!(m["reply_markup"].to_string().contains("apk:arm64-v8a"));
    }

    #[tokio::test]
    async fn gift_for_everyone_and_for_one() {
        let (bot, log) = bot().await;
        let db = bot.db();
        let p = "wg";
        let a1 = db.create_user("ali", 10.0, 5, 1, p, "", "", 701).unwrap();
        let a2 = db.create_user("ali2", 0.0, 0, 1, p, "", "", 701).unwrap(); // unlimited: stays unlimited
        let tr = db.create_user("tst", 1.0, 1, 1, p, "", "trial", 702).unwrap();
        let no_tg = db.create_user("panelonly", 20.0, 10, 1, p, "", "", 0).unwrap();
        let old = db.create_user("gone", 5.0, 3, 1, p, "", "", 703).unwrap();
        db.exec("UPDATE users SET expires_at=?1 WHERE id=?2", &[&(now() - 100), &old.id]).unwrap();
        // over quota: the gift is counted from what was used
        db.exec("UPDATE users SET used_bytes=?1 WHERE id=?2", &[&(12i64 << 30), &no_tg.id]).unwrap();
        db.exec("UPDATE users SET limit_gb=10 WHERE id=?1", &[&no_tg.id]).unwrap();
        let adm = from(ADMIN, "admin", "");

        // a customer cannot open it
        tap(&bot, from(701, "Ali", ""), "a:gift").await;
        assert!(!last(&log, 701).contains("هدیه"));

        tap(&bot, adm.clone(), "a:gift").await;
        assert!(last(&log, ADMIN).contains("هدیه‌ی حجم و زمان"));
        tap(&bot, adm.clone(), "gf:all").await;
        say(&bot, adm.clone(), "دو 10").await;
        assert!(last(&log, ADMIN).contains("فرمت درست"));
        // Persian digits and a reason
        say(&bot, adm.clone(), "۲ ۱۰ قطعی دیشب").await;
        let confirm = last(&log, ADMIN);
        assert!(confirm.contains("سرویس‌ها: <b>2</b>") && confirm.contains("<b>1</b> نفر"), "{}", confirm);
        assert_eq!(db.user(a1.id).unwrap().limit_gb, 10.0, "nothing before yes");

        tap(&bot, adm.clone(), "gfy").await;
        let u = db.user(a1.id).unwrap();
        assert_eq!(u.limit_gb, 20.0);
        assert!((u.expires_at - (a1.expires_at + 2 * 86400)).abs() <= 2);
        let u2 = db.user(a2.id).unwrap();
        assert_eq!((u2.limit_gb, u2.expires_at), (0.0, 0));
        assert_eq!(db.user(tr.id).unwrap().limit_gb, 1.0, "trials get nothing");
        assert_eq!(db.user(old.id).unwrap().limit_gb, 5.0, "expired get nothing");
        assert!((db.user(no_tg.id).unwrap().limit_gb - 22.0).abs() < 0.01);
        let msg = last(&log, 701);
        assert!(msg.contains("کاربر گرامی") && msg.contains("قطعی دیشب") && msg.contains("<b>ali</b>") && !msg.contains("ali2") && msg.contains("➕ <b>10</b> گیگ"), "{}", msg);
        assert!(last(&log, ADMIN).contains("هدیه داده شد"));
        // the yes tapped twice gives nothing more
        tap(&bot, adm.clone(), "gfy").await;
        assert_eq!(db.user(a1.id).unwrap().limit_gb, 20.0);

        // one person: even an expired account comes back
        tap(&bot, adm.clone(), &format!("u:gft:{}", old.id)).await;
        say(&bot, adm.clone(), "3 0").await;
        let o = db.user(old.id).unwrap();
        assert!(o.active() && o.expires_at > now() + 2 * 86400, "{}", o.expires_at);
        assert!(last(&log, 703).contains("➕ <b>3</b> روز"));
        assert!(last(&log, ADMIN).contains("پیام برای کاربر رفت"));
    }

    #[tokio::test]
    async fn customer_journey() {
        let (bot, log) = bot().await;
        let plan = bot.db().with(|c| {
            c.execute("INSERT INTO plans(name,days,gb,toman,usd,conns,active) VALUES('m',30,10,100000,1,1,1)", []).unwrap();
            c.last_insert_rowid()
        });

        // A: a Telegram name with nothing usable (only emoji / fancy letters) is asked for a name first
        let a = from(100, "🌙✨ 𝓜𝓪𝓱", "");
        tap(&bot, a.clone(), "trial").await;
        assert!(last(&log, 100).contains("یک نام برای کانفیگ"), "{}", last(&log, 100));
        assert!(accounts(&bot, 100).is_empty());
        say(&bot, a.clone(), "ma tab!").await;
        assert!(last(&log, 100).contains("قابل قبول نیست"));
        say(&bot, a.clone(), "mahtab87").await;
        assert_eq!(accounts(&bot, 100), vec![(1, "mahtab87".into(), "trial".into())]);
        assert!(last(&log, 100).contains("mahtab87"));

        // B: the English letters of the Telegram name are used without asking; a taken name gets a number
        let bb = from(200, "Mahtab87 ✨", "");
        tap(&bot, bb.clone(), "trial").await;
        assert_eq!(accounts(&bot, 200), vec![(2, "mahtab872".into(), "trial".into())]);

        // one trial per person
        tap(&bot, a.clone(), "trial").await;
        assert!(last(&log, 100).contains("قبلاً تست رایگان"));

        // A's trial ends: it is deleted and A is told; number 1 is free again
        bot.db().exec("UPDATE users SET expires_at=?1 WHERE id=1", &[&(now() - 5)]).unwrap();
        bot.clean_trials().await;
        assert!(accounts(&bot, 100).is_empty());
        assert!(last(&log, 100).contains("تموم شد"));
        tap(&bot, a.clone(), "trial").await;
        assert!(last(&log, 100).contains("قبلاً تست رایگان"), "a finished trial cannot be taken again");

        // C buys: the account takes the freed number 1 and C's own name
        let c = from(300, "Erfan", "erfan_x");
        tap(&bot, c.clone(), "home").await;
        let o = order(&bot, 300, plan, "new", 0, "approved");
        bot.fulfill(o).await;
        assert_eq!(accounts(&bot, 300), vec![(1, "erfan".into(), format!("order #{}", o))]);

        // B is over the data limit but has a receipt waiting for approval: the trial is kept
        bot.db().exec("UPDATE users SET used_bytes=?1 WHERE id=2", &[&(20i64 << 30)]).unwrap();
        let pending = order(&bot, 200, plan, "new", 0, "pending");
        bot.clean_trials().await;
        assert_eq!(accounts(&bot, 200).len(), 1);
        // the receipt is approved: B keeps the same account (same number and link), now a normal account
        bot.db().exec("UPDATE orders SET status='approved' WHERE id=?1", &[&pending]).unwrap();
        bot.fulfill(pending).await;
        assert_eq!(accounts(&bot, 200), vec![(2, "mahtab872".into(), format!("order #{}", pending))]);
        bot.clean_trials().await;
        assert_eq!(accounts(&bot, 200).len(), 1, "a bought account is never removed as a trial");

        // B renames the account: rules and taken names are checked
        tap(&bot, bb.clone(), "ren:2").await;
        assert!(last(&log, 200).contains("نام فعلی"));
        say(&bot, bb.clone(), "ERFAN").await;
        assert!(last(&log, 200).contains("قبلاً گرفته شده"));
        say(&bot, bb.clone(), "sara22").await;
        assert_eq!(accounts(&bot, 200)[0].1, "sara22");
        // someone else cannot rename B's account
        tap(&bot, c.clone(), "ren:2").await;
        say(&bot, c.clone(), "hacked1").await;
        assert_eq!(accounts(&bot, 200)[0].1, "sara22");

        // a new buyer without a usable name is asked before the plans are shown
        let d = from(400, "علی", "");
        tap(&bot, d.clone(), "buy").await;
        assert!(last(&log, 400).contains("یک نام برای کانفیگ"));
        say(&bot, d.clone(), "ali2").await;
        let o = order(&bot, 400, plan, "new", 0, "approved");
        bot.fulfill(o).await;
        assert_eq!(accounts(&bot, 400), vec![(3, "ali2".into(), format!("order #{}", o))]);
    }
}
