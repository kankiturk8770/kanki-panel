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
    /// a TON order: the customer may send the transaction's link
    TonTx(i64),
    /// a customer renames one of their accounts
    Rename(i64),
    /// the admin types "days GB [reason]" of a gift: for one account, or 0 = every active account
    Gift(i64),
    /// the admin sends a premium emoji for a button (its key)
    Icon(String),
}

#[derive(Clone)]
struct Pending {
    plan: i64,
    kind: String,
    target: i64,
    discount: String,
    percent: i64,
    /// when it was last changed: an entry left for a day is dropped
    at: i64,
}

impl Default for Pending {
    fn default() -> Self {
        Pending { plan: 0, kind: String::new(), target: 0, discount: String::new(), percent: 0, at: now() }
    }
}

/// How long a started purchase (`pend`) is kept without any change
const PEND_TTL: i64 = 86400;
/// The text of every purchase button while sales are closed
const SALES_CLOSED: &str = "⛔ فروش موقتاً بسته است.";

pub struct Bot {
    app: Arc<App>,
    token: String,
    admins: Vec<i64>,
    http: reqwest::Client,
    /// Telegram Bot API address (a local fake one in the tests)
    api: String,
    waits: Mutex<HashMap<i64, Wait>>,
    pend: Mutex<HashMap<i64, Pending>>,
    /// callback queries already answered: Telegram takes only the first answer of each
    answered: Mutex<std::collections::HashSet<String>>,
    /// a gift for everyone waiting for the admin's "yes": admin -> (days, GB, reason)
    gifts: Mutex<HashMap<i64, (i64, f64, String)>>,
    /// each admin's copy of an order's receipt: order -> (chat, message, is a photo, text), so a decision
    /// shows on every copy (lost on restart: then only the copy that was tapped changes)
    order_msgs: Mutex<HashMap<i64, Vec<ReceiptCopy>>>,
    /// customers seen in the required channel, until when (asked again after 10 minutes)
    members: Mutex<HashMap<i64, i64>>,
    /// the bot's @username (asked from Telegram once)
    me_name: Mutex<String>,
}

/// One admin's copy of an order receipt: (chat, message, is a photo, text)
type ReceiptCopy = (i64, i64, bool, String);

type Kb = Vec<Vec<(String, String)>>;

fn b(t: &str, d: &str) -> (String, String) {
    (t.to_string(), d.to_string())
}

/// Every customer-facing button whose text the admin can change from the bot: (key, default text, where it shows).
/// The text is kept in the setting `btn_<key>`; an empty setting means the default.
pub(crate) const BTNS: &[(&str, &str, &str)] = &[
    ("buy", "🛒 خرید اشتراک", "منوی اصلی"),
    ("trial", "🎁 تست رایگان", "منوی اصلی"),
    ("my", "📊 سرویس‌های من", "منوی اصلی"),
    ("renew", "🔁 تمدید", "منوی اصلی"),
    ("guide", "🎬 آموزش اتصال", "منوی اصلی (فقط وقتی آموزشی اضافه شده باشد)"),
    ("ref", "👥 دعوت دوستان", "منوی اصلی"),
    ("app", "📱 اپ اختصاصی اندروید", "منوی اصلی"),
    ("support", "💬 پشتیبانی", "منوی اصلی"),
    ("guide_acc", "🎬 آموزش اتصال و استفاده از اپ", "زیر پیام اشتراک و دانلود اپ"),
    ("cfg_w", "📥 کانفیگ WireGuard", "زیر پیام اشتراک"),
    ("cfg_a", "📥 کانفیگ AmneziaWG", "زیر پیام اشتراک"),
    ("cfg_h", "📥 کانفیگ Hysteria2", "زیر پیام اشتراک"),
    ("cfg_l", "📄 همه‌ی لینک‌ها (Xray + Hysteria2)", "زیر پیام اشتراک"),
    ("amz", "📦 بکاپ AmneziaVPN (همه‌ی سرورها یک‌جا)", "زیر پیام اشتراک"),
    ("miniapp", "👤 پنل من | مدیریت اشتراک", "زیر پیام اشتراک"),
    ("shop", "🧮 حجم و روز دلخواه", "فهرست پلن‌ها (خرید از مینی‌اپ)"),
    ("renew_this", "🔁 تمدید همین سرویس", "زیر پیام اشتراک"),
    ("rename", "✏️ تغییر نام کانفیگ", "زیر پیام اشتراک"),
    ("other_plans", "📦 سایر پلن‌ها", "فهرست دسته‌بندی پلن‌ها"),
    ("disc", "🎟 کد تخفیف دارم", "صفحه‌ی پرداخت"),
    ("pay_card", "💳 کارت به کارت", "صفحه‌ی پرداخت"),
    ("pay_zp", "🏦 درگاه بانکی (زرین‌پال)", "صفحه‌ی پرداخت"),
    ("pay_np", "🪙 درگاه ارزی (خودکار)", "صفحه‌ی پرداخت"),
    ("pay_wallet", "💰 ارز دیجیتال (کیف پول)", "صفحه‌ی پرداخت"),
    ("pay_ton", "💎 پرداخت با TON (تأیید خودکار)", "صفحه‌ی پرداخت"),
    ("pay_stars", "⭐️ پرداخت با استارز تلگرام", "صفحه‌ی پرداخت"),
    ("back", "⬅️ بازگشت", "همه‌ی صفحه‌ها"),
    ("home", "🏠 منوی اصلی", "بعد از خرید و زیر آموزش‌ها"),
];

/// Buttons of the main menu, in order; each one can also be hidden (`hide_<key>` = 1).
pub(crate) const MAIN_BTNS: &[&str] = &["buy", "trial", "my", "renew", "guide", "ref", "app", "support"];

/// Messages the admin can rewrite from the bot: (setting key, default, title). HTML (<b>, <i>, <code>) is allowed.
const TEXTS: &[(&str, &str, &str)] = &[
    ("welcome", "به ربات فروش خوش آمدید 🌟", "پیام خوش‌آمد (منوی اصلی)"),
    ("txt_menu", "از منوی زیر استفاده کنید 👇", "جواب پیام‌های بی‌ربط"),
    ("txt_cats", "🛍 <b>پلن‌های Kanki VPN</b>\nنوع اشتراک رو از پایین انتخاب کنید 👇", "بالای دسته‌بندی پلن‌ها"),
    ("txt_plans", "سلام 👋\nپلن خودتون رو از پایین انتخاب کنید 👇", "بالای فهرست پلن‌ها"),
    ("txt_trial_ready", "🎁 <b>اکانت تست شما آماده است</b>", "بالای پیام اکانت تست"),
    ("txt_bought", "✅ <b>خرید شما با موفقیت انجام شد!</b>", "بالای پیام بعد از خرید"),
    ("txt_renewed", "✅ <b>تمدید شما با موفقیت انجام شد!</b>", "بالای پیام بعد از تمدید"),
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
        "card_number" | "card_holder" | "zp_merchant" | "zp_callback" | "np_key" | "np_coins" | "wallet_text" | "ton_address" | "star_usd" => "a:pay",
        "ref_gb" | "ref_days" => "a:ref",
        "app_link" | "win_link" | "support" | "channel" => "a:links",
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
        "win_link" => "لینک دانلود Kanki VPN ویندوز (https://…؛ خالی = در راهنمای اتصال ویندوز پیشنهاد نمی‌شود)".into(),
        "channel" => "کانال اجباری (مثل @mychannel)".into(),
        "trial_gb" => "حجم تست (گیگ)".into(),
        "trial_days" => "مدت تست (روز)".into(),
        "ref_gb" => "گیگ هدیه‌ی دعوت".into(),
        "ref_days" => "روز هدیه‌ی دعوت".into(),
        "ton_address" => "آدرس کیف پول TON (مثل UQ… از Tonkeeper)".into(),
        "star_usd" => "دلارِ هر استارز (پیش‌فرض 0.013: همان که تلگرام به صاحب ربات می‌دهد)".into(),
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

/// A message that must never be edited into a menu: a file, a picture or video, or a text with a config or a
/// subscription link in it (what the customer bought)
fn keeps(m: &Value) -> bool {
    if ["document", "photo", "video", "animation"].iter().any(|k| m.get(*k).is_some()) {
        return true;
    }
    let t = m["text"].as_str().or_else(|| m["caption"].as_str()).unwrap_or("");
    ["/sub/", "://", "[Interface]"].iter().any(|x| t.contains(x))
}

fn ik(rows: Kb) -> Value {
    let r: Vec<Vec<Value>> = rows
        .into_iter()
        .map(|row| row.into_iter().map(|(t, d)| {
            if let Some(u) = d.strip_prefix("url:") {
                json!({"text": t, "url": u})
            } else if let Some((st, data)) = d.strip_prefix('@').and_then(|r| r.split_once('@')) {
                // "@<colour>@<data>": a button with its own colour (paint() leaves it)
                json!({"text": t, "callback_data": data, "style": st})
            } else if let Some(r) = d.strip_prefix("webapp:") {
                // "webapp:<colour key>:<url>": the key is read by paint() and not sent
                let (k, u) = r.split_once(':').unwrap_or(("miniapp", r));
                json!({"text": t, "web_app": {"url": u}, "_k": k})
            } else {
                json!({"text": t, "callback_data": d})
            }
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

/// A plan in the admin's list, short: "🟢 🚀 30GB | یک‌ماهه | ۸۵,۰۰۰ ت"
fn plan_label(p: &Plan, active: bool) -> String {
    let vol = if p.gb > 0.0 { format!("{}GB", p.gb) } else { "نامحدود".into() };
    let dur = match p.days {
        0 => "بی‌پایان".to_string(),
        30 => "یک‌ماهه".to_string(),
        d if d % 30 == 0 => format!("{}ماهه", fa_num(&(d / 30).to_string())),
        d => format!("{} روزه", fa_num(&d.to_string())),
    };
    let price = if p.toman > 0 { format!("{} ت", fa_num(&toman(p.toman).replace(" تومان", ""))) } else { format!("{}$", p.usd) };
    let users = if p.conns > 1 { format!(" | {}کاربره", fa_num(&p.conns.to_string())) } else { String::new() };
    format!("{} {} {} | {}{} | {}", if active { "🟢" } else { "⚪️" }, if p.service == "v2ray" { "🌐" } else { "🚀" }, vol, dur, users, price)
}

fn fa_num(s: &str) -> String {
    s.chars().map(|c| match c.to_digit(10) { Some(d) => "۰۱۲۳۴۵۶۷۸۹".chars().nth(d as usize).unwrap_or(c), None => c }).collect()
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
    /// colour of its button: "success", "primary", "danger", "none", or '' (by users: 1 blue, 2+ green)
    style: String,
    /// made for one custom purchase (any volume and days, from the mini app): never listed, still payable
    custom: bool,
    /// what it sells: "vip" (every protocol and the Kanki app) or "v2ray" (only the v2ray subscription)
    service: String,
    /// its label in the shop («🔥 پیشنهاد ویژه»), '' = none
    badge: String,
    /// a higher price shown struck through (0 = none)
    old_toman: i64,
}

/// Kanki's own plans (the admin loads them with one button): (name, days, GB, users, toman, old toman, badge, category)
const KANKI_PLANS: &[(&str, i64, f64, i64, i64, i64, &str, &str)] = &[
    ("20 گیگ | 1 ماهه", 30, 20.0, 1, 80000, 0, "", "تک‌کاربره"),
    ("50 گیگ | 1 ماهه", 30, 50.0, 1, 110000, 0, "🔥 پیشنهاد ویژه", "تک‌کاربره"),
    ("100 گیگ | 1 ماهه", 30, 100.0, 1, 170000, 0, "🚀 پرمصرف", "تک‌کاربره"),
    ("50 گیگ | 2 کاربره | 1 ماهه", 30, 50.0, 2, 135000, 0, "", "چندکاربره"),
    ("100 گیگ | 2 کاربره | 1 ماهه", 30, 100.0, 2, 195000, 0, "", "چندکاربره"),
    ("100 گیگ | 3 کاربره | 1 ماهه", 30, 100.0, 3, 220000, 0, "", "چندکاربره"),
    ("50 گیگ | 2 ماهه", 60, 50.0, 1, 140000, 160000, "", "بلندمدت"),
    ("100 گیگ | 2 کاربره | 2 ماهه", 60, 100.0, 2, 230000, 270000, "", "بلندمدت"),
    ("100 گیگ | 3 ماهه", 90, 100.0, 1, 260000, 330000, "", "بلندمدت"),
];

/// The names the 9 plans had in 3.28 (an emoji first, Persian digits): renamed once to the ones above
const KANKI_NAMES_328: &[&str] = &[
    "🥉 ۲۰ گیگ · ۱ ماهه", "💎 ۵۰ گیگ · ۱ ماهه", "🥇 ۱۰۰ گیگ · ۱ ماهه", "👥 ۵۰ گیگ · ۱ ماهه · ۲ کاربره",
    "👨‍👩‍👧‍👦 ۱۰۰ گیگ · ۱ ماهه · ۲ کاربره", "👑 ۱۰۰ گیگ · ۱ ماهه · ۳ کاربره", "⏳ ۵۰ گیگ · ۲ ماهه",
    "🚀 ۱۰۰ گیگ · ۲ ماهه · ۲ کاربره", "🏆 ۱۰۰ گیگ · ۳ ماهه",
];

/// How each kind of plan looks in the shop: (category, emoji, button colour, one line about it)
const CAT_LOOK: &[(&str, &str, &str, &str)] = &[
    ("تک‌کاربره", "👤", "primary", "برای یک گوشی یا یک کامپیوتر"),
    ("چندکاربره", "👥", "success", "یک اشتراک برای چند دستگاه هم‌زمان (خانواده و دوستان)"),
    ("بلندمدت", "⏳", "danger", "۲ و ۳ ماهه، با تخفیف"),
];

/// The emoji, colour and line of a category (one not in the table: a folder and a colour by its place)
fn cat_look(name: &str, i: usize) -> (&'static str, &'static str, &'static str) {
    match CAT_LOOK.iter().find(|c| c.0 == name) {
        Some(c) => (c.1, c.2, c.3),
        None => ("📂", ["primary", "success", "danger"][i % 3], ""),
    }
}

/// A plan's button in the shop, with English digits and clear separators: «50 گیگ — 2 کاربره — 1 ماهه — 135,000 تومان 🔥»
fn plan_button(p: &Plan, price: i64) -> String {
    let mut parts = vec![if p.gb > 0.0 { format!("{} گیگ", p.gb) } else { "نامحدود".into() }];
    if p.conns > 1 {
        parts.push(format!("{} کاربره", p.conns));
    }
    parts.push(match p.days {
        0 => "بی‌پایان".to_string(),
        d if d % 30 == 0 => format!("{} ماهه", d / 30),
        d => format!("{} روزه", d),
    });
    parts.push(if price > 0 { toman(price) } else { format!("{}$", p.usd) });
    let mark = p.badge.split_whitespace().next().filter(|e| e.chars().next().map(|c| !c.is_alphanumeric()).unwrap_or(false));
    format!("{}{}", parts.join(" — "), mark.map(|e| format!(" {}", e)).unwrap_or_default())
}

/// Hides every listed plan (kept for their orders) and adds Kanki's plans; how many were added
/// Kanki's plans replace the old ones once, by themselves (the owner asked for them on the live bot); after that
/// the admin's own changes stay
fn kanki_plans_once(db: &crate::db::Db) -> bool {
    // 3.29: the 9 plans' names with English digits (only a plan that still has its 3.28 name)
    if db.get("kanki_plans_v2") != "1" {
        db.set("kanki_plans_v2", "1");
        for (old, new) in KANKI_NAMES_328.iter().zip(KANKI_PLANS.iter()) {
            let _ = db.exec("UPDATE plans SET name=?1 WHERE name=?2", &[&new.0, old]);
        }
    }
    if db.get("kanki_plans_v1") == "1" {
        return false;
    }
    db.set("kanki_plans_v1", "1");
    load_kanki_plans(db) > 0
}

fn load_kanki_plans(db: &crate::db::Db) -> usize {
    let _ = db.exec("UPDATE plans SET active=0 WHERE active=1", &[]);
    let mut n = 0;
    for (name, days, gb, users, t, old, badge, cat) in KANKI_PLANS {
        if db.exec("INSERT INTO plans(name,days,gb,toman,usd,conns,active,category,style,service,badge,old_toman) VALUES(?1,?2,?3,?4,0,?5,1,?6,'','vip',?7,?8)",
            &[name, days, gb, t, users, cat, badge, old]).is_ok() { n += 1; }
    }
    n
}

/// The chat's menu button (it opens the mini app): for a customer with a working account, and for everyone else.
/// Short on purpose: the button sits beside the message box and a long text left no room to type.
/// In English: Telegram (Android) left a short Persian text on this button blank.
const MENU_MINE: &str = "My Kanki 👤";
const MENU_NEW: &str = "Kanki 🚀";

/// How to add a v2ray subscription link, under a v2ray account
const V2RAY_HELP: &str = "📲 <b>اتصال با برنامه‌های V2Ray</b>\n• اندروید: v2rayNG (گوگل‌پلی)\n• آیفون: Streisand یا V2Box (اپ‌استور)\n• ویندوز: v2rayN یا Nekoray\n\n1️⃣ لینک بالا رو کپی کنید.\n2️⃣ توی برنامه: ➕ ← اضافه کردن اشتراک (Subscription) و لینک رو بذارید.\n3️⃣ اشتراک رو به‌روز (Update) کنید، یه سرور رو انتخاب کنید و وصل بشید.\n\nسرورها که عوض بشن، با به‌روز کردن اشتراک خودش درست می‌شه.";

/// The two services a plan can sell: (database value, callback code, button, description in the buy menu)
const SERVICES: &[(&str, &str, &str, &str)] = &[
    ("v2ray", "v", "🌐 سرویس استاندارد (V2Ray)",
     "🌐 <b>سرویس استاندارد (V2Ray / Xray)</b>\n• یک لینک اشتراک، برای v2rayNG، Streisand، V2Box و Nekoray\n• قیمت اقتصادی‌تر؛ مناسب کارهای روزمره و وب‌گردی"),
    ("vip", "p", "🚀 سرویس VIP ضدتحریم",
     "🚀 <b>سرویس VIP ضدتحریم</b> (اپ اختصاصی کانکی + AmneziaWG + WireGuard)\n• همه‌ی کشورها و سرورها هم‌زمان، مستقیم و از راه تانل\n• پروتکل‌های اختصاصی کانکی (KANKI MIX و microtun) برای عبور از فیلتر\n• مخصوص بازی (پینگ پایین)، اختلال شدید اینترنت و کاربر حرفه‌ای"),
];

fn service_of_code(c: &str) -> &'static str {
    SERVICES.iter().find(|s| s.1 == c).map(|s| s.0).unwrap_or("")
}

fn service_code(s: &str) -> &'static str {
    SERVICES.iter().find(|x| x.0 == s).map(|x| x.1).unwrap_or("")
}

/// The bot that is running (polling Telegram), for the mini app: a purchase must go to its pending list
fn running_slot() -> &'static Mutex<Option<Arc<Bot>>> {
    static R: std::sync::OnceLock<Mutex<Option<Arc<Bot>>>> = std::sync::OnceLock::new();
    R.get_or_init(|| Mutex::new(None))
}

pub fn running() -> Option<Arc<Bot>> {
    running_slot().lock().unwrap_or_else(|e| e.into_inner()).clone()
}

/// The keys a button colour can be set for (setting `bst_<key>`), and the colour each has by default
pub const STYLE_KEYS: &[(&str, &str)] = &[
    ("buy", "success"), ("trial", "primary"), ("my", ""), ("renew", "success"), ("guide", ""), ("ref", ""), ("app", ""), ("support", ""),
    ("renew_this", "success"), ("pay", "success"), ("disc", ""), ("shop", "primary"), ("miniapp", "primary"), ("amz", "primary"), ("cfg", ""),
];

/// Every plan with whether it is on sale (active = 1; custom ones are active = 2)
fn all_plans(db: &crate::db::Db) -> Vec<(Plan, bool)> {
    db.with(|c| {
        let mut s = c.prepare("SELECT id,name,COALESCE(days,0),COALESCE(gb,0),COALESCE(toman,0),COALESCE(usd,0),COALESCE(conns,1),COALESCE(active,1),COALESCE(countries,0),COALESCE(category,''),COALESCE(style,''),COALESCE(service,'vip'),COALESCE(badge,''),COALESCE(old_toman,0) FROM plans ORDER BY toman").unwrap();
        let v: Vec<(Plan, bool)> = s.query_map([], |r| {
            let active: i64 = r.get(7)?;
            Ok((Plan {
                id: r.get(0)?, name: r.get(1)?, days: r.get(2)?, gb: r.get(3)?, toman: r.get(4)?, usd: r.get(5)?, conns: r.get(6)?,
                countries: r.get(8)?, category: r.get(9)?, style: r.get(10)?, custom: active == 2,
                service: if r.get::<_, String>(11)? == "v2ray" { "v2ray".into() } else { "vip".into() },
                badge: r.get(12)?, old_toman: r.get(13)?,
            }, active == 1))
        }).unwrap().filter_map(|x| x.ok()).collect();
        v
    })
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
            // a timeout on every call: one hung connection to Telegram (common on filtered networks) froze
            // the bot until a restart. Above the 30 s long poll; uploads set their own, longer one.
            app, token, admins,
            http: reqwest::Client::builder().timeout(std::time::Duration::from_secs(75)).connect_timeout(std::time::Duration::from_secs(15)).build().unwrap_or_default(),
            api: "https://api.telegram.org".into(),
            waits: Mutex::new(HashMap::new()), pend: Mutex::new(HashMap::new()), answered: Mutex::new(Default::default()), gifts: Mutex::new(HashMap::new()), order_msgs: Mutex::new(HashMap::new()), members: Mutex::new(HashMap::new()), me_name: Mutex::new(String::new()),
        }))
    }

    /// Button colours (Telegram 9.4+, older apps show plain buttons): each customer button gets the colour
    /// the admin chose (`bst_<key>`) or its default; a plan button its plan's colour (by users when unset:
    /// one blue, two or more green); the admin's approve green and reject red.
    /// With `icons`, a button whose text is one of the bot's own (`BTNS`) also gets the premium emoji the admin
    /// set for it (`buttons::icons`) in place of its plain one.
    fn paint(&self, body: &mut Value, icons: bool) {
        // looked up without `body["reply_markup"]`: indexing a JSON value for writing adds the key, and every
        // message without buttons went out with reply_markup {"inline_keyboard": null}, which is not a keyboard
        let Some(rows) = body.get_mut("reply_markup").and_then(|r| r.get_mut("inline_keyboard")).and_then(|k| k.as_array_mut()) else { return };
        // text of the button → its premium emoji (one settings read per message, and only when any is set)
        let by_text: HashMap<String, String> = if icons {
            crate::buttons::icons(self.db()).into_iter().map(|(k, id)| (self.bt(&k), id)).collect()
        } else {
            HashMap::new()
        };
        for row in rows.iter_mut() {
            let Some(row) = row.as_array_mut() else { continue };
            for btn in row.iter_mut() {
                if let Some(id) = btn["text"].as_str().and_then(|t| by_text.get(t)) {
                    let plain = crate::buttons::without_lead_emoji(btn["text"].as_str().unwrap_or(""));
                    btn["icon_custom_emoji_id"] = json!(id);
                    btn["text"] = json!(plain);
                }
                if btn.get("style").is_some() {
                    if let Some(o) = btn.as_object_mut() {
                        o.remove("_k");
                    }
                    continue;
                }
                let data = btn["callback_data"].as_str().unwrap_or("").to_string();
                let key = btn.as_object_mut().and_then(|o| o.remove("_k")).and_then(|k| k.as_str().map(|s| s.to_string()));
                let style = if let Some(k) = key {
                    self.style_of(&k)
                } else {
                    self.style_for(&data)
                };
                if !style.is_empty() {
                    btn["style"] = json!(style);
                }
            }
        }
    }

    /// The colour of a customer button key: the admin's, else the default ("" = none)
    fn style_of(&self, key: &str) -> String {
        let v = self.db().get(&format!("bst_{}", key));
        let v = v.trim();
        if ["success", "primary", "danger"].contains(&v) {
            return v.to_string();
        }
        if v == "none" {
            return String::new();
        }
        STYLE_KEYS.iter().find(|x| x.0 == key).map(|x| x.1.to_string()).unwrap_or_default()
    }

    fn style_for(&self, data: &str) -> String {
        let (head, rest) = data.split_once(':').unwrap_or((data, ""));
        match head {
            "ap" => "success".into(),
            "rj" => "danger".into(),
            "pl" | "rpl" => {
                let id: i64 = rest.split(':').next().and_then(|x| x.parse().ok()).unwrap_or(0);
                match all_plans(self.db()).into_iter().find(|x| x.0.id == id) {
                    Some((p, _)) => match p.style.as_str() {
                        "success" | "primary" | "danger" => p.style,
                        "none" => String::new(),
                        // its category's colour (as the category button), else by users
                        _ => match CAT_LOOK.iter().find(|c| c.0 == p.category) {
                            Some(c) => c.2.to_string(),
                            None => if p.conns >= 2 { "success".into() } else { "primary".into() },
                        },
                    },
                    None => String::new(),
                }
            }
            "pay" => self.style_of("pay"),
            "rnw" => self.style_of("renew_this"),
            "amz" | "amp" => self.style_of("amz"),
            "cfg" => self.style_of("cfg"),
            "app2" => self.style_of("app"),
            k if rest.is_empty() && STYLE_KEYS.iter().any(|x| x.0 == k) => self.style_of(k),
            _ => String::new(),
        }
    }

    /// The «custom volume and days» row that opens the mini app's shop (on renewing account `renew` when
    /// > 0); none when the mini app cannot open (no https address) or custom purchase is off
    fn shop_row(&self, renew: i64) -> Option<Vec<(String, String)>> {
        let mini = crate::miniapp::url(&self.app);
        if !mini.starts_with("https://") || !crate::shop::limits(self.db()).on || !self.db().on("sales_on") {
            return None;
        }
        let r = if renew > 0 { format!("&renew={}", renew) } else { String::new() };
        Some(vec![b(&self.bt("shop"), &format!("webapp:shop:{}?buy=1{}", mini, r))])
    }

    /// For the mini app: false (and the "join the channel" message in the chat) when the required channel is
    /// not joined, as every button of the bot does
    pub(crate) async fn mini_gate(&self, uid: i64) -> bool {
        if self.joined(uid).await {
            return true;
        }
        self.ask_join(uid).await;
        false
    }

    /// For the mini app: a config name is still needed before the first account (the bot asks it too)
    /// No config name chosen yet: the first purchase or trial asks for one (with the Telegram name as a one-tap answer)
    pub(crate) fn needs_name(&self, uid: i64) -> bool {
        !valid_cfg_name(&self.db().with(|c| c.query_row("SELECT COALESCE(cfg_name,'') FROM bot_users WHERE tg_id=?1", [uid], |r| r.get::<_, String>(0)).unwrap_or_default()))
    }

    /// The name made from the customer's Telegram name (or @username), when it has English letters
    pub(crate) fn name_hint(&self, uid: i64) -> Option<String> {
        let (first, last, uname): (String, String, String) = self.db().with(|c| c.query_row(
            "SELECT COALESCE(name,''), COALESCE(lname,''), COALESCE(uname,'') FROM bot_users WHERE tg_id=?1", [uid],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).ok())?;
        cfg_name_from(&format!("{}{}", first, last)).or_else(|| cfg_name_from(&uname))
    }

    /// The "type a name" message and its buttons: «use my Telegram name» when there is one, and back
    fn name_ask(&self, uid: i64, next: &str) -> (String, Value) {
        self.waits.lock().unwrap_or_else(|e| e.into_inner()).insert(uid, Wait::CfgName(next.to_string()));
        let mut rows: Kb = vec![];
        if let Some(h) = self.name_hint(uid) {
            rows.push(vec![b(&format!("⏭ همون اسم تلگرامم: {}", h), &format!("cfgsk:{}", next))]);
        }
        rows.push(vec![b(&self.bt("back"), "home")]);
        (self.name_prompt(""), ik(rows))
    }

    /// For the mini app: the config name typed there, checked as the bot checks it (Err = why not)
    pub(crate) fn set_name(&self, uid: i64, name: &str) -> Result<String, String> {
        let n = self.check_name(name.trim(), 0)?;
        // a customer who never wrote to the bot has no row yet (the names Telegram gave stay as they are)
        let _ = self.db().exec("INSERT OR IGNORE INTO bot_users(tg_id,joined) VALUES(?1,?2)", &[&uid, &now()]);
        let _ = self.db().exec("UPDATE bot_users SET cfg_name=?1 WHERE tg_id=?2", &[&n, &uid]);
        Ok(n)
    }

    /// For the mini app: can this customer still get the free trial?
    pub(crate) fn trial_open(&self, uid: i64) -> bool {
        self.db().on("trial_on") && !self.trial_taken(uid)
    }

    /// For the mini app: the free trial, delivered in the chat exactly as from the bot's button
    /// (false = the bot could not message the customer; the trial is then not used up)
    pub(crate) async fn mini_trial(&self, uid: i64) -> bool {
        self.trial_ok(uid, uid, 0).await
    }

    /// From the mini app: buy plan `pid` (a new account, or more for the buyer's account `renew`); the bot
    /// shows the plan and the payment methods in the chat, exactly as after tapping the plan in the bot.
    /// False when the bot could not message the customer.
    pub(crate) async fn start_purchase(&self, uid: i64, pid: i64, renew: i64) -> bool {
        {
            let mut g = self.pend.lock().unwrap_or_else(|e| e.into_inner());
            let mine = renew > 0 && self.app.db.user(renew).map(|u| u.tg_id == uid).unwrap_or(false);
            g.insert(uid, Pending { plan: pid, kind: if mine { "renew".into() } else { "new".into() }, target: if mine { renew } else { 0 }, ..Default::default() });
        }
        self.show_plan(uid, None, uid, pid).await
    }

    fn admin(&self, id: i64) -> bool {
        self.admins.contains(&id)
    }

    /// The bot's @username, asked from Telegram once
    async fn my_username(&self) -> String {
        let known = self.me_name.lock().unwrap_or_else(|e| e.into_inner()).clone();
        if !known.is_empty() {
            return known;
        }
        let me = self.call("getMe", json!({})).await.and_then(|v| v["username"].as_str().map(|s| s.to_string())).unwrap_or_default();
        if !me.is_empty() {
            *self.me_name.lock().unwrap_or_else(|e| e.into_inner()) = me.clone();
        }
        me
    }

    /// One customer's pace: at most 20 taps or messages in 10 seconds (a flood is dropped, so one person cannot
    /// make the bot reach Telegram's own limit and leave everyone else waiting); admins and payments are never held
    fn flood(&self, u: &Value) -> Option<(i64, String)> {
        let (uid, qid) = if u["callback_query"].is_object() {
            (u["callback_query"]["from"]["id"].as_i64().unwrap_or(0), u["callback_query"]["id"].as_str().unwrap_or("").to_string())
        } else if u["message"].is_object() && !u["message"]["successful_payment"].is_object() {
            (u["message"]["from"]["id"].as_i64().unwrap_or(0), String::new())
        } else {
            return None;
        };
        if uid == 0 || self.admin(uid) || crate::limit::hit("bot", &uid.to_string(), 20, 10) {
            return None;
        }
        Some((uid, qid))
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
            match self.call_res("copyMessage", json!({"chat_id": t, "from_chat_id": from, "message_id": msg_id})).await {
                Ok(res) => {
                    ok += 1;
                    if pin {
                        if let Some(nid) = res["message_id"].as_i64() {
                            let _ = self.call("pinChatMessage", json!({"chat_id": t, "message_id": nid, "disable_notification": true})).await;
                        }
                    }
                }
                // only when Telegram says this chat is gone for the bot; a busy moment (429) or a cut connection is not
                Err(e) if gone_chat(&e) => {
                    let _ = db.exec("UPDATE bot_users SET blocked=1 WHERE tg_id=?1", &[&t]);
                }
                Err(_) => {}
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
        let plain = body.clone();
        let mut painted = body;
        self.paint(&mut painted, true);
        let had_icons = painted.to_string().contains("icon_custom_emoji_id");
        match self.call_raw(m, painted).await {
            // a premium emoji Telegram does not take (the owner's Premium ended, the emoji was removed): the message
            // still goes, with the buttons' plain emoji
            Err(why) if had_icons && why.to_lowercase().contains("emoji") => {
                let mut b = plain;
                self.paint(&mut b, false);
                self.call_raw(m, b).await
            }
            r => r,
        }
    }

    /// `call_res` without the fallback: the preview of a premium emoji must fail when Telegram refuses it
    async fn call_strict(&self, m: &str, mut body: Value) -> Result<Value, String> {
        self.paint(&mut body, true);
        self.call_raw(m, body).await
    }

    async fn call_raw(&self, m: &str, body: Value) -> Result<Value, String> {
        // a lost message is worse than a late one: Telegram's «too many requests» (429, it says how long to wait),
        // its own errors (5xx) and a connection that never started are tried again, up to 3 more times. getUpdates is
        // not: its loop asks again by itself. An error never carries the request's address (it holds the bot token).
        let tries = if m == "getUpdates" { 1 } else { 4 };
        let mut v = Value::Null;
        for i in 0..tries {
            let last = i + 1 == tries;
            match self.http.post(format!("{}/bot{}/{}", self.api, self.token, m)).json(&body).send().await {
                Err(e) if !last && e.is_connect() => {
                    tokio::time::sleep(std::time::Duration::from_millis(700 * (i as u64 + 1))).await;
                    continue;
                }
                Err(e) => return Err(e.without_url().to_string()),
                Ok(r) => {
                    let status = r.status().as_u16();
                    v = r.json().await.map_err(|e| e.without_url().to_string())?;
                    if v["ok"].as_bool() == Some(true) || last {
                        break;
                    }
                    let wait = match v["error_code"].as_i64().unwrap_or(status as i64) {
                        429 => v["parameters"]["retry_after"].as_u64().unwrap_or(1).clamp(1, 30) * 1000,
                        500..=599 => 700 * (i as u64 + 1),
                        _ => break,
                    };
                    tokio::time::sleep(std::time::Duration::from_millis(wait)).await;
                }
            }
        }
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
        self.edit_ok(chat, mid, text, kb).await;
    }

    /// `edit`, with whether the customer has the text now (edited, or sent as a new message)
    async fn edit_ok(&self, chat: i64, mid: i64, text: &str, kb: Option<Value>) -> bool {
        // 0: no message to edit (or one that must stay, see `keeps`): a new one
        if mid == 0 {
            return self.send(chat, text, kb).await.is_some();
        }
        let mut body = json!({"chat_id": chat, "message_id": mid, "text": text, "parse_mode": "HTML", "disable_web_page_preview": true});
        if let Some(k) = kb.clone() { body["reply_markup"] = k; }
        // a message that cannot be edited any more gets a new one; the same text again (a button tapped
        // twice) is not a reason to send a second message
        match self.call_res("editMessageText", body).await {
            Ok(_) => true,
            Err(e) if e.contains("message is not modified") => true,
            Err(_) => self.send(chat, text, kb).await.is_some(),
        }
    }

    /// Answers a button tap. Telegram takes only the first answer, so a tap is answered once: the first
    /// call wins and later ones do nothing (`on_callback` gives an empty answer at the end when none was given).
    async fn answer(&self, id: &str, text: &str, alert: bool) {
        if !id.is_empty() && !self.answered.lock().unwrap_or_else(|e| e.into_inner()).insert(id.to_string()) {
            return;
        }
        self.call("answerCallbackQuery", json!({"callback_query_id": id, "text": text, "show_alert": alert})).await;
    }

    /// This customer's menu button: "my panel" with a working account, else "open the app / buy"
    async fn set_menu(&self, tg: i64) {
        let mini = crate::miniapp::url(&self.app);
        if !mini.starts_with("https://") || self.db().get("mini_menu") == "0" || tg <= 0 {
            return;
        }
        let mine = self.db().users_of_tg(tg).iter().any(|u| u.active());
        let text = if mine { MENU_MINE } else { MENU_NEW };
        let _ = self.call("setChatMenuButton", json!({"chat_id": tg, "menu_button": {"type": "web_app", "text": text, "web_app": {"url": mini}}})).await;
    }

    /// An order's receipt to every admin, remembering each copy so the decision can be written on all of them
    async fn notify_order(&self, oid: i64, text: &str, kb: Value, photo: Option<String>) {
        let mut copies = vec![];
        for a in &self.admins {
            let r = match &photo {
                Some(p) => self.call("sendPhoto", json!({"chat_id": a, "photo": p, "caption": text, "parse_mode": "HTML", "reply_markup": kb})).await,
                None => self.send(*a, text, Some(kb.clone())).await,
            };
            if let Some(mid) = r.as_ref().and_then(|m| m["message_id"].as_i64()) {
                copies.push((*a, mid, photo.is_some(), text.to_string()));
            }
        }
        self.order_msgs.lock().unwrap_or_else(|e| e.into_inner()).insert(oid, copies);
    }

    /// Writes an order's decision under every admin's copy of it (and the copy that was tapped, e.g. in the open
    /// orders list); with no buttons, so it cannot be tapped again
    async fn mark_order(&self, oid: i64, q: &Value, note: &str) {
        let mut list = self.order_msgs.lock().unwrap_or_else(|e| e.into_inner()).get(&oid).cloned().unwrap_or_default();
        let msg = &q["message"];
        let (chat, mid) = (msg["chat"]["id"].as_i64().unwrap_or(0), msg["message_id"].as_i64().unwrap_or(0));
        if mid > 0 && !list.iter().any(|c| c.0 == chat && c.1 == mid) {
            let photo = msg["photo"].is_array();
            let text = esc(msg[if photo { "caption" } else { "text" }].as_str().unwrap_or(""));
            list.push((chat, mid, photo, text));
        }
        for (chat, mid, photo, text) in list {
            let body = format!("{}\n\n{}", text, note);
            if photo {
                self.call("editMessageCaption", json!({"chat_id": chat, "message_id": mid, "caption": body, "parse_mode": "HTML"})).await;
            } else {
                self.call("editMessageText", json!({"chat_id": chat, "message_id": mid, "text": body, "parse_mode": "HTML", "disable_web_page_preview": true})).await;
            }
        }
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

    /// The "download the app" message in the customer's chat (from the mini app)
    pub(crate) async fn send_app_menu(&self, chat: i64) -> bool {
        let (t, rows) = self.app_menu(false);
        self.send(chat, &t, Some(ik(rows))).await.is_some()
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

    /// Sends a file; true when Telegram took it
    async fn send_doc(&self, chat: i64, bytes: Vec<u8>, name: &str, caption: &str) -> bool {
        // tried again as call_res does: Telegram's «too many requests» and its 5xx, and a connection that never started
        for i in 0..4u64 {
            let part = reqwest::multipart::Part::bytes(bytes.clone()).file_name(name.to_string());
            let form = reqwest::multipart::Form::new()
                .text("chat_id", chat.to_string()).text("caption", caption.to_string()).part("document", part);
            let wait = match self.http.post(format!("{}/bot{}/sendDocument", self.api, self.token)).multipart(form).timeout(std::time::Duration::from_secs(600)).send().await {
                Ok(r) => {
                    let status = r.status().as_u16() as i64;
                    let v = r.json::<Value>().await.unwrap_or(Value::Null);
                    if v["ok"].as_bool() == Some(true) {
                        return true;
                    }
                    match v["error_code"].as_i64().unwrap_or(status) {
                        429 => v["parameters"]["retry_after"].as_u64().unwrap_or(1).clamp(1, 30) * 1000,
                        500..=599 => 700 * (i + 1),
                        _ => return false,
                    }
                }
                Err(e) if e.is_connect() => 700 * (i + 1),
                Err(_) => return false,
            };
            if i < 3 {
                tokio::time::sleep(std::time::Duration::from_millis(wait)).await;
            }
        }
        false
    }

    // ============================================================ کمکی‌های داده
    fn db(&self) -> &crate::db::Db {
        &self.app.db
    }

    fn plans(&self, only_active: bool) -> Vec<(Plan, bool)> {
        all_plans(self.db()).into_iter().filter(|(p, a)| (*a && !p.custom) || !only_active).collect()
    }

    fn plan(&self, id: i64) -> Option<Plan> {
        self.plans(false).into_iter().map(|x| x.0).find(|p| p.id == id)
    }

    /// A plan that is on sale now. A button can carry any plan id (an old message, or a client that
    /// makes its own buttons): a plan the admin switched off must not be bought. `plan` stays for orders
    /// already placed.
    fn plan_on_sale(&self, id: i64) -> Option<Plan> {
        all_plans(self.db()).into_iter().find(|(p, a)| p.id == id && (*a || p.custom)).map(|x| x.0)
    }

    fn account_text(&self, u: &User) -> String {
        let left = if u.limit_gb > 0.0 { format!("{:.2} GB", (u.limit_gb - u.used_gb()).max(0.0)) } else { "نامحدود".into() };
        let st = if u.active() { "🟢 فعال" } else { "🔴 غیرفعال" };
        // a v2ray account: only its subscription link and how to add it to a v2ray app
        if u.service() == "v2ray" {
            return format!(
                "👤 <b>{}</b>  ·  {}  ·  🌐 سرویس استاندارد (V2Ray)\n📦 حجم باقی‌مانده: <b>{}</b>  (مصرف: {:.2} GB)\n⏳ زمان باقی‌مانده: <b>{}</b>\n🔌 اتصال: {}/{}\n\n🔗 <b>لینک اشتراک</b> (روش بزنید تا کپی بشه):\n<code>{}</code>\n\n{}",
                esc(&u.username), st, left, u.used_gb(), left_text(u), u.online, u.max_conn, esc(&crate::api::v2_sub_link(&self.app, u)), V2RAY_HELP
            );
        }
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
        format!(
            "👤 <b>{}</b>  ·  {}\n📦 حجم باقی‌مانده: <b>{}</b>  (مصرف: {:.2} GB)\n⏳ زمان باقی‌مانده: <b>{}</b>\n🔌 اتصال: {}/{}\n\n📱 <b>بهترین راه (پیشنهاد ما): برنامه‌ی کانکی</b>\n{}{}\n<code>{}</code>\n\n🔗 لینک اشتراک (برای برنامه‌های دیگه):\n<code>{}/sub/{}</code>",
            esc(&u.username), st, left, u.used_gb(), left_text(u), u.online, u.max_conn, step1, step2, u.sub_code(), sub_origin(&self.app), u.sub_code()
        )
    }

    /// The message after a purchase, renewal or trial: short, one link to copy and three buttons (the apps, the
    /// video tutorial, support). Everything else (configs, backups) is in the mini app and «📊 سرویس‌های من».
    fn delivery(&self, head: &str, u: &User, plan: &str) -> (String, Value) {
        let exp = if u.expires_at > 0 { crate::channel::fa_datetime(u.expires_at).0 } else { "نامحدود".into() };
        let link = if u.service() == "v2ray" { crate::api::v2_sub_link(&self.app, u) } else { format!("{}/sub/{}", sub_origin(&self.app), u.sub_code()) };
        let t = format!("{}\n\n📦 پلن: <b>{}</b>\n👤 حساب: <b>{}</b>\n⏳ انقضا: <b>{}</b>\n\n🔗 <b>لینک اتصال هوشمند شما:</b>\n<code>{}</code>\n\n📲 <b>روی کدوم دستگاه وصل می‌شید؟</b>\nدکمه‌ی دستگاهتون رو بزنید؛ برنامه‌ی مناسب، فایل و آموزش قدم‌به‌قدم همین‌جا میاد 👇",
            head, esc(plan), esc(&u.username), exp, esc(&link));
        let mut rows: Kb = vec![self.how_devices_kb(u.id)];
        let mini = crate::miniapp::url(&self.app);
        if mini.starts_with("https://") {
            rows.push(vec![b("👤 مدیریت اشتراک (مینی‌اپ)", &format!("webapp:miniapp:{}", mini))]);
        }
        // a tutorial not pinned to one app and device (a general one) stays here
        if self.guides().iter().any(|g| g["for"].as_array().map(|a| a.is_empty()).unwrap_or(true)) {
            rows.push(vec![b("آموزش ویدیویی اتصال 🎥", "guide1")]);
        }
        let sup = self.db().get("support").trim().to_string();
        let sl = if let Some(id) = sup.strip_prefix('@') { Some(format!("https://t.me/{}", id)) } else if sup.starts_with("https://") { Some(sup) } else { None };
        rows.push(vec![b("پشتیبانی 💬", &sl.map(|l| format!("url:{}", l)).unwrap_or_else(|| "support".into()))]);
        (t, ik(rows))
    }

    // ============================================================ the connection guide: device, then app

    /// The protocols an account really has on its servers (direct or through a tunnel)
    fn protos_of(&self, u: &User) -> Vec<&'static str> {
        let mut have: Vec<&'static str> = vec![];
        for n in crate::api::user_nodes(&self.app, u) {
            for p in crate::api::node_protos(&self.app, u, &n).into_iter().chain(crate::api::twin_protos(&self.app, u, &n)) {
                if !have.contains(&p) { have.push(p); }
            }
        }
        have
    }

    /// The apps offered on a device for this account, in the order shown (the first is the recommended one)
    fn how_apps(&self, u: &User, os: &str) -> Vec<&'static str> {
        let have = self.protos_of(u);
        let wg = have.contains(&"wireguard") || have.contains(&"amneziawg");
        let v2 = u.service() == "v2ray";
        let links = v2 || crate::api::links_text(&self.app, u).is_some();
        let kanki = !v2 && match os {
            "a" => !crate::apps::list(&self.app).is_empty() || self.db().get("app_link").trim().starts_with("https://"),
            "w" => self.db().get("win_link").trim().starts_with("https://"),
            _ => false,
        };
        // AmneziaVPN holds WireGuard, AmneziaWG and the Xray links (not Hysteria2): one backup file
        let amz = (wg && !v2) || crate::xray::panel::user_links(&self.app, u).iter().any(|(_, l)| crate::amnezia::server(l, "").is_some());
        let mut v: Vec<&'static str> = vec![];
        if kanki { v.push("k"); }
        // on an iPhone AmneziaVPN comes first (the Kanki app is not there); a V2Ray account still gets its V2Ray app first elsewhere
        if amz && (!v2 || os == "i") { v.push("z"); }
        if links { v.push("v"); }
        if amz && v2 && os != "i" { v.push("z"); }
        if have.contains(&"wireguard") && !v2 { v.push("g"); }
        v
    }

    /// The device menu: which app to connect with, each said in one line, the recommended one first
    fn how_device(&self, u: &User, os: &str) -> (String, Kb) {
        let apps = self.how_apps(u, os);
        let dev = match os { "i" => "🍏 آیفون / آیپد", "w" => "💻 ویندوز", _ => "🤖 اندروید" };
        let mut t = format!("{} · <b>اتصال حساب {}</b>\n\nبا کدوم برنامه وصل می‌شید؟ روی هر کدوم بزنید، فایل و آموزش قدم‌به‌قدم همین‌جا میاد 👇\n", dev, esc(&u.username));
        let mut rows: Kb = vec![];
        for (i, a) in apps.iter().enumerate() {
            let star = if i == 0 { "⭐️ " } else { "" };
            let (name, line) = how_app_line(a, os);
            t.push_str(&format!("\n{}<b>{}</b>{}: {}", star, name, if i == 0 { " (پیشنهاد ما)" } else { "" }, line));
            rows.push(vec![b(&format!("{}{}", star, name), &format!("@{}@hw:{}:{}:{}", if i == 0 { "success" } else { "primary" }, u.id, os, a))]);
        }
        if apps.is_empty() {
            t.push_str("\nبرای این دستگاه هنوز راهی برای سرویس شما فعال نیست؛ به پشتیبانی پیام بدید.");
        }
        rows.push(vec![b("📲 دستگاه دیگه", &format!("hw:{}", u.id))]);
        (t, rows)
    }

    /// The device chooser (under the delivery and the account)
    fn how_devices_kb(&self, id: i64) -> Vec<(String, String)> {
        vec![b("🤖 اندروید", &format!("hw:{}:a", id)), b("🍏 آیفون", &format!("hw:{}:i", id)), b("💻 ویندوز", &format!("hw:{}:w", id))]
    }

    /// One app on one device: where to get it, the steps, what to put in it (the file, the code or the link), and the
    /// admin's video tutorials pinned to it
    async fn how_app(&self, chat: i64, qid: &str, u: &User, os: &str, app: &str) {
        if !self.how_apps(u, os).contains(&app) {
            return self.answer(qid, "این راه برای سرویس شما فعال نیست.", true).await;
        }
        let (name, _) = how_app_line(app, os);
        let back = vec![b("⬅️ برنامه‌ی دیگه", &format!("hw:{}:{}", u.id, os))];
        let store = |label: &str, url: &str| vec![b(label, &format!("url:{}", url))];
        match app {
            "k" => {
                let mut rows: Kb = vec![];
                let get = if os == "w" {
                    rows.push(store("⬇️ دانلود Kanki VPN برای ویندوز", self.db().get("win_link").trim()));
                    "1️⃣ برنامه رو با دکمه‌ی پایین دانلود و نصب کنید."
                } else {
                    let files = crate::apps::list(&self.app);
                    if files.is_empty() {
                        rows.push(store("⬇️ دانلود Kanki VPN", self.db().get("app_link").trim()));
                    }
                    for f in &files {
                        let (title, _) = crate::apps::title(&f.abi);
                        rows.push(vec![b(&format!("⬇️ {} · {}", title, mb(f.size)), &format!("apk:{}", f.abi))]);
                    }
                    "1️⃣ فایل نصب رو از دکمه‌ی پایین بگیرید و نصب کنید (اگه مطمئن نیستید «۶۴ بیتی» رو بگیرید)."
                };
                rows.push(back);
                self.send(chat, &format!("⭐️ <b>اپ اختصاصی Kanki VPN</b>\nهمه‌ی سرورها و همه‌ی پروتکل‌ها (حتی پروتکل‌های ضدفیلتر کانکی) با یک کد؛ سرور خوب رو خودش پیدا می‌کنه.\n\n{}\n2️⃣ برنامه رو باز کنید و این <b>کد ورود</b> رو بزنید (روش بزنید کپی می‌شه):\n<code>{}</code>\n3️⃣ دکمه‌ی بزرگ اتصال رو بزنید. تمام ✅", get, u.sub_code()), Some(ik(rows))).await;
            }
            "z" => {
                let url = match os {
                    "i" => "https://apps.apple.com/app/amneziavpn/id1600529900",
                    "w" => "https://github.com/amnezia-vpn/amnezia-client/releases/latest",
                    _ => "https://play.google.com/store/apps/details?id=org.amnezia.vpn",
                };
                let where_ = match os { "i" => "اپ‌استور", "w" => "سایت گیت‌هاب (فایل Windows)", _ => "گوگل‌پلی" };
                self.send(chat, &format!("🛡 <b>AmneziaVPN</b>\nهمه‌ی سرورهای شما (WireGuard، AmneziaWG و VLESS / Xray، مستقیم و از راه تانل) با <b>یک فایل</b>.\n\n1️⃣ AmneziaVPN رو از {} نصب کنید (دکمه‌ی پایین).\n2️⃣ فایل بکاپی که الان میاد رو ذخیره کنید{}.\n3️⃣ توی برنامه: ⚙️ تنظیمات ← پشتیبان‌گیری (Backup) ← <b>بازیابی از نسخه‌ی پشتیبان</b> (Restore from backup) ← همین فایل.\n4️⃣ یک سرور رو انتخاب و دکمه‌ی اتصال رو بزنید ✅\n\n⚠️ بازیابی، سرورهای قبلی خود برنامه رو پاک می‌کنه.",
                    where_, if os == "i" { " (روش بزنید ← اشتراک‌گذاری ← Save to Files)" } else { "" }),
                    Some(ik(vec![store("⬇️ دانلود AmneziaVPN", url), back]))).await;
                self.send_amnezia(chat, qid, u, os).await;
            }
            "v" => {
                let link = crate::api::v2_sub_link(&self.app, u);
                let (get, steps) = match os {
                    "i" => ("https://apps.apple.com/app/v2box-v2ray-client/id6446814690",
                        "1️⃣ V2Box رو از اپ‌استور نصب کنید (یا Streisand).\n2️⃣ لینک اشتراک پایین رو لمس کنید تا کپی بشه.\n3️⃣ V2Box رو باز کنید: تب <b>Configs</b> ← ➕ بالای صفحه ← <b>Add subscription</b>.\n4️⃣ لینک رو توی <b>URL</b> بذارید (Paste)، یه اسم بدید و <b>Save</b> بزنید؛ صفحه رو پایین بکشید تا کانفیگ‌ها بیان.\n5️⃣ یکی رو انتخاب کنید و از تب <b>Home</b> وصل بشید (اجازه‌ی VPN رو Allow کنید) ✅"),
                    "w" => ("https://github.com/2dust/v2rayN/releases/latest",
                        "1️⃣ v2rayN رو از گیت‌هاب بگیرید (فایل windows-64-With-Core) و باز کنید.\n2️⃣ لینک اشتراک پایین رو کپی کنید.\n3️⃣ منوی <b>Subscription group</b> ← <b>Subscription group settings</b> ← <b>Add</b>: لینک رو در Url بذارید و ذخیره کنید.\n4️⃣ <b>Subscription group</b> ← <b>Update subscription</b>؛ کانفیگ‌ها میان.\n5️⃣ یکی رو انتخاب، Enter، و پایین پنجره System proxy رو روی Set system proxy بذارید ✅"),
                    _ => ("https://play.google.com/store/apps/details?id=com.v2ray.ang",
                        "1️⃣ v2rayNG رو از گوگل‌پلی نصب کنید.\n2️⃣ لینک اشتراک پایین رو لمس کنید تا کپی بشه.\n3️⃣ v2rayNG رو باز کنید: ➕ ← <b>Import config from Clipboard</b>. خودش می‌فهمه لینک اشتراکه و توی اشتراک‌ها (Subscription) می‌ذاره.\n4️⃣ منوی ⋮ ← <b>Update subscription</b> تا کانفیگ‌ها بیان.\n5️⃣ یکی رو انتخاب و دکمه‌ی ▶️ پایین صفحه ✅"),
                };
                let note = if u.service() == "v2ray" { String::new() } else { "\n\nℹ️ این برنامه‌ها کانفیگ‌های VLESS (Xray) و Hysteria2 رو وصل می‌کنن. برای WireGuard / AmneziaWG، «AmneziaVPN» رو انتخاب کنید (اون VLESS رو هم داره).".to_string() };
                self.send(chat, &format!("🚀 <b>{}</b>\n\n{}\n\n🔗 <b>لینک اشتراک شما</b> (یک بار اضافه کنید؛ سرورها عوض بشن با Update خودش درست می‌شه):\n<code>{}</code>{}", name, steps, esc(&link), note),
                    Some(ik(vec![store(&format!("⬇️ دانلود {}", name), get), back]))).await;
            }
            "g" => {
                let url = match os {
                    "i" => "https://apps.apple.com/app/wireguard/id1441195209",
                    "w" => "https://www.wireguard.com/install/",
                    _ => "https://play.google.com/store/apps/details?id=com.wireguard.android",
                };
                let add = if os == "w" { "Import tunnel(s) from file" } else if os == "i" { "➕ ← Create from file or archive" } else { "➕ ← Import from file or archive" };
                self.send(chat, &format!("🔐 <b>WireGuard</b>\nفقط کانفیگ‌های WireGuard، هر سرور یک فایل جدا.\n\n1️⃣ برنامه‌ی WireGuard رو نصب کنید (دکمه‌ی پایین).\n2️⃣ فایل‌هایی که الان میان رو ذخیره کنید.\n3️⃣ توی برنامه: <b>{}</b> ← فایل یک سرور.\n4️⃣ کلید کنار اسمش رو روشن کنید ✅\n\n💡 برای همه‌ی سرورها با هم، «AmneziaVPN» راحت‌تره.", add),
                    Some(ik(vec![store("⬇️ دانلود WireGuard", url), back]))).await;
                self.send_configs_n(chat, qid, u, "w", false).await;
            }
            _ => {}
        }
        // the admin's tutorials for this app on this device (Bot › tutorials › «📌 where it shows»)
        let target = format!("{}:{}", app, os);
        for g in self.guides().iter().filter(|g| g["for"].as_array().map(|a| a.iter().any(|x| x.as_str() == Some(target.as_str()))).unwrap_or(false)) {
            self.send_guide(chat, g).await;
        }
    }

    /// What the customer gets after a purchase / trial / "my service": the account plus a hint about the config buttons.
    fn account_msg(&self, u: &User) -> String {
        if u.service() == "v2ray" {
            return self.account_text(u);
        }
        format!("{}\n\n{}", self.account_text(u), self.tx("txt_cfg"))
    }

    /// Buttons that send the config files, in a fixed order, followed by `extra` rows.
    fn acct_kb(&self, u: &User, mut extra: Kb) -> Value {
        let have = self.protos_of(u);
        // first: the connection guide by device (Android / iPhone / Windows)
        let mut rows: Kb = vec![self.how_devices_kb(u.id)];
        // the connection tutorial first, so a new customer sees it before the manual configs
        if let Some(r) = self.guide_row() {
            rows.push(r);
        }
        // the mini app: the account, the AmneziaVPN backup and the configs in one page (Telegram opens only https)
        let mini = crate::miniapp::url(&self.app);
        if mini.starts_with("https://") {
            rows.push(vec![b(&self.bt("miniapp"), &format!("webapp:miniapp:{}", mini))]);
        }
        // every WireGuard / AmneziaWG config and Xray link in one AmneziaVPN restore file
        if have.contains(&"wireguard") || have.contains(&"amneziawg") || crate::xray::panel::user_links(&self.app, u).iter().any(|(_, l)| crate::amnezia::server(l, "").is_some()) {
            rows.push(vec![b(&self.bt("amz"), &format!("amz:{}", u.id))]);
        }
        // one subscription link brings every Xray and Hysteria2 config into a V2Ray app (no separate configs)
        if crate::api::links_text(&self.app, u).is_some() || u.service() == "v2ray" {
            rows.push(vec![b("🚀 لینک اشتراک V2Ray (v2rayNG · V2Box)", &format!("cfg:{}:v", u.id))]);
        }
        // the WireGuard / AmneziaWG files of each server, side by side
        let files: Vec<(String, String)> = [("wireguard", "w"), ("amneziawg", "a")].iter().filter(|(p, _)| have.contains(p))
            .map(|(_, c)| b(&self.bt(&format!("cfg_{}", c)), &format!("cfg:{}:{}", u.id, c))).collect();
        if !files.is_empty() {
            rows.push(files);
        }
        // the app's install files (sent as a new message, so this account message stays); a v2ray account
        // connects with a v2ray app, not the Kanki app. No rename here: the admin renames when it is needed.
        if !crate::apps::list(&self.app).is_empty() && u.service() != "v2ray" {
            rows.push(vec![b("📱 دانلود اپ اختصاصی اندروید", "app2")]);
        }
        rows.append(&mut extra);
        ik(rows)
    }

    /// Sends the config(s) of one protocol: first a short "which app and how" guide, then a file per server
    /// (Hysteria2 as a copyable link). True when the customer got at least one config.
    pub(crate) async fn send_configs(&self, chat: i64, qid: &str, u: &User, code: &str) -> bool {
        self.send_configs_n(chat, qid, u, code, true).await
    }

    /// The same, with its "which app and how" text or without it (the connection guide says it itself)
    async fn send_configs_n(&self, chat: i64, qid: &str, u: &User, code: &str, help: bool) -> bool {
        // "w:TR": only the servers of one country (the mini app's servers tab)
        let (code, cc) = match code.split_once(':') { Some((c, k)) => (c, Some(k.trim().to_uppercase())), None => (code, None) };
        if code == "l" {
            return self.send_links(chat, qid, u).await;
        }
        if code == "v" {
            return self.send_v2_sub(chat, u).await;
        }
        let (proto, title) = match code { "w" => ("wireguard", "WireGuard"), "a" => ("amneziawg", "AmneziaWG"), _ => ("hysteria2", "Hysteria2") };
        // each server's direct config, then its copy through the tunnel (WireGuard only that one)
        let mut list: Vec<(crate::db::Node, bool)> = vec![];
        for n in crate::api::user_nodes(&self.app, u) {
            if cc.as_ref().map(|c| crate::exitgeo::cc(&self.app, &n.id).to_uppercase() != *c).unwrap_or(false) {
                continue;
            }
            if crate::api::node_protos(&self.app, u, &n).contains(&proto) {
                list.push((n.clone(), false));
            }
            if crate::api::twin_protos(&self.app, u, &n).contains(&proto) {
                list.push((n, true));
            }
        }
        list.truncate(8);
        if list.is_empty() {
            self.answer(qid, "این پروتکل برای سرویس شما فعال نیست.", true).await;
            return false;
        }
        if help {
            self.send(chat, &cfg_help(code), None).await;
        }
        let mut sent = false;
        for (n, tunnel) in list {
            let Some((name, text)) = crate::api::bot_config(&self.app, u, &n, proto, tunnel).await else { continue };
            let server = if tunnel { crate::api::twin_name(&self.app, &n) } else { n.name.clone() };
            if proto == "hysteria2" {
                sent |= self.send(chat, &format!("📥 <b>{} · {}</b>\n\n<code>{}</code>\n\n☝️ روی لینک بزنید تا کپی بشه.", title, esc(&server), esc(text.trim())), None).await.is_some();
            } else {
                let cap = format!("📥 {} · {}\nاسم داخل برنامه: {}", title, server, name.trim_end_matches(".conf"));
                sent |= self.send_doc(chat, text.into_bytes(), &name, &cap).await;
            }
        }
        sent
    }

    /// The V2Ray subscription link of an account with how to add it: one link brings every Xray and Hysteria2
    /// config into v2rayNG / V2Box / Hiddify / v2rayN, and keeps them up to date
    pub(crate) async fn send_v2_sub(&self, chat: i64, u: &User) -> bool {
        let link = crate::api::v2_sub_link(&self.app, u);
        let t = format!("🚀 <b>لینک اشتراک V2Ray</b> · {}\n\n<code>{}</code>\n☝️ روش بزنید تا کپی بشه.\n\n\
            همه‌ی کانفیگ‌های VLESS (Xray) و Hysteria2 شما با همین یک لینک میان و هر وقت سرورها عوض بشن، با «به‌روزرسانی» خودش درست می‌شه.\n\n\
            🍏 <b>آیفون · V2Box</b>\n\
            1️⃣ لینک بالا رو کپی کنید.\n\
            2️⃣ V2Box ← تب <b>Configs</b> ← ➕ بالای صفحه ← <b>Add subscription</b>\n\
            3️⃣ لینک رو توی <b>URL</b> بذارید (Paste)، یه اسم بدید و <b>Save</b> بزنید.\n\
            4️⃣ صفحه رو پایین بکشید تا کانفیگ‌ها بیان؛ یکی رو انتخاب و از تب <b>Home</b> وصل بشید (اجازه‌ی VPN رو Allow کنید).\n\n\
            🤖 <b>اندروید · v2rayNG:</b> ➕ ← Import config from Clipboard ← منوی ⋮ ← Update subscription\n\
            💻 <b>ویندوز · v2rayN:</b> Subscription group ← Subscription group settings ← Add ← Update subscription",
            esc(&u.username), esc(&link));
        self.send(chat, &t, Some(ik(vec![
            vec![b("⬇️ v2rayNG (اندروید)", "url:https://github.com/2dust/v2rayNG/releases/latest"), b("⬇️ V2Box (آیفون)", "url:https://apps.apple.com/app/v2box-v2ray-client/id6446814690")],
        ]))).await.is_some()
    }

    /// The subscription link and every Hysteria2 and Xray link of an account: a .txt file, and the same text to copy
    /// when it fits in one message. The first line is the subscription, so the app keeps the configs up to date.
    pub(crate) async fn send_links(&self, chat: i64, qid: &str, u: &User) -> bool {
        let Some(text) = crate::api::links_text(&self.app, u) else {
            self.answer(qid, "برای سرویس شما لینک Xray یا Hysteria2 فعال نیست.", true).await;
            return false;
        };
        let n = text.lines().count().saturating_sub(1);
        let cap = format!(
            "📄 همه‌ی لینک‌ها · {} کانفیگ (Xray + Hysteria2)\n\n\
             خط اول لینک اشتراکه: توی برنامه به‌عنوان اشتراک (Subscription) اضافه‌ش کنید تا هر تغییری روی سرورها خودش به‌روز بشه.\n\
             بقیه‌ی خط‌ها کانفیگ‌ها هستن.\n\n\
             برنامه‌ها: v2rayNG، Hiddify، NekoBox، V2Box، Streisand\n\
             ➕ ← Import from clipboard (بعد از کپی) یا Import from file (همین فایل).",
            n
        );
        let file = self.send_doc(chat, text.clone().into_bytes(), &format!("{}-links.txt", u.username), &cap).await;
        let msg = format!("🔗 <b>لینک اشتراک</b> (یک بار اضافه‌ش کنید، خودش به‌روز می‌شه):\n<code>{}</code>\n\n📋 <b>همه با هم</b> (روش بزنید تا کپی بشه):\n<code>{}</code>",
            esc(&crate::api::v2_sub_link(&self.app, u)), esc(text.trim()));
        // Telegram's limit is 4096 characters; a longer list goes only as the file
        let text_sent = if msg.chars().count() <= 4000 {
            self.send(chat, &msg, None).await
        } else {
            self.send(chat, &format!("🔗 <b>لینک اشتراک</b> (یک بار اضافه‌ش کنید، خودش به‌روز می‌شه):\n<code>{}</code>\n\nبقیه‌ی لینک‌ها زیاد بودن و فقط توی فایل بالا هستن.", esc(&crate::api::v2_sub_link(&self.app, u))), None).await
        };
        file || text_sent.is_some()
    }

    /// The AmneziaVPN backup of an account for one platform (i, a, w), with how to restore it.
    /// True when the customer got the file.
    pub(crate) async fn send_amnezia(&self, chat: i64, qid: &str, u: &User, code: &str) -> bool {
        let Some(plat) = crate::amnezia::platform(code) else { return false };
        let cfgs = crate::api::amnezia_configs(&self.app, u).await;
        let Some(body) = crate::amnezia::backup(&cfgs, plat) else {
            self.answer(qid, "برای سرویس شما کانفیگی که AmneziaVPN بخونه (WireGuard، AmneziaWG یا VLESS) فعال نیست.", true).await;
            return false;
        };
        // the servers in the file, in its order (straight AmneziaWG, through Iran, WireGuard, Xray), with their flags
        let mut list = String::new();
        for (i, (name, _)) in cfgs.iter().enumerate() {
            let line = format!("{}. {}\n", i + 1, name);
            // Telegram's caption is at most 1024 characters: the steps below matter more than a long list
            if list.chars().count() + line.chars().count() > 420 {
                list.push_str(&format!("… و {} سرور دیگر\n", cfgs.len() - i));
                break;
            }
            list.push_str(&line);
        }
        let app_name = match plat { "iOS" => "از اپ‌استور", "Android" => "از گوگل‌پلی", _ => "از amnezia.org" };
        let cap = format!(
            "📦 بکاپ AmneziaVPN · {} سرور\n\n{}\n\
             📲 نصب، قدم به قدم:\n\
             1️⃣ AmneziaVPN رو {} نصب کنید.\n\
             2️⃣ همین فایل رو ذخیره کنید (Save to Files / Download).\n\
             3️⃣ AmneziaVPN ← Settings ← Backup ← Restore from backup و فایل رو انتخاب کنید.\n\
             4️⃣ سرورها به همین ترتیب می‌آیند: اول AmneziaWG مستقیم، بعد از راه ایران (🇮🇷→)، بعد WireGuard و آخر Xray. یکی رو بزنید و Connect ✅\n\n\
             ⚠️ بازیابی، سرورها و تنظیمات قبلی خود برنامه رو پاک می‌کنه.",
            cfgs.len(), list, app_name
        );
        self.send_doc(chat, body.into_bytes(), &crate::amnezia::file_name(&u.username), &cap).await
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
        self.create_account_svc(tg, gb, days, conns, notes, countries, "vip")
    }

    /// A new account for a plan of `service` ("vip": every protocol; "v2ray": only the v2ray subscription)
    #[allow(clippy::too_many_arguments)]
    fn create_account_svc(&self, tg: i64, gb: f64, days: i64, conns: i64, notes: &str, countries: i64, service: &str) -> Result<User, String> {
        // the customer's own name (mahtab87; mahtab872 … when taken); USER<n> only when there is no usable name.
        // The number (id) is always the lowest free one, so a deleted trial's number goes to the next customer.
        let name = match self.cfg_name_for(tg) {
            Some(n) => format!("pick:{}", n),
            None if notes == "trial" => "auto-test".to_string(),
            None => "auto".to_string(),
        };
        let nodes = self.pick_nodes(countries);
        let u = self.db().create_user(&name, gb, days, conns, &self.db().service_protocols(service), &nodes, notes, tg)?;
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
            // priced from the toman price at today's rate; checked on the chain / by Telegram, never by hand
            "ton" => db.on("ton_on") && crate::pay::raw_address(&db.get("ton_address")).is_some() && t > 0,
            "stars" => db.on("stars_on") && t > 0,
            _ => false,
        }
    }

    /// عضویت اجباری کانال (اگر تنظیم شده)
    async fn joined(&self, uid: i64) -> bool {
        let ch = self.db().get("channel");
        if ch.is_empty() || self.admin(uid) {
            return true;
        }
        // a member is not asked again for 10 minutes (every tap asked Telegram before); one who is not is asked each time
        if self.members.lock().unwrap_or_else(|e| e.into_inner()).get(&uid).map(|t| *t > now()).unwrap_or(false) {
            return true;
        }
        let ok = match self.call("getChatMember", json!({"chat_id": ch, "user_id": uid})).await {
            Some(v) => matches!(v["status"].as_str(), Some("member") | Some("administrator") | Some("creator")),
            None => return true,
        };
        if ok {
            let mut m = self.members.lock().unwrap_or_else(|e| e.into_inner());
            if m.len() > 50_000 {
                let t = now();
                m.retain(|_, until| *until > t);
            }
            m.insert(uid, now() + 600);
        }
        ok
    }

    // ============================================================ حلقه‌ی اصلی
    pub async fn run(self: Arc<Self>) {
        kanki_plans_once(self.db());
        let me3 = self.clone();
        tokio::spawn(async move { me3.ton_watch().await });
        *running_slot().lock().unwrap_or_else(|e| e.into_inner()) = Some(self.clone());
        // the chat's menu button opens the mini app (an admin can switch it off: mini_menu = 0)
        let mini = crate::miniapp::url(&self.app);
        if mini.starts_with("https://") && self.db().get("mini_menu") != "0" {
            let _ = self.call("setChatMenuButton", json!({"menu_button": {"type": "web_app", "text": MENU_NEW, "web_app": {"url": mini}}})).await;
        }
        if self.db().get("api_key").is_empty() {
            self.db().set("api_key", &rand_token(40));
        }
        // every chat that got an older menu button text gets the new one, once (a few per second, under Telegram's limit)
        if self.db().get("menu_text_v") != "2" {
            self.db().set("menu_text_v", "2");
            let me = self.clone();
            tokio::spawn(async move {
                let ids: Vec<i64> = me.db().with(|c| { let mut s = c.prepare("SELECT tg_id FROM bot_users WHERE blocked=0").unwrap();
                    let v = s.query_map([], |r| r.get(0)).unwrap().filter_map(|x| x.ok()).collect(); v });
                for id in ids {
                    me.set_menu(id).await;
                    tokio::time::sleep(std::time::Duration::from_millis(80)).await;
                }
            });
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
            let res = self.call_res("getUpdates", json!({"offset": offset, "timeout": 30, "allowed_updates": ["message", "callback_query", "pre_checkout_query"]})).await;
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
                // too fast: a tap gets a short «slow down», a message is dropped
                if let Some((_, qid)) = self.flood(&u) {
                    if !qid.is_empty() {
                        tokio::spawn(async move { me.answer(&qid, "⏳ لطفاً کمی آهسته‌تر؛ چند ثانیه صبر کنید.", false).await });
                    }
                    continue;
                }
                tokio::spawn(async move {
                    if u["callback_query"].is_object() {
                        me.on_callback(&u["callback_query"]).await;
                    } else if u["pre_checkout_query"].is_object() {
                        me.on_pre_checkout(&u["pre_checkout_query"]).await;
                    } else if u["message"]["successful_payment"].is_object() {
                        me.on_stars_paid(&u["message"]).await;
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
             ON CONFLICT(tg_id) DO UPDATE SET name=excluded.name, lname=excluded.lname, uname=excluded.uname, blocked=0",
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
                self.pend.lock().unwrap_or_else(|e| e.into_inner()).insert(uid, Pending { kind: "new".into(), ..Default::default() });
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
            self.waits.lock().unwrap_or_else(|e| e.into_inner()).remove(&uid);
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
            self.set_menu(uid).await;
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
        let wait = self.waits.lock().unwrap_or_else(|e| e.into_inner()).remove(&uid);
        let Some(w) = wait else {
            self.send(chat, &self.tx("txt_menu"), Some(self.home_kb(uid))).await;
            return;
        };
        match w {
            Wait::Receipt(method) => self.got_receipt(uid, chat, &name, &method, m).await,
            Wait::TonTx(oid) => {
                let again = |me: &Self| me.waits.lock().unwrap_or_else(|e| e.into_inner()).insert(uid, Wait::TonTx(oid));
                let kb = Some(ik(vec![vec![b("🔍 بررسی پرداخت", &format!("tchk:{}", oid))], vec![b(&self.bt("home"), "home")]]));
                let Some(h) = crate::pay::hash_in(&text) else {
                    again(self);
                    self.send(chat, "🔗 لینک تراکنش (از Tonviewer یا Tonscan یا تاریخچه‌ی Tonkeeper) یا هش تراکنش رو بفرستید. پرداخت با کامنت درست خودکار تأیید می‌شه.", kb).await;
                    return;
                };
                match self.ton_check(oid, Some(&h)).await {
                    Ok(true) => {}
                    Ok(false) => {
                        if self.ton_order(oid).is_some() {
                            again(self);
                            self.send(chat, "⏳ هنوز روی شبکه پیدا نشد؛ چند ثانیه بعد «بررسی پرداخت» رو بزنید.", kb).await;
                        }
                    }
                    Err(e) => {
                        if self.ton_order(oid).is_some() { again(self); }
                        self.send(chat, &format!("⚠️ {}", e), kb).await;
                    }
                }
            }
            Wait::CfgName(next) => match self.check_name(&text, 0) {
                Ok(n) => {
                    let _ = self.db().exec("UPDATE bot_users SET cfg_name=?1 WHERE tg_id=?2", &[&n, &uid]);
                    self.send(chat, &format!("✅ نام کانفیگ شما: <b>{}</b>", esc(&n)), None).await;
                    self.after_name(uid, chat, &next).await;
                }
                Err(e) => {
                    self.waits.lock().unwrap_or_else(|e| e.into_inner()).insert(uid, Wait::CfgName(next));
                    self.send(chat, &e, Some(ik(vec![vec![b(&self.bt("back"), "home")]]))).await;
                }
            },
            Wait::Rename(id) => {
                let Some(u) = self.db().user(id).filter(|_| self.admin(uid)) else { return };
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
                        self.waits.lock().unwrap_or_else(|e| e.into_inner()).insert(uid, Wait::Rename(id));
                        self.send(chat, &e, Some(ik(vec![vec![b(&self.bt("back"), &format!("acc:{}", id))]]))).await;
                    }
                }
            }
            Wait::DiscountUse => {
                let code = text.to_uppercase();
                // 5 tries an hour: a code cannot be found by guessing
                if !self.admin(uid) && !crate::limit::hit("disc", &uid.to_string(), 5, 3600) {
                    self.send(chat, "⏳ چند بار کد اشتباه زده شد؛ یک ساعت بعد دوباره امتحان کنید.", Some(self.home_kb(uid))).await;
                    return;
                }
                match self.discount_percent(&code) {
                    Some(p) => {
                        let plan_id = {
                            let mut g = self.pend.lock().unwrap_or_else(|e| e.into_inner());
                            let pe = g.entry(uid).or_default();
                            pe.discount = code.clone();
                            pe.percent = p;
                            pe.at = now();
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

    /// The percent of a discount code that can be used now (it exists, has uses left and is not expired)
    fn discount_percent(&self, code: &str) -> Option<i64> {
        self.db().with(|c| c.query_row(
            "SELECT percent FROM discounts WHERE code=?1 AND uses_left>0 AND (COALESCE(expires,0)=0 OR expires>?2)",
            rusqlite::params![code, now()], |r| r.get(0)).ok())
    }

    /// Is the discount of this purchase still good (the same code with the same percent)? When it is not, it is
    /// taken off the purchase, so the price is shown again without it.
    fn discount_still_ok(&self, uid: i64, pe: &Pending) -> bool {
        if pe.discount.is_empty() || self.discount_percent(&pe.discount) == Some(pe.percent) {
            return true;
        }
        if let Some(x) = self.pend.lock().unwrap_or_else(|e| e.into_inner()).get_mut(&uid) {
            x.discount.clear();
            x.percent = 0;
        }
        false
    }

    /// The discount was used up, deleted or expired since it was typed: the plan again, at its price now
    async fn discount_gone(&self, uid: i64, chat: i64, pe: &Pending) {
        self.send(chat, &format!("⚠️ کد تخفیف {} دیگر معتبر نیست؛ قیمت بدون آن حساب شد.", esc(&pe.discount)), None).await;
        self.show_plan(chat, None, uid, pe.plan).await;
    }

    async fn ask_join(&self, chat: i64) {
        let ch = self.db().get("channel");
        let link = format!("url:https://t.me/{}", ch.trim_start_matches('@'));
        self.send(chat, &format!("📢 برای استفاده از ربات، اول عضو کانال {} شوید.", esc(&ch)),
            Some(ik(vec![vec![b("📢 عضویت در کانال", &link)], vec![b("✅ عضو شدم", "home")]]))).await;
    }

    async fn got_receipt(&self, uid: i64, chat: i64, name: &str, method: &str, m: &Value) {
        let pe = self.pend.lock().unwrap_or_else(|e| e.into_inner()).get(&uid).cloned();
        let Some(pe) = pe else { return };
        // at most 3 receipts an hour from one customer (the admins are not flooded with made-up ones)
        if !self.admin(uid) && !crate::limit::hit("receipt", &uid.to_string(), 3, 3600) {
            self.send(chat, "⏳ رسیدهای شما در صف بررسی‌اند؛ برای رسید بیشتر یک ساعت بعد بفرستید یا به پشتیبانی پیام بدید.", None).await;
            return;
        }
        let Some(p) = self.plan_on_sale(pe.plan) else { return };
        let photo = m["photo"].as_array().and_then(|a| a.last()).and_then(|x| x["file_id"].as_str()).map(|s| s.to_string());
        let reference = photo.clone().unwrap_or_else(|| m["text"].as_str().unwrap_or("").to_string());
        // the customer has paid by now: the order is kept, and the admin sees when its code is no longer good
        let code_ok = pe.discount.is_empty() || self.discount_percent(&pe.discount) == Some(pe.percent);
        let (t, u) = self.price(&p, &pe);
        let amount = if method == "card" { t.to_string() } else { u.to_string() };
        let oid = self.new_order(uid, &p, &pe, method, &amount, "pending", &reference);
        self.send(chat, &format!("✅ رسید سفارش #{} ثبت شد؛ بعد از تأیید، اشتراک خودکار فعال می‌شود.", oid), Some(self.home_kb(uid))).await;
        let cap = format!(
            "🧾 <b>سفارش جدید #{}</b>\n👤 {} · <code>{}</code>\n📦 {} ({})\n💳 {} · {}{}",
            oid, esc(name), uid, esc(&p.name), if pe.kind == "renew" { "تمدید" } else { "جدید" }, method, amount,
            if pe.discount.is_empty() { String::new() } else {
                format!("\n🎟 {} ({}٪){}", esc(&pe.discount), pe.percent, if code_ok { "" } else { "\n⚠️ این کد تخفیف دیگر معتبر نیست (تمام، حذف یا منقضی شده)" })
            }
        );
        let kb = ik(vec![vec![b("✅ تأیید", &format!("ap:{}", oid)), b("❌ رد", &format!("rj:{}", oid))]]);
        if photo.is_some() {
            self.notify_order(oid, &cap, kb, photo).await;
        } else {
            self.notify_order(oid, &format!("{}\n\nTXID: <code>{}</code>", cap, esc(&reference)), kb, None).await;
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn new_order(&self, uid: i64, p: &Plan, pe: &Pending, method: &str, amount: &str, status: &str, reference: &str) -> i64 {
        let kind = if pe.kind.is_empty() { "new".to_string() } else { pe.kind.clone() };
        // the code belongs to this order now: an old button of the same purchase cannot use it again
        if !pe.discount.is_empty() {
            if let Some(x) = self.pend.lock().unwrap_or_else(|e| e.into_inner()).get_mut(&uid) {
                x.discount.clear();
                x.percent = 0;
            }
        }
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
        let qid = q["id"].as_str().unwrap_or("").to_string();
        self.on_callback_inner(q).await;
        // every tap gets exactly one answer (so the button stops loading): the handler's alert, or an empty one
        let done = self.answered.lock().unwrap_or_else(|e| e.into_inner()).remove(&qid);
        if !done {
            self.call("answerCallbackQuery", json!({"callback_query_id": qid, "text": "", "show_alert": false})).await;
        }
    }

    /// Sales are closed (the "sales" switch is off) for this customer; admins can still buy
    fn sales_closed(&self, uid: i64) -> bool {
        !self.db().on("sales_on") && !self.admin(uid)
    }

    async fn on_callback_inner(&self, q: &Value) {
        let uid = q["from"]["id"].as_i64().unwrap_or(0);
        let chat = q["message"]["chat"]["id"].as_i64().unwrap_or(uid);
        let qid = q["id"].as_str().unwrap_or("").to_string();
        let d = q["data"].as_str().unwrap_or("").to_string();
        // a menu button under a message that delivered something (a config, a file, a subscription link) opens the
        // menu as a new message: editing would wipe what the customer got. Other menus are edited in place.
        let nav = d == "home" || MAIN_BTNS.contains(&d.as_str()) || d.starts_with("acc:");
        let mid = if nav && keeps(&q["message"]) { 0 } else { q["message"]["message_id"].as_i64().unwrap_or(0) };
        self.touch(uid, &q["from"], 0);
        let back_lbl = self.bt("back");
        let back = |to: &str| vec![b(&back_lbl, to)];

        if !self.joined(uid).await {
            return self.ask_join(chat).await;
        }

        match d.as_str() {
            "home" => {
                self.waits.lock().unwrap_or_else(|e| e.into_inner()).remove(&uid);
                return self.edit(chat, mid, &self.tx("welcome"), Some(self.home_kb(uid))).await;
            }
            "buy" => {
                if self.sales_closed(uid) {
                    return self.edit(chat, mid, SALES_CLOSED, Some(ik(vec![back("home")]))).await;
                }
                if self.needs_name(uid) {
                    let (t, kb) = self.name_ask(uid, "buy");
                    return self.edit(chat, mid, &t, Some(kb)).await;
                }
                self.pend.lock().unwrap_or_else(|e| e.into_inner()).insert(uid, Pending { kind: "new".into(), ..Default::default() });
                return self.plans_menu(chat, mid, "pl").await;
            }
            // «use my Telegram name»: the name made from it, then on with the purchase or the trial
            "cfgsk:buy" | "cfgsk:trial" => {
                let Some(h) = self.name_hint(uid) else { return };
                let _ = self.db().exec("UPDATE bot_users SET cfg_name=?1 WHERE tg_id=?2", &[&h, &uid]);
                self.waits.lock().unwrap_or_else(|e| e.into_inner()).remove(&uid);
                self.edit(chat, mid, &format!("✅ نام کانفیگ شما: <b>{}</b>", esc(&h)), None).await;
                return self.after_name(uid, chat, if d.ends_with("trial") { "trial" } else { "buy" }).await;
            }
            "trial" => {
                if self.db().on("trial_on") && !self.trial_taken(uid) && self.needs_name(uid) {
                    let (t, kb) = self.name_ask(uid, "trial");
                    return self.edit(chat, mid, &t, Some(kb)).await;
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
                let me = self.my_username().await;
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
                self.waits.lock().unwrap_or_else(|e| e.into_inner()).insert(uid, Wait::DiscountUse);
                return self.edit(chat, mid, "🎟 کد تخفیف را بفرستید:", Some(ik(vec![back("home")]))).await;
            }
            _ => {}
        }

        let (head, rest) = d.split_once(':').unwrap_or((d.as_str(), ""));
        // a button of an older message (a plan, a renewal, a payment method) must not sell while sales are closed
        if matches!(head, "pcat" | "psv" | "pl" | "rpl" | "pay" | "npc" | "rnw") && self.sales_closed(uid) {
            return self.edit(chat, mid, SALES_CLOSED, Some(ik(vec![back("home")]))).await;
        }
        match head {
            "apk" => return self.send_apk(chat, rest).await,
            // the connection guide: hw:<account> (devices), hw:<account>:<device> (apps), hw:<account>:<device>:<app>
            "hw" => {
                let mut parts = rest.split(':');
                let id: i64 = parts.next().and_then(|x| x.parse().ok()).unwrap_or(0);
                let Some(u) = self.app.db.user(id).filter(|u| u.tg_id == uid || self.admin(uid)) else { return };
                let os = parts.next().filter(|o| ["a", "i", "w"].contains(o));
                match (os, parts.next()) {
                    (None, _) => {
                        self.send(chat, "📲 <b>روی کدوم دستگاه وصل می‌شید؟</b>", Some(ik(vec![self.how_devices_kb(u.id)]))).await;
                    }
                    (Some(os), None) => {
                        let (t, rows) = self.how_device(&u, os);
                        self.send(chat, &t, Some(ik(rows))).await;
                    }
                    (Some(os), Some(app)) => self.how_app(chat, &qid, &u, os, app).await,
                }
                return;
            }
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
            // the AmneziaVPN backup: first the platform, then the file
            "amz" | "amp" => {
                let mut parts = rest.split(':');
                let id: i64 = parts.next().and_then(|x| x.parse().ok()).unwrap_or(0);
                let Some(u) = self.app.db.user(id).filter(|u| u.tg_id == uid || self.admin(uid)) else { return };
                if head == "amz" {
                    let row = crate::amnezia::PLATFORMS.iter().map(|p| b(p.2, &format!("amp:{}:{}", u.id, p.0))).collect();
                    self.send(chat, "📦 <b>بکاپ Amnezia</b>\n\nهمه‌ی سرورهای WireGuard، AmneziaWG و VLESS (Xray) شما توی یک فایل، برای برنامه‌ی <b>AmneziaVPN</b>.\n\nگوشی یا کامپیوترتون کدومه؟", Some(ik(vec![row]))).await;
                } else {
                    self.send_amnezia(chat, &qid, &u, parts.next().unwrap_or("")).await;
                }
                return;
            }
            "pcat" | "psv" => {
                // pcat:<mode>:<category>[:<service>], psv:<mode>[:<service>] (no service = the service menu)
                let mut parts = rest.split(':');
                let mode = parts.next().filter(|m| !m.is_empty()).unwrap_or("b");
                let sel = if head == "pcat" { parts.next().unwrap_or("m") } else { "m" };
                let svc = service_of_code(parts.next().unwrap_or(""));
                let pattern = if mode == "b" { "pl".to_string() } else { format!("rpl:{{}}:{}", mode.get(1..).unwrap_or("0")) };
                return self.plans_menu_sel(chat, mid, &pattern, sel, svc).await;
            }
            "pl" | "rpl" => {
                let mut parts = rest.split(':');
                let pid: i64 = parts.next().and_then(|x| x.parse().ok()).unwrap_or(0);
                {
                    let mut g = self.pend.lock().unwrap_or_else(|e| e.into_inner());
                    let pe = g.entry(uid).or_default();
                    pe.plan = pid;
                    pe.at = now();
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
                self.show_plan(chat, Some(mid), uid, pid).await;
                return;
            }
            "pay" => return self.pay(uid, chat, mid, rest).await,
            "npc" => return self.np_start(uid, chat, mid, rest).await,
            "tchk" => {
                let oid: i64 = rest.parse().unwrap_or(0);
                let Some(o) = self.order(oid) else { return };
                if o.1 != uid { return; }
                if o.6 == "done" || o.6 == "paid" {
                    return self.answer(&qid, "این سفارش قبلاً پرداخت و فعال شده ✅", true).await;
                }
                return match self.ton_check(oid, None).await {
                    Ok(true) => {}
                    Ok(false) => self.answer(&qid, "⏳ هنوز پرداختی با کامنت این سفارش روی شبکه نیست. اگه پرداخت کردید چند ثانیه صبر کنید؛ خودکار تأیید می‌شه.", true).await,
                    Err(e) => self.answer(&qid, &e, true).await,
                };
            }
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
            // renaming is the admin's (an old «rename» button in a customer's chat does nothing)
            "ren" => {
                let id: i64 = rest.parse().unwrap_or(0);
                if !self.admin(uid) {
                    return self.answer(&qid, "تغییر نام فقط از طریق پشتیبانی انجام می‌شود.", true).await;
                }
                if let Some(u) = self.app.db.user(id) {
                    self.waits.lock().unwrap_or_else(|e| e.into_inner()).insert(uid, Wait::Rename(id));
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
                self.pend.lock().unwrap_or_else(|e| e.into_inner()).insert(uid, Pending { kind: "renew".into(), target: id, ..Default::default() });
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
        self.plans_menu_sel(chat, mid, pattern, "m", "").await
    }

    /// sel: "m" = category menu (or the flat list when there are no categories), "o" = plans without a category, "<n>" = n-th category.
    /// svc: the service chosen first ("v2ray" / "vip"); "" = not chosen yet. When plans of both services are on
    /// sale the customer picks the service first and sees only its plans.
    async fn plans_menu_sel(&self, chat: i64, mid: i64, pattern: &str, sel: &str, svc: &str) {
        let mut list: Vec<Plan> = self.plans(true).into_iter().map(|x| x.0).collect();
        let mode = if pattern == "pl" { "b".to_string() } else { format!("r{}", pattern.rsplit(':').next().unwrap_or("0")) };
        let on_sale: Vec<&(&str, &str, &str, &str)> = SERVICES.iter().filter(|s| list.iter().any(|p| p.service == s.0)).collect();
        let choose = on_sale.len() > 1;
        if choose && svc.is_empty() {
            let mut rows: Kb = on_sale.iter().map(|s| vec![b(s.2, &format!("psv:{}:{}", mode, s.1))]).collect();
            rows.push(vec![b(&self.bt("back"), "home")]);
            let txt = format!("🛍 <b>نوع سرویس رو انتخاب کنید</b>\n\n{}", on_sale.iter().map(|s| s.3).collect::<Vec<_>>().join("\n\n"));
            return self.edit(chat, mid, &txt, Some(ik(rows))).await;
        }
        let code = if choose { service_code(svc) } else { "" };
        if !code.is_empty() {
            list.retain(|p| p.service == svc);
        }
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
        let head = SERVICES.iter().find(|s| s.0 == svc && !code.is_empty()).map(|s| format!("{}\n\n", s.2)).unwrap_or_default();
        let mut title = format!("{}{}", head, self.tx("txt_plans"));
        let back_lbl = self.bt("back");
        // back from the plans: to the service menu when there is one
        let top = if code.is_empty() { "home".to_string() } else { format!("psv:{}", mode) };
        let mut back_to = top.clone();
        if !cats.is_empty() {
            if sel == "m" {
                // each kind with its emoji, its colour and its cheapest price; the message says what each is for
                let mut rows: Kb = vec![];
                let mut about = vec![];
                for (i, c) in cats.iter().enumerate() {
                    let (em, st, line) = cat_look(&c.1, i);
                    let of: Vec<&Plan> = list.iter().filter(|p| p.category == c.1).collect();
                    let from = of.iter().map(|p| p.toman).filter(|t| *t > 0).min().unwrap_or(0);
                    let off = of.iter().any(|p| p.old_toman > p.toman);
                    let lbl = format!("{} {}{}{}", em, c.1, if from > 0 { format!(" — از {}", toman(from)) } else { String::new() }, if off { " 🏷" } else { "" });
                    rows.push(vec![b(&lbl, &format!("@{}@pcat:{}:{}:{}", st, mode, i, code))]);
                    if !line.is_empty() {
                        about.push(format!("{} <b>{}</b>: {}", em, esc(&c.1), line));
                    }
                }
                if has_other { rows.push(vec![b(&self.bt("other_plans"), &format!("pcat:{}:o:{}", mode, code))]); }
                rows.push(vec![b(&back_lbl, &top)]);
                let about = if about.is_empty() { String::new() } else { format!("\n\n{}", about.join("\n")) };
                return self.edit(chat, mid, &format!("{}{}{}", head, self.tx("txt_cats"), about), Some(ik(rows))).await;
            }
            let want: String = if sel == "o" {
                String::new()
            } else {
                sel.parse::<usize>().ok().and_then(|i| cats.get(i)).map(|c| c.1.clone()).unwrap_or_default()
            };
            title = if want.is_empty() { "📦 <b>سایر پلن‌ها</b>\nپلن خودتون رو از پایین انتخاب کنید 👇".to_string() } else {
                let i = cats.iter().position(|c| c.1 == want).unwrap_or(0);
                let (em, _, line) = cat_look(&want, i);
                format!("{} <b>{}</b>{}\n\nپلن خودتون رو از پایین انتخاب کنید 👇", em, esc(&want), if line.is_empty() { String::new() } else { format!("\n{}", line) })
            };
            list.retain(|p| p.category == want);
            back_to = format!("pcat:{}:m:{}", mode, code);
        }
        // ordered by duration, then number of users, then price; the text groups them by duration
        list.sort_by_key(|x| (x.days, x.conns, x.toman));
        let mut rows: Kb = vec![];
        for p in list.iter() {
            let data = if pattern.contains("{}") { pattern.replace("{}", &p.id.to_string()) } else { format!("{}:{}", pattern, p.id) };
            rows.push(vec![b(&plan_button(p, p.toman), &data)]);
        }
        // any volume and days, chosen in the mini app (same price rules as the plans)
        let renew: i64 = if pattern == "pl" { 0 } else { pattern.rsplit(':').next().and_then(|x| x.parse().ok()).unwrap_or(0) };
        // the custom purchase makes a full (vip) account
        if let Some(r) = self.shop_row(renew).filter(|_| svc != "v2ray") {
            rows.push(r);
            title.push_str("\n\n🧮 حجم و روز دلخواه: قیمت همون‌جا حساب می‌شه.");
        }
        if rows.is_empty() {
            return self.edit(chat, mid, "هنوز پلنی تعریف نشده است.", Some(ik(vec![vec![b(&back_lbl, &back_to)]]))).await;
        }
        rows.push(vec![b(&back_lbl, &back_to)]);
        self.edit(chat, mid, &title, Some(ik(rows))).await;
    }

    /// The plan with its payment methods; true when the customer got it
    async fn show_plan(&self, chat: i64, mid: Option<i64>, uid: i64, pid: i64) -> bool {
        let Some(p) = self.plan_on_sale(pid) else { return false };
        let pe = self.pend.lock().unwrap_or_else(|e| e.into_inner()).get(&uid).cloned().unwrap_or_default();
        let (t, u) = self.price(&p, &pe);
        let mut rows: Kb = vec![];
        for (m, k) in [("card", "pay_card"), ("zp", "pay_zp"), ("ton", "pay_ton"), ("stars", "pay_stars"), ("np", "pay_np"), ("wallet", "pay_wallet")] {
            if self.method_ok(m, t, u) {
                rows.push(vec![b(&self.bt(k), &format!("pay:{}", m))]);
            }
        }
        if pe.discount.is_empty() { rows.push(vec![b(&self.bt("disc"), "disc")]); }
        rows.push(vec![b(&self.bt("back"), "home")]);
        // the same price in TON and in Stars, at today's rate (when those are offered)
        let (ton_on, stars_on) = (self.method_ok("ton", t, u), self.method_ok("stars", t, u));
        let mut crypto = String::new();
        if ton_on || stars_on {
            if let Some(r) = crate::pay::rates(&self.app).await {
                let mut x = vec![];
                if ton_on { x.push(format!("💎 {} TON", crate::pay::ton_text(crate::pay::ton_nano(t, &r)))); }
                if stars_on { x.push(format!("⭐️ {} استارز", crate::pay::stars_for(t, &r, crate::pay::star_usd(self.db())))); }
                crypto = format!("\n≈ {}", x.join("  ·  "));
            }
        }
        let txt = format!(
            "📦 <b>{}</b>\n{}\nحجم: {} · مدت: {} روز · {} کاربر{}\nقیمت: <b>{}</b>{}{}{}\n\nروش پرداخت را انتخاب کنید:",
            esc(&p.name), if p.service == "v2ray" { "🌐 سرویس استاندارد (V2Ray): لینک اشتراک برای v2rayNG، Streisand، V2Box" } else { "🚀 سرویس VIP: اپ کانکی، AmneziaWG، WireGuard و همه‌ی سرورها" }, if p.gb > 0.0 { format!("{} GB", p.gb) } else { "نامحدود".into() }, p.days, p.conns,
            if p.countries > 0 { format!(" · {} کشور", p.countries) } else { String::new() },
            if p.old_toman > t && pe.percent == 0 { format!("<s>{}</s>  {}", toman(p.old_toman), toman(t)) } else { toman(t) },
            if u > 0.0 { format!("  ·  <b>{}$</b>", u) } else { String::new() },
            crypto,
            if pe.percent > 0 { format!("\n🎟 تخفیف {}٪ اعمال شده", pe.percent) } else { String::new() }
        );
        match mid {
            Some(m) => self.edit_ok(chat, m, &txt, Some(ik(rows))).await,
            None => self.send(chat, &txt, Some(ik(rows))).await.is_some(),
        }
    }

    async fn pay(&self, uid: i64, chat: i64, mid: i64, method: &str) {
        let pe = self.pend.lock().unwrap_or_else(|e| e.into_inner()).get(&uid).cloned();
        let Some(pe) = pe else { return };
        let Some(p) = self.plan_on_sale(pe.plan) else { return };
        if !self.discount_still_ok(uid, &pe) {
            return self.discount_gone(uid, chat, &pe).await;
        }
        let (t, u) = self.price(&p, &pe);
        let db = self.db();
        let home = Some(ik(vec![vec![b("⬅️ بازگشت", "home")]]));
        // an old button (the method was switched off or the plan has no price for it since)
        if !self.method_ok(method, t, u) {
            return self.edit(chat, mid, "⚠️ این روش پرداخت الان فعال نیست؛ روش دیگری انتخاب کنید.", home).await;
        }
        match method {
            "card" => {
                self.waits.lock().unwrap_or_else(|e| e.into_inner()).insert(uid, Wait::Receipt("card".into()));
                self.edit(chat, mid, &format!(
                    "💳 <b>کارت به کارت</b>\n\nمبلغ: <b>{}</b>\nشماره کارت:\n<code>{}</code>\nبه نام: {}\n\n📸 بعد از واریز، <b>عکس رسید</b> را همین‌جا بفرستید.",
                    toman(t), esc(&db.get("card_number")), esc(&db.get("card_holder"))), home).await;
            }
            "wallet" => {
                self.waits.lock().unwrap_or_else(|e| e.into_inner()).insert(uid, Wait::Receipt("wallet".into()));
                // with automatic TON on, TON is paid there (checked on the chain), not by a receipt here
                let ton = if db.on("ton_on") { String::new() } else { db.get("ton_address").trim().to_string() };
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
            "ton" => self.ton_start(uid, chat, mid, &p, &pe, t).await,
            "stars" => self.stars_start(uid, chat, mid, &p, &pe, t).await,
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
        let pe = self.pend.lock().unwrap_or_else(|e| e.into_inner()).get(&uid).cloned();
        let Some(pe) = pe else { return };
        let Some(p) = self.plan_on_sale(pe.plan) else { return };
        if !self.discount_still_ok(uid, &pe) {
            return self.discount_gone(uid, chat, &pe).await;
        }
        let (t, usd) = self.price(&p, &pe);
        let home = Some(ik(vec![vec![b("⬅️ بازگشت", "home")]]));
        // an old button: the method switched off since, or a coin that is not offered (any text can come in a button)
        if !self.method_ok("np", t, usd) {
            return self.edit(chat, mid, "⚠️ این روش پرداخت الان فعال نیست؛ روش دیگری انتخاب کنید.", home).await;
        }
        if !self.db().get("np_coins").split(',').any(|c| !c.trim().is_empty() && c.trim() == coin) {
            return self.edit(chat, mid, "⚠️ این ارز الان برای پرداخت فعال نیست؛ ارز دیگری انتخاب کنید.", home).await;
        }
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
            v["pay_amount"], esc(&coin.to_uppercase()), esc(v["pay_address"].as_str().unwrap_or(""))),
            Some(ik(vec![vec![b("🔍 بررسی پرداخت", &format!("chk:{}", oid))]]))).await;
    }

    // ============================================================ TON and Stars (checked, never by hand)

    /// Today's rate in one line, for the buyer: why the amount is what it is
    fn rate_line(r: &crate::pay::Rates) -> String {
        // Tehran time (UTC+3:30, no daylight saving since 2022)
        let hm = chrono::DateTime::from_timestamp(r.at + 12600, 0).map(|d| d.format("%H:%M").to_string()).unwrap_or_default();
        format!("📊 قیمت لحظه‌ای: هر TON = <b>{} تومان</b> (TON {}$ × دلار {} تومان)\n🕒 به‌روز: ساعت {} · منبع: {}",
            crate::pay::group(r.ton_toman()), (r.ton_usd * 1000.0).round() / 1000.0, crate::pay::group(r.usd_toman), hm, esc(&r.src))
    }

    /// An order paid in TON: a fixed amount at today's price and a comment of its own, so its payment is found
    /// on the chain without a receipt; the bot then checks every 20 seconds (and when the customer asks)
    async fn ton_start(&self, uid: i64, chat: i64, mid: i64, p: &Plan, pe: &Pending, t: i64) {
        let home = Some(ik(vec![vec![b(&self.bt("back"), "home")]]));
        let Some(r) = crate::pay::rates(&self.app).await else {
            return self.edit(chat, mid, "⚠️ قیمت لحظه‌ای TON الان در دسترس نیست؛ چند دقیقه بعد دوباره امتحان کنید یا روش دیگری انتخاب کنید.", home).await;
        };
        let addr = self.db().get("ton_address").trim().to_string();
        let nano = crate::pay::ton_nano(t, &r);
        let oid = self.new_order(uid, p, pe, "ton", &t.to_string(), "waiting", "");
        let memo = format!("KANKI-{}-{}", oid, crate::util::rand_digits(4));
        let _ = self.db().exec("UPDATE orders SET ref=?1 WHERE id=?2", &[&format!("{} {}", memo, nano), &oid]);
        self.waits.lock().unwrap_or_else(|e| e.into_inner()).insert(uid, Wait::TonTx(oid));
        let ton = crate::pay::ton_text(nano);
        let txt = format!(
            "💎 <b>پرداخت با TON</b> · سفارش #{}\n\n💰 مبلغ: <b>{} TON</b>  (= {})\n{}\n\n👛 آدرس کیف پول:\n<code>{}</code>\n\n📝 کامنت (Comment) — <b>حتماً بنویسید</b>:\n<code>{}</code>\n\n\
             ✅ با دکمه‌ی Tonkeeper مبلغ و کامنت خودشون پر می‌شن.\n🤖 بعد از پرداخت تأیید <b>خودکار</b> است (معمولاً زیر یک دقیقه). می‌تونید «بررسی پرداخت» رو بزنید یا لینک تراکنش (Tonviewer / Tonscan) رو همین‌جا بفرستید.\n⏱ این قیمت تا ۲ ساعت معتبره.",
            oid, ton, toman(t), Self::rate_line(&r), esc(&addr), memo);
        let link = format!("url:https://app.tonkeeper.com/transfer/{}?amount={}&text={}", addr, nano, memo);
        self.edit(chat, mid, &txt, Some(ik(vec![
            vec![b("💎 پرداخت با Tonkeeper", &link)],
            vec![b("🔍 بررسی پرداخت", &format!("tchk:{}", oid))],
            vec![b(&self.bt("back"), "home")],
        ]))).await;
    }

    /// A transaction hash already used for an order (one payment pays one order)
    fn tx_used(&self, hash: &str) -> bool {
        // the hash is the last word of a paid order's ref (instr: no LIKE wildcards in a payment id)
        let word = format!(" {}", hash);
        self.db().with(|c| c.query_row("SELECT COUNT(*) FROM orders WHERE method IN ('ton','stars') AND instr(ref || ' ', ?1 || ' ')>0", [word], |r| r.get::<_, i64>(0)).unwrap_or(0)) > 0
    }

    /// (memo, nanoTON, created) of a TON order that is still waiting for its payment
    fn ton_order(&self, oid: i64) -> Option<(i64, String, u128, i64)> {
        let (tg, method, status, rf, created): (i64, String, String, String, i64) = self.db().with(|c| c.query_row(
            "SELECT tg_id,method,status,ref,COALESCE(created,0) FROM orders WHERE id=?1", [oid],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))).ok())?;
        if method != "ton" || status != "waiting" {
            return None;
        }
        let mut w = rf.split_whitespace();
        let memo = w.next()?.to_string();
        let nano: u128 = w.next()?.parse().ok()?;
        Some((tg, memo, nano, created))
    }

    /// Settles a TON order with a payment found on the chain: delivered when it is its own (its comment), not
    /// used before, at least the amount and within the 2 hours of its price; a late or short payment goes to the
    /// admins to decide. Ok(true) = delivered.
    async fn ton_settle(&self, oid: i64, tx: &crate::pay::TonIn, by_comment: bool) -> Result<bool, String> {
        let Some((tg, memo, need, created)) = self.ton_order(oid) else { return Err("این سفارش دیگر منتظر پرداخت نیست.".into()) };
        if self.tx_used(&tx.hash) {
            return Err("این تراکنش قبلاً برای یک سفارش استفاده شده.".into());
        }
        let late = tx.at > created + 7200;
        let short = tx.nano < need;
        let early = tx.at < created - 120;
        if by_comment && !late && !short && !early {
            // one call only gets past this (the watcher and the button can find it at the same moment)
            let claimed = self.db().exec("UPDATE orders SET status='paid', ref=?1 WHERE id=?2 AND status='waiting'",
                &[&format!("{} {} {}", memo, need, tx.hash), &oid]).unwrap_or(0);
            if claimed != 1 {
                return Ok(false);
            }
            self.waits.lock().unwrap_or_else(|e| e.into_inner()).remove(&tg);
            self.send(tg, &format!("✅ پرداخت <b>{} TON</b> سفارش #{} روی شبکه‌ی TON تأیید شد؛ در حال ساخت اشتراک…", crate::pay::ton_text(tx.nano as u64), oid), None).await;
            self.fulfill(oid).await;
            return Ok(true);
        }
        if early {
            return Err("این تراکنش قبل از ثبت این سفارش انجام شده.".into());
        }
        // a real payment into the wallet that does not fit this order by itself: the admins decide
        let why = if !by_comment { "بدون کامنت سفارش" } else if short { "کمتر از مبلغ سفارش" } else { "بعد از ۲ ساعت (قیمت قدیمی)" };
        let claimed = self.db().exec("UPDATE orders SET status='pending', ref=?1 WHERE id=?2 AND status='waiting'",
            &[&format!("{} {} {}", memo, need, tx.hash), &oid]).unwrap_or(0);
        if claimed != 1 {
            return Ok(false);
        }
        self.waits.lock().unwrap_or_else(|e| e.into_inner()).remove(&tg);
        let hash_hex = crate::tunnel::link::b64decode(&tx.hash).map(hex::encode).unwrap_or_else(|| tx.hash.clone());
        let cap = format!("🧾 <b>سفارش #{} · TON</b> ({})\n👤 <code>{}</code>\n💎 رسیده: <b>{} TON</b> · لازم: {} TON\n📝 کامنت: <code>{}</code> (باید: <code>{}</code>)\n🔗 https://tonviewer.com/transaction/{}",
            oid, why, tg, crate::pay::ton_text(tx.nano as u64), crate::pay::ton_text(need as u64), esc(&tx.comment), memo, hash_hex);
        self.notify_order(oid, &cap, ik(vec![vec![b("✅ تأیید", &format!("ap:{}", oid)), b("❌ رد", &format!("rj:{}", oid))]]), None).await;
        self.send(tg, &format!("👀 پرداخت شما برای سفارش #{} روی شبکه دیده شد ({}). پشتیبانی بررسی و تأیید می‌کند.", oid, why), None).await;
        Ok(false)
    }

    /// Looks for the payment of one TON order: by its comment among the wallet's last payments, then (when the
    /// customer sent one) by the transaction's hash. Ok(true) delivered, Ok(false) not found yet.
    async fn ton_check(&self, oid: i64, hash: Option<&str>) -> Result<bool, String> {
        let Some((_, memo, _, created)) = self.ton_order(oid) else { return Err("این سفارش دیگر منتظر پرداخت نیست.".into()) };
        let addr = self.db().get("ton_address");
        let list = crate::pay::recent(&self.app, &addr, created - 120).await.map_err(|_| "الان به شبکه‌ی TON دسترسی نیست؛ چند ثانیه بعد دوباره امتحان کنید.".to_string())?;
        if let Some(tx) = list.iter().find(|t| crate::pay::same_memo(&t.comment, &memo)) {
            return self.ton_settle(oid, tx, true).await;
        }
        let Some(h) = hash else { return Ok(false) };
        match crate::pay::by_hash(&self.app, &addr, h).await {
            Ok(Some(tx)) if crate::pay::same_memo(&tx.comment, &memo) => self.ton_settle(oid, &tx, true).await,
            // a payment with another order's comment belongs to that order
            Ok(Some(tx)) if !tx.comment.trim().is_empty() && tx.comment.to_uppercase().starts_with("KANKI-") => Err("این تراکنش با کامنت سفارش دیگری است.".into()),
            Ok(Some(tx)) => self.ton_settle(oid, &tx, false).await,
            Ok(None) => Err("این تراکنش به کیف پول ما پیدا نشد (یا هنوز روی شبکه نهایی نشده). چند ثانیه بعد دوباره بفرستید.".into()),
            Err(_) => Err("الان به شبکه‌ی TON دسترسی نیست؛ چند ثانیه بعد دوباره امتحان کنید.".into()),
        }
    }

    /// Every 20 seconds while a TON order waits (up to 3 hours): one read of the wallet settles them all
    async fn ton_watch(&self) {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(20)).await;
            let ids: Vec<(i64, i64)> = self.db().with(|c| {
                let mut s = c.prepare("SELECT id,created FROM orders WHERE method='ton' AND status='waiting' AND created>?1").unwrap();
                let v: Vec<(i64, i64)> = s.query_map([now() - 3 * 3600], |r| Ok((r.get(0)?, r.get(1)?))).unwrap().filter_map(|x| x.ok()).collect();
                v
            });
            let Some(since) = ids.iter().map(|x| x.1).min() else { continue };
            let Ok(list) = crate::pay::recent(&self.app, &self.db().get("ton_address"), since - 120).await else { continue };
            let ids: Vec<i64> = ids.into_iter().map(|x| x.0).collect();
            for oid in ids {
                let Some((_, memo, _, _)) = self.ton_order(oid) else { continue };
                if let Some(tx) = list.iter().find(|t| crate::pay::same_memo(&t.comment, &memo)) {
                    let _ = self.ton_settle(oid, tx, true).await;
                }
            }
        }
    }

    /// An order paid in Telegram Stars: Telegram's own invoice; the account is made only when Telegram reports
    /// the payment done (successful_payment), never when the button is tapped
    async fn stars_start(&self, uid: i64, chat: i64, mid: i64, p: &Plan, pe: &Pending, t: i64) {
        let home = Some(ik(vec![vec![b(&self.bt("back"), "home")]]));
        let Some(r) = crate::pay::rates(&self.app).await else {
            return self.edit(chat, mid, "⚠️ قیمت لحظه‌ای دلار الان در دسترس نیست؛ چند دقیقه بعد دوباره امتحان کنید یا روش دیگری انتخاب کنید.", home).await;
        };
        let su = crate::pay::star_usd(self.db());
        let n = crate::pay::stars_for(t, &r, su);
        let oid = self.new_order(uid, p, pe, "stars", &t.to_string(), "waiting", "");
        let nonce = crate::util::rand_token(10);
        let _ = self.db().exec("UPDATE orders SET ref=?1 WHERE id=?2", &[&format!("{} {}", nonce, n), &oid]);
        let hm = chrono::DateTime::from_timestamp(r.at + 12600, 0).map(|d| d.format("%H:%M").to_string()).unwrap_or_default();
        self.edit(chat, mid, &format!(
            "⭐️ <b>پرداخت با استارز تلگرام</b> · سفارش #{}\n\n💰 مبلغ: <b>{} استارز</b>  (= {})\n📊 هر استارز ≈ {} تومان ({}$ × دلار {} تومان، ساعت {})\n\n👇 روی دکمه‌ی «Pay ⭐️» پیام بعدی بزنید. بعد از پرداخت، اشتراک <b>خودکار</b> همین‌جا تحویل می‌شه.",
            oid, n, toman(t), crate::pay::group(su * r.usd_toman), su, crate::pay::group(r.usd_toman), hm), home).await;
        let title: String = format!("Kanki VPN · #{}", oid);
        let res = self.call_res("sendInvoice", json!({
            "chat_id": chat, "title": title, "description": format!("{} · {}", p.name, if p.service == "v2ray" { "V2Ray" } else { "VIP" }).chars().take(250).collect::<String>(),
            "payload": format!("kk:{}:{}", oid, nonce), "currency": "XTR", "prices": [{"label": p.name.chars().take(30).collect::<String>(), "amount": n}],
        })).await;
        if let Err(e) = res {
            let _ = self.db().exec("UPDATE orders SET status='error' WHERE id=?1 AND status='waiting'", &[&oid]);
            self.send(chat, &format!("⚠️ ساختن فاکتور استارز نشد: {}\nروش دیگری انتخاب کنید.", esc(&e)), None).await;
        }
    }

    /// The Stars order a payment is for: its payload, its customer, its currency and its exact amount, still waiting
    fn stars_order(&self, uid: i64, payload: &str, currency: &str, total: i64) -> Option<i64> {
        let mut it = payload.strip_prefix("kk:")?.splitn(2, ':');
        let oid: i64 = it.next()?.parse().ok()?;
        let nonce = it.next()?;
        let (tg, method, status, rf, created): (i64, String, String, String, i64) = self.db().with(|c| c.query_row(
            "SELECT tg_id,method,status,ref,COALESCE(created,0) FROM orders WHERE id=?1", [oid],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))).ok())?;
        let mut w = rf.split_whitespace();
        let ok = tg == uid && method == "stars" && status == "waiting" && currency == "XTR"
            && w.next() == Some(nonce) && w.next().and_then(|x| x.parse::<i64>().ok()) == Some(total)
            && now() - created < 86400;
        ok.then_some(oid)
    }

    /// Telegram asks before taking the Stars: yes only for a real, waiting order of this customer at its price
    async fn on_pre_checkout(&self, q: &Value) {
        let uid = q["from"]["id"].as_i64().unwrap_or(0);
        let ok = self.stars_order(uid, q["invoice_payload"].as_str().unwrap_or(""), q["currency"].as_str().unwrap_or(""), q["total_amount"].as_i64().unwrap_or(-1)).is_some();
        let mut body = json!({"pre_checkout_query_id": q["id"], "ok": ok});
        if !ok {
            body["error_message"] = json!("این فاکتور دیگر معتبر نیست؛ از ربات دوباره خرید کنید.");
        }
        let _ = self.call_res("answerPreCheckoutQuery", body).await;
    }

    /// The Stars were really paid (Telegram's own message): the order is delivered once; a payment that fits
    /// no waiting order is given back
    async fn on_stars_paid(&self, m: &Value) {
        let sp = &m["successful_payment"];
        let uid = m["from"]["id"].as_i64().unwrap_or(0);
        let charge = sp["telegram_payment_charge_id"].as_str().unwrap_or("").to_string();
        let total = sp["total_amount"].as_i64().unwrap_or(0);
        let currency = sp["currency"].as_str().unwrap_or("");
        if charge.is_empty() || currency != "XTR" || self.tx_used(&charge) {
            return;
        }
        match self.stars_order(uid, sp["invoice_payload"].as_str().unwrap_or(""), currency, total) {
            Some(oid) => {
                let rf: String = self.db().with(|c| c.query_row("SELECT ref FROM orders WHERE id=?1", [oid], |r| r.get(0)).unwrap_or_default());
                let claimed = self.db().exec("UPDATE orders SET status='paid', ref=?1 WHERE id=?2 AND status='waiting'", &[&format!("{} {}", rf, charge), &oid]).unwrap_or(0);
                if claimed == 1 {
                    self.send(uid, &format!("✅ پرداخت <b>{} استارز</b> سفارش #{} تأیید شد؛ در حال ساخت اشتراک…", total, oid), None).await;
                    self.fulfill(oid).await;
                }
            }
            None => {
                let back = self.call_res("refundStarPayment", json!({"user_id": uid, "telegram_payment_charge_id": charge})).await.is_ok();
                self.send(uid, if back { "↩️ این پرداخت به سفارش فعالی نمی‌خورد و استارزها برگردانده شد. لطفاً دوباره از ربات خرید کنید." } else { "⚠️ این پرداخت به سفارش فعالی نمی‌خورد؛ پشتیبانی بررسی می‌کند." }, None).await;
                self.notify_admins(&format!("⚠️ پرداخت {} استارز از <code>{}</code> به سفارش فعالی نخورد{}.\nشناسه: <code>{}</code>", total, uid, if back { " و برگردانده شد" } else { " و برگرداندن نشد" }, esc(&charge)), None, None).await;
            }
        }
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
        // the plan was deleted after the order was placed: the paid order stays (as an error, in the admin's
        // open orders) and both sides are told, instead of being closed with nothing delivered
        let Some(p) = self.plan(o.2) else {
            let marked = self.db().exec("UPDATE orders SET status='error' WHERE id=?1 AND status NOT IN ('done','error')", &[&oid]).unwrap_or(0);
            if marked == 1 {
                self.notify_admins(&format!("⚠️ سفارش #{} پرداخت شده ولی پلن آن (#{}) حذف شده و اشتراکی ساخته نشد.\nمشتری: <code>{}</code>\nلطفاً اشتراک را دستی بسازید یا تمدید کنید.", oid, o.2, o.1), None, None).await;
            }
            self.send(o.1, &format!("⚠️ پرداخت سفارش #{} ثبت شد ولی پلن آن دیگر وجود ندارد و اشتراک خودکار ساخته نشد.\nپشتیبانی آن را دستی پیگیری می‌کند؛ پرداخت شما محفوظ است.", oid), None).await;
            return;
        };
        // every update runs in its own task, so a double tap on "check payment" runs this twice at the
        // same time: only the call that really flips the status may deliver the service
        match self.db().exec("UPDATE orders SET status='done' WHERE id=?1 AND status<>'done'", &[&oid]) {
            Ok(1) => {}
            _ => return,
        }
        // a buyer who still has a free-trial account gets that same account (USER<n>-TEST -> USER<n>)
        let trial = self.db().users_of_tg(o.1).into_iter().find(|u| u.notes == "trial" || u.username.to_uppercase().ends_with("-TEST"));
        let res: Result<User, String> = if o.3 == "renew" && o.4 > 0 {
            self.db().renew_plan(o.4, p.days, p.gb).and_then(|_| {
                // a plan for more users raises the account to it (a renewal never lowers it)
                let _ = self.db().exec("UPDATE users SET max_conn=?1 WHERE id=?2 AND max_conn>0 AND max_conn<?1", &[&p.conns, &o.4]);
                self.db().promote_trial(o.4);
                self.set_service(o.4, &p.service);
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
                    self.set_service(t.id, &p.service);
                    self.db().user(t.id).ok_or("not found".into())
                })
        } else {
            self.create_account_svc(o.1, p.gb, p.days, p.conns, &format!("order #{}", oid), p.countries, &p.service)
        };
        match res {
            Ok(u) => {
                // a renewal whose account was gone (target 0) made a new account: it says so
                let head = if o.3 == "renew" && o.4 > 0 { self.tx("txt_renewed") } else { self.tx("txt_bought") };
                let (t, kb) = self.delivery(&head, &u, &p.name);
                self.send(o.1, &t, Some(kb)).await;
                // one use of the code for this paid order, taken only while the code is still good; the price was
                // already paid, so the order is delivered either way and the admin is told when it was not
                if !o.9.is_empty() {
                    let used = self.db().exec(
                        "UPDATE discounts SET uses_left=uses_left-1 WHERE code=?1 AND uses_left>0 AND (COALESCE(expires,0)=0 OR expires>?2)",
                        &[&o.9, &now()]).unwrap_or(0);
                    if used == 0 {
                        self.notify_admins(&format!("⚠️ سفارش #{} با کد تخفیف <code>{}</code> پرداخت و تحویل شد، ولی این کد موقع تحویل دیگر معتبر نبود (تمام، حذف یا منقضی شده).", oid, esc(&o.9)), None, None).await;
                    }
                }
                self.reward_referrer(o.1).await;
                self.set_menu(o.1).await;
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

    /// An account bought (or renewed) with a plan of the other service gets that service's protocols; an account
    /// already of the plan's service keeps its own list (an admin may have changed it)
    fn set_service(&self, id: i64, service: &str) {
        let Some(u) = self.db().user(id) else { return };
        if u.service() != service {
            let _ = self.db().exec("UPDATE users SET protocols=?1 WHERE id=?2", &[&self.db().service_protocols(service), &id]);
        }
    }

    async fn reward_referrer(&self, tg: i64) {
        let r: Option<(i64, i64)> = self.db().with(|c| c.query_row(
            "SELECT ref_by, ref_rewarded FROM bot_users WHERE tg_id=?1", [tg], |r| Ok((r.get(0)?, r.get(1)?))).ok());
        let Some((by, done)) = r else { return };
        if by == 0 || done == 1 { return; }
        // a referrer without an account yet: the reward stays open and is given on the friend's next purchase
        let Some(u) = self.db().users_of_tg(by).into_iter().next() else { return };
        match self.db().exec("UPDATE bot_users SET ref_rewarded=1 WHERE tg_id=?1 AND ref_rewarded=0", &[&tg]) {
            Ok(1) => {}
            _ => return,
        }
        let gb: f64 = self.db().get("ref_gb").parse().unwrap_or(0.0);
        let days: i64 = self.db().get("ref_days").parse().unwrap_or(0);
        if self.db().extend(u.id, days, gb).is_ok() {
            self.send(by, &format!("🎁 دوست شما خرید کرد! {} گیگ و {} روز به سرویس {} اضافه شد.", gb, days, esc(&u.username)), None).await;
        } else {
            // not given: it can be given on a later purchase
            let _ = self.db().exec("UPDATE bot_users SET ref_rewarded=0 WHERE tg_id=?1", &[&tg]);
        }
    }

    async fn review(&self, _chat: i64, _mid: i64, q: &Value, approve: bool, oid: i64) {
        let qid = q["id"].as_str().unwrap_or("").to_string();
        let Some(o) = self.order(oid) else {
            return self.answer(&qid, "این سفارش دیگر وجود ندارد (مثلاً حسابِ آن حذف شده).", true).await;
        };
        // approve and reject tapped together (or twice): only the first decision counts
        let to = if approve { "approved" } else { "rejected" };
        if !matches!(self.db().exec("UPDATE orders SET status=?1 WHERE id=?2 AND status IN ('pending','error')", &[&to, &oid]), Ok(1)) {
            return self.answer(&qid, "این سفارش قبلاً بررسی شده.", true).await;
        }
        // the button stops loading at once: making the account and sending it can take a few seconds
        self.answer(&qid, if approve { "✅ سفارش تأیید شد؛ کانفیگ برای مشتری ارسال می‌شود" } else { "❌ سفارش رد شد" }, false).await;
        let (date, time) = crate::channel::fa_datetime(now());
        if approve {
            self.mark_order(oid, q, "⏳ تأیید شد؛ در حال ساخت و ارسال کانفیگ…").await;
            self.fulfill(oid).await;
            let done = self.order(oid).map(|o| o.6 == "done").unwrap_or(false);
            let note = if done {
                format!("✅ این سفارش در تاریخ {} و ساعت {} تأیید و تحویل شد", date, time)
            } else {
                format!("⚠️ این سفارش در تاریخ {} و ساعت {} تأیید شد ولی تحویل نشد (خطا جدا فرستاده شد)", date, time)
            };
            self.mark_order(oid, q, &note).await;
        } else {
            self.mark_order(oid, q, &format!("❌ این سفارش در تاریخ {} و ساعت {} رد شد", date, time)).await;
            self.send(o.1, &format!("❌ رسید سفارش #{} تأیید نشد. پشتیبانی: {}", oid, esc(&self.db().get("support"))), None).await;
        }
        self.order_msgs.lock().unwrap_or_else(|e| e.into_inner()).remove(&oid);
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
        self.trial_ok(uid, chat, mid).await;
    }

    /// The free trial; true when the customer got the new account in the chat
    async fn trial_ok(&self, uid: i64, chat: i64, mid: i64) -> bool {
        let back = Some(ik(vec![vec![b(&self.bt("back"), "home")]]));
        if !self.db().on("trial_on") {
            self.edit(chat, mid, "تست رایگان فعلاً غیرفعال است.", back).await;
            return false;
        }
        let again = "شما قبلاً تست رایگان خودتون رو گرفتید 🙂\nبرای ادامه، از «خرید اشتراک» استفاده کنید 🛒";
        if self.trial_taken(uid) {
            self.edit(chat, mid, again, back).await;
            return false;
        }
        // claim it first so a double tap cannot create two accounts
        let claimed = self.db().exec("UPDATE bot_users SET trial_used=1 WHERE tg_id=?1 AND COALESCE(trial_used,0)=0", &[&uid]).unwrap_or(0);
        if claimed == 0 {
            self.edit(chat, mid, again, back).await;
            return false;
        }
        let gb: f64 = self.db().get("trial_gb").parse().unwrap_or(1.0);
        let days: i64 = self.db().get("trial_days").parse().unwrap_or(1);
        match self.create_account(uid, gb, days, 1, "trial") {
            Ok(u) => {
                let (t, kb) = self.delivery(&self.tx("txt_trial_ready"), &u, "🎁 تست رایگان");
                if self.edit_ok(chat, mid, &t, Some(kb)).await {
                    self.set_menu(uid).await;
                    return true;
                }
                // the customer never got it (the bot cannot message them): the account goes and the trial stays theirs
                crate::api::delete_user(&self.app, u.id);
                let _ = self.db().exec("UPDATE bot_users SET trial_used=0 WHERE tg_id=?1", &[&uid]);
                let a = self.app.clone();
                tokio::spawn(async move { sync::sync_all(&a).await });
                false
            }
            Err(e) => {
                // nothing was created: give the trial back
                let _ = self.db().exec("UPDATE bot_users SET trial_used=0 WHERE tg_id=?1", &[&uid]);
                self.notify_admins(&format!("⚠️ خطای ساخت تست: <code>{}</code>", esc(&e)), None, None).await;
                self.edit(chat, mid, "⚠️ ساخت اکانت تست ناموفق بود.", back).await;
                false
            }
        }
    }

    // ============================================================ مدیریت
    /// The admin menu: four groups, each opens its own page (`admin_group`)
    fn adm_kb(&self) -> Value {
        let open: i64 = self.db().with(|c| c.query_row("SELECT COUNT(*) FROM orders WHERE status IN ('pending','error')", [], |r| r.get(0)).unwrap_or(0));
        let orders = if open > 0 { format!("📦 سفارش‌ها و مالی · {} باز", open) } else { "📦 سفارش‌ها و مالی".to_string() };
        ik(vec![
            vec![b(&orders, "ag:o")],
            vec![b("👥 کاربران و اتصالات", "ag:u")],
            vec![b("⚙️ تنظیمات و تعرفه پلن‌ها", "ag:s")],
            vec![b("📢 پیام همگانی و ابزارها", "ag:t")],
            vec![b("⬅️ بازگشت", "home")],
        ])
    }

    /// One group of the admin menu: (title, buttons)
    fn admin_group(&self, g: &str) -> Option<(&'static str, Value)> {
        let back = vec![b("⬅️ پنل مدیریت", "adm")];
        let (t, rows): (&'static str, Kb) = match g {
            "o" => ("📦 <b>سفارش‌ها و مالی</b>", vec![
                vec![b("🧾 سفارش‌های باز", "a:pend"), b("📈 آمار و فروش", "a:stats")],
                vec![b("💳 روش‌های پرداخت", "a:pay"), b("🎟 کدهای تخفیف", "a:disc")],
                back,
            ]),
            "u" => ("👥 <b>کاربران و اتصالات</b>", vec![
                vec![b("🔍 جستجوی کاربر", "a:search"), b("➕ ساخت کانفیگ", "a:mk")],
                vec![b("🎁 هدیه حجم و زمان (جبران قطعی)", "a:gift")],
                vec![b("🎁 تست رایگان", "a:trial"), b("🖥 نودها", "a:nodes")],
                back,
            ]),
            "s" => ("⚙️ <b>تنظیمات و تعرفه پلن‌ها</b>", vec![
                vec![b("📦 پلن‌ها", "a:plans"), b("📂 دسته‌بندی‌ها", "a:cats")],
                vec![b("🎨 دکمه‌ها و متن‌ها", "a:ui"), b("🎬 آموزش‌ها", "a:guides")],
                vec![b("👥 دعوت و هدیه", "a:ref"), b("⚙️ تنظیمات عمومی", "a:gen")],
                back,
            ]),
            "t" => ("📢 <b>پیام همگانی و ابزارها</b>", vec![
                vec![b("📣 پیام همگانی", "a:bc"), b("📌 سنجاق برای همه", "a:bcp")],
                vec![b("📢 کانال هوشمند", "a:ch"), b("💾 بکاپ الان", "a:backup")],
                back,
            ]),
            _ => return None,
        };
        Some((t, ik(rows)))
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
        let set_wait = |w: Wait| { self.waits.lock().unwrap_or_else(|e| e.into_inner()).insert(uid, w); };
        match d {
            "adm" => { self.edit(chat, mid, "👑 <b>پنل مدیریت</b>\nیک بخش را انتخاب کنید:", Some(self.adm_kb())).await; true }
            g if g.starts_with("ag:") => match self.admin_group(&g[3..]) {
                Some((t, kb)) => { self.edit(chat, mid, t, Some(kb)).await; true }
                None => false,
            },
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
                // the plans of single custom purchases (mini app) are not the admin's plans and are never listed
                let mut kb: Kb = self.plans(false).into_iter().filter(|(p, _)| !p.custom).map(|(p, a)| vec![
                    b(&plan_label(&p, a), &format!("pv:{}", p.id)),
                ]).collect();
                kb.push(vec![b("➕ افزودن پلن", "pa"), b("📂 دسته‌بندی‌ها", "a:cats")]);
                kb.push(vec![b("⚡ جایگزینی با ۹ پلن کانکی", "pkp")]);
                kb.push(vec![b("⬅️ پنل مدیریت", "adm")]);
                { self.edit(chat, mid, "📦 <b>پلن‌ها</b>\n🟢 فعال · ⚪️ غیرفعال · 🚀 VIP · 🌐 V2Ray\nروی هر پلن بزنید تا همه‌چیزش (نام، نوع سرویس، مدت، حجم، قیمت، تعداد کاربر، کشورها، دسته) را عوض کنید، روشن/خاموش یا حذفش کنید.", Some(ik(kb))).await; true }
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
                let txt = format!("🔗 <b>لینک‌ها</b>\n\n📱 لینک دانلود اپ:\n{}\n\n💻 لینک دانلود اپ ویندوز:\n{}\n\n💬 پشتیبانی:\n{}\n\n📢 کانال اجباری:\n{}", show("app_link"), show("win_link"), show("support"), show("channel"));
                let kb = ik(vec![
                    vec![b("✏️ لینک دانلود اپ", "set:app_link"), b("✏️ لینک اپ ویندوز", "set:win_link")],
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
            "a:pay" => {
                let rate = match crate::pay::rates(&self.app).await {
                    Some(r) => format!("\n\n{}\n⭐️ هر استارز ≈ {} تومان", Self::rate_line(&r), crate::pay::group(crate::pay::star_usd(db) * r.usd_toman)),
                    None => "\n\n⚠️ قیمت لحظه‌ای الان خوانده نشد (TON و استارز تا خوانده نشود فروخته نمی‌شوند).".into(),
                };
                let ton = db.get("ton_address");
                self.edit(chat, mid, &format!("💳 <b>روش‌های پرداخت</b>\nکارت: {}\nکیف پول TON: <code>{}</code>{}\n\n💎 TON خودکار: مبلغ با قیمت لحظه‌ای، پرداخت با کامنت سفارش، تأیید با خواندن خود شبکه‌ی TON (فقط آدرس عمومی؛ ربات کلید کیف پول ندارد).\n⭐️ استارز: فقط وقتی تلگرام پرداخت را تأیید کند تحویل می‌شود.",
                    esc(&db.get("card_number")), if ton.trim().is_empty() { "—".into() } else { esc(&ton) }, rate),
                Some(ik(vec![
                    vec![b(&format!("{} کارت", self.onoff("card_on")), "tg:card_on"), b("✏️ شماره", "set:card_number"), b("✏️ نام", "set:card_holder")],
                    vec![b(&format!("{} زرین‌پال", self.onoff("zp_on")), "tg:zp_on"), b("✏️ مرچنت", "set:zp_merchant"), b("✏️ بازگشت", "set:zp_callback")],
                    vec![b(&format!("{} ارزی خودکار", self.onoff("np_on")), "tg:np_on"), b("✏️ API Key", "set:np_key"), b("✏️ ارزها", "set:np_coins")],
                    vec![b(&format!("{} کیف پول", self.onoff("wallet_on")), "tg:wallet_on"), b("✏️ آدرس‌ها", "set:wallet_text")],
                    vec![b(&format!("{} TON خودکار", self.onoff("ton_on")), "tg:ton_on"), b("✏️ آدرس TON", "set:ton_address")],
                    vec![b(&format!("{} استارز", self.onoff("stars_on")), "tg:stars_on"), b("✏️ دلارِ هر استارز", "set:star_usd")],
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
                if let Ok((bytes, name)) = tokio::task::block_in_place(|| make_archive(&self.app, &pass)) {
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
            if p.category.is_empty() || p.custom { continue; }
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
            "📦 <b>{}</b>  {}\n\n🛍 نوع سرویس: <b>{}</b>\n📅 مدت: {} روز\n📊 حجم: {}\n💰 قیمت: {} · {}$\n👤 تعداد کاربر: {}\n🌍 کشورها: {}\n📂 دسته: {}\n🏷 برچسب: {}\n💸 قیمت خط‌خورده: {}",
            esc(&p.name), if active { "🟢 فعال" } else { "⚪️ غیرفعال" },
            if p.service == "v2ray" { "🌐 استاندارد (V2Ray): فقط لینک اشتراک Xray" } else { "🚀 VIP: همه‌ی پروتکل‌ها و اپ کانکی" }, p.days,
            if p.gb > 0.0 { format!("{} GB", p.gb) } else { "نامحدود".into() }, toman(p.toman), p.usd, p.conns,
            if p.countries > 0 { p.countries.to_string() } else { "همه".into() },
            if p.category.is_empty() { "بدون دسته".to_string() } else { esc(&p.category) },
            if p.badge.is_empty() { "—".to_string() } else { esc(&p.badge) },
            if p.old_toman > 0 { toman(p.old_toman) } else { "—".to_string() }
        );
        let e = |f: &str, t: &str| b(t, &format!("pe:{}:{}", id, f));
        let kb = ik(vec![
            vec![e("name", "✏️ نام"), e("days", "✏️ مدت (روز)")],
            vec![e("gb", "✏️ حجم (گیگ)"), e("conns", "✏️ تعداد کاربر")],
            vec![e("toman", "✏️ قیمت تومان"), e("usd", "✏️ قیمت دلار")],
            vec![e("countries", "✏️ تعداد کشور"), e("category", "📂 دسته")],
            vec![e("badge", "🏷 برچسب"), e("old_toman", "✏️ قیمت خط‌خورده")],
            vec![b(if p.service == "v2ray" { "🔁 تبدیل به 🚀 VIP" } else { "🔁 تبدیل به 🌐 V2Ray" }, &format!("psw:{}", id))],
            // a custom purchase's plan has no on/off (it is never on sale, only payable once)
            if p.custom { vec![b("🗑 حذف", &format!("pd:{}", id))] } else { vec![b(if active { "⏸ غیرفعال کن" } else { "▶️ فعال کن" }, &format!("pt:{}", id)), b("🗑 حذف", &format!("pd:{}", id))] },
            vec![b("⬅️ پلن‌ها", "a:plans")],
        ]);
        self.edit(chat, mid, &txt, Some(kb)).await;
    }

    async fn cat_view(&self, chat: i64, mid: i64, i: usize) {
        let cats = self.categories();
        let Some((name, n)) = cats.get(i).cloned() else {
            return self.edit(chat, mid, "دسته پیدا نشد.", Some(ik(vec![vec![b("📂 دسته‌بندی‌ها", "a:cats")]]))).await;
        };
        let plans: Vec<String> = self.plans(false).into_iter().filter(|x| x.0.category == name && !x.0.custom).map(|x| format!("• {}", esc(&x.0.name))).collect();
        let kb = ik(vec![
            vec![b("✏️ تغییر نام", &format!("cr:{}", i)), b("🗑 حذف دسته", &format!("cx:{}", i))],
            vec![b("⬅️ دسته‌بندی‌ها", "a:cats")],
        ]);
        self.edit(chat, mid, &format!("📂 <b>{}</b> · {} پلن\n\n{}\n\nبا حذف دسته، پلن‌هایش پاک نمی‌شوند؛ فقط بدون دسته می‌شوند.", esc(&name), n, plans.join("\n")), Some(kb)).await;
    }

    /// Every customer button, two in a row, as customers see them, to each admin of the bot (the panel's
    /// «Send a preview»); Telegram's error when it refuses a premium emoji. How many admins got it.
    pub async fn preview_buttons(&self) -> Result<usize, String> {
        let btns: Vec<(String, String)> = BTNS.iter().map(|(k, _, _)| b(&self.bt(k), &format!("bv:{}", k))).collect();
        let kb = ik(btns.chunks(2).map(|c| c.to_vec()).collect());
        let mut sent = 0;
        let mut last = String::from("the bot has no admin");
        for a in &self.admins {
            let body = json!({"chat_id": a, "text": "👁 <b>پیش‌نمایش دکمه‌های ربات</b>\nهمه‌ی دکمه‌ها با متن، ایموجی پریمیوم و رنگشان؛ روی هر کدام بزنید تا تنظیمش باز شود.", "parse_mode": "HTML", "reply_markup": kb});
            match self.call_strict("sendMessage", body).await {
                Ok(_) => sent += 1,
                Err(e) => last = e,
            }
        }
        if sent == 0 { Err(last) } else { Ok(sent) }
    }

    /// The panel's «Set from Telegram»: each admin's next message gives button `k` its premium emoji
    pub async fn ask_icon(&self, k: &str) -> Result<usize, String> {
        if !BTNS.iter().any(|x| x.0 == k) {
            return Err("unknown button".into());
        }
        let mut sent = 0;
        for a in &self.admins {
            self.waits.lock().unwrap_or_else(|e| e.into_inner()).insert(*a, Wait::Icon(k.to_string()));
            let t = format!("⭐️ <b>ایموجی پریمیوم برای «{}»</b> (از پنل)\n\nهمین حالا یک ایموجی پریمیوم بفرستید؛ نمونه‌ی دکمه برایتان می‌آید و پنل خودش به‌روز می‌شود.", esc(&self.bt(k)));
            if self.send(*a, &t, Some(ik(vec![vec![b("⬅️ انصراف", &format!("bv:{}", k))]]))).await.is_some() {
                sent += 1;
            }
        }
        if sent == 0 { Err("the bot could not message its admins (start the bot from your Telegram first)".into()) } else { Ok(sent) }
    }

    /// Sends a sample of button `k` with premium emoji `id` and saves the emoji only when Telegram took it
    async fn try_icon(&self, chat: i64, k: &str, id: &str) -> bool {
        if !crate::buttons::valid_id(id) {
            return false;
        }
        let btn = json!({"text": crate::buttons::without_lead_emoji(&self.bt(k)), "callback_data": format!("bv:{}", k), "icon_custom_emoji_id": id});
        let body = json!({"chat_id": chat, "text": "👁 <b>نمونه‌ی دکمه</b> (مشتری همین را می‌بیند):", "parse_mode": "HTML", "reply_markup": {"inline_keyboard": [[btn]]}});
        match self.call_strict("sendMessage", body).await {
            Ok(_) => {
                crate::buttons::set_icon(self.db(), k, Some(id));
                self.send(chat, "✅ ایموجی پریمیوم ذخیره شد.", None).await;
                true
            }
            Err(why) => {
                self.send(chat, &format!("⚠️ تلگرام این ایموجی را روی دکمه قبول نکرد و ذخیره نشد.\nدلیل: <code>{}</code>\n\nسازنده‌ی ربات (حسابی که ربات را در BotFather ساخته) باید تلگرام پریمیوم داشته باشد.", esc(&why)), None).await;
                false
            }
        }
    }

    async fn btn_view(&self, chat: i64, mid: i64, k: &str) {
        let Some((_, def, place)) = BTNS.iter().find(|t| t.0 == k).cloned() else { return };
        let main = MAIN_BTNS.contains(&k);
        let hidden = main && self.db().on(&format!("hide_{}", k));
        let icon = crate::buttons::icons(self.db()).get(k).cloned();
        let sk = crate::buttons::style_key(k);
        let colour = sk.map(|s| match self.style_of(s).as_str() { "success" => "🟢 سبز", "primary" => "🔵 آبی", "danger" => "🔴 قرمز", _ => "⚪️ ساده" });
        let mut txt = format!("🔘 <b>دکمه</b>\n\nمتن فعلی: <b>{}</b>\nپیش‌فرض: {}\nجای دکمه: {}\n⭐️ ایموجی پریمیوم: {}{}",
            esc(&self.bt(k)), esc(def), place,
            if icon.is_some() { "دارد (نمونه‌اش همین دکمه‌ی پایین است)" } else { "ندارد" },
            colour.map(|c| format!("\n🎨 رنگ: {}{}", c, if sk != Some(k) { " (مشترک با دکمه‌های هم‌گروه)" } else { "" })).unwrap_or_default());
        if main { txt.push_str(&format!("\nوضعیت: {}", if hidden { "🚫 پنهان" } else { "👁 نمایش" })); }
        if k == "guide" || k == "guide_acc" { txt.push_str("\n\nاین دکمه فقط وقتی دیده می‌شود که در «🎬 آموزش‌ها» حداقل یک آموزش باشد."); }
        // the button itself first: with its premium emoji and colour, the same as customers see it
        let mut rows: Kb = vec![vec![b(&self.bt(k), &format!("bv:{}", k))]];
        rows.push(vec![b("✏️ متن جدید", &format!("set:btn_{}", k)), b("↩️ پیش‌فرض", &format!("rs:btn_{}", k))]);
        let mut er = vec![b(if icon.is_some() { "⭐️ عوض کردن ایموجی پریمیوم" } else { "⭐️ ایموجی پریمیوم" }, &format!("bic:{}", k))];
        if icon.is_some() { er.push(b("🗑 حذف ایموجی", &format!("bix:{}", k))); }
        rows.push(er);
        if sk.is_some() {
            rows.push(vec![b("🟢", &format!("@success@bsc:{}:success", k)), b("🔵", &format!("@primary@bsc:{}:primary", k)), b("🔴", &format!("@danger@bsc:{}:danger", k)), b("⚪️", &format!("bsc:{}:none", k)), b("↩️", &format!("bsc:{}:", k))]);
        }
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
        let pins: Vec<String> = x["for"].as_array().map(|a| a.iter().filter_map(|t| t.as_str()).filter_map(|t| t.split_once(':')).map(|(a, o)| how_target_title(a, o)).collect()).unwrap_or_default();
        let txt = format!(
            "🎬 <b>{}</b>{}\nنوع: {}\nمتن زیر آموزش: {}\n📌 در راهنمای اتصال: {}",
            esc(x["title"].as_str().unwrap_or("")), if pos == 0 { "  ⭐️ (آموزش اتصال اصلی)" } else { "" },
            kind_title(x["kind"].as_str().unwrap_or("")), if cap.trim().is_empty() { "— (عنوان نشان داده می‌شود)".to_string() } else { esc(cap) },
            if pins.is_empty() { "— (فقط در فهرست آموزش‌ها)".to_string() } else { pins.join("، ") }
        );
        let mut rows: Kb = vec![
            vec![b("▶️ پیش‌نمایش", &format!("gp:{}", id))],
            vec![b("✏️ عنوان", &format!("gt:{}", id)), b("✏️ متن زیر آموزش", &format!("gc:{}", id))],
            vec![b("🔄 جایگزینی ویدیو/فایل", &format!("gr:{}", id))],
            vec![b("📌 کجای راهنمای اتصال نشان داده شود", &format!("gw:{}", id))],
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
        let set_wait = |w: Wait| { self.waits.lock().unwrap_or_else(|e| e.into_inner()).insert(uid, w); };
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
            "bic" if BTNS.iter().any(|x| x.0 == rest) => {
                set_wait(Wait::Icon(rest.to_string()));
                self.edit(chat, mid, &format!("⭐️ <b>ایموجی پریمیوم برای «{}»</b>\n\nیک ایموجی پریمیوم (از پک‌های ایموجی تلگرام پریمیوم) بفرستید؛ می‌تواند تنها باشد یا وسط یک متن.\n\nربات یک نمونه از دکمه با همان ایموجی برایتان می‌فرستد و فقط اگر تلگرام قبولش کرد ذخیره می‌کند. ایموجی ساده‌ی اول متن دکمه خودش برداشته می‌شود.\n\nℹ️ تلگرام ایموجی پریمیوم را روی دکمه‌ها فقط وقتی نشان می‌دهد که سازنده‌ی ربات (حسابی که ربات را در BotFather ساخته) پریمیوم باشد.", esc(&self.bt(rest))),
                    Some(ik(vec![vec![b("⬅️ انصراف", &format!("bv:{}", rest))]]))).await;
            }
            "bix" => {
                crate::buttons::set_icon(db, rest, None);
                self.btn_view(chat, mid, rest).await;
            }
            "bsc" => {
                let (k, st) = rest.split_once(':').unwrap_or((rest, ""));
                if let (Some(sk), true) = (crate::buttons::style_key(k), ["", "success", "primary", "danger", "none"].contains(&st)) {
                    db.set(&format!("bst_{}", sk), st);
                }
                self.btn_view(chat, mid, k).await;
            }
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
                    "badge" => "برچسب پلن در فروشگاه (مثلاً 🔥 پیشنهاد ویژه؛ برای حذف یک خط تیره - بفرستید)",
                    "old_toman" => "قیمت خط‌خورده به تومان (بالاتر از قیمت اصلی؛ 0 = بدون آن)",
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
            "pkp" => {
                let list: Vec<String> = KANKI_PLANS.iter().map(|p| format!("• {} · {}{}", p.0, toman(p.4), if p.6.is_empty() { String::new() } else { format!(" · {}", p.6) })).collect();
                self.edit(chat, mid, &format!("⚡ <b>پلن‌های کانکی</b>\n\n{}\n\nهمهٔ پلن‌های فعلی <b>غیرفعال</b> می‌شوند (پاک نمی‌شوند؛ سفارش‌هایشان می‌ماند) و این ۹ پلن (VIP) اضافه می‌شوند. ادامه؟", list.join("\n")),
                    Some(ik(vec![vec![b("✅ بله، جایگزین کن", "pkpy")], vec![b("⬅️ نه", "a:plans")]]))).await;
            }
            "pkpy" => {
                let n = load_kanki_plans(db);
                self.edit(chat, mid, &format!("✅ {} پلن کانکی اضافه شد و پلن‌های قبلی غیرفعال شدند.", n), Some(ik(vec![vec![b("📦 پلن‌ها", "a:plans")]]))).await;
            }
            "psw" => {
                // the plan's service: vip <-> v2ray (accounts already sold keep what they have)
                let id: i64 = rest.parse().unwrap_or(0);
                let _ = db.exec("UPDATE plans SET service=CASE WHEN COALESCE(service,'vip')='v2ray' THEN 'vip' ELSE 'v2ray' END WHERE id=?1", &[&id]);
                self.plan_view(chat, mid, id).await;
            }
            "pt" => {
                let id: i64 = rest.parse().unwrap_or(0);
                // only on (1) and off (0): a custom purchase's plan (2) would become -1
                let _ = db.exec("UPDATE plans SET active=1-active WHERE id=?1 AND active IN (0,1)", &[&id]);
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
            // where a tutorial shows in the connection guide: a switch per app and device
            "gw" | "gwt" => {
                let mut parts = rest.split(':');
                let id: i64 = parts.next().and_then(|x| x.parse().ok()).unwrap_or(0);
                if head == "gwt" {
                    let t = format!("{}:{}", parts.next().unwrap_or(""), parts.next().unwrap_or(""));
                    if HOW_TARGETS.iter().any(|x| format!("{}:{}", x.0, x.1) == t) {
                        let mut list: Vec<Value> = self.guide(id).and_then(|g| g["for"].as_array().cloned()).unwrap_or_default();
                        if list.iter().any(|x| x.as_str() == Some(t.as_str())) { list.retain(|x| x.as_str() != Some(t.as_str())); } else { list.push(json!(t)); }
                        self.guide_set(id, "for", Value::Array(list));
                    }
                }
                let Some(g) = self.guide(id) else { return };
                let on = |t: &str| g["for"].as_array().map(|a| a.iter().any(|x| x.as_str() == Some(t))).unwrap_or(false);
                let mut rows: Kb = HOW_TARGETS.chunks(2).map(|c| c.iter().map(|(a, o)| {
                    let t = format!("{}:{}", a, o);
                    b(&format!("{} {}", if on(&t) { "✅" } else { "▫️" }, how_target_title(a, o)), &format!("gwt:{}:{}", id, t))
                }).collect()).collect();
                rows.push(vec![b("⬅️ همین آموزش", &format!("gv:{}", id))]);
                self.edit(chat, mid, &format!("📌 <b>{}</b>\n\nوقتی مشتری در «راهنمای اتصال» این برنامه و دستگاه رو انتخاب کنه، این آموزش هم براش فرستاده می‌شه. هر چند تا رو می‌خواید روشن کنید:", esc(g["title"].as_str().unwrap_or(""))), Some(ik(rows))).await;
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
                let Some((days, gb, why)) = self.gifts.lock().unwrap_or_else(|e| e.into_inner()).remove(&uid) else {
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
                    // the same as the panel's «new link»: new keys too, so the old configs stop working
                    "rgn" => crate::api::user_action(&self.app, id, "regen", &serde_json::Value::Null),
                    "del" => return self.edit(chat, mid, "⚠️ کاربر کامل حذف شود؟", Some(ik(vec![vec![b("🗑 بله", &format!("u:dly:{}", id))], vec![b("⬅️ پنل مدیریت", "adm")]]))).await,
                    "dly" => { crate::api::delete_user(&self.app, id); let a = self.app.clone(); tokio::spawn(async move { sync::sync_all(&a).await }); return self.edit(chat, mid, "🗑 حذف شد.", back).await; }
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
                // premium emoji: kept in message texts (<tg-emoji>); on a button the first one becomes its emoji
                let kept;
                let v = if is_text_key(&k) { kept = crate::buttons::keep_custom_emoji(text, m); kept.trim() } else { text.trim() };
                let mut btn_icon = None;
                let cut;
                let v = match (k.strip_prefix("btn_"), crate::buttons::first_custom(m)) {
                    (Some(_), Some((id, off, len))) => {
                        let u: Vec<u16> = text.encode_utf16().collect();
                        cut = if off + len <= u.len() { format!("{}{}", String::from_utf16_lossy(&u[..off]), String::from_utf16_lossy(&u[off + len..])) } else { text.to_string() };
                        btn_icon = Some(id);
                        cut.trim()
                    }
                    _ => v,
                };
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
                if k == "ton_address" && crate::pay::raw_address(v).is_none() {
                    self.send(chat, "⚠️ این آدرس TON درست نیست. آدرس کیف پول رو از Tonkeeper کپی کنید (با UQ یا EQ شروع می‌شه، ۴۸ حرف).", retry(to)).await;
                    return;
                }
                if k == "star_usd" && !v.parse::<f64>().map(|x| x > 0.0005 && x < 1.0).unwrap_or(false) {
                    self.send(chat, "⚠️ یک عدد مثل 0.013 بفرستید.", retry(to)).await;
                    return;
                }
                db.set(&k, v);
                self.send(chat, "✅ ذخیره شد", None).await;
                if let (Some(x), Some(id)) = (k.strip_prefix("btn_"), btn_icon) {
                    self.try_icon(chat, x, &id).await;
                }
                if let Some(x) = k.strip_prefix("btn_") {
                    self.btn_view(chat, 0, x).await;
                } else if is_text_key(&k) {
                    self.txt_view(chat, 0, &k).await;
                } else {
                    self.admin_view(uid, chat, 0, back_view(&k)).await;
                }
            }
            Wait::Icon(k) => {
                match crate::buttons::first_custom(m) {
                    Some((id, _, _)) => {
                        self.try_icon(chat, &k, &id).await;
                        self.btn_view(chat, 0, &k).await;
                    }
                    None => {
                        self.waits.lock().unwrap_or_else(|e| e.into_inner()).insert(uid, Wait::Icon(k.clone()));
                        self.send(chat, "⚠️ این ایموجی پریمیوم نیست. از پنل ایموجی تلگرام یک ایموجی از پک‌های پریمیوم (با علامت ⭐️) بفرستید.",
                            Some(ik(vec![vec![b("⬅️ انصراف", &format!("bv:{}", k))]]))).await;
                    }
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
                    "badge" => {
                        let c: String = if v == "-" || v == "—" { String::new() } else { v.chars().take(24).collect() };
                        db.exec("UPDATE plans SET badge=?1 WHERE id=?2", &[&c, &id])
                    }
                    "days" | "conns" | "toman" | "countries" | "old_toman" => match v.parse::<i64>() {
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
                        self.waits.lock().unwrap_or_else(|e| e.into_inner()).insert(uid, Wait::Gift(target));
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
                    self.gifts.lock().unwrap_or_else(|e| e.into_inner()).insert(uid, (days, gb, why.clone()));
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
                let pct = parts[1].parse::<i64>().unwrap_or(0);
                if !(1..=100).contains(&pct) { self.send(chat, "⚠️ درصد تخفیف باید بین ۱ و ۱۰۰ باشد.", kb).await; return; }
                let r = db.exec("INSERT OR REPLACE INTO discounts(code,percent,uses_left) VALUES(?1,?2,?3)",
                    &[&parts[0].to_uppercase(), &pct, &parts[2].parse::<i64>().unwrap_or(0)]);
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
            let nodes: Vec<_> = self.db().nodes().into_iter().filter(|n| n.enabled).collect();
            let offline: std::collections::HashSet<String> = nodes.iter().filter(|n| !n.online).map(|n| n.id.clone()).collect();
            let mut items: Vec<(String, String, bool, String)> =
                nodes.iter().map(|n| (format!("node:{}", n.id), format!("نود {}", n.name), n.online, String::new())).collect();
            items.extend(crate::tunnel::panel::health(&self.app, &offline));
            let keys: Vec<String> = items.iter().map(|i| i.0.clone()).collect();
            st.retain(|k, _| keys.contains(k));
            for (key, name, ok, detail) in items {
                // the tunnel agent of a VPN server waits longer: when the whole server is down, its own alert
                // (the node's) comes first and this one is not sent at all
                let need = if key.starts_with("ts:") && !detail.is_empty() { 5 } else { 3 };
                let mut msg: Option<String> = None;
                {
                    let e = st.entry(key.clone()).or_insert((0, false));
                    if ok {
                        if e.1 {
                            msg = Some(alert_text(&key, &name, true, &detail));
                        }
                        *e = (0, false);
                    } else {
                        e.0 += 1;
                        if e.0 >= need && !e.1 {
                            e.1 = true;
                            msg = Some(alert_text(&key, &name, false, &detail));
                        }
                    }
                }
                if let Some(m) = msg {
                    self.notify_admins(&m, None, None).await;
                }
            }
        }
    }

    /// Marks unpaid gateway orders that were left too long as expired; returns how many
    fn expire_waiting(&self, t: i64) -> usize {
        self.db().exec(
            "UPDATE orders SET status='expired' WHERE status='waiting' AND ((method='np' AND created<?1) OR (method<>'np' AND created<?2))",
            &[&(t - 2 * 86400), &(t - 86400)]).unwrap_or(0)
    }

    /// Drops started purchases nobody touched for a day
    fn prune_pend(&self, t: i64) {
        self.pend.lock().unwrap_or_else(|e| e.into_inner()).retain(|_, p| t - p.at < PEND_TTL);
    }

    /// Free trials that are over are deleted (their number goes to the next new customer) and the owner is told.
    async fn clean_trials(&self) {
        let done = self.db().finished_trials();
        for u in &done {
            crate::api::delete_user(&self.app, u.id);
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
            // gateway orders never paid: ZarinPal after a day, NOWPayments after the two days it is checked for.
            // A waiting order keeps a finished trial from being cleaned up.
            self.expire_waiting(now());
            self.prune_pend(now());
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
                        let mut renew = vec![vec![b("🔁 تمدید", &format!("rnw:{}", u.id))]];
                        renew.extend(self.shop_row(u.id));
                        let _ = self.db().exec("UPDATE users SET warned=?1 WHERE id=?2", &[&flag, &u.id]);
                        self.send(u.tg_id, &t, Some(self.acct_kb(&u, renew))).await;
                        continue;
                    } else if u.expires_at > 0 && u.expires_at - now() < 86400 && flag & 2 == 0 && u.active() {
                        flag |= 2;
                        msg = Some(format!("⏳ سرویس <b>{}</b> کمتر از ۲۴ ساعت دیگر منقضی می‌شود.", esc(&u.username)));
                    }
                    if let Some(t) = msg {
                        let _ = self.db().exec("UPDATE users SET warned=?1 WHERE id=?2", &[&flag, &u.id]);
                        let mut rows = vec![vec![b("🔁 تمدید", &format!("rnw:{}", u.id))]];
                        rows.extend(self.shop_row(u.id));
                        self.send(u.tg_id, &t, Some(ik(rows))).await;
                    }
                }
            }
            // بکاپ روزانه برای ادمین‌ها
            if tick.is_multiple_of(24 * 60) && self.db().on("backup_on") {
                let pass = self.db().get("tgb_pass");
                if let Ok((bytes, name)) = tokio::task::block_in_place(|| make_archive(&self.app, &pass)) {
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

/// Every app of the connection guide on every device it is offered on: (app, device), for pinning a tutorial
const HOW_TARGETS: &[(&str, &str)] = &[("k", "a"), ("k", "w"), ("z", "a"), ("z", "i"), ("z", "w"), ("v", "a"), ("v", "i"), ("v", "w"), ("g", "a"), ("g", "i"), ("g", "w")];

/// An app of the connection guide: (its name on this device, one line about it)
fn how_app_line(app: &str, os: &str) -> (&'static str, &'static str) {
    match app {
        "k" => ("اپ اختصاصی Kanki VPN", "همه‌ی سرورها و پروتکل‌ها با یک کد؛ ساده‌ترین راه"),
        "z" => ("AmneziaVPN", "همه‌ی سرورها (WireGuard، AmneziaWG و VLESS / Xray) با یک فایل بکاپ"),
        "v" => (match os { "i" => "V2Box", "w" => "v2rayN", _ => "v2rayNG" }, "با لینک اشتراک؛ کانفیگ‌های VLESS (Xray) و Hysteria2"),
        _ => ("WireGuard", "فقط کانفیگ‌های WireGuard، هر سرور یک فایل"),
    }
}

/// "AmneziaVPN · آیفون" for a pin target
fn how_target_title(app: &str, os: &str) -> String {
    format!("{} · {}", how_app_line(app, os).0, match os { "i" => "آیفون", "w" => "ویندوز", _ => "اندروید" })
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
    ["ton_address", "usdt_address", "wallet_text"].iter().any(|k| !(*k == "ton_address" && db.on("ton_on")) && !db.get(k).trim().is_empty())
}

/// Today's TON price in dollars (kept 10 minutes; None when it cannot be read)
/// A send error that means the customer is gone for the bot (blocked it, deleted the account, chat unknown),
/// not a busy moment (429) or a cut connection
fn gone_chat(e: &str) -> bool {
    let e = e.to_lowercase();
    e.starts_with("forbidden") || e.contains("bot was blocked") || e.contains("chat not found") || e.contains("user is deactivated")
}

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


/// The admin alert of one watched thing: a server (node / tunnel server) down or back, a tunnel cut or
/// back while both its servers are up, a tunnel's round trip too high or normal again
fn alert_text(key: &str, name: &str, ok: bool, detail: &str) -> String {
    let n = esc(name);
    match (key.split(':').next().unwrap_or(""), ok) {
        ("tu", false) => format!("🔴 <b>{}</b> قطع است (هر دو سرورش آنلاین‌اند)", n),
        ("tu", true) => format!("🟢 <b>{}</b> دوباره وصل شد", n),
        ("tp", false) => format!("🟠 پینگ <b>{}</b> بالاست: <b>{} ms</b>", n, detail),
        ("tp", true) => format!("🟢 پینگ <b>{}</b> عادی شد: {} ms", n, detail),
        (_, false) => format!("🔴 <b>{}</b> آفلاین است", n),
        (_, true) => format!("🟢 <b>{}</b> دوباره آنلاین شد", n),
    }
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
                    l.lock().unwrap_or_else(|e| e.into_inner()).push((m, v));
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
            waits: Mutex::new(HashMap::new()), pend: Mutex::new(HashMap::new()), answered: Mutex::new(Default::default()), gifts: Mutex::new(HashMap::new()), order_msgs: Mutex::new(HashMap::new()), members: Mutex::new(HashMap::new()), me_name: Mutex::new(String::new()),
        });
        (bot, log)
    }

    const ADMIN: i64 = 9000;

    /// The buttons of the last message to a chat: (text, callback data or web app url, colour)
    fn buttons(log: &Log, chat: i64) -> Vec<(String, String, String)> {
        let l = log.lock().unwrap_or_else(|e| e.into_inner());
        let Some((_, v)) = l.iter().rev().find(|(m, v)| (m == "sendMessage" || m == "editMessageText") && v["chat_id"].as_i64() == Some(chat)) else { return vec![] };
        v["reply_markup"]["inline_keyboard"].as_array().cloned().unwrap_or_default().iter().flat_map(|r| r.as_array().cloned().unwrap_or_default()).map(|b| (
            b["text"].as_str().unwrap_or("").to_string(),
            b["callback_data"].as_str().or(b["web_app"]["url"].as_str()).unwrap_or("").to_string(),
            b["style"].as_str().unwrap_or("").to_string(),
        )).collect()
    }

    #[tokio::test]
    async fn the_mini_app_asks_a_config_name_and_gives_the_trial_once() {
        let (bot, log) = bot().await;
        let tg = 7101;
        // a customer who never wrote to the bot, with no usable Telegram name
        assert!(bot.needs_name(tg));
        assert!(bot.set_name(tg, "1bad").is_err());
        assert!(bot.set_name(tg, "a").is_err());
        assert_eq!(bot.set_name(tg, "Mahtab87").map(|n| n.to_lowercase()), Ok("mahtab87".to_string()));
        assert!(!bot.needs_name(tg));
        // the trial: delivered in the chat with that name, then closed for that customer
        assert!(bot.trial_open(tg));
        bot.mini_trial(tg).await;
        let acc = bot.db().users_of_tg(tg);
        assert_eq!(acc.len(), 1, "{}", last(&log, tg));
        assert!(acc[0].username.to_lowercase().starts_with("mahtab87"), "{}", acc[0].username);
        assert!(!bot.trial_open(tg));
    }

    #[tokio::test]
    async fn a_custom_purchase_from_the_mini_app_is_paid_in_the_chat_and_delivered() {
        let (bot, log) = bot().await;
        let db = bot.db();
        db.set("card_on", "1");
        db.set("card_number", "6037000011112222");
        db.set("price_rules", r#"{"gb":4000,"base":10000,"round":1000}"#);
        db.set("sub_base", "https://sub.example.com");
        db.exec("INSERT INTO plans(name,days,gb,toman,usd,conns,active,style) VALUES('Duo',30,50,300000,0,2,1,''),('Red',30,10,90000,0,1,1,'danger')", &[]).unwrap();
        let buyer = 7001;
        bot.touch(buyer, &from(buyer, "Sara", "sara"), 0);
        // the mini app's «continue and pay»: 25 GB, 30 days, one user = 25 * 4000 + 10000
        let pid = crate::shop::custom_plan(db, 25, 30, 1).unwrap();
        bot.start_purchase(buyer, pid, 0).await;
        let t = last(&log, buyer);
        assert!(t.contains("دلخواه · 25 گیگ · 30 روزه") && t.contains("110,000"), "{}", t);
        let bs = buttons(&log, buyer);
        assert!(bs.iter().any(|b| b.1 == "pay:card" && b.2 == "success"), "{:?}", bs);
        // the custom plan is not listed in the bot; the listed ones have their colours, and the custom-volume button opens the mini app
        // (the first «buy» asks the config name: the Telegram name with one tap)
        tap(&bot, from(buyer, "Sara", "sara"), "buy").await;
        tap(&bot, from(buyer, "Sara", "sara"), "cfgsk:buy").await;
        assert!(bot.db().with(|c| c.query_row("SELECT cfg_name FROM bot_users WHERE tg_id=?1", [buyer], |r| r.get::<_, String>(0)).unwrap()) == "sara");
        let bs = buttons(&log, buyer);
        assert!(!bs.iter().any(|b| b.0.contains("دلخواه ·")), "{:?}", bs);
        assert!(bs.iter().any(|b| b.0 == "50 گیگ — 2 کاربره — 1 ماهه — 300,000 تومان" && b.2 == "success"), "{:?}", bs);
        assert!(bs.iter().any(|b| b.0 == "10 گیگ — 1 ماهه — 90,000 تومان" && b.2 == "danger"), "{:?}", bs);
        assert!(bs.iter().any(|b| b.1 == "https://sub.example.com/tg/?buy=1" && b.2 == "primary"), "{:?}", bs);
        assert!(!log.lock().unwrap().iter().any(|(_, v)| v.to_string().contains("\"_k\"")), "the colour key is not sent to Telegram");
        // paid by card: the receipt, the admin approves (green / red buttons), the account has the custom volume and days
        bot.start_purchase(buyer, pid, 0).await;
        tap(&bot, from(buyer, "Sara", "sara"), "pay:card").await;
        say(&bot, from(buyer, "Sara", "sara"), "رسید").await;
        let adm = buttons(&log, ADMIN);
        assert!(adm.iter().any(|b| b.1.starts_with("ap:") && b.2 == "success") && adm.iter().any(|b| b.1.starts_with("rj:") && b.2 == "danger"), "{:?}", adm);
        let oid: i64 = adm.iter().find(|b| b.1.starts_with("ap:")).unwrap().1[3..].parse().unwrap();
        tap(&bot, from(ADMIN, "Admin", "admin"), &format!("ap:{}", oid)).await;
        let acc = db.users_of_tg(buyer);
        assert_eq!(acc.len(), 1);
        assert_eq!((acc[0].limit_gb, acc[0].max_conn), (25.0, 1));
        assert!(acc[0].expires_at - now() > 29 * 86400);
        // renewing that account with the two-user plan (from the mini app): more volume and two users
        let duo: i64 = db.with(|c| c.query_row("SELECT id FROM plans WHERE name='Duo'", [], |r| r.get(0)).unwrap());
        bot.start_purchase(buyer, duo, acc[0].id).await;
        tap(&bot, from(buyer, "Sara", "sara"), "pay:card").await;
        say(&bot, from(buyer, "Sara", "sara"), "رسید").await;
        let oid: i64 = buttons(&log, ADMIN).iter().find(|b| b.1.starts_with("ap:")).unwrap().1[3..].parse().unwrap();
        tap(&bot, from(ADMIN, "Admin", "admin"), &format!("ap:{}", oid)).await;
        let u = db.user(acc[0].id).unwrap();
        assert_eq!((u.limit_gb, u.max_conn, db.users_of_tg(buyer).len()), (75.0, 2, 1));
        // someone else's account cannot be the target: it becomes a new account
        bot.start_purchase(4242, duo, acc[0].id).await;
        assert_eq!(bot.pend.lock().unwrap().get(&4242).map(|p| (p.kind.clone(), p.target)), Some(("new".to_string(), 0)));
    }

    #[tokio::test]
    async fn two_services_a_v2ray_purchase_and_the_dated_approval() {
        let (bot, log) = bot().await;
        let db = bot.db();
        db.set("card_on", "1");
        db.set("card_number", "6037000011112222");
        db.set("sub_base", "https://sub.example.com");
        db.exec("INSERT INTO plans(name,days,gb,toman,usd,conns,active,service) VALUES('Std',30,30,85000,0,1,1,'v2ray'),('Pro',30,50,190000,0,1,1,'vip')", &[]).unwrap();
        let buyer = 7101;
        bot.touch(buyer, &from(buyer, "Nima", "nima"), 0);
        db.exec("UPDATE bot_users SET cfg_name='nima' WHERE tg_id=?1", &[&buyer]).unwrap();
        // "buy" shows the two services first, each with its own plans only
        tap(&bot, from(buyer, "Nima", "nima"), "buy").await;
        let bs = buttons(&log, buyer);
        assert!(bs.iter().any(|b| b.1 == "psv:b:v") && bs.iter().any(|b| b.1 == "psv:b:p"), "{:?}", bs);
        assert!(last(&log, buyer).contains("V2Ray") && last(&log, buyer).contains("VIP"));
        tap(&bot, from(buyer, "Nima", "nima"), "psv:b:v").await;
        let bs = buttons(&log, buyer);
        let std_id: i64 = db.with(|c| c.query_row("SELECT id FROM plans WHERE name='Std'", [], |r| r.get(0)).unwrap());
        assert!(bs.iter().any(|b| b.1 == format!("pl:{}", std_id)) && !bs.iter().any(|b| b.0.contains("50GB")), "{:?}", bs);
        assert!(bs.iter().any(|b| b.1 == "psv:b"), "back goes to the service menu: {:?}", bs);
        // the v2ray plan, paid by card and approved: an Xray-only account and the v2ray guide
        tap(&bot, from(buyer, "Nima", "nima"), &format!("pl:{}", std_id)).await;
        tap(&bot, from(buyer, "Nima", "nima"), "pay:card").await;
        say(&bot, from(buyer, "Nima", "nima"), "رسید").await;
        let oid: i64 = buttons(&log, ADMIN).iter().find(|b| b.1.starts_with("ap:")).unwrap().1[3..].parse().unwrap();
        tap_id(&bot, from(ADMIN, "Admin", "admin"), &format!("ap:{}", oid), "qap").await;
        // the tap is answered with the success text, and the receipt has no buttons and says when it was delivered
        assert_eq!(answers(&log, "qap"), vec!["✅ سفارش تأیید شد؛ کانفیگ برای مشتری ارسال می‌شود".to_string()]);
        let edits: Vec<Value> = log.lock().unwrap().iter().filter(|(m, v)| m == "editMessageText" && v["chat_id"].as_i64() == Some(ADMIN)).map(|x| x.1.clone()).collect();
        let fin = edits.last().unwrap();
        assert!(fin["text"].as_str().unwrap().contains("تأیید و تحویل شد") && fin["text"].as_str().unwrap().contains("ساعت"), "{}", fin);
        assert!(fin.get("reply_markup").is_none(), "no approve / reject buttons left: {}", fin);
        // no call carries an empty keyboard
        assert!(!log.lock().unwrap().iter().any(|(_, v)| v.get("reply_markup").map(|r| r["inline_keyboard"].is_null() && r.get("keyboard").is_none() && r.get("remove_keyboard").is_none()).unwrap_or(false)));
        // the receipt message itself (message 7) and the tapped copy (message 5) both changed
        assert!(edits.iter().any(|e| e["message_id"] == 7) && edits.iter().any(|e| e["message_id"] == 5));
        let acc = db.users_of_tg(buyer);
        assert_eq!(acc.len(), 1);
        assert_eq!((acc[0].protocols.as_str(), acc[0].service()), ("xray", "v2ray"));
        let t = last(&log, buyer);
        assert!(t.contains("خرید شما با موفقیت انجام شد") && t.contains("/v2") && t.contains("📦 پلن: <b>Std</b>"), "{}", t);
        // the short delivery: only the apps, the tutorial (when there is one) and support; no config or backup buttons
        let bs: Vec<String> = buttons(&log, buyer).into_iter().map(|b| b.0).collect();
        assert!(t.contains("روی کدوم دستگاه وصل می‌شید"), "{}", t);
        assert!(["🤖 اندروید", "🍏 آیفون", "💻 ویندوز"].iter().all(|d| bs.iter().any(|b| b == d)) && bs.iter().any(|b| b.starts_with("پشتیبانی")) && bs.len() <= 5, "{:?}", bs);
        // the connection guide of a v2ray account on an iPhone: only V2Box, with its subscription link
        tap(&bot, from(buyer, "Nima", "nima"), &format!("hw:{}:i", acc[0].id)).await;
        let bs = buttons(&log, buyer);
        assert_eq!(bs.iter().filter(|b| b.1.starts_with("hw:") && b.1.matches(':').count() == 3).map(|b| b.0.clone()).collect::<Vec<_>>(), vec!["⭐️ V2Box".to_string()], "{:?}", bs);
        tap(&bot, from(buyer, "Nima", "nima"), &format!("hw:{}:i:v", acc[0].id)).await;
        let t = last(&log, buyer);
        assert!(t.contains("Import v2ray uri from clipboard") && t.contains("/v2") && !t.contains("AmneziaVPN"), "{}", t);
        // another account's guide: nothing
        let n = log.lock().unwrap().len();
        tap(&bot, from(4242, "X", "x"), &format!("hw:{}:i:v", acc[0].id)).await;
        assert!(!log.lock().unwrap()[n..].iter().any(|(m, v)| m == "sendMessage" && v["chat_id"] == 4242 && v["text"].as_str().unwrap_or("").contains("/v2")));
        // a second tap on approve: already decided
        tap_id(&bot, from(ADMIN, "Admin", "admin"), &format!("ap:{}", oid), "qap2").await;
        assert_eq!(answers(&log, "qap2"), vec!["این سفارش قبلاً بررسی شده.".to_string()]);
        // renewing it with the VIP plan makes it a full account
        let pro: i64 = db.with(|c| c.query_row("SELECT id FROM plans WHERE name='Pro'", [], |r| r.get(0)).unwrap());
        bot.start_purchase(buyer, pro, acc[0].id).await;
        tap(&bot, from(buyer, "Nima", "nima"), "pay:card").await;
        say(&bot, from(buyer, "Nima", "nima"), "رسید").await;
        let oid: i64 = buttons(&log, ADMIN).iter().find(|b| b.1.starts_with("ap:")).unwrap().1[3..].parse().unwrap();
        tap(&bot, from(ADMIN, "Admin", "admin"), &format!("ap:{}", oid)).await;
        let u = db.user(acc[0].id).unwrap();
        assert_eq!((u.protocols, db.users_of_tg(buyer).len()), (db.get("default_protocols"), 1));
        // with plans of only one service on sale, the plans show at once (as before)
        db.exec("UPDATE plans SET active=0 WHERE name='Std'", &[]).unwrap();
        tap(&bot, from(buyer, "Nima", "nima"), "buy").await;
        assert!(buttons(&log, buyer).iter().any(|b| b.1 == format!("pl:{}", pro)));
        // the admin menu: four groups
        tap(&bot, from(ADMIN, "Admin", "admin"), "adm").await;
        let g: Vec<String> = buttons(&log, ADMIN).into_iter().map(|b| b.1).collect();
        assert_eq!(g, vec!["ag:o", "ag:u", "ag:s", "ag:t", "home"]);
        tap(&bot, from(ADMIN, "Admin", "admin"), "ag:s").await;
        assert!(buttons(&log, ADMIN).iter().any(|b| b.1 == "a:plans"));
        tap(&bot, from(ADMIN, "Admin", "admin"), "a:plans").await;
        let bs = buttons(&log, ADMIN);
        assert!(bs.iter().any(|b| b.0 == "🟢 🚀 50GB | یک‌ماهه | ۱۹۰,۰۰۰ ت"), "{:?}", bs);
        // the plan's service can be switched from its page
        tap(&bot, from(ADMIN, "Admin", "admin"), &format!("psw:{}", pro)).await;
        let sv: String = db.with(|c| c.query_row("SELECT service FROM plans WHERE id=?1", [pro], |r| r.get(0)).unwrap());
        assert_eq!(sv, "v2ray");
    }

    #[tokio::test]
    async fn kanki_plans_come_once_by_themselves() {
        let (bot, _log) = bot().await;
        let db = bot.db();
        db.exec("INSERT INTO plans(name,days,gb,toman,usd,conns,active) VALUES('Old',30,20,100000,0,2,1)", &[]).unwrap();
        assert!(kanki_plans_once(db));
        let on: i64 = db.with(|c| c.query_row("SELECT COUNT(*) FROM plans WHERE active=1", [], |r| r.get(0)).unwrap());
        assert_eq!(on, 9);
        // the admin's later changes stay: it does not come again
        db.exec("UPDATE plans SET toman=99000 WHERE name LIKE '20 گیگ%'", &[]).unwrap();
        assert!(!kanki_plans_once(db));
        let t: i64 = db.with(|c| c.query_row("SELECT toman FROM plans WHERE active=1 AND name LIKE '20 گیگ%'", [], |r| r.get(0)).unwrap());
        assert_eq!(t, 99000);
    }

    #[tokio::test]
    async fn plan_buttons_read_clearly_by_kind_and_colour() {
        let (bot, log) = bot().await;
        let db = bot.db();
        // a panel that had 3.28's names gets the new ones once
        db.set("kanki_plans_v1", "1");
        db.exec("INSERT INTO plans(name,days,gb,toman,usd,conns,active,category,badge) VALUES('🥉 ۲۰ گیگ · ۱ ماهه',30,20,80000,0,1,1,'تک‌کاربره',''),('💎 ۵۰ گیگ · ۱ ماهه',30,50,110000,0,1,1,'تک‌کاربره','🔥 پیشنهاد ویژه'),('👥 ۵۰ گیگ · ۱ ماهه · ۲ کاربره',30,50,135000,0,2,1,'چندکاربره',''),('⏳ ۵۰ گیگ · ۲ ماهه',60,50,140000,0,1,1,'بلندمدت','')", &[]).unwrap();
        db.exec("UPDATE plans SET old_toman=160000 WHERE days=60", &[]).unwrap();
        kanki_plans_once(db);
        let names: Vec<String> = db.with(|c| { let mut s = c.prepare("SELECT name FROM plans ORDER BY id").unwrap(); let v = s.query_map([], |r| r.get(0)).unwrap().filter_map(|x| x.ok()).collect(); v });
        assert_eq!(names[0], "20 گیگ | 1 ماهه");
        assert_eq!(names[2], "50 گیگ | 2 کاربره | 1 ماهه");
        let buyer = 7201;
        bot.touch(buyer, &from(buyer, "Sara", "sara"), 0);
        db.exec("UPDATE bot_users SET cfg_name='sara' WHERE tg_id=?1", &[&buyer]).unwrap();
        tap(&bot, from(buyer, "Sara", "sara"), "buy").await;
        // each kind: its emoji, its cheapest price and its own colour; the message says what each is for
        let bs = buttons(&log, buyer);
        let single = bs.iter().find(|b| b.1.starts_with("pcat:b:0")).unwrap();
        assert_eq!((single.0.as_str(), single.2.as_str()), ("👤 تک‌کاربره — از 80,000 تومان", "primary"), "{:?}", bs);
        assert!(bs.iter().any(|b| b.0 == "👥 چندکاربره — از 135,000 تومان" && b.2 == "success"), "{:?}", bs);
        assert!(bs.iter().any(|b| b.0 == "⏳ بلندمدت — از 140,000 تومان 🏷" && b.2 == "danger"), "{:?}", bs);
        assert!(last(&log, buyer).contains("👥 <b>چندکاربره</b>"), "{}", last(&log, buyer));
        // a plan: English digits, dashes between, the label's emoji at the end, no medal in front
        tap(&bot, from(buyer, "Sara", "sara"), &single.1).await;
        let bs = buttons(&log, buyer);
        assert!(bs.iter().any(|b| b.0 == "20 گیگ — 1 ماهه — 80,000 تومان" && b.2 == "primary"), "{:?}", bs);
        assert!(bs.iter().any(|b| b.0 == "50 گیگ — 1 ماهه — 110,000 تومان 🔥"), "{:?}", bs);
        assert!(!bs.iter().any(|b| b.0.contains('۰') || b.0.contains('·') || b.0.contains('🥉')), "{:?}", bs);
        assert!(last(&log, buyer).starts_with("👤 <b>تک‌کاربره</b>"), "{}", last(&log, buyer));
    }

    /// A fake toncenter (v3): /transactions lists `txs`, or the one whose hash is asked for
    async fn fake_toncenter(txs: Arc<Mutex<Vec<Value>>>) -> String {
        let router = axum::Router::new().route("/transactions", axum::routing::get(
            move |axum::extract::Query(q): axum::extract::Query<HashMap<String, String>>| {
                let txs = txs.clone();
                async move {
                    let all = txs.lock().unwrap().clone();
                    let list: Vec<Value> = match q.get("hash") {
                        Some(h) => all.into_iter().filter(|t| crate::tunnel::link::b64decode(t["hash"].as_str().unwrap_or("")).map(hex::encode).as_deref() == Some(h.as_str())).collect(),
                        None => all,
                    };
                    axum::Json(json!({"transactions": list}))
                }
            })).route("/transactionsByMessage", axum::routing::get(|| async { axum::Json(json!({"transactions": []})) }));
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(l, router).await.unwrap() });
        format!("http://{}", addr)
    }

    const MY_TON: &str = "UQCD39VS5jcptHL8vMjEXrzGaRcCVYto7HUn4bpAOg8xqEBI";

    fn ton_tx(hash_byte: u8, nano: u64, comment: &str, at: i64) -> Value {
        let hash = crate::util::b64(&[hash_byte; 32]);
        json!({"account": "0:83DFD552E63729B472FCBCC8C45EBCC6691702558B68EC7527E1BA403A0F31A8", "hash": hash, "now": at,
            "description": {"aborted": false, "credit_ph": {"credit": nano.to_string()}},
            "in_msg": {"source": "0:ABCD", "value": nano.to_string(), "bounced": false,
                "message_content": {"decoded": {"type": "text_comment", "comment": comment}}},
            "out_msgs": [], "finality": "finalized"})
    }

    /// A buyer with a name, a plan of 80,000 toman chosen, prices of today cached (271,500 toman a dollar, 1.17 $ a TON)
    async fn paying(bot: &Bot, buyer: i64) -> i64 {
        let db = bot.db();
        db.set("rate_usd_toman", "271500");
        db.set("rate_ton_usd", "1.17");
        db.set("rate_at", &now().to_string());
        db.set("rate_src", "Exir");
        if all_plans(db).is_empty() {
            load_kanki_plans(db);
        }
        bot.touch(buyer, &from(buyer, "Ali", "ali"), 0);
        db.exec("UPDATE bot_users SET cfg_name=?1 WHERE tg_id=?2", &[&format!("ali{}", buyer), &buyer]).unwrap();
        let pid: i64 = db.with(|c| c.query_row("SELECT id FROM plans WHERE toman=80000 AND active=1", [], |r| r.get(0)).unwrap());
        tap(bot, from(buyer, "Ali", "ali"), &format!("pl:{}", pid)).await;
        pid
    }

    fn last_order(bot: &Bot, buyer: i64) -> (i64, String, String, String) {
        bot.db().with(|c| c.query_row("SELECT id,method,status,ref FROM orders WHERE tg_id=?1 ORDER BY id DESC LIMIT 1", [buyer],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))).unwrap())
    }

    #[tokio::test]
    async fn ton_is_delivered_only_for_its_own_payment_on_the_chain() {
        let (bot, log) = bot().await;
        let db = bot.db();
        let txs = Arc::new(Mutex::new(vec![]));
        db.set("toncenter_url", &fake_toncenter(txs.clone()).await);
        db.set("ton_on", "1");
        db.set("ton_address", MY_TON);
        let buyer = 7301;
        paying(&bot, buyer).await;
        // the plan page shows the TON button and the amount at today's price
        assert!(buttons(&log, buyer).iter().any(|b| b.1 == "pay:ton"), "{:?}", buttons(&log, buyer));
        assert!(last(&log, buyer).contains("0.252 TON"), "{}", last(&log, buyer));
        tap(&bot, from(buyer, "Ali", "ali"), "pay:ton").await;
        let (oid, m, st, rf) = last_order(&bot, buyer);
        assert_eq!((m.as_str(), st.as_str()), ("ton", "waiting"));
        let memo = rf.split_whitespace().next().unwrap().to_string();
        assert!(memo.starts_with(&format!("KANKI-{}-", oid)) && rf.ends_with(" 252000000"), "{}", rf);
        let t = last(&log, buyer);
        assert!(t.contains("0.252 TON") && t.contains(&memo) && t.contains("317,655 تومان") && t.contains(MY_TON), "{}", t);
        let kb = log.lock().unwrap().iter().rev().find(|(m, _)| m == "editMessageText").map(|x| x.1["reply_markup"].to_string()).unwrap();
        assert!(kb.contains(&format!("https://app.tonkeeper.com/transfer/{}?amount=252000000&text={}", MY_TON, memo)), "{}", kb);
        // nothing on the chain yet; a payment of someone else (no comment) is not this order's
        txs.lock().unwrap().push(ton_tx(1, 252_000_000, "", now()));
        tap_id(&bot, from(buyer, "Ali", "ali"), &format!("tchk:{}", oid), "q1").await;
        assert!(answers(&log, "q1")[0].contains("هنوز"), "{:?}", answers(&log, "q1"));
        assert!(db.users_of_tg(buyer).is_empty());
        // its own comment and amount: delivered once
        txs.lock().unwrap().push(ton_tx(2, 252_000_000, &memo.to_lowercase(), now()));
        tap_id(&bot, from(buyer, "Ali", "ali"), &format!("tchk:{}", oid), "q2").await;
        assert_eq!(last_order(&bot, buyer).2, "done");
        assert_eq!(db.users_of_tg(buyer).len(), 1);
        assert!(log.lock().unwrap().iter().any(|(m, v)| m == "sendMessage" && v["text"].as_str().unwrap_or("").contains("روی شبکه‌ی TON تأیید شد")));
        // the same transaction cannot pay a second order (sent as a link)
        tap(&bot, from(buyer, "Ali", "ali"), "buy").await;
        paying(&bot, buyer).await;
        tap(&bot, from(buyer, "Ali", "ali"), "pay:ton").await;
        let (oid2, ..) = last_order(&bot, buyer);
        assert!(oid2 > oid);
        say(&bot, from(buyer, "Ali", "ali"), &format!("https://tonviewer.com/transaction/{}", hex::encode([2u8; 32]))).await;
        assert!(last(&log, buyer).contains("⚠️"), "{}", last(&log, buyer));
        assert_eq!(last_order(&bot, buyer).2, "waiting");
        assert_eq!(db.users_of_tg(buyer).len(), 1);
        // a payment short of the amount, with the right comment: not delivered, the admins decide
        let memo2 = last_order(&bot, buyer).3.split_whitespace().next().unwrap().to_string();
        txs.lock().unwrap().push(ton_tx(3, 200_000_000, &memo2, now()));
        bot.ton_check(oid2, None).await.unwrap();
        assert_eq!(last_order(&bot, buyer).2, "pending");
        assert!(buttons(&log, ADMIN).iter().any(|b| b.1 == format!("ap:{}", oid2)), "{:?}", buttons(&log, ADMIN));
        assert!(last(&log, ADMIN).contains("کمتر از مبلغ"), "{}", last(&log, ADMIN));
        assert_eq!(db.users_of_tg(buyer).len(), 1);
        // a TON address with a wrong checksum is not saved
        tap(&bot, from(ADMIN, "Admin", "admin"), "set:ton_address").await;
        say(&bot, from(ADMIN, "Admin", "admin"), "UQCD39VS5jcptHL8vMjEXrzGaRcCVYto7HUn4bpAOg8xqEBJ").await;
        assert_eq!(db.get("ton_address"), MY_TON);
    }

    #[tokio::test]
    async fn stars_are_delivered_only_when_telegram_says_paid() {
        let (bot, log) = bot().await;
        let db = bot.db();
        db.set("stars_on", "1");
        let buyer = 7401;
        paying(&bot, buyer).await;
        assert!(last(&log, buyer).contains("⭐️ 23 استارز"), "{}", last(&log, buyer));
        tap(&bot, from(buyer, "Ali", "ali"), "pay:stars").await;
        let (oid, m, st, rf) = last_order(&bot, buyer);
        assert_eq!((m.as_str(), st.as_str()), ("stars", "waiting"));
        let inv = log.lock().unwrap().iter().rev().find(|(m, _)| m == "sendInvoice").map(|x| x.1.clone()).unwrap();
        assert_eq!((inv["currency"].as_str(), inv["prices"][0]["amount"].as_i64()), (Some("XTR"), Some(23)));
        let payload = inv["payload"].as_str().unwrap().to_string();
        assert_eq!(payload, format!("kk:{}:{}", oid, rf.split_whitespace().next().unwrap()));
        let pre = |id: &str, uid: i64, total: i64, payload: &str| json!({"id": id, "from": from(uid, "Ali", "ali"), "currency": "XTR", "total_amount": total, "invoice_payload": payload});
        let pre_ok = |id: &str| log.lock().unwrap().iter().rev().find(|(m, v)| m == "answerPreCheckoutQuery" && v["pre_checkout_query_id"] == id).map(|x| x.1["ok"].as_bool().unwrap()).unwrap();
        // Telegram asks first: a changed amount, another customer or a made-up order are refused
        bot.on_pre_checkout(&pre("p1", buyer, 1, &payload)).await;
        assert!(!pre_ok("p1"));
        bot.on_pre_checkout(&pre("p2", 9999, 23, &payload)).await;
        assert!(!pre_ok("p2"));
        bot.on_pre_checkout(&pre("p3", buyer, 23, &format!("kk:{}:guess", oid))).await;
        assert!(!pre_ok("p3"));
        bot.on_pre_checkout(&pre("p4", buyer, 23, &payload)).await;
        assert!(pre_ok("p4"));
        // tapping pay is not paying: nothing until Telegram's own successful_payment
        assert!(db.users_of_tg(buyer).is_empty());
        let paid = |uid: i64, total: i64, charge: &str| json!({"from": from(uid, "Ali", "ali"), "chat": {"id": uid},
            "successful_payment": {"currency": "XTR", "total_amount": total, "invoice_payload": payload, "telegram_payment_charge_id": charge}});
        bot.on_stars_paid(&paid(buyer, 23, "ch1")).await;
        assert_eq!(last_order(&bot, buyer).2, "done");
        assert_eq!(db.users_of_tg(buyer).len(), 1);
        // the same payment again: nothing more
        bot.on_stars_paid(&paid(buyer, 23, "ch1")).await;
        assert_eq!(db.users_of_tg(buyer).len(), 1);
        // a payment for an order that is no longer waiting: given back
        bot.on_stars_paid(&paid(buyer, 23, "ch2")).await;
        assert!(log.lock().unwrap().iter().any(|(m, v)| m == "refundStarPayment" && v["telegram_payment_charge_id"] == "ch2"));
        assert_eq!(db.users_of_tg(buyer).len(), 1);
    }

    #[tokio::test]
    async fn the_connection_guide_by_device_and_app() {
        let (bot, log) = bot().await;
        let db = bot.db();
        let tg = 7501;
        bot.touch(tg, &from(tg, "Reza", "reza"), 0);
        let u = bot.create_account(tg, 50.0, 30, 1, "test").unwrap();
        db.set("app_link", "https://example.com/kanki.apk");
        // Android: the Kanki app first (recommended), with the login code; Windows offers it only with a https link
        assert_eq!(bot.how_apps(&u, "a").first(), Some(&"k"));
        assert!(!bot.how_apps(&u, "w").contains(&"k") && !bot.how_apps(&u, "i").contains(&"k"));
        db.set("win_link", "https://github.com/x/KankiVPN-Setup.exe");
        assert_eq!(bot.how_apps(&u, "w").first(), Some(&"k"));
        tap(&bot, from(tg, "Reza", "reza"), &format!("hw:{}:a", u.id)).await;
        let bs = buttons(&log, tg);
        assert_eq!((bs[0].0.as_str(), bs[0].2.as_str()), ("⭐️ اپ اختصاصی Kanki VPN", "success"), "{:?}", bs);
        tap(&bot, from(tg, "Reza", "reza"), &format!("hw:{}:a:k", u.id)).await;
        assert!(last(&log, tg).contains(&u.sub_code()), "{}", last(&log, tg));
        // an app that is not offered for this account (no WireGuard server here): refused
        tap_id(&bot, from(tg, "Reza", "reza"), &format!("hw:{}:i:g", u.id), "qg").await;
        assert!(answers(&log, "qg")[0].contains("فعال نیست"));
        // a tutorial pinned to «Kanki · Android» comes with it; the admin pins it with a switch
        bot.save_guides(&[json!({"id": 1, "title": "Kanki", "kind": "text", "file": "", "caption": "ویدیوی کانکی"})]);
        tap(&bot, from(ADMIN, "Admin", "admin"), "gwt:1:k:a").await;
        assert_eq!(bot.guide(1).unwrap()["for"], json!(["k:a"]));
        tap(&bot, from(tg, "Reza", "reza"), &format!("hw:{}:a:k", u.id)).await;
        assert_eq!(last(&log, tg), "ویدیوی کانکی");
        tap(&bot, from(ADMIN, "Admin", "admin"), "gwt:1:k:a").await;
        assert_eq!(bot.guide(1).unwrap()["for"], json!([]));
        // the account's buttons: the devices first, no rename; the V2Ray link comes as one message with how to add it
        let kb = bot.acct_kb(&u, vec![]).to_string();
        assert!(kb.contains(&format!("hw:{}:a", u.id)) && !kb.contains("ren:"), "{}", kb);
        tap(&bot, from(tg, "Reza", "reza"), &format!("cfg:{}:v", u.id)).await;
        let t = last(&log, tg);
        assert!(t.contains("لینک اشتراک V2Ray") && t.contains("/v2") && t.contains("Import v2ray uri from clipboard"), "{}", t);
    }

    /// A fake Telegram that says «too many requests» to the first `busy` calls, then takes them
    async fn busy_telegram(busy: usize) -> (String, Arc<std::sync::atomic::AtomicUsize>) {
        let n = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let n2 = n.clone();
        let router = axum::Router::new().route("/:bot/:method", axum::routing::post(move || {
            let n = n2.clone();
            async move {
                let i = n.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                axum::Json(if i < busy { json!({"ok": false, "error_code": 429, "description": "Too Many Requests: retry after 1", "parameters": {"retry_after": 1}}) } else { json!({"ok": true, "result": {"message_id": 7}}) })
            }
        }));
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(l, router).await.unwrap() });
        (format!("http://{}", addr), n)
    }

    fn bot_at(app: Arc<App>, api: &str, token: &str) -> Bot {
        Bot { app, token: token.into(), admins: vec![ADMIN], http: reqwest::Client::new(), api: api.into(),
            waits: Mutex::new(HashMap::new()), pend: Mutex::new(HashMap::new()), answered: Mutex::new(Default::default()), gifts: Mutex::new(HashMap::new()),
            order_msgs: Mutex::new(HashMap::new()), members: Mutex::new(HashMap::new()), me_name: Mutex::new(String::new()) }
    }

    #[tokio::test]
    async fn telegram_is_asked_again_and_the_token_never_shows() {
        let (bot, log) = bot().await;
        // «too many requests» twice: the message still goes, after the wait Telegram asked for
        let (api, n) = busy_telegram(2).await;
        let b2 = bot_at(bot.app.clone(), &api, "SECRET123TOKEN");
        assert!(b2.send(7, "hi", None).await.is_some());
        assert_eq!(n.load(std::sync::atomic::Ordering::SeqCst), 3);
        // Telegram cannot be reached: the error says why without the address (it holds the token)
        let b3 = bot_at(bot.app.clone(), "http://127.0.0.1:1", "SECRET123TOKEN");
        let e = b3.call_res("sendMessage", json!({"chat_id": 7, "text": "x"})).await.unwrap_err();
        assert!(!e.contains("SECRET123TOKEN") && !e.contains("/bot"), "{}", e);
        // one customer tapping too fast is held after 20 taps in 10 seconds; an admin never
        let tap_u = |id: i64| json!({"callback_query": {"id": "f", "from": {"id": id}, "data": "home"}});
        assert!((0..20).all(|_| bot.flood(&tap_u(7601)).is_none()));
        assert!(bot.flood(&tap_u(7601)).is_some());
        assert!((0..30).all(|_| bot.flood(&tap_u(ADMIN)).is_none()));
        // a payment is never held
        assert!(bot.flood(&json!({"message": {"from": {"id": 7601}, "successful_payment": {}}})).is_none());
        // renaming from an old button: only the admin
        let tg = 7602;
        bot.touch(tg, &from(tg, "Nima", "nima"), 0);
        let u = bot.create_account(tg, 10.0, 30, 1, "x").unwrap();
        tap_id(&bot, from(tg, "Nima", "nima"), &format!("ren:{}", u.id), "qr").await;
        assert!(answers(&log, "qr")[0].contains("پشتیبانی"));
        say(&bot, from(tg, "Nima", "nima"), "hacked1").await;
        assert_ne!(bot.db().user(u.id).unwrap().username, "hacked1");
        // discount codes: 5 tries an hour
        for _ in 0..5 {
            tap(&bot, from(tg, "Nima", "nima"), "disc").await;
            say(&bot, from(tg, "Nima", "nima"), "GUESS").await;
            assert!(last(&log, tg).contains("نامعتبر"), "{}", last(&log, tg));
        }
        tap(&bot, from(tg, "Nima", "nima"), "disc").await;
        say(&bot, from(tg, "Nima", "nima"), "GUESS").await;
        assert!(last(&log, tg).contains("یک ساعت بعد"), "{}", last(&log, tg));
    }

    #[tokio::test]
    async fn kanki_plans_replace_the_listed_ones() {
        let (bot, log) = bot().await;
        let db = bot.db();
        db.exec("INSERT INTO plans(name,days,gb,toman,usd,conns,active) VALUES('Old',30,10,50000,0,1,1)", &[]).unwrap();
        tap(&bot, from(ADMIN, "Admin", "admin"), "pkp").await;
        assert!(last(&log, ADMIN).contains("۹ پلن") || last(&log, ADMIN).contains("پلن‌های کانکی"));
        tap(&bot, from(ADMIN, "Admin", "admin"), "pkpy").await;
        let on: Vec<(String, i64, i64, String, String)> = db.with(|c| { let mut s = c.prepare("SELECT name,toman,old_toman,badge,category FROM plans WHERE active=1 ORDER BY id").unwrap();
            let v = s.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))).unwrap().filter_map(|x| x.ok()).collect(); v });
        assert_eq!(on.len(), 9);
        assert!(on.iter().any(|p| p.1 == 110000 && p.3 == "🔥 پیشنهاد ویژه" && p.4 == "تک‌کاربره"));
        assert!(on.iter().any(|p| p.1 == 260000 && p.2 == 330000 && p.4 == "بلندمدت"));
        let old: i64 = db.with(|c| c.query_row("SELECT active FROM plans WHERE name='Old'", [], |r| r.get(0)).unwrap());
        assert_eq!(old, 0, "the old plan is hidden, not deleted");
    }

    #[tokio::test]
    async fn the_menu_never_wipes_a_delivered_config() {
        let (bot, log) = bot().await;
        let c = 7702;
        let tap_on = |text: &str, data: &str| json!({"id": "q", "from": from(c, "Ali", "ali"), "data": data,
            "message": {"message_id": 55, "chat": {"id": c}, "text": text}});
        let count = |m: &str| log.lock().unwrap_or_else(|e| e.into_inner()).iter().filter(|(x, v)| x == m && v["chat_id"] == c).count();
        // «main menu» under the subscription message: a new menu, the subscription stays
        bot.on_callback(&tap_on("🔗 لینک اشتراک: https://panel.example.com/sub/abc/v2", "home")).await;
        assert_eq!((count("editMessageText"), count("sendMessage")), (0, 1));
        // under a plain menu: edited in place, no new message
        bot.on_callback(&tap_on("از منوی زیر استفاده کنید", "home")).await;
        assert_eq!((count("editMessageText"), count("sendMessage")), (1, 1));
        // under a config file: a new message too
        bot.on_callback(&json!({"id": "q2", "from": from(c, "Ali", "ali"), "data": "home", "message": {"message_id": 56, "chat": {"id": c}, "document": {"file_id": "x"}}})).await;
        assert_eq!((count("editMessageText"), count("sendMessage")), (1, 2));
    }

    /// Telegram that refuses every premium emoji on a button (the owner's Premium ended)
    async fn no_premium_telegram() -> (String, Log) {
        let log: Log = Arc::new(Mutex::new(vec![]));
        let l2 = log.clone();
        let router = axum::Router::new().route("/:bot/:method", axum::routing::post(move |axum::extract::Path((_b, m)): axum::extract::Path<(String, String)>, body: String| {
            let l = l2.clone();
            async move {
                let v: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
                let refuse = body.contains("icon_custom_emoji_id");
                l.lock().unwrap_or_else(|e| e.into_inner()).push((m, v));
                axum::Json(if refuse { json!({"ok": false, "error_code": 400, "description": "Bad Request: custom emoji can't be used by the bot"}) } else { json!({"ok": true, "result": {"message_id": 7}}) })
            }
        }));
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(l, router).await.unwrap() });
        (format!("http://{}", addr), log)
    }

    #[tokio::test]
    async fn a_button_gets_its_premium_emoji() {
        let (bot, log) = bot().await;
        const ID: &str = "5368324170671202286";
        // the admin opens the button and sends a message with a premium emoji in it
        tap(&bot, from(ADMIN, "Admin", "admin"), "bic:buy").await;
        bot.on_message(&json!({"from": from(ADMIN, "Admin", "admin"), "chat": {"id": ADMIN}, "text": "🔥",
            "entities": [{"type": "custom_emoji", "offset": 0, "length": 2, "custom_emoji_id": ID}]})).await;
        assert_eq!(crate::buttons::icons(bot.db()).get("buy").map(|s| s.as_str()), Some(ID));
        // a customer's menu: the emoji on the button, the plain one of its text gone
        let c = 7701;
        say(&bot, from(c, "Sara", "sara"), "/start").await;
        let l = log.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let (_, v) = l.iter().rev().find(|(m, v)| m == "sendMessage" && v["chat_id"] == c && v["reply_markup"]["inline_keyboard"].is_array()).expect("a menu");
        let btn = v["reply_markup"]["inline_keyboard"].as_array().unwrap().iter().flat_map(|r| r.as_array().unwrap().clone())
            .find(|b| b["icon_custom_emoji_id"] == ID).expect("the buy button has the emoji");
        assert_eq!(btn["text"], "خرید اشتراک");
        // a text that is not a premium emoji is refused and nothing changes
        tap(&bot, from(ADMIN, "Admin", "admin"), "bic:trial").await;
        say(&bot, from(ADMIN, "Admin", "admin"), "🔥").await;
        assert!(last(&log, ADMIN).contains("پریمیوم نیست"), "{}", last(&log, ADMIN));
        assert!(!crate::buttons::icons(bot.db()).contains_key("trial"));
        // a message text keeps its premium emoji
        tap(&bot, from(ADMIN, "Admin", "admin"), "set:welcome").await;
        bot.on_message(&json!({"from": from(ADMIN, "Admin", "admin"), "chat": {"id": ADMIN}, "text": "سلام 🔥",
            "entities": [{"type": "custom_emoji", "offset": 5, "length": 2, "custom_emoji_id": ID}]})).await;
        assert_eq!(bot.db().get("welcome"), format!("سلام <tg-emoji emoji-id=\"{}\">🔥</tg-emoji>", ID));

        // Telegram refuses premium emoji: the customer still gets the message, with the plain buttons
        let (api, log2) = no_premium_telegram().await;
        let b2 = bot_at(bot.app.clone(), &api, "T");
        assert!(b2.send(c, "menu", Some(ik(vec![vec![b(&b2.bt("buy"), "buy")]]))).await.is_some());
        let sent: Vec<Value> = log2.lock().unwrap_or_else(|e| e.into_inner()).iter().map(|x| x.1.clone()).collect();
        assert_eq!(sent.len(), 2);
        assert_eq!(sent[1]["reply_markup"]["inline_keyboard"][0][0]["text"], "🛒 خرید اشتراک");
        // and a new emoji is not saved
        assert!(!b2.try_icon(ADMIN, "trial", ID).await);
        assert!(!crate::buttons::icons(bot.db()).contains_key("trial"));
    }

    /// The answers Telegram got for one button tap (callback id)
    fn answers(log: &Log, qid: &str) -> Vec<String> {
        log.lock().unwrap_or_else(|e| e.into_inner()).iter()
            .filter(|(m, v)| m == "answerCallbackQuery" && v["callback_query_id"].as_str() == Some(qid))
            .map(|(_, v)| v["text"].as_str().unwrap_or("").to_string()).collect()
    }

    async fn tap_id(bot: &Bot, f: Value, data: &str, qid: &str) {
        let chat = f["id"].clone();
        bot.on_callback(&json!({"id": qid, "from": f, "data": data, "message": {"message_id": 5, "chat": {"id": chat}}})).await;
    }

    #[tokio::test]
    async fn sales_discounts_orders_and_button_answers() {
        let (bot, log) = bot().await;
        let db = bot.db();
        db.set("card_on", "1");
        db.set("card_number", "6037000011112222");
        let plan = db.with(|c| {
            c.execute("INSERT INTO plans(name,days,gb,toman,usd,conns,active) VALUES('m',30,10,100000,1,1,1)", []).unwrap();
            c.last_insert_rowid()
        });
        let buyer = 5001;
        let f = || from(buyer, "Sara", "sara");
        bot.touch(buyer, &f(), 0);
        db.exec("UPDATE bot_users SET cfg_name='sara' WHERE tg_id=?1", &[&buyer]).unwrap();

        // every tap is answered exactly once: empty, or with the handler's own alert
        tap_id(&bot, f(), "home", "q1").await;
        assert_eq!(answers(&log, "q1"), vec![String::new()]);
        let done = order(&bot, buyer, plan, "new", 0, "done");
        tap_id(&bot, f(), &format!("chk:{}", done), "q2").await;
        assert_eq!(answers(&log, "q2"), vec!["این سفارش قبلاً فعال شده ✅".to_string()]);
        // an order that is gone (its account was deleted): the admin's approve says so
        tap_id(&bot, from(ADMIN, "Admin", "admin"), "ap:99999", "q3").await;
        assert_eq!(answers(&log, "q3").len(), 1);
        assert!(answers(&log, "q3")[0].contains("دیگر وجود ندارد"));

        // a one-use code: typed, paid once, then gone from the purchase (an old «card» button pays full price)
        db.exec("INSERT INTO discounts(code,percent,uses_left) VALUES('OFF50',50,1)", &[]).unwrap();
        tap(&bot, f(), &format!("pl:{}", plan)).await;
        tap(&bot, f(), "disc").await;
        say(&bot, f(), "off50").await;
        assert!(last(&log, buyer).contains("50,000"), "{}", last(&log, buyer));
        tap(&bot, f(), "pay:card").await;
        say(&bot, f(), "رسید").await;
        assert!(bot.pend.lock().unwrap().get(&buyer).map(|p| p.discount.is_empty()).unwrap_or(false));
        tap(&bot, f(), "pay:card").await;
        assert!(last(&log, buyer).contains("100,000"), "{}", last(&log, buyer));
        say(&bot, f(), "رسید ۲").await;
        let codes: Vec<String> = db.with(|c| {
            let mut s = c.prepare("SELECT discount FROM orders WHERE tg_id=?1 AND status='pending' ORDER BY id").unwrap();
            let v: Vec<String> = s.query_map([buyer], |r| r.get(0)).unwrap().filter_map(|x| x.ok()).collect();
            v
        });
        assert_eq!(codes, vec!["OFF50".to_string(), String::new()]);
        // a code deleted after it was typed: the payment shows the price again without it
        db.exec("INSERT INTO discounts(code,percent,uses_left) VALUES('GONE',20,5)", &[]).unwrap();
        tap(&bot, f(), "disc").await;
        say(&bot, f(), "gone").await;
        db.exec("DELETE FROM discounts WHERE code='GONE'", &[]).unwrap();
        tap(&bot, f(), "pay:card").await;
        let l = log.lock().unwrap().iter().rev().filter(|(m, v)| m == "sendMessage" && v["chat_id"].as_i64() == Some(buyer)).take(2)
            .map(|(_, v)| v["text"].as_str().unwrap_or("").to_string()).collect::<Vec<_>>();
        assert!(l.iter().any(|t| t.contains("دیگر معتبر نیست")) && l.iter().any(|t| t.contains("100,000")), "{:?}", l);

        // closed sales: an old plan, renewal or payment button sells nothing
        db.set("sales_on", "0");
        bot.pend.lock().unwrap().clear();
        for d in [format!("pl:{}", plan), "pay:card".to_string(), "rnw:1".to_string(), "npc:trx".to_string()] {
            tap(&bot, f(), &d).await;
            assert_eq!(last(&log, buyer), SALES_CLOSED, "{}", d);
        }
        assert!(bot.pend.lock().unwrap().get(&buyer).is_none());
        db.set("sales_on", "1");

        // NOWPayments: a coin that is not offered is refused
        db.set("np_on", "1");
        db.set("np_key", "k");
        db.set("np_coins", "trx");
        tap(&bot, f(), &format!("pl:{}", plan)).await;
        tap(&bot, f(), "npc:<b>x</b>").await;
        assert!(last(&log, buyer).contains("این ارز"), "{}", last(&log, buyer));

        // a paid order whose plan was deleted: kept as an error, both sides told
        let gone_plan = db.with(|c| {
            c.execute("INSERT INTO plans(name,days,gb,toman,usd,conns,active) VALUES('old',30,10,1000,0,1,1)", []).unwrap();
            c.last_insert_rowid()
        });
        let o = order(&bot, buyer, gone_plan, "new", 0, "approved");
        db.exec("DELETE FROM plans WHERE id=?1", &[&gone_plan]).unwrap();
        bot.fulfill(o).await;
        assert_eq!(bot.order(o).unwrap().6, "error");
        assert!(last(&log, buyer).contains("پلن آن دیگر وجود ندارد"));
        assert!(last(&log, ADMIN).contains(&format!("#{}", o)));

        // a renewal of an account that is gone makes a new account and says so
        let o = order(&bot, buyer, plan, "renew", 0, "approved");
        bot.fulfill(o).await;
        assert!(last(&log, buyer).contains("خرید شما با موفقیت انجام شد"), "{}", last(&log, buyer));

        // a referrer with no account yet keeps the reward for later
        let friend = 5002;
        bot.touch(friend, &from(friend, "Ali", "ali"), 5099);
        bot.reward_referrer(friend).await;
        let r: i64 = db.with(|c| c.query_row("SELECT ref_rewarded FROM bot_users WHERE tg_id=?1", [friend], |r| r.get(0)).unwrap());
        assert_eq!(r, 0);

        // custom purchase plans are not the admin's plans, and have no on/off
        let custom = crate::shop::custom_plan(db, 25, 30, 1).unwrap_or_else(|_| {
            db.with(|c| {
                c.execute("INSERT INTO plans(name,days,gb,toman,usd,conns,active) VALUES('دلخواه',30,25,1,0,1,2)", []).unwrap();
                c.last_insert_rowid()
            })
        });
        tap(&bot, from(ADMIN, "Admin", "admin"), "a:plans").await;
        assert!(!buttons(&log, ADMIN).iter().any(|b| b.1 == format!("pv:{}", custom)));
        tap(&bot, from(ADMIN, "Admin", "admin"), &format!("pt:{}", custom)).await;
        let a: i64 = db.with(|c| c.query_row("SELECT active FROM plans WHERE id=?1", [custom], |r| r.get(0)).unwrap());
        assert_eq!(a, 2);

        // a customer who writes again is not blocked any more
        db.exec("UPDATE bot_users SET blocked=1 WHERE tg_id=?1", &[&buyer]).unwrap();
        say(&bot, f(), "سلام").await;
        let bl: i64 = db.with(|c| c.query_row("SELECT blocked FROM bot_users WHERE tg_id=?1", [buyer], |r| r.get(0)).unwrap());
        assert_eq!(bl, 0);

        // gateway orders left unpaid expire; old started purchases are dropped
        let w = order(&bot, buyer, plan, "new", 0, "waiting");
        db.exec("UPDATE orders SET method='zp', created=?1 WHERE id=?2", &[&(now() - 2 * 86400), &w]).unwrap();
        let fresh = order(&bot, buyer, plan, "new", 0, "waiting");
        db.exec("UPDATE orders SET method='np' WHERE id=?1", &[&fresh]).unwrap();
        assert_eq!(bot.expire_waiting(now()), 1);
        assert_eq!((bot.order(w).unwrap().6, bot.order(fresh).unwrap().6), ("expired".to_string(), "waiting".to_string()));
        bot.pend.lock().unwrap().clear();
        bot.pend.lock().unwrap().insert(1, Pending { at: now() - PEND_TTL - 1, ..Default::default() });
        bot.pend.lock().unwrap().insert(2, Pending::default());
        bot.prune_pend(now());
        let keys: Vec<i64> = bot.pend.lock().unwrap().keys().copied().collect();
        assert_eq!(keys, vec![2]);
    }

    #[test]
    fn only_a_gone_chat_marks_a_customer_blocked() {
        assert!(gone_chat("Forbidden: bot was blocked by the user"));
        assert!(gone_chat("Bad Request: chat not found"));
        assert!(gone_chat("Forbidden: user is deactivated"));
        assert!(!gone_chat("Too Many Requests: retry after 5"));
        assert!(!gone_chat("error sending request for url"));
    }

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
        log.lock().unwrap_or_else(|e| e.into_inner()).iter().rev()
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
        let kb = log.lock().unwrap_or_else(|e| e.into_inner()).iter().rev().find(|(m, _)| m == "editMessageText").map(|(_, v)| v["reply_markup"].to_string()).unwrap();
        assert!(kb.contains("apk:arm64-v8a") && kb.contains("38.2 MB"), "{}", kb);
        tap(&bot, u.clone(), "apk:arm64-v8a").await;
        let sent = log.lock().unwrap_or_else(|e| e.into_inner()).iter().rev().find(|(m, _)| m == "sendDocument").map(|(_, v)| v.clone()).unwrap();
        assert_eq!(sent["document"], "FILE1");
        assert!(sent["caption"].as_str().unwrap().contains("Kanki VPN 1.15.1 · arm64"));
        // the channel's "download the app" link opens the same menu right away
        say(&bot, from(501, "رضا", ""), "/start app").await;
        let m = log.lock().unwrap_or_else(|e| e.into_inner()).iter().rev().find(|(m, v)| m == "sendMessage" && v["chat_id"] == 501).map(|(_, v)| v.clone()).unwrap();
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

        // B: asked too, with the English letters of the Telegram name as a one-tap answer; a taken name gets a number
        let bb = from(200, "Mahtab87 ✨", "");
        tap(&bot, bb.clone(), "trial").await;
        assert!(accounts(&bot, 200).is_empty());
        assert!(buttons(&log, 200).iter().any(|b| b.0 == "⏭ همون اسم تلگرامم: mahtab87" && b.1 == "cfgsk:trial"), "{:?}", buttons(&log, 200));
        tap(&bot, bb.clone(), "cfgsk:trial").await;
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

        // only the admin renames an account (the owner asked: customers do not): rules and taken names are checked
        tap(&bot, bb.clone(), "ren:2").await;
        say(&bot, bb.clone(), "sara99").await;
        assert_eq!(accounts(&bot, 200)[0].1, "mahtab872");
        let adm = from(ADMIN, "Admin", "admin");
        tap(&bot, adm.clone(), "ren:2").await;
        assert!(last(&log, ADMIN).contains("نام فعلی"));
        say(&bot, adm.clone(), "ERFAN").await;
        assert!(last(&log, ADMIN).contains("قبلاً گرفته شده"));
        say(&bot, adm.clone(), "sara22").await;
        assert_eq!(accounts(&bot, 200)[0].1, "sara22");
        // nor anyone else
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

#[cfg(test)]
mod alert_tests {
    use super::alert_text;

    #[test]
    fn each_alert_says_what_happened() {
        assert_eq!(alert_text("node:tr", "نود TURKEY", false, ""), "🔴 <b>نود TURKEY</b> آفلاین است");
        assert_eq!(alert_text("ts:abc", "سرور تانل IRAN1", true, ""), "🟢 <b>سرور تانل IRAN1</b> دوباره آنلاین شد");
        assert!(alert_text("tu:t1", "تانل IR1-TURKEY", false, "").contains("قطع است"));
        assert_eq!(alert_text("tp:t1", "تانل IR1-TURKEY", false, "950"), "🟠 پینگ <b>تانل IR1-TURKEY</b> بالاست: <b>950 ms</b>");
        assert!(alert_text("tp:t1", "تانل IR1-TURKEY", true, "120").contains("عادی شد"));
    }
}
