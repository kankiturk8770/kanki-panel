//! Smart channel manager for the sales bot.
//!
//! The bot (as an admin of your Telegram channel) writes and publishes posts on its own:
//! price lists made from your real plans, discount campaigns with a fresh code, tips, how-to
//! guides, free-trial and referral invitations, trust posts with live numbers, and greetings for
//! Iranian occasions (Nowruz, Yalda, …). Texts are put together from a word bank so posts do not
//! repeat, nothing is sent at night (quiet hours), and every post carries a "buy from the bot"
//! button. Discount codes made here work in the bot right away and expire on their own.

use crate::api::err;
use crate::guard;
use crate::util::{esc, now};
use crate::App;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use rand::seq::SliceRandom;
use rand::Rng;
use serde_json::{json, Value};
use std::sync::Arc;

type St = State<Arc<App>>;

/// Iran time (UTC+3:30, no daylight saving)
const TZ: i64 = 12600;

pub const KINDS: &[(&str, &str)] = &[
    ("plans", "Price list"),
    ("offer", "Discount campaign"),
    ("tip", "Tip"),
    ("guide", "How to connect"),
    ("trial", "Free trial"),
    ("ref", "Invite friends"),
    ("trust", "Why us"),
    ("occasion", "Occasion greeting"),
];

// ------------------------------------------------------------------ word bank

const HOOK: &[&str] = &[
    "اینترنت آزاد، بدون دردسر", "سرعت واقعی، نه وعده", "وصل بمون، هر جا که هستی", "دیگه با قطعی کنار نیا",
    "یه بار وصل شو، خیالت راحت", "اینترنت پرسرعت و پایدار", "بدون قطعی، بدون محدودیت", "اتصال امن و همیشگی",
    "پینگ پایین، سرعت بالا", "فیلترشکن حرفه‌ای با پشتیبانی واقعی",
];
const BENEFIT: &[&str] = &[
    "⚡️ سرعت بالا روی همه اپراتورها (همراه اول، ایرانسل، رایتل، مخابرات)",
    "🛡 رمزنگاری کامل؛ اطلاعاتت فقط مال خودته",
    "🎮 پینگ پایین برای گیم و تماس تصویری",
    "📺 یوتیوب، اینستاگرام و تلگرام بدون لگ",
    "🔁 اگر یک سرور مشکل داشت، خودکار سرور دیگر",
    "📱 یک لینک برای اندروید، آیفون، ویندوز و مک",
    "🧑‍💻 پشتیبانی سریع و واقعی",
    "♻️ تمدید ساده با یک کلیک داخل ربات",
    "🌍 چند کشور مختلف در یک اشتراک",
    "🔒 بدون ثبت لاگ از فعالیت شما",
    "💳 پرداخت کارت به کارت و آنلاین",
    "⏱ تحویل خودکار و فوری بعد از پرداخت",
];
const CTA: &[&str] = &[
    "👇 همین الان از ربات بخر و ظرف چند ثانیه وصل شو", "👇 برای خرید روی دکمه زیر بزن", "👇 خرید و تحویل فوری از ربات",
    "👇 اول تست بگیر، بعد خرید کن", "👇 جا نمونی؛ از ربات سفارش بده", "👇 فقط با یک کلیک، وصل شو",
];
const TIPS: &[&str] = &[
    "اگر سرعت کم شد، یک‌بار اتصال را قطع و وصل کن؛ معمولاً سرور بهتری انتخاب می‌شود.",
    "روی اینترنت همراه، پروتکل Hysteria2 معمولاً سریع‌تر و پایدارتر است.",
    "روی وای‌فای خانه، WireGuard کم‌مصرف‌ترین و سریع‌ترین گزینه است.",
    "اگر یک اپراتور اذیت می‌کند، AmneziaWG را امتحان کن؛ برای عبور از محدودیت ساخته شده.",
    "لینک اشتراکت را با کسی به اشتراک نگذار؛ تعداد اتصال همزمان محدود است.",
    "حجم و زمان باقی‌مانده را هر وقت خواستی از بخش «سرویس‌های من» در ربات ببین.",
    "قبل از تمام شدن اشتراک، ربات خبرت می‌کند تا بدون قطعی تمدید کنی.",
    "باتری زیاد مصرف می‌شود؟ در تنظیمات گوشی، بهینه‌سازی باتری را برای اپ خاموش کن تا وسط کار قطع نشود.",
    "برای بازی آنلاین، نزدیک‌ترین سرور با کمترین پینگ را انتخاب کن.",
    "اگر وصل نمی‌شوی، ساعت و تاریخ گوشی را روی خودکار بگذار؛ اختلاف ساعت اتصال را خراب می‌کند.",
];
const GUIDE: &[&str] = &[
    "1️⃣ از ربات اشتراک بخر یا تست بگیر\n2️⃣ لینک اشتراک را کپی کن\n3️⃣ اپ را باز کن و لینک را وارد کن\n4️⃣ روی اتصال بزن ✅",
    "📱 اندروید: اپ را از ربات دانلود کن، کد اشتراک را بزن و وصل شو.\n🍏 آیفون: WireGuard یا Hiddify را نصب کن و لینک را اضافه کن.\n💻 ویندوز / مک: WireGuard را نصب کن و فایل کانفیگ را وارد کن.",
];
const HASHTAG: &[&str] = &["#فیلترشکن", "#vpn", "#اینترنت_آزاد", "#وی_پی_ان", "#سرعت", "#پرسرعت", "#امن"];

fn pick<'a>(r: &mut impl Rng, v: &'a [&'a str]) -> &'a str {
    v.choose(r).copied().unwrap_or("")
}

fn toman(n: i64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, ch) in s.chars().enumerate() {
        if i > 0 && (s.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(ch);
    }
    format!("{} تومان", out)
}

// ------------------------------------------------------------------ Jalali calendar

/// Gregorian -> Jalali (year, month, day)
pub fn jalali(gy: i64, gm: i64, gd: i64) -> (i64, i64, i64) {
    let g_d_m = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
    let gy2 = if gm > 2 { gy + 1 } else { gy };
    let mut days = 355666 + (365 * gy) + ((gy2 + 3) / 4) - ((gy2 + 99) / 100) + ((gy2 + 399) / 400) + gd + g_d_m[(gm - 1) as usize];
    let mut jy = -1595 + (33 * (days / 12053));
    days %= 12053;
    jy += 4 * (days / 1461);
    days %= 1461;
    if days > 365 {
        jy += (days - 1) / 365;
        days = (days - 1) % 365;
    }
    let (jm, jd) = if days < 186 { (1 + days / 31, 1 + days % 31) } else { (7 + (days - 186) / 30, 1 + (days - 186) % 30) };
    (jy, jm, jd)
}

/// Unix time -> Gregorian date (UTC)
fn ymd(ts: i64) -> (i64, i64, i64) {
    let z = ts.div_euclid(86400) + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Today's Iranian occasion, if any: (name, greeting, suggested discount %)
fn occasion(ts: i64) -> Option<(&'static str, &'static str, i64)> {
    let (gy, gm, gd) = ymd(ts + TZ);
    let (_, jm, jd) = jalali(gy, gm, gd);
    match (jm, jd) {
        (12, 25..=29) | (12, 30) => Some(("Nowruz", "🌸 حال‌وهوای نوروز است! سال نو را با اینترنت آزاد شروع کن.", 25)),
        (1, 1..=4) => Some(("Nowruz", "🌷 نوروزتان پیروز! سال نو مبارک.", 25)),
        (1, 13) => Some(("Sizdah", "🌿 سیزده‌به‌در مبارک! طبیعت‌گردی با اینترنت بی‌دغدغه.", 15)),
        (9, 30) => Some(("Yalda", "🍉 شب یلدا مبارک! طولانی‌ترین شب سال را بدون قطعی بگذران.", 20)),
        (7, 1) => Some(("School", "📚 بازگشایی مدارس و دانشگاه‌ها؛ کلاس آنلاین بدون قطعی.", 10)),
        _ => {
            // Black Friday (fourth Friday of November) — widely known in Iran too
            if gm == 11 && (23..=29).contains(&gd) {
                let wd = (ts + TZ).div_euclid(86400).rem_euclid(7); // 0 = Thursday (1970-01-01)
                if wd == 1 {
                    return Some(("BlackFriday", "🖤 بلک‌فرایدی رسید! بزرگ‌ترین تخفیف سال.", 30));
                }
            }
            None
        }
    }
}

fn greeting(ts: i64) -> &'static str {
    let h = ((ts + TZ) % 86400) / 3600;
    match h {
        5..=11 => "☀️ صبح بخیر",
        12..=16 => "🌤 ظهر بخیر",
        17..=20 => "🌇 عصر بخیر",
        _ => "🌙 شب بخیر",
    }
}

// ------------------------------------------------------------------ data for posts

struct Facts {
    plans: Vec<(String, i64, f64, i64, i64, i64)>, // name, days, gb, toman, conns, countries
    users: i64,
    countries: i64,
    discount: Option<(String, i64, i64)>, // code, percent, expires
    trial: Option<(String, String)>,      // gb, days
    ref_gift: Option<(String, String)>,
}

fn facts(app: &App) -> Facts {
    let db = &app.db;
    let plans = db.with(|c| {
        let mut s = c.prepare("SELECT name,days,gb,toman,conns,COALESCE(countries,0) FROM plans WHERE active=1 ORDER BY toman").unwrap();
        let v: Vec<(String, i64, f64, i64, i64, i64)> = s
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)))
            .unwrap()
            .filter_map(|x| x.ok())
            .collect();
        v
    });
    let t = now();
    let discount = db.with(|c| {
        c.query_row(
            "SELECT code,percent,COALESCE(expires,0) FROM discounts WHERE uses_left>0 AND (COALESCE(expires,0)=0 OR expires>?1) ORDER BY percent DESC LIMIT 1",
            [t],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?)),
        )
        .ok()
    });
    let countries = db.nodes().iter().filter(|n| n.enabled).count() as i64;
    Facts {
        plans,
        users: db.count("SELECT COUNT(*) FROM users WHERE enabled=1"),
        countries,
        discount,
        trial: if db.on("trial_on") { Some((db.get("trial_gb"), db.get("trial_days"))) } else { None },
        ref_gift: if db.get("ref_gb").parse::<f64>().unwrap_or(0.0) > 0.0 || db.get("ref_days").parse::<i64>().unwrap_or(0) > 0 {
            Some((db.get("ref_gb"), db.get("ref_days")))
        } else {
            None
        },
    }
}

fn plan_lines(f: &Facts, pct: i64) -> String {
    f.plans
        .iter()
        .take(8)
        .map(|(n, d, g, t, c, k)| {
            let vol = if *g > 0.0 { format!("{} گیگ", g) } else { "نامحدود".into() };
            let extra = format!("{}{}", if *c > 1 { format!(" · {} کاربره", c) } else { String::new() }, if *k > 0 { format!(" · {} کشور", k) } else { String::new() });
            let price = if pct > 0 {
                format!("<s>{}</s> ➜ <b>{}</b>", toman(*t), toman(t * (100 - pct) / 100))
            } else {
                format!("<b>{}</b>", toman(*t))
            };
            format!("🔹 {} — {} / {} روز{}\n      {}", esc(n), vol, d, extra, price)
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn tags(r: &mut impl Rng) -> String {
    let mut v: Vec<&str> = HASHTAG.to_vec();
    v.shuffle(r);
    v.into_iter().take(3).collect::<Vec<_>>().join(" ")
}

fn sign(app: &App) -> String {
    let s = app.db.get("ch_sign");
    let bot = app.db.get("bot_username");
    if !s.is_empty() {
        s
    } else if !bot.is_empty() {
        format!("🤖 @{}", bot)
    } else {
        String::new()
    }
}

/// Builds one post. `kind` "auto" picks the best kind for the moment.
pub fn make_post(app: &App, kind: &str) -> (String, String) {
    let mut r = rand::thread_rng();
    let f = facts(app);
    let t = now();
    let kind = if kind == "auto" { auto_kind(app, &f, t) } else { kind.to_string() };
    let body = match kind.as_str() {
        "plans" if !f.plans.is_empty() => {
            let d = f.discount.as_ref().map(|x| x.1).unwrap_or(0);
            format!(
                "{}\n\n💎 <b>{}</b>\n\n{}\n\n{}\n{}{}\n\n{}",
                greeting(t), pick(&mut r, HOOK), plan_lines(&f, d), pick(&mut r, BENEFIT), pick(&mut r, BENEFIT),
                f.discount.as_ref().map(|(c, p, _)| format!("\n\n🎟 کد تخفیف <code>{}</code> = {}٪ تخفیف", esc(c), p)).unwrap_or_default(),
                pick(&mut r, CTA)
            )
        }
        "offer" => match &f.discount {
            Some((c, p, e)) => {
                let left = if *e > 0 { format!("\n⏳ فقط تا {} ساعت دیگر", ((e - t) / 3600).max(1)) } else { String::new() };
                format!(
                    "🔥 <b>تخفیف ویژه {}٪</b> 🔥\n\n{}\n\n🎟 کد تخفیف: <code>{}</code>{}\n\n{}\n\n{}",
                    p, pick(&mut r, HOOK), esc(c), left, plan_lines(&f, *p), pick(&mut r, CTA)
                )
            }
            None => return make_post(app, "plans"),
        },
        "tip" => format!("💡 <b>نکته امروز</b>\n\n{}\n\n{}", pick(&mut r, TIPS), pick(&mut r, CTA)),
        "guide" => format!("📖 <b>آموزش اتصال در ۱ دقیقه</b>\n\n{}\n\n{}", pick(&mut r, GUIDE), pick(&mut r, CTA)),
        "trial" => match &f.trial {
            Some((g, d)) => format!(
                "🎁 <b>تست رایگان!</b>\n\nقبل از خرید، {} گیگ و {} روز رایگان امتحان کن.\n\n{}\n{}\n\n👇 از ربات «تست رایگان» را بزن",
                g, d, pick(&mut r, BENEFIT), pick(&mut r, BENEFIT)
            ),
            None => return make_post(app, "tip"),
        },
        "ref" => match &f.ref_gift {
            Some((g, d)) => format!(
                "👥 <b>دوستاتو دعوت کن، هدیه بگیر!</b>\n\nبه ازای هر دوستی که با لینک تو خرید کند، {} گیگ و {} روز هدیه می‌گیری.\n\n👇 لینک دعوت اختصاصیت در ربات، بخش «دعوت دوستان»",
                g, d
            ),
            None => return make_post(app, "tip"),
        },
        "trust" => format!(
            "✅ <b>چرا ما؟</b>\n\n👤 بیش از {} کاربر فعال\n🌍 {} سرور در کشورهای مختلف\n{}\n{}\n{}\n\n{}",
            f.users.max(1), f.countries.max(1), pick(&mut r, BENEFIT), pick(&mut r, BENEFIT), pick(&mut r, BENEFIT), pick(&mut r, CTA)
        ),
        "occasion" => match occasion(t) {
            Some((_, g, _)) => format!(
                "{}\n\n{}{}\n\n{}",
                g, pick(&mut r, HOOK),
                f.discount.as_ref().map(|(c, p, _)| format!("\n\n🎟 به همین مناسبت: کد <code>{}</code> با {}٪ تخفیف", esc(c), p)).unwrap_or_default(),
                pick(&mut r, CTA)
            ),
            None => return make_post(app, "trust"),
        },
        _ => return make_post(app, "tip"),
    };
    let s = sign(app);
    let text = format!("{}\n\n{}{}", body, tags(&mut r), if s.is_empty() { String::new() } else { format!("\n{}", s) });
    (kind, text)
}

/// Picks a kind: occasions first, a live discount next, otherwise rotate through the
/// kinds the admin enabled, avoiding the last two kinds that were posted.
fn auto_kind(app: &App, f: &Facts, t: i64) -> String {
    let enabled: Vec<String> = {
        let v = app.db.get("ch_kinds");
        if v.is_empty() { KINDS.iter().map(|k| k.0.to_string()).collect() } else { v.split(',').map(|s| s.to_string()).collect() }
    };
    let on = |k: &str| enabled.iter().any(|x| x == k);
    let recent = app.db.get("ch_recent");
    let last: Vec<&str> = recent.split(',').filter(|s| !s.is_empty()).collect();
    if on("occasion") && occasion(t).is_some() && !last.contains(&"occasion") {
        return "occasion".into();
    }
    if on("offer") && f.discount.is_some() && !last.iter().take(2).any(|k| *k == "offer") {
        return "offer".into();
    }
    let mut cand: Vec<&str> = KINDS.iter().map(|k| k.0).filter(|k| on(k) && *k != "occasion").filter(|k| !last.iter().take(2).any(|x| x == k)).collect();
    if cand.is_empty() {
        cand = vec!["plans", "tip"];
    }
    // the price list matters most: give it double weight
    if cand.contains(&"plans") {
        cand.push("plans");
    }
    cand.choose(&mut rand::thread_rng()).copied().unwrap_or("tip").to_string()
}

// ------------------------------------------------------------------ sending

fn buy_button(app: &App) -> Option<Value> {
    let bot = app.db.get("bot_username");
    if bot.is_empty() {
        return None;
    }
    Some(json!({"inline_keyboard": [[{"text": "🛒 خرید از ربات", "url": format!("https://t.me/{}?start=ch", bot)}],
        [{"text": "🎁 تست رایگان", "url": format!("https://t.me/{}?start=trial", bot)}]]}))
}

pub async fn send_to_channel(app: &App, text: &str) -> Result<(), String> {
    let token = crate::bot::bot_token(app);
    let ch = app.db.get("ch_id");
    if token.is_empty() {
        return Err("the sales bot is not set up".into());
    }
    if ch.is_empty() {
        return Err("channel is not set".into());
    }
    let chat: Value = ch.trim().parse::<i64>().map(Value::from).unwrap_or_else(|_| {
        let c = ch.trim().trim_start_matches("https://t.me/").trim_start_matches('@');
        Value::from(format!("@{}", c))
    });
    let mut body = json!({"chat_id": chat, "text": text, "parse_mode": "HTML", "disable_web_page_preview": true});
    if let Some(kb) = buy_button(app) {
        body["reply_markup"] = kb;
    }
    let r = app
        .http
        .post(format!("https://api.telegram.org/bot{}/sendMessage", token))
        .json(&body)
        .timeout(std::time::Duration::from_secs(20))
        .send()
        .await
        .map_err(|e| e.to_string())?;
    let v: Value = r.json().await.map_err(|e| e.to_string())?;
    if v["ok"].as_bool() == Some(true) {
        app.db.set("ch_last", &now().to_string());
        let n: i64 = app.db.get("ch_count").parse().unwrap_or(0);
        app.db.set("ch_count", &(n + 1).to_string());
        Ok(())
    } else {
        Err(v["description"].as_str().unwrap_or("telegram error").to_string())
    }
}

fn remember(app: &App, kind: &str) {
    let r = app.db.get("ch_recent");
    let mut v: Vec<&str> = r.split(',').filter(|s| !s.is_empty()).collect();
    v.insert(0, kind);
    v.truncate(4);
    app.db.set("ch_recent", &v.join(","));
}

/// Makes a fresh discount code (e.g. KANKI20-7Q4M) that expires after `hours`.
pub fn new_campaign(app: &App, pct: i64, hours: i64, uses: i64) -> Result<String, String> {
    let pct = pct.clamp(1, 90);
    let tag: String = crate::util::rand_token(4).to_uppercase();
    let base = app.db.get("ch_code").trim().to_uppercase();
    let base = if base.is_empty() { "KANKI".to_string() } else { base };
    let code = format!("{}{}-{}", base, pct, tag);
    let exp = if hours > 0 { now() + hours * 3600 } else { 0 };
    app.db.exec(
        "INSERT OR REPLACE INTO discounts(code,percent,uses_left,expires) VALUES(?1,?2,?3,?4)",
        &[&code, &pct, &uses.max(1), &exp],
    )?;
    Ok(code)
}

/// Publishes posts on schedule: every `ch_hours`, never in quiet hours (01:00–08:00 Iran time).
/// On an occasion (Nowruz, Yalda…) with auto offers on, a time-limited code is made first.
pub async fn channel_loop(app: Arc<App>) {
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(120)).await;
        if !app.db.on("ch_on") || app.db.get("ch_id").is_empty() {
            continue;
        }
        let t = now();
        let h = ((t + TZ) % 86400) / 3600;
        if (1..8).contains(&h) {
            continue;
        }
        let every: i64 = app.db.get("ch_hours").parse::<i64>().unwrap_or(8).clamp(1, 72);
        let last: i64 = app.db.get("ch_last").parse().unwrap_or(0);
        if t - last < every * 3600 {
            continue;
        }
        if app.db.on("ch_auto_offer") {
            if let Some((name, _, pct)) = occasion(t) {
                let key = format!("{}-{}", name, ymd(t + TZ).0);
                if app.db.get("ch_occ_done") != key {
                    app.db.set("ch_occ_done", &key);
                    let _ = new_campaign(&app, pct, 48, 500);
                }
            }
        }
        let (kind, text) = make_post(&app, "auto");
        match send_to_channel(&app, &text).await {
            Ok(_) => {
                remember(&app, &kind);
                app.db.set("ch_status", "ok");
            }
            Err(e) => {
                // try again next interval, not every two minutes
                app.db.set("ch_last", &t.to_string());
                app.db.set("ch_status", &format!("error: {}", e));
            }
        }
    }
}

// ------------------------------------------------------------------ panel API

pub fn router() -> Router<Arc<App>> {
    Router::new()
        .route("/api/channel", get(ch_get).put(ch_put))
        .route("/api/channel/preview", post(ch_preview))
        .route("/api/channel/post", post(ch_post))
        .route("/api/channel/campaign", post(ch_campaign))
        .route("/api/discounts", get(disc_list).post(disc_add))
        .route("/api/discounts/:code", axum::routing::delete(disc_del))
}

async fn ch_get(State(app): St, h: HeaderMap) -> Response {
    let _ = guard!(app, h, "settings");
    let db = &app.db;
    let kinds = db.get("ch_kinds");
    Json(json!({
        "on": db.on("ch_on"), "id": db.get("ch_id"), "hours": db.get("ch_hours").parse::<i64>().unwrap_or(8),
        "kinds": if kinds.is_empty() { KINDS.iter().map(|k| k.0).collect::<Vec<_>>().join(",") } else { kinds },
        "all_kinds": KINDS.iter().map(|k| json!({"id": k.0, "name": k.1})).collect::<Vec<_>>(),
        "sign": db.get("ch_sign"), "code": db.get("ch_code"), "auto_offer": db.on("ch_auto_offer"),
        "last": db.get("ch_last").parse::<i64>().unwrap_or(0), "count": db.get("ch_count").parse::<i64>().unwrap_or(0),
        "status": db.get("ch_status"), "bot": db.get("bot_username"),
        "occasion": occasion(now()).map(|o| o.0),
    }))
    .into_response()
}

async fn ch_put(State(app): St, h: HeaderMap, Json(b): Json<Value>) -> Response {
    let _ = guard!(app, h, "settings");
    let db = &app.db;
    if let Some(v) = b["on"].as_bool() {
        db.set("ch_on", if v { "1" } else { "0" });
    }
    if let Some(v) = b["auto_offer"].as_bool() {
        db.set("ch_auto_offer", if v { "1" } else { "0" });
    }
    if let Some(v) = b["id"].as_str() {
        db.set("ch_id", v.trim());
    }
    if let Some(v) = b["hours"].as_i64().or_else(|| b["hours"].as_str().and_then(|s| s.parse().ok())) {
        db.set("ch_hours", &v.clamp(1, 72).to_string());
    }
    if let Some(v) = b["kinds"].as_str() {
        let ok: Vec<&str> = v.split(',').filter(|k| KINDS.iter().any(|x| x.0 == *k)).collect();
        db.set("ch_kinds", &ok.join(","));
    }
    if let Some(v) = b["sign"].as_str() {
        db.set("ch_sign", v.trim());
    }
    if let Some(v) = b["code"].as_str() {
        let c: String = v.trim().to_uppercase().chars().filter(|c| c.is_ascii_alphanumeric()).take(10).collect();
        db.set("ch_code", &c);
    }
    Json(json!({"ok": true})).into_response()
}

async fn ch_preview(State(app): St, h: HeaderMap, Json(b): Json<Value>) -> Response {
    let _ = guard!(app, h, "settings");
    let (kind, text) = make_post(&app, b["kind"].as_str().unwrap_or("auto"));
    Json(json!({"kind": kind, "text": text})).into_response()
}

async fn ch_post(State(app): St, h: HeaderMap, Json(b): Json<Value>) -> Response {
    let _ = guard!(app, h, "settings");
    let text = b["text"].as_str().unwrap_or("").to_string();
    if text.trim().is_empty() {
        return err(StatusCode::BAD_REQUEST, "text is empty");
    }
    match send_to_channel(&app, &text).await {
        Ok(_) => {
            if let Some(k) = b["kind"].as_str() {
                remember(&app, k);
            }
            Json(json!({"ok": true})).into_response()
        }
        Err(e) => err(StatusCode::BAD_GATEWAY, &e),
    }
}

async fn ch_campaign(State(app): St, h: HeaderMap, Json(b): Json<Value>) -> Response {
    let _ = guard!(app, h, "settings");
    let pct = b["percent"].as_i64().unwrap_or(15);
    let hours = b["hours"].as_i64().unwrap_or(48);
    let uses = b["uses"].as_i64().unwrap_or(200);
    let code = match new_campaign(&app, pct, hours, uses) {
        Ok(c) => c,
        Err(e) => return err(StatusCode::BAD_REQUEST, &e),
    };
    let (_, text) = make_post(&app, "offer");
    let posted = if b["post"].as_bool().unwrap_or(true) {
        match send_to_channel(&app, &text).await {
            Ok(_) => {
                remember(&app, "offer");
                Ok(())
            }
            Err(e) => Err(e),
        }
    } else {
        Ok(())
    };
    Json(json!({"ok": true, "code": code, "text": text, "posted": posted.is_ok(), "error": posted.err()})).into_response()
}

async fn disc_list(State(app): St, h: HeaderMap) -> Response {
    let _ = guard!(app, h, "settings");
    let t = now();
    // expired or used-up codes are removed so the list stays clean
    let _ = app.db.exec("DELETE FROM discounts WHERE uses_left<=0 OR (COALESCE(expires,0)>0 AND expires<?1)", &[&t]);
    let v: Vec<Value> = app.db.with(|c| {
        let mut s = c.prepare("SELECT code,percent,uses_left,COALESCE(expires,0) FROM discounts ORDER BY percent DESC").unwrap();
        let v: Vec<Value> = s
            .query_map([], |r| Ok(json!({"code": r.get::<_, String>(0)?, "percent": r.get::<_, i64>(1)?, "uses": r.get::<_, i64>(2)?, "expires": r.get::<_, i64>(3)?})))
            .unwrap()
            .filter_map(|x| x.ok())
            .collect();
        v
    });
    Json(json!(v)).into_response()
}

async fn disc_add(State(app): St, h: HeaderMap, Json(b): Json<Value>) -> Response {
    let _ = guard!(app, h, "settings");
    let code: String = b["code"].as_str().unwrap_or("").trim().to_uppercase().chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_').take(24).collect();
    if code.is_empty() {
        return err(StatusCode::BAD_REQUEST, "code is required");
    }
    let pct = b["percent"].as_i64().unwrap_or(10).clamp(1, 90);
    let uses = b["uses"].as_i64().unwrap_or(100).max(1);
    let hours = b["hours"].as_i64().unwrap_or(0).max(0);
    let exp = if hours > 0 { now() + hours * 3600 } else { 0 };
    match app.db.exec("INSERT OR REPLACE INTO discounts(code,percent,uses_left,expires) VALUES(?1,?2,?3,?4)", &[&code, &pct, &uses, &exp]) {
        Ok(_) => Json(json!({"ok": true, "code": code})).into_response(),
        Err(e) => err(StatusCode::BAD_REQUEST, &e),
    }
}

async fn disc_del(State(app): St, h: HeaderMap, Path(code): Path<String>) -> Response {
    let _ = guard!(app, h, "settings");
    let _ = app.db.exec("DELETE FROM discounts WHERE code=?1", &[&code]);
    Json(json!({"ok": true})).into_response()
}
