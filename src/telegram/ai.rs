//! AI writer for the channel posts: Groq (groq.com) or Grok (x.ai), both OpenAI-compatible chat APIs.
//! The provider is told by the key (Groq keys start with `gsk_`, x.ai keys with `xai-`) unless the
//! admin picks one.
//!
//! The admin pastes an API key and a short brief (who we are, what to stress, the tone) in the panel.
//! At each posting time the channel manager asks Grok for one post of the chosen kind, with the real
//! plans, prices, discount code, free trial and bot name as facts it must not change. A failed call is
//! tried again (network errors, 429 and 5xx with a growing wait), a model the key cannot use is
//! replaced by one the account lists, and when Grok still gives nothing the built-in writer posts
//! instead, so the channel never stays silent.
use crate::App;
use serde_json::{json, Value};
use std::time::Duration;

/// One OpenAI-compatible provider: (name, base URL, default model, models tried when one is refused)
pub struct Provider {
    pub name: &'static str,
    pub base: &'static str,
    pub model: &'static str,
    pub fallback: &'static [&'static str],
}

pub const GROQ: Provider = Provider {
    name: "groq",
    base: "https://api.groq.com/openai/v1",
    model: "openai/gpt-oss-120b",
    fallback: &["openai/gpt-oss-120b", "llama-3.3-70b-versatile", "openai/gpt-oss-20b", "llama-3.1-8b-instant"],
};
pub const XAI: Provider = Provider { name: "xai", base: "https://api.x.ai/v1", model: "grok-4", fallback: &["grok-4", "grok-3", "grok-3-mini"] };

/// The provider of a key: what the admin chose, else told by the key's prefix (Groq: gsk_)
pub fn provider_of(choice: &str, key: &str) -> &'static Provider {
    match choice {
        "groq" => &GROQ,
        "xai" => &XAI,
        _ if key.trim().starts_with("xai-") => &XAI,
        _ => &GROQ,
    }
}
/// waits before the 2nd and 3rd try of the same model
const BACKOFF: &[u64] = &[3, 10];

pub struct AiCfg {
    pub on: bool,
    pub key: String,
    pub model: String,
    pub brief: String,
    pub provider: &'static Provider,
}

pub fn cfg(app: &App) -> AiCfg {
    let key = app.db.get("ai_key");
    let provider = provider_of(&app.db.get("ai_provider"), &key);
    let m = app.db.get("ai_model");
    let m = m.trim();
    // a model of the other provider (left from before) is not sent to this one
    let foreign = (provider.name == "groq" && m.starts_with("grok")) || (provider.name == "xai" && !m.starts_with("grok"));
    let model = if m.is_empty() || foreign { provider.model.to_string() } else { m.to_string() };
    AiCfg { on: app.db.on("ai_on"), key, model, brief: app.db.get("ai_brief"), provider }
}

/// what each post kind is about, told to the model
fn theme(kind: &str) -> &'static str {
    match kind {
        "plans" => "a price list of the plans below, with what makes them worth it",
        "offer" => "a time-limited discount campaign with the discount code below",
        "tip" => "one useful tip about using the internet / the VPN better",
        "guide" => "a short step-by-step guide: buy from the bot, get the link, connect in the app",
        "trial" => "an invitation to the free trial",
        "ref" => "an invitation to bring friends and get the referral gift",
        "trust" => "why customers trust us: support, stability, the numbers below",
        "occasion" => "a greeting for today's Iranian occasion, with an offer if there is one",
        "story" => "a short relatable story of someone whose internet problem was solved",
        "day" => "a day (morning, noon, night) with a stable internet",
        "poll" => "a question to the audience with 3-4 emoji options to react with",
        "faq" => "one frequently asked question and its clear answer",
        "mood" => "a short punchy post, two or three lines",
        "versus" => "before and after: three short contrasts",
        _ => "an engaging post that brings people to the bot",
    }
}

/// The facts and the instructions for one post.
pub fn prompt(app: &App, kind: &str, facts: &str, recent: &[String]) -> (String, String) {
    let c = cfg(app);
    let system = "You write posts for a Telegram channel that sells VPN subscriptions in Iran, in Persian (Farsi). \
Write like a skilled native Persian copywriter, not a translator: think the post in Persian, never translate English phrases word by word. \
Rules: output ONLY the post text, nothing before or after it. 350 to 900 characters. A few fitting emojis, not too many. \
Formatting: only these HTML tags are allowed: <b>, <i>, <u>, <s>, <code>; no Markdown, no other tags, no links, no hashtags (they are added later). \
Use the prices, plan names, discount code and numbers EXACTLY as given; never invent a price, a code, a percentage or a number. \
End with a short call to action to buy from the Telegram bot. Never mention politics, never promise anything illegal, never name the filtering authorities.\n\
قواعد نگارش فارسی (مهم‌ترین بخش):\n\
- هر جمله کامل و درست باشد: فاعل و فعل روشن، فعل در جای درست، زمان فعل‌ها یکدست. جمله‌ی نیمه‌کاره یا درهم ننویس.\n\
- جمله‌ها کوتاه باشند (حداکثر حدود ۱۵ کلمه) و هر جمله فقط یک حرف بزند.\n\
- فقط کلمه‌های رایج و طبیعی فارسی امروز؛ هیچ کلمه‌ی ساختگی، بی‌معنی یا بی‌ربط و هیچ ترکیب عجیب ننویس.\n\
- لحن را یکدست نگه دار: یا محاوره‌ی مؤدب (مثل «می‌تونی»، «وصل می‌شی») یا نوشتاری ساده؛ این دو را در یک پست قاطی نکن. مخاطب را «تو» خطاب کن.\n\
- نیم‌فاصله را درست بگذار (می‌شود، سرورها، بهترین) و از نشانه‌های فارسی استفاده کن (، ؛ ؟ «»).\n\
- اگر مطمئن نیستی جمله‌ای درست و روشن است، آن را ساده‌تر بنویس یا ننویس.\n\
- پیش از پایان، متن را یک بار مثل یک ویراستار فارسی بخوان و هر خطا را درست کن."
        .to_string();
    let mut user = format!("Write one post. Topic: {}.\n\nFacts:\n{}\n", theme(kind), facts);
    if !c.brief.trim().is_empty() {
        user.push_str(&format!("\nAbout us and how to write (from the channel owner):\n{}\n", c.brief.trim()));
    }
    if !recent.is_empty() {
        user.push_str("\nRecent posts (do not repeat their opening, wording or structure):\n");
        for r in recent {
            user.push_str(&format!("---\n{}\n", r.chars().take(300).collect::<String>()));
        }
    }
    (system, user)
}

/// Telegram HTML: everything escaped except the few tags it allows; Markdown bold/italic turned into tags.
pub fn tg_html(raw: &str) -> String {
    let mut t = raw.trim().to_string();
    // a model sometimes wraps the post in a code fence or quotes
    if t.starts_with("```") {
        t = t.trim_start_matches(|c| c == '`').trim_start_matches(|c: char| c.is_ascii_alphabetic()).to_string();
        t = t.trim_end_matches(|c| c == '`').to_string();
    }
    let t = t.trim().trim_matches('"').trim();
    let mut s = t.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;");
    for tag in ["b", "i", "u", "s", "code"] {
        s = s.replace(&format!("&lt;{}&gt;", tag), &format!("<{}>", tag)).replace(&format!("&lt;/{}&gt;", tag), &format!("</{}>", tag));
    }
    // **bold** → <b>bold</b>
    let mut out = String::new();
    let mut open = false;
    let mut rest = s.as_str();
    while let Some(i) = rest.find("**") {
        out.push_str(&rest[..i]);
        out.push_str(if open { "</b>" } else { "<b>" });
        open = !open;
        rest = &rest[i + 2..];
    }
    out.push_str(rest);
    if open {
        out.push_str("</b>");
    }
    // tags must be balanced or Telegram refuses the whole message
    for tag in ["b", "i", "u", "s", "code"] {
        let (o, c) = (out.matches(&format!("<{}>", tag)).count(), out.matches(&format!("</{}>", tag)).count());
        if o != c {
            out = out.replace(&format!("<{}>", tag), "").replace(&format!("</{}>", tag), "");
        }
    }
    let out: String = out.chars().take(3500).collect();
    out.trim().to_string()
}

/// Every tag taken out (the plain-text fallback when Telegram refuses the HTML)
pub fn strip_tags(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut inside = false;
    for c in s.chars() {
        match c {
            '<' => inside = true,
            '>' if inside => inside = false,
            _ if !inside => out.push(c),
            _ => {}
        }
    }
    out.replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&")
}

enum Fail {
    /// the key is wrong or has no access: no use trying again
    Key(String),
    /// this model cannot be used with the key
    Model(String),
    /// worth another try (network, 429, 5xx, an empty answer)
    Again(String),
}

async fn call(app: &App, pv: &Provider, key: &str, model: &str, system: &str, user: &str, temp: f64) -> Result<String, Fail> {
    let mut body = json!({ "model": model, "temperature": temp, "max_tokens": 3000, "messages": [ { "role": "system", "content": system }, { "role": "user", "content": user } ] });
    // the gpt-oss models think first: a little thinking leaves the tokens for the post
    if model.contains("gpt-oss") {
        body["reasoning_effort"] = json!("medium");
    }
    let r = app
        .http
        .post(format!("{}/chat/completions", pv.base))
        .bearer_auth(key)
        .json(&body)
        .timeout(Duration::from_secs(90))
        .send()
        .await
        .map_err(|e| Fail::Again(format!("cannot reach {}: {}", pv.name, e)))?;
    let code = r.status().as_u16();
    let v: Value = r.json().await.unwrap_or(Value::Null);
    let msg = v["error"]["message"].as_str().or(v["error"].as_str()).or(v["message"].as_str()).unwrap_or("").to_string();
    match code {
        200 => {
            let text = v["choices"][0]["message"]["content"].as_str().unwrap_or("").trim().to_string();
            if text.chars().count() < 40 {
                return Err(Fail::Again("the AI gave an empty answer".into()));
            }
            Ok(text)
        }
        401 | 403 => {
            let low = msg.to_lowercase();
            if low.contains("model") && !low.contains("key") {
                Err(Fail::Model(format!("{}: {}", model, msg)))
            } else {
                Err(Fail::Key(format!("the API key was refused ({}): {}", code, msg)))
            }
        }
        404 => Err(Fail::Model(format!("{}: {}", model, if msg.is_empty() { "model not found".into() } else { msg }))),
        400 | 422 if msg.to_lowercase().contains("model") => Err(Fail::Model(format!("{}: {}", model, msg))),
        429 | 500..=599 => Err(Fail::Again(format!("{} answered {}{}", pv.name, code, if msg.is_empty() { String::new() } else { format!(": {}", msg) }))),
        _ => Err(Fail::Key(format!("{} answered {}: {}", pv.name, code, msg))),
    }
}

const EDITOR: &str = "تو ویراستار حرفه‌ای زبان فارسی هستی. متنی که می‌گیری یک پست تلگرام است. \
فقط خطاهای آن را درست کن: جمله‌های ناقص، بی‌معنی یا درهم، فعل‌های جاافتاده یا نادرست، ترجمه‌ی تحت‌اللفظی از انگلیسی، \
کلمه‌های بی‌ربط، املا، نیم‌فاصله (می‌شود، ‌ها، ‌ترین) و نشانه‌گذاری فارسی (، ؛ ؟). جمله‌ای که معنی روشنی ندارد را ساده و روشن بازنویسی کن یا حذف کن. \
معنی، لحن، ایموجی‌ها، تگ‌های HTML (<b> <i> <u> <s> <code>)، قیمت‌ها، عددها، نام پلن‌ها، کد تخفیف و کلمه‌های لاتین (مثل VPN و نام پروتکل‌ها) را دست نزن. \
چیز تازه‌ای اضافه نکن. فقط متن نهایی پست را بنویس، بدون هیچ توضیح، عنوان یا علامت نقل‌قول.";

/// A second pass by the same model as a Persian editor: broken or meaningless sentences fixed. The
/// first text is kept when the editor fails or changes the post too much (numbers lost, length).
async fn proofread(app: &App, pv: &Provider, key: &str, model: &str, post: &str) -> String {
    let Ok(t) = call(app, pv, key, model, EDITOR, post, 0.2).await else { return post.to_string() };
    let fixed = tg_html(&t);
    let (a, b) = (strip_tags(post).chars().count(), strip_tags(&fixed).chars().count());
    if b * 10 < a * 6 || b * 10 > a * 15 || !keeps_numbers(post, &fixed) {
        return post.to_string();
    }
    fixed
}

/// every number of the post (prices, percentages, codes) is still in the edited text
fn keeps_numbers(old: &str, new: &str) -> bool {
    let digits = |s: &str| -> Vec<String> {
        let s: String = s.chars().map(|c| match c { '۰'..='۹' => char::from(b'0' + (c as u32 - '۰' as u32) as u8), _ => c }).collect();
        s.split(|c: char| !c.is_ascii_digit()).filter(|x| !x.is_empty()).map(|x| x.to_string()).collect()
    };
    let n = digits(new);
    digits(old).iter().all(|d| n.contains(d))
}

/// The chat models this key may use, from the account's own list.
async fn listed_models(app: &App, pv: &Provider, key: &str) -> Vec<String> {
    let Ok(r) = app.http.get(format!("{}/models", pv.base)).bearer_auth(key).timeout(Duration::from_secs(20)).send().await else { return vec![] };
    let v: Value = r.json().await.unwrap_or(Value::Null);
    let mut m: Vec<String> = v["data"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|x| x["id"].as_str().map(|s| s.to_string()))
        .filter(|id| {
            let l = id.to_lowercase();
            let text = !["image", "vision", "imagine", "whisper", "tts", "guard", "playai", "orpheus", "distil", "compound", "embed"].iter().any(|x| l.contains(x));
            text && (pv.name != "xai" || l.starts_with("grok"))
        })
        .collect();
    // our known good ones first, in their order, then the rest of the list
    m.sort_by_key(|id| pv.fallback.iter().position(|f| f == id).unwrap_or(99));
    m
}

/// One post from Grok: (the model that wrote it, the post in Telegram HTML). Tries again on passing
/// errors and moves to another model when the chosen one is refused.
pub async fn write(app: &App, system: &str, user: &str) -> Result<(String, String), String> {
    let c = cfg(app);
    if c.key.trim().is_empty() {
        return Err("no AI API key".into());
    }
    let key = c.key.trim().to_string();
    let mut models = vec![c.model.clone()];
    let mut listed = false;
    let mut last = String::new();
    let mut i = 0;
    while i < models.len() && i < 6 {
        let model = models[i].clone();
        let mut tries = 0;
        loop {
            match call(app, c.provider, &key, &model, system, user, 0.7).await {
                Ok(t) => {
                    let html = tg_html(&t);
                    if html.chars().count() >= 40 {
                        let html = proofread(app, c.provider, &key, &model, &html).await;
                        return Ok((model, html));
                    }
                    last = "the AI gave an empty answer".into();
                }
                Err(Fail::Key(e)) => return Err(e),
                Err(Fail::Model(e)) => {
                    last = e;
                    break;
                }
                Err(Fail::Again(e)) => last = e,
            }
            if tries >= BACKOFF.len() {
                break;
            }
            tokio::time::sleep(Duration::from_secs(BACKOFF[tries])).await;
            tries += 1;
        }
        if !listed {
            listed = true;
            for m in listed_models(app, c.provider, &key).await.into_iter().chain(c.provider.fallback.iter().map(|s| s.to_string())) {
                if !models.contains(&m) {
                    models.push(m);
                }
            }
        }
        i += 1;
    }
    Err(if last.is_empty() { "the AI did not answer".into() } else { last })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_telegram_tags_survive() {
        assert_eq!(tg_html("**سلام** <b>دنیا</b> <script>x</script> & <a href=x>y</a>"), "<b>سلام</b> <b>دنیا</b> &lt;script&gt;x&lt;/script&gt; &amp; &lt;a href=x&gt;y&lt;/a&gt;");
        assert_eq!(tg_html("```html\n<i>متن</i>\n```"), "<i>متن</i>");
        // an unclosed tag would make Telegram refuse the message
        assert_eq!(tg_html("<b>باز <i>کج</i>"), "باز <i>کج</i>");
        assert_eq!(strip_tags("<b>a</b> &lt;3 &amp; <i>b</i>"), "a <3 & b");
    }

    #[test]
    fn the_editor_may_not_lose_a_number() {
        assert!(keeps_numbers("پلن ۳۰ روزه ۱۵۰ هزار", "پلن 30 روزه فقط 150 هزار تومان"));
        assert!(!keeps_numbers("کد KANKI20 با ۲۰٪", "کد KANKI با تخفیف"));
    }

    #[test]
    fn the_key_tells_the_provider() {
        assert_eq!(provider_of("", "gsk_abc").name, "groq");
        assert_eq!(provider_of("", "xai-abc").name, "xai");
        assert_eq!(provider_of("xai", "gsk_abc").name, "xai");
        assert_eq!(provider_of("", "").base, "https://api.groq.com/openai/v1");
    }

    #[test]
    fn the_prompt_carries_the_facts_and_the_kind() {
        let (s, u) = (theme("offer"), theme("nope"));
        assert!(s.contains("discount") && u.contains("bot"));
    }
}
