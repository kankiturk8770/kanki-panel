//! AI writer for the channel posts: Grok (x.ai, an OpenAI-compatible chat API).
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

const API: &str = "https://api.x.ai/v1";
pub const DEFAULT_MODEL: &str = "grok-4";
/// tried after the chosen model when it is refused (the account's own list comes first)
const FALLBACK_MODELS: &[&str] = &["grok-4", "grok-3", "grok-3-mini"];
/// waits before the 2nd and 3rd try of the same model
const BACKOFF: &[u64] = &[3, 10];

pub struct AiCfg {
    pub on: bool,
    pub key: String,
    pub model: String,
    pub brief: String,
}

pub fn cfg(app: &App) -> AiCfg {
    let m = app.db.get("ai_model");
    AiCfg { on: app.db.on("ai_on"), key: app.db.get("ai_key"), model: if m.trim().is_empty() { DEFAULT_MODEL.into() } else { m.trim().to_string() }, brief: app.db.get("ai_brief") }
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
    let system = "You write posts for a Telegram channel that sells VPN subscriptions in Iran. Write in natural, warm, modern Persian (Farsi). \
Rules: output ONLY the post text, nothing before or after it. 350 to 900 characters. A few fitting emojis, not too many. \
Formatting: only these HTML tags are allowed: <b>, <i>, <u>, <s>, <code>; no Markdown, no other tags, no links, no hashtags (they are added later). \
Use the prices, plan names, discount code and numbers EXACTLY as given; never invent a price, a code, a percentage or a number. \
End with a short call to action to buy from the Telegram bot. Never mention politics, never promise anything illegal, never name the filtering authorities."
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

async fn call(app: &App, key: &str, model: &str, system: &str, user: &str) -> Result<String, Fail> {
    let body = json!({ "model": model, "temperature": 0.9, "max_tokens": 900, "messages": [ { "role": "system", "content": system }, { "role": "user", "content": user } ] });
    let r = app
        .http
        .post(format!("{}/chat/completions", API))
        .bearer_auth(key)
        .json(&body)
        .timeout(Duration::from_secs(90))
        .send()
        .await
        .map_err(|e| Fail::Again(format!("cannot reach Grok: {}", e)))?;
    let code = r.status().as_u16();
    let v: Value = r.json().await.unwrap_or(Value::Null);
    let msg = v["error"]["message"].as_str().or(v["error"].as_str()).or(v["message"].as_str()).unwrap_or("").to_string();
    match code {
        200 => {
            let text = v["choices"][0]["message"]["content"].as_str().unwrap_or("").trim().to_string();
            if text.chars().count() < 40 {
                return Err(Fail::Again("Grok gave an empty answer".into()));
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
        429 | 500..=599 => Err(Fail::Again(format!("Grok answered {}{}", code, if msg.is_empty() { String::new() } else { format!(": {}", msg) }))),
        _ => Err(Fail::Key(format!("Grok answered {}: {}", code, msg))),
    }
}

/// The chat models this key may use, from the account's own list.
async fn listed_models(app: &App, key: &str) -> Vec<String> {
    let Ok(r) = app.http.get(format!("{}/models", API)).bearer_auth(key).timeout(Duration::from_secs(20)).send().await else { return vec![] };
    let v: Value = r.json().await.unwrap_or(Value::Null);
    let mut m: Vec<String> = v["data"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|x| x["id"].as_str().map(|s| s.to_string()))
        .filter(|id| id.starts_with("grok") && !id.contains("image") && !id.contains("vision") && !id.contains("imagine"))
        .collect();
    // the newest families first
    m.sort_by(|a, b| b.cmp(a));
    m
}

/// One post from Grok: (the model that wrote it, the post in Telegram HTML). Tries again on passing
/// errors and moves to another model when the chosen one is refused.
pub async fn write(app: &App, system: &str, user: &str) -> Result<(String, String), String> {
    let c = cfg(app);
    if c.key.trim().is_empty() {
        return Err("no Grok API key".into());
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
            match call(app, &key, &model, system, user).await {
                Ok(t) => {
                    let html = tg_html(&t);
                    if html.chars().count() >= 40 {
                        return Ok((model, html));
                    }
                    last = "Grok gave an empty answer".into();
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
            for m in listed_models(app, &key).await.into_iter().chain(FALLBACK_MODELS.iter().map(|s| s.to_string())) {
                if !models.contains(&m) {
                    models.push(m);
                }
            }
        }
        i += 1;
    }
    Err(if last.is_empty() { "Grok did not answer".into() } else { last })
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
    fn the_prompt_carries_the_facts_and_the_kind() {
        let (s, u) = (theme("offer"), theme("nope"));
        assert!(s.contains("discount") && u.contains("bot"));
    }
}
