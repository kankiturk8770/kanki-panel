//! Button manager of the sales bot (3.34): the text, the premium emoji and the colour of every customer button.
//!
//! - text: `btn_<key>` (empty = the default in `bot::BTNS`)
//! - premium emoji: the setting `btn_icons`, JSON {key: custom emoji id}. Telegram (Bot API 9.4) shows it before the
//!   button's text when the bot's owner has Telegram Premium (or the bot bought a Fragment username); the button's own
//!   plain emoji is then dropped, so the two do not sit side by side.
//! - colour: `bst_<style key>` (several buttons can share one, as every payment button shares «pay»)
//!
//! The panel's bot page and the bot's own admin menu both edit the same settings.

use crate::db::Db;
use crate::App;
use serde_json::{json, Value};
use std::collections::HashMap;

/// The custom emoji of each button key
pub fn icons(db: &Db) -> HashMap<String, String> {
    serde_json::from_str::<HashMap<String, String>>(&db.get("btn_icons")).unwrap_or_default()
}

pub fn set_icon(db: &Db, key: &str, id: Option<&str>) {
    let mut m = icons(db);
    match id {
        Some(i) if valid_id(i) => {
            m.insert(key.to_string(), i.to_string());
        }
        _ => {
            m.remove(key);
        }
    }
    db.set("btn_icons", &serde_json::to_string(&m).unwrap_or_default());
}

/// A custom emoji id is a plain number (Telegram's are about 19 digits)
pub fn valid_id(id: &str) -> bool {
    (5..=24).contains(&id.len()) && id.bytes().all(|c| c.is_ascii_digit())
}

/// The colour setting a button key uses, if it has one
pub fn style_key(k: &str) -> Option<&'static str> {
    if let Some(s) = crate::bot::STYLE_KEYS.iter().find(|x| x.0 == k) {
        return Some(s.0);
    }
    if k.starts_with("pay_") {
        return Some("pay");
    }
    if k.starts_with("cfg_") {
        return Some("cfg");
    }
    None
}

/// "🛒 خرید اشتراک" → "خرید اشتراک": the plain emoji (or symbol) a button starts with, when a premium one takes its place
pub fn without_lead_emoji(t: &str) -> String {
    match t.trim().split_once(' ') {
        Some((first, rest)) if !first.is_empty() && !first.chars().any(|c| c.is_alphanumeric()) && !rest.trim().is_empty() => rest.trim().to_string(),
        _ => t.to_string(),
    }
}

/// The first custom (premium) emoji of a message: its id and its place in the text (UTF-16 offset, length)
pub fn first_custom(m: &Value) -> Option<(String, usize, usize)> {
    let ents = m["entities"].as_array().or_else(|| m["caption_entities"].as_array())?;
    ents.iter().find(|e| e["type"] == "custom_emoji").and_then(|e| {
        let id = e["custom_emoji_id"].as_str()?.to_string();
        Some((id, e["offset"].as_u64()? as usize, e["length"].as_u64()? as usize))
    })
}

/// The admin's text with its premium emoji kept: each custom emoji becomes <tg-emoji emoji-id="…">x</tg-emoji>
/// (the bot sends HTML). Telegram counts entity offsets in UTF-16 units.
pub fn keep_custom_emoji(text: &str, m: &Value) -> String {
    let Some(ents) = m["entities"].as_array() else { return text.to_string() };
    let mut ce: Vec<(usize, usize, String)> = ents.iter().filter(|e| e["type"] == "custom_emoji").filter_map(|e| {
        let id = e["custom_emoji_id"].as_str()?;
        valid_id(id).then(|| (e["offset"].as_u64().unwrap_or(0) as usize, e["length"].as_u64().unwrap_or(0) as usize, id.to_string()))
    }).collect();
    if ce.is_empty() {
        return text.to_string();
    }
    ce.sort();
    let u: Vec<u16> = text.encode_utf16().collect();
    let mut out = String::new();
    let mut at = 0;
    for (off, len, id) in ce {
        if off < at || off + len > u.len() {
            continue;
        }
        out.push_str(&String::from_utf16_lossy(&u[at..off]));
        out.push_str(&format!("<tg-emoji emoji-id=\"{}\">{}</tg-emoji>", id, String::from_utf16_lossy(&u[off..off + len])));
        at = off + len;
    }
    out.push_str(&String::from_utf16_lossy(&u[at..]));
    out
}

/// Every button for the panel's manager, in the bot's order: key, where it shows, default, current text, emoji, colour
pub fn list(app: &App) -> Value {
    let db = &app.db;
    let ic = icons(db);
    let v: Vec<Value> = crate::bot::BTNS.iter().map(|(k, def, place)| {
        let sk = style_key(k);
        let def_style = sk.and_then(|s| crate::bot::STYLE_KEYS.iter().find(|x| x.0 == s)).map(|x| x.1).unwrap_or("");
        json!({
            "key": k, "place": place, "default": def, "text": db.get(&format!("btn_{}", k)),
            "icon": ic.get(*k).cloned().unwrap_or_default(),
            "style_key": sk, "style": sk.map(|s| db.get(&format!("bst_{}", s))).unwrap_or_default(), "style_default": def_style,
            "main": crate::bot::MAIN_BTNS.contains(k), "hidden": db.on(&format!("hide_{}", k)),
        })
    }).collect();
    json!({ "buttons": v, "bot": !crate::bot::bot_token(app).is_empty() })
}

/// Saves {key: {text, icon, style, hidden}} from the panel; anything not a known button or value is refused
pub fn save(app: &App, b: &Value) -> Result<(), String> {
    let db = &app.db;
    let Some(m) = b["buttons"].as_object() else { return Err("no buttons".into()) };
    // check everything first: nothing is half saved
    for (k, v) in m {
        if !crate::bot::BTNS.iter().any(|x| x.0 == k) {
            return Err(format!("unknown button {}", k));
        }
        if let Some(t) = v["text"].as_str() {
            if t.chars().count() > 60 {
                return Err("a button text is at most 60 characters".into());
            }
        }
        if let Some(i) = v["icon"].as_str() {
            if !i.is_empty() && !valid_id(i) {
                return Err("an emoji id is a number: send the emoji to the bot to get it".into());
            }
        }
        if let Some(s) = v["style"].as_str() {
            if !["", "success", "primary", "danger", "none"].contains(&s) || (!s.is_empty() && style_key(k).is_none()) {
                return Err("bad colour".into());
            }
        }
    }
    let mut ic = icons(db);
    for (k, v) in m {
        if let Some(t) = v["text"].as_str() {
            db.set(&format!("btn_{}", k), t.trim());
        }
        if let Some(i) = v["icon"].as_str() {
            if i.is_empty() { ic.remove(k); } else { ic.insert(k.clone(), i.to_string()); }
        }
        if let (Some(s), Some(sk)) = (v["style"].as_str(), style_key(k)) {
            db.set(&format!("bst_{}", sk), s);
        }
        if let Some(h) = v["hidden"].as_bool() {
            if crate::bot::MAIN_BTNS.contains(&k.as_str()) {
                db.set(&format!("hide_{}", k), if h { "1" } else { "0" });
            }
        }
    }
    db.set("btn_icons", &serde_json::to_string(&ic).unwrap_or_default());
    Ok(())
}

/// The picture of a premium emoji for the panel's preview: its still thumbnail (WebP), read once from Telegram
pub async fn emoji_image(app: &App, id: &str) -> Option<(Vec<u8>, &'static str)> {
    static CACHE: std::sync::OnceLock<std::sync::Mutex<HashMap<String, (Vec<u8>, &'static str)>>> = std::sync::OnceLock::new();
    let cache = CACHE.get_or_init(Default::default);
    if let Some(x) = cache.lock().unwrap_or_else(|e| e.into_inner()).get(id) {
        return Some(x.clone());
    }
    if !valid_id(id) {
        return None;
    }
    let tok = crate::bot::bot_token(app);
    if tok.is_empty() {
        return None;
    }
    let api = |m: &str| format!("https://api.telegram.org/bot{}/{}", tok, m);
    let call = |m: &str, body: Value| {
        let r = app.http.post(api(m)).json(&body).timeout(std::time::Duration::from_secs(15)).send();
        async move { let v: Value = r.await.ok()?.json().await.ok()?; (v["ok"] == true).then(|| v["result"].clone()) }
    };
    let st = call("getCustomEmojiStickers", json!({"custom_emoji_ids": [id]})).await?;
    let s = st.as_array()?.first()?.clone();
    // a still sticker is a WebP itself; animated (.tgs) and video ones have a WebP thumbnail
    let (fid, kind) = match s["thumbnail"]["file_id"].as_str() {
        Some(t) => (t.to_string(), "image/webp"),
        None if s["is_animated"] == false && s["is_video"] == false => (s["file_id"].as_str()?.to_string(), "image/webp"),
        None => return None,
    };
    let f = call("getFile", json!({"file_id": fid})).await?;
    let path = f["file_path"].as_str()?;
    let bytes = app.http.get(format!("https://api.telegram.org/file/bot{}/{}", tok, path)).timeout(std::time::Duration::from_secs(15))
        .send().await.ok()?.bytes().await.ok()?.to_vec();
    if bytes.is_empty() || bytes.len() > 512 * 1024 {
        return None;
    }
    let mut c = cache.lock().unwrap_or_else(|e| e.into_inner());
    if c.len() > 300 {
        c.clear();
    }
    c.insert(id.to_string(), (bytes.clone(), kind));
    Some((bytes, kind))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_premium_emoji_takes_the_place_of_the_plain_one() {
        assert_eq!(without_lead_emoji("🛒 خرید اشتراک"), "خرید اشتراک");
        assert_eq!(without_lead_emoji("⬅️ بازگشت"), "بازگشت");
        // a text without a leading emoji stays as it is
        assert_eq!(without_lead_emoji("خرید اشتراک"), "خرید اشتراک");
        assert_eq!(without_lead_emoji("Kanki 🚀"), "Kanki 🚀");
        assert_eq!(without_lead_emoji("🛒"), "🛒");
    }

    #[test]
    fn premium_emoji_in_a_text_are_kept() {
        // "سلام 🔥 خوش آمدی": 🔥 is two UTF-16 units at offset 5
        let m = json!({"entities": [{"type": "custom_emoji", "offset": 5, "length": 2, "custom_emoji_id": "5368324170671202286"}]});
        assert_eq!(keep_custom_emoji("سلام 🔥 خوش آمدی", &m), "سلام <tg-emoji emoji-id=\"5368324170671202286\">🔥</tg-emoji> خوش آمدی");
        // no custom emoji: the same text
        assert_eq!(keep_custom_emoji("سلام", &json!({})), "سلام");
        // a bad id or a place outside the text is left out
        let bad = json!({"entities": [{"type": "custom_emoji", "offset": 50, "length": 2, "custom_emoji_id": "5368324170671202286"}, {"type": "custom_emoji", "offset": 0, "length": 2, "custom_emoji_id": "x"}]});
        assert_eq!(keep_custom_emoji("🔥 hi", &bad), "🔥 hi");
        assert_eq!(first_custom(&m), Some(("5368324170671202286".into(), 5, 2)));
    }

    #[test]
    fn colours_are_shared_where_the_bot_shares_them() {
        assert_eq!(style_key("buy"), Some("buy"));
        assert_eq!(style_key("pay_ton"), Some("pay"));
        assert_eq!(style_key("cfg_w"), Some("cfg"));
        assert_eq!(style_key("back"), None);
        assert!(valid_id("5368324170671202286") && !valid_id("12a") && !valid_id(""));
    }
}
