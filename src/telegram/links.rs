//! The links bot: a second, separate Telegram bot that gives the standard links for other apps
//! (v2rayNG, Hiddify, V2Box…): Hysteria2 / WireGuard / Xray links and the AmneziaWG config files.
//! With "Kanki apps only" these links are nowhere on the web; this bot is the only place to get them.
//!
//! The customer sends the subscription code or link (or opens t.me/<bot>?start=<code> from the sales bot or
//! the subscription page). Token: setting `links_bot_token` (Settings › Apps & devices); empty = off.
use crate::db::User;
use crate::util::esc;
use crate::App;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;

const API: &str = "https://api.telegram.org";

fn token(app: &App) -> String {
    app.db.get("links_bot_token").trim().to_string()
}

/// A subscription code inside any text: a full link, `/start <code>` or the bare code
pub fn find_code(text: &str) -> Option<String> {
    for w in text.split(|c: char| c.is_whitespace() || c == '/' || c == '?' || c == '&' || c == '=') {
        let w = w.trim_matches(|c: char| !c.is_ascii_alphanumeric());
        if crate::api::parse_code(w).is_some() && w.rsplit('-').next().map(|c| c.len() >= 4).unwrap_or(false) {
            return Some(w.to_string());
        }
    }
    None
}

struct Bot {
    app: Arc<App>,
    token: String,
    http: reqwest::Client,
}

impl Bot {
    async fn call(&self, m: &str, body: Value) -> Result<Value, String> {
        let r = self.http.post(format!("{}/bot{}/{}", API, self.token, m)).json(&body).send().await.map_err(|e| e.to_string())?;
        let v: Value = r.json().await.map_err(|e| e.to_string())?;
        if v["ok"].as_bool() == Some(true) {
            Ok(v["result"].clone())
        } else {
            Err(v["description"].as_str().unwrap_or("telegram error").to_string())
        }
    }

    async fn send(&self, chat: i64, text: &str) {
        let _ = self.call("sendMessage", json!({"chat_id": chat, "text": text, "parse_mode": "HTML", "disable_web_page_preview": true})).await;
    }

    async fn send_doc(&self, chat: i64, bytes: Vec<u8>, name: &str, caption: &str) {
        let part = reqwest::multipart::Part::bytes(bytes).file_name(name.to_string());
        let form = reqwest::multipart::Form::new().text("chat_id", chat.to_string()).text("caption", caption.to_string()).part("document", part);
        let _ = self.http.post(format!("{}/bot{}/sendDocument", API, self.token)).multipart(form).send().await;
    }

    async fn on_message(&self, m: &Value) {
        let chat = m["chat"]["id"].as_i64().unwrap_or(0);
        // private chats only: links must not land in a group
        if chat == 0 || m["chat"]["type"].as_str() != Some("private") {
            return;
        }
        let text = m["text"].as_str().unwrap_or("");
        let Some(code) = find_code(text) else {
            return self.send(chat, HELP).await;
        };
        // a few codes per chat: this is not a place to guess codes
        if !crate::limit::hit("links_bot", &chat.to_string(), 10, 600) {
            return self.send(chat, "⏳ چند دقیقه دیگر دوباره امتحان کنید.\nTry again in a few minutes.").await;
        }
        let user = crate::api::parse_code(&code).and_then(|(id, c)| self.app.db.user_by_code(id, &c));
        let Some(u) = user else {
            return self.send(chat, "❌ این کد اشتراک پیدا نشد.\nSubscription code not found.").await;
        };
        if !u.active() {
            return self.send(chat, &format!("🔴 <b>{}</b>: اشتراک فعال نیست ({}).\nThe subscription is not active.", esc(&u.username), u.status())).await;
        }
        self.send_links(chat, &u).await;
    }

    async fn send_links(&self, chat: i64, u: &User) {
        let links = crate::api::other_app_links(&self.app, u);
        let mut msg = format!("👤 <b>{}</b>\n🔗 لینک‌ها برای برنامه‌های دیگر (v2rayNG، Hiddify، V2Box …). روی هر لینک بزنید تا کپی شود.\nLinks for other apps: tap one to copy it.\n", esc(&u.username));
        for l in &links {
            let part = format!("\n<code>{}</code>\n", esc(l));
            // Telegram's limit is 4096 characters a message
            if msg.len() + part.len() > 3900 {
                self.send(chat, &msg).await;
                msg.clear();
            }
            msg.push_str(&part);
        }
        if links.is_empty() {
            msg.push_str("\n—");
        }
        self.send(chat, &msg).await;
        // AmneziaWG has no link format: its config files
        for n in crate::api::user_nodes(&self.app, u) {
            for tunnel in [false, true] {
                let protos = if tunnel { crate::api::twin_protos(&self.app, u, &n) } else { crate::api::node_protos(&self.app, u, &n) };
                if !protos.contains(&"amneziawg") {
                    continue;
                }
                if let Some((name, text)) = crate::api::bot_config(&self.app, u, &n, "amneziawg", tunnel).await {
                    self.send_doc(chat, text.into_bytes(), &name, "AmneziaWG").await;
                }
            }
        }
    }
}

const HELP: &str = "سلام! کد یا لینک اشتراک خود را بفرستید تا لینک‌های برنامه‌های دیگر (v2rayNG و …) را بگیرید.\nSend your subscription code or link to get the links for other apps.";

/// Runs the links bot while it has a token; a new token in the settings is picked up within a minute
pub async fn run(app: Arc<App>) {
    let http = reqwest::Client::builder().timeout(Duration::from_secs(60)).build().unwrap_or_default();
    let mut offset = 0i64;
    let mut cur = String::new();
    loop {
        let t = token(&app);
        if t.is_empty() {
            if !app.db.get("links_bot_user").is_empty() {
                app.db.set("links_bot_user", "");
            }
            tokio::time::sleep(Duration::from_secs(30)).await;
            continue;
        }
        let bot = Arc::new(Bot { app: app.clone(), token: t.clone(), http: http.clone() });
        if t != cur {
            // its @username, for the subscription page and the sales bot
            match bot.call("getMe", json!({})).await {
                Ok(me) => app.db.set("links_bot_user", me["username"].as_str().unwrap_or("")),
                Err(_) => {
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    continue;
                }
            }
            cur = t;
            offset = 0;
        }
        let res = bot.call("getUpdates", json!({"offset": offset, "timeout": 25, "allowed_updates": ["message"]})).await;
        let Ok(Value::Array(list)) = res else {
            if let Err(e) = &res {
                if e.contains("webhook is active") {
                    let _ = bot.call("deleteWebhook", json!({"drop_pending_updates": false})).await;
                }
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
            continue;
        };
        for u in list {
            offset = u["update_id"].as_i64().unwrap_or(offset) + 1;
            let b = bot.clone();
            tokio::spawn(async move {
                if u["message"].is_object() {
                    b.on_message(&u["message"]).await;
                }
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::find_code;

    #[test]
    fn finds_the_code_in_any_message() {
        assert_eq!(find_code("/start kanki-12-4821930012"), Some("kanki-12-4821930012".into()));
        assert_eq!(find_code("https://sub.kanki.pro:2053/sub/kanki-12-4821930012"), Some("kanki-12-4821930012".into()));
        assert_eq!(find_code("kod man: kanki-7-abcd1234 mamnoon"), Some("kanki-7-abcd1234".into()));
        assert_eq!(find_code("salam"), None);
        assert_eq!(find_code("/start"), None);
    }
}
