//! Paying in TON and in Telegram Stars: today's prices (the dollar and TON in toman, from Iranian and world
//! markets) and checking a TON payment on the chain, read only: the bot never holds a key of the wallet,
//! it only reads the public list of payments that came into the owner's address.

use serde_json::Value;
use std::time::Duration;

/// A plan priced in toman, in TON and in Stars at today's rates
pub struct Rates {
    /// toman for one dollar (USDT on Iranian exchanges)
    pub usd_toman: f64,
    /// dollars for one TON
    pub ton_usd: f64,
    /// where the prices came from, for the buyer ("Exir, Nobitex · 12:30")
    pub src: String,
    /// when they were read
    pub at: i64,
}

impl Rates {
    pub fn ton_toman(&self) -> f64 {
        self.ton_usd * self.usd_toman
    }
}

/// What Telegram pays the bot owner for one Star, in dollars (setting `star_usd`, by default Telegram's own
/// rate for developers: 1000 Stars = 13 dollars)
pub fn star_usd(db: &crate::db::Db) -> f64 {
    db.get("star_usd").replace(',', ".").trim().parse::<f64>().ok().filter(|x| *x > 0.0005 && *x < 1.0).unwrap_or(0.013)
}

/// The amount in nanoTON for a toman price: rounded up to 0.001 TON, so the owner never gets less than the price
pub fn ton_nano(toman: i64, r: &Rates) -> u64 {
    let ton = toman as f64 / r.ton_toman();
    ((ton * 1000.0).ceil() as u64) * 1_000_000
}

/// The number of Stars for a toman price (rounded up, at least 1)
pub fn stars_for(toman: i64, r: &Rates, star_usd: f64) -> i64 {
    let star_toman = star_usd * r.usd_toman;
    ((toman as f64 / star_toman).ceil() as i64).max(1)
}

/// "0.252" from nanoTON
pub fn ton_text(nano: u64) -> String {
    let s = format!("{:.3}", nano as f64 / 1e9);
    let s = s.trim_end_matches('0').trim_end_matches('.');
    if s.is_empty() { "0".into() } else { s.to_string() }
}

/// "317,655"
pub fn group(n: f64) -> String {
    let s = (n.round() as i64).to_string();
    let mut o = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i) % 3 == 0 {
            o.push(',');
        }
        o.push(c);
    }
    o
}

fn median(mut v: Vec<f64>) -> Option<f64> {
    v.retain(|x| x.is_finite() && *x > 0.0);
    if v.is_empty() {
        return None;
    }
    v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let n = v.len();
    Some(if n % 2 == 1 { v[n / 2] } else { (v[n / 2 - 1] + v[n / 2]) / 2.0 })
}

fn num(v: &Value) -> Option<f64> {
    v.as_f64().or_else(|| v.as_str().and_then(|s| s.replace(',', "").trim().parse().ok()))
}

async fn get_json(http: &reqwest::Client, url: &str) -> Option<Value> {
    let r = http.get(url).timeout(Duration::from_secs(7)).header("User-Agent", "Mozilla/5.0 (kanki-panel)").send().await.ok()?;
    if !r.status().is_success() {
        return None;
    }
    r.json::<Value>().await.ok()
}

/// One price from each market that answers: (dollar in toman by source, TON in dollars by source)
async fn read_markets(http: &reqwest::Client) -> (Vec<(&'static str, f64)>, Vec<(&'static str, f64)>) {
    let (ex_usd, ex_ton, nb, wx, tonapi, cg) = tokio::join!(
        get_json(http, "https://api.exir.io/v2/ticker?symbol=usdt-irt"),
        get_json(http, "https://api.exir.io/v2/ticker?symbol=ton-usdt"),
        get_json(http, "https://api.nobitex.ir/market/stats?srcCurrency=usdt&dstCurrency=rls"),
        get_json(http, "https://api.wallex.ir/v1/markets"),
        get_json(http, "https://tonapi.io/v2/rates?tokens=ton&currencies=usd"),
        get_json(http, "https://api.coingecko.com/api/v3/simple/price?ids=the-open-network&vs_currencies=usd"),
    );
    let mut usd = vec![];
    let mut ton = vec![];
    // the dollar in toman: only Iranian markets (a world "IRR" rate is the official one, far from the real price)
    if let Some(x) = ex_usd.as_ref().and_then(|v| num(&v["last"])) { usd.push(("Exir", x)); }
    if let Some(x) = nb.as_ref().and_then(|v| num(&v["stats"]["usdt-rls"]["latest"])) { usd.push(("Nobitex", x / 10.0)); }
    if let Some(x) = wx.as_ref().and_then(|v| num(&v["result"]["symbols"]["USDTTMN"]["stats"]["lastPrice"])) { usd.push(("Wallex", x)); }
    if let Some(x) = ex_ton.as_ref().and_then(|v| num(&v["last"])) { ton.push(("Exir", x)); }
    if let Some(x) = wx.as_ref().and_then(|v| num(&v["result"]["symbols"]["TONUSDT"]["stats"]["lastPrice"])) { ton.push(("Wallex", x)); }
    if let Some(x) = tonapi.as_ref().and_then(|v| num(&v["rates"]["TON"]["prices"]["USD"])) { ton.push(("TonAPI", x)); }
    if let Some(x) = cg.as_ref().and_then(|v| num(&v["the-open-network"]["usd"])) { ton.push(("CoinGecko", x)); }
    // a price far outside what a market can be is a broken answer, not a price
    usd.retain(|x| x.1 > 10_000.0 && x.1 < 50_000_000.0);
    ton.retain(|x| x.1 > 0.01 && x.1 < 10_000.0);
    (usd, ton)
}

/// The middle of the prices, after dropping any more than 15% from it (one market with a wrong price)
fn agree(list: &[(&'static str, f64)]) -> Option<(f64, Vec<&'static str>)> {
    let m = median(list.iter().map(|x| x.1).collect())?;
    let good: Vec<&(&str, f64)> = list.iter().filter(|x| (x.1 / m - 1.0).abs() <= 0.15).collect();
    let v = median(good.iter().map(|x| x.1).collect())?;
    Some((v, good.iter().map(|x| x.0).collect()))
}

/// Today's prices: read again after 5 minutes; when no market answers, the last prices for up to 2 hours,
/// and for the dollar the admin's own rate (Sales › Toman per dollar). None = no price to sell with.
pub async fn rates(app: &crate::App) -> Option<Rates> {
    let db = &app.db;
    let now = crate::util::now();
    let cached = || -> Option<Rates> {
        let usd: f64 = db.get("rate_usd_toman").parse().ok()?;
        let ton: f64 = db.get("rate_ton_usd").parse().ok()?;
        let at: i64 = db.get("rate_at").parse().ok()?;
        (usd > 0.0 && ton > 0.0).then(|| Rates { usd_toman: usd, ton_usd: ton, src: db.get("rate_src"), at })
    };
    if let Some(c) = cached() {
        if now - c.at < 300 {
            return Some(c);
        }
    }
    let (usd, ton) = read_markets(&app.http).await;
    let manual: f64 = db.get("usd_rate").replace([',', '٬'], "").trim().parse().unwrap_or(0.0);
    let old = cached().filter(|c| now - c.at < 7200);
    let (u, mut src) = match agree(&usd) {
        Some((v, s)) => (v, s),
        None => match &old {
            Some(c) => return Some(Rates { usd_toman: c.usd_toman, ton_usd: agree(&ton).map(|x| x.0).unwrap_or(c.ton_usd), src: c.src.clone(), at: c.at }),
            None if manual > 0.0 => (manual, vec!["نرخ دستی"]),
            None => return None,
        },
    };
    let t = match agree(&ton) {
        Some((v, s)) => {
            for x in s { if !src.contains(&x) { src.push(x); } }
            v
        }
        None => old.as_ref().map(|c| c.ton_usd)?,
    };
    let r = Rates { usd_toman: u, ton_usd: t, src: src.join("، "), at: now };
    db.set("rate_usd_toman", &r.usd_toman.to_string());
    db.set("rate_ton_usd", &r.ton_usd.to_string());
    db.set("rate_at", &now.to_string());
    db.set("rate_src", &r.src);
    Some(r)
}

// ============================================================ TON on the chain

/// One payment that came into the wallet
#[derive(Debug, Clone, PartialEq)]
pub struct TonIn {
    /// the transaction hash (base64, as toncenter gives it)
    pub hash: String,
    /// what really reached the wallet, in nanoTON
    pub nano: u128,
    /// its text comment ("" = none)
    pub comment: String,
    /// when it was made (unix seconds)
    pub at: i64,
    /// the account it reached (raw "0:HEX")
    pub account: String,
}

/// The raw form "0:HEX" (upper case) of a TON address written either way (UQ…/EQ… or 0:…); None = not an address
pub fn raw_address(a: &str) -> Option<String> {
    let a = a.trim();
    if let Some((wc, h)) = a.split_once(':') {
        let wc: i32 = wc.parse().ok()?;
        if h.len() == 64 && h.chars().all(|c| c.is_ascii_hexdigit()) {
            return Some(format!("{}:{}", wc, h.to_uppercase()));
        }
        return None;
    }
    if a.len() != 48 {
        return None;
    }
    let t = a.replace('-', "+").replace('_', "/");
    let b = crate::tunnel::link::b64decode(&t)?;
    if b.len() != 36 || crc16(&b[..34]) != u16::from_be_bytes([b[34], b[35]]) {
        return None;
    }
    Some(format!("{}:{}", b[1] as i8, hex::encode_upper(&b[2..34])))
}

/// CRC-16/XMODEM, the checksum of a user-friendly TON address
fn crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &x in data {
        crc ^= (x as u16) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 { (crc << 1) ^ 0x1021 } else { crc << 1 };
        }
    }
    crc
}

/// The payments in a toncenter v3 answer that really stayed in the wallet: a message from another wallet
/// (not an external one), not bounced, nothing sent back in the same transaction, finished on the chain
pub fn incoming(v: &Value) -> Vec<TonIn> {
    let Some(list) = v["transactions"].as_array() else { return vec![] };
    list.iter().filter_map(|t| {
        let m = &t["in_msg"];
        let source = m["source"].as_str().unwrap_or("");
        if source.is_empty() || m["bounced"].as_bool().unwrap_or(false) || t["emulated"].as_bool().unwrap_or(false) {
            return None;
        }
        if t["finality"].as_str().map(|f| f != "finalized").unwrap_or(false) {
            return None;
        }
        // a bounce or any message out of the wallet in the same transaction: the money did not stay
        if t["out_msgs"].as_array().map(|o| !o.is_empty()).unwrap_or(false) {
            return None;
        }
        let d = &t["description"];
        if d["aborted"].as_bool().unwrap_or(false) && d["bounce"]["type"].as_str() == Some("ok") {
            return None;
        }
        let value: u128 = m["value"].as_str().and_then(|s| s.parse().ok()).unwrap_or(0);
        // what the credit phase put on the account; never more than the message carried
        let credit: u128 = d["credit_ph"]["credit"].as_str().and_then(|s| s.parse().ok()).unwrap_or(value);
        let nano = credit.min(value);
        if nano == 0 {
            return None;
        }
        let dec = &m["message_content"]["decoded"];
        let comment = if dec["type"].as_str() == Some("text_comment") { dec["comment"].as_str().unwrap_or("").to_string() } else { String::new() };
        Some(TonIn {
            hash: t["hash"].as_str().unwrap_or("").to_string(),
            nano,
            comment,
            at: t["now"].as_i64().unwrap_or(0),
            account: t["account"].as_str().unwrap_or("").to_uppercase(),
        })
    }).filter(|x| !x.hash.is_empty()).collect()
}

/// A comment as the buyer may have typed it: no spaces, upper case ("kanki-12-ab3" = "KANKI-12-AB3")
pub fn same_memo(a: &str, b: &str) -> bool {
    let n = |s: &str| s.chars().filter(|c| !c.is_whitespace()).collect::<String>().to_uppercase();
    !a.trim().is_empty() && n(a) == n(b)
}

/// The transaction hash in what a buyer sent: a Tonviewer / Tonscan / Tonkeeper link or the bare hash
/// (64 hex, or 44 base64); None when there is none
pub fn hash_in(text: &str) -> Option<String> {
    // each word whole (a bare base64 hash has '/' in it), then the parts of a link
    let words: Vec<&str> = text.split_whitespace().collect();
    let parts = words.iter().flat_map(|w| w.split(|c: char| c == '/' || c == '?' || c == '#' || c == '&' || c == '='));
    for w in words.iter().copied().chain(parts) {
        let w = w.trim_matches(|c: char| c == '"' || c == '\'' || c == '<' || c == '>' || c == '.' || c == ',');
        if w.len() == 64 && w.chars().all(|c| c.is_ascii_hexdigit()) {
            return Some(w.to_lowercase());
        }
        if (w.len() == 43 || w.len() == 44) && w.chars().all(|c| c.is_ascii_alphanumeric() || "+/-_=".contains(c)) && w.chars().any(|c| c.is_ascii_digit()) {
            let t = w.replace('-', "+").replace('_', "/");
            let t = if t.len() == 43 { format!("{}=", t) } else { t };
            if let Some(b) = crate::tunnel::link::b64decode(&t) {
                if b.len() == 32 {
                    return Some(hex::encode(b));
                }
            }
        }
    }
    None
}

fn toncenter(db: &crate::db::Db) -> String {
    let u = db.get("toncenter_url");
    if u.trim().is_empty() { "https://toncenter.com/api/v3".into() } else { u.trim().trim_end_matches('/').to_string() }
}

async fn tc_get(app: &crate::App, path: &str) -> Result<Value, String> {
    let url = format!("{}{}", toncenter(&app.db), path);
    let mut rq = app.http.get(&url).timeout(Duration::from_secs(12));
    let key = app.db.get("toncenter_key");
    if !key.trim().is_empty() {
        rq = rq.header("X-API-Key", key.trim());
    }
    let r = rq.send().await.map_err(|e| e.to_string())?;
    let st = r.status();
    let v: Value = r.json().await.map_err(|e| e.to_string())?;
    if !st.is_success() {
        return Err(format!("toncenter {}: {}", st.as_u16(), v["error"].as_str().unwrap_or("")));
    }
    Ok(v)
}

/// The payments into the wallet since a time (newest first; up to 256, so a flood of tiny spam payments
/// cannot push an order's payment out of the list within its hours)
pub async fn recent(app: &crate::App, address: &str, since: i64) -> Result<Vec<TonIn>, String> {
    let v = tc_get(app, &format!("/transactions?account={}&start_utime={}&limit=256&sort=desc", address.trim(), since.max(0))).await?;
    Ok(incoming(&v))
}

/// The payment into this wallet with this hash: the transaction's own hash, or the hash of the message that
/// made it (what some wallets and explorers show)
pub async fn by_hash(app: &crate::App, address: &str, hash_hex: &str) -> Result<Option<TonIn>, String> {
    let me = raw_address(address).ok_or("bad address")?;
    for path in [format!("/transactions?hash={}", hash_hex), format!("/transactionsByMessage?msg_hash={}&direction=in", hash_hex)] {
        if let Ok(v) = tc_get(app, &path).await {
            if let Some(t) = incoming(&v).into_iter().find(|t| t.account == me) {
                return Ok(Some(t));
            }
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The real markets (needs the internet): `cargo test live_markets -- --ignored --nocapture`
    #[tokio::test]
    #[ignore]
    async fn live_markets() {
        let (usd, ton) = read_markets(&reqwest::Client::new()).await;
        println!("dollar: {:?}\nTON: {:?}", usd, ton);
        assert!(agree(&usd).is_some() && agree(&ton).is_some());
    }

    /// Real payments of a busy wallet read the same way (needs the internet)
    #[tokio::test]
    #[ignore]
    async fn live_toncenter() {
        let v: Value = reqwest::get("https://toncenter.com/api/v3/transactions?account=UQCD39VS5jcptHL8vMjEXrzGaRcCVYto7HUn4bpAOg8xqEBI&limit=30&sort=desc")
            .await.unwrap().json().await.unwrap();
        let got = incoming(&v);
        println!("{} of {}: {:?}", got.len(), v["transactions"].as_array().map(|a| a.len()).unwrap_or(0), got.iter().take(3).collect::<Vec<_>>());
        assert!(got.iter().all(|t| t.account == raw_address("UQCD39VS5jcptHL8vMjEXrzGaRcCVYto7HUn4bpAOg8xqEBI").unwrap()));
    }

    #[test]
    fn prices_round_up_for_the_owner() {
        let r = Rates { usd_toman: 271_500.0, ton_usd: 1.17, src: String::new(), at: 0 };
        // 80,000 toman / 317,655 = 0.25185 TON → 0.252
        assert_eq!(ton_nano(80_000, &r), 252_000_000);
        assert_eq!(ton_text(252_000_000), "0.252");
        assert_eq!(ton_text(2_000_000_000), "2");
        // a Star is 0.013 $ = 3,529.5 toman → 80,000 toman = 22.67 → 23 Stars
        assert_eq!(stars_for(80_000, &r, 0.013), 23);
        assert_eq!(group(317_655.4), "317,655");
    }

    #[test]
    fn a_wrong_market_price_is_left_out() {
        let (v, s) = agree(&[("Exir", 271_500.0), ("Nobitex", 270_000.0), ("Wallex", 27_000.0)]).unwrap();
        assert!((v - 270_750.0).abs() < 1.0, "{}", v);
        assert_eq!(s, vec!["Exir", "Nobitex"]);
        assert!(agree(&[]).is_none());
    }

    #[test]
    fn addresses_both_ways() {
        let raw = "0:83DFD552E63729B472FCBCC8C45EBCC6691702558B68EC7527E1BA403A0F31A8";
        assert_eq!(raw_address("UQCD39VS5jcptHL8vMjEXrzGaRcCVYto7HUn4bpAOg8xqEBI").as_deref(), Some(raw));
        assert_eq!(raw_address("EQCD39VS5jcptHL8vMjEXrzGaRcCVYto7HUn4bpAOg8xqB2N").as_deref(), Some(raw));
        assert_eq!(raw_address(&raw.to_lowercase()).as_deref(), Some(raw));
        // one letter changed: the checksum fails
        assert!(raw_address("UQCD39VS5jcptHL8vMjEXrzGaRcCVYto7HUn4bpAOg8xqEBJ").is_none());
        assert!(raw_address("hello").is_none());
    }

    fn tx(hash: &str, value: &str, comment: &str, out: Value, extra: Value) -> Value {
        let mut t = json!({
            "account": "0:83DFD552E63729B472FCBCC8C45EBCC6691702558B68EC7527E1BA403A0F31A8", "hash": hash, "now": 1_800_000_000,
            "description": {"aborted": false, "credit_ph": {"credit": value}},
            "in_msg": {"source": "0:ADDC", "value": value, "bounced": false,
                "message_content": {"decoded": {"type": "text_comment", "comment": comment}}},
            "out_msgs": out, "finality": "finalized"
        });
        if let (Some(o), Some(e)) = (t.as_object_mut(), extra.as_object()) {
            for (k, v) in e { o.insert(k.clone(), v.clone()); }
        }
        t
    }

    #[test]
    fn only_money_that_stayed_counts() {
        let v = json!({"transactions": [
            tx("A", "252000000", "KANKI-7-X1", json!([]), json!({})),
            // sent back in the same transaction (a bounce)
            tx("B", "252000000", "KANKI-8-X1", json!([{"destination": "0:ADDC"}]), json!({})),
            // an external message (the wallet's own outgoing transfer)
            tx("C", "5", "", json!([]), json!({"in_msg": {"source": null, "value": "0"}})),
            // still being processed
            tx("D", "252000000", "KANKI-9-X1", json!([]), json!({"finality": "pending"})),
            // emulated, not on the chain
            tx("E", "252000000", "KANKI-9-X1", json!([]), json!({"emulated": true})),
        ]});
        let got = incoming(&v);
        assert_eq!(got.len(), 1, "{:?}", got);
        assert_eq!(got[0].hash, "A");
        assert_eq!(got[0].nano, 252_000_000);
        assert_eq!(got[0].comment, "KANKI-7-X1");
        assert!(same_memo(" kanki-7-x1 ", "KANKI-7-X1"));
        assert!(!same_memo("", ""));
    }

    #[test]
    fn hashes_in_links() {
        let h = "a".repeat(64);
        assert_eq!(hash_in(&format!("https://tonviewer.com/transaction/{}", h)).as_deref(), Some(h.as_str()));
        assert_eq!(hash_in(&format!("https://tonscan.org/tx/{}", h.to_uppercase())).as_deref(), Some(h.as_str()));
        // base64 (toncenter's own form) becomes hex
        assert_eq!(hash_in("DFx067sIC0AA1VKRRZ4eft/5LQW2QZcCMVfO9ZT46Fo=").map(|x| x.len()), Some(64));
        assert_eq!(hash_in("https://tonscan.org/tx/DFx067sIC0AA1VKRRZ4eft_5LQW2QZcCMVfO9ZT46Fo").map(|x| x.len()), Some(64));
        assert!(hash_in("سلام پرداخت کردم").is_none());
    }
}
