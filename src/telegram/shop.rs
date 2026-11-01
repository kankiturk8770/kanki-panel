//! Custom purchases: any volume, days and users, priced with the same rules as the panel's smart plan
//! builder (setting `price_rules`, `smartPrice` in panel.js), so a custom plan costs what a listed plan of
//! the same size costs.
//!
//! A custom purchase becomes a plan row with active = 2: never listed in the bot or the panel, payable once
//! like any plan, kept for the orders that point at it.

use crate::db::Db;
use serde_json::{json, Value};

/// The price rules (same defaults as `smartRules` in panel.js)
#[derive(Clone, Debug, PartialEq)]
pub struct Rules {
    pub gb: f64,
    pub base: f64,
    pub country: f64,
    pub conn: f64,
    pub round: f64,
    pub bulk: f64,
}

pub fn rules(db: &Db) -> Rules {
    let v: Value = serde_json::from_str(&db.get("price_rules")).unwrap_or(json!({}));
    let n = |k: &str, d: f64| -> f64 {
        match &v[k] {
            Value::Number(x) => x.as_f64().unwrap_or(d),
            Value::String(s) => s.trim().parse().unwrap_or(d),
            _ => d,
        }
    };
    Rules { gb: n("gb", 3000.0), base: n("base", 20000.0), country: n("country", 15000.0), conn: n("conn", 20000.0), round: n("round", 5000.0), bulk: n("bulk", 10.0) }
}

/// Toman price of `gb` GB for `days` days and `conns` users (`countries` 0 or 1 = all servers), exactly as
/// panel.js smartPrice: base and per-user / per-country parts per month, the volume once, a discount from
/// 50 GB (double from 100 GB, at most 40 %), rounded.
pub fn price(r: &Rules, gb: f64, days: i64, conns: i64, countries: i64) -> i64 {
    let m = (days as f64 / 30.0).max(1.0);
    let mut p = r.base * m + gb * r.gb + ((conns - 1).max(0) as f64) * r.conn * m + ((countries.max(1) - 1) as f64) * r.country * m;
    if gb >= 50.0 && r.bulk > 0.0 {
        p *= 1.0 - (r.bulk * if gb >= 100.0 { 2.0 } else { 1.0 }).min(40.0) / 100.0;
    }
    let rd = if r.round > 0.0 { r.round } else { 1000.0 };
    ((p / rd).round() * rd).max(rd) as i64
}

/// What a buyer may choose: on/off, volume range, durations, most users
#[derive(Clone, Debug, PartialEq)]
pub struct Limits {
    pub on: bool,
    pub min_gb: i64,
    pub max_gb: i64,
    pub days: Vec<i64>,
    pub users: i64,
}

pub fn limits(db: &Db) -> Limits {
    let num = |k: &str, d: i64| db.get(k).trim().parse::<i64>().ok().filter(|x| *x > 0).unwrap_or(d);
    let mut days: Vec<i64> = db.get("cp_days").split([',', '،', ' ']).filter_map(|x| x.trim().parse().ok()).filter(|d: &i64| (1..=730).contains(d)).collect();
    if days.is_empty() {
        days = vec![30, 60, 90];
    }
    days.sort();
    days.dedup();
    let min_gb = num("cp_min_gb", 10).clamp(1, 5000);
    Limits { on: db.get("cp_on") != "0", min_gb, max_gb: num("cp_max_gb", 200).clamp(min_gb, 5000), days, users: num("cp_users", 3).clamp(1, 10) }
}

/// The plan row of one custom purchase (an identical earlier one is reused); Err says what is not allowed
pub fn custom_plan(db: &Db, gb: i64, days: i64, users: i64) -> Result<i64, String> {
    let l = limits(db);
    if !l.on {
        return Err("custom purchase is off".into());
    }
    if gb < l.min_gb || gb > l.max_gb || !l.days.contains(&days) || users < 1 || users > l.users {
        return Err("that volume, duration or number of users is not offered".into());
    }
    let toman = price(&rules(db), gb as f64, days, users, 0);
    let name = format!("دلخواه · {} گیگ · {} روزه{}", gb, days, if users > 1 { format!(" · {} کاربره", users) } else { String::new() });
    let old: Option<i64> = db.with(|c| {
        c.query_row("SELECT id FROM plans WHERE active=2 AND name=?1 AND toman=?2 AND gb=?3 AND days=?4 AND conns=?5",
            rusqlite::params![name, toman, gb as f64, days, users], |r| r.get(0)).ok()
    });
    if let Some(id) = old {
        return Ok(id);
    }
    db.with(|c| {
        c.execute("INSERT INTO plans(name,days,gb,toman,usd,conns,countries,active,category) VALUES(?1,?2,?3,?4,0,?5,0,2,'')",
            rusqlite::params![name, days, gb as f64, toman, users]).map_err(|e| e.to_string())?;
        Ok(c.last_insert_rowid())
    })
}

/// For the mini app: the rules and limits, so the page shows the price while the buyer chooses
pub fn custom_json(db: &Db) -> Value {
    let (r, l) = (rules(db), limits(db));
    json!({
        "on": l.on, "min_gb": l.min_gb, "max_gb": l.max_gb, "days": l.days, "users": l.users,
        "rules": { "gb": r.gb, "base": r.base, "country": r.country, "conn": r.conn, "round": r.round, "bulk": r.bulk },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_price_is_the_one_the_panel_builder_shows() {
        // the same numbers panel.js smartPrice gives with its default rules
        let r = Rules { gb: 3000.0, base: 20000.0, country: 15000.0, conn: 20000.0, round: 5000.0, bulk: 10.0 };
        assert_eq!(price(&r, 10.0, 30, 1, 1), 50000);
        assert_eq!(price(&r, 50.0, 30, 2, 1), 170000);
        assert_eq!(price(&r, 100.0, 90, 1, 1), 290000);
        assert_eq!(price(&r, 20.0, 60, 3, 1), 180000);
        assert_eq!(price(&r, 7.0, 45, 1, 1), 50000);
        assert_eq!(price(&r, 10.0, 30, 1, 0), 50000);
    }

    fn db() -> Db {
        let dir = std::env::temp_dir().join(format!("kanki-shop-test-{}", crate::util::rand_token(8)));
        std::fs::create_dir_all(&dir).unwrap();
        Db::open(dir.join("kanki.db").to_str().unwrap())
    }

    #[test]
    fn a_custom_plan_is_priced_hidden_and_made_once() {
        let d = db();
        d.set("price_rules", r#"{"gb":"4000","base":10000,"round":1000}"#);
        let a = custom_plan(&d, 25, 30, 1).unwrap();
        assert_eq!(custom_plan(&d, 25, 30, 1).unwrap(), a);
        let (toman, active): (i64, i64) = d.with(|c| c.query_row("SELECT toman,active FROM plans WHERE id=?1", [a], |r| Ok((r.get(0)?, r.get(1)?))).unwrap());
        assert_eq!((toman, active), (110000, 2));
        // outside what is offered
        assert!(custom_plan(&d, 5, 30, 1).is_err());
        assert!(custom_plan(&d, 25, 45, 1).is_err());
        assert!(custom_plan(&d, 25, 30, 4).is_err());
        d.set("cp_on", "0");
        assert!(custom_plan(&d, 25, 30, 1).is_err());
    }

    #[test]
    fn limits_read_the_settings() {
        let d = db();
        assert_eq!(limits(&d), Limits { on: true, min_gb: 10, max_gb: 200, days: vec![30, 60, 90], users: 3 });
        d.set("cp_days", "90, 30,30 x 365");
        d.set("cp_users", "2");
        let l = limits(&d);
        assert_eq!((l.days, l.users), (vec![30, 90, 365], 2));
    }
}
