//! The one price list of the shop: every listed plan and every custom purchase is priced by the same
//! formula (setting `pricing`, defaults below), so a custom plan costs what a listed plan of the same size
//! costs plus a small margin. The mini app gets the same numbers (`custom_json`) and shows the same price;
//! the price the customer pays is always the one computed here.
//!
//! price = base + factor × volume + (users − 1) × per user + (days / 30 − 1) × per month, rounded
//! volume = the GB priced tier by tier (the first GB at one rate, the next at another, …)
//!
//! A custom purchase becomes a plan row with active = 2: never listed in the bot or the panel, payable once
//! like any plan, kept for the orders that point at it.

use crate::db::Db;
use serde_json::{json, Value};

/// The three services, in the order the shop shows them
pub const SERVICES: &[&str] = &["v2ray", "game", "vip"];

/// One service's part of the price
#[derive(Clone, Debug, PartialEq)]
pub struct Svc {
    pub base: f64,
    pub factor: f64,
    pub user: f64,
    pub month: f64,
}

/// The whole price list
#[derive(Clone, Debug, PartialEq)]
pub struct Pricing {
    /// (up to this many GB, toman per GB in this tier); 0 = no upper end (the last tier)
    pub tiers: Vec<(f64, f64)>,
    pub v2ray: Svc,
    pub game: Svc,
    pub vip: Svc,
    /// extra percent on a custom purchase
    pub margin: f64,
    pub round: f64,
    pub min_gb: i64,
    pub max_gb: i64,
    pub min_days: i64,
    pub max_days: i64,
    pub step_days: i64,
    pub max_users: i64,
}

impl Default for Pricing {
    fn default() -> Self {
        Pricing {
            // these reproduce the shop's one-month VIP prices: 20 GB 80,000, 50 GB 110,000, 100 GB 170,000
            tiers: vec![(20.0, 1500.0), (50.0, 1000.0), (100.0, 1200.0), (0.0, 800.0)],
            v2ray: Svc { base: 25000.0, factor: 0.9, user: 20000.0, month: 30000.0 },
            game: Svc { base: 37000.0, factor: 0.9, user: 20000.0, month: 30000.0 },
            vip: Svc { base: 50000.0, factor: 1.0, user: 25000.0, month: 35000.0 },
            margin: 10.0,
            round: 1000.0,
            min_gb: 10,
            max_gb: 300,
            min_days: 15,
            max_days: 180,
            step_days: 15,
            max_users: 4,
        }
    }
}

impl Pricing {
    pub fn svc(&self, s: &str) -> &Svc {
        match s {
            "v2ray" => &self.v2ray,
            "game" => &self.game,
            _ => &self.vip,
        }
    }

    /// The volume part, tier by tier
    pub fn volume(&self, gb: f64) -> f64 {
        let (mut prev, mut v) = (0.0f64, 0.0f64);
        for (upto, rate) in self.tiers.iter() {
            let top = if *upto <= 0.0 { f64::INFINITY } else { *upto };
            let take = gb.min(top) - prev;
            if take > 0.0 {
                v += take * rate;
            }
            if gb <= top {
                break;
            }
            prev = top;
        }
        v
    }

    /// Toman price of `gb` GB for `days` days and `users` users of a service; `custom` adds the margin
    pub fn price(&self, svc: &str, gb: f64, days: i64, users: i64, custom: bool) -> i64 {
        let s = self.svc(svc);
        let mut p = s.base + s.factor * self.volume(gb.max(0.0)) + ((users.max(1) - 1) as f64) * s.user + (days as f64 / 30.0 - 1.0) * s.month;
        if custom {
            p *= 1.0 + self.margin / 100.0;
        }
        let rd = if self.round > 0.0 { self.round } else { 1000.0 };
        ((p / rd).round() * rd).max(rd) as i64
    }

    pub fn to_json(&self) -> Value {
        let s = |x: &Svc| json!({ "base": x.base, "factor": x.factor, "user": x.user, "month": x.month });
        json!({
            "tiers": self.tiers.iter().map(|(a, b)| json!([a, b])).collect::<Vec<_>>(),
            "services": { "v2ray": s(&self.v2ray), "game": s(&self.game), "vip": s(&self.vip) },
            "margin": self.margin, "round": self.round,
            "gb": [self.min_gb, self.max_gb], "days": [self.min_days, self.max_days, self.step_days], "users": self.max_users,
        })
    }
}

fn num(v: &Value) -> Option<f64> {
    match v {
        Value::Number(x) => x.as_f64(),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
    .filter(|x: &f64| x.is_finite())
}

/// The price list from a JSON object (any part missing or wrong keeps its default); Err for a value out of range
pub fn parse(v: &Value) -> Result<Pricing, String> {
    let mut p = Pricing::default();
    if let Some(a) = v["tiers"].as_array() {
        let mut t = vec![];
        for x in a {
            let (Some(upto), Some(rate)) = (num(&x[0]), num(&x[1])) else { return Err("tiers".into()) };
            if !(0.0..=100000.0).contains(&upto) || !(0.0..=1_000_000.0).contains(&rate) {
                return Err("tiers".into());
            }
            t.push((upto, rate));
        }
        // rising upper ends, the open one (0) last
        let ends: Vec<f64> = t.iter().map(|x| x.0).collect();
        let open = ends.iter().position(|e| *e <= 0.0);
        if t.is_empty() || open.is_some_and(|i| i != ends.len() - 1) || ends.iter().filter(|e| **e > 0.0).collect::<Vec<_>>().windows(2).any(|w| w[0] >= w[1]) {
            return Err("tiers".into());
        }
        if open.is_none() {
            let last = t.last().map(|x| x.1).unwrap_or(0.0);
            t.push((0.0, last));
        }
        p.tiers = t;
    }
    for (k, s) in [("v2ray", &mut p.v2ray), ("game", &mut p.game), ("vip", &mut p.vip)] {
        let o = &v["services"][k];
        for (f, slot, max) in [("base", &mut s.base, 10_000_000.0), ("factor", &mut s.factor, 10.0), ("user", &mut s.user, 10_000_000.0), ("month", &mut s.month, 10_000_000.0)] {
            if let Some(x) = num(&o[f]) {
                if !(0.0..=max).contains(&x) {
                    return Err(format!("{}.{}", k, f));
                }
                *slot = x;
            }
        }
    }
    if let Some(x) = num(&v["margin"]) {
        if !(0.0..=100.0).contains(&x) { return Err("margin".into()); }
        p.margin = x;
    }
    if let Some(x) = num(&v["round"]) {
        if !(1.0..=1_000_000.0).contains(&x) { return Err("round".into()); }
        p.round = x;
    }
    let int = |x: &Value| num(x).map(|f| f.round() as i64);
    if let (Some(a), Some(b)) = (int(&v["gb"][0]), int(&v["gb"][1])) {
        if a < 1 || b < a || b > 5000 { return Err("gb".into()); }
        (p.min_gb, p.max_gb) = (a, b);
    }
    if let (Some(a), Some(b)) = (int(&v["days"][0]), int(&v["days"][1])) {
        let st = int(&v["days"][2]).unwrap_or(p.step_days);
        if a < 1 || b < a || b > 730 || st < 1 { return Err("days".into()); }
        (p.min_days, p.max_days, p.step_days) = (a, b, st);
    }
    if let Some(u) = int(&v["users"]) {
        if !(1..=10).contains(&u) { return Err("users".into()); }
        p.max_users = u;
    }
    Ok(p)
}

/// The shop's price list (setting `pricing`; a broken one falls back to the defaults)
pub fn pricing(db: &Db) -> Pricing {
    serde_json::from_str::<Value>(&db.get("pricing")).ok().and_then(|v| parse(&v).ok()).unwrap_or_default()
}

/// Whether customers may build their own plan
pub fn custom_on(db: &Db) -> bool {
    db.get("cp_on") != "0"
}

/// A service's name in a plan's name
pub fn service_name(s: &str) -> &'static str {
    match s {
        "v2ray" => "V2Ray",
        "game" => "گیمینگ",
        _ => "VIP",
    }
}

/// The plan row of one custom purchase (an identical earlier one is reused); Err says what is not allowed
pub fn custom_plan(db: &Db, svc: &str, gb: i64, days: i64, users: i64) -> Result<i64, String> {
    let p = pricing(db);
    if !custom_on(db) {
        return Err("custom purchase is off".into());
    }
    let svc = crate::api::plan_service(svc);
    if gb < p.min_gb || gb > p.max_gb || days < p.min_days || days > p.max_days || (days - p.min_days) % p.step_days != 0 || users < 1 || users > p.max_users {
        return Err("that volume, duration or number of users is not offered".into());
    }
    let toman = p.price(&svc, gb as f64, days, users, true);
    let name = format!("دلخواه {} · {} گیگ · {} روزه{}", service_name(&svc), gb, days, if users > 1 { format!(" · {} کاربره", users) } else { String::new() });
    let old: Option<i64> = db.with(|c| {
        c.query_row("SELECT id FROM plans WHERE active=2 AND name=?1 AND toman=?2 AND gb=?3 AND days=?4 AND conns=?5 AND service=?6",
            rusqlite::params![name, toman, gb as f64, days, users, svc], |r| r.get(0)).ok()
    });
    if let Some(id) = old {
        return Ok(id);
    }
    db.with(|c| {
        c.execute("INSERT INTO plans(name,days,gb,toman,usd,conns,countries,active,category,service) VALUES(?1,?2,?3,?4,0,?5,0,2,'',?6)",
            rusqlite::params![name, days, gb as f64, toman, users, svc]).map_err(|e| e.to_string())?;
        Ok(c.last_insert_rowid())
    })
}

/// The listed plans of every service: (service, name, days, gb, users, toman, badge, category)
pub const BADGE_OFFER: &str = "🔥 پیشنهاد ویژه";
pub const BADGE_BEST: &str = "⭐ پرفروش‌ترین";

pub fn standard_plans(p: &Pricing) -> Vec<(&'static str, String, i64, f64, i64, i64, &'static str, &'static str)> {
    // (gb, users, days, badge, category)
    let shapes: [(f64, i64, i64, &str, &str); 9] = [
        (20.0, 1, 30, "", "تک‌کاربره"),
        (50.0, 1, 30, BADGE_OFFER, "تک‌کاربره"),
        (100.0, 1, 30, BADGE_BEST, "تک‌کاربره"),
        (50.0, 2, 30, "", "چندکاربره"),
        (100.0, 2, 30, "", "چندکاربره"),
        (100.0, 3, 30, "", "چندکاربره"),
        (50.0, 1, 60, "", "بلندمدت"),
        (100.0, 2, 60, "", "بلندمدت"),
        (100.0, 1, 90, "", "بلندمدت"),
    ];
    let mut out = vec![];
    for s in SERVICES {
        for (gb, users, days, badge, cat) in shapes {
            let name = format!("{} گیگ{} | {} ماهه", gb, if users > 1 { format!(" | {} کاربره", users) } else { String::new() }, days / 30);
            out.push((*s, name, days, gb, users, p.price(s, gb, days, users, false), badge, cat));
        }
    }
    out
}

/// Puts the listed plans of the price list on sale in place of every plan on sale now; how many were added
pub fn load_standard(db: &Db) -> usize {
    let p = pricing(db);
    let _ = db.exec("UPDATE plans SET active=0 WHERE active=1", &[]);
    let mut n = 0;
    for (svc, name, days, gb, users, t, badge, cat) in standard_plans(&p) {
        if db.exec("INSERT INTO plans(name,days,gb,toman,usd,conns,active,category,style,service,badge,old_toman) VALUES(?1,?2,?3,?4,0,?5,1,?6,'',?7,?8,0)",
            &[&name, &days, &gb, &t, &users, &cat, &svc, &badge]).is_ok() {
            n += 1;
        }
    }
    n
}

/// For the mini app: the price list and the custom purchase switch, so the page shows the price while the
/// buyer chooses
pub fn custom_json(db: &Db) -> Value {
    let mut v = pricing(db).to_json();
    v["on"] = json!(custom_on(db));
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_price_list_gives_the_shops_prices() {
        let p = Pricing::default();
        // the VIP one-month prices the shop always had
        for (gb, users, t) in [(20.0, 1, 80000), (50.0, 1, 110000), (100.0, 1, 170000), (50.0, 2, 135000), (100.0, 2, 195000), (100.0, 3, 220000)] {
            assert_eq!(p.price("vip", gb, 30, users, false), t, "{} GB {} users", gb, users);
        }
        // gaming is V2Ray plus 12,000 for every size; V2Ray is the cheapest, VIP the dearest
        for (gb, days, users) in [(20.0, 30, 1), (50.0, 30, 2), (100.0, 90, 1), (300.0, 180, 4), (10.0, 15, 1), (37.0, 45, 3)] {
            let (v, g, x) = (p.price("v2ray", gb, days, users, false), p.price("game", gb, days, users, false), p.price("vip", gb, days, users, false));
            assert_eq!(g, v + 12000);
            assert!(x > g, "{} {} {}", gb, days, users);
        }
        // longer costs more, the volume is priced tier by tier
        assert_eq!(p.volume(120.0), 20.0 * 1500.0 + 30.0 * 1000.0 + 50.0 * 1200.0 + 20.0 * 800.0);
        assert_eq!(p.price("vip", 50.0, 60, 1, false), 145000);
        assert_eq!(p.price("vip", 100.0, 90, 1, false), 240000);
        // a custom plan: the same plus 10 %, to the nearest thousand
        assert_eq!(p.price("vip", 50.0, 30, 1, true), 121000);
        assert_eq!(p.price("v2ray", 25.0, 15, 1, true), 46000);
        // the same numbers the mini app shows (its own copy of the formula is checked against these)
        for (s, gb, days, users, t) in [("vip", 120.0, 90, 3, 337000), ("game", 300.0, 180, 4, 549000), ("v2ray", 10.0, 15, 1, 26000), ("game", 75.0, 45, 2, 168000), ("v2ray", 255.0, 105, 4, 418000)] {
            assert_eq!(p.price(s, gb, days, users, true), t, "{} {} {} {}", s, gb, days, users);
        }
    }

    #[test]
    fn a_price_list_is_read_with_its_defaults_and_checked() {
        let p = parse(&json!({ "services": { "vip": { "base": "60000" } }, "margin": 5 })).unwrap();
        assert_eq!((p.vip.base, p.vip.user, p.margin), (60000.0, 25000.0, 5.0));
        assert!(parse(&json!({ "margin": 500 })).is_err());
        assert!(parse(&json!({ "tiers": [[50, 1000], [20, 900]] })).is_err());
        assert!(parse(&json!({ "tiers": [[0, 1000], [20, 900]] })).is_err());
        // a list without an open end keeps its last rate for the rest
        let p = parse(&json!({ "tiers": [[20, 1000]] })).unwrap();
        assert_eq!(p.tiers, vec![(20.0, 1000.0), (0.0, 1000.0)]);
        assert_eq!(parse(&p.to_json()).unwrap(), p);
        assert_eq!(parse(&Pricing::default().to_json()).unwrap(), Pricing::default());
    }

    fn db() -> Db {
        let dir = std::env::temp_dir().join(format!("kanki-shop-test-{}", crate::util::rand_token(8)));
        std::fs::create_dir_all(&dir).unwrap();
        Db::open(dir.join("kanki.db").to_str().unwrap())
    }

    #[test]
    fn a_custom_plan_is_priced_hidden_and_made_once() {
        let d = db();
        let a = custom_plan(&d, "game", 25, 30, 1).unwrap();
        assert_eq!(custom_plan(&d, "game", 25, 30, 1).unwrap(), a);
        // the same size of another service is another plan
        assert_ne!(custom_plan(&d, "vip", 25, 30, 1).unwrap(), a);
        let (toman, active, svc): (i64, i64, String) = d.with(|c| c.query_row("SELECT toman,active,service FROM plans WHERE id=?1", [a], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap());
        assert_eq!((toman, active, svc.as_str()), (pricing(&d).price("game", 25.0, 30, 1, true), 2, "game"));
        // outside what is offered
        assert!(custom_plan(&d, "vip", 5, 30, 1).is_err());
        assert!(custom_plan(&d, "vip", 25, 40, 1).is_err());
        assert!(custom_plan(&d, "vip", 25, 30, 5).is_err());
        assert!(custom_plan(&d, "vip", 301, 30, 1).is_err());
        d.set("cp_on", "0");
        assert!(custom_plan(&d, "vip", 25, 30, 1).is_err());
    }

    #[test]
    fn the_listed_plans_come_from_the_price_list() {
        let d = db();
        d.exec("INSERT INTO plans(name,days,gb,toman,active) VALUES('old',30,10,1000,1)", &[]).unwrap();
        assert_eq!(load_standard(&d), 27);
        let on: Vec<(String, i64, String)> = d.with(|c| {
            let mut s = c.prepare("SELECT service,toman,badge FROM plans WHERE active=1 AND gb=50 AND conns=1 AND days=30").unwrap();
            let v = s.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap().filter_map(|x| x.ok()).collect();
            v
        });
        assert_eq!(on.len(), 3);
        assert!(on.iter().any(|x| x.0 == "vip" && x.1 == 110000 && x.2 == BADGE_OFFER));
        let old: i64 = d.with(|c| c.query_row("SELECT active FROM plans WHERE name='old'", [], |r| r.get(0)).unwrap());
        assert_eq!(old, 0);
    }
}
