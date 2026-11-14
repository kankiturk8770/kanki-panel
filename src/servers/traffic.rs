//! How much traffic every server really used (3.45.0): one row per server in the traffic page.
//!
//! What is counted is the server's network card (`admin::nic_sample`), not the users' counters: a
//! user behind a tunnel goes Iran server -> tunnel -> foreign server, so the same bytes cross both
//! machines (and both datacenters bill them), while the user's own counter sees them once. The card
//! sees all of it: VPN users, every tunnel in and out, Xray, DNS, the panel itself.
//!
//! Every server sends its card's counters since boot (the agent with each report, a VPN node in its
//! info, the panel server reads its own). The panel keeps the last sample of each and adds the
//! difference to the server's total and to the day (Tehran time). A reboot starts the counters at 0
//! again (the boot id changes): everything since that boot is added. A counter that went back
//! without a reboot (the card came back) is taken from 0 too. The first sample of a server, a
//! changed card and a jump no card can make are only a new starting point, never counted.
//!
//! A machine with both a VPN node and an agent reports the same card twice: only one of the two is
//! shown (the one counting longer), so nothing is counted twice.

use crate::guard;
use crate::util::now;
use crate::App;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex, OnceLock};

const KEY: &str = "srv_traffic";
/// Tehran is UTC+3:30 all year
const TEHRAN: i64 = 3 * 3600 + 1800;
/// days kept for the table (today, 7 and 30 days)
const KEEP_DAYS: i64 = 62;
/// a server not heard from this long is dropped from the store
const FORGET: i64 = 120 * 86400;
/// faster than this (bytes a second, 25 Gbit/s) no card moves: such a jump is a new starting point
const MAX_RATE: f64 = 25e9 / 8.0;

/// What is known of one source ("local", "a:<agent id>", "n:<node id>")
#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq)]
pub struct Src {
    /// the last sample: card, boot id, counters, when
    pub nic: String,
    pub boot: String,
    pub rx: u64,
    pub tx: u64,
    pub at: i64,
    /// counted since
    pub since: i64,
    /// counted in all, received and sent
    pub trx: u64,
    pub ttx: u64,
    /// Tehran day number -> (received, sent)
    pub days: BTreeMap<i64, (u64, u64)>,
    /// bytes a second between the last two samples
    pub rrx: f64,
    pub rtx: f64,
}

pub fn day_of(t: i64) -> i64 {
    (t + TEHRAN).div_euclid(86400)
}

impl Src {
    /// one sample of the card at time `t`; true when something changed
    pub fn note(&mut self, nic: &str, boot: &str, rx: u64, tx: u64, t: i64) -> bool {
        if self.since == 0 {
            *self = Src { nic: nic.into(), boot: boot.into(), rx, tx, at: t, since: t, ..Default::default() };
            return true;
        }
        if nic == self.nic && boot == self.boot && rx == self.rx && tx == self.tx {
            // the same sample again (an agent sends its cached one with every report)
            return false;
        }
        let gap = (t - self.at).max(0);
        let (drx, dtx) = if nic != self.nic {
            // another card: its counters say nothing about the old one
            (0, 0)
        } else if boot != self.boot || rx < self.rx || tx < self.tx {
            // rebooted (or the card came back): the counters started again from 0
            (rx, tx)
        } else {
            (rx - self.rx, tx - self.tx)
        };
        // what boot alone would not explain (a bad or foreign sample): a new starting point only
        let room = (gap.max(1) as f64 + 60.0) * MAX_RATE;
        let (drx, dtx) = if boot == self.boot && (drx as f64 > room || dtx as f64 > room) { (0, 0) } else { (drx, dtx) };
        if drx > 0 || dtx > 0 {
            self.trx += drx;
            self.ttx += dtx;
            let d = self.days.entry(day_of(t)).or_default();
            d.0 += drx;
            d.1 += dtx;
        }
        if gap > 0 && boot == self.boot && nic == self.nic {
            self.rrx = drx as f64 / gap as f64;
            self.rtx = dtx as f64 / gap as f64;
        } else {
            self.rrx = 0.0;
            self.rtx = 0.0;
        }
        self.nic = nic.into();
        self.boot = boot.into();
        self.rx = rx;
        self.tx = tx;
        self.at = t;
        let old = day_of(t) - KEEP_DAYS;
        self.days.retain(|d, _| *d > old);
        true
    }

    /// (received, sent) of the days from `from` to today (Tehran)
    pub fn sum(&self, from: i64) -> (u64, u64) {
        self.days.range(from..).fold((0, 0), |a, (_, v)| (a.0 + v.0, a.1 + v.1))
    }
}

struct Store {
    m: HashMap<String, Src>,
    dirty: bool,
}

fn store(app: &App) -> &'static Mutex<Store> {
    static S: OnceLock<Mutex<Store>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(Store { m: serde_json::from_str(&app.db.get(KEY)).unwrap_or_default(), dirty: false }))
}

/// One sample from a server: `net` is `admin::nic_sample` ({if, rx, tx, boot}; Null from an
/// older server, which is then just not counted)
pub fn note(app: &App, src: &str, net: &Value) {
    let (Some(rx), Some(tx)) = (net["rx"].as_u64(), net["tx"].as_u64()) else { return };
    let nic = net["if"].as_str().unwrap_or("");
    if nic.is_empty() {
        return;
    }
    let boot = net["boot"].as_str().unwrap_or("");
    let mut g = store(app).lock().unwrap_or_else(|e| e.into_inner());
    if g.m.entry(src.to_string()).or_default().note(nic, boot, rx, tx, now()) {
        g.dirty = true;
    }
}

/// Written to the database once a minute (a report comes every few seconds); the panel server's own
/// card is read here too
pub async fn run(app: Arc<App>) {
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(30));
    let mut n = 0u64;
    loop {
        tick.tick().await;
        let net = tokio::task::spawn_blocking(crate::admin::nic_sample).await.unwrap_or_default();
        note(&app, "local", &net);
        n += 1;
        if n % 2 == 0 {
            save(&app);
        }
    }
}

fn save(app: &App) {
    let mut g = store(app).lock().unwrap_or_else(|e| e.into_inner());
    let t = now();
    let before = g.m.len();
    g.m.retain(|_, s| t - s.at < FORGET);
    if !g.dirty && g.m.len() == before {
        return;
    }
    g.dirty = false;
    let v = serde_json::to_string(&g.m).unwrap_or_default();
    drop(g);
    app.db.set(KEY, &v);
}

pub fn router() -> Router<Arc<App>> {
    Router::new().route("/api/servers/traffic", get(table))
}

/// The sources that can stand for one server of the servers list (`servers::list_json`)
fn sources_of(s: &Value) -> Vec<String> {
    let key = s["key"].as_str().unwrap_or("");
    if key == "local" {
        return vec!["local".into()];
    }
    if let Some(n) = key.strip_prefix("node:") {
        return vec![format!("n:{n}")];
    }
    let mut v = vec![format!("a:{key}")];
    if let Some(n) = s["node"]["id"].as_str().filter(|n| !n.is_empty() && *n != "local") {
        v.push(format!("n:{n}"));
    }
    v
}

/// Of the sources of one machine, the one counting longest (they read the same card)
fn pick<'a>(m: &'a HashMap<String, Src>, srcs: &[String]) -> Option<&'a Src> {
    srcs.iter().filter_map(|k| m.get(k)).min_by_key(|s| s.since)
}

fn row(s: &Src, t: i64) -> Value {
    let today = day_of(t);
    let days: Vec<Value> = (0..30).rev().map(|i| {
        let d = today - i;
        let v = s.days.get(&d).copied().unwrap_or((0, 0));
        json!([d, v.0, v.1])
    }).collect();
    // the speed of the last two samples, while they are fresh
    let fresh = t - s.at < 150;
    json!({
        "nic": s.nic, "since": s.since, "at": s.at,
        "live": [if fresh { s.rrx } else { 0.0 }, if fresh { s.rtx } else { 0.0 }],
        "today": s.sum(today), "yesterday": s.days.get(&(today - 1)).copied().unwrap_or((0, 0)),
        "d7": s.sum(today - 6), "d30": s.sum(today - 29), "total": (s.trx, s.ttx), "days": days,
    })
}

async fn table(State(app): State<Arc<App>>, h: HeaderMap) -> Response {
    let _ = guard!(app, h, "nodes");
    let list = crate::servers::list_json(&app);
    let t = now();
    let g = store(&app).lock().unwrap_or_else(|e| e.into_inner());
    let rows: Vec<Value> = list["servers"].as_array().cloned().unwrap_or_default().iter().map(|s| {
        let a = &s["agent"];
        let online = s["local"].as_bool() == Some(true) || a["online"].as_bool() == Some(true) || s["node"]["online"].as_bool() == Some(true);
        let mut r = json!({ "key": s["key"], "name": s["name"], "cc": s["cc"], "loc": s["loc"], "online": online });
        match pick(&g.m, &sources_of(s)) {
            Some(x) => {
                if let (Some(o), Some(v)) = (r.as_object_mut(), row(x, t).as_object()) {
                    o.extend(v.clone());
                }
            }
            // an older server that does not send its card yet
            None => r["none"] = json!(true),
        }
        r
    }).collect();
    Json(json!({ "servers": rows, "today": day_of(t), "now": t })).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    const G: u64 = 1 << 30;

    #[test]
    fn counts_the_difference_and_never_the_first_sample() {
        let mut s = Src::default();
        let t = 1_800_000_000;
        assert!(s.note("eth0", "b1", 50 * G, 70 * G, t));
        assert_eq!((s.trx, s.ttx), (0, 0), "what came before the panel counted is not known");
        s.note("eth0", "b1", 50 * G + 1000, 70 * G + 4000, t + 30);
        s.note("eth0", "b1", 51 * G, 71 * G, t + 60);
        assert_eq!((s.trx, s.ttx), (G, G));
        assert_eq!(s.sum(day_of(t)), (G, G));
        // the same sample again changes nothing
        assert!(!s.note("eth0", "b1", 51 * G, 71 * G, t + 90));
        assert_eq!((s.trx, s.ttx), (G, G));
    }

    #[test]
    fn a_reboot_adds_what_came_since_boot() {
        let mut s = Src::default();
        let t = 1_800_000_000;
        s.note("eth0", "b1", 10 * G, 10 * G, t);
        s.note("eth0", "b1", 12 * G, 11 * G, t + 600);
        // rebooted: the counters start at 0, 3 GB / 1 GB moved since
        s.note("eth0", "b2", 3 * G, G, t + 1200);
        assert_eq!((s.trx, s.ttx), (5 * G, 2 * G));
        s.note("eth0", "b2", 4 * G, 2 * G, t + 1800);
        assert_eq!((s.trx, s.ttx), (6 * G, 3 * G));
        // the card came back without a reboot: from 0 again
        s.note("eth0", "b2", 1000, 2000, t + 1830);
        assert_eq!((s.trx, s.ttx), (6 * G + 1000, 3 * G + 2000));
    }

    #[test]
    fn another_card_or_an_impossible_jump_is_only_a_new_start() {
        let mut s = Src::default();
        let t = 1_800_000_000;
        s.note("eth0", "b1", 10 * G, 10 * G, t);
        s.note("ens3", "b1", 900 * G, 900 * G, t + 30);
        assert_eq!((s.trx, s.ttx), (0, 0));
        // 30 seconds, 5 TB: no card does that
        s.note("ens3", "b1", 900 * G + 5000 * G, 900 * G, t + 60);
        assert_eq!((s.trx, s.ttx), (0, 0));
        // and from there it counts again
        s.note("ens3", "b1", 900 * G + 5001 * G, 900 * G + G, t + 90);
        assert_eq!((s.trx, s.ttx), (G, G));
    }

    #[test]
    fn days_are_tehran_days_and_old_ones_go() {
        let mut s = Src::default();
        // 20:29 UTC = 23:59 Tehran; 20:31 UTC = 00:01 the next day there
        let t = 1_799_965_740 - 1_799_965_740 % 86400 + 20 * 3600 + 29 * 60;
        assert_eq!(day_of(t) + 1, day_of(t + 120));
        s.note("eth0", "b1", 0, 0, t - 60);
        s.note("eth0", "b1", G, 0, t);
        s.note("eth0", "b1", 3 * G, 0, t + 120);
        assert_eq!(s.days.get(&day_of(t)).copied(), Some((G, 0)));
        assert_eq!(s.days.get(&day_of(t + 120)).copied(), Some((2 * G, 0)));
        assert_eq!(s.sum(day_of(t)), (3 * G, 0));
        // 70 days later only the new day is kept, the total stays
        s.note("eth0", "b1", 4 * G, 0, t + 70 * 86400);
        assert_eq!(s.days.len(), 1);
        assert_eq!(s.trx, 4 * G);
    }

    #[test]
    fn speed_is_bytes_a_second_of_the_last_two_samples() {
        let mut s = Src::default();
        let t = 1_800_000_000;
        s.note("eth0", "b1", 0, 0, t);
        s.note("eth0", "b1", 30_000_000, 3_000_000, t + 30);
        assert_eq!((s.rrx, s.rtx), (1_000_000.0, 100_000.0));
    }

    #[test]
    fn one_machine_with_a_node_and_an_agent_is_counted_once() {
        let mut m: HashMap<String, Src> = HashMap::new();
        let t = 1_800_000_000;
        // the agent reports the card, the node reports the same card: only one is shown
        let mut a = Src::default();
        a.note("eth0", "b1", 0, 0, t);
        a.note("eth0", "b1", 5 * G, 5 * G, t + 60);
        let mut n = Src::default();
        n.note("eth0", "b1", G, G, t + 30);
        n.note("eth0", "b1", 5 * G, 5 * G, t + 60);
        m.insert("a:s1".into(), a);
        m.insert("n:7".into(), n);
        let srv = json!({"key": "s1", "node": {"id": "7"}});
        assert_eq!(sources_of(&srv), vec!["a:s1".to_string(), "n:7".to_string()]);
        let p = pick(&m, &sources_of(&srv)).unwrap();
        assert_eq!(p.trx, 5 * G, "the one counting longer");
        assert_eq!(sources_of(&json!({"key": "local"})), vec!["local".to_string()]);
        assert_eq!(sources_of(&json!({"key": "node:9"})), vec!["n:9".to_string()]);
    }
}
