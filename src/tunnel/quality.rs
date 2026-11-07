//! Path quality for the admins, in Telegram only (read-only): how well each server pair carries a game.
//!
//! The entry of every running tunnel measures it once a minute (`engine::quality_task`: 20 UDP packets
//! of 64 bytes through the tunnel to the exit's echo and back) and reports {loss, ping, jit, max} with its
//! status. Nothing new listens anywhere and ICMP is not needed, so a path where ping is blocked one way
//! (Iran → a filtered IP) is still measured. The panel keeps the last hour of every tunnel here (memory
//! only), judges each server pair over the last 10 minutes and gives the bot:
//! * `health`: one alert item per pair ("pq:<a>|<b>"), bad when the pair loses packets or jitters
//!   (with a margin before it is good again, so a borderline path does not flap);
//! * `report`: the text of «📡 وضعیت مسیرها» in the admin menu.

use super::panel::{live_quality, pair_names, Tunnel};
use crate::util::{esc, now};
use crate::App;
use serde_json::Value;
use std::collections::{HashMap, VecDeque};
use std::sync::{Mutex, OnceLock};

/// a pair is judged over this many seconds of samples
pub const WINDOW: i64 = 600;
/// samples needed in the window before a tunnel is judged (one a minute)
const MIN_SAMPLES: usize = 5;
/// history kept per tunnel
const KEEP: i64 = 3600;
/// bad above these (loss %, jitter ms) ...
pub const BAD_LOSS: f64 = 3.0;
pub const BAD_JIT: f64 = 30.0;
/// ... and good again only below these
const OK_LOSS: f64 = 2.0;
const OK_JIT: f64 = 20.0;
/// a tunnel this clean is green; between this and bad, yellow
const FINE_LOSS: f64 = 1.0;
const FINE_JIT: f64 = 15.0;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Sample {
    pub at: i64,
    pub loss: f64,
    pub ping: u64,
    pub jit: f64,
    pub max: u64,
}

/// Averages of some samples: loss and jitter are means, ping the median
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Agg {
    pub n: usize,
    pub loss: f64,
    pub ping: u64,
    pub jit: f64,
    pub max: u64,
}

fn hist() -> &'static Mutex<HashMap<String, VecDeque<Sample>>> {
    static H: OnceLock<Mutex<HashMap<String, VecDeque<Sample>>>> = OnceLock::new();
    H.get_or_init(|| Mutex::new(HashMap::new()))
}

/// pair key -> currently judged bad
fn verdicts() -> &'static Mutex<HashMap<String, bool>> {
    static V: OnceLock<Mutex<HashMap<String, bool>>> = OnceLock::new();
    V.get_or_init(|| Mutex::new(HashMap::new()))
}

fn sample_of(q: &Value) -> Option<Sample> {
    Some(Sample {
        at: q["at"].as_i64()?,
        loss: q["loss"].as_f64()?,
        ping: q["ping"].as_u64().unwrap_or(0),
        jit: q["jit"].as_f64().unwrap_or(0.0),
        max: q["max"].as_u64().unwrap_or(0),
    })
}

/// Takes the newest result of every tunnel (called by the panel's tunnel loop every few seconds).
pub fn ingest(app: &App) {
    let live = live_quality(app);
    let t = now();
    let mut h = hist().lock().unwrap_or_else(|e| e.into_inner());
    h.retain(|id, _| live.iter().any(|(tu, _, _)| &tu.id == id));
    for (tu, _, q) in &live {
        let Some(s) = q.as_ref().and_then(sample_of) else { continue };
        let v = h.entry(tu.id.clone()).or_default();
        if v.back().map(|x| x.at < s.at).unwrap_or(true) {
            v.push_back(s);
        }
        while v.front().map(|x| t - x.at > KEEP).unwrap_or(false) {
            v.pop_front();
        }
    }
}

/// The samples of the last `secs` seconds, averaged (None below `min` samples)
pub fn agg(v: &[Sample], t: i64, secs: i64, min: usize) -> Option<Agg> {
    let w: Vec<&Sample> = v.iter().filter(|s| t - s.at <= secs).collect();
    if w.len() < min.max(1) {
        return None;
    }
    let n = w.len() as f64;
    let mut pings: Vec<u64> = w.iter().map(|s| s.ping).collect();
    pings.sort();
    Some(Agg {
        n: w.len(),
        loss: round1(w.iter().map(|s| s.loss).sum::<f64>() / n),
        ping: pings[pings.len() / 2],
        jit: round1(w.iter().map(|s| s.jit).sum::<f64>() / n),
        max: w.iter().map(|s| s.max).max().unwrap_or(0),
    })
}

fn round1(x: f64) -> f64 {
    (x * 10.0).round() / 10.0
}

/// One pair from the windows of its tunnels: the median tunnel, so a single tunnel with a poor
/// transport does not make the whole path look bad (that one shows in the report on its own line).
pub fn pair_agg(tunnels: &[Agg]) -> Option<Agg> {
    if tunnels.is_empty() {
        return None;
    }
    let mid = |mut v: Vec<f64>| {
        v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        v[v.len() / 2]
    };
    let mut pings: Vec<u64> = tunnels.iter().map(|a| a.ping).collect();
    pings.sort();
    Some(Agg {
        n: tunnels.iter().map(|a| a.n).sum(),
        loss: mid(tunnels.iter().map(|a| a.loss).collect()),
        ping: pings[pings.len() / 2],
        jit: mid(tunnels.iter().map(|a| a.jit).collect()),
        max: tunnels.iter().map(|a| a.max).max().unwrap_or(0),
    })
}

pub fn is_bad(a: &Agg) -> bool {
    a.loss > BAD_LOSS || a.jit > BAD_JIT
}

fn is_good(a: &Agg) -> bool {
    a.loss <= OK_LOSS && a.jit <= OK_JIT
}

/// Bad / good with a margin: in between, the last verdict stays
pub fn judge(was_bad: bool, a: &Agg) -> bool {
    if is_bad(a) {
        true
    } else if is_good(a) {
        false
    } else {
        was_bad
    }
}

fn dot(a: &Agg) -> &'static str {
    if is_bad(a) {
        "🔴"
    } else if a.loss <= FINE_LOSS && a.jit <= FINE_JIT {
        "🟢"
    } else {
        "🟡"
    }
}

fn line(a: &Agg) -> String {
    format!("پینگ {}ms · افت {}% · لرزش {}ms", a.ping, num(a.loss), num(a.jit))
}

fn num(x: f64) -> String {
    if x.fract() == 0.0 {
        format!("{}", x as i64)
    } else {
        format!("{:.1}", x)
    }
}

fn transport_name(t: &str) -> String {
    match t {
        "game" => "Game-FEC".into(),
        "hq" => "HQ-QUIC".into(),
        "kcp" => "KCP".into(),
        "quic" => "QUIC".into(),
        "tcpmux" => "TCP Mux".into(),
        "faketcp" => "FakeTCP".into(),
        "awg" => "AmneziaWG".into(),
        "hy2" => "Hysteria2".into(),
        o => o.to_uppercase(),
    }
}

/// the pair of a tunnel, the same both ways round
fn pair_key(tu: &Tunnel) -> String {
    let (a, b) = if tu.entry <= tu.exit { (&tu.entry, &tu.exit) } else { (&tu.exit, &tu.entry) };
    format!("{}|{}", a, b)
}

struct Pair {
    key: String,
    name: String,
    /// (tunnel, up, its 10-minute window, its hour)
    tunnels: Vec<(Tunnel, bool, Option<Agg>, Option<Agg>)>,
}

fn pairs(app: &App) -> Vec<Pair> {
    let live = live_quality(app);
    let h = hist().lock().unwrap_or_else(|e| e.into_inner()).clone();
    let t = now();
    let mut out: Vec<Pair> = vec![];
    for (tu, up, _) in live {
        let v: Vec<Sample> = h.get(&tu.id).map(|d| d.iter().copied().collect()).unwrap_or_default();
        let (w, hour) = (agg(&v, t, WINDOW, MIN_SAMPLES), agg(&v, t, KEEP, MIN_SAMPLES));
        let key = pair_key(&tu);
        match out.iter_mut().find(|p| p.key == key) {
            Some(p) => p.tunnels.push((tu, up, w, hour)),
            None => {
                let (a, b) = pair_names(app, &tu.entry, &tu.exit);
                out.push(Pair { key, name: format!("{} ↔ {}", a, b), tunnels: vec![(tu, up, w, hour)] });
            }
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    for p in &mut out {
        p.tunnels.sort_by(|a, b| a.0.name.cmp(&b.0.name));
    }
    out
}

/// (key, name, ok, detail) of every server pair with enough samples, for the bot's alerts
pub fn health(app: &App) -> Vec<(String, String, bool, String)> {
    let mut v = verdicts().lock().unwrap_or_else(|e| e.into_inner());
    let mut out = vec![];
    let ps = pairs(app);
    v.retain(|k, _| ps.iter().any(|p| &p.key == k));
    for p in ps {
        let ws: Vec<Agg> = p.tunnels.iter().filter(|x| x.1).filter_map(|x| x.2).collect();
        let Some(a) = pair_agg(&ws) else { continue };
        let bad = judge(v.get(&p.key).copied().unwrap_or(false), &a);
        v.insert(p.key.clone(), bad);
        out.push((format!("pq:{}", p.key), p.name, !bad, line(&a)));
    }
    out
}

/// Path alerts («🟠 مسیر … پر افت شده») on or off (setting `path_alerts`, on unless "0"). The server
/// offline / online alerts do not depend on it.
pub fn alerts_on(app: &App) -> bool {
    app.db.get("path_alerts") != "0"
}

fn agg_json(a: &Option<Agg>) -> Value {
    match a {
        Some(a) => serde_json::json!({ "ping": a.ping, "loss": round1(a.loss), "jit": round1(a.jit), "max": a.max, "level": level(a) }),
        None => Value::Null,
    }
}

/// good / fine / bad, the colours of the bot's report
fn level(a: &Agg) -> &'static str {
    if is_bad(a) {
        "bad"
    } else if a.loss <= FINE_LOSS && a.jit <= FINE_JIT {
        "good"
    } else {
        "fine"
    }
}

/// The paths page of the admins' mini app (`/tg/api/admin/paths`): one card per server abroad (the
/// side that is not in Iran; for a tunnel between two servers abroad, its exit) with every tunnel
/// that reaches it, where it comes from, its transport and its numbers over the last 10 minutes,
/// and the card's own numbers (the median tunnel, like the alerts) and its last hour. Read-only.
pub fn view(app: &App) -> Value {
    use serde_json::json;
    let live = live_quality(app);
    let lanes = super::panel::live_lanes(app);
    let locs = super::panel::server_locs(app);
    let ccs = crate::exitgeo::all_cc(app);
    let iran = |id: &str| locs.get(id).map(|l| l.0 == "iran").unwrap_or(false);
    let h = hist().lock().unwrap_or_else(|e| e.into_inner()).clone();
    let t = now();
    // (foreign server id, name, cc, tunnels: (json, up, window, hour))
    let mut groups: Vec<(String, String, String, Vec<(Value, bool, Option<Agg>, Option<Agg>)>)> = vec![];
    let mut last = 0i64;
    for (tu, up, _) in live {
        let v: Vec<Sample> = h.get(&tu.id).map(|d| d.iter().copied().collect()).unwrap_or_default();
        if let Some(s) = v.last() {
            last = last.max(s.at);
        }
        let (w, hour) = (agg(&v, t, WINDOW, MIN_SAMPLES), agg(&v, t, KEEP, MIN_SAMPLES));
        let (near, far) = if iran(&tu.exit) && !iran(&tu.entry) { (tu.exit.clone(), tu.entry.clone()) } else { (tu.entry.clone(), tu.exit.clone()) };
        let (near_name, far_name) = pair_names(app, &tu.entry, &tu.exit);
        let cc = ccs.get(&crate::exitgeo::srv_key(&far)).cloned().unwrap_or_default();
        let (ln, links) = lanes.get(&tu.id).copied().unwrap_or((0, 0));
        let row = json!({
            "name": tu.name, "from": near_name, "from_id": near, "transport": transport_name(&tu.transport),
            "up": up, "now": agg_json(&w), "lanes": ln, "links": links,
        });
        match groups.iter_mut().find(|g| g.0 == far) {
            Some(g) => g.3.push((row, up, w, hour)),
            None => groups.push((far, far_name, cc, vec![(row, up, w, hour)])),
        }
    }
    let mut out: Vec<Value> = groups
        .into_iter()
        .map(|(id, name, cc, mut ts)| {
            ts.sort_by(|a, b| a.0["from"].as_str().cmp(&b.0["from"].as_str()).then(a.0["name"].as_str().cmp(&b.0["name"].as_str())));
            let ws: Vec<Agg> = ts.iter().filter(|x| x.1).filter_map(|x| x.2).collect();
            let hs: Vec<Agg> = ts.iter().filter(|x| x.1).filter_map(|x| x.3).collect();
            let all_down = ts.iter().all(|x| !x.1);
            let now_a = pair_agg(&ws);
            let state = match &now_a {
                Some(a) => level(a),
                None if all_down => "down",
                None => "wait",
            };
            json!({
                "id": id, "name": name, "cc": cc, "flag": if cc.len() == 2 { crate::amnezia::flag(&cc) } else { String::new() },
                "state": state, "now": agg_json(&now_a), "hour": agg_json(&pair_agg(&hs)),
                "up": ts.iter().filter(|x| x.1).count(), "tunnels": ts.into_iter().map(|x| x.0).collect::<Vec<_>>(),
            })
        })
        .collect();
    // the worst first, then by name: what needs a look is on top
    let rank = |s: &str| match s {
        "down" => 0,
        "bad" => 1,
        "fine" => 2,
        "good" => 3,
        _ => 4,
    };
    out.sort_by(|a, b| rank(a["state"].as_str().unwrap_or("")).cmp(&rank(b["state"].as_str().unwrap_or(""))).then(a["name"].as_str().cmp(&b["name"].as_str())));
    json!({
        "servers": out, "at": t, "last": last, "alerts": alerts_on(app),
        "limits": { "bad_loss": BAD_LOSS, "bad_jit": BAD_JIT, "window_min": WINDOW / 60 },
    })
}

/// Telegram's limit is 4096 characters; the report stops a little before it
const MAX_TEXT: usize = 3800;

/// The «📡 وضعیت مسیرها» page (HTML for Telegram)
pub fn report(app: &App) -> String {
    let ps = pairs(app);
    let mut s = String::from("📡 <b>وضعیت مسیرها</b>\n<i>هر دقیقه ۲۰ بستهٔ کوچک UDP داخل هر تانل رفت و برگشت می‌کند؛ عددها میانگین ۱۰ دقیقهٔ اخیرند.</i>\n");
    if ps.is_empty() {
        s.push_str("\nهنوز تانلی نیست.");
        return s;
    }
    let verdict = verdicts().lock().unwrap_or_else(|e| e.into_inner()).clone();
    for p in ps {
        let mut block = String::new();
        let ws: Vec<Agg> = p.tunnels.iter().filter(|x| x.1).filter_map(|x| x.2).collect();
        let hs: Vec<Agg> = p.tunnels.iter().filter(|x| x.1).filter_map(|x| x.3).collect();
        let all_down = p.tunnels.iter().all(|x| !x.1);
        match pair_agg(&ws) {
            Some(a) => {
                let d = if verdict.get(&p.key).copied().unwrap_or(false) || is_bad(&a) { "🔴" } else { dot(&a) };
                block.push_str(&format!("\n{} <b>{}</b>\n{}\n", d, esc(&p.name), line(&a)));
            }
            None if all_down => block.push_str(&format!("\n🔴 <b>{}</b>\nهمهٔ تانل‌هایش قطع‌اند\n", esc(&p.name))),
            None => block.push_str(&format!("\n⚪️ <b>{}</b>\nهنوز داده نیست (چند دقیقه صبر کنید)\n", esc(&p.name))),
        }
        if let Some(h) = pair_agg(&hs) {
            block.push_str(&format!("<i>ساعت گذشته: افت {}% · لرزش {}ms · بدترین پینگ {}ms</i>\n", num(h.loss), num(h.jit), h.max));
        }
        for (tu, up, w, _) in &p.tunnels {
            let tr = transport_name(&tu.transport);
            let row = match (up, w) {
                (false, _) => format!("  🔴 {} · {}: قطع", esc(&tu.name), tr),
                (true, Some(a)) => format!("  {} {} · {}: {}ms · {}% · {}ms", dot(a), esc(&tu.name), tr, a.ping, num(a.loss), num(a.jit)),
                (true, None) => format!("  ⚪️ {} · {}: هنوز داده نیست", esc(&tu.name), tr),
            };
            block.push_str(&row);
            block.push('\n');
        }
        if s.chars().count() + block.chars().count() > MAX_TEXT {
            s.push_str("\n…");
            break;
        }
        s.push_str(&block);
    }
    s.push_str("\n🟢 خوب · 🟡 قابل قبول · 🔴 پر افت یا قطع\n<i>پینگ: میانه · افت: بسته‌ای که تا ۱ ثانیه برنگشت · لرزش: تغییر پینگ از هر بسته به بعدی</i>");
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(at: i64, loss: f64, jit: f64) -> Sample {
        Sample { at, loss, ping: 70, jit, max: 90 }
    }

    #[test]
    fn a_window_needs_enough_samples_and_ignores_old_ones() {
        let t = 10_000;
        let v: Vec<Sample> = (0..4).map(|i| s(t - i * 60, 5.0, 2.0)).collect();
        assert_eq!(agg(&v, t, WINDOW, MIN_SAMPLES), None);
        let mut v: Vec<Sample> = (0..6).map(|i| s(t - i * 60, 5.0, 2.0)).collect();
        // older than the window: not counted
        v.insert(0, s(t - 2000, 100.0, 500.0));
        let a = agg(&v, t, WINDOW, MIN_SAMPLES).unwrap();
        assert_eq!((a.n, a.loss, a.jit, a.ping), (6, 5.0, 2.0, 70));
    }

    #[test]
    fn one_poor_tunnel_does_not_make_the_path_bad() {
        let good = Agg { n: 10, loss: 0.0, ping: 75, jit: 3.0, max: 90 };
        let poor = Agg { n: 10, loss: 15.0, ping: 120, jit: 80.0, max: 400 };
        let p = pair_agg(&[good, good, poor]).unwrap();
        assert!(!is_bad(&p));
        let p = pair_agg(&[good, poor, poor]).unwrap();
        assert!(is_bad(&p));
    }

    #[test]
    fn the_verdict_has_a_margin_so_it_does_not_flap() {
        let a = |loss, jit| Agg { n: 10, loss, ping: 70, jit, max: 90 };
        assert!(judge(false, &a(4.0, 5.0)));
        assert!(judge(false, &a(0.0, 35.0)));
        // between good and bad: the last verdict stays
        assert!(judge(true, &a(2.5, 5.0)));
        assert!(!judge(false, &a(2.5, 5.0)));
        assert!(!judge(true, &a(1.0, 10.0)));
    }
}
