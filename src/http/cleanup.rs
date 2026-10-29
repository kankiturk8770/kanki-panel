//! Keeping the panel clean of servers that are gone: a sweep of what removed servers left behind (at
//! start and once a day), and the removal of a server that stays offline for too long (Settings).
use crate::App;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

/// Every key that is a live server: VPN node ids, agent server ids and "local"
fn live_ids(app: &App) -> (HashSet<String>, HashSet<String>) {
    let nodes: HashSet<String> = app.db.nodes().into_iter().map(|n| n.id).collect();
    let mut agents: HashSet<String> = crate::tunnel::panel::servers(app).into_iter().map(|s| s.id).collect();
    agents.insert("local".into());
    (nodes, agents)
}

/// Removes every setting that names a server that no longer exists (left by deletes of older versions
/// or by a delete that did not reach every part) and says what it removed. Cheap; run at start and daily.
pub fn sweep(app: &App) -> Vec<String> {
    let (nodes, agents) = live_ids(app);
    let mut gone: Vec<String> = vec![];
    // per node settings
    for id in crate::kmix::node_ids(app).into_iter().filter(|id| !nodes.contains(id)) {
        crate::kmix::forget_node(app, &id);
        gone.push(format!("KANKI MIX {}", id));
    }
    for id in crate::microtun::node_ids(app).into_iter().filter(|id| !nodes.contains(id)) {
        crate::microtun::forget_node(app, &id);
        gone.push(format!("microtun {}", id));
    }
    for id in crate::cores::load(app).into_keys().filter(|id| !nodes.contains(id)) {
        crate::cores::forget(app, &id);
        gone.push(format!("core switches {}", id));
    }
    // the second config of servers ("node:<id>", an agent server id or "local")
    for key in crate::twin::all(app).into_keys() {
        let live = match key.strip_prefix("node:") {
            Some(nid) => nodes.contains(nid),
            None => agents.contains(&key),
        };
        if !live {
            crate::twin::forget(app, &key);
            gone.push(format!("tunnel domain {}", key));
        }
    }
    // the exit country of servers ("<node id>", "srv:<id>", "xray:<id>")
    let geo: Vec<String> = serde_json::from_str::<HashMap<String, Value>>(&app.db.get("exit_geo")).map(|m| m.into_keys().collect()).unwrap_or_default();
    let dead_geo: Vec<String> = geo
        .into_iter()
        .filter(|k| match k.split_once(':') {
            Some(("srv", id)) | Some(("xray", id)) => !agents.contains(id),
            Some(_) => false,
            None => !nodes.contains(k) && k != "local",
        })
        .collect();
    if !dead_geo.is_empty() {
        crate::exitgeo::forget(app, &dead_geo);
        gone.extend(dead_geo.iter().map(|k| format!("exit country {}", k)));
    }
    // users' server lists (a user who had only gone servers moves to the panel server: an empty list
    // would mean every server)
    for u in app.db.users() {
        let list: Vec<&str> = u.nodes.split(',').map(|x| x.trim()).filter(|x| !x.is_empty()).collect();
        let keep: Vec<&str> = list.iter().copied().filter(|x| *x == "local" || nodes.contains(*x)).collect();
        if keep.len() != list.len() {
            let v = if keep.is_empty() { "local".to_string() } else { keep.join(",") };
            let _ = app.db.exec("UPDATE users SET nodes=?1 WHERE id=?2", &[&v, &u.id]);
            gone.push(format!("{}: {} gone server(s)", u.username, list.len() - keep.len()));
        }
    }
    for g in &gone {
        eprintln!("cleanup: removed {}", g);
    }
    gone
}

pub async fn sweep_loop(app: Arc<App>) {
    loop {
        sweep(&app);
        tokio::time::sleep(std::time::Duration::from_secs(86400)).await;
    }
}

// ------------------------------------------------------------------ servers offline for too long

/// Settings: on (default), hours (default 24), Iran servers too (default off: when Iran's internet is
/// cut its servers can be away for days, and removing them would take every tunnel with them)
pub fn auto_settings(app: &App) -> (bool, i64, bool) {
    let hours = app.db.get("autodel_hours").parse::<i64>().unwrap_or(24).clamp(1, 24 * 30);
    (app.db.get("autodel_on") != "0", hours, app.db.get("autodel_iran") == "1")
}

/// Every server the panel could remove: (key, name, Iran, online now)
fn candidates(app: &App) -> Vec<(String, String, bool, bool)> {
    let now = crate::util::now();
    let nodes = app.db.nodes();
    let mut out = vec![];
    let list = crate::tunnel::panel::servers(app);
    for s in &list {
        let agent_on = crate::tunnel::panel::agent_state(&s.id).map(|(at, ..)| now - at < 300).unwrap_or(false);
        let node_on = !s.node.is_empty() && nodes.iter().any(|n| n.id == s.node && n.online);
        let ir = s.loc == "iran" || crate::exitgeo::cc(app, &s.node) == "IR";
        out.push((s.id.clone(), s.name.clone(), ir, agent_on || node_on));
    }
    // VPN nodes with no agent server next to them
    for n in nodes.iter().filter(|n| n.id != "local" && !list.iter().any(|s| s.node == n.id)) {
        out.push((format!("node:{}", n.id), n.name.clone(), crate::exitgeo::cc(app, &n.id) == "IR", n.online));
    }
    out
}

pub async fn offline_loop(app: Arc<App>) {
    // after a start the agents need a few minutes to report again
    tokio::time::sleep(std::time::Duration::from_secs(600)).await;
    loop {
        offline_round(&app).await;
        tokio::time::sleep(std::time::Duration::from_secs(600)).await;
    }
}

async fn offline_round(app: &Arc<App>) {
    let (on, hours, iran) = auto_settings(app);
    let mut since: HashMap<String, (i64, bool)> = serde_json::from_str(&app.db.get("offline_since")).unwrap_or_default();
    let now = crate::util::now();
    let list = candidates(app);
    // every server away at once is the panel's own network, not the servers: nothing is counted
    if !list.is_empty() && list.iter().all(|c| !c.3) {
        return;
    }
    since.retain(|k, _| list.iter().any(|c| &c.0 == k && !c.3));
    let mut remove = vec![];
    for (key, name, ir, online) in &list {
        if *online {
            continue;
        }
        let e = since.entry(key.clone()).or_insert((now, false));
        if !on || (*ir && !iran) {
            continue;
        }
        let away = now - e.0;
        if !e.1 && away >= hours * 1800 {
            e.1 = true;
            crate::backup::tell_admin(app, &format!("⚠️ {} · سرور «{}» {} ساعت است آفلاین است و اگر برنگردد {} ساعت دیگر خودکار حذف می‌شود.", app.db.get("panel_name"), name, away / 3600, (hours * 3600 - away).max(0) / 3600)).await;
        }
        if away >= hours * 3600 {
            remove.push((key.clone(), name.clone()));
        }
    }
    app.db.set("offline_since", &json!(since).to_string());
    if remove.is_empty() {
        return;
    }
    // a backup right before, so a removal can be undone
    if let Err(e) = crate::backup::send_backup(app).await {
        // no Telegram backup: one kept on the panel server instead ({data}/before-autoremove.*)
        let pass = crate::backup::backup_pass(app);
        match crate::backup::make_archive(app, &pass) {
            Ok((bytes, name)) => {
                let ext = if name.ends_with(".kbk") { "kbk" } else { "tar.gz" };
                let _ = std::fs::write(format!("{}/before-autoremove.{}", app.data_dir(), ext), bytes);
            }
            Err(e2) => eprintln!("auto-remove: no backup before it ({}; {}), removing anyway", e, e2),
        }
    }
    for (key, name) in remove {
        match crate::servers::purge_server(app, &key, true) {
            Ok(_) => {
                eprintln!("auto-remove: {} was offline for {} hours: removed", name, hours);
                crate::backup::tell_admin(app, &format!("🗑 {} · سرور «{}» بیش از {} ساعت آفلاین بود و از پنل حذف شد.", app.db.get("panel_name"), name, hours)).await;
            }
            Err((_, e)) => eprintln!("auto-remove: {}: {}", name, e),
        }
        let mut s: HashMap<String, (i64, bool)> = serde_json::from_str(&app.db.get("offline_since")).unwrap_or_default();
        s.remove(&key);
        app.db.set("offline_since", &json!(s).to_string());
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::{atomic::AtomicI64, Arc, Mutex};

    #[test]
    fn a_sweep_leaves_nothing_of_a_gone_server() {
        let dir = std::env::temp_dir().join(format!("kanki-sweep-{}", crate::util::rand_token(8)));
        std::fs::create_dir_all(&dir).unwrap();
        let db = crate::db::Db::open(dir.join("kanki.db").to_str().unwrap());
        let app = Arc::new(crate::App {
            db,
            env: HashMap::new(),
            hy2_allowed: Mutex::new(HashMap::new()), limits: Mutex::new(HashMap::new()), reported: Mutex::new(HashMap::new()),
            login_fails: Mutex::new(HashMap::new()), sync_lock: tokio::sync::Mutex::new(()), bot_alive: AtomicI64::new(0),
            http: reqwest::Client::new(), http_insecure: reqwest::Client::new(), pin_clients: Mutex::new(HashMap::new()),
        });
        app.db.exec("INSERT INTO nodes(id,name,address,endpoint,token,online,endpoint_mode) VALUES('live','Live','a','','t',1,'panel')", &[]).unwrap();
        app.db.exec("INSERT INTO users(username,code,nodes) VALUES('u1','c1','node-dead,live'),('u2','c2','node-dead')", &[]).unwrap();
        app.db.set("kmix_nodes", r#"{"node-dead":{"port":4001},"live":{"port":4002}}"#);
        crate::microtun::set_node_port(&app, "node-dead", 4201);
        crate::cores::all_off(&app, "node-dead");
        app.db.set("exit_geo", r#"{"node-dead":{"cc":"DE"},"live":{"cc":"TR"},"srv:gone":{"cc":"IR"},"local":{"cc":"FI"}}"#);
        let gone = super::sweep(&app);
        assert!(!gone.is_empty());
        for k in ["kmix_nodes", "mtun_cfg", "core_off", "exit_geo"] {
            assert!(!app.db.get(k).contains("node-dead"), "{} still names the gone node", k);
        }
        assert!(!app.db.get("exit_geo").contains("srv:gone"));
        assert!(app.db.get("kmix_nodes").contains("live") && app.db.get("exit_geo").contains("local"));
        let users = app.db.users();
        assert_eq!(users.iter().find(|u| u.username == "u1").unwrap().nodes, "live");
        assert_eq!(users.iter().find(|u| u.username == "u2").unwrap().nodes, "local");
        // a second sweep finds nothing
        assert!(super::sweep(&app).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
