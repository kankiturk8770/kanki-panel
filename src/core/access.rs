//! Who may run and who may use which core.
//!
//! A server has a role: `gaming` servers run only the gaming cores (KANKI MIX, WireGuard, AmneziaWG, Kanki DNS),
//! `antifilter` servers only the anti-filter cores (Xray, Hysteria2), `panel` (the panel's own machine) and `iran`
//! (an Iran entry that only carries tunnels) run no VPN core and get no VPN user, `hybrid` servers (every server
//! made before roles existed) run everything. A core the role does not allow counts as switched off on that server,
//! whatever its own switch says, so changing the role takes effect on the next sync and switching back to `hybrid`
//! restores what the admin had chosen. An antifilter server that ran AmneziaWG before 3.70 keeps it
//! (`antifilter_awg_keep`, set once by the migration) so nobody on it is cut off.
//!
//! A user has one of three tiers, one account and one subscription code whatever the tier:
//! `v2ray` «ضد فیلتر V2Ray» (Xray + Hysteria2), `gaming` «گیمینگ WireGuard» (KANKI MIX + AmneziaWG + WireGuard + DNS),
//! `vip` «ترکیبی VIP» (every core). An account only ever has the protocols of its tier (`Tier::clamp`); an upgrade
//! to `vip` adds the rest on the same account.
use crate::App;

/// The cores a user of each tier gets
pub const V2RAY_PROTOS: &[&str] = &["xray", "hy2"];
pub const GAMING_PROTOS: &[&str] = crate::db::GAME_PROTOS;
/// Every user protocol, in the order a full (vip) account lists them
pub const VIP_PROTOS: &[&str] = &["xray", "hy2", "kmix", "awg", "wg", "dns"];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tier {
    V2ray,
    Gaming,
    Vip,
}

impl Tier {
    /// The stored name ("game" is the plans' name of gaming; "combo" the name of vip before 3.70)
    pub fn parse(s: &str) -> Option<Tier> {
        match s.trim().to_ascii_lowercase().as_str() {
            "v2ray" => Some(Tier::V2ray),
            "gaming" | "game" => Some(Tier::Gaming),
            "vip" | "combo" => Some(Tier::Vip),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Tier::V2ray => "v2ray",
            Tier::Gaming => "gaming",
            Tier::Vip => "vip",
        }
    }

    /// The name customers see
    pub fn label(self) -> &'static str {
        match self {
            Tier::V2ray => "ضد فیلتر V2Ray",
            Tier::Gaming => "گیمینگ WireGuard",
            Tier::Vip => "ترکیبی VIP",
        }
    }

    /// The tier a plan of `service` sells ('v2ray', 'game' or 'vip'; anything else is 'vip')
    pub fn of_service(service: &str) -> Tier {
        Tier::parse(service).unwrap_or(Tier::Vip)
    }

    /// The plans' name of the service (what `Db::service_protocols` takes)
    pub fn service(self) -> &'static str {
        match self {
            Tier::V2ray => "v2ray",
            Tier::Gaming => "game",
            Tier::Vip => "vip",
        }
    }

    /// Every protocol this tier is entitled to
    pub fn protocols(self) -> &'static [&'static str] {
        match self {
            Tier::V2ray => V2RAY_PROTOS,
            Tier::Gaming => GAMING_PROTOS,
            Tier::Vip => VIP_PROTOS,
        }
    }

    pub fn allows(self, proto: &str) -> bool {
        self.protocols().contains(&proto)
    }

    /// `list` without what this tier is not entitled to (order kept, no duplicates)
    pub fn clamp(self, list: &str) -> String {
        let mut out: Vec<&str> = vec![];
        for p in list.split(',').map(|x| x.trim()).filter(|x| !x.is_empty()) {
            if self.allows(p) && !out.contains(&p) {
                out.push(p);
            }
        }
        out.join(",")
    }

    /// The protocols of `list` this tier is not entitled to
    pub fn outside(self, list: &str) -> Vec<String> {
        list.split(',').map(|x| x.trim()).filter(|x| !x.is_empty() && !self.allows(x)).map(|x| x.to_string()).collect()
    }

    /// The tier after buying `other` on top of this one: two different tiers make `vip`
    pub fn with(self, other: Tier) -> Tier {
        if self == other { self } else { Tier::Vip }
    }

    /// Can an account of this tier be upgraded in place to `to`? (only to vip, from the other two)
    pub fn upgrades_to(self, to: Tier) -> bool {
        to == Tier::Vip && self != Tier::Vip
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Gaming,
    Antifilter,
    Hybrid,
    /// the panel's own machine: no VPN core, no VPN user
    Panel,
    /// an Iran entry: carries tunnels to the servers abroad, runs no VPN core itself
    Iran,
}

/// Every core a role decides about (wg, awg, hy2, kmix are VPN cores of the node; xray and dns run
/// in the server agent)
pub const SERVER_CORES: &[&str] = &["wg", "awg", "hy2", "kmix", "xray", "dns"];

impl Role {
    pub fn parse(s: &str) -> Option<Role> {
        match s.trim().to_ascii_lowercase().as_str() {
            "gaming" => Some(Role::Gaming),
            "antifilter" => Some(Role::Antifilter),
            "hybrid" => Some(Role::Hybrid),
            "panel" => Some(Role::Panel),
            "iran" => Some(Role::Iran),
            _ => None,
        }
    }

    /// The stored value; empty or unknown (a row from before roles) is `hybrid`
    pub fn of(s: &str) -> Role {
        Role::parse(s).unwrap_or(Role::Hybrid)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Role::Gaming => "gaming",
            Role::Antifilter => "antifilter",
            Role::Hybrid => "hybrid",
            Role::Panel => "panel",
            Role::Iran => "iran",
        }
    }

    pub fn allows(self, core: &str) -> bool {
        match self {
            // AmneziaWG is WireGuard with hidden packets: as good for games as WireGuard itself
            Role::Gaming => matches!(core, "kmix" | "wg" | "awg" | "dns"),
            Role::Antifilter => matches!(core, "xray" | "hy2"),
            Role::Hybrid => true,
            Role::Panel | Role::Iran => false,
        }
    }

    /// Does a server of this role take VPN users at all?
    pub fn serves_users(self) -> bool {
        !matches!(self, Role::Panel | Role::Iran)
    }

    /// The cores of `SERVER_CORES` this role does not run
    pub fn denied(self) -> Vec<&'static str> {
        SERVER_CORES.iter().copied().filter(|c| !self.allows(c)).collect()
    }

    /// The text of a refused switch
    pub fn refusal(self, core: &str) -> String {
        format!("this server's role is {}: it does not run {}", self.as_str(), core_name(core))
    }
}

/// Antifilter servers that ran AmneziaWG before 3.70 and keep it
fn awg_kept(app: &App, nid: &str) -> bool {
    serde_json::from_str::<Vec<String>>(&app.db.get("antifilter_awg_keep")).unwrap_or_default().iter().any(|x| x == nid)
}

/// May VPN node `nid` run `core` by its role (with the AmneziaWG kept on old antifilter servers)?
pub fn node_allows(app: &App, nid: &str, core: &str) -> bool {
    let role = node_role(app, nid);
    role.allows(core) || (role == Role::Antifilter && core == "awg" && awg_kept(app, nid))
}

/// The role a node may be set to: a node that is the panel's own machine may only be `panel` or `hybrid`
/// (a panel that is also a VPN server, as before roles); `panel` only for that node
pub fn role_fits(nid: &str, role: Role) -> Result<(), String> {
    if role == Role::Panel && nid != "local" {
        return Err("only the panel's own server (local) can have the role panel".into());
    }
    Ok(())
}

pub fn core_name(core: &str) -> &'static str {
    match core {
        "wg" => "WireGuard",
        "awg" => "AmneziaWG",
        "hy2" => "Hysteria2",
        "kmix" => "KANKI MIX",
        "xray" => "Xray",
        "dns" => "Kanki DNS",
        _ => "this core",
    }
}

/// The role of VPN node `nid` (unknown node = `hybrid`)
pub fn node_role(app: &App, nid: &str) -> Role {
    app.db.node(nid).map(|n| n.role()).unwrap_or(Role::Hybrid)
}

/// The role of agent server `sid` (the Xray and Kanki DNS servers are keyed by it; "local" is the
/// panel server): the role of the VPN node on the same machine, `hybrid` while it has none
pub fn server_role(app: &App, sid: &str) -> Role {
    if sid == "local" {
        return node_role(app, "local");
    }
    crate::tunnel::panel::servers(app)
        .into_iter()
        .find(|s| s.id == sid && !s.node.is_empty())
        .map(|s| node_role(app, &s.node))
        .unwrap_or(Role::Hybrid)
}

/// May agent server `sid` run `core` (xray / dns) by its role?
pub fn server_allows(app: &App, sid: &str, core: &str) -> bool {
    server_role(app, sid).allows(core)
}

/// The cores of the server agent (Xray, Kanki DNS) that have their own switch on each server
pub const AGENT_CORES: &[&str] = &["xray", "dns"];

/// agent server id -> its agent cores switched off (their settings stay; switching back on restores them)
fn agent_off_map(app: &App) -> std::collections::HashMap<String, Vec<String>> {
    serde_json::from_str(&app.db.get("agent_core_off")).unwrap_or_default()
}

/// The agent cores switched off on agent server `sid`
pub fn agent_off(app: &App, sid: &str) -> Vec<String> {
    agent_off_map(app).remove(sid).unwrap_or_default()
}

/// Switches agent core `core` (xray | dns) of agent server `sid` off, or back on
pub fn set_agent_off(app: &App, sid: &str, core: &str, off: bool) -> Result<(), String> {
    if !AGENT_CORES.contains(&core) {
        return Err("core: xray or dns".into());
    }
    let mut m = agent_off_map(app);
    let l = m.entry(sid.to_string()).or_default();
    l.retain(|c| c != core);
    if off {
        l.push(core.to_string());
    }
    l.sort();
    if l.is_empty() {
        m.remove(sid);
    }
    let v = serde_json::to_string(&m).map_err(|e| e.to_string())?;
    app.db.set("agent_core_off", &v);
    Ok(())
}

/// A removed server's switches go with it
pub fn forget_agent(app: &App, sid: &str) {
    let mut m = agent_off_map(app);
    if m.remove(sid).is_some() {
        if let Ok(v) = serde_json::to_string(&m) {
            app.db.set("agent_core_off", &v);
        }
    }
}

/// Does agent server `sid` run `core` (xray / dns): its role allows it and its switch is on?
pub fn server_runs(app: &App, sid: &str, core: &str) -> bool {
    server_allows(app, sid, core) && !agent_off(app, sid).iter().any(|c| c == core)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roles_split_the_cores_and_hybrid_keeps_everything() {
        for c in ["kmix", "wg", "awg", "dns"] {
            assert!(Role::Gaming.allows(c) && !Role::Antifilter.allows(c), "{}", c);
        }
        for c in ["xray", "hy2"] {
            assert!(Role::Antifilter.allows(c) && !Role::Gaming.allows(c), "{}", c);
        }
        assert!(SERVER_CORES.iter().all(|c| Role::Hybrid.allows(c)));
        assert!(Role::Hybrid.denied().is_empty());
        assert_eq!(Role::Gaming.denied(), vec!["hy2", "xray"]);
        assert_eq!(Role::Antifilter.denied(), vec!["wg", "awg", "kmix", "dns"]);
        // the panel and an Iran entry run no VPN core and carry no user
        for r in [Role::Panel, Role::Iran] {
            assert_eq!(r.denied().len(), SERVER_CORES.len());
            assert!(!r.serves_users());
        }
        assert!(Role::Gaming.serves_users() && Role::Antifilter.serves_users() && Role::Hybrid.serves_users());
        assert!(role_fits("local", Role::Panel).is_ok() && role_fits("n2", Role::Panel).is_err() && role_fits("n2", Role::Iran).is_ok());
        // a row from before roles, or a value nobody knows, is hybrid; never a role that takes cores away
        assert_eq!(Role::of(""), Role::Hybrid);
        assert_eq!(Role::of("GAMING "), Role::Gaming);
        assert_eq!(Role::of("gaming;drop table nodes"), Role::Hybrid);
        assert!(Role::parse("nonsense").is_none());
    }

    #[test]
    fn three_tiers_have_exactly_their_cores() {
        assert_eq!(Tier::V2ray.protocols(), &["xray", "hy2"]);
        for p in ["wg", "awg", "kmix", "dns"] {
            assert!(!Tier::V2ray.allows(p) && Tier::Gaming.allows(p), "{}", p);
        }
        for p in ["xray", "hy2"] {
            assert!(!Tier::Gaming.allows(p), "{}", p);
        }
        assert!(VIP_PROTOS.iter().all(|p| Tier::Vip.allows(p)));
        // nothing outside the six cores, whatever the tier
        assert!(!Tier::Vip.allows("ovpn") && !Tier::Vip.allows(""));
        assert_eq!(Tier::V2ray.clamp("wg,xray,awg,hy2,xray"), "xray,hy2");
        assert_eq!(Tier::Gaming.clamp("xray,kmix,wg,dns,hy2"), "kmix,wg,dns");
        assert_eq!(Tier::Gaming.outside("xray,kmix"), vec!["xray".to_string()]);
        assert_eq!(Tier::V2ray.with(Tier::Gaming), Tier::Vip);
        assert_eq!(Tier::Gaming.with(Tier::V2ray), Tier::Vip);
        assert_eq!(Tier::V2ray.with(Tier::V2ray), Tier::V2ray);
        assert_eq!(Tier::Vip.with(Tier::Gaming), Tier::Vip);
        assert_eq!(Tier::of_service("game"), Tier::Gaming);
        assert_eq!(Tier::of_service("vip"), Tier::Vip);
        assert_eq!(Tier::of_service(""), Tier::Vip);
        // the name before 3.70 still reads
        assert_eq!(Tier::parse("combo"), Some(Tier::Vip));
        assert_eq!(Tier::Vip.as_str(), "vip");
        assert_eq!(Tier::parse("v2ray").map(|t| t.service()), Some("v2ray"));
        // only v2ray / gaming go up, and only to vip
        assert!(Tier::V2ray.upgrades_to(Tier::Vip) && Tier::Gaming.upgrades_to(Tier::Vip));
        assert!(!Tier::Vip.upgrades_to(Tier::Vip) && !Tier::V2ray.upgrades_to(Tier::Gaming));
    }
}
