//! Who may run and who may use which core.
//!
//! A server has a role: `gaming` servers run only the gaming cores (KANKI MIX, WireGuard, Kanki DNS),
//! `antifilter` servers only the anti-filter cores (Xray, Hysteria2, AmneziaWG), `hybrid` servers
//! (every server made before roles existed) run everything. A core the role does not allow counts as
//! switched off on that server, whatever its own switch says, so changing the role takes effect on
//! the next sync and switching back to `hybrid` restores what the admin had chosen.
//!
//! A user has a tier: `v2ray` (Xray + Hysteria2), `gaming` (WireGuard + AmneziaWG + KANKI MIX) or
//! `combo` (every core). Purchases and the «give everyone» buttons only hand out what the tier allows;
//! an admin may still tick any protocol on one user by hand.
use crate::App;

/// The cores a user of each tier gets
pub const V2RAY_PROTOS: &[&str] = &["xray", "hy2"];
pub const GAMING_PROTOS: &[&str] = crate::db::GAME_PROTOS;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tier {
    V2ray,
    Gaming,
    Combo,
}

impl Tier {
    /// The stored name ("game" and "vip", the names of the plans' services, are read as well)
    pub fn parse(s: &str) -> Option<Tier> {
        match s.trim().to_ascii_lowercase().as_str() {
            "v2ray" => Some(Tier::V2ray),
            "gaming" | "game" => Some(Tier::Gaming),
            "combo" | "vip" => Some(Tier::Combo),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Tier::V2ray => "v2ray",
            Tier::Gaming => "gaming",
            Tier::Combo => "combo",
        }
    }

    /// The tier a plan of `service` sells ('v2ray', 'game' or 'vip'; anything else is 'vip')
    pub fn of_service(service: &str) -> Tier {
        Tier::parse(service).unwrap_or(Tier::Combo)
    }

    /// The plans' name of the service (what `Db::service_protocols` takes)
    pub fn service(self) -> &'static str {
        match self {
            Tier::V2ray => "v2ray",
            Tier::Gaming => "game",
            Tier::Combo => "vip",
        }
    }

    pub fn allows(self, proto: &str) -> bool {
        match self {
            Tier::V2ray => V2RAY_PROTOS.contains(&proto),
            Tier::Gaming => GAMING_PROTOS.contains(&proto),
            Tier::Combo => true,
        }
    }

    /// The tier after buying `other` on top of this one: two different tiers make `combo`
    pub fn with(self, other: Tier) -> Tier {
        if self == other { self } else { Tier::Combo }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Gaming,
    Antifilter,
    Hybrid,
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
        }
    }

    pub fn allows(self, core: &str) -> bool {
        match self {
            Role::Gaming => matches!(core, "kmix" | "wg" | "dns"),
            Role::Antifilter => matches!(core, "xray" | "hy2" | "awg"),
            Role::Hybrid => true,
        }
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

fn core_name(core: &str) -> &'static str {
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

/// May agent server `sid` run `core` (xray / dns)?
pub fn server_allows(app: &App, sid: &str, core: &str) -> bool {
    server_role(app, sid).allows(core)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roles_split_the_cores_and_hybrid_keeps_everything() {
        for c in ["kmix", "wg", "dns"] {
            assert!(Role::Gaming.allows(c) && !Role::Antifilter.allows(c), "{}", c);
        }
        for c in ["xray", "hy2", "awg"] {
            assert!(Role::Antifilter.allows(c) && !Role::Gaming.allows(c), "{}", c);
        }
        assert!(SERVER_CORES.iter().all(|c| Role::Hybrid.allows(c)));
        assert!(Role::Hybrid.denied().is_empty());
        assert_eq!(Role::Gaming.denied(), vec!["awg", "hy2", "xray"]);
        assert_eq!(Role::Antifilter.denied(), vec!["wg", "kmix", "dns"]);
        // a row from before roles, or a value nobody knows, is hybrid; never a role that takes cores away
        assert_eq!(Role::of(""), Role::Hybrid);
        assert_eq!(Role::of("GAMING "), Role::Gaming);
        assert_eq!(Role::of("gaming;drop table nodes"), Role::Hybrid);
        assert!(Role::parse("nonsense").is_none());
    }

    #[test]
    fn tiers_allow_only_their_cores_and_upgrades_make_combo() {
        assert!(Tier::V2ray.allows("xray") && Tier::V2ray.allows("hy2"));
        for p in ["wg", "awg", "kmix", "dns"] {
            assert!(!Tier::V2ray.allows(p), "{}", p);
        }
        for p in ["wg", "awg", "kmix"] {
            assert!(Tier::Gaming.allows(p), "{}", p);
        }
        for p in ["xray", "hy2", "dns"] {
            assert!(!Tier::Gaming.allows(p), "{}", p);
        }
        assert!(["wg", "awg", "kmix", "xray", "hy2", "dns"].iter().all(|p| Tier::Combo.allows(p)));
        assert_eq!(Tier::V2ray.with(Tier::Gaming), Tier::Combo);
        assert_eq!(Tier::Gaming.with(Tier::V2ray), Tier::Combo);
        assert_eq!(Tier::V2ray.with(Tier::V2ray), Tier::V2ray);
        assert_eq!(Tier::Combo.with(Tier::Gaming), Tier::Combo);
        assert_eq!(Tier::of_service("game"), Tier::Gaming);
        assert_eq!(Tier::of_service("vip"), Tier::Combo);
        assert_eq!(Tier::of_service(""), Tier::Combo);
        assert_eq!(Tier::parse("v2ray").map(|t| t.service()), Some("v2ray"));
    }
}
