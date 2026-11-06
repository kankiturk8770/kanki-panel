//! Database (SQLite)
use crate::util::now;
use rusqlite::{params, Connection, OptionalExtension, Row};
use serde::Serialize;
use std::sync::Mutex;

pub struct Db(pub Mutex<Connection>);

/// Serialises picking a free user number + inserting it.
static SLOT: Mutex<()> = Mutex::new(());

/// The longest time one create / renew may add (100 years): bigger numbers would overflow `days * 86400`.
pub const MAX_DAYS: i64 = 36500;

/// days as given, kept within 0..=MAX_DAYS
fn clamp_days(days: i64) -> i64 {
    days.clamp(0, MAX_DAYS)
}

/// GB as given; not-a-number or negative is 0, and no more than a million GB
fn clamp_gb(gb: f64) -> f64 {
    if gb.is_finite() { gb.clamp(0.0, 1_000_000.0) } else { 0.0 }
}

/// log rows kept while running (the same bounds as at start)
const AUDIT_KEEP: i64 = 5000;
const LOGIN_LOG_KEEP: i64 = 2000;

/// The WireGuard / AmneziaWG address of a user in the server's /16 (`base` is "10.66" or "10.67").
/// Ids below 62500 keep the address they always had (third byte id/250, fourth id%250+2). Bigger ids
/// take the part of the /16 the first form never uses (third byte 250..255, fourth 1..254), so they are
/// still inside the server's network and its NAT. None when the /16 is full.
pub fn peer_ip(base: &str, user_id: i64) -> Option<String> {
    if user_id < 0 {
        return None;
    }
    if user_id < 62500 {
        return Some(format!("{}.{}.{}", base, (user_id / 250) % 250, user_id % 250 + 2));
    }
    let k = user_id - 62500;
    let (third, fourth) = (250 + k / 254, k % 254 + 1);
    (third <= 255).then(|| format!("{}.{}.{}", base, third, fourth))
}

#[derive(Clone, Debug, Serialize)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub code: String,
    pub limit_gb: f64,
    pub used_bytes: i64,
    pub expires_at: i64,
    pub max_conn: i64,
    pub enabled: bool,
    pub protocols: String,
    pub nodes: String,
    pub notes: String,
    pub tg_id: i64,
    pub created_at: i64,
    pub last_seen: i64,
    pub online: i64,
    pub warned: i64,
}

impl User {
    fn from_row(r: &Row) -> rusqlite::Result<User> {
        Ok(User {
            id: r.get(0)?,
            username: r.get(1)?,
            code: r.get(2)?,
            limit_gb: r.get(3)?,
            used_bytes: r.get(4)?,
            expires_at: r.get(5)?,
            max_conn: r.get(6)?,
            enabled: r.get::<_, i64>(7)? == 1,
            protocols: r.get(8)?,
            nodes: r.get(9)?,
            notes: r.get(10)?,
            tg_id: r.get(11)?,
            created_at: r.get(12)?,
            last_seen: r.get(13)?,
            online: r.get(14)?,
            warned: r.get(15)?,
        })
    }

    pub fn sub_code(&self) -> String {
        format!("kanki-{}-{}", self.id, self.code)
    }

    pub fn used_gb(&self) -> f64 {
        crate::util::gb(self.used_bytes)
    }

    pub fn expired(&self) -> bool {
        self.expires_at > 0 && self.expires_at <= now()
    }

    pub fn over_quota(&self) -> bool {
        self.limit_gb > 0.0 && self.used_gb() >= self.limit_gb
    }

    /// کاربر الان اجازه‌ی اتصال دارد؟
    pub fn active(&self) -> bool {
        self.enabled && !self.expired() && !self.over_quota()
    }

    pub fn status(&self) -> &'static str {
        if !self.enabled {
            "Disabled"
        } else if self.expired() {
            "Expired"
        } else if self.over_quota() {
            "Limited"
        } else {
            "Active"
        }
    }

    pub fn has_proto(&self, p: &str) -> bool {
        self.protocols.split(',').any(|x| x.trim() == p)
    }

    /// 'v2ray' when the account has only what a v2ray client reads (Xray, Hysteria2) and Xray is one of
    /// them, else 'vip'
    pub fn service(&self) -> &'static str {
        let ps: Vec<&str> = self.protocols.split(',').map(|x| x.trim()).filter(|x| !x.is_empty()).collect();
        if ps.contains(&"xray") && ps.iter().all(|p| matches!(*p, "xray" | "hy2")) { "v2ray" } else { "vip" }
    }

    pub fn explicit_nodes(&self) -> bool {
        !self.nodes.trim().is_empty()
    }

    /// Users without an explicit node list land on every node that accepts them
    pub fn on(&self, n: &Node) -> bool {
        if self.explicit_nodes() {
            self.nodes.split(',').any(|x| x.trim() == n.id)
        } else {
            n.accept_all
        }
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Node {
    pub id: String,
    pub name: String,
    pub address: String,
    pub endpoint: String,
    pub token: String,
    pub enabled: bool,
    pub online: bool,
    pub last_sync: i64,
    pub info: String,
    pub note: String,
    pub insecure: bool,
    pub drain: bool,
    pub maint: bool,
    pub accept_all: bool,
    pub endpoint_mode: String,
    pub sync_state: String,
}

impl Node {
    fn from_row(r: &Row) -> rusqlite::Result<Node> {
        Ok(Node {
            id: r.get(0)?,
            name: r.get(1)?,
            address: r.get(2)?,
            endpoint: r.get(3)?,
            token: r.get(4)?,
            enabled: r.get::<_, i64>(5)? == 1,
            online: r.get::<_, i64>(6)? == 1,
            last_sync: r.get(7)?,
            info: r.get(8)?,
            note: r.get(9)?,
            insecure: r.get::<_, i64>(10)? == 1,
            drain: r.get::<_, i64>(11)? == 1,
            maint: r.get::<_, i64>(12)? == 1,
            accept_all: r.get::<_, i64>(13)? == 1,
            endpoint_mode: r.get(14)?,
            sync_state: r.get(15)?,
        })
    }

    /// Node takes new users and shows on the subscription page (not in maintenance). A node in maintenance is
    /// still synced, so users already on it keep working ("Under maintenance: new users are not sent here").
    pub fn usable(&self) -> bool {
        self.enabled && !self.maint
    }
}

#[derive(Clone, Debug)]
pub struct Peer {
    pub user_id: i64,
    pub node_id: String,
    pub proto: String,
    pub privkey: String,
    pub pubkey: String,
    pub psk: String,
    pub ip: String,
    pub rx: i64,
    pub tx: i64,
}

const USER_COLS: &str = "id,username,code,limit_gb,used_bytes,expires_at,max_conn,enabled,protocols,nodes,notes,tg_id,created_at,last_seen,online,warned";
const NODE_COLS: &str = "id,name,address,endpoint,token,enabled,online,last_sync,info,note,insecure,drain,maint,accept_all,endpoint_mode,sync_state";

impl Db {
    pub fn open(path: &str) -> Db {
        let c = Connection::open(path).expect("open db");
        c.execute_batch(
            "PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, code TEXT,
                limit_gb REAL DEFAULT 0, used_bytes INTEGER DEFAULT 0, expires_at INTEGER DEFAULT 0, max_conn INTEGER DEFAULT 1,
                enabled INTEGER DEFAULT 1, protocols TEXT DEFAULT 'wg,awg,hy2', nodes TEXT DEFAULT '', notes TEXT DEFAULT '',
                tg_id INTEGER DEFAULT 0, created_at INTEGER DEFAULT 0, last_seen INTEGER DEFAULT 0, online INTEGER DEFAULT 0, warned INTEGER DEFAULT 0);
            CREATE TABLE IF NOT EXISTS peers(user_id INTEGER, node_id TEXT, proto TEXT, privkey TEXT, pubkey TEXT, psk TEXT, ip TEXT,
                rx INTEGER DEFAULT 0, tx INTEGER DEFAULT 0, PRIMARY KEY(user_id,node_id,proto));
            CREATE TABLE IF NOT EXISTS nodes(id TEXT PRIMARY KEY, name TEXT, address TEXT, endpoint TEXT, token TEXT,
                enabled INTEGER DEFAULT 1, online INTEGER DEFAULT 0, last_sync INTEGER DEFAULT 0, info TEXT DEFAULT '{}');
            CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY, v TEXT);
            CREATE TABLE IF NOT EXISTS bot_users(tg_id INTEGER PRIMARY KEY, name TEXT, joined INTEGER, trial_used INTEGER DEFAULT 0,
                ref_by INTEGER DEFAULT 0, ref_rewarded INTEGER DEFAULT 0, blocked INTEGER DEFAULT 0);
            CREATE TABLE IF NOT EXISTS plans(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, days INTEGER, gb REAL, toman INTEGER,
                usd REAL, conns INTEGER DEFAULT 1, active INTEGER DEFAULT 1);
            CREATE TABLE IF NOT EXISTS orders(id INTEGER PRIMARY KEY AUTOINCREMENT, tg_id INTEGER, plan_id INTEGER, kind TEXT, target INTEGER,
                method TEXT, amount TEXT, status TEXT, ref TEXT, discount TEXT DEFAULT '', created INTEGER);
            CREATE TABLE IF NOT EXISTS discounts(code TEXT PRIMARY KEY, percent INTEGER, uses_left INTEGER);
            CREATE TABLE IF NOT EXISTS sessions(id TEXT PRIMARY KEY, hash TEXT UNIQUE, username TEXT, ip TEXT, ua TEXT,
                created INTEGER, last_seen INTEGER, expires INTEGER);
            CREATE TABLE IF NOT EXISTS api_tokens(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, hash TEXT UNIQUE, prefix TEXT,
                scopes TEXT, created INTEGER, last_used INTEGER DEFAULT 0);
            CREATE TABLE IF NOT EXISTS login_log(id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, username TEXT, ip TEXT, method TEXT, ok INTEGER);
            CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, actor TEXT, method TEXT, path TEXT, status INTEGER, ip TEXT);
            CREATE TABLE IF NOT EXISTS claims(id TEXT PRIMARY KEY, tg_id INTEGER, user_id INTEGER DEFAULT 0, created INTEGER);
            CREATE TABLE IF NOT EXISTS devices(user_id INTEGER, id TEXT, bound INTEGER DEFAULT 0, kind TEXT DEFAULT '', app TEXT DEFAULT '',
                ip TEXT DEFAULT '', first_seen INTEGER, last_seen INTEGER, PRIMARY KEY(user_id, id));",
        )
        .expect("schema");
        // forward-only migrations (errors = column already exists)
        for m in [
            "ALTER TABLE nodes ADD COLUMN note TEXT DEFAULT ''",
            "ALTER TABLE nodes ADD COLUMN insecure INTEGER DEFAULT 0",
            "ALTER TABLE nodes ADD COLUMN drain INTEGER DEFAULT 0",
            "ALTER TABLE nodes ADD COLUMN maint INTEGER DEFAULT 0",
            "ALTER TABLE nodes ADD COLUMN accept_all INTEGER DEFAULT 1",
            "ALTER TABLE nodes ADD COLUMN endpoint_mode TEXT DEFAULT 'custom'",
            "ALTER TABLE nodes ADD COLUMN sync_state TEXT DEFAULT ''",
            // v2.5: plans carry how many countries (servers) they give; discount codes can expire
            "ALTER TABLE plans ADD COLUMN countries INTEGER DEFAULT 0",
            "ALTER TABLE plans ADD COLUMN category TEXT DEFAULT ''",
            // 3.23: the colour of a plan's button in the bot (success / primary / danger, '' = by users)
            "ALTER TABLE plans ADD COLUMN style TEXT DEFAULT ''",
            // 3.26: what a plan sells: 'vip' (every protocol, the Kanki app, AmneziaWG / WireGuard) or 'v2ray'
            // (only the subscription link for v2rayNG / Streisand / V2Box). Plans made before stay 'vip'.
            "ALTER TABLE plans ADD COLUMN service TEXT DEFAULT 'vip'",
            // 3.28: a plan's label in the shop («🔥 پیشنهاد ویژه») and a higher price shown struck through
            "ALTER TABLE plans ADD COLUMN badge TEXT DEFAULT ''",
            "ALTER TABLE plans ADD COLUMN old_toman INTEGER DEFAULT 0",
            "ALTER TABLE discounts ADD COLUMN expires INTEGER DEFAULT 0",
            // v2.9.4: the config name a customer chose, and the Telegram @username / last name (to suggest one)
            "ALTER TABLE bot_users ADD COLUMN cfg_name TEXT DEFAULT ''",
            "ALTER TABLE bot_users ADD COLUMN uname TEXT DEFAULT ''",
            "ALTER TABLE bot_users ADD COLUMN lname TEXT DEFAULT ''",
        ] {
            let _ = c.execute(m, []);
        }
        let _ = c.execute("UPDATE nodes SET note='' WHERE note IS NULL", []);
        let _ = c.execute("UPDATE nodes SET endpoint_mode='custom' WHERE endpoint_mode IS NULL", []);
        let _ = c.execute("UPDATE nodes SET sync_state='' WHERE sync_state IS NULL", []);
        let _ = c.execute("UPDATE nodes SET insecure=0 WHERE insecure IS NULL", []);
        let _ = c.execute("UPDATE nodes SET drain=0 WHERE drain IS NULL", []);
        let _ = c.execute("UPDATE nodes SET maint=0 WHERE maint IS NULL", []);
        let _ = c.execute("UPDATE nodes SET accept_all=1 WHERE accept_all IS NULL", []);
        // cleanup: drop a retired protocol name from old data
        let _ = c.execute("UPDATE settings SET v='Kanki Panel' WHERE k='panel_name' AND v IN ('KANKI VPN','KANKI-VPN','Kanki VPN')", []);
        let _ = c.execute("UPDATE settings SET v=trim(replace(','||v||',', ',ovpn,', ','), ',') WHERE k='default_protocols' AND ','||v||',' LIKE '%,ovpn,%'", []);
        let _ = c.execute("UPDATE users SET protocols=trim(replace(','||protocols||',', ',ovpn,', ','), ',') WHERE ','||protocols||',' LIKE '%,ovpn,%'", []);
        // 3.19: MIX+ (and the Game-FEC / HQ-QUIC / FakeTCP names it came from) is gone: its user protocols
        // and its settings and secrets
        for p in ["kgame", "khq", "kftcp"] {
            let pat = format!(",{},", p);
            let _ = c.execute("UPDATE settings SET v=trim(replace(','||v||',', ?1, ','), ',') WHERE k='default_protocols' AND instr(','||v||',', ?1) > 0", [&pat]);
            let _ = c.execute("UPDATE users SET protocols=trim(replace(','||protocols||',', ?1, ','), ',') WHERE instr(','||protocols||',', ?1) > 0", [&pat]);
        }
        let _ = c.execute("DELETE FROM settings WHERE k IN ('kgame_cfg','khq_cfg','kftcp_cfg','kc_door','kc_secret')", []);
        // v2.9.4: a trial is a user whose note is "trial"; finished trials are deleted. Before, a trial that was
        // extended / renewed kept that note (only USER<n>-TEST was renamed to USER<n>), so clear it once on those
        // accounts: they are customers now and must never be removed.
        let migrated: bool = c.query_row("SELECT 1 FROM settings WHERE k='mig_trial_notes'", [], |_| Ok(())).is_ok();
        if !migrated {
            let _ = c.execute("UPDATE users SET notes='' WHERE notes='trial' AND UPPER(username) NOT LIKE '%-TEST'", []);
            let _ = c.execute("INSERT OR REPLACE INTO settings(k,v) VALUES('mig_trial_notes','1')", []);
        }
        // keep logs bounded
        trim_logs(&c);
        Db(Mutex::new(c))
    }

    /// Keeps the audit and login logs bounded while the panel runs: called after each insert, it trims
    /// only every 200th row (one cheap delete, not one per request).
    pub fn note_log_row(&self) {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        if N.fetch_add(1, Ordering::Relaxed) % 200 == 199 {
            self.with(trim_logs);
        }
    }

    pub fn with<T>(&self, f: impl FnOnce(&Connection) -> T) -> T {
        // a panic inside one query must not leave the database locked out for the rest of the run
        let c = self.0.lock().unwrap_or_else(|e| e.into_inner());
        f(&c)
    }

    // ---------------- تنظیمات
    /// The protocols an account of a plan's service gets ('v2ray' or 'vip')
    pub fn service_protocols(&self, service: &str) -> String {
        if service == "v2ray" {
            let v = self.get("v2ray_protocols");
            let ok: Vec<&str> = v.split(',').map(|x| x.trim()).filter(|x| matches!(*x, "xray" | "hy2")).collect();
            if ok.contains(&"xray") { ok.join(",") } else { "xray".into() }
        } else {
            self.get("default_protocols")
        }
    }

    pub fn get(&self, k: &str) -> String {
        self.with(|c| {
            c.query_row("SELECT v FROM settings WHERE k=?1", params![k], |r| r.get::<_, String>(0))
                .optional()
                .ok()
                .flatten()
                .unwrap_or_else(|| default_setting(k).to_string())
        })
    }

    pub fn set(&self, k: &str, v: &str) {
        self.with(|c| {
            let _ = c.execute(
                "INSERT INTO settings(k,v) VALUES(?1,?2) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
                params![k, v],
            );
        });
    }

    pub fn on(&self, k: &str) -> bool {
        self.get(k) == "1"
    }

    // ---------------- کاربران
    pub fn users(&self) -> Vec<User> {
        self.with(|c| {
            let mut s = c.prepare(&format!("SELECT {} FROM users ORDER BY id DESC", USER_COLS)).unwrap();
            let v: Vec<User> = s.query_map([], User::from_row).unwrap().filter_map(|x| x.ok()).collect();
            v
        })
    }

    pub fn user(&self, id: i64) -> Option<User> {
        self.with(|c| {
            c.query_row(&format!("SELECT {} FROM users WHERE id=?1", USER_COLS), params![id], User::from_row)
                .optional()
                .ok()
                .flatten()
        })
    }

    pub fn user_by_code(&self, id: i64, code: &str) -> Option<User> {
        self.user(id).filter(|u| u.code == code)
    }

    pub fn users_of_tg(&self, tg: i64) -> Vec<User> {
        self.users().into_iter().filter(|u| u.tg_id == tg).collect()
    }

    /// Lowest free user number: id n is unused and no user is called USERn / USERn-TEST.
    /// Deleted users free their number, so the next new user takes it again.
    pub fn next_slot(&self) -> i64 {
        let rows: Vec<(i64, String)> = self.with(|c| {
            let mut out = vec![];
            if let Ok(mut st) = c.prepare("SELECT id, username FROM users") {
                if let Ok(it) = st.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))) {
                    for x in it.flatten() {
                        out.push(x);
                    }
                }
            }
            out
        });
        let ids: std::collections::HashSet<i64> = rows.iter().map(|x| x.0).collect();
        let names: std::collections::HashSet<String> = rows.iter().map(|x| x.1.to_uppercase()).collect();
        let mut n = 1i64;
        while ids.contains(&n) || names.contains(&format!("USER{}", n)) || names.contains(&format!("USER{}-TEST", n)) {
            n += 1;
        }
        n
    }

    /// Is this name used by another user (any upper / lower case)?
    pub fn name_taken(&self, name: &str, except: i64) -> bool {
        self.with(|c| c.query_row("SELECT COUNT(*) FROM users WHERE UPPER(username)=UPPER(?1) AND id<>?2", params![name, except], |r| r.get::<_, i64>(0)).unwrap_or(1)) > 0
    }

    /// `base` when it is free, else base2, base3, … (kept within 12 characters)
    pub fn free_name(&self, base: &str) -> String {
        if !self.name_taken(base, 0) {
            return base.to_string();
        }
        for i in 2..10_000 {
            let suf = i.to_string();
            let cand = format!("{}{}", base.chars().take(12 - suf.len()).collect::<String>(), suf);
            if !self.name_taken(&cand, 0) {
                return cand;
            }
        }
        format!("{}{}", base.chars().take(6).collect::<String>(), crate::util::rand_digits(6))
    }

    /// Free trials whose time or data is over: they are deleted so their number is given to the next new user.
    /// A trial whose owner has an order that is not settled yet (a receipt waiting for approval, a payment
    /// being checked) is kept: the order may renew exactly this account.
    pub fn finished_trials(&self) -> Vec<User> {
        self.users().into_iter().filter(|u| u.notes == "trial" && (u.expired() || u.over_quota())).filter(|u| {
            let open: i64 = self.with(|c| c.query_row(
                "SELECT COUNT(*) FROM orders WHERE status IN ('pending','waiting','error') AND (target=?1 OR (?2<>0 AND tg_id=?2))",
                params![u.id, u.tg_id], |r| r.get(0)).unwrap_or(1));
            open == 0
        }).collect()
    }

    /// Creates a user. An empty username (or "auto") gives USER<n>; "auto-test" gives USER<n>-TEST
    /// (a free trial); "pick:<name>" gives that name, or name2, name3… when it is taken.
    /// The user's id is always the lowest free number, so the numbers of deleted users are used again.
    #[allow(clippy::too_many_arguments)]
    pub fn create_user(&self, username: &str, limit_gb: f64, days: i64, max_conn: i64, protocols: &str, nodes: &str, notes: &str, tg_id: i64) -> Result<User, String> {
        let code = crate::util::rand_digits(19);
        let days = clamp_days(days);
        let exp = if days > 0 { now() + days * 86400 } else { 0 };
        let _g = SLOT.lock().unwrap_or_else(|e| e.into_inner());
        let n = self.next_slot();
        let name = match username.trim() {
            "" | "auto" => format!("USER{}", n),
            "auto-test" => format!("USER{}-TEST", n),
            x => match x.strip_prefix("pick:") {
                Some(base) => self.free_name(base),
                None => x.to_string(),
            },
        };
        // mahtab87 and MAHTAB87 would look like the same customer
        if self.name_taken(&name, 0) {
            return Err("this name is already used by another user".into());
        }
        let id = self.with(|c| {
            c.execute(
                "INSERT INTO users(id,username,code,limit_gb,expires_at,max_conn,protocols,nodes,notes,tg_id,created_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
                params![n, name, code, limit_gb, exp, max_conn, protocols, nodes, notes, tg_id, now()],
            )
            .map(|_| c.last_insert_rowid())
            .map_err(|e| if e.to_string().contains("UNIQUE") { "this username already exists".to_string() } else { e.to_string() })
        })?;
        self.user(id).ok_or_else(|| "not found".into())
    }

    /// A trial that is bought / renewed / extended becomes a normal account (never deleted as a finished trial);
    /// an old style name USER<n>-TEST becomes USER<n>.
    pub fn promote_trial(&self, id: i64) {
        let _ = self.exec("UPDATE users SET notes='' WHERE id=?1 AND notes='trial'", &[&id]);
        if let Some(u) = self.user(id) {
            let up = u.username.to_uppercase();
            if let Some(base) = up.strip_suffix("-TEST") {
                let taken: i64 = self.with(|c| c.query_row("SELECT COUNT(*) FROM users WHERE UPPER(username)=?1", [base], |r| r.get(0)).unwrap_or(1));
                if base.starts_with("USER") && taken == 0 {
                    let _ = self.exec("UPDATE users SET username=?1 WHERE id=?2", &[&base.to_string(), &id]);
                }
            }
        }
    }

    pub fn exec(&self, sql: &str, p: &[&dyn rusqlite::ToSql]) -> Result<usize, String> {
        self.with(|c| c.execute(sql, p).map_err(|e| e.to_string()))
    }

    /// تمدید: روز به انقضا (یا از الان اگر گذشته) و حجم به سقف اضافه می‌شود
    pub fn extend(&self, id: i64, days: i64, add_gb: f64) -> Result<(), String> {
        let u = self.user(id).ok_or("user not found")?;
        let (days, add_gb) = (clamp_days(days), clamp_gb(add_gb));
        let base = if u.expires_at > now() { u.expires_at } else { now() };
        let exp = if days > 0 { base.saturating_add(days * 86400) } else { u.expires_at };
        let lim = if add_gb > 0.0 { added_limit(&u, add_gb) } else { u.limit_gb };
        self.exec("UPDATE users SET expires_at=?1, limit_gb=?2, warned=0 WHERE id=?3", &[&exp, &lim, &id]).map(|_| ())
    }

    /// Renewal with a plan: like `extend`, but 0 means what it means in a plan (and in create_user):
    /// days 0 = no end date, GB 0 = unlimited volume. An unlimited account renewed with a limited plan
    /// gets the plan's GB on top of what it already used, so it is not cut off right after paying.
    pub fn renew_plan(&self, id: i64, days: i64, gb: f64) -> Result<(), String> {
        let u = self.user(id).ok_or("user not found")?;
        let (days, gb) = (clamp_days(days), clamp_gb(gb));
        let base = if u.expires_at > now() { u.expires_at } else { now() };
        let exp = if days > 0 { base.saturating_add(days * 86400) } else { 0 };
        let lim = if gb > 0.0 { added_limit(&u, gb) } else { 0.0 };
        self.exec("UPDATE users SET expires_at=?1, limit_gb=?2, warned=0 WHERE id=?3", &[&exp, &lim, &id]).map(|_| ())
    }

    /// هدیه (جبران قطعی): روز به انقضا و حجم به سقف اضافه می‌شود، ولی زمان یا حجم نامحدود
    /// نامحدود می‌ماند (برخلاف extend که از نامحدود، محدود می‌سازد). true = چیزی عوض شد.
    pub fn gift(&self, id: i64, days: i64, add_gb: f64) -> Result<bool, String> {
        let u = self.user(id).ok_or("user not found")?;
        let (days, add_gb) = (clamp_days(days), clamp_gb(add_gb));
        let exp = if days > 0 && u.expires_at > 0 { u.expires_at.max(now()).saturating_add(days * 86400) } else { u.expires_at };
        let lim = if add_gb > 0.0 && u.limit_gb > 0.0 {
            if u.over_quota() { u.used_gb() + add_gb } else { u.limit_gb + add_gb }
        } else {
            u.limit_gb
        };
        if exp == u.expires_at && lim == u.limit_gb {
            return Ok(false);
        }
        self.exec("UPDATE users SET expires_at=?1, limit_gb=?2, warned=0 WHERE id=?3", &[&exp, &lim, &id]).map(|_| true)
    }

    pub fn count(&self, sql: &str) -> i64 {
        self.with(|c| c.query_row(sql, [], |r| r.get::<_, i64>(0)).unwrap_or(0))
    }

    /// Removes a user completely: account, keys / peers and rejected orders. Every other order stays but
    /// no longer points at the (now free) user number: a paid one keeps its amount for the sales total,
    /// and one still open (a receipt waiting for approval, a payment being checked, a failed delivery)
    /// gives the buyer a new account when it is approved.
    pub fn delete_user(&self, id: i64) {
        let _ = self.exec("DELETE FROM users WHERE id=?1", &[&id]);
        let _ = self.exec("DELETE FROM peers WHERE user_id=?1", &[&id]);
        let _ = self.exec("DELETE FROM devices WHERE user_id=?1", &[&id]);
        let _ = self.exec("DELETE FROM orders WHERE target=?1 AND status NOT IN ('done','approved','pending','waiting','error')", &[&id]);
        let _ = self.exec("UPDATE orders SET target=0 WHERE target=?1", &[&id]);
    }

    // ---------------- نودها
    pub fn nodes(&self) -> Vec<Node> {
        self.with(|c| {
            let mut s = c.prepare(&format!("SELECT {} FROM nodes ORDER BY id='local' DESC, name", NODE_COLS)).unwrap();
            let v: Vec<Node> = s.query_map([], Node::from_row).unwrap().filter_map(|x| x.ok()).collect();
            v
        })
    }

    pub fn node(&self, id: &str) -> Option<Node> {
        self.nodes().into_iter().find(|n| n.id == id)
    }

    // ---------------- پیرها
    pub fn peer(&self, user_id: i64, node: &str, proto: &str) -> Option<Peer> {
        self.with(|c| {
            c.query_row(
                "SELECT user_id,node_id,proto,privkey,pubkey,psk,ip,rx,tx FROM peers WHERE user_id=?1 AND node_id=?2 AND proto=?3",
                params![user_id, node, proto],
                |r| {
                    Ok(Peer {
                        user_id: r.get(0)?,
                        node_id: r.get(1)?,
                        proto: r.get(2)?,
                        privkey: r.get(3)?,
                        pubkey: r.get(4)?,
                        psk: r.get(5)?,
                        ip: r.get(6)?,
                        rx: r.get(7)?,
                        tx: r.get(8)?,
                    })
                },
            )
            .optional()
            .ok()
            .flatten()
        })
    }

    /// پیر کاربر روی یک نود (اگر نبود، کلید ساخته می‌شود)
    pub fn ensure_peer(&self, user_id: i64, node: &str, proto: &str) -> Option<Peer> {
        if let Some(p) = self.peer(user_id, node, proto) {
            return Some(p);
        }
        let (privk, pubk) = crate::wg::genkey()?;
        let psk = crate::wg::genpsk()?;
        let base = if proto == "awg" { "10.67" } else { "10.66" };
        let Some(ip) = peer_ip(base, user_id) else {
            eprintln!("{}: user {} has no free address left in {}.0.0/16 (user numbers up to 64023 fit)", proto, user_id, base);
            return None;
        };
        let _ = self.exec(
            "INSERT OR IGNORE INTO peers(user_id,node_id,proto,privkey,pubkey,psk,ip) VALUES(?1,?2,?3,?4,?5,?6,?7)",
            &[&user_id, &node, &proto, &privk, &pubk, &psk, &ip],
        );
        self.peer(user_id, node, proto)
    }
}

/// the new limit when `add` GB is added: on top of what was used when the account is unlimited or over its
/// limit, else on top of the limit
fn added_limit(u: &User, add: f64) -> f64 {
    if u.limit_gb <= 0.0 || u.over_quota() { u.used_gb() + add } else { u.limit_gb + add }
}

fn trim_logs(c: &Connection) {
    let _ = c.execute("DELETE FROM audit WHERE id <= (SELECT id FROM audit ORDER BY id DESC LIMIT 1 OFFSET ?1)", [AUDIT_KEEP]);
    let _ = c.execute("DELETE FROM login_log WHERE id <= (SELECT id FROM login_log ORDER BY id DESC LIMIT 1 OFFSET ?1)", [LOGIN_LOG_KEEP]);
}

pub fn default_setting(k: &str) -> &'static str {
    match k {
        "dns" => "1.1.1.1, 8.8.8.8",
        "mtu" => "1380",
        "mtu_auto" => "1",
        "mtu_budget" => "1380",
        "default_protocols" => "wg,awg,hy2,kmix",
        // what a 'v2ray' plan gives (the v2ray clients read only Xray, and Hysteria2 when added here)
        "v2ray_protocols" => "xray",
        "kmix_on" => "1",
        "kmix_port" => "4000",
        "kmix_parity" => "3",
        "kmix_gaming" => "1",
        "panel_name" => "Kanki Panel",
        "lang" => "fa",
        "theme" => "dark",
        "color" => "gold",
        "refresh" => "10",
        "session_hours" => "24",
        "awg_compat" => "0",
        "tgb_hours" => "24",
        "sales_on" => "1",
        "cp_on" => "1",
        "mini_menu" => "1",
        "trial_on" => "1",
        "trial_gb" => "1",
        "trial_days" => "1",
        "card_on" => "1",
        "np_coins" => "usdttrc20,trx,ton",
        "ref_gb" => "5",
        "ref_days" => "3",
        "warn_on" => "1",
        "backup_on" => "1",
        "welcome" => "به ربات فروش خوش آمدید 🌟",
        "def_gb" => "30",
        "def_days" => "30",
        "def_conns" => "1",
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_db() -> (std::path::PathBuf, Db) {
        let dir = std::env::temp_dir().join(format!("kanki-db-test-{}", crate::util::rand_token(8)));
        std::fs::create_dir_all(&dir).unwrap();
        let db = Db::open(dir.join("kanki.db").to_str().unwrap());
        (dir, db)
    }

    #[test]
    fn peer_addresses_stay_and_never_repeat() {
        // the addresses existing users have today
        assert_eq!(peer_ip("10.66", 1).unwrap(), "10.66.0.3");
        assert_eq!(peer_ip("10.66", 251).unwrap(), "10.66.1.3");
        assert_eq!(peer_ip("10.67", 62499).unwrap(), "10.67.249.251");
        // bigger numbers: inside the same /16, never one of the old addresses
        let mut seen = std::collections::HashSet::new();
        for id in 0..64024 {
            let ip = peer_ip("10.66", id).unwrap();
            assert!(ip != "10.66.0.1" && !ip.ends_with(".255.255"), "{}", ip);
            assert!(seen.insert(ip.clone()), "{} repeats", ip);
        }
        assert_eq!(peer_ip("10.66", 62500).unwrap(), "10.66.250.1");
        assert!(peer_ip("10.66", 64024).is_none());
    }

    #[test]
    fn plan_services() {
        let (dir, db) = temp_db();
        // a plan made before 3.26 sells the full service
        db.exec("INSERT INTO plans(name,days,gb,toman) VALUES('old',30,10,1000)", &[]).unwrap();
        let s: String = db.with(|c| c.query_row("SELECT service FROM plans WHERE name='old'", [], |r| r.get(0)).unwrap());
        assert_eq!(s, "vip");
        assert_eq!(db.service_protocols("vip"), db.get("default_protocols"));
        assert_eq!(db.service_protocols("v2ray"), "xray");
        db.set("v2ray_protocols", "xray,hy2,wg");
        assert_eq!(db.service_protocols("v2ray"), "xray,hy2");
        db.set("v2ray_protocols", "wg");
        assert_eq!(db.service_protocols("v2ray"), "xray");
        let u = db.create_user("v2u", 10.0, 30, 1, "xray", "", "", 0).unwrap();
        assert_eq!(u.service(), "v2ray");
        let u = db.create_user("v2h", 10.0, 30, 1, "xray,hy2", "", "", 0).unwrap();
        assert_eq!(u.service(), "v2ray");
        let u = db.create_user("vipu", 10.0, 30, 1, "wg,awg,hy2,kmix,xray", "", "", 0).unwrap();
        assert_eq!(u.service(), "vip");
        let u = db.create_user("hy", 10.0, 30, 1, "hy2", "", "", 0).unwrap();
        assert_eq!(u.service(), "vip");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn renewal_with_a_plan() {
        let (dir, db) = temp_db();
        // unlimited volume, limited plan: the plan's GB on top of what was used
        let u = db.create_user("a", 0.0, 30, 1, "wg", "", "", 0).unwrap();
        db.exec("UPDATE users SET used_bytes=?1 WHERE id=?2", &[&(50i64 * 1024 * 1024 * 1024), &u.id]).unwrap();
        db.renew_plan(u.id, 30, 20.0).unwrap();
        let v = db.user(u.id).unwrap();
        assert!((v.limit_gb - (v.used_gb() + 20.0)).abs() < 0.01 && !v.over_quota());
        // a plan with 0 GB and 0 days: unlimited volume and no end date
        db.renew_plan(u.id, 0, 0.0).unwrap();
        let v = db.user(u.id).unwrap();
        assert_eq!((v.limit_gb, v.expires_at), (0.0, 0));
        // extend keeps 0 as "add nothing"
        let w = db.create_user("b", 10.0, 30, 1, "wg", "", "", 0).unwrap();
        db.extend(w.id, 0, 5.0).unwrap();
        let x = db.user(w.id).unwrap();
        assert_eq!((x.limit_gb, x.expires_at), (15.0, w.expires_at));
        // huge numbers do not overflow into the past
        db.extend(w.id, i64::MAX, f64::INFINITY).unwrap();
        let x = db.user(w.id).unwrap();
        assert!(x.expires_at > now() && x.limit_gb == 15.0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn deleting_a_user_keeps_open_orders() {
        let (dir, db) = temp_db();
        let u = db.create_user("a", 1.0, 30, 1, "wg", "", "", 0).unwrap();
        for st in ["pending", "waiting", "error", "done", "rejected"] {
            db.exec("INSERT INTO orders(tg_id,plan_id,kind,target,status,created) VALUES(1,1,'renew',?1,?2,0)", &[&u.id, &st]).unwrap();
        }
        db.delete_user(u.id);
        let left: Vec<(String, i64)> = db.with(|c| {
            let mut s = c.prepare("SELECT status, target FROM orders ORDER BY id").unwrap();
            let v: Vec<(String, i64)> = s.query_map([], |r| Ok((r.get(0)?, r.get(1)?))).unwrap().flatten().collect();
            v
        });
        let want: Vec<(String, i64)> = ["pending", "waiting", "error", "done"].iter().map(|s| (s.to_string(), 0)).collect();
        assert_eq!(left, want);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn logs_are_trimmed_while_running() {
        let (dir, db) = temp_db();
        db.with(|c| {
            for _ in 0..(AUDIT_KEEP + 10) {
                c.execute("INSERT INTO audit(ts,actor,method,path,status,ip) VALUES(0,'a','POST','/x',200,'')", []).unwrap();
            }
        });
        // the trim runs on every 200th row (the counter is shared with other tests running at once)
        for _ in 0..100_000 {
            db.note_log_row();
            if db.count("SELECT COUNT(*) FROM audit") == AUDIT_KEEP {
                break;
            }
        }
        assert_eq!(db.count("SELECT COUNT(*) FROM audit"), AUDIT_KEEP);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn mixplus_is_cleaned_out() {
        let dir = std::env::temp_dir().join(format!("kanki-db-test-{}", crate::util::rand_token(8)));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("kanki.db");
        {
            let db = Db::open(path.to_str().unwrap());
            db.create_user("a", 1.0, 30, 1, "wg,kgame,mtun", "", "", 0).unwrap();
            db.create_user("b", 1.0, 30, 1, "kgame", "", "", 0).unwrap();
            db.create_user("c", 1.0, 30, 1, "awg,khq", "", "", 0).unwrap();
            db.set("default_protocols", "wg,awg,kgame");
            db.set("kgame_cfg", "{}");
            db.set("kc_door", "x");
        }
        // the cleanup runs when the database is opened again (on the next start)
        let db = Db::open(path.to_str().unwrap());
        let mut protos: Vec<(String, String)> = db.users().iter().map(|u| (u.username.clone(), u.protocols.clone())).collect();
        protos.sort();
        assert_eq!(protos, vec![("a".into(), "wg,mtun".into()), ("b".into(), "".into()), ("c".into(), "awg".into())]);
        assert_eq!(db.get("default_protocols"), "wg,awg");
        assert_eq!(db.get("kgame_cfg"), "");
        assert_eq!(db.get("kc_door"), "");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
