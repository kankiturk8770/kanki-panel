//! Database (SQLite)
use crate::util::now;
use rusqlite::{params, Connection, OptionalExtension, Row};
use serde::Serialize;
use std::sync::Mutex;

pub struct Db(pub Mutex<Connection>);

/// Serialises picking a free user number + inserting it.
static SLOT: Mutex<()> = Mutex::new(());

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

#[derive(Clone, Debug, Serialize)]
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

    /// Node is hidden from users / not synced while in maintenance
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
            CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, actor TEXT, method TEXT, path TEXT, status INTEGER, ip TEXT);",
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
            "ALTER TABLE discounts ADD COLUMN expires INTEGER DEFAULT 0",
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
        // keep logs bounded
        let _ = c.execute("DELETE FROM audit WHERE id NOT IN (SELECT id FROM audit ORDER BY id DESC LIMIT 5000)", []);
        let _ = c.execute("DELETE FROM login_log WHERE id NOT IN (SELECT id FROM login_log ORDER BY id DESC LIMIT 2000)", []);
        Db(Mutex::new(c))
    }

    pub fn with<T>(&self, f: impl FnOnce(&Connection) -> T) -> T {
        let c = self.0.lock().unwrap();
        f(&c)
    }

    // ---------------- تنظیمات
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

    /// Creates a user. An empty username (or "auto") gives USER<n>; "auto-test" gives USER<n>-TEST
    /// (a free trial). The user's id is always that same lowest free number.
    #[allow(clippy::too_many_arguments)]
    pub fn create_user(&self, username: &str, limit_gb: f64, days: i64, max_conn: i64, protocols: &str, nodes: &str, notes: &str, tg_id: i64) -> Result<User, String> {
        let code = crate::util::rand_digits(19);
        let exp = if days > 0 { now() + days * 86400 } else { 0 };
        let _g = SLOT.lock().unwrap_or_else(|e| e.into_inner());
        let n = self.next_slot();
        let name = match username.trim() {
            "" | "auto" => format!("USER{}", n),
            "auto-test" => format!("USER{}-TEST", n),
            x => x.to_string(),
        };
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

    /// A trial (USER<n>-TEST) that is bought / renewed becomes USER<n>.
    pub fn promote_trial(&self, id: i64) {
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
        let base = if u.expires_at > now() { u.expires_at } else { now() };
        let exp = if days > 0 { base + days * 86400 } else { u.expires_at };
        let lim = if add_gb > 0.0 {
            if u.over_quota() { u.used_gb() + add_gb } else { u.limit_gb + add_gb }
        } else {
            u.limit_gb
        };
        self.exec("UPDATE users SET expires_at=?1, limit_gb=?2, warned=0 WHERE id=?3", &[&exp, &lim, &id]).map(|_| ())
    }

    pub fn count(&self, sql: &str) -> i64 {
        self.with(|c| c.query_row(sql, [], |r| r.get::<_, i64>(0)).unwrap_or(0))
    }

    /// Removes a user completely: account, keys / peers and unpaid orders; paid orders keep their
    /// amount for the sales total but no longer point at the (now free) user number.
    pub fn delete_user(&self, id: i64) {
        let _ = self.exec("DELETE FROM users WHERE id=?1", &[&id]);
        let _ = self.exec("DELETE FROM peers WHERE user_id=?1", &[&id]);
        let _ = self.exec("DELETE FROM orders WHERE target=?1 AND status NOT IN ('done','approved')", &[&id]);
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
        let ip = format!("{}.{}.{}", base, (user_id / 250) % 250, user_id % 250 + 2);
        let _ = self.exec(
            "INSERT OR IGNORE INTO peers(user_id,node_id,proto,privkey,pubkey,psk,ip) VALUES(?1,?2,?3,?4,?5,?6,?7)",
            &[&user_id, &node, &proto, &privk, &pubk, &psk, &ip],
        );
        self.peer(user_id, node, proto)
    }
}

pub fn default_setting(k: &str) -> &'static str {
    match k {
        "dns" => "1.1.1.1, 8.8.8.8",
        "mtu" => "1380",
        "default_protocols" => "wg,awg,hy2",
        "panel_name" => "Kanki Panel",
        "lang" => "fa",
        "theme" => "dark",
        "color" => "gold",
        "refresh" => "10",
        "session_hours" => "24",
        "awg_compat" => "0",
        "tgb_hours" => "24",
        "sales_on" => "1",
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
