//! پایگاه داده (SQLite)
use crate::util::now;
use rusqlite::{params, Connection, OptionalExtension, Row};
use serde::Serialize;
use std::sync::Mutex;

pub struct Db(pub Mutex<Connection>);

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
        format!("bub-{}-{}", self.id, self.code)
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

    pub fn on_node(&self, node: &str) -> bool {
        self.nodes.trim().is_empty() || self.nodes.split(',').any(|x| x.trim() == node)
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
        })
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
const NODE_COLS: &str = "id,name,address,endpoint,token,enabled,online,last_sync,info";

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
            CREATE TABLE IF NOT EXISTS discounts(code TEXT PRIMARY KEY, percent INTEGER, uses_left INTEGER);",
        )
        .expect("schema");
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

    #[allow(clippy::too_many_arguments)]
    pub fn create_user(&self, username: &str, limit_gb: f64, days: i64, max_conn: i64, protocols: &str, nodes: &str, notes: &str, tg_id: i64) -> Result<User, String> {
        let code = crate::util::rand_digits(19);
        let exp = if days > 0 { now() + days * 86400 } else { 0 };
        let id = self.with(|c| {
            c.execute(
                "INSERT INTO users(username,code,limit_gb,expires_at,max_conn,protocols,nodes,notes,tg_id,created_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
                params![username, code, limit_gb, exp, max_conn, protocols, nodes, notes, tg_id, now()],
            )
            .map(|_| c.last_insert_rowid())
            .map_err(|e| e.to_string())
        })?;
        self.user(id).ok_or_else(|| "not found".into())
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

    pub fn delete_user(&self, id: i64) {
        let _ = self.exec("DELETE FROM users WHERE id=?1", &[&id]);
        let _ = self.exec("DELETE FROM peers WHERE user_id=?1", &[&id]);
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
        _ => "",
    }
}
