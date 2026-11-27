//! Backup & restore: encrypted archive (AES-256 + PBKDF2 via openssl) with the database,
//! server keys/configs and certificates; scheduled Telegram backups.
use crate::api::err;
use crate::guard;
use crate::util::{now, rand_token, stamp};
use crate::App;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Value};
use std::process::Command;
use std::sync::Arc;

type St = State<Arc<App>>;

/// Files that make a server reproducible (keys, configs). Missing ones are skipped.
const FILES: &[&str] = &[
    "/etc/kanki/kanki.env",
    "/etc/kanki/repo",
    "/etc/wireguard/wg0.conf",
    "/etc/amnezia/amneziawg/awg0.conf",
    "/etc/hysteria/config.yaml",
    "/etc/kanki/tls/fullchain.pem",
    "/etc/kanki/tls/privkey.pem",
];

/// Creates a directory only the owner can enter. Backups hold password hashes, API keys and the
/// private keys of the VPN servers, so nothing of them may sit in a folder others can list.
fn private_dir(path: &str) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(path).map_err(|e| e.to_string())?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())
}

/// 3.68: backup and restore work inside `<data>/tmp` (0700), never the shared /tmp
fn work_dir() -> String {
    let data = crate::util::load_env("/etc/kanki/kanki.env").get("DATA_DIR").cloned().unwrap_or_else(|| "/var/lib/kanki".into());
    let d = format!("{}/tmp", data);
    if let Err(e) = crate::util::private_dir(&d) {
        eprintln!("backup: {} could not be made ({}); using the system temp folder", d, e);
        return std::env::temp_dir().to_string_lossy().to_string();
    }
    d
}

/// A restored database waiting in the data folder for the next start
const PENDING: &str = "restore.db.pending";

/// At start, before the database is opened: a restored database waiting from the last run takes the
/// place of the old one (and the old one's write-ahead log goes with it).
pub fn take_pending(data: &str) {
    let p = format!("{}/{}", data, PENDING);
    let ok = std::fs::read(&p).map(|b| b.len() > 100 && &b[..15] == b"SQLite format 3").unwrap_or(false);
    if !ok {
        let _ = std::fs::remove_file(&p);
        return;
    }
    let _ = std::fs::remove_file(format!("{}/kanki.db-wal", data));
    let _ = std::fs::remove_file(format!("{}/kanki.db-shm", data));
    match std::fs::rename(&p, format!("{}/kanki.db", data)) {
        Ok(()) => eprintln!("the restored database is in place"),
        Err(e) => eprintln!("the restored database could not be put in place: {}", e),
    }
}

/// certbot's certificates of this server (Xray, Kanki DNS … on their own domains)
const LE_DIR: &str = "/etc/letsencrypt";
const LE_PARTS: &[&str] = &["archive", "live", "renewal", "accounts"];

/// The extra state of this server in a backup folder: certbot's certificates (`letsencrypt.tgz`, links
/// kept). The names of the items made, for tar.
fn extra_into(dir: &str) -> Vec<&'static str> {
    let mut items = vec![];
    let live = std::fs::read_dir(format!("{}/live", LE_DIR)).map(|r| r.flatten().any(|e| e.path().is_dir())).unwrap_or(false);
    if live {
        let parts: Vec<String> = LE_PARTS.iter().filter(|p| std::path::Path::new(&format!("{}/{}", LE_DIR, p)).is_dir()).map(|p| format!("letsencrypt/{}", p)).collect();
        let tgz = format!("{}/letsencrypt.tgz", dir);
        let mut args: Vec<&str> = vec!["-czf", &tgz, "-C", "/etc"];
        args.extend(parts.iter().map(|s| s.as_str()));
        if run("tar", &args, None).is_ok() {
            items.push("letsencrypt.tgz");
        }
    }
    items
}

/// Puts back what `extra_into` saved, from an unpacked backup in `x` (also `kanki-panel restore-files`,
/// which the installer runs on a new server). Only what this machine lacks: a certificate this machine
/// already has (made afresh for the same domain) is kept. Nothing is written outside /etc/letsencrypt, and
/// the certificate links must point into their own domain's archive. A chat database in an old backup
/// (the emergency chat, gone in 3.65) is left out.
pub fn restore_extra(x: &str) -> Vec<String> {
    restore_extra_to(x, LE_DIR)
}

fn restore_extra_to(x: &str, le_dir: &str) -> Vec<String> {
    let mut done = vec![];
    let tgz = format!("{}/letsencrypt.tgz", x);
    if std::fs::symlink_metadata(&tgz).map(|m| m.is_file()).unwrap_or(false) {
        match le_restore(&tgz, le_dir) {
            Ok(n) if n > 0 => done.push(format!("{} certificates", n)),
            Ok(_) => {}
            Err(e) => eprintln!("restore: certificates: {}", e),
        }
    }
    done
}

/// a file or folder name certbot makes (a domain, `cert1.pem`, an account id): no path tricks
fn le_name(s: &str) -> bool {
    !s.is_empty() && s != "." && s != ".." && s.len() <= 255 && s.bytes().all(|c| c.is_ascii_alphanumeric() || b"-_.@".contains(&c))
}

/// Copies the plain files of `src` into `dst`, folder by folder (no links), each name checked
fn copy_tree(src: &std::path::Path, dst: &std::path::Path, depth: usize) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for e in std::fs::read_dir(src)?.flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        let m = std::fs::symlink_metadata(e.path())?;
        if !le_name(&name) {
            continue;
        }
        if m.is_dir() && depth < 6 {
            copy_tree(&e.path(), &dst.join(&name), depth + 1)?;
        } else if m.is_file() {
            std::fs::copy(e.path(), dst.join(&name))?;
        }
    }
    Ok(())
}

/// certbot's folders from a backup: each domain this machine has no certificate for gets its archive,
/// its renewal file and its live links again (made here, each `../../archive/<domain>/<file>`), and the
/// account comes along when this machine has none. The number of domains put back.
fn le_restore(tgz: &str, le_dir: &str) -> Result<usize, String> {
    let tmp = format!("{}/kanki-le-{}", work_dir(), rand_token(12));
    private_dir(&tmp)?;
    let res = (|| -> Result<usize, String> {
        run("tar", &["-xzf", tgz, "-C", &tmp, "--no-same-owner"], None)?;
        let src = std::path::Path::new(&tmp).join("letsencrypt");
        let dst = std::path::Path::new(le_dir);
        let mut n = 0;
        let live = src.join("live");
        for e in std::fs::read_dir(&live).map_err(|e| e.to_string())?.flatten() {
            let d = e.file_name().to_string_lossy().to_string();
            if !le_name(&d) || !crate::certbot::valid_domain(&d) || !std::fs::symlink_metadata(e.path()).map(|m| m.is_dir()).unwrap_or(false) {
                continue;
            }
            if dst.join("live").join(&d).exists() {
                continue;
            }
            let arch = src.join("archive").join(&d);
            if !std::fs::symlink_metadata(&arch).map(|m| m.is_dir()).unwrap_or(false) {
                continue;
            }
            // each live link must name a file of this domain's own archive
            let mut links = vec![];
            for l in std::fs::read_dir(e.path()).map_err(|e| e.to_string())?.flatten() {
                let name = l.file_name().to_string_lossy().to_string();
                let Ok(t) = std::fs::read_link(l.path()) else { continue };
                let t = t.to_string_lossy().to_string();
                let Some(file) = t.strip_prefix(&format!("../../archive/{}/", d)) else { continue };
                if le_name(&name) && le_name(file) && std::fs::symlink_metadata(arch.join(file)).map(|m| m.is_file()).unwrap_or(false) {
                    links.push((name, t));
                }
            }
            if !links.iter().any(|l| l.0 == "fullchain.pem") || !links.iter().any(|l| l.0 == "privkey.pem") {
                continue;
            }
            copy_tree(&arch, &dst.join("archive").join(&d), 0).map_err(|e| e.to_string())?;
            let ld = dst.join("live").join(&d);
            std::fs::create_dir_all(&ld).map_err(|e| e.to_string())?;
            for (name, t) in links {
                let _ = std::os::unix::fs::symlink(&t, ld.join(&name));
            }
            let conf = src.join("renewal").join(format!("{}.conf", d));
            if std::fs::symlink_metadata(&conf).map(|m| m.is_file()).unwrap_or(false) {
                let _ = std::fs::create_dir_all(dst.join("renewal"));
                let _ = std::fs::copy(&conf, dst.join("renewal").join(format!("{}.conf", d)));
            }
            n += 1;
        }
        let acc = src.join("accounts");
        if n > 0 && acc.is_dir() && !dst.join("accounts").exists() {
            copy_tree(&acc, &dst.join("accounts"), 0).map_err(|e| e.to_string())?;
        }
        // the private keys stay readable by root only
        let _ = Command::new("chmod").args(["-R", "go-rwx", &format!("{}/archive", le_dir), &format!("{}/accounts", le_dir)]).output();
        Ok(n)
    })();
    let _ = std::fs::remove_dir_all(&tmp);
    res
}

/// A consistent copy of the database. 3.68: made only inside `<data>/tmp` (0700; never the shared /tmp), read,
/// then overwritten and removed at once.
pub fn db_snapshot(app: &App) -> Option<Vec<u8>> {
    let base = format!("{}/tmp", app.data_dir());
    if let Err(e) = crate::util::private_dir(&base) {
        eprintln!("backup: {} could not be made: {}", base, e);
        return None;
    }
    let dir = format!("{}/snap-{}", base, rand_token(12));
    if let Err(e) = crate::util::private_dir(&dir) {
        eprintln!("backup: {} could not be made: {}", dir, e);
        return None;
    }
    let path = format!("{}/snap.db", dir);
    // the path is made here from fixed parts and a random token (letters and digits): nothing to quote
    let ok = app.db.with(|c| c.execute(&format!("VACUUM INTO '{}'", path), [])).is_ok();
    // 3.68: the copy carries its secrets opened, so it restores on a server with another master key (the archive
    // has its own protection; the restored panel seals them again at its first start)
    let ok = ok && match crate::secrets::plain_copy(&path) {
        Ok(()) => true,
        Err(e) => {
            eprintln!("backup: the snapshot's secrets could not be opened: {}", e);
            false
        }
    };
    let b = if ok { std::fs::read(&path).ok() } else { None };
    if let Err(e) = crate::util::shred_remove(&path) {
        eprintln!("backup: the snapshot could not be wiped: {}", e);
    }
    if let Err(e) = std::fs::remove_dir_all(&dir) {
        eprintln!("backup: {} could not be removed: {}", dir, e);
    }
    b
}

fn run(cmd: &str, args: &[&str], pass: Option<&str>) -> Result<(), String> {
    let mut c = Command::new(cmd);
    c.args(args);
    if let Some(p) = pass {
        c.env("KANKI_BK_PASS", p);
    }
    let o = c.output().map_err(|e| format!("{}: {}", cmd, e))?;
    if o.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&o.stderr).trim().chars().take(300).collect())
    }
}

/// Returns (bytes, file name). Encrypted when a passphrase is given.
pub fn make_archive(app: &App, pass: &str) -> Result<(Vec<u8>, String), String> {
    make_archive_with(app, pass, false)
}

/// Plain files directly in `src` copied to `dst` (no links, no folders): the app files and the node
/// certificate pins are flat folders, and nothing else may come out of a backup.
fn copy_flat(src: &str, dst: &str) -> usize {
    let Ok(rd) = std::fs::read_dir(src) else { return 0 };
    let _ = std::fs::create_dir_all(dst);
    let mut n = 0;
    for e in rd.flatten() {
        let Ok(m) = std::fs::symlink_metadata(e.path()) else { continue };
        let name = e.file_name().to_string_lossy().to_string();
        if !m.is_file() || name.starts_with('.') || name.contains('/') {
            continue;
        }
        if std::fs::copy(e.path(), format!("{}/{}", dst, name)).is_ok() {
            n += 1;
        }
    }
    n
}

/// What a backup holds, written next to it (meta.json): the version, when, the domain and the public
/// IP of the server it was made on (a restore elsewhere replaces that IP), and counts to check it by.
fn meta(app: &App, apps: usize) -> Value {
    json!({
        "version": crate::VERSION, "ts": now(), "domain": app.env.get("DOMAIN").cloned().unwrap_or_default(),
        "ip": app.db.get("my_ip"),
        "users": app.db.count("SELECT COUNT(*) FROM users"),
        "nodes": app.db.count("SELECT COUNT(*) FROM nodes"),
        "servers": crate::tunnel::panel::servers(app).len(),
        "tunnels": crate::tunnel::panel::tunnels(app).len(),
        "apps": apps,
    })
}

/// `with_apps`: also the app install files uploaded in the panel (a download and a move take them;
/// the nightly Telegram backup does not, a bot cannot send files over 50 MB).
pub fn make_archive_with(app: &App, pass: &str, with_apps: bool) -> Result<(Vec<u8>, String), String> {
    let dir = format!("{}/kanki-bk-{}", work_dir(), rand_token(12));
    private_dir(&dir)?;
    std::fs::create_dir_all(format!("{}/files", dir)).map_err(|e| e.to_string())?;
    let res = (|| -> Result<(Vec<u8>, String), String> {
        let db = db_snapshot(app).ok_or("database snapshot failed")?;
        std::fs::write(format!("{}/kanki.db", dir), db).map_err(|e| e.to_string())?;
        for f in FILES {
            if std::path::Path::new(f).exists() {
                let dst = format!("{}/files{}", dir, f);
                if let Some(parent) = std::path::Path::new(&dst).parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                let _ = std::fs::copy(f, &dst);
            }
        }
        let data = app.data_dir();
        // the certificates of nodes with a self-signed one, as first seen: the new server keeps
        // trusting exactly those
        let pins = copy_flat(&format!("{}/nodepins", data), &format!("{}/nodepins", dir));
        let apps = if with_apps { copy_flat(&format!("{}/apps", data), &format!("{}/apps", dir)) } else { 0 };
        let extra = extra_into(&dir);
        std::fs::write(format!("{}/meta.json", dir), meta(app, apps).to_string()).map_err(|e| e.to_string())?;
        let tgz = format!("{}/out.tar.gz", dir);
        // a panel without a self-signed node has no nodepins folder, and tar fails on a missing item
        let mut items = vec!["kanki.db", "files", "meta.json"];
        if pins > 0 {
            items.push("nodepins");
        }
        if apps > 0 {
            items.push("apps");
        }
        items.extend(extra);
        let mut args = vec!["-czf", tgz.as_str(), "-C", dir.as_str()];
        args.extend(items);
        run("tar", &args, None)?;
        let name_base = format!("kanki-backup-{}", stamp(now()));
        if pass.is_empty() {
            return Ok((std::fs::read(&tgz).map_err(|e| e.to_string())?, format!("{}.tar.gz", name_base)));
        }
        let enc = format!("{}/out.kbk", dir);
        run("openssl", &["enc", "-aes-256-cbc", "-salt", "-pbkdf2", "-iter", "200000", "-in", &tgz, "-out", &enc, "-pass", "env:KANKI_BK_PASS"], Some(pass))?;
        Ok((std::fs::read(&enc).map_err(|e| e.to_string())?, format!("{}.kbk", name_base)))
    })();
    let _ = std::fs::remove_dir_all(&dir);
    res
}

/// What a restore did: a message, and the meta of the backup (Null for an old one)
pub struct Restored {
    pub message: String,
    pub meta: Value,
}

/// Accepts .kbk (encrypted), .tar.gz, or a raw SQLite file from older versions
pub fn restore(app: &App, data: &[u8], pass: &str, full: bool) -> Result<Restored, String> {
    let dir = format!("{}/kanki-rs-{}", work_dir(), rand_token(12));
    private_dir(&dir)?;
    std::fs::create_dir_all(format!("{}/x", dir)).map_err(|e| e.to_string())?;
    let res = (|| -> Result<Restored, String> {
        let dbfile: String;
        let mut meta = Value::Null;
        let mut extra: Vec<String> = vec![];
        if data.len() > 16 && &data[..15] == b"SQLite format 3" {
            dbfile = format!("{}/kanki.db", dir);
            std::fs::write(&dbfile, data).map_err(|e| e.to_string())?;
        } else {
            let tgz = format!("{}/in.tar.gz", dir);
            if data.len() > 8 && &data[..8] == b"Salted__" {
                if pass.is_empty() {
                    return Err("this backup is encrypted, enter the passphrase".to_string());
                }
                let enc = format!("{}/in.kbk", dir);
                std::fs::write(&enc, data).map_err(|e| e.to_string())?;
                run("openssl", &["enc", "-d", "-aes-256-cbc", "-pbkdf2", "-iter", "200000", "-in", &enc, "-out", &tgz, "-pass", "env:KANKI_BK_PASS"], Some(pass))
                    .map_err(|_| "wrong passphrase or damaged file".to_string())?;
            } else if data.len() > 2 && data[0] == 0x1f && data[1] == 0x8b {
                std::fs::write(&tgz, data).map_err(|e| e.to_string())?;
            } else {
                return Err("not a Kanki backup file".to_string());
            }
            let x = format!("{}/x", dir);
            run("tar", &["-xzf", &tgz, "-C", &x], None).map_err(|_| "archive is damaged".to_string())?;
            dbfile = format!("{}/kanki.db", x);
            meta = std::fs::read_to_string(format!("{}/meta.json", x)).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or(Value::Null);
            if full {
                // only the known server files, and only as plain files: a backup (or a file that was
                // passed off as one) must not be able to write anywhere else on this machine
                for f in FILES {
                    let src = format!("{}/files{}", x, f);
                    let is_plain = std::fs::symlink_metadata(&src).map(|m| m.is_file()).unwrap_or(false);
                    if !is_plain {
                        continue;
                    }
                    if let Some(parent) = std::path::Path::new(f).parent() {
                        let _ = std::fs::create_dir_all(parent);
                    }
                    // 3.68: secrets come back 0600 with the owner the file had (Hysteria's config stays the
                    // `hysteria` user's); the TLS files keep the mode they had (Caddy's group reads them)
                    let data = std::fs::read(&src).map_err(|e| format!("{}: {}", f, e))?;
                    let keep = {
                        use std::os::unix::fs::PermissionsExt;
                        std::fs::metadata(f).ok().map(|m| m.permissions().mode() & 0o7777)
                    };
                    crate::util::write_private_bytes(f, &data).map_err(|e| format!("{}: {}", f, e))?;
                    if *f == "/etc/hysteria/config.yaml" {
                        crate::util::service_readable(f, "hysteria").map_err(|e| format!("{}: {}", f, e))?;
                    } else if f.starts_with("/etc/kanki/tls/") || *f == "/etc/kanki/repo" {
                        let mode = keep.unwrap_or(if *f == "/etc/kanki/repo" { 0o644 } else { 0o640 });
                        crate::util::chmod_if_present(f, mode).map_err(|e| format!("{}: {}", f, e))?;
                    }
                }
                let ddir = app.data_dir();
                let pins = copy_flat(&format!("{}/nodepins", x), &format!("{}/nodepins", ddir));
                if pins > 0 {
                    extra.push(format!("{} node certificate pins", pins));
                }
                if std::path::Path::new(&format!("{}/apps", x)).is_dir() {
                    let n = copy_flat(&format!("{}/apps", x), &format!("{}/apps", ddir));
                    if n > 0 {
                        extra.push(format!("{} app files", n));
                    }
                }
                extra.extend(restore_extra(&x));
            }
        }
        let head = std::fs::read(&dbfile).map_err(|_| "database missing in backup".to_string())?;
        if head.len() < 100 || &head[..15] != b"SQLite format 3" {
            return Err("database in backup is invalid".to_string());
        }
        // the database must open and have the panel's tables (a damaged file must not replace a good one)
        {
            let c = rusqlite::Connection::open_with_flags(&dbfile, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).map_err(|_| "database in backup is invalid".to_string())?;
            let ok: Result<i64, _> = c.query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0));
            let ok2: Result<i64, _> = c.query_row("SELECT COUNT(*) FROM settings", [], |r| r.get(0));
            if ok.is_err() || ok2.is_err() {
                return Err("database in backup is damaged (no users / settings table)".to_string());
            }
        }
        let ddir = app.data_dir();
        let tmp = format!("{}/restore.db", ddir);
        std::fs::write(&tmp, &head).map_err(|e| e.to_string())?;
        // a backup taken by a move was made with the panel frozen: the restored panel must run
        if let Ok(c) = rusqlite::Connection::open(&tmp) {
            let _ = c.execute("DELETE FROM settings WHERE k IN ('mig_frozen','mig_token','mig_pass','mig_cmd','mig_exp')", []);
        }
        // put in place by the next start (`take_pending`), not now: this running panel still has the
        // old database open, and what it writes before it stops (its write-ahead log) must never land
        // on the restored one
        std::fs::rename(&tmp, format!("{}/{}", ddir, PENDING)).map_err(|e| e.to_string())?;
        let mut message = if full { "database + server files restored".to_string() } else { "database restored".to_string() };
        if !extra.is_empty() {
            message.push_str(&format!(" ({})", extra.join(", ")));
        }
        Ok(Restored { message, meta })
    })();
    let _ = std::fs::remove_dir_all(&dir);
    res
}

/// Marks in the restored settings file that this start follows a restore: from another server (its
/// IP is replaced in the panel's addresses, see `migrate::after_move`) or this one.
fn mark_restored(old_ip: &str) {
    let path = crate::ENV_PATH;
    let t = std::fs::read_to_string(path).unwrap_or_default();
    let mut lines: Vec<String> = t.lines().filter(|l| !l.starts_with("MOVED_FROM=") && !l.starts_with("RESTORED_AT=")).map(|l| l.to_string()).collect();
    if !old_ip.is_empty() {
        lines.push(format!("MOVED_FROM={}", old_ip));
    }
    lines.push(format!("RESTORED_AT={}", now()));
    let _ = std::fs::write(path, lines.join("\n") + "\n");
}

const CADDYFILE: &str = "/etc/caddy/Caddyfile";
const VPN_CONFS: &[&str] = &["/etc/wireguard/wg0.conf", "/etc/amnezia/amneziawg/awg0.conf"];

/// Every `reverse_proxy 127.0.0.1:<port>` of a Caddyfile sent to `port`.
fn set_proxy_port(cf: &str, port: &str) -> String {
    cf.lines().map(|l| {
        match l.find("reverse_proxy 127.0.0.1:") {
            Some(i) => {
                let head = &l[..i + "reverse_proxy 127.0.0.1:".len()];
                let rest = &l[head.len()..];
                let tail = rest.trim_start_matches(|c: char| c.is_ascii_digit());
                format!("{}{}{}", head, port, tail)
            }
            None => l.to_string(),
        }
    }).collect::<Vec<_>>().join("\n") + if cf.ends_with('\n') { "\n" } else { "" }
}

/// The network card in the NAT rules of a VPN config (`-o <card> -j MASQUERADE`) set to `eth`.
fn set_masq_iface(conf: &str, eth: &str) -> String {
    let mut out = String::new();
    let mut rest = conf;
    while let Some(i) = rest.find(" -o ") {
        let after = &rest[i + 4..];
        let end = after.find(' ').unwrap_or(after.len());
        if after[end..].starts_with(" -j MASQUERADE") {
            out.push_str(&rest[..i + 4]);
            out.push_str(eth);
            rest = &after[end..];
        } else {
            out.push_str(&rest[..i + 4]);
            rest = after;
        }
    }
    out.push_str(rest);
    out
}

/// The network card of the default route.
fn default_iface() -> String {
    for l in std::fs::read_to_string("/proc/net/route").unwrap_or_default().lines().skip(1) {
        let f: Vec<&str> = l.split_whitespace().collect();
        if f.len() > 1 && f[1] == "00000000" {
            return f[0].to_string();
        }
    }
    String::new()
}

/// After a full restore the server files are the old server's: Caddy still sends the panel's
/// requests to the port of the install made here (the panel page answered 502), and the VPN
/// configs name the old server's network card. Both are set to this server.
fn after_full_restore() {
    let env = crate::util::load_env(crate::ENV_PATH);
    if let Some(port) = env.get("PANEL_PORT").filter(|p| p.parse::<u16>().is_ok()) {
        if let Ok(cf) = std::fs::read_to_string(CADDYFILE) {
            let n = set_proxy_port(&cf, port);
            if n != cf {
                let _ = std::fs::write(CADDYFILE, n);
            }
        }
    }
    let eth = default_iface();
    if !eth.is_empty() {
        for c in VPN_CONFS {
            if let Ok(t) = std::fs::read_to_string(c) {
                let n = set_masq_iface(&t, &eth);
                if n != t {
                    let _ = std::fs::write(c, n);
                }
            }
        }
    }
}

/// The VPN services and Caddy restarted with the restored files (Hysteria2 stopped when the
/// restored settings have it off). Blocking.
fn restart_services() {
    let sc = |args: &[&str]| { let _ = Command::new("systemctl").args(args).output(); };
    if std::path::Path::new(VPN_CONFS[0]).exists() {
        sc(&["restart", "wg-quick@wg0"]);
    }
    if std::path::Path::new(VPN_CONFS[1]).exists() {
        sc(&["restart", "awg-quick@awg0"]);
    }
    let env = crate::util::load_env(crate::ENV_PATH);
    if env.get("HY2_PORT").map(|s| s.trim().is_empty()).unwrap_or(true) {
        sc(&["disable", "--now", "hysteria-server"]);
    } else {
        sc(&["restart", "hysteria-server"]);
    }
    if std::path::Path::new(CADDYFILE).exists() {
        sc(&["restart", "caddy"]);
    }
}

pub fn router() -> Router<Arc<App>> {
    Router::new()
        .route("/api/backup", get(backup_legacy).post(backup_download))
        // a backup file can be big; only a signed-in admin gets that far (see auth::middleware)
        .route("/api/restore", post(restore_upload).layer(DefaultBodyLimit::max(128 * 1024 * 1024)))
        .route("/api/restore/check", get(restore_check))
        .route("/api/tgbackup", get(tgb_get).put(tgb_put))
        .route("/api/tgbackup/test", post(tgb_test))
        .route("/api/tgbackup/send", post(tgb_send))
        .route("/api/db/clean", post(db_clean))
}

/// Keeps the database small and tidy: drops old login / audit rows, expired sessions and
/// abandoned unpaid orders, then compacts the file. Users, plans and paid orders are untouched.
pub fn clean_db(app: &App) -> Value {
    let t = now();
    let month = t - 30 * 86400;
    let week = t - 7 * 86400;
    let n = |sql: &str, p: i64| app.db.exec(sql, &[&p]).unwrap_or(0) as i64;
    let logins = n("DELETE FROM login_log WHERE ts<?1", month);
    let audit = n("DELETE FROM audit WHERE ts<?1", month);
    let sessions = n("DELETE FROM sessions WHERE expires<?1", t);
    let orders = n("DELETE FROM orders WHERE status IN ('pending','waiting','rejected','error','expired') AND created<?1", week);
    // free trials that are over (the bot removes them within a minute; this also covers a paused bot)
    let trials = app.db.finished_trials();
    for u in &trials {
        crate::api::delete_user(app, u.id);
    }
    // peers of users that no longer exist
    let peers = app.db.exec("DELETE FROM peers WHERE user_id NOT IN (SELECT id FROM users)", &[]).unwrap_or(0) as i64;
    let before = std::fs::metadata(db_path(app)).map(|m| m.len()).unwrap_or(0);
    let _ = app.db.with(|c| c.execute_batch("PRAGMA wal_checkpoint(TRUNCATE); VACUUM; PRAGMA optimize;"));
    let after = std::fs::metadata(db_path(app)).map(|m| m.len()).unwrap_or(0);
    app.db.set("db_cleaned", &t.to_string());
    json!({"trials": trials.len(), "logins": logins, "audit": audit, "sessions": sessions, "orders": orders, "peers": peers, "before": before, "after": after})
}

fn db_path(app: &App) -> String {
    format!("{}/kanki.db", app.env.get("DATA_DIR").cloned().unwrap_or_else(|| "/var/lib/kanki".into()))
}

async fn db_clean(State(app): St, h: HeaderMap) -> Response {
    if let Err(r) = crate::auth::check_session(&app, &h) { return r; } // 3.68: a login session only, never an API token
    // VACUUM can take seconds on a big database: not on an async worker
    let a = app.clone();
    let r = tokio::task::spawn_blocking(move || clean_db(&a)).await.unwrap_or_else(|_| json!({}));
    Json(json!({"ok": true, "result": r})).into_response()
}

/// The panel's own backup passphrase; made once (random) so nightly backups are never plain.
pub fn backup_pass(app: &App) -> String {
    let p = app.db.get("tgb_pass");
    if !p.is_empty() {
        return p;
    }
    let p = rand_token(20);
    app.db.set("tgb_pass", &p);
    p
}

fn file_response(bytes: Vec<u8>, name: &str) -> Response {
    (
        [(header::CONTENT_TYPE, "application/octet-stream".to_string()),
         (header::CONTENT_DISPOSITION, format!("attachment; filename=\"{}\"", name))],
        bytes,
    ).into_response()
}

/// Old API: plain SQLite file
async fn backup_legacy(State(app): St, h: HeaderMap) -> Response {
    if let Err(r) = crate::auth::check_session(&app, &h) { return r; } // 3.68: a login session only, never an API token
    let a = app.clone();
    match tokio::task::spawn_blocking(move || db_snapshot(&a)).await.ok().flatten() {
        Some(b) => file_response(b, &format!("kanki-backup-{}.db", stamp(now()))),
        None => err(StatusCode::INTERNAL_SERVER_ERROR, "backup failed"),
    }
}

async fn backup_download(State(app): St, h: HeaderMap, Json(b): Json<Value>) -> Response {
    if let Err(r) = crate::auth::check_session(&app, &h) { return r; } // 3.68: a login session only, never an API token
    // empty = the panel's own backup passphrase, so a download is never left unencrypted
    let mut pass = b["passphrase"].as_str().unwrap_or("").to_string();
    if pass.is_empty() {
        pass = backup_pass(&app);
    }
    if pass.len() < 6 {
        return err(StatusCode::BAD_REQUEST, "passphrase must be at least 6 characters");
    }
    // the app install files go in too, unless asked not to (they can be big)
    let apps = b["apps"].as_bool().unwrap_or(true);
    let a = app.clone();
    match tokio::task::spawn_blocking(move || make_archive_with(&a, &pass, apps)).await {
        Ok(Ok((bytes, name))) => file_response(bytes, &name),
        Ok(Err(e)) => err(StatusCode::INTERNAL_SERVER_ERROR, &e),
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "backup failed"),
    }
}

async fn restore_upload(State(app): St, h: HeaderMap, body: Bytes) -> Response {
    if let Err(r) = crate::auth::check_session(&app, &h) {
        return r;
    }
    let mut pass = h.get("x-passphrase").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    if pass.is_empty() {
        pass = backup_pass(&app);
    }
    let full = h.get("x-full").and_then(|v| v.to_str().ok()) == Some("1");
    let a = app.clone();
    let data = body.to_vec();
    let here = app.db.get("my_ip");
    match tokio::task::spawn_blocking(move || restore(&a, &data, &pass, full)).await {
        Ok(Ok(r)) => {
            if full {
                // the old server's files are in place now: set them to this server, then restart
                let old = r.meta["ip"].as_str().unwrap_or("").to_string();
                // made on another server (this one's IP is unknown when it could not look it up: the
                // backup's IP is taken as the old server's; on the same server that only empties
                // addresses that are found again by themselves)
                let moved = if !old.is_empty() && old != here { old } else { String::new() };
                mark_restored(&moved);
                after_full_restore();
                tokio::spawn(async {
                    tokio::time::sleep(std::time::Duration::from_millis(700)).await;
                    let _ = tokio::task::spawn_blocking(restart_services).await;
                    std::process::exit(0)
                });
            } else {
                crate::admin::restart_self();
            }
            Json(json!({"ok": true, "message": r.message, "meta": r.meta})).into_response()
        }
        Ok(Err(e)) => err(StatusCode::BAD_REQUEST, &e),
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "restore failed"),
    }
}

/// After a restore: whether every server and service came back (the Backup page shows it)
async fn restore_check(State(app): St, h: HeaderMap) -> Response {
    let _ = guard!(app, h, "backup");
    let list = crate::servers::list_json(&app);
    let mut servers = vec![];
    for s in list["servers"].as_array().into_iter().flatten() {
        let agent = &s["agent"];
        let node = &s["node"];
        servers.push(json!({
            "name": s["name"], "local": s["local"],
            "agent": if agent.is_null() { Value::Null } else { agent["online"].clone() },
            "vpn": if node.is_null() { Value::Null } else { node["online"].clone() },
            "vpn_on": node["enabled"].clone(),
        }));
    }
    let services = crate::admin::service_states();
    Json(json!({
        "restored_at": app.db.get("restored_at").parse::<i64>().unwrap_or(0),
        "moved_from": app.env.get("MOVED_FROM").cloned().unwrap_or_default(),
        "servers": servers, "services": services,
        "sub_domain": app.db.get("sub_domain"),
        // the old server's panel still runs the same bot (both answer customers, both post)
        "bot_conflict": now() - app.db.get("bot_conflict").parse::<i64>().unwrap_or(0) < 300,
    }))
    .into_response()
}

// ---------------------------------------------------------------- Telegram auto backup
fn tgb_token(app: &App) -> String {
    let t = app.db.get("tgb_token");
    if t.is_empty() { crate::bot::bot_token(app) } else { t }
}

async fn tgb_get(State(app): St, h: HeaderMap) -> Response {
    let _ = guard!(app, h, "backup");
    let t = app.db.get("tgb_token");
    Json(json!({
        "on": app.db.on("tgb_on"), "token_set": !t.is_empty(), "uses_bot_token": t.is_empty() && !crate::bot::bot_token(&app).is_empty(),
        "chat": app.db.get("tgb_chat"), "hours": app.db.get("tgb_hours"), "pass_set": true, "pass": backup_pass(&app),
        "mode": if app.db.get("tgb_mode") == "hours" { "hours" } else { "nightly" }, "at": tgb_at(&app),
        "cleaned": app.db.get("db_cleaned").parse::<i64>().unwrap_or(0),
        "db_size": std::fs::metadata(db_path(&app)).map(|m| m.len()).unwrap_or(0),
        "last": app.db.get("tgb_last").parse::<i64>().unwrap_or(0), "status": app.db.get("tgb_status"),
    })).into_response()
}

async fn tgb_put(State(app): St, h: HeaderMap, Json(b): Json<Value>) -> Response {
    let _ = guard!(app, h, "backup");
    if let Some(t) = b["token"].as_str().map(|s| s.trim()).filter(|s| !s.is_empty()) {
        app.db.set("tgb_token", t);
    }
    if let Some(c) = b["chat"].as_str() {
        app.db.set("tgb_chat", c.trim());
    }
    if let Some(hh) = b["hours"].as_i64().or_else(|| b["hours"].as_str().and_then(|s| s.parse().ok())) {
        app.db.set("tgb_hours", &hh.clamp(1, 24 * 30).to_string());
    }
    if let Some(p) = b["pass"].as_str().filter(|s| !s.is_empty()) {
        if p.len() < 6 {
            return err(StatusCode::BAD_REQUEST, "passphrase must be at least 6 characters");
        }
        app.db.set("tgb_pass", p);
    }
    if let Some(on) = b["on"].as_bool() {
        app.db.set("tgb_on", if on { "1" } else { "0" });
    }
    if let Some(m) = b["mode"].as_str() {
        app.db.set("tgb_mode", if m == "hours" { "hours" } else { "nightly" });
    }
    if let Some(at) = b["at"].as_str() {
        let ok = at.split_once(':').and_then(|(h, m)| Some((h.trim().parse::<u32>().ok()?, m.trim().parse::<u32>().ok()?))).filter(|(h, m)| *h < 24 && *m < 60);
        match ok {
            Some((h, m)) => app.db.set("tgb_at", &format!("{:02}:{:02}", h, m)),
            None => return err(StatusCode::BAD_REQUEST, "time must look like 03:00"),
        }
    }
    Json(json!({"ok": true})).into_response()
}

async fn tg_call(app: &App, token: &str, method: &str, body: Value) -> Option<Value> {
    let r = app.http.post(format!("https://api.telegram.org/bot{}/{}", token, method)).json(&body).send().await.ok()?;
    let v: Value = r.json().await.ok()?;
    if v["ok"].as_bool() == Some(true) { Some(v["result"].clone()) } else { None }
}

/// The newest private chat with one of the bot admins among the bot's updates. Anyone can write to
/// the bot, so a group or a stranger's chat is never taken (backups and alerts would go there).
fn admin_chat(ups: &[Value], admins: &str) -> Option<String> {
    let admins: Vec<&str> = admins.split(',').map(|x| x.trim()).filter(|x| !x.is_empty()).collect();
    ups.iter().rev().find_map(|u| {
        let c = &u["message"]["chat"];
        let id = c["id"].as_i64()?.to_string();
        let from = u["message"]["from"]["id"].as_i64()?.to_string();
        (c["type"].as_str() == Some("private") && from == id && admins.contains(&id.as_str())).then_some(id)
    })
}

async fn tgb_test(State(app): St, h: HeaderMap) -> Response {
    let _ = guard!(app, h, "backup");
    let token = tgb_token(&app);
    if token.is_empty() {
        return err(StatusCode::BAD_REQUEST, "set a bot token first");
    }
    let Some(me) = tg_call(&app, &token, "getMe", json!({})).await else {
        return err(StatusCode::BAD_GATEWAY, "token invalid or Telegram unreachable");
    };
    let mut chat = app.db.get("tgb_chat");
    if chat.is_empty() {
        // the sales bot long-polls its own token, so only probe updates on a dedicated token
        if !app.db.get("tgb_token").is_empty() && app.db.get("tgb_token") != crate::bot::bot_token(&app) {
            if let Some(Value::Array(ups)) = tg_call(&app, &token, "getUpdates", json!({"limit": 50})).await {
                if let Some(id) = admin_chat(&ups, &crate::bot::bot_admins_raw(&app)) {
                    chat = id;
                }
            }
        }
        if chat.is_empty() {
            chat = crate::bot::bot_admins_raw(&app).split(',').next().unwrap_or("").trim().to_string();
        }
        if chat.is_empty() {
            return err(StatusCode::BAD_REQUEST, "send /start to the bot from a bot admin's account first, or fill Chat ID");
        }
        app.db.set("tgb_chat", &chat);
    }
    let sent = tg_call(&app, &token, "sendMessage", json!({"chat_id": chat, "text": "✅ Kanki Panel backup channel connected"})).await;
    Json(json!({"ok": sent.is_some(), "bot": me["username"], "chat": chat})).into_response()
}

/// A text to the admin on the backup bot's chat (nothing when no bot or chat is set)
pub async fn tell_admin(app: &App, text: &str) {
    // the report bot, when there is one, gets every report of the panel (never the sales bot)
    if crate::monitor::on() {
        return crate::monitor::notify(text, None).await;
    }
    let token = tgb_token(app);
    let chat = app.db.get("tgb_chat");
    if !token.is_empty() && !chat.is_empty() {
        let _ = tg_call(app, &token, "sendMessage", json!({"chat_id": chat, "text": text})).await;
    }
}

pub async fn send_backup(app: &App) -> Result<(), String> {
    let token = tgb_token(app);
    let chat = app.db.get("tgb_chat");
    if token.is_empty() || chat.is_empty() {
        return Err("token / chat id missing".into());
    }
    // tidy first so every nightly backup is a clean database
    let pass = backup_pass(app);
    // VACUUM, tar and openssl take seconds: the worker thread steps aside so other requests go on meanwhile
    let (c, archive) = tokio::task::block_in_place(|| (clean_db(app), make_archive(app, &pass)));
    let (bytes, name) = archive?;
    let users = app.db.count("SELECT COUNT(*) FROM users");
    let caption = format!(
        "💾 {} · بکاپ پنل\n🕒 {}\n👤 {} کاربر · 🗄 {} KB\n🔐 رمزنگاری‌شده (رمز بکاپ در پنل > بکاپ)",
        app.db.get("panel_name"), crate::util::iso(now()), users, c["after"].as_u64().unwrap_or(0) / 1024
    );
    let part = reqwest::multipart::Part::bytes(bytes).file_name(name);
    let form = reqwest::multipart::Form::new().text("chat_id", chat).text("caption", caption).part("document", part);
    let r = app.http.post(format!("https://api.telegram.org/bot{}/sendDocument", token)).multipart(form)
        .timeout(std::time::Duration::from_secs(180)).send().await.map_err(|e| e.without_url().to_string())?;
    // without the address: it holds the bot token
    let v: Value = r.json().await.map_err(|e| e.without_url().to_string())?;
    if v["ok"].as_bool() == Some(true) {
        Ok(())
    } else {
        Err(v["description"].as_str().unwrap_or("telegram error").to_string())
    }
}

async fn tgb_send(State(app): St, h: HeaderMap) -> Response {
    let _ = guard!(app, h, "backup");
    let r = send_backup(&app).await;
    record(&app, &r);
    match r {
        Ok(_) => Json(json!({"ok": true})).into_response(),
        Err(e) => err(StatusCode::BAD_GATEWAY, &e),
    }
}

fn record(app: &App, r: &Result<(), String>) {
    app.db.set("tgb_last", &now().to_string());
    app.db.set("tgb_status", &match r { Ok(_) => "ok".to_string(), Err(e) => format!("error: {}", e) });
}

fn tgb_at(app: &App) -> String {
    let a = app.db.get("tgb_at");
    if a.is_empty() { "03:00".into() } else { a }
}

/// Iran time (UTC+3:30, no daylight saving) — "nightly" means the admin's night.
const TZ_OFFSET: i64 = 12600;

pub async fn telegram_loop(app: Arc<App>) {
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        if crate::migrate::frozen() || !app.db.on("tgb_on") {
            continue;
        }
        let t = now();
        if app.db.get("tgb_mode") == "hours" {
            let hours: i64 = app.db.get("tgb_hours").parse::<i64>().unwrap_or(24).max(1);
            let last: i64 = app.db.get("tgb_last").parse().unwrap_or(0);
            if t - last < hours * 3600 {
                continue;
            }
        } else {
            // once a day, at the chosen time
            let local = t + TZ_OFFSET;
            let day = local / 86400;
            let minute = (local % 86400) / 60;
            let (h, m) = tgb_at(&app).split_once(':').map(|(h, m)| (h.parse::<i64>().unwrap_or(3), m.parse::<i64>().unwrap_or(0))).unwrap_or((3, 0));
            let done: i64 = app.db.get("tgb_day").parse().unwrap_or(-1);
            if done == day || minute < h * 60 + m {
                continue;
            }
            app.db.set("tgb_day", &day.to_string());
        }
        let r = send_backup(&app).await;
        record(&app, &r);
        if let Err(e) = &r {
            // a failed nightly backup was only written on the Backup page; tell the admin too
            tell_admin(&app, &format!("⚠️ {} · بکاپ پنل ساخته نشد\n{}", app.db.get("panel_name"), e)).await;
        }
    }
}

#[cfg(test)]
mod archive_tests {
    use crate::App;
    use std::collections::HashMap;
    use std::sync::{atomic::AtomicI64, Arc, Mutex};

    #[test]
    fn a_panel_without_nodepins_still_backs_up() {
        let dir = std::env::temp_dir().join(format!("kanki-bk-test-{}", crate::util::rand_token(8)));
        std::fs::create_dir_all(&dir).unwrap();
        let db = crate::db::Db::open(dir.join("kanki.db").to_str().unwrap());
        let app = Arc::new(App {
            db,
            env: HashMap::from([("DATA_DIR".to_string(), dir.to_string_lossy().to_string())]),
            hy2_allowed: Mutex::new(HashMap::new()), limits: Mutex::new(HashMap::new()), reported: Mutex::new(HashMap::new()),
            login_fails: Mutex::new(HashMap::new()), sync_lock: tokio::sync::Mutex::new(()), bot_alive: AtomicI64::new(0),
            http: reqwest::Client::new(), http_insecure: reqwest::Client::new(), pin_clients: Mutex::new(HashMap::new()),
        });
        assert!(!dir.join("nodepins").exists());
        let (bytes, name) = super::make_archive(&app, "").expect("backup without nodepins");
        assert!(name.ends_with(".tar.gz") && !bytes.is_empty());
        // with a pin it is taken along
        std::fs::create_dir_all(dir.join("nodepins")).unwrap();
        std::fs::write(dir.join("nodepins/a.pin"), "x").unwrap();
        assert!(super::make_archive(&app, "").is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod restore_tests {
    #[test]
    fn caddy_is_sent_to_the_restored_port() {
        let cf = "{\n  auto_https off\n}\nhttps://a.b:2053 {\n  reverse_proxy 127.0.0.1:20973\n}\nsub.b:2053 {\n  reverse_proxy 127.0.0.1:20973 {\n  }\n}\n";
        let n = super::set_proxy_port(cf, "29332");
        assert!(!n.contains("20973"));
        assert_eq!(n.matches("reverse_proxy 127.0.0.1:29332").count(), 2);
        assert!(n.ends_with("}\n") && n.contains("reverse_proxy 127.0.0.1:29332 {"));
    }
    #[test]
    fn the_nat_rule_names_this_servers_card() {
        let c = "PostUp = iptables -t nat -A POSTROUTING -s 10.66.0.0/16 -o ens18 -j MASQUERADE; iptables -A FORWARD -i wg0 -o ens18 -j ACCEPT\nPostDown = iptables -t nat -D POSTROUTING -s 10.66.0.0/16 -o ens18 -j MASQUERADE\n";
        let n = super::set_masq_iface(c, "eth0");
        assert_eq!(n.matches("-o eth0 -j MASQUERADE").count(), 2);
        // only the NAT rules: a FORWARD rule with -o is left as it was
        assert!(n.contains("-o ens18 -j ACCEPT"));
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    #[test]
    fn test_takes_only_an_admin_private_chat() {
        let ups = vec![
            json!({"message": {"chat": {"id": 111, "type": "private"}, "from": {"id": 111}}}),
            json!({"message": {"chat": {"id": -500, "type": "group"}, "from": {"id": 111}}}),
            json!({"message": {"chat": {"id": 999, "type": "private"}, "from": {"id": 999}}}),
        ];
        // the newest chat is a stranger's, before it a group: the admin's own private chat is taken
        assert_eq!(super::admin_chat(&ups, "111, 222").as_deref(), Some("111"));
        assert_eq!(super::admin_chat(&ups, "222"), None);
        assert_eq!(super::admin_chat(&ups, ""), None);
    }

    fn tmpdir(tag: &str) -> String {
        let d = std::env::temp_dir().join(format!("kanki-bk-test-{}-{}", tag, crate::util::rand_token(8)));
        std::fs::create_dir_all(&d).unwrap();
        d.to_string_lossy().to_string()
    }

    /// certbot's folders of a domain as certbot makes them, under `root/letsencrypt`
    fn le_tree(root: &str, d: &str, link: &str) {
        let le = format!("{}/letsencrypt", root);
        std::fs::create_dir_all(format!("{}/archive/{}", le, d)).unwrap();
        std::fs::create_dir_all(format!("{}/live/{}", le, d)).unwrap();
        std::fs::create_dir_all(format!("{}/renewal", le)).unwrap();
        std::fs::create_dir_all(format!("{}/accounts/acme/x", le)).unwrap();
        for n in ["cert", "chain", "fullchain", "privkey"] {
            std::fs::write(format!("{}/archive/{}/{}1.pem", le, d, n), format!("{} {}", d, n)).unwrap();
            let target = if n == "privkey" { link.to_string() } else { format!("../../archive/{}/{}1.pem", d, n) };
            std::os::unix::fs::symlink(target, format!("{}/live/{}/{}.pem", le, d, n)).unwrap();
        }
        std::fs::write(format!("{}/renewal/{}.conf", le, d), "version = 2").unwrap();
        std::fs::write(format!("{}/accounts/acme/x/private_key.json", le), "{}").unwrap();
    }

    #[test]
    fn certificates_come_back_and_bad_links_do_not() {
        let src = tmpdir("le-src");
        le_tree(&src, "xr.example.com", "../../archive/xr.example.com/privkey1.pem");
        // a link that leaves its own archive: that domain is left out
        le_tree(&src, "evil.example.com", "/etc/shadow");
        le_tree(&src, "bad.example.com", "../../archive/xr.example.com/privkey1.pem");
        let tgz = format!("{}/le.tgz", src);
        super::run("tar", &["-czf", &tgz, "-C", &src, "letsencrypt"], None).unwrap();
        let dst = tmpdir("le-dst");
        // a certificate this machine already has stays as it is
        std::fs::create_dir_all(format!("{}/live/keep.example.com", dst)).unwrap();
        le_tree(&src, "keep.example.com", "../../archive/keep.example.com/privkey1.pem");
        super::run("tar", &["-czf", &tgz, "-C", &src, "letsencrypt"], None).unwrap();
        assert_eq!(super::le_restore(&tgz, &dst).unwrap(), 1);
        let key = std::fs::read_to_string(format!("{}/live/xr.example.com/privkey.pem", dst)).unwrap();
        assert_eq!(key, "xr.example.com privkey");
        assert_eq!(std::fs::read_link(format!("{}/live/xr.example.com/fullchain.pem", dst)).unwrap().to_string_lossy(), "../../archive/xr.example.com/fullchain1.pem");
        assert!(std::path::Path::new(&format!("{}/renewal/xr.example.com.conf", dst)).exists());
        assert!(std::path::Path::new(&format!("{}/accounts/acme/x/private_key.json", dst)).exists());
        for d in ["evil.example.com", "bad.example.com"] {
            assert!(!std::path::Path::new(&format!("{}/live/{}", dst, d)).exists(), "{}", d);
        }
        assert!(std::fs::read_dir(format!("{}/live/keep.example.com", dst)).unwrap().next().is_none());
        let _ = std::fs::remove_dir_all(&src);
        let _ = std::fs::remove_dir_all(&dst);
    }

    #[test]
    fn a_chat_database_in_an_old_backup_is_left_out() {
        let x = tmpdir("chat-x");
        std::fs::create_dir_all(format!("{}/emergency", x)).unwrap();
        let c = rusqlite::Connection::open(format!("{}/emergency/chat.db", x)).unwrap();
        c.execute_batch("CREATE TABLE m(t TEXT); INSERT INTO m VALUES('from the backup');").unwrap();
        drop(c);
        let here = tmpdir("chat-here");
        let le = format!("{}/le", here);
        assert!(super::restore_extra_to(&x, &le).is_empty());
        assert!(!std::path::Path::new(&format!("{}/emergency", here)).exists());
        let _ = std::fs::remove_dir_all(&x);
        let _ = std::fs::remove_dir_all(&here);
    }

    #[test]
    fn a_restored_database_waits_for_the_next_start() {
        let d = tmpdir("pending");
        let c = rusqlite::Connection::open(format!("{}/kanki.db", d)).unwrap();
        c.execute_batch("CREATE TABLE t(v TEXT); INSERT INTO t VALUES('old');").unwrap();
        drop(c);
        std::fs::write(format!("{}/kanki.db-wal", d), "a log of the old database").unwrap();
        let n = rusqlite::Connection::open(format!("{}/{}", d, super::PENDING)).unwrap();
        n.execute_batch("PRAGMA journal_mode=DELETE; CREATE TABLE t(v TEXT); INSERT INTO t VALUES('restored');").unwrap();
        drop(n);
        super::take_pending(&d);
        assert!(!std::path::Path::new(&format!("{}/{}", d, super::PENDING)).exists());
        assert!(!std::path::Path::new(&format!("{}/kanki.db-wal", d)).exists());
        let v: String = rusqlite::Connection::open(format!("{}/kanki.db", d)).unwrap().query_row("SELECT v FROM t", [], |r| r.get(0)).unwrap();
        assert_eq!(v, "restored");
        // a broken file waiting there is thrown away, the database stays
        std::fs::write(format!("{}/{}", d, super::PENDING), "junk").unwrap();
        super::take_pending(&d);
        let v: String = rusqlite::Connection::open(format!("{}/kanki.db", d)).unwrap().query_row("SELECT v FROM t", [], |r| r.get(0)).unwrap();
        assert_eq!(v, "restored");
        let _ = std::fs::remove_dir_all(&d);
    }
}
