//! One process per job on a machine.
//!
//! Every long-running job (`serve` = the panel, `tunnel-agent`, `tunnel-run <file>`) holds an
//! exclusive `flock` on `/run/kanki/<name>.lock` for as long as it lives. The kernel drops the lock
//! the moment the process dies (crash, kill -9, restart), so a lock can never go stale.
//!
//! The lock does two things:
//! * a second copy of the same job waits instead of running tunnels next to the first one. Two
//!   copies each tearing down the other's AmneziaWG interfaces was the "tunnel up, gone, up again
//!   every few seconds" bug (two different PIDs in the log);
//! * other jobs on the same machine can ask "is `<name>` running?" ([`alive`]) and leave its
//!   interfaces alone while it is.

use std::fs::{File, OpenOptions, TryLockError};
use std::io::{Seek, SeekFrom, Write};
use std::time::Duration;

/// Where the lock files live. `/run` is cleared at boot, which is fine: a lock only means something
/// while its process runs. The second place is for machines where `/run` cannot be written.
const DIRS: [&str; 2] = ["/run/kanki", "/var/lib/kanki/run"];

/// The lock of this process. Keep it alive for as long as the job runs (dropping it frees the lock).
pub struct Held {
    _file: File,
}

pub enum Try {
    Got(Held),
    /// another process holds it: who it is ("pid 499002, kanki-tunnel.service")
    Busy(String),
    /// the lock file cannot be made here (read-only system, no permission): run without one
    Unavailable(String),
}

fn clean(name: &str) -> String {
    name.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' }).collect()
}

fn path_in(dir: &str, name: &str) -> String {
    format!("{}/{}.lock", dir, clean(name))
}

/// "pid 499002, kanki-tunnel.service" (or just "pid 499002" when the unit is unknown)
fn describe(pid: &str) -> String {
    let pid = pid.trim();
    if pid.is_empty() {
        return "pid unknown".into();
    }
    let unit = std::fs::read_to_string(format!("/proc/{}/cgroup", pid))
        .ok()
        .and_then(|t| t.lines().filter_map(|l| l.rsplit('/').next()).find(|u| u.ends_with(".service")).map(|u| u.to_string()));
    match unit {
        Some(u) => format!("pid {}, {}", pid, u),
        None => format!("pid {}", pid),
    }
}

/// Tries once to take the lock `name` in `dir`.
fn try_in(dir: &str, name: &str) -> Try {
    if let Err(e) = std::fs::create_dir_all(dir) {
        return Try::Unavailable(format!("{}: {}", dir, e));
    }
    let path = path_in(dir, name);
    let mut f = match OpenOptions::new().read(true).write(true).create(true).truncate(false).open(&path) {
        Ok(f) => f,
        Err(e) => return Try::Unavailable(format!("{}: {}", path, e)),
    };
    match f.try_lock() {
        Ok(()) => {
            // the pid inside is only for the message other copies print
            let _ = f.set_len(0);
            let _ = f.seek(SeekFrom::Start(0));
            let _ = writeln!(f, "{}", std::process::id());
            Try::Got(Held { _file: f })
        }
        Err(TryLockError::WouldBlock) => Try::Busy(describe(&std::fs::read_to_string(&path).unwrap_or_default())),
        Err(TryLockError::Error(e)) => Try::Unavailable(format!("{}: {}", path, e)),
    }
}

/// Takes the lock `name` in the first place that works.
pub fn try_acquire(name: &str) -> Try {
    try_acquire_in(&DIRS, name)
}

fn try_acquire_in(dirs: &[&str], name: &str) -> Try {
    let mut why = String::new();
    for d in dirs {
        // a copy that holds the lock in the other place counts too: never run beside it
        for other in dirs.iter().filter(|o| *o != d) {
            if held_in(other, name) == Some(true) {
                return Try::Busy(describe(&std::fs::read_to_string(path_in(other, name)).unwrap_or_default()));
            }
        }
        match try_in(d, name) {
            Try::Unavailable(e) => why = e,
            other => return other,
        }
    }
    Try::Unavailable(why)
}

/// Takes the lock `name`, waiting as long as another copy of this job runs. While it waits this
/// process does nothing at all (no tunnels, no interfaces), so it cannot fight the running copy.
/// When no lock can be made on this machine it carries on without one (returns `None`).
pub async fn hold_or_wait(name: &str, what: &str) -> Option<Held> {
    let mut waited = 0u64;
    loop {
        match try_acquire(name) {
            Try::Got(h) => {
                if waited > 0 {
                    eprintln!("the other copy of the {} stopped: this one takes over now", what);
                }
                return Some(h);
            }
            Try::Unavailable(e) => {
                eprintln!("note: cannot make the single-instance lock ({}); running without it", e);
                return None;
            }
            Try::Busy(who) => {
                if waited % 60 == 0 {
                    eprintln!(
                        "another kanki-panel {} is already running on this server ({}). This copy waits and touches \
                         nothing until that one stops. Two copies would tear down each other's tunnels. \
                         See what runs: systemctl list-units 'kanki*' ; ps aux | grep kanki-panel",
                        what, who
                    );
                }
                tokio::time::sleep(Duration::from_secs(5)).await;
                waited += 5;
            }
        }
    }
}

/// Is somebody holding the lock `name` in `dir`? `None` = cannot tell (the file exists but cannot be
/// opened), which callers must treat as "running": never tear down what we cannot check.
fn held_in(dir: &str, name: &str) -> Option<bool> {
    let path = path_in(dir, name);
    if !std::path::Path::new(&path).exists() {
        return Some(false);
    }
    // read-only, never created or truncated here: only a quick look
    let f = match File::open(&path) {
        Ok(f) => f,
        Err(_) => return None,
    };
    match f.try_lock() {
        Ok(()) => {
            let _ = f.unlock();
            Some(false)
        }
        Err(TryLockError::WouldBlock) => Some(true),
        Err(TryLockError::Error(_)) => None,
    }
}

/// Is the job `name` running on this machine right now? `Some(false)` only when that is certain.
pub fn alive(name: &str) -> Option<bool> {
    alive_in(&DIRS, name)
}

fn alive_in(dirs: &[&str], name: &str) -> Option<bool> {
    let mut unknown = false;
    for d in dirs {
        match held_in(d, name) {
            Some(true) => return Some(true),
            None => unknown = true,
            Some(false) => {}
        }
    }
    if unknown { None } else { Some(false) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> String {
        let d = std::env::temp_dir().join(format!("kanki-instance-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d.to_string_lossy().to_string()
    }

    /// The fix itself: a second copy of the same job cannot take the lock while the first lives,
    /// and gets it as soon as the first one is gone.
    #[test]
    fn a_second_copy_is_refused_until_the_first_one_stops() {
        let d = tmpdir("second");
        let dirs = [d.as_str()];
        let first = match try_acquire_in(&dirs, "panel") {
            Try::Got(h) => h,
            _ => panic!("the first copy must get the lock"),
        };
        // flock locks belong to the open file, so a second open in the same process behaves like
        // a second process would
        match try_acquire_in(&dirs, "panel") {
            Try::Busy(who) => assert!(who.contains(&std::process::id().to_string()), "the message names the pid: {}", who),
            _ => panic!("a second copy must be refused while the first runs"),
        }
        assert_eq!(alive_in(&dirs, "panel"), Some(true));
        drop(first);
        assert_eq!(alive_in(&dirs, "panel"), Some(false), "a dead job is seen as not running");
        assert!(matches!(try_acquire_in(&dirs, "panel"), Try::Got(_)), "the lock is free again once the first copy stops");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn different_jobs_do_not_block_each_other() {
        let d = tmpdir("jobs");
        let dirs = [d.as_str()];
        let _a = match try_acquire_in(&dirs, "panel") {
            Try::Got(h) => h,
            _ => panic!("panel"),
        };
        assert!(matches!(try_acquire_in(&dirs, "tunnel-agent"), Try::Got(_)), "the panel and the tunnel agent are different jobs");
        assert_eq!(alive_in(&dirs, "never-started"), Some(false), "no lock file = not running");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_copy_in_the_fallback_place_still_counts() {
        let a = tmpdir("dir-a");
        let b = tmpdir("dir-b");
        let _held = match try_in(&b, "panel") {
            Try::Got(h) => h,
            _ => panic!("lock in the second place"),
        };
        assert!(matches!(try_acquire_in(&[a.as_str(), b.as_str()], "panel"), Try::Busy(_)), "a lock in the other place blocks too");
        let _ = std::fs::remove_dir_all(&a);
        let _ = std::fs::remove_dir_all(&b);
    }
}
