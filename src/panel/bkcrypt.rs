//! 3.69: authenticated backups and a safe unpack.
//!
//! A backup carries the panel's secrets opened (so it restores on a server with another master key), so it is
//! sealed with AES-256-GCM under a key made from the backup passphrase with PBKDF2-HMAC-SHA256:
//!
//!   "KANKIBK2" | iterations (u32 BE) | salt (16) | nonce (12) | ciphertext + tag
//!
//! The header is the AAD: changing the iteration count, the salt or the nonce breaks the tag like a changed
//! byte of the archive does. The old format (`openssl enc -aes-256-cbc -pbkdf2`, "Salted__", no MAC) is still
//! read for the backups made before.
//!
//! The passphrase lives outside kanki.db (`/etc/kanki/backup.pass`, 0600): a stolen database (or a backup of it)
//! does not open the backups. It is at least 12 characters and never sent back by a GET.
//!
//! `unpack` opens a .tar.gz into a folder in Rust, entry by entry: only plain files and folders, no absolute
//! path, no `..`, nothing through a link, bounded in count and size (Zip-Slip and link tricks are refused
//! before a byte is written outside the folder).

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use std::io::Read;
use std::path::{Component, Path};

pub const MAGIC: &[u8; 8] = b"KANKIBK2";
/// PBKDF2 rounds of a new backup (as for the admin password)
pub const ITER: u32 = 600_000;
/// a file may not ask for more (a crafted header would keep the CPU busy)
const ITER_MAX: u32 = 10_000_000;
const HEAD: usize = 8 + 4 + 16 + 12;
/// the shortest passphrase a new one may be
pub const PASS_MIN: usize = 12;
/// where the passphrase is kept when kanki.env names no other file
pub const PASS_FILE: &str = "/etc/kanki/backup.pass";

fn derive(pass: &str, salt: &[u8], iter: u32) -> Result<[u8; 32], String> {
    let n = std::num::NonZeroU32::new(iter).ok_or("bad iteration count")?;
    let mut k = [0u8; 32];
    ring::pbkdf2::derive(ring::pbkdf2::PBKDF2_HMAC_SHA256, n, salt, pass.as_bytes(), &mut k);
    Ok(k)
}

/// `data` sealed with `pass` (a new salt and nonce every time)
pub fn seal(data: &[u8], pass: &str) -> Result<Vec<u8>, String> {
    seal_iter(data, pass, ITER)
}

fn seal_iter(data: &[u8], pass: &str, iter: u32) -> Result<Vec<u8>, String> {
    if pass.is_empty() {
        return Err("no backup passphrase".into());
    }
    let salt: [u8; 16] = rand::random();
    let nonce: [u8; 12] = rand::random();
    let key = derive(pass, &salt, iter)?;
    let mut head = Vec::with_capacity(HEAD);
    head.extend_from_slice(MAGIC);
    head.extend_from_slice(&iter.to_be_bytes());
    head.extend_from_slice(&salt);
    head.extend_from_slice(&nonce);
    let c = Aes256Gcm::new_from_slice(&key).map_err(|e| e.to_string())?;
    let ct = c.encrypt(Nonce::from_slice(&nonce), Payload { msg: data, aad: &head }).map_err(|_| "encryption failed".to_string())?;
    head.extend_from_slice(&ct);
    Ok(head)
}

pub fn is_sealed(data: &[u8]) -> bool {
    data.len() > HEAD && &data[..8] == MAGIC
}

/// The archive inside a sealed backup; a wrong passphrase and a changed byte give the same error
pub fn open(data: &[u8], pass: &str) -> Result<Vec<u8>, String> {
    if !is_sealed(data) {
        return Err("not a sealed Kanki backup".into());
    }
    let iter = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
    if iter == 0 || iter > ITER_MAX {
        return Err("wrong passphrase or damaged file".into());
    }
    let (salt, nonce) = (&data[12..28], &data[28..40]);
    let key = derive(pass, salt, iter)?;
    let c = Aes256Gcm::new_from_slice(&key).map_err(|e| e.to_string())?;
    c.decrypt(Nonce::from_slice(nonce), Payload { msg: &data[HEAD..], aad: &data[..HEAD] }).map_err(|_| "wrong passphrase or damaged file".to_string())
}

// ------------------------------------------------------------------ the passphrase, outside the database

/// The file the passphrase is kept in (kanki.env may name another one: `BACKUP_PASS_FILE`)
pub fn pass_file(env: &std::collections::HashMap<String, String>) -> String {
    env.get("BACKUP_PASS_FILE").map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).unwrap_or_else(|| PASS_FILE.to_string())
}

pub fn read_pass(file: &str) -> Result<Option<String>, String> {
    match std::fs::read_to_string(file) {
        Ok(t) => Ok(Some(t.trim_end_matches(['\n', '\r']).to_string()).filter(|s| !s.is_empty())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("{}: {}", file, e)),
    }
}

/// Writes the passphrase (0600 from the first byte)
pub fn write_pass(file: &str, pass: &str) -> Result<(), String> {
    if let Some(dir) = Path::new(file).parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {}", dir.display(), e))?;
    }
    crate::util::write_private(file, &format!("{}\n", pass)).map_err(|e| format!("{}: {}", file, e))
}

/// A passphrase the admin chose: 12 to 256 characters, no line break (it is one line of its file)
pub fn check_new_pass(p: &str) -> Result<(), String> {
    if p.chars().count() < PASS_MIN {
        return Err(format!("the backup passphrase must be at least {} characters", PASS_MIN));
    }
    if p.len() > 256 || p.contains(['\n', '\r', '\0']) {
        return Err("the backup passphrase must be one line of at most 256 characters".into());
    }
    Ok(())
}

// ------------------------------------------------------------------ a safe unpack

/// At most this many entries and this many bytes come out of one archive
pub const MAX_ENTRIES: usize = 20_000;
pub const MAX_BYTES: u64 = 2 << 30;

/// A path inside the archive as plain names only (no root, no `..`, no `.` games)
fn clean_rel(p: &Path) -> Result<std::path::PathBuf, String> {
    let mut out = std::path::PathBuf::new();
    for c in p.components() {
        match c {
            Component::Normal(x) => out.push(x),
            Component::CurDir => {}
            _ => return Err(format!("unsafe path in the archive: {}", p.display())),
        }
    }
    if out.as_os_str().is_empty() {
        return Err("empty path in the archive".into());
    }
    Ok(out)
}

/// No part of `rel` under `root` may be a link that is already on disk (nothing is written through one)
fn no_link_on_the_way(root: &Path, rel: &Path) -> Result<(), String> {
    let mut cur = root.to_path_buf();
    for c in rel.components() {
        cur.push(c);
        if let Ok(m) = std::fs::symlink_metadata(&cur) {
            if m.file_type().is_symlink() {
                return Err(format!("a link in the way: {}", rel.display()));
            }
        }
    }
    Ok(())
}

/// Unpacks the gzip'ed tar `tgz` into the (existing) folder `dest`. `links_ok`: symbolic links are kept as links
/// (certbot's own tree: each link is checked later by its reader; one to an absolute path is left out) but never
/// written through; else any link,
/// hard link, device or fifo stops the unpack.
pub fn unpack(tgz: &[u8], dest: &Path, links_ok: bool) -> Result<usize, String> {
    use std::io::Write;
    let gz = flate2::read::GzDecoder::new(tgz);
    let mut ar = tar::Archive::new(gz);
    let (mut n, mut total) = (0usize, 0u64);
    for e in ar.entries().map_err(|e| format!("archive is damaged: {}", e))? {
        let mut e = e.map_err(|e| format!("archive is damaged: {}", e))?;
        n += 1;
        if n > MAX_ENTRIES {
            return Err("the archive has too many entries".into());
        }
        let raw = e.path().map_err(|e| format!("archive is damaged: {}", e))?.into_owned();
        let rel = clean_rel(&raw)?;
        no_link_on_the_way(dest, &rel)?;
        let out = dest.join(&rel);
        let kind = e.header().entry_type();
        if kind.is_dir() {
            std::fs::create_dir_all(&out).map_err(|e| e.to_string())?;
            continue;
        }
        if let Some(parent) = out.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        if kind.is_symlink() && links_ok {
            let target = e.link_name().map_err(|e| e.to_string())?.ok_or("a link without a target")?.into_owned();
            // a link to an absolute path is left out (its reader skips what has no link)
            if target.is_absolute() {
                continue;
            }
            if std::fs::symlink_metadata(&out).is_ok() {
                return Err(format!("an entry twice: {}", rel.display()));
            }
            std::os::unix::fs::symlink(&target, &out).map_err(|e| e.to_string())?;
            continue;
        }
        if !(kind.is_file() || kind == tar::EntryType::Continuous) {
            return Err(format!("not a plain file in the archive: {}", rel.display()));
        }
        let size = e.header().size().map_err(|e| e.to_string())?;
        total = total.saturating_add(size);
        if total > MAX_BYTES {
            return Err("the archive is too big".into());
        }
        // a new file only (an entry twice, or one over a link made just before, is refused)
        let mut f = std::fs::OpenOptions::new().write(true).create_new(true).open(&out).map_err(|e| format!("{}: {}", rel.display(), e))?;
        let mut left = size;
        let mut buf = vec![0u8; 64 << 10];
        while left > 0 {
            let want = buf.len().min(left as usize);
            let got = e.read(&mut buf[..want]).map_err(|e| e.to_string())?;
            if got == 0 {
                return Err("archive is damaged (short entry)".into());
            }
            f.write_all(&buf[..got]).map_err(|e| e.to_string())?;
            left -= got as u64;
        }
        {
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(std::fs::Permissions::from_mode(0o600)).map_err(|e| e.to_string())?;
        }
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("kanki-bkc-{}-{}", tag, crate::util::rand_token(8)));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn a_sealed_backup_opens_with_its_passphrase_only_and_every_changed_byte_is_seen() {
        let data = b"the archive of a panel".repeat(100);
        let s = seal_iter(&data, "correct horse battery", 1000).unwrap();
        assert!(is_sealed(&s));
        assert_eq!(open(&s, "correct horse battery").unwrap(), data);
        assert!(open(&s, "correct horse batterz").is_err());
        // a byte of the archive, of the tag, of the salt, of the iteration count: all refused
        for i in [HEAD + 3, s.len() - 1, 14, 11] {
            let mut x = s.clone();
            x[i] ^= 1;
            assert!(open(&x, "correct horse battery").is_err(), "byte {}", i);
        }
        // a header asking for a huge iteration count is refused before any work
        let mut x = s.clone();
        x[8..12].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(open(&x, "correct horse battery").is_err());
        // truncated
        assert!(open(&s[..HEAD], "correct horse battery").is_err());
        // two seals of the same data differ (new salt and nonce)
        assert_ne!(seal_iter(&data, "correct horse battery", 1000).unwrap(), s);
    }

    #[test]
    fn the_passphrase_rules() {
        assert!(check_new_pass("short-pass1").is_err());
        assert!(check_new_pass("a-long-enough-pass").is_ok());
        assert!(check_new_pass("twelve chars\nsecond").is_err());
        assert!(check_new_pass(&"x".repeat(300)).is_err());
        let d = tmp("pass");
        let f = d.join("backup.pass").to_string_lossy().to_string();
        assert_eq!(read_pass(&f).unwrap(), None);
        write_pass(&f, "a-long-enough-pass").unwrap();
        assert_eq!(read_pass(&f).unwrap().as_deref(), Some("a-long-enough-pass"));
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&f).unwrap().permissions().mode() & 0o777, 0o600);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A tar.gz built by hand, entry by entry (name, kind, link target, data)
    fn tgz(entries: &[(&str, tar::EntryType, &str, &[u8])]) -> Vec<u8> {
        let mut b = tar::Builder::new(flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast()));
        for (name, kind, link, data) in entries {
            let mut h = tar::Header::new_gnu();
            h.set_entry_type(*kind);
            h.set_size(data.len() as u64);
            h.set_mode(0o644);
            // the name is written raw: the builder's own checks would refuse the bad ones this test needs
            let nb = name.as_bytes();
            h.as_old_mut().name[..nb.len()].copy_from_slice(nb);
            if !link.is_empty() {
                let lb = link.as_bytes();
                h.as_old_mut().linkname[..lb.len()].copy_from_slice(lb);
            }
            h.set_cksum();
            b.append(&h, *data).unwrap();
        }
        b.into_inner().unwrap().finish().unwrap()
    }

    #[test]
    fn zip_slip_links_and_devices_are_refused() {
        use tar::EntryType as T;
        let good = tgz(&[("files/", T::Directory, "", b""), ("kanki.db", T::Regular, "", b"db"), ("files/etc/kanki/kanki.env", T::Regular, "", b"A=1")]);
        let d = tmp("good");
        assert_eq!(unpack(&good, &d, false).unwrap(), 3);
        assert_eq!(std::fs::read(d.join("files/etc/kanki/kanki.env")).unwrap(), b"A=1");
        let _ = std::fs::remove_dir_all(&d);
        let outside = std::env::temp_dir().join(format!("kanki-bkc-escape-{}", crate::util::rand_token(6)));
        for (what, bad) in [
            ("dot-dot", tgz(&[("../../escape", T::Regular, "", b"x")])),
            ("absolute", tgz(&[(outside.to_str().unwrap(), T::Regular, "", b"x")])),
            ("symlink", tgz(&[("link", T::Symlink, "/etc", b""), ("link/passwd", T::Regular, "", b"x")])),
            ("hard link", tgz(&[("h", T::Link, "/etc/shadow", b"")])),
            ("device", tgz(&[("dev", T::Char, "", b"")])),
            ("twice", tgz(&[("a", T::Regular, "", b"1"), ("a", T::Regular, "", b"2")])),
        ] {
            let d = tmp("bad");
            assert!(unpack(&bad, &d, false).is_err(), "{}", what);
            let _ = std::fs::remove_dir_all(&d);
        }
        assert!(!outside.exists());
        // certbot's tree: a relative link is kept as a link, but a file is never written through it
        let le = tgz(&[("live/a/", T::Directory, "", b""), ("live/a/cert.pem", T::Symlink, "../../archive/a/cert1.pem", b"")]);
        let d = tmp("le");
        assert_eq!(unpack(&le, &d, true).unwrap(), 2);
        assert!(std::fs::symlink_metadata(d.join("live/a/cert.pem")).unwrap().file_type().is_symlink());
        let through = tgz(&[("x", T::Symlink, "..", b""), ("x/evil", T::Regular, "", b"x")]);
        assert!(unpack(&through, &d, true).is_err());
        assert_eq!(unpack(&tgz(&[("abs", T::Symlink, "/etc/passwd", b"")]), &d, true).unwrap(), 1);
        assert!(std::fs::symlink_metadata(d.join("abs")).is_err(), "an absolute link is left out");
        let _ = std::fs::remove_dir_all(&d);
        // not a gzip at all
        assert!(unpack(b"not an archive", &tmp("junk"), false).is_err());
    }
}
