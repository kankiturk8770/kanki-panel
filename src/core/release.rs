//! 3.69: what runs as root on the servers is checked before it runs.
//!
//! * Third-party programs (Hysteria2, Xray-core, Caddy) are fixed releases whose SHA-256 is written here (the same
//!   values as in install.sh). A file whose hash is not the pinned one is never written in place or started.
//! * The panel program itself is signed with minisign. The public key is put into the program when it is built
//!   (`KANKI_UPDATE_PUBKEY`, the base64 line of `minisign.pub`); a downloaded program is checked against it
//!   before it is ever started (not even `<file> version`). A build without the key updates nothing by itself
//!   (fail closed) and keeps the automatic update off.

// ------------------------------------------------------------------ pinned releases

/// Hysteria2 (`app/v2.14.0`): SHA-256 of `hysteria-linux-<arch>` as published in the release's hashes.txt
pub const HY2_VERSION: &str = "v2.14.0";
const HY2_SHA256: &[(&str, &str)] = &[
    ("amd64", "fc25edff9948708cb00a4ff01f3bccde677660aca050133bb1ad46c6860362d2"),
    ("arm64", "e7c52241299fe85aba11e9d36e85d8d88ddbb5799ac0e33d272219d20e313bab"),
    ("arm", "50a7a9ac1ab0660ebfae0651f03faa234c7d99d0701806e10a7f5060857647ab"),
    ("386", "a30c618690b4aecf521c10ea2ec199aa13cff54696d3cecd5fa4502abdb2985a"),
];

/// Xray-core: SHA-256 of the release zips (the `SHA2-256` line of each `.dgst`)
pub const XRAY_VERSION: &str = "v26.11.9";
const XRAY_SHA256: &[(&str, &str)] = &[
    ("Xray-linux-64.zip", "b651f7e1d9966ee2c1b1ee1bf8b52c72771824d3065dce96bbc8bcc19ed95f82"),
    ("Xray-linux-arm64-v8a.zip", "64ed6858982a7f5eb85d88b811089063bd4f17561f4c8f44e0f1dc8e6f6430be"),
    ("Xray-linux-arm32-v7a.zip", "19c51e08a6562705fb1cb032a84fd87df21d7e27b194f035be7e754dbe3a97b3"),
];

fn find(t: &'static [(&'static str, &'static str)], k: &str) -> Option<&'static str> {
    t.iter().find(|(a, _)| *a == k).map(|(_, h)| *h)
}

pub fn hy2_sha256(arch_name: &str) -> Option<&'static str> {
    find(HY2_SHA256, arch_name)
}

pub fn xray_sha256(zip: &str) -> Option<&'static str> {
    find(XRAY_SHA256, zip)
}

pub fn sha256_hex(b: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(b))
}

/// `bytes` are exactly the pinned file
pub fn matches(bytes: &[u8], want: &str) -> bool {
    !want.is_empty() && crate::util::ct_eq(&sha256_hex(bytes), want)
}

// ------------------------------------------------------------------ minisign

/// The release key built into this program (`KANKI_UPDATE_PUBKEY` at build time), when there is one
pub fn update_key_text() -> Option<&'static str> {
    option_env!("KANKI_UPDATE_PUBKEY").map(|s| s.trim()).filter(|s| !s.is_empty())
}

/// Signed updates work in this build (its key is there and readable)
pub fn signing_active() -> bool {
    update_key_text().and_then(|k| PublicKey::parse(k).ok()).is_some()
}

#[derive(Clone, Debug, PartialEq)]
pub struct PublicKey {
    id: [u8; 8],
    key: [u8; 32],
}

impl PublicKey {
    /// The base64 line of a `minisign.pub` ("RW…"), or the whole file
    pub fn parse(text: &str) -> Result<PublicKey, String> {
        let line = text.lines().map(|l| l.trim()).find(|l| !l.is_empty() && !l.starts_with("untrusted comment:")).ok_or("empty public key")?;
        let b = crate::tunnel::link::b64decode(line).ok_or("the public key is not base64")?;
        if b.len() != 42 || &b[..2] != b"Ed" {
            return Err("not a minisign Ed25519 public key".into());
        }
        let mut id = [0u8; 8];
        id.copy_from_slice(&b[2..10]);
        let mut key = [0u8; 32];
        key.copy_from_slice(&b[10..42]);
        Ok(PublicKey { id, key })
    }

    fn verify_raw(&self, msg: &[u8], sig: &[u8]) -> bool {
        ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, &self.key).verify(msg, sig).is_ok()
    }
}

/// What a good signature says about the file: its trusted comment
#[derive(Debug, PartialEq)]
pub struct Verified {
    pub trusted: String,
}

impl Verified {
    /// The version named in a trusted comment `kanki-panel <version>` (what the release workflow signs)
    pub fn version(&self) -> Option<String> {
        let rest = self.trusted.split_whitespace().skip_while(|w| *w != "kanki-panel").nth(1)?;
        let v = rest.trim_start_matches('v');
        (!v.is_empty() && v.len() <= 32 && v.chars().all(|c| c.is_ascii_digit() || c == '.')).then(|| v.to_string())
    }
}

/// Checks a minisign signature file (`.minisig`) of `data`: the key id, the file's signature (plain "Ed" or
/// the prehashed "ED", BLAKE2b-512) and the signature over the trusted comment
pub fn verify(pk: &PublicKey, data: &[u8], sig_text: &str) -> Result<Verified, String> {
    if sig_text.len() > 4096 {
        return Err("signature file too big".into());
    }
    let lines: Vec<&str> = sig_text.lines().map(|l| l.trim_end_matches('\r')).collect();
    if lines.len() < 4 || !lines[0].starts_with("untrusted comment:") {
        return Err("not a minisign signature".into());
    }
    let sig = crate::tunnel::link::b64decode(lines[1].trim()).ok_or("the signature is not base64")?;
    if sig.len() != 74 {
        return Err("not a minisign signature".into());
    }
    let (alg, id, s) = (&sig[..2], &sig[2..10], &sig[10..74]);
    if id != pk.id {
        return Err("signed with another key".into());
    }
    let ok = match alg {
        b"ED" => {
            use blake2::Digest;
            let h = blake2::Blake2b512::digest(data);
            pk.verify_raw(&h, s)
        }
        b"Ed" => pk.verify_raw(data, s),
        _ => return Err("unknown signature algorithm".into()),
    };
    if !ok {
        return Err("bad signature".into());
    }
    let trusted = lines[2].strip_prefix("trusted comment: ").ok_or("no trusted comment")?.to_string();
    let global = crate::tunnel::link::b64decode(lines[3].trim()).ok_or("the comment signature is not base64")?;
    let mut m = s.to_vec();
    m.extend_from_slice(trusted.as_bytes());
    if global.len() != 64 || !pk.verify_raw(&m, &global) {
        return Err("bad signature of the trusted comment".into());
    }
    Ok(Verified { trusted })
}

/// A downloaded panel program against the key built in: Err when this build has none, or it does not match
pub fn verify_update(data: &[u8], sig_text: &str) -> Result<Verified, String> {
    let k = update_key_text().ok_or("this build has no update signing key (KANKI_UPDATE_PUBKEY): update it by hand")?;
    let pk = PublicKey::parse(k)?;
    verify(&pk, data, sig_text)
}

/// Where the signature of the program that runs here is kept (served to the agents with the program)
pub const SELF_SIG: &str = "/etc/kanki/kanki-panel.minisig";

/// The signature of the program on disk, when there is one and it is of this file
pub fn own_signature() -> Option<String> {
    let t = std::fs::read_to_string(SELF_SIG).ok()?;
    (t.len() <= 4096).then_some(t)
}

pub fn save_own_signature(sig: &str) -> Result<(), String> {
    crate::util::write_private(SELF_SIG, sig).map_err(|e| format!("{}: {}", SELF_SIG, e))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use ring::signature::KeyPair;

    /// A minisign key and signer made with ring, so the verifier is tested against real Ed25519 signatures
    pub(crate) struct Signer {
        kp: ring::signature::Ed25519KeyPair,
        id: [u8; 8],
    }

    impl Signer {
        pub(crate) fn new() -> Signer {
            let rng = ring::rand::SystemRandom::new();
            let doc = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
            Signer { kp: ring::signature::Ed25519KeyPair::from_pkcs8(doc.as_ref()).unwrap(), id: rand::random() }
        }
        pub(crate) fn public(&self) -> String {
            let mut b = b"Ed".to_vec();
            b.extend_from_slice(&self.id);
            b.extend_from_slice(self.kp.public_key().as_ref());
            format!("untrusted comment: minisign public key\n{}\n", crate::util::b64(&b))
        }
        pub(crate) fn sign(&self, data: &[u8], trusted: &str, prehash: bool) -> String {
            use blake2::Digest;
            let s = if prehash { self.kp.sign(&blake2::Blake2b512::digest(data)) } else { self.kp.sign(data) };
            let mut sig = if prehash { b"ED".to_vec() } else { b"Ed".to_vec() };
            sig.extend_from_slice(&self.id);
            sig.extend_from_slice(s.as_ref());
            let mut g = s.as_ref().to_vec();
            g.extend_from_slice(trusted.as_bytes());
            let gs = self.kp.sign(&g);
            format!("untrusted comment: signature\n{}\ntrusted comment: {}\n{}\n", crate::util::b64(&sig), trusted, crate::util::b64(gs.as_ref()))
        }
    }

    #[test]
    fn minisign_signatures_are_checked_and_anything_changed_is_refused() {
        let s = Signer::new();
        let pk = PublicKey::parse(&s.public()).unwrap();
        let data = b"\x7fELF the new panel program".repeat(50);
        for prehash in [true, false] {
            let sig = s.sign(&data, "kanki-panel 3.69.0 timestamp:1", prehash);
            let v = verify(&pk, &data, &sig).unwrap();
            assert_eq!(v.version().as_deref(), Some("3.69.0"));
            // one byte of the program changed
            let mut bad = data.clone();
            bad[7] ^= 1;
            assert!(verify(&pk, &bad, &sig).is_err());
            // the trusted comment changed (a downgrade dressed as a newer version)
            let forged = sig.replace("kanki-panel 3.69.0", "kanki-panel 9.99.0");
            assert!(verify(&pk, &data, &forged).is_err());
            // another key
            let other = PublicKey::parse(&Signer::new().public()).unwrap();
            assert_eq!(verify(&other, &data, &sig).unwrap_err(), "signed with another key");
        }
        // a signature by another key with this key's id
        let mallory = Signer { kp: Signer::new().kp, id: s.id };
        assert!(verify(&pk, &data, &mallory.sign(&data, "kanki-panel 3.69.0", true)).is_err());
        // junk
        assert!(verify(&pk, &data, "").is_err());
        assert!(verify(&pk, &data, "untrusted comment: x\nnot-base64!\ntrusted comment: y\nzz\n").is_err());
        assert!(verify(&pk, &data, &"x".repeat(5000)).is_err());
        assert!(PublicKey::parse("RWQ=").is_err());
    }

    /// Caddy (install.sh only, when the distribution has no package): SHA-256 of `caddy_<v>_linux_<arch>.tar.gz`
    /// (the release's checksums file gives SHA-512; these were computed from the same files)
    const CADDY_VERSION: &str = "2.11.9";
    const CADDY_SHA256: &[(&str, &str)] = &[
        ("amd64", "5b8cb7faf8726a2028ad96a66e54e6e81e8f361bc6175e5d22bbd997cc5177fb"),
        ("arm64", "5e377cff994fc9362a6fcf695c53f226cfca3a3ef85bd3a3687cf252d6310165"),
        ("armv7", "8c191dd2688c30dbe19793a0a3f532ede64547c5a70a47eebf7d8ab43a4d7514"),
    ];

    #[test]
    fn pinned_hashes_are_well_formed() {
        for (_, h) in HY2_SHA256.iter().chain(XRAY_SHA256).chain(CADDY_SHA256) {
            assert!(h.len() == 64 && h.bytes().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()), "{}", h);
        }
        assert!(matches(b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
        assert!(!matches(b"x", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
        assert!(!matches(b"", ""));
        assert!(hy2_sha256("amd64").is_some() && hy2_sha256("riscv64").is_none());
        assert!(xray_sha256("Xray-linux-64.zip").is_some());
        // install.sh carries the same values
        let sh = include_str!("../../install.sh");
        for (_, h) in HY2_SHA256.iter().chain(CADDY_SHA256) {
            assert!(sh.contains(h), "install.sh lacks {}", h);
        }
        assert!(sh.contains(&format!("HY2_VER={}", HY2_VERSION)) && sh.contains(&format!("CADDY_VER={}", CADDY_VERSION)));
    }
}
