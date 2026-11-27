//! Certificate pinning (TOFU) for TLS channels that run without a public CA — the agent→panel
//! link on installs without a domain (INSECURE=1) and the panel→node link when a node has a
//! self-signed certificate.
//!
//! 3.69: a pin is the SHA-256 of the certificate's public key (SPKI, the form `curl --pinnedpubkey` takes:
//! `sha256//<base64>`) and has a mode:
//!
//! * `ca`: the pinned side uses a certificate a public CA vouches for (a domain with Let's Encrypt, which
//!   renews with a new key every ~60 days): any CA-valid certificate for the name is taken and becomes the pin;
//!   one that is not CA-valid must have the pinned key.
//! * `self`: a self-signed certificate. Only the pinned key is taken; a CA-valid certificate with another key is
//!   refused too (before 3.69 any CA-valid certificate silently replaced the pin: whoever got one for the
//!   name, or for an IP, could take over the channel).
//!
//! The first contact pins (TOFU) unless the pin was given beforehand: the panel puts its own pin and mode into
//! the join command (`KANKI_PANEL_PIN`), so a new server trusts exactly the panel from its first packet.
//! A pin file from before (the hex SHA-256 of the whole certificate) is still read; the first match upgrades it.
//!
//!   spki:sha256//<base64>
//!   mode:ca|self

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// The text every pin-mismatch error starts with (to tell it apart from "offline").
pub const MISMATCH: &str = "certificate pin mismatch";

#[derive(Clone, Debug, PartialEq)]
pub enum PinState {
    /// the SPKI pin and whether the pinned side has a CA-valid certificate
    Spki { pin: String, ca: bool },
    /// before 3.69: the hex SHA-256 of the whole certificate
    Legacy(String),
}

/// What a pin file says (None = no usable pin: first contact)
pub fn parse_pin(text: &str) -> Option<PinState> {
    let mut pin = None;
    let mut ca = false;
    for l in text.lines().map(|l| l.trim()) {
        if let Some(p) = l.strip_prefix("spki:") {
            pin = Some(p.trim().to_string()).filter(|p| valid_spki_pin(p));
        } else if let Some(m) = l.strip_prefix("mode:") {
            ca = m.trim() == "ca";
        }
    }
    if let Some(pin) = pin {
        return Some(PinState::Spki { pin, ca });
    }
    let l = text.trim().to_lowercase();
    (l.len() == 64 && l.bytes().all(|c| c.is_ascii_hexdigit())).then_some(PinState::Legacy(l))
}

/// `sha256//` and the base64 of 32 bytes
pub fn valid_spki_pin(p: &str) -> bool {
    p.strip_prefix("sha256//").and_then(crate::tunnel::link::b64decode).map(|b| b.len() == 32).unwrap_or(false) && p.len() == 52
}

pub fn pin_text(pin: &str, ca: bool) -> String {
    format!("spki:{}\nmode:{}\n", pin, if ca { "ca" } else { "self" })
}

/// A certificate given beforehand (the join command): written as the pin unless the file already has one
pub fn preset(pin_file: &Path, pin: &str, ca: bool) -> Result<(), String> {
    if !valid_spki_pin(pin) {
        return Err("not a public key pin (sha256//<base64>)".into());
    }
    if let Some(dir) = pin_file.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    crate::util::write_private(&pin_file.to_string_lossy(), &pin_text(pin, ca)).map_err(|e| e.to_string())
}

/// The SubjectPublicKeyInfo of a DER certificate (Certificate → tbsCertificate → its 7th element, after the
/// optional [0] version)
pub fn spki_der(cert: &[u8]) -> Option<&[u8]> {
    /// (tag, content, the whole element, rest)
    fn tlv(b: &[u8]) -> Option<(u8, &[u8], &[u8], &[u8])> {
        let tag = *b.first()?;
        let l0 = *b.get(1)? as usize;
        let (len, hl) = if l0 < 0x80 {
            (l0, 2)
        } else {
            let n = l0 & 0x7f;
            if n == 0 || n > 4 {
                return None;
            }
            let mut len = 0usize;
            for i in 0..n {
                len = (len << 8) | *b.get(2 + i)? as usize;
            }
            (len, 2 + n)
        };
        let end = hl.checked_add(len)?;
        if end > b.len() {
            return None;
        }
        Some((tag, &b[hl..end], &b[..end], &b[end..]))
    }
    let (t, cert_body, _, _) = tlv(cert)?;
    if t != 0x30 {
        return None;
    }
    let (t, tbs, _, _) = tlv(cert_body)?;
    if t != 0x30 {
        return None;
    }
    let mut rest = tbs;
    // [0] EXPLICIT version
    if rest.first() == Some(&0xa0) {
        rest = tlv(rest)?.3;
    }
    // serialNumber, signature, issuer, validity, subject
    for _ in 0..5 {
        rest = tlv(rest)?.3;
    }
    let (t, _, whole, _) = tlv(rest)?;
    (t == 0x30).then_some(whole)
}

/// `sha256//<base64>` of a certificate's public key
pub fn spki_pin(cert: &[u8]) -> Option<String> {
    use sha2::{Digest, Sha256};
    spki_der(cert).map(|s| format!("sha256//{}", crate::util::b64(&Sha256::digest(s))))
}

/// A TLS server-certificate verifier: the pinned key, a CA-valid certificate where the pin says the side has
/// one, or the first certificate seen (TOFU).
#[derive(Debug)]
pub struct Pinned {
    pin_file: PathBuf,
    state: Mutex<Option<PinState>>,
    provider: Arc<rustls::crypto::CryptoProvider>,
    /// the normal CA check; None when it cannot be built
    ca: Option<Arc<rustls::client::WebPkiServerVerifier>>,
}

fn read_pin(pin_file: &Path) -> Option<PinState> {
    std::fs::read_to_string(pin_file).ok().and_then(|t| parse_pin(&t))
}

impl Pinned {
    /// Loads the pin file if it exists; otherwise the first certificate seen becomes the pin.
    pub fn load(pin_file: PathBuf) -> Arc<Self> {
        let roots = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
        Self::with_roots(pin_file, roots)
    }

    /// Like `load`, with the given CA roots for the normal check.
    pub fn with_roots(pin_file: PathBuf, roots: rustls::RootCertStore) -> Arc<Self> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let ca = rustls::client::WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone()).build().ok();
        Arc::new(Pinned { state: Mutex::new(read_pin(&pin_file)), pin_file, provider, ca })
    }

    fn write_pin(&self, st: &PinState) -> bool {
        let PinState::Spki { pin, ca } = st else { return false };
        if let Some(dir) = self.pin_file.parent() {
            if std::fs::create_dir_all(dir).is_err() {
                return false;
            }
        }
        crate::util::write_private(&self.pin_file.to_string_lossy(), &pin_text(pin, *ca)).is_ok()
    }

    fn fingerprint(cert: &rustls::pki_types::CertificateDer<'_>) -> String {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(cert.as_ref()))
    }

    /// The decision for one certificate: Ok(new state to keep, when it changes) or the refusal
    fn decide(&self, cur: &Option<PinState>, spki: &str, fp: &str, ca_ok: bool) -> Result<Option<PinState>, String> {
        let fresh = PinState::Spki { pin: spki.to_string(), ca: ca_ok };
        match cur {
            // trust on first use: the pin and whether the side is CA-checked
            None => Ok(Some(fresh)),
            Some(PinState::Spki { pin, ca }) => {
                if pin == spki {
                    // a self-signed side that now has a CA-valid certificate with the same key stays `self`
                    Ok(None)
                } else if *ca && ca_ok {
                    // a renewal (a new key) of a CA-valid certificate
                    Ok(Some(PinState::Spki { pin: spki.to_string(), ca: true }))
                } else {
                    Err(format!("the server shows key {} but {} is pinned ({})", spki, pin, if *ca { "CA mode" } else { "self-signed mode: a CA-valid certificate with another key is refused too" }))
                }
            }
            Some(PinState::Legacy(old)) => {
                if old == fp {
                    // the same certificate as before 3.69: the pin becomes its key
                    Ok(Some(fresh))
                } else if ca_ok {
                    // before 3.69 every CA-valid certificate re-pinned: kept once for a pin file of before, so an
                    // agent whose panel renewed during the upgrade is not locked out; from now on the key counts
                    Ok(Some(PinState::Spki { pin: spki.to_string(), ca: true }))
                } else {
                    Err(format!("the server shows certificate {} but {} is pinned", fp, old))
                }
            }
        }
    }
}

impl rustls::client::danger::ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        server_name: &rustls::pki_types::ServerName<'_>,
        ocsp_response: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let fp = Self::fingerprint(end_entity);
        let spki = spki_pin(end_entity.as_ref()).ok_or_else(|| rustls::Error::General("the server's certificate cannot be read".into()))?;
        let ca_ok = self.ca.as_ref().is_some_and(|ca| ca.verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now).is_ok());
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        // the pin file may have been changed or deleted by hand since it was read
        let on_disk = read_pin(&self.pin_file);
        if on_disk != *st {
            *st = on_disk;
        }
        match self.decide(&st, &spki, &fp, ca_ok) {
            Ok(None) => Ok(rustls::client::danger::ServerCertVerified::assertion()),
            Ok(Some(next)) => {
                if self.write_pin(&next) {
                    *st = Some(next);
                    Ok(rustls::client::danger::ServerCertVerified::assertion())
                } else {
                    Err(rustls::Error::General(format!("cannot write the certificate pin file {}", self.pin_file.display())))
                }
            }
            Err(why) => Err(rustls::Error::General(format!(
                "{}: {} — refusing to connect (possible MITM). If the certificate was changed on purpose (reinstall, new self-signed certificate), delete the pin file {}",
                MISMATCH, why, self.pin_file.display()
            ))),
        }
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// Takes any certificate and remembers it (for `probe`)
#[derive(Debug)]
struct Capture {
    seen: Mutex<Option<(Vec<u8>, bool)>>,
    provider: Arc<rustls::crypto::CryptoProvider>,
    ca: Option<Arc<rustls::client::WebPkiServerVerifier>>,
}

impl rustls::client::danger::ServerCertVerifier for Capture {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        server_name: &rustls::pki_types::ServerName<'_>,
        ocsp_response: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let ca_ok = self.ca.as_ref().is_some_and(|ca| ca.verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now).is_ok());
        *self.seen.lock().unwrap_or_else(|e| e.into_inner()) = Some((end_entity.as_ref().to_vec(), ca_ok));
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(&self, message: &[u8], cert: &rustls::pki_types::CertificateDer<'_>, dss: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }
    fn verify_tls13_signature(&self, message: &[u8], cert: &rustls::pki_types::CertificateDer<'_>, dss: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// The public key pin of the certificate `host:port` shows for the name `host`, and whether a public CA vouches
/// for it (3.69: the panel puts its own into the join command). `roots`: the CA roots (None = the public ones).
pub async fn probe(host: &str, port: u16, roots: Option<rustls::RootCertStore>) -> Result<(String, bool), String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let roots = roots.unwrap_or_else(|| rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() });
    let ca = rustls::client::WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone()).build().ok();
    let cap = Arc::new(Capture { seen: Mutex::new(None), provider: provider.clone(), ca });
    let cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .dangerous()
        .with_custom_certificate_verifier(cap.clone())
        .with_no_client_auth();
    let name = rustls::pki_types::ServerName::try_from(host.trim_start_matches('[').trim_end_matches(']').to_string()).map_err(|e| e.to_string())?;
    let run = async {
        let tcp = tokio::net::TcpStream::connect((host.trim_start_matches('[').trim_end_matches(']'), port)).await.map_err(|e| e.to_string())?;
        tokio_rustls::TlsConnector::from(Arc::new(cfg)).connect(name, tcp).await.map_err(|e| e.to_string())?;
        Ok::<(), String>(())
    };
    tokio::time::timeout(std::time::Duration::from_secs(8), run).await.map_err(|_| "timed out".to_string())??;
    let seen = cap.seen.lock().unwrap_or_else(|e| e.into_inner()).take().ok_or("no certificate")?;
    Ok((spki_pin(&seen.0).ok_or("the certificate cannot be read")?, seen.1))
}

/// An HTTP client that pins the peer certificate (TOFU) instead of checking a CA. Use it for
/// channels that would otherwise run with certificate verification fully off.
/// How long opening a connection may take. A server whose packets are dropped (filtered, gone) is given up
/// on after this, not after the whole request timeout: one such server held every sync round for 45 s.
pub const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// A kept-alive connection to a server or the panel is reused this long when idle (the polls every few
/// seconds keep it open: no new TCP and TLS handshake for each)
pub const POOL_IDLE: std::time::Duration = std::time::Duration::from_secs(90);
/// TCP keepalive on those connections, so a NAT on the way does not drop them while idle
pub const TCP_KEEPALIVE: std::time::Duration = std::time::Duration::from_secs(30);

pub fn pinned_client(pin_file: &Path, timeout: std::time::Duration) -> reqwest::Client {
    let mut cfg = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .expect("tls versions")
        .dangerous()
        .with_custom_certificate_verifier(Pinned::load(pin_file.to_path_buf()))
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    reqwest::Client::builder()
        .timeout(timeout)
        .connect_timeout(CONNECT_TIMEOUT)
        .use_preconfigured_tls(cfg)
        .pool_idle_timeout(POOL_IDLE)
        .tcp_keepalive(TCP_KEEPALIVE)
        .build()
        .expect("pinned http client")
}

/// The full text of an error with its causes (reqwest hides the TLS reason in `source()`).
pub fn error_text(e: &(dyn std::error::Error + 'static)) -> String {
    let mut t = e.to_string();
    let mut src = e.source();
    while let Some(s) = src {
        let m = s.to_string();
        if !t.contains(&m) {
            t.push_str(": ");
            t.push_str(&m);
        }
        src = s.source();
    }
    t
}

/// The pin-mismatch message inside an error, if that is what it is.
pub fn mismatch_of(e: &(dyn std::error::Error + 'static)) -> Option<String> {
    let t = error_text(e);
    t.find(MISMATCH).map(|i| t[i..].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::client::danger::ServerCertVerifier;
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

    fn dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("kanki-pin-test-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    fn self_signed(host: &str) -> CertificateDer<'static> {
        let k = rcgen::KeyPair::generate().unwrap();
        rcgen::CertificateParams::new(vec![host.to_string()]).unwrap().self_signed(&k).unwrap().der().clone()
    }

    fn check(p: &Pinned, cert: &CertificateDer<'static>, chain: &[CertificateDer<'static>], host: &str) -> Result<(), rustls::Error> {
        let name = ServerName::try_from(host.to_string()).unwrap();
        p.verify_server_cert(cert, chain, &name, &[], UnixTime::now()).map(|_| ())
    }

    struct Ca {
        key: rcgen::KeyPair,
        cert: rcgen::Certificate,
    }

    impl Ca {
        fn new() -> Ca {
            let key = rcgen::KeyPair::generate().unwrap();
            let mut p = rcgen::CertificateParams::new(vec![]).unwrap();
            p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            let cert = p.self_signed(&key).unwrap();
            Ca { key, cert }
        }
        fn roots(&self) -> rustls::RootCertStore {
            let mut r = rustls::RootCertStore::empty();
            r.add(self.cert.der().clone()).unwrap();
            r
        }
        fn leaf(&self, host: &str) -> CertificateDer<'static> {
            let k = rcgen::KeyPair::generate().unwrap();
            let mut p = rcgen::CertificateParams::new(vec![host.to_string()]).unwrap();
            p.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
            p.signed_by(&k, &self.cert, &self.key).unwrap().der().clone()
        }
    }

    #[test]
    fn the_spki_is_read_out_of_the_certificate() {
        let k = rcgen::KeyPair::generate().unwrap();
        let c = rcgen::CertificateParams::new(vec!["a.example.com".to_string()]).unwrap().self_signed(&k).unwrap();
        assert_eq!(spki_der(c.der()), Some(k.public_key_der().as_slice()));
        let pin = spki_pin(c.der()).unwrap();
        assert!(valid_spki_pin(&pin), "{}", pin);
        // the same key in another certificate: the same pin
        let c2 = rcgen::CertificateParams::new(vec!["b.example.com".to_string()]).unwrap().self_signed(&k).unwrap();
        assert_eq!(spki_pin(c2.der()), Some(pin));
        assert!(spki_der(b"\x30\x03\x02\x01").is_none());
        assert!(spki_der(&[0x30, 0x84, 0xff, 0xff, 0xff, 0xff]).is_none());
        assert!(parse_pin("spki:sha256//short\n").is_none());
    }

    #[test]
    fn a_self_signed_pin_is_not_replaced_by_a_ca_valid_certificate() {
        let ca = Ca::new();
        let d = dir("self");
        let file = d.join("panel.pin");
        let p = Pinned::with_roots(file.clone(), ca.roots());
        let first = self_signed("panel.example.com");
        assert!(check(&p, &first, &[], "panel.example.com").is_ok());
        assert_eq!(read_pin(&file), Some(PinState::Spki { pin: spki_pin(first.as_ref()).unwrap(), ca: false }));
        // someone got a CA-valid certificate for the name: refused (before 3.69 it became the pin)
        let e = check(&p, &ca.leaf("panel.example.com"), &[], "panel.example.com").unwrap_err();
        assert!(e.to_string().contains(MISMATCH), "{}", e);
        assert_eq!(read_pin(&file), Some(PinState::Spki { pin: spki_pin(first.as_ref()).unwrap(), ca: false }));
        // another self-signed one: refused; the pinned one still passes
        assert!(check(&p, &self_signed("panel.example.com"), &[], "panel.example.com").is_err());
        assert!(check(&p, &first, &[], "panel.example.com").is_ok());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_ca_pin_follows_renewals_but_not_a_self_signed_impostor() {
        let ca = Ca::new();
        let d = dir("ca");
        let file = d.join("panel.pin");
        let p = Pinned::with_roots(file.clone(), ca.roots());
        let first = ca.leaf("panel.example.com");
        assert!(check(&p, &first, &[], "panel.example.com").is_ok());
        assert_eq!(read_pin(&file), Some(PinState::Spki { pin: spki_pin(first.as_ref()).unwrap(), ca: true }));
        // certbot renewed with a new key: taken and pinned
        let renewed = ca.leaf("panel.example.com");
        assert!(check(&p, &renewed, &[], "panel.example.com").is_ok());
        assert_eq!(read_pin(&file), Some(PinState::Spki { pin: spki_pin(renewed.as_ref()).unwrap(), ca: true }));
        // a self-signed certificate (not CA-valid) with another key: refused
        assert!(check(&p, &self_signed("panel.example.com"), &[], "panel.example.com").is_err());
        // CA-valid but for another name: not CA-valid for this one, so the key must match: refused
        assert!(check(&p, &ca.leaf("evil.example.com"), &[], "panel.example.com").is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_pin_given_beforehand_is_the_only_one_taken_from_the_first_contact() {
        let d = dir("preset");
        let file = d.join("panel.pin");
        let real = self_signed("panel.example.com");
        preset(&file, &spki_pin(real.as_ref()).unwrap(), false).unwrap();
        let p = Pinned::load(file.clone());
        // a man in the middle at the very first contact: refused (no TOFU any more)
        assert!(check(&p, &self_signed("panel.example.com"), &[], "panel.example.com").is_err());
        assert!(check(&p, &real, &[], "panel.example.com").is_ok());
        assert!(preset(&file, "sha256//not-a-pin", false).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_pin_file_of_before_is_upgraded_on_its_first_match() {
        let d = dir("legacy");
        let file = d.join("node.pin");
        std::fs::create_dir_all(&d).unwrap();
        let cert = self_signed("node.example.com");
        std::fs::write(&file, format!("{}\n", Pinned::fingerprint(&cert))).unwrap();
        let p = Pinned::load(file.clone());
        assert!(check(&p, &self_signed("node.example.com"), &[], "node.example.com").is_err());
        assert!(check(&p, &cert, &[], "node.example.com").is_ok());
        assert_eq!(read_pin(&file), Some(PinState::Spki { pin: spki_pin(cert.as_ref()).unwrap(), ca: false }));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn self_signed_is_pinned_on_first_use() {
        let d = dir("tofu");
        let file = d.join("node.pin");
        let p = Pinned::load(file.clone());
        let first = self_signed("node.example.com");
        assert!(check(&p, &first, &[], "node.example.com").is_ok());
        assert!(check(&p, &first, &[], "node.example.com").is_ok());
        // a different certificate is refused
        let second = self_signed("node.example.com");
        let e = check(&p, &second, &[], "node.example.com").unwrap_err();
        assert!(e.to_string().contains(MISMATCH));
        // deleting the pin file resets it without a restart
        std::fs::remove_file(&file).unwrap();
        assert!(check(&p, &second, &[], "node.example.com").is_ok());
        assert_eq!(read_pin(&file), Some(PinState::Spki { pin: spki_pin(second.as_ref()).unwrap(), ca: false }));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[tokio::test]
    async fn reqwest_error_shows_the_mismatch() {
        // a TLS server with a self-signed certificate, and a pin of another one
        let k = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap().self_signed(&k).unwrap();
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(k.serialize_der().into());
        let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.der().clone()], key)
            .unwrap();
        let acc = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((s, _)) = l.accept().await {
                let _ = acc.accept(s).await;
            }
        });
        let d = dir("reqwest");
        std::fs::create_dir_all(&d).unwrap();
        let file = d.join("x.pin");
        preset(&file, &spki_pin(self_signed("localhost").as_ref()).unwrap(), false).unwrap();
        let c = pinned_client(&file, std::time::Duration::from_secs(5));
        let e = c.get(format!("https://localhost:{}/", port)).send().await.unwrap_err();
        assert!(mismatch_of(&e).is_some(), "{}", error_text(&e));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// The panel reads its own pin the way a new server will see it
    #[tokio::test]
    async fn the_probe_reads_the_key_and_the_ca_state() {
        let ca = Ca::new();
        let k = rcgen::KeyPair::generate().unwrap();
        let mut p = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        p.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        let leaf = p.signed_by(&k, &ca.cert, &ca.key).unwrap();
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(k.serialize_der().into());
        let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions().unwrap().with_no_client_auth().with_single_cert(vec![leaf.der().clone()], key).unwrap();
        let acc = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((s, _)) = l.accept().await {
                let _ = acc.accept(s).await;
            }
        });
        let (pin, ca_ok) = probe("localhost", port, Some(ca.roots())).await.unwrap();
        assert_eq!(pin, spki_pin(leaf.der()).unwrap());
        assert!(ca_ok);
        // the same certificate without its CA among the roots: pinned as self-signed
        let (pin2, ca2) = probe("localhost", port, Some(rustls::RootCertStore::empty())).await.unwrap();
        assert_eq!((pin2, ca2), (pin, false));
        // nothing listens: an error, not a pin
        assert!(probe("127.0.0.1", 1, None).await.is_err());
    }

    #[test]
    fn mismatch_is_found_in_the_error_chain() {
        let inner = std::io::Error::new(std::io::ErrorKind::InvalidData, rustls::Error::General(format!("{}: x", MISMATCH)));
        let outer = std::io::Error::other(inner);
        assert_eq!(mismatch_of(&outer).as_deref(), Some("certificate pin mismatch: x"));
        assert!(mismatch_of(&std::io::Error::other("timed out")).is_none());
    }
}
