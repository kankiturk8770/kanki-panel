//! Certificate pinning (TOFU) for TLS channels that run without a public CA — the agent→panel
//! link on installs without a domain (INSECURE=1) and the panel→node link when a node has a
//! self-signed certificate.
//!
//! A certificate a public CA vouches for is accepted first and becomes the new pin (the panel has
//! a domain with a Let's Encrypt certificate; INSECURE=1 often only means the agent's own CA
//! bundle is old, and certbot renews with a new key every ~60 days). Otherwise the first
//! connection stores the peer certificate's SHA-256 fingerprint in a pin file; every later
//! connection must present the same certificate or it is refused. This closes the window
//! where a man-in-the-middle could keep impersonating the panel (tokens, tunnel specs and update
//! binaries all travel over this channel). For zero first-contact trust, copy the pin file by
//! hand or use a real certificate on a domain.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// The text every pin-mismatch error starts with (to tell it apart from "offline").
pub const MISMATCH: &str = "certificate pin mismatch";

/// A TLS server-certificate verifier: a CA-valid certificate is accepted (and re-pinned),
/// anything else must match the pin, or is pinned on first sight (TOFU).
#[derive(Debug)]
pub struct Pinned {
    pin_file: PathBuf,
    expected: Mutex<Option<String>>,
    provider: Arc<rustls::crypto::CryptoProvider>,
    /// the normal CA check; None when it cannot be built
    ca: Option<Arc<rustls::client::WebPkiServerVerifier>>,
}

fn read_pin(pin_file: &Path) -> Option<String> {
    std::fs::read_to_string(pin_file).ok().map(|s| s.trim().to_lowercase()).filter(|s| !s.is_empty())
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
        Arc::new(Pinned { expected: Mutex::new(read_pin(&pin_file)), pin_file, provider, ca })
    }

    fn write_pin(&self, fp: &str) -> bool {
        if let Some(dir) = self.pin_file.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        if std::fs::write(&self.pin_file, format!("{}\n", fp)).is_err() {
            return false;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&self.pin_file, std::fs::Permissions::from_mode(0o600));
        }
        true
    }

    fn fingerprint(cert: &rustls::pki_types::CertificateDer<'_>) -> String {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(cert.as_ref());
        hex::encode(h.finalize())
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
        // a certificate a public CA vouches for needs no pin: accept it and pin it, so a renewal
        // (new key) never locks the agent out
        if let Some(ca) = &self.ca {
            if ca.verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now).is_ok() {
                let mut expected = self.expected.lock().unwrap_or_else(|e| e.into_inner());
                if expected.as_deref() != Some(fp.as_str()) && self.write_pin(&fp) {
                    *expected = Some(fp);
                }
                return Ok(rustls::client::danger::ServerCertVerified::assertion());
            }
        }
        let mut expected = self.expected.lock().unwrap_or_else(|e| e.into_inner());
        if expected.as_deref() == Some(fp.as_str()) {
            return Ok(rustls::client::danger::ServerCertVerified::assertion());
        }
        // the pin file may have been changed or deleted by hand since it was read
        *expected = read_pin(&self.pin_file);
        match &*expected {
            Some(pin) if *pin == fp => Ok(rustls::client::danger::ServerCertVerified::assertion()),
            Some(pin) => Err(rustls::Error::General(format!(
                "{}: the server shows certificate {} but {} is pinned — refusing to connect (possible MITM). If the certificate was changed on purpose (reinstall, new self-signed certificate), delete the pin file {}",
                MISMATCH, fp, pin, self.pin_file.display()
            ))),
            None => {
                // trust on first use
                if self.write_pin(&fp) {
                    *expected = Some(fp);
                    Ok(rustls::client::danger::ServerCertVerified::assertion())
                } else {
                    Err(rustls::Error::General(format!("cannot write the certificate pin file {}", self.pin_file.display())))
                }
            }
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

/// An HTTP client that pins the peer certificate (TOFU) instead of checking a CA. Use it for
/// channels that would otherwise run with certificate verification fully off.
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
        .use_preconfigured_tls(cfg)
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

    #[test]
    fn ca_valid_certificate_is_accepted_and_repinned() {
        // a private CA stands in for Let's Encrypt
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut ca_params = rcgen::CertificateParams::new(vec![]).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca.der().clone()).unwrap();
        let leaf = |host: &str| {
            let k = rcgen::KeyPair::generate().unwrap();
            let mut p = rcgen::CertificateParams::new(vec![host.to_string()]).unwrap();
            p.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
            p.signed_by(&k, &ca, &ca_key).unwrap().der().clone()
        };
        let d = dir("ca");
        let file = d.join("panel.pin");
        // an old pin from before the renewal
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(&file, "00ff\n").unwrap();
        let p = Pinned::with_roots(file.clone(), roots);
        let renewed = leaf("panel.example.com");
        assert!(check(&p, &renewed, &[], "panel.example.com").is_ok());
        assert_eq!(read_pin(&file).unwrap(), Pinned::fingerprint(&renewed));
        // a second renewal (new key) is fine too
        let again = leaf("panel.example.com");
        assert!(check(&p, &again, &[], "panel.example.com").is_ok());
        assert_eq!(read_pin(&file).unwrap(), Pinned::fingerprint(&again));
        // valid chain but the wrong name: falls back to the pin, which does not match
        let other = leaf("evil.example.com");
        let e = check(&p, &other, &[], "panel.example.com").unwrap_err();
        assert!(e.to_string().contains(MISMATCH));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn self_signed_is_pinned_on_first_use() {
        let d = dir("tofu");
        let file = d.join("node.pin");
        let p = Pinned::load(file.clone());
        let first = self_signed("node.example.com");
        assert!(check(&p, &first, &[], "node.example.com").is_ok());
        assert_eq!(read_pin(&file).unwrap(), Pinned::fingerprint(&first));
        assert!(check(&p, &first, &[], "node.example.com").is_ok());
        // a different certificate is refused
        let second = self_signed("node.example.com");
        let e = check(&p, &second, &[], "node.example.com").unwrap_err();
        assert!(e.to_string().contains(MISMATCH));
        // deleting the pin file resets it without a restart
        std::fs::remove_file(&file).unwrap();
        assert!(check(&p, &second, &[], "node.example.com").is_ok());
        assert_eq!(read_pin(&file).unwrap(), Pinned::fingerprint(&second));
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
        std::fs::write(&file, "00ff\n").unwrap();
        let c = pinned_client(&file, std::time::Duration::from_secs(5));
        let e = c.get(format!("https://localhost:{}/", port)).send().await.unwrap_err();
        assert!(mismatch_of(&e).is_some(), "{}", error_text(&e));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn mismatch_is_found_in_the_error_chain() {
        let inner = std::io::Error::new(std::io::ErrorKind::InvalidData, rustls::Error::General(format!("{}: x", MISMATCH)));
        let outer = std::io::Error::other(inner);
        assert_eq!(mismatch_of(&outer).as_deref(), Some("certificate pin mismatch: x"));
        assert!(mismatch_of(&std::io::Error::other("timed out")).is_none());
    }
}
