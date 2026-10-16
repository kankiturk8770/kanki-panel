//! Certificates and DNS records for Kanki DNS, made by the panel itself through the DNS provider's API
//! (Cloudflare or ArvanCloud): an A record for every DNS server and for `*.` it (each subscriber's DoT
//! name), and one Let's Encrypt certificate for all of them with the DNS-01 challenge. Nothing has to
//! reach the DNS servers from outside, so it works for servers inside Iran too.
use super::panel::{self, DnsSettings};
use crate::util::now;
use crate::App;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;

const RENEW_AFTER: i64 = 60 * 86400;

struct Prov<'a> {
    app: &'a App,
    kind: &'a str,
    token: &'a str,
}

impl Prov<'_> {
    fn req(&self, m: reqwest::Method, url: &str) -> reqwest::RequestBuilder {
        let r = self.app.http.request(m, url).timeout(Duration::from_secs(30));
        match self.kind {
            "cloudflare" => r.bearer_auth(self.token),
            _ => {
                let t = self.token.trim();
                r.header("Authorization", if t.to_ascii_lowercase().starts_with("apikey ") { t.to_string() } else { format!("Apikey {}", t) })
            }
        }
    }

    async fn json(&self, r: reqwest::RequestBuilder) -> Result<Value, String> {
        let resp = r.send().await.map_err(|e| format!("{} API: {}", self.kind, e))?;
        let st = resp.status();
        let v: Value = resp.json().await.unwrap_or(Value::Null);
        if !st.is_success() || v["success"].as_bool() == Some(false) {
            let msg = v["errors"][0]["message"].as_str().or(v["message"].as_str()).unwrap_or("").to_string();
            return Err(format!("{} API {}: {}", self.kind, st.as_u16(), msg));
        }
        Ok(v)
    }

    /// (zone id or name, zone name) holding `name`
    async fn zone(&self, name: &str) -> Result<(String, String), String> {
        let labels: Vec<&str> = name.split('.').collect();
        for i in 0..labels.len().saturating_sub(1) {
            let cand = labels[i..].join(".");
            match self.kind {
                "cloudflare" => {
                    let v = self.json(self.req(reqwest::Method::GET, &format!("https://api.cloudflare.com/client/v4/zones?name={}", cand))).await?;
                    if let Some(id) = v["result"][0]["id"].as_str() {
                        return Ok((id.to_string(), cand));
                    }
                }
                _ => {
                    if self.json(self.req(reqwest::Method::GET, &format!("https://napi.arvancloud.ir/cdn/4.0/domains/{}", cand))).await.is_ok() {
                        return Ok((cand.clone(), cand));
                    }
                }
            }
        }
        Err(format!("no zone for {} in this {} account", name, self.kind))
    }

    /// existing records of `name` and `typ`: their ids
    async fn find(&self, zone: &(String, String), name: &str, typ: &str) -> Result<Vec<String>, String> {
        match self.kind {
            "cloudflare" => {
                let v = self.json(self.req(reqwest::Method::GET, &format!("https://api.cloudflare.com/client/v4/zones/{}/dns_records?type={}&name={}", zone.0, typ, name))).await?;
                Ok(v["result"].as_array().into_iter().flatten().filter_map(|r| r["id"].as_str().map(|s| s.to_string())).collect())
            }
            _ => {
                let rel = relative(name, &zone.1);
                let v = self.json(self.req(reqwest::Method::GET, &format!("https://napi.arvancloud.ir/cdn/4.0/domains/{}/dns-records?search={}", zone.0, rel))).await?;
                Ok(v["data"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter(|r| r["type"].as_str().map(|t| t.eq_ignore_ascii_case(typ)).unwrap_or(false) && r["name"].as_str() == Some(rel.as_str()))
                    .filter_map(|r| r["id"].as_str().map(|s| s.to_string()))
                    .collect())
            }
        }
    }

    async fn delete(&self, zone: &(String, String), id: &str) {
        let url = match self.kind {
            "cloudflare" => format!("https://api.cloudflare.com/client/v4/zones/{}/dns_records/{}", zone.0, id),
            _ => format!("https://napi.arvancloud.ir/cdn/4.0/domains/{}/dns-records/{}", zone.0, id),
        };
        let _ = self.json(self.req(reqwest::Method::DELETE, &url)).await;
    }

    async fn create(&self, zone: &(String, String), name: &str, typ: &str, value: &str) -> Result<String, String> {
        let (url, body) = match self.kind {
            "cloudflare" => (
                format!("https://api.cloudflare.com/client/v4/zones/{}/dns_records", zone.0),
                json!({ "type": typ, "name": name, "content": value, "ttl": 120, "proxied": false }),
            ),
            _ => {
                let rel = relative(name, &zone.1);
                let v = if typ == "A" { json!([{ "ip": value }]) } else { json!({ "text": value }) };
                (
                    format!("https://napi.arvancloud.ir/cdn/4.0/domains/{}/dns-records", zone.0),
                    json!({ "type": typ.to_ascii_lowercase(), "name": rel, "value": v, "ttl": 120, "cloud": false }),
                )
            }
        };
        let v = self.json(self.req(reqwest::Method::POST, &url).json(&body)).await?;
        Ok(v["result"]["id"].as_str().or(v["data"]["id"].as_str()).unwrap_or("").to_string())
    }

    /// `name` A `ip`, replacing whatever A records it had
    async fn set_a(&self, name: &str, ip: &str) -> Result<(), String> {
        let zone = self.zone(name.trim_start_matches("*.")).await?;
        for id in self.find(&zone, name, "A").await? {
            self.delete(&zone, &id).await;
        }
        self.create(&zone, name, "A", ip).await.map(|_| ())
    }
}

fn relative(name: &str, zone: &str) -> String {
    match name.strip_suffix(zone).map(|p| p.trim_end_matches('.')) {
        Some("") => "@".into(),
        Some(p) => p.to_string(),
        None => name.to_string(),
    }
}

/// The names the certificate must cover: every DNS server and `*.` it.
pub fn cert_names(s: &DnsSettings) -> Vec<String> {
    let mut v = vec![];
    for x in &s.servers {
        let h = panel::host_of(s, x);
        if !h.is_empty() {
            v.push(h.clone());
            v.push(format!("*.{}", h));
        }
    }
    v
}

/// A records for every DNS server (and `*.` it).
pub async fn sync_records(app: &App, s: &DnsSettings) -> Result<usize, String> {
    let p = Prov { app, kind: &s.provider, token: &s.api_token };
    let mut n = 0;
    for x in &s.servers {
        let h = panel::host_of(s, x);
        let ip = panel::answer_ip(x);
        if h.is_empty() || ip.is_empty() {
            continue;
        }
        p.set_a(&h, &ip).await?;
        p.set_a(&format!("*.{}", h), &ip).await?;
        n += 1;
    }
    Ok(n)
}

/// Get a new certificate for every DNS server name. Returns (chain PEM, key PEM).
pub async fn issue(app: &App, s: &DnsSettings) -> Result<(String, String), String> {
    let names = cert_names(s);
    if names.is_empty() {
        return Err("no DNS server has a name yet: set the DNS domain and the server labels".into());
    }
    issue_for(app, &s.provider, &s.api_token, &s.email, &names).await
}

/// Point `name` at `ip` (an A record) with the provider's API.
pub async fn set_a_record(app: &App, kind: &str, token: &str, name: &str, ip: &str) -> Result<(), String> {
    Prov { app, kind, token }.set_a(name, ip).await
}

/// A Let's Encrypt certificate for `names` with the DNS-01 challenge through the provider's API (Cloudflare
/// or ArvanCloud). Returns (chain PEM, key PEM).
pub async fn issue_for(app: &App, kind: &str, token: &str, email: &str, names: &[String]) -> Result<(String, String), String> {
    use instant_acme::{Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, LetsEncrypt, NewAccount, NewOrder, OrderStatus, RetryPolicy};
    let names = names.to_vec();
    let p = Prov { app, kind, token };
    let e = |x: instant_acme::Error| format!("Let's Encrypt: {}", x);
    // one account, kept for renewals
    let creds: Option<AccountCredentials> = serde_json::from_str(&app.db.get("dns_acme_account")).ok();
    let account = match creds {
        Some(c) => Account::builder().map_err(e)?.from_credentials(c).await.map_err(e)?,
        None => {
            let contact = if email.trim().is_empty() { vec![] } else { vec![format!("mailto:{}", email.trim())] };
            let contact: Vec<&str> = contact.iter().map(|x| x.as_str()).collect();
            let (a, c) = Account::builder()
                .map_err(e)?
                .create(&NewAccount { contact: &contact, terms_of_service_agreed: true, only_return_existing: false }, LetsEncrypt::Production.url().to_owned(), None)
                .await
                .map_err(e)?;
            app.db.set("dns_acme_account", &serde_json::to_string(&c).unwrap_or_default());
            a
        }
    };
    let ids: Vec<Identifier> = names.iter().map(|n| Identifier::Dns(n.clone())).collect();
    let mut order = account.new_order(&NewOrder::new(&ids)).await.map_err(e)?;
    // 1. every TXT record first (a name and its wildcard share one TXT name)
    let mut made: Vec<((String, String), String)> = vec![];
    let mut todo = false;
    {
        let mut auths = order.authorizations();
        while let Some(a) = auths.next().await {
            let mut a = a.map_err(e)?;
            if matches!(a.status, AuthorizationStatus::Valid) {
                continue;
            }
            todo = true;
            let ch = a.challenge(ChallengeType::Dns01).ok_or("Let's Encrypt offered no DNS challenge")?;
            let Identifier::Dns(d) = ch.identifier().identifier else { continue };
            let rec = format!("_acme-challenge.{}", d);
            let zone = p.zone(d).await?;
            let id = p.create(&zone, &rec, "TXT", &ch.key_authorization().dns_value()).await?;
            made.push((zone, id));
        }
    }
    let result = async {
        if todo {
            // let the provider's name servers see the records
            tokio::time::sleep(Duration::from_secs(30)).await;
            let mut auths = order.authorizations();
            while let Some(a) = auths.next().await {
                let mut a = a.map_err(e)?;
                if matches!(a.status, AuthorizationStatus::Valid) {
                    continue;
                }
                if let Some(mut ch) = a.challenge(ChallengeType::Dns01) {
                    ch.set_ready().await.map_err(e)?;
                }
            }
        }
        let st = order.poll_ready(&RetryPolicy::new().timeout(Duration::from_secs(180))).await.map_err(e)?;
        if st != OrderStatus::Ready {
            return Err(format!("Let's Encrypt did not accept the DNS records ({:?})", st));
        }
        let key = rcgen::KeyPair::generate().map_err(|x| x.to_string())?;
        let params = rcgen::CertificateParams::new(names.clone()).map_err(|x| x.to_string())?;
        let csr = params.serialize_request(&key).map_err(|x| x.to_string())?;
        order.finalize_csr(csr.der()).await.map_err(e)?;
        let chain = order.poll_certificate(&RetryPolicy::new().timeout(Duration::from_secs(120))).await.map_err(e)?;
        Ok((chain, key.serialize_pem()))
    }
    .await;
    for (zone, id) in made {
        if !id.is_empty() {
            p.delete(&zone, &id).await;
        }
    }
    result
}

/// Records + certificate now; saves the result in the settings.
pub async fn run_once(app: &App) -> Result<String, String> {
    let s = panel::settings(app);
    if s.provider.is_empty() || s.api_token.is_empty() {
        return Err("choose the DNS provider (Cloudflare or ArvanCloud) and give its API token".into());
    }
    let n = sync_records(app, &s).await?;
    let (cert, key) = issue(app, &s).await?;
    let names = cert_names(&s).join(",");
    panel::update(app, |x| {
        x.cert = cert.clone();
        x.key = key.clone();
        x.cert_at = now();
        x.cert_names = names.clone();
        x.acme_err.clear();
    });
    Ok(format!("{} server name(s) set, certificate issued", n))
}

/// Daily: keep the records and the certificate fresh (new servers, renamed labels, 60 days old).
pub async fn renew_loop(app: Arc<App>) {
    tokio::time::sleep(Duration::from_secs(120)).await;
    loop {
        let s = panel::settings(&app);
        let due = s.on
            && !s.provider.is_empty()
            && !s.api_token.is_empty()
            && !cert_names(&s).is_empty()
            && (s.cert.is_empty() || now() - s.cert_at > RENEW_AFTER || s.cert_names != cert_names(&s).join(","));
        if due {
            match run_once(&app).await {
                Ok(m) => eprintln!("dns certificate: {}", m),
                Err(err) => {
                    eprintln!("dns certificate: {}", err);
                    panel::update(&app, |x| x.acme_err = err.clone());
                }
            }
        }
        tokio::time::sleep(Duration::from_secs(6 * 3600)).await;
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn relative_names() {
        assert_eq!(super::relative("_acme-challenge.de.dns.kanki.pro", "kanki.pro"), "_acme-challenge.de.dns");
        assert_eq!(super::relative("kanki.pro", "kanki.pro"), "@");
        assert_eq!(super::relative("*.de.dns.kanki.pro", "kanki.pro"), "*.de.dns");
    }
}
