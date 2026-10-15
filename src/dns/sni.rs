//! Reading where a connection wants to go without terminating it: the SNI of a TLS ClientHello and the
//! Host of a plain HTTP request. Both readers only look at bytes already received and never panic.

/// How much of a ClientHello we wait for (a post-quantum hello is ~1.8 KB; 16 KB is one full record)
pub const MAX_HELLO: usize = 16 * 1024 + 5;
pub const MAX_HTTP_HEAD: usize = 8 * 1024;

pub enum Hello {
    /// the server name (lower case; empty = the hello has no SNI)
    Name(String),
    /// read more bytes first
    More,
    /// not TLS, or a broken hello
    Bad,
}

fn u16_at(b: &[u8], i: usize) -> Option<usize> {
    Some(u16::from_be_bytes([*b.get(i)?, *b.get(i + 1)?]) as usize)
}

/// The handshake bytes carried by the TLS records received so far (a hello may span records).
fn handshake_bytes(b: &[u8]) -> Result<Vec<u8>, bool> {
    let mut out = vec![];
    let mut i = 0;
    while i < b.len() {
        if b.len() < i + 5 {
            return Err(true);
        }
        // handshake record, TLS 1.0 .. 1.3 record versions
        if b[i] != 0x16 || b[i + 1] != 0x03 {
            return Err(false);
        }
        let len = u16_at(b, i + 3).ok_or(true)?;
        if len == 0 || len > 16384 + 256 {
            return Err(false);
        }
        if b.len() < i + 5 + len {
            out.extend_from_slice(&b[i + 5..]);
            return Ok(out);
        }
        out.extend_from_slice(&b[i + 5..i + 5 + len]);
        i += 5 + len;
    }
    Ok(out)
}

/// The SNI of a ClientHello from the bytes received so far.
pub fn client_hello_sni(b: &[u8]) -> Hello {
    let hs = match handshake_bytes(b) {
        Ok(h) => h,
        Err(true) => return Hello::More,
        Err(false) => return Hello::Bad,
    };
    if hs.len() < 4 {
        return Hello::More;
    }
    if hs[0] != 0x01 {
        return Hello::Bad;
    }
    let body_len = ((hs[1] as usize) << 16) | ((hs[2] as usize) << 8) | hs[3] as usize;
    if body_len > MAX_HELLO {
        return Hello::Bad;
    }
    if hs.len() < 4 + body_len {
        return if b.len() >= MAX_HELLO { Hello::Bad } else { Hello::More };
    }
    match parse_body(&hs[4..4 + body_len]) {
        Some(s) => Hello::Name(s),
        None => Hello::Bad,
    }
}

fn parse_body(h: &[u8]) -> Option<String> {
    // version(2) random(32)
    let mut i = 34;
    let sid = *h.get(i)? as usize;
    i += 1 + sid;
    let cs = u16_at(h, i)?;
    i += 2 + cs;
    let cm = *h.get(i)? as usize;
    i += 1 + cm;
    if i == h.len() {
        return Some(String::new());
    }
    let ext_len = u16_at(h, i)?;
    i += 2;
    let end = i + ext_len;
    if end > h.len() {
        return None;
    }
    while i + 4 <= end {
        let t = u16_at(h, i)?;
        let l = u16_at(h, i + 2)?;
        i += 4;
        if i + l > end {
            return None;
        }
        if t == 0 {
            // server_name list: len(2) then entries type(1) len(2) name
            let e = &h[i..i + l];
            let mut j = 2;
            while j + 3 <= e.len() {
                let nt = e[j];
                let nl = u16_at(e, j + 1)?;
                let name = e.get(j + 3..j + 3 + nl)?;
                if nt == 0 {
                    return clean_host(name);
                }
                j += 3 + nl;
            }
            return None;
        }
        i += l;
    }
    Some(String::new())
}

/// A host name that is safe to match and dial: letters, digits, '-', '.', '_', at most 253 bytes.
fn clean_host(b: &[u8]) -> Option<String> {
    if b.is_empty() || b.len() > 253 {
        return None;
    }
    let s = std::str::from_utf8(b).ok()?.trim_end_matches('.').to_ascii_lowercase();
    if s.is_empty() || !s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'.' || c == b'_') {
        return None;
    }
    Some(s)
}

pub enum Head {
    /// (host without the port, path)
    Req(String, String),
    More,
    Bad,
}

/// The Host header and path of a plain HTTP request from the bytes received so far.
pub fn http_host(b: &[u8]) -> Head {
    let Some(end) = b.windows(4).position(|w| w == b"\r\n\r\n") else {
        return if b.len() >= MAX_HTTP_HEAD { Head::Bad } else { Head::More };
    };
    let Ok(text) = std::str::from_utf8(&b[..end]) else { return Head::Bad };
    let mut lines = text.split("\r\n");
    let first = lines.next().unwrap_or("");
    let mut parts = first.split(' ');
    let (Some(_method), Some(path)) = (parts.next(), parts.next()) else { return Head::Bad };
    for l in lines {
        if let Some((k, v)) = l.split_once(':') {
            if k.trim().eq_ignore_ascii_case("host") {
                let v = v.trim();
                // [v6]:port or host:port
                let host = if v.starts_with('[') { v.split(']').next().unwrap_or("").trim_start_matches('[') } else { v.rsplit_once(':').map(|x| x.0).unwrap_or(v) };
                return match clean_host(host.as_bytes()).or_else(|| host.parse::<std::net::IpAddr>().ok().map(|i| i.to_string())) {
                    Some(h) => Head::Req(h, path.to_string()),
                    None => Head::Bad,
                };
            }
        }
    }
    Head::Bad
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// a minimal but well-formed ClientHello with the given SNI (None = no SNI extension)
    pub fn hello(sni: Option<&str>) -> Vec<u8> {
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[7u8; 32]);
        body.push(0);
        body.extend_from_slice(&[0, 2, 0x13, 0x01]);
        body.extend_from_slice(&[1, 0]);
        let mut ext = vec![];
        // an unrelated extension first
        ext.extend_from_slice(&[0x00, 0x0b, 0x00, 0x02, 0x01, 0x00]);
        if let Some(s) = sni {
            let n = s.as_bytes();
            let list_len = 3 + n.len();
            ext.extend_from_slice(&[0, 0]);
            ext.extend_from_slice(&((list_len + 2) as u16).to_be_bytes());
            ext.extend_from_slice(&(list_len as u16).to_be_bytes());
            ext.push(0);
            ext.extend_from_slice(&(n.len() as u16).to_be_bytes());
            ext.extend_from_slice(n);
        }
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);
        let mut hs = vec![0x01, 0, (body.len() >> 8) as u8, body.len() as u8];
        hs.extend_from_slice(&body);
        let mut rec = vec![0x16, 0x03, 0x01];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    fn name(b: &[u8]) -> Option<String> {
        match client_hello_sni(b) {
            Hello::Name(s) => Some(s),
            _ => None,
        }
    }

    #[test]
    fn reads_sni() {
        let h = hello(Some("Download.Example.COM"));
        assert_eq!(name(&h).as_deref(), Some("download.example.com"));
        assert_eq!(name(&hello(None)).as_deref(), Some(""));
        // partial: wants more
        for n in 0..h.len() {
            assert!(matches!(client_hello_sni(&h[..n]), Hello::More), "{}", n);
        }
        // the hello split over two records
        let hs = &h[5..];
        let mut two = vec![0x16, 0x03, 0x01, 0, 10];
        two.extend_from_slice(&hs[..10]);
        two.extend_from_slice(&[0x16, 0x03, 0x01]);
        two.extend_from_slice(&((hs.len() - 10) as u16).to_be_bytes());
        two.extend_from_slice(&hs[10..]);
        assert_eq!(name(&two).as_deref(), Some("download.example.com"));
        assert!(matches!(client_hello_sni(b"GET / HTTP/1.1\r\n"), Hello::Bad));
        assert!(name(&hello(Some("bad host"))).is_none());
    }

    #[test]
    fn hello_never_panics() {
        let h = hello(Some("a.example.com"));
        for i in 0..h.len() {
            for v in [0u8, 1, 0x7f, 0xff] {
                let mut p = h.clone();
                p[i] = v;
                let _ = client_hello_sni(&p);
            }
        }
    }

    #[test]
    fn reads_http_host() {
        let r = b"GET /x/y HTTP/1.1\r\nUser-Agent: a\r\nHost: Gs2.WW.Prod.DL.PlayStation.net:80\r\n\r\n";
        match http_host(r) {
            Head::Req(h, p) => {
                assert_eq!(h, "gs2.ww.prod.dl.playstation.net");
                assert_eq!(p, "/x/y");
            }
            _ => panic!(),
        }
        assert!(matches!(http_host(b"GET / HTTP/1.1\r\nHost: a"), Head::More));
        assert!(matches!(http_host(b"GET / HTTP/1.1\r\n\r\n"), Head::Bad));
        match http_host(b"GET /kdns/r/abc HTTP/1.1\r\nHost: 1.2.3.4\r\n\r\n") {
            Head::Req(h, _) => assert_eq!(h, "1.2.3.4"),
            _ => panic!(),
        }
    }
}
