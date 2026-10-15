//! DNS messages: just enough of RFC 1035 to read a question, answer it ourselves, and age the TTLs of
//! a cached upstream reply. Every read is bounds-checked: a malformed packet gives `None`, never a panic.

pub const A: u16 = 1;
pub const AAAA: u16 = 28;
pub const SVCB: u16 = 64;
pub const HTTPS: u16 = 65;
const OPT: u16 = 41;

pub const NOERROR: u8 = 0;
pub const FORMERR: u8 = 1;
pub const SERVFAIL: u8 = 2;
pub const REFUSED: u8 = 5;

#[derive(Debug, Clone, PartialEq)]
pub struct Question {
    pub id: u16,
    /// lower case, without the final dot ("" = the root)
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
    /// end of the question section (the header and the question are copied into every answer)
    pub end: usize,
}

fn u16_at(b: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(i)?, *b.get(i + 1)?]))
}

/// A standard query (QR = 0, opcode 0) with exactly one question.
pub fn parse_query(b: &[u8]) -> Option<Question> {
    if b.len() < 12 || b.len() > 65535 {
        return None;
    }
    let flags = u16_at(b, 2)?;
    if flags & 0x8000 != 0 || (flags >> 11) & 0xF != 0 || u16_at(b, 4)? != 1 {
        return None;
    }
    let mut i = 12;
    let mut name = String::new();
    loop {
        let l = *b.get(i)? as usize;
        i += 1;
        if l == 0 {
            break;
        }
        // no compression inside a question, and no extended label types
        if l > 63 {
            return None;
        }
        let label = b.get(i..i + l)?;
        i += l;
        if !name.is_empty() {
            name.push('.');
        }
        for &c in label {
            // a dot or a non-printable byte inside a label can only be an attack on string matching
            if c == b'.' || !(0x21..0x7f).contains(&c) {
                return None;
            }
            name.push(c.to_ascii_lowercase() as char);
        }
        if name.len() > 253 {
            return None;
        }
    }
    let qtype = u16_at(b, i)?;
    let qclass = u16_at(b, i + 2)?;
    Some(Question { id: u16_at(b, 0)?, name, qtype, qclass, end: i + 4 })
}

/// The id of a packet that is too broken to parse, so it can still get FORMERR.
pub fn id_of(b: &[u8]) -> Option<u16> {
    if b.len() >= 12 && b[2] & 0x80 == 0 { u16_at(b, 0) } else { None }
}

/// Header + question of the query, turned into a response with `rcode` and no records.
fn head(req: &[u8], q: &Question, rcode: u8, ancount: u16) -> Vec<u8> {
    let mut r = Vec::with_capacity(q.end + 16 * ancount as usize);
    r.extend_from_slice(&req[..q.end]);
    // QR=1, keep opcode and RD, RA=1, AD/CD/AA cleared
    let rd = req[2] & 0x01;
    r[2] = 0x80 | rd;
    r[3] = 0x80 | (rcode & 0x0F);
    r[6..8].copy_from_slice(&ancount.to_be_bytes());
    r[8..12].copy_from_slice(&[0, 0, 0, 0]);
    r
}

/// An answer with no records (NODATA when `rcode` is NOERROR).
pub fn empty(req: &[u8], q: &Question, rcode: u8) -> Vec<u8> {
    head(req, q, rcode, 0)
}

/// A bare error reply for a packet whose question could not be read.
pub fn error_for(req: &[u8], rcode: u8) -> Option<Vec<u8>> {
    let id = id_of(req)?;
    let mut r = vec![0u8; 12];
    r[0..2].copy_from_slice(&id.to_be_bytes());
    r[2] = 0x80 | (req[2] & 0x01);
    r[3] = 0x80 | (rcode & 0x0F);
    Some(r)
}

/// A records for the question's name.
pub fn answer_a(req: &[u8], q: &Question, ips: &[std::net::Ipv4Addr], ttl: u32) -> Vec<u8> {
    let mut r = head(req, q, NOERROR, ips.len() as u16);
    for ip in ips {
        // name = pointer to the question (offset 12)
        r.extend_from_slice(&[0xC0, 0x0C]);
        r.extend_from_slice(&A.to_be_bytes());
        r.extend_from_slice(&1u16.to_be_bytes());
        r.extend_from_slice(&ttl.to_be_bytes());
        r.extend_from_slice(&4u16.to_be_bytes());
        r.extend_from_slice(&ip.octets());
    }
    r
}

/// Position after a (possibly compressed) name that starts at `i`.
fn skip_name(b: &[u8], mut i: usize) -> Option<usize> {
    loop {
        let l = *b.get(i)?;
        match l & 0xC0 {
            0x00 => {
                if l == 0 {
                    return Some(i + 1);
                }
                i += 1 + l as usize;
                if i > b.len() {
                    return None;
                }
            }
            0xC0 => {
                b.get(i + 1)?;
                return Some(i + 2);
            }
            _ => return None,
        }
    }
}

/// Offsets of the TTL fields of every record except OPT, or None for a malformed reply.
fn ttl_offsets(b: &[u8]) -> Option<Vec<usize>> {
    let qd = u16_at(b, 4)? as usize;
    let rr = u16_at(b, 6)? as usize + u16_at(b, 8)? as usize + u16_at(b, 10)? as usize;
    let mut i = 12;
    for _ in 0..qd {
        i = skip_name(b, i)? + 4;
    }
    let mut out = Vec::with_capacity(rr);
    for _ in 0..rr {
        i = skip_name(b, i)?;
        let t = u16_at(b, i)?;
        let len = u16_at(b, i + 8)? as usize;
        if t != OPT {
            out.push(i + 4);
        }
        i += 10 + len;
        if i > b.len() {
            return None;
        }
    }
    Some(out)
}

pub fn rcode(b: &[u8]) -> u8 {
    b.get(3).map(|x| x & 0x0F).unwrap_or(SERVFAIL)
}

pub fn truncated(b: &[u8]) -> bool {
    b.get(2).map(|x| x & 0x02 != 0).unwrap_or(false)
}

/// The smallest TTL of the reply (None = malformed). A reply without records gets `empty_ttl`.
pub fn min_ttl(b: &[u8], empty_ttl: u32) -> Option<u32> {
    let offs = ttl_offsets(b)?;
    let mut m: Option<u32> = None;
    for o in offs {
        let t = u32::from_be_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]);
        m = Some(m.map_or(t, |x| x.min(t)));
    }
    Some(m.unwrap_or(empty_ttl))
}

/// Take `age` seconds off every TTL (cache hit). Returns false for a malformed reply.
pub fn age_ttls(b: &mut [u8], age: u32) -> bool {
    let Some(offs) = ttl_offsets(b) else { return false };
    for o in offs {
        let t = u32::from_be_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]);
        b[o..o + 4].copy_from_slice(&t.saturating_sub(age).to_be_bytes());
    }
    true
}

/// The A records of a reply (used to find where to send a relayed connection).
pub fn a_records(b: &[u8]) -> Vec<std::net::Ipv4Addr> {
    let mut out = vec![];
    let (Some(qd), Some(an)) = (u16_at(b, 4), u16_at(b, 6)) else { return out };
    let mut i = 12;
    for _ in 0..qd {
        match skip_name(b, i) {
            Some(x) => i = x + 4,
            None => return out,
        }
    }
    for _ in 0..an {
        let Some(x) = skip_name(b, i) else { return out };
        i = x;
        let (Some(t), Some(len)) = (u16_at(b, i), u16_at(b, i + 8)) else { return out };
        let len = len as usize;
        if t == A && len == 4 {
            if let Some(d) = b.get(i + 10..i + 14) {
                out.push(std::net::Ipv4Addr::new(d[0], d[1], d[2], d[3]));
            }
        }
        i += 10 + len;
    }
    out
}

/// A query for `name` / `qtype` with the given id (RD set, no EDNS).
pub fn build_query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut r = Vec::with_capacity(18 + name.len());
    r.extend_from_slice(&id.to_be_bytes());
    r.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for l in name.split('.').filter(|l| !l.is_empty()) {
        r.push(l.len().min(63) as u8);
        r.extend_from_slice(&l.as_bytes()[..l.len().min(63)]);
    }
    r.push(0);
    r.extend_from_slice(&qtype.to_be_bytes());
    r.extend_from_slice(&1u16.to_be_bytes());
    r
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn reply_with_a(q: &[u8], ttl: u32) -> Vec<u8> {
        let qq = parse_query(q).unwrap();
        answer_a(q, &qq, &[Ipv4Addr::new(1, 2, 3, 4), Ipv4Addr::new(5, 6, 7, 8)], ttl)
    }

    #[test]
    fn parses_and_answers() {
        let q = build_query(0x1234, "WWW.Example.COM", A);
        let p = parse_query(&q).unwrap();
        assert_eq!(p.id, 0x1234);
        assert_eq!(p.name, "www.example.com");
        assert_eq!((p.qtype, p.qclass, p.end), (A, 1, q.len()));
        let r = reply_with_a(&q, 300);
        assert_eq!(&r[0..2], &[0x12, 0x34]);
        assert_eq!(r[2] & 0x80, 0x80);
        assert_eq!(rcode(&r), NOERROR);
        assert_eq!(a_records(&r), vec![Ipv4Addr::new(1, 2, 3, 4), Ipv4Addr::new(5, 6, 7, 8)]);
        assert_eq!(min_ttl(&r, 0), Some(300));
        let e = empty(&q, &p, REFUSED);
        assert_eq!(rcode(&e), REFUSED);
        assert_eq!(&e[6..12], &[0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn ages_ttls() {
        let q = build_query(1, "a.b", A);
        let mut r = reply_with_a(&q, 100);
        assert!(age_ttls(&mut r, 30));
        assert_eq!(min_ttl(&r, 0), Some(70));
        assert!(age_ttls(&mut r, 500));
        assert_eq!(min_ttl(&r, 0), Some(0));
        assert_eq!(min_ttl(&empty(&q, &parse_query(&q).unwrap(), NOERROR), 42), Some(42));
    }

    #[test]
    fn root_and_refusals() {
        let q = build_query(7, "", A);
        assert_eq!(parse_query(&q).unwrap().name, "");
        // a response is not a query
        let mut r = q.clone();
        r[2] |= 0x80;
        assert!(parse_query(&r).is_none());
        // two questions
        let mut two = q.clone();
        two[5] = 2;
        assert!(parse_query(&two).is_none());
        // a dot inside a label
        let mut dot = build_query(1, "abc.de", A);
        dot[14] = b'.';
        assert!(parse_query(&dot).is_none());
        assert_eq!(error_for(&q, FORMERR).map(|r| rcode(&r)), Some(FORMERR));
    }

    #[test]
    fn never_panics_on_garbage() {
        let q = build_query(9, "x.example.org", AAAA);
        let r = reply_with_a(&build_query(9, "x.example.org", A), 60);
        // every prefix and every single-byte change of a query and a reply
        for base in [q, r] {
            for n in 0..=base.len() {
                let mut p = base[..n].to_vec();
                let _ = parse_query(&p);
                let _ = min_ttl(&p, 1);
                let _ = age_ttls(&mut p, 1);
                let _ = a_records(&p);
                let _ = error_for(&p, FORMERR);
            }
            for i in 0..base.len() {
                for v in [0u8, 0x3F, 0x40, 0xC0, 0xFF] {
                    let mut p = base.clone();
                    p[i] = v;
                    let _ = parse_query(&p);
                    let _ = min_ttl(&p, 1);
                    let _ = age_ttls(&mut p, 1);
                    let _ = a_records(&p);
                }
            }
        }
    }
}
