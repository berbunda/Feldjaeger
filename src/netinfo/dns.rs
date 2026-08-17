//! Reverse DNS (PTR) lookup (follow-up to Roadmap §3:131 — AS-range REALITY candidate scan).
//!
//! `std::net` only resolves forward (name → IP); there is no portable PTR lookup in `std`. Rather
//! than pull in a DNS crate, this hand-rolls a minimal RFC 1035 client — a single UDP query/
//! response for one PTR record — the same "implement the simple protocol ourselves" choice
//! already made for the whois client in the parent module. Queries a hardcoded public resolver
//! (Cloudflare, falling back to Google) rather than the OS-configured resolver: this scan
//! deliberately wants one canonical, internet-facing answer for "what does this IP publicly
//! reverse-resolve to," not whatever a corporate/split-horizon DNS setup might locally override.

use std::net::{Ipv4Addr, UdpSocket};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::{NetInfoError, NetInfoErrorKind, NetInfoResult};

const DNS_RESOLVERS: [&str; 2] = ["1.1.1.1:53", "8.8.8.8:53"];
const DNS_TIMEOUT: Duration = Duration::from_secs(5);
/// DNS-over-UDP responses without EDNS are capped at 512 bytes; a single PTR answer is small.
const MAX_UDP_RESPONSE: usize = 512;
/// Guards against a malformed/malicious response with a compression-pointer loop.
const MAX_NAME_POINTER_JUMPS: u8 = 20;

const QTYPE_PTR: u16 = 12;
const QCLASS_IN: u16 = 1;

/// Looks up the PTR (reverse DNS) record for `ip`, trying each resolver in [`DNS_RESOLVERS`] in
/// order until one answers.
pub fn reverse_dns_lookup(ip: Ipv4Addr) -> NetInfoResult<String> {
    let mut last_error = None;
    for resolver in DNS_RESOLVERS {
        match query_ptr(ip, resolver) {
            Ok(name) => return Ok(name),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        NetInfoError::new(
            NetInfoErrorKind::ConnectionFailed,
            "no DNS resolver reachable".to_owned(),
        )
    }))
}

fn query_ptr(ip: Ipv4Addr, resolver: &str) -> NetInfoResult<String> {
    let socket = UdpSocket::bind("0.0.0.0:0").map_err(|error| {
        NetInfoError::new(
            NetInfoErrorKind::ConnectionFailed,
            format!("could not open a UDP socket: {error}"),
        )
    })?;
    socket.set_read_timeout(Some(DNS_TIMEOUT)).ok();
    socket.set_write_timeout(Some(DNS_TIMEOUT)).ok();

    let id = query_id();
    let query = build_ptr_query(ip, id);
    socket.send_to(&query, resolver).map_err(|error| {
        NetInfoError::new(
            NetInfoErrorKind::ConnectionFailed,
            format!("could not send DNS query to {resolver}: {error}"),
        )
    })?;

    let mut buf = [0u8; MAX_UDP_RESPONSE];
    let (len, _from) = socket.recv_from(&mut buf).map_err(|error| {
        NetInfoError::new(
            NetInfoErrorKind::ConnectionFailed,
            format!("no response from {resolver}: {error}"),
        )
    })?;

    parse_ptr_response(&buf[..len], id)
}

/// Not cryptographically random — this query ID only needs to distinguish our own request from a
/// stale/unrelated UDP packet, not resist an active off-path attacker; this is a read-only
/// reconnaissance tool, not a security boundary.
fn query_id() -> u16 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    (nanos as u16) ^ 0xA5A5
}

/// Builds a standard RFC 1035 query for the PTR record of `A.B.C.D.in-addr.arpa` (IPv4 reverse
/// zone — octets in reverse order).
fn build_ptr_query(ip: Ipv4Addr, id: u16) -> Vec<u8> {
    let mut packet = Vec::with_capacity(32);
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&0x0100u16.to_be_bytes()); // standard query, recursion desired
    packet.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    packet.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    packet.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    packet.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

    for octet in ip.octets().iter().rev() {
        let label = octet.to_string();
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(7);
    packet.extend_from_slice(b"in-addr");
    packet.push(4);
    packet.extend_from_slice(b"arpa");
    packet.push(0); // root label

    packet.extend_from_slice(&QTYPE_PTR.to_be_bytes());
    packet.extend_from_slice(&QCLASS_IN.to_be_bytes());
    packet
}

fn parse_ptr_response(buf: &[u8], expected_id: u16) -> NetInfoResult<String> {
    if buf.len() < 12 {
        return Err(truncated());
    }
    let id = u16::from_be_bytes([buf[0], buf[1]]);
    if id != expected_id {
        return Err(NetInfoError::new(
            NetInfoErrorKind::ParseFailed,
            "DNS response ID mismatch".to_owned(),
        ));
    }
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    let rcode = flags & 0x000F;
    if rcode != 0 {
        return Err(NetInfoError::new(
            NetInfoErrorKind::ResolutionFailed,
            format!("DNS server returned RCODE {rcode}"),
        ));
    }
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;

    let mut pos = 12;
    for _ in 0..qdcount {
        let (_name, next) = parse_name(buf, pos)?;
        pos = next
            .checked_add(4) // QTYPE + QCLASS
            .filter(|&p| p <= buf.len())
            .ok_or_else(truncated)?;
    }

    for _ in 0..ancount {
        let (_name, next) = parse_name(buf, pos)?;
        pos = next;
        let header = buf.get(pos..pos + 10).ok_or_else(truncated)?;
        let rtype = u16::from_be_bytes([header[0], header[1]]);
        let rdlength = u16::from_be_bytes([header[8], header[9]]) as usize;
        let rdata_start = pos + 10;
        let rdata_end = rdata_start.checked_add(rdlength).ok_or_else(truncated)?;
        if rdata_end > buf.len() {
            return Err(truncated());
        }
        if rtype == QTYPE_PTR {
            let (ptr_name, _) = parse_name(buf, rdata_start)?;
            return Ok(ptr_name);
        }
        pos = rdata_end;
    }

    Err(NetInfoError::new(
        NetInfoErrorKind::ResolutionFailed,
        "no PTR record in DNS response".to_owned(),
    ))
}

/// Parses a (possibly compressed) domain name starting at `start`, returning the decoded dotted
/// name and the position immediately after it in the *caller's* stream — i.e. after the pointer
/// itself when one is followed, not after wherever the pointer led.
fn parse_name(buf: &[u8], start: usize) -> NetInfoResult<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut pos = start;
    let mut end_pos: Option<usize> = None;
    let mut jumps = 0u8;

    loop {
        let len_byte = *buf.get(pos).ok_or_else(truncated)?;
        if len_byte == 0 {
            if end_pos.is_none() {
                end_pos = Some(pos + 1);
            }
            break;
        } else if len_byte & 0xC0 == 0xC0 {
            let second = *buf.get(pos + 1).ok_or_else(truncated)?;
            let offset = (((len_byte as usize) & 0x3F) << 8) | second as usize;
            if end_pos.is_none() {
                end_pos = Some(pos + 2);
            }
            jumps += 1;
            if jumps > MAX_NAME_POINTER_JUMPS {
                return Err(NetInfoError::new(
                    NetInfoErrorKind::ParseFailed,
                    "DNS name compression pointer loop".to_owned(),
                ));
            }
            pos = offset;
        } else if len_byte & 0xC0 != 0 {
            return Err(NetInfoError::new(
                NetInfoErrorKind::ParseFailed,
                "invalid DNS label length byte".to_owned(),
            ));
        } else {
            let label_len = len_byte as usize;
            let label_start = pos + 1;
            let label_end = label_start + label_len;
            let label_bytes = buf.get(label_start..label_end).ok_or_else(truncated)?;
            labels.push(String::from_utf8_lossy(label_bytes).into_owned());
            pos = label_end;
        }
    }

    Ok((labels.join("."), end_pos.unwrap_or(pos)))
}

fn truncated() -> NetInfoError {
    NetInfoError::new(
        NetInfoErrorKind::ParseFailed,
        "truncated DNS response".to_owned(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(id: u16, flags: u16, qd: u16, an: u16) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&id.to_be_bytes());
        buf.extend_from_slice(&flags.to_be_bytes());
        buf.extend_from_slice(&qd.to_be_bytes());
        buf.extend_from_slice(&an.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf
    }

    fn encode_name(name: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        for label in name.split('.') {
            buf.push(label.len() as u8);
            buf.extend_from_slice(label.as_bytes());
        }
        buf.push(0);
        buf
    }

    #[test]
    fn builds_reversed_in_addr_arpa_query() {
        let query = build_ptr_query("8.8.4.4".parse().unwrap(), 0x1234);
        // Header (12 bytes) then question: 1.4.4.8.4.8.4.4? no -- reversed octets of 8.8.4.4 are
        // 4.4.8.8, so the QNAME is 4.4.8.8.in-addr.arpa.
        let mut expected_question = Vec::new();
        for label in ["4", "4", "8", "8", "in-addr", "arpa"] {
            expected_question.push(label.len() as u8);
            expected_question.extend_from_slice(label.as_bytes());
        }
        expected_question.push(0);
        expected_question.extend_from_slice(&QTYPE_PTR.to_be_bytes());
        expected_question.extend_from_slice(&QCLASS_IN.to_be_bytes());
        assert_eq!(&query[12..], expected_question.as_slice());
        assert_eq!(&query[0..2], &0x1234u16.to_be_bytes());
    }

    #[test]
    fn parses_response_with_uncompressed_ptr_answer() {
        let id = 0xBEEF;
        let mut buf = header(id, 0x8180, 1, 1); // QR=1, RA=1, RCODE=0
        buf.extend_from_slice(&encode_name("4.4.8.8.in-addr.arpa"));
        buf.extend_from_slice(&QTYPE_PTR.to_be_bytes());
        buf.extend_from_slice(&QCLASS_IN.to_be_bytes());
        // answer
        buf.extend_from_slice(&encode_name("4.4.8.8.in-addr.arpa"));
        buf.extend_from_slice(&QTYPE_PTR.to_be_bytes());
        buf.extend_from_slice(&QCLASS_IN.to_be_bytes());
        buf.extend_from_slice(&300u32.to_be_bytes()); // TTL
        let rdata = encode_name("dns.google");
        buf.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        buf.extend_from_slice(&rdata);

        let name = parse_ptr_response(&buf, id).expect("parse");
        assert_eq!(name, "dns.google");
    }

    #[test]
    fn parses_response_with_compressed_ptr_answer() {
        let id = 0x0042;
        let mut buf = header(id, 0x8180, 1, 1);
        let question_name_offset = buf.len();
        buf.extend_from_slice(&encode_name("4.4.8.8.in-addr.arpa"));
        buf.extend_from_slice(&QTYPE_PTR.to_be_bytes());
        buf.extend_from_slice(&QCLASS_IN.to_be_bytes());
        // answer: name is a compression pointer back to the question's QNAME
        let pointer = 0xC000u16 | (question_name_offset as u16 & 0x3FFF);
        buf.extend_from_slice(&pointer.to_be_bytes());
        buf.extend_from_slice(&QTYPE_PTR.to_be_bytes());
        buf.extend_from_slice(&QCLASS_IN.to_be_bytes());
        buf.extend_from_slice(&300u32.to_be_bytes());
        let rdata = encode_name("dns.google");
        buf.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        buf.extend_from_slice(&rdata);

        let name = parse_ptr_response(&buf, id).expect("parse");
        assert_eq!(name, "dns.google");
    }

    #[test]
    fn rejects_id_mismatch() {
        let buf = header(1, 0x8180, 0, 0);
        let error = parse_ptr_response(&buf, 2).unwrap_err();
        assert_eq!(error.kind(), NetInfoErrorKind::ParseFailed);
    }

    #[test]
    fn rejects_nonzero_rcode() {
        let buf = header(1, 0x8183, 0, 0); // RCODE = 3 (NXDOMAIN)
        let error = parse_ptr_response(&buf, 1).unwrap_err();
        assert_eq!(error.kind(), NetInfoErrorKind::ResolutionFailed);
    }

    #[test]
    fn rejects_no_ptr_answer_present() {
        let mut buf = header(1, 0x8180, 1, 0);
        buf.extend_from_slice(&encode_name("4.4.8.8.in-addr.arpa"));
        buf.extend_from_slice(&QTYPE_PTR.to_be_bytes());
        buf.extend_from_slice(&QCLASS_IN.to_be_bytes());
        let error = parse_ptr_response(&buf, 1).unwrap_err();
        assert_eq!(error.kind(), NetInfoErrorKind::ResolutionFailed);
    }

    #[test]
    fn detects_compression_pointer_loop() {
        // A name at offset 12 that points right back to itself.
        let mut buf = header(1, 0x8180, 0, 0);
        let self_offset = buf.len() as u16;
        let pointer = 0xC000u16 | self_offset;
        buf.extend_from_slice(&pointer.to_be_bytes());
        let error = parse_name(&buf, 12).unwrap_err();
        assert_eq!(error.kind(), NetInfoErrorKind::ParseFailed);
    }

    #[test]
    fn rejects_truncated_buffer() {
        let error = parse_ptr_response(&[0u8; 4], 0).unwrap_err();
        assert_eq!(error.kind(), NetInfoErrorKind::ParseFailed);
    }
}
