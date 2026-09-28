//! Header rows, the Request-URI and skipped lines of a raw message.
#![cfg(feature = "message")]

use sip_header::{
    extract_all_headers, extract_header, extract_request_uri, ParseError, SipHeader,
    SipHeaderFields, SipHeaderLookup, SipHeaderRowsExt, SipMessageHeaders,
};

const MSG: &str = concat!(
    "INVITE sip:bob@example.com SIP/2.0\r\n",
    "Via: SIP/2.0/UDP 198.51.100.1;branch=z9hG4bK1\r\n",
    "v: SIP/2.0/TCP 203.0.113.5\r\n",
    " ;branch=z9hG4bK2\r\n",
    "f: Alice <sip:alice@example.com>;tag=a\r\n",
    "not a header\r\n",
    " orphan continuation\r\n",
    "VIA: SIP/2.0/UDP 198.51.100.3;branch=z9hG4bK3\r\n",
    "Supported: timer\r\n",
    "\r\n",
    "v=0\r\n",
);

#[test]
fn message_headers_are_a_row_store() -> Result<(), ParseError> {
    let headers = SipMessageHeaders::new(MSG);
    assert_eq!(
        headers.sip_header_rows(SipHeader::Via)?,
        [
            "SIP/2.0/UDP 198.51.100.1;branch=z9hG4bK1",
            "SIP/2.0/TCP 203.0.113.5 ;branch=z9hG4bK2",
            "SIP/2.0/UDP 198.51.100.3;branch=z9hG4bK3",
        ]
    );
    let via = headers
        .via()?
        .unwrap();
    assert_eq!(via.len(), 3);
    assert_eq!(via.entries()[1].branch(), Some("z9hG4bK2"));
    assert_eq!(
        headers
            .sip_from()?
            .unwrap()
            .tag(),
        Some("a")
    );
    assert!(headers
        .supported()?
        .unwrap()
        .contains("timer"));
    assert_eq!(headers.len(), 5);
    assert_eq!(
        headers
            .iter()
            .next(),
        Some(("Via", "SIP/2.0/UDP 198.51.100.1;branch=z9hG4bK1"))
    );
    Ok(())
}

#[test]
fn skipped_lines_are_reported_by_position() {
    let not_a_header = MSG
        .find("not a header")
        .unwrap();
    let orphan = MSG
        .find(" orphan")
        .unwrap();
    assert_eq!(
        SipMessageHeaders::new(MSG).skipped(),
        [not_a_header, orphan]
    );
    let all = extract_all_headers(MSG);
    assert_eq!(all.skipped, [not_a_header, orphan]);
    assert_eq!(
        all.headers
            .len(),
        5
    );
    assert_eq!(
        all.headers
            .iter()
            .nth(1),
        Some(("v", "SIP/2.0/TCP 203.0.113.5 ;branch=z9hG4bK2"))
    );
    assert!(SipMessageHeaders::new("SIP/2.0 200 OK\r\n\r\n")
        .skipped()
        .is_empty());
}

fn rows() -> SipHeaderFields<'static> {
    SipHeaderFields::from(vec![
        ("Via", "SIP/2.0/UDP 198.51.100.1;branch=z9hG4bK1"),
        ("v", "SIP/2.0/TCP 203.0.113.5 ;branch=z9hG4bK2"),
        ("f", "Alice <sip:alice@example.com>;tag=a"),
        ("VIA", "SIP/2.0/UDP 198.51.100.3;branch=z9hG4bK3"),
        ("Supported", "timer"),
    ])
}

fn outlives_the_message(fields: SipHeaderFields<'static>) -> SipHeaderFields<'static> {
    fields
}

#[test]
fn message_headers_hold_their_rows_as_fields() {
    let headers = SipMessageHeaders::new(MSG);
    assert_eq!(headers.fields(), &rows());
    let skipped = headers
        .skipped()
        .to_vec();
    assert_eq!(
        headers
            .clone()
            .into_fields(),
        rows()
    );
    let all = extract_all_headers(MSG);
    assert_eq!(all.skipped, skipped);
    assert_eq!(outlives_the_message(all.headers), rows());
}

#[test]
fn extract_header_keeps_returning_strings() {
    assert_eq!(
        extract_header(MSG, "From"),
        vec!["Alice <sip:alice@example.com>;tag=a".to_string()]
    );
}

#[test]
fn request_uri_is_a_uri() -> Result<(), ParseError> {
    let uri = extract_request_uri(MSG)?.unwrap();
    assert_eq!(uri.to_string(), "sip:bob@example.com");
    assert_eq!(extract_request_uri("SIP/2.0 200 OK\r\n\r\n")?, None);
    assert!(extract_request_uri("").is_err());
    assert!(extract_request_uri("INVITE sip:bob@example.com\r\n\r\n").is_err());
    assert!(extract_request_uri("IN VITE sip:bob@example.com SIP/2.0\r\n\r\n").is_err());
    Ok(())
}
