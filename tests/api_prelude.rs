//! The recommended imports: the prelude glob beside sip-uri's root glob,
//! this crate's types named explicitly.

use std::collections::HashMap;

use sip_header::prelude::*;
use sip_header::sip_uri::*;
use sip_header::{
    ParseError, Parsed, SipHeader, SipHeaderAddr, SipHeaderAddrList, SipReason, SipVia, WarningCode,
};

#[test]
fn named_imports_win_over_the_sip_uri_glob() -> Result<(), ParseError> {
    let parsed: Parsed<SipHeaderAddr> =
        SipHeaderAddr::parse_with_warnings("<sip:alice@example.com>junk")?;
    assert_eq!(parsed.warnings[0].code, WarningCode::TrailingContent);
    let uri = Uri::parse("sip:alice@example.com").map_err(|_| {
        ParseError::Malformed(sip_header::Fault::new(
            sip_header::Field::Addr,
            sip_header::FaultCode::Missing,
        ))
    })?;
    assert_eq!(
        uri.redacted(Redaction::default())
            .to_string(),
        "sip:***@example.com"
    );
    Ok(())
}

#[test]
fn the_prelude_brings_every_extension_trait() -> Result<(), ParseError> {
    let headers = HashMap::from([("Route".to_string(), "<sip:p1.example.com;lr>".to_string())]);
    assert_eq!(
        headers
            .route()?
            .map(|r| r.len()),
        Some(1)
    );
    assert!(headers
        .sip_header(SipHeader::Route)?
        .is_some());
    assert_eq!(SipVia::from_entries(["SIP/2.0/UDP 198.51.100.1"])?.len(), 1);
    assert_eq!(
        SipReason::parse_uri_header("SIP%3Bcause%3D200")?.protocol(),
        "SIP"
    );
    let list = SipHeaderAddrList::parse("<sip:+15551234567@example.com>")?;
    assert_eq!(
        list.redacted(Redaction::default())
            .to_string(),
        "<sip:***@example.com>"
    );
    assert!(list.entries()[0]
        .replaces()
        .is_none());
    Ok(())
}

#[cfg(feature = "message")]
#[test]
fn the_prelude_brings_extract_from() {
    let msg = "SIP/2.0 200 OK\r\nv: SIP/2.0/UDP 198.51.100.1\r\n\r\n";
    assert_eq!(
        SipHeader::Via.extract_from(msg),
        ["SIP/2.0/UDP 198.51.100.1"]
    );
}

struct Store;

impl SipHeaderRows for Store {
    fn sip_header_rows_str<'a>(&'a self, _: &str) -> Result<Vec<&'a str>, sip_header::RowError> {
        Ok(Vec::new())
    }
}

#[test]
fn a_store_implements_rows_through_the_prelude() {
    assert_eq!(Store.via(), Ok(None));
}
