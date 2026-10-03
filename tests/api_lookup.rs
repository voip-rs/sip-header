//! Typed accessors: one return shape, the generic parse, token lists.

use sip_header::{
    ContactList, FaultCode, Field, ParseError, SipAuthValue, SipCallId, SipHeader, SipHeaderAddr,
    SipHeaderAddrList, SipHeaderLookup, SipHeaderRows, SipReasonList, SipVia, TokenList,
    TypedHeader, UriInfo, WarningCode,
};
use sip_header_catalog::RowError;

type R = Result<(), ParseError>;

/// A message's header lines in wire order, names as sent.
struct Wire(Vec<(String, String)>);

impl Wire {
    fn new(lines: &[(&str, &str)]) -> Self {
        Wire(
            lines
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        )
    }
}

impl SipHeaderRows for Wire {
    fn sip_header_rows_str<'a>(&'a self, name: &str) -> Result<Vec<&'a str>, RowError> {
        Ok(self
            .0
            .iter()
            .filter(|(k, _)| SipHeader::name_matches(name, k))
            .map(|(_, v)| v.as_str())
            .collect())
    }
}

fn message() -> Wire {
    Wire::new(&[
        ("VIA", "SIP/2.0/UDP 198.51.100.1;branch=z9hG4bK1"),
        ("f", r#""Alice" <sip:alice@example.com>;tag=a1"#),
        ("v", "SIP/2.0/TCP 203.0.113.5;branch=z9hG4bK2"),
        ("to", "<sip:bob@example.com>"),
        ("i", "a84b4c76e66710@example.com"),
        ("Via", "SIP/2.0/UDP 198.51.100.3;branch=z9hG4bK3"),
        (
            "r",
            "<sip:carol@example.com?Replaces=x%3Bto-tag%3Dt%3Bfrom-tag%3Df>",
        ),
        ("b", "<sip:alice@example.com>"),
        (
            "reason",
            r#"SIP;cause=200;text="elsewhere", Q.850;cause=16"#,
        ),
        ("Route", "<sip:p1.example.com;lr>"),
        ("route", "<sip:p2.example.com;lr>, <sip:p3.example.com;lr>"),
        ("k", "timer, 100REL"),
        ("allow", "INVITE, ACK"),
        (
            "Remote-Party-ID",
            "<sip:+15551234567@example.com>;party=calling",
        ),
        (
            "remote-party-id",
            "<sip:+15557654321@example.com>;party=called",
        ),
        (
            "Authorization",
            r#"Digest username="a", realm="example.com""#,
        ),
        (
            "authorization",
            r#"Digest username="b", realm="example.org""#,
        ),
    ])
}

#[test]
fn every_accessor_reads_a_wire_store() -> R {
    let m = message();
    let via = m
        .via()?
        .unwrap();
    assert_eq!(via.len(), 3);
    assert_eq!(via.entries()[1].transport(), "TCP");

    let from: SipHeaderAddr = m
        .sip_from()?
        .unwrap();
    assert_eq!(from.tag(), Some("a1"));
    assert_eq!(
        m.sip_to()?
            .unwrap()
            .tag(),
        None
    );
    let call_id: SipCallId = m
        .call_id()?
        .unwrap();
    assert_eq!(call_id.host(), Some("example.com"));
    assert!(m
        .refer_to()?
        .unwrap()
        .sip_uri()
        .is_some());
    assert!(m
        .referred_by()?
        .is_some());
    let reason: SipReasonList = m
        .reason()?
        .unwrap();
    assert_eq!(reason.len(), 2);

    let route: SipHeaderAddrList = m
        .route()?
        .unwrap();
    assert_eq!(route.len(), 3);
    assert_eq!(m.record_route()?, None);

    let rpid = m
        .remote_party_id()?
        .unwrap();
    assert_eq!(rpid.len(), 2);

    let auth: Vec<SipAuthValue> = m
        .authorization()?
        .unwrap();
    assert_eq!(auth[1].realm(), Some("example.org"));
    assert_eq!(m.www_authenticate()?, None);
    assert_eq!(m.contact()?, None::<ContactList>);
    Ok(())
}

#[test]
fn token_lists_borrow_and_know_their_case_rule() -> R {
    let m = message();
    let allow: TokenList = m
        .allow()?
        .unwrap();
    assert_eq!(
        allow
            .iter()
            .collect::<Vec<_>>(),
        ["INVITE", "ACK"]
    );
    assert!(allow.contains("INVITE"));
    assert!(!allow.contains("invite"));
    let supported = m
        .supported()?
        .unwrap();
    assert!(supported.contains("100rel"));
    assert!(supported.contains("TIMER"));
    assert_eq!(supported.len(), 2);
    assert_eq!(m.require()?, None);
    Ok(())
}

#[test]
fn token_lists_report_what_they_drop() -> R {
    let m = Wire::new(&[
        ("Allow", "INVITE, , ACK"),
        ("Require", " "),
        ("Supported", ""),
    ]);
    let parsed = m
        .parse_header::<TokenList>(SipHeader::Allow)?
        .unwrap();
    assert_eq!(
        parsed
            .value
            .len(),
        2
    );
    assert_eq!(parsed.warnings[0].code, WarningCode::EmptyEntry);
    assert_eq!(parsed.warnings[0].entry, Some(1));
    assert!(m
        .parse_header_strict::<TokenList>(SipHeader::Allow)
        .is_err());
    assert_eq!(
        m.require(),
        Err(ParseError::Malformed(sip_header::Fault::new(
            Field::Value,
            FaultCode::Empty
        )))
    );
    assert!(m
        .supported()?
        .unwrap()
        .is_empty());
    let m = Wire::new(&[("Supported", "time<r"), ("Allow", "IN VITE")]);
    let parsed = m
        .parse_header::<TokenList>(SipHeader::Supported)?
        .unwrap();
    assert_eq!(
        parsed
            .value
            .iter()
            .collect::<Vec<_>>(),
        ["timer"]
    );
    assert_eq!(parsed.warnings[0].code, WarningCode::StrayDelimiter);
    let parsed = m
        .parse_header::<TokenList>(SipHeader::Allow)?
        .unwrap();
    assert_eq!(parsed.warnings[0].code, WarningCode::InvalidToken);
    Ok(())
}

#[test]
fn parse_header_reports_warnings_and_strict_refuses() -> R {
    let m = Wire::new(&[("Call-Info", "https://example.com/a;purpose=icon")]);
    let parsed = m
        .parse_header::<UriInfo>(SipHeader::CallInfo)?
        .unwrap();
    assert_eq!(
        parsed
            .value
            .len(),
        1
    );
    assert_eq!(parsed.warnings[0].code, WarningCode::MissingBrackets);
    assert!(matches!(
        m.parse_header_strict::<UriInfo>(SipHeader::CallInfo),
        Err(ParseError::NonConformant(_))
    ));
    assert_eq!(m.parse_header::<UriInfo>(SipHeader::AlertInfo)?, None);
    Ok(())
}

#[test]
fn parse_header_refuses_a_header_the_type_does_not_hold() {
    let m = message();
    assert_eq!(
        m.parse_header::<SipVia>(SipHeader::From),
        Err(ParseError::Malformed(sip_header::Fault::new(
            Field::Value,
            FaultCode::WrongHeader
        )))
    );
    assert!(<SipVia as TypedHeader>::HEADERS.contains(&SipHeader::Via));
    assert!(<SipHeaderAddr as TypedHeader>::HEADERS.contains(&SipHeader::ReferTo));
}

#[test]
fn a_single_valued_header_twice_is_an_error() {
    let m = Wire::new(&[
        ("From", "<sip:a@example.com>"),
        ("f", "<sip:b@example.com>"),
        ("Call-ID", "a@example.com"),
        ("i", "b@example.com"),
    ]);
    let duplicate =
        ParseError::Malformed(sip_header::Fault::new(Field::Value, FaultCode::Duplicate));
    assert_eq!(m.sip_from(), Err(duplicate.clone()));
    assert_eq!(m.call_id(), Err(duplicate));
}

#[test]
fn every_type_holds_headers_of_one_row_policy() {
    fn single<T: TypedHeader>() {
        for h in T::HEADERS {
            assert!(!h.may_repeat(), "{h}");
        }
    }
    fn repeatable<T: TypedHeader>() {
        for h in T::HEADERS {
            assert!(h.may_repeat(), "{h}");
        }
    }
    single::<SipHeaderAddr>();
    single::<SipCallId>();
    single::<sip_header::SipReplaces>();
    single::<sip_header::SipJoin>();
    single::<sip_header::SipTargetDialog>();
    repeatable::<SipHeaderAddrList>();
    repeatable::<SipReasonList>();
    repeatable::<TokenList>();
    repeatable::<Vec<SipAuthValue>>();
    repeatable::<UriInfo>();
    repeatable::<SipVia>();
    repeatable::<ContactList>();
    repeatable::<sip_header::HistoryInfo>();
    repeatable::<sip_header::SipWarning>();
    repeatable::<sip_header::SipSecurity>();
    repeatable::<sip_header::SipAccept>();
    repeatable::<sip_header::SipAcceptEncoding>();
    repeatable::<sip_header::SipAcceptLanguage>();
    repeatable::<sip_header::SipGeolocation>();
}

#[test]
fn address_headers_of_name_addr_grammar_parse_as_addresses() {
    let m = Wire::new(&[
        ("Reply-To", "Bob <sip:bob@example.com>"),
        ("P-Called-Party-ID", "<sip:+15551234567@example.com>"),
        (
            "P-Served-User",
            "<sip:a@example.com>;sescase=orig;regstate=reg",
        ),
        ("P-DCS-Trace-Party-ID", "<tel:+15551234567>;timestamp=1"),
        (
            "P-Refused-URI-List",
            "<sip:a@example.com>, sip:b@example.com",
        ),
        (
            "Permission-Missing",
            "<sip:a@example.com>, <sip:b@example.com>",
        ),
    ]);
    for header in [
        SipHeader::ReplyTo,
        SipHeader::PCalledPartyId,
        SipHeader::PServedUser,
        SipHeader::PDcsTracePartyId,
    ] {
        let parsed = m
            .parse_header_strict::<SipHeaderAddr>(header)
            .unwrap_or_else(|e| panic!("{header}: {e}"));
        assert!(parsed.is_some(), "{header}");
    }
    for header in [SipHeader::PRefusedUriList, SipHeader::PermissionMissing] {
        let parsed = m
            .parse_header_strict::<SipHeaderAddrList>(header)
            .unwrap_or_else(|e| panic!("{header}: {e}"));
        assert_eq!(parsed.map(|l| l.len()), Some(2), "{header}");
    }
    let wrong = ParseError::Malformed(sip_header::Fault::new(Field::Value, FaultCode::WrongHeader));
    for header in [
        SipHeader::PAssociatedUri,
        SipHeader::PolicyContact,
        SipHeader::TriggerConsent,
    ] {
        assert_eq!(
            m.parse_header::<SipHeaderAddrList>(header),
            Err(wrong.clone()),
            "{header}"
        );
    }
}
