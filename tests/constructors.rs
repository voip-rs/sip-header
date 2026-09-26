use sip_header::sip_uri::{Uri, UriParse};
use sip_header::{
    AddrParts, ContactList, ContactValue, DialogFraming, DialogIdEdit, HeaderParse, HistoryInfo,
    HistoryInfoEntry, ListParse, ParseError, Redact, SipAccept, SipAcceptEncoding,
    SipAcceptEncodingEntry, SipAcceptEntry, SipAcceptLanguage, SipAcceptLanguageEntry,
    SipAuthValue, SipGeolocation, SipGeolocationEntry, SipGeolocationRef, SipHeaderAddr,
    SipReplaces, SipSecurity, SipSecurityMechanism, SipTargetDialog, SipVia, SipViaEntry,
    SipWarning, SipWarningEntry, UriInfo, UriInfoEntry,
};

/// `value` prints as `wire`, and parsing `wire` gives `value` back.
fn built_as<T>(value: T, wire: &str)
where
    T: HeaderParse + std::fmt::Display + std::fmt::Debug + PartialEq,
{
    assert_eq!(value.to_string(), wire);
    assert_eq!(T::parse_strict(wire), Ok(value), "{wire}");
}

fn uri(s: &str) -> Uri {
    Uri::parse(s).unwrap()
}

#[test]
fn addr_builder_lowercases_keys() {
    let addr = SipHeaderAddr::new(uri("sip:alice@example.com"))
        .with_display_name("Alice Smith")
        .unwrap()
        .with_param("Tag", Some("abc"))
        .unwrap()
        .with_param("lr", None::<&str>)
        .unwrap();
    assert_eq!(addr.tag(), Some("abc"));
    built_as(addr, r#""Alice Smith" <sip:alice@example.com>;tag=abc;lr"#);
}

#[test]
fn addr_build_validates() {
    let addr = SipHeaderAddr::new(uri("sip:alice@example.com"))
        .with_display_name("Alice")
        .unwrap()
        .with_param("tag", Some("abc"))
        .unwrap();
    built_as(addr.clone(), "Alice <sip:alice@example.com>;tag=abc");
    assert!(addr
        .clone()
        .with_param("tag", Some("a;b"))
        .is_err());
    assert!(addr
        .with_display_name("a\r\nb")
        .is_err());
}

#[test]
fn addr_redacted_masks_name_and_user() {
    let addr = SipHeaderAddr::parse(r#""Alice" <sip:alice@example.com>;tag=abc"#).unwrap();
    assert_eq!(
        addr.redacted(sip_header::sip_uri::Redaction::default())
            .to_string(),
        "*** <sip:***@example.com>;tag=abc"
    );
}

#[test]
fn addr_parts_read_uri_headers() {
    let addr = SipHeaderAddr::parse(
        "<sip:bob@example.com?Replaces=a%40example.com%3Bto-tag%3Dt%3Bfrom-tag%3Df&Reason=SIP%3Bcause%3D302>",
    )
    .unwrap();
    assert_eq!(
        addr.replaces()
            .unwrap()
            .unwrap(),
        SipReplaces::new("a@example.com", "t", "f").with_framing(DialogFraming::UriHeader)
    );
    let reason = addr
        .reason()
        .unwrap()
        .unwrap();
    assert_eq!((reason.protocol(), reason.cause()), ("SIP", Some(302)));
    assert_eq!(
        SipHeaderAddr::parse_list("<sip:a@example.com>, <sip:b@example.com>")
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn via_entry() {
    let entry = SipViaEntry::new("SIP", "2.0", "UDP")
        .with_host("[2001:db8::1]")
        .with_port(5060)
        .with_param("rport", Some("5061"))
        .and_then(|e| e.with_param("Branch", Some("z9hG4bK1")))
        .unwrap();
    assert_eq!(entry.host(), Some("2001:db8::1"));
    assert_eq!(entry.rport(), Some(Some(5061)));
    assert_eq!(entry.branch(), Some("z9hG4bK1"));
    built_as(
        SipVia::new(vec![entry]).unwrap(),
        "SIP/2.0/UDP [2001:db8::1]:5060;rport=5061;branch=z9hG4bK1",
    );
    assert!(SipViaEntry::new("SIP", "2.0", "UDP")
        .with_param("rport", Some("x"))
        .is_none());
    assert_eq!(SipVia::new(Vec::new()), None);
}

#[test]
fn accept_family() {
    let accept = SipAccept::new(vec![
        SipAcceptEntry::new("Application", "SDP").with_param("q", Some("0.5")),
        SipAcceptEntry::new("text", "plain"),
    ]);
    assert_eq!(accept.entries()[0].media_type(), "application");
    assert_eq!(accept.entries()[0].subtype(), "sdp");
    built_as(accept, "application/sdp;q=0.5, text/plain");
    built_as(
        SipAcceptEncoding::new(vec![SipAcceptEncodingEntry::new("GZIP")]),
        "gzip",
    );
    built_as(
        SipAcceptLanguage::new(vec![
            SipAcceptLanguageEntry::new("fr-CA").with_param("q", Some("1"))
        ]),
        "fr-ca;q=1",
    );
    assert!(SipAccept::new(Vec::new()).is_empty());
}

#[test]
fn warning_entry() {
    built_as(
        SipWarning::new(vec![SipWarningEntry::new(
            399,
            "example.com",
            r#"say "hi""#,
        )])
        .unwrap(),
        r#"399 example.com "say \"hi\"""#,
    );
    assert_eq!(SipWarning::new(Vec::new()), None);
}

#[test]
fn auth_value() {
    built_as(
        SipAuthValue::new("Digest")
            .with_quoted_param("Realm", "example.com")
            .with_quoted_param("qop", "auth")
            .with_param("algorithm", "MD5"),
        r#"Digest realm="example.com", qop="auth", algorithm=MD5"#,
    );
    built_as(
        SipAuthValue::from_token68("Bearer", "abc.def"),
        "Bearer abc.def",
    );
    let replaced = SipAuthValue::from_token68("Bearer", "abc").with_param("realm", "x");
    assert_eq!(replaced.token68(), None);
}

#[test]
fn security_mechanism() {
    built_as(
        SipSecurity::new(vec![SipSecurityMechanism::new("Digest")
            .with_param("q", Some("0.1"))
            .with_quoted_param("d-alg", "md5")])
        .unwrap(),
        r#"digest;q=0.1;d-alg="md5""#,
    );
}

#[test]
fn uri_info_and_geolocation() {
    built_as(
        UriInfo::new(vec![
            UriInfoEntry::new("https://example.com/a").with_param("Purpose", Some("icon"))
        ])
        .unwrap(),
        "<https://example.com/a>;purpose=icon",
    );
    assert_eq!(UriInfo::new(Vec::new()), None);
    built_as(
        SipGeolocation::new(vec![
            SipGeolocationEntry::new(SipGeolocationRef::Cid("a@example.com".into())),
            SipGeolocationEntry::new(SipGeolocationRef::Url("https://example.com/l".into()))
                .with_param("inserted-by", Some("example.com")),
        ]),
        "<cid:a@example.com>, <https://example.com/l>;inserted-by=example.com",
    );
}

#[test]
fn history_info_and_contact() {
    let addr = SipHeaderAddr::parse("<sip:a@example.com>;index=1").unwrap();
    built_as(
        HistoryInfo::new(vec![HistoryInfoEntry::new(addr.clone())]).unwrap(),
        "<sip:a@example.com>;index=1",
    );
    built_as(
        ContactList::new(vec![ContactValue::Addr(Box::new(addr))]),
        "<sip:a@example.com>;index=1",
    );
    assert_eq!(
        ContactList::from_entries(["*"]).map(ContactList::into_entries),
        Ok(vec![ContactValue::Wildcard])
    );
}

#[test]
fn dialog_ids() {
    let replaces = SipReplaces::new("a@example.com", "t", "f")
        .with_early_only(true)
        .with_param("Foo", Some("bar"));
    built_as(
        replaces.clone(),
        "a@example.com;to-tag=t;from-tag=f;early-only;foo=bar",
    );
    let encoded = replaces.with_framing(DialogFraming::UriHeader);
    assert_eq!(
        encoded.to_string(),
        "a%40example.com%3Bto-tag%3Dt%3Bfrom-tag%3Df%3Bearly-only%3Bfoo%3Dbar"
    );
    assert_eq!(
        SipReplaces::parse_uri_header_strict(&encoded.to_string()),
        Ok(encoded.clone())
    );
    assert_eq!(
        encoded
            .with_call_id("b@example.com")
            .map(|r| r.to_string()),
        Ok("b%40example.com%3Bto-tag%3Dt%3Bfrom-tag%3Df%3Bearly-only%3Bfoo%3Dbar".to_string())
    );
    built_as(
        SipTargetDialog::new("a@example.com", "l", "r"),
        "a@example.com;local-tag=l;remote-tag=r",
    );
    assert!(matches!(
        SipTargetDialog::new("a@example.com", "l", "r").with_call_id("a b"),
        Err(ParseError::Malformed(_))
    ));
}
