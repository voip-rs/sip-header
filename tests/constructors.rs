use sip_header::sip_uri::{Host, Uri, UriParse};
use sip_header::{
    AddrParts, ContactList, DialogFraming, FaultCode, Field, HeaderParse, HistoryInfo,
    HistoryInfoEntry, ListParse, ParseError, Redact, SipAccept, SipAcceptEncoding,
    SipAcceptEncodingEntry, SipAcceptEntry, SipAcceptLanguage, SipAcceptLanguageEntry,
    SipAuthValue, SipGeolocation, SipGeolocationEntry, SipHeaderAddr, SipHeaderAddrList, SipReason,
    SipReplaces, SipSecurity, SipSecurityMechanism, SipTargetDialog, SipVia, SipViaEntry,
    SipWarning, SipWarningEntry, UriHeaderParse, UriInfo, UriInfoEntry,
};

type R = Result<(), ParseError>;

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

/// The field and code of a refused construction.
fn refused<T: std::fmt::Debug>(r: Result<T, ParseError>) -> (Field, FaultCode) {
    match r {
        Err(ParseError::Malformed(f)) => (f.field, f.code),
        other => panic!("not refused as malformed: {other:?}"),
    }
}

#[test]
fn addr_builder_lowercases_keys() -> R {
    let addr = SipHeaderAddr::new(uri("sip:alice@example.com"))?
        .with_display_name("Alice Smith")?
        .with_tag("abc")?
        .with_param("lr", None)?;
    assert_eq!(addr.tag(), Some("abc"));
    built_as(addr, r#""Alice Smith" <sip:alice@example.com>;tag=abc;lr"#);
    Ok(())
}

#[test]
fn addr_build_validates() -> R {
    let addr = SipHeaderAddr::new(uri("sip:alice@example.com"))?
        .with_display_name("Alice")?
        .with_tag("abc")?;
    built_as(addr.clone(), "Alice <sip:alice@example.com>;tag=abc");
    assert!(addr
        .clone()
        .with_tag("a;b")
        .is_err());
    assert!(addr
        .clone()
        .with_param("x", Some("a\r\nb"))
        .is_err());
    for name in ["a\r\nb", "a\0b"] {
        assert_eq!(
            refused(
                addr.clone()
                    .with_display_name(name)
            ),
            (Field::DisplayName, FaultCode::InvalidChar)
        );
    }
    assert_eq!(
        addr.with_display_name("")?
            .display_name(),
        None
    );
    Ok(())
}

#[test]
fn addr_refuses_a_uri_that_breaks_its_brackets() {
    let host = sip_header::sip_uri::Host::Hostname("example.com".into());
    for user in ["a>b", "a<b"] {
        let uri: Uri = sip_header::sip_uri::SipUri::new(host.clone())
            .with_user(user)
            .into();
        if let Ok(addr) = SipHeaderAddr::new(uri) {
            assert_eq!(
                SipHeaderAddr::parse_strict(&addr.to_string()),
                Ok(addr),
                "{user}"
            );
        }
    }
}

#[test]
fn addr_redacted_masks_name_and_user() {
    let addr = SipHeaderAddr::parse(r#""Alice" <sip:alice@example.com>;tag=abc"#).unwrap();
    assert_eq!(
        addr.redacted(&sip_header::HeaderRedaction::default())
            .to_string(),
        "*** <sip:***@example.com>;tag=abc"
    );
}

#[test]
fn addr_parts_read_uri_headers() -> R {
    let addr = SipHeaderAddr::parse(
        "<sip:bob@example.com?Replaces=a%40example.com%3Bto-tag%3Dt%3Bfrom-tag%3Df&Reason=SIP%3Bcause%3D302>",
    )?;
    assert_eq!(
        addr.replaces()
            .unwrap()?,
        SipReplaces::new("a@example.com", "t", "f")?.with_framing(DialogFraming::UriHeader)
    );
    let reason = addr
        .reason()
        .unwrap()?;
    assert_eq!(
        (
            reason.protocol(),
            reason
                .cause()
                .map(|c| c.as_str())
        ),
        ("SIP", Some("302"))
    );
    assert_eq!(
        SipHeaderAddrList::parse("<sip:a@example.com>, <sip:b@example.com>")?.len(),
        2
    );
    Ok(())
}

fn host(name: &str) -> Host {
    Host::Hostname(name.into())
}

#[test]
fn via_entry() -> R {
    let v6 = Host::IPv6(
        "2001:db8::1"
            .parse()
            .unwrap(),
    );
    let entry = SipViaEntry::new("SIP", "2.0", "UDP", v6.clone())?
        .with_port(5060)
        .with_rport(Some(5061))
        .with_param("Branch", Some("z9hG4bK1"))?;
    assert_eq!(entry.host(), &v6);
    assert_eq!(entry.rport(), Some(Some(5061)));
    assert_eq!(entry.branch(), Some("z9hG4bK1"));
    built_as(
        SipVia::new(vec![entry]).unwrap(),
        "SIP/2.0/UDP [2001:db8::1]:5060;rport=5061;branch=z9hG4bK1",
    );
    assert!(SipViaEntry::new("SIP", "2.0", "UDP", host("example.com"))?
        .with_param("rport", Some("5061"))
        .is_err());
    Ok(())
}

#[test]
fn via_refuses_what_would_print_as_another_entry() {
    for (p, v, t) in [
        ("", "2.0", "UDP"),
        ("SIP", "2.0", ""),
        ("SIP", "2.0", "U;DP"),
    ] {
        assert_eq!(
            refused(SipViaEntry::new(p, v, t, host("example.com"))).0,
            Field::SentProtocol,
            "{p}/{v}/{t}"
        );
    }
    assert!(SipViaEntry::new("SIP", "2/0", "UDP", host("example.com")).is_err());
    for name in [
        "",
        "a;branch=x",
        "a,b",
        "a?b",
        "a>b",
        "a b",
        "a\r\nb",
        "a\0b",
        "exa_mple.com",
    ] {
        assert_eq!(
            refused(SipViaEntry::new("SIP", "2.0", "UDP", host(name))).0,
            Field::SentBy,
            "{name:?}"
        );
    }
}

#[test]
fn accept_family() -> R {
    let accept = SipAccept::new(vec![
        SipAcceptEntry::new("Application", "SDP")?.with_param("q", Some("0.5"))?,
        SipAcceptEntry::new("text", "plain")?,
    ]);
    assert_eq!(accept.entries()[0].media_type(), "application");
    assert_eq!(accept.entries()[0].subtype(), "sdp");
    built_as(accept, "application/sdp;q=0.5, text/plain");
    built_as(
        SipAcceptEncoding::new(vec![SipAcceptEncodingEntry::new("GZIP")?]),
        "gzip",
    );
    built_as(
        SipAcceptLanguage::new(vec![
            SipAcceptLanguageEntry::new("fr-CA")?.with_param("q", Some("1"))?
        ]),
        "fr-ca;q=1",
    );
    assert!(SipAccept::new(Vec::new()).is_empty());
    Ok(())
}

#[test]
fn accept_family_refuses_non_tokens_and_bad_q() -> R {
    for (t, s) in [
        ("", "sdp"),
        ("application", ""),
        ("a/b", "c"),
        ("a", "b/c"),
        ("a b", "c"),
    ] {
        assert_eq!(
            refused(SipAcceptEntry::new(t, s)).0,
            Field::MediaRange,
            "{t}/{s}"
        );
    }
    assert_eq!(
        refused(SipAcceptEncodingEntry::new("gz;ip")),
        (Field::Coding, FaultCode::InvalidChar)
    );
    assert_eq!(
        refused(SipAcceptEncodingEntry::new("")),
        (Field::Coding, FaultCode::Empty)
    );
    assert_eq!(
        refused(SipAcceptLanguageEntry::new("en_US")).0,
        Field::Language
    );
    let entry = SipAcceptEntry::new("text", "plain")?;
    assert_eq!(
        refused(
            entry
                .clone()
                .with_param("q", Some("high"))
        ),
        (Field::Qvalue, FaultCode::InvalidNumber)
    );
    assert!(entry
        .with_quoted_param("q", "0.5")
        .is_err());
    Ok(())
}

#[test]
fn warning_entry() -> R {
    built_as(
        SipWarning::new(vec![SipWarningEntry::new(
            399,
            "example.com",
            r#"say "hi""#,
        )?])
        .unwrap(),
        r#"399 example.com "say \"hi\"""#,
    );
    assert!(SipWarning::new(Vec::new()).is_err());
    Ok(())
}

#[test]
fn warning_refuses_code_range_agent_and_controls() {
    for code in [0, 99, 1000] {
        assert_eq!(
            refused(SipWarningEntry::new(code, "example.com", "x")),
            (Field::Code, FaultCode::InvalidNumber),
            "{code}"
        );
    }
    for agent in ["", "a b", "a\"b", "a,b"] {
        assert_eq!(
            refused(SipWarningEntry::new(399, agent, "x")).0,
            Field::Agent,
            "{agent:?}"
        );
    }
    assert_eq!(
        refused(SipWarningEntry::new(399, "example.com", "a\nb")),
        (Field::Text, FaultCode::InvalidChar)
    );
    assert!(SipWarningEntry::new(100, "[2001:db8::1]:5060", "x").is_ok());
}

#[test]
fn auth_value() -> R {
    built_as(
        SipAuthValue::new("Digest")?
            .with_quoted_param("Realm", "example.com")?
            .with_quoted_param("qop", "auth")?
            .with_param("algorithm", "MD5")?,
        r#"Digest realm="example.com", qop="auth", algorithm=MD5"#,
    );
    built_as(
        SipAuthValue::from_token68("Bearer", "abc.def")?,
        "Bearer abc.def",
    );
    let replaced = SipAuthValue::from_token68("Bearer", "abc")?.with_param("realm", "x")?;
    assert_eq!(replaced.token68(), None);
    Ok(())
}

#[test]
fn auth_refuses_bad_scheme_and_token68() {
    for scheme in ["", "Dig est", "Digest,", "a\r\nb"] {
        assert_eq!(
            refused(SipAuthValue::new(scheme)).0,
            Field::Scheme,
            "{scheme:?}"
        );
    }
    for t in ["", "a b", "a,b", "=", "a=b"] {
        assert_eq!(
            refused(SipAuthValue::from_token68("Bearer", t)).0,
            Field::Credentials,
            "{t:?}"
        );
    }
}

#[test]
fn security_mechanism() -> R {
    built_as(
        SipSecurity::new(vec![SipSecurityMechanism::new("Digest")?
            .with_param("q", Some("0.1"))?
            .with_quoted_param("d-alg", "md5")?])
        .unwrap(),
        r#"digest;q=0.1;d-alg="md5""#,
    );
    assert_eq!(
        refused(SipSecurityMechanism::new("dig est")),
        (Field::Mechanism, FaultCode::InvalidChar)
    );
    assert_eq!(
        refused(SipSecurityMechanism::new("")),
        (Field::Mechanism, FaultCode::Empty)
    );
    Ok(())
}

#[test]
fn uri_info_and_geolocation() -> R {
    built_as(
        UriInfo::new(vec![
            UriInfoEntry::new(uri("https://example.com/a"))?.with_param("Purpose", Some("icon"))?
        ])
        .unwrap(),
        "<https://example.com/a>;purpose=icon",
    );
    built_as(
        SipGeolocation::new(vec![
            SipGeolocationEntry::new(uri("cid:a@example.com"))?,
            SipGeolocationEntry::new(uri("https://example.com/l"))?
                .with_param("inserted-by", Some("example.com"))?,
        ])?,
        "<cid:a@example.com>, <https://example.com/l>;inserted-by=example.com",
    );
    Ok(())
}

#[test]
fn uri_info_and_geolocation_refuse_what_does_not_read_back() {
    for text in ["data", "a b>c", "a\r\nb"] {
        assert_eq!(
            refused(UriInfoEntry::new(uri(text))).0,
            Field::Addr,
            "{text:?}"
        );
        assert_eq!(
            refused(SipGeolocationEntry::new(uri(text))).0,
            Field::Reference,
            "{text:?}"
        );
    }
}

#[test]
fn history_info_and_contact() -> R {
    let addr = SipHeaderAddr::parse("<sip:a@example.com>;index=1")?;
    built_as(
        HistoryInfo::new(vec![HistoryInfoEntry::new(addr.clone(), "1")?])?,
        "<sip:a@example.com>;index=1",
    );
    built_as(ContactList::new(vec![addr])?, "<sip:a@example.com>;index=1");
    assert_eq!(
        ContactList::from_entries(["*"]),
        Ok(ContactList::wildcard())
    );
    Ok(())
}

#[test]
fn history_info_reason_refuses() -> R {
    let reason = SipReason::new("SIP")?
        .with_cause(302)
        .with_text("Moved")?;
    assert_eq!(reason.text(), Some("Moved"));
    assert_eq!(
        refused(SipReason::new("S;IP")),
        (Field::Protocol, FaultCode::InvalidChar)
    );
    assert_eq!(
        refused(SipReason::new("")),
        (Field::Protocol, FaultCode::Empty)
    );
    assert_eq!(
        refused(reason.with_text("a\r\nb")),
        (Field::Text, FaultCode::InvalidChar)
    );
    Ok(())
}

#[test]
fn dialog_ids() -> R {
    let replaces = SipReplaces::new("a@example.com", "t", "f")?
        .with_early_only(true)
        .with_param("Foo", Some("bar"))?;
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
        SipTargetDialog::new("a@example.com", "l", "r")?,
        "a@example.com;local-tag=l;remote-tag=r",
    );
    assert!(matches!(
        SipTargetDialog::new("a@example.com", "l", "r")?.with_call_id("a b"),
        Err(ParseError::Malformed(_))
    ));
    Ok(())
}

#[test]
fn dialog_ids_refuse_injected_structure() {
    for call_id in ["", "a;to-tag=x", "a,b", "a@b@c", "a\r\nb", "a\0"] {
        assert_eq!(
            refused(SipReplaces::new(call_id, "t", "f")).0,
            Field::CallId,
            "{call_id:?}"
        );
    }
    for tag in ["", "t;x=1", "t,u", "t@u", "t\n"] {
        assert_eq!(
            refused(SipReplaces::new("a@example.com", tag, "f")).0,
            Field::Tag,
            "{tag:?}"
        );
        assert_eq!(
            refused(SipTargetDialog::new("a@example.com", "l", tag)).0,
            Field::Tag,
            "{tag:?}"
        );
    }
}
