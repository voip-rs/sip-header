//! What each value type holds, how it prints and what it refuses.

use std::collections::HashMap;

use sip_header::sip_uri::{Host, Uri, UriParse, WarningKind};
use sip_header::{
    AddrParts, ContactList, Fault, FaultCode, Field, HeaderParse, HistoryInfo, HistoryInfoEntry,
    ListParse, ParseError, SipAccept, SipAcceptEncoding, SipAcceptLanguage, SipGeolocation,
    SipGeolocationEntry, SipHeaderAddr, SipHeaderLookup, SipJoin, SipReason, SipReasonCause,
    SipSecurity, SipVia, SipViaEntry, SipWarning, UriInfo, UriInfoEntry, WarningCode,
};

type R = Result<(), ParseError>;

fn empty() -> ParseError {
    ParseError::Malformed(Fault::new(Field::Value, FaultCode::Empty))
}

fn uri(s: &str) -> Uri {
    Uri::parse(s).unwrap()
}

#[test]
fn contact_is_a_wildcard_or_addresses() -> R {
    let star = ContactList::parse_strict("*")?;
    assert!(star.is_wildcard());
    assert!(star
        .addrs()
        .is_empty());
    assert_eq!(star, ContactList::wildcard());
    assert_eq!(star.to_string(), "*");

    let a = SipHeaderAddr::parse("<sip:a@example.com>")?;
    let b = SipHeaderAddr::parse("\"B C\" <sip:b@example.com>;expires=60")?;
    let list = ContactList::new(vec![a.clone(), b.clone()])?;
    assert!(!list.is_wildcard());
    assert_eq!(list.addrs(), &[a.clone(), b.clone()]);
    assert_eq!(
        list.to_string(),
        r#"<sip:a@example.com>, "B C" <sip:b@example.com>;expires=60"#
    );
    assert_eq!(
        ContactList::parse_strict(&list.to_string()),
        Ok(list.clone())
    );
    assert_eq!(ContactList::new(Vec::new()), Err(empty()));
    assert_eq!(ContactList::parse(" "), Err(empty()));
    Ok(())
}

#[test]
fn contact_wildcard_beside_addresses_is_dropped() -> R {
    let a = SipHeaderAddr::parse("<sip:a@example.com>")?;
    let input = "*, <sip:a@example.com>, *";
    let parsed = ContactList::parse_with_warnings(input)?;
    assert_eq!(parsed.value, ContactList::new(vec![a.clone()])?);
    let seen: Vec<_> = parsed
        .warnings
        .iter()
        .map(|w| (w.field, w.code, w.kind, w.entry))
        .collect();
    let dropped = |i| {
        (
            Field::Entry,
            WarningCode::WildcardNotAlone,
            WarningKind::Lost,
            Some(i),
        )
    };
    assert_eq!(seen, vec![dropped(0), dropped(2)]);
    assert_eq!(
        ContactList::parse_strict(input),
        Err(ParseError::NonConformant(parsed.warnings[0]))
    );
    assert_eq!(
        ContactList::from_entries(["*", "*"])?,
        ContactList::wildcard()
    );

    let headers: HashMap<String, String> =
        [("Contact".to_string(), "<sip:a@example.com>".to_string())].into();
    assert_eq!(headers.contact()?, Some(ContactList::new(vec![a])?));
    assert_eq!(HashMap::<String, String>::new().contact()?, None);
    Ok(())
}

#[test]
fn geolocation_is_never_empty() {
    assert_eq!(SipGeolocation::parse("junk, <>"), Err(empty()));
    assert_eq!(SipGeolocation::new(Vec::new()), Err(empty()));
    assert_eq!(SipGeolocation::from_entries(["junk"]), Err(empty()));
}

#[test]
fn list_new_is_fallible_only_where_the_grammar_forbids_empty() {
    assert_eq!(SipVia::new(Vec::new()), Err(empty()));
    assert_eq!(SipWarning::new(Vec::new()), Err(empty()));
    assert_eq!(SipSecurity::new(Vec::new()), Err(empty()));
    assert_eq!(UriInfo::new(Vec::new()), Err(empty()));
    assert_eq!(HistoryInfo::new(Vec::new()), Err(empty()));
    assert!(SipAccept::new(Vec::new()).is_empty());
    assert!(SipAcceptEncoding::new(Vec::new()).is_empty());
    assert!(SipAcceptLanguage::new(Vec::new()).is_empty());
}

#[test]
fn history_info_entry_takes_its_index() -> R {
    let addr = SipHeaderAddr::parse("<sip:a@example.com>;index=9;x=1;index=8")?;
    let entry = HistoryInfoEntry::new(addr.clone(), "1.2")?;
    assert_eq!(entry.index(), Some("1.2"));
    assert_eq!(entry.to_string(), "<sip:a@example.com>;index=1.2;x=1");
    for bad in ["", "1.", ".1", "1..2", "a", "1 2", "1;x"] {
        match HistoryInfoEntry::new(addr.clone(), bad) {
            Err(ParseError::Malformed(f)) => assert_eq!(f.field, Field::Index, "{bad:?}"),
            other => panic!("{bad:?}: {other:?}"),
        }
    }
    Ok(())
}

#[test]
fn uri_info_holds_a_uri() -> R {
    let https = uri("https://example.com/a");
    let entry = UriInfoEntry::new(https.clone())?.with_param("purpose", Some("icon"))?;
    assert_eq!(entry.uri(), &https);
    assert_eq!(entry.to_string(), "<https://example.com/a>;purpose=icon");
    let info = UriInfo::parse_strict("<urn:example:call:1>;purpose=info")?;
    assert!(info.entries()[0]
        .uri()
        .as_urn()
        .is_some());

    let data = UriInfo::parse_with_warnings("<data>")?;
    assert_eq!(
        data.value
            .entries()[0]
            .uri()
            .to_string(),
        "data"
    );
    assert_eq!(
        data.warnings[0].code,
        WarningCode::Uri(sip_header::sip_uri::WarningCode::MissingScheme)
    );
    assert!(UriInfoEntry::new(uri("data")).is_err());
    Ok(())
}

#[test]
fn geolocation_cid_comes_from_the_scheme() -> R {
    let geo = SipGeolocation::parse("<CID:loc@example.com>, <https://lis.example.com/l>")?;
    assert_eq!(geo.cid(), Some("loc@example.com"));
    assert_eq!(geo.entries()[0].cid(), Some("loc@example.com"));
    assert_eq!(geo.entries()[1].cid(), None);
    assert_eq!(
        geo.url()
            .map(ToString::to_string),
        Some("https://lis.example.com/l".to_string())
    );
    assert_eq!(
        geo.to_string(),
        "<cid:loc@example.com>, <https://lis.example.com/l>"
    );
    let entry = SipGeolocationEntry::new(uri("cid:a@example.com"))?;
    assert_eq!(entry.cid(), Some("a@example.com"));
    assert_eq!(entry.uri(), &uri("cid:a@example.com"));
    Ok(())
}

#[test]
fn via_sent_by_is_a_host() -> R {
    let host = Host::IPv6(
        "2001:db8::1"
            .parse()
            .unwrap(),
    );
    let via = SipViaEntry::new("SIP", "2.0", "UDP", host.clone())?.with_port(5060);
    assert_eq!(via.host(), &host);
    assert_eq!(via.to_string(), "SIP/2.0/UDP [2001:db8::1]:5060");
    let parsed = SipVia::parse("SIP/2.0/UDP Example.COM")?;
    assert_eq!(
        parsed.entries()[0].host(),
        &Host::Hostname("example.com".into())
    );
    for bad in ["a;b", "exa_mple.com", "a b"] {
        assert!(
            SipViaEntry::new("SIP", "2.0", "UDP", Host::Hostname(bad.into())).is_err(),
            "{bad}"
        );
    }
    Ok(())
}

#[test]
fn via_entry_without_host_is_dropped() -> R {
    let parsed = SipVia::parse_with_warnings("SIP/2.0/UDP :5060, SIP/2.0/TCP 198.51.100.1")?;
    assert_eq!(
        parsed
            .value
            .len(),
        1
    );
    let w = parsed.warnings[0];
    assert_eq!(
        (w.field, w.code, w.kind, w.entry),
        (
            Field::Entry,
            WarningCode::SkippedEntry,
            WarningKind::Lost,
            Some(0)
        )
    );
    assert_eq!(SipVia::parse("SIP/2.0/UDP :5060"), Err(empty()));
    Ok(())
}

#[test]
fn join_has_no_early_only() -> R {
    let wire = "a@example.com;to-tag=t;from-tag=f;early-only";
    let join = SipJoin::parse_strict(wire)?;
    assert_eq!((join.to_tag(), join.from_tag()), ("t", "f"));
    assert_eq!(join.param("early-only"), Some(None));
    assert_eq!(join.to_string(), wire);
    let built = SipJoin::new("a@example.com", "t", "f")?.with_param("early-only", None::<&str>)?;
    assert_eq!(built, join);
    assert!(SipJoin::new("a@example.com", "t", "f")?
        .with_param("from-tag", Some("x"))
        .is_err());

    let headers: HashMap<String, String> = [(
        "Join".to_string(),
        "a@example.com;to-tag=t;from-tag=f".to_string(),
    )]
    .into();
    assert_eq!(
        headers.join()?,
        Some(SipJoin::new("a@example.com", "t", "f")?)
    );
    Ok(())
}

#[test]
fn reason_keeps_cause_digits_and_extension_params() -> R {
    let wire = r#"Q.850;cause=0016;text="Normal";location=LN"#;
    let reason = SipReason::parse_strict(wire)?;
    assert_eq!(reason.protocol(), "Q.850");
    let cause = reason
        .cause()
        .unwrap();
    assert_eq!((cause.as_str(), cause.as_u16()), ("0016", Some(16)));
    assert_eq!(reason.text(), Some("Normal"));
    assert_eq!(reason.param("location"), Some(Some("LN")));
    assert_eq!(reason.to_string(), wire);

    let big = SipReason::parse_with_warnings("SIP;cause=70000")?;
    assert!(big
        .warnings
        .is_empty());
    assert_eq!(
        big.value
            .cause()
            .map(SipReasonCause::as_u16),
        Some(None)
    );

    let bad = SipReason::parse_with_warnings("SIP;cause=+5")?;
    assert_eq!(
        bad.value
            .cause(),
        None
    );
    assert_eq!(
        (bad.warnings[0].field, bad.warnings[0].code),
        (Field::Cause, WarningCode::InvalidCause)
    );
    Ok(())
}

#[test]
fn reason_builds_and_refuses() -> R {
    let built = SipReason::new("SIP")?
        .with_cause(302)
        .with_text("Moved")?
        .with_param("x", Some("y"))?;
    assert_eq!(built.to_string(), r#"SIP;cause=302;text="Moved";x=y"#);
    assert_eq!(
        SipReason::parse_strict(&built.to_string()),
        Ok(built.clone())
    );
    assert_eq!(
        built
            .clone()
            .with_cause(SipReasonCause::new("0302")?)
            .to_string(),
        r#"SIP;cause=0302;text="Moved";x=y"#
    );
    for key in ["cause", "TEXT"] {
        assert!(built
            .clone()
            .with_param(key, Some("1"))
            .is_err());
    }
    for protocol in ["", "S;IP", "S IP"] {
        assert!(SipReason::new(protocol).is_err(), "{protocol:?}");
    }
    for digits in ["", "1a", "+5", "1 2"] {
        assert!(SipReasonCause::new(digits).is_err(), "{digits:?}");
    }
    assert_eq!(SipReasonCause::from(16).as_str(), "16");
    Ok(())
}

#[test]
fn addr_reason_is_a_sip_reason() -> R {
    let addr = SipHeaderAddr::parse(
        "<sip:a@example.com?Reason=Q.850%3Bcause%3D16%3Blocation%3DLN>;index=1",
    )?;
    let reason: SipReason = addr
        .reason()
        .unwrap()?;
    assert_eq!(reason.param("location"), Some(Some("LN")));
    assert_eq!(
        reason
            .cause()
            .and_then(SipReasonCause::as_u16),
        Some(16)
    );
    Ok(())
}
