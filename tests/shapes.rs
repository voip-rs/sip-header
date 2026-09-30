//! What each value type holds, how it prints and what it refuses.

use std::collections::HashMap;

use sip_header::sip_uri::{Host, Uri, UriParse, WarningKind};
use sip_header::{
    AddrParts, ContactList, Fault, FaultCode, Field, HeaderParse, HistoryInfo, HistoryInfoEntry,
    ListParse, ParseError, SipAccept, SipAcceptEncoding, SipAcceptLanguage, SipGeolocation,
    SipGeolocationEntry, SipHeaderAddr, SipHeaderAddrList, SipHeaderLookup, SipJoin, SipReason,
    SipReasonCause, SipReasonList, SipSecurity, SipVia, SipViaEntry, SipWarning, UriInfo,
    UriInfoEntry, WarningCode,
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

/// A blank entry between `a` and `b` is dropped under EmptyEntry; an
/// all-blank list is `all_blank`.
fn blank_beside_real<T>(a: &str, b: &str, all_blank: Result<T, ParseError>)
where
    T: ListParse + PartialEq + std::fmt::Debug,
{
    let wire = format!("{a}, , {b}");
    let parsed = T::parse_with_warnings(&wire).unwrap_or_else(|e| panic!("{wire}: {e}"));
    assert_eq!(
        parsed.value,
        T::parse(&format!("{a}, {b}")).unwrap(),
        "{wire}"
    );
    let seen: Vec<_> = parsed
        .warnings
        .iter()
        .map(|w| (w.field, w.code, w.position, w.entry))
        .collect();
    assert_eq!(
        seen,
        [(
            Field::Entry,
            WarningCode::EmptyEntry,
            Some(a.len() + 1),
            Some(1)
        )],
        "{wire}"
    );
    assert_eq!(
        T::parse_strict(&wire),
        Err(ParseError::NonConformant(parsed.warnings[0]))
    );
    let split = T::from_entries_with_warnings([a, "", b]).unwrap();
    assert_eq!(split.value, parsed.value, "{wire}");
    let in_rows: Vec<_> = split
        .warnings
        .iter()
        .map(|w| (w.field, w.code, w.position, w.row, w.entry))
        .collect();
    assert_eq!(
        in_rows,
        [(
            Field::Entry,
            WarningCode::EmptyEntry,
            Some(0),
            Some(1),
            Some(1)
        )],
        "{wire}"
    );
    assert_eq!(T::parse(" , "), all_blank, "{a}");
}

#[test]
fn blank_entry_beside_real_ones_is_empty_entry() {
    blank_beside_real::<SipAccept>("application/sdp", "text/plain", Ok(SipAccept::new(vec![])));
    blank_beside_real::<SipAcceptEncoding>("gzip", "identity", Ok(SipAcceptEncoding::new(vec![])));
    blank_beside_real::<SipAcceptLanguage>("en", "fr", Ok(SipAcceptLanguage::new(vec![])));
    blank_beside_real::<SipHeaderAddrList>(
        "<sip:a@example.com>",
        "<sip:b@example.com>",
        Err(empty()),
    );
    blank_beside_real::<ContactList>("<sip:a@example.com>", "<sip:b@example.com>", Err(empty()));
    blank_beside_real::<HistoryInfo>(
        "<sip:a@example.com>;index=1",
        "<sip:b@example.com>;index=2",
        Err(empty()),
    );
    blank_beside_real::<SipVia>(
        "SIP/2.0/UDP a.example.com",
        "SIP/2.0/UDP b.example.com",
        Err(empty()),
    );
    blank_beside_real::<SipWarning>(
        r#"399 example.com "a""#,
        r#"399 example.com "b""#,
        Err(empty()),
    );
    blank_beside_real::<SipSecurity>("tls;q=0.1", "digest", Err(empty()));
    blank_beside_real::<SipReasonList>("SIP;cause=200", "Q.850;cause=16", Err(empty()));
    blank_beside_real::<UriInfo>(
        "<http://example.com/a>",
        "<http://example.com/b>",
        Err(empty()),
    );
    blank_beside_real::<SipGeolocation>("<cid:a@example.com>", "<cid:b@example.com>", Err(empty()));
}

mod equality_and_case {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    use sip_header::{
        ContactList, Fault, HeaderParams, HeaderParse, HistoryInfo, HistoryInfoEntry, ParseError,
        ParseWarning, Parsed, QValue, SipAccept, SipAcceptEncoding, SipAcceptEncodingEntry,
        SipAcceptEntry, SipAcceptLanguage, SipAcceptLanguageEntry, SipAuthValue, SipGeolocation,
        SipGeolocationEntry, SipHeaderAddr, SipJoin, SipReason, SipReasonCause, SipReplaces,
        SipSecurity, SipSecurityMechanism, SipTargetDialog, SipVia, SipViaEntry, SipWarning,
        SipWarningEntry, UriFault, UriInfo, UriInfoEntry,
    };

    type R = Result<(), ParseError>;

    fn value_type<T: Send + Sync + Clone + Eq + Hash + std::fmt::Debug + std::fmt::Display>() {}

    fn send_sync<T: Send + Sync>() {}

    #[test]
    fn every_value_type_is_send_sync_and_hashable() {
        value_type::<SipHeaderAddr>();
        value_type::<ContactList>();
        value_type::<SipVia>();
        value_type::<SipViaEntry>();
        value_type::<SipWarning>();
        value_type::<SipWarningEntry>();
        value_type::<SipAuthValue>();
        value_type::<SipAccept>();
        value_type::<SipAcceptEntry>();
        value_type::<SipAcceptEncoding>();
        value_type::<SipAcceptEncodingEntry>();
        value_type::<SipAcceptLanguage>();
        value_type::<SipAcceptLanguageEntry>();
        value_type::<SipSecurity>();
        value_type::<SipSecurityMechanism>();
        value_type::<UriInfo>();
        value_type::<UriInfoEntry>();
        value_type::<SipGeolocation>();
        value_type::<SipGeolocationEntry>();
        value_type::<HistoryInfo>();
        value_type::<HistoryInfoEntry>();
        value_type::<SipReason>();
        value_type::<SipReasonCause>();
        value_type::<SipReplaces>();
        value_type::<SipJoin>();
        value_type::<SipTargetDialog>();
        value_type::<HeaderParams>();
        value_type::<QValue>();
        send_sync::<ParseError>();
        send_sync::<ParseWarning>();
        send_sync::<Fault>();
        send_sync::<UriFault>();
        send_sync::<Parsed<SipVia>>();
    }

    fn hash<T: Hash>(v: &T) -> u64 {
        let mut h = DefaultHasher::new();
        v.hash(&mut h);
        h.finish()
    }

    fn same<T: HeaderParse + Hash + Eq + std::fmt::Debug>(a: &str, b: &str) {
        let (a, b) = (T::parse(a).unwrap(), T::parse(b).unwrap());
        assert_eq!(a, b);
        assert_eq!(hash(&a), hash(&b));
    }

    #[test]
    fn equal_values_hash_equal() {
        same::<SipAccept>("Text/Plain;a=1;b=2", "text/plain;b=2;a=1");
        same::<SipVia>(
            "SIP/2.0/UDP Example.COM;branch=x",
            "SIP/2.0/UDP example.com;branch=x",
        );
        same::<SipHeaderAddr>(
            "<sip:a@example.com>;x=1;tag=t",
            "<sip:a@example.com>;tag=t;x=1",
        );
        same::<ContactList>("*", " * ");
        same::<SipReason>("SIP;text=\"a\";cause=1", "SIP;cause=1;text=\"a\"");
        same::<SipReplaces>(
            "a@example.com;from-tag=f;to-tag=t",
            "a@example.com;to-tag=t;from-tag=f",
        );
    }

    #[test]
    fn protocol_tokens_compare_without_case_and_print_as_sent() -> R {
        same::<SipVia>(
            "SIP/2.0/UDP 198.51.100.1;branch=x",
            "sip/2.0/udp 198.51.100.1;branch=x",
        );
        same::<SipVia>("SIP/2.0A/TLS 198.51.100.1", "SIP/2.0a/tls 198.51.100.1");
        same::<SipReason>("Q.850;cause=16", "q.850;cause=16");
        assert_ne!(
            SipVia::parse("SIP/2.0/UDP 198.51.100.1")?,
            SipVia::parse("SIP/2.0/TCP 198.51.100.1")?
        );
        assert_ne!(SipReason::parse("SIP")?, SipReason::parse("Q.850")?);
        let via = SipVia::parse("sip/2.0/Udp 198.51.100.1")?;
        assert_eq!(via.to_string(), "sip/2.0/Udp 198.51.100.1");
        assert_eq!(
            SipReason::parse("q.850;cause=16")?.to_string(),
            "q.850;cause=16"
        );
        Ok(())
    }

    #[test]
    fn case_rules() -> R {
        let accept = SipAccept::parse("Application/SDP")?;
        assert_eq!(accept.entries()[0].media_range(), "application/sdp");
        let coding = SipAcceptEncoding::parse("GZIP")?;
        assert_eq!(coding.entries()[0].encoding(), "gzip");
        let language = SipAcceptLanguage::parse("EN-US")?;
        assert_eq!(language.entries()[0].language(), "en-us");
        let security = SipSecurity::parse("Digest;D-Alg=MD5")?;
        assert_eq!(security.entries()[0].mechanism(), "digest");
        assert_eq!(security.entries()[0].d_alg(), Some("MD5"));
        let auth = SipAuthValue::parse("DIGEST realm=\"a\"")?;
        assert_eq!(auth.scheme(), "DIGEST");
        let replaces = SipReplaces::parse("AbC@Example.com;to-tag=Tt;from-tag=fF")?;
        assert_eq!(
            (replaces.call_id(), replaces.to_tag(), replaces.from_tag()),
            ("AbC@Example.com", "Tt", "fF")
        );
        let via = SipVia::parse("sip/2.0/udp 198.51.100.1")?;
        assert_eq!(
            (via.entries()[0].protocol(), via.entries()[0].transport()),
            ("sip", "udp")
        );
        Ok(())
    }

    #[test]
    fn q_is_a_qvalue() -> R {
        let accept = SipAccept::parse("text/plain;q=0.5, text/html;Q=1.000, a/b;q=high, c/d")?;
        let q: Vec<_> = accept
            .entries()
            .iter()
            .map(|e| {
                e.q()
                    .map(QValue::thousandths)
            })
            .collect();
        assert_eq!(q, vec![Some(500), Some(1000), None, None]);
        assert_eq!(accept.entries()[2].param("q"), Some(Some("high")));
        assert_eq!(
            SipAcceptEncoding::parse("gzip;q=0.050")?.entries()[0].q(),
            Some(QValue::new(50)?)
        );
        assert_eq!(
            SipAcceptLanguage::parse("fr;q=0")?.entries()[0].q(),
            Some(QValue::new(0)?)
        );
        assert_eq!(
            SipSecurity::parse("digest;q=0.1")?.entries()[0].q(),
            Some(QValue::new(100)?)
        );
        assert!(SipSecurityMechanism::new("tls")?
            .with_param("q", Some("2"))
            .is_err());
        assert!(SipSecurity::parse_strict("tls;q=2").is_err());
        Ok(())
    }

    #[test]
    fn qvalue_reads_and_prints_the_grammar() -> R {
        for (text, thousandths, canonical) in [
            ("0", 0, "0"),
            ("0.", 0, "0"),
            ("0.5", 500, "0.5"),
            ("0.050", 50, "0.05"),
            ("0.123", 123, "0.123"),
            ("1", 1000, "1"),
            ("1.000", 1000, "1"),
        ] {
            let q: QValue = text.parse()?;
            assert_eq!(q.thousandths(), thousandths, "{text}");
            assert_eq!(q.to_string(), canonical, "{text}");
        }
        for bad in ["", ".5", "1.5", "2", "0.1234", "01", "0,5", "-0"] {
            assert!(
                bad.parse::<QValue>()
                    .is_err(),
                "{bad:?}"
            );
        }
        assert!(QValue::new(1001).is_err());
        assert!(QValue::new(1)? < QValue::new(2)?);
        Ok(())
    }

    #[test]
    fn lists_separate_with_comma_space() -> R {
        let hi = HistoryInfo::parse("<sip:a@example.com>;index=1,<sip:b@example.com>;index=2")?;
        assert_eq!(
            hi.to_string(),
            "<sip:a@example.com>;index=1, <sip:b@example.com>;index=2"
        );
        let info = UriInfo::parse("<https://example.com/a>,<https://example.com/b>")?;
        assert_eq!(
            info.to_string(),
            "<https://example.com/a>, <https://example.com/b>"
        );
        assert_eq!(
            SipWarning::parse(r#"399 a.example.com "x",399 b.example.com "y""#)?.to_string(),
            r#"399 a.example.com "x", 399 b.example.com "y""#
        );
        Ok(())
    }

    #[cfg(feature = "serde")]
    #[test]
    fn dialog_framing_serializes_kebab_case() {
        use sip_header::DialogFraming;

        assert_eq!(
            serde_json::to_value(DialogFraming::UriHeader).unwrap(),
            serde_json::json!("uri-header")
        );
        assert_eq!(
            serde_json::from_value::<DialogFraming>(serde_json::json!("uri-header")).unwrap(),
            DialogFraming::UriHeader
        );
        assert_eq!(
            serde_json::to_value(DialogFraming::Header).unwrap(),
            serde_json::json!("header")
        );
        let target = SipTargetDialog::new("a@example.com", "l", "r")
            .unwrap()
            .with_framing(DialogFraming::UriHeader);
        assert_eq!(
            serde_json::to_value(&target).unwrap()["framing"],
            serde_json::json!("uri-header")
        );
    }
}
