use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use sip_header::sip_uri::{Uri, UriParse};
use sip_header::{
    FaultCode, Field, HeaderParams, HeaderParse, HistoryInfoEntry, ParseError, SipAuthValue,
    SipHeaderAddr, SipReplaces, SipTargetDialog, SipViaEntry, WarningCode,
};
use sip_uri::WarningKind;

fn addr() -> SipHeaderAddr {
    SipHeaderAddr::new(Uri::parse("sip:alice@example.com").unwrap()).unwrap()
}

fn params_of(tail: &str) -> HeaderParams {
    SipHeaderAddr::parse(&format!("<sip:alice@example.com>{tail}"))
        .unwrap()
        .params()
        .clone()
}

fn hash_of(p: &HeaderParams) -> u64 {
    let mut h = DefaultHasher::new();
    p.hash(&mut h);
    h.finish()
}

fn is_misplaced_param<T: std::fmt::Debug>(r: Result<T, ParseError>) -> bool {
    matches!(
        r,
        Err(ParseError::Malformed(f)) if f.field == Field::Param && f.code == FaultCode::Misplaced
    )
}

#[test]
fn iter_len_and_get_follow_wire_order() {
    let p = params_of(";Tag=abc;lr;e=\"\";X=1;x=2");
    assert_eq!(
        p.iter()
            .collect::<Vec<_>>(),
        vec![
            ("tag", Some("abc")),
            ("lr", None),
            ("e", Some("")),
            ("x", Some("1")),
            ("x", Some("2"))
        ]
    );
    assert_eq!(p.len(), 5);
    assert!(!p.is_empty());
    assert_eq!(p.get("TAG"), Some(Some("abc")));
    assert_eq!(p.get("lr"), Some(None));
    assert_eq!(p.get("e"), Some(Some("")));
    assert_eq!(p.get("x"), Some(Some("1")));
    assert_eq!(p.get("absent"), None);
    assert!(params_of("").is_empty());
}

#[test]
fn setting_an_existing_key_replaces_it_in_place() {
    let a = SipHeaderAddr::parse("<sip:alice@example.com>;a=1;b=2;a=3")
        .unwrap()
        .with_param("A", Some("x"))
        .unwrap();
    assert_eq!(a.to_string(), "<sip:alice@example.com>;a=x;b=2");
    let a = SipHeaderAddr::parse("<sip:alice@example.com>;tag=1;x=y;tag=2")
        .unwrap()
        .with_tag("t")
        .unwrap();
    assert_eq!(a.to_string(), "<sip:alice@example.com>;tag=t;x=y");
    assert_eq!(a.tag(), Some("t"));
    assert_eq!(
        addr()
            .with_param("x", Some("1"))
            .unwrap()
            .with_tag("t")
            .unwrap()
            .to_string(),
        "<sip:alice@example.com>;x=1;tag=t"
    );
}

#[test]
fn reserved_keys_refuse_the_generic_setter() {
    assert!(is_misplaced_param(addr().with_param("Tag", Some("x"))));
    assert!(addr()
        .with_tag("a b")
        .is_err());
    let via = SipViaEntry::new(
        "SIP",
        "2.0",
        "UDP",
        sip_header::sip_uri::Host::IPv4([198, 51, 100, 1].into()),
    )
    .unwrap();
    assert!(is_misplaced_param(
        via.clone()
            .with_param("rport", None)
    ));
    let via = via.with_rport(Some(5060));
    assert_eq!(via.rport(), Some(Some(5060)));
    assert_eq!(via.to_string(), "SIP/2.0/UDP 198.51.100.1;rport=5060");
    let via = via.with_rport(None);
    assert_eq!(via.rport(), Some(None));
    assert_eq!(via.to_string(), "SIP/2.0/UDP 198.51.100.1;rport");

    let r = SipReplaces::new("a@example.com", "t", "f").unwrap();
    for key in ["to-tag", "From-Tag", "early-only"] {
        assert!(
            is_misplaced_param(
                r.clone()
                    .with_param(key, None)
            ),
            "{key}"
        );
    }
    let r = r
        .with_to_tag("t2")
        .and_then(|r| r.with_from_tag("f2"))
        .unwrap();
    assert_eq!(r.to_string(), "a@example.com;to-tag=t2;from-tag=f2");
    assert!(r
        .with_to_tag("a;b")
        .is_err());

    let t = SipTargetDialog::new("a@example.com", "l", "r").unwrap();
    assert!(is_misplaced_param(
        t.clone()
            .with_param("local-tag", Some("x"))
    ));
    assert_eq!(
        t.with_param("early-only", None)
            .and_then(|t| t.with_remote_tag("r2"))
            .map(|t| t.to_string()),
        Ok("a@example.com;local-tag=l;remote-tag=r2;early-only".to_string())
    );
}

#[test]
fn history_info_index_setter() {
    let entry = HistoryInfoEntry::new(
        SipHeaderAddr::parse("<sip:a@example.com>;index=1;index=2").unwrap(),
        "1.1",
    )
    .unwrap();
    assert_eq!(entry.index(), Some("1.1"));
    assert_eq!(entry.to_string(), "<sip:a@example.com>;index=1.1");
    assert_eq!(
        entry
            .params()
            .len(),
        1
    );
    assert!(entry
        .with_index("1..2")
        .is_err());
}

#[test]
fn values_are_bare_only_when_a_token_or_host() {
    let a = addr()
        .with_param("received", Some("2001:db8::1"))
        .and_then(|a| a.with_param("maddr", Some("[2001:db8::1]")))
        .and_then(|a| a.with_param("branch", Some("z9hG4bK1")))
        .and_then(|a| a.with_param("note", Some("a b")))
        .and_then(|a| a.with_param("e", Some("")))
        .and_then(|a| a.with_param("f", None))
        .unwrap();
    assert_eq!(
        a.to_string(),
        r#"<sip:alice@example.com>;received=2001:db8::1;maddr=[2001:db8::1];branch=z9hG4bK1;note="a b";e="";f"#
    );
    let p = a.params();
    assert!(!p.is_quoted("received"));
    assert!(!p.is_quoted("maddr"));
    assert!(p.is_quoted("note"));
    assert!(p.is_quoted("e"));
    assert!(!p.is_quoted("f"));
    assert!(!p.is_quoted("absent"));
    assert_eq!(p.get("e"), Some(Some("")));
    assert_eq!(p.get("f"), Some(None));
    assert_eq!(SipHeaderAddr::parse_strict(&a.to_string()), Ok(a));
}

#[test]
fn quoted_token_stays_quoted() {
    let p = params_of(r#";a="x";b=x"#);
    assert_eq!(p.get("a"), Some(Some("x")));
    assert!(p.is_quoted("a"));
    assert!(!p.is_quoted("b"));
    assert_eq!(p.to_string(), r#";a="x";b=x"#);
    let quoted = addr()
        .with_quoted_param("a", "x")
        .unwrap();
    assert_eq!(quoted.params(), &params_of(r#";a="x""#));
}

#[test]
fn display_escapes_and_parses_back() {
    let text = r#"say "hi" \o/"#;
    let a = addr()
        .with_param("t", Some(text))
        .unwrap();
    assert_eq!(
        a.to_string(),
        r#"<sip:alice@example.com>;t="say \"hi\" \\o/""#
    );
    let back = SipHeaderAddr::parse_strict(&a.to_string()).unwrap();
    assert_eq!(
        back.params()
            .get("t"),
        Some(Some(text))
    );
    assert_eq!(back, a);
}

#[test]
fn equality_ignores_order_across_keys_only() {
    let ab = params_of(";a=1;b=2");
    let ba = params_of(";b=2;a=1");
    assert_eq!(ab, ba);
    assert_eq!(hash_of(&ab), hash_of(&ba));
    assert_ne!(params_of(";a=1;a=2"), params_of(";a=2;a=1"));
    assert_eq!(params_of(";a=1;b=0;a=2"), params_of(";b=0;a=1;a=2"));
    assert_ne!(params_of(";a=x"), params_of(r#";a="x""#));
    assert_ne!(params_of(";a"), params_of(r#";a="""#));
    assert_ne!(params_of(";a=1"), params_of(";a=1;a=1"));
}

#[test]
fn duplicate_param_is_warned() {
    let input = "<sip:alice@example.com>;x=1;X=2";
    let a = SipHeaderAddr::parse(input).unwrap();
    assert_eq!(
        a.params()
            .get("x"),
        Some(Some("1"))
    );
    assert_eq!(
        a.params()
            .len(),
        2
    );
    let parsed = SipHeaderAddr::parse_with_warnings(input).unwrap();
    assert_eq!(parsed.value, a);
    let w = parsed.warnings[0];
    assert_eq!(
        (w.field, w.code, w.kind, w.position),
        (
            Field::Param,
            WarningCode::DuplicateParam,
            WarningKind::Recovered,
            input.find('X')
        )
    );
    assert_eq!(
        SipHeaderAddr::parse_strict(input),
        Err(ParseError::NonConformant(w))
    );
    assert_eq!(a.to_string(), "<sip:alice@example.com>;x=1;x=2");
}

#[test]
fn auth_flag_is_warned() {
    let input = r#"Digest realm="example.com", stale, nonce="abc""#;
    let auth = SipAuthValue::parse(input).unwrap();
    assert_eq!(auth.param("stale"), Some(None));
    assert_eq!(auth.nonce(), Some("abc"));
    let parsed = SipAuthValue::parse_with_warnings(input).unwrap();
    assert_eq!(parsed.value, auth);
    let w = parsed.warnings[0];
    assert_eq!(
        (w.field, w.code, w.kind, w.position),
        (
            Field::Credentials,
            WarningCode::AuthParamFlag,
            WarningKind::Recovered,
            input.find("stale")
        )
    );
    assert_eq!(
        SipAuthValue::parse_strict(input),
        Err(ParseError::NonConformant(w))
    );
    assert_eq!(auth.to_string(), input);
    assert_eq!(
        auth.params()
            .get("realm"),
        Some(Some("example.com"))
    );
}

#[test]
fn auth_params_separate_with_comma() {
    let auth = SipAuthValue::new("Digest")
        .and_then(|a| a.with_param("realm", "example.com"))
        .and_then(|a| a.with_param("algorithm", "MD5"))
        .and_then(|a| a.with_quoted_param("qop", "auth"))
        .unwrap();
    assert_eq!(
        auth.to_string(),
        r#"Digest realm="example.com", algorithm=MD5, qop="auth""#
    );
    assert!(SipAuthValue::new("Digest")
        .and_then(|a| a.with_param("a b", "x"))
        .is_err());
}

#[cfg(feature = "serde")]
mod serde_shape {
    use super::*;
    use serde_json::json;

    #[test]
    fn params_serialize_as_name_value_quoted() {
        let a = addr()
            .with_tag("abc")
            .and_then(|a| a.with_param("lr", None))
            .and_then(|a| a.with_param("note", Some("a b")))
            .and_then(|a| a.with_param("x", Some("1")))
            .unwrap();
        let v = serde_json::to_value(&a).unwrap();
        assert_eq!(v["tag"], json!("abc"));
        assert_eq!(
            v["params"],
            json!([
                ["lr", null, false],
                ["note", "a b", true],
                ["x", "1", false]
            ])
        );
        assert_eq!(serde_json::from_value::<SipHeaderAddr>(v).unwrap(), a);
        assert_eq!(
            serde_json::to_value(a.params()).unwrap(),
            json!([
                ["tag", "abc", false],
                ["lr", null, false],
                ["note", "a b", true],
                ["x", "1", false]
            ])
        );
    }

    #[test]
    fn params_deserialize_normalizes_quoting_and_lowercases() {
        let p: HeaderParams =
            serde_json::from_value(json!([["X", "a b", false], ["e", "", false]])).unwrap();
        assert_eq!(p.to_string(), r#";x="a b";e="""#);
        assert!(p.is_quoted("x"));
    }

    fn refused(params: serde_json::Value) {
        assert!(
            serde_json::from_value::<HeaderParams>(params.clone()).is_err(),
            "{params}"
        );
    }

    #[test]
    fn params_deserialize_refuses_what_no_parse_produces() {
        refused(json!([["lr", null, true]]));
        refused(json!([["", null, false]]));
        refused(json!([["a;b", "1", false]]));
        refused(json!([["a=b", null, false]]));
        refused(json!([["x", "a\r\nb", true]]));
        refused(json!([["x\0", "1", false]]));
        refused(json!([["x", "1"]]));
    }

    #[test]
    fn params_deserialize_reads_back_what_the_parser_keeps() {
        for tail in [";x=1;X=2", ";a b=1", ";x=\"\\\"p\""] {
            let p = params_of(tail);
            let json = serde_json::to_value(&p).unwrap();
            assert_eq!(
                serde_json::from_value::<HeaderParams>(json).unwrap(),
                p,
                "{tail}"
            );
        }
    }

    fn reads_back<T>(value: &T)
    where
        T: serde::Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
    {
        let json = serde_json::to_value(value).unwrap();
        assert_eq!(&serde_json::from_value::<T>(json).unwrap(), value);
    }

    #[test]
    fn reserved_keys_the_parser_keeps_read_back() {
        for tail in [
            ";tag=a;tag=b",
            r#";tag="a b""#,
            r#";tag="a";tag=b"#,
            ";tag;tag=a",
        ] {
            let a = SipHeaderAddr::parse(&format!("<sip:alice@example.com>{tail}")).unwrap();
            reads_back(&a);
        }
        let a = SipHeaderAddr::parse("<sip:alice@example.com>;tag=a;tag=b").unwrap();
        let v = serde_json::to_value(&a).unwrap();
        assert_eq!(v["tag"], json!("a"));
        assert_eq!(v["params"], json!([["tag", "b", false]]));
        let a = SipHeaderAddr::parse(r#"<sip:alice@example.com>;tag="a b""#).unwrap();
        let v = serde_json::to_value(&a).unwrap();
        assert_eq!(v["tag"], json!(null));
        assert_eq!(v["params"], json!([["tag", "a b", true]]));

        for input in [
            "SIP/2.0/UDP 198.51.100.1;rport;rport=5060",
            "SIP/2.0/UDP 198.51.100.1;rport=05060",
            r#"SIP/2.0/UDP 198.51.100.1;rport="5060""#,
        ] {
            reads_back(&sip_header::SipVia::parse(input).unwrap());
        }
        for input in [
            "a@example.com;to-tag=t;from-tag=f;early-only;early-only",
            "a@example.com;to-tag=t;from-tag=f;early-only=x",
            "a@example.com;to-tag;to-tag=t;from-tag=f",
            r#"a@example.com;to-tag="t";from-tag=f"#,
            "a b@example.com;to-tag=t;from-tag=f",
        ] {
            reads_back(&SipReplaces::parse(input).unwrap());
        }
        reads_back(&SipAuthValue::parse(r#"Digest realm="a", stale, realm="b""#).unwrap());
    }

    #[test]
    fn a_reserved_key_the_field_would_carry_is_refused_in_params() {
        let mut v = serde_json::to_value(addr()).unwrap();
        v["params"] = json!([["tag", "abc", false]]);
        assert!(serde_json::from_value::<SipHeaderAddr>(v.clone()).is_err());
        v["tag"] = json!("abc");
        assert_eq!(
            serde_json::from_value::<SipHeaderAddr>(v)
                .unwrap()
                .to_string(),
            "<sip:alice@example.com>;tag=abc;tag=abc"
        );

        let mut r =
            serde_json::to_value(SipReplaces::new("a@example.com", "t", "f").unwrap()).unwrap();
        r["params"] = json!([["early-only", null, false]]);
        assert!(serde_json::from_value::<SipReplaces>(r).is_err());

        let via = SipViaEntry::new(
            "SIP",
            "2.0",
            "UDP",
            sip_header::sip_uri::Host::IPv4([198, 51, 100, 1].into()),
        )
        .unwrap()
        .with_rport(None);
        let mut v = serde_json::to_value(&via).unwrap();
        assert_eq!(v["rport"], json!(null));
        assert_eq!(v["params"], json!([]));
        assert_eq!(
            serde_json::from_value::<SipViaEntry>(v.clone()).unwrap(),
            via
        );
        v.as_object_mut()
            .unwrap()
            .remove("rport");
        v["params"] = json!([["rport", "5060", false]]);
        assert!(serde_json::from_value::<SipViaEntry>(v).is_err());
    }
}
