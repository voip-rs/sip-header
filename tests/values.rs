use sip_header::sip_uri::{Host, SipUri, TelUri, Uri, UriParse};
use sip_header::{
    ContactList, DialogFraming, HistoryInfo, HistoryInfoEntry, ParseError, SipAccept,
    SipAcceptEncoding, SipAcceptEncodingEntry, SipAcceptEntry, SipAcceptLanguage,
    SipAcceptLanguageEntry, SipAuthValue, SipGeolocation, SipGeolocationEntry, SipHeaderAddr,
    SipReason, SipReplaces, SipSecurity, SipSecurityMechanism, SipTargetDialog, SipVia,
    SipViaEntry, SipWarning, SipWarningEntry, UriInfo, UriInfoEntry,
};

type R = Result<(), ParseError>;

fn uri(s: &str) -> Uri {
    Uri::parse(s).unwrap()
}

fn alice() -> Uri {
    SipUri::new(Host::Hostname("example.com".into()))
        .with_user("alice")
        .into()
}

fn addr() -> SipHeaderAddr {
    SipHeaderAddr::new(alice())
        .and_then(|a| a.with_display_name("Alice Smith"))
        .and_then(|a| a.with_tag("abc"))
        .and_then(|a| a.with_param("lr", None))
        .unwrap()
}

fn via() -> SipVia {
    SipVia::new(vec![SipViaEntry::new(
        "SIP",
        "2.0",
        "TCP",
        Host::IPv6(
            "2001:db8::1"
                .parse()
                .unwrap(),
        ),
    )
    .map(|v| {
        v.with_port(5061)
            .with_rport(None)
    })
    .and_then(|v| v.with_param("branch", Some("z9hG4bK1")))
    .unwrap()])
    .unwrap()
}

fn replaces() -> SipReplaces {
    SipReplaces::new("a@example.com", "t", "f")
        .map(|r| r.with_early_only(true))
        .and_then(|r| r.with_param("foo", Some("bar")))
        .unwrap()
}

#[test]
fn addr_constructors_and_display() -> R {
    let addr = addr();
    assert_eq!(addr.display_name(), Some("Alice Smith"));
    assert_eq!(addr.tag(), Some("abc"));
    assert_eq!(addr.param("lr"), Some(None));
    assert_eq!(
        addr.to_string(),
        r#""Alice Smith" <sip:alice@example.com>;tag=abc;lr"#
    );
    assert_eq!(
        SipHeaderAddr::new(TelUri::new("+15551234567").into())?.to_string(),
        "<tel:+15551234567>"
    );
    let contact = ContactList::new(vec![addr.clone(), addr])?;
    assert_eq!(
        contact.to_string(),
        r#""Alice Smith" <sip:alice@example.com>;tag=abc;lr, "Alice Smith" <sip:alice@example.com>;tag=abc;lr"#
    );
    assert_eq!(ContactList::wildcard().to_string(), "*");
    Ok(())
}

#[test]
fn list_and_entry_display() -> R {
    assert_eq!(
        via().to_string(),
        "SIP/2.0/TCP [2001:db8::1]:5061;rport;branch=z9hG4bK1"
    );
    assert_eq!(via().entries()[0].rport(), Some(None));
    assert_eq!(
        SipAccept::new(vec![
            SipAcceptEntry::new("Application", "SDP")?.with_param("q", Some("0.5"))?
        ])
        .to_string(),
        "application/sdp;q=0.5"
    );
    assert_eq!(
        SipAcceptEncoding::new(vec![SipAcceptEncodingEntry::new("gzip")?]).to_string(),
        "gzip"
    );
    assert_eq!(
        SipAcceptLanguage::new(vec![SipAcceptLanguageEntry::new("fr")?]).to_string(),
        "fr"
    );
    assert_eq!(
        SipWarning::new(vec![SipWarningEntry::new(399, "example.com", "a \"b\"")?])
            .unwrap()
            .to_string(),
        r#"399 example.com "a \"b\"""#
    );
    assert_eq!(
        SipSecurity::new(vec![
            SipSecurityMechanism::new("digest")?.with_quoted_param("d-alg", "md5")?
        ])
        .unwrap()
        .to_string(),
        r#"digest;d-alg="md5""#
    );
    assert_eq!(
        UriInfo::new(vec![
            UriInfoEntry::new(uri("https://example.com/i"))?.with_param("purpose", Some("icon"))?
        ])
        .unwrap()
        .to_string(),
        "<https://example.com/i>;purpose=icon"
    );
    assert_eq!(
        SipGeolocation::new(vec![SipGeolocationEntry::new(uri("cid:loc@example.com"))?])?
            .to_string(),
        "<cid:loc@example.com>"
    );
    assert_eq!(
        HistoryInfo::new(vec![HistoryInfoEntry::new(addr(), "1")?])?.to_string(),
        r#""Alice Smith" <sip:alice@example.com>;tag=abc;lr;index=1"#
    );
    assert_eq!(
        SipAuthValue::new("Digest")?
            .with_param("realm", "example.com")?
            .with_param("algorithm", "MD5")?
            .to_string(),
        r#"Digest realm="example.com", algorithm=MD5"#
    );
    let reason = SipReason::new("SIP")?
        .with_cause(302)
        .with_text("Moved")?;
    assert_eq!(
        (
            reason.protocol(),
            reason
                .cause()
                .as_ref()
                .map(|c| c.as_str()),
            reason.text()
        ),
        ("SIP", Some("302"), Some("Moved"))
    );
    Ok(())
}

#[test]
fn structural_invariants() -> R {
    assert!(
        SipViaEntry::new("SIP", "2.0", "UDP", Host::IPv4([198, 51, 100, 1].into()))?
            .with_param("RPORT", Some("5060"))
            .is_err()
    );
    assert_eq!(
        SipAuthValue::from_token68("Bearer", "abc")?
            .with_param("realm", "x")?
            .token68(),
        None
    );
    Ok(())
}

#[test]
fn dialog_ids() -> R {
    let r = replaces();
    assert_eq!(
        r.to_string(),
        "a@example.com;to-tag=t;from-tag=f;early-only;foo=bar"
    );
    assert_eq!(r.host(), Some("example.com"));
    assert_eq!(r.framing(), DialogFraming::Header);
    assert_eq!(
        r.with_framing(DialogFraming::UriHeader)
            .to_string(),
        "a%40example.com%3Bto-tag%3Dt%3Bfrom-tag%3Df%3Bearly-only%3Bfoo%3Dbar"
    );
    let t = SipTargetDialog::new("a@example.com", "l", "r")?;
    assert_eq!((t.local_tag(), t.remote_tag()), ("l", "r"));
    assert_eq!(t.to_string(), "a@example.com;local-tag=l;remote-tag=r");
    Ok(())
}

#[cfg(feature = "serde")]
mod serde_round_trip {
    use super::*;
    use serde::de::DeserializeOwned;
    use serde::Serialize;
    use serde_json::json;
    use sip_header::{
        HeaderParse, ListParse, SipCallId, SipHeader, SipHeaderAddrList, SipJoin, SipReasonCause,
        SipReasonList, TokenList, TypedHeader,
    };

    fn token_list() -> TokenList {
        TokenList::new(SipHeader::Supported, ["timer", "100rel"]).unwrap()
    }

    #[test]
    fn token_lists_round_trip_as_header_and_tokens() -> R {
        pinned(
            &token_list(),
            json!({"header": "Supported", "tokens": ["timer", "100rel"]}),
        );
        for header in <TokenList as TypedHeader>::HEADERS {
            let token = if *header == SipHeader::InReplyTo {
                "a@example.com"
            } else {
                "x"
            };
            round_trip(TokenList::new(*header, [token])?);
        }
        round_trip(TokenList::new(SipHeader::Allow, Vec::<&str>::new())?);
        assert_eq!(
            serde_json::from_value::<TokenList>(json!({"header": "k", "tokens": ["timer"]}))
                .unwrap(),
            TokenList::new(SipHeader::Supported, ["timer"])?
        );
        Ok(())
    }

    #[test]
    fn token_lists_refuse_what_new_refuses() {
        rejects::<TokenList>(json!({"header": "Require", "tokens": []}));
        rejects::<TokenList>(json!({"header": "Via", "tokens": ["secret"]}));
        rejects::<TokenList>(json!({"header": "Supported", "tokens": ["secret, x"]}));
        rejects::<TokenList>(json!({"header": "Supported", "tokens": ["secret\r\n"]}));
        rejects::<TokenList>(json!({"header": "X-Secret", "tokens": ["x"]}));
        rejects::<TokenList>(json!({"tokens": ["secret"]}));
        refuses_field(&token_list(), "unknown");
    }

    fn round_trip<T: Serialize + DeserializeOwned + PartialEq + std::fmt::Debug>(value: T) {
        let json = serde_json::to_value(&value).unwrap();
        assert_eq!(serde_json::from_value::<T>(json).unwrap(), value);
    }

    fn rejects<T: DeserializeOwned + std::fmt::Debug>(value: serde_json::Value) {
        let err = serde_json::from_value::<T>(value.clone()).unwrap_err();
        assert!(
            !err.to_string()
                .contains("secret"),
            "{err}"
        );
    }

    #[test]
    fn every_type_round_trips() -> R {
        round_trip(addr());
        round_trip(ContactList::new(vec![addr()])?);
        round_trip(ContactList::wildcard());
        round_trip(via());
        round_trip(SipAccept::new(vec![SipAcceptEntry::new(
            "application",
            "sdp",
        )?
        .with_param("q", Some("0.5"))?]));
        round_trip(SipAcceptEncoding::new(vec![SipAcceptEncodingEntry::new(
            "gzip",
        )?]));
        round_trip(SipAcceptLanguage::new(vec![SipAcceptLanguageEntry::new(
            "fr",
        )?]));
        round_trip(SipWarning::new(vec![SipWarningEntry::new(399, "example.com", "x")?]).unwrap());
        round_trip(
            SipSecurity::new(vec![SipSecurityMechanism::new("digest")?
                .with_param("q", Some("0.1"))?
                .with_quoted_param("d-alg", "md5")?])
            .unwrap(),
        );
        round_trip(SipAuthValue::new("Digest")?.with_quoted_param("realm", "example.com")?);
        round_trip(SipAuthValue::from_token68("Bearer", "abc.def")?);
        round_trip(UriInfo::new(vec![UriInfoEntry::new(uri("https://example.com/i"))?]).unwrap());
        round_trip(SipGeolocation::new(vec![SipGeolocationEntry::new(uri(
            "https://example.com/l",
        ))?
        .with_param("inserted-by", Some("example.com"))?])?);
        round_trip(HistoryInfo::new(vec![HistoryInfoEntry::new(
            addr(),
            "1.1",
        )?])?);
        round_trip(SipReason::new("SIP")?.with_cause(302));
        round_trip(replaces().with_framing(DialogFraming::UriHeader));
        round_trip(SipTargetDialog::new("a@example.com", "l", "r")?);
        Ok(())
    }

    fn pinned<T>(value: &T, expected: serde_json::Value)
    where
        T: Serialize + DeserializeOwned + PartialEq + std::fmt::Debug,
    {
        let json = serde_json::to_value(value).unwrap();
        assert_eq!(json, expected, "{json}");
        assert_eq!(&serde_json::from_value::<T>(json).unwrap(), value);
    }

    fn first<L: ListParse, E: Clone>(raw: &str, entries: impl Fn(&L) -> &[E]) -> E {
        entries(&L::parse(raw).unwrap())[0].clone()
    }

    #[test]
    fn parsed_values_serialize_as_pinned_parts() {
        pinned(
            &SipReason::parse(r#"SIP;cause=200;text="Call completed elsewhere";foo=bar"#).unwrap(),
            json!({
                "protocol": "SIP",
                "params": [
                    ["cause", "200", false],
                    ["text", "Call completed elsewhere", true],
                    ["foo", "bar", false],
                ],
            }),
        );
        pinned(
            &SipReason::parse(r#"SIP;text="x";cause=200"#).unwrap(),
            json!({
                "protocol": "SIP",
                "params": [["text", "x", true], ["cause", "200", false]],
            }),
        );
        pinned(
            &SipJoin::parse("a@example.com;to-tag=t;from-tag=f").unwrap(),
            json!({
                "call_id": "a@example.com",
                "to_tag": "t",
                "from_tag": "f",
                "params": [],
                "framing": "header",
            }),
        );
        pinned(
            &SipTargetDialog::parse("a@example.com;local-tag=l;remote-tag=r;x").unwrap(),
            json!({
                "call_id": "a@example.com",
                "local_tag": "l",
                "remote_tag": "r",
                "params": [["x", null, false]],
                "framing": "header",
            }),
        );
        pinned(
            &first(
                "<cid:loc@example.com>;inserted-by=example.com",
                SipGeolocation::entries,
            ),
            json!({
                "uri": {"other": {"scheme": "cid", "rest": "loc@example.com"}},
                "params": [["inserted-by", "example.com", false]],
            }),
        );
        pinned(
            &first("gzip;q=0.5", SipAcceptEncoding::entries),
            json!({"encoding": "gzip", "params": [["q", "0.5", false]]}),
        );
        pinned(
            &first("fr;q=0.8", SipAcceptLanguage::entries),
            json!({"language": "fr", "params": [["q", "0.8", false]]}),
        );
        pinned(
            &first("application/sdp;q=0.5", SipAccept::entries),
            json!({
                "media_type": "application",
                "subtype": "sdp",
                "params": [["q", "0.5", false]],
            }),
        );
        pinned(
            &first("<https://example.com/i.png>;purpose=icon", UriInfo::entries),
            json!({
                "uri": {"other": {"scheme": "https", "rest": "//example.com/i.png"}},
                "params": [["purpose", "icon", false]],
            }),
        );
        pinned(
            &first(
                "SIP/2.0/UDP 198.51.100.1:5060;rport;branch=z9hG4bK1",
                SipVia::entries,
            ),
            json!({
                "protocol": "SIP",
                "version": "2.0",
                "transport": "UDP",
                "host": {"ipv4": "198.51.100.1"},
                "port": 5060,
                "params": [["rport", null, false], ["branch", "z9hG4bK1", false]],
            }),
        );
        pinned(
            &first(r#"399 example.com "x""#, SipWarning::entries),
            json!({"code": 399, "agent": "example.com", "text": "x"}),
        );
        pinned(
            &first("digest;d-alg=md5;q=0.1", SipSecurity::entries),
            json!({
                "mechanism": "digest",
                "params": [["d-alg", "md5", false], ["q", "0.1", false]],
            }),
        );
        pinned(
            &first("<sip:a@example.com>;index=1", HistoryInfo::entries),
            json!({"addr": {
                "display_name": null,
                "uri": {"sip": {
                    "scheme": "sip",
                    "user": "a",
                    "user_params": [],
                    "password": null,
                    "host": {"hostname": "example.com"},
                    "port": null,
                    "params": [],
                    "headers": [],
                    "fragment": null,
                }},
                "params": [["index", "1", false]],
            }}),
        );
        pinned(
            &SipAuthValue::parse(r#"Digest realm="example.com", qop=auth"#).unwrap(),
            json!({
                "scheme": "Digest",
                "params": [["realm", "example.com", true], ["qop", "auth", false]],
                "token68": null,
            }),
        );
    }

    #[test]
    fn serializes_as_parts_with_every_field() -> R {
        pinned(
            &addr(),
            json!({
                "display_name": "Alice Smith",
                "uri": {"sip": {
                    "scheme": "sip",
                    "user": "alice",
                    "user_params": [],
                    "password": null,
                    "host": {"hostname": "example.com"},
                    "port": null,
                    "params": [],
                    "headers": [],
                    "fragment": null,
                }},
                "params": [["tag", "abc", false], ["lr", null, false]],
            }),
        );
        pinned(
            &replaces(),
            json!({
                "call_id": "a@example.com",
                "to_tag": "t",
                "from_tag": "f",
                "early_only": true,
                "params": [["foo", "bar", false]],
                "framing": "header",
            }),
        );
        pinned(
            &SipAuthValue::from_token68("Bearer", "abc")?,
            json!({"scheme": "Bearer", "params": [], "token68": "abc"}),
        );
        assert_eq!(
            serde_json::to_value(ContactList::wildcard()).unwrap(),
            json!("*")
        );
        Ok(())
    }

    #[test]
    fn deserialize_normalizes_as_the_parser_does() -> R {
        let entry: SipAcceptEntry = serde_json::from_value(json!({
            "media_type": "APPLICATION",
            "subtype": "SDP",
            "params": [["Q", "1", false]],
        }))
        .unwrap();
        assert_eq!(
            entry,
            SipAcceptEntry::new("application", "sdp")?.with_param("q", Some("1"))?
        );
        let via: SipViaEntry = serde_json::from_value(json!({
            "protocol": "SIP",
            "version": "2.0",
            "transport": "UDP",
            "host": {"ipv4": "198.51.100.1"},
            "params": [["rport", "5060", false]],
        }))
        .unwrap();
        assert_eq!(via.rport(), Some(Some(5060)));
        Ok(())
    }

    #[test]
    fn invalid_parts_are_rejected() {
        rejects::<SipVia>(json!([]));
        rejects::<SipWarning>(json!([]));
        rejects::<SipSecurity>(json!([]));
        rejects::<UriInfo>(json!([]));
        rejects::<HistoryInfo>(json!([]));
        rejects::<SipAuthValue>(json!({
            "scheme": "Bearer",
            "params": [["realm", "secret", false]],
            "token68": "abc",
        }));
        rejects::<SipSecurityMechanism>(json!({
            "mechanism": "digest",
            "params": [["d-alg", null, true]],
        }));
        rejects::<SipWarningEntry>(json!({"code": 1000, "agent": "example.com", "text": "secret"}));
        rejects::<SipAcceptEntry>(json!({"media_type": "a/b", "subtype": "secret"}));
        rejects::<SipReason>(json!({"protocol": "S;IP", "params": [["text", "secret", true]]}));
        rejects::<SipReason>(json!({"protocol": "SIP", "params": [["cause", "secret", false]]}));
        rejects::<SipReason>(json!({"protocol": "SIP", "params": [["text", "secret", false]]}));
    }

    const MARKER: &str = "zz-marker-77";
    const MARKER_NUMBER: u64 = 7_700_077_077;
    /// Keys holding a sip-uri type, whose serde is sip-uri's.
    const SIP_URI_KEYS: [&str; 2] = ["uri", "host"];

    fn pointers(value: &serde_json::Value, at: String, out: &mut Vec<String>) {
        match value {
            serde_json::Value::Object(map) => {
                for (k, v) in map {
                    pointers(v, format!("{at}/{k}"), out);
                }
            }
            serde_json::Value::Array(items) => {
                for (i, v) in items
                    .iter()
                    .enumerate()
                {
                    pointers(v, format!("{at}/{i}"), out);
                }
            }
            _ => {}
        }
        out.push(at);
    }

    fn leaks<T: Serialize + DeserializeOwned>(value: &T) -> Vec<String> {
        leaks_below(value, |_| true)
    }

    /// [`leaks`] at the pointers `probe` accepts.
    fn leaks_below<T: Serialize + DeserializeOwned>(
        value: &T,
        probe: impl Fn(&str) -> bool,
    ) -> Vec<String> {
        let json = serde_json::to_value(value).unwrap();
        let mut at = Vec::new();
        pointers(&json, String::new(), &mut at);
        let substitutes = [
            json!(MARKER),
            json!(MARKER_NUMBER),
            json!(true),
            serde_json::Value::Null,
            json!({ "k": MARKER }),
            json!([MARKER]),
        ];
        let mut found = Vec::new();
        for pointer in at
            .iter()
            .filter(|p| {
                probe(p)
                    && !p
                        .split('/')
                        .any(|s| SIP_URI_KEYS.contains(&s))
            })
        {
            // An array read as a struct fills fields in declaration order, which
            // the JSON cannot show, so it may land on a sip-uri field.
            let holds_uri = json
                .pointer(pointer)
                .and_then(serde_json::Value::as_object)
                .is_some_and(|o| {
                    SIP_URI_KEYS
                        .iter()
                        .any(|k| o.contains_key(*k))
                });
            for substitute in substitutes
                .iter()
                .filter(|s| !(holds_uri && s.is_array()))
            {
                let mut probe = json.clone();
                *probe
                    .pointer_mut(pointer)
                    .unwrap() = substitute.clone();
                let errors = [
                    serde_json::from_value::<T>(probe.clone()).err(),
                    serde_json::from_str::<T>(&probe.to_string()).err(),
                ];
                for e in errors
                    .into_iter()
                    .flatten()
                {
                    let m = e.to_string();
                    if m.starts_with("invalid ") && !m.contains("expected") {
                        found.push(format!(
                            "{} {pointer:?} <- {substitute}: no expected type: {m}",
                            std::any::type_name::<T>()
                        ));
                    }
                    if m.contains(MARKER) || m.contains(&MARKER_NUMBER.to_string()) {
                        found.push(format!(
                            "{} {pointer:?} <- {substitute}: {m}",
                            std::any::type_name::<T>()
                        ));
                    }
                }
            }
        }
        found
    }

    #[test]
    fn deserialize_errors_never_quote_the_value() -> R {
        let mut found = Vec::new();
        found.extend(leaks(&SipReason::parse(
            r#"SIP;cause=200;text="x";foo=bar"#,
        )?));
        found.extend(leaks(&SipReasonList::parse(
            "SIP;cause=200, Q.850;cause=16",
        )?));
        found.extend(leaks(&replaces()));
        found.extend(leaks(&replaces().with_framing(DialogFraming::UriHeader)));
        found.extend(leaks(&SipJoin::parse(
            "a@example.com;to-tag=t;from-tag=f;x=y",
        )?));
        found.extend(leaks(&SipTargetDialog::parse(
            "a@example.com;local-tag=l;remote-tag=r;x",
        )?));
        found.extend(leaks(&addr()));
        found.extend(leaks(&SipHeaderAddrList::parse(
            "<sip:a@example.com>;tag=t",
        )?));
        found.extend(leaks(&ContactList::new(vec![addr()])?));
        found.extend(leaks(&ContactList::wildcard()));
        found.extend(leaks(&via()));
        found.extend(leaks(&first::<SipVia, _>(
            "SIP/2.0/UDP 198.51.100.1:5060;branch=z9hG4bK1",
            SipVia::entries,
        )));
        found.extend(leaks(&SipAccept::parse("application/sdp;q=0.5")?));
        found.extend(leaks(&SipAcceptEncoding::parse("gzip;q=0.5")?));
        found.extend(leaks(&SipAcceptLanguage::parse("fr;q=0.8")?));
        found.extend(leaks(&SipWarning::parse(r#"399 example.com "x""#)?));
        found.extend(leaks(&SipSecurity::parse("digest;d-alg=md5;q=0.1")?));
        found.extend(leaks(&SipAuthValue::parse(
            r#"Digest realm="example.com", qop=auth"#,
        )?));
        found.extend(leaks(&SipAuthValue::from_token68("Bearer", "abc")?));
        found.extend(leaks(&UriInfo::parse(
            "<https://example.com/i.png>;purpose=icon",
        )?));
        found.extend(leaks(&SipGeolocation::parse(
            "<cid:loc@example.com>;inserted-by=example.com",
        )?));
        found.extend(leaks(&HistoryInfo::parse("<sip:a@example.com>;index=1")?));
        found.extend(leaks(&SipCallId::new("a@example.com")?));
        found.extend(leaks(&SipReasonCause::new("16")?));
        found.extend(leaks(&DialogFraming::Header));
        found.extend(leaks(&DialogFraming::UriHeader));
        found.extend(leaks(addr().params()));
        found.extend(leaks(&SipHeader::CallId));
        found.extend(leaks(&token_list()));
        found.extend(leaks(&TokenList::new(
            SipHeader::InReplyTo,
            ["a@example.com"],
        )?));
        assert!(found.is_empty(), "{}", found.join("\n"));
        Ok(())
    }

    macro_rules! adapted {
        ($found:ident: $($ty:ty = $value:expr, $plain:literal, $option:literal;)*) => {$({
            #[derive(Serialize, serde::Deserialize)]
            struct Holder {
                #[serde(with = $plain)]
                plain: $ty,
                #[serde(with = $option)]
                option: Option<$ty>,
            }
            let value = $value;
            let holder = Holder {
                plain: value.clone(),
                option: Some(value),
            };
            $found.extend(leaks_below(&holder, |p| !p.is_empty()));
        })*};
    }

    #[test]
    fn serde_str_errors_never_quote_the_value() -> R {
        let mut found = Vec::new();
        adapted! { found:
            SipHeaderAddr = addr(),
                "sip_header::serde_str::header_addr", "sip_header::serde_str::header_addr::option";
            SipHeaderAddrList = SipHeaderAddrList::parse("<sip:a@example.com>")?,
                "sip_header::serde_str::addr_list", "sip_header::serde_str::addr_list::option";
            ContactList = ContactList::new(vec![addr()])?,
                "sip_header::serde_str::contact", "sip_header::serde_str::contact::option";
            SipVia = via(), "sip_header::serde_str::via", "sip_header::serde_str::via::option";
            SipWarning = SipWarning::parse(r#"399 example.com "x""#)?,
                "sip_header::serde_str::warning", "sip_header::serde_str::warning::option";
            SipAuthValue = SipAuthValue::from_token68("Bearer", "abc")?,
                "sip_header::serde_str::auth", "sip_header::serde_str::auth::option";
            SipSecurity = SipSecurity::parse("digest;q=0.1")?,
                "sip_header::serde_str::security", "sip_header::serde_str::security::option";
            SipAccept = SipAccept::parse("application/sdp")?,
                "sip_header::serde_str::accept", "sip_header::serde_str::accept::option";
            SipAcceptEncoding = SipAcceptEncoding::parse("gzip")?,
                "sip_header::serde_str::accept_encoding",
                "sip_header::serde_str::accept_encoding::option";
            SipAcceptLanguage = SipAcceptLanguage::parse("fr")?,
                "sip_header::serde_str::accept_language",
                "sip_header::serde_str::accept_language::option";
            UriInfo = UriInfo::parse("<https://example.com/i.png>")?,
                "sip_header::serde_str::uri_info", "sip_header::serde_str::uri_info::option";
            HistoryInfo = HistoryInfo::parse("<sip:a@example.com>;index=1")?,
                "sip_header::serde_str::history_info",
                "sip_header::serde_str::history_info::option";
            SipGeolocation = SipGeolocation::parse("<cid:loc@example.com>")?,
                "sip_header::serde_str::geolocation", "sip_header::serde_str::geolocation::option";
            SipReplaces = replaces(),
                "sip_header::serde_str::replaces", "sip_header::serde_str::replaces::option";
            SipJoin = SipJoin::parse("a@example.com;to-tag=t;from-tag=f")?,
                "sip_header::serde_str::join", "sip_header::serde_str::join::option";
            SipReason = SipReason::parse("SIP;cause=200")?,
                "sip_header::serde_str::reason", "sip_header::serde_str::reason::option";
            SipReasonList = SipReasonList::parse("SIP;cause=200")?,
                "sip_header::serde_str::reason_list", "sip_header::serde_str::reason_list::option";
            SipTargetDialog = SipTargetDialog::parse("a@example.com;local-tag=l;remote-tag=r")?,
                "sip_header::serde_str::target_dialog",
                "sip_header::serde_str::target_dialog::option";
        }
        assert!(found.is_empty(), "{}", found.join("\n"));
        Ok(())
    }

    fn refuses_field<T: Serialize + DeserializeOwned + std::fmt::Debug>(value: &T, key: &str) {
        let mut json = serde_json::to_value(value).unwrap();
        json.as_object_mut()
            .unwrap()
            .insert(key.into(), json!("secret"));
        rejects::<T>(json);
    }

    #[test]
    fn unknown_fields_are_refused() -> R {
        fn unknown<T: Serialize + DeserializeOwned + std::fmt::Debug>(value: &T) {
            refuses_field(value, "unknown");
        }
        unknown(&addr());
        unknown(&replaces());
        unknown(&SipTargetDialog::new("a@example.com", "l", "r")?);
        unknown(&SipJoin::parse("a@example.com;to-tag=t;from-tag=f").unwrap());
        unknown(&SipReason::new("SIP")?.with_cause(302));
        unknown(&SipAuthValue::parse(r#"Digest realm="example.com""#).unwrap());
        unknown(&first("<cid:loc@example.com>", SipGeolocation::entries));
        unknown(&first("gzip;q=0.5", SipAcceptEncoding::entries));
        unknown(&first("fr;q=0.8", SipAcceptLanguage::entries));
        unknown(&first("application/sdp", SipAccept::entries));
        unknown(&first("<https://example.com/i.png>", UriInfo::entries));
        unknown(&first("SIP/2.0/UDP 198.51.100.1", SipVia::entries));
        unknown(&first(r#"399 example.com "x""#, SipWarning::entries));
        unknown(&first("digest;q=0.1", SipSecurity::entries));
        unknown(&first("<sip:a@example.com>;index=1", HistoryInfo::entries));
        Ok(())
    }

    #[test]
    fn tag_and_rport_fields_are_refused() {
        refuses_field(&addr(), "tag");
        refuses_field(&first("SIP/2.0/UDP 198.51.100.1", SipVia::entries), "rport");
        for key in ["cause", "text"] {
            refuses_field(&SipReason::parse(r#"SIP;cause=200;text="x""#).unwrap(), key);
        }
    }

    #[test]
    fn control_chars_are_rejected_in_every_field() {
        rejects::<SipHeaderAddr>(json!({
            "display_name": "secret\r\nX: y",
            "uri": serde_json::to_value(alice()).unwrap(),
        }));
        rejects::<SipReplaces>(json!({
            "call_id": "secret\n", "to_tag": "t", "from_tag": "f",
        }));
        rejects::<SipReplaces>(json!({
            "call_id": "a", "to_tag": "t\0", "from_tag": "f",
        }));
        rejects::<SipWarningEntry>(
            json!({"code": 399, "agent": "example.com", "text": "secret\r"}),
        );
        rejects::<SipAuthValue>(json!({"scheme": "Bearer", "params": [], "token68": "secret\n"}));
        let via = serde_json::from_value::<SipViaEntry>(json!({
            "protocol": "SIP", "version": "2.0", "transport": "UDP",
            "host": {"hostname": "secret\r\n.example.com"}, "port": null,
        }));
        assert!(via.map_or(true, |v| !v
            .to_string()
            .contains(['\r', '\n'])));
        let entry = serde_json::from_value::<UriInfoEntry>(json!({
            "uri": {"other": {"scheme": "https", "rest": "//example.com/secret\n"}},
        }));
        assert!(entry.map_or(true, |e| !e
            .to_string()
            .contains('\n')));
        rejects::<SipHeaderAddr>(json!({
            "uri": serde_json::to_value(alice()).unwrap(),
            "params": [["x", "secret\r\nX: y", true]],
        }));
    }
}
