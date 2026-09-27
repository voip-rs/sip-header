use sip_header::sip_uri::{Host, SipUri, TelUri, Uri};
use sip_header::{
    ContactList, ContactValue, DialogFraming, HistoryInfo, HistoryInfoEntry, HistoryInfoReason,
    ParseError, SipAccept, SipAcceptEncoding, SipAcceptEncodingEntry, SipAcceptEntry,
    SipAcceptLanguage, SipAcceptLanguageEntry, SipAuthValue, SipGeolocation, SipGeolocationEntry,
    SipGeolocationRef, SipHeaderAddr, SipReplaces, SipSecurity, SipSecurityMechanism,
    SipTargetDialog, SipVia, SipViaEntry, SipWarning, SipWarningEntry, UriInfo, UriInfoEntry,
};

type R = Result<(), ParseError>;

fn alice() -> Uri {
    SipUri::new(Host::Hostname("example.com".into()))
        .with_user("alice")
        .into()
}

fn addr() -> SipHeaderAddr {
    SipHeaderAddr::new(alice())
        .and_then(|a| a.with_display_name("Alice Smith"))
        .and_then(|a| a.with_tag("abc"))
        .and_then(|a| a.with_param("lr", None::<&str>))
        .unwrap()
}

fn via() -> SipVia {
    SipVia::new(vec![SipViaEntry::new("SIP", "2.0", "TCP")
        .and_then(|v| v.with_host("[2001:db8::1]"))
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
    let contact = ContactList::new(vec![
        ContactValue::Addr(Box::new(addr)),
        ContactValue::Wildcard,
    ]);
    assert_eq!(
        contact.to_string(),
        r#""Alice Smith" <sip:alice@example.com>;tag=abc;lr, *"#
    );
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
            UriInfoEntry::new("https://example.com/i")?.with_param("purpose", Some("icon"))?
        ])
        .unwrap()
        .to_string(),
        "<https://example.com/i>;purpose=icon"
    );
    assert_eq!(
        SipGeolocation::new(vec![SipGeolocationEntry::new(SipGeolocationRef::Cid(
            "loc@example.com".into()
        ))?])
        .to_string(),
        "<cid:loc@example.com>"
    );
    assert_eq!(
        HistoryInfo::new(vec![HistoryInfoEntry::new(addr())])
            .unwrap()
            .to_string(),
        r#""Alice Smith" <sip:alice@example.com>;tag=abc;lr"#
    );
    assert_eq!(
        SipAuthValue::new("Digest")?
            .with_param("realm", "example.com")?
            .with_param("algorithm", "MD5")?
            .to_string(),
        r#"Digest realm="example.com", algorithm=MD5"#
    );
    let reason = HistoryInfoReason::new("SIP")?
        .with_cause(302)
        .with_text("Moved")?;
    assert_eq!(
        (reason.protocol(), reason.cause(), reason.text()),
        ("SIP", Some(302), Some("Moved"))
    );
    Ok(())
}

#[test]
fn structural_invariants() -> R {
    assert_eq!(SipVia::new(Vec::new()), None);
    assert_eq!(SipWarning::new(Vec::new()), None);
    assert_eq!(SipSecurity::new(Vec::new()), None);
    assert_eq!(UriInfo::new(Vec::new()), None);
    assert_eq!(HistoryInfo::new(Vec::new()), None);
    assert!(SipViaEntry::new("SIP", "2.0", "UDP")?
        .with_param("RPORT", Some("5060"))
        .is_err());
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
        round_trip(ContactList::new(vec![
            ContactValue::Wildcard,
            ContactValue::Addr(Box::new(addr())),
        ]));
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
        round_trip(UriInfo::new(vec![UriInfoEntry::new("https://example.com/i")?]).unwrap());
        round_trip(SipGeolocation::new(vec![SipGeolocationEntry::new(
            SipGeolocationRef::Url("https://example.com/l".into()),
        )?
        .with_param("inserted-by", Some("example.com"))?]));
        round_trip(HistoryInfo::new(vec![HistoryInfoEntry::new(addr())]).unwrap());
        round_trip(HistoryInfoReason::new("SIP")?.with_cause(302));
        round_trip(replaces().with_framing(DialogFraming::UriHeader));
        round_trip(SipTargetDialog::new("a@example.com", "l", "r")?);
        Ok(())
    }

    #[test]
    fn serializes_as_parts_with_every_field() -> R {
        assert_eq!(
            serde_json::to_value(addr()).unwrap(),
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
                "tag": "abc",
                "params": [["lr", null, false]],
            })
        );
        assert_eq!(
            serde_json::to_value(replaces()).unwrap(),
            json!({
                "call_id": "a@example.com",
                "to_tag": "t",
                "from_tag": "f",
                "early_only": true,
                "params": [["foo", "bar", false]],
                "framing": "header",
            })
        );
        assert_eq!(
            serde_json::to_value(SipAuthValue::from_token68("Bearer", "abc")?).unwrap(),
            json!({"scheme": "Bearer", "params": [], "token68": "abc"})
        );
        assert_eq!(
            serde_json::to_value(ContactValue::Wildcard).unwrap(),
            json!("wildcard")
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
            "host": "198.51.100.1",
            "rport": 5060,
            "params": [],
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
        rejects::<SipViaEntry>(json!({
            "protocol": "SIP",
            "version": "2.0",
            "transport": "UDP",
            "host": "198.51.100.1",
            "port": null,
            "params": [["rport", "secret", false]],
        }));
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
        rejects::<HistoryInfoReason>(json!({"protocol": "S;IP", "cause": null, "text": "secret"}));
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
        rejects::<SipViaEntry>(json!({
            "protocol": "SIP", "version": "2.0", "transport": "UDP",
            "host": "secret\r\n.example.com", "port": null,
        }));
        rejects::<UriInfoEntry>(json!({"uri": "https://example.com/secret\n"}));
        rejects::<SipHeaderAddr>(json!({
            "uri": serde_json::to_value(alice()).unwrap(),
            "params": [["x", "secret\r\nX: y", true]],
        }));
    }
}
