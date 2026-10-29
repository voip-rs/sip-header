//! The address list, URI-header parsers, strict entries and the owned Call-ID.

use sip_header::{
    FaultCode, Field, HeaderParse, ListParse, ParseError, SipCallId, SipContentLength,
    SipContentType, SipHeaderAddrList, SipReason, SipReasonList, SipReplaces, SipTargetDialog,
    SipVia, UriHeaderParse, WarningCode, WarningKind,
};

type R = Result<(), ParseError>;

#[test]
fn addr_list_parses_and_builds_from_entries() -> R {
    let list = SipHeaderAddrList::parse(r#""A" <sip:a@example.com>, <sip:b@example.com>;lr"#)?;
    assert_eq!(list.len(), 2);
    assert_eq!(list.entries()[0].display_name(), Some("A"));
    assert_eq!(
        list.to_string(),
        r#"A <sip:a@example.com>, <sip:b@example.com>;lr"#
    );
    let from_entries =
        SipHeaderAddrList::from_entries(["<sip:a@example.com>", "<tel:+15551234567>"])?;
    assert_eq!(from_entries.len(), 2);
    Ok(())
}

#[test]
fn addr_list_needs_an_entry() {
    assert_eq!(
        SipHeaderAddrList::parse("  "),
        Err(ParseError::Malformed(sip_header::Fault::new(
            Field::Value,
            FaultCode::Empty
        )))
    );
    assert!(SipHeaderAddrList::new(Vec::new()).is_err());
}

#[test]
fn from_entries_strict_refuses_the_first_breach() -> R {
    let entries = ["SIP/2.0/UDP 198.51.100.1", "SIP/2.0/UDP 198.51.100.2;;"];
    assert_eq!(SipVia::from_entries(entries)?.len(), 2);
    assert!(SipVia::from_entries_strict(["SIP/2.0/UDP 198.51.100.1"]).is_ok());
    let breach = ["<sip:a@example.com>junk"];
    assert!(matches!(
        SipHeaderAddrList::from_entries_strict(breach),
        Err(ParseError::NonConformant(w)) if w.code == WarningCode::TrailingContent && w.entry == Some(0)
    ));
    Ok(())
}

#[test]
fn reason_list_holds_every_reason_value() -> R {
    let list = SipReasonList::parse(r#"Q.850;cause=16;text="Terminated", SIP;cause=200"#)?;
    assert_eq!(list.len(), 2);
    assert_eq!(list.entries()[1].protocol(), "SIP");
    assert!(SipReasonList::parse("").is_err());
    Ok(())
}

#[test]
fn uri_header_parse_covers_dialogs_and_reason() -> R {
    let r = SipReplaces::parse_uri_header("abc%40example.com%3Bto-tag%3Dt%3Bfrom-tag%3Df")?;
    assert_eq!(r.call_id(), "abc@example.com");
    let t = SipTargetDialog::parse_uri_header_strict("abc%3Blocal-tag%3Dl%3Bremote-tag%3Dr")?;
    assert_eq!(t.local_tag(), "l");
    let reason = SipReason::parse_uri_header("Q.850%3Bcause%3D16%3Btext%3D%22a+b%22")?;
    assert_eq!(reason.text(), Some("a+b"));
    let parsed = SipReason::parse_uri_header_with_warnings("Q.850%3Bcause%3Dx")?;
    assert_eq!(parsed.warnings[0].code, WarningCode::InvalidCause);
    assert!(SipReason::parse_uri_header_strict("Q.850%3Bcause%3Dx").is_err());
    assert!(SipReason::parse_uri_header("%C0%80").is_err());
    Ok(())
}

#[test]
fn uri_header_reason_parses_as_one_entry() -> R {
    let raw = "Q.850%3Bcause%3D16%2C%20SIP%3Bcause%3D200";
    let one = SipReason::parse("Q.850;cause=16")?;
    assert_eq!(SipReason::parse_uri_header(raw)?, one);
    let parsed = SipReason::parse_uri_header_with_warnings(raw)?;
    assert_eq!(parsed.value, one);
    let codes: Vec<_> = parsed
        .warnings
        .iter()
        .map(|w| (w.code, w.kind, w.span()))
        .collect();
    assert_eq!(
        codes,
        [(WarningCode::TrailingContent, WarningKind::Lost, None)]
    );
    assert!(SipReason::parse_uri_header_strict(raw).is_err());
    Ok(())
}

#[test]
fn call_id_is_owned_and_parses_like_every_value() -> R {
    let id = {
        let wire = String::from(" a84b4c76e66710@example.com ");
        SipCallId::parse(&wire)?
    };
    assert_eq!(id.as_str(), "a84b4c76e66710@example.com");
    assert_eq!(id.local(), "a84b4c76e66710");
    assert_eq!(id.host(), Some("example.com"));
    assert_eq!(id.to_string(), "a84b4c76e66710@example.com");

    let parsed = SipCallId::parse_with_warnings("a b@example.com")?;
    assert_eq!(
        parsed
            .value
            .as_str(),
        "a b@example.com"
    );
    assert_eq!(parsed.warnings[0].field, Field::CallId);
    assert_eq!(parsed.warnings[0].code, WarningCode::InvalidToken);
    assert_eq!(parsed.warnings[0].position, Some(1));
    assert!(SipCallId::parse_strict("a b@example.com").is_err());
    assert!(SipCallId::parse_strict("a@b@c").is_err());
    assert_eq!(
        SipCallId::parse(" "),
        Err(ParseError::Malformed(sip_header::Fault::new(
            Field::CallId,
            FaultCode::Empty
        )))
    );
    Ok(())
}

#[test]
fn call_id_constructor_refuses_what_strict_parse_refuses() {
    assert!(SipCallId::new("abc@example.com").is_ok());
    for bad in [
        "",
        "a;b",
        "a,b",
        "a b",
        "a\r\nb",
        "a@b@c",
        "@example.com",
        "abc@",
    ] {
        assert!(SipCallId::new(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn call_id_compares_byte_for_byte() -> R {
    assert_ne!(
        SipCallId::parse("abc@example.com")?,
        SipCallId::parse("ABC@example.com")?
    );
    Ok(())
}

#[cfg(feature = "serde")]
#[test]
fn call_id_serde_is_its_text() {
    let id = SipCallId::new("abc@example.com").unwrap();
    let json = serde_json::to_string(&id).unwrap();
    assert_eq!(json, r#""abc@example.com""#);
    assert_eq!(serde_json::from_str::<SipCallId>(&json).unwrap(), id);
    assert!(serde_json::from_str::<SipCallId>(r#""a;b""#).is_err());
}

#[test]
fn content_length_reads_digits_and_nothing_else_silently() -> R {
    assert_eq!(SipContentLength::parse(" 318 ")?.get(), 318);
    assert_eq!(SipContentLength::parse_strict("318")?.to_string(), "318");
    let zeros = SipContentLength::parse_with_warnings("00318")?;
    assert_eq!(
        zeros
            .value
            .get(),
        318
    );
    assert!(zeros
        .warnings
        .is_empty());
    assert!(SipContentLength::parse_strict("00318").is_ok());
    assert_eq!(SipContentLength::from(0).to_string(), "0");
    Ok(())
}

#[test]
fn content_length_keeps_the_digits_and_reports_the_dropped_text() -> R {
    let raw = "318 bytes";
    let parsed = SipContentLength::parse_with_warnings(raw)?;
    assert_eq!(
        parsed
            .value
            .get(),
        318
    );
    assert_eq!(SipContentLength::parse(raw)?, SipContentLength::from(318));
    assert_eq!(
        parsed
            .warnings
            .len(),
        1
    );
    let warning = &parsed.warnings[0];
    assert_eq!(warning.field, Field::Value);
    assert_eq!(warning.code, WarningCode::TrailingContent);
    assert_eq!(warning.position, Some(3));
    assert_eq!(
        warning
            .span()
            .map(|s| s.get(raw)),
        Some(Ok(" bytes"))
    );
    assert!(SipContentLength::parse_strict(raw).is_err());
    Ok(())
}

#[test]
fn content_length_without_a_usable_number_is_an_error() {
    let overflow = "9".repeat(40);
    for raw in ["abc", "-1", "+5", overflow.as_str()] {
        for result in [
            SipContentLength::parse(raw),
            SipContentLength::parse_strict(raw),
        ] {
            match result {
                Err(ParseError::Malformed(fault)) => {
                    assert_eq!(fault.code, FaultCode::InvalidNumber, "{raw:?}");
                    assert_eq!(fault.field, Field::Value, "{raw:?}");
                }
                other => panic!("{raw:?}: {other:?}"),
            }
        }
    }
    for raw in ["", "  "] {
        assert_eq!(
            SipContentLength::parse(raw),
            Err(ParseError::Malformed(sip_header::Fault::new(
                Field::Value,
                FaultCode::Empty
            ))),
            "{raw:?}"
        );
    }
}

#[cfg(feature = "serde")]
#[test]
fn content_length_serde_is_a_number() {
    let length = SipContentLength::from(318);
    let json = serde_json::to_string(&length).unwrap();
    assert_eq!(json, "318");
    assert_eq!(
        serde_json::from_str::<SipContentLength>(&json).unwrap(),
        length
    );
    assert!(serde_json::from_str::<SipContentLength>(r#""318""#).is_err());
    assert!(serde_json::from_str::<SipContentLength>("-1").is_err());
}

#[test]
fn content_type_holds_the_media_type_lowercased_and_the_parameters_as_received() -> R {
    let sdp = SipContentType::parse_strict("application/sdp")?;
    assert_eq!((sdp.media_type(), sdp.subtype()), ("application", "sdp"));
    assert_eq!(sdp.to_string(), "application/sdp");
    let raw = r#"Multipart/Mixed;Boundary="UniqueBoundaryXyZ";charset=UTF-8"#;
    let mixed = SipContentType::parse_strict(raw)?;
    assert_eq!(
        (mixed.media_type(), mixed.subtype()),
        ("multipart", "mixed")
    );
    assert_eq!(mixed.param("boundary"), Some(Some("UniqueBoundaryXyZ")));
    assert_eq!(mixed.param("CHARSET"), Some(Some("UTF-8")));
    assert_eq!(
        mixed.to_string(),
        r#"multipart/mixed;boundary="UniqueBoundaryXyZ";charset=UTF-8"#
    );
    assert_eq!(SipContentType::parse(&mixed.to_string())?, mixed);
    Ok(())
}

#[test]
fn content_type_q_is_an_ordinary_parameter() -> R {
    for raw in ["text/plain;q=x", r#"text/plain;q="1""#, "text/plain;q=1.5"] {
        let parsed = SipContentType::parse_with_warnings(raw)?;
        assert!(
            parsed
                .warnings
                .is_empty(),
            "{raw}: {:?}",
            parsed.warnings
        );
        assert!(SipContentType::parse_strict(raw).is_ok(), "{raw}");
        assert_eq!(
            parsed
                .value
                .to_string(),
            raw
        );
    }
    Ok(())
}

#[test]
fn content_type_keeps_a_wildcard_under_invalid_token() -> R {
    for (raw, at) in [("*/*", vec![0, 2]), ("text/*", vec![5]), ("*/sdp", vec![0])] {
        let parsed = SipContentType::parse_with_warnings(raw)?;
        let got: Vec<_> = parsed
            .warnings
            .iter()
            .map(|w| (w.field, w.code, w.position))
            .collect();
        let want: Vec<_> = at
            .into_iter()
            .map(|p| (Field::MediaRange, WarningCode::InvalidToken, Some(p)))
            .collect();
        assert_eq!(got, want, "{raw}");
        assert_eq!(SipContentType::parse(raw)?.to_string(), raw);
        assert!(SipContentType::parse_strict(raw).is_err(), "{raw}");
    }
    Ok(())
}

#[test]
fn content_type_without_a_subtype_is_an_error() {
    let missing = |at| {
        Err(ParseError::Malformed(
            sip_header::Fault::new(Field::MediaRange, FaultCode::Missing).at(at),
        ))
    };
    for raw in ["text", "text/", "/plain", "text/;charset=x"] {
        assert_eq!(SipContentType::parse(raw), missing(0), "{raw}");
        assert_eq!(SipContentType::parse_strict(raw), missing(0), "{raw}");
    }
    assert_eq!(SipContentType::parse("  text/"), missing(2));
    for raw in ["", "  "] {
        assert_eq!(
            SipContentType::parse(raw),
            Err(ParseError::Malformed(sip_header::Fault::new(
                Field::Value,
                FaultCode::Empty
            ))),
            "{raw:?}"
        );
    }
}

#[test]
fn content_type_reports_whitespace_beyond_lws() -> R {
    let raw = "\u{a0}text/plain";
    let parsed = SipContentType::parse_with_warnings(raw)?;
    assert_eq!(
        parsed
            .warnings
            .iter()
            .map(|w| (w.code, w.position))
            .collect::<Vec<_>>(),
        [(WarningCode::NonLwsWhitespace, Some(0))]
    );
    assert!(SipContentType::parse_strict(raw).is_err());
    assert_eq!(
        parsed
            .value
            .to_string(),
        "text/plain"
    );
    Ok(())
}

#[test]
fn content_type_parameter_spans_point_into_the_text() -> R {
    let raw = r#"multipart/mixed;boundary="b1";x=y"#;
    let parsed = SipContentType::parse(raw)?;
    let spans: Vec<_> = parsed
        .params()
        .value_spans("boundary")
        .map(|s| {
            s.and_then(|s| {
                s.get(raw)
                    .ok()
            })
        })
        .collect();
    assert_eq!(spans, [Some(r#""b1""#)]);
    Ok(())
}

#[test]
fn content_type_constructor_refuses_what_would_print_differently() -> R {
    let built = SipContentType::new("Application", "SDP")?.with_quoted_param("charset", "x y")?;
    assert_eq!(built.to_string(), r#"application/sdp;charset="x y""#);
    assert_eq!(SipContentType::parse_strict(&built.to_string())?, built);
    for (t, s) in [
        ("", "sdp"),
        ("application", ""),
        ("*", "sdp"),
        ("text", "*"),
        ("a/b", "c"),
        ("a", "b/c"),
        ("a b", "c"),
        ("a;b", "c"),
        ("a\r\n", "c"),
    ] {
        match SipContentType::new(t, s) {
            Err(ParseError::Malformed(fault)) => {
                assert_eq!(fault.field, Field::MediaRange, "{t}/{s}")
            }
            other => panic!("{t}/{s}: {other:?}"),
        }
    }
    let plain = SipContentType::new("text", "plain")?;
    assert!(plain
        .clone()
        .with_param("a b", Some("x"))
        .is_err());
    assert!(plain
        .clone()
        .with_param("a", Some("x\r\ny"))
        .is_err());
    assert!(plain
        .clone()
        .with_quoted_param("a", "x\0")
        .is_err());
    assert_eq!(
        plain
            .with_param("q", Some("x"))?
            .to_string(),
        "text/plain;q=x"
    );
    Ok(())
}

#[test]
fn content_type_params_guard_runs_the_builders_check() -> R {
    let mut value = SipContentType::new("text", "plain")?;
    value
        .params_mut()
        .set("charset", Some("utf-8"))?;
    assert!(value
        .params_mut()
        .set("a b", Some("x"))
        .is_err());
    assert_eq!(value.to_string(), "text/plain;charset=utf-8");
    Ok(())
}

#[cfg(feature = "serde")]
#[test]
fn content_type_serde_is_parts_read_back_through_the_parser() -> R {
    let value = SipContentType::new("multipart", "mixed")?.with_quoted_param("boundary", "b 1")?;
    let json = serde_json::to_value(&value).unwrap();
    assert_eq!(
        json,
        serde_json::json!({
            "media_type": "multipart",
            "subtype": "mixed",
            "params": [["boundary", "b 1", true]],
        })
    );
    assert_eq!(
        serde_json::from_value::<SipContentType>(json).unwrap(),
        value
    );
    let upper: SipContentType =
        serde_json::from_value(serde_json::json!({"media_type": "TEXT", "subtype": "Plain"}))
            .unwrap();
    assert_eq!(upper.to_string(), "text/plain");
    for bad in [
        serde_json::json!({"media_type": "a/b", "subtype": "secret"}),
        serde_json::json!({"media_type": "text", "subtype": ""}),
        serde_json::json!({"media_type": "text", "subtype": "plain", "params": [["a;b", "secret", false]]}),
        serde_json::json!({"media_type": "text", "subtype": "plain", "unknown": "secret"}),
    ] {
        let err = serde_json::from_value::<SipContentType>(bad).unwrap_err();
        assert!(
            !err.to_string()
                .contains("secret"),
            "{err}"
        );
    }
    Ok(())
}

fn rust_sources(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry
            .unwrap()
            .path();
        if path.is_dir() {
            rust_sources(&path, out);
        } else if path.extension() == Some("rs".as_ref()) {
            out.push(path);
        }
    }
}

fn ends_in_parts(ty: &str) -> bool {
    ty.trim_end_matches(|c: char| !c.is_alphanumeric() && c != '_')
        .ends_with("Parts")
}

#[test]
fn no_public_conversion_names_a_serde_mirror() {
    let mut files = Vec::new();
    rust_sources(
        &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut files,
    );
    assert!(!files.is_empty());
    for file in files {
        let text = std::fs::read_to_string(&file).unwrap();
        for (n, line) in text
            .lines()
            .enumerate()
        {
            let Some((_, from)) = line
                .trim_start()
                .strip_prefix("impl")
                .and_then(|rest| rest.split_once("From<"))
            else {
                continue;
            };
            let (arg, target) = from
                .split_once(" for ")
                .unwrap_or((from, ""));
            let target = target
                .split_whitespace()
                .next()
                .unwrap_or("");
            assert!(
                !ends_in_parts(arg) && !ends_in_parts(target),
                "{}:{}: {line}",
                file.display(),
                n + 1
            );
        }
    }
}

#[test]
fn a_warning_kind_is_named_at_the_root() -> R {
    use sip_header::WarningKind;

    let parsed = SipVia::parse_with_warnings("SIP/2.0/UDP 198.51.100.1:x")?;
    let kind: WarningKind = parsed.warnings[0].kind;
    assert_eq!(kind, WarningKind::Lost);
    Ok(())
}
