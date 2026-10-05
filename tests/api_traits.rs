//! The address list, URI-header parsers, strict entries and the owned Call-ID.

use sip_header::{
    FaultCode, Field, HeaderParse, ListParse, ParseError, SipCallId, SipHeaderAddrList, SipReason,
    SipReasonList, SipReplaces, SipTargetDialog, SipVia, UriHeaderParse, WarningCode, WarningKind,
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
