//! Content-ID in a SIP header (RFC 8262): the msg-id split at its `@`, the
//! constructor, serde, redaction and the store accessor. Its body-part
//! reading is in `body_part.rs`.

use std::collections::HashMap;

use sip_header::sip_uri::Redaction;
use sip_header::{
    FaultCode, Field, HeaderParse, HeaderRedaction, ParseError, ParseWarning, Redact, SipContentId,
    SipHeader, SipHeaderLookup, TypedValue, WarningCode, WarningKind,
};

type R = Result<(), ParseError>;

fn codes(warnings: &[ParseWarning]) -> Vec<(WarningCode, Option<usize>)> {
    warnings
        .iter()
        .map(|w| (w.code, w.position))
        .collect()
}

/// `parse` keeps the value, `parse_with_warnings` reports `want`, and
/// `parse_strict` refuses the first of them.
fn relaxed(raw: &str, want: &[(WarningCode, Option<usize>)]) -> SipContentId {
    let parsed = SipContentId::parse_with_warnings(raw).unwrap();
    assert_eq!(codes(&parsed.warnings), want, "{raw}");
    assert_eq!(
        SipContentId::parse(raw),
        Ok(parsed
            .value
            .clone()),
        "{raw}"
    );
    match SipContentId::parse_strict(raw) {
        Err(ParseError::NonConformant(w)) => assert_eq!((w.code, w.position), want[0], "{raw}"),
        other => panic!("{raw}: strict read {other:?}"),
    }
    assert!(
        parsed
            .warnings
            .iter()
            .all(|w| w.field == Field::ContentId),
        "{raw}"
    );
    parsed.value
}

#[test]
fn a_msg_id_splits_at_its_at() -> R {
    let id = SipContentId::parse_strict("<a84b4c76e66710@example.com>")?;
    assert_eq!(id.left(), "a84b4c76e66710");
    assert_eq!(id.right(), Some("example.com"));
    assert_eq!(id.id(), "a84b4c76e66710@example.com");
    assert_eq!(id.to_string(), "<a84b4c76e66710@example.com>");
    let id = SipContentId::parse_strict("  <a.b!#$%&'*+/=?^_`{|}~-c@x.y>  ")?;
    assert_eq!(id.left(), "a.b!#$%&'*+/=?^_`{|}~-c");
    Ok(())
}

#[test]
fn a_literal_right_side_is_one_part() -> R {
    for (raw, left, right) in [
        ("<abc@[198.51.100.1]>", "abc", "[198.51.100.1]"),
        ("<a@[b@c]>", "a", "[b@c]"),
        ("<a@[b>c]>", "a", "[b>c]"),
    ] {
        let id = SipContentId::parse_strict(raw)?;
        assert_eq!((id.left(), id.right()), (left, Some(right)), "{raw}");
        assert_eq!(SipContentId::parse(&id.to_string())?, id, "{raw}");
    }
    Ok(())
}

#[test]
fn missing_brackets_keep_the_id() {
    let id = relaxed(
        "abc@example.com",
        &[(WarningCode::MissingBrackets, Some(0))],
    );
    assert_eq!(id.to_string(), "<abc@example.com>");
    let parsed = SipContentId::parse_with_warnings("  abc@example.com").unwrap();
    assert_eq!(parsed.warnings[0].kind, WarningKind::Recovered);
    assert_eq!(
        parsed.warnings[0]
            .span()
            .unwrap()
            .get("  abc@example.com"),
        Ok("abc@example.com")
    );
    let id = relaxed(
        "<abc@example.com",
        &[(WarningCode::UnclosedBracket, Some(0))],
    );
    assert_eq!(id.to_string(), "<abc@example.com>");
}

#[test]
fn text_after_the_closing_bracket_is_dropped() {
    let id = relaxed(
        "<abc@example.com> x",
        &[(WarningCode::TrailingContent, Some(17))],
    );
    assert_eq!(id.id(), "abc@example.com");
    let id = relaxed(
        "abc@example.com>x",
        &[
            (WarningCode::MissingBrackets, Some(0)),
            (WarningCode::TrailingContent, Some(15)),
        ],
    );
    assert_eq!(id.id(), "abc@example.com");
}

#[test]
fn an_id_without_an_at_has_no_right_side() {
    let id = relaxed("<abc>", &[(WarningCode::MissingIdRight, Some(4))]);
    assert_eq!((id.left(), id.right(), id.id()), ("abc", None, "abc"));
    assert_eq!(id.to_string(), "<abc>");
    let parsed = SipContentId::parse_with_warnings("<abc>").unwrap();
    assert_eq!(parsed.warnings[0].kind, WarningKind::Recovered);
}

#[test]
fn text_outside_dot_atom_text_is_kept_as_sent() {
    for (raw, at, left, right) in [
        ("<a b@example.com>", 2, "a b", Some("example.com")),
        ("<a(c)@example.com>", 2, "a(c)", Some("example.com")),
        ("<\"a b\"@example.com>", 1, "\"a b\"", Some("example.com")),
        ("<\"a@b\"@example.com>", 1, "\"a@b\"", Some("example.com")),
        ("<a..b@example.com>", 3, "a..b", Some("example.com")),
        ("<.a@example.com>", 1, ".a", Some("example.com")),
        ("<a.@example.com>", 3, "a.", Some("example.com")),
        ("<@example.com>", 1, "", Some("example.com")),
        ("<a@>", 3, "a", Some("")),
        ("<a@b@c>", 4, "a", Some("b@c")),
        ("<a@b c>", 4, "a", Some("b c")),
        ("<a@[b c]>", 3, "a", Some("[b c]")),
        ("<a@[b>", 3, "a", Some("[b")),
        ("<a\u{e9}@b>", 2, "a\u{e9}", Some("b")),
    ] {
        let id = relaxed(raw, &[(WarningCode::InvalidToken, Some(at))]);
        assert_eq!((id.left(), id.right()), (left, right), "{raw}");
        assert_eq!(SipContentId::parse(&id.to_string()), Ok(id), "{raw}");
    }
}

#[test]
fn an_empty_value_is_an_error() {
    let empty = Err(ParseError::Malformed(sip_header::Fault::new(
        Field::ContentId,
        FaultCode::Empty,
    )));
    for raw in ["", "  ", "<>", "< >"] {
        assert_eq!(SipContentId::parse(raw), empty, "{raw:?}");
    }
}

#[test]
fn new_refuses_what_would_not_read_back_strictly() -> R {
    let id = SipContentId::new("abc", "example.com")?;
    assert_eq!(id, SipContentId::parse_strict("<abc@example.com>")?);
    let id = SipContentId::new("abc", "[198.51.100.1]")?;
    assert_eq!(id.right(), Some("[198.51.100.1]"));
    for (left, right) in [
        ("", "example.com"),
        ("abc", ""),
        ("a b", "example.com"),
        ("\"a\"", "example.com"),
        ("a@b", "example.com"),
        ("abc", "b@c"),
        ("abc", "b>c"),
        ("a\r\nb", "example.com"),
        ("abc", "example.com\0"),
        ("a(b)", "example.com"),
    ] {
        assert!(
            SipContentId::new(left, right).is_err(),
            "{left:?} {right:?}"
        );
    }
    Ok(())
}

#[test]
fn equality_is_byte_for_byte() -> R {
    assert_ne!(
        SipContentId::new("abc", "example.com")?,
        SipContentId::new("ABC", "example.com")?
    );
    Ok(())
}

#[test]
fn redaction_masks_the_id_unless_locations_are_shown() -> R {
    let id = SipContentId::new("abc", "example.com")?;
    assert_eq!(
        id.redacted(&HeaderRedaction::default())
            .to_string(),
        "<***>"
    );
    let shown = HeaderRedaction::new(Redaction::default()).show_location();
    assert_eq!(
        id.redacted(&shown)
            .to_string(),
        "<abc@example.com>"
    );
    Ok(())
}

#[test]
fn the_store_reads_content_id_in_the_sip_framing() -> R {
    let one = HashMap::from([("Content-ID".to_string(), "<abc@example.com>".to_string())]);
    let id = SipContentId::new("abc", "example.com")?;
    assert_eq!(one.content_id()?, Some(id.clone()));
    let typed = one
        .parse_typed(SipHeader::ContentId)?
        .unwrap();
    assert_eq!(typed.value, TypedValue::ContentId(id));
    let commented = HashMap::from([(
        "Content-ID".to_string(),
        "<abc@example.com> (c)".to_string(),
    )]);
    let parsed = commented
        .parse_header::<SipContentId>(SipHeader::ContentId)?
        .unwrap();
    assert_eq!(
        codes(&parsed.warnings),
        [(WarningCode::TrailingContent, Some(17))]
    );
    assert_eq!(HashMap::<String, String>::new().content_id()?, None);
    Ok(())
}

#[cfg(feature = "serde")]
#[test]
fn serde_holds_both_sides_and_reads_back_what_the_parser_produces() -> R {
    let id = SipContentId::new("abc", "example.com")?;
    let json = serde_json::to_value(&id).unwrap();
    assert_eq!(
        json,
        serde_json::json!({"left": "abc", "right": "example.com"})
    );
    assert_eq!(serde_json::from_value::<SipContentId>(json).unwrap(), id);
    for raw in ["<abc>", "<a b@c>", "<\"a@b\"@c>", "<a@[b>c]>"] {
        let id = SipContentId::parse(raw)?;
        let json = serde_json::to_value(&id).unwrap();
        assert_eq!(
            serde_json::from_value::<SipContentId>(json).unwrap(),
            id,
            "{raw}"
        );
    }
    for json in [
        serde_json::json!({"left": "a@b", "right": "c"}),
        serde_json::json!({"left": "a>", "right": "c"}),
        serde_json::json!({"left": "a", "right": "c\r\n"}),
        serde_json::json!({"left": "", "right": null}),
        serde_json::json!("<abc@example.com>"),
    ] {
        assert!(
            serde_json::from_value::<SipContentId>(json.clone()).is_err(),
            "{json}"
        );
    }
    Ok(())
}
