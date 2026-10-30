//! Body-part framing: a value read from a MIME body part's header, where
//! RFC 2045 §1 allows RFC 822 comments and a token is an RFC 2045 `token`.

use proptest::prelude::*;
use sip_header::{
    BodyPartParse, FaultCode, Field, HeaderParse, ParseError, ParseWarning, Parsed, SipContentId,
    SipContentTransferEncoding, SipContentType, TransferEncoding, WarningCode, WarningKind,
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
fn relaxed<T: std::fmt::Debug>(
    parsed: Result<Parsed<T>, ParseError>,
    lenient: Result<T, ParseError>,
    strict: Result<T, ParseError>,
    want: &[(WarningCode, Option<usize>)],
) -> T {
    let parsed = parsed.unwrap();
    assert_eq!(codes(&parsed.warnings), want);
    lenient.unwrap();
    match strict {
        Err(ParseError::NonConformant(w)) => assert_eq!((w.code, w.position), want[0]),
        other => panic!("strict read {other:?}"),
    }
    parsed.value
}

macro_rules! relaxed_body_part {
    ($Type:ty, $raw:expr, $want:expr) => {
        relaxed(
            <$Type>::parse_body_part_with_warnings($raw),
            <$Type>::parse_body_part($raw),
            <$Type>::parse_body_part_strict($raw),
            $want,
        )
    };
}

#[test]
fn content_type_comments_are_whitespace_in_a_body_part() -> R {
    let plain = SipContentType::parse_strict("text/plain;charset=utf-8")?;
    for raw in [
        "text/plain;charset=utf-8 (a comment)",
        "(c) text/plain;charset=utf-8",
        "text(c)/plain;charset=utf-8",
        "text/(c)plain;charset=utf-8",
        "text/plain (c);charset=utf-8",
        "text/plain; (c) charset = (d) utf-8",
        "text/plain;charset=utf-8 (outer (inner) \\) still)",
        "text/plain;charset=(\"\")utf-8",
    ] {
        let parsed = SipContentType::parse_body_part_with_warnings(raw)?;
        assert_eq!(codes(&parsed.warnings), [], "{raw}");
        assert_eq!(parsed.value, plain, "{raw}");
        assert_eq!(SipContentType::parse_body_part_strict(raw)?, plain, "{raw}");
    }
    Ok(())
}

#[test]
fn a_sip_content_type_keeps_parentheses_as_value_text() -> R {
    let raw = "text/plain (c)";
    let sip = SipContentType::parse_with_warnings(raw)?;
    assert_eq!(codes(&sip.warnings), [(WarningCode::InvalidToken, Some(5))]);
    assert_eq!(
        sip.value
            .subtype(),
        "plain (c)"
    );
    let body = SipContentType::parse_body_part_with_warnings(raw)?;
    assert_eq!(codes(&body.warnings), []);
    assert_eq!(
        body.value
            .subtype(),
        "plain"
    );
    Ok(())
}

#[test]
fn a_parenthesis_inside_a_quoted_parameter_value_is_text() -> R {
    let raw = r#"text/plain;a="b (c)";d=(e)f"#;
    let value = SipContentType::parse_body_part_strict(raw)?;
    assert_eq!(value.param("a"), Some(Some("b (c)")));
    assert_eq!(value.param("d"), Some(Some("f")));
    Ok(())
}

#[test]
fn a_quote_outside_a_parameter_value_opens_nothing() {
    let raw = r#"text/pl"ain (x); a="b (c)""#;
    let value = relaxed_body_part!(
        SipContentType,
        raw,
        &[(WarningCode::StrayDelimiter, Some(7))]
    );
    assert_eq!(value.subtype(), "plain");
    assert_eq!(value.param("a"), Some(Some("b (c)")));
}

#[test]
fn an_unclosed_parenthesis_is_text_and_later_comments_still_read() {
    let raw = "text/plain (a (b) c";
    let value = relaxed_body_part!(SipContentType, raw, &[(WarningCode::InvalidToken, Some(5))]);
    assert_eq!(value.subtype(), "plain (a c");
    let value = relaxed_body_part!(
        SipContentType,
        "text/plain;a=b ) c",
        &[(WarningCode::InvalidToken, Some(13))]
    );
    assert_eq!(value.param("a"), Some(Some("b ) c")));
}

#[test]
fn a_comment_inside_a_token_is_one_token_break() {
    let value = relaxed_body_part!(
        SipContentType,
        "text/plain;a=b(c)d;e(f)g=h",
        &[
            (WarningCode::InvalidToken, Some(13)),
            (WarningCode::InvalidToken, Some(19)),
        ]
    );
    assert_eq!(value.param("a"), Some(Some("b d")));
    assert_eq!(value.param("e g"), Some(Some("h")));
    assert_eq!(value.to_string(), r#"text/plain;a="b d";e g=h"#);
    let value = relaxed_body_part!(
        SipContentType,
        "te(x)xt/plain",
        &[(WarningCode::InvalidToken, Some(0))]
    );
    assert_eq!(value.media_type(), "te xt");
}

#[test]
fn comment_content_is_reported_where_it_breaks_ctext() {
    let value = relaxed_body_part!(
        SipContentType,
        "text/plain (a\u{1}b)",
        &[(WarningCode::ControlChar, Some(13))]
    );
    assert_eq!(value.to_string(), "text/plain");
    let parsed = SipContentType::parse_body_part_with_warnings("text/plain (a\u{1}b)").unwrap();
    assert_eq!(parsed.warnings[0].kind, WarningKind::Lost);
    assert_eq!(parsed.warnings[0].field, Field::Value);
    let value = relaxed_body_part!(
        SipContentType,
        "text/plain (caf\u{e9})",
        &[(WarningCode::NonAscii, Some(15))]
    );
    assert_eq!(value.to_string(), "text/plain");
}

#[test]
fn positions_after_a_comment_point_into_the_row() -> R {
    let row = "(c\r\nd) text/p@in;a=\"x\"";
    let parsed = SipContentType::parse_body_part_with_warnings(row)?;
    let at: Vec<_> = parsed
        .warnings
        .iter()
        .map(|w| {
            (
                w.code,
                w.position
                    .map(|p| &row[p..]),
            )
        })
        .collect();
    assert_eq!(
        at,
        [
            (WarningCode::ControlChar, Some("\r\nd) text/p@in;a=\"x\"")),
            (WarningCode::InvalidToken, Some("p@in;a=\"x\"")),
        ]
    );
    assert_eq!(
        parsed.warnings[0]
            .span()
            .unwrap()
            .get(row),
        Ok("\r\n")
    );
    assert_eq!(
        parsed
            .value
            .params()
            .value_span("a")
            .unwrap()
            .get(row),
        Ok("\"x\"")
    );
    Ok(())
}

#[test]
fn a_mime_token_is_legal_in_a_body_part() -> R {
    let raw = "text/x-a#b;p{q}=r|s;t=$&^";
    let value = SipContentType::parse_body_part_strict(raw)?;
    assert_eq!(value.subtype(), "x-a#b");
    assert_eq!(value.param("p{q}"), Some(Some("r|s")));
    assert_eq!(
        codes(&SipContentType::parse_with_warnings(raw)?.warnings),
        [
            (WarningCode::InvalidToken, Some(5)),
            (WarningCode::InvalidToken, Some(11)),
            (WarningCode::InvalidToken, Some(16)),
            (WarningCode::InvalidToken, Some(22)),
        ]
    );
    assert_eq!(
        SipContentType::parse_body_part_strict(&value.to_string())?,
        value
    );
    for raw in ["text/plain;a=2001:db8::1", "text/plain;a=[2001:db8::1]"] {
        relaxed_body_part!(
            SipContentType,
            raw,
            &[(WarningCode::InvalidToken, Some(13))]
        );
        assert!(SipContentType::parse_strict(raw).is_ok(), "{raw}");
    }
    Ok(())
}

/// A transfer encoding read both ways, which share one grammar: `parse`
/// keeps the value, the warnings are `want`, and strict refuses the first.
fn relaxed_cte(raw: &str, want: &[(WarningCode, Option<usize>)]) -> SipContentTransferEncoding {
    let body = relaxed_body_part!(SipContentTransferEncoding, raw, want);
    let sip = relaxed(
        SipContentTransferEncoding::parse_with_warnings(raw),
        SipContentTransferEncoding::parse(raw),
        SipContentTransferEncoding::parse_strict(raw),
        want,
    );
    assert_eq!(sip, body, "{raw}");
    body
}

#[test]
fn transfer_encoding_names_the_rfc_2045_mechanisms_in_any_case() -> R {
    for (raw, known) in [
        ("7bit", TransferEncoding::SevenBit),
        ("8BIT", TransferEncoding::EightBit),
        ("Binary", TransferEncoding::Binary),
        ("Quoted-Printable", TransferEncoding::QuotedPrintable),
        ("bAsE64", TransferEncoding::Base64),
    ] {
        let value = SipContentTransferEncoding::parse_body_part_strict(raw)?;
        assert_eq!(value.known(), Some(known), "{raw}");
        assert_eq!(value.as_str(), raw.to_ascii_lowercase());
        assert_eq!(value.to_string(), raw.to_ascii_lowercase());
        assert_eq!(SipContentTransferEncoding::parse_strict(raw)?, value);
        assert_eq!(SipContentTransferEncoding::new(raw)?, value);
    }
    let mut seen = std::collections::HashSet::new();
    for raw in ["7bit", "8bit", "binary", "quoted-printable", "base64"] {
        let known = SipContentTransferEncoding::new(raw)?.known();
        assert!(known.is_some() && seen.insert(known), "{raw}");
    }
    Ok(())
}

#[test]
fn transfer_encoding_keeps_any_other_token_unnamed() -> R {
    for raw in ["x-uuencode", "X-Custom#1", "ietf-$&^{|}"] {
        let value = SipContentTransferEncoding::parse_body_part_strict(raw)?;
        assert_eq!(value.known(), None, "{raw}");
        assert_eq!(value.as_str(), raw.to_ascii_lowercase());
    }
    Ok(())
}

#[test]
fn transfer_encoding_reads_comments_in_both_entry_points() -> R {
    let base64 = SipContentTransferEncoding::new("base64")?;
    for raw in [
        "base64 (encoded)",
        "(c) base64",
        "base64(a (b) c)",
        " \tBASE64 ( x ) ",
    ] {
        assert_eq!(relaxed_cte_clean(raw)?, base64, "{raw}");
    }
    Ok(())
}

fn relaxed_cte_clean(raw: &str) -> Result<SipContentTransferEncoding, ParseError> {
    let body = SipContentTransferEncoding::parse_body_part_strict(raw)?;
    assert_eq!(
        SipContentTransferEncoding::parse_strict(raw)?,
        body,
        "{raw}"
    );
    Ok(body)
}

#[test]
fn transfer_encoding_keeps_its_first_word() {
    let value = relaxed_cte("base64 x", &[(WarningCode::TrailingContent, Some(6))]);
    assert_eq!(value.as_str(), "base64");
    let value = relaxed_cte("base(c)64", &[(WarningCode::TrailingContent, Some(4))]);
    assert_eq!(value.as_str(), "base");
    let parsed = SipContentTransferEncoding::parse_body_part_with_warnings("base64 x y").unwrap();
    assert_eq!(parsed.warnings[0].kind, WarningKind::Lost);
    assert_eq!(parsed.warnings[0].field, Field::TransferEncoding);
    assert_eq!(
        parsed.warnings[0]
            .span()
            .unwrap()
            .get("base64 x y"),
        Ok(" x y")
    );
}

#[test]
fn transfer_encoding_keeps_a_non_token_under_invalid_token() {
    let value = relaxed_cte("base64;x=1", &[(WarningCode::InvalidToken, Some(0))]);
    assert_eq!(value.as_str(), "base64;x=1");
    let value = relaxed_cte("(c) b@se64", &[(WarningCode::InvalidToken, Some(4))]);
    assert_eq!(value.as_str(), "b@se64");
    let value = relaxed_cte("\"base64\"", &[(WarningCode::StrayDelimiter, Some(0))]);
    assert_eq!(value.as_str(), "base64");
    let value = relaxed_cte("base64 (\u{1})", &[(WarningCode::ControlChar, Some(8))]);
    assert_eq!(value.as_str(), "base64");
}

#[test]
fn transfer_encoding_without_a_word_is_an_error() {
    let empty = Err(ParseError::Malformed(sip_header::Fault::new(
        Field::TransferEncoding,
        FaultCode::Empty,
    )));
    for raw in ["", " ", "(base64)", "\"\""] {
        assert_eq!(SipContentTransferEncoding::parse(raw), empty, "{raw:?}");
        assert_eq!(
            SipContentTransferEncoding::parse_body_part(raw),
            empty,
            "{raw:?}"
        );
    }
}

#[test]
fn transfer_encoding_new_refuses_what_is_no_mime_token() {
    for raw in ["", "a b", "a;b", "a(b)", "a\r\nb", "\u{e9}"] {
        assert!(SipContentTransferEncoding::new(raw).is_err(), "{raw:?}");
    }
}

#[cfg(feature = "serde")]
#[test]
fn transfer_encoding_serde_is_its_mechanism() {
    let value = SipContentTransferEncoding::new("Base64").unwrap();
    assert_eq!(serde_json::to_string(&value).unwrap(), r#""base64""#);
    for json in [r#""base64""#, r#""BASE64""#] {
        assert_eq!(
            serde_json::from_str::<SipContentTransferEncoding>(json).unwrap(),
            value
        );
    }
    let kept = SipContentTransferEncoding::parse("b@se64").unwrap();
    let json = serde_json::to_string(&kept).unwrap();
    assert_eq!(
        serde_json::from_str::<SipContentTransferEncoding>(&json).unwrap(),
        kept
    );
    for json in [r#""a b""#, r#""""#, r#""a\nb""#, "1"] {
        assert!(
            serde_json::from_str::<SipContentTransferEncoding>(json).is_err(),
            "{json}"
        );
    }
}

#[test]
fn content_id_comments_around_the_msg_id_are_legal() -> R {
    let id = SipContentId::parse_strict("<abc@example.com>")?;
    for raw in [
        "(c) <abc@example.com> (d)",
        "<abc@example.com>(d (e))",
        "\t(c)<abc@example.com>",
    ] {
        assert_eq!(SipContentId::parse_body_part_strict(raw)?, id, "{raw}");
    }
    Ok(())
}

#[test]
fn content_id_obsolete_forms_are_read_and_reported() {
    for (raw, at, left) in [
        ("<a . b (c) @ example.com>", 2, "a.b"),
        ("< abc@example.com >", 1, "abc"),
        ("<abc(c)@example.com>", 4, "abc"),
        ("<\"a b\"@example.com>", 1, "\"a b\""),
        ("<\"a\".\"b\"@example.com>", 1, "\"a\".\"b\""),
        ("<a. \"b\"@example.com>", 3, "a.\"b\""),
    ] {
        let id = relaxed_body_part!(SipContentId, raw, &[(WarningCode::ObsoleteMsgId, Some(at))]);
        assert_eq!(
            (id.left(), id.right()),
            (left, Some("example.com")),
            "{raw}"
        );
        assert_eq!(
            SipContentId::parse_body_part(&id.to_string()),
            Ok(id),
            "{raw}"
        );
    }
    let parsed = SipContentId::parse_body_part_with_warnings("< abc@example.com >").unwrap();
    assert_eq!(parsed.warnings[0].kind, WarningKind::Recovered);
    assert_eq!(parsed.warnings[0].field, Field::ContentId);
    let id = relaxed_body_part!(
        SipContentId,
        "<a@ [b@c] >",
        &[(WarningCode::ObsoleteMsgId, Some(3))]
    );
    assert_eq!(id.right(), Some("[b@c]"));
}

#[test]
fn a_sip_content_id_keeps_what_a_body_part_reads_as_a_comment() -> R {
    let raw = "<abc(c)@example.com>";
    let sip = SipContentId::parse_with_warnings(raw)?;
    assert_eq!(codes(&sip.warnings), [(WarningCode::InvalidToken, Some(4))]);
    assert_eq!(
        sip.value
            .left(),
        "abc(c)"
    );
    let body = SipContentId::parse_body_part_with_warnings(raw)?;
    assert_eq!(
        body.value
            .left(),
        "abc"
    );
    Ok(())
}

#[test]
fn content_id_breaches_outside_the_obsolete_forms_are_kept() {
    let id = relaxed_body_part!(
        SipContentId,
        "<a (c) b@x>",
        &[(WarningCode::InvalidToken, Some(2))]
    );
    assert_eq!(id.left(), "a b");
    let id = relaxed_body_part!(
        SipContentId,
        "<a@[b (c)]>",
        &[(WarningCode::InvalidToken, Some(3))]
    );
    assert_eq!(id.right(), Some("[b (c)]"));
    let id = relaxed_body_part!(
        SipContentId,
        "<a\"(c)\"@x>",
        &[(WarningCode::InvalidToken, Some(2))]
    );
    assert_eq!(id.left(), "a\" \"");
    let id = relaxed_body_part!(
        SipContentId,
        "abc@example.com (c)",
        &[(WarningCode::MissingBrackets, Some(0))]
    );
    assert_eq!(id.id(), "abc@example.com");
    let id = relaxed_body_part!(
        SipContentId,
        "<abc (c)>",
        &[
            (WarningCode::ObsoleteMsgId, Some(4)),
            (WarningCode::MissingIdRight, Some(8)),
        ]
    );
    assert_eq!((id.left(), id.right()), ("abc", None));
    relaxed_body_part!(
        SipContentId,
        "<abc@example.com> (\u{1})",
        &[(WarningCode::ControlChar, Some(19))]
    );
}

#[test]
fn content_id_of_comments_alone_is_an_error() {
    for raw in ["(c)", "<(c)>", "< (c) >"] {
        assert_eq!(
            SipContentId::parse_body_part(raw),
            Err(ParseError::Malformed(sip_header::Fault::new(
                Field::ContentId,
                FaultCode::Empty
            ))),
            "{raw}"
        );
    }
}

/// Text built from the characters that frame a body-part value.
fn body_text() -> impl Strategy<Value = String> {
    let piece = prop_oneof![
        3 => "[a-z]{1,3}",
        2 => prop::sample::select(vec![
            "(", ")", "\"", "\\", ";", "=", "/", " ", "\t", "<", ">", "@", "[", "]", ".", ",",
            "\u{a0}", "\u{1}", "\u{e9}", "\r\n", "\r\n ",
        ])
        .prop_map(str::to_string),
    ];
    prop::collection::vec(piece, 0..16).prop_map(|v| v.concat())
}

/// A SIP-legal Content-Type value, with no comment.
fn sip_content_type() -> impl Strategy<Value = String> {
    let token = "[a-zA-Z0-9.!%*_+`'~-]{1,6}";
    let value = prop_oneof![
        token.prop_map(|t| t.to_string()),
        "[a-z ;,()<>@]{0,6}".prop_map(|t| format!("\"{t}\"")),
    ];
    (token, token, prop::collection::vec((token, value), 0..3)).prop_map(|(t, s, params)| {
        let params: String = params
            .into_iter()
            .map(|(k, v)| format!(";{k}={v}"))
            .collect();
        format!("{t}/{s}{params}")
    })
}

/// Positions in input order, spans slicing the input.
fn placed_in(input: &str, warnings: &[ParseWarning]) -> Result<(), TestCaseError> {
    let mut last = 0;
    for w in warnings {
        if let Some(p) = w.position {
            prop_assert!(p >= last && p <= input.len(), "{:?}: {:?}", input, warnings);
            last = p;
        }
        if let Some(span) = w.span() {
            prop_assert!(
                span.get(input)
                    .is_ok(),
                "{:?}: {:?}",
                input,
                w
            );
        }
    }
    Ok(())
}

/// A body-part read of `input` with its warnings placed in it, whose print
/// carries no CR, LF or NUL and reads back as the same value.
fn body_part_is_stable<T>(input: &str) -> Result<(), TestCaseError>
where
    T: BodyPartParse + std::fmt::Display + std::fmt::Debug + PartialEq,
{
    let Ok(parsed) = T::parse_body_part_with_warnings(input) else {
        return Ok(());
    };
    placed_in(input, &parsed.warnings)?;
    let wire = parsed
        .value
        .to_string();
    prop_assert!(!wire.contains(['\r', '\n', '\0']), "{:?}", wire);
    prop_assert_eq!(
        T::parse_body_part(&wire),
        Ok(parsed.value),
        "{:?} -> {:?}",
        input,
        wire
    );
    Ok(())
}

proptest! {
    #[test]
    fn content_type_body_part_reads_back_its_print(raw in body_text()) {
        body_part_is_stable::<SipContentType>(&raw)?;
        body_part_is_stable::<SipContentType>(&format!("text/plain;a={raw}"))?;
    }

    #[test]
    fn transfer_encoding_reads_back_its_print(raw in body_text()) {
        body_part_is_stable::<SipContentTransferEncoding>(&raw)?;
        let sip = SipContentTransferEncoding::parse_with_warnings(&raw);
        prop_assert_eq!(sip, SipContentTransferEncoding::parse_body_part_with_warnings(&raw));
    }

    #[test]
    fn content_type_without_comments_reads_as_its_sip_header(raw in sip_content_type()) {
        let sip = SipContentType::parse_strict(&raw);
        prop_assume!(sip.is_ok());
        prop_assert_eq!(SipContentType::parse_body_part_strict(&raw), sip);
    }

    #[test]
    fn content_type_positions_count_the_comments_before_them(
        comment in prop::collection::vec(
            prop::sample::select(vec!["a", " ", "\t", "(b)", "(c (d))", "\\)", "\\(", "\\\\", "\"", ";"]),
            0..8,
        ),
        lead in "[ \t]{0,3}",
    ) {
        let row = format!("{lead}({}) text/p@in", comment.concat());
        let parsed = SipContentType::parse_body_part_with_warnings(&row).unwrap();
        prop_assert_eq!(
            codes(&parsed.warnings),
            vec![(WarningCode::InvalidToken, Some(row.len() - 4))]
        );
        let row = format!("{lead}({}) <a@b c>", comment.concat());
        let parsed = SipContentId::parse_body_part_with_warnings(&row).unwrap();
        prop_assert_eq!(
            codes(&parsed.warnings),
            vec![(WarningCode::InvalidToken, Some(row.len() - 3))]
        );
    }

    #[test]
    fn content_id_body_part_reads_back_its_print(raw in body_text()) {
        body_part_is_stable::<SipContentId>(&raw)?;
        body_part_is_stable::<SipContentId>(&format!("<{raw}@example.com>"))?;
        body_part_is_stable::<SipContentId>(&format!("<a.b@{raw}>"))?;
    }

    #[test]
    fn content_id_without_comments_reads_as_its_sip_header(
        left in "[a-z0-9!#$%&'*+/=?^_`{|}~-]{1,4}(\\.[a-z0-9-]{1,4}){0,2}",
        right in prop_oneof![
            "[a-z0-9-]{1,6}(\\.[a-z0-9-]{1,6}){0,2}",
            "\\[[!-Z^-~]{0,8}\\]",
        ],
    ) {
        let raw = format!("<{left}@{right}>");
        let sip = SipContentId::parse_strict(&raw);
        prop_assert!(sip.is_ok(), "{:?}: {:?}", raw, sip);
        prop_assert_eq!(SipContentId::parse_body_part_strict(&raw), sip);
    }
}
