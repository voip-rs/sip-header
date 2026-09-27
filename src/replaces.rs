//! RFC 3891 `Replaces` header parser.
//!
//! Also serves `Join` (RFC 3911), whose grammar is identical:
//! `callid *(SEMI param)` with mandatory `to-tag` and `from-tag`.

use crate::dialog_id::{DialogBuild, DialogFields, DialogFraming, DialogId};

/// A `Replaces` header value (RFC 3891 §6.1).
///
/// Identifies the dialog to be replaced: Call-ID plus the mandatory
/// `to-tag` and `from-tag`. Also used for `Join` (RFC 3911 §7.1), whose
/// grammar is identical. [`Display`](std::fmt::Display) emits the
/// [`framing`](Self::framing) the value holds.
///
/// ```
/// use sip_header::{DialogFraming, SipReplaces};
///
/// let r = SipReplaces::new("abc@203.0.113.5", "t1", "f1").with_early_only(true);
/// assert_eq!(r.to_string(), "abc@203.0.113.5;to-tag=t1;from-tag=f1;early-only");
/// assert_eq!(
///     r.with_framing(DialogFraming::UriHeader).to_string(),
///     "abc%40203.0.113.5%3Bto-tag%3Dt1%3Bfrom-tag%3Df1%3Bearly-only"
/// );
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(from = "SipReplacesParts", into = "SipReplacesParts")
)]
#[non_exhaustive]
pub struct SipReplaces(DialogId);

dialog_id_type!(SipReplaces, to_tag => "to-tag", from_tag => "from-tag", early_only: true);

impl SipReplaces {
    /// Whether the `early-only` flag is present (RFC 3891 §3).
    pub fn early_only(&self) -> bool {
        self.0
            .early_only()
    }

    /// Set or clear the `early-only` flag.
    pub fn with_early_only(mut self, early_only: bool) -> Self {
        self.0
            .set_early_only(early_only);
        self
    }
}

#[cfg(feature = "serde")]
#[derive(serde::Serialize, serde::Deserialize)]
struct SipReplacesParts {
    call_id: String,
    to_tag: String,
    from_tag: String,
    #[serde(default)]
    early_only: bool,
    #[serde(default)]
    params: Vec<(String, Option<String>)>,
    #[serde(default)]
    framing: DialogFraming,
}

#[cfg(feature = "serde")]
impl From<SipReplacesParts> for SipReplaces {
    fn from(p: SipReplacesParts) -> Self {
        p.params
            .into_iter()
            .fold(
                SipReplaces::new(p.call_id, p.to_tag, p.from_tag)
                    .with_early_only(p.early_only)
                    .with_framing(p.framing),
                |r, (k, v)| r.with_param(k, v),
            )
    }
}

#[cfg(feature = "serde")]
impl From<SipReplaces> for SipReplacesParts {
    fn from(r: SipReplaces) -> Self {
        SipReplacesParts {
            call_id: r
                .call_id()
                .to_string(),
            to_tag: r
                .to_tag()
                .to_string(),
            from_tag: r
                .from_tag()
                .to_string(),
            early_only: r.early_only(),
            params: r
                .params()
                .to_vec(),
            framing: r.framing(),
        }
    }
}

impl DialogBuild for SipReplaces {
    fn build(fields: DialogFields, framing: DialogFraming) -> Self {
        fields
            .params
            .into_iter()
            .fold(
                SipReplaces::new(fields.call_id, fields.first_tag, fields.second_tag)
                    .with_early_only(fields.early_only)
                    .with_framing(framing),
                |r, (key, value)| r.with_param(key, value),
            )
    }
}

dialog_id_parse!(SipReplaces);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DialogIdEdit, HeaderParse};
    use sip_uri::WarningKind;

    use crate::diagnostic::{Field, WarningCode};
    use crate::error::{FaultCode, ParseError};

    #[test]
    fn parse_basic() {
        let r = SipReplaces::parse("abc123@203.0.113.5;to-tag=t1;from-tag=f1").unwrap();
        assert_eq!(r.call_id(), "abc123@203.0.113.5");
        assert_eq!(r.host(), Some("203.0.113.5"));
        assert_eq!(r.to_tag(), "t1");
        assert_eq!(r.from_tag(), "f1");
        assert!(!r.early_only());
    }

    #[test]
    fn host_none_without_at() {
        let r = SipReplaces::parse("abc123;to-tag=t1;from-tag=f1").unwrap();
        assert_eq!(r.call_id(), "abc123");
        assert_eq!(r.host(), None);
    }

    #[test]
    fn early_only_flag() {
        let r = SipReplaces::parse("abc@example.com;to-tag=t1;from-tag=f1;early-only").unwrap();
        assert!(r.early_only());
    }

    #[test]
    fn param_names_case_insensitive_values_preserved() {
        let r = SipReplaces::parse("abc@example.com;TO-TAG=T1abc;From-Tag=F1xyz").unwrap();
        assert_eq!(r.to_tag(), "T1abc");
        assert_eq!(r.from_tag(), "F1xyz");
    }

    #[test]
    fn generic_params_preserved() {
        let r = SipReplaces::parse("abc@example.com;to-tag=t1;from-tag=f1;foo=bar;flag").unwrap();
        assert_eq!(r.param("foo"), Some(Some("bar")));
        assert_eq!(r.param("flag"), Some(None));
        assert_eq!(r.param("missing"), None);
        assert_eq!(
            r.params()
                .len(),
            2
        );
    }

    #[test]
    fn missing_to_tag_fails() {
        assert_eq!(
            SipReplaces::parse("abc@example.com;from-tag=f1"),
            Err(ParseError::malformed(Field::Tag, FaultCode::Missing, None))
        );
    }

    #[test]
    fn missing_from_tag_fails() {
        assert!(SipReplaces::parse("abc@example.com;to-tag=t1").is_err());
    }

    #[test]
    fn duplicate_to_tag_fails() {
        let input = "abc@example.com;to-tag=t1;to-tag=t2;from-tag=f1";
        assert_eq!(
            SipReplaces::parse(input),
            Err(ParseError::malformed(
                Field::Tag,
                FaultCode::Duplicate,
                input.rfind("to-tag")
            ))
        );
    }

    #[test]
    fn empty_fails() {
        assert_eq!(SipReplaces::parse(""), Err(ParseError::empty(Field::Value)));
        assert_eq!(
            SipReplaces::parse("  "),
            Err(ParseError::empty(Field::Value))
        );
    }

    #[test]
    fn uri_header_error_has_no_position() {
        assert_eq!(
            SipReplaces::parse_uri_header("abc%3Bto-tag%3Dt1%3Bto-tag%3Dt2%3Bfrom-tag%3Df1"),
            Err(ParseError::malformed(
                Field::Tag,
                FaultCode::Duplicate,
                None
            ))
        );
    }

    #[test]
    fn parse_uri_header_encoded() {
        let r = SipReplaces::parse_uri_header("abc123%40203.0.113.5%3Bto-tag%3Dt1%3Bfrom-tag%3Df1")
            .unwrap();
        assert_eq!(r.call_id(), "abc123@203.0.113.5");
        assert_eq!(r.host(), Some("203.0.113.5"));
        assert_eq!(r.to_tag(), "t1");
        assert_eq!(r.from_tag(), "f1");
    }

    #[test]
    fn parse_uri_header_lowercase_hex() {
        let r = SipReplaces::parse_uri_header("abc123%40203.0.113.5%3bto-tag%3dt1%3bfrom-tag%3df1")
            .unwrap();
        assert_eq!(r.host(), Some("203.0.113.5"));
        assert_eq!(r.to_tag(), "t1");
    }

    #[test]
    fn parse_uri_header_early_only() {
        let r = SipReplaces::parse_uri_header(
            "abc123%40203.0.113.5%3Bto-tag%3Dt1%3Bfrom-tag%3Df1%3Bearly-only",
        )
        .unwrap();
        assert!(r.early_only());
    }

    #[test]
    fn parse_uri_header_invalid_utf8_fails() {
        assert_eq!(
            SipReplaces::parse_uri_header("abc%C0%80;to-tag=t1;from-tag=f1"),
            Err(ParseError::malformed(
                Field::Value,
                FaultCode::NotUtf8,
                None
            ))
        );
    }

    #[test]
    fn display_roundtrip_wire() {
        let input = "abc123@203.0.113.5;to-tag=t1;from-tag=f1;early-only;foo=bar";
        let r = SipReplaces::parse(input).unwrap();
        assert_eq!(r.to_string(), input);
        assert_eq!(SipReplaces::parse(&r.to_string()).unwrap(), r);
    }

    #[test]
    fn display_roundtrip_uri_header() {
        let input = "abc123%40203.0.113.5%3Bto-tag%3Dt1%3Bfrom-tag%3Df1";
        let r = SipReplaces::parse_uri_header(input).unwrap();
        assert_eq!(r.to_string(), input);
        assert_eq!(SipReplaces::parse_uri_header(&r.to_string()).unwrap(), r);
    }

    #[test]
    fn with_call_id_wire_changes_only_call_id() {
        let input = "abc123@203.0.113.5;to-tag=t1;from-tag=f1;early-only;foo=bar";
        let r = SipReplaces::parse(input)
            .unwrap()
            .with_call_id("xyz789@example.com")
            .unwrap();
        assert_eq!(
            r.to_string(),
            "xyz789@example.com;to-tag=t1;from-tag=f1;early-only;foo=bar"
        );
    }

    #[test]
    fn with_call_id_keeps_uri_header_framing() {
        let input = "abc123%40203.0.113.5%3Bto-tag%3Dt1%3Bfrom-tag%3Df1";
        let r = SipReplaces::parse_uri_header(input)
            .unwrap()
            .with_call_id("abc123@example.com")
            .unwrap();
        assert_eq!(
            r.to_string(),
            "abc123%40example.com%3Bto-tag%3Dt1%3Bfrom-tag%3Df1"
        );
    }

    #[test]
    fn with_call_id_replacing_host_only() {
        let r = SipReplaces::parse("abc123@203.0.113.5;to-tag=t1;from-tag=f1").unwrap();
        let host = r
            .host()
            .unwrap();
        let call_id = format!(
            "{}example.com",
            &r.call_id()[..r
                .call_id()
                .len()
                - host.len()]
        );
        let r = r
            .with_call_id(call_id)
            .unwrap();
        assert_eq!(r.call_id(), "abc123@example.com");
    }

    #[test]
    fn with_call_id_rejects_non_word() {
        let r = SipReplaces::parse("abc@example.com;to-tag=t1;from-tag=f1").unwrap();
        for bad in [
            "",
            "a;to-tag=t2",
            "a,b",
            "a b",
            "a\r\nSubject: x",
            "a@b@c",
            "a@",
            "@b",
            "a@ b",
        ] {
            assert!(
                r.clone()
                    .with_call_id(bad)
                    .is_err(),
                "accepted {bad:?}"
            );
        }
    }

    #[test]
    fn with_call_id_accepts_full_word_charset() {
        let call_id = "a%b!*_+`'~()<>:\\\"/[]?{}.-@example.com";
        let r = SipReplaces::parse("abc@example.com;to-tag=t1;from-tag=f1")
            .unwrap()
            .with_call_id(call_id)
            .unwrap();
        assert_eq!(r.call_id(), call_id);
    }

    #[test]
    fn quoted_param_hides_tag_lookalike() {
        let r =
            SipReplaces::parse(r#"a@example.com;x="p;to-tag=evil";to-tag=t;from-tag=f"#).unwrap();
        assert_eq!(r.call_id(), "a@example.com");
        assert_eq!(r.to_tag(), "t");
        assert_eq!(r.from_tag(), "f");
        assert_eq!(r.param("x"), Some(Some(r#""p;to-tag=evil""#)));
        assert_eq!(
            r.to_string(),
            r#"a@example.com;to-tag=t;from-tag=f;x="p;to-tag=evil""#
        );
    }

    #[test]
    fn unterminated_quote_splits_at_next_semicolon() {
        let r = SipReplaces::parse(r#"a;x="p;to-tag=t;from-tag=f"#).unwrap();
        assert_eq!(r.to_tag(), "t");
        assert_eq!(r.from_tag(), "f");
        assert_eq!(r.param("x"), Some(Some(r#""p"#)));
    }

    #[test]
    fn call_id_with_quote_splits_at_first_semicolon() {
        let r = SipReplaces::parse(r#"a"b@example.com;to-tag=t;from-tag=f"#).unwrap();
        assert_eq!(r.call_id(), r#"a"b@example.com"#);
        assert_eq!(r.to_tag(), "t");
    }

    #[test]
    fn tags_and_params_sws_trimmed() {
        let r =
            SipReplaces::parse("a@example.com ; to-tag = t ; from-tag = f ; foo = bar").unwrap();
        assert_eq!(r.to_tag(), "t");
        assert_eq!(r.from_tag(), "f");
        assert_eq!(r.param("foo"), Some(Some("bar")));
    }

    fn only_warning(p: &crate::Parsed<SipReplaces>) -> crate::ParseWarning {
        assert_eq!(
            p.warnings
                .len(),
            1,
            "{:?}",
            p.warnings
        );
        p.warnings[0]
    }

    #[test]
    fn unterminated_quote_param_warns() {
        let input = r#"a@example.com;x="p;to-tag=t;from-tag=f"#;
        let r = SipReplaces::parse(input).unwrap();
        assert_eq!(r.to_tag(), "t");
        let w = only_warning(&SipReplaces::parse_with_warnings(input).unwrap());
        assert_eq!(
            (w.field, w.code, w.kind, w.position),
            (
                Field::Param,
                WarningCode::UnterminatedQuote,
                WarningKind::Recovered,
                input.find('"')
            )
        );
        assert_eq!(
            SipReplaces::parse_strict(input),
            Err(ParseError::NonConformant(w))
        );
    }

    #[test]
    fn call_id_outside_callid_grammar_warns() {
        for (input, at) in [
            ("a b@example.com;to-tag=t;from-tag=f", 1),
            (" a@b@c;to-tag=t;from-tag=f", 4),
        ] {
            let r = SipReplaces::parse(input).unwrap();
            assert_eq!(r.to_tag(), "t");
            let w = only_warning(&SipReplaces::parse_with_warnings(input).unwrap());
            assert_eq!(
                (w.field, w.code, w.kind, w.position),
                (
                    Field::CallId,
                    WarningCode::InvalidToken,
                    WarningKind::Recovered,
                    Some(at)
                ),
                "{input}"
            );
            assert_eq!(
                SipReplaces::parse_strict(input),
                Err(ParseError::NonConformant(w))
            );
        }
        assert!(
            SipReplaces::parse_with_warnings("abc@example.com;to-tag=t;from-tag=f;early-only")
                .unwrap()
                .warnings
                .is_empty()
        );
    }

    #[test]
    fn uri_header_warning_points_into_decoded_value() {
        let input = "a%20b%40example.com%3Bto-tag%3Dt%3Bfrom-tag%3Df";
        let r = SipReplaces::parse_uri_header(input).unwrap();
        assert_eq!(r.call_id(), "a b@example.com");
        let w = only_warning(&SipReplaces::parse_uri_header_with_warnings(input).unwrap());
        assert_eq!(
            (w.field, w.code, w.position),
            (Field::CallId, WarningCode::InvalidToken, Some(1))
        );
        assert_eq!(
            SipReplaces::parse_uri_header_strict(input),
            Err(ParseError::NonConformant(w))
        );
        assert!(SipReplaces::parse_uri_header_strict(
            "abc123%40203.0.113.5%3Bto-tag%3Dt1%3Bfrom-tag%3Df1"
        )
        .is_ok());
    }

    #[test]
    fn parse_is_wire_framing() {
        let r = SipReplaces::parse("abc123@203.0.113.5;to-tag=t1;from-tag=f1").unwrap();
        assert_eq!(r.call_id(), "abc123@203.0.113.5");
    }
}
