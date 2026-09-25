//! RFC 3891 `Replaces` header parser.
//!
//! Also serves `Join` (RFC 3911), whose grammar is identical:
//! `callid *(SEMI param)` with mandatory `to-tag` and `from-tag`.

use crate::dialog_id::{DialogId, DialogKind};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Replaces;

impl DialogKind for Replaces {
    const FIRST_TAG: &'static str = "to-tag";
    const SECOND_TAG: &'static str = "from-tag";
    const EARLY_ONLY: bool = true;
}

/// A parsed `Replaces` header value (RFC 3891 §6.1).
///
/// Identifies the dialog to be replaced: Call-ID plus the mandatory
/// `to-tag` and `from-tag`. Also used for `Join` (RFC 3911 §7.1), whose
/// grammar is identical.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SipReplaces(DialogId<Replaces>);

dialog_id_type!(SipReplaces, example: "abc@203.0.113.5;to-tag=t1;from-tag=f1;early-only");

impl SipReplaces {
    /// The mandatory `to-tag` value.
    pub fn to_tag(&self) -> &str {
        self.0
            .first_tag()
    }

    /// The mandatory `from-tag` value.
    pub fn from_tag(&self) -> &str {
        self.0
            .second_tag()
    }

    /// Whether the `early-only` flag is present (RFC 3891 §3).
    pub fn early_only(&self) -> bool {
        self.0
            .early_only()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diagnostic::Field;
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
        assert_eq!(SipReplaces::parse(""), Err(ParseError::Empty));
        assert_eq!(SipReplaces::parse("  "), Err(ParseError::Empty));
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

    #[test]
    fn from_str_is_wire_framing() {
        let r: SipReplaces = "abc123@203.0.113.5;to-tag=t1;from-tag=f1"
            .parse()
            .unwrap();
        assert_eq!(r.call_id(), "abc123@203.0.113.5");
    }
}
