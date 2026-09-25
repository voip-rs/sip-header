//! RFC 3891 `Replaces` header parser.
//!
//! Also serves `Join` (RFC 3911), whose grammar is identical:
//! `callid *(SEMI param)` with mandatory `to-tag` and `from-tag`.

use std::fmt;

use percent_encoding::percent_decode_str;

use crate::diagnostic::Field;
use crate::error::{FaultCode, ParseError};

pub(crate) struct DialogId {
    pub call_id: String,
    pub first_tag: String,
    pub second_tag: String,
    pub early_only: bool,
    pub params: Vec<(String, Option<String>)>,
}

/// Parse `callid *(SEMI param)` with two mandatory tag params.
///
/// `early-only` is recognized as a flag only when `with_early_only` is set
/// (RFC 3891 defines it; RFC 4538 does not).
pub(crate) fn parse_dialog_id(
    raw: &str,
    first_tag_name: &str,
    second_tag_name: &str,
    with_early_only: bool,
) -> Result<DialogId, ParseError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(ParseError::Empty);
    }

    // A call-id `word` may contain `"`, so it ends at the first raw `;`.
    let (call_id, rest) = trimmed
        .split_once(';')
        .unwrap_or((trimmed, ""));
    let call_id = call_id.trim();
    if call_id.is_empty() {
        return Err(ParseError::malformed(
            Field::CallId,
            FaultCode::Missing,
            Some(crate::offset_in(raw, trimmed)),
        ));
    }

    let mut first_tag: Option<String> = None;
    let mut second_tag: Option<String> = None;
    let mut early_only = false;
    let mut params = Vec::new();

    for param in crate::parse_params(rest) {
        let key = param
            .key
            .to_ascii_lowercase();
        if let Some(value) = param.value {
            let slot = if key == first_tag_name {
                Some(&mut first_tag)
            } else if key == second_tag_name {
                Some(&mut second_tag)
            } else {
                None
            };
            match slot {
                Some(slot) => {
                    if value.is_empty() {
                        return Err(ParseError::malformed(
                            Field::Tag,
                            FaultCode::Missing,
                            Some(crate::offset_in(raw, value)),
                        ));
                    }
                    if slot
                        .replace(value.to_string())
                        .is_some()
                    {
                        return Err(ParseError::malformed(
                            Field::Tag,
                            FaultCode::Duplicate,
                            Some(crate::offset_in(raw, param.key)),
                        ));
                    }
                }
                None => params.push((key, Some(value.to_string()))),
            }
        } else {
            if with_early_only && key == "early-only" {
                early_only = true;
            } else {
                params.push((key, None));
            }
        }
    }

    let missing_tag = || ParseError::malformed(Field::Tag, FaultCode::Missing, None);
    let first_tag = first_tag.ok_or_else(missing_tag)?;
    let second_tag = second_tag.ok_or_else(missing_tag)?;

    Ok(DialogId {
        call_id: call_id.to_string(),
        first_tag,
        second_tag,
        early_only,
        params,
    })
}

/// Validate `callid = word [ "@" word ]` (RFC 3261 §25.1).
pub(crate) fn validate_call_id(raw: &str) -> Result<(), ParseError> {
    crate::call_id::SipCallId::parse(raw).map(|_| ())
}

/// Decode a percent-encoded URI-header value for dialog-id parsing.
pub(crate) fn decode_uri_header_value(raw: &str) -> Result<String, ParseError> {
    percent_decode_str(raw)
        .decode_utf8()
        .map(|s| s.into_owned())
        .map_err(|_| ParseError::malformed(Field::Value, FaultCode::NotUtf8, None))
}

/// Parse the URI-header framing of a dialog identifier; positions in the
/// decoded text do not point into `raw`, so they are dropped.
pub(crate) fn parse_uri_header_dialog_id(
    raw: &str,
    first_tag_name: &str,
    second_tag_name: &str,
    with_early_only: bool,
) -> Result<DialogId, ParseError> {
    let decoded = decode_uri_header_value(raw)?;
    parse_dialog_id(&decoded, first_tag_name, second_tag_name, with_early_only)
        .map_err(ParseError::without_position)
}

/// A parsed `Replaces` header value (RFC 3891 §6.1).
///
/// Identifies the dialog to be replaced: Call-ID plus the mandatory
/// `to-tag` and `from-tag`. Also used for `Join` (RFC 3911 §7.1), whose
/// grammar is identical.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SipReplaces {
    call_id: String,
    to_tag: String,
    from_tag: String,
    early_only: bool,
    params: Vec<(String, Option<String>)>,
    uri_header_framing: bool,
}

impl SipReplaces {
    /// Parse a wire-form header value: `callid;to-tag=x;from-tag=y`.
    pub fn parse(raw: &str) -> Result<Self, ParseError> {
        let id = parse_dialog_id(raw, "to-tag", "from-tag", true)?;
        Ok(Self::from_id(id, false))
    }

    fn from_id(id: DialogId, uri_header_framing: bool) -> Self {
        Self {
            call_id: id.call_id,
            to_tag: id.first_tag,
            from_tag: id.second_tag,
            early_only: id.early_only,
            params: id.params,
            uri_header_framing,
        }
    }

    /// Parse the percent-encoded framing found in a URI header
    /// (`<sip:…?Replaces=…>`), e.g. `callid%40host%3Bto-tag%3Dx%3Bfrom-tag%3Dy`.
    ///
    /// Accepts the canonicalised value returned by
    /// [`sip_uri::SipUri::header`]; [`Display`](fmt::Display) re-encodes to
    /// that same canonical form (uppercase hex).
    ///
    /// Error positions are dropped: they would point into the decoded text.
    pub fn parse_uri_header(raw: &str) -> Result<Self, ParseError> {
        let id = parse_uri_header_dialog_id(raw, "to-tag", "from-tag", true)?;
        Ok(Self::from_id(id, true))
    }

    /// The Call-ID of the dialog being replaced.
    pub fn call_id(&self) -> &str {
        &self.call_id
    }

    /// Returns this value with a different Call-ID.
    ///
    /// Framing, both tags, `early-only` and all generic parameters are
    /// preserved, so [`Display`](fmt::Display) re-emits the parsed input with
    /// only the Call-ID changed.
    ///
    /// Errors unless `call_id` is an RFC 3261 §25.1
    /// `callid = word [ "@" word ]`. [`parse`](Self::parse) is lenient about
    /// this token; a value that never came off the wire is not.
    ///
    /// ```
    /// use sip_header::SipReplaces;
    ///
    /// let r = SipReplaces::parse("abc@203.0.113.5;to-tag=t1;from-tag=f1;early-only")?
    ///     .with_call_id("abc@example.com")?;
    /// assert_eq!(r.to_string(), "abc@example.com;to-tag=t1;from-tag=f1;early-only");
    /// # Ok::<(), sip_header::ParseError>(())
    /// ```
    pub fn with_call_id(mut self, call_id: impl Into<String>) -> Result<Self, ParseError> {
        let call_id = call_id.into();
        validate_call_id(&call_id)?;
        self.call_id = call_id;
        Ok(self)
    }

    /// The host part of the Call-ID (after `@`), if present.
    pub fn host(&self) -> Option<&str> {
        self.call_id
            .split_once('@')
            .map(|(_, host)| host)
    }

    /// The mandatory `to-tag` value.
    pub fn to_tag(&self) -> &str {
        &self.to_tag
    }

    /// The mandatory `from-tag` value.
    pub fn from_tag(&self) -> &str {
        &self.from_tag
    }

    /// Whether the `early-only` flag is present (RFC 3891 §3).
    pub fn early_only(&self) -> bool {
        self.early_only
    }

    /// Returns all generic parameters (tags and `early-only` excluded).
    pub fn params(&self) -> &[(String, Option<String>)] {
        &self.params
    }

    /// Returns a specific generic parameter by key (case-insensitive).
    pub fn param(&self, key: &str) -> Option<Option<&str>> {
        let key_lower = key.to_ascii_lowercase();
        self.params
            .iter()
            .find(|(k, _)| k == &key_lower)
            .map(|(_, v)| v.as_deref())
    }

    fn wire_form(&self) -> Result<String, fmt::Error> {
        let mut s = format!(
            "{};to-tag={};from-tag={}",
            self.call_id, self.to_tag, self.from_tag
        );
        if self.early_only {
            s.push_str(";early-only");
        }
        write_params(&mut s, &self.params)?;
        Ok(s)
    }
}

pub(crate) fn write_params(s: &mut String, params: &[(String, Option<String>)]) -> fmt::Result {
    for (key, value) in params {
        crate::write_param(s, key, value.as_deref(), false)?;
    }
    Ok(())
}

impl fmt::Display for SipReplaces {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let wire = self.wire_form()?;
        if self.uri_header_framing {
            f.write_str(&sip_uri::encode_uri_header(&wire))
        } else {
            f.write_str(&wire)
        }
    }
}

impl_from_str_via_parse!(SipReplaces, ParseError);

#[cfg(test)]
mod tests {
    use super::*;

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
