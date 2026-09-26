//! SIP header field parsers for standard RFC types.
//!
//! This crate provides parsers for SIP header values as defined in RFC 3261
//! and extensions. It sits between URI parsing ([`sip_uri`]) and full SIP
//! stacks, handling the header-level grammar: display names, header parameters,
//! and structured header values.
//!
//! # Modules
//!
//! - [`header_addr`] — RFC 3261 `name-addr` with header-level parameters
//! - [`header`] — SIP header name catalog and [`SipHeaderLookup`] trait
//! - [`call_id`] — RFC 3261 Call-ID value
//! - [`message`] — Extract headers, Request-URI and body from raw SIP message text (feature: `message`)
//! - [`via`] — RFC 3261 Via header parser
//! - [`warning`] — RFC 3261 Warning header parser
//! - [`auth`] — SIP authentication value parser (Authorization, WWW-Authenticate, etc.)
//! - [`contact`] — RFC 3261 Contact header parser
//! - [`diagnostic`] — [`Parsed`] results and [`ParseWarning`]s for accepted grammar breaches
//! - [`error`] — [`ParseError`], returned by every header-value parser
//! - [`accept`] — RFC 3261 Accept header parser
//! - [`accept_encoding`] — RFC 3261 Accept-Encoding header parser
//! - [`accept_language`] — RFC 3261 Accept-Language header parser
//! - [`security`] — RFC 3329 Security mechanism parser
//! - [`uri_info`] — `<absoluteURI> *(SEMI generic-param)` parser (Call-Info, Alert-Info, Error-Info)
//! - [`history_info`] — RFC 7044 History-Info header parser
//! - [`geolocation`] — RFC 6442 Geolocation header parser
//! - [`replaces`] — RFC 3891 Replaces / RFC 3911 Join header parser
//! - [`target_dialog`] — RFC 4538 Target-Dialog header parser
//! - `conference_info` — RFC 4575 conference event package (feature: `conference-info`)

#[macro_use]
mod macros;
#[macro_use]
mod list;
#[macro_use]
mod dialog_id;

#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;

pub use sip_uri;

pub mod accept;
pub mod accept_encoding;
pub mod accept_language;
pub mod auth;
pub mod call_id;
#[cfg(feature = "conference-info")]
pub mod conference_info;
pub mod contact;
pub mod diagnostic;
pub mod error;
pub mod geolocation;
pub mod header;
pub mod header_addr;
pub mod history_info;
#[cfg(feature = "message")]
pub mod message;
pub mod replaces;
pub mod security;
pub mod target_dialog;
mod traits;
pub mod uri_info;
pub mod via;
pub mod warning;

pub use accept::{SipAccept, SipAcceptEntry};
pub use accept_encoding::{SipAcceptEncoding, SipAcceptEncodingEntry};
pub use accept_language::{SipAcceptLanguage, SipAcceptLanguageEntry};
pub use auth::SipAuthValue;
pub use call_id::SipCallId;
pub use contact::{ContactList, ContactValue};
pub use diagnostic::{Field, ParseWarning, Parsed, WarningCode};
pub use dialog_id::{DialogFraming, DialogKind};
pub use error::{Fault, FaultCode, ParseError};
pub use geolocation::{SipGeolocation, SipGeolocationEntry, SipGeolocationRef};
pub use header::{ParseSipHeaderError, SipHeader, SipHeaderLookup};
pub use header_addr::{SipHeaderAddr, SipHeaderAddrParts};
pub use history_info::{HistoryInfo, HistoryInfoEntry, HistoryInfoReason};
#[cfg(feature = "message")]
pub use message::{extract_all_headers, extract_body, extract_header, extract_request_uri};
pub use replaces::SipReplaces;
pub use security::{SipSecurity, SipSecurityMechanism};
pub use target_dialog::SipTargetDialog;
pub use traits::{AddrBuild, AddrParts, DialogIdEdit, HeaderParse, ListParse, Redact};
pub use uri_info::{UriInfo, UriInfoEntry};
pub use via::{SipVia, SipViaEntry};
pub use warning::{SipWarning, SipWarningEntry};

/// Format a slice of displayable items as a separated list.
pub(crate) fn fmt_joined<T: std::fmt::Display>(
    f: &mut std::fmt::Formatter<'_>,
    items: &[T],
    separator: &str,
) -> std::fmt::Result {
    for (i, item) in items
        .iter()
        .enumerate()
    {
        if i > 0 {
            f.write_str(separator)?;
        }
        write!(f, "{item}")?;
    }
    Ok(())
}

/// Parameter keys lowercased, values untouched.
pub(crate) fn lowercase_keys<V>(params: Vec<(String, V)>) -> Vec<(String, V)> {
    params
        .into_iter()
        .map(|(mut k, v)| {
            k.make_ascii_lowercase();
            (k, v)
        })
        .collect()
}

/// Append a parameter, its key lowercased.
pub(crate) fn push_lowercased<V>(params: &mut Vec<(String, V)>, mut key: String, value: V) {
    key.make_ascii_lowercase();
    params.push((key, value));
}

/// Parameters already read, in stored form.
pub(crate) fn stored_params(params: Vec<RawParam<'_>>) -> Vec<(String, Option<String>)> {
    params
        .into_iter()
        .map(|p| {
            (
                p.key
                    .to_ascii_lowercase(),
                p.value
                    .map(str::to_string),
            )
        })
        .collect()
}

/// Write stored parameters as `;key` or `;key=value`, values as stored.
pub(crate) fn write_params<W: std::fmt::Write + ?Sized>(
    w: &mut W,
    params: &[(String, Option<String>)],
) -> std::fmt::Result {
    for (key, value) in params {
        write_param(w, key, value.as_deref(), false)?;
    }
    Ok(())
}

/// Look up a stored parameter by key, case-insensitively: `Some(None)` for a flag.
pub(crate) fn find_param<'a>(
    params: &'a [(String, Option<String>)],
    key: &str,
) -> Option<Option<&'a str>> {
    params
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(key))
        .map(|(_, v)| v.as_deref())
}

/// Stored parameters as borrowed `(key, value)` pairs.
pub(crate) fn iter_params(
    params: &[(String, Option<String>)],
) -> impl Iterator<Item = (&str, Option<&str>)> {
    params
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_deref()))
}

/// Byte offset of `inner`, a subslice of `outer`, within `outer`.
pub(crate) fn offset_in(outer: &str, inner: &str) -> usize {
    (inner.as_ptr() as usize).saturating_sub(outer.as_ptr() as usize)
}

/// Unescape RFC 3261 §25.1 `quoted-pair` sequences: `\"` → `"`, `\\` → `\`.
///
/// Operates on the content *between* surrounding double-quotes (caller strips
/// them). Skips allocation when no backslash escapes are present.
pub(crate) fn unescape_quoted_pair(s: &str) -> String {
    unescape_quoted_pair_checked(s).0
}

/// [`unescape_quoted_pair`], plus whether a lone trailing `\`, which escapes
/// nothing, was dropped.
pub(crate) fn unescape_quoted_pair_checked(s: &str) -> (String, bool) {
    if !s.contains('\\') {
        return (s.to_string(), false);
    }
    let mut result = String::with_capacity(s.len());
    let mut escaped = false;
    for ch in s.chars() {
        if escaped {
            result.push(ch);
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else {
            result.push(ch);
        }
    }
    (result, escaped)
}

/// RFC 3261 §25.1 `token` character.
pub(crate) fn is_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(
            c,
            '-' | '.' | '!' | '%' | '*' | '_' | '+' | '`' | '\'' | '~'
        )
}

/// RFC 3261 §25.1 `token`.
pub(crate) fn is_token(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(is_token_char)
}

/// Whether `value` opens a quoted-string that never closes.
pub(crate) fn opens_unterminated_quote(value: &str) -> bool {
    value
        .strip_prefix('"')
        .is_some_and(|rest| closing_quote(rest).is_none())
}

/// Whether unescaping `inner` would drop a lone trailing `\`.
fn ends_in_lone_backslash(inner: &str) -> bool {
    inner
        .bytes()
        .rev()
        .take_while(|&b| b == b'\\')
        .count()
        % 2
        == 1
}

/// A control character `qdtext` excludes but `quoted-pair` carries
/// (RFC 3261 §25.1); CR and LF fit neither.
pub(crate) fn is_quoted_pair_only(c: char) -> bool {
    c.is_ascii_control() && !matches!(c, '\t' | '\r' | '\n')
}

/// Write a `quoted-string`: surrounds with `"` and emits `"`, `\` and
/// [`is_quoted_pair_only`] characters as `quoted-pair` (RFC 3261 §25.1).
pub(crate) fn write_quoted_pair<W: std::fmt::Write + ?Sized>(
    f: &mut W,
    value: &str,
) -> std::fmt::Result {
    f.write_char('"')?;
    for ch in value.chars() {
        if ch == '"' || ch == '\\' || is_quoted_pair_only(ch) {
            f.write_char('\\')?;
        }
        f.write_char(ch)?;
    }
    f.write_char('"')
}

/// Byte index of the first `"` not escaped by `quoted-pair`, scanning text
/// that follows an opening quote.
fn closing_quote(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2,
            b'"' => return Some(i),
            _ => i += 1,
        }
    }
    None
}

/// One `generic-param` (RFC 3261 §25.1) as it appeared on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RawParam<'a> {
    /// Name, SWS-trimmed, case preserved.
    pub(crate) key: &'a str,
    /// Value, SWS-trimmed, quotes and escapes intact; `None` for a flag.
    pub(crate) value: Option<&'a str>,
    /// Whether the value opens a quote that never closes.
    pub(crate) unterminated: bool,
}

/// A parameter value without its surrounding quotes, `quoted-pair` unescaped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Unquoted {
    pub(crate) value: String,
    /// Whether the value arrived as a quoted-string.
    pub(crate) quoted: bool,
    /// Whether a lone `\` before the closing quote was dropped.
    pub(crate) trailing_backslash: bool,
}

impl RawParam<'_> {
    /// The value without its surrounding quotes and with `quoted-pair` unescaped.
    pub(crate) fn unquoted(&self) -> Option<Unquoted> {
        let v = self.value?;
        Some(if v.len() >= 2 && v.starts_with('"') && v.ends_with('"') {
            let (value, trailing_backslash) = unescape_quoted_pair_checked(&v[1..v.len() - 1]);
            Unquoted {
                value,
                quoted: true,
                trailing_backslash,
            }
        } else {
            Unquoted {
                value: v.to_string(),
                quoted: false,
                trailing_backslash: false,
            }
        })
    }

    /// [`unquoted`](Self::unquoted), raising [`WarningCode::UnterminatedQuote`]
    /// and [`WarningCode::TrailingBackslash`] at their position in `input`, the
    /// string the parameter was read from.
    pub(crate) fn unquoted_reporting(
        &self,
        input: &str,
        warnings: &mut Vec<ParseWarning>,
    ) -> Option<Unquoted> {
        self.report_quoting(input, warnings);
        self.unquoted()
    }

    /// Raise the quote breaches [`unquoted_reporting`](Self::unquoted_reporting)
    /// would, for a type that stores the value as sent.
    pub(crate) fn report_quoting(&self, input: &str, warnings: &mut Vec<ParseWarning>) {
        let Some(v) = self.value else {
            return;
        };
        let at = offset_in(input, v);
        if self.unterminated {
            warnings.push(ParseWarning::new(
                Field::Param,
                WarningCode::UnterminatedQuote,
                Some(at),
            ));
        }
        let closed = v.len() >= 2 && v.starts_with('"') && v.ends_with('"');
        if closed && ends_in_lone_backslash(&v[1..v.len() - 1]) {
            warnings.push(ParseWarning::new(
                Field::Param,
                WarningCode::TrailingBackslash,
                Some(at + v.len() - 2),
            ));
        }
    }
}

/// Read `*(SEMI generic-param)` from `params`, a slice of `input`, values as
/// sent, reporting quote breaches at their position in `input`.
pub(crate) fn read_params_reporting(
    input: &str,
    params: &str,
    warnings: &mut Vec<ParseWarning>,
) -> Vec<(String, Option<String>)> {
    let raw = parse_params(params);
    report_params_quoting(input, &raw, warnings);
    stored_params(raw)
}

/// Raise the quote breaches in `params`, read from `input`.
pub(crate) fn report_params_quoting(
    input: &str,
    params: &[RawParam<'_>],
    warnings: &mut Vec<ParseWarning>,
) {
    for p in params {
        p.report_quoting(input, warnings);
    }
}

/// Read `*(SEMI generic-param)`, with or without the leading `;`.
///
/// A value opening with `"` runs to its closing quote, so a `;` inside it does
/// not split; a quote that never closes ends at the next `;` like any value.
pub(crate) fn parse_params(s: &str) -> Vec<RawParam<'_>> {
    let mut params = Vec::new();
    let mut rest = s;
    loop {
        rest = rest.trim_start_matches(|c: char| c == ';' || c.is_ascii_whitespace());
        if rest.is_empty() {
            return params;
        }
        let segment_end = rest
            .find(';')
            .unwrap_or(rest.len());
        let Some(eq) = rest[..segment_end].find('=') else {
            params.push(RawParam {
                key: rest[..segment_end].trim_end(),
                value: None,
                unterminated: false,
            });
            rest = &rest[segment_end..];
            continue;
        };
        let key = rest[..eq].trim_end();
        let value = rest[eq + 1..].trim_start();
        let close = value
            .strip_prefix('"')
            .map(closing_quote);
        let value_end = match close.flatten() {
            Some(close) => {
                let after = close + 2;
                after
                    + value[after..]
                        .find(';')
                        .unwrap_or(value.len() - after)
            }
            None => value
                .find(';')
                .unwrap_or(value.len()),
        };
        params.push(RawParam {
            key,
            value: Some(value[..value_end].trim_end()),
            unterminated: close == Some(None),
        });
        rest = &value[value_end..];
    }
}

/// Write `;key`, `;key=value`, or `;key="value"` when `quote` is set.
pub(crate) fn write_param<W: std::fmt::Write + ?Sized>(
    w: &mut W,
    key: &str,
    value: Option<&str>,
    quote: bool,
) -> std::fmt::Result {
    w.write_char(';')?;
    w.write_str(key)?;
    match value {
        None => Ok(()),
        Some(v) => {
            w.write_char('=')?;
            if quote {
                write_quoted_pair(w, v)
            } else {
                w.write_str(v)
            }
        }
    }
}

/// Split comma-separated header entries respecting angle-bracket nesting
/// and double-quoted strings.
///
/// SIP headers that carry lists (RFC 3261 §7.3.1) use commas as delimiters,
/// but commas may also appear inside angle-bracketed URIs or quoted strings
/// (e.g. Warning warn-text per §20.43). This function splits only on commas
/// at bracket depth zero and outside quoted strings.
///
/// Backslash escapes inside quoted strings (RFC 3261 §25.1 `quoted-pair`)
/// are respected to avoid premature quote-close on `\"`. Quotes are only
/// significant at bracket depth zero: a stray `"` inside `<...>` (not legal
/// in any §25.1 URI character set) affects that entry alone.
pub fn split_comma_entries(raw: &str) -> Vec<&str> {
    let bytes = raw.as_bytes();
    let mut entries = Vec::new();
    let mut depth = 0u32;
    let mut start = 0;
    let mut i = 0;

    while i < bytes.len() {
        match bytes[i] {
            b'"' if depth == 0 => match closing_quote(&raw[i + 1..]) {
                Some(close) => i += close + 1,
                None => break,
            },
            b'<' => depth += 1,
            b'>' => depth = depth.saturating_sub(1),
            b',' if depth == 0 => {
                entries.push(&raw[start..i]);
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    if start < raw.len() {
        entries.push(&raw[start..]);
    }

    entries
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_comma_simple() {
        assert_eq!(split_comma_entries("a, b, c"), vec!["a", " b", " c"]);
    }

    #[test]
    fn split_comma_respects_angle_brackets() {
        let input = "<sip:a@host,x>, <sip:b@host>";
        let parts = split_comma_entries(input);
        assert_eq!(parts.len(), 2);
        assert!(parts[0].contains("host,x"));
    }

    #[test]
    fn split_comma_respects_quoted_strings() {
        let input = r#"301 example.com "text, comma", 399 example.org "ok""#;
        let parts = split_comma_entries(input);
        assert_eq!(parts.len(), 2);
        assert!(parts[0].contains("text, comma"));
    }

    #[test]
    fn split_comma_respects_escaped_quote() {
        let input = r#"301 example.com "say \"hi, there\"", 399 example.org "ok""#;
        let parts = split_comma_entries(input);
        assert_eq!(parts.len(), 2);
    }

    #[test]
    fn split_comma_quote_inside_brackets_confined_to_one_entry() {
        let input = r#"<https://example.com/a"b>;purpose=icon, <urn:example:call:1>;purpose=info, <https://example.com/c>;purpose=card"#;
        let parts = split_comma_entries(input);
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[2], " <https://example.com/c>;purpose=card");
    }

    #[test]
    fn split_comma_quote_inside_brackets_keeps_later_quoted_param() {
        let input = r#"<https://example.com/a"b>;purpose=icon, <sip:b@example.com>;note="x,y", <sip:c@example.com>"#;
        let parts = split_comma_entries(input);
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[1], r#" <sip:b@example.com>;note="x,y""#);
    }

    fn params(s: &str) -> Vec<(&str, Option<&str>)> {
        parse_params(s)
            .into_iter()
            .map(|p| (p.key, p.value))
            .collect()
    }

    #[test]
    fn params_quoted_value_keeps_semicolon() {
        assert_eq!(
            params(r#";foo="a;b";tag=x"#),
            vec![("foo", Some(r#""a;b""#)), ("tag", Some("x"))]
        );
    }

    #[test]
    fn params_trim_sws_around_semi_and_equal() {
        assert_eq!(
            params(" ; tag = x ; lr "),
            vec![("tag", Some("x")), ("lr", None)]
        );
    }

    #[test]
    fn params_without_leading_semicolon_and_empty_segments() {
        assert_eq!(params("tag=x;;lr;"), vec![("tag", Some("x")), ("lr", None)]);
    }

    #[test]
    fn params_unterminated_quote_splits_at_next_semicolon() {
        assert_eq!(
            params(r#";x="a;to-tag=1;from-tag=2"#),
            vec![
                ("x", Some(r#""a"#)),
                ("to-tag", Some("1")),
                ("from-tag", Some("2"))
            ]
        );
    }

    fn unquoted(value: &str, quoted: bool, trailing_backslash: bool) -> Option<Unquoted> {
        Some(Unquoted {
            value: value.to_string(),
            quoted,
            trailing_backslash,
        })
    }

    #[test]
    fn params_escaped_quote_inside_value() {
        let p = parse_params(r#";t="say \"hi;\"";x=1"#);
        assert_eq!(p.len(), 2);
        assert_eq!(p[0].value, Some(r#""say \"hi;\"""#));
        assert_eq!(p[0].unquoted(), unquoted(r#"say "hi;""#, true, false));
        assert_eq!(p[1].value, Some("1"));
        assert!(!p[0].unterminated);
    }

    #[test]
    fn params_empty_quoted_value() {
        let p = parse_params(r#";a="""#);
        assert_eq!(p[0].unquoted(), unquoted("", true, false));
    }

    #[test]
    fn params_unquoted_token_value() {
        let p = parse_params(";a=b");
        assert_eq!(p[0].unquoted(), unquoted("b", false, false));
        assert_eq!(parse_params(";lr")[0].unquoted(), None);
    }

    #[test]
    fn params_record_unterminated_quote() {
        let p = parse_params(r#";x="a;to-tag=1;y=b"#);
        assert_eq!(
            p.iter()
                .map(|p| p.unterminated)
                .collect::<Vec<_>>(),
            vec![true, false, false]
        );
        assert!(!parse_params(";lr")[0].unterminated);
    }

    #[test]
    fn params_escaped_closing_quote_leaves_trailing_backslash() {
        let p = parse_params(r#";x="a\";y=1"#);
        assert_eq!(p[0].value, Some(r#""a\""#));
        assert!(p[0].unterminated);
        assert_eq!(p[0].unquoted(), unquoted("a", true, true));
        assert_eq!(p[1].value, Some("1"));
    }

    #[test]
    fn unescape_reports_lone_trailing_backslash() {
        assert_eq!(
            unescape_quoted_pair_checked(r"ab\"),
            ("ab".to_string(), true)
        );
        assert_eq!(
            unescape_quoted_pair_checked(r"a\\"),
            (r"a\".to_string(), false)
        );
        assert_eq!(
            unescape_quoted_pair_checked(r#"a\"b"#),
            (r#"a"b"#.to_string(), false)
        );
        assert_eq!(unescape_quoted_pair(r"ab\"), "ab");
    }

    #[test]
    fn write_quoted_pair_escapes_controls_outside_qdtext() {
        let mut s = String::new();
        write_quoted_pair(&mut s, "a\u{1}b\tc\u{7f}").unwrap();
        assert_eq!(s, "\"a\\\u{1}b\tc\\\u{7f}\"");
    }

    #[test]
    fn write_param_forms() {
        let mut s = String::new();
        write_param(&mut s, "lr", None, false).unwrap();
        write_param(&mut s, "tag", Some("x"), false).unwrap();
        write_param(&mut s, "d-ver", Some(r#"a"b"#), true).unwrap();
        assert_eq!(s, r#";lr;tag=x;d-ver="a\"b""#);
    }

    #[test]
    fn split_comma_bracket_inside_quoted_display_name_inert() {
        let input = r#""a<b" <sip:x@example.com>, <sip:y@example.com>"#;
        let parts = split_comma_entries(input);
        assert_eq!(parts.len(), 2);
    }
}
