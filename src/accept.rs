//! SIP Accept header parser (RFC 3261 §20.1).

use std::fmt;

use crate::diagnostic::{Field, ParseWarning};
use crate::error::{FaultCode, ParseError};
use crate::list::CommaList;

/// A single Accept entry: `type/subtype *(SEMI accept-param)`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SipAcceptEntry {
    media_range: String,
    slash_pos: usize,
    params: Vec<(String, Option<String>)>,
}

impl SipAcceptEntry {
    /// The media type (e.g. `"application"`).
    pub fn media_type(&self) -> &str {
        &self.media_range[..self.slash_pos]
    }

    /// The media subtype (e.g. `"sdp"`).
    pub fn subtype(&self) -> &str {
        &self.media_range[self.slash_pos + 1..]
    }

    /// The full media range as `type/subtype`.
    pub fn media_range(&self) -> &str {
        &self.media_range
    }

    /// All parameters as `(key, value)` pairs; keys lowercased, `None` for a flag.
    pub fn params(&self) -> &[(String, Option<String>)] {
        &self.params
    }

    /// Look up a parameter by key (case-insensitive); `Some(None)` for a flag.
    pub fn param(&self, key: &str) -> Option<Option<&str>> {
        crate::find_param(&self.params, key)
    }

    /// The `q` quality value, if present.
    pub fn q(&self) -> Option<&str> {
        self.param("q")
            .flatten()
    }
}

impl fmt::Display for SipAcceptEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.media_range)?;
        crate::write_params(f, &self.params)
    }
}

fn parse_accept_entry(entry: &str) -> Result<SipAcceptEntry, ParseError> {
    let raw = entry.trim();
    if raw.is_empty() {
        return Err(missing_entry());
    }

    let (media_part, params_part) = match raw.split_once(';') {
        Some((m, p)) => (m.trim(), Some(p)),
        None => (raw, None),
    };
    let bad_range = || {
        ParseError::malformed(
            Field::MediaRange,
            FaultCode::Missing,
            Some(crate::offset_in(entry, media_part)),
        )
    };

    let (type_str, subtype_str) = media_part
        .split_once('/')
        .ok_or_else(bad_range)?;

    let type_str = type_str.trim();
    let subtype_str = subtype_str.trim();

    if type_str.is_empty() || subtype_str.is_empty() {
        return Err(bad_range());
    }

    let mut media_range = type_str.to_ascii_lowercase();
    let slash_pos = media_range.len();
    media_range.push('/');
    media_range.push_str(&subtype_str.to_ascii_lowercase());

    Ok(SipAcceptEntry {
        media_range,
        slash_pos,
        params: crate::read_params(params_part.unwrap_or("")),
    })
}

/// A blank entry beside a real one, shared by the Accept-* headers.
pub(crate) fn missing_entry() -> ParseError {
    ParseError::malformed(Field::Entry, FaultCode::Missing, None)
}

/// Parsed SIP Accept header value.
///
/// An empty value, or entries that are all blank, is the empty list
/// (RFC 3261 §25.1); a blank entry beside a real one is an error.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SipAccept(Vec<SipAcceptEntry>);

impl CommaList for SipAccept {
    type Entry = SipAcceptEntry;
    const BLANK_ENTRIES_ARE_EMPTY: bool = true;

    fn parse_entry(
        entry: &str,
        _: &mut Vec<ParseWarning>,
    ) -> Result<Option<SipAcceptEntry>, ParseError> {
        parse_accept_entry(entry).map(Some)
    }

    fn from_parsed(entries: Vec<SipAcceptEntry>) -> Result<Self, ParseError> {
        Ok(Self(entries))
    }

    fn blank() -> Result<Self, ParseError> {
        Ok(Self(Vec::new()))
    }
}

list_type!(SipAccept, SipAcceptEntry, sep: ", ", entry: "accept-range");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_media_type() {
        let accept = SipAccept::parse("application/sdp").unwrap();
        assert_eq!(accept.len(), 1);
        assert_eq!(accept.entries()[0].media_type(), "application");
        assert_eq!(accept.entries()[0].subtype(), "sdp");
    }

    #[test]
    fn multiple_types() {
        let accept = SipAccept::parse("application/sdp, application/pidf+xml;q=0.5").unwrap();
        assert_eq!(accept.len(), 2);
        assert_eq!(accept.entries()[0].media_range(), "application/sdp");
        assert_eq!(accept.entries()[1].q(), Some("0.5"));
    }

    #[test]
    fn wildcard_type() {
        let accept = SipAccept::parse("*/*").unwrap();
        assert_eq!(accept.entries()[0].media_type(), "*");
        assert_eq!(accept.entries()[0].subtype(), "*");
    }

    #[test]
    fn wildcard_subtype() {
        let accept = SipAccept::parse("application/*").unwrap();
        assert_eq!(accept.entries()[0].media_type(), "application");
        assert_eq!(accept.entries()[0].subtype(), "*");
    }

    #[test]
    fn empty_input_is_empty_list() {
        assert!(SipAccept::parse("")
            .unwrap()
            .is_empty());
        assert!(SipAccept::parse("  ")
            .unwrap()
            .is_empty());
    }

    #[test]
    fn flag_param_roundtrip() {
        let raw = "application/sdp;foo;Q=0.5";
        let accept = SipAccept::parse(raw).unwrap();
        let entry = &accept.entries()[0];
        assert_eq!(entry.param("FOO"), Some(None));
        assert_eq!(entry.param("absent"), None);
        assert_eq!(
            entry.params(),
            &[
                ("foo".to_string(), None),
                ("q".to_string(), Some("0.5".to_string()))
            ]
        );
        assert_eq!(accept.to_string(), "application/sdp;foo;q=0.5");
    }

    #[test]
    fn quoted_param_keeps_semicolon() {
        let raw = r#"application/sdp;x="a;b";q=0.5"#;
        let accept = SipAccept::parse(raw).unwrap();
        assert_eq!(accept.entries()[0].param("x"), Some(Some(r#""a;b""#)));
        assert_eq!(accept.entries()[0].q(), Some("0.5"));
        assert_eq!(accept.to_string(), raw);
    }

    #[test]
    fn error_display_omits_input() {
        let err = SipAccept::parse("secretvalue").unwrap_err();
        assert!(!err
            .to_string()
            .contains("secretvalue"));
    }

    #[test]
    fn missing_slash() {
        assert_eq!(
            SipAccept::parse("application"),
            Err(ParseError::malformed(Field::MediaRange, FaultCode::Missing, Some(0)).in_entry(0))
        );
    }

    #[test]
    fn from_str() {
        let accept: SipAccept = "application/sdp"
            .parse()
            .unwrap();
        assert_eq!(accept.len(), 1);
    }

    #[test]
    fn display_roundtrip() {
        let raw = "application/sdp;q=0.8";
        let accept = SipAccept::parse(raw).unwrap();
        assert_eq!(accept.to_string(), raw);
    }

    #[test]
    fn from_entries_matches_parse() {
        let a = "application/sdp";
        let b = "application/pidf+xml;q=0.5";
        let split = SipAccept::from_entries([a, b]).unwrap();
        let joined = SipAccept::parse(&format!("{a}, {b}")).unwrap();
        assert_eq!(split, joined);
    }

    #[test]
    fn from_entries_bad_entry_is_error() {
        assert_eq!(
            SipAccept::from_entries(["application/sdp", " noslash"]),
            Err(ParseError::malformed(Field::MediaRange, FaultCode::Missing, Some(1)).in_entry(1))
        );
    }

    #[test]
    fn blank_entry_beside_real_one_is_error() {
        assert_eq!(
            SipAccept::parse("application/sdp, "),
            Err(missing_entry().in_entry(1))
        );
    }

    #[test]
    fn from_entries_empty_is_empty_list() {
        assert!(SipAccept::from_entries(std::iter::empty::<&str>())
            .unwrap()
            .is_empty());
        assert!(SipAccept::from_entries(["", "  "])
            .unwrap()
            .is_empty());
    }

    #[test]
    fn warnings_api_on_conformant_input() {
        let raw = "application/sdp, application/pidf+xml;q=0.5";
        let parsed = SipAccept::parse_with_warnings(raw).unwrap();
        assert!(!parsed.has_warnings());
        assert_eq!(SipAccept::parse_strict(raw), Ok(parsed.value));
        let blank = SipAccept::from_entries_with_warnings(["", " "]).unwrap();
        assert!(blank
            .value
            .is_empty());
        assert!(SipAccept::parse_strict("")
            .unwrap()
            .is_empty());
    }
}
