//! SIP Accept-Encoding header parser (RFC 3261 §20.2).

use std::fmt;

use crate::accept::missing_entry;
use crate::diagnostic::{Field, ParseWarning};
use crate::error::{FaultCode, ParseError};
use crate::list::CommaList;

/// A single Accept-Encoding entry: `encoding *(SEMI accept-param)`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SipAcceptEncodingEntry {
    encoding: String,
    params: Vec<(String, Option<String>)>,
}

impl SipAcceptEncodingEntry {
    /// The content-coding value (e.g. `"gzip"`, `"identity"`, `"*"`).
    pub fn encoding(&self) -> &str {
        &self.encoding
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

impl fmt::Display for SipAcceptEncodingEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.encoding)?;
        crate::write_params(f, &self.params)
    }
}

fn parse_entry(entry: &str) -> Result<SipAcceptEncodingEntry, ParseError> {
    let raw = entry.trim();
    if raw.is_empty() {
        return Err(missing_entry());
    }

    let (encoding_part, params_part) = match raw.split_once(';') {
        Some((e, p)) => (e.trim(), Some(p)),
        None => (raw, None),
    };

    if encoding_part.is_empty() {
        return Err(ParseError::malformed(
            Field::Coding,
            FaultCode::Missing,
            Some(crate::offset_in(entry, raw)),
        ));
    }

    Ok(SipAcceptEncodingEntry {
        encoding: encoding_part.to_ascii_lowercase(),
        params: crate::read_params(params_part.unwrap_or("")),
    })
}

/// Parsed SIP Accept-Encoding header value.
///
/// An empty value, or entries that are all blank, is the empty list
/// (RFC 3261 §25.1); a blank entry beside a real one is an error.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SipAcceptEncoding(Vec<SipAcceptEncodingEntry>);

impl CommaList for SipAcceptEncoding {
    type Entry = SipAcceptEncodingEntry;
    const BLANK_ENTRIES_ARE_EMPTY: bool = true;

    fn parse_entry(
        entry: &str,
        _: &mut Vec<ParseWarning>,
    ) -> Result<Option<SipAcceptEncodingEntry>, ParseError> {
        parse_entry(entry).map(Some)
    }

    fn from_parsed(entries: Vec<SipAcceptEncodingEntry>) -> Result<Self, ParseError> {
        Ok(Self(entries))
    }

    fn blank() -> Result<Self, ParseError> {
        Ok(Self(Vec::new()))
    }
}

list_type!(SipAcceptEncoding, SipAcceptEncodingEntry, sep: ", ", entry: "encoding");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_encoding() {
        let ae = SipAcceptEncoding::parse("gzip").unwrap();
        assert_eq!(ae.len(), 1);
        assert_eq!(ae.entries()[0].encoding(), "gzip");
    }

    #[test]
    fn multiple_encodings_with_q() {
        let ae = SipAcceptEncoding::parse("gzip;q=1.0, identity;q=0.5").unwrap();
        assert_eq!(ae.len(), 2);
        assert_eq!(ae.entries()[0].q(), Some("1.0"));
        assert_eq!(ae.entries()[1].encoding(), "identity");
    }

    #[test]
    fn wildcard() {
        let ae = SipAcceptEncoding::parse("*").unwrap();
        assert_eq!(ae.entries()[0].encoding(), "*");
    }

    #[test]
    fn empty_input_is_empty_list() {
        assert!(SipAcceptEncoding::parse("")
            .unwrap()
            .is_empty());
        assert!(SipAcceptEncoding::parse("  ")
            .unwrap()
            .is_empty());
    }

    #[test]
    fn flag_param_roundtrip() {
        let raw = "gzip;foo";
        let ae = SipAcceptEncoding::parse(raw).unwrap();
        assert_eq!(ae.entries()[0].param("foo"), Some(None));
        assert_eq!(ae.entries()[0].params(), &[("foo".to_string(), None)]);
        assert_eq!(ae.to_string(), raw);
    }

    #[test]
    fn quoted_param_keeps_semicolon() {
        let raw = r#"gzip;x="a;b";q=0.5"#;
        let ae = SipAcceptEncoding::parse(raw).unwrap();
        assert_eq!(ae.entries()[0].param("X"), Some(Some(r#""a;b""#)));
        assert_eq!(ae.entries()[0].q(), Some("0.5"));
        assert_eq!(ae.to_string(), raw);
    }

    #[test]
    fn error_display_omits_input() {
        let err = SipAcceptEncoding::parse(";secretvalue").unwrap_err();
        assert!(!err
            .to_string()
            .contains("secretvalue"));
    }

    #[test]
    fn from_str() {
        let ae: SipAcceptEncoding = "gzip"
            .parse()
            .unwrap();
        assert_eq!(ae.len(), 1);
    }

    #[test]
    fn display_roundtrip() {
        let raw = "gzip;q=0.8";
        let ae = SipAcceptEncoding::parse(raw).unwrap();
        assert_eq!(ae.to_string(), raw);
    }

    #[test]
    fn from_entries_matches_parse() {
        let split = SipAcceptEncoding::from_entries(["gzip;q=0.8", "identity"]).unwrap();
        let joined = SipAcceptEncoding::parse("gzip;q=0.8, identity").unwrap();
        assert_eq!(split, joined);
    }

    #[test]
    fn from_entries_bad_entry_is_error() {
        assert_eq!(
            SipAcceptEncoding::from_entries(["gzip", "   "]),
            Err(missing_entry().in_entry(1))
        );
    }

    #[test]
    fn params_without_coding_is_error() {
        assert_eq!(
            SipAcceptEncoding::parse(" ;q=1"),
            Err(ParseError::malformed(Field::Coding, FaultCode::Missing, Some(1)).in_entry(0))
        );
    }

    #[test]
    fn from_entries_empty_is_empty_list() {
        assert!(SipAcceptEncoding::from_entries(std::iter::empty::<&str>())
            .unwrap()
            .is_empty());
        assert!(SipAcceptEncoding::from_entries(["", "  "])
            .unwrap()
            .is_empty());
    }

    #[test]
    fn warnings_api_on_conformant_input() {
        let raw = "gzip;q=0.8, identity";
        let parsed = SipAcceptEncoding::parse_with_warnings(raw).unwrap();
        assert!(!parsed.has_warnings());
        assert_eq!(SipAcceptEncoding::parse_strict(raw), Ok(parsed.value));
        assert_eq!(
            SipAcceptEncoding::from_entries_with_warnings(["gzip", "   "]),
            Err(missing_entry().in_entry(1))
        );
    }
}
