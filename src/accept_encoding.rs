//! SIP Accept-Encoding header parser (RFC 3261 §20.2).

use std::fmt;

use crate::accept::{all_blank, missing_entry, parse_entries};
use crate::diagnostic::Field;
use crate::error::{FaultCode, ParseError};

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
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SipAcceptEncoding(Vec<SipAcceptEncodingEntry>);

impl SipAcceptEncoding {
    /// Parse a comma-separated Accept-Encoding header value.
    ///
    /// An empty or whitespace-only value is the empty list (RFC 3261 §25.1).
    pub fn parse(raw: &str) -> Result<Self, ParseError> {
        Self::from_entries(crate::split_comma_entries(raw))
    }

    /// Build from entries a transport already split; each is one `encoding`.
    ///
    /// No entries, or only blank ones, is the empty list; a blank entry beside
    /// a real one is an error. Error positions are relative to the entry.
    pub fn from_entries<'a>(
        entries: impl IntoIterator<Item = &'a str>,
    ) -> Result<Self, ParseError> {
        let entries: Vec<&str> = entries
            .into_iter()
            .collect();
        if all_blank(&entries) {
            return Ok(Self(Vec::new()));
        }
        parse_entries(entries, parse_entry).map(Self)
    }

    /// The parsed entries as a slice.
    pub fn entries(&self) -> &[SipAcceptEncodingEntry] {
        &self.0
    }

    /// Consume self and return entries as a `Vec`.
    pub fn into_entries(self) -> Vec<SipAcceptEncodingEntry> {
        self.0
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.0
            .len()
    }

    /// Returns `true` if there are no entries.
    pub fn is_empty(&self) -> bool {
        self.0
            .is_empty()
    }
}

impl fmt::Display for SipAcceptEncoding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        crate::fmt_joined(f, &self.0, ", ")
    }
}

impl_from_str_via_parse!(SipAcceptEncoding, ParseError);

impl<'a> IntoIterator for &'a SipAcceptEncoding {
    type Item = &'a SipAcceptEncodingEntry;
    type IntoIter = std::slice::Iter<'a, SipAcceptEncodingEntry>;

    fn into_iter(self) -> Self::IntoIter {
        self.0
            .iter()
    }
}

impl IntoIterator for SipAcceptEncoding {
    type Item = SipAcceptEncodingEntry;
    type IntoIter = std::vec::IntoIter<SipAcceptEncodingEntry>;

    fn into_iter(self) -> Self::IntoIter {
        self.0
            .into_iter()
    }
}

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
}
