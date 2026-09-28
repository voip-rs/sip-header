//! SIP Accept-Encoding header parser (RFC 3261 §20.2).
//!
//! An empty value, or entries that are all blank, is the empty list
//! (RFC 3261 §25.1); a blank entry beside a real one is an error.

use std::fmt;

use crate::accept::{check_accept_param, q_of, read_named_accept_entry, QValue};
use crate::check::checked_token;
use crate::diagnostic::{Field, ParseWarning};
use crate::error::ParseError;
use crate::is_token;
use crate::list::CommaList;
use crate::params::HeaderParams;

/// A single Accept-Encoding entry: `encoding *(SEMI accept-param)`.
///
/// # Equality
///
/// Two entries are equal when their wire forms are: the coding
/// lowercased, the parameters as [`HeaderParams`] compares them. [`Hash`]
/// follows the same rule.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(
        try_from = "SipAcceptEncodingEntryParts",
        into = "SipAcceptEncodingEntryParts"
    )
)]
#[non_exhaustive]
pub struct SipAcceptEncodingEntry {
    encoding: String,
    params: HeaderParams,
}

header_params!(SipAcceptEncodingEntry, check: check_accept_param);

impl SipAcceptEncodingEntry {
    /// An entry for the given content-coding, lowercased, with no parameters.
    ///
    /// Errors unless the coding is a `token`.
    pub fn new(encoding: impl Into<String>) -> Result<Self, ParseError> {
        checked_token(Field::Coding, encoding.into()).map(Self::unchecked)
    }

    fn unchecked(mut encoding: String) -> Self {
        encoding.make_ascii_lowercase();
        SipAcceptEncodingEntry {
            encoding,
            params: HeaderParams::default(),
        }
    }

    /// The content-coding (e.g. `"gzip"`, `"identity"`, `"*"`), lowercase.
    pub fn encoding(&self) -> &str {
        &self.encoding
    }

    /// The first `q`; `None` when absent or not a `qvalue`, whose text
    /// [`param`](Self::param) returns.
    pub fn q(&self) -> Option<QValue> {
        q_of(&self.params)
    }
}

impl fmt::Display for SipAcceptEncodingEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{}", self.encoding, self.params)
    }
}

/// SIP Accept-Encoding header value; its grammar admits the empty list (RFC 3261 §25.1).
///
/// # Equality
///
/// Entry by entry, in order, each as [`SipAcceptEncodingEntry`] compares. [`Hash`] follows
/// the same rule.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct SipAcceptEncoding(Vec<SipAcceptEncodingEntry>);

list_type!(SipAcceptEncoding, SipAcceptEncodingEntry, may_be_empty);

#[cfg(feature = "serde")]
#[derive(serde::Serialize, serde::Deserialize)]
struct SipAcceptEncodingEntryParts {
    encoding: String,
    #[serde(default, deserialize_with = "crate::params::deserialize_unchecked")]
    params: HeaderParams,
}

#[cfg(feature = "serde")]
impl TryFrom<SipAcceptEncodingEntryParts> for SipAcceptEncodingEntry {
    type Error = ParseError;

    fn try_from(p: SipAcceptEncodingEntryParts) -> Result<Self, Self::Error> {
        let entry = SipAcceptEncodingEntry {
            params: p.params,
            ..SipAcceptEncodingEntry::unchecked(p.encoding)
        };
        crate::list::entry_reads_back::<SipAcceptEncoding>(entry)
    }
}

#[cfg(feature = "serde")]
impl From<SipAcceptEncodingEntry> for SipAcceptEncodingEntryParts {
    fn from(e: SipAcceptEncodingEntry) -> Self {
        SipAcceptEncodingEntryParts {
            encoding: e.encoding,
            params: e.params,
        }
    }
}

fn parse_entry(
    entry: &str,
    warnings: &mut Vec<ParseWarning>,
) -> Result<SipAcceptEncodingEntry, ParseError> {
    let (encoding, params) = read_named_accept_entry(entry, Field::Coding, is_token, warnings)?;
    Ok(SipAcceptEncodingEntry {
        params,
        ..SipAcceptEncodingEntry::unchecked(encoding)
    })
}

impl CommaList for SipAcceptEncoding {
    type Entry = SipAcceptEncodingEntry;
    const BLANK_ENTRIES_ARE_EMPTY: bool = true;

    fn parse_entry(
        entry: &str,
        warnings: &mut Vec<ParseWarning>,
    ) -> Result<Option<SipAcceptEncodingEntry>, ParseError> {
        parse_entry(entry, warnings).map(Some)
    }

    fn from_parsed(entries: Vec<SipAcceptEncodingEntry>) -> Result<Self, ParseError> {
        Ok(Self::new(entries))
    }
}

list_parse!(SipAcceptEncoding);

#[cfg(test)]
mod tests {
    use crate::list::testing::{self, Seen};
    use crate::{HeaderParse, ListParse};
    use sip_uri::WarningKind;

    use super::*;
    use crate::diagnostic::WarningCode;
    use crate::error::FaultCode;

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
        assert_eq!(ae.entries()[0].param("q"), Some(Some("1.0")));
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
        assert_eq!(
            ae.entries()[0]
                .params()
                .iter()
                .collect::<Vec<_>>(),
            [("foo", None)]
        );
        assert_eq!(ae.to_string(), raw);
    }

    #[test]
    fn quoted_param_keeps_semicolon() {
        let raw = r#"gzip;x="a;b";q=0.5"#;
        let ae = SipAcceptEncoding::parse(raw).unwrap();
        assert_eq!(ae.entries()[0].param("X"), Some(Some("a;b")));
        assert_eq!(ae.entries()[0].param("q"), Some(Some("0.5")));
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
    fn parse_value() {
        let ae = SipAcceptEncoding::parse("gzip").unwrap();
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
    fn from_entries_blank_entry_is_empty_entry() {
        let parsed = SipAcceptEncoding::from_entries_with_warnings(["gzip", "   "]).unwrap();
        assert_eq!(parsed.value, SipAcceptEncoding::parse("gzip").unwrap());
        let w = parsed.warnings[0];
        assert_eq!((w.code, w.entry), (WarningCode::EmptyEntry, Some(1)));
        assert_eq!(
            SipAcceptEncoding::from_entries_strict(["gzip", "   "]),
            Err(ParseError::NonConformant(w))
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

    fn seen(raw: &str) -> Vec<Seen> {
        testing::seen::<SipAcceptEncoding>(raw)
    }

    fn assert_strict_refuses(raw: &str) {
        let parsed = SipAcceptEncoding::parse_with_warnings(raw).unwrap();
        assert_eq!(parsed.value, SipAcceptEncoding::parse(raw).unwrap());
        assert_eq!(
            SipAcceptEncoding::parse_strict(raw),
            Err(ParseError::NonConformant(parsed.warnings[0]))
        );
    }

    #[test]
    fn invalid_coding_token_is_warned() {
        let raw = "gzip, gz/ip";
        assert_eq!(
            SipAcceptEncoding::parse(raw)
                .unwrap()
                .entries()[1]
                .encoding(),
            "gz/ip"
        );
        assert_eq!(
            seen(raw),
            vec![(
                Field::Coding,
                WarningCode::InvalidToken,
                WarningKind::Recovered,
                Some(1),
                Some(1)
            )]
        );
        assert_strict_refuses(raw);
    }

    #[test]
    fn invalid_qvalue_is_warned() {
        let raw = "gzip;q=0.1234";
        assert_eq!(
            SipAcceptEncoding::parse(raw)
                .unwrap()
                .entries()[0]
                .param("q"),
            Some(Some("0.1234"))
        );
        assert_eq!(
            seen(raw),
            vec![(
                Field::Qvalue,
                WarningCode::InvalidQvalue,
                WarningKind::Recovered,
                Some("gzip;q=".len()),
                Some(0)
            )]
        );
        assert_strict_refuses(raw);
    }

    #[test]
    fn unterminated_param_quote_is_warned() {
        let raw = r#"gzip;x="a"#;
        assert_eq!(
            seen(raw),
            vec![(
                Field::Param,
                WarningCode::UnterminatedQuote,
                WarningKind::Recovered,
                raw.find('"'),
                Some(0)
            )]
        );
        assert_strict_refuses(raw);
    }

    #[test]
    fn wildcard_is_conformant() {
        assert!(seen("*;q=0, identity;q=1.0").is_empty());
    }

    #[test]
    fn warnings_api_on_conformant_input() {
        let raw = "gzip;q=0.8, identity";
        let parsed = SipAcceptEncoding::parse_with_warnings(raw).unwrap();
        assert!(!parsed.has_warnings());
        assert_eq!(SipAcceptEncoding::parse_strict(raw), Ok(parsed.value));
    }
}
