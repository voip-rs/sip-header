//! SIP Accept-Language header parser (RFC 3261 §20.3).
//!
//! An empty value, or entries that are all blank, is the empty list
//! (RFC 3261 §25.1); a blank entry beside a real one is an error.

use std::fmt;

use crate::accept::{flag_invalid_token, missing_entry, read_accept_params};
use crate::diagnostic::{Field, ParseWarning};
use crate::error::{FaultCode, ParseError};
use crate::list::CommaList;
use crate::params::HeaderParams;

/// A single Accept-Language entry: `language-range *(SEMI accept-param)`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(
        from = "SipAcceptLanguageEntryParts",
        into = "SipAcceptLanguageEntryParts"
    )
)]
#[non_exhaustive]
pub struct SipAcceptLanguageEntry {
    language: String,
    params: HeaderParams,
}

header_params!(SipAcceptLanguageEntry);

impl SipAcceptLanguageEntry {
    /// An entry for the given language range, lowercased, with no parameters.
    pub fn new(language: impl Into<String>) -> Self {
        let mut language = language.into();
        language.make_ascii_lowercase();
        SipAcceptLanguageEntry {
            language,
            params: HeaderParams::default(),
        }
    }

    /// The language tag (e.g. `"en"`, `"en-US"`, `"*"`).
    pub fn language(&self) -> &str {
        &self.language
    }

    /// The `q` quality value, if present.
    pub fn q(&self) -> Option<&str> {
        self.param("q")
            .flatten()
    }
}

impl fmt::Display for SipAcceptLanguageEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{}", self.language, self.params)
    }
}

/// SIP Accept-Language header value; its grammar admits the empty list (RFC 3261 §25.1).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SipAcceptLanguage(Vec<SipAcceptLanguageEntry>);

list_type!(SipAcceptLanguage, SipAcceptLanguageEntry, sep: ", ", may_be_empty);

#[cfg(feature = "serde")]
#[derive(serde::Serialize, serde::Deserialize)]
struct SipAcceptLanguageEntryParts {
    language: String,
    #[serde(default)]
    params: HeaderParams,
}

#[cfg(feature = "serde")]
impl From<SipAcceptLanguageEntryParts> for SipAcceptLanguageEntry {
    fn from(p: SipAcceptLanguageEntryParts) -> Self {
        SipAcceptLanguageEntry {
            params: p.params,
            ..SipAcceptLanguageEntry::new(p.language)
        }
    }
}

#[cfg(feature = "serde")]
impl From<SipAcceptLanguageEntry> for SipAcceptLanguageEntryParts {
    fn from(e: SipAcceptLanguageEntry) -> Self {
        SipAcceptLanguageEntryParts {
            language: e.language,
            params: e.params,
        }
    }
}

fn parse_entry(
    entry: &str,
    warnings: &mut Vec<ParseWarning>,
) -> Result<SipAcceptLanguageEntry, ParseError> {
    let raw = entry.trim();
    if raw.is_empty() {
        return Err(missing_entry());
    }

    let (lang_part, params_part) = match raw.split_once(';') {
        Some((l, p)) => (l.trim(), Some(p)),
        None => (raw, None),
    };

    if lang_part.is_empty() {
        return Err(ParseError::malformed(
            Field::Language,
            FaultCode::Missing,
            Some(crate::offset_in(entry, raw)),
        ));
    }
    flag_invalid_token(
        entry,
        lang_part,
        is_language_range(lang_part),
        Field::Language,
        warnings,
    );

    Ok(SipAcceptLanguageEntry {
        params: read_accept_params(entry, params_part.unwrap_or(""), warnings),
        ..SipAcceptLanguageEntry::new(lang_part)
    })
}

/// RFC 3261 §20.3 `language-range = ( 1*8ALPHA *( "-" 1*8ALPHA ) ) / "*"`.
fn is_language_range(s: &str) -> bool {
    s == "*"
        || s.split('-')
            .all(|tag| {
                (1..=8).contains(&tag.len())
                    && tag
                        .bytes()
                        .all(|b| b.is_ascii_alphabetic())
            })
}

impl CommaList for SipAcceptLanguage {
    type Entry = SipAcceptLanguageEntry;
    const BLANK_ENTRIES_ARE_EMPTY: bool = true;

    fn parse_entry(
        entry: &str,
        warnings: &mut Vec<ParseWarning>,
    ) -> Result<Option<SipAcceptLanguageEntry>, ParseError> {
        parse_entry(entry, warnings).map(Some)
    }

    fn from_parsed(entries: Vec<SipAcceptLanguageEntry>) -> Result<Self, ParseError> {
        Ok(Self::new(entries))
    }

    fn blank() -> Result<Self, ParseError> {
        Ok(Self::new(Vec::new()))
    }
}

list_parse!(SipAcceptLanguage);

#[cfg(test)]
mod tests {
    use crate::{HeaderParse, ListParse};
    use sip_uri::WarningKind;

    use super::*;
    use crate::diagnostic::WarningCode;

    #[test]
    fn single_language() {
        let al = SipAcceptLanguage::parse("en").unwrap();
        assert_eq!(al.len(), 1);
        assert_eq!(al.entries()[0].language(), "en");
    }

    #[test]
    fn multiple_languages_with_q() {
        let al = SipAcceptLanguage::parse("en;q=0.9, fr;q=0.8, *;q=0.1").unwrap();
        assert_eq!(al.len(), 3);
        assert_eq!(al.entries()[0].language(), "en");
        assert_eq!(al.entries()[1].q(), Some("0.8"));
        assert_eq!(al.entries()[2].language(), "*");
    }

    #[test]
    fn language_subtag() {
        let al = SipAcceptLanguage::parse("en-US").unwrap();
        assert_eq!(al.entries()[0].language(), "en-us");
    }

    #[test]
    fn empty_input_is_empty_list() {
        assert!(SipAcceptLanguage::parse("")
            .unwrap()
            .is_empty());
        assert!(SipAcceptLanguage::parse("  ")
            .unwrap()
            .is_empty());
    }

    #[test]
    fn flag_param_roundtrip() {
        let raw = "en;foo";
        let al = SipAcceptLanguage::parse(raw).unwrap();
        assert_eq!(al.entries()[0].param("foo"), Some(None));
        assert_eq!(
            al.entries()[0]
                .params()
                .iter()
                .collect::<Vec<_>>(),
            [("foo", None)]
        );
        assert_eq!(al.to_string(), raw);
    }

    #[test]
    fn quoted_param_keeps_semicolon() {
        let raw = r#"en;x="a;b";q=0.5"#;
        let al = SipAcceptLanguage::parse(raw).unwrap();
        assert_eq!(al.entries()[0].param("X"), Some(Some("a;b")));
        assert_eq!(al.entries()[0].q(), Some("0.5"));
        assert_eq!(al.to_string(), raw);
    }

    #[test]
    fn error_display_omits_input() {
        let err = SipAcceptLanguage::parse(";secretvalue").unwrap_err();
        assert!(!err
            .to_string()
            .contains("secretvalue"));
    }

    #[test]
    fn parse_value() {
        let al = SipAcceptLanguage::parse("en").unwrap();
        assert_eq!(al.len(), 1);
    }

    #[test]
    fn display_roundtrip() {
        let raw = "en;q=0.9";
        let al = SipAcceptLanguage::parse(raw).unwrap();
        assert_eq!(al.to_string(), raw);
    }

    #[test]
    fn from_entries_matches_parse() {
        let split = SipAcceptLanguage::from_entries(["en;q=0.9", "fr-CA"]).unwrap();
        let joined = SipAcceptLanguage::parse("en;q=0.9, fr-CA").unwrap();
        assert_eq!(split, joined);
    }

    #[test]
    fn from_entries_bad_entry_is_error() {
        assert_eq!(
            SipAcceptLanguage::from_entries(["en", "   "]),
            Err(missing_entry().in_entry(1))
        );
    }

    #[test]
    fn params_without_language_is_error() {
        assert_eq!(
            SipAcceptLanguage::parse("en, ;q=1"),
            Err(ParseError::malformed(Field::Language, FaultCode::Missing, Some(1)).in_entry(1))
        );
    }

    #[test]
    fn from_entries_empty_is_empty_list() {
        assert!(SipAcceptLanguage::from_entries(std::iter::empty::<&str>())
            .unwrap()
            .is_empty());
        assert!(SipAcceptLanguage::from_entries(["", "  "])
            .unwrap()
            .is_empty());
    }

    type Seen = (
        Field,
        WarningCode,
        WarningKind,
        Option<usize>,
        Option<usize>,
    );

    fn seen(raw: &str) -> Vec<Seen> {
        SipAcceptLanguage::parse_with_warnings(raw)
            .unwrap()
            .warnings
            .iter()
            .map(|w| (w.field, w.code, w.kind, w.position, w.entry))
            .collect()
    }

    fn assert_strict_refuses(raw: &str) {
        let parsed = SipAcceptLanguage::parse_with_warnings(raw).unwrap();
        assert_eq!(parsed.value, SipAcceptLanguage::parse(raw).unwrap());
        assert_eq!(
            SipAcceptLanguage::parse_strict(raw),
            Err(ParseError::NonConformant(parsed.warnings[0]))
        );
    }

    #[test]
    fn language_range_grammar() {
        for ok in ["*", "en", "en-us", "abcdefgh", "i-abcdefgh-x"] {
            assert!(is_language_range(ok), "{ok}");
        }
        for bad in [
            "",
            "en_us",
            "en-",
            "-en",
            "en--us",
            "abcdefghi",
            "en-abcdefghi",
            "es-419",
            "e*",
        ] {
            assert!(!is_language_range(bad), "{bad}");
        }
    }

    #[test]
    fn invalid_language_range_is_warned() {
        let raw = "fr, en_US;q=0.5";
        assert_eq!(
            SipAcceptLanguage::parse(raw)
                .unwrap()
                .entries()[1]
                .language(),
            "en_us"
        );
        assert_eq!(
            seen(raw),
            vec![(
                Field::Language,
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
        let raw = "en;q=2";
        assert_eq!(
            seen(raw),
            vec![(
                Field::Qvalue,
                WarningCode::InvalidQvalue,
                WarningKind::Recovered,
                Some("en;q=".len()),
                Some(0)
            )]
        );
        assert_strict_refuses(raw);
    }

    #[test]
    fn unterminated_param_quote_is_warned() {
        let raw = r#"en;x="a;q=0.5"#;
        assert_eq!(
            SipAcceptLanguage::parse(raw)
                .unwrap()
                .entries()[0]
                .q(),
            Some("0.5")
        );
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
    fn warnings_api_on_conformant_input() {
        let raw = "en;q=0.8, fr";
        let parsed = SipAcceptLanguage::parse_with_warnings(raw).unwrap();
        assert!(!parsed.has_warnings());
        assert_eq!(SipAcceptLanguage::parse_strict(raw), Ok(parsed.value));
        let split = SipAcceptLanguage::from_entries_with_warnings(["en"]).unwrap();
        assert_eq!(
            split
                .value
                .len(),
            1
        );
    }
}
