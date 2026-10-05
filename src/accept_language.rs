//! SIP Accept-Language header parser (RFC 3261 §20.3).
//!
//! An empty value, or entries that are all blank, is the empty list
//! (RFC 3261 §25.1); a blank entry beside a real one is dropped with
//! [`EmptyEntry`](crate::WarningCode::EmptyEntry).

use std::fmt;

use crate::accept::{check_accept_param, q_of, read_named_accept_entry, QValue};
use crate::diagnostic::{Field, ParseWarning};
use crate::error::{FaultCode, ParseError};
use crate::list::CommaList;
use crate::params::HeaderParams;

/// A single Accept-Language entry: `language-range *(SEMI accept-param)`.
///
/// Parsed as an entry of [`SipAcceptLanguage`].
///
/// # Equality
///
/// Two entries are equal when their wire forms are: the language range
/// lowercased, the parameters as [`HeaderParams`] compares them. [`Hash`]
/// follows the same rule.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct SipAcceptLanguageEntry {
    language: String,
    params: HeaderParams,
}

header_params!(SipAcceptLanguageEntry, check: check_accept_param);
params_located!(SipAcceptLanguageEntry);

impl SipAcceptLanguageEntry {
    /// An entry for the given language range, lowercased, with no parameters.
    ///
    /// Errors unless it is an RFC 3261 §20.3 `language-range`.
    pub fn new(language: impl AsRef<str>) -> Result<Self, ParseError> {
        let language = language.as_ref();
        if language.is_empty() {
            return Err(ParseError::empty(Field::Language));
        }
        if !is_language_range(language) {
            return Err(ParseError::malformed(
                Field::Language,
                FaultCode::InvalidChar,
                None,
            ));
        }
        Ok(Self::unchecked(language.to_owned()))
    }

    fn unchecked(mut language: String) -> Self {
        language.make_ascii_lowercase();
        SipAcceptLanguageEntry {
            language,
            params: HeaderParams::default(),
        }
    }

    /// The language range (e.g. `"en"`, `"en-us"`, `"*"`), lowercase.
    pub fn language(&self) -> &str {
        &self.language
    }

    /// The first `q`; `None` when absent or not a `qvalue`, whose text
    /// [`param`](Self::param) returns.
    pub fn q(&self) -> Option<QValue> {
        q_of(&self.params)
    }
}

impl fmt::Display for SipAcceptLanguageEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{}", self.language, self.params)
    }
}

/// SIP Accept-Language header value; its grammar admits the empty list (RFC 3261 §25.1).
///
/// Parsed through [`HeaderParse`](crate::HeaderParse) and
/// [`ListParse`](crate::ListParse).
///
/// # Equality
///
/// Entry by entry, in order, each as [`SipAcceptLanguageEntry`] compares. [`Hash`] follows
/// the same rule.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct SipAcceptLanguage(Vec<SipAcceptLanguageEntry>);

list_type!(SipAcceptLanguage, SipAcceptLanguageEntry, may_be_empty);

#[cfg(feature = "serde")]
serde_parts!(SipAcceptLanguageEntry, SipAcceptLanguageEntryParts);

#[cfg(feature = "serde")]
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SipAcceptLanguageEntryParts {
    #[serde(deserialize_with = "crate::serde_parts::field::language")]
    language: String,
    #[serde(default, deserialize_with = "crate::params::deserialize_unchecked")]
    params: HeaderParams,
}

#[cfg(feature = "serde")]
impl SipAcceptLanguageEntryParts {
    fn into_value(p: Self) -> Result<SipAcceptLanguageEntry, ParseError> {
        let entry = SipAcceptLanguageEntry {
            params: p.params,
            ..SipAcceptLanguageEntry::unchecked(p.language)
        };
        crate::list::entry_reads_back::<SipAcceptLanguage>(entry)
    }

    fn from_value(e: SipAcceptLanguageEntry) -> Self {
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
    let (lang, params) =
        read_named_accept_entry(entry, Field::Language, is_language_range, warnings)?;
    Ok(SipAcceptLanguageEntry {
        params,
        ..SipAcceptLanguageEntry::unchecked(lang)
    })
}

/// `1*8ALPHA`: longest subtag of a `language-range`.
const LANGUAGE_SUBTAG_MAX_LEN: usize = 8;

/// RFC 3261 §20.3 `language-range = ( 1*8ALPHA *( "-" 1*8ALPHA ) ) / "*"`.
fn is_language_range(s: &str) -> bool {
    s == "*"
        || s.split('-')
            .all(|tag| {
                (1..=LANGUAGE_SUBTAG_MAX_LEN).contains(&tag.len())
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
    ) -> Result<SipAcceptLanguageEntry, ParseError> {
        parse_entry(entry, warnings)
    }

    fn from_parsed(entries: Vec<SipAcceptLanguageEntry>) -> Result<Self, ParseError> {
        Ok(Self::new(entries))
    }
}

list_parse!(SipAcceptLanguage);

#[cfg(test)]
mod tests {
    use crate::list::testing::{self, Seen};
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
        assert_eq!(al.entries()[1].param("q"), Some(Some("0.8")));
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
        assert_eq!(al.entries()[0].param("q"), Some(Some("0.5")));
        assert_eq!(al.to_string(), raw);
    }

    #[test]
    fn error_display_omits_input() {
        let err = SipAcceptLanguage::parse_strict(";secretvalue").unwrap_err();
        assert!(!err
            .to_string()
            .contains("secretvalue"));
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
    fn from_entries_blank_entry_is_empty_entry() {
        let parsed = SipAcceptLanguage::from_entries_with_warnings(["en", "   "]).unwrap();
        assert_eq!(parsed.value, SipAcceptLanguage::parse("en").unwrap());
        let w = parsed.warnings[0];
        assert_eq!((w.code, w.entry), (WarningCode::EmptyEntry, Some(1)));
        assert_eq!(
            SipAcceptLanguage::from_entries_strict(["en", "   "]),
            Err(ParseError::NonConformant(w))
        );
    }

    #[test]
    fn params_without_language_skip_the_entry() {
        let (al, seen) = testing::lenient::<SipAcceptLanguage>("en, ;q=1");
        assert_eq!(al, SipAcceptLanguage::parse("en").unwrap());
        assert_eq!(
            seen,
            [(
                Field::Language,
                WarningCode::SkippedEntry,
                WarningKind::Lost,
                Some(4),
                Some(1)
            )]
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

    fn seen(raw: &str) -> Vec<Seen> {
        testing::seen::<SipAcceptLanguage>(raw)
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
                raw.find("en_"),
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
                .param("q"),
            Some(Some("0.5"))
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
