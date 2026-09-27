//! SIP Geolocation header parser (RFC 6442).
//!
//! An entry that is not a non-empty `<uri>` is dropped with
//! [`SkippedEntry`](crate::WarningCode::SkippedEntry), a blank one with
//! [`EmptyEntry`](crate::WarningCode::EmptyEntry); only an empty value is an
//! error.

use std::fmt;

use crate::diagnostic::{Field, ParseWarning, WarningCode};
use crate::error::ParseError;
use crate::list::CommaList;

/// A reference extracted from a SIP Geolocation header (RFC 6442).
///
/// Each entry is either a `cid:` reference to a MIME body part
/// (typically containing PIDF-LO XML) or a URL for location dereference.
///
/// Resolving `cid:` references against the SIP message body (multipart
/// MIME) or dereferencing HTTP URLs is the caller's responsibility.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "lowercase")
)]
#[non_exhaustive]
pub enum SipGeolocationRef {
    /// Content-ID reference to a MIME body part (e.g., `cid:uuid`).
    Cid(String),
    /// HTTP(S) or other URL for location dereference.
    Url(String),
}

impl fmt::Display for SipGeolocationRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cid(id) => write!(f, "<cid:{id}>"),
            Self::Url(url) => write!(f, "<{url}>"),
        }
    }
}

/// One `locationValue = LAQUOT locationURI RAQUOT *(SEMI geoloc-param)`
/// (RFC 6442 §4.1).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(from = "SipGeolocationEntryParts", into = "SipGeolocationEntryParts")
)]
#[non_exhaustive]
pub struct SipGeolocationEntry {
    reference: SipGeolocationRef,
    params: Vec<(String, Option<String>)>,
}

impl SipGeolocationEntry {
    /// An entry for `reference`, with no parameters.
    pub fn new(reference: SipGeolocationRef) -> Self {
        SipGeolocationEntry {
            reference,
            params: Vec::new(),
        }
    }

    /// Add a geoloc-param, lowercasing the key; the value is emitted as given.
    pub fn with_param(mut self, key: impl Into<String>, value: Option<impl Into<String>>) -> Self {
        crate::push_lowercased(&mut self.params, key.into(), value.map(Into::into));
        self
    }

    /// The location reference inside the angle brackets.
    pub fn reference(&self) -> &SipGeolocationRef {
        &self.reference
    }

    /// All geoloc-params as `(key, value)` pairs; keys lowercased, values as
    /// sent, `None` for a flag.
    pub fn params(&self) -> impl Iterator<Item = (&str, Option<&str>)> {
        crate::iter_params(&self.params)
    }

    /// Look up a geoloc-param by key (case-insensitive); `Some(None)` for a flag.
    pub fn param(&self, key: &str) -> Option<Option<&str>> {
        crate::find_param(&self.params, key)
    }
}

impl fmt::Display for SipGeolocationEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.reference)?;
        crate::write_params(f, &self.params)
    }
}

/// SIP Geolocation header value (RFC 6442): `locationValue` entries, each a
/// `cid:` body-part reference or a dereference URL.
///
/// ```
/// use sip_header::{SipGeolocation, SipGeolocationEntry, SipGeolocationRef};
///
/// let geo = SipGeolocation::new(vec![
///     SipGeolocationEntry::new(SipGeolocationRef::Cid("abc-123".into())),
///     SipGeolocationEntry::new(SipGeolocationRef::Url("https://lis.example.com/held/abc".into())),
/// ]);
/// assert_eq!(geo.len(), 2);
/// assert!(geo.cid().is_some());
/// assert!(geo.url().is_some());
/// assert_eq!(geo.to_string(), "<cid:abc-123>, <https://lis.example.com/held/abc>");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SipGeolocation(Vec<SipGeolocationEntry>);

list_type!(SipGeolocation, SipGeolocationEntry, sep: ", ", may_be_empty);

impl SipGeolocation {
    /// Every entry's reference, in order.
    pub fn refs(&self) -> impl Iterator<Item = &SipGeolocationRef> {
        self.0
            .iter()
            .map(SipGeolocationEntry::reference)
    }

    /// The first `cid:` reference, if any.
    pub fn cid(&self) -> Option<&str> {
        self.cids()
            .next()
    }

    /// The first URL reference, if any.
    pub fn url(&self) -> Option<&str> {
        self.urls()
            .next()
    }

    /// Iterate over all `cid:` references.
    pub fn cids(&self) -> impl Iterator<Item = &str> {
        self.refs()
            .filter_map(|r| match r {
                SipGeolocationRef::Cid(id) => Some(id.as_str()),
                _ => None,
            })
    }

    /// Iterate over all URL references.
    pub fn urls(&self) -> impl Iterator<Item = &str> {
        self.refs()
            .filter_map(|r| match r {
                SipGeolocationRef::Url(url) => Some(url.as_str()),
                _ => None,
            })
    }
}

#[cfg(feature = "serde")]
#[derive(serde::Serialize, serde::Deserialize)]
struct SipGeolocationEntryParts {
    reference: SipGeolocationRef,
    #[serde(default)]
    params: Vec<(String, Option<String>)>,
}

#[cfg(feature = "serde")]
impl From<SipGeolocationEntryParts> for SipGeolocationEntry {
    fn from(p: SipGeolocationEntryParts) -> Self {
        p.params
            .into_iter()
            .fold(SipGeolocationEntry::new(p.reference), |e, (k, v)| {
                e.with_param(k, v)
            })
    }
}

#[cfg(feature = "serde")]
impl From<SipGeolocationEntry> for SipGeolocationEntryParts {
    fn from(e: SipGeolocationEntry) -> Self {
        SipGeolocationEntryParts {
            reference: e.reference,
            params: e.params,
        }
    }
}

/// Read one `locationValue`, positions relative to `entry`; `None` when it
/// is not a non-empty `<uri>`.
fn read_entry(entry: &str, warnings: &mut Vec<ParseWarning>) -> Option<SipGeolocationEntry> {
    let raw = entry.trim();
    if raw.is_empty() {
        warnings.push(ParseWarning::new(
            Field::Entry,
            WarningCode::EmptyEntry,
            None,
        ));
        return None;
    }
    let Some((inner, tail)) = raw
        .strip_prefix('<')
        .and_then(|s| s.split_once('>'))
        .filter(|(inner, _)| !inner.is_empty())
    else {
        warnings.push(ParseWarning::new(
            Field::Entry,
            WarningCode::SkippedEntry,
            Some(crate::offset_in(entry, raw)),
        ));
        return None;
    };
    let junk = tail.trim_start();
    let params = if junk.is_empty() || junk.starts_with(';') {
        tail
    } else {
        warnings.push(ParseWarning::new(
            Field::Param,
            WarningCode::TrailingContent,
            Some(crate::offset_in(entry, junk)),
        ));
        &junk[junk
            .find(';')
            .unwrap_or(junk.len())..]
    };
    let reference = match inner
        .get(..4)
        .filter(|scheme| scheme.eq_ignore_ascii_case("cid:"))
    {
        Some(_) => SipGeolocationRef::Cid(inner[4..].to_string()),
        None => SipGeolocationRef::Url(inner.to_string()),
    };
    Some(
        crate::read_params_reporting(entry, params, warnings)
            .into_iter()
            .fold(SipGeolocationEntry::new(reference), |e, (k, v)| {
                e.with_param(k, v)
            }),
    )
}

impl CommaList for SipGeolocation {
    type Entry = SipGeolocationEntry;

    fn parse_entry(
        entry: &str,
        warnings: &mut Vec<ParseWarning>,
    ) -> Result<Option<SipGeolocationEntry>, ParseError> {
        Ok(read_entry(entry, warnings))
    }

    fn from_parsed(entries: Vec<SipGeolocationEntry>) -> Result<Self, ParseError> {
        Ok(Self::new(entries))
    }
}

list_parse!(SipGeolocation);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diagnostic::{Field, WarningCode};
    use crate::{HeaderParse, ListParse};
    use sip_uri::WarningKind;

    fn parse(raw: &str) -> SipGeolocation {
        SipGeolocation::parse(raw).unwrap()
    }

    #[test]
    fn parse_cid_and_url() {
        let raw = "<cid:32863354-18b4-4069-bd00-7bced5fc6c9b>, <https://lis.example.com/api/v1/held/test>";
        let geo = parse(raw);
        assert_eq!(geo.len(), 2);
        assert_eq!(geo.cid(), Some("32863354-18b4-4069-bd00-7bced5fc6c9b"));
        assert!(geo
            .url()
            .unwrap()
            .contains("lis.example.com"));
    }

    #[test]
    fn single_cid() {
        let geo = parse("<cid:abc-123>");
        assert_eq!(geo.len(), 1);
        assert_eq!(geo.cid(), Some("abc-123"));
        assert!(geo
            .url()
            .is_none());
    }

    #[test]
    fn single_url() {
        let geo = parse("<https://lis.example.com/location>");
        assert_eq!(geo.len(), 1);
        assert!(geo
            .cid()
            .is_none());
        assert_eq!(geo.url(), Some("https://lis.example.com/location"));
    }

    #[test]
    fn empty_input() {
        assert_eq!(
            SipGeolocation::parse(""),
            Err(ParseError::empty(Field::Value))
        );
        assert_eq!(
            SipGeolocation::parse(" \t"),
            Err(ParseError::empty(Field::Value))
        );
        assert!(parse("junk").is_empty());
    }

    type Seen = (
        Field,
        WarningCode,
        WarningKind,
        Option<usize>,
        Option<usize>,
    );

    /// Lenient value and warnings, after checking strict parsing refuses.
    fn lenient(raw: &str) -> (SipGeolocation, Vec<Seen>) {
        assert!(matches!(
            SipGeolocation::parse_strict(raw),
            Err(ParseError::NonConformant(_))
        ));
        let parsed = SipGeolocation::parse_with_warnings(raw).unwrap();
        assert_eq!(parse(raw), parsed.value);
        let seen = parsed
            .warnings
            .iter()
            .map(|w| (w.field, w.code, w.kind, w.position, w.entry))
            .collect();
        (parsed.value, seen)
    }

    #[test]
    fn empty_brackets_skipped() {
        let (geo, seen) = lenient("<>, <cid:test>");
        assert_eq!(geo.len(), 1);
        assert_eq!(geo.cid(), Some("test"));
        assert_eq!(
            seen,
            vec![(
                Field::Entry,
                WarningCode::SkippedEntry,
                WarningKind::Lost,
                Some(0),
                Some(0)
            )]
        );
    }

    #[test]
    fn blank_entry_dropped_with_empty_entry() {
        let (geo, seen) = lenient("<cid:a>,, <cid:b>");
        assert_eq!(geo.len(), 2);
        assert_eq!(
            seen,
            vec![(
                Field::Entry,
                WarningCode::EmptyEntry,
                WarningKind::Lost,
                None,
                Some(1)
            )]
        );
    }

    #[test]
    fn display_roundtrip() {
        let raw = "<cid:abc-123>;inserted-by=example.org, <https://lis.example.com/test>";
        let geo = parse(raw);
        assert_eq!(geo.to_string(), raw);
    }

    #[test]
    fn geoloc_params_kept() {
        let geo = parse("<cid:x@example.com> ; Inserted-By = y ; flag");
        let entry = &geo.entries()[0];
        assert_eq!(
            entry.reference(),
            &SipGeolocationRef::Cid("x@example.com".into())
        );
        assert_eq!(entry.param("inserted-by"), Some(Some("y")));
        assert_eq!(entry.param("flag"), Some(None));
        assert_eq!(
            entry
                .params()
                .collect::<Vec<_>>(),
            vec![("inserted-by", Some("y")), ("flag", None)]
        );
        assert_eq!(entry.to_string(), "<cid:x@example.com>;inserted-by=y;flag");
    }

    #[test]
    fn text_after_bracket_is_dropped_with_warning() {
        let raw = "<cid:a>junk;inserted-by=x";
        let (geo, seen) = lenient(raw);
        assert_eq!(geo.entries()[0].param("inserted-by"), Some(Some("x")));
        assert_eq!(
            seen,
            vec![(
                Field::Param,
                WarningCode::TrailingContent,
                WarningKind::Lost,
                raw.find('j'),
                Some(0)
            )]
        );
    }

    #[test]
    fn param_unterminated_quote_is_warned() {
        let raw = r#"<cid:a>;note="x;inserted-by=y"#;
        let (geo, seen) = lenient(raw);
        assert_eq!(geo.entries()[0].param("inserted-by"), Some(Some("y")));
        assert_eq!(
            seen,
            vec![(
                Field::Param,
                WarningCode::UnterminatedQuote,
                WarningKind::Recovered,
                raw.find('"'),
                Some(0)
            )]
        );
    }

    #[test]
    fn comma_inside_brackets_not_split() {
        let geo = parse("<https://example.com/a,b>");
        assert_eq!(
            geo.refs()
                .collect::<Vec<_>>(),
            vec![&SipGeolocationRef::Url("https://example.com/a,b".into())]
        );
    }

    #[test]
    fn cid_scheme_case_insensitive() {
        let geo = parse("<CID:x@example.com>");
        assert_eq!(geo.cid(), Some("x@example.com"));
    }

    #[test]
    fn unbracketed_entry_skipped() {
        let (geo, seen) = lenient("<cid:a>, cid:x@example.com, <https://example.com/loc>");
        assert_eq!(geo.len(), 2);
        assert_eq!(geo.url(), Some("https://example.com/loc"));
        assert_eq!(
            seen,
            vec![(
                Field::Entry,
                WarningCode::SkippedEntry,
                WarningKind::Lost,
                Some(1),
                Some(1)
            )]
        );
    }

    #[test]
    fn from_entries_matches_parse() {
        let split =
            SipGeolocation::from_entries(["<cid:a>;inserted-by=x", "<https://example.com/a,b>"])
                .unwrap();
        let joined = parse("<cid:a>;inserted-by=x, <https://example.com/a,b>");
        assert_eq!(split, joined);
        assert_eq!(split.len(), 2);
    }

    #[test]
    fn multiple_cids() {
        let raw = "<cid:first>, <cid:second>, <https://example.com/loc>";
        let geo = parse(raw);
        let cids: Vec<_> = geo
            .cids()
            .collect();
        assert_eq!(cids, vec!["first", "second"]);
        let urls: Vec<_> = geo
            .urls()
            .collect();
        assert_eq!(urls, vec!["https://example.com/loc"]);
    }

    #[test]
    fn warnings_api_and_from_entries() {
        let raw = "<cid:a>, <https://example.com/loc>";
        let parsed = SipGeolocation::parse_with_warnings(raw).unwrap();
        assert!(!parsed.has_warnings());
        assert_eq!(
            SipGeolocation::parse_strict(raw),
            Ok(parsed
                .value
                .clone())
        );
        let split = SipGeolocation::from_entries_with_warnings(["<cid:a>", "junk"]).unwrap();
        assert_eq!(
            split
                .value
                .len(),
            1
        );
        assert_eq!(split.warnings[0].code, WarningCode::SkippedEntry);
        assert!(SipGeolocation::from_entries(["junk"])
            .unwrap()
            .is_empty());
        assert_eq!(
            SipGeolocation::parse_with_warnings(" "),
            Err(ParseError::empty(Field::Value))
        );
    }
}
