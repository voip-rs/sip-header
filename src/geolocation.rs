//! SIP Geolocation header parser (RFC 6442).
//!
//! An entry that is not a non-empty `<uri>` is dropped with
//! [`SkippedEntry`](crate::WarningCode::SkippedEntry), a blank one with
//! [`EmptyEntry`](crate::WarningCode::EmptyEntry), and `Err(Empty)` means
//! no entry yielded a URI (RFC 6442 §4.1 `locationValue *(COMMA
//! locationValue)`).

use std::fmt::{self, Write as _};

use sip_uri::{Uri, UriRedact};

use crate::diagnostic::{Field, ParseWarning, WarningCode};
use crate::error::ParseError;
use crate::list::CommaList;
use crate::params::HeaderParams;
use crate::redact::{HeaderRedaction, Redact};
use crate::uri_info::read_uri;

/// One `locationValue = LAQUOT locationURI RAQUOT *(SEMI geoloc-param)`
/// (RFC 6442 §4.1): a `cid:` reference to a MIME body part (typically
/// PIDF-LO) or a URI to dereference.
///
/// Resolving `cid:` references against the message body or dereferencing
/// the URI is the caller's responsibility.
///
/// # Equality
///
/// Two entries are equal when their wire forms are: the URI as [`Uri`]
/// compares it, the parameters as [`HeaderParams`] does. [`Hash`] follows
/// the same rule.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(
        try_from = "SipGeolocationEntryParts",
        into = "SipGeolocationEntryParts"
    )
)]
#[non_exhaustive]
pub struct SipGeolocationEntry {
    uri: Uri,
    params: HeaderParams,
}

header_params!(SipGeolocationEntry);

impl SipGeolocationEntry {
    /// An entry for `uri`, with no parameters.
    ///
    /// Errors when the URI's text holds `<`, `>`, CR, LF or NUL, or does
    /// not read back strictly as `uri`.
    pub fn new(uri: Uri) -> Result<Self, ParseError> {
        Ok(SipGeolocationEntry {
            uri: crate::check::checked_uri(Field::Reference, uri)?,
            params: HeaderParams::default(),
        })
    }

    /// The location URI inside the angle brackets.
    pub fn uri(&self) -> &Uri {
        &self.uri
    }

    /// The Content-ID of a `cid:` URI (RFC 2392), the text after the scheme.
    pub fn cid(&self) -> Option<&str> {
        self.uri
            .as_other()
            .filter(|o| o.scheme() == Some("cid"))
            .map(|o| o.rest())
    }
}

impl fmt::Display for SipGeolocationEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<{}>{}", self.uri, self.params)
    }
}

impl SipGeolocationEntry {
    fn write_redacted(&self, f: &mut fmt::Formatter<'_>, how: HeaderRedaction<'_>) -> fmt::Result {
        f.write_char('<')?;
        if how.masks_location() {
            if let Some(scheme) = self
                .uri
                .scheme()
            {
                write!(f, "{scheme}:")?;
            }
            f.write_str("***")?;
        } else {
            write!(
                f,
                "{}",
                self.uri
                    .redacted(how.uri())
            )?;
        }
        write!(
            f,
            ">{}",
            self.params
                .masked(how.masked_params())
        )
    }
}

impl Redact for SipGeolocation {
    /// Render for logs: each reference as its scheme and `***` unless `how`
    /// shows locations, and then through sip-uri's redaction.
    fn redacted<'a>(&'a self, how: impl Into<HeaderRedaction<'a>>) -> impl fmt::Display + 'a {
        RedactedGeolocation(self, how.into())
    }
}

struct RedactedGeolocation<'a>(&'a SipGeolocation, HeaderRedaction<'a>);

impl fmt::Display for RedactedGeolocation<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, entry) in self
            .0
            .entries()
            .iter()
            .enumerate()
        {
            if i > 0 {
                f.write_str(", ")?;
            }
            entry.write_redacted(f, self.1)?;
        }
        Ok(())
    }
}

/// SIP Geolocation header value (RFC 6442): one `locationValue` or more,
/// each a `cid:` body-part reference or a URI to dereference.
///
/// ```
/// use sip_header::sip_uri::{Uri, UriParse};
/// use sip_header::{SipGeolocation, SipGeolocationEntry};
///
/// let geo = SipGeolocation::new(vec![
///     SipGeolocationEntry::new(Uri::parse("cid:abc-123")?)?,
///     SipGeolocationEntry::new(Uri::parse("https://lis.example.com/held/abc")?)?,
/// ])?;
/// assert_eq!(geo.len(), 2);
/// assert_eq!(geo.cid(), Some("abc-123"));
/// assert!(geo.url().is_some());
/// assert_eq!(geo.to_string(), "<cid:abc-123>, <https://lis.example.com/held/abc>");
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// # Equality
///
/// Entry by entry, in order, each as [`SipGeolocationEntry`] compares. [`Hash`] follows
/// the same rule.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct SipGeolocation(Vec<SipGeolocationEntry>);

list_type!(SipGeolocation, SipGeolocationEntry, non_empty);

impl SipGeolocation {
    /// Every entry's URI, in order.
    pub fn uris(&self) -> impl Iterator<Item = &Uri> {
        self.0
            .iter()
            .map(SipGeolocationEntry::uri)
    }

    /// The first `cid:` reference's Content-ID, if any.
    pub fn cid(&self) -> Option<&str> {
        self.cids()
            .next()
    }

    /// The first URI that is not a `cid:` reference, if any.
    pub fn url(&self) -> Option<&Uri> {
        self.urls()
            .next()
    }

    /// Every `cid:` reference's Content-ID.
    pub fn cids(&self) -> impl Iterator<Item = &str> {
        self.0
            .iter()
            .filter_map(SipGeolocationEntry::cid)
    }

    /// Every URI that is not a `cid:` reference.
    pub fn urls(&self) -> impl Iterator<Item = &Uri> {
        self.0
            .iter()
            .filter(|e| {
                e.cid()
                    .is_none()
            })
            .map(SipGeolocationEntry::uri)
    }
}

#[cfg(feature = "serde")]
#[derive(serde::Serialize, serde::Deserialize)]
struct SipGeolocationEntryParts {
    uri: Uri,
    #[serde(default, deserialize_with = "crate::params::deserialize_unchecked")]
    params: HeaderParams,
}

#[cfg(feature = "serde")]
impl TryFrom<SipGeolocationEntryParts> for SipGeolocationEntry {
    type Error = ParseError;

    fn try_from(p: SipGeolocationEntryParts) -> Result<Self, Self::Error> {
        let entry = SipGeolocationEntry {
            uri: p.uri,
            params: p.params,
        };
        crate::list::entry_reads_back::<SipGeolocation>(entry)
    }
}

#[cfg(feature = "serde")]
impl From<SipGeolocationEntry> for SipGeolocationEntryParts {
    fn from(e: SipGeolocationEntry) -> Self {
        SipGeolocationEntryParts {
            uri: e.uri,
            params: e.params,
        }
    }
}

/// Read one `locationValue`, positions relative to `entry`; `None` when it
/// is not a non-empty `<uri>` sip-uri can read.
fn read_entry(entry: &str, warnings: &mut Vec<ParseWarning>) -> Option<SipGeolocationEntry> {
    let raw = entry.trim();
    let skipped = |warnings: &mut Vec<ParseWarning>| {
        warnings.push(
            ParseWarning::new(Field::Entry, WarningCode::SkippedEntry)
                .at(crate::offset_in(entry, raw)),
        );
    };
    let Some((inner, tail)) = raw
        .strip_prefix('<')
        .and_then(|s| s.split_once('>'))
        .filter(|(inner, _)| !inner.is_empty() && !inner.contains('<'))
    else {
        skipped(warnings);
        return None;
    };
    let Some((uri, uri_warnings)) = read_uri(inner, crate::offset_in(entry, inner)) else {
        skipped(warnings);
        return None;
    };
    warnings.extend(uri_warnings);
    let junk = tail.trim_start();
    let params = if junk.is_empty() || junk.starts_with(';') {
        tail
    } else {
        warnings.push(
            ParseWarning::new(Field::Param, WarningCode::TrailingContent)
                .at(crate::offset_in(entry, junk)),
        );
        &junk[junk
            .find(';')
            .unwrap_or(junk.len())..]
    };
    Some(SipGeolocationEntry {
        uri,
        params: HeaderParams::read(entry, params, warnings),
    })
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
        Self::new(entries)
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
            .to_string()
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
        assert_eq!(
            geo.url()
                .map(ToString::to_string)
                .as_deref(),
            Some("https://lis.example.com/location")
        );
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
        assert_eq!(
            SipGeolocation::parse("junk"),
            Err(ParseError::empty(Field::Value))
        );
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
                WarningKind::Recovered,
                Some(0),
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
        assert_eq!(entry.cid(), Some("x@example.com"));
        assert_eq!(entry.param("inserted-by"), Some(Some("y")));
        assert_eq!(entry.param("flag"), Some(None));
        assert_eq!(
            entry
                .params()
                .iter()
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
            geo.uris()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            vec!["https://example.com/a,b"]
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
        assert_eq!(
            geo.url()
                .map(ToString::to_string)
                .as_deref(),
            Some("https://example.com/loc")
        );
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
            .map(ToString::to_string)
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
        assert_eq!(
            SipGeolocation::from_entries(["junk"]),
            Err(ParseError::empty(Field::Value))
        );
        assert_eq!(
            SipGeolocation::parse_with_warnings(" "),
            Err(ParseError::empty(Field::Value))
        );
    }
}
