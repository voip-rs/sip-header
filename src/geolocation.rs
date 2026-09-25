//! SIP Geolocation header types (RFC 6442).

use std::fmt;

use crate::error::ParseError;

/// A reference extracted from a SIP Geolocation header (RFC 6442).
///
/// Each entry is either a `cid:` reference to a MIME body part
/// (typically containing PIDF-LO XML) or a URL for location dereference.
///
/// This crate only parses the header references themselves. Resolving
/// `cid:` references against the SIP message body (multipart MIME) or
/// dereferencing HTTP URLs is the caller's responsibility.
#[derive(Debug, Clone, PartialEq, Eq)]
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

/// Read `locationValue = LAQUOT locationURI RAQUOT *(SEMI geoloc-param)`
/// (RFC 6442 §4.1), keeping only the URI.
fn parse_ref(entry: &str) -> Option<SipGeolocationRef> {
    let (inner, _) = entry
        .trim()
        .strip_prefix('<')?
        .split_once('>')?;
    if inner.is_empty() {
        return None;
    }
    Some(
        match inner
            .get(..4)
            .filter(|scheme| scheme.eq_ignore_ascii_case("cid:"))
        {
            Some(_) => SipGeolocationRef::Cid(inner[4..].to_string()),
            None => SipGeolocationRef::Url(inner.to_string()),
        },
    )
}

/// Parsed SIP Geolocation header value (RFC 6442).
///
/// Contains one or more `<uri>` references, comma-separated. Each reference
/// is classified as either a `cid:` body-part reference or a dereference URL.
///
/// ```
/// use sip_header::SipGeolocation;
///
/// let raw = "<cid:abc-123>, <https://lis.example.com/held/abc>";
/// let geo = SipGeolocation::parse(raw)?;
/// assert_eq!(geo.len(), 2);
/// assert!(geo.cid().is_some());
/// assert!(geo.url().is_some());
/// # Ok::<(), sip_header::ParseError>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SipGeolocation(Vec<SipGeolocationRef>);

impl SipGeolocation {
    /// Parse a raw Geolocation header value into typed references.
    ///
    /// Entries that are not a `<uri>` are skipped; only an empty value is an
    /// error.
    pub fn parse(raw: &str) -> Result<Self, ParseError> {
        if raw
            .trim()
            .is_empty()
        {
            return Err(ParseError::Empty);
        }
        Ok(Self::from_entries(crate::split_comma_entries(raw)))
    }

    /// Build from entries a transport already split; each is one
    /// `locationValue`. Entries that are not a `<uri>` are skipped, and
    /// geoloc-params after the `>` are dropped.
    pub fn from_entries<'a>(entries: impl IntoIterator<Item = &'a str>) -> Self {
        Self(
            entries
                .into_iter()
                .filter_map(parse_ref)
                .collect(),
        )
    }

    /// The parsed references as a slice.
    pub fn refs(&self) -> &[SipGeolocationRef] {
        &self.0
    }

    /// Number of references.
    pub fn len(&self) -> usize {
        self.0
            .len()
    }

    /// Returns `true` if there are no references.
    pub fn is_empty(&self) -> bool {
        self.0
            .is_empty()
    }

    /// The first `cid:` reference, if any.
    pub fn cid(&self) -> Option<&str> {
        self.0
            .iter()
            .find_map(|r| match r {
                SipGeolocationRef::Cid(id) => Some(id.as_str()),
                _ => None,
            })
    }

    /// The first URL reference, if any.
    pub fn url(&self) -> Option<&str> {
        self.0
            .iter()
            .find_map(|r| match r {
                SipGeolocationRef::Url(url) => Some(url.as_str()),
                _ => None,
            })
    }

    /// Iterate over all `cid:` references.
    pub fn cids(&self) -> impl Iterator<Item = &str> {
        self.0
            .iter()
            .filter_map(|r| match r {
                SipGeolocationRef::Cid(id) => Some(id.as_str()),
                _ => None,
            })
    }

    /// Iterate over all URL references.
    pub fn urls(&self) -> impl Iterator<Item = &str> {
        self.0
            .iter()
            .filter_map(|r| match r {
                SipGeolocationRef::Url(url) => Some(url.as_str()),
                _ => None,
            })
    }
}

impl fmt::Display for SipGeolocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        crate::fmt_joined(f, &self.0, ", ")
    }
}

impl<'a> IntoIterator for &'a SipGeolocation {
    type Item = &'a SipGeolocationRef;
    type IntoIter = std::slice::Iter<'a, SipGeolocationRef>;

    fn into_iter(self) -> Self::IntoIter {
        self.0
            .iter()
    }
}

impl IntoIterator for SipGeolocation {
    type Item = SipGeolocationRef;
    type IntoIter = std::vec::IntoIter<SipGeolocationRef>;

    fn into_iter(self) -> Self::IntoIter {
        self.0
            .into_iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(SipGeolocation::parse(""), Err(ParseError::Empty));
        assert_eq!(SipGeolocation::parse(" \t"), Err(ParseError::Empty));
        assert!(parse("junk").is_empty());
    }

    #[test]
    fn empty_brackets_skipped() {
        let geo = parse("<>, <cid:test>");
        assert_eq!(geo.len(), 1);
        assert_eq!(geo.cid(), Some("test"));
    }

    #[test]
    fn display_roundtrip() {
        let raw = "<cid:abc-123>, <https://lis.example.com/test>";
        let geo = parse(raw);
        assert_eq!(geo.to_string(), raw);
    }

    #[test]
    fn geoloc_params_dropped() {
        let geo = parse("<cid:x@example.com>;inserted-by=y");
        assert_eq!(
            geo.refs(),
            &[SipGeolocationRef::Cid("x@example.com".into())]
        );
    }

    #[test]
    fn comma_inside_brackets_not_split() {
        let geo = parse("<https://example.com/a,b>");
        assert_eq!(
            geo.refs(),
            &[SipGeolocationRef::Url("https://example.com/a,b".into())]
        );
    }

    #[test]
    fn cid_scheme_case_insensitive() {
        let geo = parse("<CID:x@example.com>");
        assert_eq!(geo.cid(), Some("x@example.com"));
    }

    #[test]
    fn unbracketed_entry_skipped() {
        let geo = parse("cid:x@example.com, <https://example.com/loc>");
        assert_eq!(geo.len(), 1);
        assert_eq!(geo.url(), Some("https://example.com/loc"));
    }

    #[test]
    fn from_entries_matches_parse() {
        let split =
            SipGeolocation::from_entries(["<cid:a>;inserted-by=x", "<https://example.com/a,b>"]);
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
    fn warnings_api_and_infallible_from_entries() {
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
        let lenient: SipGeolocation = SipGeolocation::from_entries(["junk"]);
        assert!(lenient.is_empty());
        assert_eq!(
            parsed
                .value
                .entries(),
            parsed
                .value
                .refs()
        );
        assert_eq!(
            SipGeolocation::parse_with_warnings(" "),
            Err(ParseError::Empty)
        );
    }
}
