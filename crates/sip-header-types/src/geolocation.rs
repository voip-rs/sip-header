//! SIP Geolocation header value (RFC 6442).

use std::fmt;

/// A reference extracted from a SIP Geolocation header (RFC 6442).
///
/// Each entry is either a `cid:` reference to a MIME body part
/// (typically containing PIDF-LO XML) or a URL for location dereference.
///
/// Resolving `cid:` references against the SIP message body (multipart
/// MIME) or dereferencing HTTP URLs is the caller's responsibility.
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

/// One `locationValue = LAQUOT locationURI RAQUOT *(SEMI geoloc-param)`
/// (RFC 6442 §4.1).
#[derive(Debug, Clone, PartialEq, Eq)]
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
/// use sip_header_types::{SipGeolocation, SipGeolocationEntry, SipGeolocationRef};
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
