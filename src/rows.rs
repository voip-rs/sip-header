//! The raw row lookup a header store implements.

use std::fmt;

use crate::header::SipHeader;

/// What a store's framing of a header's rows broke.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RowErrorKind {
    /// More entries than the store allows.
    TooManyEntries,
}

impl RowErrorKind {
    /// Stable kebab-case name, for logs and machine consumers.
    pub fn as_str(self) -> &'static str {
        match self {
            RowErrorKind::TooManyEntries => "too-many-entries",
        }
    }
}

impl fmt::Display for RowErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A store that decodes its own framing failed to produce a header's rows.
///
/// Names the entry at fault, never its text.
///
/// ```
/// use sip_header::{RowError, RowErrorKind};
///
/// let e = RowError::new(RowErrorKind::TooManyEntries, 4000);
/// assert_eq!(e.to_string(), "too-many-entries in entry 4000");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RowError {
    kind: RowErrorKind,
    entry: usize,
}

impl RowError {
    /// A `kind` failure at entry index `entry`.
    pub fn new(kind: RowErrorKind, entry: usize) -> Self {
        RowError { kind, entry }
    }

    /// What broke.
    pub fn kind(&self) -> RowErrorKind {
        self.kind
    }

    /// Index of the entry at fault.
    pub fn entry(&self) -> usize {
        self.entry
    }
}

impl fmt::Display for RowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} in entry {}", self.kind, self.entry)
    }
}

impl std::error::Error for RowError {}

/// Raw lookup of SIP header values from any key-value store.
///
/// Implementors provide [`sip_header_str`](Self::sip_header_str), and
/// override the multi-row methods when the store keeps every occurrence.
///
/// ```
/// use std::collections::HashMap;
/// use sip_header::{SipHeader, SipHeaderRows};
///
/// let mut headers = HashMap::new();
/// headers.insert("Via".to_string(), vec!["SIP/2.0/UDP a".to_string(), "SIP/2.0/UDP b".to_string()]);
/// assert_eq!(headers.sip_header(SipHeader::Via), Some("SIP/2.0/UDP a"));
/// assert_eq!(headers.sip_header_rows(SipHeader::Via), Ok(vec!["SIP/2.0/UDP a", "SIP/2.0/UDP b"]));
/// ```
pub trait SipHeaderRows {
    /// Look up a SIP header by its canonical name (e.g. `"Call-Info"`).
    fn sip_header_str(&self, name: &str) -> Option<&str>;

    /// Look up a SIP header by its [`SipHeader`] enum variant.
    fn sip_header(&self, name: SipHeader) -> Option<&str> {
        self.sip_header_str(name.as_str())
    }

    /// Return all occurrences of a header by canonical name.
    ///
    /// The default wraps [`sip_header_str`](Self::sip_header_str) in a
    /// single-element `Vec`; a store that keeps every occurrence overrides it.
    fn sip_header_all_str<'a>(&'a self, name: &str) -> Vec<&'a str> {
        self.sip_header_str(name)
            .into_iter()
            .collect()
    }

    /// Return all occurrences of a header by [`SipHeader`] variant.
    fn sip_header_all(&self, name: SipHeader) -> Vec<&str> {
        self.sip_header_all_str(name.as_str())
    }

    /// Every occurrence of a header by canonical name, as typed accessors
    /// read it.
    ///
    /// Defaults to [`sip_header_all_str`](Self::sip_header_all_str). A store
    /// that decodes its own framing overrides this to report a decoding
    /// failure.
    fn sip_header_rows_str<'a>(&'a self, name: &str) -> Result<Vec<&'a str>, RowError> {
        Ok(self.sip_header_all_str(name))
    }

    /// Every occurrence of a header by [`SipHeader`] variant, as typed
    /// accessors read it.
    fn sip_header_rows(&self, name: SipHeader) -> Result<Vec<&str>, RowError> {
        self.sip_header_rows_str(name.as_str())
    }
}

/// Keys are matched exactly, case included.
impl SipHeaderRows for std::collections::HashMap<String, String> {
    fn sip_header_str(&self, name: &str) -> Option<&str> {
        self.get(name)
            .map(|s| s.as_str())
    }
}

/// Keys are matched exactly, case included.
impl SipHeaderRows for std::collections::HashMap<String, Vec<String>> {
    fn sip_header_str(&self, name: &str) -> Option<&str> {
        self.get(name)
            .and_then(|v| v.first())
            .map(|s| s.as_str())
    }

    fn sip_header_all_str<'a>(&'a self, name: &str) -> Vec<&'a str> {
        self.get(name)
            .map(|v| {
                v.iter()
                    .map(|s| s.as_str())
                    .collect()
            })
            .unwrap_or_default()
    }
}
