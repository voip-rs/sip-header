//! SIP Accept-Encoding header value (RFC 3261 §20.2).

use std::fmt;

/// A single Accept-Encoding entry: `encoding *(SEMI accept-param)`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(
        from = "SipAcceptEncodingEntryParts",
        into = "SipAcceptEncodingEntryParts"
    )
)]
#[non_exhaustive]
pub struct SipAcceptEncodingEntry {
    encoding: String,
    params: Vec<(String, Option<String>)>,
}

impl SipAcceptEncodingEntry {
    /// An entry for the given content-coding, lowercased, with no parameters.
    pub fn new(encoding: impl Into<String>) -> Self {
        let mut encoding = encoding.into();
        encoding.make_ascii_lowercase();
        SipAcceptEncodingEntry {
            encoding,
            params: Vec::new(),
        }
    }

    /// Add a parameter, lowercasing the key; the value is emitted as given.
    pub fn with_param(mut self, key: impl Into<String>, value: Option<impl Into<String>>) -> Self {
        crate::push_lowercased(&mut self.params, key.into(), value.map(Into::into));
        self
    }

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

/// SIP Accept-Encoding header value; its grammar admits the empty list (RFC 3261 §25.1).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SipAcceptEncoding(Vec<SipAcceptEncodingEntry>);

list_type!(SipAcceptEncoding, SipAcceptEncodingEntry, sep: ", ", may_be_empty);

#[cfg(feature = "serde")]
#[derive(serde::Serialize, serde::Deserialize)]
struct SipAcceptEncodingEntryParts {
    encoding: String,
    #[serde(default)]
    params: Vec<(String, Option<String>)>,
}

#[cfg(feature = "serde")]
impl From<SipAcceptEncodingEntryParts> for SipAcceptEncodingEntry {
    fn from(p: SipAcceptEncodingEntryParts) -> Self {
        p.params
            .into_iter()
            .fold(SipAcceptEncodingEntry::new(p.encoding), |e, (k, v)| {
                e.with_param(k, v)
            })
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
