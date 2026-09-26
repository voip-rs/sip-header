//! `<absoluteURI> *(SEMI generic-param)` values (Call-Info, Alert-Info, Error-Info).

use std::fmt;

/// One `<uri>;key=value;key=value` entry from a URI-info-style header.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct UriInfoEntry {
    uri: String,
    params: Vec<(String, Option<String>)>,
}

impl UriInfoEntry {
    /// An entry for `uri`, written inside angle brackets, with no parameters.
    pub fn new(uri: impl Into<String>) -> Self {
        UriInfoEntry {
            uri: uri.into(),
            params: Vec::new(),
        }
    }

    /// Add a parameter, lowercasing the key; the value is emitted as given.
    pub fn with_param(mut self, key: impl Into<String>, value: Option<impl Into<String>>) -> Self {
        crate::push_lowercased(&mut self.params, key.into(), value.map(Into::into));
        self
    }

    /// The URI or data inside the angle brackets, with brackets stripped.
    pub fn uri(&self) -> &str {
        &self.uri
    }

    /// All parameters as `(key, value)` pairs; keys lowercased, values as
    /// sent, `None` for a flag.
    pub fn params(&self) -> impl Iterator<Item = (&str, Option<&str>)> {
        crate::iter_params(&self.params)
    }

    /// Look up a parameter by key (case-insensitive); `Some(None)` for a flag.
    pub fn param(&self, key: &str) -> Option<Option<&str>> {
        crate::find_param(&self.params, key)
    }

    /// The `purpose` parameter value, if present with a value.
    pub fn purpose(&self) -> Option<&str> {
        self.param("purpose")
            .flatten()
    }
}

impl fmt::Display for UriInfoEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<{}>", self.uri)?;
        crate::write_params(f, &self.params)
    }
}

/// `<absoluteURI> *(SEMI generic-param)` header value, one entry or more.
///
/// Used by Call-Info, Alert-Info, and Error-Info.
///
/// ```
/// use sip_header_types::{UriInfo, UriInfoEntry};
///
/// let info = UriInfo::new(vec![
///     UriInfoEntry::new("urn:example:call:123").with_param("purpose", Some("emergency-CallId")),
///     UriInfoEntry::new("https://example.com/data"),
/// ])
/// .unwrap();
/// assert_eq!(info.to_string(), "<urn:example:call:123>;purpose=emergency-CallId,<https://example.com/data>");
/// assert_eq!(info.entries()[0].purpose(), Some("emergency-CallId"));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UriInfo(Vec<UriInfoEntry>);

list_type!(UriInfo, UriInfoEntry, sep: ",", non_empty);
