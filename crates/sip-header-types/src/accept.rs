//! SIP Accept header value (RFC 3261 §20.1).

use std::fmt;

/// A single Accept entry: `type/subtype *(SEMI accept-param)`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SipAcceptEntry {
    media_range: String,
    slash_pos: usize,
    params: Vec<(String, Option<String>)>,
}

impl SipAcceptEntry {
    /// An entry for `media_type/subtype`, both lowercased, with no parameters.
    pub fn new(media_type: impl Into<String>, subtype: impl AsRef<str>) -> Self {
        let mut media_range = media_type.into();
        media_range.make_ascii_lowercase();
        let slash_pos = media_range.len();
        media_range.push('/');
        media_range.push_str(
            &subtype
                .as_ref()
                .to_ascii_lowercase(),
        );
        SipAcceptEntry {
            media_range,
            slash_pos,
            params: Vec::new(),
        }
    }

    /// Add a parameter, lowercasing the key; the value is emitted as given.
    pub fn with_param(mut self, key: impl Into<String>, value: Option<impl Into<String>>) -> Self {
        crate::push_lowercased(&mut self.params, key.into(), value.map(Into::into));
        self
    }

    /// The media type (e.g. `"application"`).
    pub fn media_type(&self) -> &str {
        &self.media_range[..self.slash_pos]
    }

    /// The media subtype (e.g. `"sdp"`).
    pub fn subtype(&self) -> &str {
        &self.media_range[self.slash_pos + 1..]
    }

    /// The full media range as `type/subtype`.
    pub fn media_range(&self) -> &str {
        &self.media_range
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

impl fmt::Display for SipAcceptEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.media_range)?;
        crate::write_params(f, &self.params)
    }
}

/// SIP Accept header value; its grammar admits the empty list (RFC 3261 §25.1).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SipAccept(Vec<SipAcceptEntry>);

list_type!(SipAccept, SipAcceptEntry, sep: ", ", may_be_empty);
