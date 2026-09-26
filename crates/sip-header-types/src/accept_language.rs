//! SIP Accept-Language header value (RFC 3261 §20.3).

use std::fmt;

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
    params: Vec<(String, Option<String>)>,
}

impl SipAcceptLanguageEntry {
    /// An entry for the given language range, lowercased, with no parameters.
    pub fn new(language: impl Into<String>) -> Self {
        let mut language = language.into();
        language.make_ascii_lowercase();
        SipAcceptLanguageEntry {
            language,
            params: Vec::new(),
        }
    }

    /// Add a parameter, lowercasing the key; the value is emitted as given.
    pub fn with_param(mut self, key: impl Into<String>, value: Option<impl Into<String>>) -> Self {
        crate::push_lowercased(&mut self.params, key.into(), value.map(Into::into));
        self
    }

    /// The language tag (e.g. `"en"`, `"en-US"`, `"*"`).
    pub fn language(&self) -> &str {
        &self.language
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

impl fmt::Display for SipAcceptLanguageEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.language)?;
        crate::write_params(f, &self.params)
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
    params: Vec<(String, Option<String>)>,
}

#[cfg(feature = "serde")]
impl From<SipAcceptLanguageEntryParts> for SipAcceptLanguageEntry {
    fn from(p: SipAcceptLanguageEntryParts) -> Self {
        p.params
            .into_iter()
            .fold(SipAcceptLanguageEntry::new(p.language), |e, (k, v)| {
                e.with_param(k, v)
            })
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
