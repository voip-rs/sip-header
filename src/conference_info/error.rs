use std::error::Error;
use std::fmt;
use std::sync::Arc;

/// Error from reading, parsing or writing an RFC 4575 conference-info document.
///
/// Display names the layer that failed; the underlying error, which may quote
/// the document, is the [`source`](Error::source).
#[derive(Debug, Clone)]
pub struct ConferenceInfoError {
    kind: ConferenceInfoErrorKind,
    source: Arc<dyn Error + Send + Sync>,
}

impl ConferenceInfoError {
    pub(super) fn new(
        kind: ConferenceInfoErrorKind,
        source: impl Error + Send + Sync + 'static,
    ) -> Self {
        ConferenceInfoError {
            kind,
            source: Arc::new(source),
        }
    }

    /// The layer that failed.
    pub fn kind(&self) -> ConferenceInfoErrorKind {
        self.kind
    }
}

impl fmt::Display for ConferenceInfoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "conference-info: {}", self.kind)
    }
}

impl Error for ConferenceInfoError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&*self.source)
    }
}

/// The layer a [`ConferenceInfoError`] failed in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ConferenceInfoErrorKind {
    /// The document is not well-formed XML.
    Read,
    /// Writing the document without namespace prefixes failed.
    Normalize,
    /// The normalized document is not UTF-8.
    NotUtf8,
    /// Well-formed XML that does not match the RFC 4575 schema.
    Deserialize,
    /// The value could not be written as XML.
    Serialize,
}

impl ConferenceInfoErrorKind {
    /// Stable kebab-case name, for logs and machine consumers.
    pub fn as_str(self) -> &'static str {
        match self {
            ConferenceInfoErrorKind::Read => "ill-formed-xml",
            ConferenceInfoErrorKind::Normalize => "normalize-failed",
            ConferenceInfoErrorKind::NotUtf8 => "not-utf8",
            ConferenceInfoErrorKind::Deserialize => "schema-mismatch",
            ConferenceInfoErrorKind::Serialize => "serialize-failed",
        }
    }
}

impl fmt::Display for ConferenceInfoErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
