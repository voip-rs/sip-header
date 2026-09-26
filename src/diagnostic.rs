//! Parse results together with the grammar breaches the parser survived.

use std::fmt;

use sip_uri::WarningKind;

use crate::error::ParseError;

/// A parse result together with the non-conformance found on the way.
///
/// Returned by the `parse_with_warnings` constructors; `value` is what
/// [`HeaderParse::parse`](crate::HeaderParse::parse) returns for the same input.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Parsed<T> {
    /// The parsed value.
    pub value: T,
    /// Grammar breaches the parser accepted, in input order.
    pub warnings: Vec<ParseWarning>,
}

impl<T> Parsed<T> {
    pub(crate) fn new(value: T, warnings: Vec<ParseWarning>) -> Self {
        Parsed { value, warnings }
    }

    /// Whether any warning was raised.
    pub fn has_warnings(&self) -> bool {
        !self
            .warnings
            .is_empty()
    }

    /// The value, or the first warning as [`ParseError::NonConformant`].
    pub fn into_strict(self) -> Result<T, ParseError> {
        match self
            .warnings
            .first()
        {
            Some(w) => Err(ParseError::NonConformant(*w)),
            None => Ok(self.value),
        }
    }

    /// Transform the value, keeping the warnings.
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> Parsed<U> {
        Parsed {
            value: f(self.value),
            warnings: self.warnings,
        }
    }
}

/// A grammar breach the parser accepted rather than rejected.
///
/// Names where the breach is, never what text it was.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct ParseWarning {
    /// Part of the header value the breach is in.
    pub field: Field,
    /// What is wrong with it.
    pub code: WarningCode,
    /// Byte offset into the string handed to the parser, when one points at
    /// the breach.
    pub position: Option<usize>,
    /// Index of the list entry the breach is in, for list-valued headers.
    pub entry: Option<usize>,
    /// Whether the parsed value still carries what was sent.
    pub kind: WarningKind,
}

impl ParseWarning {
    pub(crate) fn new(field: Field, code: WarningCode, position: Option<usize>) -> Self {
        ParseWarning {
            field,
            code,
            position,
            entry: None,
            kind: code.own_kind(),
        }
    }

    /// Lift a sip-uri warning whose input began `offset` bytes into ours.
    pub(crate) fn from_uri(w: sip_uri::ParseWarning, offset: usize) -> Self {
        ParseWarning {
            field: Field::Uri(w.component),
            code: WarningCode::Uri(w.code),
            position: w
                .position
                .map(|p| p + offset),
            entry: None,
            kind: w.kind,
        }
    }

    pub(crate) fn in_entry(mut self, entry: usize) -> Self {
        self.entry = Some(entry);
        self
    }
}

impl fmt::Display for ParseWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.field, self.code)?;
        write_location(f, self.position, self.entry)
    }
}

pub(crate) fn write_location(
    f: &mut fmt::Formatter<'_>,
    position: Option<usize>,
    entry: Option<usize>,
) -> fmt::Result {
    if let Some(pos) = position {
        write!(f, " at byte {pos}")?;
    }
    if let Some(entry) = entry {
        write!(f, " in entry {entry}")?;
    }
    Ok(())
}

/// Part of a header value a [`ParseWarning`] or [`Fault`](crate::Fault)
/// refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Field {
    /// A whole list entry.
    Entry,
    /// A `display-name`.
    DisplayName,
    /// The `name-addr` / `addr-spec` holding a URI.
    Addr,
    /// A component inside a URI, as sip-uri names it.
    Uri(sip_uri::Component),
    /// A header parameter.
    Param,
    /// A `callid`.
    CallId,
    /// A dialog tag parameter.
    Tag,
    /// Via `sent-protocol`.
    SentProtocol,
    /// Via `sent-by`.
    SentBy,
    /// Warning `warn-code`.
    Code,
    /// Warning `warn-agent`.
    Agent,
    /// A quoted text value (Warning `warn-text`, Reason `text`).
    Text,
    /// Reason `cause`.
    Cause,
    /// History-Info `index`.
    Index,
    /// Authentication scheme.
    Scheme,
    /// Authentication credentials or challenge parameters.
    Credentials,
    /// Security `mechanism-name`.
    Mechanism,
    /// Accept `media-range`.
    MediaRange,
    /// Accept-Encoding `codings`.
    Coding,
    /// Accept-Language `language-range`.
    Language,
    /// An accept-param `qvalue`.
    Qvalue,
    /// A Geolocation `locationValue`.
    Reference,
    /// The header value as a whole.
    Value,
}

impl fmt::Display for Field {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Field::Uri(c) => return write!(f, "uri {}", c.as_str()),
            Field::Entry => "entry",
            Field::DisplayName => "display-name",
            Field::Addr => "addr",
            Field::Param => "param",
            Field::CallId => "call-id",
            Field::Tag => "tag",
            Field::SentProtocol => "sent-protocol",
            Field::SentBy => "sent-by",
            Field::Code => "warn-code",
            Field::Agent => "warn-agent",
            Field::Text => "text",
            Field::Cause => "cause",
            Field::Index => "index",
            Field::Scheme => "auth-scheme",
            Field::Credentials => "credentials",
            Field::Mechanism => "mechanism",
            Field::MediaRange => "media-range",
            Field::Coding => "coding",
            Field::Language => "language-range",
            Field::Qvalue => "qvalue",
            Field::Reference => "location",
            Field::Value => "value",
        };
        f.write_str(name)
    }
}

/// What a [`ParseWarning`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum WarningCode {
    /// A breach inside a URI, as sip-uri reports it.
    Uri(sip_uri::WarningCode),
    /// Text after a complete value that starts no parameter (RFC 3261
    /// §25.1 `*( SEMI generic-param )`), dropped.
    TrailingContent,
    /// A character outside RFC 3261 §25.1 `token` where one is required,
    /// kept as sent.
    InvalidToken,
    /// A `"` that opens a quoted-string (RFC 3261 §25.1) and never closes;
    /// the value ends at the next delimiter.
    UnterminatedQuote,
    /// A `\` ending a quoted-string, which RFC 3261 §25.1 `quoted-pair`
    /// requires to escape a character; dropped.
    TrailingBackslash,
    /// Contact `*` beside addresses, where RFC 3261 §20.10 allows it only
    /// alone; kept.
    WildcardNotAlone,
    /// A History-Info entry without the `index` RFC 7044 §9.1 makes
    /// mandatory.
    MissingIndex,
    /// A History-Info entry as a bare `addr-spec` where RFC 7044 §9.1
    /// requires `name-addr`.
    NotNameAddr,
    /// A Reason `cause` that is not the RFC 3326 `1*DIGIT` a `u16` holds,
    /// dropped.
    InvalidCause,
    /// A Reason `text` without the quotes RFC 3326 requires, kept.
    UnquotedText,
    /// A URI-info entry without the angle brackets RFC 3261 §20.9 requires.
    MissingBrackets,
    /// A list entry that yields no value, dropped.
    SkippedEntry,
    /// An empty list entry between commas, dropped.
    EmptyEntry,
    /// A Via `sent-by` without the host RFC 3261 §20.42 requires.
    MissingHost,
    /// An accept-param `q` outside RFC 3261 §25.1 `qvalue`, kept as sent.
    InvalidQvalue,
}

impl WarningCode {
    /// Whether the value keeps what was sent; sip-uri codes carry their own.
    fn own_kind(self) -> WarningKind {
        match self {
            WarningCode::TrailingContent
            | WarningCode::TrailingBackslash
            | WarningCode::InvalidCause
            | WarningCode::SkippedEntry
            | WarningCode::EmptyEntry
            | WarningCode::MissingHost => WarningKind::Lost,
            _ => WarningKind::Recovered,
        }
    }

    /// Stable kebab-case name, for logs and machine consumers.
    pub fn as_str(self) -> &'static str {
        match self {
            WarningCode::Uri(c) => c.as_str(),
            WarningCode::TrailingContent => "trailing-content",
            WarningCode::InvalidToken => "invalid-token",
            WarningCode::UnterminatedQuote => "unterminated-quote",
            WarningCode::TrailingBackslash => "trailing-backslash",
            WarningCode::WildcardNotAlone => "wildcard-not-alone",
            WarningCode::MissingIndex => "missing-index",
            WarningCode::NotNameAddr => "not-name-addr",
            WarningCode::InvalidCause => "invalid-cause",
            WarningCode::UnquotedText => "unquoted-text",
            WarningCode::MissingBrackets => "missing-brackets",
            WarningCode::SkippedEntry => "skipped-entry",
            WarningCode::EmptyEntry => "empty-entry",
            WarningCode::MissingHost => "missing-host",
            WarningCode::InvalidQvalue => "invalid-qvalue",
        }
    }
}

impl fmt::Display for WarningCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_follows_code() {
        let w = ParseWarning::new(Field::Addr, WarningCode::TrailingContent, Some(3));
        assert_eq!(w.kind, WarningKind::Lost);
        let w = ParseWarning::new(Field::DisplayName, WarningCode::InvalidToken, None);
        assert_eq!(w.kind, WarningKind::Recovered);
    }

    #[test]
    fn display_names_location_never_text() {
        let w =
            ParseWarning::new(Field::Param, WarningCode::UnterminatedQuote, Some(12)).in_entry(2);
        assert_eq!(
            w.to_string(),
            "param: unterminated-quote at byte 12 in entry 2"
        );
    }

    #[test]
    fn into_strict_returns_first_warning() {
        let w = ParseWarning::new(Field::Addr, WarningCode::TrailingContent, Some(1));
        let p = Parsed::new((), vec![w]);
        assert_eq!(p.into_strict(), Err(ParseError::NonConformant(w)));
        assert_eq!(Parsed::new(5, Vec::new()).into_strict(), Ok(5));
    }
}
