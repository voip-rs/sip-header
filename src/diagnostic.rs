//! Parse results together with the grammar breaches the parser survived.

use std::fmt;

use sip_uri::WarningKind;

use crate::span::Relocation;

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
    /// `value` with the breaches found parsing it, in input order.
    pub fn new(value: T, warnings: Vec<ParseWarning>) -> Self {
        Parsed { value, warnings }
    }

    /// Whether any warning was raised.
    pub fn has_warnings(&self) -> bool {
        !self
            .warnings
            .is_empty()
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
    /// Byte offset into the row the breach is in, when one points at it: the
    /// string handed to `parse`, or the row or entry named by
    /// [`row`](Self::row).
    pub position: Option<usize>,
    /// Index of the row the breach is in, among the rows or entries a value
    /// was built from; `None` for a value parsed from one string.
    pub row: Option<usize>,
    /// Index of the list entry the breach is in, for list-valued headers.
    pub entry: Option<usize>,
    /// Whether the parsed value still carries what was sent.
    pub kind: WarningKind,
}

impl ParseWarning {
    /// A breach in `field`, with no position or entry; `kind` follows `code`,
    /// and is [`WarningKind::Recovered`] for every [`WarningCode::Uri`].
    ///
    /// For a layer outside this crate that decodes header values:
    ///
    /// ```
    /// use sip_header::{Field, ParseWarning, Parsed, WarningCode};
    ///
    /// let w = ParseWarning::new(Field::Entry, WarningCode::SkippedEntry).at(9).in_entry(1);
    /// let parsed = Parsed::new(vec!["kept"], vec![w]);
    /// assert_eq!(parsed.warnings[0].to_string(), "entry: skipped-entry at byte 9 in entry 1");
    /// ```
    pub fn new(field: Field, code: WarningCode) -> Self {
        ParseWarning {
            field,
            code,
            position: None,
            row: None,
            entry: None,
            kind: code.own_kind(),
        }
    }

    /// Point the warning at byte `position`.
    pub fn at(mut self, position: usize) -> Self {
        self.position = Some(position);
        self
    }

    /// Place the warning in row `row`.
    pub fn in_row(mut self, row: usize) -> Self {
        self.row = Some(row);
        self
    }

    /// Lift a sip-uri warning whose input began `offset` bytes into ours.
    pub(crate) fn from_uri(w: sip_uri::ParseWarning, offset: usize) -> Self {
        ParseWarning {
            field: Field::Uri(w.component),
            code: WarningCode::Uri(w.code),
            position: w
                .position
                .map(|p| p + offset),
            row: None,
            entry: None,
            kind: w.kind,
        }
    }

    /// Move the warning to where `to` places the text it was found in.
    pub(crate) fn relocate(mut self, to: &Relocation<'_>) -> Self {
        self.position = self
            .position
            .and_then(|p| to.start(p));
        self.row = to
            .row()
            .or(self.row);
        self
    }

    /// Attribute the warning to list entry `entry`.
    pub fn in_entry(mut self, entry: usize) -> Self {
        self.entry = Some(entry);
        self
    }
}

impl fmt::Display for ParseWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.field, self.code)?;
        write_location(f, self.position, self.row, self.entry)
    }
}

pub(crate) fn write_location(
    f: &mut fmt::Formatter<'_>,
    position: Option<usize>,
    row: Option<usize>,
    entry: Option<usize>,
) -> fmt::Result {
    if let Some(pos) = position {
        write!(f, " at byte {pos}")?;
    }
    if let Some(row) = row {
        write!(f, " in row {row}")?;
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
    /// Reason `protocol`.
    Protocol,
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
            Field::Protocol => "protocol",
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
    /// Contact `*` beside addresses or another `*`, where RFC 3261 §20.10
    /// allows it only alone; dropped.
    WildcardNotAlone,
    /// A History-Info entry without the `index` RFC 7044 §9.1 makes
    /// mandatory.
    MissingIndex,
    /// A History-Info entry as a bare `addr-spec` where RFC 7044 §9.1
    /// requires `name-addr`.
    NotNameAddr,
    /// A Reason `cause` that is not the RFC 3326 `1*DIGIT`, dropped.
    InvalidCause,
    /// A Reason `text` without the quotes RFC 3326 requires, kept.
    UnquotedText,
    /// A URI without the angle brackets RFC 3261 requires: a URI-info entry
    /// (§20.9), or an addr-spec holding a comma, semicolon or question mark (§20).
    MissingBrackets,
    /// A list entry that yields no value, dropped.
    SkippedEntry,
    /// A blank list element or header parameter, which RFC 3261 §25.1
    /// `x *(COMMA x)` and `*(SEMI generic-param)` never leave empty; ignored.
    EmptyEntry,
    /// An accept-param `q` outside RFC 3261 §25.1 `qvalue`, kept as sent.
    InvalidQvalue,
    /// A parameter name repeated within one value, kept; lookup returns the
    /// first. RFC 3261 §25.1 `generic-param` defines no meaning for a second
    /// occurrence, and of `auth-param`s RFC 9110 §11.2 says "each parameter
    /// name MUST only occur once per challenge".
    DuplicateParam,
    /// An `auth-param` without the value RFC 3261 §25.1
    /// `auth-param = auth-param-name EQUAL ( token / quoted-string )`
    /// requires, kept as a flag.
    AuthParamFlag,
    /// A CR or LF outside the fold of RFC 3261 §25.1 `LWS = [*WSP CRLF]
    /// 1*WSP`, which neither `qdtext` nor `quoted-pair` carries, or a NUL,
    /// which only `quoted-pair` does; dropped, with a `\` escaping it.
    ControlChar,
    /// A `warn-code` below 100, three digits as RFC 3261 §20.43 `warn-code =
    /// 3DIGIT` requires but in no class §27.2 defines by first digit; kept.
    WarnCodeLeadingZero,
    /// A `"`, `<`, `>` or `,` inside a field RFC 3261 §25.1 makes a `token`,
    /// where it would reframe the list the value is written into; dropped.
    StrayDelimiter,
    /// A `,` ending a list, which the list grammars' `x *(COMMA x)` (RFC
    /// 3261 §25.1) never leave without an entry after it; ignored.
    TrailingComma,
    /// Whitespace around the elements of a request line other than the one
    /// SP between each that RFC 3261 §25.1 `Request-Line = Method SP
    /// Request-URI SP SIP-Version CRLF` allows; read as a separator.
    RequestLineWhitespace,
}

impl WarningCode {
    /// Whether the value keeps what was sent; sip-uri codes carry their own.
    fn own_kind(self) -> WarningKind {
        match self {
            WarningCode::TrailingContent
            | WarningCode::TrailingBackslash
            | WarningCode::WildcardNotAlone
            | WarningCode::InvalidCause
            | WarningCode::SkippedEntry
            | WarningCode::ControlChar
            | WarningCode::StrayDelimiter => WarningKind::Lost,
            _ => WarningKind::Recovered,
        }
    }

    /// Stable kebab-case name within the crate that defines the code: a
    /// sip-uri code is sip-uri's own name, so it may equal one of ours.
    /// [`Display`](fmt::Display) prefixes it `uri-`, so no two codes print
    /// the same.
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
            WarningCode::InvalidQvalue => "invalid-qvalue",
            WarningCode::DuplicateParam => "duplicate-param",
            WarningCode::AuthParamFlag => "auth-param-flag",
            WarningCode::ControlChar => "control-char",
            WarningCode::WarnCodeLeadingZero => "warn-code-leading-zero",
            WarningCode::StrayDelimiter => "stray-delimiter",
            WarningCode::TrailingComma => "trailing-comma",
            WarningCode::RequestLineWhitespace => "request-line-whitespace",
        }
    }
}

impl fmt::Display for WarningCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let WarningCode::Uri(_) = self {
            f.write_str("uri-")?;
        }
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_follows_code() {
        let w = ParseWarning::new(Field::Addr, WarningCode::TrailingContent).at(3);
        assert_eq!(w.kind, WarningKind::Lost);
        let w = ParseWarning::new(Field::DisplayName, WarningCode::InvalidToken);
        assert_eq!(w.kind, WarningKind::Recovered);
    }

    #[test]
    fn display_names_location_never_text() {
        let w = ParseWarning::new(Field::Param, WarningCode::UnterminatedQuote)
            .at(12)
            .in_entry(2);
        assert_eq!(
            w.to_string(),
            "param: unterminated-quote at byte 12 in entry 2"
        );
    }

    /// Every code of this crate; a new variant fails to compile here.
    fn own_codes() -> Vec<WarningCode> {
        let all = vec![
            WarningCode::TrailingContent,
            WarningCode::InvalidToken,
            WarningCode::UnterminatedQuote,
            WarningCode::TrailingBackslash,
            WarningCode::WildcardNotAlone,
            WarningCode::MissingIndex,
            WarningCode::NotNameAddr,
            WarningCode::InvalidCause,
            WarningCode::UnquotedText,
            WarningCode::MissingBrackets,
            WarningCode::SkippedEntry,
            WarningCode::EmptyEntry,
            WarningCode::InvalidQvalue,
            WarningCode::DuplicateParam,
            WarningCode::AuthParamFlag,
            WarningCode::ControlChar,
            WarningCode::WarnCodeLeadingZero,
            WarningCode::StrayDelimiter,
            WarningCode::TrailingComma,
            WarningCode::RequestLineWhitespace,
        ];
        for code in &all {
            match code {
                WarningCode::Uri(_)
                | WarningCode::TrailingContent
                | WarningCode::InvalidToken
                | WarningCode::UnterminatedQuote
                | WarningCode::TrailingBackslash
                | WarningCode::WildcardNotAlone
                | WarningCode::MissingIndex
                | WarningCode::NotNameAddr
                | WarningCode::InvalidCause
                | WarningCode::UnquotedText
                | WarningCode::MissingBrackets
                | WarningCode::SkippedEntry
                | WarningCode::EmptyEntry
                | WarningCode::InvalidQvalue
                | WarningCode::DuplicateParam
                | WarningCode::AuthParamFlag
                | WarningCode::ControlChar
                | WarningCode::WarnCodeLeadingZero
                | WarningCode::StrayDelimiter
                | WarningCode::TrailingComma
                | WarningCode::RequestLineWhitespace => {}
            }
        }
        all
    }

    #[test]
    fn printed_code_names_are_injective() {
        let mut seen = std::collections::HashSet::new();
        for code in own_codes() {
            assert!(
                !code
                    .as_str()
                    .starts_with("uri-"),
                "{code:?}"
            );
            assert!(seen.insert(code.to_string()), "{code:?}");
        }
        for &code in sip_uri::WarningCode::ALL {
            let ours = WarningCode::Uri(code);
            assert_eq!(ours.as_str(), code.as_str(), "{code:?}");
            assert_eq!(
                ours.to_string(),
                format!("uri-{}", code.as_str()),
                "{code:?}"
            );
            assert!(seen.insert(ours.to_string()), "{code:?}");
        }
    }
}
